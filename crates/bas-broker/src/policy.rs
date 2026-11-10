//! The active policy, `/var/lib/bas/policy.toml`, which says how each secret may leave the
//! broker.
//!
//! Only `[secret.NAME]` tables exist so far:
//!
//! ```toml
//! version = 1
//!
//! [secret.JINA_API_KEY]
//! ref = "bas://home/<secret-id>"
//! delivery = "proxy"                    # proxy or env
//! host = "api.jina.ai"                  # proxy only
//! header = "Authorization"              # proxy only
//! value = "Bearer {secret}"             # proxy only
//! allow = ["GET /v1/*", "POST /v1/*"]   # proxy only; method and path globs, default deny
//! ```
//!
//! Unknown tables and keys make the policy fail to load, so a rule the broker does not
//! understand is never silently ignored.

use std::collections::BTreeMap;
use std::path::Path;

use bas_core::reference::{EnvName, ProfileName, SecretRef};
use hudsucker::hyper::header::{HeaderName, HeaderValue};
use hudsucker::hyper::{Method, Uri};
use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::Error;

/// Placeholder in `value` that the secret replaces.
const SECRET_PLACEHOLDER: &str = "{secret}";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default)]
    secret: BTreeMap<String, SecretFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretFile {
    #[serde(rename = "ref")]
    reference: String,
    delivery: DeliveryKind,
    host: Option<String>,
    header: Option<String>,
    value: Option<String>,
    allow: Option<Vec<String>>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum DeliveryKind {
    Proxy,
    Env,
}

/// The loaded policy.
#[derive(Debug)]
pub struct Policy {
    hash: String,
    secrets: BTreeMap<String, Secret>,
}

/// One `[secret.NAME]` entry.
#[derive(Debug)]
pub struct Secret {
    /// The policy name, which is also the environment variable name for `env` delivery.
    pub name: String,
    /// Where the value lives in Secrets Manager.
    pub reference: SecretRef,
    /// How the value may leave the broker.
    pub delivery: Delivery,
}

/// How a secret may leave the broker.
#[derive(Debug)]
pub enum Delivery {
    /// `bas run` receives the value and puts it in the program's environment.
    Env,
    /// The proxy adds the value to requests for one host.
    Proxy(ProxyRule),
}

/// What the proxy does for one host.
#[derive(Debug)]
pub struct ProxyRule {
    /// Lowercase host name, without a port.
    pub host: String,
    /// Header the proxy sets.
    pub header: HeaderName,
    value: String,
    allow: Vec<Allow>,
}

#[derive(Debug)]
struct Allow {
    method: Method,
    path: Regex,
}

impl ProxyRule {
    /// The header value with the secret in place of `{secret}`, marked sensitive so hyper
    /// keeps it out of debug output and HTTP/2 header compression.
    pub fn header_value(&self, secret: &str) -> Option<HeaderValue> {
        let mut value =
            HeaderValue::from_str(&self.value.replace(SECRET_PLACEHOLDER, secret)).ok()?;
        value.set_sensitive(true);
        Some(value)
    }

    /// Whether some `allow` entry matches the method and path of `uri`.
    ///
    /// Paths with `.` or `..` segments, backslashes, or encoded dots, slashes, or
    /// backslashes never match, because the upstream server could read them as another
    /// path than the one checked here.
    pub fn allows(&self, method: &Method, uri: &Uri) -> bool {
        let path = uri.path();
        let lower = path.to_ascii_lowercase();
        let ambiguous = path.contains('\\')
            || ["%2e", "%2f", "%5c"]
                .iter()
                .any(|encoded| lower.contains(encoded))
            || path
                .split('/')
                .any(|segment| segment == "." || segment == "..");
        !ambiguous
            && self
                .allow
                .iter()
                .any(|allow| allow.method == method && allow.path.is_match(path))
    }
}

impl Policy {
    /// Reads and checks the policy. Every `ref` must name `profile`, the broker's profile.
    pub fn load(path: &Path, profile: &ProfileName) -> Result<Self, Error> {
        let text = std::fs::read(path)
            .map_err(|err| Error::new(format!("could not read {}: {err}", path.display())))?;
        let hash = Sha256::digest(&text)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let text = std::str::from_utf8(&text)
            .map_err(|_| Error::new(format!("{} is not UTF-8", path.display())))?;
        let file: PolicyFile = toml::from_str(text)
            .map_err(|err| Error::new(format!("{} is malformed: {err}", path.display())))?;
        if file.version != 1 {
            return Err(Error::new(format!("{}: version must be 1", path.display())));
        }
        let mut secrets = BTreeMap::new();
        let mut hosts: BTreeMap<String, String> = BTreeMap::new();
        for (name, entry) in file.secret {
            let invalid =
                |reason: &str| Error::new(format!("{}: secret.{name}: {reason}", path.display()));
            name.parse::<EnvName>()
                .map_err(|_| invalid("the name must be a valid environment variable name"))?;
            let reference: SecretRef = entry
                .reference
                .parse()
                .map_err(|_| invalid("ref must look like bas://<profile>/<secret-id>"))?;
            if reference.profile != *profile {
                return Err(invalid(&format!(
                    "ref must use the broker's profile '{profile}'"
                )));
            }
            let delivery = match entry.delivery {
                DeliveryKind::Env => {
                    if entry.host.is_some()
                        || entry.header.is_some()
                        || entry.value.is_some()
                        || entry.allow.is_some()
                    {
                        return Err(invalid(
                            "host, header, value, and allow belong to delivery = \"proxy\" only",
                        ));
                    }
                    Delivery::Env
                }
                DeliveryKind::Proxy => {
                    let rule = proxy_rule(entry).map_err(|reason| invalid(&reason))?;
                    if let Some(other) = hosts.insert(rule.host.clone(), name.clone()) {
                        return Err(invalid(&format!(
                            "host {} is already used by secret.{other}",
                            rule.host
                        )));
                    }
                    Delivery::Proxy(rule)
                }
            };
            secrets.insert(
                name.clone(),
                Secret {
                    name,
                    reference,
                    delivery,
                },
            );
        }
        Ok(Self { hash, secrets })
    }

    /// SHA-256 of the policy file, in lowercase hex.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// The entry for a policy name.
    pub fn secret(&self, name: &str) -> Option<&Secret> {
        self.secrets.get(name)
    }

    /// The proxy entry for a lowercase host name.
    pub fn for_host(&self, host: &str) -> Option<(&Secret, &ProxyRule)> {
        self.secrets
            .values()
            .find_map(|secret| match &secret.delivery {
                Delivery::Proxy(rule) if rule.host == host => Some((secret, rule)),
                _ => None,
            })
    }
}

fn proxy_rule(entry: SecretFile) -> Result<ProxyRule, String> {
    let (Some(host), Some(header), Some(value), Some(allow)) =
        (entry.host, entry.header, entry.value, entry.allow)
    else {
        return Err("delivery = \"proxy\" needs host, header, value, and allow".to_owned());
    };
    let host = host.to_ascii_lowercase();
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && !host.starts_with('.')
        && !host.ends_with('.');
    if !host_ok {
        return Err("host must be a DNS name without a port".to_owned());
    }
    let header: HeaderName = header
        .parse()
        .map_err(|_| "header must be a valid HTTP header name".to_owned())?;
    if value.matches(SECRET_PLACEHOLDER).count() != 1 {
        return Err("value must contain {secret} exactly once".to_owned());
    }
    if HeaderValue::from_str(&value).is_err() {
        return Err("value must be a valid HTTP header value".to_owned());
    }
    let allow = allow
        .iter()
        .map(|entry| parse_allow(entry))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProxyRule {
        host,
        header,
        value,
        allow,
    })
}

/// Parses `METHOD /path/glob`, where `*` in the path matches any run of characters,
/// including `/`.
fn parse_allow(entry: &str) -> Result<Allow, String> {
    let invalid = || format!("allow entry '{entry}' must look like \"GET /v1/*\"");
    let (method, path) = entry.split_once(' ').ok_or_else(invalid)?;
    if !path.starts_with('/') || path.contains(' ') {
        return Err(invalid());
    }
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| invalid())?;
    let pattern = path
        .split('*')
        .map(regex::escape)
        .collect::<Vec<_>>()
        .join(".*");
    let path = Regex::new(&format!("^{pattern}$")).map_err(|_| invalid())?;
    Ok(Allow { method, path })
}
