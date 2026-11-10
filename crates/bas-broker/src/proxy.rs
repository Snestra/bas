//! HTTPS proxy on a loopback port that adds a policy credential to requests for one host.
//!
//! Only `CONNECT host:443` is accepted. A host without a policy rule gets a plain tunnel,
//! so the broker never sees its traffic. For a rule host the broker ends the client's TLS
//! with a certificate from its own authority, checks that the inner `Host` is the
//! `CONNECT` host and that the method and path match `allow`, removes any client
//! `Authorization`, sets the configured header, and opens its own TLS connection upstream,
//! verified against the Mozilla roots.

use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bas_core::secrets::Session;
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::hyper::header::{AUTHORIZATION, HOST, HeaderValue, PROXY_AUTHORIZATION};
use hudsucker::hyper::http::uri::Scheme;
use hudsucker::hyper::{Method, Request, Response, StatusCode};
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use hudsucker::rustls::crypto::ring;
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use crate::policy::Policy;
use crate::{Error, audit};

const CA_KEY_FILE: &str = "ca.key";
const CA_CERT_FILE: &str = "ca.pem";
/// How many generated host certificates the proxy keeps in memory.
const CERT_CACHE: u64 = 1_000;
/// System trust bundles, in the order Debian, Fedora, and Arch-like systems keep them.
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
];

/// The proxy's certificate authority, kept in the broker's state directory.
pub struct Authority {
    key_pem: Zeroizing<String>,
    cert_pem: String,
}

impl Authority {
    /// Loads the authority from `state_dir`, or creates it on first start. The private key
    /// file is mode 0600.
    pub fn load_or_create(state_dir: &Path) -> Result<Self, Error> {
        let key_path = state_dir.join(CA_KEY_FILE);
        let cert_path = state_dir.join(CA_CERT_FILE);
        match std::fs::read_to_string(&key_path) {
            Ok(key_pem) => {
                let cert_pem = std::fs::read_to_string(&cert_path)
                    .map_err(|err| file_error("read", &cert_path, &err))?;
                return Ok(Self {
                    key_pem: Zeroizing::new(key_pem),
                    cert_pem,
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(file_error("read", &key_path, &err)),
        }
        let failed = |err: hudsucker::rcgen::Error| {
            Error::new(format!("could not create the proxy authority: {err}"))
        };
        let key = KeyPair::generate().map_err(failed)?;
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "bas broker proxy authority");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(3650);
        let cert = params.self_signed(&key).map_err(failed)?;
        let authority = Self {
            key_pem: Zeroizing::new(key.serialize_pem()),
            cert_pem: cert.pem(),
        };
        create_dir(state_dir)?;
        write_new(&cert_path, authority.cert_pem.as_bytes(), 0o644)?;
        write_new(&key_path, authority.key_pem.as_bytes(), 0o600)?;
        Ok(authority)
    }

    /// Writes the system roots followed by this authority to `path`, mode 0644, replacing
    /// the file in one rename.
    pub fn write_bundle(&self, path: &Path) -> Result<(), Error> {
        let system = SYSTEM_BUNDLES
            .iter()
            .find_map(|candidate| std::fs::read_to_string(candidate).ok())
            .ok_or_else(|| Error::new("could not find the system certificate bundle"))?;
        let mut bundle = system;
        if !bundle.ends_with('\n') {
            bundle.push('\n');
        }
        bundle.push_str("# bas broker proxy authority\n");
        bundle.push_str(&self.cert_pem);
        if let Some(parent) = path.parent() {
            create_dir(parent)?;
        }
        let mut staged = PathBuf::from(path);
        staged.as_mut_os_string().push(".new");
        let _ = std::fs::remove_file(&staged);
        write_new(&staged, bundle.as_bytes(), 0o644)?;
        std::fs::rename(&staged, path).map_err(|err| file_error("write", path, &err))
    }

    fn rcgen(&self) -> Result<RcgenAuthority, Error> {
        let failed = |err: hudsucker::rcgen::Error| {
            Error::new(format!(
                "the proxy authority in the state directory is unusable: {err}"
            ))
        };
        let key = KeyPair::from_pem(&self.key_pem).map_err(failed)?;
        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, key).map_err(failed)?;
        Ok(RcgenAuthority::new(
            issuer,
            CERT_CACHE,
            ring::default_provider(),
        ))
    }
}

fn file_error(action: &str, path: &Path, err: &std::io::Error) -> Error {
    Error::new(format!("could not {action} {}: {err}", path.display()))
}

fn create_dir(dir: &Path) -> Result<(), Error> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|err| file_error("create", dir, &err))
}

/// Creates `path`, which must not exist, and sets `mode` after writing, because the
/// service's umask would narrow a mode given at creation.
fn write_new(path: &Path, contents: &[u8], mode: u32) -> Result<(), Error> {
    let failed = |err: std::io::Error| file_error("write", path, &err);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(failed)?;
    file.write_all(contents).map_err(failed)?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(failed)?;
    file.sync_all().map_err(failed)
}

/// Binds the proxy port and returns the future that serves it.
pub async fn start(
    addr: SocketAddr,
    authority: Authority,
    policy: Arc<Policy>,
    session: Session,
) -> Result<impl Future<Output = Result<(), Error>>, Error> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|err| Error::new(format!("could not listen on {addr}: {err}")))?;
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(authority.rcgen()?)
        .with_rustls_connector(ring::default_provider())
        .with_http_handler(Injector {
            policy,
            session,
            tunnel: None,
        })
        .build()
        .map_err(|err| Error::new(format!("could not build the proxy: {err}")))?;
    Ok(async move {
        proxy
            .start()
            .await
            .map_err(|err| Error::new(format!("the proxy stopped: {err}")))
    })
}

/// Request handler. hudsucker clones it for each connection, and the clone that handled a
/// `CONNECT` also handles every request inside that tunnel, so `tunnel` is per tunnel.
#[derive(Clone)]
struct Injector {
    policy: Arc<Policy>,
    session: Session,
    tunnel: Option<Arc<Tunnel>>,
}

/// A `CONNECT` to a rule host, with the header value fetched for it.
struct Tunnel {
    name: String,
    host: String,
    value: HeaderValue,
}

impl HttpHandler for Injector {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse {
        if request.method() == Method::CONNECT {
            return self.connect(request).await;
        }
        match self.tunnel.clone() {
            Some(tunnel) => self.inject(request, &tunnel),
            None => reply(
                StatusCode::FORBIDDEN,
                "the bas proxy accepts only CONNECT to port 443\n",
            ),
        }
    }

    async fn should_intercept_connect(
        &mut self,
        _ctx: &HttpContext,
        _request: &Request<Body>,
    ) -> bool {
        self.tunnel.is_some()
    }
}

impl Injector {
    /// Accepts `CONNECT host:443`. For a rule host it fetches the secret now, so a failure
    /// refuses the tunnel instead of each request in it.
    async fn connect(&mut self, request: Request<Body>) -> RequestOrResponse {
        let Some(authority) = request.uri().authority() else {
            return reply(StatusCode::BAD_REQUEST, "CONNECT needs host:port\n");
        };
        if authority.port_u16() != Some(443) {
            return reply(
                StatusCode::FORBIDDEN,
                "the bas proxy accepts only CONNECT to port 443\n",
            );
        }
        let host = normalize_host(authority.host());
        let policy = Arc::clone(&self.policy);
        let Some((secret, rule)) = policy.for_host(&host) else {
            return request.into();
        };
        let value = match self.session.get(secret.reference.id).await {
            Ok(found) => found.into_value(),
            Err(err) => {
                tracing::warn!("could not read {} for {host}: {err}", secret.name);
                return reply(
                    StatusCode::BAD_GATEWAY,
                    "the broker could not read the secret\n",
                );
            }
        };
        let Some(value) = rule.header_value(value.expose()) else {
            tracing::warn!("{} does not fit in an HTTP header value", secret.name);
            return reply(
                StatusCode::BAD_GATEWAY,
                "the secret is not a valid header value\n",
            );
        };
        self.tunnel = Some(Arc::new(Tunnel {
            name: secret.name.clone(),
            host,
            value,
        }));
        request.into()
    }

    /// Checks one request inside a rule host's tunnel and sets the policy header on it.
    fn inject(&self, mut request: Request<Body>, tunnel: &Tunnel) -> RequestOrResponse {
        let method = request.method().as_str().to_owned();
        let path = request.uri().path().to_owned();
        let refuse = |status: StatusCode, reason: &str| {
            audit::deny_request(&tunnel.name, &tunnel.host, &method, &path, reason);
            reply(status, "refused by bas policy\n")
        };
        if request.uri().scheme() != Some(&Scheme::HTTPS) {
            return refuse(StatusCode::FORBIDDEN, "not TLS inside the tunnel");
        }
        let inner_host = request
            .headers()
            .get(HOST)
            .and_then(|host| host.to_str().ok())
            .map(|host| normalize_host(host.strip_suffix(":443").unwrap_or(host)));
        let target_host = request.uri().host().map(normalize_host);
        if inner_host.as_deref() != Some(&tunnel.host)
            || target_host.as_deref() != Some(&tunnel.host)
        {
            return refuse(StatusCode::FORBIDDEN, "Host differs from the CONNECT host");
        }
        let Some((_, rule)) = self.policy.for_host(&tunnel.host) else {
            return refuse(StatusCode::FORBIDDEN, "no rule for the host");
        };
        if !rule.allows(request.method(), request.uri()) {
            return refuse(StatusCode::FORBIDDEN, "method and path not in allow");
        }
        let headers = request.headers_mut();
        headers.remove(AUTHORIZATION);
        headers.remove(PROXY_AUTHORIZATION);
        headers.remove(&rule.header);
        headers.insert(rule.header.clone(), tunnel.value.clone());
        audit::inject(&tunnel.name, &tunnel.host, &method, &path);
        request.into()
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn reply(status: StatusCode, text: &'static str) -> RequestOrResponse {
    let mut response = Response::new(Body::from(text));
    *response.status_mut() = status;
    response.into()
}
