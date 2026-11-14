//! Enrolled passkeys and one-time enrollment links.
//!
//! The user asked for convenience, so any passkey works: a YubiKey touched in the browser,
//! or a passkey on a phone, synced or not. Each approval still needs user verification
//! on the device, which an agent on this machine can't give.
//!
//! The passkeys' public keys live in `passkeys.json` in the state directory. While none is
//! enrolled, the broker writes a one-time enrollment link to `enroll-url` there, which only
//! the broker's user and root can read. Root opens that link in a browser. Each later
//! passkey needs an approval from an enrolled one, and the approval page shows its link to
//! the approval page only.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use bas_core::Uuid;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::files::{file_error, replace};
use crate::{Error, audit};

const PASSKEYS_FILE: &str = "passkeys.json";
const ENROLL_FILE: &str = "enroll-url";
/// How long an enrollment link made by an approval stays usable.
const LINK_LIFETIME: Duration = Duration::from_secs(15 * 60);

#[derive(Default, Serialize, Deserialize)]
struct PasskeyFile {
    /// WebAuthn user handle shared by every passkey of this broker.
    user: Option<Uuid>,
    passkeys: Vec<Stored>,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    label: String,
    added: String,
    passkey: Passkey,
}

struct Link {
    /// `None` for the link in `enroll-url`, which lasts until used.
    expires: Option<Instant>,
    registration: Option<PasskeyRegistration>,
}

/// Why a passkey step failed. Every variant becomes HTTP 403 or 404 on the page.
#[derive(Debug)]
pub enum Refused {
    /// The link is unknown, used, or expired.
    NoLink,
    /// The ceremony failed: no challenge, a bad signature, no user verification, or a
    /// passkey that is not enrolled.
    Ceremony(String),
    /// A state file could not be written.
    Storage(Error),
}

/// The passkeys and the WebAuthn relying party.
pub struct Passkeys {
    webauthn: Webauthn,
    origin: Url,
    path: PathBuf,
    link_path: PathBuf,
    inner: Mutex<Inner>,
}

struct Inner {
    file: PasskeyFile,
    links: BTreeMap<String, Link>,
}

impl Passkeys {
    /// Loads the passkeys for `origin`, and writes a first enrollment link when there are
    /// none.
    pub fn open(state_dir: &Path, origin: &Url) -> Result<Self, Error> {
        let rp_id = origin
            .host_str()
            .ok_or_else(|| Error::new("approvals.origin has no host"))?;
        let webauthn = WebauthnBuilder::new(rp_id, origin)
            .and_then(|builder| builder.rp_name("bas broker").build())
            .map_err(|err| {
                Error::new(format!(
                    "approvals.origin is not usable for WebAuthn: {err}"
                ))
            })?;
        let path = state_dir.join(PASSKEYS_FILE);
        let file = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| Error::new(format!("{} is malformed", path.display())))?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => PasskeyFile::default(),
            Err(err) => return Err(file_error("read", &path, &err)),
        };
        let passkeys = Self {
            webauthn,
            origin: origin.clone(),
            path,
            link_path: state_dir.join(ENROLL_FILE),
            inner: Mutex::new(Inner {
                file,
                links: BTreeMap::new(),
            }),
        };
        if passkeys.count() == 0 {
            let token = random_token();
            let url = passkeys.link_url(&token);
            replace(&passkeys.link_path, format!("{url}\n").as_bytes(), 0o600)?;
            passkeys.lock().links.insert(
                token,
                Link {
                    expires: None,
                    registration: None,
                },
            );
            tracing::warn!(
                "no passkey is enrolled; root can read the one-time enrollment link in {}",
                passkeys.link_path.display()
            );
        } else {
            match std::fs::remove_file(&passkeys.link_path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(file_error("remove", &passkeys.link_path, &err)),
            }
        }
        Ok(passkeys)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn link_url(&self, token: &str) -> String {
        format!("{}enroll/{token}", self.origin)
    }

    /// How many passkeys are enrolled.
    pub fn count(&self) -> usize {
        self.lock().file.passkeys.len()
    }

    /// Makes a new enrollment link that lasts 15 minutes, and returns its URL.
    pub fn new_link(&self) -> String {
        let token = random_token();
        let url = self.link_url(&token);
        self.lock().links.insert(
            token,
            Link {
                expires: Some(Instant::now() + LINK_LIFETIME),
                registration: None,
            },
        );
        url
    }

    /// Whether `token` is a usable enrollment link.
    pub fn link_valid(&self, token: &str) -> bool {
        let mut inner = self.lock();
        prune(&mut inner.links);
        inner.links.contains_key(token)
    }

    /// Starts enrolling a passkey through the link `token`.
    pub fn begin_enroll(&self, token: &str) -> Result<CreationChallengeResponse, Refused> {
        let mut inner = self.lock();
        prune(&mut inner.links);
        if !inner.links.contains_key(token) {
            return Err(Refused::NoLink);
        }
        let user = *inner.file.user.get_or_insert_with(Uuid::new_v4);
        let exclude = inner
            .file
            .passkeys
            .iter()
            .map(|stored| stored.passkey.cred_id().clone())
            .collect::<Vec<_>>();
        let (challenge, registration) = self
            .webauthn
            .start_passkey_registration(user, "bas", "bas approver", Some(exclude))
            .map_err(|err| Refused::Ceremony(format!("could not start enrollment: {err}")))?;
        if let Some(link) = inner.links.get_mut(token) {
            link.registration = Some(registration);
        }
        Ok(challenge)
    }

    /// Finishes enrolling through `token`, saves the passkey, and uses up the link.
    pub fn finish_enroll(
        &self,
        token: &str,
        credential: &RegisterPublicKeyCredential,
        label: &str,
    ) -> Result<(), Refused> {
        let mut inner = self.lock();
        prune(&mut inner.links);
        let registration = inner
            .links
            .get_mut(token)
            .ok_or(Refused::NoLink)?
            .registration
            .take()
            .ok_or_else(|| Refused::Ceremony("enrollment was not started".to_owned()))?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &registration)
            .map_err(|err| Refused::Ceremony(format!("the passkey was not accepted: {err}")))?;
        if inner
            .file
            .passkeys
            .iter()
            .any(|stored| stored.passkey.cred_id() == passkey.cred_id())
        {
            return Err(Refused::Ceremony(
                "this passkey is already enrolled".to_owned(),
            ));
        }
        let label = if label.trim().is_empty() {
            format!("passkey {}", inner.file.passkeys.len() + 1)
        } else {
            label.trim().chars().take(64).collect()
        };
        inner.file.passkeys.push(Stored {
            label: label.clone(),
            added: now_text(),
            passkey,
        });
        self.save(&inner.file).map_err(Refused::Storage)?;
        let link = inner.links.remove(token);
        drop(inner);
        if link.is_some_and(|link| link.expires.is_none()) {
            match std::fs::remove_file(&self.link_path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(Refused::Storage(file_error(
                        "remove",
                        &self.link_path,
                        &err,
                    )));
                }
            }
        }
        audit::enroll(&label);
        Ok(())
    }

    /// Starts an assertion that any enrolled passkey can answer, with user verification
    /// required.
    pub fn begin_assertion(
        &self,
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), Refused> {
        let inner = self.lock();
        let keys: Vec<Passkey> = inner
            .file
            .passkeys
            .iter()
            .map(|stored| stored.passkey.clone())
            .collect();
        if keys.is_empty() {
            return Err(Refused::Ceremony("no passkey is enrolled".to_owned()));
        }
        self.webauthn
            .start_passkey_authentication(&keys)
            .map_err(|err| Refused::Ceremony(format!("could not start the assertion: {err}")))
    }

    /// Checks an assertion against the challenge it answers, and that the user was
    /// verified. Updates the passkey's signature counter.
    pub fn finish_assertion(
        &self,
        credential: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<String, Refused> {
        let result = self
            .webauthn
            .finish_passkey_authentication(credential, state)
            .map_err(|err| Refused::Ceremony(format!("the assertion failed: {err}")))?;
        if !result.user_verified() {
            return Err(Refused::Ceremony(
                "the passkey did not verify the user".to_owned(),
            ));
        }
        let mut inner = self.lock();
        let Some(stored) = inner
            .file
            .passkeys
            .iter_mut()
            .find(|stored| stored.passkey.cred_id() == result.cred_id())
        else {
            return Err(Refused::Ceremony("the passkey is not enrolled".to_owned()));
        };
        let label = stored.label.clone();
        if stored.passkey.update_credential(&result) == Some(true) {
            self.save(&inner.file).map_err(Refused::Storage)?;
        }
        Ok(label)
    }

    fn save(&self, file: &PasskeyFile) -> Result<(), Error> {
        let bytes = serde_json::to_vec_pretty(file)
            .map_err(|_| Error::new("could not encode the passkeys"))?;
        replace(&self.path, &bytes, 0o600)
    }
}

fn prune(links: &mut BTreeMap<String, Link>) {
    let now = Instant::now();
    links.retain(|_, link| link.expires.is_none_or(|expires| expires > now));
}

/// 244 random bits from two version 4 UUIDs, as 64 hex digits.
pub fn random_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// The current UTC time in RFC 3339.
pub fn now_text() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}
