//! Short-lived tokens the broker mints and the proxy adds: GitHub App installation tokens
//! scoped to one repository, and Tailscale OAuth access tokens.
//!
//! The long-lived keys (the App's private key, the OAuth client secret) are read from
//! Secrets Manager for each mint and dropped right after. Minted tokens are kept in memory
//! until five minutes before they expire, and `bas rotate github` or `bas rotate
//! tailscale` drops them at once.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use bas_core::secrets::Session;
use oauth2::basic::BasicClient;
use oauth2::{ClientId, ClientSecret, Scope, TokenResponse, TokenUrl};
use octocrab::Octocrab;
use octocrab::models::AppId;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use crate::policy::{Github, Repo, Tailscale};
use crate::{Error, audit};

/// Tailscale's OAuth token endpoint.
const TAILSCALE_TOKEN_URL: &str = "https://api.tailscale.com/api/v2/oauth/token";
/// A cached token is replaced this long before it expires.
const MARGIN: Duration = Duration::from_secs(300);

/// A minted token and when it stops working.
#[derive(Clone)]
pub struct Minted {
    /// The token. Never logged.
    pub token: Zeroizing<String>,
    /// Expiry as the issuer reported it.
    pub expires: SystemTime,
}

impl Minted {
    fn fresh(&self) -> bool {
        self.expires
            .duration_since(SystemTime::now())
            .is_ok_and(|left| left > MARGIN)
    }
}

/// Mints and caches tokens.
pub struct Minter {
    session: Session,
    github: Mutex<BTreeMap<String, Minted>>,
    tailscale: Mutex<Option<Minted>>,
}

#[derive(Deserialize)]
struct InstallationToken {
    token: String,
    expires_at: String,
}

impl Minter {
    /// A minter that reads keys through `session`.
    pub fn new(session: Session) -> Self {
        Self {
            session,
            github: Mutex::new(BTreeMap::new()),
            tailscale: Mutex::new(None),
        }
    }

    /// Drops every cached GitHub token. The next request mints a new one.
    pub fn forget_github(&self) {
        self.github
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Drops the cached Tailscale token.
    pub fn forget_tailscale(&self) {
        *self
            .tailscale
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// An installation token for one repository, with the permissions the policy lists.
    pub async fn github(&self, github: &Github, repo: &Repo) -> Result<Minted, Error> {
        let key = repo.name.to_ascii_lowercase();
        if let Some(cached) = self
            .github
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .filter(|cached| cached.fresh())
        {
            return Ok(cached.clone());
        }
        let failed = |reason: String| {
            Error::new(format!(
                "could not mint a GitHub token for {}: {reason}",
                repo.name
            ))
        };
        let pem = self
            .session
            .get(github.private_key.id)
            .await
            .map_err(|failure| {
                failed(
                    failure
                        .read_error(self.session.profile(), "read the App's private key")
                        .to_string(),
                )
            })?
            .into_value();
        let key_pem =
            octocrab::EncodingKey::from_rsa_pem(pem.expose().as_bytes()).map_err(|_| {
                failed("[github] private_key is not an RSA private key in PEM".to_owned())
            })?;
        drop(pem);
        let app = Octocrab::builder()
            .app(AppId(github.app_id), key_pem)
            .build()
            .map_err(|err| failed(format!("could not build the GitHub client: {err}")))?;
        let repository = repo
            .name
            .split_once('/')
            .map_or(repo.name.as_str(), |(_, name)| name);
        let body = serde_json::json!({
            "repositories": [repository],
            "permissions": repo.permissions,
        });
        let route = format!("/app/installations/{}/access_tokens", repo.installation_id);
        let reply: InstallationToken = app
            .post(route, Some(&body))
            .await
            .map_err(|err| failed(format!("GitHub refused: {err}")))?;
        let expires = OffsetDateTime::parse(&reply.expires_at, &Rfc3339)
            .map_err(|_| failed("GitHub sent an expiry bas could not read".to_owned()))?;
        let minted = Minted {
            token: Zeroizing::new(reply.token),
            expires: expires.into(),
        };
        audit::mint("github", &repo.name, &reply.expires_at);
        self.github
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, minted.clone());
        Ok(minted)
    }

    /// A Tailscale API access token with the policy's scopes.
    pub async fn tailscale(&self, tailscale: &Tailscale) -> Result<Minted, Error> {
        if let Some(cached) = self
            .tailscale
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|cached| cached.fresh())
        {
            return Ok(cached.clone());
        }
        let failed =
            |reason: String| Error::new(format!("could not mint a Tailscale token: {reason}"));
        let read = |what: &'static str| {
            move |failure: bas_core::secrets::Failure| {
                failed(failure.read_error(self.session.profile(), what).to_string())
            }
        };
        let client_id = self
            .session
            .get(tailscale.client_id.id)
            .await
            .map_err(read("read the OAuth client ID"))?
            .into_value();
        let client_secret = self
            .session
            .get(tailscale.client_secret.id)
            .await
            .map_err(read("read the OAuth client secret"))?
            .into_value();
        let token_url = TokenUrl::new(TAILSCALE_TOKEN_URL.to_owned())
            .map_err(|_| failed("the token URL is invalid".to_owned()))?;
        let client = BasicClient::new(ClientId::new(client_id.expose().trim().to_owned()))
            .set_client_secret(ClientSecret::new(client_secret.expose().trim().to_owned()))
            .set_token_uri(token_url);
        drop(client_secret);
        let http = oauth2::reqwest::Client::builder()
            .redirect(oauth2::reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| failed("could not build the HTTP client".to_owned()))?;
        let reply = client
            .exchange_client_credentials()
            .add_scopes(tailscale.scopes.iter().cloned().map(Scope::new))
            .request_async(&http)
            .await
            .map_err(|err| failed(format!("Tailscale refused: {err}")))?;
        let lifetime = reply.expires_in().unwrap_or(Duration::from_secs(3600));
        let expires = SystemTime::now() + lifetime;
        let minted = Minted {
            token: Zeroizing::new(reply.access_token().secret().clone()),
            expires,
        };
        let expires_text = OffsetDateTime::from(expires)
            .format(&Rfc3339)
            .unwrap_or_default();
        audit::mint("tailscale", &tailscale.scopes.join(" "), &expires_text);
        *self
            .tailscale
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(minted.clone());
        Ok(minted)
    }
}
