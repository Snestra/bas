//! Authenticated Secrets Manager operations through the published SDK.
//!
//! SDK request and response types stay inside this module. Callers receive
//! [`Identifier`] metadata and [`Secret`] values whose `Debug` output is redacted.

use std::fmt;

use bitwarden::secrets_manager::secrets::{
    SecretCreateRequest, SecretGetRequest, SecretIdentifiersByProjectRequest,
    SecretIdentifiersRequest, SecretPutRequest, SecretResponse, SecretsGetRequest,
};
use bitwarden::secrets_manager::{
    AccessTokenLoginRequest, ClientSettings, DeviceType, SecretsManagerClient,
};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::credential::{MachineToken, SecretText};
use crate::output::Error;
use crate::profile::Profile;

/// How an SDK call failed, derived without reading the upstream message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The server answered with this HTTP status.
    Status(u16),
    /// The identity server refused the credential.
    IdentityRejected,
    /// No usable response arrived: connection, TLS, timeout, or I/O failure.
    Transport,
    /// The SDK refused the request before sending it.
    Validation,
    /// The response arrived but could not be decoded or decrypted.
    Unprocessable,
}

impl Failure {
    /// Classifies an SDK error by its derived `Debug` variant name.
    ///
    /// The published SDK keeps `SecretsManagerError` in a private module, so its variants
    /// cannot be matched by path. Variant names are stable for the locked SDK version, and
    /// anything unrecognized becomes [`Failure::Unprocessable`], which callers treat as an
    /// unknown outcome. The rendered text is inspected here and never printed.
    fn classify(err: &impl fmt::Debug) -> Self {
        let rendered = format!("{err:?}");
        if let Some(rest) = rendered.strip_prefix("Api(ResponseContent { status: ") {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            return digits.parse().map_or(Self::Unprocessable, Self::Status);
        }
        if rendered.starts_with("Api(Reqwest") || rendered.starts_with("Api(Io(") {
            Self::Transport
        } else if rendered.starts_with("IdentityFail(") {
            Self::IdentityRejected
        } else if rendered.starts_with("Validation(") {
            Self::Validation
        } else {
            Self::Unprocessable
        }
    }

    /// The SDK or server refused the request, so the service performed no change.
    pub fn is_rejection(self) -> bool {
        matches!(self, Self::Status(400..=499) | Self::Validation)
    }

    /// Describes a failed read or listing with fixed wording.
    pub fn read_error(self, profile: &Profile, operation: &str) -> Error {
        let name = &profile.name;
        match self {
            Self::Status(401 | 403) => {
                Error::new(format!("profile '{name}' is not authorized to {operation}"))
            }
            Self::Status(404) => Error::new(format!(
                "could not {operation}: not found or not accessible to profile '{name}'"
            )),
            Self::Status(status) => Error::new(format!(
                "Secrets Manager refused to {operation} for profile '{name}' (HTTP {status})"
            )),
            Self::Transport => Error::new(format!(
                "could not reach Secrets Manager at {} to {operation}",
                profile.endpoints.api()
            )),
            Self::IdentityRejected | Self::Validation | Self::Unprocessable => Error::new(format!(
                "could not {operation}: the Secrets Manager response was unusable"
            )),
        }
    }
}

/// Secret metadata from the identifier listing, which carries no values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identifier {
    pub id: Uuid,
    pub key: String,
    pub project_ids: Vec<Uuid>,
}

/// A retrieved secret. Value and note are redacted from `Debug` and zeroed on drop.
pub struct Secret {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Option<Uuid>,
    pub key: String,
    pub value: SecretText,
    pub note: SecretText,
}

impl Secret {
    fn from_response(response: SecretResponse) -> Self {
        let SecretResponse {
            id,
            organization_id,
            project_id,
            key,
            value,
            note,
            ..
        } = response;
        Self {
            id,
            organization_id,
            project_id,
            key,
            value: SecretText::new(value),
            note: SecretText::new(note),
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("id", &self.id)
            .field("organization_id", &self.organization_id)
            .field("project_id", &self.project_id)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// Fields written by a create or value update.
pub struct WriteRequest<'a> {
    pub key: &'a str,
    pub value: &'a SecretText,
    pub note: &'a SecretText,
    pub project_ids: &'a [Uuid],
}

/// An authenticated SDK client confirmed to belong to the profile's organization.
///
/// The SDK keeps its session in memory only; no state file is written.
pub struct Session {
    client: SecretsManagerClient,
    profile: Profile,
}

impl Session {
    /// Authenticates with the machine token and confirms the organization.
    ///
    /// # Errors
    ///
    /// Fails when the token is refused, the service is unreachable, or the token belongs
    /// to a different organization than the profile names.
    pub async fn open(profile: &Profile, token: &MachineToken) -> Result<Self, Error> {
        let name = &profile.name;
        let client = SecretsManagerClient::new(Some(ClientSettings {
            identity_url: profile.endpoints.identity().to_owned(),
            api_url: profile.endpoints.api().to_owned(),
            user_agent: concat!("bas/", env!("CARGO_PKG_VERSION")).to_owned(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        }));
        let mut request = AccessTokenLoginRequest {
            access_token: token.expose().to_owned(),
            state_file: None,
        };
        let result = client.auth().login_access_token(&request).await;
        request.access_token.zeroize();
        let authenticated = match result {
            Ok(response) => response.authenticated,
            Err(err) => {
                return Err(match Failure::classify(&err) {
                    Failure::IdentityRejected | Failure::Status(400..=499) => Error::new(format!(
                        "Secrets Manager refused the machine token for profile '{name}'"
                    )),
                    Failure::Transport => Error::new(format!(
                        "could not reach the identity endpoint {} for profile '{name}'",
                        profile.endpoints.identity()
                    )),
                    _ => Error::new(format!("authentication failed for profile '{name}'")),
                });
            }
        };
        if !authenticated {
            return Err(Error::new(format!(
                "Secrets Manager did not authenticate profile '{name}'"
            )));
        }
        let organization = client
            .get_access_token_organization()
            .map(Uuid::from)
            .ok_or_else(|| {
                Error::new(format!(
                    "the machine token for profile '{name}' names no organization"
                ))
            })?;
        if organization != profile.organization {
            return Err(Error::new(format!(
                "the machine token for profile '{name}' belongs to organization {organization}, \
                 not the configured {}",
                profile.organization
            )));
        }
        Ok(Self {
            client,
            profile: profile.clone(),
        })
    }

    /// Lists secret identifiers visible to the machine account, optionally in one project.
    ///
    /// Uses the identifier endpoints, which return keys and project IDs but no values.
    ///
    /// # Errors
    ///
    /// Fails when the listing is refused or unusable.
    pub async fn list_identifiers(&self, project: Option<Uuid>) -> Result<Vec<Identifier>, Error> {
        let secrets = self.client.secrets();
        let response = match project {
            Some(project_id) => {
                secrets
                    .list_by_project(&SecretIdentifiersByProjectRequest { project_id })
                    .await
            }
            None => {
                secrets
                    .list(&SecretIdentifiersRequest {
                        organization_id: self.profile.organization,
                    })
                    .await
            }
        };
        let response = response.map_err(|err| {
            Failure::classify(&err).read_error(&self.profile, "list secret identifiers")
        })?;
        Ok(response
            .data
            .into_iter()
            .filter(|identifier| identifier.organization_id == self.profile.organization)
            .map(|identifier| Identifier {
                id: identifier.id,
                key: identifier.key,
                project_ids: identifier.project_ids,
            })
            .collect())
    }

    /// Retrieves exactly the given secrets in one request.
    ///
    /// # Errors
    ///
    /// Fails when the request is refused or any secret is in another organization.
    pub async fn get_many(&self, ids: &[Uuid]) -> Result<Vec<Secret>, Error> {
        let response = self
            .client
            .secrets()
            .get_by_ids(SecretsGetRequest { ids: ids.to_vec() })
            .await
            .map_err(|err| {
                Failure::classify(&err).read_error(&self.profile, "retrieve the selected secrets")
            })?;
        let secrets: Vec<Secret> = response
            .data
            .into_iter()
            .map(Secret::from_response)
            .collect();
        if secrets
            .iter()
            .all(|secret| secret.organization_id == self.profile.organization)
        {
            Ok(secrets)
        } else {
            Err(Error::new(format!(
                "Secrets Manager returned a secret outside the organization of profile '{}'",
                self.profile.name
            )))
        }
    }

    /// Retrieves one secret.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn get(&self, id: Uuid) -> Result<Secret, Failure> {
        self.client
            .secrets()
            .get(&SecretGetRequest { id })
            .await
            .map(Secret::from_response)
            .map_err(|err| Failure::classify(&err))
    }

    /// Creates a secret in the profile's organization. Never retried.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn create(&self, write: &WriteRequest<'_>) -> Result<Secret, Failure> {
        let mut request = SecretCreateRequest {
            organization_id: self.profile.organization,
            key: write.key.to_owned(),
            value: write.value.expose().to_owned(),
            note: write.note.expose().to_owned(),
            project_ids: Some(write.project_ids.to_vec()),
        };
        let result = self.client.secrets().create(&request).await;
        request.value.zeroize();
        request.note.zeroize();
        result
            .map(Secret::from_response)
            .map_err(|err| Failure::classify(&err))
    }

    /// Replaces a secret's key, value, note, and project. Never retried.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn update(&self, id: Uuid, write: &WriteRequest<'_>) -> Result<Secret, Failure> {
        let mut request = SecretPutRequest {
            id,
            organization_id: self.profile.organization,
            key: write.key.to_owned(),
            value: write.value.expose().to_owned(),
            note: write.note.expose().to_owned(),
            project_ids: Some(write.project_ids.to_vec()),
        };
        let result = self.client.secrets().update(&request).await;
        request.value.zeroize();
        request.note.zeroize();
        result
            .map(Secret::from_response)
            .map_err(|err| Failure::classify(&err))
    }
}

/// Builds a current-thread async runtime for SDK calls.
///
/// # Errors
///
/// Fails when the operating system refuses the runtime's resources.
pub fn runtime() -> Result<tokio::runtime::Runtime, Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::new("could not start the async runtime"))
}
