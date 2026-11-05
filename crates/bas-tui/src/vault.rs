//! Secrets Manager operations a machine account token can perform, through the published SDK.
//!
//! SDK request and response types stay inside this module. Values and notes travel as
//! [`SecretValue`], which zeroes its memory on drop and never prints through `Debug`.

use std::error::Error;
use std::fmt;

use bitwarden::secrets_manager::projects::{
    ProjectCreateRequest, ProjectPutRequest, ProjectResponse, ProjectsDeleteRequest,
    ProjectsListRequest,
};
use bitwarden::secrets_manager::secrets::{
    SecretCreateRequest, SecretGetRequest, SecretIdentifiersByProjectRequest,
    SecretIdentifiersRequest, SecretPutRequest, SecretResponse, SecretsDeleteRequest,
};
use bitwarden::secrets_manager::{
    AccessTokenLoginRequest, ClientSettings, DeviceType, SecretsManagerClient,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Secret text that is zeroed on drop and redacted from `Debug`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    /// Wraps text so it is zeroed when dropped.
    pub fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    /// Borrows the plain text. Callers must not log or persist it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Appends one character, as typed into a form.
    pub fn push(&mut self, ch: char) {
        self.0.push(ch);
    }

    /// Removes the last character, as erased in a form.
    pub fn pop(&mut self) {
        self.0.pop();
    }

    /// Counts characters, so a form can show one mask symbol per typed character.
    pub fn char_count(&self) -> usize {
        self.0.chars().count()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Where and as whom to connect.
#[derive(Clone)]
pub struct Connection {
    /// Secrets Manager API base URL, such as `https://api.bitwarden.com`.
    pub api_url: String,
    /// Identity server base URL, such as `https://identity.bitwarden.com`.
    pub identity_url: String,
    /// Organization the token must belong to.
    pub organization: Uuid,
    /// Machine account access token.
    pub token: SecretValue,
    /// User agent sent with every request.
    pub user_agent: String,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("api_url", &self.api_url)
            .field("identity_url", &self.identity_url)
            .field("organization", &self.organization)
            .field("user_agent", &self.user_agent)
            .finish_non_exhaustive()
    }
}

/// A project visible to the machine account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
}

/// Secret metadata from a listing, which carries no value or note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretListing {
    pub id: Uuid,
    pub key: String,
    pub project_ids: Vec<Uuid>,
}

/// A secret as the server returned it, value and note included.
#[derive(Clone)]
pub struct SecretDetail {
    pub id: Uuid,
    pub key: String,
    pub value: SecretValue,
    pub note: SecretValue,
    pub project_id: Option<Uuid>,
}

impl fmt::Debug for SecretDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretDetail")
            .field("id", &self.id)
            .field("key", &self.key)
            .field("project_id", &self.project_id)
            .finish_non_exhaustive()
    }
}

impl SecretDetail {
    fn from_response(response: SecretResponse) -> Self {
        let SecretResponse {
            id,
            project_id,
            key,
            value,
            note,
            ..
        } = response;
        Self {
            id,
            key,
            value: SecretValue::new(value),
            note: SecretValue::new(note),
            project_id,
        }
    }
}

/// Fields written by a secret create or update.
///
/// A machine account must place every secret in a project, so the project is required.
#[derive(Clone)]
pub struct SecretDraft {
    pub key: String,
    pub value: SecretValue,
    pub note: SecretValue,
    pub project_id: Uuid,
}

impl fmt::Debug for SecretDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretDraft")
            .field("key", &self.key)
            .field("project_id", &self.project_id)
            .finish_non_exhaustive()
    }
}

/// Why a Secrets Manager operation failed, in fixed wording that never repeats a server body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// The token is not in Secrets Manager access-token format.
    AccessTokenInvalid,
    /// The identity server refused the token.
    TokenRejected,
    /// The token belongs to another organization.
    WrongOrganization { token: Uuid, configured: Uuid },
    /// The server answered 401 or 403.
    Unauthorized,
    /// The server answered 404.
    NotFound,
    /// The server answered with another error status.
    Status(u16),
    /// The SDK refused the input before sending it: a field is empty or too long.
    Invalid,
    /// The server refused to delete the item.
    DeleteRefused,
    /// No response arrived: connection, TLS, timeout, or I/O failure.
    Unreachable,
    /// The response arrived but could not be decoded or decrypted.
    Unusable,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessTokenInvalid => {
                f.write_str("the access token is not in Secrets Manager access-token format")
            }
            Self::TokenRejected => f.write_str("Secrets Manager refused the access token"),
            Self::WrongOrganization { token, configured } => write!(
                f,
                "the access token belongs to organization {token}, not the configured {configured}"
            ),
            Self::Unauthorized => f.write_str("the machine account is not allowed to do this"),
            Self::NotFound => f.write_str("not found, or not visible to this machine account"),
            Self::Status(status) => {
                write!(f, "Secrets Manager refused the request (HTTP {status})")
            }
            Self::Invalid => f.write_str("a field is empty, only spaces, or too long"),
            Self::DeleteRefused => f.write_str("Secrets Manager refused to delete the item"),
            Self::Unreachable => f.write_str("could not reach Secrets Manager"),
            Self::Unusable => f.write_str("the Secrets Manager response could not be read"),
        }
    }
}

impl Error for VaultError {}

impl VaultError {
    /// Classifies an SDK error by its derived `Debug` variant name.
    ///
    /// The published SDK keeps its error enum in a private module, so its variants cannot be
    /// matched by path. The rendered text is inspected here and never shown.
    fn classify(err: &impl fmt::Debug) -> Self {
        let rendered = format!("{err:?}");
        if let Some(rest) = rendered.strip_prefix("Api(ResponseContent { status: ") {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            return match digits.parse() {
                Ok(401 | 403) => Self::Unauthorized,
                Ok(404) => Self::NotFound,
                Ok(status) => Self::Status(status),
                Err(_) => Self::Unusable,
            };
        }
        if rendered.starts_with("Api(Reqwest") || rendered.starts_with("Api(Io(") {
            Self::Unreachable
        } else if rendered.starts_with("AccessTokenInvalid(") {
            Self::AccessTokenInvalid
        } else if rendered.starts_with("IdentityFail(") {
            Self::TokenRejected
        } else if rendered.starts_with("Validation(") {
            Self::Invalid
        } else {
            Self::Unusable
        }
    }
}

/// An authenticated Secrets Manager session for one organization.
///
/// The SDK keeps the session in memory only. Cloning shares the session.
#[derive(Clone)]
pub struct Vault {
    client: SecretsManagerClient,
    organization: Uuid,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("organization", &self.organization)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Logs in with the access token and confirms it belongs to the configured organization.
    ///
    /// # Errors
    ///
    /// Fails when the token is malformed or refused, the server is unreachable, or the token
    /// belongs to another organization.
    pub async fn connect(connection: Connection) -> Result<Self, VaultError> {
        let Connection {
            api_url,
            identity_url,
            organization,
            token,
            user_agent,
        } = connection;
        let client = SecretsManagerClient::new(Some(ClientSettings {
            identity_url,
            api_url,
            user_agent,
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
        match result {
            Ok(response) if response.authenticated => {}
            Ok(_) => return Err(VaultError::TokenRejected),
            Err(err) => {
                return Err(match VaultError::classify(&err) {
                    VaultError::Status(400..=499) | VaultError::Unauthorized => {
                        VaultError::TokenRejected
                    }
                    other => other,
                });
            }
        }
        let token_organization = client
            .get_access_token_organization()
            .map(Uuid::from)
            .ok_or(VaultError::Unusable)?;
        if token_organization != organization {
            return Err(VaultError::WrongOrganization {
                token: token_organization,
                configured: organization,
            });
        }
        Ok(Self {
            client,
            organization,
        })
    }

    /// Lists the projects the machine account can read, sorted by name.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn list_projects(&self) -> Result<Vec<Project>, VaultError> {
        let response = self
            .client
            .projects()
            .list(&ProjectsListRequest {
                organization_id: self.organization,
            })
            .await
            .map_err(|err| VaultError::classify(&err))?;
        let mut projects: Vec<Project> = response
            .data
            .into_iter()
            .filter(|project| project.organization_id == self.organization)
            .map(Project::from_response)
            .collect();
        projects.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(projects)
    }

    /// Lists secrets the machine account can read, in one project or the whole organization,
    /// sorted by key. Listings carry no values.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn list_secrets(
        &self,
        project: Option<Uuid>,
    ) -> Result<Vec<SecretListing>, VaultError> {
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
                        organization_id: self.organization,
                    })
                    .await
            }
        }
        .map_err(|err| VaultError::classify(&err))?;
        let mut listings: Vec<SecretListing> = response
            .data
            .into_iter()
            .filter(|identifier| identifier.organization_id == self.organization)
            .map(|identifier| SecretListing {
                id: identifier.id,
                key: identifier.key,
                project_ids: identifier.project_ids,
            })
            .collect();
        listings.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(listings)
    }

    /// Reads one secret, value and note included.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn get_secret(&self, id: Uuid) -> Result<SecretDetail, VaultError> {
        self.client
            .secrets()
            .get(&SecretGetRequest { id })
            .await
            .map(SecretDetail::from_response)
            .map_err(|err| VaultError::classify(&err))
    }

    /// Creates a secret and returns what the server stored.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn create_secret(&self, draft: &SecretDraft) -> Result<SecretDetail, VaultError> {
        let mut request = SecretCreateRequest {
            organization_id: self.organization,
            key: draft.key.clone(),
            value: draft.value.expose().to_owned(),
            note: draft.note.expose().to_owned(),
            project_ids: Some(vec![draft.project_id]),
        };
        let result = self.client.secrets().create(&request).await;
        request.value.zeroize();
        request.note.zeroize();
        result
            .map(SecretDetail::from_response)
            .map_err(|err| VaultError::classify(&err))
    }

    /// Replaces a secret's key, value, note, and project, and returns what the server stored.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn update_secret(
        &self,
        id: Uuid,
        draft: &SecretDraft,
    ) -> Result<SecretDetail, VaultError> {
        let mut request = SecretPutRequest {
            id,
            organization_id: self.organization,
            key: draft.key.clone(),
            value: draft.value.expose().to_owned(),
            note: draft.note.expose().to_owned(),
            project_ids: Some(vec![draft.project_id]),
        };
        let result = self.client.secrets().update(&request).await;
        request.value.zeroize();
        request.note.zeroize();
        result
            .map(SecretDetail::from_response)
            .map_err(|err| VaultError::classify(&err))
    }

    /// Deletes a secret. The server moves it to the organization's trash.
    ///
    /// # Errors
    ///
    /// Returns the classified failure, or [`VaultError::DeleteRefused`] when the server
    /// answered but refused this secret.
    pub async fn delete_secret(&self, id: Uuid) -> Result<(), VaultError> {
        let response = self
            .client
            .secrets()
            .delete(SecretsDeleteRequest { ids: vec![id] })
            .await
            .map_err(|err| VaultError::classify(&err))?;
        if response
            .data
            .iter()
            .any(|item| item.id == id && item.error.is_none())
        {
            Ok(())
        } else {
            Err(VaultError::DeleteRefused)
        }
    }

    /// Creates a project and returns what the server stored.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn create_project(&self, name: &str) -> Result<Project, VaultError> {
        self.client
            .projects()
            .create(&ProjectCreateRequest {
                organization_id: self.organization,
                name: name.to_owned(),
            })
            .await
            .map(Project::from_response)
            .map_err(|err| VaultError::classify(&err))
    }

    /// Renames a project and returns what the server stored.
    ///
    /// # Errors
    ///
    /// Returns the classified failure.
    pub async fn rename_project(&self, id: Uuid, name: &str) -> Result<Project, VaultError> {
        self.client
            .projects()
            .update(&ProjectPutRequest {
                id,
                organization_id: self.organization,
                name: name.to_owned(),
            })
            .await
            .map(Project::from_response)
            .map_err(|err| VaultError::classify(&err))
    }

    /// Deletes a project. The server deletes it outright; projects have no trash.
    ///
    /// # Errors
    ///
    /// Returns the classified failure, or [`VaultError::DeleteRefused`] when the server
    /// answered but refused this project.
    pub async fn delete_project(&self, id: Uuid) -> Result<(), VaultError> {
        let response = self
            .client
            .projects()
            .delete(ProjectsDeleteRequest { ids: vec![id] })
            .await
            .map_err(|err| VaultError::classify(&err))?;
        if response
            .data
            .iter()
            .any(|item| item.id == id && item.error.is_none())
        {
            Ok(())
        } else {
            Err(VaultError::DeleteRefused)
        }
    }
}

impl Project {
    fn from_response(response: ProjectResponse) -> Self {
        Self {
            id: response.id,
            name: response.name,
        }
    }
}

/// The web vault origin that belongs to a Secrets Manager API URL.
///
/// The two Bitwarden cloud regions map to their vault hosts. A self-hosted server serves
/// the vault at the API URL without its trailing `/api`.
pub fn web_vault_base(api_url: &str) -> String {
    let api_url = api_url.trim_end_matches('/');
    match api_url {
        "https://api.bitwarden.com" => "https://vault.bitwarden.com".to_owned(),
        "https://api.bitwarden.eu" => "https://vault.bitwarden.eu".to_owned(),
        other => other.strip_suffix("/api").unwrap_or(other).to_owned(),
    }
}
