//! Signs a machine token in for a direct profile and saves the profile, learning from the
//! server whatever the user left out.
//!
//! The token names neither its organization nor its region. The identity server's answer
//! names the organization, and a hosted token is tried at each region in turn.

use uuid::Uuid;

use crate::Error;
use crate::credential::{self, MachineToken};
use crate::lock::ConfigLock;
use crate::profile::{CredentialSource, Endpoints, Profile, Profiles, Region};
use crate::reference::ProfileName;
use crate::secrets::Session;

/// Name a profile gets when the user does not choose one.
pub const DEFAULT_PROFILE: &str = "default";

/// What the user gave for a direct profile. Unset parts are learned at sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    /// Profile to create or refresh.
    pub name: ProfileName,
    /// Organization the token must belong to, or `None` to accept the token's own.
    pub organization: Option<Uuid>,
    /// Deployment to sign in to, or `None` to reuse the profile's or try each hosted region.
    pub endpoints: Option<Endpoints>,
    /// Where the profile reads its token afterwards.
    pub credential: CredentialSource,
}

impl LoginRequest {
    /// Returns the existing profile this login would refresh.
    ///
    /// # Errors
    ///
    /// Refuses a remote profile of the same name, and an existing profile bound to another
    /// organization or endpoint than the request names.
    pub fn check(&self, profiles: &Profiles) -> Result<Option<Profile>, Error> {
        conflict(
            profiles,
            &self.name,
            self.organization,
            self.endpoints.as_ref(),
        )
    }

    /// Signs the token in and returns the session, whose profile is ready to save.
    ///
    /// Without endpoints it signs in where `previous` points, else at each hosted region in
    /// the order of [`Region::ALL`].
    ///
    /// # Errors
    ///
    /// Fails as [`Session::sign_in`] does.
    pub async fn sign_in(
        &self,
        previous: Option<&Profile>,
        token: &MachineToken,
        user_agent: &str,
    ) -> Result<Session, Error> {
        let candidates: Vec<Endpoints> = match (&self.endpoints, previous) {
            (Some(endpoints), _) => vec![endpoints.clone()],
            (None, Some(previous)) => vec![previous.endpoints.clone()],
            (None, None) => Region::ALL.into_iter().map(Endpoints::hosted).collect(),
        };
        Session::sign_in(
            &self.name,
            &candidates,
            self.organization,
            self.credential,
            token,
            user_agent,
        )
        .await
    }
}

/// Saves a signed-in profile and its token, replacing an earlier login of the same profile.
///
/// The configuration is read again under `lock`, so a profile created meanwhile is not
/// overwritten with another organization or endpoint. A profile that switches to
/// [`CredentialSource::Environment`] loses its stored token.
///
/// # Errors
///
/// Fails on a conflicting profile, or when the credential store or configuration cannot be
/// written.
pub fn save(lock: &ConfigLock, profile: &Profile, token: &MachineToken) -> Result<(), Error> {
    let mut profiles = Profiles::load()?;
    let previous = conflict(
        &profiles,
        &profile.name,
        Some(profile.organization),
        Some(&profile.endpoints),
    )?;
    if profile.credential == CredentialSource::OsStore {
        credential::store_token(&profile.name, token)?;
    } else if previous.is_some_and(|previous| previous.credential == CredentialSource::OsStore) {
        credential::delete_token(&profile.name)?;
    }
    profiles.insert(profile.clone());
    profiles.save(lock)
}

fn conflict(
    profiles: &Profiles,
    name: &ProfileName,
    organization: Option<Uuid>,
    endpoints: Option<&Endpoints>,
) -> Result<Option<Profile>, Error> {
    if profiles.remote(name).is_some() {
        return Err(Error::new(format!(
            "profile '{name}' is a remote profile; run `bas auth logout {name}` first"
        )));
    }
    let previous = profiles.find(name);
    if let Some(previous) = &previous
        && (organization.is_some_and(|organization| organization != previous.organization)
            || endpoints.is_some_and(|endpoints| *endpoints != previous.endpoints))
    {
        return Err(Error::new(format!(
            "profile '{name}' is bound to another organization or endpoint; run `bas auth \
             logout {name}` first"
        )));
    }
    Ok(previous)
}
