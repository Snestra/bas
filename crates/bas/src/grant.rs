//! Standing grants: the trusted operator lets one paired device receive exact secrets from
//! one listener profile without a prompt, until the grant is revoked.
//!
//! Grants live in `grants.toml` beside the profile configuration, outside any repository,
//! with owner-only permissions. Policy and profile changes, and every credential reply a
//! listener releases, happen under one cross-process lock. A revocation that `bas grant
//! revoke` reports is therefore ordered entirely before or entirely after each delivery.
//! A missing file means no grants. An unreadable, malformed, or unprotected file
//! authorizes nothing and is never rewritten.

use std::collections::{BTreeSet, HashSet};

use bas_core::lock::ConfigLock;
use bas_core::profile::Profiles;
use bas_core::reference::ProfileName;
use bas_core::{IdentityFingerprint, Uuid};
use serde::{Deserialize, Serialize};

use crate::output::{self, Error};
use crate::private_toml::PrivateToml;

const POLICY_FILE: &str = "grants.toml";

/// Schema version of `grants.toml`. Any other version authorizes nothing.
const VERSION: u32 = 1;

/// Waits for the configuration lock, saying so on stderr when another process holds it.
///
/// # Errors
///
/// Fails when the lock file cannot be opened or locked.
pub fn acquire_lock() -> Result<ConfigLock, Error> {
    if let Some(lock) = ConfigLock::try_acquire()? {
        return Ok(lock);
    }
    output::write_error(
        "waiting for another bas process that is changing grants or profiles, or delivering a \
         secret",
    );
    Ok(ConfigLock::acquire()?)
}

/// Whether a grant still lets its device receive secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Active,
    Revoked,
}

/// One standing grant. Its schema is the same in `grants.toml` and in command output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: Uuid,
    pub state: State,
    /// Identity fingerprint of the paired device, as lowercase hex.
    #[serde(with = "device_hex")]
    pub device: IdentityFingerprint,
    /// Listener profile whose Secrets Manager access delivers the secrets.
    pub profile: ProfileName,
    /// Organization that profile was bound to when the grant was made.
    pub organization: Uuid,
    /// The only secret IDs the grant covers.
    pub secrets: BTreeSet<Uuid>,
}

mod device_hex {
    use ap_client::IdentityFingerprint;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S: Serializer>(
        device: &IdentityFingerprint,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&device.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<IdentityFingerprint, D::Error> {
        let raw = String::deserialize(deserializer)?;
        super::parse_device(&raw).map_err(|_| de::Error::custom("not a device fingerprint"))
    }
}

/// Parses a device identity fingerprint: 64 hexadecimal characters, in either letter case.
///
/// # Errors
///
/// Returns a usage error that does not repeat the input.
pub fn parse_device(raw: &str) -> Result<IdentityFingerprint, Error> {
    let valid = raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit());
    valid
        .then(|| IdentityFingerprint::from_hex(raw).ok())
        .flatten()
        .ok_or_else(|| {
            Error::usage(
                "a device fingerprint is 64 hexadecimal characters, as shown by `bas auth list`",
            )
        })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default)]
    grants: Vec<Grant>,
}

/// Whether a command changed the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Applied,
    /// The policy already said this; nothing was written.
    AlreadyInPlace,
}

/// All grants and the file they came from.
#[derive(Debug)]
pub struct Policy {
    file: PrivateToml,
    grants: Vec<Grant>,
}

impl Policy {
    /// Reads the current policy from disk.
    ///
    /// # Errors
    ///
    /// Fails when the file is unreadable, malformed, not a regular file, or accessible to
    /// other users. Callers then deny instead of assuming any grant or none.
    pub fn load() -> Result<Self, Error> {
        let file = PrivateToml::new(POLICY_FILE, "grant policy", "no grant applies")?;
        let grants = file
            .load(VERSION, |policy: &PolicyFile| policy.version)?
            .map_or_else(Vec::new, |policy| policy.grants);
        let mut ids = HashSet::new();
        let valid = grants
            .iter()
            .all(|grant| !grant.secrets.is_empty() && ids.insert(grant.id));
        if !valid {
            return Err(file.unusable("is malformed"));
        }
        Ok(Self { file, grants })
    }

    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// Returns the ID of an active grant covering exactly this device, profile,
    /// organization, and secret.
    pub fn authorizing(
        &self,
        device: IdentityFingerprint,
        profile: &ProfileName,
        organization: Uuid,
        secret: Uuid,
    ) -> Option<Uuid> {
        self.grants
            .iter()
            .find(|grant| {
                grant.state == State::Active
                    && grant.device == device
                    && grant.profile == *profile
                    && grant.organization == organization
                    && grant.secrets.contains(&secret)
            })
            .map(|grant| grant.id)
    }

    /// Replaces the policy file atomically and flushes it and its directory to disk before
    /// returning, so a reported change survives a crash.
    ///
    /// # Errors
    ///
    /// Fails if durable completion cannot be confirmed. The file may already have changed.
    fn save(&self, _lock: &ConfigLock) -> Result<(), Error> {
        self.file.save(&PolicyFile {
            version: VERSION,
            grants: self.grants.clone(),
        })
    }
}

/// Grants `device` the exact `secrets` of listener profile `name`.
///
/// The device must be paired with that listener now. An identical active grant is
/// returned instead of a duplicate.
///
/// # Errors
///
/// Fails when the profile is not a direct profile, the device is not paired with it, or the
/// policy cannot be read or written.
pub fn add(
    lock: &ConfigLock,
    name: &ProfileName,
    device: IdentityFingerprint,
    secrets: BTreeSet<Uuid>,
) -> Result<(Grant, Change), Error> {
    let profiles = Profiles::load()?;
    let profile = profiles.get(name)?;
    let paired = profiles
        .listener_peers(name)
        .iter()
        .any(|peer| peer.fingerprint == device);
    if !paired {
        return Err(Error::new(format!(
            "device {} is not paired with listener profile '{name}'; pair it with `bas listen \
             --pair` first",
            device.to_hex()
        )));
    }
    let mut policy = Policy::load()?;
    let wanted = Grant {
        id: Uuid::new_v4(),
        state: State::Active,
        device,
        profile: name.clone(),
        organization: profile.organization,
        secrets,
    };
    let existing = policy.grants.iter().find(|grant| {
        grant.state == State::Active
            && grant.device == wanted.device
            && grant.profile == wanted.profile
            && grant.organization == wanted.organization
            && grant.secrets == wanted.secrets
    });
    if let Some(existing) = existing {
        return Ok((existing.clone(), Change::AlreadyInPlace));
    }
    policy.grants.push(wanted.clone());
    policy.save(lock)?;
    Ok((wanted, Change::Applied))
}

/// Revokes one grant. Returns only after the revocation is on disk.
///
/// # Errors
///
/// Fails when no grant has this ID or the policy cannot be read or written.
pub fn revoke(lock: &ConfigLock, id: Uuid) -> Result<(Grant, Change), Error> {
    let mut policy = Policy::load()?;
    let grant = policy
        .grants
        .iter_mut()
        .find(|grant| grant.id == id)
        .ok_or_else(|| Error::new(format!("no grant has ID {id}; run `bas grant list`")))?;
    if grant.state == State::Revoked {
        return Ok((grant.clone(), Change::AlreadyInPlace));
    }
    grant.state = State::Revoked;
    let revoked = grant.clone();
    policy.save(lock)?;
    Ok((revoked, Change::Applied))
}

/// Revokes every active grant of a listener profile. Returns how many were revoked.
///
/// # Errors
///
/// Fails when the policy cannot be read or written.
pub fn revoke_profile(lock: &ConfigLock, name: &ProfileName) -> Result<usize, Error> {
    let mut policy = Policy::load()?;
    let mut revoked = 0;
    for grant in &mut policy.grants {
        if grant.profile == *name && grant.state == State::Active {
            grant.state = State::Revoked;
            revoked += 1;
        }
    }
    if revoked > 0 {
        policy.save(lock)?;
    }
    Ok(revoked)
}
