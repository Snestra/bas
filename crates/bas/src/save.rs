//! Create and value-only update, verified by reading the secret back.
//!
//! A write is attempted once. A refusal means nothing changed. A transport failure, server
//! error, or unreadable response after sending means the result is unknown, and `bas`
//! never resends. A server-accepted write whose read-back fails or differs is reported as
//! written but unverified.

use uuid::Uuid;

use crate::output::{Error, Operation, Outcome, Receipt};
use bas_core::credential::{self, SecretText};
use bas_core::profile::Profile;
use bas_core::reference::SecretRef;
use bas_core::secrets::{Failure, Secret, Session, WriteRequest};

/// SDK limit on key length, in characters.
const MAX_KEY_CHARS: usize = 500;
/// SDK limit on value length, in characters.
const MAX_VALUE_CHARS: usize = 25_000;

const READ_BACK_FAILED: &str = "the write was accepted but reading it back failed";
const READ_BACK_DIFFERS: &str = "the write was accepted but the read-back differs from it";
const RESULT_UNKNOWN: &str =
    "the service did not confirm the result; check the secret before trying again";

/// Validates a key for creation. The SDK trims keys, so surrounding whitespace is refused
/// rather than silently changed.
///
/// # Errors
///
/// Fails when the key is empty, too long, or has surrounding whitespace.
pub fn check_key(key: &str) -> Result<(), Error> {
    if key.is_empty() || key.trim() != key || key.chars().count() > MAX_KEY_CHARS {
        Err(Error::usage(format!(
            "a key must be 1 to {MAX_KEY_CHARS} characters without leading or trailing whitespace"
        )))
    } else {
        Ok(())
    }
}

fn check_value(value: &SecretText) -> Result<(), Error> {
    if value.expose().chars().count() > MAX_VALUE_CHARS {
        Err(Error::new(format!(
            "the secret input exceeds the {MAX_VALUE_CHARS}-character Secrets Manager limit"
        )))
    } else {
        Ok(())
    }
}

/// Creates a secret in a project and verifies it. The caller checks the key with
/// [`check_key`] before reading the value.
///
/// # Errors
///
/// Fails before writing when input, credentials, or authentication fail, and when the
/// service refuses the write. Accepted and ambiguous writes return a receipt instead.
pub fn create(
    profile: &Profile,
    key: &str,
    project_id: Uuid,
    value: &SecretText,
) -> Result<Receipt, Error> {
    check_value(value)?;
    let token = credential::load_token(profile)?;
    crate::runtime()?.block_on(async {
        let session = Session::open(profile, &token, crate::USER_AGENT).await?;
        let duplicate_keys: Vec<SecretRef> = session
            .list_identifiers(None)
            .await?
            .into_iter()
            .filter(|identifier| identifier.key() == key)
            .map(|identifier| SecretRef {
                profile: profile.name.clone(),
                id: identifier.id(),
            })
            .collect();
        let note = SecretText::new(String::new());
        let write = WriteRequest {
            key,
            value,
            note: &note,
            project_ids: &[project_id],
        };
        let mut receipt = Receipt {
            outcome: Outcome::Unknown,
            operation: Operation::Create,
            reference: None,
            key: key.to_owned(),
            project_id: Some(project_id),
            reason: Some(RESULT_UNKNOWN),
            duplicate_keys,
        };
        match session.create(&write).await {
            Ok(created) => {
                receipt.reference = Some(SecretRef {
                    profile: profile.name.clone(),
                    id: created.id(),
                });
                (receipt.outcome, receipt.reason) =
                    verify(&session, created.id(), &write, profile).await;
            }
            Err(failure) if failure.is_rejection() => {
                return Err(refused(failure, profile, "create the secret"));
            }
            Err(_) => {}
        }
        Ok(receipt)
    })
}

/// Replaces only the value of an existing secret, keeping its key, note, and project.
///
/// The update is a full replacement on the server, so a concurrent change to the other
/// fields between the read and the write can be overwritten.
///
/// # Errors
///
/// Fails before writing when the secret cannot be read or its metadata cannot be kept
/// exactly, and when the service refuses the write.
pub fn update(
    profile: &Profile,
    reference: &SecretRef,
    value: &SecretText,
) -> Result<Receipt, Error> {
    check_value(value)?;
    let token = credential::load_token(profile)?;
    crate::runtime()?.block_on(async {
        let session = Session::open(profile, &token, crate::USER_AGENT).await?;
        let current = session
            .get(reference.id)
            .await
            .map_err(|failure| failure.read_error(profile, "read the secret to update"))?;
        if current.key().trim() != current.key()
            || current.note().expose().trim() != current.note().expose()
        {
            return Err(Error::new(format!(
                "not written: {reference} has a key or note with surrounding whitespace, which \
                 the SDK would trim; update it in the Bitwarden web app instead"
            )));
        }
        // The value response exposes only the first project; identifiers retain every ID.
        let project_ids = session
            .list_identifiers(None)
            .await?
            .into_iter()
            .find(|identifier| identifier.id() == reference.id)
            .ok_or_else(|| {
                Error::new("not written: could not confirm existing project membership")
            })?
            .project_ids()
            .to_vec();
        let write = WriteRequest {
            key: current.key(),
            value,
            note: current.note(),
            project_ids: &project_ids,
        };
        let mut receipt = Receipt {
            outcome: Outcome::Unknown,
            operation: Operation::Update,
            reference: Some(reference.clone()),
            key: current.key().to_owned(),
            project_id: current.project_id(),
            reason: Some(RESULT_UNKNOWN),
            duplicate_keys: Vec::new(),
        };
        match session.update(reference.id, &write).await {
            Ok(_) => {
                (receipt.outcome, receipt.reason) =
                    verify(&session, reference.id, &write, profile).await;
            }
            Err(failure) if failure.is_rejection() => {
                return Err(refused(failure, profile, "update the secret"));
            }
            Err(_) => {}
        }
        Ok(receipt)
    })
}

/// Reads the secret back and compares every written field in memory.
async fn verify(
    session: &Session,
    id: Uuid,
    write: &WriteRequest<'_>,
    profile: &Profile,
) -> (Outcome, Option<&'static str>) {
    match session.get(id).await {
        Ok(stored) if matches_write(&stored, write, profile) => {}
        Ok(_) => return (Outcome::WrittenUnverified, Some(READ_BACK_DIFFERS)),
        Err(_) => return (Outcome::WrittenUnverified, Some(READ_BACK_FAILED)),
    }
    let Ok(identifiers) = session.list_identifiers(None).await else {
        return (Outcome::WrittenUnverified, Some(READ_BACK_FAILED));
    };
    let Some(stored) = identifiers
        .into_iter()
        .find(|identifier| identifier.id() == id)
    else {
        return (Outcome::WrittenUnverified, Some(READ_BACK_FAILED));
    };
    let mut stored_projects = stored.project_ids().to_vec();
    let mut expected_projects = write.project_ids.to_vec();
    stored_projects.sort_unstable();
    expected_projects.sort_unstable();
    if stored_projects == expected_projects {
        (Outcome::Verified, None)
    } else {
        (Outcome::WrittenUnverified, Some(READ_BACK_DIFFERS))
    }
}

fn matches_write(stored: &Secret, write: &WriteRequest<'_>, profile: &Profile) -> bool {
    stored.organization_id() == profile.organization
        && stored.key() == write.key
        && stored.value().expose() == write.value.expose()
        && stored.note().expose() == write.note.expose()
}

/// Describes a write the service or the SDK refused. Only [`Failure::is_rejection`] failures
/// reach here, so a failure without an HTTP status is the SDK's own validation.
fn refused(failure: Failure, profile: &Profile, operation: &str) -> Error {
    let reason = match failure {
        Failure::Status(_) => failure.read_error(profile, operation).to_string(),
        _ => format!("the SDK refused to {operation} before sending it"),
    };
    Error::new(format!("not written: {reason}"))
}
