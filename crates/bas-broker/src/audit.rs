//! Journal entries for every credential the broker hands out, adds, or refuses.
//!
//! Each audit entry carries `BAS_AUDIT=1` and `EVENT`, plus `NAME`, `PEER_UID`, `PEER_PID`,
//! `HOST`, `APPROVAL_ID`, and `CLAIMED_ARGV` where they apply. journald adds `_SYSTEMD_UNIT` itself, so a
//! client cannot forge an entry for the broker's unit. No entry ever holds a value.

use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::Error;

/// Sends `tracing` events to the journal: this crate's at info level and above, every other
/// crate's at warn level and above, so libraries never log request details.
pub fn init() -> Result<(), Error> {
    let journald = tracing_journald::layer()
        .map_err(|err| Error::new(format!("could not open the system journal: {err}")))?
        .with_field_prefix(None)
        .with_syslog_identifier("bas-broker".to_owned());
    let filter = Targets::new()
        .with_target(env!("CARGO_CRATE_NAME"), Level::INFO)
        .with_default(Level::WARN);
    tracing_subscriber::registry()
        .with(journald)
        .with(filter)
        .try_init()
        .map_err(|_| Error::new("could not install the journal logger"))
}

/// The process on the other end of a socket connection, as the kernel reports it.
#[derive(Debug, Clone, Copy)]
pub struct Peer {
    /// User ID of the client.
    pub uid: u32,
    /// Process ID of the client, when the kernel knows it.
    pub pid: Option<i32>,
}

/// Records the names a `bas run` client will use through the proxy.
pub fn run(names: &str, peer: Peer, claimed_argv: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "run",
        name = names,
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        claimed_argv,
        "sent proxy settings for {names} to uid {}",
        peer.uid
    );
}

/// Records one signature the ssh-agent made.
pub fn sign(name: &str, peer: Peer, purpose: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "sign",
        name,
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        purpose,
        "signed with ssh key {name} for uid {} ({purpose})",
        peer.uid
    );
}

/// Records a signature the ssh-agent refused.
pub fn deny_sign(name: &str, peer: Peer, reason: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "deny",
        name,
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        "refused a signature with ssh key {name} for uid {}: {reason}",
        peer.uid
    );
}

/// Records a new request that waits for a passkey approval.
pub fn request(id: &str, kind: &str, name: &str, peer: Peer) {
    tracing::info!(
        bas_audit = 1,
        event = "request",
        approval_id = id,
        kind,
        name,
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        "uid {} asked for approval {id} ({kind} {name})",
        peer.uid
    );
}

/// Records a request approved with a verified passkey assertion.
pub fn approve(id: &str, kind: &str, name: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "approve",
        approval_id = id,
        kind,
        name,
        "approved {id} ({kind} {name}) with a passkey"
    );
}

/// Records a refused approval attempt or a denied request.
pub fn deny_approval(id: &str, kind: &str, name: &str, reason: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "deny",
        approval_id = id,
        kind,
        name,
        "approval {id} ({kind} {name}): {reason}"
    );
}

/// Records a change of the active policy.
pub fn policy(hash: &str, approval_id: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "policy",
        approval_id,
        policy_hash = hash,
        "the active policy is now {hash}"
    );
}

/// Records a token the broker minted.
pub fn mint(name: &str, scope: &str, expires: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "mint",
        name,
        scope,
        expires,
        "minted a {name} token for {scope}, valid until {expires}"
    );
}

/// Records a passkey enrollment.
pub fn enroll(label: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "enroll",
        name = label,
        "enrolled passkey {label}"
    );
}

/// Records a request the policy or the peer check refused.
pub fn deny_peer(peer: Peer, reason: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "deny",
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        "refused uid {}: {reason}",
        peer.uid
    );
}

/// Records a `bas run` request for a name that is not a proxy entry.
pub fn deny_name(name: &str, peer: Peer, claimed_argv: &str, reason: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "deny",
        name,
        peer_uid = peer.uid,
        peer_pid = peer.pid,
        claimed_argv,
        "refused {name} to uid {}: {reason}",
        peer.uid
    );
}

/// Records a header the proxy added to one request.
pub fn inject(name: &str, host: &str, method: &str, path: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "inject",
        name,
        host,
        method,
        path,
        "added {name} to {method} https://{host}{path}"
    );
}

/// Records a proxied request the policy refused.
pub fn deny_request(name: &str, host: &str, method: &str, path: &str, reason: &str) {
    tracing::info!(
        bas_audit = 1,
        event = "deny",
        name,
        host,
        method,
        path,
        "refused {method} https://{host}{path}: {reason}"
    );
}
