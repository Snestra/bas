//! Request and reply bodies of the broker's socket API, shared by the broker and the `bas`
//! client commands. No body ever holds a secret value.

use serde::{Deserialize, Serialize};

pub use crate::policy::SecretFile as SecretEntry;

/// Socket the broker listens on unless told otherwise.
pub const DEFAULT_SOCKET: &str = "/run/bas/broker.sock";
/// ssh-agent socket the broker listens on unless told otherwise.
pub const DEFAULT_SSH_AGENT_SOCKET: &str = "/run/bas/ssh-agent.sock";

/// Reply to `GET /v1/status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    /// Version of the running broker.
    pub version: String,
    /// SHA-256 of the active policy text, in lowercase hex.
    pub policy_hash: String,
    /// IDs of requests that wait for an approval.
    pub pending: Vec<String>,
}

/// Body of `POST /v1/run`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RunRequest {
    /// Policy names the program will use through the proxy.
    pub names: Vec<String>,
    /// Program and arguments as the client says it will run them. Recorded, not checked.
    pub argv: Vec<String>,
    /// Working directory as the client states it. Recorded, not checked.
    pub cwd: String,
}

/// Reply to an allowed `POST /v1/run`. It never holds a value: the program reaches each
/// name's host through the proxy, which adds the credential.
#[derive(Debug, Serialize, Deserialize)]
pub struct RunReply {
    /// The names, each confirmed to be a proxy entry of the active policy.
    pub names: Vec<String>,
    /// Where the program sends its HTTPS requests.
    pub proxy: ProxyInfo,
}

/// Where a program sends HTTPS requests so the broker can add credentials.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyInfo {
    /// Proxy URL, such as `http://127.0.0.1:3128`.
    pub url: String,
    /// File with the system roots and the proxy's certificate authority.
    pub ca_bundle: String,
}

/// Body of `POST /v1/secrets`, sent by `bas add`. The value is typed on the approval page.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddSecret {
    /// Policy name of the new entry, also the key of the new Secrets Manager secret.
    pub name: String,
    /// The `[secret.NAME]` table without `ref`.
    pub entry: SecretEntry,
}

/// Body of `POST /v1/policy`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyProposal {
    /// The whole proposed policy text.
    pub toml: String,
}

/// Reply to `GET /v1/policy`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ActivePolicy {
    /// SHA-256 of the text, in lowercase hex.
    pub hash: String,
    /// The active policy text.
    pub toml: String,
}

/// Reply to a request that waits for a passkey approval (HTTP 202).
#[derive(Debug, Serialize, Deserialize)]
pub struct Accepted {
    /// The approval to open on the phone.
    pub approval: ApprovalLink,
    /// For a policy change, the unified diff from the active policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
}

/// One pending approval.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalLink {
    /// Approval ID.
    pub id: String,
    /// Page to open on the phone.
    pub url: String,
}

/// Reply to `GET /v1/approvals/ID`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalState {
    /// `pending`, `approved`, `denied`, `expired`, or `failed`.
    pub state: String,
    /// What the approved change produced, such as the new reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Why an approved change could not be applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Body of an error reply.
#[derive(Debug, Serialize, Deserialize)]
pub struct Refusal {
    /// `denied` when policy refuses the request, or a short reason otherwise.
    pub error: String,
    /// The policy name the refusal is about, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 1-based line of a policy error, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}
