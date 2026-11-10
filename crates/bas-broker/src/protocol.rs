//! Request and reply bodies of the broker's socket API, shared by the broker and `bas run`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Socket the broker listens on unless told otherwise.
pub const DEFAULT_SOCKET: &str = "/run/bas/broker.sock";

/// Reply to `GET /v1/status`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    /// Version of the running broker.
    pub version: String,
    /// SHA-256 of the active policy file, in lowercase hex.
    pub policy_hash: String,
    /// IDs of requests that wait for an approval. Always empty until approvals exist.
    pub pending: Vec<String>,
}

/// Body of `POST /v1/run`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RunRequest {
    /// Policy names whose values the program needs.
    pub names: Vec<String>,
    /// Program and arguments as the client says it will run them. The broker records them
    /// in the audit entry and does not check them.
    pub argv: Vec<String>,
    /// Working directory as the client states it. Recorded, not checked.
    pub cwd: String,
}

/// Reply to an allowed `POST /v1/run`.
#[derive(Serialize, Deserialize)]
pub struct RunReply {
    /// Environment variables to set in the program, keyed by policy name.
    pub env: BTreeMap<String, String>,
    /// Names whose values the client must mask in the program's output.
    pub mask: Vec<String>,
    /// Proxy settings for names with proxy delivery. Absent until `bas run` uses the proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyInfo>,
}

impl std::fmt::Debug for RunReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunReply")
            .field("env", &self.env.keys().collect::<Vec<_>>())
            .field("mask", &self.mask)
            .field("proxy", &self.proxy)
            .finish()
    }
}

/// Where a program sends HTTPS requests so the broker can add credentials.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyInfo {
    /// Proxy URL, such as `http://127.0.0.1:3128`.
    pub url: String,
    /// File with the system roots and the proxy's certificate authority.
    pub ca_bundle: String,
}

/// Body of an error reply.
#[derive(Debug, Serialize, Deserialize)]
pub struct Refusal {
    /// `denied` when policy refuses the request, or a short reason otherwise.
    pub error: String,
    /// The policy name the refusal is about, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}
