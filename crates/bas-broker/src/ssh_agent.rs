//! An ssh-agent on a unix socket that signs with the `[ssh.NAME]` keys of the active policy.
//!
//! Stock `ssh-agent` refuses peers with a different uid, and the broker runs as its own
//! user, so this agent checks each peer's uid against `allow-uids` instead. Clients can list
//! keys and ask for signatures. They cannot add, remove, or export keys.
//!
//! Each key signs only what its `use` allows. `sign-git` allows an SSHSIG signature in the
//! `git` namespace, which is what `git commit -S` asks for through `ssh-keygen -Y sign -n
//! git`. `auth` allows everything else an SSH client signs, which is a login. Every
//! signature and every refusal is written to the journal.

use std::path::Path;
use std::sync::{Arc, PoisonError, RwLock};

use bas_core::secrets::Session as SecretsSession;
use signature::Signer;
use ssh_agent_lib::agent::{self, ListeningSocket, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest, signature as flags};
use ssh_agent_lib::ssh_key::private::KeypairData;
use ssh_agent_lib::ssh_key::public::KeyData;
use ssh_agent_lib::ssh_key::{PrivateKey, Signature};
use tokio::net::{UnixListener, UnixStream};

use crate::Error;
use crate::audit::{self, Peer};
use crate::policy::Policy;

/// Start of the data an SSHSIG signature covers (PROTOCOL.sshsig).
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
/// The SSHSIG namespace git uses for commit and tag signatures.
const GIT_NAMESPACE: &[u8] = b"git";

/// One key the agent signs with.
pub struct Key {
    name: String,
    private: PrivateKey,
    public: KeyData,
    sign_git: bool,
    auth: bool,
}

/// The keys of the active policy, swapped as a whole when the policy changes.
#[derive(Default)]
pub struct Keys(RwLock<Arc<Vec<Key>>>);

impl Keys {
    /// Replaces the keys.
    pub fn set(&self, keys: Vec<Key>) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(keys);
    }

    fn get(&self) -> Arc<Vec<Key>> {
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Reads every `[ssh.NAME]` key of `policy` from Secrets Manager.
///
/// Fails when a key is missing, is not an OpenSSH private key, has a passphrase, or is not
/// ed25519 or rsa. The message names the key, never its contents.
pub async fn load(policy: &Policy, session: &SecretsSession) -> Result<Vec<Key>, Error> {
    let mut keys = Vec::new();
    for (name, entry) in policy.ssh() {
        let secret = session
            .get(entry.reference.id)
            .await
            .map_err(|failure| {
                Error::new(format!(
                    "ssh.{name}: {}",
                    failure.read_error(session.profile(), "read the key")
                ))
            })?
            .into_value();
        let private = PrivateKey::from_openssh(secret.expose().trim()).map_err(|_| {
            Error::new(format!(
                "ssh.{name}: the secret is not an OpenSSH private key"
            ))
        })?;
        if private.is_encrypted() {
            return Err(Error::new(format!(
                "ssh.{name}: the key has a passphrase; store it without one"
            )));
        }
        // ECDSA signing goes through crypto-bigint 0.5, which is not constant-time
        // (RUSTSEC-2026-0387), so the agent refuses ECDSA keys.
        if !matches!(
            private.key_data(),
            KeypairData::Ed25519(_) | KeypairData::Rsa(_)
        ) {
            return Err(Error::new(format!(
                "ssh.{name}: only ed25519 and rsa keys are supported"
            )));
        }
        let public = private.public_key().key_data().clone();
        keys.push(Key {
            name: name.clone(),
            private,
            public,
            sign_git: entry.sign_git,
            auth: entry.auth,
        });
    }
    Ok(keys)
}

/// Binds the agent socket, open to every local user, and returns the future that serves
/// it. The peer check, not the file mode, decides who may use it.
pub fn start(
    path: &Path,
    allow_uids: std::collections::BTreeSet<u32>,
    keys: Arc<Keys>,
) -> Result<impl std::future::Future<Output = Result<(), Error>>, Error> {
    let listener = crate::files::bind_socket(path, 0o666)?;
    let socket = CheckedListener {
        listener,
        allow_uids,
    };
    Ok(async move {
        agent::listen(socket, Agent { keys })
            .await
            .map_err(|err| Error::new(format!("the ssh-agent stopped: {err}")))
    })
}

/// A listener that drops connections from uids outside `allow-uids` before the agent
/// reads a byte from them.
#[derive(Debug)]
struct CheckedListener {
    listener: UnixListener,
    allow_uids: std::collections::BTreeSet<u32>,
}

#[ssh_agent_lib::async_trait]
impl ListeningSocket for CheckedListener {
    type Stream = UnixStream;

    async fn accept(&mut self) -> std::io::Result<UnixStream> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            match peer(&stream) {
                Some(peer) if self.allow_uids.contains(&peer.uid) => return Ok(stream),
                Some(peer) => audit::deny_peer(peer, "ssh-agent: uid not in allow-uids"),
                None => {}
            }
        }
    }
}

fn peer(stream: &UnixStream) -> Option<Peer> {
    stream.peer_cred().ok().map(|cred| Peer {
        uid: cred.uid(),
        pid: cred.pid(),
    })
}

struct Agent {
    keys: Arc<Keys>,
}

impl agent::Agent<CheckedListener> for Agent {
    fn new_session(&mut self, socket: &UnixStream) -> impl Session {
        AgentSession {
            keys: Arc::clone(&self.keys),
            peer: peer(socket),
        }
    }
}

struct AgentSession {
    keys: Arc<Keys>,
    peer: Option<Peer>,
}

#[ssh_agent_lib::async_trait]
impl Session for AgentSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(self
            .keys
            .get()
            .iter()
            .map(|key| Identity {
                credential: PublicCredential::Key(key.public.clone()),
                comment: format!("bas:{}", key.name),
            })
            .collect())
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let Some(peer) = self.peer else {
            return Err(AgentError::Failure);
        };
        let keys = self.keys.get();
        let Some(key) = keys
            .iter()
            .find(|key| &key.public == request.credential.key_data())
        else {
            return Err(AgentError::Failure);
        };
        let purpose = match sshsig_namespace(&request.data) {
            Some(namespace) if key.sign_git && namespace == GIT_NAMESPACE => "sign-git",
            Some(_) => {
                audit::deny_sign(
                    &key.name,
                    peer,
                    "an SSHSIG signature outside the git namespace, or a key without sign-git",
                );
                return Err(AgentError::Failure);
            }
            None if key.auth => "auth",
            None => {
                audit::deny_sign(&key.name, peer, "a login signature with a key without auth");
                return Err(AgentError::Failure);
            }
        };
        if matches!(key.private.key_data(), KeypairData::Rsa(_))
            && request.flags & flags::RSA_SHA2_512 == 0
        {
            audit::deny_sign(&key.name, peer, "an rsa signature other than rsa-sha2-512");
            return Err(AgentError::Failure);
        }
        let signature = key
            .private
            .try_sign(&request.data)
            .map_err(|_| AgentError::Failure)?;
        audit::sign(&key.name, peer, purpose);
        Ok(signature)
    }
}

/// The namespace of an SSHSIG signed-data blob, or `None` when `data` is not one.
fn sshsig_namespace(data: &[u8]) -> Option<&[u8]> {
    let rest = data.strip_prefix(SSHSIG_MAGIC)?;
    let (length, rest) = rest.split_first_chunk::<4>()?;
    let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
    rest.get(..length)
}
