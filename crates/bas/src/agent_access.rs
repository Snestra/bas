//! Agent Access delivery: a trusted listener answers paired remote devices, and remote
//! profiles resolve references through their pinned listener.
//!
//! The listener keeps the Secrets Manager endpoint, organization, and machine token. A
//! remote device holds only its identity key and session keys. A request is answered only
//! when the device is paired, the query is one explicit secret ID, the ID is in the
//! listener's scope, and either an active grant covers that device and secret or the
//! operator approves that exact request on the trusted terminal, in that order. Only then
//! is the secret retrieved. Pairing authenticates a device; it grants nothing.
//!
//! The SDK encrypts and sends a reply after the listener hands it over, so handing it over
//! is not delivery. The listener keeps at most one reply inside the SDK. It releases an
//! approved reply under the policy lock, after checking pairing, profile, and grant on
//! disk again, and keeps the lock until [`PinnedRelay`] has passed that reply to the relay.
//! A reply the SDK has not sent in time is refused for good, so a revocation that waited
//! for the lock can never be overtaken by a reply authorized before it.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::{self, Display};
use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ap_client::{
    ClientError, ConnectionInfo, ConnectionStore, ConnectionUpdate, CredentialData,
    CredentialQuery, CredentialRequestReply, DefaultRelayClient, FingerprintVerificationReply,
    IdentityFingerprint, MemoryConnectionStore, MemoryIdentityProvider, MultiDeviceTransport,
    RelayClient, RemoteClient, RemoteClientFingerprintReply, RemoteClientHandle,
    RemoteClientRequest, UserClient, UserClientHandle, UserClientNotification, UserClientRequest,
};
use ap_relay_client::IncomingMessage;
use ap_relay_protocol::{IdentityKeyPair, RendezvousCode};
use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep_until};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::approval::{self, Decision, Terminal};
use crate::grant::{self, Policy};
use crate::output::{self, Error};
use bas_core::credential::{self, Material, SecretText};
use bas_core::lock::ConfigLock;
use bas_core::profile::{PairedPeer, Profile, Profiles, RelayUrl, RemoteProfile};
use bas_core::reference::{ProfileName, SecretRef, parse_secret_id};
use bas_core::secrets::Session;

/// How long the listener waits for the operator to approve one credential request.
///
/// This is shorter than the requester's default 120-second timeout, but queueing and
/// network delay can still make the requester finish first. The SDK exposes no cancellation
/// message; an approval belongs only to its original reply channel.
const APPROVAL_WINDOW: Duration = Duration::from_secs(100);

/// How long either side waits for the pairing code or fingerprint during pairing.
///
/// Upstream discards a pending pairing after ten minutes.
const PAIRING_WINDOW: Duration = Duration::from_secs(10 * 60);

/// How long the remote operator has to confirm the fingerprint.
///
/// The upstream remote client abandons verification after 60 seconds.
const REMOTE_VERIFY_WINDOW: Duration = Duration::from_secs(55);

/// How often a listener retries the policy lock while another process holds it.
const LOCK_RETRY: Duration = Duration::from_millis(25);

/// What `bas listen` serves.
#[derive(Debug)]
pub struct Listener {
    /// Direct profile whose Secrets Manager access the listener uses.
    pub profile: Profile,
    pub relay: RelayUrl,
    /// The only secret IDs the listener may deliver.
    pub scope: BTreeSet<Uuid>,
    /// Accept one new device during this run.
    pub pairing: Option<Pairing>,
}

/// One pairing offered by the listener.
#[derive(Debug)]
pub struct Pairing {
    /// Label recorded for the paired device.
    pub peer_name: Option<ProfileName>,
}

/// Paired devices shared between the request handler and the connection store.
struct Pins {
    profile: Profile,
    peers: HashMap<IdentityFingerprint, Option<ProfileName>>,
    /// A device whose fingerprint the operator just approved, waiting to be saved.
    verified: Option<PairedPeer>,
    /// Paired devices whose session was replaced by a new handshake during this run.
    ///
    /// Agent Access re-handshakes a known fingerprint without a pre-shared key or
    /// fingerprint verification and switches to the new session before the store sees it,
    /// so a replaced session is not proof of the paired device. `bas pair` never
    /// re-handshakes; it reuses the paired session.
    replaced: HashSet<IdentityFingerprint>,
    /// Devices with a reply the SDK did not send in time. Their credential responses are
    /// refused and their requests denied until the listener restarts.
    fenced: HashSet<IdentityFingerprint>,
    /// The one credential reply the listener has handed to the SDK and not seen sent.
    in_flight: Option<InFlight>,
}

impl Pins {
    /// Tells `release` at once that the reply to `device` will not be sent, so it does not
    /// wait for the deadline.
    fn fail_flight(&mut self, device: IdentityFingerprint) {
        if self
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.device == device && !flight.sending)
            && let Some(flight) = self.in_flight.take()
        {
            let _ = flight.sent.send(false);
        }
    }
}

struct InFlight {
    device: IdentityFingerprint,
    /// [`PinnedRelay`] is passing the reply to the relay; it can no longer be withheld.
    sending: bool,
    /// Told whether the relay client accepted the outbound reply, not whether it arrived.
    sent: oneshot::Sender<bool>,
}

type SharedPins = Arc<Mutex<Pins>>;

fn lock(pins: &SharedPins) -> std::sync::MutexGuard<'_, Pins> {
    pins.lock().expect("pairing state lock poisoned")
}

/// The SDK chooses encryption keys after receiving an approved reply. Refuse outbound
/// messages after an unverified replacement, including replies already queued in the SDK,
/// and pass on a credential response only when it is the one reply the listener released.
struct PinnedRelay {
    inner: DefaultRelayClient,
    pins: SharedPins,
}

#[async_trait]
impl RelayClient for PinnedRelay {
    async fn connect(
        &mut self,
        identity: IdentityKeyPair,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ClientError> {
        self.inner.connect(identity).await
    }

    async fn request_rendezvous(&self) -> Result<(), ClientError> {
        self.inner.request_rendezvous().await
    }

    async fn request_identity(&self, code: RendezvousCode) -> Result<(), ClientError> {
        self.inner.request_identity(code).await
    }

    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), ClientError> {
        let released = needs_release(&data);
        {
            let mut pins = lock(&self.pins);
            if pins.replaced.contains(&fingerprint) {
                if released {
                    pins.fail_flight(fingerprint);
                }
                return Err(refused(
                    "refused delivery to an unverified replacement session",
                ));
            }
            if released {
                if pins.fenced.contains(&fingerprint) {
                    pins.fail_flight(fingerprint);
                    return Err(refused("refused a reply the listener withheld"));
                }
                match &mut pins.in_flight {
                    Some(flight) if flight.device == fingerprint && !flight.sending => {
                        flight.sending = true;
                    }
                    _ => return Err(refused("refused a reply the listener did not release")),
                }
            }
        }
        let result = self.inner.send_to(fingerprint, data).await;
        if released && let Some(flight) = lock(&self.pins).in_flight.take() {
            let _ = flight.sent.send(result.is_ok());
        }
        result
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
        self.inner.disconnect().await
    }
}

fn refused(reason: &str) -> ClientError {
    ClientError::ConnectionCache(reason.to_owned())
}

/// Outer, unencrypted type tag of an Agent Access protocol message.
#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "type")]
    kind: String,
}

/// Whether an outbound message may carry a credential. Only handshake messages, which
/// cannot, pass without a release; anything unrecognized is treated as a credential.
fn needs_release(data: &[u8]) -> bool {
    serde_json::from_slice::<Envelope>(data).map_or(true, |envelope| {
        !matches!(
            envelope.kind.as_str(),
            "handshake-init" | "handshake-response"
        )
    })
}

/// Listener connection store: sessions live in memory and in the OS credential store, and
/// only devices the operator verified can be saved.
struct ListenerStore {
    pins: SharedPins,
    connections: HashMap<IdentityFingerprint, ConnectionInfo>,
}

impl ListenerStore {
    fn persist(&self, connection: &ConnectionInfo) -> Result<(), Error> {
        let fingerprint = connection.fingerprint;
        let mut pins = lock(&self.pins);
        let profile = pins.profile.name.clone();
        let known = pins.peers.contains_key(&fingerprint);
        if known && self.connections.contains_key(&fingerprint) {
            pins.replaced.insert(fingerprint);
            return Err(Error::new(format!(
                "device {} started a new unverified session; its requests are denied until \
                 the listener restarts or the device is paired again",
                fingerprint.to_hex()
            )));
        }
        let verified = pins
            .verified
            .as_ref()
            .is_some_and(|peer| peer.fingerprint == fingerprint);
        if !known && !verified {
            return Err(Error::new("refused to save an unverified device"));
        }
        let transport = connection
            .transport_state
            .as_ref()
            .ok_or_else(|| Error::new("the paired session has no keys"))?;
        let material = Material::ListenerPeer(profile.clone(), fingerprint);
        material.store(&encode_transport(transport)?)?;
        if !known {
            // This runs inside the SDK event loop. Waiting here for a lock that this
            // listener holds while that loop sends a reply would stall both.
            let acquired = ConfigLock::try_acquire();
            let Ok(Some(policy_lock)) = acquired else {
                drop(material.delete());
                return Err(acquired.err().map_or_else(|| Error::new(
                    "another bas process is changing profiles or grants, or a reply is being \
                     released; pair again",
                ), Error::from));
            };
            let peer = pins.verified.take().ok_or_else(|| {
                Error::new("the verified device changed while it was being saved")
            })?;
            let recorded = Profiles::load()
                .map_err(Error::from)
                .and_then(|mut profiles| {
                    if profiles.get(&profile)? != pins.profile {
                        return Err(Error::new(
                            "the listener profile changed during pairing; restart the listener",
                        ));
                    }
                    profiles.insert_listener_peer(&profile, peer.clone());
                    Ok(profiles.save(&policy_lock)?)
                });
            if let Err(err) = recorded {
                drop(material.delete());
                return Err(err);
            }
            pins.peers.insert(fingerprint, peer.name);
        }
        Ok(())
    }
}

#[async_trait]
impl ConnectionStore for ListenerStore {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<ConnectionInfo> {
        self.connections.get(fingerprint).cloned()
    }

    async fn save(&mut self, connection: ConnectionInfo) -> Result<(), ClientError> {
        if let Err(err) = self.persist(&connection) {
            output::write_error(&format!("pairing not saved: {err}"));
            return Err(ClientError::ConnectionCache("not saved".to_owned()));
        }
        self.connections.insert(connection.fingerprint, connection);
        Ok(())
    }

    async fn update(&mut self, update: ConnectionUpdate) -> Result<(), ClientError> {
        if let Some(connection) = self.connections.get_mut(&update.fingerprint) {
            connection.last_connected_at = update.last_connected_at;
        }
        Ok(())
    }

    async fn list(&self) -> Vec<ConnectionInfo> {
        self.connections.values().cloned().collect()
    }
}

fn encode_transport(transport: &MultiDeviceTransport) -> Result<Zeroizing<Vec<u8>>, Error> {
    transport
        .save_state()
        .map(Zeroizing::new)
        .map_err(|_| Error::new("could not encode the session keys"))
}

fn load_transport(material: &Material) -> Result<Option<MultiDeviceTransport>, Error> {
    material
        .load()?
        .map(|bytes| {
            MultiDeviceTransport::restore_state(&bytes).map_err(|_| {
                Error::new(
                    "stored Agent Access session keys are corrupt; run `bas auth logout` for \
                     this profile and pair again",
                )
            })
        })
        .transpose()
}

fn store_identity(material: &Material, identity: &IdentityKeyPair) -> Result<(), Error> {
    Ok(material.store(&Zeroizing::new(identity.to_cose()))?)
}

fn load_identity(material: &Material) -> Result<Option<IdentityKeyPair>, Error> {
    material
        .load()?
        .map(|bytes| {
            IdentityKeyPair::from_cose(&bytes).map_err(|_| {
                Error::new(
                    "the stored Agent Access identity key is corrupt; run `bas auth logout` for \
                     this profile and pair again",
                )
            })
        })
        .transpose()
}

/// Why the listener refused a request. Shown on the listener only; the requester learns
/// just that the request was denied.
#[derive(Debug)]
enum Denial {
    UnpairedDevice,
    UnsupportedQuery(&'static str),
    MalformedId,
    OutsideScope(Uuid),
    NoTerminal,
    ApprovalBusy,
    Rejected,
    NoAnswer,
    Retrieval(Error),
    Expired,
    ReplacedSession,
    Fenced,
    /// The grant policy or profile configuration could not be read.
    Unreadable(Error),
    /// The listener profile was removed or rebound since the listener started.
    ProfileChanged,
    /// No active grant covers the request any more.
    GrantRevoked,
    /// Another process held the policy lock until the requester gave up.
    PolicyBusy,
}

impl Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnpairedDevice => f.write_str("the device is not paired with this listener"),
            Self::ReplacedSession => {
                f.write_str("the device's paired session was replaced by an unverified handshake")
            }
            Self::UnsupportedQuery(kind) => {
                write!(
                    f,
                    "{kind} queries are not supported; only explicit secret IDs"
                )
            }
            Self::MalformedId => f.write_str("the requested ID is not a hyphenated UUID"),
            Self::OutsideScope(id) => write!(f, "secret {id} is outside the listener scope"),
            Self::NoTerminal => f.write_str("no trusted terminal is available for approval"),
            Self::ApprovalBusy => f.write_str("another request is awaiting terminal approval"),
            Self::Rejected => f.write_str("the operator did not approve"),
            Self::NoAnswer => f.write_str("no approval arrived in time"),
            Self::Retrieval(err) => write!(f, "retrieval failed: {err}"),
            Self::Expired => f.write_str("the request expired before the reply was released"),
            Self::Fenced => f.write_str(
                "an earlier reply to the device was withheld; it is denied until the listener \
                 restarts",
            ),
            Self::Unreadable(err) => write!(f, "{err}"),
            Self::ProfileChanged => {
                f.write_str("the listener profile was removed or changed; restart the listener")
            }
            Self::GrantRevoked => {
                f.write_str("the grant was revoked before the reply was released")
            }
            Self::PolicyBusy => f.write_str(
                "the policy stayed locked by another bas process until the requester gave up",
            ),
        }
    }
}

/// Runs the listener until interrupted.
///
/// # Errors
///
/// Fails when stored pairing state is missing or corrupt, the relay is unreachable, or
/// pairing is requested without a terminal.
pub fn listen(listener: Listener) -> Result<ExitCode, Error> {
    crate::runtime()?.block_on(run_listener(listener))
}

async fn run_listener(listener: Listener) -> Result<ExitCode, Error> {
    let Listener {
        profile,
        relay,
        scope,
        mut pairing,
    } = listener;
    let mut terminal = Terminal::open();
    if pairing.is_some() && terminal.is_none() {
        return Err(Error::usage(
            "--pair needs an interactive terminal to show the code and verify the device",
        ));
    }
    let name = profile.name.clone();
    let startup_lock = grant::acquire_lock()?;
    let profiles = Profiles::load()?;
    if profiles.get(&name)? != profile {
        return Err(Error::new(
            "the listener profile changed during startup; restart the listener",
        ));
    }
    let peers = profiles.listener_peers(&name);
    let identity_material = Material::ListenerIdentity(name.clone());
    let identity = match load_identity(&identity_material)? {
        Some(identity) => identity,
        None if peers.is_empty() => {
            let identity = IdentityKeyPair::generate();
            store_identity(&identity_material, &identity)?;
            identity
        }
        None => {
            return Err(Error::new(format!(
                "listener '{name}' has paired devices but its identity key is missing from the \
                 OS credential store; run `bas auth logout {name}` and set it up again"
            )));
        }
    };
    let mut connections = HashMap::new();
    let mut paired = HashMap::new();
    for peer in peers {
        let transport = load_transport(&Material::ListenerPeer(name.clone(), peer.fingerprint))?
            .ok_or_else(|| {
                Error::new(format!(
                    "the session of paired device {} is missing from the OS credential store; \
                     run `bas auth logout {name}` and pair again",
                    peer.fingerprint.to_hex()
                ))
            })?;
        connections.insert(
            peer.fingerprint,
            ConnectionInfo {
                fingerprint: peer.fingerprint,
                name: peer.name.as_ref().map(ToString::to_string),
                cached_at: 0,
                last_connected_at: 0,
                transport_state: Some(transport),
            },
        );
        paired.insert(peer.fingerprint, peer.name);
    }
    let pins = Arc::new(Mutex::new(Pins {
        profile: profile.clone(),
        peers: paired,
        verified: None,
        replaced: HashSet::new(),
        fenced: HashSet::new(),
        in_flight: None,
    }));
    drop(startup_lock);
    let own = identity.identity().fingerprint();
    let UserClientHandle {
        client,
        mut notifications,
        mut requests,
    } = UserClient::connect(
        Box::new(MemoryIdentityProvider::from_keypair(identity)),
        Box::new(ListenerStore {
            pins: Arc::clone(&pins),
            connections,
        }),
        Box::new(PinnedRelay {
            inner: DefaultRelayClient::from_url(relay.to_string()),
            pins: Arc::clone(&pins),
        }),
        None,
        None,
    )
    .await
    .map_err(|_| Error::new(format!("could not connect to relay {relay}")))?;
    output::write_error(&format!(
        "listening for profile '{name}' as {} on {relay}; {} secret ID(s) in scope",
        own.to_hex(),
        scope.len()
    ));
    if terminal.is_none() {
        output::write_error("no trusted terminal: requests need an active exact grant");
    }
    if let (Some(offer), Some(terminal)) = (&pairing, terminal.as_mut()) {
        let code = client
            .get_rendezvous_token(offer.peer_name.as_ref().map(ToString::to_string))
            .await
            .map_err(|_| Error::new(format!("relay {relay} did not issue a pairing code")))?;
        terminal.say(&format!("Pairing code: {code}"));
        terminal.say(&format!(
            "On the remote machine run `bas pair <profile> --relay {relay}` and enter it. \
             Pairing lets the device ask; delivery needs approval or an exact grant here."
        ));
    }
    let mut session = None;
    let mut pending: Option<PendingApproval> = None;
    let mut sequence: u64 = 0;
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            request = requests.recv() => match request {
                Some(UserClientRequest::VerifyFingerprint { fingerprint, identity, reply }) => {
                    let approved = match (if pending.is_none() { pairing.take() } else { None }, terminal.as_mut()) {
                        (Some(offer), Some(terminal)) => {
                            let approved = tokio::select! {
                                approved = verify_device(terminal, &fingerprint, identity) => approved,
                                _ = &mut shutdown => {
                                    drop(reply);
                                    return Ok(ExitCode::SUCCESS);
                                }
                            };
                            if approved {
                                lock(&pins).verified = Some(PairedPeer {
                                    fingerprint: identity,
                                    name: offer.peer_name,
                                });
                            }
                            approved
                        }
                        _ => false,
                    };
                    output::write_error(&format!(
                        "pairing with device {}: {}",
                        identity.to_hex(),
                        if approved { "verified" } else { "rejected" }
                    ));
                    drop(reply.send(FingerprintVerificationReply { approved, name: None }));
                }
                Some(UserClientRequest::CredentialRequest { query, identity, reply }) => {
                    let deadline = Instant::now() + APPROVAL_WINDOW;
                    sequence += 1;
                    let label = device_label(&pins, identity);
                    let context = DeliveryContext { profile: &profile, scope: &scope, pins: &pins, sequence, deadline };
                    let prepared = prepare(&context, &query, identity);
                    let decision = match prepared {
                        Ok(Prepared::NeedsApproval { id }) if pending.is_none() && terminal.is_some() => {
                            let mut tty = terminal.take().expect("terminal is available");
                            let code = approval::approval_code();
                            let shown = tty.say("") && tty.say(&format!(
                                "Request {sequence}: {label} asks for secret {id} from profile '{name}'."
                            ));
                            if shown {
                                let prompt = format!("Type {code} to approve this one request, or press Enter to deny:");
                                pending = Some(PendingApproval {
                                    device: identity, id, sequence, deadline, reply,
                                    confirmation: Box::pin(async move {
                                        let decision = tty.confirm(&prompt, &code, deadline).await;
                                        (tty, decision)
                                    }),
                                });
                                continue;
                            }
                            terminal = Some(tty);
                            Err(Denial::NoTerminal)
                        }
                        Ok(Prepared::NeedsApproval { .. }) => Err(if pending.is_some() {
                            Denial::ApprovalBusy
                        } else {
                            Denial::NoTerminal
                        }),
                        Ok(Prepared::Granted { id, grant }) => {
                            tokio::select! {
                                decision = deliver(&context, &mut session, id, Some(grant)) => decision,
                                _ = &mut shutdown => return Ok(ExitCode::SUCCESS),
                            }
                        }
                        Err(denial) => Err(denial),
                    };
                    let approved = tokio::select! {
                        approved = release(&context, identity, decision, reply) => approved,
                        _ = &mut shutdown => return Ok(ExitCode::SUCCESS),
                    };
                    output::write_error(&format!(
                        "request {sequence} from {label}: {}",
                        if approved { "queued for relay" } else { "not delivered" }
                    ));
                }
                None => return Err(Error::new("the Agent Access connection ended")),
            },
            (tty, answer) = async {
                match pending.as_mut() {
                    Some(pending) => pending.confirmation.as_mut().await,
                    None => std::future::pending().await,
                }
            } => {
                terminal = Some(tty);
                let PendingApproval { device, id, sequence, deadline, reply, .. } = pending.take().expect("approval is pending");
                let context = DeliveryContext { profile: &profile, scope: &scope, pins: &pins, sequence, deadline };
                let decision = match answer {
                    Decision::Approved if Instant::now() >= deadline => Err(Denial::Expired),
                    Decision::Approved => tokio::select! {
                        decision = deliver(&context, &mut session, id, None) => decision,
                        _ = &mut shutdown => return Ok(ExitCode::SUCCESS),
                    },
                    Decision::Denied => Err(Denial::Rejected),
                    Decision::TimedOut => Err(Denial::NoAnswer),
                    Decision::Unavailable => Err(Denial::NoTerminal),
                };
                let approved = tokio::select! {
                    approved = release(&context, device, decision, reply) => approved,
                    _ = &mut shutdown => return Ok(ExitCode::SUCCESS),
                };
                let label = device_label(&pins, device);
                output::write_error(&format!(
                    "request {sequence} from {label}: {}",
                    if approved { "queued for relay" } else { "not delivered" }
                ));
            },
            Some(notification) = notifications.recv() => report(&notification),
            _ = &mut shutdown => return Ok(ExitCode::SUCCESS),
        }
    }
}

fn device_label(pins: &SharedPins, device: IdentityFingerprint) -> String {
    match lock(pins).peers.get(&device) {
        Some(Some(name)) => format!("device '{name}' ({})", device.to_hex()),
        Some(None) => format!("device {}", device.to_hex()),
        None => format!("unpaired device {}", device.to_hex()),
    }
}

async fn verify_device(
    terminal: &mut Terminal,
    fingerprint: &str,
    device: IdentityFingerprint,
) -> bool {
    terminal.say(&format!(
        "Device {} completed the pairing handshake.",
        device.to_hex()
    ));
    terminal.say(&format!(
        "Handshake fingerprint: {fingerprint}. The remote shows the same value unless someone \
         intercepted the pairing."
    ));
    terminal
        .confirm(
            "Type the fingerprint shown on the remote to pair, or press Enter to reject:",
            fingerprint,
            Instant::now() + PAIRING_WINDOW,
        )
        .await
        == Decision::Approved
}

/// Fixed facts about one pending request.
struct DeliveryContext<'a> {
    profile: &'a Profile,
    scope: &'a BTreeSet<Uuid>,
    pins: &'a SharedPins,
    sequence: u64,
    deadline: Instant,
}

struct PendingApproval {
    device: IdentityFingerprint,
    id: Uuid,
    sequence: u64,
    deadline: Instant,
    reply: oneshot::Sender<CredentialRequestReply>,
    confirmation: Pin<Box<dyn Future<Output = (Terminal, Decision)>>>,
}

enum Prepared {
    Granted { id: Uuid, grant: Uuid },
    NeedsApproval { id: Uuid },
}

fn prepare(
    context: &DeliveryContext<'_>,
    query: &CredentialQuery,
    device: IdentityFingerprint,
) -> Result<Prepared, Denial> {
    check_peer(context, device)?;
    let raw = match query {
        CredentialQuery::Id(raw) => raw,
        CredentialQuery::Domain(_) => return Err(Denial::UnsupportedQuery("domain")),
        CredentialQuery::Search(_) => return Err(Denial::UnsupportedQuery("search")),
    };
    let id = parse_secret_id(raw).map_err(|_| Denial::MalformedId)?;
    if !context.scope.contains(&id) {
        return Err(Denial::OutsideScope(id));
    }
    let policy = Policy::load().map_err(Denial::Unreadable)?;
    let grant = policy.authorizing(
        device,
        &context.profile.name,
        context.profile.organization,
        id,
    );
    Ok(match grant {
        Some(grant) => Prepared::Granted { id, grant },
        None => Prepared::NeedsApproval { id },
    })
}

async fn deliver(
    context: &DeliveryContext<'_>,
    session: &mut Option<Session>,
    id: Uuid,
    grant: Option<Uuid>,
) -> Result<Delivery, Denial> {
    let value = retrieve(context.profile, session, id)
        .await
        .map_err(Denial::Retrieval)?;
    if Instant::now() >= context.deadline {
        return Err(Denial::Expired);
    }
    Ok(Delivery { id, value, grant })
}

struct Delivery {
    id: Uuid,
    value: SecretText,
    grant: Option<Uuid>,
}

fn check_peer(context: &DeliveryContext<'_>, device: IdentityFingerprint) -> Result<(), Denial> {
    {
        let pins = lock(context.pins);
        if !pins.peers.contains_key(&device) {
            return Err(Denial::UnpairedDevice);
        }
        if pins.replaced.contains(&device) {
            return Err(Denial::ReplacedSession);
        }
        if pins.fenced.contains(&device) {
            return Err(Denial::Fenced);
        }
    }
    let profiles = Profiles::load().map_err(|err| Denial::Unreadable(err.into()))?;
    let current = profiles
        .get(&context.profile.name)
        .map_err(|_| Denial::ProfileChanged)?;
    if current != *context.profile {
        return Err(Denial::ProfileChanged);
    }
    if !profiles
        .listener_peers(&current.name)
        .iter()
        .any(|peer| peer.fingerprint == device)
    {
        return Err(Denial::UnpairedDevice);
    }
    Ok(())
}

async fn final_authorization(
    context: &DeliveryContext<'_>,
    device: IdentityFingerprint,
    delivery: &Delivery,
) -> Result<ConfigLock, Denial> {
    let policy_lock = loop {
        if Instant::now() >= context.deadline {
            return Err(Denial::PolicyBusy);
        }
        if let Some(guard) =
            ConfigLock::try_acquire().map_err(|err| Denial::Unreadable(err.into()))?
        {
            break guard;
        }
        sleep_until((Instant::now() + LOCK_RETRY).min(context.deadline)).await;
    };
    check_peer(context, device)?;
    let policy = Policy::load().map_err(Denial::Unreadable)?;
    if delivery.grant.is_some()
        && policy
            .authorizing(
                device,
                &context.profile.name,
                context.profile.organization,
                delivery.id,
            )
            .is_none()
    {
        return Err(Denial::GrantRevoked);
    }
    if Instant::now() >= context.deadline {
        return Err(Denial::Expired);
    }
    Ok(policy_lock)
}

async fn release(
    context: &DeliveryContext<'_>,
    device: IdentityFingerprint,
    decision: Result<Delivery, Denial>,
    reply: oneshot::Sender<CredentialRequestReply>,
) -> bool {
    let authorized = match decision {
        Ok(delivery) => final_authorization(context, device, &delivery)
            .await
            .map(|guard| (delivery, guard)),
        Err(denial) => Err(denial),
    };
    let (answer, policy_lock) = match authorized {
        Ok((delivery, guard)) => {
            let id = delivery.id.hyphenated().to_string();
            (
                CredentialRequestReply {
                    approved: true,
                    credential: Some(CredentialData {
                        username: None,
                        password: Some(delivery.value.into_zeroizing()),
                        totp: None,
                        uri: None,
                        notes: None,
                        credential_id: Some(id.clone()),
                        domain: None,
                    }),
                    credential_id: Some(id),
                },
                Some(guard),
            )
        }
        Err(denial) => {
            output::write_error(&format!("request {} denied: {denial}", context.sequence));
            (
                CredentialRequestReply {
                    approved: false,
                    credential: None,
                    credential_id: None,
                },
                None,
            )
        }
    };
    let approved = answer.approved;
    let (sent, mut received) = oneshot::channel();
    lock(context.pins).in_flight = Some(InFlight {
        device,
        sending: false,
        sent,
    });
    if reply.send(answer).is_err() {
        lock(context.pins).in_flight = None;
        return false;
    }
    let delivered = tokio::select! {
        result = &mut received => result.unwrap_or(false),
        _ = sleep_until(context.deadline) => {
            let sending = {
                let mut pins = lock(context.pins);
                let sending = pins.in_flight.as_ref().is_some_and(|flight| flight.sending);
                if !sending {
                    pins.fenced.insert(device);
                    pins.in_flight = None;
                }
                sending
            };
            // A send already in progress cannot be recalled. Keep revocation blocked
            // until that send returns; otherwise fence every later queued response.
            if sending { received.await.unwrap_or(false) } else { false }
        }
    };
    drop(policy_lock);
    approved && delivered
}

/// Retrieves one secret, opening the Secrets Manager session on first use.
async fn retrieve(
    profile: &Profile,
    session: &mut Option<Session>,
    id: Uuid,
) -> Result<SecretText, Error> {
    let open = match session {
        Some(open) => open,
        None => {
            let token = credential::load_token(profile)?;
            session.insert(Session::open(profile, &token, crate::USER_AGENT).await?)
        }
    };
    let result = open.get_many(&[id]).await;
    let mut secrets = match result {
        Ok(secrets) => secrets,
        Err(err) => {
            *session = None;
            return Err(err.into());
        }
    };
    match secrets.pop() {
        Some(secret) if secrets.is_empty() && secret.id() == id => Ok(secret.into_value()),
        _ => Err(Error::new(format!(
            "secret {id} is not accessible to profile '{}'",
            profile.name
        ))),
    }
}

fn report(notification: &UserClientNotification) {
    let message = match notification {
        UserClientNotification::ClientDisconnected {} => "relay connection lost; reconnecting",
        UserClientNotification::Reconnected {} => "reconnected to the relay",
        UserClientNotification::FingerprintRejected { .. } => "pairing rejected",
        UserClientNotification::Error { .. } => "Agent Access reported a protocol error",
        _ => return,
    };
    output::write_error(message);
}

/// Pairs this machine with a listener and saves the remote profile.
///
/// # Errors
///
/// Fails when the name is taken, no terminal is available, the code or fingerprint is not
/// confirmed, the relay is unreachable, or the key material cannot be stored.
pub fn pair(name: ProfileName, relay: RelayUrl) -> Result<ExitCode, Error> {
    crate::runtime()?.block_on(run_pair(name, relay))
}

async fn run_pair(name: ProfileName, relay: RelayUrl) -> Result<ExitCode, Error> {
    let taken = || {
        Error::new(format!(
            "profile '{name}' already exists; run `bas auth logout {name}` first"
        ))
    };
    if Profiles::load()?.is_configured(&name) {
        return Err(taken());
    }
    let mut terminal = Terminal::open().ok_or_else(|| {
        Error::usage("pairing needs an interactive terminal to enter the code and verify it")
    })?;
    let code = terminal
        .ask(
            "Pairing code shown by `bas listen --pair`:",
            Instant::now() + PAIRING_WINDOW,
        )
        .await
        .ok_or_else(|| Error::new("no pairing code was entered"))?;
    let code = parse_rendezvous_code(&code)?;
    let identity = IdentityKeyPair::generate();
    let RemoteClientHandle {
        client,
        notifications: _notifications,
        mut requests,
    } = RemoteClient::connect(
        Box::new(MemoryIdentityProvider::from_keypair(identity.clone())),
        Box::new(MemoryConnectionStore::new()),
        Box::new(DefaultRelayClient::from_url(relay.to_string())),
    )
    .await
    .map_err(|_| Error::new(format!("could not connect to relay {relay}")))?;
    let pairing = client.pair_with_handshake(code, true);
    tokio::pin!(pairing);
    let listener = loop {
        tokio::select! {
            result = &mut pairing => break result.map_err(|err| pairing_error(&err))?,
            Some(RemoteClientRequest::VerifyFingerprint { fingerprint, reply }) = requests.recv() => {
                terminal.say(&format!(
                    "Handshake fingerprint: {fingerprint}. The listener shows the same value \
                     unless someone intercepted the pairing."
                ));
                let decision = terminal
                    .confirm(
                        "Type the fingerprint shown on the listener to pair, or press Enter to reject:",
                        &fingerprint,
                        Instant::now() + REMOTE_VERIFY_WINDOW,
                    )
                    .await;
                drop(reply.send(RemoteClientFingerprintReply {
                    approved: decision == Decision::Approved,
                }));
            }
        }
    };
    let transport = client
        .list_connections()
        .await
        .ok()
        .and_then(|connections| {
            connections
                .into_iter()
                .find(|connection| connection.fingerprint == listener)
        })
        .and_then(|connection| connection.transport_state)
        .ok_or_else(|| Error::new("pairing finished without a session"))?;
    let identity_material = Material::RemoteIdentity(name.clone());
    let connection_material = Material::RemoteConnection(name.clone());
    let policy_lock = grant::acquire_lock()?;
    let mut profiles = Profiles::load()?;
    if profiles.is_configured(&name) {
        return Err(taken());
    }
    let saved = store_identity(&identity_material, &identity)
        .and_then(|()| Ok(connection_material.store(&encode_transport(&transport)?)?))
        .and_then(|()| {
            profiles.insert_remote(RemoteProfile {
                name: name.clone(),
                relay: relay.clone(),
                listener,
            });
            Ok(profiles.save(&policy_lock)?)
        });
    if let Err(err) = saved {
        drop(identity_material.delete());
        drop(connection_material.delete());
        return Err(err);
    }
    writeln!(
        io::stdout().lock(),
        "paired remote profile '{name}' with listener {} through {relay}; bas://{name}/<secret-id> \
         references resolve through that listener, and delivery needs approval or an exact grant there",
        listener.to_hex()
    )
    .map_err(|_| Error::new("could not write to standard output"))?;
    Ok(ExitCode::SUCCESS)
}

/// Accepts the upstream `XXX-XXX-XXX` code format in either letter case.
fn parse_rendezvous_code(raw: &str) -> Result<String, Error> {
    let code = raw.trim().to_ascii_uppercase();
    let groups: Vec<&str> = code.split('-').collect();
    let valid = groups.len() == 3
        && groups
            .iter()
            .all(|group| group.len() == 3 && group.bytes().all(|b| b.is_ascii_alphanumeric()));
    if valid {
        Ok(code)
    } else {
        Err(Error::usage("a pairing code looks like ABC-DEF-123"))
    }
}

fn pairing_error(err: &ClientError) -> Error {
    match err {
        ClientError::FingerprintRejected => {
            Error::new("pairing rejected: the fingerprint was not confirmed")
        }
        ClientError::Timeout(_) => Error::new("pairing timed out"),
        ClientError::RendezvousResolutionFailed(_) => {
            Error::new("the relay does not know that pairing code, or the listener is offline")
        }
        _ => Error::new("pairing failed"),
    }
}

/// Requests each ID from the remote profile's pinned listener, one request per ID.
///
/// Every result must carry exactly the requested ID and a value and nothing else. No
/// Secrets Manager credential is used, and a failure never falls back to one.
///
/// # Errors
///
/// Fails on the first ID that is denied, malformed, or cannot be delivered.
pub async fn fetch(remote: &RemoteProfile, ids: &[Uuid]) -> Result<Vec<(Uuid, SecretText)>, Error> {
    let name = &remote.name;
    let not_paired = || {
        Error::new(format!(
            "not started: remote profile '{name}' has no stored pairing; run `bas auth logout \
             {name}` and `bas pair {name}` again"
        ))
    };
    let identity =
        load_identity(&Material::RemoteIdentity(name.clone()))?.ok_or_else(not_paired)?;
    let transport =
        load_transport(&Material::RemoteConnection(name.clone()))?.ok_or_else(not_paired)?;
    let mut store = MemoryConnectionStore::new();
    store
        .save(ConnectionInfo {
            fingerprint: remote.listener,
            name: None,
            cached_at: 0,
            last_connected_at: 0,
            transport_state: Some(transport),
        })
        .await
        .map_err(|_| not_paired())?;
    let relay = &remote.relay;
    let RemoteClientHandle { client, .. } = RemoteClient::connect(
        Box::new(MemoryIdentityProvider::from_keypair(identity)),
        Box::new(store),
        Box::new(DefaultRelayClient::from_url(relay.to_string())),
    )
    .await
    .map_err(|_| Error::new(format!("not started: could not connect to relay {relay}")))?;
    client
        .load_cached_connection(remote.listener)
        .await
        .map_err(|_| not_paired())?;
    let mut values = Vec::with_capacity(ids.len());
    for &id in ids {
        let reference = SecretRef {
            profile: name.clone(),
            id,
        };
        let credential = client
            .request_credential(&CredentialQuery::Id(id.hyphenated().to_string()), None)
            .await
            .map_err(|err| request_error(&reference, relay, &err))?;
        values.push((id, accept(&reference, credential)?));
    }
    Ok(values)
}

fn accept(reference: &SecretRef, credential: CredentialData) -> Result<SecretText, Error> {
    let CredentialData {
        username,
        password,
        totp,
        uri,
        notes,
        credential_id,
        domain,
    } = credential;
    let matches = credential_id
        .as_deref()
        .and_then(|raw| parse_secret_id(raw).ok())
        == Some(reference.id);
    let extra = username.is_some()
        || totp.is_some()
        || uri.is_some()
        || notes.is_some()
        || domain.is_some();
    match password {
        Some(password) if matches && !extra => Ok(SecretText::from_zeroizing(password)),
        _ => Err(Error::new(format!(
            "not started: the listener's response for {reference} was malformed"
        ))),
    }
}

fn request_error(reference: &SecretRef, relay: &RelayUrl, err: &ClientError) -> Error {
    Error::new(match err {
        ClientError::CredentialRequestFailed(_) => {
            format!("not started: the listener denied {reference}")
        }
        ClientError::Timeout(_) => {
            format!("not started: the listener did not answer for {reference} in time")
        }
        ClientError::ChannelClosed
        | ClientError::ConnectionFailed(_)
        | ClientError::WebSocket(_)
        | ClientError::RelayAuthFailed(_) => {
            format!("not started: lost the connection to relay {relay}")
        }
        _ => format!("not started: the Agent Access request for {reference} failed"),
    })
}

/// Deletes the key material of a remote profile.
///
/// # Errors
///
/// Fails when the credential store is unusable.
pub fn forget_remote(name: &ProfileName) -> Result<(), Error> {
    Material::RemoteIdentity(name.clone()).delete()?;
    Ok(Material::RemoteConnection(name.clone()).delete()?)
}

/// Deletes the listener identity and paired-device sessions of a direct profile.
///
/// # Errors
///
/// Fails when the credential store is unusable.
pub fn forget_listener(name: &ProfileName, peers: &[PairedPeer]) -> Result<(), Error> {
    for peer in peers {
        Material::ListenerPeer(name.clone(), peer.fingerprint).delete()?;
    }
    Ok(Material::ListenerIdentity(name.clone()).delete()?)
}
