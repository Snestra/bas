//! Starts the broker: loads settings and policy, signs in to Secrets Manager, opens the
//! socket API and the proxy, and tells systemd it is ready.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::extract::{FromRequestParts, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::serve::IncomingStream;
use axum::{Json, Router};
use bas_core::credential;
use bas_core::secrets::Session;
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};

use crate::audit::{self, Peer};
use crate::config::Config;
use crate::policy::{Delivery, Policy};
use crate::protocol::{Refusal, RunReply, RunRequest, Status};
use crate::{Error, proxy};

/// User agent the broker sends to Secrets Manager.
const USER_AGENT: &str = concat!("bas-broker/", env!("CARGO_PKG_VERSION"));

/// Where the broker reads its settings and writes its files. The defaults match the
/// `bas-broker.service` unit. Other paths are for development.
#[derive(Debug, Clone)]
pub struct Options {
    /// Unix socket for the API. The broker replaces a stale file there.
    pub socket: PathBuf,
    /// Machine settings, normally `/etc/bas/broker.toml`.
    pub config: PathBuf,
    /// Active policy, normally `/var/lib/bas/policy.toml`.
    pub policy: PathBuf,
    /// Private directory for the proxy's certificate authority, normally `/var/lib/bas`.
    pub state_dir: PathBuf,
    /// File the broker writes with the system roots and its certificate authority, for
    /// clients of the proxy, normally `/run/bas/ca-bundle.pem`.
    pub ca_bundle: PathBuf,
}

/// Shared by every request handler.
struct Broker {
    allow_uids: BTreeSet<u32>,
    policy: Arc<Policy>,
    session: Session,
}

/// Runs the broker until SIGTERM or SIGINT.
pub fn serve(options: &Options) -> Result<(), Error> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| Error::new(format!("could not start the async runtime: {err}")))?;
    runtime.block_on(run(options))
}

async fn run(options: &Options) -> Result<(), Error> {
    audit::init()?;
    let config = Config::load(&options.config)?;
    let policy = Arc::new(Policy::load(&options.policy, &config.profile.name)?);
    let token = credential::load_token(&config.profile)?;
    let session = Session::open(&config.profile, &token, USER_AGENT).await?;
    drop(token);

    let authority = proxy::Authority::load_or_create(&options.state_dir)?;
    authority.write_bundle(&options.ca_bundle)?;
    let proxy = proxy::start(
        config.proxy,
        authority,
        Arc::clone(&policy),
        session.clone(),
    )
    .await?;

    let listener = bind_socket(&options.socket)?;
    let broker = Arc::new(Broker {
        allow_uids: config.allow_uids,
        policy,
        session,
    });
    let app = Router::new()
        .route("/v1/status", get(status))
        .route("/v1/run", post(run_request))
        .with_state(broker)
        .into_make_service_with_connect_info::<PeerCred>();
    let api = axum::serve(listener, app).into_future();

    let mut term = signal(SignalKind::terminate())
        .map_err(|err| Error::new(format!("could not watch SIGTERM: {err}")))?;
    let mut int = signal(SignalKind::interrupt())
        .map_err(|err| Error::new(format!("could not watch SIGINT: {err}")))?;
    tracing::info!(
        socket = %options.socket.display(),
        proxy = %config.proxy,
        "bas broker ready"
    );
    // The broker works without systemd too, so a missing notify socket is not an error.
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);

    let result = tokio::select! {
        served = api => served.map_err(|err| Error::new(format!("the socket API stopped: {err}"))),
        served = proxy => served,
        _ = term.recv() => Ok(()),
        _ = int.recv() => Ok(()),
    };
    let _ = sd_notify::notify(&[sd_notify::NotifyState::Stopping]);
    let _ = std::fs::remove_file(&options.socket);
    result
}

/// Binds the API socket and opens it to every local user. The peer check, not the file
/// mode, decides who may use it.
fn bind_socket(path: &Path) -> Result<UnixListener, Error> {
    let failed =
        |err: std::io::Error| Error::new(format!("could not listen on {}: {err}", path.display()));
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(failed(err)),
    }
    let listener = UnixListener::bind(path).map_err(failed)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).map_err(failed)?;
    Ok(listener)
}

/// Peer credentials of a socket connection, read once when it is accepted.
#[derive(Debug, Clone, Copy)]
struct PeerCred(Option<Peer>);

impl Connected<IncomingStream<'_, UnixListener>> for PeerCred {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self(stream.io().peer_cred().ok().map(|cred| Peer {
            uid: cred.uid(),
            pid: cred.pid(),
        }))
    }
}

/// A peer whose uid is in `allow-uids`. Extracting it refuses every other caller with 403.
struct Allowed(Peer);

impl FromRequestParts<Arc<Broker>> for Allowed {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        broker: &Arc<Broker>,
    ) -> Result<Self, Self::Rejection> {
        let refuse = || refusal(StatusCode::FORBIDDEN, "peer not allowed", None);
        let Some(ConnectInfo(PeerCred(Some(peer)))) =
            parts.extensions.get::<ConnectInfo<PeerCred>>().copied()
        else {
            return Err(refuse());
        };
        if broker.allow_uids.contains(&peer.uid) {
            Ok(Self(peer))
        } else {
            audit::deny_peer(peer, "uid not in allow-uids");
            Err(refuse())
        }
    }
}

fn refusal(status: StatusCode, error: &str, name: Option<&str>) -> Response {
    (
        status,
        Json(Refusal {
            error: error.to_owned(),
            name: name.map(str::to_owned),
        }),
    )
        .into_response()
}

async fn status(State(broker): State<Arc<Broker>>, Allowed(_): Allowed) -> Json<Status> {
    Json(Status {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        policy_hash: broker.policy.hash().to_owned(),
        pending: Vec::new(),
    })
}

/// Hands out `env` secrets. Any name that is not in the policy, or whose delivery is not
/// `env`, refuses the whole request, so the program never starts with only some values.
async fn run_request(
    State(broker): State<Arc<Broker>>,
    Allowed(peer): Allowed,
    Json(request): Json<RunRequest>,
) -> Response {
    let claimed_argv = serde_json::to_string(&request.argv).unwrap_or_default();
    let mut wanted = Vec::new();
    for name in &request.names {
        match broker.policy.secret(name) {
            Some(secret) if matches!(secret.delivery, Delivery::Env) => wanted.push(secret),
            Some(_) => {
                audit::deny_name(name, peer, &claimed_argv, "delivery is not env");
                return refusal(StatusCode::FORBIDDEN, "denied", Some(name));
            }
            None => {
                audit::deny_name(name, peer, &claimed_argv, "not in policy");
                return refusal(StatusCode::FORBIDDEN, "denied", Some(name));
            }
        }
    }
    let mut ids: Vec<_> = wanted.iter().map(|secret| secret.reference.id).collect();
    ids.sort_unstable();
    ids.dedup();
    let values = match broker.session.get_many(&ids).await {
        Ok(found) => found
            .into_iter()
            .map(|secret| (secret.id(), secret.into_value()))
            .collect::<BTreeMap<_, _>>(),
        Err(err) => {
            tracing::warn!("could not read secrets for a run request: {err}");
            return refusal(StatusCode::BAD_GATEWAY, "secrets manager failed", None);
        }
    };
    let mut env = BTreeMap::new();
    for secret in &wanted {
        let Some(value) = values.get(&secret.reference.id) else {
            return refusal(
                StatusCode::BAD_GATEWAY,
                "secret not found",
                Some(&secret.name),
            );
        };
        env.insert(secret.name.clone(), value.expose().to_owned());
    }
    for secret in &wanted {
        audit::env(&secret.name, peer, &claimed_argv);
    }
    Json(RunReply {
        mask: env.keys().cloned().collect(),
        env,
        proxy: None,
    })
    .into_response()
}
