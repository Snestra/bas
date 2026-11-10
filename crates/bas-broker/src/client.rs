//! The client side of the socket API, used by `bas run --with`.

use std::path::{Path, PathBuf};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

use crate::Error;
use crate::protocol::{DEFAULT_SOCKET, Refusal, RunReply, RunRequest};

/// Environment variable that points `bas` at another broker socket, for development.
pub const SOCKET_VAR: &str = "BAS_BROKER_SOCKET";

/// The broker socket: `$BAS_BROKER_SOCKET`, or `/run/bas/broker.sock`.
pub fn socket_path() -> PathBuf {
    std::env::var_os(SOCKET_VAR).map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from)
}

/// Asks the broker for the values of `request.names`.
///
/// Fails when the broker cannot be reached, or refuses any name.
pub async fn run(socket: &Path, request: &RunRequest) -> Result<RunReply, Error> {
    let unreachable = |err: &dyn std::fmt::Display| {
        Error::new(format!(
            "could not reach the bas broker at {}: {err}",
            socket.display()
        ))
    };
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|err| unreachable(&err))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|err| unreachable(&err))?;
    tokio::spawn(connection);
    let body = serde_json::to_vec(request)
        .map_err(|_| Error::new("could not encode the broker request"))?;
    let http_request = Request::post("/v1/run")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| Error::new("could not build the broker request"))?;
    let response = sender
        .send_request(http_request)
        .await
        .map_err(|err| unreachable(&err))?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|err| unreachable(&err))?
        .to_bytes();
    if status == StatusCode::OK {
        return serde_json::from_slice(&body)
            .map_err(|_| Error::new("the bas broker sent a reply bas could not read"));
    }
    let refusal: Option<Refusal> = serde_json::from_slice(&body).ok();
    Err(match refusal {
        Some(Refusal {
            error,
            name: Some(name),
        }) if error == "denied" => Error::new(format!(
            "the bas broker denied {name}: it is not in the active policy, or its delivery is \
             not env"
        )),
        Some(Refusal { error, name }) => Error::new(format!(
            "the bas broker refused the request (HTTP {}): {error}{}",
            status.as_u16(),
            name.map(|name| format!(" ({name})")).unwrap_or_default()
        )),
        None => Error::new(format!(
            "the bas broker refused the request (HTTP {})",
            status.as_u16()
        )),
    })
}
