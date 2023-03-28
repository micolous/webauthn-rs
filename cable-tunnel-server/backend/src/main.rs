use std::{
    borrow::Cow, collections::HashMap, convert::Infallible, error::Error as StdError,
    net::SocketAddr, sync::Arc, time::Duration,
};

use clap::Parser;

use futures::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    header::CONTENT_TYPE,
    http::HeaderValue,
    upgrade::Upgraded,
    Request, Response, StatusCode,
};

use tokio::{
    sync::mpsc::{channel, error::TrySendError, Receiver, Sender},
    time::error::Elapsed,
};

use tokio::{select, sync::RwLock};

use tokio_tungstenite::WebSocketStream;
use tungstenite::protocol::{frame::coding::CloseCode, CloseFrame, Message, Role, WebSocketConfig};

use cable_tunnel_server_common::*;

#[macro_use]
extern crate tracing;

type Rx = Receiver<Message>;
type Tx = Sender<Message>;
type PeerMap = RwLock<HashMap<TunnelId, Tunnel>>;
const CHANNEL_BUFFER_SIZE: usize = 6;

struct ServerState {
    peer_map: PeerMap,
    max_messages: u8,
    max_length: usize,
    origin: Option<String>,
    routing_id: RoutingId,
    tunnel_ttl: Duration,
}

#[derive(Debug, Parser)]
#[clap(about = "caBLE tunnel server backend")]
pub struct Flags {
    /// Bind address and port for the server.
    #[clap(long, default_value = "127.0.0.1:8081", value_name = "ADDR")]
    bind_address: String,

    /// If set, the routing ID to report on new tunnel requests. This is a 3
    /// byte, base-16 encoded value (eg: `123456`).
    ///
    /// Note: the routing ID provided in connect requests is never checked
    /// against this value.
    #[clap(long, default_value = "000000", value_parser = parse_hex::<RoutingId>, value_name = "ID")]
    routing_id: RoutingId,

    /// If set, the required Origin for requests sent to the WebSocket server.
    ///
    /// When not set, the tunnel server allows requests from any Origin.
    #[clap(long)]
    origin: Option<String>,

    /// Maximum amount of time a tunnel may be open for, in seconds.
    #[clap(long, default_value = "120", value_parser = parse_duration_secs, value_name = "SECONDS")]
    tunnel_ttl: Duration,

    /// Maximum number of messages that may be sent to a tunnel by each peer in
    /// a session.
    #[clap(long, default_value = "16", value_name = "MESSAGES")]
    max_messages: u8,

    /// Maximum message length which may be sent to a tunnel by a peer. If a
    /// peer sends a longer message, the connection will be closed.
    #[clap(long, default_value = "16384", value_name = "BYTES")]
    max_length: usize,

    /// Serving protocol to use.
    #[clap(subcommand)]
    protocol: ServerTransportProtocol,
}

impl From<&Flags> for ServerState {
    fn from(f: &Flags) -> Self {
        Self {
            peer_map: RwLock::new(HashMap::new()),
            max_messages: f.max_messages,
            max_length: f.max_length,
            origin: f.origin.to_owned(),
            routing_id: f.routing_id,
            tunnel_ttl: f.tunnel_ttl,
        }
    }
}

struct Tunnel {
    authenticator_rx: Rx,
    initiator_tx: Tx,
}

impl Tunnel {
    pub fn new(authenticator_rx: Rx, initiator_tx: Tx) -> Self {
        Self {
            authenticator_rx,
            initiator_tx,
        }
    }
}

const PEER_DISCONNECTED_FRAME: CloseFrame = CloseFrame {
    code: CloseCode::Normal,
    reason: Cow::Borrowed("Remote peer cleanly disconnected"),
};

#[derive(thiserror::Error, Debug)]
enum CableError {
    #[error("Remote peer sent erroneous frame")]
    RemotePeerErrorFrame,
    #[error("Remote peer abnormally disconnected")]
    RemotePeerAbnormallyDisconnected,
    #[error("Client sent too many messages")]
    TooManyMessages,
    #[error("Client sent unsupported message type")]
    UnsupportedMessageType,
    #[error("Tunnel TTL exceeded")]
    TtlExceeded,
    #[error("WebSocket error: {0}")]
    WebSocketError(tungstenite::Error),
}

impl From<tungstenite::Error> for CableError {
    fn from(e: tungstenite::Error) -> Self {
        Self::WebSocketError(e)
    }
}

impl CableError {
    fn close_reason(&self) -> Option<CloseFrame> {
        use CableError::*;
        let code = match self {
            RemotePeerErrorFrame => CloseCode::Policy,
            RemotePeerAbnormallyDisconnected => CloseCode::Away,
            TooManyMessages => CloseCode::Policy,
            UnsupportedMessageType => CloseCode::Unsupported,
            TtlExceeded => CloseCode::Policy,
            // Don't expose other error types
            _ => return None,
        };

        Some(CloseFrame {
            code,
            reason: self.to_string().into(),
        })
    }

    /// Create a message to notify the remote peer about a local error.
    fn peer_message(&self) -> Option<Message> {
        use CableError::*;
        let f = match self {
            RemotePeerAbnormallyDisconnected => return None,

            TtlExceeded => TtlExceeded.close_reason(),
            TooManyMessages => TooManyMessages.close_reason(),
            WebSocketError(_) => RemotePeerAbnormallyDisconnected.close_reason(),
            _ => RemotePeerErrorFrame.close_reason(),
        };

        Some(Message::Close(f))
    }
}

async fn connect_stream(
    state: Arc<ServerState>,
    mut ws_stream: WebSocketStream<Upgraded>,
    tx: Tx,
    mut rx: Rx,
    addr: SocketAddr,
) -> Result<(), CableError> {
    info!("{addr}: WebSocket connected");
    let mut message_count = 0u8;

    let r = match tokio::time::timeout(state.tunnel_ttl, async {
        loop {
            select! {
                r = rx.recv() => match r {
                    Some(msg) => {
                        // A message was received from the remote peer, send it onward.
                        match msg {
                            Message::Close(reason) => {
                                info!("{addr}: client closing message: {reason:?}");
                                ws_stream.close(reason).await?;
                                return Ok(());
                            }
                            msg => {
                                ws_stream.send(msg).await?;
                            }
                        }
                    },
                    None => {
                        // The peer disconnected
                        return Err(CableError::RemotePeerAbnormallyDisconnected);
                    }
                },

                r = ws_stream.next() => match r {
                    None => {
                        // Stream ended
                        error!("{addr}: client disconnected");
                        tx.try_send(Message::Close(Some(PEER_DISCONNECTED_FRAME.clone()))).ok();
                        return Ok(());
                    },
                    Some(Err(e)) => {
                        // Websocket protocol error
                        error!("{addr}: reading websocket: {e}");
                        return Err(e.into());
                    },
                    Some(Ok(msg)) => {
                        // A message was received from the local peer, validate it and
                        // send it onward
                        if msg.is_close() {
                            info!("{addr}: closing connection");
                            tx.try_send(Message::Close(Some(PEER_DISCONNECTED_FRAME.clone()))).ok();
                            ws_stream.close(None).await?;
                            return Ok(());
                        }

                        if msg.is_ping() || msg.is_pong() {
                            // Ignore PING/PONG messages, and don't count them towards
                            // quota. Tungstenite handles replies for us.
                            continue;
                        }

                        let msg = if let Message::Binary(msg) = msg {
                            msg
                        } else {
                            // Drop connection on other message types.
                            return Err(CableError::UnsupportedMessageType);
                        };

                        // Count the message towards the quota
                        message_count += 1;

                        if message_count > state.max_messages || message_count == u8::MAX {
                            return Err(CableError::TooManyMessages);
                        }

                        info!("{addr}: message {message_count}: {}", hex::encode(&msg));
                        match tx.try_send(Message::Binary(msg)) {
                            Err(TrySendError::Closed(_)) =>
                                return Err(CableError::RemotePeerAbnormallyDisconnected),
                            Err(TrySendError::Full(_)) =>
                                return Err(CableError::TooManyMessages),
                            Ok(_) => (),
                        }
                    }
                }
            }
        }
    })
    .await
    {
        Err(e) => {
            let _: Elapsed = e;
            // Timeout elapsed
            Err(CableError::TtlExceeded)
        }
        Ok(o) => o,
    };

    if let Err(e) = &r {
        // An error result indicates that no Close message has been sent
        // already, and we may need to notify the peer. Sending messages or
        // closing may fail at this stage, but we don't care.
        error!("{addr}: {e}");
        if let Some(msg) = e.peer_message() {
            tx.try_send(msg).ok();
        }
        ws_stream.close(e.close_reason()).await.ok();
    }

    info!("{addr}: Closing connection");
    r
}

async fn handle_request(
    state: Arc<ServerState>,
    addr: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    info!("{addr}: {} {}", req.method(), req.uri().path());
    trace!("Request data: {req:?}");
    let mut req = req.map(|_| ());

    let (mut res, mut path) = match Router::route(&req, &state.origin) {
        Router::Static(res) => return Ok(res),
        Router::Websocket(res, path) => (res, path),
        Router::Debug => {
            let peer_map_read = state.peer_map.read().await;
            let debug = format!(
                "server_state.strong_count = {}\npeer_map.capacity = {}\npeer_map.len = {}\n",
                Arc::strong_count(&state),
                peer_map_read.capacity(),
                peer_map_read.len(),
            );
            let mut res = Response::new(Bytes::from(debug).into());
            res.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            return Ok(res);
        }
    };

    let (tx, rx) = match path.method {
        CableMethod::New => {
            // Add the routing ID to the response header.
            path.routing_id.copy_from_slice(&state.routing_id);
            path.insert_routing_id_header(res.headers_mut());

            // Create both channels in the authenticator side, as the first one here
            let (authenticator_tx, authenticator_rx) = channel(CHANNEL_BUFFER_SIZE);
            let (initiator_tx, initiator_rx) = channel(CHANNEL_BUFFER_SIZE);
            let tunnel = Tunnel::new(authenticator_rx, initiator_tx);

            // Put it in our peer_map, if we can...
            {
                let mut lock = state.peer_map.write().await;
                if lock.contains_key(&path.tunnel_id) {
                    error!("{addr}: tunnel already exists: {path}");
                    return Ok(Response::builder()
                        .status(StatusCode::CONFLICT)
                        .body(Bytes::new().into())
                        .unwrap());
                }
                lock.insert(path.tunnel_id, tunnel);
            }

            (authenticator_tx, initiator_rx)
        }

        CableMethod::Connect => {
            if let Some(c) = state.peer_map.write().await.remove(&path.tunnel_id) {
                (c.initiator_tx, c.authenticator_rx)
            } else {
                error!("{addr}: no peer available for tunnel: {path}");
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Bytes::new().into())
                    .unwrap());
            }
        }
    };

    tokio::task::spawn(async move {
        let ss = state.clone();
        let config = Some(WebSocketConfig {
            max_message_size: Some(ss.max_length),
            max_frame_size: Some(ss.max_length),
            ..Default::default()
        });

        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                let ws_stream =
                    WebSocketStream::from_raw_socket(upgraded, Role::Server, config).await;
                connect_stream(ss, ws_stream, tx, rx, addr).await.ok();
            }
            Err(e) => {
                error!("{addr}: upgrade error: {e}");
            }
        }

        if path.method == CableMethod::New {
            // Remove any stale entry
            state.peer_map.write().await.remove(&path.tunnel_id);
        }
    });

    Ok(res)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    tracing_subscriber::fmt::init();
    let flags = Flags::parse();
    let server_state = ServerState::from(&flags);
    let bind_address: SocketAddr = flags.bind_address.parse().expect("invalid --bind-address");

    run_server(bind_address, flags.protocol, server_state, handle_request).await?;

    Ok(())
}
