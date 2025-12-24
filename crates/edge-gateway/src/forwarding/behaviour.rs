use libp2p::StreamProtocol;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use std::{collections::HashSet, task::Poll};
use tracing::debug;

use super::handler::Handler;
use crate::forwarding::conn_handler::{ForwardingConnHandler, ForwardingInEvent, ForwardingOutEvent};
use crate::forwarding::metrics::global_forward_metrics;
use crate::forwarding::limiter::ForwardLimiter;
use crate::forwarding::types::{CloseReason, ErrorCode, map_bridge_error_to_close_reason, map_io_error};
use crate::forwarding::bridge::bridge_with_idle;
use crate::forwarding::{backend::unix::connect_unix, router::BackendSpec};
use futures::AsyncWriteExt;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use std::time::Duration;

/// Forwarding behaviour stub wired with a custom connection handler.
pub struct ForwardingBehaviour {
    protocols: Vec<StreamProtocol>,
    limiter: Option<ForwardLimiter>,
    router: std::sync::Arc<crate::forwarding::router::Router>,
    connect_timeout: std::time::Duration,
}

pub struct ForwardingProtocols {
    protocols: HashSet<StreamProtocol>,
}

impl ForwardingProtocols {
    pub fn from_handler(handler: &Handler) -> anyhow::Result<Self> {
        let protocols = handler
            .stream_protocols()?
            .into_iter()
            .collect::<HashSet<_>>();
        Ok(Self { protocols })
    }

    pub fn protocols(&self) -> &HashSet<StreamProtocol> {
        &self.protocols
    }
}

impl ForwardingBehaviour {
    pub fn new(
        protocols: Vec<StreamProtocol>,
        limiter: Option<ForwardLimiter>,
        router: std::sync::Arc<crate::forwarding::router::Router>,
        connect_timeout: std::time::Duration,
    ) -> Self {
        Self {
            protocols,
            limiter,
            router,
            connect_timeout,
        }
    }
}

/// Return supported forwarding protocols in stable, deduped order.
pub fn forwarding_supported_protocols(handler: &Handler) -> anyhow::Result<Vec<StreamProtocol>> {
    let mut protos = handler.stream_protocols()?;
    protos.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
    protos.dedup_by(|a, b| a.to_string() == b.to_string());
    Ok(protos)
}

impl NetworkBehaviour for ForwardingBehaviour {
    type ConnectionHandler = ForwardingConnHandler;
    type ToSwarm = ForwardingOutEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: libp2p::PeerId,
        _local_addr: &libp2p::Multiaddr,
        _remote_addr: &libp2p::Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(ForwardingConnHandler::new(
            self.protocols.clone(),
            self.limiter.clone(),
            self.router.clone(),
            self.connect_timeout,
        ))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: libp2p::PeerId,
        _addr: &libp2p::Multiaddr,
        _role_override: libp2p::core::Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(ForwardingConnHandler::new(
            self.protocols.clone(),
            self.limiter.clone(),
            self.router.clone(),
            self.connect_timeout,
        ))
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _peer_id: libp2p::PeerId,
        _connection_id: ConnectionId,
        _event: THandlerOutEvent<Self>,
    ) {
        let ForwardingInEvent::Inbound {
            protocol,
            permit,
            mut stream,
        } = _event;
        let proto = protocol.to_string();
        let metrics = global_forward_metrics().clone();
        let router = self.router.clone();
        let connect_timeout = self.connect_timeout;
        let idle_timeout = Duration::from_secs(30);
        metrics.on_open(&proto);
        tokio::spawn(async move {
            let mut close_reason = CloseReason::NotImplemented;
            if let Some(spec) = router.route(proto.as_str()).ok() {
                match spec {
                    BackendSpec::Unix { path } => {
                        match connect_unix(path.clone(), connect_timeout).await {
                            Ok(unix_stream) => {
                                let stream_tokio = stream.compat();
                                match bridge_with_idle(stream_tokio, unix_stream, idle_timeout).await {
                                    Ok(stats) => {
                                        metrics.add_bytes(&proto, "in", stats.bytes_a_to_b);
                                        metrics.add_bytes(&proto, "out", stats.bytes_b_to_a);
                                        close_reason = stats.close_reason;
                                    }
                                    Err(err) => {
                                        let code = map_io_error(&err.io);
                                        metrics.on_error(&proto, code.as_str());
                                        close_reason = map_bridge_error_to_close_reason(Some(&err.io));
                                    }
                                }
                            }
                            Err(err) => {
                                let code = match err {
                                    crate::forwarding::backend::unix::BackendConnectError::BackendConnectFailed => ErrorCode::BackendConnectFailed,
                                    crate::forwarding::backend::unix::BackendConnectError::BackendConnectTimeout => ErrorCode::BackendConnectTimeout,
                                };
                                metrics.on_error(&proto, code.as_str());
                                close_reason = CloseReason::BackendConnectFailed;
                            }
                        }
                    }
                }
            } else {
                metrics.on_error(&proto, ErrorCode::NoRoute.as_str());
                close_reason = CloseReason::NoRoute;
                let _ = stream.close().await;
            }

            drop(permit);
            metrics.on_close(&proto, close_reason.as_str());
            debug!(target: "forwarding", protocol = %proto, ?close_reason, "inbound forwarding protocol handled");
        });
    }

    fn poll(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}
