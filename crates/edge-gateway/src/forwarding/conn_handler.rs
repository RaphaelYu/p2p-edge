use futures::future::BoxFuture;
use libp2p::core::upgrade::{DeniedUpgrade, InboundUpgrade, UpgradeInfo};
use libp2p::swarm::handler::{
    ConnectionEvent, ConnectionHandler, ConnectionHandlerEvent, SubstreamProtocol,
};
use libp2p::{Stream, StreamProtocol};
use std::{
    collections::VecDeque,
    task::{Context, Poll},
};
use tokio::sync::OwnedSemaphorePermit;

use super::backend::unix::connect_unix;
use super::limiter::{ForwardLimitError, ForwardLimiter};
use super::router::Router;
use crate::forwarding::metrics::global_forward_metrics;
use crate::forwarding::types::{CloseReason, ErrorCode};

/// Connection handler skeleton for forwarding protocols; currently does nothing.
pub struct ForwardingConnHandler {
    protocols: Vec<StreamProtocol>,
    pending: VecDeque<ForwardingInEvent>,
    limiter: Option<ForwardLimiter>,
    router: std::sync::Arc<Router>,
    connect_timeout: std::time::Duration,
}

// Hard cap to avoid unbounded stream accumulation if the behaviour lags.
const MAX_PENDING_EVENTS: usize = 1024;

#[derive(Debug)]
pub enum ForwardingInEvent {
    Inbound {
        protocol: StreamProtocol,
        stream: Stream,
        permit: Option<OwnedSemaphorePermit>,
    },
}

#[derive(Debug)]
pub enum ForwardingOutEvent {}

impl ForwardingConnHandler {
    pub fn new(
        protocols: Vec<StreamProtocol>,
        limiter: Option<ForwardLimiter>,
        router: std::sync::Arc<Router>,
        connect_timeout: std::time::Duration,
    ) -> Self {
        Self {
            protocols,
            pending: VecDeque::new(),
            limiter,
            router,
            connect_timeout,
        }
    }
}

impl ConnectionHandler for ForwardingConnHandler {
    type FromBehaviour = ForwardingOutEvent;
    type ToBehaviour = ForwardingInEvent;
    type InboundProtocol = ForwardingUpgrade;
    type OutboundProtocol = DeniedUpgrade;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(
        &self,
    ) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(ForwardingUpgrade::new(self.protocols.clone()), ())
    }

    fn on_behaviour_event(&mut self, _event: Self::FromBehaviour) {}

    fn on_connection_event(
        &mut self,
        _event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        if let ConnectionEvent::FullyNegotiatedInbound(negotiated) = _event {
            let (protocol, stream) = negotiated.protocol;
            let proto_str = protocol.to_string();
            let router = self.router.clone();
            let connect_timeout = self.connect_timeout;
            if let Some(limiter) = &self.limiter {
                match limiter.try_acquire_now() {
                    Ok(permit) => {
                        match router.route(proto_str.as_str()) {
                            Ok(super::router::BackendSpec::Unix { path }) => {
                                let metrics = global_forward_metrics();
                                let connect_res = tokio::task::block_in_place(|| {
                                    let p = path.clone();
                                    tokio::runtime::Handle::current().block_on(
                                        async move {
                                            tokio::time::timeout(
                                                connect_timeout,
                                                connect_unix(p.clone(), connect_timeout),
                                            )
                                            .await
                                        },
                                    )
                                });

                                match connect_res {
                                    Ok(Ok(_stream)) => {
                                        // drop unix stream; just a connectivity check
                                        if self.pending.len() >= MAX_PENDING_EVENTS {
                                            metrics.on_error(
                                                proto_str.as_str(),
                                                ErrorCode::TooManyStreams.as_str(),
                                            );
                                            metrics.on_close(
                                                proto_str.as_str(),
                                                CloseReason::TooManyStreams.as_str(),
                                            );
                                        } else {
                                            self.pending.push_back(ForwardingInEvent::Inbound {
                                                protocol,
                                                stream,
                                                permit: Some(permit),
                                            });
                                        }
                                    }
                                    Ok(Err(_)) => {
                                        metrics.on_error(
                                            proto_str.as_str(),
                                            ErrorCode::BackendConnectFailed.as_str(),
                                        );
                                        metrics.on_close(
                                            proto_str.as_str(),
                                            CloseReason::BackendConnectFailed.as_str(),
                                        );
                                    }
                                    Err(_elapsed) => {
                                        metrics.on_error(
                                            proto_str.as_str(),
                                            ErrorCode::BackendConnectTimeout.as_str(),
                                        );
                                        metrics.on_close(
                                            proto_str.as_str(),
                                            CloseReason::BackendConnectFailed.as_str(),
                                        );
                                    }
                                }
                            }
                            Err(err) => {
                                let metrics = global_forward_metrics();
                                metrics.on_error(proto_str.as_str(), err.as_str());
                                metrics.on_close(
                                    proto_str.as_str(),
                                    CloseReason::NoRoute.as_str(),
                                );
                            }
                        }
                    }
                    Err(ForwardLimitError::TooManyStreams) => {
                        let metrics = global_forward_metrics();
                        metrics.on_error(proto_str.as_str(), ErrorCode::TooManyStreams.as_str());
                        metrics.on_close(
                            proto_str.as_str(),
                            CloseReason::TooManyStreams.as_str(),
                        );
                        return;
                    }
                }
            } else {
                if self.pending.len() >= MAX_PENDING_EVENTS {
                    let metrics = global_forward_metrics();
                    metrics.on_error(proto_str.as_str(), ErrorCode::TooManyStreams.as_str());
                    metrics.on_close(
                        proto_str.as_str(),
                        CloseReason::TooManyStreams.as_str(),
                    );
                } else {
                    self.pending.push_back(ForwardingInEvent::Inbound {
                        protocol,
                        stream,
                        permit: None,
                    });
                }
            }
        }
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::ToBehaviour>,
    > {
        if let Some(ev) = self.pending.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(ev));
        }
        Poll::Pending
    }
}

#[derive(Clone, Debug)]
pub struct ForwardingUpgrade {
    protocols: Vec<StreamProtocol>,
}

impl ForwardingUpgrade {
    pub fn new(protocols: Vec<StreamProtocol>) -> Self {
        Self { protocols }
    }
}

impl UpgradeInfo for ForwardingUpgrade {
    type Info = StreamProtocol;
    type InfoIter = Vec<StreamProtocol>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocols.clone()
    }
}

impl<C> InboundUpgrade<C> for ForwardingUpgrade
where
    C: Send + 'static,
{
    type Output = (StreamProtocol, C);
    type Error = std::io::Error;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, socket: C, info: Self::Info) -> Self::Future {
        Box::pin(async move {
            Ok((info, socket))
        })
    }
}
