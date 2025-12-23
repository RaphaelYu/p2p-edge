use crate::config::AppConfig;
use crate::registry::{NodeStatus, RegistryStore};
use async_trait::async_trait;
use futures::{StreamExt, io as fio, prelude::*};
use libp2p::{
    Multiaddr, PeerId, Swarm, Transport,
    core::upgrade,
    identity, noise,
    request_response::{
        Behaviour as RequestResponse, Config as RequestResponseConfig,
        Event as RequestResponseEvent, Message as RequestResponseMessage, ProtocolSupport,
    },
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use multiaddr::Protocol;
use std::{str::FromStr, time::Duration};
use tokio::time::timeout;
use tracing::{debug, warn};

pub async fn run_probe_loop(config: AppConfig, registry: RegistryStore) {
    let interval = Duration::from_secs(config.probe_interval_secs);
    loop {
        tokio::time::sleep(interval).await;
        if let Err(e) = probe_once(
            &registry,
            config.probe_fail_threshold,
            config.probe_recent_secs,
        )
        .await
        {
            warn!("probe iteration failed: {e}");
        }
    }
}

async fn probe_once(
    registry: &RegistryStore,
    _fail_threshold: u32,
    _recent_secs: u64,
) -> anyhow::Result<()> {
    let active = registry.list_by_status(Some(NodeStatus::Active))?;
    for node in active {
        let mut err_code = None;
        let ok = match ping_peer(&node.peer_id, &node.addrs).await {
            Ok(true) => true,
            Ok(false) => {
                err_code = Some("ping_failed".to_string());
                false
            }
            Err(e) => {
                err_code = Some(format!("{e}"));
                false
            }
        };
        if let Err(e) = registry.update_probe(&node.peer_id, ok, err_code.clone()) {
            warn!("failed to update probe for {}: {e}", node.peer_id);
        } else {
            debug!("probe {} ok={} err={:?}", node.peer_id, ok, err_code);
        }
    }
    // prune old results: update_probe already sets timestamps; manifest filtering uses probe_recent_secs
    Ok(())
}

#[derive(Clone, Default)]
struct PingCodec;

#[derive(Debug, Clone)]
struct PingProtocol;

#[derive(Debug, Clone)]
struct PingRequest;

#[derive(Debug, Clone)]
struct PingResponse {
    _message: String,
}

#[async_trait]
impl libp2p::request_response::Codec for PingCodec {
    type Protocol = PingProtocol;
    type Request = PingRequest;
    type Response = PingResponse;

    async fn read_request<T>(
        &mut self,
        _: &PingProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        fio::copy(io, &mut buf).await?;
        Ok(PingRequest)
    }

    async fn read_response<T>(
        &mut self,
        _: &PingProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        fio::copy(io, &mut buf).await?;
        let msg = String::from_utf8(buf).unwrap_or_default();
        Ok(PingResponse { _message: msg })
    }

    async fn write_request<T>(
        &mut self,
        _: &PingProtocol,
        io: &mut T,
        _req: PingRequest,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        fio::AsyncWriteExt::close(io).await
    }

    async fn write_response<T>(
        &mut self,
        _: &PingProtocol,
        io: &mut T,
        resp: PingResponse,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        fio::AsyncWriteExt::write_all(io, resp._message.as_bytes()).await?;
        fio::AsyncWriteExt::close(io).await
    }
}

impl AsRef<str> for PingProtocol {
    fn as_ref(&self) -> &str {
        "/p2p-edge/ping/1.0.0"
    }
}

#[derive(NetworkBehaviour)]
struct ProbeBehaviour {
    ping: RequestResponse<PingCodec>,
}

async fn ping_peer(peer_id: &str, addrs: &[String]) -> anyhow::Result<bool> {
    let target = PeerId::from_str(peer_id)?;
    let local_key = identity::Keypair::generate_ed25519();
    let noise_keys = noise::Config::new(&local_key)?;

    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise_keys)
        .multiplex(yamux::Config::default())
        .boxed();

    let rr_cfg = RequestResponseConfig::default();
    let behaviour = ProbeBehaviour {
        ping: RequestResponse::with_codec(
            PingCodec::default(),
            std::iter::once((PingProtocol, ProtocolSupport::Full)),
            rr_cfg,
        ),
    };

    let mut swarm = Swarm::new(
        transport,
        behaviour,
        local_key.public().to_peer_id(),
        libp2p::swarm::Config::with_tokio_executor(),
    );

    for addr in addrs {
        if let Ok(mut ma) = addr.parse::<Multiaddr>() {
            ma.push(Protocol::P2p(target.into()));
            let _ = swarm.dial(ma);
        }
    }

    swarm
        .behaviour_mut()
        .ping
        .send_request(&target, PingRequest);

    let probe_fut = async {
        loop {
            match swarm.next().await {
                Some(SwarmEvent::Behaviour(ProbeBehaviourEvent::Ping(
                    RequestResponseEvent::Message { message, .. },
                ))) => {
                    if let RequestResponseMessage::Response { .. } = message {
                        return Ok(true);
                    }
                }
                Some(SwarmEvent::Behaviour(ProbeBehaviourEvent::Ping(
                    RequestResponseEvent::OutboundFailure { .. },
                ))) => {
                    return Ok(false);
                }
                Some(SwarmEvent::Behaviour(ProbeBehaviourEvent::Ping(
                    RequestResponseEvent::InboundFailure { .. },
                ))) => {
                    return Ok(false);
                }
                Some(SwarmEvent::Behaviour(ProbeBehaviourEvent::Ping(
                    RequestResponseEvent::ResponseSent { .. },
                ))) => {}
                Some(_) => {}
                None => return Ok(false),
            }
        }
    };

    match timeout(Duration::from_secs(5), probe_fut).await {
        Ok(v) => v,
        Err(_) => Ok(false),
    }
}
