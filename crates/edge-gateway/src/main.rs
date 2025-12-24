use anyhow::{Context, Result};
use axum::{Router, body::Body, routing::get};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use libp2p::{
    Multiaddr, PeerId, Swarm, Transport,
    core::upgrade,
    futures::StreamExt,
    identity, noise,
    request_response::{
        Behaviour as RequestResponse, Config as RequestResponseConfig,
        Event as RequestResponseEvent, Message as RequestResponseMessage, ProtocolSupport,
    },
    swarm::{Config as SwarmConfig, NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};
use rand::{Rng, seq::SliceRandom};
use reqwest::Client;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::signal;
use tracing::{info, warn};

use forwarding::config::{ForwardRule, load_forward_rules};
mod forwarding;
mod manifest;
mod proto;

// Forwarding interface boundary (future gateway mode):
// - Route strictly by protocol ID; never parse or persist payload bytes.
// - Do not emit business audit events; transport-level only.
// - Keep this boundary intact when adding forwarding to avoid scope creep.

#[derive(Debug, Deserialize, Clone)]
struct GatewayConfig {
    listen_multiaddrs: Vec<String>,
    bootstrap_api_url: String,
    bootstrap_manifest_urls: Vec<String>,
    operator_token: String,
    admin_token: Option<String>,
    mode: String,
    secret_key_b64: String,
    secret_key_path: Option<String>,
    manifest_pubkey_b64: Option<String>,
    manifest_pubkeys_b64: Option<Vec<String>>,
    manifest_trusted_keys: Option<HashMap<String, String>>,
    manifest_poll_secs: Option<u64>,
    target_peers: Option<usize>,
    min_peers: Option<usize>,
    max_peers: Option<usize>,
    redial_secs: Option<u64>,
    dial_batch_size: Option<usize>,
    backoff_base_secs: Option<u64>,
    backoff_max_secs: Option<u64>,
    metrics_bind: Option<String>,
    manifest_grace_secs: Option<u64>,
    forward_rules: Option<Vec<ForwardRule>>,
    forward_max_streams: Option<usize>,
    forward_wait_timeout_secs: Option<u64>,
    forward_connect_timeout_secs: Option<u64>,
}

#[derive(NetworkBehaviour)]
struct GatewayBehaviour {
    ping: RequestResponse<proto::PingCodec>,
    forward: forwarding::behaviour::ForwardingBehaviour,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .without_time()
        .init();

    let cfg = load_config()?;
    let key_b64 = load_secret_key(&cfg)?;
    let (signing_key, peer_id, verifying_key_b64) = build_keys(&key_b64)?;
    info!("edge-gateway peer_id={peer_id}");
    let manifest_keys = load_manifest_keys(
        cfg.manifest_trusted_keys.as_ref(),
        cfg.manifest_pubkeys_b64.as_ref(),
        cfg.manifest_pubkey_b64.as_deref(),
    )?;
    let metrics = Metrics::new()?;
    let manifest_cache = Arc::new(Mutex::new(ManifestCache::default()));
    let forward_handler =
        forwarding::handler::Handler::new(cfg.forward_rules.clone().unwrap_or_default());

    // metrics server
    if let Some(bind) = cfg.metrics_bind.as_deref() {
        let addr: SocketAddr = bind.parse().context("parse metrics bind addr")?;
        let metrics_clone = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_metrics(metrics_clone, addr).await {
                warn!("metrics server error: {e}");
            }
        });
    }

    // Register with bootstrap directory
    if let Err(e) = register_with_directory(&cfg, &signing_key, &verifying_key_b64, &peer_id).await
    {
        warn!("registration failed: {e}");
    }

    let mut swarm = build_swarm(signing_key, &forward_handler, &cfg)?;
    let mut connected: HashSet<PeerId> = HashSet::new();
    let mut last_dial: HashMap<PeerId, Instant> = HashMap::new();
    // jitter start to avoid herd dialing
    let start_jitter = cfg.manifest_poll_secs.unwrap_or(30);
    if start_jitter > 0 {
        let delay = rand::thread_rng().gen_range(0..start_jitter);
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }

    // initial dial
    if let Err(e) = dial_manifest_peers(
        &cfg,
        &manifest_keys,
        &mut swarm,
        &peer_id,
        &mut connected,
        &mut last_dial,
        &mut std::collections::HashMap::new(),
        &metrics,
        &manifest_cache,
    )
    .await
    {
        warn!("dial manifest peers failed: {e}");
    }

    let mut manifest_interval =
        tokio::time::interval(Duration::from_secs(cfg.manifest_poll_secs.unwrap_or(30)));

    for addr in &cfg.listen_multiaddrs {
        let ma: Multiaddr = addr.parse()?;
        swarm
            .listen_on(ma.clone())
            .with_context(|| format!("listen_on {ma}"))?;
    }

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("shutdown requested");
                break;
            }
            event = swarm.select_next_some() => {
                handle_event(&mut swarm, event, &mut connected, &mut last_dial, &metrics);
            }
            _ = manifest_interval.tick() => {
                if let Err(e) = dial_manifest_peers(&cfg, &manifest_keys, &mut swarm, &peer_id, &mut connected, &mut last_dial, &mut std::collections::HashMap::new(), &metrics, &manifest_cache).await {
                    warn!("manifest poll failed: {e}");
                }
            }
        }
    }

    Ok(())
}

fn handle_event(
    swarm: &mut Swarm<GatewayBehaviour>,
    event: SwarmEvent<GatewayBehaviourEvent>,
    connected: &mut HashSet<PeerId>,
    last_dial: &mut HashMap<PeerId, Instant>,
    metrics: &Metrics,
) {
    match event {
        SwarmEvent::Behaviour(GatewayBehaviourEvent::Ping(RequestResponseEvent::Message {
            peer,
            message,
        })) => match message {
            RequestResponseMessage::Request {
                request: _,
                channel,
                ..
            } => {
                info!("ping request from {peer}");
                let resp = proto::PingResponse {
                    message: format!("pong {}", chrono::Utc::now().to_rfc3339()),
                };
                if let Err(e) = swarm.behaviour_mut().ping.send_response(channel, resp) {
                    warn!("respond ping error: {:?}", e);
                }
            }
            RequestResponseMessage::Response {
                request_id,
                response,
            } => {
                info!(
                    "ping response to {request_id:?} from {peer}: {:?}",
                    response
                );
                metrics.ping_ok.inc();
            }
        },
        SwarmEvent::Behaviour(GatewayBehaviourEvent::Ping(
            RequestResponseEvent::OutboundFailure { peer, error, .. },
        )) => {
            warn!("ping outbound failure to {peer}: {error}");
            metrics.ping_fail.inc();
        }
        SwarmEvent::Behaviour(GatewayBehaviourEvent::Ping(
            RequestResponseEvent::InboundFailure { peer, error, .. },
        )) => {
            warn!("ping inbound failure from {peer}: {error}");
            metrics.ping_fail.inc();
        }
        SwarmEvent::Behaviour(GatewayBehaviourEvent::Ping(
            RequestResponseEvent::ResponseSent { peer, .. },
        )) => {
            info!("ping response sent to {peer}");
        }
        SwarmEvent::NewListenAddr { address, .. } => {
            info!("listening on {address}");
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            connected.insert(peer_id);
            last_dial.insert(peer_id, Instant::now());
            metrics.connected_peers.set(connected.len() as i64);
            metrics.dial_success.inc();
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            connected.remove(&peer_id);
            metrics.connected_peers.set(connected.len() as i64);
        }
        _ => {}
    }
}

fn build_swarm(
    signing_key: SigningKey,
    forward_handler: &forwarding::handler::Handler,
    cfg: &GatewayConfig,
) -> Result<Swarm<GatewayBehaviour>> {
    let ed_kp = ed25519_to_identity(&signing_key)?;
    let noise_config = noise::Config::new(&ed_kp)?;

    let rr_config = RequestResponseConfig::default();
    let ping_proto = RequestResponse::with_codec(
        proto::PingCodec::default(),
        std::iter::once((proto::PingProtocol, ProtocolSupport::Full)),
        rr_config,
    );

    let forward_protocols =
        forwarding::behaviour::forwarding_supported_protocols(forward_handler)?;
    let forward_limiter = forwarding::limiter::ForwardLimiter::new(
        cfg.forward_max_streams.unwrap_or(200),
        Duration::from_secs(cfg.forward_wait_timeout_secs.unwrap_or(1)),
    );
    let forward_router = std::sync::Arc::new(forwarding::router::Router::new(
        cfg.forward_rules.as_deref().unwrap_or(&[]),
    ));
    let forward = forwarding::behaviour::ForwardingBehaviour::new(
        forward_protocols,
        Some(forward_limiter),
        forward_router,
        Duration::from_secs(cfg.forward_connect_timeout_secs.unwrap_or(2)),
    );
    let behaviour = GatewayBehaviour {
        ping: ping_proto,
        forward,
    };

    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(noise_config)
        .multiplex(yamux::Config::default())
        .boxed();

    let swarm = Swarm::new(
        transport,
        behaviour,
        ed_kp.public().to_peer_id(),
        SwarmConfig::with_tokio_executor(),
    );
    Ok(swarm)
}

async fn register_with_directory(
    cfg: &GatewayConfig,
    signing_key: &SigningKey,
    verifying_key_b64: &str,
    peer_id: &str,
) -> Result<()> {
    let client = Client::new();
    let challenge_resp = client
        .post(format!("{}/registry/challenge", cfg.bootstrap_api_url))
        .bearer_auth(&cfg.operator_token)
        .json(&serde_json::json!({ "peer_id": peer_id }))
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;
    let challenge_b64 = challenge_resp
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("challenge missing"))?;
    let challenge_bytes = STANDARD_NO_PAD
        .decode(challenge_b64)
        .or_else(|_| STANDARD.decode(challenge_b64))?;
    let signature = signing_key.sign(&challenge_bytes);
    let signature_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());

    let addrs = cfg
        .listen_multiaddrs
        .iter()
        .map(|s| s.clone())
        .collect::<Vec<_>>();

    let enroll_body = serde_json::json!({
        "peer_id": peer_id,
        "addrs": addrs,
        "signature": signature_b64,
        "pubkey": verifying_key_b64,
        "tags": ["bootstrap"],
        "weight": 100u16
    });

    let enroll = client
        .post(format!("{}/registry/enroll", cfg.bootstrap_api_url))
        .bearer_auth(&cfg.operator_token)
        .json(&enroll_body)
        .send()
        .await?
        .error_for_status()?;
    info!("enroll response: {:?}", enroll.status());

    if let Some(admin) = &cfg.admin_token {
        let approve = client
            .post(format!("{}/registry/approve", cfg.bootstrap_api_url))
            .bearer_auth(admin)
            .json(&serde_json::json!({"peer_id": peer_id}))
            .send()
            .await?;
        if approve.status().is_success() {
            info!("approved peer");
        } else {
            warn!("approve failed: {}", approve.status());
        }
    }

    Ok(())
}

async fn dial_manifest_peers(
    cfg: &GatewayConfig,
    manifest_keys: &ManifestKeys,
    swarm: &mut Swarm<GatewayBehaviour>,
    self_peer: &str,
    connected: &mut HashSet<PeerId>,
    last_dial: &mut HashMap<PeerId, Instant>,
    fail_counts: &mut HashMap<PeerId, u32>,
    metrics: &Metrics,
    cache: &Arc<Mutex<ManifestCache>>,
) -> Result<()> {
    let urls = &cfg.bootstrap_manifest_urls;
    if urls.is_empty() {
        return Ok(());
    }
    let client = Client::new();
    let mut manifest_doc = None;
    for url in urls {
        match client.get(url).send().await {
            Ok(resp) => match resp.json::<manifest::Manifest>().await {
                Ok(m) => {
                    manifest_doc = Some(m);
                    metrics.manifest_fetch_ok.inc();
                    break;
                }
                Err(e) => {
                    metrics.manifest_fetch_fail.inc();
                    warn!("parse manifest from {url} failed: {e}");
                }
            },
            Err(e) => {
                metrics.manifest_fetch_fail.inc();
                warn!("fetch manifest {url} failed: {e}");
            }
        }
    }
    let m = match manifest_doc {
        Some(m) => {
            verify_manifest(&m, manifest_keys)?;
            let mut lock = cache.lock().unwrap();
            lock.push(m.clone());
            m
        }
        None => {
            match cache
                .lock()
                .unwrap()
                .last_good(cfg.manifest_grace_secs.unwrap_or(300))
            {
                Some(cached) => {
                    warn!("using cached manifest due to fetch/parse failures");
                    cached
                }
                None => return Ok(()),
            }
        }
    };

    // drop revoked and self
    let mut peers: Vec<_> = m
        .bootstrap_peers
        .into_iter()
        .filter(|p| p.peer_id != self_peer && !m.revoked_peer_ids.contains(&p.peer_id))
        .collect();
    let target = cfg.target_peers.unwrap_or(8);
    let _min_peers = cfg.min_peers.unwrap_or(target / 2);
    let max_peers = cfg.max_peers.unwrap_or(target);
    let dial_batch = cfg.dial_batch_size.unwrap_or(4);
    let backoff_base = Duration::from_secs(cfg.backoff_base_secs.unwrap_or(30));
    let backoff_max = Duration::from_secs(cfg.backoff_max_secs.unwrap_or(300));

    let mut rng = rand::thread_rng();
    peers.shuffle(&mut rng);

    let mut dialed = 0usize;
    for peer in peers {
        if connected.len() >= max_peers {
            break;
        }
        if dialed >= dial_batch {
            break;
        }
        let peer_id = match PeerId::from_str(&peer.peer_id) {
            Ok(id) => id,
            Err(e) => {
                warn!("invalid peer id {}: {e}", peer.peer_id);
                continue;
            }
        };
        if let Some(last) = last_dial.get(&peer_id) {
            let fails = *fail_counts.get(&peer_id).unwrap_or(&0);
            let mut delay = backoff_base * 2u32.saturating_pow(fails.min(8));
            if delay > backoff_max {
                delay = backoff_max;
            }
            let jitter_ms = rng.gen_range(0..1000);
            if last.elapsed() + Duration::from_millis(jitter_ms) < delay {
                continue;
            }
        }
        for addr in peer.addrs {
            let mut ma: Multiaddr = match addr.parse() {
                Ok(m) => m,
                Err(e) => {
                    warn!("invalid addr {addr}: {e}");
                    continue;
                }
            };
            ma.push(libp2p::multiaddr::Protocol::P2p(peer_id.into()));
            metrics.dial_attempt.inc();
            if let Err(e) = swarm.dial(ma.clone()) {
                warn!("dial {addr} failed: {e}");
                *fail_counts.entry(peer_id).or_insert(0) += 1;
            } else {
                last_dial.insert(peer_id, Instant::now());
                dialed += 1;
            }
        }
        swarm
            .behaviour_mut()
            .ping
            .send_request(&peer_id, proto::PingRequest {});
        if connected.len() + dialed >= max_peers {
            break;
        }
    }
    // continue dialing in future ticks until min_peers satisfied
    Ok(())
}

fn load_config() -> Result<GatewayConfig> {
    let path =
        env::var("EDGE_GATEWAY_CONFIG").unwrap_or_else(|_| "gateway.config.json".to_string());
    let cfg_str =
        fs::read_to_string(&path).with_context(|| format!("read gateway config at {path}"))?;
    let mut cfg: GatewayConfig = serde_json::from_str(&cfg_str)
        .with_context(|| format!("parse gateway config JSON at {path}"))?;
    if cfg.listen_multiaddrs.is_empty() {
        cfg.listen_multiaddrs = vec!["/ip4/0.0.0.0/tcp/4001".into()];
    }
    if cfg.mode.is_empty() {
        cfg.mode = "bootstrap".into();
    }
    if cfg.manifest_poll_secs.is_none() {
        cfg.manifest_poll_secs = Some(30);
    }
    if cfg.target_peers.is_none() {
        cfg.target_peers = Some(8);
    }
    if cfg.min_peers.is_none() {
        cfg.min_peers = Some(4);
    }
    if cfg.max_peers.is_none() {
        cfg.max_peers = Some(12);
    }
    if cfg.redial_secs.is_none() {
        cfg.redial_secs = Some(30);
    }
    if cfg.backoff_base_secs.is_none() {
        cfg.backoff_base_secs = Some(30);
    }
    if cfg.backoff_max_secs.is_none() {
        cfg.backoff_max_secs = Some(300);
    }
    if cfg.dial_batch_size.is_none() {
        cfg.dial_batch_size = Some(4);
    }
    if cfg.metrics_bind.is_none() {
        cfg.metrics_bind = Some("0.0.0.0:9090".into());
    }
    if cfg.manifest_grace_secs.is_none() {
        cfg.manifest_grace_secs = Some(300);
    }
    if cfg.forward_max_streams.is_none() {
        cfg.forward_max_streams = Some(200);
    }
    if cfg.forward_wait_timeout_secs.is_none() {
        cfg.forward_wait_timeout_secs = Some(1);
    }
    if cfg.forward_connect_timeout_secs.is_none() {
        cfg.forward_connect_timeout_secs = Some(2);
    }
    cfg.forward_rules = Some(load_forward_rules(cfg.forward_rules.clone())?);
    if let Some(rules) = &cfg.forward_rules {
        info!("forward_rules_count={}", rules.len());
        for r in rules {
            info!("forward_rule protocol={} backend={}", r.protocol, r.backend);
        }
    }
    Ok(cfg)
}

fn build_keys(secret_b64: &str) -> Result<(SigningKey, String, String)> {
    let bytes = STANDARD_NO_PAD
        .decode(secret_b64)
        .or_else(|_| STANDARD.decode(secret_b64))
        .context("decode gateway key")?;
    let secret: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("gateway key must be 32 bytes ed25519 secret"))?;
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();
    let pub_b64 = STANDARD_NO_PAD.encode(verifying_key.to_bytes());
    let peer_id = peer_id_from_key(&signing_key);
    Ok((signing_key, peer_id, pub_b64))
}

fn peer_id_from_key(signing_key: &SigningKey) -> String {
    let id_kp = ed25519_to_identity(signing_key).expect("convert key");
    id_kp.public().to_peer_id().to_string()
}

fn ed25519_to_identity(signing_key: &SigningKey) -> Result<identity::Keypair> {
    let sk_bytes = signing_key.to_bytes();
    let secret = identity::ed25519::SecretKey::try_from_bytes(sk_bytes)?;
    let keypair = identity::ed25519::Keypair::from(secret);
    Ok(identity::Keypair::from(keypair))
}

fn load_secret_key(cfg: &GatewayConfig) -> Result<String> {
    if let Some(path) = &cfg.secret_key_path {
        let contents =
            fs::read_to_string(path).with_context(|| format!("read secret key from {path}"))?;
        let b64 = contents.trim().to_string();
        if b64.is_empty() {
            anyhow::bail!("secret key file {path} is empty");
        }
        return Ok(b64);
    }
    if cfg.secret_key_b64.is_empty() {
        anyhow::bail!("secret_key_b64 is required when secret_key_path is not set");
    }
    Ok(cfg.secret_key_b64.clone())
}

#[derive(Clone)]
struct Metrics {
    manifest_fetch_ok: IntCounter,
    manifest_fetch_fail: IntCounter,
    dial_attempt: IntCounter,
    dial_success: IntCounter,
    ping_ok: IntCounter,
    ping_fail: IntCounter,
    connected_peers: IntGauge,
    registry: Registry,
}

impl Metrics {
    fn new() -> Result<Self> {
        let registry = Registry::new();
        let manifest_fetch_ok =
            IntCounter::new("manifest_fetch_ok_total", "manifest fetch success")?;
        let manifest_fetch_fail =
            IntCounter::new("manifest_fetch_fail_total", "manifest fetch failure")?;
        let dial_attempt = IntCounter::new("dial_attempt_total", "dial attempts")?;
        let dial_success =
            IntCounter::new("dial_success_total", "successful dials (conn established)")?;
        let ping_ok = IntCounter::new("ping_ok_total", "ping responses received")?;
        let ping_fail = IntCounter::new("ping_fail_total", "ping failures")?;
        let connected_peers = IntGauge::new("connected_peers", "current connected peers")?;
        registry.register(Box::new(manifest_fetch_ok.clone()))?;
        registry.register(Box::new(manifest_fetch_fail.clone()))?;
        registry.register(Box::new(dial_attempt.clone()))?;
        registry.register(Box::new(dial_success.clone()))?;
        registry.register(Box::new(ping_ok.clone()))?;
        registry.register(Box::new(ping_fail.clone()))?;
        registry.register(Box::new(connected_peers.clone()))?;
        Ok(Self {
            manifest_fetch_ok,
            manifest_fetch_fail,
            dial_attempt,
            dial_success,
            ping_ok,
            ping_fail,
            connected_peers,
            registry,
        })
    }

    fn render(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let mut buf = Vec::new();
        let mut mf = self.registry.gather();
        mf.extend(forwarding::metrics::global_forward_metrics().gather());
        encoder.encode(&mf, &mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}

async fn serve_metrics(metrics: Metrics, addr: SocketAddr) -> Result<()> {
    let app = Router::new().route(
        "/metrics",
        get(move || {
            let m = metrics.clone();
            async move {
                match m.render() {
                    Ok(body) => axum::response::Response::builder()
                        .status(200)
                        .header("Content-Type", "text/plain; version=0.0.4")
                        .body(Body::from(body))
                        .unwrap(),
                    Err(e) => axum::response::Response::builder()
                        .status(500)
                        .body(Body::from(format!("metrics error: {e}")))
                        .unwrap(),
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

struct ManifestKeys {
    by_id: HashMap<String, VerifyingKey>,
    fallback: Vec<VerifyingKey>,
}

fn load_manifest_keys(
    map: Option<&HashMap<String, String>>,
    list: Option<&Vec<String>>,
    single: Option<&str>,
) -> Result<ManifestKeys> {
    let mut by_id = HashMap::new();
    if let Some(map) = map {
        for (kid, b64) in map {
            if let Ok(vk) = decode_vk(b64) {
                by_id.insert(kid.clone(), vk);
            }
        }
    }
    let mut fallback = Vec::new();
    if let Some(list) = list {
        for b64 in list {
            if let Ok(vk) = decode_vk(b64) {
                fallback.push(vk);
            }
        }
    }
    if fallback.is_empty() {
        if let Some(one) = single {
            if let Ok(vk) = decode_vk(one) {
                fallback.push(vk);
            }
        }
    }
    if by_id.is_empty() && fallback.is_empty() {
        warn!(
            "manifest verification disabled: no manifest_trusted_keys / manifest_pubkeys_b64 / manifest_pubkey_b64 provided"
        );
    }
    Ok(ManifestKeys { by_id, fallback })
}

fn decode_vk(b64: &str) -> Result<VerifyingKey> {
    let bytes = STANDARD_NO_PAD
        .decode(b64)
        .or_else(|_| STANDARD.decode(b64))
        .context("decode manifest verifying key")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("manifest verifying key must be 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&arr)?;
    Ok(key)
}

fn verify_manifest(m: &manifest::Manifest, keys: &ManifestKeys) -> Result<()> {
    if keys.by_id.is_empty() && keys.fallback.is_empty() {
        return Ok(());
    }
    let unsigned = m.unsigned();
    let canon = unsigned
        .canonical_bytes()
        .context("manifest canonical encode")?;
    let sig_bytes_vec = STANDARD_NO_PAD
        .decode(&m.signature)
        .or_else(|_| STANDARD.decode(&m.signature))
        .context("decode manifest signature")?;
    let sig_bytes: [u8; 64] = sig_bytes_vec
        .try_into()
        .map_err(|_| anyhow::anyhow!("manifest signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    if let Some(vk) = keys.by_id.get(&m.signing_key_id) {
        vk.verify_strict(&canon, &sig)
            .context("manifest signature verify failed (kid match)")?;
    } else {
        let mut verified = false;
        for vk in keys.fallback.iter() {
            if vk.verify_strict(&canon, &sig).is_ok() {
                verified = true;
                break;
            }
        }
        if !verified {
            anyhow::bail!("manifest signature verify failed");
        }
    }
    let now = OffsetDateTime::now_utc();
    if let Ok(exp) = OffsetDateTime::parse(&m.expires_at, &Rfc3339) {
        if exp < now {
            anyhow::bail!("manifest expired");
        }
    }
    Ok(())
}

#[derive(Default)]
struct ManifestCache {
    current: Option<manifest::Manifest>,
    previous: Option<manifest::Manifest>,
}

impl ManifestCache {
    fn push(&mut self, m: manifest::Manifest) {
        if let Some(cur) = self.current.take() {
            self.previous = Some(cur);
        }
        self.current = Some(m);
    }

    fn last_good(&self, grace_secs: u64) -> Option<manifest::Manifest> {
        let now = OffsetDateTime::now_utc();
        let grace = Duration::from_secs(grace_secs);
        for candidate in [&self.current, &self.previous] {
            if let Some(man) = candidate {
                if let Ok(exp) = OffsetDateTime::parse(&man.expires_at, &Rfc3339) {
                    if exp + grace >= now {
                        return Some(man.clone());
                    }
                }
            }
        }
        None
    }
}
