use crate::auth::OperatorTokens;
use crate::error::{BootstrapError, Result};
use crate::manifest::PeerRecord;
use serde::Deserialize;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub bind_addr: SocketAddr,
    pub epoch: u64,
    pub ttl_secs: u64,
    pub signing_key_b64: String,
    pub peers: Vec<PeerRecord>,
    pub static_base_urls: Vec<String>,
    pub revoked_peer_ids: Vec<String>,
    pub cache_max_age_secs: u64,
    pub operator_tokens: OperatorTokens,
    pub admin_tokens: OperatorTokens,
    pub registry_db_path: PathBuf,
    pub challenge_ttl_secs: u64,
    pub registry_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct PeerRecordInput {
    peer_id: String,
    addrs: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    weight: Option<u16>,
}

impl PeerRecordInput {
    fn into_peer_record(self) -> PeerRecord {
        PeerRecord {
            peer_id: self.peer_id,
            addrs: self.addrs,
            tags: self.tags,
            weight: self.weight.unwrap_or(100),
        }
    }
}

pub fn default_bind_addr() -> SocketAddr {
    // Static default; parse is infallible for this literal.
    "0.0.0.0:8080"
        .parse()
        .unwrap_or_else(|_| unreachable!("default bind address literal must parse"))
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let bind_addr = env::var("EDGE_BIND_ADDR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(default_bind_addr);

        let epoch = env::var("EDGE_MANIFEST_EPOCH")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let ttl_secs = env::var("EDGE_MANIFEST_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);

        if ttl_secs == 0 {
            return Err(BootstrapError::Config(
                "EDGE_MANIFEST_TTL_SECS must be greater than zero".to_string(),
            ));
        }

        let cache_max_age_secs = env::var("EDGE_CACHE_MAX_AGE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        let signing_key_b64 = env::var("EDGE_SIGNING_KEY_B64")
            .map_err(|_| BootstrapError::Config("EDGE_SIGNING_KEY_B64 is required".to_string()))?;

        let peers_json = env::var("EDGE_BOOTSTRAP_PEERS_JSON").map_err(|_| {
            BootstrapError::Config("EDGE_BOOTSTRAP_PEERS_JSON is required".to_string())
        })?;
        let peers: Vec<PeerRecord> = serde_json::from_str::<Vec<PeerRecordInput>>(&peers_json)
            .map_err(|e| BootstrapError::Config(format!("invalid EDGE_BOOTSTRAP_PEERS_JSON: {e}")))?
            .into_iter()
            .map(PeerRecordInput::into_peer_record)
            .collect();

        if peers.is_empty() {
            return Err(BootstrapError::Config(
                "at least one bootstrap peer is required".to_string(),
            ));
        }
        if peers.iter().any(|p| p.addrs.is_empty()) {
            return Err(BootstrapError::Config(
                "each bootstrap peer must have at least one addr".to_string(),
            ));
        }

        let static_base_urls = env::var("EDGE_STATIC_BASE_URLS_JSON")
            .ok()
            .and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok())
            .unwrap_or_default();

        let revoked_peer_ids = env::var("EDGE_REVOKED_PEER_IDS_JSON")
            .ok()
            .and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok())
            .unwrap_or_default();

        let operator_tokens = load_operator_tokens()?;
        let admin_tokens = load_admin_tokens()?;
        let registry_db_path = env::var("EDGE_REGISTRY_DB_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("registry.db"));
        let challenge_ttl_secs = env::var("EDGE_CHALLENGE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120);
        let registry_enabled = env::var("EDGE_REGISTRY_ENABLE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Ok(AppConfig {
            bind_addr,
            epoch,
            ttl_secs,
            signing_key_b64,
            peers,
            static_base_urls,
            revoked_peer_ids,
            cache_max_age_secs,
            operator_tokens,
            admin_tokens,
            registry_db_path,
            challenge_ttl_secs,
            registry_enabled,
        })
    }
}

fn load_operator_tokens() -> Result<OperatorTokens> {
    if let Ok(raw) = env::var("EDGE_OPERATOR_TOKENS_HASHED_JSON") {
        let entries: Vec<TokenPair> = serde_json::from_str(&raw).map_err(|e| {
            BootstrapError::Config(format!("invalid EDGE_OPERATOR_TOKENS_HASHED_JSON: {e}"))
        })?;
        let pairs: Vec<(String, String)> = entries
            .into_iter()
            .map(|t| (t.operator_id, t.token))
            .collect();
        OperatorTokens::from_hashed(pairs).ok_or_else(|| {
            BootstrapError::Config("invalid token hash format; expect hex sha256".to_string())
        })
    } else if let Ok(raw) = env::var("EDGE_OPERATOR_TOKENS_JSON") {
        let entries: Vec<TokenPair> = serde_json::from_str(&raw).map_err(|e| {
            BootstrapError::Config(format!("invalid EDGE_OPERATOR_TOKENS_JSON: {e}"))
        })?;
        let pairs: Vec<(String, String)> = entries
            .into_iter()
            .map(|t| (t.operator_id, t.token))
            .collect();
        Ok(OperatorTokens::from_plain(pairs))
    } else {
        Ok(OperatorTokens::default())
    }
}

#[derive(Debug, Deserialize)]
struct TokenPair {
    operator_id: String,
    token: String,
}

fn load_admin_tokens() -> Result<OperatorTokens> {
    if let Ok(raw) = env::var("EDGE_ADMIN_TOKENS_HASHED_JSON") {
        let entries: Vec<TokenPair> = serde_json::from_str(&raw).map_err(|e| {
            BootstrapError::Config(format!("invalid EDGE_ADMIN_TOKENS_HASHED_JSON: {e}"))
        })?;
        let pairs: Vec<(String, String)> = entries
            .into_iter()
            .map(|t| (t.operator_id, t.token))
            .collect();
        OperatorTokens::from_hashed(pairs).ok_or_else(|| {
            BootstrapError::Config("invalid admin token hash format; expect hex sha256".to_string())
        })
    } else if let Ok(raw) = env::var("EDGE_ADMIN_TOKENS_JSON") {
        let entries: Vec<TokenPair> = serde_json::from_str(&raw)
            .map_err(|e| BootstrapError::Config(format!("invalid EDGE_ADMIN_TOKENS_JSON: {e}")))?;
        let pairs: Vec<(String, String)> = entries
            .into_iter()
            .map(|t| (t.operator_id, t.token))
            .collect();
        Ok(OperatorTokens::from_plain(pairs))
    } else if let Ok(token) = env::var("EDGE_ADMIN_TOKEN") {
        Ok(OperatorTokens::from_plain(vec![(
            "admin".to_string(),
            token,
        )]))
    } else {
        Ok(OperatorTokens::default())
    }
}
