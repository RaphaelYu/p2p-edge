use crate::config::AppConfig;
use crate::error::{BootstrapError, Result};
use crate::registry::{NodeRecord, NodeStatus, RegistryStore};
use crate::signer::ManifestSigner;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerRecord {
    pub peer_id: String,
    pub addrs: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_weight")]
    pub weight: u16,
}

fn default_weight() -> u16 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BootstrapManifestV1 {
    pub version: String,
    pub epoch: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub bootstrap_peers: Vec<PeerRecord>,
    pub static_base_urls: Vec<String>,
    pub revoked_peer_ids: Vec<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnsignedBootstrapManifest {
    pub version: String,
    pub epoch: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub bootstrap_peers: Vec<PeerRecord>,
    pub static_base_urls: Vec<String>,
    pub revoked_peer_ids: Vec<String>,
}

impl UnsignedBootstrapManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| BootstrapError::Serialization(e.to_string()))
    }

    pub fn into_signed(self, signature: String) -> BootstrapManifestV1 {
        BootstrapManifestV1 {
            version: self.version,
            epoch: self.epoch,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            bootstrap_peers: self.bootstrap_peers,
            static_base_urls: self.static_base_urls,
            revoked_peer_ids: self.revoked_peer_ids,
            signature,
        }
    }
}

impl BootstrapManifestV1 {
    pub fn without_signature(&self) -> UnsignedBootstrapManifest {
        UnsignedBootstrapManifest {
            version: self.version.clone(),
            epoch: self.epoch,
            issued_at: self.issued_at.clone(),
            expires_at: self.expires_at.clone(),
            bootstrap_peers: self.bootstrap_peers.clone(),
            static_base_urls: self.static_base_urls.clone(),
            revoked_peer_ids: self.revoked_peer_ids.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManifestState {
    pub manifest: BootstrapManifestV1,
    pub etag: String,
    pub cache_control: String,
    pub canonical_bytes: Vec<u8>,
}

pub fn build_manifest_state(config: &AppConfig, signer: &ManifestSigner) -> Result<ManifestState> {
    let issued_at = OffsetDateTime::now_utc();
    let expires_at = issued_at + Duration::seconds(config.ttl_secs as i64);

    let unsigned = UnsignedBootstrapManifest {
        version: "v1".to_string(),
        epoch: config.epoch,
        issued_at: issued_at.format(&Rfc3339)?,
        expires_at: expires_at.format(&Rfc3339)?,
        bootstrap_peers: config.peers.clone(),
        static_base_urls: config.static_base_urls.clone(),
        revoked_peer_ids: config.revoked_peer_ids.clone(),
    };

    let canonical_bytes = unsigned.canonical_bytes()?;
    let signature = signer.sign(&canonical_bytes)?;
    let manifest = unsigned.into_signed(signature);

    let etag = compute_etag(&canonical_bytes);
    let cache_control = format!("public, max-age={}", config.cache_max_age_secs);

    Ok(ManifestState {
        manifest,
        etag,
        cache_control,
        canonical_bytes,
    })
}

#[derive(Clone)]
pub struct ManifestService {
    config: AppConfig,
    signer: ManifestSigner,
    registry: RegistryStore,
    cache: Arc<Mutex<Option<(ManifestState, String)>>>,
}

impl ManifestService {
    pub fn new(config: AppConfig, signer: ManifestSigner, registry: RegistryStore) -> Self {
        Self {
            config,
            signer,
            registry,
            cache: Arc::new(Mutex::new(None)),
        }
    }

    pub fn current(&self) -> Result<ManifestState> {
        let (peers, revoked, source_hash) = self.collect_sources()?;
        {
            let cache = self
                .cache
                .lock()
                .map_err(|_| BootstrapError::Config("manifest cache poisoned".to_string()))?;
            if let Some((state, cached_hash)) = cache.as_ref() {
                if *cached_hash == source_hash && !is_expired(&state.manifest.expires_at) {
                    return Ok(state.clone());
                }
            }
        }

        let issued_at = OffsetDateTime::now_utc();
        let expires_at = issued_at + Duration::seconds(self.config.ttl_secs as i64);
        let unsigned = UnsignedBootstrapManifest {
            version: "v1".to_string(),
            epoch: self.config.epoch,
            issued_at: issued_at.format(&Rfc3339)?,
            expires_at: expires_at.format(&Rfc3339)?,
            bootstrap_peers: peers,
            static_base_urls: self.config.static_base_urls.clone(),
            revoked_peer_ids: revoked,
        };

        let canonical_bytes = unsigned.canonical_bytes()?;
        let signature = self.signer.sign(&canonical_bytes)?;
        let manifest = unsigned.into_signed(signature);
        let etag = compute_etag(&canonical_bytes);
        let cache_control = format!("public, max-age={}", self.config.cache_max_age_secs);

        let state = ManifestState {
            manifest,
            etag,
            cache_control,
            canonical_bytes,
        };
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| BootstrapError::Config("manifest cache poisoned".to_string()))?;
        *cache = Some((state.clone(), source_hash));
        Ok(state)
    }

    fn collect_sources(&self) -> Result<(Vec<PeerRecord>, Vec<String>, String)> {
        let (peers, revoked) = if self.config.registry_enabled {
            let active = self.registry.list_by_status(Some(NodeStatus::Active))?;
            let peers = active.into_iter().map(node_to_peer).collect();
            let mut revoked = self
                .registry
                .list_by_status(Some(NodeStatus::Revoked))?
                .into_iter()
                .map(|n| n.peer_id)
                .collect::<Vec<_>>();
            // include configured revoked ids too
            revoked.extend(self.config.revoked_peer_ids.clone());
            revoked.sort();
            revoked.dedup();
            (peers, revoked)
        } else {
            (
                self.config.peers.clone(),
                self.config.revoked_peer_ids.clone(),
            )
        };
        let mut hash_hasher = Sha256::new();
        hash_hasher.update(format!("{:?}", peers));
        hash_hasher.update(format!("{:?}", revoked));
        hash_hasher.update(self.config.epoch.to_le_bytes());
        hash_hasher.update(self.config.static_base_urls.join(",").as_bytes());
        let source_hash = STANDARD_NO_PAD.encode(hash_hasher.finalize());
        Ok((peers, revoked, source_hash))
    }
}

fn node_to_peer(node: NodeRecord) -> PeerRecord {
    PeerRecord {
        peer_id: node.peer_id,
        addrs: node.addrs,
        tags: node.tags,
        weight: node.weight,
    }
}

fn is_expired(expires_at: &str) -> bool {
    if let Ok(ts) = OffsetDateTime::parse(expires_at, &Rfc3339) {
        return ts < OffsetDateTime::now_utc();
    }
    true
}

fn compute_etag(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    STANDARD_NO_PAD.encode(digest)
}
