use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub epoch: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub signing_key_id: String,
    pub bootstrap_peers: Vec<ManifestPeer>,
    pub static_base_urls: Vec<String>,
    pub revoked_peer_ids: Vec<String>,
    pub signature: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ManifestPeer {
    pub peer_id: String,
    pub addrs: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub weight: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UnsignedManifest {
    pub version: String,
    pub epoch: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub signing_key_id: String,
    pub bootstrap_peers: Vec<ManifestPeer>,
    pub static_base_urls: Vec<String>,
    pub revoked_peer_ids: Vec<String>,
}

impl Manifest {
    pub fn unsigned(&self) -> UnsignedManifest {
        UnsignedManifest {
            version: self.version.clone(),
            epoch: self.epoch,
            issued_at: self.issued_at.clone(),
            expires_at: self.expires_at.clone(),
            signing_key_id: self.signing_key_id.clone(),
            bootstrap_peers: self.bootstrap_peers.clone(),
            static_base_urls: self.static_base_urls.clone(),
            revoked_peer_ids: self.revoked_peer_ids.clone(),
        }
    }
}

impl UnsignedManifest {
    pub fn canonical_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }
}
