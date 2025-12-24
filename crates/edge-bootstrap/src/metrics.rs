use once_cell::sync::Lazy;
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};
use std::sync::Arc;

#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Registry>,
    pub manifest_issued: IntCounter,
    pub manifest_etag_changes: IntCounter,
    pub registry_enroll: IntCounter,
    pub registry_approve: IntCounter,
    pub registry_revoke: IntCounter,
    pub active_nodes: IntGauge,
    pub pending_nodes: IntGauge,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Arc::new(Registry::new());
        let manifest_issued =
            IntCounter::new("manifest_issued_total", "number of manifest generations").unwrap();
        let manifest_etag_changes =
            IntCounter::new("manifest_etag_changes_total", "manifest etag changes").unwrap();
        let registry_enroll =
            IntCounter::new("registry_enroll_total", "registry enroll operations").unwrap();
        let registry_approve =
            IntCounter::new("registry_approve_total", "registry approve operations").unwrap();
        let registry_revoke =
            IntCounter::new("registry_revoke_total", "registry revoke operations").unwrap();
        let active_nodes = IntGauge::new("active_nodes", "active nodes").unwrap();
        let pending_nodes = IntGauge::new("pending_nodes", "pending nodes").unwrap();

        registry.register(Box::new(manifest_issued.clone())).ok();
        registry
            .register(Box::new(manifest_etag_changes.clone()))
            .ok();
        registry.register(Box::new(registry_enroll.clone())).ok();
        registry.register(Box::new(registry_approve.clone())).ok();
        registry.register(Box::new(registry_revoke.clone())).ok();
        registry.register(Box::new(active_nodes.clone())).ok();
        registry.register(Box::new(pending_nodes.clone())).ok();

        Self {
            registry,
            manifest_issued,
            manifest_etag_changes,
            registry_enroll,
            registry_approve,
            registry_revoke,
            active_nodes,
            pending_nodes,
        }
    }

    pub fn render(&self) -> String {
        let mf = self.registry.gather();
        let encoder = TextEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&mf, &mut buf).unwrap_or_default();
        String::from_utf8_lossy(&buf).into_owned()
    }
}

pub static GLOBAL_METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);
