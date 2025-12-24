use std::collections::HashSet;

use super::config::ForwardRule;
use libp2p::StreamProtocol;
use tokio::io::AsyncWriteExt;

#[derive(Clone, Debug)]
pub struct Handler {
    rules: Vec<ForwardRule>,
    protocols: HashSet<String>,
}

/// Forwarding entry interface (placeholder until libp2p wiring is added).
pub trait ForwardingEntry {
    fn protocols(&self) -> Vec<String>;
    fn handle_inbound_placeholder(&self, protocol: &str);
}

impl Handler {
    pub fn new(rules: Vec<ForwardRule>) -> Self {
        let protocols = rules.iter().map(|r| r.protocol.clone()).collect();
        Self { rules, protocols }
    }

    pub fn protocols(&self) -> &HashSet<String> {
        &self.protocols
    }

    pub fn rules(&self) -> &[ForwardRule] {
        &self.rules
    }

    pub fn stream_protocols(&self) -> anyhow::Result<Vec<StreamProtocol>> {
        let mut set = HashSet::new();
        for p in &self.protocols {
            if p.trim().is_empty() {
                anyhow::bail!("protocol cannot be empty");
            }
            if p.len() > 256 {
                anyhow::bail!("protocol too long");
            }
            set.insert(p.clone());
        }
        if set.is_empty() {
            anyhow::bail!("no forwarding protocols configured");
        }
        let mut vec: Vec<_> = set.into_iter().collect();
        vec.sort();
        let mut out = Vec::new();
        for p in vec {
            // StreamProtocol::new wants &'static str; we need to store owned protocols elsewhere for lifetime.
            // For now we leak strings into a static to satisfy the API; acceptable for small protocol sets.
            let leaked: &'static str = Box::leak(p.into_boxed_str());
            out.push(StreamProtocol::new(leaked));
        }
        Ok(out)
    }

    pub async fn handle_inbound<S: AsyncWriteExt + Unpin>(&self, mut stream: S, protocol: &str) {
        let metrics = crate::forwarding::metrics::global_forward_metrics();
        metrics.on_open(protocol);
        let _ = stream.shutdown().await;
        metrics.on_close(protocol, "not_implemented");
    }
}

impl ForwardingEntry for Handler {
    fn protocols(&self) -> Vec<String> {
        let mut v: Vec<_> = self.protocols.iter().cloned().collect();
        v.sort();
        v
    }

    fn handle_inbound_placeholder(&self, _protocol: &str) {
        // no-op placeholder for future libp2p wiring
    }
}
