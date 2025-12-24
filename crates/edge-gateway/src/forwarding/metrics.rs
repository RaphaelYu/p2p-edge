use std::sync::OnceLock;

use prometheus::{CounterVec, Encoder, Registry, TextEncoder};

#[derive(Clone)]
pub struct ForwardMetrics {
    registry: Registry,
    open: CounterVec,
    close: CounterVec,
    bytes: CounterVec,
    errors: CounterVec,
}

impl ForwardMetrics {
    fn new() -> Self {
        let registry = Registry::new();
        let open = CounterVec::new(
            prometheus::Opts::new("forward_stream_open_total", "forward streams opened"),
            &["protocol"],
        )
        .unwrap_or_else(|e| {
            tracing::warn!("forward metrics init failed (open): {e}");
            CounterVec::new(
                prometheus::Opts::new("forward_stream_open_total_fallback", "fallback"),
                &["protocol"],
            )
            .expect("fallback counter vec must build")
        });
        let close = CounterVec::new(
            prometheus::Opts::new("forward_stream_close_total", "forward streams closed"),
            &["protocol", "reason"],
        )
        .unwrap_or_else(|e| {
            tracing::warn!("forward metrics init failed (close): {e}");
            CounterVec::new(
                prometheus::Opts::new("forward_stream_close_total_fallback", "fallback"),
                &["protocol", "reason"],
            )
            .expect("fallback counter vec must build")
        });
        let bytes = CounterVec::new(
            prometheus::Opts::new("forward_bytes_total", "forwarded bytes"),
            &["protocol", "dir"],
        )
        .unwrap_or_else(|e| {
            tracing::warn!("forward metrics init failed (bytes): {e}");
            CounterVec::new(
                prometheus::Opts::new("forward_bytes_total_fallback", "fallback"),
                &["protocol", "dir"],
            )
            .expect("fallback counter vec must build")
        });
        let errors = CounterVec::new(
            prometheus::Opts::new("forward_errors_total", "forward errors"),
            &["protocol", "code"],
        )
        .unwrap_or_else(|e| {
            tracing::warn!("forward metrics init failed (errors): {e}");
            CounterVec::new(
                prometheus::Opts::new("forward_errors_total_fallback", "fallback"),
                &["protocol", "code"],
            )
            .expect("fallback counter vec must build")
        });
        registry.register(Box::new(open.clone())).ok();
        registry.register(Box::new(close.clone())).ok();
        registry.register(Box::new(bytes.clone())).ok();
        registry.register(Box::new(errors.clone())).ok();
        Self {
            registry,
            open,
            close,
            bytes,
            errors,
        }
    }

    pub fn on_open(&self, protocol: &str) {
        self.open.with_label_values(&[protocol]).inc();
    }

    pub fn on_close(&self, protocol: &str, reason: &str) {
        self.close.with_label_values(&[protocol, reason]).inc();
    }

    pub fn add_bytes(&self, protocol: &str, dir: &str, n: u64) {
        self.bytes
            .with_label_values(&[protocol, dir])
            .inc_by(n as f64);
    }

    pub fn on_error(&self, protocol: &str, code: &str) {
        self.errors.with_label_values(&[protocol, code]).inc();
    }

    pub fn render(&self) -> String {
        let mf = self.registry.gather();
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        if let Err(e) = encoder.encode(&mf, &mut buf) {
            tracing::warn!("forward metrics encode failed: {e}");
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }
}

pub fn global_forward_metrics() -> &'static ForwardMetrics {
    static INSTANCE: OnceLock<ForwardMetrics> = OnceLock::new();
    INSTANCE.get_or_init(ForwardMetrics::new)
}
