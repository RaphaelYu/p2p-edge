use anyhow::Result;
use edge_bootstrap::api::{AppState, RateLimiter, router};
use edge_bootstrap::challenge::ChallengeManager;
use edge_bootstrap::config::AppConfig;
use edge_bootstrap::manifest::ManifestService;
use edge_bootstrap::prober::run_probe_loop;
use edge_bootstrap::registry::RegistryStore;
use edge_bootstrap::signer::ManifestSigner;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .without_time()
        .init();

    let config = AppConfig::load()?;
    let signer = ManifestSigner::from_base64(&config.signing_key_b64)?;
    let registry = RegistryStore::open(&config.registry_db_path)?;
    let state = ManifestService::new(config.clone(), signer.clone(), registry.clone());
    let challenges = ChallengeManager::new(Duration::from_secs(config.challenge_ttl_secs));
    if config.registry_enabled {
        let probe_config = config.clone();
        let probe_registry = registry.clone();
        tokio::spawn(async move {
            run_probe_loop(probe_config, probe_registry).await;
        });
    }

    let app_state = AppState {
        manifest: state,
        registry,
        challenges,
        tokens: config.operator_tokens.clone(),
        admin_tokens: config.admin_tokens.clone(),
        rate_limiter: RateLimiter::new(5.0, 10.0),
    };

    info!(
        "edge-bootstrap listening on {} (epoch={}, ttl_secs={}, peers={})",
        config.bind_addr,
        config.epoch,
        config.ttl_secs,
        config.peers.len()
    );

    let listener = TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, router(app_state)).await?;
    Ok(())
}
