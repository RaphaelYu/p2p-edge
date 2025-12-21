use anyhow::Result;
use edge_bootstrap::api::router;
use edge_bootstrap::config::AppConfig;
use edge_bootstrap::manifest::build_manifest_state;
use edge_bootstrap::signer::ManifestSigner;
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
    let state = build_manifest_state(&config, &signer)?;

    info!(
        "edge-bootstrap listening on {} (epoch={}, ttl_secs={}, peers={})",
        config.bind_addr,
        config.epoch,
        config.ttl_secs,
        config.peers.len()
    );

    let listener = TcpListener::bind(config.bind_addr).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}
