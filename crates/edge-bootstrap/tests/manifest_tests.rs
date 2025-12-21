use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ed25519_dalek::{Signature, Verifier};
use edge_bootstrap::api::{AppState, router};
use edge_bootstrap::auth::OperatorTokens;
use edge_bootstrap::challenge::ChallengeManager;
use edge_bootstrap::config::{AppConfig, default_bind_addr};
use edge_bootstrap::manifest::{
    BootstrapManifestV1, ManifestService, ManifestState, PeerRecord, build_manifest_state,
};
use edge_bootstrap::registry::RegistryStore;
use edge_bootstrap::signer::ManifestSigner;
use hyper::StatusCode;
use lazy_static::lazy_static;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::tempdir;
use tower::ServiceExt;

const TEST_SIGNING_KEY_BYTES: [u8; 32] = [7u8; 32];
lazy_static! {
    static ref TEST_SIGNING_KEY_B64: String = STANDARD_NO_PAD.encode(TEST_SIGNING_KEY_BYTES);
}

fn build_app_state(config: &AppConfig, _manifest_state: ManifestState) -> AppState {
    let registry = RegistryStore::open(&config.registry_db_path).unwrap();
    let challenges = ChallengeManager::new(Duration::from_secs(config.challenge_ttl_secs));
    let signer = ManifestSigner::from_base64(&config.signing_key_b64).unwrap();
    AppState {
        manifest: ManifestService::new(config.clone(), signer, registry.clone()),
        registry,
        challenges,
        tokens: config.operator_tokens.clone(),
        admin_tokens: config.admin_tokens.clone(),
        rate_limiter: edge_bootstrap::api::RateLimiter::new(5.0, 10.0),
    }
}

fn test_config(db_path: PathBuf) -> AppConfig {
    AppConfig {
        bind_addr: default_bind_addr(),
        epoch: 1,
        ttl_secs: 600,
        signing_key_b64: TEST_SIGNING_KEY_B64.clone(),
        peers: vec![PeerRecord {
            peer_id: "peer1".into(),
            addrs: vec!["/ip4/127.0.0.1/tcp/4001".into()],
            tags: vec!["bootstrap".into()],
            weight: 100,
        }],
        static_base_urls: vec!["https://static.example.com".into()],
        revoked_peer_ids: vec![],
        cache_max_age_secs: 60,
        operator_tokens: OperatorTokens::default(),
        admin_tokens: OperatorTokens::default(),
        registry_db_path: db_path,
        challenge_ttl_secs: 120,
        registry_enabled: false,
    }
}

#[test]
fn test_sign_and_verify_manifest_ok() {
    let dir = tempdir().unwrap();
    let config = test_config(dir.path().join("reg1.db"));
    let signer = ManifestSigner::from_base64(&config.signing_key_b64).unwrap();
    let state = build_manifest_state(&config, &signer).unwrap();

    let unsigned = state.manifest.without_signature();
    let canonical = unsigned.canonical_bytes().unwrap();
    let sig_bytes = STANDARD_NO_PAD.decode(&state.manifest.signature).unwrap();
    let signature = Signature::from_bytes(&sig_bytes.try_into().expect("signature length matches"));
    signer
        .verifying_key()
        .verify(&canonical, &signature)
        .expect("signature verifies");
}

#[test]
fn test_manifest_tamper_fails_verify() {
    let dir = tempdir().unwrap();
    let config = test_config(dir.path().join("reg2.db"));
    let signer = ManifestSigner::from_base64(&config.signing_key_b64).unwrap();
    let state = build_manifest_state(&config, &signer).unwrap();

    let mut tampered: BootstrapManifestV1 = state.manifest.clone();
    tampered.bootstrap_peers[0].addrs[0] = "/ip4/127.0.0.2/tcp/5001".into();

    let unsigned = tampered.without_signature();
    let canonical = unsigned.canonical_bytes().unwrap();
    let sig_bytes = STANDARD_NO_PAD.decode(&tampered.signature).unwrap();
    let signature = Signature::from_bytes(&sig_bytes.try_into().expect("signature length matches"));
    let verify_result = signer.verifying_key().verify(&canonical, &signature);
    assert!(
        verify_result.is_err(),
        "tampered manifest must fail verification"
    );
}

#[test]
fn test_etag_changes_when_manifest_changes() {
    let dir = tempdir().unwrap();
    let config = test_config(dir.path().join("reg3.db"));
    let signer = ManifestSigner::from_base64(&config.signing_key_b64).unwrap();
    let state_a = build_manifest_state(&config, &signer).unwrap();

    let mut config_b = config.clone();
    config_b.epoch = config.epoch + 1;
    let state_b = build_manifest_state(&config_b, &signer).unwrap();

    assert_ne!(state_a.etag, state_b.etag);
}

#[tokio::test]
async fn test_manifest_endpoint_headers() {
    let dir = tempdir().unwrap();
    let config = test_config(dir.path().join("reg4.db"));
    let signer = ManifestSigner::from_base64(&config.signing_key_b64).unwrap();
    let manifest_state = build_manifest_state(&config, &signer).unwrap();
    let app_state = build_app_state(&config, manifest_state.clone());
    let app = router(app_state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/bootstrap/manifest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let cache_control = response.headers().get("cache-control").unwrap();
    assert!(
        cache_control
            .to_str()
            .unwrap()
            .starts_with("public, max-age=")
    );
    let etag = response
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("signature").is_some());

    let response_304 = router(app_state)
        .oneshot(
            Request::builder()
                .uri("/bootstrap/manifest")
                .header("if-none-match", etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response_304.status(), StatusCode::NOT_MODIFIED);
}
