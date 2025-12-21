use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use edge_bootstrap::api::{AppState, router};
use edge_bootstrap::auth::OperatorTokens;
use edge_bootstrap::challenge::ChallengeManager;
use edge_bootstrap::config::{AppConfig, default_bind_addr};
use edge_bootstrap::manifest::{ManifestService, PeerRecord};
use edge_bootstrap::registry::RegistryStore;
use edge_bootstrap::signer::ManifestSigner;
use hyper::StatusCode;
use std::time::Duration;
use tempfile::{TempDir, tempdir};
use tower::ServiceExt;

fn base_app_state(challenge_ttl: u64) -> (AppState, RegistryStore, TempDir) {
    let dir = tempdir().unwrap();
    let registry_path = dir.path().join("registry.db");
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let signing_key_b64 = STANDARD_NO_PAD.encode(signing_key.to_bytes());
    let config = AppConfig {
        bind_addr: default_bind_addr(),
        epoch: 1,
        ttl_secs: 600,
        signing_key_b64,
        peers: vec![PeerRecord {
            peer_id: "peer1".into(),
            addrs: vec!["/ip4/127.0.0.1/tcp/4001".into()],
            tags: vec![],
            weight: 100,
        }],
        static_base_urls: vec![],
        revoked_peer_ids: vec![],
        cache_max_age_secs: 60,
        operator_tokens: OperatorTokens::from_plain(vec![(
            "ops-1".to_string(),
            "op_secret".to_string(),
        )]),
        admin_tokens: OperatorTokens::from_plain(vec![(
            "admin".to_string(),
            "admin_secret".to_string(),
        )]),
        registry_db_path: registry_path.clone(),
        challenge_ttl_secs: challenge_ttl,
        registry_enabled: true,
    };

    let signer = ManifestSigner::from_base64(&config.signing_key_b64).unwrap();
    let registry = RegistryStore::open(&registry_path).unwrap();
    let manifest_state = ManifestService::new(config.clone(), signer, registry.clone());
    let challenges = ChallengeManager::new(Duration::from_secs(challenge_ttl));

    let app_state = AppState {
        manifest: manifest_state,
        registry: registry.clone(),
        challenges,
        tokens: config.operator_tokens.clone(),
        admin_tokens: config.admin_tokens.clone(),
        rate_limiter: edge_bootstrap::api::RateLimiter::new(5.0, 10.0),
    };
    (app_state, registry, dir)
}

#[tokio::test]
async fn challenge_requires_auth() {
    let (state, _, _dir) = base_app_state(120);
    let app = router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/registry/challenge")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"peer_id":"peer-new"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn challenge_and_enroll_flow() {
    let (state, registry, _dir) = base_app_state(120);
    let app = router(state.clone());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/registry/challenge")
                .header("Authorization", "Bearer op_secret")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"peer_id":"peer-new"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let challenge_b64 = v.get("challenge").unwrap().as_str().unwrap();
    let challenge = STANDARD_NO_PAD.decode(challenge_b64).unwrap();

    let key = SigningKey::from_bytes(&[9u8; 32]);
    let signature = key.sign(&challenge);
    let signature_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());
    let pubkey_b64 = STANDARD_NO_PAD.encode(key.verifying_key().to_bytes());

    let enroll_body = serde_json::json!({
        "peer_id": "peer-new",
        "addrs": ["/ip4/10.0.0.1/tcp/4001"],
        "signature": signature_b64,
        "pubkey": pubkey_b64,
        "tags": ["bootstrap"],
        "weight": 120
    });

    let enroll = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/registry/enroll")
                .header("Authorization", "Bearer op_secret")
                .header("content-type", "application/json")
                .body(Body::from(enroll_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(enroll.status(), StatusCode::OK);
    let rec = registry.get("peer-new").unwrap().expect("stored");
    assert_eq!(rec.status, edge_bootstrap::registry::NodeStatus::Pending);
    assert_eq!(rec.operator_id, "ops-1");
    assert_eq!(rec.pubkey_b64.unwrap(), pubkey_b64);
}

#[tokio::test]
async fn challenge_expiry_blocks_enroll() {
    let (state, _, _dir) = base_app_state(1);
    let app = router(state.clone());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/registry/challenge")
                .header("Authorization", "Bearer op_secret")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"peer_id":"peer-expire"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let challenge_b64 = v.get("challenge").unwrap().as_str().unwrap();
    let challenge = STANDARD_NO_PAD.decode(challenge_b64).unwrap();

    let key = SigningKey::from_bytes(&[10u8; 32]);
    let signature = key.sign(&challenge);
    let signature_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());
    let pubkey_b64 = STANDARD_NO_PAD.encode(key.verifying_key().to_bytes());

    tokio::time::sleep(Duration::from_secs(2)).await;

    let enroll_body = serde_json::json!({
        "peer_id": "peer-expire",
        "addrs": ["/ip4/10.0.0.2/tcp/4001"],
        "signature": signature_b64,
        "pubkey": pubkey_b64
    });

    let enroll = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/registry/enroll")
                .header("Authorization", "Bearer op_secret")
                .header("content-type", "application/json")
                .body(Body::from(enroll_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(enroll.status(), StatusCode::BAD_REQUEST);
}
