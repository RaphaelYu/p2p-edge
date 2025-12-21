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
use edge_bootstrap::manifest::ManifestService;
use edge_bootstrap::registry::{NodeStatus, RegistryStore};
use edge_bootstrap::signer::ManifestSigner;
use hyper::StatusCode;
use serde_json::Value;
use std::time::Duration;
use tempfile::tempdir;
use tower::ServiceExt;

fn make_config(registry_path: &std::path::Path) -> AppConfig {
    let signing_key_b64 = STANDARD_NO_PAD.encode([7u8; 32]);
    AppConfig {
        bind_addr: default_bind_addr(),
        epoch: 1,
        ttl_secs: 600,
        signing_key_b64,
        peers: vec![],
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
        registry_db_path: registry_path.to_path_buf(),
        challenge_ttl_secs: 120,
        registry_enabled: true,
    }
}

fn make_app(config: &AppConfig) -> AppState {
    let registry = RegistryStore::open(&config.registry_db_path).unwrap();
    let signer = ManifestSigner::from_base64(&config.signing_key_b64).unwrap();
    let manifest = ManifestService::new(config.clone(), signer, registry.clone());
    let challenges = ChallengeManager::new(Duration::from_secs(config.challenge_ttl_secs));
    AppState {
        manifest,
        registry,
        challenges,
        tokens: config.operator_tokens.clone(),
        admin_tokens: config.admin_tokens.clone(),
        rate_limiter: edge_bootstrap::api::RateLimiter::new(5.0, 10.0),
    }
}

async fn enroll_peer(app: &axum::Router, peer_id: &str, token: &str, key: &SigningKey) {
    let challenge_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/registry/challenge")
                .header("Authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"peer_id":"{peer_id}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(challenge_resp.status(), StatusCode::OK);
    let bytes = to_bytes(challenge_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let challenge = STANDARD_NO_PAD
        .decode(v.get("challenge").unwrap().as_str().unwrap())
        .unwrap();
    let signature = key.sign(&challenge);
    let signature_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());
    let pubkey_b64 = STANDARD_NO_PAD.encode(key.verifying_key().to_bytes());
    let enroll_body = serde_json::json!({
        "peer_id": peer_id,
        "addrs": ["/ip4/10.0.0.1/tcp/4001"],
        "signature": signature_b64,
        "pubkey": pubkey_b64
    });
    let enroll = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/registry/enroll")
                .header("Authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(enroll_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(enroll.status(), StatusCode::OK);
}

#[tokio::test]
async fn challenge_then_enroll_ok() {
    let dir = tempdir().unwrap();
    let config = make_config(&dir.path().join("db1.sqlite"));
    let app = router(make_app(&config));
    let key = SigningKey::from_bytes(&[9u8; 32]);
    enroll_peer(&app, "peer-ok", "op_secret", &key).await;
}

#[tokio::test]
async fn enroll_with_wrong_signature_fails() {
    let dir = tempdir().unwrap();
    let config = make_config(&dir.path().join("db2.sqlite"));
    let app = router(make_app(&config));

    // obtain challenge
    let challenge_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/registry/challenge")
                .header("Authorization", "Bearer op_secret")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"peer_id":"peer-bad"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(challenge_resp.status(), StatusCode::OK);
    let bytes = to_bytes(challenge_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let challenge = STANDARD_NO_PAD
        .decode(v.get("challenge").unwrap().as_str().unwrap())
        .unwrap();

    // sign with wrong key but present a different valid pubkey to force verify failure
    let wrong_key = SigningKey::from_bytes(&[5u8; 32]);
    let other_key = SigningKey::from_bytes(&[6u8; 32]);
    let signature = wrong_key.sign(&challenge);
    let enroll_body = serde_json::json!({
        "peer_id": "peer-bad",
        "addrs": ["/ip4/10.0.0.1/tcp/4001"],
        "signature": STANDARD_NO_PAD.encode(signature.to_bytes()),
        "pubkey": STANDARD_NO_PAD.encode(other_key.verifying_key().to_bytes())
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
    assert_eq!(enroll.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn approve_requires_admin() {
    let dir = tempdir().unwrap();
    let config = make_config(&dir.path().join("db3.sqlite"));
    let app = router(make_app(&config));
    let key = SigningKey::from_bytes(&[11u8; 32]);
    enroll_peer(&app, "peer-approve", "op_secret", &key).await;

    let approve = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/registry/approve")
                .header("Authorization", "Bearer op_secret") // operator, not admin
                .header("content-type", "application/json")
                .body(Body::from(r#"{"peer_id":"peer-approve"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(approve.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_removes_from_manifest_and_adds_to_revoked() {
    let dir = tempdir().unwrap();
    let config = make_config(&dir.path().join("db4.sqlite"));
    let app_state = make_app(&config);
    let app = router(app_state.clone());
    let key = SigningKey::from_bytes(&[12u8; 32]);
    enroll_peer(&app, "peer-revoke", "op_secret", &key).await;

    // approve
    let approve = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/registry/approve")
                .header("Authorization", "Bearer admin_secret")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"peer_id":"peer-revoke"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(approve.status(), StatusCode::OK);

    // manifest should include peer
    let m1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/bootstrap/manifest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(m1.status(), StatusCode::OK);
    let etag_before = m1
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let body = to_bytes(m1.into_body(), usize::MAX).await.unwrap();
    let v1: Value = serde_json::from_slice(&body).unwrap();
    let peers1 = v1.get("bootstrap_peers").unwrap().as_array().unwrap();
    assert!(
        peers1
            .iter()
            .any(|p| p.get("peer_id").unwrap() == "peer-revoke")
    );

    // revoke
    let revoke = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/registry/revoke")
                .header("Authorization", "Bearer admin_secret")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"peer_id":"peer-revoke"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::OK);

    // manifest should drop peer and include revoked id; etag changes
    let m2 = app
        .oneshot(
            Request::builder()
                .uri("/bootstrap/manifest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(m2.status(), StatusCode::OK);
    let etag_after = m2
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(etag_before, etag_after);
    let body2 = to_bytes(m2.into_body(), usize::MAX).await.unwrap();
    let v2: Value = serde_json::from_slice(&body2).unwrap();
    let peers2 = v2.get("bootstrap_peers").unwrap().as_array().unwrap();
    assert!(
        !peers2
            .iter()
            .any(|p| p.get("peer_id").unwrap() == "peer-revoke")
    );
    let revoked = v2.get("revoked_peer_ids").unwrap().as_array().unwrap();
    assert!(revoked.iter().any(|id| id == "peer-revoke"));
}

#[tokio::test]
async fn etag_changes_on_registry_change() {
    let dir = tempdir().unwrap();
    let config = make_config(&dir.path().join("db5.sqlite"));
    let app_state = make_app(&config);
    let app = router(app_state.clone());
    let key = SigningKey::from_bytes(&[13u8; 32]);
    enroll_peer(&app, "peer-etag", "op_secret", &key).await;

    // initial manifest (pending only, not active)
    let m1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/bootstrap/manifest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let etag1 = m1
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // approve to make it active
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/registry/approve")
                .header("Authorization", "Bearer admin_secret")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"peer_id":"peer-etag"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    let m2 = app
        .oneshot(
            Request::builder()
                .uri("/bootstrap/manifest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let etag2 = m2
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(etag1, etag2);
}
