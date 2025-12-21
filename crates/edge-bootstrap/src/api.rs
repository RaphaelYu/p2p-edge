use crate::auth::{OperatorTokens, parse_bearer};
use crate::challenge::{ChallengeError, ChallengeManager};
use crate::health::health;
use crate::manifest::ManifestService;
use crate::registry::{NodeStatus, RegistryStore};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, ETAG, IF_NONE_MATCH},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use time::format_description::well_known::Rfc3339;

#[derive(Clone)]
pub struct AppState {
    pub manifest: ManifestService,
    pub registry: RegistryStore,
    pub challenges: ChallengeManager,
    pub tokens: OperatorTokens,
    pub admin_tokens: OperatorTokens,
    pub rate_limiter: RateLimiter,
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<RateLimiterState>>,
}

#[derive(Debug)]
struct RateLimiterState {
    tokens: f64,
    last: Instant,
    rate_per_sec: f64,
    burst: f64,
}

impl RateLimiter {
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RateLimiterState {
                tokens: burst,
                last: Instant::now(),
                rate_per_sec,
                burst,
            })),
        }
    }

    pub fn allow(&self) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let now = Instant::now();
        let elapsed = now.duration_since(guard.last).as_secs_f64();
        guard.tokens = (guard.tokens + elapsed * guard.rate_per_sec).min(guard.burst);
        guard.last = now;
        if guard.tokens >= 1.0 {
            guard.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// This service only serves the signed bootstrap manifest and health; it does not parse or proxy client payloads.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/bootstrap/manifest", get(manifest_handler))
        .route("/registry/challenge", post(issue_challenge))
        .route("/registry/enroll", post(enroll_node))
        .route("/registry/approve", post(approve_node))
        .route("/registry/reject", post(reject_node))
        .route("/registry/revoke", post(revoke_node))
        .route("/registry/nodes", get(list_nodes))
        .route("/registry/node/:peer_id", get(get_node))
        .with_state(Arc::new(state))
}

async fn manifest_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let manifest_state = match state.manifest.current() {
        Ok(m) => m,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("manifest_error: {e}"),
            );
        }
    };
    let quoted_etag = format!("\"{}\"", manifest_state.etag);

    if let Some(inm) = headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if inm.trim_matches('"') == manifest_state.etag {
            let mut response = StatusCode::NOT_MODIFIED.into_response();
            attach_cache_headers(&mut response, &manifest_state.cache_control, &quoted_etag);
            return response;
        }
    }

    let mut response = Json(manifest_state.manifest.clone()).into_response();
    *response.status_mut() = StatusCode::OK;
    attach_cache_headers(&mut response, &manifest_state.cache_control, &quoted_etag);
    response
}

#[derive(Deserialize)]
struct ChallengeRequest {
    peer_id: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    challenge: String,
    expires_at: String,
}

async fn issue_challenge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChallengeRequest>,
) -> Response {
    if !state.rate_limiter.allow() {
        return error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let _operator_id = match authenticate(&headers, &state.tokens) {
        Ok(id) => id,
        Err(err) => return error_response(err.status, err.message),
    };
    let (challenge, expires_at) = match state.challenges.issue(&payload.peer_id) {
        Ok(v) => v,
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "challenge_unavailable");
        }
    };
    let expires = expires_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| "invalid".to_string());
    let response = ChallengeResponse {
        challenge,
        expires_at: expires,
    };
    Json(response).into_response()
}

#[derive(Deserialize)]
struct EnrollRequest {
    peer_id: String,
    addrs: Vec<String>,
    signature: String,
    pubkey: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    weight: Option<u16>,
}

#[derive(Serialize)]
struct EnrollResponse {
    status: &'static str,
    peer_id: String,
    operator_id: String,
}

async fn enroll_node(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<EnrollRequest>,
) -> Response {
    if !state.rate_limiter.allow() {
        return error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    if payload.addrs.is_empty() || payload.addrs.len() > 32 {
        return error_response(StatusCode::BAD_REQUEST, "invalid_addrs_count");
    }
    if payload.addrs.iter().any(|a| a.len() > 512) {
        return error_response(StatusCode::BAD_REQUEST, "addr_too_long");
    }
    if payload.tags.len() > 16 || payload.tags.iter().any(|t| t.len() > 64) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_tags");
    }
    let operator_id = match authenticate(&headers, &state.tokens) {
        Ok(id) => id,
        Err(err) => return error_response(err.status, err.message),
    };

    let challenge_bytes = match state.challenges.take(&payload.peer_id) {
        Ok(challenge) => challenge,
        Err(ChallengeError::NotFound) => {
            return error_response(StatusCode::BAD_REQUEST, "challenge_not_found");
        }
        Err(ChallengeError::Expired) => {
            return error_response(StatusCode::BAD_REQUEST, "challenge_expired");
        }
        Err(ChallengeError::Poisoned) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "challenge_unavailable");
        }
    };

    let pubkey_bytes = match STANDARD_NO_PAD
        .decode(&payload.pubkey)
        .or_else(|_| STANDARD.decode(&payload.pubkey))
    {
        Ok(bytes) if bytes.len() == 32 => bytes,
        Ok(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_pubkey_length"),
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_pubkey"),
    };
    let signature_bytes = match STANDARD_NO_PAD
        .decode(&payload.signature)
        .or_else(|_| STANDARD.decode(&payload.signature))
    {
        Ok(bytes) => bytes,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_signature"),
    };
    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_signature"),
    };
    let pubkey_array: [u8; 32] = match pubkey_bytes.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_pubkey_length"),
    };
    let verifying_key = match VerifyingKey::from_bytes(&pubkey_array) {
        Ok(k) => k,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_pubkey"),
    };
    if verifying_key.verify(&challenge_bytes, &signature).is_err() {
        return error_response(StatusCode::UNAUTHORIZED, "signature_verification_failed");
    }

    let weight = payload.weight.unwrap_or(100);
    if let Err(e) = state.registry.upsert_pending(
        &payload.peer_id,
        payload.addrs.clone(),
        &operator_id,
        payload.tags.clone(),
        weight,
        Some(payload.pubkey.clone()),
    ) {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store_error: {e}"),
        );
    }

    let response = EnrollResponse {
        status: "pending",
        peer_id: payload.peer_id,
        operator_id,
    };
    (StatusCode::OK, Json(response)).into_response()
}

#[derive(Deserialize)]
struct StatusChangeRequest {
    peer_id: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Serialize)]
struct StatusChangeResponse {
    status: String,
    peer_id: String,
    actor: String,
}

async fn approve_node(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<StatusChangeRequest>,
) -> Response {
    if !state.rate_limiter.allow() {
        return error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let actor = match authenticate(&headers, &state.admin_tokens) {
        Ok(id) => id,
        Err(err) => return error_response(err.status, err.message),
    };
    match state.registry.set_status(
        &payload.peer_id,
        NodeStatus::Active,
        &actor,
        payload.reason.clone(),
    ) {
        Ok(_) => Json(StatusChangeResponse {
            status: "Active".to_string(),
            peer_id: payload.peer_id,
            actor,
        })
        .into_response(),
        Err(e) => error_response(
            StatusCode::BAD_REQUEST,
            &format!("status_change_failed: {e}"),
        ),
    }
}

async fn reject_node(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<StatusChangeRequest>,
) -> Response {
    if !state.rate_limiter.allow() {
        return error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let actor = match authenticate(&headers, &state.admin_tokens) {
        Ok(id) => id,
        Err(err) => return error_response(err.status, err.message),
    };
    match state.registry.set_status(
        &payload.peer_id,
        NodeStatus::Rejected,
        &actor,
        payload.reason.clone(),
    ) {
        Ok(_) => Json(StatusChangeResponse {
            status: "Rejected".to_string(),
            peer_id: payload.peer_id,
            actor,
        })
        .into_response(),
        Err(e) => error_response(
            StatusCode::BAD_REQUEST,
            &format!("status_change_failed: {e}"),
        ),
    }
}

async fn revoke_node(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<StatusChangeRequest>,
) -> Response {
    if !state.rate_limiter.allow() {
        return error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let actor = match authenticate(&headers, &state.admin_tokens) {
        Ok(id) => id,
        Err(err) => return error_response(err.status, err.message),
    };
    match state.registry.set_status(
        &payload.peer_id,
        NodeStatus::Revoked,
        &actor,
        payload.reason.clone(),
    ) {
        Ok(_) => Json(StatusChangeResponse {
            status: "Revoked".to_string(),
            peer_id: payload.peer_id,
            actor,
        })
        .into_response(),
        Err(e) => error_response(
            StatusCode::BAD_REQUEST,
            &format!("status_change_failed: {e}"),
        ),
    }
}

#[derive(Deserialize)]
struct ListParams {
    status: Option<String>,
}

async fn list_nodes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    if let Err(err) = authenticate(&headers, &state.admin_tokens) {
        return error_response(err.status, err.message);
    }
    let status = match params.status.as_deref() {
        None => None,
        Some("pending") => Some(NodeStatus::Pending),
        Some("active") => Some(NodeStatus::Active),
        Some("revoked") => Some(NodeStatus::Revoked),
        Some("rejected") => Some(NodeStatus::Rejected),
        Some(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_status"),
    };
    match state.registry.list_by_status(status) {
        Ok(nodes) => Json(nodes).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store_error: {e}"),
        ),
    }
}

async fn get_node(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(peer_id): Path<String>,
) -> Response {
    if let Err(err) = authenticate(&headers, &state.admin_tokens) {
        return error_response(err.status, err.message);
    }
    match state.registry.get(&peer_id) {
        Ok(Some(node)) => Json(node).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "not_found"),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store_error: {e}"),
        ),
    }
}

fn attach_cache_headers(response: &mut Response, cache_control: &str, etag: &str) {
    if let Ok(value) = HeaderValue::from_str(cache_control) {
        response.headers_mut().insert(CACHE_CONTROL, value);
    }
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(ETAG, value);
    }
}

struct AuthError {
    status: StatusCode,
    message: &'static str,
}

fn authenticate(headers: &HeaderMap, tokens: &OperatorTokens) -> Result<String, AuthError> {
    if tokens.is_empty() {
        return Err(AuthError {
            status: StatusCode::UNAUTHORIZED,
            message: "operator_tokens_not_configured",
        });
    }
    let header = match headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        Some(h) => h,
        None => {
            return Err(AuthError {
                status: StatusCode::UNAUTHORIZED,
                message: "missing_authorization",
            });
        }
    };
    let token = match parse_bearer(header) {
        Some(t) => t,
        None => {
            return Err(AuthError {
                status: StatusCode::UNAUTHORIZED,
                message: "invalid_authorization_format",
            });
        }
    };
    if let Some(operator_id) = tokens.authenticate(token) {
        Ok(operator_id)
    } else {
        Err(AuthError {
            status: StatusCode::UNAUTHORIZED,
            message: "invalid_token",
        })
    }
}

fn error_response(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({ "error": message });
    (status, Json(body)).into_response()
}
