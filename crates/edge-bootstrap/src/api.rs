use crate::health::health;
use crate::manifest::ManifestState;
use axum::{
    Json, Router,
    extract::State,
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, ETAG, IF_NONE_MATCH},
    },
    response::{IntoResponse, Response},
    routing::get,
};

// This service only serves the signed bootstrap manifest and health; it does not parse or proxy client payloads.
pub fn router(state: ManifestState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/bootstrap/manifest", get(manifest_handler))
        .with_state(state)
}

async fn manifest_handler(State(state): State<ManifestState>, headers: HeaderMap) -> Response {
    let quoted_etag = format!("\"{}\"", state.etag);

    if let Some(inm) = headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if inm.trim_matches('"') == state.etag {
            let mut response = StatusCode::NOT_MODIFIED.into_response();
            attach_cache_headers(&mut response, &state.cache_control, &quoted_etag);
            return response;
        }
    }

    let mut response = Json(state.manifest.clone()).into_response();
    *response.status_mut() = StatusCode::OK;
    attach_cache_headers(&mut response, &state.cache_control, &quoted_etag);
    response
}

fn attach_cache_headers(response: &mut Response, cache_control: &str, etag: &str) {
    if let Ok(value) = HeaderValue::from_str(cache_control) {
        response.headers_mut().insert(CACHE_CONTROL, value);
    }
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(ETAG, value);
    }
}
