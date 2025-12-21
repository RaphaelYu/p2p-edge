use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

pub async fn health() -> impl IntoResponse {
    let payload = HealthResponse { status: "ok" };
    (StatusCode::OK, Json(payload))
}
