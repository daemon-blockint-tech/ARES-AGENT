use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};

/// API key authentication middleware.
///
/// Validates `Authorization: Bearer <api_key>` header against the configured key.
/// If no API key is configured (None), authentication is disabled.
pub async fn require_api_key(
    expected_key: Option<String>,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let Some(ref expected) = expected_key else {
        // No API key configured — auth disabled
        return Ok(next.run(req).await);
    };

    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let provided = header.trim_start_matches("Bearer ");
            if provided == expected {
                Ok(next.run(req).await)
            } else {
                Err((StatusCode::UNAUTHORIZED, "Invalid API key".to_string()))
            }
        }
        _ => Err((
            StatusCode::UNAUTHORIZED,
            "Missing or invalid Authorization header. Expected: Bearer <api_key>".to_string(),
        )),
    }
}
