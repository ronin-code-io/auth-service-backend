use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use secrecy::Secret;
use serde::Deserialize;

use crate::{app_state::AppState, domain::AuthAPIError, utils::validate_token};

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: Secret<String>,
}

#[tracing::instrument(name = "Verify Token", skip_all)]
pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    match validate_token(&request.token, state.banned_token_store).await {
        Ok(_) => Ok(StatusCode::OK.into_response()),
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}
