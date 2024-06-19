use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use secrecy::Secret;
use serde::Deserialize;

use crate::{
    domain::{AuthAPIError, Email},
    AppState,
};

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    pub email: Secret<String>,
}

#[tracing::instrument(name = "Delete Account", skip_all)]
pub async fn delete_account(
    State(state): State<AppState>,
    Json(request): Json<DeleteAccountRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email).map_err(|_| AuthAPIError::InvalidCredentials)?;

    let mut user_store = state.user_store.write().await;

    match user_store.delete_user(&email).await {
        Err(_) => Err(AuthAPIError::UserNotFound),
        Ok(_) => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}
