use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{
    domain::{AuthApiError, Email},
    AppState,
};

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    pub email: String,
}

pub async fn delete_account(
    State(state): State<AppState>,
    Json(request): Json<DeleteAccountRequest>,
) -> Result<impl IntoResponse, AuthApiError> {
    let email =
        Email::parse(&request.email).or_else(|_| return Err(AuthApiError::InvalidCredentials))?;

    let mut user_store = state.user_store.write().await;

    match user_store.delete_user(&email).await {
        Err(_) => return Err(AuthApiError::UserNotFound),
        Ok(_) => return Ok(StatusCode::NO_CONTENT.into_response()),
    }
}
