use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{domain::AuthAPIError, utils::validate_token};

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

pub async fn verify_token(
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let token = &request.token;

    match validate_token(token).await {
        Ok(_) => Ok(StatusCode::OK.into_response()),
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}
