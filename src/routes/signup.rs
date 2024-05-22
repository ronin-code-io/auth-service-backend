use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    domain::{AuthApiError, Email, Password, User, UserStoreError},
    AppState,
};

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthApiError> {
    let email =
        Email::parse(&request.email).or_else(|_| return Err(AuthApiError::InvalidCredentials))?;
    let password = Password::parse(&request.password)
        .or_else(|_| return Err(AuthApiError::InvalidCredentials))?;

    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    match user_store.add_user(user).await {
        Err(UserStoreError::UserAlreadyExists) => return Err(AuthApiError::UserAlreadyExists),
        Err(_) => return Err(AuthApiError::UnexpectedError),
        Ok(_) => (),
    };

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SignupResponse {
    pub message: String,
}
