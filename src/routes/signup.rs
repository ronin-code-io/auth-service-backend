use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    domain::{AuthApiError, User, UserStoreError},
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
    let email = request.email;
    let password = request.password;

    if email.is_empty()
        || !Regex::new(r"^\S+@\S+\.\S{2,}$").unwrap().is_match(&email)
        || password.len() < 8
    {
        return Err(AuthApiError::InvalidCredentials);
    }

    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    match user_store.add_user(user) {
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
