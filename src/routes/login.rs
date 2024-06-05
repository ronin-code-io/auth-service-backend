use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password},
    utils::generate_auth_cookie,
};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = Email::parse(&request.email);
    let password = Password::parse(&request.password);

    if email.is_err() || password.is_err() {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    }

    let user_store = &state.user_store.read().await;

    let email = email.unwrap();
    let password = password.unwrap();

    match user_store.validate_user(&email, &password).await {
        Ok(()) => (),
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    let user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    match user.requires_2fa {
        true => handle_2fa(jar).await,
        false => handle_no_2fa(&user.email, jar).await,
    }
}

async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = generate_auth_cookie(&email);

    if auth_cookie.is_err() {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    let updated_jar = jar.add(auth_cookie.unwrap());

    (
        updated_jar,
        Ok((StatusCode::OK, Json::from(LoginResponse::RegularAuth))),
    )
}

async fn handle_2fa(
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let response = TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: "123456".to_owned(),
    };

    (
        jar,
        Ok((StatusCode::PARTIAL_CONTENT, Json::from(LoginResponse::TwoFactorAuth(response)))),
    )
}
