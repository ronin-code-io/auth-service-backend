use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode},
};

#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyTwoFactorAuthToken {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub code: String,
}

pub async fn verify_2fa(
    State(_state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<VerifyTwoFactorAuthToken>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = Email::parse(&request.email);
    let login_attempt_id = LoginAttemptId::parse(&request.login_attempt_id);
    let two_fa_code = TwoFACode::parse(request.code.clone());

    if email.is_err() || login_attempt_id.is_err() || two_fa_code.is_err() {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    }

    (jar, Ok(StatusCode::OK.into_response()))
}
