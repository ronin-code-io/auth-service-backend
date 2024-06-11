use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode, TwoFACodeStoreError},
    utils::generate_auth_cookie,
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
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<VerifyTwoFactorAuthToken>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = Email::parse(&request.email);
    let login_attempt_id = LoginAttemptId::parse(&request.login_attempt_id);
    let two_fa_code = TwoFACode::parse(request.code.clone());

    if email.is_err() || login_attempt_id.is_err() || two_fa_code.is_err() {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    }
    let email = email.unwrap();
    let two_fa_code = two_fa_code.unwrap();
    let login_attempt_id = login_attempt_id.unwrap();

    let two_fa_code_store = state.two_fa_code_store.write().await;

    match two_fa_code_store.get_code(&email).await {
        Ok((stored_login_attempt_id, stored_two_fa_code)) => {
            if stored_login_attempt_id != login_attempt_id || stored_two_fa_code != two_fa_code {
                return (jar, Err(AuthAPIError::IncorrectCredentials));
            }

            let cookie = generate_auth_cookie(&email);

            if cookie.is_err() {
                return (jar, Err(AuthAPIError::UnexpectedError));
            }

            let updated_jar = jar.add(cookie.unwrap());

            return (updated_jar, Ok(StatusCode::OK.into_response()));
        }
        Err(TwoFACodeStoreError::LoginAttemptIdNotFound) => {
            (jar, Err(AuthAPIError::IncorrectCredentials))
        }
        Err(_) => (jar, Err(AuthAPIError::UnexpectedError)),
    }
}
