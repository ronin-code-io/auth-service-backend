use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use secrecy::Secret;
use serde::Deserialize;

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode, TwoFACodeStoreError},
    utils::generate_auth_cookie,
};

#[derive(Deserialize, Debug)]
pub struct VerifyTwoFactorAuthToken {
    pub email: Secret<String>,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: Secret<String>,
    #[serde(rename = "2FACode")]
    pub code: Secret<String>,
}

#[tracing::instrument(name = "Verify 2FA code", skip_all)]
pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<VerifyTwoFactorAuthToken>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = Email::parse(request.email);
    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id);
    let two_fa_code = TwoFACode::parse(request.code.clone());

    if email.is_err() || login_attempt_id.is_err() || two_fa_code.is_err() {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    let email = email.unwrap();
    let login_attempt_id = login_attempt_id.unwrap();
    let two_fa_code = two_fa_code.unwrap();

    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    match two_fa_code_store.get_code(&email).await {
        Ok((stored_login_attempt_id, stored_two_fa_code)) => {
            if stored_login_attempt_id != login_attempt_id || stored_two_fa_code != two_fa_code {
                return (jar, Err(AuthAPIError::IncorrectCredentials));
            }

            let cookie = generate_auth_cookie(&email)
                .map_err(AuthAPIError::UnexpectedError)
                .unwrap();

            two_fa_code_store
                .remove_code(&email)
                .await
                .map_err(|e| AuthAPIError::UnexpectedError(e.into()))
                .unwrap();

            let updated_jar = jar.add(cookie);

            (updated_jar, Ok(StatusCode::OK.into_response()))
        }
        Err(TwoFACodeStoreError::LoginAttemptIdNotFound) => {
            (jar, Err(AuthAPIError::IncorrectCredentials))
        }
        Err(e) => (jar, Err(AuthAPIError::UnexpectedError(e.into()))),
    }
}
