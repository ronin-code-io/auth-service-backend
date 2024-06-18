use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie::Cookie, CookieJar};

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{validate_token, JWT_COOKIE_NAME},
};

#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let cookie = jar.get(JWT_COOKIE_NAME);

    match cookie {
        None => return (jar, Err(AuthAPIError::MissingToken)),
        Some(_) => (),
    }

    let cookie = cookie.unwrap();
    let token = cookie.value().to_owned();
    let banned_token_store = state.banned_token_store;

    if validate_token(&token, banned_token_store.clone())
        .await
        .is_err()
    {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    if let Err(e) = banned_token_store
        .write()
        .await
        .add_token(token)
        .await
    {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    };

    let static_cookie = Cookie::from(JWT_COOKIE_NAME);
    let jar = jar.remove(static_cookie);

    (jar, Ok(StatusCode::OK.into_response()))
}
