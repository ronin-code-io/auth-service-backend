use axum::{http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie::Cookie, CookieJar};

use crate::{
    domain::AuthAPIError,
    utils::{validate_token, JWT_COOKIE_NAME},
};

pub async fn logout(jar: CookieJar) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let cookie = jar.get(JWT_COOKIE_NAME);

    match cookie {
        None => return (jar, Err(AuthAPIError::MissingToken)),
        Some(_) => (),
    }

    let cookie = cookie.unwrap();

    let token = validate_token(cookie.value()).await;

    if token.is_err() {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    let static_cookie = Cookie::from(JWT_COOKIE_NAME);
    let jar = jar.remove(static_cookie);

    (jar, Ok(StatusCode::OK.into_response()))
}
