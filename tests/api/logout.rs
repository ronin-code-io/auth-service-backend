use crate::helpers::get_random_email;
use auth_service::{
    domain::Email,
    utils::{constants::JWT_COOKIE_NAME, generate_auth_cookie},
    ErrorResponse,
};
use reqwest::{self, Url};

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let mut app = TestApp::new().await;

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 400);

    let error_response: ErrorResponse = response.json().await.unwrap();
    assert_eq!(error_response.error, "Missing cookie");
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;

    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid_token; HttpOnly; SameSite=Lax; Secure; Patch=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse url"),
    );

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 401);

    let error_response: ErrorResponse = response.json().await.unwrap();
    assert_eq!(error_response.error, "Invalid auth token");
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200, "Failed to login");

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let token = auth_cookie.value();

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200, "Failed to logout");

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(auth_cookie.value().is_empty());

    let banned_token_store = app.banned_token_store.clone();
    let contains_token = banned_token_store
        .read()
        .await
        .contains_token(token)
        .await
        .expect("Failed to check if token is banned");

    assert!(contains_token);
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let mut app = TestApp::new().await;

    let email = Email::parse(&get_random_email()).expect("Could not generate email");
    let cookie = generate_auth_cookie(&email).expect("Could not generate cookie");

    app.cookie_jar.add_cookie_str(
        &cookie.to_string(),
        &Url::parse("http://127.0.0.1").expect("Failed to parse url"),
    );

    assert_eq!(app.post_logout().await.status().as_u16(), 200);

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 400);
    app.clean_up().await;
}
