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
    let app = TestApp::new().await;

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 400);

    let error_response: ErrorResponse = response.json().await.unwrap();
    assert_eq!(error_response.error, "Missing cookie");
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

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
    assert_eq!(error_response.error, "Invalid token");
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let app = TestApp::new().await;

    let email = Email::parse(&get_random_email()).expect("Could not generate email");
    let cookie = generate_auth_cookie(&email).expect("Could not generate cookie");

    app.cookie_jar.add_cookie_str(
        &cookie.to_string(),
        &Url::parse("http://127.0.0.1").expect("Failed to parse url"),
    );

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let app = TestApp::new().await;

    let email = Email::parse(&get_random_email()).expect("Could not generate email");
    let cookie = generate_auth_cookie(&email).expect("Could not generate cookie");

    app.cookie_jar.add_cookie_str(
        &cookie.to_string(),
        &Url::parse("http://127.0.0.1").expect("Failed to parse url"),
    );

    assert_eq!(app.post_logout().await.status().as_u16(), 200);

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 400);
}
