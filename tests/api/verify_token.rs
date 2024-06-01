use auth_service::{utils::JWT_COOKIE_NAME, ErrorResponse};
use serde_json::json;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    let test_cases = [
        json!({
            "token": "",
        }),
        json!({
            "token": "Invalid",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_token(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            401,
            "Failed for input {:?}",
            test_case,
        );

        let error = response
            .json::<ErrorResponse>()
            .await
            .expect("Failed to deserialize response body")
            .error;

        assert_eq!(
            error, "Invalid auth token",
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "password";

    let signup_body = json!({
        "email": random_email,
        "password": password,
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = json!({
        "email": random_email,
        "password": password,
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("Could not find auth cookie");

    assert!(!auth_cookie.value().is_empty());

    let token = auth_cookie.value();

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200);

    let verify_token_body = serde_json::json!({
        "token": token,
    });

    let response = app.post_verify_token(&verify_token_body).await;

    assert_eq!(response.status().as_u16(), 401);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid auth token".to_owned()
    );
}

#[tokio::test]
async fn should_return_422_if_invalid_input() {
    let app = TestApp::new().await;

    let test_cases = [
        json!({
            "token": true,
        }),
        json!({
            "token": 42,
        }),
        json!({
            "qwerty": "asdf",
        }),
        json!({}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_token(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input {:?}",
            test_case,
        );
    }
}

#[tokio::test]
async fn should_return_200_if_valid_token() {
    let app = TestApp::new().await;

    let email = get_random_email();
    let signup_body = json!({
        "email": email,
        "password": "some_strong_passwd",
        "requires2FA": false,
    });

    let signup_response = app.post_signup(&signup_body).await;

    assert_eq!(signup_response.status().as_u16(), 201);

    let login_response = app.post_login(&signup_body).await;

    assert_eq!(login_response.status().as_u16(), 200);

    let auth_cookie = login_response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("Failed to find auth Cooke");

    assert!(!auth_cookie.value().is_empty());

    let token = auth_cookie.value();

    let response = app
        .post_verify_token(&json!({
            "token": token,
        }))
        .await;

    assert_eq!(response.status().as_u16(), 200)
}
