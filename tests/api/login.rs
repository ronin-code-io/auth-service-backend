use auth_service::domain::Email;
use auth_service::{routes::TwoFactorAuthResponse, utils::JWT_COOKIE_NAME, ErrorResponse};
use serde_json::json;
use std::borrow::Borrow;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new().await;

    let credentials = json!({
        "incorrect": "credentials",
    });
    let response = app.post_login(&credentials).await;

    assert_eq!(response.status().as_u16(), 422);
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let test_cases = [
        json!({
            "email": get_random_email(),
            "password": "",
        }),
        json!({
            "email": "test@rand.email",
            "password": "",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input {:?}",
            test_case,
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        )
    }
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let known_email = "test@e.mail";

    let mut app = TestApp::new().await;

    app.post_signup(
        json!({
            "email": known_email,
            "password": "StrongPassword",
        })
        .borrow(),
    )
    .await;

    let test_cases = [
        json!({
            "email": get_random_email(),
            "password": "incorrect_password",
        }),
        json!({
            "email": known_email,
            "password": "incorrect_password",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            401,
            "Failed for input {:?}",
            test_case,
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Incorrect credentials".to_owned()
        )
    }

    app.delete_account(
        json!({
            "email": known_email,
        })
        .borrow(),
    )
    .await;
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "strong_password";

    let signup_body = json!({
        "email": random_email,
        "password": password,
        "requires2FA": false,
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
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();
    let password = "strong_password";

    let signup_body = json!({
        "email": random_email,
        "password": password,
        "requires2FA": true,
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = json!({
        "email": random_email,
        "password": password,
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let response_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to ErrorResponse");

    assert_eq!(response_body.message, "2FA required");

    assert!(!response_body.login_attempt_id.is_empty());

    let email = Email::parse(&random_email).expect("Could not parse email.");

    let contains_code = app.two_fa_code_store.write().await.get_code(&email).await;

    assert!(
        contains_code.is_ok(),
        "2FA store should contain code and attempt id."
    );
    app.clean_up().await;
}
