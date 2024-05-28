use std::borrow::Borrow;

use auth_service::ErrorResponse;
use serde_json::json;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

    let credentials = json!({
        "incorrect": "credentials",
    });
    let response = app.post_login(&credentials).await;

    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

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
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let known_email = "test@e.mail";

    let app = TestApp::new().await;

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
}

#[tokio::test]
async fn login_returns_200() {
    let known_email = "test@e.mail";
    let password = "strong_password";

    let app = TestApp::new().await;

    app.post_signup(
        json!({
            "email": known_email,
            "password": password,
            "requires2FA": false
        })
        .borrow(),
    )
    .await;

    let response = app
        .post_login(
            json!({
                "email": known_email,
                "password": password,
            })
            .borrow(),
        )
        .await;

    assert_eq!(response.status().as_u16(), 200);
}
