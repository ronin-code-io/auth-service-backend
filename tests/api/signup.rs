use auth_service::{routes::SignupResponse, ErrorResponse};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;
    let password = "password123";

    let test_cases = [
        serde_json::json!({
            "email": get_random_email(),
            "password": password,
            "requires2FA": false,
        }),
        serde_json::json!({
            "email": get_random_email(),
            "password": password,
            "requires2FA": true,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            201,
            "Failed for input {:?}",
            test_case,
        );

        let expected_response = SignupResponse {
            message: "User created successfully!".to_owned(),
        };

        assert_eq!(
            response
                .json::<SignupResponse>()
                .await
                .expect("Could not deserialize response body to UserBody"),
            expected_response
        );
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
            "email":"123456",
            "password": "password123",
            "requires2FA": true,
        }),
        serde_json::json!({
            "email": get_random_email(),
            "password": "",
            "requires2FA": true,
        }),
        serde_json::json!({
            "email": "",
            "password": "password123",
            "requires2FA": false,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(&test_case).await;
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
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;
    let password = "password123";

    let test_case = serde_json::json!({
        "email": get_random_email(),
        "password": password,
        "requires2FA": false,
    });

    let response_one = app.post_signup(&test_case).await;
    let response_two = app.post_signup(&test_case).await;

    assert_eq!(
        response_one.status().as_u16(),
        201,
        "Failed for input {:?}",
        test_case,
    );
    assert_eq!(
        response_two.status().as_u16(),
        409,
        "Failed for input {:?}",
        test_case,
    );

    assert_eq!(
        response_two
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    )
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true,
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true,
        }),
        serde_json::json!({
            "password": "password123",
            "email": random_email,
        }),
        serde_json::json!({
            "trash": 0,
        }),
        serde_json::json!({}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(&test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input {:?}",
            test_case,
        );
    }
}
