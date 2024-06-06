use crate::helpers::{get_random_email, TestApp};
use auth_service::domain::{LoginAttemptId, TwoFACode};
use serde_json::json;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let test_cases = [
        json!({}),
        json!({
            "mail": get_random_email(),
            "loginAttemptId": LoginAttemptId::default().as_ref(),
            "2FACode": "111111",
        }),
        json!({
            "email": get_random_email(),
            "loginAttempt": LoginAttemptId::default().as_ref(),
            "2FACode": "111111",
        }),
        json!({
            "email": get_random_email(),
            "loginAttemptId": LoginAttemptId::default().as_ref(),
            "FACode": "111111",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(&test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input {:?}",
            test_case,
        );
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let test_cases = [
        json!({
            "email": get_random_email(),
            "loginAttemptId": 123546,
            "2FACode": "111111",
        }),
        json!({
            "email": get_random_email(),
            "loginAttemptId": LoginAttemptId::default().as_ref(),
            "FACode": 123654,
        }),
        json!({
            "email": get_random_email(),
            "loginAttemptId": LoginAttemptId::default().as_ref(),
            "FACode": "asdf",
        }),
        json!({
            "email": get_random_email(),
            "loginAttemptId": "asdf",
            "FACode": TwoFACode::default().as_ref(),
        }),
        json!({
            "email": get_random_email(),
            "loginAttemptId": LoginAttemptId::default().as_ref(),
            "FACode": "123456789123456789",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(&test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input {:?}",
            test_case,
        );
    }
}
