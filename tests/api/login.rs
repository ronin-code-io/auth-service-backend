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


// #[tokio::test]
// async fn login_returns_200() {
//     let app = TestApp::new().await;

//     let response = app.post_login().await;

//     assert_eq!(response.status().as_u16(), 200);
// }
