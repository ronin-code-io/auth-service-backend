use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformd_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "request2FA": true,
        }),
        serde_json::json!({
            "email": random_email,
            "request2FA": true,
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

// #[tokio::test]
// async fn should_return_201_if_valid_input() {
//     let _app = TestApp::new().await;

//     // TODO
//     todo!();
// }
