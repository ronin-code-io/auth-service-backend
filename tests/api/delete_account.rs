use auth_service::ErrorResponse;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_204_if_valid_input_and_user_is_deleted() {
    let mut app = TestApp::new().await;

    let email = get_random_email();

    let user = serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false,
    })
    .take();

    let delete_payload = serde_json::json!({"email": email}).take();

    let signup_response = app.post_signup(&user).await;
    assert_eq!(
        signup_response.status().as_u16(),
        201,
        "Failed for input {:?}",
        user,
    );

    let delete_response = app.delete_account(&delete_payload).await;

    assert_eq!(
        delete_response.status().as_u16(),
        204,
        "Failed for input {:?}",
        email
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_404_if_user_not_found() {
    let mut app = TestApp::new().await;
    let email = get_random_email();
    let delete_payload = serde_json::json!({"email": email}).take();

    let delete_response = app.delete_account(&delete_payload).await;

    assert_eq!(
        delete_response.status().as_u16(),
        404,
        "Failed for input {:?}",
        delete_payload
    );

    assert_eq!(
        delete_response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User not found".to_owned()
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_email_is_malformed() {
    let mut app = TestApp::new().await;
    let delete_payload = serde_json::json!({"email": "wrong-email"}).take();

    let delete_response = app.delete_account(&delete_payload).await;

    assert_eq!(
        delete_response.status().as_u16(),
        400,
        "Failed for input {:?}",
        delete_payload
    );

    assert_eq!(
        delete_response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Invalid credentials".to_owned()
    );
    app.clean_up().await;
}
