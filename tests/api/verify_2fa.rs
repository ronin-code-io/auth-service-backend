use crate::helpers::{get_random_email, TestApp};
use auth_service::{
    domain::Email, routes::TwoFactorAuthResponse, utils::JWT_COOKIE_NAME, ErrorResponse,
};
use secrecy::{ExposeSecret, Secret};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let test_cases = [
        json!({}),
        json!({
            "mail": get_random_email(),
            "loginAttemptId": Uuid::new_v4().to_string(),
            "2FACode": "111111",
        }),
        json!({
            "email": get_random_email(),
            "loginAttempt": Uuid::new_v4().to_string(),
            "2FACode": "111111",
        }),
        json!({
            "email": get_random_email(),
            "loginAttemptId": Uuid::new_v4().to_string(),
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
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let test_cases = [
        json!({
            "email": get_random_email().to_string(),
            "loginAttemptId": 123546,
            "2FACode": "111111",
        }),
        json!({
            "email": get_random_email(),
            "loginAttemptId": Uuid::new_v4().to_string(),
            "FACode": 123654,
        }),
        json!({
            "email": get_random_email(),
            "loginAttemptId": Uuid::new_v4().to_string(),
            "FACode": "asdf",
        }),
        json!({
            "email": get_random_email(),
            "loginAttemptId": "asdf",
            "FACode": "666666",
        }),
        json!({
            "email": get_random_email(),
            "loginAttemptId": Uuid::new_v4().to_string(),
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
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;

    let email = get_random_email();
    let password = "TestPassword";

    let response = app
        .post_signup(&json!({
            "email": email,
            "password": password,
            "requires2FA": true,
        }))
        .await;

    assert_eq!(response.status().as_u16(), 201, "Failed to sign up user.");

    let response = app
        .post_login(&json!({
            "email": email,
            "password": password,
        }))
        .await;

    let login_attempt_id = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not dispatch response for login attempt")
        .login_attempt_id;

    let code = app
        .two_fa_code_store
        .write()
        .await
        .get_code(&Email::parse(Secret::new(email.to_owned())).expect("Failed to parse email"))
        .await
        .expect("Could not obtain code from app state")
        .1;

    let test_cases = [
        json!({
        "email": email,
        "loginAttemptId": login_attempt_id,
        "2FACode": "000000",
        }),
        json!({
            "email": get_random_email(),
            "loginAttemptId": login_attempt_id,
            "2FACode": code.expose_secret(),
        }),
        json!({
            "email": email,
            "loginAttemptId": Uuid::new_v4(),
            "2FACode": code.expose_secret(),
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(&test_case).await;

        println!("{:?}", response);

        assert_eq!(
            response.status().as_u16(),
            401,
            "Failed for input {:?}.",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Incorrect credentials".to_owned()
        );
    }
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let mut app = TestApp::new().await;

    let email = get_random_email();
    let password = "TestPassword";

    let response = app
        .post_signup(&json!({
            "email": email,
            "password": password,
            "requires2FA": true,
        }))
        .await;

    assert_eq!(response.status().as_u16(), 201, "Failed to sign up user.");

    let response = app
        .post_login(&json!({
            "email": email,
            "password": password,
        }))
        .await;

    let code = app
        .two_fa_code_store
        .write()
        .await
        .get_code(&Email::parse(Secret::new(email.clone())).expect("Failed to parse email."))
        .await
        .expect("Could not obtain code from app state")
        .1;

    app.post_login(&json!({
        "email": email,
        "password": password,
    }))
    .await;

    let login_attempt_id = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not dispatch response for login attempt")
        .login_attempt_id;

    let response = app
        .post_verify_2fa(&json!({
            "email": email,
            "2FACode": code.expose_secret(),
            "loginAttemptId": login_attempt_id,
        }))
        .await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed to refuse old code verification."
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Incorrect credentials".to_owned()
    );
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let mut app = TestApp::new().await;

    let email = get_random_email();
    let password = "TesPassword";

    let response = app
        .post_signup(&json!({
            "email": email,
            "password": password,
            "requires2FA": true,
        }))
        .await;

    assert_eq!(response.status().as_u16(), 201);

    let login_attempt_id = app
        .post_login(&json!({
            "email": email,
            "password": password,

        }))
        .await
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to LoginAttemptIdResponse")
        .login_attempt_id;

    let code = app
        .two_fa_code_store
        .write()
        .await
        .get_code(&Email::parse(Secret::new(email.clone())).expect("Failed to parse email"))
        .await
        .expect("Could not obtain code from app state")
        .1;

    let response = app
        .post_verify_2fa(&json!({
            "email": email,
            "loginAttemptId": login_attempt_id,
            "2FACode": code.expose_secret(),
        }))
        .await;

    assert_eq!(response.status().as_u16(), 200, "Verify request fails");

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_correct_code_used_twice() {
    let mut app = TestApp::new().await;

    let email = get_random_email();
    let password = "TesPassword";

    let response = app
        .post_signup(&json!({
            "email": email,
            "password": password,
            "requires2FA": true,
        }))
        .await;

    assert_eq!(response.status().as_u16(), 201);

    let login_attempt_id = app
        .post_login(&json!({
            "email": email,
            "password": password,

        }))
        .await
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to LoginAttemptIdResponse")
        .login_attempt_id;

    let code = app
        .two_fa_code_store
        .write()
        .await
        .get_code(&Email::parse(Secret::new(email.clone())).expect("Failed to parse email"))
        .await
        .expect("Could not obtain code from app state")
        .1;

    let response = app
        .post_verify_2fa(&json!({
            "email": email,
            "loginAttemptId": login_attempt_id,
            "2FACode": code.expose_secret(),
        }))
        .await;

    assert_eq!(response.status().as_u16(), 200, "Verify request fails");

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let response = app
        .post_verify_2fa(&json!({
            "email": email,
            "2FACode": code.expose_secret(),
            "loginAttemptId": login_attempt_id,
        }))
        .await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Failed to refuse old code verification."
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "Incorrect credentials".to_owned()
    );
    app.clean_up().await;
}
