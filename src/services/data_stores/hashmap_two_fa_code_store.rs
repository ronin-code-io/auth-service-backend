use std::collections::HashMap;

use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

#[derive(Default)]
pub struct HashMapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashMapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        match self.codes.get(email) {
            Some(code) => Ok(code.clone()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        match self.codes.remove(email) {
            Some(_) => Ok(()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStoreError};

    #[tokio::test]
    async fn test_add_code_success() {
        let mut store = HashMapTwoFACodeStore::default();

        let email = Email::parse("test@this.mail").expect("Can not parse email.");
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        let result = store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await;
        assert!(result.is_ok(), "Failed to add 2FA code");
    }

    #[tokio::test]
    async fn test_get_code_not_found() {
        let store = HashMapTwoFACodeStore::default();

        let email = Email::parse("test@this.email").expect("Failed to parse email");

        let result = store.get_code(&email).await;
        assert_eq!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound));
    }

    #[tokio::test]
    async fn test_get_code_success() {
        let mut store = HashMapTwoFACodeStore::default();

        let email = Email::parse("test@this.mail").expect("Can not parse email.");
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .expect("Failed to add 2FA code");

        let result = store.get_code(&email).await;
        assert!(result.is_ok(), "Failed to retrieve 2FA code");
        let return_value = result.unwrap();
        assert_eq!(
            return_value,
            (login_attempt_id, code),
            "Failed to retrieve proper code"
        );
    }
}
