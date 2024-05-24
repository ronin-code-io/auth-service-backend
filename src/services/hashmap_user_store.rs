use crate::domain::{Email, Password, User, UserStore, UserStoreError};
use std::collections::HashMap;

#[derive(Default)]
pub struct HashMapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashMapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }

        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_user(self, email: &Email) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    async fn validate_user(self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) => {
                if user.password.eq(password) {
                    Ok(())
                } else {
                    Err(UserStoreError::InvalidCredentials)
                }
            }
            None => Err(UserStoreError::UserNotFound),
        }
    }

    async fn delete_user(&mut self, email: &Email) -> Result<(), UserStoreError> {
        match self.users.remove(email) {
            Some(_) => Ok(()),
            None => Err(UserStoreError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn should_add_user() {
        let mut user_service = HashMapUserStore::default();
        let email = Email::parse("user@example.com").expect("Should parse email");
        let password = Password::parse("test-password").expect("Should parse password");

        let user = User::new(email, password, false);
        user_service.add_user(user).await.expect("should add user");

        assert_eq!(user_service.users.len(), 1);
    }

    #[tokio::test]
    async fn should_fail_to_add_duplicated_user() {
        let mut user_service = HashMapUserStore::default();
        let email = Email::parse("user@example.com").expect("Should parse email");
        let password = Password::parse("test-password").expect("Should parse password");
        let user = User::new(email, password, false);

        user_service
            .add_user(user.clone())
            .await
            .expect("should add user");
        assert_eq!(
            user_service.add_user(user).await.unwrap_err(),
            UserStoreError::UserAlreadyExists,
        );
    }

    #[tokio::test]
    async fn should_return_uesr() {
        let mut user_service = HashMapUserStore::default();
        let email = Email::parse("user@example.com").expect("Should parse email");
        let password = Password::parse("test-password").expect("Should parse password");
        let user = User::new(email.clone(), password, false);

        user_service.add_user(user).await.expect("should add user");

        assert!(user_service.get_user(&email).await.is_ok());
    }

    #[tokio::test]
    async fn should_fail_if_user_do_not_exists() {
        let user_service = HashMapUserStore::default();
        let email = Email::parse("user@example.com").expect("Should parse email");

        assert_eq!(
            user_service.get_user(&email).await.unwrap_err(),
            UserStoreError::UserNotFound
        );
    }

    #[tokio::test]
    async fn should_validate_password() {
        let mut user_service = HashMapUserStore::default();
        let email = Email::parse("user@example.com").expect("Should parse email");
        let password = Password::parse("test-password").expect("Should parse password");
        let user = User::new(email.clone(), password.clone(), false);

        user_service.add_user(user).await.expect("should add user");

        assert!(user_service.validate_user(&email, &password).await.is_ok());
    }

    #[tokio::test]
    async fn should_fail_to_validate_password() {
        let mut user_service = HashMapUserStore::default();
        let email = Email::parse("user@example.com").expect("Should parse email");
        let password = Password::parse("test-password").expect("Should parse password");
        let wrong_password = Password::parse("wrong-password").expect("Should parse password");
        let user = User::new(email.clone(), password, false);

        user_service.add_user(user).await.expect("should add user");

        assert_eq!(
            user_service
                .validate_user(&email, &wrong_password)
                .await
                .unwrap_err(),
            UserStoreError::InvalidCredentials
        );
    }

    #[tokio::test]
    async fn should_fail_to_validate_password_if_user_does_not_exists() {
        let user_service = HashMapUserStore::default();
        let email = Email::parse("user@example.com").expect("Should parse email");
        let password = Password::parse("test-password").expect("Should parse password");

        assert_eq!(
            user_service
                .validate_user(&email, &password)
                .await
                .unwrap_err(),
            UserStoreError::UserNotFound
        );
    }
}
