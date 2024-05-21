use crate::domain::{Email, User, UserStore, UserStoreError};
use async_trait::async_trait;
use std::collections::HashMap;

#[derive(Default)]
pub struct HashMapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait]
impl UserStore for HashMapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let email: Email = format!("{}", user.email);
        match self.users.get(&email) {
            Some(_) => return Err(UserStoreError::UserAlreadyExists),
            None => {
                self.users.insert(email, user);
            }
        }

        Ok(())
    }

    async fn get_user(self, email: &str) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    async fn validate_user(self, email: &str, password: &str) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) if user.password == password => Ok(()),
            Some(_) => Err(UserStoreError::InvalidCredentials),
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
        let user = User::new(
            "user@example.com".to_owned(),
            "test-password".to_owned(),
            false,
        );
        user_service.add_user(user).await.expect("should add user");

        assert_eq!(user_service.users.len(), 1);
    }

    #[tokio::test]
    async fn should_fail_to_add_duplicated_user() {
        let mut user_service = HashMapUserStore::default();
        let user = User::new(
            "user@example.com".to_owned(),
            "test-password".to_owned(),
            false,
        );

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
        let user = User::new(
            "user@example.com".to_owned(),
            "test-password".to_owned(),
            false,
        );
        user_service.add_user(user).await.expect("should add user");

        assert!(user_service.get_user("user@example.com").await.is_ok());
    }

    #[tokio::test]
    async fn should_fail_if_user_do_not_exists() {
        let user_service = HashMapUserStore::default();

        assert_eq!(
            user_service.get_user("user@example.com").await.unwrap_err(),
            UserStoreError::UserNotFound
        );
    }

    #[tokio::test]
    async fn should_validate_password() {
        let mut user_service = HashMapUserStore::default();
        let user = User::new(
            "user@example.com".to_owned(),
            "test-password".to_owned(),
            false,
        );
        user_service.add_user(user).await.expect("should add user");

        assert!(user_service
            .validate_user("user@example.com", "test-password")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn should_fail_to_validate_password() {
        let mut user_service = HashMapUserStore::default();
        let user = User::new(
            "user@example.com".to_owned(),
            "test-password".to_owned(),
            false,
        );
        user_service.add_user(user).await.expect("should add user");

        assert_eq!(
            user_service
                .validate_user("user@example.com", "invalid-password")
                .await
                .unwrap_err(),
            UserStoreError::InvalidCredentials
        );
    }

    #[tokio::test]
    async fn should_fail_to_validate_password_if_user_does_not_exists() {
        let user_service = HashMapUserStore::default();

        assert_eq!(
            user_service
                .validate_user("user@example.com", "invalid-password")
                .await
                .unwrap_err(),
            UserStoreError::UserNotFound
        );
    }
}
