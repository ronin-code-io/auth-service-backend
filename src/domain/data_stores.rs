use super::User;
use axum::async_trait;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[async_trait]
pub trait UserStore: Send + Sync + 'static {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(self, email: &str) -> Result<User, UserStoreError>;
    async fn validate_user(self, email: &str, password: &str) -> Result<(), UserStoreError>;
}
