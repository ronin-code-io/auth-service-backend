use super::{Email, Password, User};
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
    async fn get_user(self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(self, email: &Email, password: &Password) -> Result<(), UserStoreError>;
    async fn delete_user(&mut self, email: &Email) -> Result<(), UserStoreError>;
}
