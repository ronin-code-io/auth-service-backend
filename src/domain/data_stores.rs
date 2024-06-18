use rand::Rng;

use super::{AuthAPIError, Email, Password, User};
use thiserror::Error;

use color_eyre::eyre::{eyre, Context, Report, Result};

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, PartialEq)]
pub enum BannedTokenStoreError {
    UnexpectedError,
}

#[async_trait::async_trait]
pub trait UserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password)
        -> Result<(), UserStoreError>;
    async fn delete_user(&mut self, email: &Email) -> Result<(), UserStoreError>;
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&mut self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl Default for LoginAttemptId {
    fn default() -> Self {
        LoginAttemptId(uuid::Uuid::new_v4().to_string())
    }
}

impl LoginAttemptId {
    pub fn parse(id: &str) -> Result<Self, AuthAPIError> {
        let parsed_id = uuid::Uuid::parse_str(id)
            .wrap_err("Invalid login attempt id")
            .unwrap();

        Ok(Self(parsed_id.to_string()))
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self> {
        let code_as_u32 = code.parse::<u32>().wrap_err("Invalid 2FA code")?;

        if (100_000..=999_999).contains(&code_as_u32) {
            Ok(Self(code))
        } else {
            Err(eyre!("Invalid 2FA code"))
        }
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        let code = rand::thread_rng().gen_range(100000..=999999).to_string();
        TwoFACode(code)
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &mut self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
}
