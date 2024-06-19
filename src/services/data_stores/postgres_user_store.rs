use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};

use sqlx::PgPool;
use tokio::task;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

use color_eyre::eyre::{eyre, Context, Result};
use secrecy::{ExposeSecret, Secret};

pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    #[tracing::instrument(name = "Adding user to PostgreSQL", skip_all)]
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let password_hash = compute_password_hash(user.password.as_ref().to_owned())
            .await
            .map_err(UserStoreError::UnexpectedError)?;
        let email = user.email.as_ref();

        if sqlx::query!("SELECT email FROM users WHERE email = $1", email)
            .fetch_one(&self.pool)
            .await
            .is_ok()
        {
            return Err(UserStoreError::UserAlreadyExists);
        }

        sqlx::query!(
            r#"
        INSERT INTO users (email, password_hash, requires_2fa)
        VALUES ($1, $2, $3)
        "#,
            email,
            &password_hash.expose_secret(),
            user.requires_2fa
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        Ok(())
    }

    #[tracing::instrument(name = "Retrieving user from PostgreSQL", skip_all)]
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        sqlx::query!(
            r#"
            SELECT email, password_hash, requires_2fa
            FROM users
            WHERE email = $1
            "#,
            email.as_ref()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserStoreError::UnexpectedError(e.into()))?
        .map(|row| {
            let email = Email::parse(&row.email).map_err(UserStoreError::UnexpectedError)?;
            let password = Password::parse(Secret::new(row.password_hash))
                .map_err(UserStoreError::UnexpectedError)?;

            Ok(User::new(email, password, row.requires_2fa))
        })
        .ok_or(UserStoreError::UserNotFound)?
    }

    #[tracing::instrument(name = "Validating user credentials in PostgreSQL", skip_all)]
    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;
        match verify_password_hash(
            password.as_ref().to_owned(),
            user.password.as_ref().to_owned(),
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(_) => Err(UserStoreError::InvalidCredentials),
        }
    }

    #[tracing::instrument(name = "Deleting user data from PostgreSQL", skip_all)]
    async fn delete_user(&mut self, email: &Email) -> Result<(), UserStoreError> {
        let result = sqlx::query!("DELETE FROM users WHERE email = $1", email.as_ref())
            .execute(&self.pool)
            .await
            .map_err(|e| UserStoreError::UnexpectedError(e.into()))?;

        if result.rows_affected() == 0 {
            Err(UserStoreError::UserNotFound)
        } else {
            Ok(())
        }
    }
}

#[tracing::instrument(name = "Verify password hash", skip_all)]
async fn verify_password_hash(
    password: Secret<String>,
    hashed_password: Secret<String>,
) -> Result<()> {
    let current_span: tracing::Span = tracing::Span::current();

    task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let hash: PasswordHash<'_> = PasswordHash::new(hashed_password.expose_secret())?;
            Argon2::default()
                .verify_password(password.expose_secret().as_bytes(), &hash)
                .wrap_err("Failed to verify password hash.")
        })
    })
    .await?
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: Secret<String>) -> Result<Secret<String>> {
    let current_span: tracing::Span = tracing::Span::current();
    let result = task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
            Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None).unwrap(),
            )
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .unwrap()
            .to_string()
        })
    })
    .await;

    match result {
        Ok(result) => Ok(Secret::new(result)),
        Err(_) => Err(eyre!("Password don't match")),
    }
}
