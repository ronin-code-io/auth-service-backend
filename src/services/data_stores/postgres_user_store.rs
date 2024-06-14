use std::error::Error;

use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};

use sqlx::PgPool;
use tokio::task;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

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
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        let email = user.email.as_ref();

        if sqlx::query!("SELECT email FROM users WHERE email = $1", email)
            .fetch_one(&self.pool)
            .await
            .is_ok()
        {
            return Err(UserStoreError::UserAlreadyExists);
        }

        let password = user.password.as_ref().to_owned();
        let hashed_password = match compute_password_hash(password).await {
            Ok(hash) => hash.clone(),
            Err(_) => {
                return Err(UserStoreError::UnexpectedError);
            }
        };

        match sqlx::query!(
            r#"
              INSERT INTO users (email, password_hash, requires_2fa)
              VALUES ($1, $2, $3)
              ON CONFLICT (email) DO NOTHING;
            "#,
            email,
            hashed_password,
            user.requires_2fa
        )
        .execute(&self.pool)
        .await
        {
            Ok(_) => Ok(()),
            Err(_) => Err(UserStoreError::UnexpectedError),
        }
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        sqlx::query!("SELECT * FROM users WHERE email = $1", email.as_ref())
            .fetch_one(&self.pool)
            .await
            .map(|row| User {
                email: Email::parse(&row.email).unwrap(),
                password: Password::parse(&row.password_hash).unwrap(),
                requires_2fa: row.requires_2fa,
            })
            .map_err(|_| UserStoreError::UserNotFound)
    }

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

    async fn delete_user(&mut self, email: &Email) -> Result<(), UserStoreError> {
        let result = sqlx::query!("DELETE FROM users WHERE email = $1", email.as_ref())
            .execute(&self.pool)
            .await;

        if result.is_err() {
            return Err(UserStoreError::UnexpectedError);
        };

        if result.unwrap().rows_affected() == 0 {
            Err(UserStoreError::UserNotFound)
        } else {
            Ok(())
        }
    }
}

async fn verify_password_hash(
    password: String,
    hashed_password: String,
) -> Result<(), Box<dyn Error>> {
    let result = task::spawn_blocking(move || {
        let hash: PasswordHash<'_> = PasswordHash::new(&hashed_password)?;
        Argon2::default().verify_password(password.as_bytes(), &hash.clone())
    })
    .await?;

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(Box::new(e)),
    }
}

async fn compute_password_hash(password: String) -> Result<String, Box<dyn Error>> {
    let result = task::spawn_blocking(move || {
        let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        )
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
    })
    .await;

    match result {
        Ok(result) => Ok(result),
        Err(e) => Err(Box::new(e)),
    }
}
