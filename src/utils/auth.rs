use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::app_state::BannedTokenStoreType;
use crate::domain::Email;
use color_eyre::eyre::{eyre, Context, ContextCompat, Result};

use crate::utils::{JWT_COOKIE_NAME, JWT_SECRET};

pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

fn create_auth_cookie(token: String) -> Cookie<'static> {
    Cookie::build((JWT_COOKIE_NAME, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub const TOKEN_TTL_SECONDS: i64 = 600;

fn generate_auth_token(email: &Email) -> Result<String> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .wrap_err("Failed to create 10 minute time delta.")?;

    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(eyre!("Failed to add 10 minutes to current time."))?
        .timestamp();

    let exp: usize = exp.try_into().wrap_err(format!(
        "Failed to cast exp time to usize. exp time: {}",
        exp
    ))?;

    let sub = email.as_ref().expose_secret().clone();

    let claims = Claims { sub, exp };

    create_token(&claims)
}

fn create_token(claims: &Claims) -> Result<String> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
    )
    .wrap_err("Failed to create token.")
}

pub async fn validate_token(
    token: &str,
    banned_token_store: BannedTokenStoreType,
) -> Result<Claims> {
    match banned_token_store.read().await.contains_token(token).await {
        Ok(value) => {
            if value {
                return Err(eyre!("Token is banned."));
            }
        }
        Err(e) => return Err(e.into()),
    };
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .wrap_err("Failed to decode token.")
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use secrecy::Secret;
    use tokio::sync::RwLock;

    use crate::{domain::BannedTokenStore, services::HashSetBannedTokenStore};

    use super::*;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();

        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_create_auth_cookie() {
        let token = "test_token".to_owned();
        let cookie = create_auth_cookie(token.clone());
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_generate_auth_token() {
        let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
        let result = generate_auth_token(&email).unwrap();
        assert_eq!(result.split('.').count(), 3);
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
        let token = generate_auth_token(&email).unwrap();
        let result = validate_token(
            &token,
            Arc::new(RwLock::new(HashSetBannedTokenStore::default())),
        )
        .await
        .expect("Could not verify token");
        assert_eq!(result.sub, "test@example.com");

        let exp = Utc::now()
            .checked_add_signed(chrono::Duration::try_minutes(9).expect("valid duration"))
            .expect("valid timestamp")
            .timestamp();

        assert!(result.exp > exp as usize);
    }

    #[tokio::test]
    async fn test_validate_token_with_banned_token() {
        let email = Email::parse(Secret::new("test@example.com".to_owned())).unwrap();
        let token = generate_auth_token(&email).unwrap();
        let mut banned_token_store = HashSetBannedTokenStore::default();

        banned_token_store
            .add_token(token.clone())
            .await
            .expect("Should add token to banned list");

        let result = validate_token(&token, Arc::new(RwLock::new(banned_token_store))).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token = "invalid_token".to_owned();
        let result = validate_token(
            &token,
            Arc::new(RwLock::new(HashSetBannedTokenStore::default())),
        )
        .await;
        assert!(result.is_err());
    }
}
