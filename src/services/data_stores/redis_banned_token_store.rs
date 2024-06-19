use std::sync::Arc;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};
use color_eyre::eyre::Context;
use redis::{Commands, Connection};
use secrecy::{ExposeSecret, Secret};
use tokio::sync::RwLock;

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn add_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        let token_key = get_key(token.expose_secret().as_str());

        let value = true;

        let _: () = self
            .conn
            .write()
            .await
            .set_ex(&token_key, value, TOKEN_TTL_SECONDS)
            .wrap_err("failed to set banned token in Redis")
            .map_err(BannedTokenStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn contains_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        let token_key = get_key(token.expose_secret());

        let is_banned: bool = self
            .conn
            .write()
            .await
            .exists(&token_key)
            .wrap_err("failed to check if token exists in Redis")
            .map_err(BannedTokenStoreError::UnexpectedError)?;

        Ok(is_banned)
    }
}

const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token";
const TOKEN_TTL_SECONDS: u64 = 24 * 60 * 60;

fn get_key(token: &str) -> String {
    format!("{}:{}", BANNED_TOKEN_KEY_PREFIX, token)
}
