use crate::domain::{BannedTokenStore, BannedTokenStoreError};
use redis::{Commands, Connection};

pub struct RedisBannedTokenStore {
    conn: Connection,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        let key = get_key(&token);
        self.conn
            .set_ex(key, true, TOKEN_TTL_SECONDS)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)
    }

    async fn contains_token(&mut self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let key = get_key(token);

        self.conn
            .exists(key)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)
    }
}

const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token";
const TOKEN_TTL_SECONDS: u64 = 24 * 60 * 60;

fn get_key(token: &str) -> String {
    format!("{}:{}", BANNED_TOKEN_KEY_PREFIX, token)
}
