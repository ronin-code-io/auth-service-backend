use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashSetBannedTokenStore {
    banned_tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        match self.banned_tokens.insert(token) {
            true => Ok(()),
            false => Err(BannedTokenStoreError::UnexpectedError),
        }
    }

    async fn is_token_banned(self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.banned_tokens.contains(token))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn should_return_false_if_token_is_not_banned() {
        let banned_token_store = HashSetBannedTokenStore::default();

        let result = banned_token_store
            .is_token_banned("Unknown")
            .await
            .expect("Could not check banned token");

        assert!(!result);
    }

    #[tokio::test]
    async fn should_add_token() {
        let token = "Known".to_owned();
        let mut banned_token_store = HashSetBannedTokenStore::default();

        assert!(banned_token_store.add_token(token.clone()).await.is_ok());

        assert!(banned_token_store.is_token_banned(&token).await.is_ok());
    }
}
