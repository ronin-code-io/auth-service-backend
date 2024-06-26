use std::collections::HashSet;

use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashSetBannedTokenStore {
    banned_tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn add_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        match self.banned_tokens.insert(token.expose_secret().to_owned()) {
            true => Ok(()),
            false => Err(BannedTokenStoreError::UnexpectedError(eyre!(
                "Failed to add token into hashset.".to_owned()
            ))),
        }
    }

    async fn contains_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        Ok(self
            .banned_tokens
            .contains(&token.expose_secret().to_owned()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn should_return_false_if_token_is_not_banned() {
        let banned_token_store = HashSetBannedTokenStore::default();

        let result = banned_token_store
            .contains_token(&Secret::new("Unknown".to_owned()))
            .await
            .expect("Could not check banned token");

        assert!(!result);
    }

    #[tokio::test]
    async fn should_add_token() {
        let token = Secret::new("Known".to_owned());
        let mut banned_token_store = HashSetBannedTokenStore::default();

        assert!(banned_token_store.add_token(token.clone()).await.is_ok());

        assert!(banned_token_store.contains_token(&token).await.is_ok());
    }
}
