use std::sync::Arc;

use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);

        let store_code = serde_json::to_string(&TwoFATuple(
            login_attempt_id.as_ref().to_owned(),
            code.as_ref().to_owned(),
        ))
        .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        self.conn
            .write()
            .await
            .set_ex(key, store_code, TEN_MINUTES_IN_SECONDS)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(email);

        self.conn
            .write()
            .await
            .del(key.as_str())
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)
    }

    async fn get_code(
        &mut self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(email);

        let stored_code: String = self
            .conn
            .write()
            .await
            .get(key)
            .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;

        let code_tuple = serde_json::from_str::<TwoFATuple>(stored_code.as_str())
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        let login_attempt_id = LoginAttemptId::parse(&code_tuple.0)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let code =
            TwoFACode::parse(code_tuple.1).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok((login_attempt_id, code))
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 10 * 60;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code";

fn get_key(email: &Email) -> String {
    format!("{}:{}", TWO_FA_CODE_PREFIX, email.as_ref())
}
