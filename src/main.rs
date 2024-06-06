extern crate dotenv;

use auth_service::{
    app_state::AppState,
    services::{HashMapTwoFACodeStore, HashMapUserStore, HashSetBannedTokenStore, MockEmailClient},
    utils::prod,
    Application,
};
use std::sync::Arc;

use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashMapUserStore::default()));
    let banned_token_store = Arc::new(RwLock::new(HashSetBannedTokenStore::default()));
    let two_fa_code_store = Arc::new(RwLock::new(HashMapTwoFACodeStore::default()));
    let email_client = Arc::new(RwLock::new(MockEmailClient {}));

    let app_state = AppState::new(
        user_store,
        banned_token_store,
        two_fa_code_store,
        email_client,
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
