extern crate dotenv;

use auth_service::{
    app_state::AppState,
    services::{HashMapUserStore, HashSetBannedTokenStore},
    utils::prod,
    Application,
};
use std::sync::Arc;

use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashMapUserStore::default()));
    let banned_token_store = Arc::new(RwLock::new(HashSetBannedTokenStore::default()));

    let app_state = AppState::new(user_store, banned_token_store);

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
