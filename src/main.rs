extern crate dotenv;

use auth_service::{app_state::AppState, services::HashMapUserStore, Application};
use dotenv::dotenv;
use std::{env, sync::Arc};

use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    match dotenv() {
        Ok(_) => println!("Loaded env file."),
        Err(_) => println!("Failed to load env file!"),
    }

    let user_store = Arc::new(RwLock::new(HashMapUserStore::default()));
    let app_state = AppState::new(user_store);

    let assets_dir = env::var("ASSETS_DIR").unwrap_or_else(|_| "assets".to_owned());

    let app = Application::build(app_state, "0.0.0.0:3000", &assets_dir)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
