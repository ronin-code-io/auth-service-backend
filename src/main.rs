extern crate dotenv;

use auth_service::{
    app_state::AppState,
    get_postgres_pool,
    services::{
        data_stores::{HashMapTwoFACodeStore, HashSetBannedTokenStore},
        MockEmailClient, PostgresUserStore,
    },
    utils::{prod, DATABASE_URL},
    Application,
};
use sqlx::PgPool;
use std::sync::Arc;

use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let pg_pol = configure_postgres().await;

    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pol)));
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

async fn configure_postgres() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run database migrations!");

    pg_pool
}
