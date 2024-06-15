extern crate dotenv;

use auth_service::{
    app_state::AppState,
    get_postgres_pool, get_redis_client,
    services::{MockEmailClient, PostgresUserStore, RedisBannedTokenStore, RedisTwoFACodeStore},
    utils::{prod, DATABASE_URL, REDIS_HOSTNAME, REDIS_PORT},
    Application,
};
use sqlx::PgPool;
use std::sync::Arc;

use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let pg_pol = configure_postgres().await;
    let redis_connection = Arc::new(RwLock::new(configure_redis()));

    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pol)));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(
        redis_connection.clone(),
    )));
    let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(
        redis_connection.clone(),
    )));
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

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOSTNAME.to_owned(), *REDIS_PORT)
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}
