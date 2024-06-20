extern crate dotenv;

use auth_service::{
    app_state::AppState,
    domain::Email,
    get_postgres_pool, get_redis_client,
    services::{
        PostgresUserStore, PostmarkEmailClient, RedisBannedTokenStore, RedisTwoFACodeStore,
    },
    utils::{init_tracing, prod, DATABASE_URL, POSTMARK_AUTH_TOKEN, REDIS_HOSTNAME, REDIS_PORT},
    Application,
};
use reqwest::Client;
use secrecy::Secret;
use sqlx::PgPool;
use std::sync::Arc;

use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    color_eyre::install().expect("Failed to install color_eyre.");
    init_tracing();

    let email_client = Arc::new(configure_postmark_email_client());

    let pg_pol = configure_postgres().await;
    let redis_connection = Arc::new(RwLock::new(configure_redis()));

    let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pol)));
    let banned_token_store = Arc::new(RwLock::new(RedisBannedTokenStore::new(
        redis_connection.clone(),
    )));
    let two_fa_code_store = Arc::new(RwLock::new(RedisTwoFACodeStore::new(
        redis_connection.clone(),
    )));

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

fn configure_postmark_email_client() -> PostmarkEmailClient {
    let http_client = Client::builder()
        .timeout(prod::email_client::TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    PostmarkEmailClient::new(
        prod::email_client::BASE_URL.to_owned(),
        Email::parse(Secret::new(prod::email_client::SENDER.to_owned())).unwrap(),
        POSTMARK_AUTH_TOKEN.to_owned(),
        http_client,
    )
}
