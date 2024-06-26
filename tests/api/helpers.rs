use auth_service::{
    app_state::AppState,
    domain::{BannedTokenStore, Email, TwoFACodeStore},
    get_postgres_pool, get_redis_client,
    services::{
        data_stores::HashMapTwoFACodeStore, PostgresUserStore,
        PostmarkEmailClient, RedisBannedTokenStore,
    },
    utils::{test, DATABASE_URL, REDIS_HOSTNAME, REDIS_PORT},
    Application,
};
use reqwest::{cookie::Jar, Client};
use secrecy::{ExposeSecret, Secret};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    Connection as _, Executor, PgConnection, PgPool,
};
use std::{str::FromStr as _, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;
use wiremock::MockServer;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub banned_token_store: Arc<RwLock<dyn BannedTokenStore>>,
    pub two_fa_code_store: Arc<RwLock<dyn TwoFACodeStore>>,
    pub email_server: MockServer,
    pub http_client: reqwest::Client,
    pub db_name: String,
    pub clean_up_called: bool,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.clean_up_called {
            panic!("Call TestApp.cleanup()");
        };
    }
}

impl TestApp {
    pub async fn new() -> Self {
        // TODO: Add test container at runtime
        let (pg_pool, db_name) = configure_postgresql().await;
        let redis_connection = Arc::new(RwLock::new(configure_redis()));

        let user_store = Arc::new(RwLock::new(PostgresUserStore::new(pg_pool)));
        let banned_token_store =
            Arc::new(RwLock::new(RedisBannedTokenStore::new(redis_connection)));
        let two_fa_code_store = Arc::new(RwLock::new(HashMapTwoFACodeStore::default()));

        let email_server = MockServer::start().await;
        let base_url = email_server.uri();
        let email_client = Arc::new(configure_postmark_email_client(base_url));

        let app_state = AppState::new(
            user_store,
            banned_token_store.clone(),
            two_fa_code_store.clone(),
            email_client.clone(),
        );

        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build test app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        TestApp {
            address,
            db_name,
            cookie_jar,
            http_client,
            banned_token_store,
            two_fa_code_store,
            email_server,
            clean_up_called: false,
        }
    }

    pub async fn clean_up(&mut self) {
        delete_database(&self.db_name).await;
        self.clean_up_called = true;
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn delete_account<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .delete(&format!("{}/account", &self.address))
            .json(body)
            .send()
            .await
            .expect("Fail to send delete account request.")
    }
}

async fn configure_postgresql() -> (PgPool, String) {
    let postgresql_conn_url = &DATABASE_URL;
    let db_name = format!("{}_test", Uuid::new_v4());

    configure_database(postgresql_conn_url, &db_name).await;

    let postgresql_conn_url_with_db = Secret::new(format!(
        "{}/{}",
        postgresql_conn_url.expose_secret(),
        db_name
    ));

    (
        get_postgres_pool(&postgresql_conn_url_with_db)
            .await
            .expect("Failed to create Postgres connection pool!"),
        db_name,
    )
}

async fn configure_database(db_conn_string: &Secret<String>, db_name: &str) {
    let connection = PgPoolOptions::new()
        .connect(db_conn_string.expose_secret())
        .await
        .expect("Failed to create Postgres connection pool.");

    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database.");

    let connection = PgPoolOptions::new()
        .connect(format!("{}/{}", db_conn_string.expose_secret(), db_name).as_str())
        .await
        .expect("Failed to create Postgres connection pool.");

    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate database.");
}

async fn delete_database(db_name: &str) {
    let postgresql_conn_url = &DATABASE_URL;

    let connection_options = PgConnectOptions::from_str(postgresql_conn_url.expose_secret())
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    connection
        .execute(
            format!(
                r#"
            SELECT pg_terminate_backend(pg_stat_activity.pid)
            FROM pg_stat_activity
            WHERE pg_stat_activity.datname = '{}'
                AND pid <> pg_backend_pid();
        "#,
                db_name,
            )
            .as_str(),
        )
        .await
        .expect("Failed to drop pending connections");

    connection
        .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to drop the database.");
}

fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOSTNAME.to_owned(), *REDIS_PORT)
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4()).replace('-', "")
}

fn configure_postmark_email_client(base_url: String) -> PostmarkEmailClient {
    let postmark_auth_token = Secret::new("auth_token".to_owned());

    let sender = Email::parse(Secret::new(test::email_client::SENDER.to_owned())).unwrap();

    let http_client = Client::builder()
        .timeout(test::email_client::TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    PostmarkEmailClient::new(base_url, sender, postmark_auth_token, http_client)
}
