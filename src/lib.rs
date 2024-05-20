use std::{error::Error, sync::Arc};

use axum::{routing::post, serve::Serve, Router};
use services::HashMapUserStore;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;

pub mod domain;
pub mod routes;
pub mod services;

// This struct encapsulates our application-related logic.
pub struct Application {
    server: Serve<Router, Router>,
    pub address: String,
}

pub type UserStoreType = Arc<RwLock<HashMapUserStore>>;

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
}

impl AppState {
    pub fn new(user_store: UserStoreType) -> Self {
        Self { user_store }
    }
}

impl Application {
    pub async fn build(
        app_state: AppState,
        address: &str,
        assets_dir: &str,
    ) -> Result<Self, Box<dyn Error>> {
        println!("Assets dir: {}", assets_dir);

        let router = Router::new()
            .nest_service("/", ServeDir::new(assets_dir))
            .route("/signup", post(routes::signup))
            .route("/login", post(routes::login))
            .route("/logout", post(routes::logout))
            .route("/verify-2fa", post(routes::verify_2fa))
            .route("/verify-token", post(routes::verify_token))
            .with_state(app_state);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        // Create a new Application instance and return it
        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}
