use std::{error::Error, sync::Arc};

use crate::domain::AuthApiError;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use domain::UserStore;
use serde::{Deserialize, Serialize};
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

pub type UserStoreType = Arc<RwLock<dyn UserStore + 'static>>;

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthApiError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthApiError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthApiError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });

        (status, body).into_response()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub user_store: UserStoreType,
}

impl AppState {
    pub fn new(user_store: UserStoreType) -> Self {
        Self { user_store }
    }
}
