use std::error::Error;

use app_state::AppState;
use axum::{
    http::{StatusCode, Method},
    response::{IntoResponse, Response},
    routing::{delete, post},
    serve::Serve,
    Json, Router,
};
use domain::AuthAPIError;
use routes::{delete_account, login, logout, signup, verify_2fa, verify_token};
use serde::{Deserialize, Serialize};
use tower_http::{cors::CorsLayer, services::ServeDir};

pub mod app_state;
pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

use utils::ASSETS_DIR;

pub struct Application {
    pub server: Serve<Router, Router>,
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        let assets_dir = ASSETS_DIR.as_str();
        let allowed_origins = [
            "http://localhost".parse()?,
            "https://ronin-code.io".parse()?,
        ];

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::DELETE])
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        let router = Router::new()
            .nest_service("/", ServeDir::new(assets_dir))
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/logout", post(logout))
            .route("/verify-2fa", post(verify_2fa))
            .route("/verify-token", post(verify_token))
            .route("/account", delete(delete_account))
            .with_state(app_state)
            .layer(cors);

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

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
            AuthAPIError::IncorrectCredentials => {
                (StatusCode::UNAUTHORIZED, "Incorrect credentials")
            }
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "Missing cookie"),
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });

        (status, body).into_response()
    }
}
