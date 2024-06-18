use axum::{body::Body, extract::Request, response::Response};
use tracing::{Level, Span};
use tracing_error::ErrorLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{fmt, prelude::*};

use std::time::Duration;

pub fn init_tracing() {
    let fmt_layer = fmt::layer().compact();
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(ErrorLayer::default())
        .init();
}

pub fn make_span_with_request_id(request: &Request<Body>) -> Span {
    let request_id = uuid::Uuid::new_v4();
    tracing::span!(
        Level::INFO,
        "[REQUEST]",
        method = tracing::field::display(request.method()),
        uri = tracing::field::debug(request.uri()),
        version = tracing::field::debug(request.version()),
        request_id = tracing::field::display(request_id),
    )
}

pub fn on_request(_on_request: &Request<Body>, _span: &Span) {
    tracing::event!(Level::INFO, "[REQUEST START]",);
}

pub fn on_response(response: &Response, latency: Duration, _span: &Span) {
    let status = response.status();
    let status_code = status.as_u16();
    let status_code_class = status_code / 100;

    match status_code_class {
        4..=5 => {
            tracing::event!(
              Level::ERROR,
              latency = ?latency,
              status = status_code,
              "[REQUEST END]"
            )
        }
        _ => {
            tracing::event!(
              Level::INFO,
              latency = ?latency,
              status = status_code,
              "[REQUEST END]"
            )
        }
    }
}
