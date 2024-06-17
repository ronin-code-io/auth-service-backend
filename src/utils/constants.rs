use dotenv::dotenv;
use lazy_static::lazy_static;
use std::env as std_env;

lazy_static! {
    pub static ref JWT_SECRET: String = set_token();
    pub static ref ASSETS_DIR: String = set_assets_dir();
    pub static ref POSTGRES_PASSWORD: String = set_postgres_password();
    pub static ref DATABASE_URL: String = set_database_url();
    pub static ref REDIS_HOSTNAME: String = set_redis_hostname();
    pub static ref REDIS_PORT: u32 = set_redis_port();
}

fn load_env_file() {
    match dotenv() {
        Ok(_) => tracing::debug!("Loaded env file."),
        Err(_) => tracing::warn!("Failed to load env file!"),
    }
}

fn set_token() -> String {
    load_env_file();
    let secret = std_env::var(env::JWT_SECRET_ENV_VAR).unwrap_or_else(|_| {
        panic!(
            "{} environment variable must be set.",
            env::JWT_SECRET_ENV_VAR
        )
    });

    if secret.is_empty() {
        panic!("{} must not be empty.", env::JWT_SECRET_ENV_VAR);
    }

    secret
}

fn set_assets_dir() -> String {
    load_env_file();
    let assets_dir = std_env::var(env::ASSETS_DIR_ENV_VAR).unwrap_or_else(|_| "assets".to_owned());
    tracing::debug!("Assets dir: {}", assets_dir);
    assets_dir
}

fn set_postgres_password() -> String {
    load_env_file();
    std_env::var(env::POSTGRES_PASSWORD_ENV_VAR).unwrap_or_else(|_| {
        panic!(
            "{} environment variable must be set.",
            env::POSTGRES_PASSWORD_ENV_VAR
        )
    })
}

fn set_database_url() -> String {
    load_env_file();
    std_env::var(env::DATABASE_URL_ENV_VAR).unwrap_or_else(|_| {
        panic!(
            "{} environment variable must be set.",
            env::DATABASE_URL_ENV_VAR
        )
    })
}

fn set_redis_hostname() -> String {
    load_env_file();
    std_env::var(env::REDIS_HOSTNAME_ENV_VAR).unwrap_or(env::DEFAULT_REDIS_HOSTNAME.to_owned())
}

fn set_redis_port() -> u32 {
    load_env_file();
    std_env::var(env::REDIS_PORT_ENV_VAR)
        .map(|v| v.parse::<u32>().expect("REDIS_PORT should be of type u32"))
        .unwrap_or(env::DEFAULT_REDIS_PORT)
}

pub mod env {
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
    pub const ASSETS_DIR_ENV_VAR: &str = "ASSETS_DIR";
    pub const POSTGRES_PASSWORD_ENV_VAR: &str = "POSTGRES_PASSWORD";
    pub const DATABASE_URL_ENV_VAR: &str = "DATABASE_URL";
    pub const REDIS_HOSTNAME_ENV_VAR: &str = "REDIS_HOSTNAME";
    pub const REDIS_PORT_ENV_VAR: &str = "REDIS_PORT";
    pub const DEFAULT_REDIS_HOSTNAME: &str = "127.0.0.1";
    pub const DEFAULT_REDIS_PORT: u32 = 6379;
}

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:3000";
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:0";
}

pub const JWT_COOKIE_NAME: &str = "jwt";
