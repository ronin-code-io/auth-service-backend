use dotenv::dotenv;
use lazy_static::lazy_static;
use std::env as std_env;

lazy_static! {
    pub static ref JWT_SECRET: String = set_token();
    pub static ref ASSETS_DIR: String = set_assets_dir();
    pub static ref POSTGRES_PASSWORD: String = set_postgres_password();
}

fn load_env_file() {
    match dotenv() {
        Ok(_) => println!("Loaded env file."),
        Err(_) => println!("Failed to load env file!"),
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
    println!("Assets dir: {}", assets_dir);
    assets_dir
}

fn set_postgres_password() -> String {
    load_env_file();
    let postgres_password = std_env::var(env::POSTGRES_PASSWORD_ENV_VAR).unwrap_or_else(|_| {
        panic!(
            "{} environment variable must be set.",
            env::POSTGRES_PASSWORD_ENV_VAR
        )
    });
    postgres_password
}

pub mod env {
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
    pub const ASSETS_DIR_ENV_VAR: &str = "ASSETS_DIR";
    pub const POSTGRES_PASSWORD_ENV_VAR: &str = "POSTGRES_PASSWORD";
}

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:3000";
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:0";
}

pub const JWT_COOKIE_NAME: &str = "jwt";
