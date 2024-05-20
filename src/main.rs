extern crate dotenv;

use auth_service::Application;
use dotenv::dotenv;

#[tokio::main]
async fn main() {
    match dotenv() {
        Ok(_) => println!("Loaded env file."),
        Err(_) => println!("Failed to load env file!"),
    }

    let app = Application::build("0.0.0.0:3000")
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
