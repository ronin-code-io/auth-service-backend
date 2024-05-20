extern crate dotenv;

use dotenv::dotenv;
use auth_service::Application;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let app = Application::build("0.0.0.0:3000")
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
