use anyhow::Result;

use api::bootstrap::app;

#[tokio::main]
async fn main() -> Result<()> {
    app::run().await
}
