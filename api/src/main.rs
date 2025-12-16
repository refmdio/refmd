use anyhow::Result;

use bootstrap::app;

#[tokio::main]
async fn main() -> Result<()> {
    app::run().await
}
