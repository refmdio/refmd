#[tokio::main]
async fn main() -> anyhow::Result<()> {
    api_app::run().await
}
