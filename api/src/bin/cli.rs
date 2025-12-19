#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli_app::run().await
}
