pub fn init_tracing() {
    use std::io;
    use tracing_subscriber::fmt::writer::MakeWriterExt;

    let filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| "api=debug,warp=info,axum=info,tower_http=info".into());

    tracing_subscriber::fmt()
        .with_env_filter(&filter)
        .with_writer(io::stderr.with_max_level(tracing::Level::TRACE))
        .with_ansi(false)
        .init();

    eprintln!("[telemetry] tracing initialized with filter: {filter}");
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_tracing_idempotent() {
        // Should not panic on multiple init calls in tests.
        let _ = std::panic::catch_unwind(super::init_tracing);
        let _ = std::panic::catch_unwind(super::init_tracing);
    }
}
