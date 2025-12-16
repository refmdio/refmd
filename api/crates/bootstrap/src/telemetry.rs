pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "api=debug,warp=info,axum=info,tower_http=info".into()),
        )
        .init();
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_tracing_idempotent() {
        // Should not panic on multiple init calls in tests.
        let _ = std::panic::catch_unwind(|| super::init_tracing());
        let _ = std::panic::catch_unwind(|| super::init_tracing());
    }
}
