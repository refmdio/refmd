use std::cell::Cell;

use axum::http::{Request, StatusCode, header};
use axum::{body::Body, middleware::Next, response::Response};

tokio::task_local! {
    static TOKEN_EXPIRED_FLAG: Cell<bool>;
}

pub fn mark_token_expired() {
    let _ = TOKEN_EXPIRED_FLAG.try_with(|flag| flag.set(true));
}

pub async fn middleware(req: Request<Body>, next: Next) -> Response {
    TOKEN_EXPIRED_FLAG
        .scope(Cell::new(false), async move {
            let mut response = next.run(req).await;
            let expired = TOKEN_EXPIRED_FLAG.with(|flag| flag.get());
            if expired && response.status() == StatusCode::UNAUTHORIZED {
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    header::HeaderValue::from_static("Bearer error=\"token_expired\""),
                );
            }
            response
        })
        .await
}

