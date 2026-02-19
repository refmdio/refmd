//! PoP verification Tower middleware
//!
//! Applies Proof-of-Possession verification at the routing layer so that
//! individual handlers don't need to perform it themselves.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use application::dto::{DeviceDto, SessionDto};
use application::encryption::{VerifyPopAndBindHandler, VerifyPopCommand};
use application::types::UserId;
use axum::{body::Body, http::Request, response::IntoResponse, response::Response};
use tower::{Layer, Service};

use super::pop::{extract_pop_headers, map_verify_pop_and_bind_error};
use super::session::authenticate;
use crate::state::type_aliases::{DynChallengeStore, DynDeviceRepository, DynSessionRepository};

/// PoP verification result inserted into request extensions by the middleware.
#[derive(Debug, Clone)]
pub struct PopVerifiedDevice {
    pub user_id: UserId,
    pub device: DeviceDto,
    pub session: SessionDto,
}

/// Tower [`Layer`] that wraps services with PoP verification.
#[derive(Clone)]
pub struct PopLayer {
    device_repo: DynDeviceRepository,
    session_repo: DynSessionRepository,
    challenge_store: DynChallengeStore,
}

impl PopLayer {
    pub fn new(
        device_repo: DynDeviceRepository,
        session_repo: DynSessionRepository,
        challenge_store: DynChallengeStore,
    ) -> Self {
        Self {
            device_repo,
            session_repo,
            challenge_store,
        }
    }
}

impl<S> Layer<S> for PopLayer {
    type Service = PopService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PopService {
            inner,
            device_repo: self.device_repo.clone(),
            session_repo: self.session_repo.clone(),
            challenge_store: self.challenge_store.clone(),
        }
    }
}

/// Tower [`Service`] that performs session auth + PoP verification before
/// forwarding the request to the inner service.
#[derive(Clone)]
pub struct PopService<S> {
    inner: S,
    device_repo: DynDeviceRepository,
    session_repo: DynSessionRepository,
    challenge_store: DynChallengeStore,
}

impl<S> Service<Request<Body>> for PopService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Clone the inner service for the async block (tower best practice).
        let mut inner = self.inner.clone();
        // Swap so `self.inner` holds the clone and we use the ready one.
        std::mem::swap(&mut self.inner, &mut inner);

        let device_repo = self.device_repo.clone();
        let session_repo = self.session_repo.clone();
        let challenge_store = self.challenge_store.clone();

        Box::pin(async move {
            // 1. Session authentication
            let auth = match authenticate(req.headers(), &session_repo).await {
                Ok(auth) => auth,
                Err(e) => return Ok(e.into_response()),
            };

            // 2. Extract PoP headers
            let (challenge_str, challenge_bytes, signature_bytes, device_id, device_id_str) =
                match extract_pop_headers(req.headers()) {
                    Ok(h) => h,
                    Err(e) => return Ok(e.into_response()),
                };

            // 3. Verify PoP and bind device to session
            let handler =
                VerifyPopAndBindHandler::new(device_repo, session_repo, challenge_store);

            let command = VerifyPopCommand {
                user_id: auth.user_id,
                device_id,
                challenge_str,
                challenge_bytes,
                signature_bytes,
                device_id_str,
            };

            let result = match handler.handle(command, auth.session).await {
                Ok(r) => r,
                Err(e) => return Ok(map_verify_pop_and_bind_error(e).into_response()),
            };

            // 4. Insert verified device into extensions
            let mut req = req;
            req.extensions_mut().insert(PopVerifiedDevice {
                user_id: auth.user_id,
                device: result.device,
                session: result.session,
            });

            // 5. Forward to inner service
            inner.call(req).await
        })
    }
}
