use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use application::core::services::errors::ServiceError;

#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<&'static str>,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: Option<&'static str>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            message: None,
        }
    }

    pub fn with_message(mut self, message: &'static str) -> Self {
        self.message = Some(message);
        self
    }

    pub fn bad_request(code: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code)
    }

    pub fn unauthorized(code: &'static str) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code)
    }

    pub fn forbidden(code: &'static str) -> Self {
        Self::new(StatusCode::FORBIDDEN, code)
    }

    pub fn not_found(code: &'static str) -> Self {
        Self::new(StatusCode::NOT_FOUND, code)
    }

    pub fn conflict(code: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, code)
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                code: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

pub fn map_service_error(err: ServiceError, log_context: &'static str) -> ApiError {
    match err {
        ServiceError::Unauthorized => ApiError::unauthorized("unauthorized"),
        ServiceError::TokenExpired => ApiError::unauthorized("token_expired"),
        ServiceError::Forbidden => ApiError::forbidden("forbidden"),
        ServiceError::Conflict => ApiError::conflict("conflict"),
        ServiceError::NotFound => ApiError::not_found("not_found"),
        ServiceError::BadRequest(code) => ApiError::bad_request(code).with_message(code),
        ServiceError::Unexpected(inner) => {
            tracing::error!(error = ?inner, context = log_context, "service_error");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    }
}

pub fn map_service_error_no_log(err: ServiceError) -> ApiError {
    match err {
        ServiceError::Unauthorized => ApiError::unauthorized("unauthorized"),
        ServiceError::TokenExpired => ApiError::unauthorized("token_expired"),
        ServiceError::Forbidden => ApiError::forbidden("forbidden"),
        ServiceError::Conflict => ApiError::conflict("conflict"),
        ServiceError::NotFound => ApiError::not_found("not_found"),
        ServiceError::BadRequest(code) => ApiError::bad_request(code).with_message(code),
        ServiceError::Unexpected(_) => {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    }
}
