//! Identity services
//!
//! Application-level services for identity domain

mod registration_service;

pub use registration_service::{RegistrationData, RegistrationService, RegistrationServiceError};
