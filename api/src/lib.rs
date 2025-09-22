// Module layout (Clean Architecture style)
// - bootstrap: configuration and startup
// - infrastructure: DB/filesystem/crypto/realtime adapters
// - presentation: HTTP/WS handlers and routing
// - application: cross-cutting policies and domain services
// - domain: core models

pub mod application;
pub mod bootstrap;
pub mod domain;
pub mod infrastructure;
pub mod presentation;
