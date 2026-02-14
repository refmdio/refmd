//! Integration tests for RefMD
//!
//! This crate contains integration tests that test the full stack,
//! from HTTP requests through to the database.
//!
//! ## Running tests
//!
//! Tests that require a database connection are gated behind the
//! `TEST_DATABASE_URL` environment variable. To run all tests:
//!
//! ```sh
//! TEST_DATABASE_URL=postgres://... cargo test -p tests
//! ```
//!
//! Without `TEST_DATABASE_URL`, only non-DB tests will run.

#[cfg(test)]
mod helpers;

#[cfg(test)]
mod tests;
