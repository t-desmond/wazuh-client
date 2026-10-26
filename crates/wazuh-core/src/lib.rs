//! Shared primitives for Wazuh clients.
//!
//! This crate deliberately has **no HTTP client opinions**: it only holds the
//! pieces that are genuinely shared between the Manager and Indexer clients —
//! the error type, the common configuration, and the auth token state. The
//! actual HTTP transport lives in `wazuh-manager` / `wazuh-indexer`.

pub mod auth;
pub mod config;
pub mod error;

pub use auth::AuthToken;
pub use config::ManagerConfig;
pub use error::{BulkFailure, WazuhError};
