//! Client for the Wazuh Manager REST API (port 55000).
//!
//! The transport is a single choke point ([`ManagerClient::request`]) that
//! composes every guardrail in one place — client-side rate limiting, proactive
//! token refresh, and a single reactive retry on 401 — so typed resource
//! methods can't accidentally bypass them. Resource modules (`agents`, ...) are
//! feature-gated so you only compile in what you use.

pub mod agents;
mod client;
mod rate_limiter;

pub use client::{
    ApiInfo, BulkResponse, FailedItem, HttpMethod, ManagerClient, Query, WazuhResponse,
};
