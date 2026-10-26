use std::time::{Duration, Instant};

/// A JWT plus the instant it was acquired, used to decide when to refresh
/// proactively.
///
/// The refresh decision is wall-clock based (`acquired_at + ttl`). This is the
/// same approach `wazuh-api-kit` uses; a future refinement is to decode the
/// JWT's `exp` claim instead of trusting a configured TTL, which would avoid
/// the "mismatched TTL" warning class entirely.
#[derive(Debug, Clone)]
pub struct AuthToken {
    pub token: String,
    pub acquired_at: Instant,
}

impl AuthToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            acquired_at: Instant::now(),
        }
    }

    /// Whether the token is still within its configured lifetime.
    pub fn is_fresh(&self, ttl: Duration) -> bool {
        self.acquired_at.elapsed() < ttl
    }
}
