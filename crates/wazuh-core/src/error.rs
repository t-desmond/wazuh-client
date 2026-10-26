use std::error::Error as StdError;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Aggregate info about the failed half of a bulk operation.
///
/// Wazuh signals partial/failed operations through the response envelope's
/// `error` field (`0` = complete, `1` = failed, `2` = partial) rather than the
/// HTTP status. The affected items are still returned in `data`, but the
/// `failed_items` list tells you exactly what went wrong — which is what a CLI
/// needs to map to a distinct exit code.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BulkFailure {
    #[serde(default)]
    pub total_affected: u64,
    #[serde(default)]
    pub total_failed: u64,
    #[serde(default)]
    pub failed_items: Vec<Value>,
}

/// The single error type shared across all Wazuh client crates.
#[derive(Debug, thiserror::Error)]
pub enum WazuhError {
    /// Credentials were rejected during authentication.
    #[error("authentication failed: {message}")]
    Auth { message: String },

    /// A previously-issued token was rejected (401) — the reactive refresh path.
    #[error("unauthorized: token rejected or expired")]
    Unauthorized,

    /// Wazuh returned a structured API error (non-2xx, or an `error` envelope).
    #[error("wazuh api error {code}: {title}")]
    Api {
        code: i64,
        title: String,
        detail: Option<String>,
        remediation: Option<String>,
    },

    /// A non-2xx HTTP response that didn't parse as a structured Wazuh error.
    #[error("http {status} from {url}")]
    Http {
        status: u16,
        url: String,
        body: Option<String>,
    },

    /// A resource (e.g. an agent) was not found.
    #[error("resource not found: {resource} `{id}`")]
    NotFound { resource: String, id: String },

    /// A transport-level failure (DNS, connect, reset, ...).
    #[error("network error: {source}")]
    Network {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },

    /// The server's TLS certificate could not be verified (e.g. self-signed or
    /// signed by an untrusted CA). Kept distinct from [`WazuhError::Network`]
    /// so callers can point the user at the right remediation (trust the CA or
    /// disable verification) instead of blaming the network.
    #[error("tls error: {message}")]
    Tls { message: String },

    /// The request exceeded the configured timeout.
    #[error("request timed out")]
    Timeout,

    /// The response body could not be decoded.
    #[error("failed to decode response: {0}")]
    Json(String),

    /// Invalid configuration supplied by the caller.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// The operation completed only partially (Wazuh `error: 1|2`).
    #[error("operation partially failed: {} failed item(s)", .0.total_failed)]
    Partial(BulkFailure),
}

impl From<BulkFailure> for WazuhError {
    fn from(f: BulkFailure) -> Self {
        WazuhError::Partial(f)
    }
}

impl WazuhError {
    /// Build an error from a non-2xx HTTP response, leniently parsing Wazuh's
    /// error body shape: `{"title": ..., "detail": ..., "remediation": ...,
    /// "error": {"code": N}}`.
    pub fn from_http_response(status: u16, url: &str, body: Option<&str>) -> Self {
        if status == 401 {
            return WazuhError::Unauthorized;
        }

        if let Some(body) = body {
            if let Ok(v) = serde_json::from_str::<Value>(body) {
                let title = v.get("title").and_then(Value::as_str).map(str::to_owned);
                let detail = v.get("detail").and_then(Value::as_str).map(str::to_owned);
                let remediation = v
                    .get("remediation")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let code = v.get("error").and_then(|e| match e {
                    Value::Object(o) => o.get("code").and_then(Value::as_i64),
                    Value::Number(n) => n.as_i64(),
                    Value::String(s) => s.parse().ok(),
                    _ => None,
                });

                if title.is_some() || code.is_some() {
                    return WazuhError::Api {
                        code: code.unwrap_or(status as i64),
                        title: title.unwrap_or_else(|| "unknown error".into()),
                        detail,
                        remediation,
                    };
                }
            }
        }

        WazuhError::Http {
            status,
            url: url.to_owned(),
            body: body.map(str::to_owned),
        }
    }
}
