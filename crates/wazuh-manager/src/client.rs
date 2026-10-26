use std::time::Instant;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use wazuh_core::{BulkFailure, ManagerConfig, WazuhError};

use crate::rate_limiter::RateLimiter;

/// A query string as an ordered list of key/value pairs. Values are URL-encoded
/// by reqwest (unlike hand-rolled `format!("{}={}", k, v)` strings, which break
/// on spaces / `&` / `=`).
pub type Query = Vec<(String, String)>;

#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl From<HttpMethod> for reqwest::Method {
    fn from(m: HttpMethod) -> Self {
        match m {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
        }
    }
}

/// Raw Wazuh response envelope: `{"data": ..., "error": 0|1|2, "message": ...}`.
///
/// `error` is `0` (complete), `1` (failed) or `2` (partial). HTTP 200 does not
/// imply success — callers must inspect this field, which is what
/// [`WazuhResponse::into_bulk`] does.
#[derive(Debug, Clone, Deserialize)]
pub struct WazuhResponse {
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub error: i64,
    #[serde(default)]
    pub message: Option<String>,
}

/// Wazuh's `failed_items` entry shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedItem {
    #[serde(default)]
    pub error: Option<Value>,
    #[serde(default)]
    pub id: Vec<Value>,
}

/// Typed bulk result separating affected from failed items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResponse<A, F = FailedItem> {
    #[serde(default = "Vec::new")]
    pub affected_items: Vec<A>,
    #[serde(default)]
    pub total_affected_items: u64,
    #[serde(default = "Vec::new")]
    pub failed_items: Vec<F>,
    #[serde(default)]
    pub total_failed_items: u64,
}

/// Server/API info returned by `GET /`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiInfo {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub api_version: Option<String>,
    /// Wazuh returns this as an integer in some versions and a string in
    /// others, so deserialize leniently.
    #[serde(default, deserialize_with = "string_or_number_as_string")]
    pub revision: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
    /// Any fields not modeled above, preserved for forward compatibility.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Deserialize a field that Wazuh may return as either a JSON string or a
/// number, normalizing both to a `String`.
fn string_or_number_as_string<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(d)?;
    Ok(value.and_then(|v| match v {
        Value::String(s) => Some(s),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }))
}

impl WazuhResponse {
    /// Deserialize `data` into a typed [`BulkResponse`], surfacing partial or
    /// failed operations as a [`WazuhError::Partial`] carrying the failed items.
    pub fn into_bulk<A: DeserializeOwned, F: DeserializeOwned>(
        self,
    ) -> Result<BulkResponse<A, F>, WazuhError> {
        if self.error == 0 {
            return serde_json::from_value(self.data)
                .map_err(|e| WazuhError::Json(format!("malformed response data: {e}")));
        }

        let failed_items = match self.data.get("failed_items") {
            Some(Value::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        let total_affected = self
            .data
            .get("total_affected_items")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        Err(WazuhError::Partial(BulkFailure {
            total_affected,
            total_failed: failed_items.len() as u64,
            failed_items,
        }))
    }
}

/// The Manager API client.
///
/// Holds a single unauthenticated `reqwest::Client` (built once with the TLS /
/// timeout settings) plus a `Mutex`-guarded token state. Every request flows
/// through [`ManagerClient::request`].
pub struct ManagerClient {
    http: reqwest::Client,
    base_url: String,
    config: ManagerConfig,
    auth: Mutex<AuthState>,
    limiter: RateLimiter,
}

#[derive(Default)]
struct AuthState {
    token: Option<String>,
    acquired_at: Option<Instant>,
}

impl ManagerClient {
    pub fn new(config: ManagerConfig) -> Result<Self, WazuhError> {
        config.validate()?;
        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .danger_accept_invalid_certs(!config.verify_tls);

        if let Some(ca_path) = &config.ca_cert {
            let pem = std::fs::read(ca_path).map_err(|e| {
                WazuhError::Config(format!(
                    "failed to read CA certificate {}: {e}",
                    ca_path.display()
                ))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
                WazuhError::Config(format!(
                    "failed to parse CA certificate {}: {e}",
                    ca_path.display()
                ))
            })?;
            builder = builder.add_root_certificate(cert);
        }

        let http = builder
            .build()
            .map_err(|e| WazuhError::Config(format!("failed to build http client: {e}")))?;

        Ok(Self {
            base_url: config.base_url(),
            limiter: RateLimiter::new(config.rate_limit_max, config.rate_limit_period),
            http,
            auth: Mutex::new(AuthState::default()),
            config,
        })
    }

    pub fn config(&self) -> &ManagerConfig {
        &self.config
    }

    /// Fetch server/API info from `GET /`.
    ///
    /// This goes through the full [`ManagerClient::request`] path (rate limit →
    /// auth → send), so it doubles as a connectivity *and* auth check — the
    /// basis for the CLI's `ping` command.
    pub async fn api_info(&self) -> Result<ApiInfo, WazuhError> {
        let resp = self.request(HttpMethod::Get, "/", None, None).await?;
        serde_json::from_value(resp.data)
            .map_err(|e| WazuhError::Json(format!("malformed api info: {e}")))
    }

    /// The single request choke point.
    ///
    /// Order: rate limit → proactive token refresh → send → on 401, re-auth once
    /// and retry. Every typed resource method goes through here.
    pub async fn request(
        &self,
        method: HttpMethod,
        path: &str,
        query: Option<&Query>,
        body: Option<&Value>,
    ) -> Result<WazuhResponse, WazuhError> {
        self.limiter.acquire().await;
        let token = self.ensure_token().await?;

        match self.send(method, path, query, body, Some(&token)).await {
            Err(WazuhError::Unauthorized) => {
                warn!("got 401 with a fresh token; re-authenticating once");
                let fresh = self.authenticate().await?;
                self.send(method, path, query, body, Some(&fresh)).await
            }
            other => other,
        }
    }

    async fn send(
        &self,
        method: HttpMethod,
        path: &str,
        query: Option<&Query>,
        body: Option<&Value>,
        token: Option<&str>,
    ) -> Result<WazuhResponse, WazuhError> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.request(method.into(), &url);
        if let Some(q) = query {
            req = req.query(q);
        }
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(b);
        }

        let resp = req.send().await.map_err(|e| map_reqwest_error(e))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| map_reqwest_error(e))?;

        if !(200..300).contains(&status) {
            return Err(WazuhError::from_http_response(status, &url, Some(&text)));
        }

        let value: Value = serde_json::from_str(&text)
            .map_err(|e| WazuhError::Json(format!("response is not valid json: {e}")))?;
        serde_json::from_value(value)
            .map_err(|e| WazuhError::Json(format!("unexpected response envelope: {e}")))
    }

    /// Return a fresh token, refreshing proactively if the cached one is older
    /// than `token_ttl`.
    async fn ensure_token(&self) -> Result<String, WazuhError> {
        let mut state = self.auth.lock().await;
        if let (Some(token), Some(at)) = (&state.token, state.acquired_at) {
            if at.elapsed() < self.config.token_ttl {
                return Ok(token.clone());
            }
            debug!("token older than {:?}; refreshing proactively", self.config.token_ttl);
        }
        self.authenticate_locked(&mut state).await
    }

    /// Force re-authentication (used on the reactive 401 path).
    async fn authenticate(&self) -> Result<String, WazuhError> {
        let mut state = self.auth.lock().await;
        self.authenticate_locked(&mut state).await
    }

    /// POST /security/user/authenticate with HTTP Basic auth → JWT.
    ///
    /// Deliberately **not** routed through `request()` to avoid recursion.
    async fn authenticate_locked(&self, state: &mut AuthState) -> Result<String, WazuhError> {
        let url = format!("{}/security/user/authenticate", self.base_url);
        let resp = self
            .http
            .post(&url)
            .basic_auth(self.config.username.clone(), Some(self.config.password.clone()))
            .send()
            .await
            .map_err(|e| map_reqwest_error(e))?;

        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(|e| map_reqwest_error(e))?;

        if status == 401 {
            return Err(WazuhError::Auth {
                message: "invalid credentials".into(),
            });
        }
        if !(200..300).contains(&status) {
            return Err(WazuhError::from_http_response(status, &url, Some(&text)));
        }

        let value: Value = serde_json::from_str(&text)
            .map_err(|e| WazuhError::Json(format!("auth response is not valid json: {e}")))?;
        let token = value
            .pointer("/data/token")
            .and_then(Value::as_str)
            .ok_or_else(|| WazuhError::Json("auth response missing data.token".into()))?
            .to_owned();

        debug!("authenticated; token acquired");
        state.token = Some(token.clone());
        state.acquired_at = Some(Instant::now());
        Ok(token)
    }
}

fn map_reqwest_error(e: reqwest::Error) -> WazuhError {
    if e.is_timeout() {
        return WazuhError::Timeout;
    }
    // A TLS handshake / certificate failure is not a connectivity problem —
    // surface it distinctly so the caller can point at the right remediation.
    if let Some(message) = tls_error_message(&e) {
        return WazuhError::Tls { message };
    }
    WazuhError::Network {
        source: Box::new(e),
    }
}

/// Walk the error source chain looking for a TLS / certificate failure.
///
/// reqwest wraps hyper, which wraps rustls; the meaningful message (e.g.
/// `invalid peer certificate: UnknownIssuer`) lives several layers down, so we
/// inspect the whole chain rather than just the top-level error.
fn tls_error_message(e: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        let lower = err.to_string().to_lowercase();
        if lower.contains("certificate")
            || lower.contains("tls")
            || lower.contains("handshake")
            || lower.contains("unknownissuer")
            || lower.contains("invalid peer")
        {
            return Some(err.to_string());
        }
        cur = err.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_complete_envelope() {
        let v = json!({
            "data": {
                "affected_items": [{"id": "001", "name": "a"}],
                "total_affected_items": 1
            },
            "error": 0
        });
        let env: WazuhResponse = serde_json::from_value(v).unwrap();
        assert_eq!(env.error, 0);
        let bulk: BulkResponse<Value> = env.into_bulk().unwrap();
        assert_eq!(bulk.affected_items.len(), 1);
        assert_eq!(bulk.total_affected_items, 1);
    }

    #[test]
    fn surfaces_partial_failure() {
        let v = json!({
            "data": {
                "affected_items": [{"id": "001", "name": "a"}],
                "total_affected_items": 1,
                "failed_items": [{"error": {"code": 100, "message": "bad"}, "id": ["002"]}]
            },
            "error": 2
        });
        let env: WazuhResponse = serde_json::from_value(v).unwrap();
        let err = env.into_bulk::<Value, Value>().unwrap_err();
        match err {
            WazuhError::Partial(f) => {
                assert_eq!(f.total_failed, 1);
                assert_eq!(f.failed_items.len(), 1);
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    #[test]
    fn maps_401_to_unauthorized() {
        let err = WazuhError::from_http_response(401, "https://x:55000/a", Some("{}"));
        assert!(matches!(err, WazuhError::Unauthorized));
    }

    #[test]
    fn parses_structured_api_error() {
        let body = r#"{"title":"Bad Request","detail":"invalid param","remediation":"fix it","error":{"code":1729}}"#;
        let err = WazuhError::from_http_response(400, "https://x:55000/a", Some(body));
        match err {
            WazuhError::Api { code, title, .. } => {
                assert_eq!(code, 1729);
                assert_eq!(title, "Bad Request");
            }
            other => panic!("expected Api, got {other:?}"),
        }
    }

    #[test]
    fn falls_back_to_http_error_on_unparseable_body() {
        let err = WazuhError::from_http_response(500, "https://x:55000/a", Some("not json"));
        assert!(matches!(err, WazuhError::Http { status: 500, .. }));
    }

    #[test]
    fn parses_api_info() {
        let v = json!({
            "data": {
                "title": "Wazuh API",
                "api_version": "4.9.2",
                "revision": 40902,
                "hostname": "single-cluster",
                "type": "wazuh",
                "timestamp": "2024-01-01T00:00:00Z"
            },
            "error": 0
        });
        let env: WazuhResponse = serde_json::from_value(v).unwrap();
        let info: ApiInfo = serde_json::from_value(env.data).unwrap();
        assert_eq!(info.api_version.as_deref(), Some("4.9.2"));
        assert_eq!(info.hostname.as_deref(), Some("single-cluster"));
    }

    #[derive(Debug)]
    struct TestError(&'static str);

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for TestError {}

    #[test]
    fn detects_tls_error_deep_in_chain() {
        // Simulate reqwest -> hyper -> rustls: the TLS message is buried.
        let inner = TestError("invalid peer certificate: UnknownIssuer");
        let mid = std::io::Error::new(std::io::ErrorKind::Other, inner);
        let chain = std::io::Error::new(std::io::ErrorKind::Other, mid);

        let msg = tls_error_message(&chain).expect("should find the TLS message");
        assert!(msg.contains("UnknownIssuer"));
    }

    #[test]
    fn does_not_flag_plain_connect_error_as_tls() {
        let err = TestError("connection refused");
        assert!(tls_error_message(&err).is_none());
    }
}
