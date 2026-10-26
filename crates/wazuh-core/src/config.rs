use std::time::Duration;

use crate::error::WazuhError;

/// Common configuration for talking to a Wazuh Manager.
///
/// Defaults are chosen to be safe by default: TLS verification is **on**, and
/// there is **no** fallback to default credentials. The token TTL defaults to
/// 840s — a 60s safety margin under Wazuh's server default of 900s — and the
/// client-side rate limit defaults to 12 req / 3s (~240 req/min), safely under
/// Wazuh's default server limit of 300 req/min.
#[derive(Debug, Clone)]
pub struct ManagerConfig {
    /// Manager hostname or IP. May include an `https://` / `http://` scheme;
    /// if omitted, `https` is assumed.
    pub host: String,
    /// Manager REST API port (default 55000).
    pub port: u16,
    /// API username.
    pub username: String,
    /// API password.
    pub password: String,
    /// Verify TLS certificates. Defaults to `true`.
    pub verify_tls: bool,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Proactive token refresh interval (default 840s).
    pub token_ttl: Duration,
    /// Max requests allowed within `rate_limit_period`.
    pub rate_limit_max: usize,
    /// Sliding-window period for the rate limiter.
    pub rate_limit_period: Duration,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            host: "localhost".into(),
            port: 55000,
            username: String::new(),
            password: String::new(),
            verify_tls: true,
            timeout: Duration::from_secs(30),
            token_ttl: Duration::from_secs(840),
            rate_limit_max: 12,
            rate_limit_period: Duration::from_secs(3),
        }
    }
}

impl ManagerConfig {
    /// Build the base URL (`scheme://host:port`) used to prefix request paths.
    pub fn base_url(&self) -> String {
        let host = self.host.trim().trim_end_matches('/');
        if let Some(rest) = host.strip_prefix("https://") {
            join("https", rest.trim_end_matches('/'), self.port)
        } else if let Some(rest) = host.strip_prefix("http://") {
            join("http", rest.trim_end_matches('/'), self.port)
        } else {
            join("https", host, self.port)
        }
    }

    /// Validate required fields. Returns a `Config` error on the first problem.
    pub fn validate(&self) -> Result<(), WazuhError> {
        if self.host.trim().is_empty() {
            return Err(WazuhError::Config("host must not be empty".into()));
        }
        if self.username.is_empty() {
            return Err(WazuhError::Config("username must not be empty".into()));
        }
        Ok(())
    }
}

fn join(scheme: &str, host: &str, port: u16) -> String {
    // If the host already carries a port, don't append another one.
    if host.contains(':') {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_defaults_to_https_and_port() {
        let cfg = ManagerConfig {
            host: "wazuh.example.com".into(),
            ..Default::default()
        };
        assert_eq!(cfg.base_url(), "https://wazuh.example.com:55000");
    }

    #[test]
    fn base_url_respects_explicit_scheme() {
        let cfg = ManagerConfig {
            host: "http://10.0.0.5".into(),
            ..Default::default()
        };
        assert_eq!(cfg.base_url(), "http://10.0.0.5:55000");
    }

    #[test]
    fn base_url_keeps_explicit_port() {
        let cfg = ManagerConfig {
            host: "https://wazuh.example.com:8443".into(),
            ..Default::default()
        };
        assert_eq!(cfg.base_url(), "https://wazuh.example.com:8443");
    }

    #[test]
    fn validate_rejects_empty_host_and_user() {
        assert!(ManagerConfig::default().validate().is_err());
        let cfg = ManagerConfig {
            host: "wazuh.example.com".into(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
