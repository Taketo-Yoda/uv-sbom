use crate::ports::outbound::{PythonCompatibilityInfo, PythonCompatibilityRepository};
use crate::shared::Result;
use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Default, Deserialize)]
struct PyPiInfo {
    #[serde(default)]
    requires_python: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PyPiVersionResponse {
    #[serde(default)]
    info: PyPiInfo,
}

/// PyPiCompatibilityClient adapter for fetching `Requires-Python` metadata from PyPI
///
/// Queries the version-level endpoint (`/pypi/{name}/{version}/json`) to
/// retrieve the `Requires-Python` constraint declared for a specific locked
/// package version, used for target-Python compatibility checking.
#[derive(Clone)]
pub struct PyPiCompatibilityClient {
    client: reqwest::Client,
    base_url: String,
}

impl PyPiCompatibilityClient {
    const MAX_RETRIES: u32 = 3;
    // 10 MB — well above any realistic PyPI package metadata response
    const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

    /// Creates a new PyPI compatibility client with default configuration
    ///
    /// # Errors
    /// Returns an error if the underlying HTTP client fails to build.
    pub fn new() -> Result<Self> {
        let version = env!("CARGO_PKG_VERSION");
        let user_agent = format!("uv-sbom/{}", version);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(user_agent)
            .build()?;

        Ok(Self {
            client,
            base_url: "https://pypi.org".to_string(),
        })
    }

    #[cfg(test)]
    fn new_with_base_url_and_timeout(
        base_url: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self> {
        let user_agent = format!("uv-sbom/{}", env!("CARGO_PKG_VERSION"));
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(user_agent)
            .build()?;

        Ok(Self {
            client,
            base_url: base_url.into(),
        })
    }

    async fn fetch_from_pypi(
        &self,
        package_name: &str,
        package_version: &str,
    ) -> Result<PyPiVersionResponse> {
        crate::shared::security::validate_url_component(package_name, "Package name")?;
        crate::shared::security::validate_url_component(package_version, "Package version")?;
        let encoded_name = urlencoding::encode(package_name);
        let encoded_version = urlencoding::encode(package_version);
        let url = format!(
            "{}/pypi/{}/{}/json",
            self.base_url, encoded_name, encoded_version
        );

        let response = self.client.get(&url).send().await?;
        if !response.status().is_success() {
            anyhow::bail!("PyPI API returned status code {}", response.status());
        }
        // Reject oversized responses before allocating memory
        if let Some(len) = response.content_length() {
            if len as usize > Self::MAX_RESPONSE_BYTES {
                anyhow::bail!("PyPI API response too large: {} bytes", len);
            }
        }
        let bytes = response.bytes().await?;
        if bytes.len() > Self::MAX_RESPONSE_BYTES {
            anyhow::bail!(
                "PyPI API response exceeded {} byte limit",
                Self::MAX_RESPONSE_BYTES
            );
        }
        Ok(serde_json::from_slice::<PyPiVersionResponse>(&bytes)?)
    }

    async fn fetch_with_retry(
        &self,
        package_name: &str,
        package_version: &str,
    ) -> Result<PyPiVersionResponse> {
        crate::shared::http_retry::fetch_with_retry(Self::MAX_RETRIES, || {
            self.fetch_from_pypi(package_name, package_version)
        })
        .await
    }
}

#[async_trait]
impl PythonCompatibilityRepository for PyPiCompatibilityClient {
    async fn fetch_python_compatibility(
        &self,
        package_name: &str,
        package_version: &str,
    ) -> Result<PythonCompatibilityInfo> {
        let resp = self.fetch_with_retry(package_name, package_version).await?;
        Ok(PythonCompatibilityInfo {
            requires_python: resp.info.requires_python,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_pypi_compatibility_client_creation() {
        assert!(PyPiCompatibilityClient::new().is_ok());
    }

    #[test]
    fn test_deserialize_requires_python_present() {
        let json = r#"{"info": {"requires_python": ">=3.8,<3.12"}}"#;
        let response: PyPiVersionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            response.info.requires_python,
            Some(">=3.8,<3.12".to_string())
        );
    }

    #[test]
    fn test_deserialize_requires_python_absent() {
        let json = r#"{"info": {}}"#;
        let response: PyPiVersionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.info.requires_python, None);
    }

    #[test]
    fn test_deserialize_requires_python_null() {
        let json = r#"{"info": {"requires_python": null}}"#;
        let response: PyPiVersionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.info.requires_python, None);
    }

    #[test]
    fn test_deserialize_minimal_response() {
        let json = r#"{}"#;
        let response: PyPiVersionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.info.requires_python, None);
    }

    #[tokio::test]
    async fn test_fetch_python_compatibility_present() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/2.31.0/json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"info": {"requires_python": ">=3.7"}})),
            )
            .mount(&mock_server)
            .await;

        let client = PyPiCompatibilityClient::new_with_base_url_and_timeout(
            mock_server.uri(),
            Duration::from_secs(5),
        )
        .unwrap();

        let info = client
            .fetch_python_compatibility("requests", "2.31.0")
            .await
            .unwrap();
        assert_eq!(info.requires_python, Some(">=3.7".to_string()));
    }

    #[tokio::test]
    async fn test_fetch_python_compatibility_absent_field() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/somepkg/1.0.0/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"info": {}})))
            .mount(&mock_server)
            .await;

        let client = PyPiCompatibilityClient::new_with_base_url_and_timeout(
            mock_server.uri(),
            Duration::from_secs(5),
        )
        .unwrap();

        let info = client
            .fetch_python_compatibility("somepkg", "1.0.0")
            .await
            .unwrap();
        assert_eq!(info.requires_python, None);
    }

    #[tokio::test]
    async fn test_fetch_python_compatibility_not_found() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/nonexistent/9.9.9/json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = PyPiCompatibilityClient::new_with_base_url_and_timeout(
            mock_server.uri(),
            Duration::from_secs(5),
        )
        .unwrap();

        let result = client
            .fetch_python_compatibility("nonexistent", "9.9.9")
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_python_compatibility_malformed_json() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/badjson/1.0.0/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
            .mount(&mock_server)
            .await;

        let client = PyPiCompatibilityClient::new_with_base_url_and_timeout(
            mock_server.uri(),
            Duration::from_secs(5),
        )
        .unwrap();

        let result = client.fetch_python_compatibility("badjson", "1.0.0").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_python_compatibility_timeout() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/slowpkg/1.0.0/json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"info": {"requires_python": ">=3.8"}}))
                    .set_delay(Duration::from_millis(500)),
            )
            .mount(&mock_server)
            .await;

        let client = PyPiCompatibilityClient::new_with_base_url_and_timeout(
            mock_server.uri(),
            Duration::from_millis(150),
        )
        .unwrap();

        let result = client.fetch_python_compatibility("slowpkg", "1.0.0").await;
        assert!(result.is_err());
    }
}
