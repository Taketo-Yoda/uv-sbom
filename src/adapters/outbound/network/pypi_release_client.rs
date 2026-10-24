use crate::ports::outbound::ReleaseRepository;
use crate::sbom_generation::domain::advisory::ReleaseStatus;
use crate::shared::response_size_guard;
use crate::shared::Result;
use async_trait::async_trait;
use reqwest::StatusCode;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Default, Deserialize)]
struct PyPiReleaseInfo {
    #[serde(default)]
    yanked: bool,
}

#[derive(Debug, Default, Deserialize)]
struct PyPiReleaseFile {
    #[serde(default)]
    yanked: bool,
}

#[derive(Debug, Default, Deserialize)]
struct PyPiVersionResponse {
    #[serde(default)]
    info: PyPiReleaseInfo,
    #[serde(default)]
    urls: Vec<PyPiReleaseFile>,
}

/// PyPiReleaseClient adapter for checking whether a specific version is published on PyPI
///
/// Queries the version-level endpoint (`/pypi/{name}/{version}/json`) and
/// classifies the version as released, yanked, or not found. Used by
/// `--incident` mode to decide whether a fixed version is installable.
#[derive(Clone)]
pub struct PyPiReleaseClient {
    client: reqwest::Client,
    base_url: String,
}

impl PyPiReleaseClient {
    const MAX_RETRIES: u32 = 3;
    // 10 MB — well above any realistic PyPI release metadata response
    const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

    /// Shared constructor logic for [`Self::new`] and [`Self::new_with_base_url`].
    fn build(base_url: String) -> Result<Self> {
        let version = env!("CARGO_PKG_VERSION");
        let user_agent = format!("uv-sbom/{}", version);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(user_agent)
            .build()?;

        Ok(Self { client, base_url })
    }

    /// Creates a new PyPI release client with default configuration
    ///
    /// # Errors
    /// Returns an error if the underlying HTTP client fails to build.
    pub fn new() -> Result<Self> {
        Self::build("https://pypi.org".to_string())
    }

    /// Creates a client pointed at a custom base URL (e.g. a wiremock server),
    /// for tests only.
    #[cfg(test)]
    fn new_with_base_url(base_url: impl Into<String>) -> Result<Self> {
        Self::build(base_url.into())
    }

    /// Fetches the version-level metadata; HTTP 404 is `Ok(None)`.
    ///
    /// Returning 404 as a success (rather than an error) is what keeps
    /// `fetch_with_retry` from retrying a definitive "not published" answer.
    async fn fetch_from_pypi(
        &self,
        package_name: &str,
        version: &str,
    ) -> Result<Option<PyPiVersionResponse>> {
        crate::shared::security::validate_url_component(package_name, "Package name")
            .map_err(crate::shared::http_retry::permanent)?;
        crate::shared::security::validate_url_component(version, "Package version")
            .map_err(crate::shared::http_retry::permanent)?;
        let encoded_name = urlencoding::encode(package_name);
        let encoded_version = urlencoding::encode(version);
        let url = format!(
            "{}/pypi/{}/{}/json",
            self.base_url, encoded_name, encoded_version
        );

        let response = self.client.get(&url).send().await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            anyhow::bail!("PyPI API returned status code {}", response.status());
        }
        let bytes = response_size_guard::read_bounded_bytes(
            response,
            Self::MAX_RESPONSE_BYTES,
            Some("PyPI release metadata"),
        )
        .await?;
        Ok(Some(serde_json::from_slice::<PyPiVersionResponse>(&bytes)?))
    }

    /// A version is yanked when PyPI marks the release yanked, or when it has
    /// files and every one of them is yanked. A partially yanked release is
    /// still installable, so it counts as released.
    fn classify(response: &PyPiVersionResponse) -> ReleaseStatus {
        let all_files_yanked =
            !response.urls.is_empty() && response.urls.iter().all(|file| file.yanked);
        if response.info.yanked || all_files_yanked {
            ReleaseStatus::Yanked
        } else {
            ReleaseStatus::Released
        }
    }
}

#[async_trait]
impl ReleaseRepository for PyPiReleaseClient {
    async fn release_status(&self, package_name: &str, version: &str) -> Result<ReleaseStatus> {
        let response = crate::shared::http_retry::fetch_with_retry(Self::MAX_RETRIES, || {
            self.fetch_from_pypi(package_name, version)
        })
        .await?;
        Ok(response.map_or(ReleaseStatus::NotFound, |r| Self::classify(&r)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const RELEASE_PATH: &str = "/pypi/requests/2.31.0/json";

    async fn status_for(body: serde_json::Value) -> ReleaseStatus {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(RELEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&mock_server)
            .await;

        let client = PyPiReleaseClient::new_with_base_url(mock_server.uri()).unwrap();
        client.release_status("requests", "2.31.0").await.unwrap()
    }

    #[test]
    fn test_pypi_release_client_creation() {
        assert!(PyPiReleaseClient::new().is_ok());
    }

    #[tokio::test]
    async fn test_release_status_released() {
        let status = status_for(serde_json::json!({
            "info": { "name": "requests", "version": "2.31.0", "yanked": false },
            "urls": [
                { "filename": "requests-2.31.0-py3-none-any.whl", "yanked": false },
                { "filename": "requests-2.31.0.tar.gz", "yanked": false }
            ]
        }))
        .await;
        assert_eq!(status, ReleaseStatus::Released);
    }

    #[tokio::test]
    async fn test_release_status_yanked_via_info() {
        let status = status_for(serde_json::json!({
            "info": { "name": "requests", "version": "2.31.0", "yanked": true },
            "urls": [
                { "filename": "requests-2.31.0-py3-none-any.whl", "yanked": true }
            ]
        }))
        .await;
        assert_eq!(status, ReleaseStatus::Yanked);
    }

    #[tokio::test]
    async fn test_release_status_yanked_when_every_file_yanked() {
        let status = status_for(serde_json::json!({
            "info": { "yanked": false },
            "urls": [
                { "filename": "a.whl", "yanked": true },
                { "filename": "a.tar.gz", "yanked": true }
            ]
        }))
        .await;
        assert_eq!(status, ReleaseStatus::Yanked);
    }

    #[tokio::test]
    async fn test_release_status_partially_yanked_is_released() {
        let status = status_for(serde_json::json!({
            "info": { "yanked": false },
            "urls": [
                { "filename": "a.whl", "yanked": true },
                { "filename": "a.tar.gz", "yanked": false }
            ]
        }))
        .await;
        assert_eq!(status, ReleaseStatus::Released);
    }

    #[tokio::test]
    async fn test_release_status_no_files_is_released() {
        let status = status_for(serde_json::json!({ "info": {}, "urls": [] })).await;
        assert_eq!(status, ReleaseStatus::Released);
    }

    #[tokio::test]
    async fn test_release_status_not_found_is_not_retried() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(RELEASE_PATH))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = PyPiReleaseClient::new_with_base_url(mock_server.uri()).unwrap();
        let status = client.release_status("requests", "2.31.0").await.unwrap();
        assert_eq!(status, ReleaseStatus::NotFound);
    }

    #[tokio::test]
    async fn test_release_status_server_error_is_retried_then_err() {
        // A 5xx must surface as an error, never as NotFound: the domain treats
        // an unknown release status differently from "not published".
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(RELEASE_PATH))
            .respond_with(ResponseTemplate::new(500))
            .expect(PyPiReleaseClient::MAX_RETRIES as u64)
            .mount(&mock_server)
            .await;

        let client = PyPiReleaseClient::new_with_base_url(mock_server.uri()).unwrap();
        let err = client
            .release_status("requests", "2.31.0")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("500"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn test_release_status_invalid_version_rejected() {
        let client = PyPiReleaseClient::new_with_base_url("http://127.0.0.1:1").unwrap();
        assert!(client.release_status("requests", "../x").await.is_err());
    }

    #[tokio::test]
    async fn test_release_status_rejects_oversized_response_without_retry() {
        let mock_server = MockServer::start().await;
        let body = vec![b' '; PyPiReleaseClient::MAX_RESPONSE_BYTES + 1];
        Mock::given(method("GET"))
            .and(path(RELEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = PyPiReleaseClient::new_with_base_url(mock_server.uri()).unwrap();
        let err = client
            .release_status("requests", "2.31.0")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("too large"), "unexpected error: {msg}");
        assert!(
            msg.contains("PyPI release metadata"),
            "unexpected error: {msg}"
        );
    }
}
