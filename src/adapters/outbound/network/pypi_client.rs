use crate::ports::outbound::{LicenseRepository, PyPiMetadata};
use crate::shared::Result;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct PyPiPackageInfo {
    info: PyPiInfo,
    #[serde(default)]
    urls: Vec<PyPiUrl>,
}

#[derive(Debug, Deserialize)]
struct PyPiUrl {
    #[serde(default)]
    digests: PyPiDigests,
}

#[derive(Debug, Default, Deserialize)]
struct PyPiDigests {
    #[serde(default)]
    sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PyPiInfo {
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    license_expression: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    classifiers: Vec<String>,
}

/// PyPiLicenseRepository adapter for fetching license information from PyPI API
///
/// This adapter implements the LicenseRepository port, providing async network access
/// to the PyPI JSON API for package metadata.
///
/// # Async Support
/// Uses async reqwest client for non-blocking HTTP requests, enabling parallel
/// license fetching for improved performance.
#[derive(Clone)]
pub struct PyPiLicenseRepository {
    client: reqwest::Client,
    base_url: String,
}

impl PyPiLicenseRepository {
    const MAX_RETRIES: u32 = 3;
    // 10 MB — well above any realistic PyPI package metadata response
    const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

    /// Creates a new PyPI license repository with default configuration
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

    /// Creates a client pointed at a custom base URL (e.g. a wiremock server
    /// or a raw TCP test server), for tests only.
    #[cfg(test)]
    fn new_with_base_url(base_url: impl Into<String>) -> Result<Self> {
        let version = env!("CARGO_PKG_VERSION");
        let user_agent = format!("uv-sbom/{}", version);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(user_agent)
            .build()?;

        Ok(Self {
            client,
            base_url: base_url.into(),
        })
    }

    /// Fetches package information from PyPI with retry logic (async)
    async fn fetch_with_retry(&self, package_name: &str, version: &str) -> Result<PyPiPackageInfo> {
        crate::shared::http_retry::fetch_with_retry(Self::MAX_RETRIES, || {
            self.fetch_from_pypi(package_name, version)
        })
        .await
    }

    /// Fetches package information from PyPI API (async)
    async fn fetch_from_pypi(&self, package_name: &str, version: &str) -> Result<PyPiPackageInfo> {
        // Security: Validate URL components before using them
        crate::shared::security::validate_url_component(package_name, "Package name")?;
        crate::shared::security::validate_url_component(version, "Version")?;

        // URL encode components to handle special characters safely
        let encoded_package = urlencoding::encode(package_name);
        let encoded_version = urlencoding::encode(version);

        let url = format!(
            "{}/pypi/{}/{}/json",
            self.base_url, encoded_package, encoded_version
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

        let package_info: PyPiPackageInfo = serde_json::from_slice(&bytes)?;
        Ok(package_info)
    }
}

impl PyPiLicenseRepository {
    /// Verify that a package exists on PyPI by sending an HTTP HEAD request
    /// to the PyPI JSON API endpoint, which correctly returns 404 for
    /// non-existent packages (unlike the /project/ HTML endpoint which
    /// returns 200 for all requests).
    pub async fn verify_package_exists(&self, package_name: &str) -> bool {
        let normalized = package_name.to_lowercase().replace('_', "-");
        let url = format!("{}/pypi/{}/json", self.base_url, normalized);
        match self
            .client
            .head(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }

    /// Verify multiple packages in parallel, returning a set of verified package names.
    /// Uses a concurrency limit to avoid overwhelming PyPI.
    pub async fn verify_packages(&self, names: &[String]) -> HashSet<String> {
        use futures::stream::{self, StreamExt};

        const MAX_CONCURRENT: usize = 10;

        let results: Vec<(String, bool)> = stream::iter(names.iter().cloned())
            .map(|name| async move {
                let exists = self.verify_package_exists(&name).await;
                (name, exists)
            })
            .buffer_unordered(MAX_CONCURRENT)
            .collect()
            .await;

        results
            .into_iter()
            .filter_map(|(name, exists)| if exists { Some(name) } else { None })
            .collect()
    }
}

// Note: Default implementation removed for security reasons.
// Default::default() would panic if client creation fails, which is not safe for production.
// Use PyPiLicenseRepository::new() explicitly and handle the Result.

#[async_trait]
impl LicenseRepository for PyPiLicenseRepository {
    async fn fetch_license_info(&self, package_name: &str, version: &str) -> Result<PyPiMetadata> {
        let package_info = self.fetch_with_retry(package_name, version).await?;

        let sha256_hash = package_info
            .urls
            .iter()
            .find_map(|url| url.digests.sha256.clone());

        Ok((
            package_info.info.license,
            package_info.info.license_expression,
            package_info.info.classifiers,
            package_info.info.summary,
            sha256_hash,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_pypi_client_creation() {
        let client = PyPiLicenseRepository::new();
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_verify_packages_empty_list() {
        let client = PyPiLicenseRepository::new().unwrap();
        let result = client.verify_packages(&[]).await;
        assert!(result.is_empty());
    }

    #[test]
    fn test_pypi_url_deserialization_with_digests() {
        let json = r#"{
            "info": {
                "license": "MIT",
                "summary": "A test package"
            },
            "urls": [
                {
                    "digests": {
                        "sha256": "abc123def456"
                    }
                }
            ]
        }"#;

        let package_info: PyPiPackageInfo = serde_json::from_str(json).unwrap();
        assert_eq!(package_info.urls.len(), 1);
        assert_eq!(
            package_info.urls[0].digests.sha256,
            Some("abc123def456".to_string())
        );
    }

    #[test]
    fn test_pypi_url_deserialization_without_urls() {
        let json = r#"{
            "info": {
                "license": "MIT",
                "summary": "A test package"
            }
        }"#;

        let package_info: PyPiPackageInfo = serde_json::from_str(json).unwrap();
        assert!(package_info.urls.is_empty());
    }

    #[test]
    fn test_pypi_url_deserialization_empty_digests() {
        let json = r#"{
            "info": {
                "license": "MIT",
                "summary": "A test package"
            },
            "urls": [
                {
                    "digests": {}
                }
            ]
        }"#;

        let package_info: PyPiPackageInfo = serde_json::from_str(json).unwrap();
        assert!(package_info.urls[0].digests.sha256.is_none());
    }

    // Integration tests - require network access
    // Uncomment to run with real PyPI API
    // #[tokio::test]
    // async fn test_verify_package_exists_real() {
    //     let client = PyPiLicenseRepository::new().unwrap();
    //     assert!(client.verify_package_exists("requests").await);
    // }
    //
    // #[tokio::test]
    // async fn test_verify_package_not_exists_real() {
    //     let client = PyPiLicenseRepository::new().unwrap();
    //     assert!(!client.verify_package_exists("nonexistent-pkg-xyz-123456").await);
    // }
    //
    // #[tokio::test]
    // async fn test_verify_packages_real() {
    //     let client = PyPiLicenseRepository::new().unwrap();
    //     let names = vec!["requests".to_string(), "nonexistent-pkg-xyz-123456".to_string()];
    //     let verified = client.verify_packages(&names).await;
    //     assert!(verified.contains("requests"));
    //     assert!(!verified.contains("nonexistent-pkg-xyz-123456"));
    // }

    /// Builds a syntactically valid PyPI package-info JSON body whose total
    /// length is exactly `total_len` bytes, padded via the `summary` field.
    /// The body is deliberately *valid* JSON: if the size guard were absent,
    /// deserialization would succeed, so an error from the client proves the
    /// guard fired rather than a parse failure.
    fn package_json_of_len(total_len: usize) -> Vec<u8> {
        let prefix: &[u8] = br#"{"info":{"license":"MIT","summary":""#;
        let suffix: &[u8] = br#""}}"#;
        let mut body = Vec::with_capacity(total_len);
        body.extend_from_slice(prefix);
        body.resize(total_len - suffix.len(), b'x');
        body.extend_from_slice(suffix);
        assert_eq!(body.len(), total_len);
        body
    }

    #[tokio::test]
    async fn test_fetch_from_pypi_success_via_mock() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/2.31.0/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "info": {"license": "MIT", "summary": "A test package"},
                "urls": [{"digests": {"sha256": "abc123"}}]
            })))
            .mount(&mock_server)
            .await;

        let client = PyPiLicenseRepository::new_with_base_url(mock_server.uri()).unwrap();
        let info = client.fetch_from_pypi("requests", "2.31.0").await.unwrap();
        assert_eq!(info.info.license, Some("MIT".to_string()));
        assert_eq!(info.urls[0].digests.sha256, Some("abc123".to_string()));
    }

    #[tokio::test]
    async fn test_fetch_from_pypi_rejects_oversized_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/2.31.0/json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                package_json_of_len(PyPiLicenseRepository::MAX_RESPONSE_BYTES + 1),
                "application/json",
            ))
            .mount(&mock_server)
            .await;

        let client = PyPiLicenseRepository::new_with_base_url(mock_server.uri()).unwrap();
        let err = client
            .fetch_from_pypi("requests", "2.31.0")
            .await
            .unwrap_err();
        // "too large" is the Content-Length pre-check branch specifically.
        assert!(
            err.to_string().contains("too large"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_fetch_from_pypi_accepts_response_at_limit() {
        // Exactly at the limit must pass: proves the comparison is `>`, not `>=`.
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/2.31.0/json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                package_json_of_len(PyPiLicenseRepository::MAX_RESPONSE_BYTES),
                "application/json",
            ))
            .mount(&mock_server)
            .await;

        let client = PyPiLicenseRepository::new_with_base_url(mock_server.uri()).unwrap();
        let info = client.fetch_from_pypi("requests", "2.31.0").await.unwrap();
        assert_eq!(info.info.license, Some("MIT".to_string()));
    }

    /// Serves exactly one HTTP/1.1 response using `Transfer-Encoding: chunked`
    /// and no `Content-Length`, so `Response::content_length()` is `None` on
    /// the client side and only the post-download `bytes.len()` check can
    /// reject it.
    ///
    /// wiremock cannot express this: its bodies are always backed by a
    /// known-length buffer, so the underlying hyper server always emits an
    /// accurate `Content-Length` (and asserts on a mismatched one under
    /// `debug_assertions`), making a `Content-Length`/body-size mismatch
    /// impossible to construct through it.
    fn spawn_chunked_oversize_server(body_len: usize) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf); // drain the (small) request head
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: application/json\r\n\
                  Transfer-Encoding: chunked\r\n\r\n",
            );
            let chunk = vec![b'x'; 64 * 1024];
            let mut written = 0usize;
            while written < body_len {
                let _ = write!(stream, "{:x}\r\n", chunk.len());
                let _ = stream.write_all(&chunk);
                let _ = stream.write_all(b"\r\n");
                written += chunk.len();
            }
            let _ = stream.write_all(b"0\r\n\r\n");
            let _ = stream.flush();
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn test_fetch_from_pypi_rejects_oversized_chunked_response() {
        // No Content-Length -> the pre-check cannot fire; only the
        // post-download bytes.len() check can reject this. Asserting on the
        // distinct wording proves which of the two stages actually ran.
        let base =
            spawn_chunked_oversize_server(PyPiLicenseRepository::MAX_RESPONSE_BYTES + 64 * 1024);
        let client = PyPiLicenseRepository::new_with_base_url(base).unwrap();
        let err = client
            .fetch_from_pypi("requests", "2.31.0")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("exceeded"),
            "unexpected error: {err}"
        );
    }
}
