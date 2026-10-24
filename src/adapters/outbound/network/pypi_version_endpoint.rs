//! Shared fetch for PyPI's version-level endpoint (`/pypi/{name}/{version}/json`).
//!
//! Used by `PyPiReleaseClient` and `PyPiCompatibilityClient`, which previously
//! carried near-identical copies of this logic (#978). The helper returns the
//! raw, size-bounded body and leaves deserialization and the meaning of a 404
//! to each caller: the release client treats 404 as "not published", while the
//! compatibility client treats it as an ordinary error.

use crate::shared::response_size_guard;
use crate::shared::Result;
use reqwest::StatusCode;
use std::time::Duration;

/// Default request timeout for PyPI version-endpoint clients.
pub(super) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Builds the PyPI HTTP client with the given timeout and the
/// `uv-sbom/{version}` User-Agent.
///
/// # Errors
/// Returns an error if the underlying HTTP client fails to build.
pub(super) fn build_client(timeout: Duration) -> Result<reqwest::Client> {
    let user_agent = format!("uv-sbom/{}", env!("CARGO_PKG_VERSION"));
    Ok(reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(user_agent)
        .build()?)
}

/// Builds the error for an unsuccessful PyPI response status.
///
/// Shared so that callers re-raising a 404 as an error (the compatibility
/// client) produce exactly the same text as the helper itself.
pub(super) fn status_error(status: StatusCode) -> anyhow::Error {
    anyhow::anyhow!("PyPI API returned status code {}", status)
}

/// Fetches `{base_url}/pypi/{package_name}/{version}/json`.
///
/// Returns `Ok(Some(body))` on a 2xx response and `Ok(None)` on HTTP 404.
///
/// # Errors
/// - Invalid `package_name` / `version` → error wrapped with
///   [`crate::shared::http_retry::permanent`], so it is not retried
/// - Any other non-2xx status or network failure → ordinary (retryable) error
/// - Body larger than `max_bytes` → permanent error from the size guard,
///   identified by `context`
pub(super) async fn fetch_version_json(
    client: &reqwest::Client,
    base_url: &str,
    package_name: &str,
    version: &str,
    max_bytes: usize,
    context: &str,
) -> Result<Option<Vec<u8>>> {
    crate::shared::security::validate_url_component(package_name, "Package name")
        .map_err(crate::shared::http_retry::permanent)?;
    crate::shared::security::validate_url_component(version, "Package version")
        .map_err(crate::shared::http_retry::permanent)?;
    let encoded_name = urlencoding::encode(package_name);
    let encoded_version = urlencoding::encode(version);
    let url = format!(
        "{}/pypi/{}/{}/json",
        base_url, encoded_name, encoded_version
    );

    let response = client.get(&url).send().await?;
    // Checked before `is_success` so callers can tell "not published" apart
    // from a failure.
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(status_error(response.status()));
    }
    let bytes = response_size_guard::read_bounded_bytes(response, max_bytes, Some(context)).await?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::http_retry::PermanentError;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const CONTEXT: &str = "PyPI test metadata";

    async fn fetch_from(server_uri: &str, name: &str, version: &str) -> Result<Option<Vec<u8>>> {
        let client = build_client(DEFAULT_TIMEOUT).unwrap();
        fetch_version_json(&client, server_uri, name, version, 16, CONTEXT).await
    }

    async fn mock_server_responding(response: ResponseTemplate) -> MockServer {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/2.31.0/json"))
            .respond_with(response)
            .mount(&mock_server)
            .await;
        mock_server
    }

    #[test]
    fn test_build_client_succeeds() {
        assert!(build_client(DEFAULT_TIMEOUT).is_ok());
    }

    #[tokio::test]
    async fn test_fetch_version_json_ok_returns_body_bytes() {
        let server = mock_server_responding(
            ResponseTemplate::new(200).set_body_raw("{}", "application/json"),
        )
        .await;
        let body = fetch_from(&server.uri(), "requests", "2.31.0")
            .await
            .unwrap();
        assert_eq!(body, Some(b"{}".to_vec()));
    }

    #[tokio::test]
    async fn test_fetch_version_json_not_found_returns_none() {
        let server = mock_server_responding(ResponseTemplate::new(404)).await;
        let body = fetch_from(&server.uri(), "requests", "2.31.0")
            .await
            .unwrap();
        assert!(body.is_none());
    }

    #[tokio::test]
    async fn test_fetch_version_json_server_error_is_retryable_err() {
        let server = mock_server_responding(ResponseTemplate::new(500)).await;
        let err = fetch_from(&server.uri(), "requests", "2.31.0")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("PyPI API returned status code 500"),
            "unexpected error: {err}"
        );
        assert!(err.downcast_ref::<PermanentError>().is_none());
    }

    #[tokio::test]
    async fn test_fetch_version_json_invalid_name_is_permanent_err() {
        // Nothing listens on port 1; validation must fail before any request.
        let err = fetch_from("http://127.0.0.1:1", "../x", "2.31.0")
            .await
            .unwrap_err();
        assert!(err.downcast_ref::<PermanentError>().is_some());
    }

    #[tokio::test]
    async fn test_fetch_version_json_invalid_version_is_permanent_err() {
        let err = fetch_from("http://127.0.0.1:1", "requests", "../x")
            .await
            .unwrap_err();
        assert!(err.downcast_ref::<PermanentError>().is_some());
    }

    #[tokio::test]
    async fn test_fetch_version_json_oversized_body_carries_context() {
        let server = mock_server_responding(
            ResponseTemplate::new(200).set_body_raw(vec![b' '; 17], "application/json"),
        )
        .await;
        let err = fetch_from(&server.uri(), "requests", "2.31.0")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("too large"), "unexpected error: {msg}");
        assert!(msg.contains(CONTEXT), "unexpected error: {msg}");
        assert!(err.downcast_ref::<PermanentError>().is_some());
    }
}
