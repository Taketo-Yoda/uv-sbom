use crate::ports::outbound::{MaintenanceInfo, MaintenanceRepository};
use crate::shared::response_size_guard;
use crate::shared::Result;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDate};
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct PyPiPackageResponse {
    #[serde(default)]
    urls: Vec<PyPiUploadEntry>,
}

#[derive(Debug, Deserialize)]
struct PyPiUploadEntry {
    #[serde(default)]
    upload_time_iso_8601: Option<String>,
}

/// PyPiMaintenanceRepository adapter for fetching package maintenance information from PyPI
///
/// Queries the package-level endpoint (`/pypi/{name}/json`, no version segment) to
/// retrieve the latest release date, used for abandoned-package detection.
#[derive(Clone)]
pub struct PyPiMaintenanceRepository {
    client: reqwest::Client,
    base_url: String,
}

impl PyPiMaintenanceRepository {
    const MAX_RETRIES: u32 = 3;
    // 10 MB — well above any realistic PyPI package metadata response
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

    /// Creates a new PyPI maintenance repository with default configuration
    pub fn new() -> Result<Self> {
        Self::build("https://pypi.org".to_string())
    }

    /// Creates a client pointed at a custom base URL (e.g. a wiremock server),
    /// for tests only.
    #[cfg(test)]
    fn new_with_base_url(base_url: impl Into<String>) -> Result<Self> {
        Self::build(base_url.into())
    }

    async fn fetch_from_pypi(&self, package_name: &str) -> Result<PyPiPackageResponse> {
        crate::shared::security::validate_url_component(package_name, "Package name")?;
        let encoded = urlencoding::encode(package_name);
        let url = format!("{}/pypi/{}/json", self.base_url, encoded);

        let response = self.client.get(&url).send().await?;
        if !response.status().is_success() {
            anyhow::bail!("PyPI API returned status code {}", response.status());
        }
        let bytes = response_size_guard::read_bounded_bytes(
            response,
            Self::MAX_RESPONSE_BYTES,
            Some("PyPI maintenance metadata"),
        )
        .await?;
        Ok(serde_json::from_slice::<PyPiPackageResponse>(&bytes)?)
    }

    async fn fetch_with_retry(&self, package_name: &str) -> Result<PyPiPackageResponse> {
        crate::shared::http_retry::fetch_with_retry(Self::MAX_RETRIES, || {
            self.fetch_from_pypi(package_name)
        })
        .await
    }

    /// Parses the latest release date from a PyPI package response.
    ///
    /// Returns the maximum `upload_time_iso_8601` across all `urls[]` entries,
    /// converted to UTC date. Returns `None` when `urls` is empty or all entries
    /// have unparseable timestamps.
    fn parse_last_release_date(response: &PyPiPackageResponse) -> Option<NaiveDate> {
        response
            .urls
            .iter()
            .filter_map(|u| u.upload_time_iso_8601.as_deref())
            .filter_map(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.naive_utc().date())
            .max()
    }
}

#[async_trait]
impl MaintenanceRepository for PyPiMaintenanceRepository {
    async fn fetch_maintenance_info(&self, package_name: &str) -> Result<MaintenanceInfo> {
        let resp = self.fetch_with_retry(package_name).await?;
        Ok(MaintenanceInfo {
            last_release_date: Self::parse_last_release_date(&resp),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_pypi_maintenance_client_creation() {
        assert!(PyPiMaintenanceRepository::new().is_ok());
    }

    #[test]
    fn test_parse_last_release_date_valid() {
        let response = PyPiPackageResponse {
            urls: vec![PyPiUploadEntry {
                upload_time_iso_8601: Some("2024-01-15T10:30:00.000000+00:00".to_string()),
            }],
        };
        let date = PyPiMaintenanceRepository::parse_last_release_date(&response);
        assert_eq!(date, Some(NaiveDate::from_ymd_opt(2024, 1, 15).unwrap()));
    }

    #[test]
    fn test_parse_last_release_date_picks_max() {
        let response = PyPiPackageResponse {
            urls: vec![
                PyPiUploadEntry {
                    upload_time_iso_8601: Some("2023-06-01T00:00:00.000000+00:00".to_string()),
                },
                PyPiUploadEntry {
                    upload_time_iso_8601: Some("2024-03-20T12:00:00.000000+00:00".to_string()),
                },
                PyPiUploadEntry {
                    upload_time_iso_8601: Some("2022-12-31T23:59:59.000000+00:00".to_string()),
                },
            ],
        };
        let date = PyPiMaintenanceRepository::parse_last_release_date(&response);
        assert_eq!(date, Some(NaiveDate::from_ymd_opt(2024, 3, 20).unwrap()));
    }

    #[test]
    fn test_parse_last_release_date_empty_urls() {
        let response = PyPiPackageResponse { urls: vec![] };
        assert!(PyPiMaintenanceRepository::parse_last_release_date(&response).is_none());
    }

    #[test]
    fn test_parse_last_release_date_malformed_string() {
        let response = PyPiPackageResponse {
            urls: vec![PyPiUploadEntry {
                upload_time_iso_8601: Some("not-a-date".to_string()),
            }],
        };
        assert!(PyPiMaintenanceRepository::parse_last_release_date(&response).is_none());
    }

    #[test]
    fn test_parse_last_release_date_malformed_skipped_when_mixed() {
        let response = PyPiPackageResponse {
            urls: vec![
                PyPiUploadEntry {
                    upload_time_iso_8601: Some("not-a-date".to_string()),
                },
                PyPiUploadEntry {
                    upload_time_iso_8601: Some("2024-05-01T00:00:00.000000+00:00".to_string()),
                },
            ],
        };
        let date = PyPiMaintenanceRepository::parse_last_release_date(&response);
        assert_eq!(date, Some(NaiveDate::from_ymd_opt(2024, 5, 1).unwrap()));
    }

    #[test]
    fn test_parse_last_release_date_null_upload_time() {
        let response = PyPiPackageResponse {
            urls: vec![PyPiUploadEntry {
                upload_time_iso_8601: None,
            }],
        };
        assert!(PyPiMaintenanceRepository::parse_last_release_date(&response).is_none());
    }

    #[test]
    fn test_deserialize_minimal_response() {
        let json = r#"{}"#;
        let response: PyPiPackageResponse = serde_json::from_str(json).unwrap();
        assert!(response.urls.is_empty());
    }

    #[test]
    fn test_deserialize_with_upload_times() {
        let json = r#"{
            "urls": [
                {"upload_time_iso_8601": "2024-01-15T10:30:00.000000+00:00"},
                {"upload_time_iso_8601": "2024-01-16T08:00:00.000000+00:00"}
            ]
        }"#;
        let response: PyPiPackageResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.urls.len(), 2);
    }

    #[test]
    fn test_deserialize_with_extra_fields() {
        let json = r#"{
            "info": {"name": "requests", "version": "2.31.0"},
            "urls": [{"upload_time_iso_8601": "2024-01-15T10:30:00.000000+00:00", "filename": "requests-2.31.0.tar.gz"}]
        }"#;
        let response: PyPiPackageResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.urls.len(), 1);
    }

    // Integration tests - require network access
    // Uncomment to run with real PyPI API
    // #[tokio::test]
    // async fn test_fetch_maintenance_info_real() {
    //     let client = PyPiMaintenanceRepository::new().unwrap();
    //     let info = client.fetch_maintenance_info("requests").await.unwrap();
    //     assert!(info.last_release_date.is_some());
    // }
    //
    // #[tokio::test]
    // async fn test_fetch_maintenance_info_nonexistent_real() {
    //     let client = PyPiMaintenanceRepository::new().unwrap();
    //     assert!(client.fetch_maintenance_info("nonexistent-pkg-xyz-123456").await.is_err());
    // }

    /// Builds a syntactically valid maintenance-endpoint JSON body whose total
    /// length is exactly `total_len` bytes, padded through a field the
    /// `PyPiPackageResponse` deserializer ignores. The body is deliberately
    /// *valid* JSON: if the size guard were absent, deserialization would
    /// succeed, so an error from the client proves the guard fired rather
    /// than a parse failure.
    fn maintenance_json_of_len(total_len: usize) -> Vec<u8> {
        let prefix: &[u8] =
            br#"{"urls":[{"upload_time_iso_8601":"2024-01-15T10:30:00.000000+00:00"}],"padding":""#;
        let suffix: &[u8] = br#""}"#;
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
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "urls": [{"upload_time_iso_8601": "2024-01-15T10:30:00.000000+00:00"}]
            })))
            .mount(&mock_server)
            .await;

        let client = PyPiMaintenanceRepository::new_with_base_url(mock_server.uri()).unwrap();
        let resp = client.fetch_from_pypi("requests").await.unwrap();
        assert_eq!(
            PyPiMaintenanceRepository::parse_last_release_date(&resp),
            Some(NaiveDate::from_ymd_opt(2024, 1, 15).unwrap())
        );
    }

    #[tokio::test]
    async fn test_fetch_from_pypi_rejects_oversized_response() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                maintenance_json_of_len(PyPiMaintenanceRepository::MAX_RESPONSE_BYTES + 1),
                "application/json",
            ))
            .mount(&mock_server)
            .await;

        let client = PyPiMaintenanceRepository::new_with_base_url(mock_server.uri()).unwrap();
        let err = client.fetch_from_pypi("requests").await.unwrap_err();
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
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                maintenance_json_of_len(PyPiMaintenanceRepository::MAX_RESPONSE_BYTES),
                "application/json",
            ))
            .mount(&mock_server)
            .await;

        let client = PyPiMaintenanceRepository::new_with_base_url(mock_server.uri()).unwrap();
        let resp = client.fetch_from_pypi("requests").await.unwrap();
        assert_eq!(
            PyPiMaintenanceRepository::parse_last_release_date(&resp),
            Some(NaiveDate::from_ymd_opt(2024, 1, 15).unwrap())
        );
    }
}
