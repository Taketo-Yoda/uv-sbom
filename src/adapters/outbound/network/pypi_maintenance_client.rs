// No binary consumer until Issue #555 wires this adapter into GenerateSbomUseCase.
#![allow(dead_code)]

use crate::ports::outbound::{MaintenanceInfo, MaintenanceRepository};
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
}

impl PyPiMaintenanceRepository {
    const MAX_RETRIES: u32 = 3;
    // 10 MB — well above any realistic PyPI package metadata response
    const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

    /// Creates a new PyPI maintenance repository with default configuration
    pub fn new() -> Result<Self> {
        let version = env!("CARGO_PKG_VERSION");
        let user_agent = format!("uv-sbom/{}", version);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(user_agent)
            .build()?;

        Ok(Self { client })
    }

    /// Validates a URL component to prevent injection attacks
    fn validate_url_component(component: &str, component_type: &str) -> Result<()> {
        if component.contains('/') || component.contains('\\') {
            anyhow::bail!(
                "Security: {} contains path separators which are not allowed",
                component_type
            );
        }
        if component.contains("..") {
            anyhow::bail!(
                "Security: {} contains '..' which is not allowed",
                component_type
            );
        }
        if component.contains('#') || component.contains('?') || component.contains('@') {
            anyhow::bail!(
                "Security: {} contains URL-unsafe characters",
                component_type
            );
        }
        Ok(())
    }

    async fn fetch_from_pypi(&self, package_name: &str) -> Result<PyPiPackageResponse> {
        Self::validate_url_component(package_name, "Package name")?;
        let encoded = urlencoding::encode(package_name);
        let url = format!("https://pypi.org/pypi/{}/json", encoded);

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
        Ok(serde_json::from_slice::<PyPiPackageResponse>(&bytes)?)
    }

    async fn fetch_with_retry(&self, package_name: &str) -> Result<PyPiPackageResponse> {
        let mut last_error = None;
        for attempt in 1..=Self::MAX_RETRIES {
            match self.fetch_from_pypi(package_name).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < Self::MAX_RETRIES {
                        // Linear back-off: 100 ms, 200 ms — matches PyPiLicenseRepository
                        tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
                    }
                }
            }
        }
        Err(last_error.unwrap())
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

    #[test]
    fn test_validate_url_component_accepts_normal_name() {
        assert!(
            PyPiMaintenanceRepository::validate_url_component("requests", "Package name").is_ok()
        );
        assert!(PyPiMaintenanceRepository::validate_url_component(
            "my-package-123",
            "Package name"
        )
        .is_ok());
    }

    #[test]
    fn test_validate_url_component_rejects_path_separators() {
        assert!(
            PyPiMaintenanceRepository::validate_url_component("pkg/evil", "Package name").is_err()
        );
        assert!(
            PyPiMaintenanceRepository::validate_url_component("pkg\\evil", "Package name").is_err()
        );
        assert!(
            PyPiMaintenanceRepository::validate_url_component("pkg..evil", "Package name").is_err()
        );
    }

    #[test]
    fn test_validate_url_component_rejects_unsafe_chars() {
        assert!(
            PyPiMaintenanceRepository::validate_url_component("pkg#evil", "Package name").is_err()
        );
        assert!(
            PyPiMaintenanceRepository::validate_url_component("pkg?evil", "Package name").is_err()
        );
        assert!(
            PyPiMaintenanceRepository::validate_url_component("pkg@evil", "Package name").is_err()
        );
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
}
