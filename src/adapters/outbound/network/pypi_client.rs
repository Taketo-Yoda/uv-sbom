use crate::ports::outbound::{LicenseRepository, PyPiMetadata};
use crate::shared::Result;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct PyPiPackageInfo {
    info: PyPiInfo,
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
pub struct PyPiLicenseRepository {
    client: reqwest::Client,
    max_retries: u32,
}

impl PyPiLicenseRepository {
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
            max_retries: 3,
        })
    }

    /// Fetches package information from PyPI with retry logic (async)
    async fn fetch_with_retry(&self, package_name: &str, version: &str) -> Result<PyPiPackageInfo> {
        let mut last_error = None;

        for attempt in 1..=self.max_retries {
            match self.fetch_from_pypi(package_name, version).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.max_retries {
                        // Retry after a short wait (async)
                        tokio::time::sleep(Duration::from_millis(100 * attempt as u64)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap())
    }

    /// Validates and sanitizes package name and version for URL safety
    fn validate_url_component(component: &str, component_type: &str) -> Result<()> {
        // Security: Prevent URL injection attacks
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

        // Check for URL-unsafe characters that could cause issues
        if component.contains('#') || component.contains('?') || component.contains('@') {
            anyhow::bail!(
                "Security: {} contains URL-unsafe characters",
                component_type
            );
        }

        Ok(())
    }

    /// Fetches package information from PyPI API (async)
    async fn fetch_from_pypi(&self, package_name: &str, version: &str) -> Result<PyPiPackageInfo> {
        // Security: Validate URL components before using them
        Self::validate_url_component(package_name, "Package name")?;
        Self::validate_url_component(version, "Version")?;

        // URL encode components to handle special characters safely
        let encoded_package = urlencoding::encode(package_name);
        let encoded_version = urlencoding::encode(version);

        let url = format!(
            "https://pypi.org/pypi/{}/{}/json",
            encoded_package, encoded_version
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("PyPI API returned status code {}", response.status());
        }

        let package_info: PyPiPackageInfo = response.json().await?;
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
        let url = format!("https://pypi.org/pypi/{}/json", normalized);
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

        Ok((
            package_info.info.license,
            package_info.info.license_expression,
            package_info.info.classifiers,
            package_info.info.summary,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
