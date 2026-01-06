use crate::ports::outbound::{LicenseRepository, PyPiMetadata};
use crate::shared::Result;
use serde::Deserialize;
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
/// This adapter implements the LicenseRepository port, providing network access
/// to the PyPI JSON API for package metadata.
pub struct PyPiLicenseRepository {
    client: reqwest::blocking::Client,
    max_retries: u32,
}

impl PyPiLicenseRepository {
    /// Creates a new PyPI license repository with default configuration
    pub fn new() -> Result<Self> {
        let version = env!("CARGO_PKG_VERSION");
        let user_agent = format!("uv-sbom/{}", version);
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(user_agent)
            .build()?;

        Ok(Self {
            client,
            max_retries: 3,
        })
    }

    /// Fetches package information from PyPI with retry logic
    fn fetch_with_retry(&self, package_name: &str, version: &str) -> Result<PyPiPackageInfo> {
        let mut last_error = None;

        for attempt in 1..=self.max_retries {
            match self.fetch_from_pypi(package_name, version) {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.max_retries {
                        // Retry after a short wait
                        std::thread::sleep(Duration::from_millis(100 * attempt as u64));
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

    /// Fetches package information from PyPI API
    fn fetch_from_pypi(&self, package_name: &str, version: &str) -> Result<PyPiPackageInfo> {
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

        let response = self.client.get(&url).send()?;

        if !response.status().is_success() {
            anyhow::bail!("PyPI API returned status code {}", response.status());
        }

        let package_info: PyPiPackageInfo = response.json()?;
        Ok(package_info)
    }
}

// Note: Default implementation removed for security reasons.
// Default::default() would panic if client creation fails, which is not safe for production.
// Use PyPiLicenseRepository::new() explicitly and handle the Result.

impl LicenseRepository for PyPiLicenseRepository {
    fn fetch_license_info(&self, package_name: &str, version: &str) -> Result<PyPiMetadata> {
        let package_info = self.fetch_with_retry(package_name, version)?;

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

    // Integration test - requires network access
    // Uncomment to run with real PyPI API
    // #[test]
    // fn test_fetch_license_info_real() {
    //     let client = PyPiLicenseRepository::new().unwrap();
    //     let result = client.fetch_license_info("requests", "2.31.0");
    //     assert!(result.is_ok());
    // }
}
