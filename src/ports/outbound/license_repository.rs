use crate::sbom_generation::domain::LicenseInfo;
use crate::shared::Result;
use async_trait::async_trait;

/// Type alias for PyPI metadata: (license, license_expression, classifiers, description)
pub type PyPiMetadata = (Option<String>, Option<String>, Vec<String>, Option<String>);

/// LicenseRepository port for fetching license information
///
/// This port abstracts the external data source (e.g., PyPI API)
/// used to retrieve license and description information for packages.
///
/// # Async Support
/// All methods are async for efficient parallel license fetching.
/// Implementations must be `Send + Sync` to support concurrent access.
#[async_trait]
pub trait LicenseRepository: Send + Sync {
    /// Fetches license information for a specific package version
    ///
    /// # Arguments
    /// * `package_name` - Name of the package
    /// * `version` - Version of the package
    ///
    /// # Returns
    /// PyPiMetadata tuple containing:
    /// - Optional license field from package metadata
    /// - Optional license_expression field from package metadata
    /// - List of classifiers from package metadata
    /// - Optional package description/summary
    ///
    /// # Errors
    /// Returns an error if:
    /// - The network request fails
    /// - The API returns an error status code
    /// - The response cannot be parsed
    async fn fetch_license_info(&self, package_name: &str, version: &str) -> Result<PyPiMetadata>;

    /// Enriches a package with license information from the repository
    ///
    /// This is a convenience method that fetches raw data and converts
    /// it to a LicenseInfo domain object using license priority rules.
    ///
    /// # Arguments
    /// * `package_name` - Name of the package
    /// * `version` - Version of the package
    ///
    /// # Returns
    /// A LicenseInfo object with the selected license and description
    async fn enrich_with_license(&self, package_name: &str, version: &str) -> Result<LicenseInfo> {
        let (license, license_expression, classifiers, description) =
            self.fetch_license_info(package_name, version).await?;

        use crate::sbom_generation::policies::LicensePriority;
        Ok(LicensePriority::create_license_info(
            license,
            license_expression,
            &classifiers,
            description,
        ))
    }
}
