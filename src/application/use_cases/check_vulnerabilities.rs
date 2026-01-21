use crate::ports::outbound::{ProgressCallback, VulnerabilityRepository};
use crate::sbom_generation::domain::{Package, PackageVulnerabilities};
use crate::shared::Result;

/// CheckVulnerabilitiesUseCase - Use case for checking vulnerabilities
///
/// This use case provides vulnerability fetching functionality with progress reporting.
/// It delegates to the VulnerabilityRepository for the actual fetching.
///
/// # Type Parameters
/// * `R` - VulnerabilityRepository implementation
pub struct CheckVulnerabilitiesUseCase<R: VulnerabilityRepository> {
    vulnerability_repository: R,
}

impl<R: VulnerabilityRepository> CheckVulnerabilitiesUseCase<R> {
    /// Creates a new CheckVulnerabilitiesUseCase with injected repository
    ///
    /// # Arguments
    /// * `vulnerability_repository` - Repository for fetching vulnerability data
    pub fn new(vulnerability_repository: R) -> Self {
        Self {
            vulnerability_repository,
        }
    }

    /// Fetches vulnerabilities with progress reporting
    ///
    /// This method is used when progress feedback is needed (e.g., CLI with progress bar).
    /// It delegates to the repository's progress-aware method.
    ///
    /// # Arguments
    /// * `packages` - Packages to check for vulnerabilities
    /// * `progress_callback` - Callback for progress updates (current, total)
    ///
    /// # Returns
    /// Vector of PackageVulnerabilities for packages that have vulnerabilities
    pub async fn fetch_vulnerabilities_with_progress(
        &self,
        packages: Vec<Package>,
        progress_callback: ProgressCallback<'static>,
    ) -> Result<Vec<PackageVulnerabilities>> {
        self.vulnerability_repository
            .fetch_vulnerabilities_with_progress(packages, progress_callback)
            .await
    }
}
