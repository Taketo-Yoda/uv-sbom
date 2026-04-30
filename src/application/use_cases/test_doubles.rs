use crate::ports::outbound::{ProgressCallback, VulnerabilityRepository};
use crate::sbom_generation::domain::{Package, PackageVulnerabilities};
use crate::shared::Result;
use async_trait::async_trait;

/// Configurable in-memory mock implementing `VulnerabilityRepository`.
///
/// Use `MockVulnerabilityRepository::new()` for the empty variant returning `Ok(vec![])`.
/// Use `MockVulnerabilityRepository { vulnerabilities: ... }` for tests that need pre-loaded data.
#[derive(Clone, Default)]
pub(crate) struct MockVulnerabilityRepository {
    pub vulnerabilities: Vec<PackageVulnerabilities>,
}

impl MockVulnerabilityRepository {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl VulnerabilityRepository for MockVulnerabilityRepository {
    async fn fetch_vulnerabilities(
        &self,
        _packages: Vec<Package>,
    ) -> Result<Vec<PackageVulnerabilities>> {
        Ok(self.vulnerabilities.clone())
    }

    async fn fetch_vulnerabilities_with_progress(
        &self,
        _packages: Vec<Package>,
        _progress_callback: ProgressCallback<'static>,
    ) -> Result<Vec<PackageVulnerabilities>> {
        Ok(self.vulnerabilities.clone())
    }
}
