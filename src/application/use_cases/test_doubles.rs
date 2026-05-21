use crate::ports::outbound::{
    MaintenanceInfo, MaintenanceRepository, ProgressCallback, VulnerabilityRepository,
};
use crate::sbom_generation::domain::{Package, PackageVulnerabilities};
use crate::shared::Result;
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Configurable in-memory mock implementing `MaintenanceRepository`.
///
/// Each call to `fetch_maintenance_info` pops the next response from the queue.
/// When the queue is exhausted, returns `Ok(MaintenanceInfo { last_release_date: None })`.
///
/// `Clone` clones the `Arc`, so both copies share the same queue — consistent with
/// how the production code clones the repository into sub-use-cases.
#[derive(Clone)]
pub(crate) struct MockMaintenanceRepository {
    queue: Arc<Mutex<VecDeque<std::result::Result<MaintenanceInfo, String>>>>,
}

impl MockMaintenanceRepository {
    /// Creates an empty mock (all calls return `last_release_date: None`).
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Creates a mock with pre-loaded ordered responses.
    pub fn with_responses(
        responses: impl IntoIterator<Item = std::result::Result<MaintenanceInfo, String>>,
    ) -> Self {
        Self {
            queue: Arc::new(Mutex::new(responses.into_iter().collect())),
        }
    }
}

impl Default for MockMaintenanceRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MaintenanceRepository for MockMaintenanceRepository {
    async fn fetch_maintenance_info(&self, _package_name: &str) -> Result<MaintenanceInfo> {
        let next = self.queue.lock().unwrap().pop_front();
        match next {
            Some(Ok(info)) => Ok(info),
            Some(Err(msg)) => Err(anyhow::anyhow!("{}", msg)),
            None => Ok(MaintenanceInfo {
                last_release_date: None,
            }),
        }
    }
}

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
