use crate::ports::outbound::{
    MaintenanceInfo, MaintenanceRepository, ProgressCallback, PythonCompatibilityInfo,
    PythonCompatibilityRepository, VulnerabilityRepository,
};
use crate::sbom_generation::domain::{
    Package, PackageVulnerabilities, SimulationResult, UvLockSimulator,
};
use crate::shared::Result;
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// Mock VulnerabilityRepository that returns pre-configured responses in order.
///
/// Each call to `fetch_vulnerabilities` pops the next response from the queue.
/// Designed for testing `GenerateDiffUseCase`'s CVE delta computation, where the
/// use case calls `fetch_vulnerabilities` twice — once for base packages and once
/// for current packages — in sequential order.
#[derive(Clone, Default)]
pub(crate) struct PairedMockVulnerabilityRepository {
    queue: Arc<Mutex<VecDeque<Vec<PackageVulnerabilities>>>>,
}

impl PairedMockVulnerabilityRepository {
    /// Creates a mock that returns `base_response` on the first call and
    /// `current_response` on the second call.
    pub fn new(
        base_response: Vec<PackageVulnerabilities>,
        current_response: Vec<PackageVulnerabilities>,
    ) -> Self {
        let mut queue = VecDeque::new();
        queue.push_back(base_response);
        queue.push_back(current_response);
        Self {
            queue: Arc::new(Mutex::new(queue)),
        }
    }
}

#[async_trait]
impl VulnerabilityRepository for PairedMockVulnerabilityRepository {
    async fn fetch_vulnerabilities(
        &self,
        _packages: Vec<Package>,
    ) -> Result<Vec<PackageVulnerabilities>> {
        Ok(self.queue.lock().unwrap().pop_front().unwrap_or_default())
    }
}

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

/// Configurable in-memory mock implementing `PythonCompatibilityRepository`.
///
/// Responses are keyed by package name rather than popped from a FIFO queue,
/// because `CheckPythonCompatibilityUseCase` fetches packages concurrently via
/// `buffer_unordered` — a FIFO queue would make test assertions depend on
/// nondeterministic completion order. A package name with no configured
/// response returns an error (simulating a 404), matching the soft-fail path.
#[derive(Clone, Default)]
pub(crate) struct MockPythonCompatibilityRepository {
    responses: Arc<HashMap<String, std::result::Result<PythonCompatibilityInfo, String>>>,
}

impl MockPythonCompatibilityRepository {
    /// Creates a mock keyed by package name.
    pub fn with_responses(
        pairs: impl IntoIterator<Item = (String, std::result::Result<PythonCompatibilityInfo, String>)>,
    ) -> Self {
        Self {
            responses: Arc::new(pairs.into_iter().collect()),
        }
    }
}

#[async_trait]
impl PythonCompatibilityRepository for MockPythonCompatibilityRepository {
    async fn fetch_python_compatibility(
        &self,
        package_name: &str,
        _package_version: &str,
    ) -> Result<PythonCompatibilityInfo> {
        match self.responses.get(package_name) {
            Some(Ok(info)) => Ok(info.clone()),
            Some(Err(msg)) => Err(anyhow::anyhow!("{}", msg)),
            None => Err(anyhow::anyhow!("404 Not Found: {}", package_name)),
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

/// Configurable in-memory mock implementing `UvLockSimulator`.
///
/// Responses are keyed by package name rather than a FIFO queue, because
/// `SimulateUpgradesUseCase::run` deduplicates and iterates direct
/// dependencies via a `HashSet` — a FIFO queue would make test assertions
/// depend on nondeterministic iteration order, matching the reasoning behind
/// `MockPythonCompatibilityRepository` above. Shared between
/// `simulate_upgrades`'s own tests and `generate_sbom/tests.rs` now that both
/// are consumers (previously kept local to `generate_sbom/tests.rs`, back
/// when it was the only consumer).
///
/// Records every `simulate_upgrade` call in `calls` so tests can assert on
/// deduplication (e.g. that a package shared by multiple resolution entries
/// is only simulated once).
#[derive(Default)]
pub(crate) struct MockUvLockSimulator {
    results: HashMap<String, SimulationResult>,
    errors: HashMap<String, String>,
    calls: Mutex<Vec<String>>,
}

impl MockUvLockSimulator {
    pub(crate) fn with_result(package: &str, result: SimulationResult) -> Self {
        let mut results = HashMap::new();
        results.insert(package.to_string(), result);
        Self {
            results,
            errors: HashMap::new(),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn with_error(package: &str, error: &str) -> Self {
        let mut errors = HashMap::new();
        errors.insert(package.to_string(), error.to_string());
        Self {
            results: HashMap::new(),
            errors,
            calls: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn with_results_and_errors(
        results: HashMap<String, SimulationResult>,
        errors: HashMap<String, String>,
    ) -> Self {
        Self {
            results,
            errors,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Returns the package names passed to `simulate_upgrade`, in call order.
    pub(crate) fn call_log(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl UvLockSimulator for MockUvLockSimulator {
    async fn simulate_upgrade(
        &self,
        package_name: &str,
        _project_path: &std::path::Path,
    ) -> Result<SimulationResult> {
        self.calls.lock().unwrap().push(package_name.to_string());

        if let Some(error) = self.errors.get(package_name) {
            anyhow::bail!("{}", error);
        }
        self.results.get(package_name).cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "MockUvLockSimulator: no response configured for {}",
                package_name
            )
        })
    }
}
