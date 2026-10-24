use crate::ports::outbound::{
    GroupRoots, LockfileParseResult, LockfileReader, MaintenanceInfo, MaintenanceRepository,
    PackageSourceMap, ProgressCallback, ProjectConfigError, ProjectConfigReader,
    PythonCompatibilityInfo, PythonCompatibilityRepository, VulnerabilityRepository,
};
use crate::sbom_generation::domain::{
    Package, PackageVulnerabilities, SimulationResult, TargetedSimulationOutcome, UvLockSimulator,
};
use crate::shared::Result;
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// In-memory `LockfileReader` returning fixed packages, dependency map, group
/// roots, and source map regardless of the path. Shared by
/// `GenerateSbomUseCase`'s tests and `RespondToIncidentUseCase`'s tests (moved
/// here from `generate_sbom/mod.rs` once it gained a second consumer).
#[derive(Default)]
pub(crate) struct MockLockfileReader {
    pub(crate) packages: Vec<Package>,
    pub(crate) deps: HashMap<String, Vec<String>>,
    pub(crate) group_roots: GroupRoots,
    pub(crate) source_map: PackageSourceMap,
}

impl LockfileReader for MockLockfileReader {
    fn read_lockfile(&self, _path: &Path) -> Result<String> {
        Ok(String::new())
    }

    fn read_and_parse_lockfile(&self, _path: &Path) -> Result<LockfileParseResult> {
        Ok((self.packages.clone(), self.deps.clone()))
    }

    fn read_and_parse_lockfile_for_member(
        &self,
        _path: &Path,
        _member_name: &str,
    ) -> Result<LockfileParseResult> {
        Ok((self.packages.clone(), self.deps.clone()))
    }

    fn read_and_parse_group_roots(&self, _path: &Path) -> Result<GroupRoots> {
        Ok(self.group_roots.clone())
    }

    fn read_and_parse_package_sources(&self, _path: &Path) -> Result<PackageSourceMap> {
        Ok(self.source_map.clone())
    }
}

/// In-memory `ProjectConfigReader`. When `pyproject_missing` is set, returns the
/// typed `ProjectConfigError::PyprojectNotFound` the real adapter raises.
pub(crate) struct MockProjectConfigReader {
    pub(crate) project_name: String,
    pub(crate) pyproject_missing: bool,
}

impl ProjectConfigReader for MockProjectConfigReader {
    fn read_project_name(&self, _path: &Path) -> Result<String> {
        if self.pyproject_missing {
            return Err(ProjectConfigError::PyprojectNotFound.into());
        }
        Ok(self.project_name.clone())
    }
}

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
///
/// `simulate_upgrade_to` (incident mode, #967) answers from `targeted`, keyed
/// by package name: `Ok(outcome)` or `Err(message)`. An unconfigured package
/// is an error. Each call is recorded as `(package, target_version)` in
/// `targeted_calls`.
#[derive(Default)]
pub(crate) struct MockUvLockSimulator {
    results: HashMap<String, SimulationResult>,
    errors: HashMap<String, String>,
    calls: Mutex<Vec<String>>,
    targeted: HashMap<String, std::result::Result<TargetedSimulationOutcome, String>>,
    targeted_calls: Mutex<Vec<(String, String)>>,
    targeted_paths: Mutex<Vec<std::path::PathBuf>>,
}

impl MockUvLockSimulator {
    pub(crate) fn with_result(package: &str, result: SimulationResult) -> Self {
        let mut results = HashMap::new();
        results.insert(package.to_string(), result);
        Self {
            results,
            ..Self::default()
        }
    }

    pub(crate) fn with_error(package: &str, error: &str) -> Self {
        let mut errors = HashMap::new();
        errors.insert(package.to_string(), error.to_string());
        Self {
            errors,
            ..Self::default()
        }
    }

    pub(crate) fn with_results_and_errors(
        results: HashMap<String, SimulationResult>,
        errors: HashMap<String, String>,
    ) -> Self {
        Self {
            results,
            errors,
            ..Self::default()
        }
    }

    /// Returns the package names passed to `simulate_upgrade`, in call order.
    pub(crate) fn call_log(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    /// Adds a `simulate_upgrade_to` response for `package` (`Err` holds the
    /// error message to return).
    pub(crate) fn with_targeted(
        mut self,
        package: &str,
        outcome: std::result::Result<TargetedSimulationOutcome, String>,
    ) -> Self {
        self.targeted.insert(package.to_string(), outcome);
        self
    }

    /// Returns the `(package, target_version)` pairs passed to
    /// `simulate_upgrade_to`, in call order.
    pub(crate) fn targeted_call_log(&self) -> Vec<(String, String)> {
        self.targeted_calls.lock().unwrap().clone()
    }

    /// Returns the project paths passed to `simulate_upgrade_to`, in call order.
    pub(crate) fn targeted_path_log(&self) -> Vec<std::path::PathBuf> {
        self.targeted_paths.lock().unwrap().clone()
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
    async fn simulate_upgrade_to(
        &self,
        package_name: &str,
        target_version: &str,
        project_path: &std::path::Path,
    ) -> Result<TargetedSimulationOutcome> {
        self.targeted_calls
            .lock()
            .unwrap()
            .push((package_name.to_string(), target_version.to_string()));
        self.targeted_paths
            .lock()
            .unwrap()
            .push(project_path.to_path_buf());

        match self.targeted.get(package_name) {
            Some(Ok(outcome)) => Ok(outcome.clone()),
            Some(Err(msg)) => Err(anyhow::anyhow!("{}", msg)),
            None => anyhow::bail!(
                "MockUvLockSimulator: simulate_upgrade_to not configured for {}",
                package_name
            ),
        }
    }
}
