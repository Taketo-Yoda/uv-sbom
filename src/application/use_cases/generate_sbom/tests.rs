use super::*;
use crate::application::use_cases::test_doubles::{
    MockMaintenanceRepository, MockPythonCompatibilityRepository, MockVulnerabilityRepository,
};
use crate::ports::outbound::{GroupRoots, LockfileParseResult, PackageSourceMap, PyPiMetadata};
use crate::sbom_generation::domain::{Package, SimulationResult};
use std::collections::HashMap;
use std::path::Path;

struct MockLockfileReader {
    packages: Vec<Package>,
    deps: HashMap<String, Vec<String>>,
    group_roots: GroupRoots,
    source_map: PackageSourceMap,
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

struct MockProjectConfigReader {
    project_name: String,
}

impl ProjectConfigReader for MockProjectConfigReader {
    fn read_project_name(&self, _path: &Path) -> Result<String> {
        Ok(self.project_name.clone())
    }
}

#[derive(Clone)]
struct MockLicenseRepository;

#[async_trait::async_trait]
impl LicenseRepository for MockLicenseRepository {
    async fn fetch_license_info(
        &self,
        _package_name: &str,
        _version: &str,
    ) -> Result<PyPiMetadata> {
        Ok((
            Some("MIT".to_string()),
            None,
            vec![],
            Some("A test package".to_string()),
            None,
        ))
    }
}

struct MockProgressReporter;

impl ProgressReporter for MockProgressReporter {
    fn report(&self, _message: &str) {}
    fn report_error(&self, _message: &str) {}
    fn report_completion(&self, _message: &str) {}
}

/// Configurable in-memory mock implementing `UvLockSimulator`.
///
/// Responses are keyed by package name rather than a FIFO queue, because
/// `UpgradeAdvisor::advise` iterates a `HashMap` of unique direct deps — a
/// FIFO queue would make test assertions depend on nondeterministic
/// iteration order, matching the reasoning behind
/// `MockPythonCompatibilityRepository` in `test_doubles.rs`. Not shared via
/// `test_doubles.rs` since this use case is its only consumer.
#[derive(Default)]
struct MockUvLockSimulator {
    results: HashMap<String, SimulationResult>,
    errors: HashMap<String, String>,
}

impl MockUvLockSimulator {
    fn with_result(package: &str, result: SimulationResult) -> Self {
        let mut results = HashMap::new();
        results.insert(package.to_string(), result);
        Self {
            results,
            errors: HashMap::new(),
        }
    }

    fn with_error(package: &str, error: &str) -> Self {
        let mut errors = HashMap::new();
        errors.insert(package.to_string(), error.to_string());
        Self {
            results: HashMap::new(),
            errors,
        }
    }
}

#[async_trait::async_trait]
impl UvLockSimulator for MockUvLockSimulator {
    async fn simulate_upgrade(
        &self,
        package_name: &str,
        _project_path: &Path,
    ) -> Result<SimulationResult> {
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

mod test_helpers {
    use super::*;
    use crate::i18n::Locale;

    pub(super) type TestUseCase = GenerateSbomUseCase<
        MockLockfileReader,
        MockProjectConfigReader,
        MockLicenseRepository,
        MockProgressReporter,
        MockVulnerabilityRepository,
        MockMaintenanceRepository,
        MockPythonCompatibilityRepository,
        MockUvLockSimulator,
    >;

    pub(super) struct UseCaseBuilder {
        packages: Vec<Package>,
        deps: HashMap<String, Vec<String>>,
        group_roots: GroupRoots,
        source_map: PackageSourceMap,
        project_name: String,
        vuln: Option<MockVulnerabilityRepository>,
        maint: Option<MockMaintenanceRepository>,
        pyc: Option<MockPythonCompatibilityRepository>,
        sim: Option<MockUvLockSimulator>,
    }

    impl Default for UseCaseBuilder {
        fn default() -> Self {
            Self {
                packages: Vec::new(),
                deps: HashMap::new(),
                group_roots: HashMap::new(),
                source_map: PackageSourceMap::new(),
                project_name: "test-project".to_string(),
                vuln: None,
                maint: None,
                pyc: None,
                sim: None,
            }
        }
    }

    impl UseCaseBuilder {
        pub(super) fn with_lockfile(mut self, packages: Vec<Package>) -> Self {
            self.packages = packages;
            self
        }

        pub(super) fn with_lockfile_and_deps(
            mut self,
            packages: Vec<Package>,
            deps: HashMap<String, Vec<String>>,
        ) -> Self {
            self.packages = packages;
            self.deps = deps;
            self
        }

        pub(super) fn with_group_roots(mut self, roots: GroupRoots) -> Self {
            self.group_roots = roots;
            self
        }

        pub(super) fn with_project_name(mut self, name: impl Into<String>) -> Self {
            self.project_name = name.into();
            self
        }

        pub(super) fn with_vuln_repo(mut self) -> Self {
            self.vuln = Some(MockVulnerabilityRepository::new());
            self
        }

        pub(super) fn with_maintenance_repo(mut self, repo: MockMaintenanceRepository) -> Self {
            self.maint = Some(repo);
            self
        }

        pub(super) fn with_python_compat_repo(
            mut self,
            repo: MockPythonCompatibilityRepository,
        ) -> Self {
            self.pyc = Some(repo);
            self
        }

        pub(super) fn with_simulator(mut self, sim: MockUvLockSimulator) -> Self {
            self.sim = Some(sim);
            self
        }

        pub(super) fn with_source_map(mut self, map: PackageSourceMap) -> Self {
            self.source_map = map;
            self
        }

        pub(super) fn build(self) -> TestUseCase {
            GenerateSbomUseCase::new(
                MockLockfileReader {
                    packages: self.packages,
                    deps: self.deps,
                    group_roots: self.group_roots,
                    source_map: self.source_map,
                },
                MockProjectConfigReader {
                    project_name: self.project_name,
                },
                MockLicenseRepository,
                MockProgressReporter,
                self.vuln,
                self.maint,
                self.pyc,
                self.sim,
                Locale::default(),
            )
        }
    }

    pub(super) fn default_request() -> SbomRequest {
        SbomRequest::builder()
            .project_path("/test/project")
            .build()
            .unwrap()
    }

    pub(super) fn pkg(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
    }
}

mod tests_execute {
    use super::test_helpers::*;
    use super::*;

    #[tokio::test]
    async fn test_execute_without_dependencies() {
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![
                pkg("certifi", "2024.8.30"),
                pkg("charset-normalizer", "3.4.0"),
            ])
            .build();

        let response = use_case.execute(default_request()).await.unwrap();

        assert_eq!(response.enriched_packages.len(), 2);
        assert!(response.dependency_graph.is_none());
        assert!(!response.metadata.serial_number().is_empty());
    }

    #[tokio::test]
    async fn test_execute_with_dependencies() {
        let packages = vec![
            pkg("myproject", "1.0.0"),
            pkg("requests", "2.31.0"),
            pkg("urllib3", "1.26.0"),
        ];
        let deps = HashMap::from([
            ("myproject".to_string(), vec!["requests".to_string()]),
            ("requests".to_string(), vec!["urllib3".to_string()]),
            ("urllib3".to_string(), vec![]),
        ]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile_and_deps(packages, deps)
            .with_project_name("myproject")
            .build();

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .include_dependency_info(true)
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();

        assert_eq!(response.enriched_packages.len(), 3);
        assert!(response.dependency_graph.is_some());
        let graph = response.dependency_graph.unwrap();
        assert_eq!(graph.direct_dependency_count(), 1);
        assert_eq!(graph.transitive_dependency_count(), 1);
    }

    #[tokio::test]
    async fn test_execute_with_cve_check_enabled() {
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![
                pkg("certifi", "2024.8.30"),
                pkg("charset-normalizer", "3.4.0"),
            ])
            .with_vuln_repo()
            .build();

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_cve(true)
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();

        assert_eq!(response.enriched_packages.len(), 2);
        assert!(response.vulnerability_check_result.is_some());
    }

    #[tokio::test]
    async fn test_execute_with_cve_check_but_no_repository() {
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("certifi", "2024.8.30")])
            .build();

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_cve(true)
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();

        assert_eq!(response.enriched_packages.len(), 1);
        assert!(response.vulnerability_check_result.is_none());
    }

    #[tokio::test]
    async fn test_execute_with_cve_check_disabled() {
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("certifi", "2024.8.30")])
            .with_vuln_repo()
            .build();

        let response = use_case.execute(default_request()).await.unwrap();

        assert_eq!(response.enriched_packages.len(), 1);
        assert!(response.vulnerability_check_result.is_none());
    }

    #[tokio::test]
    async fn test_execute_with_cve_check_in_dry_run_mode() {
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("certifi", "2024.8.30")])
            .with_vuln_repo()
            .build();

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .dry_run(true)
            .check_cve(true)
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();

        assert_eq!(response.enriched_packages.len(), 0);
        assert!(response.vulnerability_check_result.is_none());
    }
}

mod tests_exclusion {
    use super::test_helpers::*;
    use super::*;

    #[test]
    fn test_apply_exclusion_filters_empty_patterns() {
        let use_case = UseCaseBuilder::default().build();
        let packages = vec![pkg("pkg1", "1.0.0"), pkg("pkg2", "2.0.0")];

        let filtered = use_case
            .apply_exclusion_filters(packages, &default_request())
            .unwrap();

        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_apply_exclusion_filters_with_patterns() {
        let use_case = UseCaseBuilder::default().build();
        let packages = vec![
            pkg("requests", "1.0.0"),
            pkg("urllib3", "2.0.0"),
            pkg("certifi", "3.0.0"),
        ];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .exclude_patterns(vec!["requests".to_string()])
            .build()
            .unwrap();

        let filtered = use_case
            .apply_exclusion_filters(packages, &request)
            .unwrap();

        assert_eq!(filtered.len(), 2);
        assert!(!filtered.iter().any(|p| p.name() == "requests"));
    }

    #[test]
    fn test_apply_exclusion_filters_all_excluded_error() {
        let use_case = UseCaseBuilder::default().build();
        let packages = vec![pkg("pkg1", "1.0.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .exclude_patterns(vec!["pkg1".to_string()])
            .build()
            .unwrap();

        let result = use_case.apply_exclusion_filters(packages, &request);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("All 1 package(s) were excluded"));
    }
}

mod tests_dependencies {
    use super::test_helpers::*;
    use super::*;

    #[test]
    fn test_analyze_dependencies_disabled() {
        let use_case = UseCaseBuilder::default().build();
        let dependency_map: HashMap<String, Vec<String>> = HashMap::new();

        let result = use_case
            .analyze_dependencies_if_requested(&default_request(), &dependency_map)
            .unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_analyze_dependencies_enabled() {
        let use_case = UseCaseBuilder::default()
            .with_project_name("myproject")
            .build();
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .include_dependency_info(true)
            .build()
            .unwrap();
        let dependency_map = HashMap::from([
            ("myproject".to_string(), vec!["requests".to_string()]),
            ("requests".to_string(), vec![]),
        ]);

        let result = use_case
            .analyze_dependencies_if_requested(&request, &dependency_map)
            .unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().direct_dependency_count(), 1);
    }
}

mod tests_response {
    use super::test_helpers::*;
    use super::*;

    #[test]
    fn test_build_response() {
        let use_case = UseCaseBuilder::default().build();
        let enriched_packages = vec![EnrichedPackage::new(
            pkg("test-pkg", "1.0.0"),
            Some("MIT".to_string()),
            Some("Test description".to_string()),
        )];

        let response = use_case.build_response(
            enriched_packages,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            vec![],
        );

        assert_eq!(response.enriched_packages.len(), 1);
        assert!(response.dependency_graph.is_none());
        assert!(response.vulnerability_check_result.is_none());
        assert!(!response.metadata.serial_number().is_empty());
        assert!(!response.metadata.timestamp().is_empty());
    }

    #[test]
    fn test_build_response_with_threshold_exceeded() {
        use crate::sbom_generation::domain::vulnerability::{CvssScore, Severity, Vulnerability};

        let use_case = UseCaseBuilder::default().build();
        let enriched_packages = vec![EnrichedPackage::new(
            pkg("test-pkg", "1.0.0"),
            Some("MIT".to_string()),
            Some("Test description".to_string()),
        )];
        let vuln = Vulnerability::new(
            "CVE-2024-001".to_string(),
            Some(CvssScore::new(9.0).unwrap()),
            Severity::Critical,
            None,
            None,
        )
        .unwrap();
        let pkg_vulns = crate::sbom_generation::domain::PackageVulnerabilities::new(
            "test-pkg".to_string(),
            "1.0.0".to_string(),
            vec![vuln],
        );
        let check_result = VulnerabilityCheckResult {
            above_threshold: vec![pkg_vulns],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let response = use_case.build_response(
            enriched_packages,
            None,
            Some(check_result),
            None,
            None,
            None,
            None,
            None,
            vec![],
        );

        assert!(response.has_vulnerabilities_above_threshold);
        assert!(
            response
                .vulnerability_check_result
                .unwrap()
                .threshold_exceeded
        );
    }

    #[test]
    fn test_build_response_with_threshold_not_exceeded() {
        use crate::sbom_generation::domain::vulnerability::{CvssScore, Severity, Vulnerability};

        let use_case = UseCaseBuilder::default().build();
        let enriched_packages = vec![EnrichedPackage::new(
            pkg("test-pkg", "1.0.0"),
            Some("MIT".to_string()),
            Some("Test description".to_string()),
        )];
        let vuln = Vulnerability::new(
            "CVE-2024-001".to_string(),
            Some(CvssScore::new(3.0).unwrap()),
            Severity::Low,
            None,
            None,
        )
        .unwrap();
        let pkg_vulns = crate::sbom_generation::domain::PackageVulnerabilities::new(
            "test-pkg".to_string(),
            "1.0.0".to_string(),
            vec![vuln],
        );
        let check_result = VulnerabilityCheckResult {
            above_threshold: vec![],
            below_threshold: vec![pkg_vulns],
            threshold_exceeded: false,
        };

        let response = use_case.build_response(
            enriched_packages,
            None,
            Some(check_result),
            None,
            None,
            None,
            None,
            None,
            vec![],
        );

        assert!(!response.has_vulnerabilities_above_threshold);
        assert!(
            !response
                .vulnerability_check_result
                .unwrap()
                .threshold_exceeded
        );
    }
}

mod tests_vulnerabilities {
    use super::test_helpers::*;
    use super::*;

    #[tokio::test]
    async fn test_fetch_license_info() {
        let use_case = UseCaseBuilder::default().build();
        let packages = vec![pkg("pkg1", "1.0.0"), pkg("pkg2", "2.0.0")];

        let enriched = use_case.fetch_license_info(packages).await.unwrap();

        assert_eq!(enriched.len(), 2);
        assert!(enriched[0].license.is_some());
        assert_eq!(enriched[0].license.as_ref().unwrap(), "MIT");
    }

    #[tokio::test]
    async fn test_check_vulnerabilities_if_requested_disabled() {
        let use_case = UseCaseBuilder::default().with_vuln_repo().build();
        let packages = vec![pkg("pkg1", "1.0.0")];

        let result = use_case
            .check_vulnerabilities_if_requested(&default_request(), &packages)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_check_vulnerabilities_if_requested_enabled() {
        let use_case = UseCaseBuilder::default().with_vuln_repo().build();
        let packages = vec![pkg("pkg1", "1.0.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_cve(true)
            .build()
            .unwrap();

        let result = use_case
            .check_vulnerabilities_if_requested(&request, &packages)
            .await
            .unwrap();

        assert!(result.is_some());
    }

    #[test]
    fn test_build_threshold_config_none() {
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_cve(true)
            .build()
            .unwrap();

        let config = TestUseCase::build_threshold_config(&request);

        assert_eq!(config, ThresholdConfig::None);
    }

    #[test]
    fn test_build_threshold_config_severity() {
        use crate::sbom_generation::domain::vulnerability::Severity;

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_cve(true)
            .severity_threshold_opt(Some(Severity::High))
            .build()
            .unwrap();

        let config = TestUseCase::build_threshold_config(&request);

        assert_eq!(config, ThresholdConfig::Severity(Severity::High));
    }

    #[test]
    fn test_build_threshold_config_cvss() {
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_cve(true)
            .cvss_threshold_opt(Some(7.0))
            .build()
            .unwrap();

        let config = TestUseCase::build_threshold_config(&request);

        assert_eq!(config, ThresholdConfig::Cvss(7.0));
    }
}

mod tests_abandoned {
    use super::test_helpers::*;
    use super::*;
    use crate::application::use_cases::test_doubles::MockMaintenanceRepository;
    use crate::ports::outbound::MaintenanceInfo;
    use chrono::NaiveDate;

    #[tokio::test]
    async fn test_check_abandoned_disabled_returns_none() {
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("requests", "2.31.0")])
            .build();
        let packages = [pkg("requests", "2.31.0")];

        let result = use_case
            .check_abandoned_if_requested(&default_request(), &packages, None)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_check_abandoned_no_repo_returns_none() {
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("requests", "2.31.0")])
            .build();
        let packages = [pkg("requests", "2.31.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_abandoned(true)
            .build()
            .unwrap();

        let result = use_case
            .check_abandoned_if_requested(&request, &packages, None)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_check_abandoned_with_old_package_returns_report() {
        let old_date = NaiveDate::from_ymd_opt(2020, 1, 1).unwrap();
        let maint_repo = MockMaintenanceRepository::with_responses([Ok(MaintenanceInfo {
            last_release_date: Some(old_date),
        })]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("requests", "2.31.0")])
            .with_maintenance_repo(maint_repo)
            .build();
        let packages = [pkg("requests", "2.31.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_abandoned(true)
            .abandoned_threshold_days(365)
            .build()
            .unwrap();

        let result = use_case
            .check_abandoned_if_requested(&request, &packages, None)
            .await
            .unwrap();

        assert!(result.is_some());
        let report = result.unwrap();
        assert_eq!(report.total_count(), 1);
        assert_eq!(report.packages[0].name, "requests");
        assert!(report.packages[0].days_inactive >= 365);
        assert_eq!(report.threshold_days, 365);
        assert_eq!(report.direct_count(), 0); // no graph supplied → all non-direct
        assert_eq!(report.transitive_count(), 1);
    }

    #[tokio::test]
    async fn test_check_abandoned_recent_package_produces_empty_report() {
        use chrono::Utc;
        let recent_date = Utc::now().date_naive();
        let maint_repo = MockMaintenanceRepository::with_responses([Ok(MaintenanceInfo {
            last_release_date: Some(recent_date),
        })]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("requests", "2.31.0")])
            .with_maintenance_repo(maint_repo)
            .build();
        let packages = [pkg("requests", "2.31.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_abandoned(true)
            .abandoned_threshold_days(365)
            .build()
            .unwrap();

        let result = use_case
            .check_abandoned_if_requested(&request, &packages, None)
            .await
            .unwrap();

        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_check_abandoned_unknown_release_date_excluded() {
        let maint_repo = MockMaintenanceRepository::with_responses([Ok(MaintenanceInfo {
            last_release_date: None,
        })]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("old-pkg", "1.0.0")])
            .with_maintenance_repo(maint_repo)
            .build();
        let packages = [pkg("old-pkg", "1.0.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_abandoned(true)
            .abandoned_threshold_days(1)
            .build()
            .unwrap();

        let result = use_case
            .check_abandoned_if_requested(&request, &packages, None)
            .await
            .unwrap();

        // Package with unknown release date is excluded from the report
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_check_abandoned_sorted_by_days_inactive_descending() {
        let older_date = NaiveDate::from_ymd_opt(2018, 1, 1).unwrap();
        let newer_date = NaiveDate::from_ymd_opt(2021, 1, 1).unwrap();
        let maint_repo = MockMaintenanceRepository::with_responses([
            Ok(MaintenanceInfo {
                last_release_date: Some(newer_date),
            }),
            Ok(MaintenanceInfo {
                last_release_date: Some(older_date),
            }),
        ]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("newer-pkg", "1.0.0"), pkg("older-pkg", "1.0.0")])
            .with_maintenance_repo(maint_repo)
            .build();
        let packages = [pkg("newer-pkg", "1.0.0"), pkg("older-pkg", "1.0.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_abandoned(true)
            .abandoned_threshold_days(365)
            .build()
            .unwrap();

        let result = use_case
            .check_abandoned_if_requested(&request, &packages, None)
            .await
            .unwrap();

        assert!(result.is_some());
        let report = result.unwrap();
        assert_eq!(report.total_count(), 2);
        // Sorted descending: older-pkg (more days inactive) should be first
        assert!(report.packages[0].days_inactive >= report.packages[1].days_inactive);
    }
}

mod tests_python_compatibility {
    use super::test_helpers::*;
    use super::*;
    use crate::ports::outbound::PythonCompatibilityInfo;

    #[tokio::test]
    async fn test_python_compat_target_unset_returns_none() {
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("requests", "2.31.0")])
            .build();
        let packages = [pkg("requests", "2.31.0")];

        let result = use_case
            .check_python_compatibility_if_requested(&default_request(), &packages, None)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_python_compat_no_repo_returns_none() {
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("requests", "2.31.0")])
            .build();
        let packages = [pkg("requests", "2.31.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .target_python(Some("3.13".to_string()))
            .build()
            .unwrap();

        let result = use_case
            .check_python_compatibility_if_requested(&request, &packages, None)
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_python_compat_with_incompatible_package_returns_report() {
        let pyc_repo = MockPythonCompatibilityRepository::with_responses([(
            "legacy-lib".to_string(),
            Ok(PythonCompatibilityInfo {
                requires_python: Some(">=3.8,<3.12".to_string()),
            }),
        )]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("legacy-lib", "1.0.0")])
            .with_python_compat_repo(pyc_repo)
            .build();
        let packages = [pkg("legacy-lib", "1.0.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .target_python(Some("3.13".to_string()))
            .build()
            .unwrap();

        let result = use_case
            .check_python_compatibility_if_requested(&request, &packages, None)
            .await
            .unwrap();

        assert!(result.is_some());
        let report = result.unwrap();
        assert_eq!(report.total_count(), 1);
        assert_eq!(report.incompatible[0].name, "legacy-lib");
        assert_eq!(report.target_python, "3.13");
    }

    #[tokio::test]
    async fn test_python_compat_all_compatible_produces_empty_report() {
        let pyc_repo = MockPythonCompatibilityRepository::with_responses([(
            "requests".to_string(),
            Ok(PythonCompatibilityInfo {
                requires_python: Some(">=3.7".to_string()),
            }),
        )]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("requests", "2.31.0")])
            .with_python_compat_repo(pyc_repo)
            .build();
        let packages = [pkg("requests", "2.31.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .target_python(Some("3.13".to_string()))
            .build()
            .unwrap();

        let result = use_case
            .check_python_compatibility_if_requested(&request, &packages, None)
            .await
            .unwrap();

        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    /// End-to-end integration test: exercises the `target_python` path through
    /// `execute()`, verifying `SbomResponse.python_compatibility_report` is
    /// populated from a mock `PythonCompatibilityRepository`.
    #[tokio::test]
    async fn test_execute_with_target_python_populates_response_report() {
        let pyc_repo = MockPythonCompatibilityRepository::with_responses([(
            "legacy-lib".to_string(),
            Ok(PythonCompatibilityInfo {
                requires_python: Some(">=3.8,<3.12".to_string()),
            }),
        )]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("legacy-lib", "1.0.0")])
            .with_python_compat_repo(pyc_repo)
            .build();

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .target_python(Some("3.13".to_string()))
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();

        assert!(response.python_compatibility_report.is_some());
        let report = response.python_compatibility_report.unwrap();
        assert_eq!(report.total_count(), 1);
        assert_eq!(report.incompatible[0].name, "legacy-lib");
    }

    #[tokio::test]
    async fn test_execute_without_target_python_leaves_report_none() {
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("requests", "2.31.0")])
            .build();

        let response = use_case.execute(default_request()).await.unwrap();

        assert!(response.python_compatibility_report.is_none());
    }
}

// Tests for issue #206: Excluding root project preserves dependency classification
mod tests_regression {
    use super::test_helpers::*;
    use super::*;

    #[tokio::test]
    async fn test_execute_with_root_excluded_preserves_dependency_classification() {
        let packages = vec![
            pkg("myproject", "1.0.0"),
            pkg("requests", "2.31.0"),
            pkg("urllib3", "1.26.0"),
            pkg("certifi", "2024.8.30"),
            pkg("numpy", "1.26.0"),
        ];
        let deps = HashMap::from([
            (
                "myproject".to_string(),
                vec!["requests".to_string(), "numpy".to_string()],
            ),
            (
                "requests".to_string(),
                vec!["urllib3".to_string(), "certifi".to_string()],
            ),
            ("urllib3".to_string(), vec![]),
            ("certifi".to_string(), vec![]),
            ("numpy".to_string(), vec![]),
        ]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile_and_deps(packages, deps)
            .with_project_name("myproject")
            .build();

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .include_dependency_info(true)
            .exclude_patterns(vec!["myproject".to_string()])
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();

        assert_eq!(response.enriched_packages.len(), 4);
        assert!(!response
            .enriched_packages
            .iter()
            .any(|p| p.package.name() == "myproject"));
        assert!(response.dependency_graph.is_some());
        let graph = response.dependency_graph.unwrap();
        assert_eq!(graph.direct_dependency_count(), 2);
        let direct_dep_names: Vec<&str> = graph
            .direct_dependencies()
            .iter()
            .map(|p| p.as_str())
            .collect();
        assert!(direct_dep_names.contains(&"requests"));
        assert!(direct_dep_names.contains(&"numpy"));
        assert_eq!(graph.transitive_dependency_count(), 2);
    }

    #[tokio::test]
    async fn test_execute_without_root_excluded_baseline() {
        let packages = vec![
            pkg("myproject", "1.0.0"),
            pkg("requests", "2.31.0"),
            pkg("urllib3", "1.26.0"),
        ];
        let deps = HashMap::from([
            ("myproject".to_string(), vec!["requests".to_string()]),
            ("requests".to_string(), vec!["urllib3".to_string()]),
            ("urllib3".to_string(), vec![]),
        ]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile_and_deps(packages, deps)
            .with_project_name("myproject")
            .build();

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .include_dependency_info(true)
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();

        assert_eq!(response.enriched_packages.len(), 3);
        assert!(response.dependency_graph.is_some());
        let graph = response.dependency_graph.unwrap();
        assert_eq!(graph.direct_dependency_count(), 1);
        assert_eq!(graph.transitive_dependency_count(), 1);
    }

    #[tokio::test]
    async fn test_execute_exclude_non_root_preserves_dependency_classification() {
        let packages = vec![
            pkg("myproject", "1.0.0"),
            pkg("requests", "2.31.0"),
            pkg("urllib3", "1.26.0"),
            pkg("pytest", "7.0.0"),
        ];
        let deps = HashMap::from([
            (
                "myproject".to_string(),
                vec!["requests".to_string(), "pytest".to_string()],
            ),
            ("requests".to_string(), vec!["urllib3".to_string()]),
            ("urllib3".to_string(), vec![]),
            ("pytest".to_string(), vec![]),
        ]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile_and_deps(packages, deps)
            .with_project_name("myproject")
            .build();

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .include_dependency_info(true)
            .exclude_patterns(vec!["pytest".to_string()])
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();

        assert_eq!(response.enriched_packages.len(), 3);
        assert!(!response
            .enriched_packages
            .iter()
            .any(|p| p.package.name() == "pytest"));
        assert!(response.dependency_graph.is_some());
        let graph = response.dependency_graph.unwrap();
        assert_eq!(graph.direct_dependency_count(), 2);
    }

    #[tokio::test]
    async fn test_execute_with_check_abandoned_enabled_completes_successfully() {
        // Exercises the check_abandoned=true path through execute().
        // Detection is deferred; the use case must complete without error and
        // consume both check_abandoned and abandoned_threshold_days.
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("certifi", "2024.8.30")])
            .build();

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_abandoned(true)
            .abandoned_threshold_days(365)
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();
        assert_eq!(response.enriched_packages.len(), 1);
    }
}

mod tests_group_exclusion {
    use super::test_helpers::*;
    use super::*;

    fn make_dep_graph(edges: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for &(parent, deps) in edges {
            let entry = map.entry(parent.to_string()).or_default();
            for &dep in deps {
                entry.push(dep.to_string());
            }
            for &dep in deps {
                map.entry(dep.to_string()).or_default();
            }
        }
        map
    }

    fn make_group_roots(groups: &[(&str, &[&str])]) -> GroupRoots {
        groups
            .iter()
            .map(|&(g, roots)| (g.to_string(), roots.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    #[tokio::test]
    async fn test_empty_exclude_groups_returns_all_packages() {
        let packages = vec![
            pkg("myapp", "1.0.0"),
            pkg("requests", "2.0.0"),
            pkg("pytest", "7.0.0"),
        ];
        let deps = make_dep_graph(&[("myapp", &["requests"]), ("requests", &[]), ("pytest", &[])]);
        let group_roots = make_group_roots(&[("dev", &["pytest"])]);

        let use_case = UseCaseBuilder::default()
            .with_lockfile_and_deps(packages, deps)
            .with_group_roots(group_roots)
            .build();

        let response = use_case.execute(default_request()).await.unwrap();

        assert_eq!(response.enriched_packages.len(), 3);
    }

    #[tokio::test]
    async fn test_dev_only_package_excluded_via_execute() {
        let packages = vec![
            pkg("myapp", "1.0.0"),
            pkg("requests", "2.0.0"),
            pkg("pytest", "7.0.0"),
            pkg("iniconfig", "2.0.0"),
        ];
        let deps = make_dep_graph(&[
            ("myapp", &["requests"]),
            ("requests", &[]),
            ("pytest", &["iniconfig"]),
            ("iniconfig", &[]),
        ]);
        let group_roots = make_group_roots(&[("dev", &["pytest"])]);

        let use_case = UseCaseBuilder::default()
            .with_lockfile_and_deps(packages, deps)
            .with_group_roots(group_roots)
            .build();

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .exclude_groups(vec!["dev".to_string()])
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();

        let names: Vec<&str> = response
            .enriched_packages
            .iter()
            .map(|ep| ep.package.name())
            .collect();
        assert!(!names.contains(&"pytest"), "dev root must be excluded");
        assert!(
            !names.contains(&"iniconfig"),
            "dev transitive must be excluded"
        );
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"myapp"));
    }

    #[tokio::test]
    async fn test_shared_package_retained() {
        let packages = vec![
            pkg("myapp", "1.0.0"),
            pkg("requests", "2.0.0"),
            pkg("certifi", "2024.1.1"),
            pkg("pytest", "7.0.0"),
        ];
        let deps = make_dep_graph(&[
            ("myapp", &["requests"]),
            ("requests", &["certifi"]),
            ("pytest", &["certifi"]),
            ("certifi", &[]),
        ]);
        let group_roots = make_group_roots(&[("dev", &["pytest"])]);

        let use_case = UseCaseBuilder::default()
            .with_lockfile_and_deps(packages, deps)
            .with_group_roots(group_roots)
            .build();

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .exclude_groups(vec!["dev".to_string()])
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();

        let names: Vec<&str> = response
            .enriched_packages
            .iter()
            .map(|ep| ep.package.name())
            .collect();
        assert!(
            names.contains(&"certifi"),
            "shared package must be retained"
        );
        assert!(!names.contains(&"pytest"), "dev-only root must be excluded");
    }

    #[tokio::test]
    async fn test_unknown_group_name_is_ignored() {
        let packages = vec![pkg("myapp", "1.0.0"), pkg("requests", "2.0.0")];
        let deps = make_dep_graph(&[("myapp", &["requests"]), ("requests", &[])]);

        let use_case = UseCaseBuilder::default()
            .with_lockfile_and_deps(packages, deps)
            .with_group_roots(HashMap::new())
            .build();

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .exclude_groups(vec!["nonexistent".to_string()])
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();

        assert_eq!(response.enriched_packages.len(), 2);
    }
}

mod tests_non_pypi {
    use super::test_helpers::*;
    use super::*;
    use crate::ports::outbound::lockfile_reader::PackageSourceKind;

    #[test]
    fn test_check_non_pypi_disabled_returns_none() {
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("requests", "2.31.0")])
            .build();
        let packages = [pkg("requests", "2.31.0")];

        let result = use_case
            .check_non_pypi_if_requested(&default_request(), &packages, None)
            .unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_check_non_pypi_empty_source_map_returns_empty_report() {
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("requests", "2.31.0")])
            .build();
        let packages = [pkg("requests", "2.31.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_non_pypi(true)
            .build()
            .unwrap();

        let result = use_case
            .check_non_pypi_if_requested(&request, &packages, None)
            .unwrap();

        let report = result.expect("check enabled → Some");
        assert!(report.is_empty());
    }

    #[test]
    fn test_check_non_pypi_pypi_packages_excluded() {
        let mut source_map = PackageSourceMap::new();
        source_map.insert("requests".to_string(), PackageSourceKind::PyPi);
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("requests", "2.31.0")])
            .with_source_map(source_map)
            .build();
        let packages = [pkg("requests", "2.31.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_non_pypi(true)
            .build()
            .unwrap();

        let result = use_case
            .check_non_pypi_if_requested(&request, &packages, None)
            .unwrap()
            .expect("check enabled → Some");

        assert!(result.is_empty(), "PyPI packages must not appear in report");
    }

    #[test]
    fn test_check_non_pypi_git_package_detected() {
        let mut source_map = PackageSourceMap::new();
        source_map.insert(
            "my-lib".to_string(),
            PackageSourceKind::Git("https://github.com/user/my-lib?rev=abc123".to_string()),
        );
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("my-lib", "0.1.0")])
            .with_source_map(source_map)
            .build();
        let packages = [pkg("my-lib", "0.1.0")];
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_non_pypi(true)
            .build()
            .unwrap();

        let result = use_case
            .check_non_pypi_if_requested(&request, &packages, None)
            .unwrap()
            .expect("check enabled → Some");

        assert_eq!(result.total_count(), 1);
        let view = &result.packages[0];
        assert_eq!(view.name, "my-lib");
        assert_eq!(view.source_label, "Git");
        assert_eq!(
            view.source_location,
            "https://github.com/user/my-lib?rev=abc123"
        );
        assert!(!view.is_direct, "no graph → is_direct defaults to false");
    }

    #[test]
    fn test_check_non_pypi_is_direct_from_dependency_graph() {
        use crate::sbom_generation::domain::{DependencyGraph, PackageName};

        let mut source_map = PackageSourceMap::new();
        source_map.insert(
            "internal".to_string(),
            PackageSourceKind::PrivateRegistry("https://internal.example.com/simple".to_string()),
        );

        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("internal", "1.0.0")])
            .with_source_map(source_map)
            .build();
        let packages = [pkg("internal", "1.0.0")];

        let direct = vec![PackageName::new("internal".to_string()).unwrap()];
        let graph = DependencyGraph::new(direct, Default::default(), Default::default());

        let request = SbomRequest::builder()
            .project_path("/test/project")
            .check_non_pypi(true)
            .build()
            .unwrap();

        let result = use_case
            .check_non_pypi_if_requested(&request, &packages, Some(&graph))
            .unwrap()
            .expect("check enabled → Some");

        assert_eq!(result.direct_count(), 1);
        assert_eq!(result.transitive_count(), 0);
        assert!(result.packages[0].is_direct);
    }
}

mod tests_python_compat_markdown {
    use super::test_helpers::*;
    use super::*;
    use crate::adapters::outbound::formatters::MarkdownFormatter;
    use crate::application::read_models::SbomReadModelBuilder;
    use crate::i18n::Locale;
    use crate::ports::outbound::{PythonCompatibilityInfo, SbomFormatter};

    fn format_markdown(response: &crate::application::dto::SbomResponse) -> String {
        let read_model = SbomReadModelBuilder::build_with_project(
            response.enriched_packages.clone(),
            &response.metadata,
            response.dependency_graph.as_ref(),
            response.vulnerability_check_result.as_ref(),
            response.license_compliance_result.as_ref(),
            None,
            response.upgrade_recommendations.as_deref(),
            response.abandoned_packages_report.as_ref(),
            response.non_pypi_packages_report.as_ref(),
            response.python_compatibility_report.as_ref(),
            &response.applied_group_filter,
        );
        MarkdownFormatter::new(Locale::En)
            .format(&read_model)
            .unwrap()
    }

    #[tokio::test]
    async fn test_markdown_renders_python_compat_issues_table() {
        let pyc_repo = MockPythonCompatibilityRepository::with_responses([(
            "legacy-lib".to_string(),
            Ok(PythonCompatibilityInfo {
                requires_python: Some(">=3.8,<3.12".to_string()),
            }),
        )]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("legacy-lib", "1.0.0")])
            .with_python_compat_repo(pyc_repo)
            .build();
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .target_python(Some("3.13".to_string()))
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();
        let markdown = format_markdown(&response);

        assert!(markdown.contains("## ⚠️ Python 3.13 Compatibility Issues"));
        assert!(markdown.contains("| Package | Version | Requires-Python | Type |"));
        assert!(markdown.contains("| legacy-lib | 1.0.0 | >=3.8,<3.12 |"));
    }

    #[tokio::test]
    async fn test_markdown_renders_python_compat_all_clear() {
        let pyc_repo = MockPythonCompatibilityRepository::with_responses([(
            "requests".to_string(),
            Ok(PythonCompatibilityInfo {
                requires_python: Some(">=3.7".to_string()),
            }),
        )]);
        let use_case = UseCaseBuilder::default()
            .with_lockfile(vec![pkg("requests", "2.31.0")])
            .with_python_compat_repo(pyc_repo)
            .build();
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .target_python(Some("3.13".to_string()))
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();
        let markdown = format_markdown(&response);

        assert!(markdown.contains("## ✅ Python 3.13 Compatibility"));
        assert!(!markdown.contains("Compatibility Issues"));
    }
}

mod tests_upgrade_advisor {
    use super::test_helpers::*;
    use super::*;
    use crate::sbom_generation::domain::vulnerability::{CvssScore, Severity, Vulnerability};
    use crate::sbom_generation::domain::{DependencyGraph, PackageName, PackageVulnerabilities};

    /// Builds a minimal fixture: a direct dependency `app-dep` that transitively
    /// introduces `vuln-lib`, which has one vulnerability with a fixed version.
    /// This is the shape `ResolutionAnalyzer::analyze` requires to produce a
    /// non-empty `ResolutionEntry` list (see resolution_analyzer.rs).
    struct Fixture {
        graph: DependencyGraph,
        vulns: Vec<PackageVulnerabilities>,
        enriched: Vec<EnrichedPackage>,
    }

    fn make_fixture() -> Fixture {
        let direct = vec![PackageName::new("app-dep".to_string()).unwrap()];
        let transitive = HashMap::from([(
            PackageName::new("app-dep".to_string()).unwrap(),
            vec![PackageName::new("vuln-lib".to_string()).unwrap()],
        )]);
        let graph = DependencyGraph::new(direct, transitive, HashMap::new());

        let vuln = Vulnerability::new(
            "CVE-2024-0001".to_string(),
            Some(CvssScore::new(7.5).unwrap()),
            Severity::High,
            Some("2.0.0".to_string()),
            None,
        )
        .unwrap();
        let vulns = vec![PackageVulnerabilities::new(
            "vuln-lib".to_string(),
            "1.0.0".to_string(),
            vec![vuln],
        )];

        let enriched = vec![EnrichedPackage::new(
            pkg("app-dep", "1.0.0"),
            Some("MIT".to_string()),
            None,
        )];

        Fixture {
            graph,
            vulns,
            enriched,
        }
    }

    #[tokio::test]
    async fn test_advise_returns_none_when_suggest_fix_disabled() {
        let use_case = UseCaseBuilder::default().build();
        let fixture = make_fixture();

        let result = use_case
            .advise_upgrades_if_requested(
                &default_request(),
                Some(&fixture.graph),
                Some(&fixture.vulns),
                &fixture.enriched,
            )
            .await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_advise_returns_empty_when_no_graph_or_vuln_report() {
        let use_case = UseCaseBuilder::default().build();
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .suggest_fix(true)
            .build()
            .unwrap();

        let result = use_case
            .advise_upgrades_if_requested(&request, None, None, &[])
            .await;

        assert!(result.expect("suggest_fix enabled → Some").is_empty());
    }

    #[tokio::test]
    async fn test_advise_returns_empty_when_no_resolution_entries() {
        let use_case = UseCaseBuilder::default().build();
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .suggest_fix(true)
            .build()
            .unwrap();
        let graph = DependencyGraph::new(vec![], HashMap::new(), HashMap::new());

        let result = use_case
            .advise_upgrades_if_requested(&request, Some(&graph), Some(&[]), &[])
            .await;

        assert!(result.expect("suggest_fix enabled → Some").is_empty());
    }

    #[tokio::test]
    async fn test_advise_returns_upgradable_with_mock_simulator() {
        let simulator = MockUvLockSimulator::with_result(
            "app-dep",
            SimulationResult {
                upgraded_to_version: "3.0.0".to_string(),
                resolved_versions: HashMap::from([("vuln-lib".to_string(), "2.0.0".to_string())]),
            },
        );
        let use_case = UseCaseBuilder::default().with_simulator(simulator).build();
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .suggest_fix(true)
            .build()
            .unwrap();
        let fixture = make_fixture();

        let result = use_case
            .advise_upgrades_if_requested(
                &request,
                Some(&fixture.graph),
                Some(&fixture.vulns),
                &fixture.enriched,
            )
            .await;

        let recommendations = result.expect("suggest_fix enabled with entries → Some");
        assert_eq!(recommendations.len(), 1);
        assert!(matches!(
            recommendations[0],
            UpgradeRecommendation::Upgradable { .. }
        ));
    }

    #[tokio::test]
    async fn test_advise_returns_simulation_failed_on_simulator_error() {
        let simulator = MockUvLockSimulator::with_error("app-dep", "uv command timed out");
        let use_case = UseCaseBuilder::default().with_simulator(simulator).build();
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .suggest_fix(true)
            .build()
            .unwrap();
        let fixture = make_fixture();

        let result = use_case
            .advise_upgrades_if_requested(
                &request,
                Some(&fixture.graph),
                Some(&fixture.vulns),
                &fixture.enriched,
            )
            .await;

        let recommendations = result.expect("suggest_fix enabled with entries → Some");
        assert_eq!(recommendations.len(), 1);
        assert!(matches!(
            recommendations[0],
            UpgradeRecommendation::SimulationFailed { .. }
        ));
    }

    #[tokio::test]
    async fn test_advise_returns_empty_when_no_simulator_injected() {
        // No `.with_simulator(...)` — documents the injected-`None` branch:
        // `self.uv_lock_simulator` is `None`, so `advise_upgrades_if_requested`
        // must not panic or call a simulator, even with real entries present.
        let use_case = UseCaseBuilder::default().build();
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .suggest_fix(true)
            .build()
            .unwrap();
        let fixture = make_fixture();

        let result = use_case
            .advise_upgrades_if_requested(
                &request,
                Some(&fixture.graph),
                Some(&fixture.vulns),
                &fixture.enriched,
            )
            .await;

        assert!(result.expect("suggest_fix enabled → Some").is_empty());
    }
}
