mod checks;
mod filtering;
mod response;
mod upgrade;

use crate::application::dto::{SbomRequest, SbomResponse};
use crate::i18n::Locale;
use crate::ports::outbound::{
    LicenseRepository, LockfileReader, MaintenanceRepository, ProgressReporter,
    ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
};
use crate::sbom_generation::domain::services::VulnerabilityChecker;
use crate::sbom_generation::domain::UvLockSimulator;
use crate::shared::Result;

/// GenerateSbomUseCase - Core use case for SBOM generation
///
/// This use case orchestrates the SBOM generation workflow using
/// generic dependency injection for all infrastructure dependencies.
///
/// # Type Parameters
/// * `LR` - LockfileReader implementation
/// * `PCR` - ProjectConfigReader implementation
/// * `LREPO` - LicenseRepository implementation
/// * `PR` - ProgressReporter implementation
/// * `VREPO` - VulnerabilityRepository implementation (optional)
/// * `MREPO` - MaintenanceRepository implementation (optional)
/// * `PCREPO` - PythonCompatibilityRepository implementation (optional)
/// * `USIM` - UvLockSimulator implementation (optional)
pub struct GenerateSbomUseCase<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO = (), USIM = ()> {
    lockfile_reader: LR,
    project_config_reader: PCR,
    license_repository: LREPO,
    progress_reporter: PR,
    vulnerability_repository: Option<VREPO>,
    maintenance_repository: Option<MREPO>,
    compatibility_repository: Option<PCREPO>,
    uv_lock_simulator: Option<USIM>,
    locale: Locale,
}

impl<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO, USIM>
    GenerateSbomUseCase<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO, USIM>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    LREPO: LicenseRepository + Clone,
    PR: ProgressReporter,
    VREPO: VulnerabilityRepository + Clone,
    MREPO: MaintenanceRepository + Clone,
    PCREPO: PythonCompatibilityRepository + Clone,
    USIM: UvLockSimulator,
{
    /// Creates a new GenerateSbomUseCase with injected dependencies
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lockfile_reader: LR,
        project_config_reader: PCR,
        license_repository: LREPO,
        progress_reporter: PR,
        vulnerability_repository: Option<VREPO>,
        maintenance_repository: Option<MREPO>,
        compatibility_repository: Option<PCREPO>,
        uv_lock_simulator: Option<USIM>,
        locale: Locale,
    ) -> Self {
        Self {
            lockfile_reader,
            project_config_reader,
            license_repository,
            progress_reporter,
            vulnerability_repository,
            maintenance_repository,
            compatibility_repository,
            uv_lock_simulator,
            locale,
        }
    }

    /// Executes the SBOM generation use case
    ///
    /// # Arguments
    /// * `request` - SBOM generation request containing project path and options
    ///
    /// # Returns
    /// SbomResponse containing enriched packages, optional dependency graph, and metadata
    pub async fn execute(&self, request: SbomRequest) -> Result<SbomResponse> {
        // Step 1: Read and parse lockfile
        let (packages, dependency_map) = self.read_and_report_lockfile(&request)?;

        // Step 2: Apply exclusion filters to packages only
        // Note: We pass dependency_map by reference to preserve it for dependency analysis.
        // The root project may be excluded from packages but we still need its entry
        // in dependency_map to correctly identify direct vs transitive dependencies.
        let filtered_packages = self.apply_exclusion_filters(packages, &request)?;

        // Step 2b: Apply group reachability filter when exclude_groups is non-empty.
        // dependency_map is borrowed (not filtered) to preserve direct/transitive classification.
        let filtered_packages =
            self.apply_group_filter(filtered_packages, &dependency_map, &request)?;

        // Early return for dry-run mode (validation only)
        if request.dry_run {
            return self.build_dry_run_response();
        }

        // Step 3: Analyze dependencies if requested
        // Use original dependency_map to preserve dependency classification even when
        // root project is excluded from the package list (fixes #206)
        let dependency_graph = self.analyze_dependencies_if_requested(&request, &dependency_map)?;

        // Step 4: Enrich packages with license information
        let enriched_packages = self.fetch_license_info(filtered_packages.clone()).await?;

        // Step 5: CVE check if requested
        let vulnerability_report = self
            .check_vulnerabilities_if_requested(&request, &filtered_packages)
            .await?;

        // Step 6: Apply threshold evaluation if vulnerabilities were found
        let vulnerability_check_result = vulnerability_report.as_ref().map(|report| {
            let threshold_config = Self::build_threshold_config(&request);
            VulnerabilityChecker::check(report.clone(), threshold_config, &request.ignore_cves)
        });

        // Step 7: License compliance check if requested
        let license_compliance_result =
            self.check_license_compliance_if_requested(&request, &enriched_packages);

        // Step 8: Upgrade advisor if requested
        let upgrade_recommendations = self
            .advise_upgrades_if_requested(
                &request,
                dependency_graph.as_ref(),
                vulnerability_report.as_deref(),
                &enriched_packages,
            )
            .await;

        // Step 9: Abandoned package check if requested
        let abandoned_packages_report = self
            .check_abandoned_if_requested(&request, &filtered_packages, dependency_graph.as_ref())
            .await?;

        // Step 10: Non-PyPI source detection if requested
        let non_pypi_packages_report = self.check_non_pypi_if_requested(
            &request,
            &filtered_packages,
            dependency_graph.as_ref(),
        )?;

        // Step 11: Python version compatibility check if requested
        let python_compatibility_report = self
            .check_python_compatibility_if_requested(
                &request,
                &filtered_packages,
                dependency_graph.as_ref(),
            )
            .await?;

        // Step 11.5: Build the --explain dependency-path view if requested.
        // Must run before build_response, which takes ownership of dependency_graph.
        let explain_view =
            self.build_explain_view_if_requested(&request, dependency_graph.as_ref());

        // Step 12: Build and return response
        Ok(self.build_response(
            enriched_packages,
            dependency_graph,
            vulnerability_check_result,
            license_compliance_result,
            upgrade_recommendations,
            abandoned_packages_report,
            non_pypi_packages_report,
            python_compatibility_report,
            explain_view,
            request.exclude_groups.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::test_doubles::{
        MockMaintenanceRepository, MockPythonCompatibilityRepository, MockUvLockSimulator,
        MockVulnerabilityRepository,
    };
    use crate::ports::outbound::{GroupRoots, LockfileParseResult, PackageSourceMap, PyPiMetadata};
    use crate::sbom_generation::domain::Package;
    use std::collections::HashMap;
    use std::path::Path;

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

    pub(crate) struct MockProjectConfigReader {
        pub(crate) project_name: String,
    }

    impl ProjectConfigReader for MockProjectConfigReader {
        fn read_project_name(&self, _path: &Path) -> Result<String> {
            Ok(self.project_name.clone())
        }
    }

    #[derive(Clone)]
    pub(crate) struct MockLicenseRepository;

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

    pub(crate) struct MockProgressReporter;

    impl ProgressReporter for MockProgressReporter {
        fn report(&self, _message: &str) {}
        fn report_error(&self, _message: &str) {}
        fn report_completion(&self, _message: &str) {}
    }

    pub(crate) mod test_helpers {
        use super::*;
        use crate::i18n::Locale;

        pub(crate) type TestUseCase = GenerateSbomUseCase<
            MockLockfileReader,
            MockProjectConfigReader,
            MockLicenseRepository,
            MockProgressReporter,
            MockVulnerabilityRepository,
            MockMaintenanceRepository,
            MockPythonCompatibilityRepository,
            MockUvLockSimulator,
        >;

        pub(crate) struct UseCaseBuilder {
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
            pub(crate) fn with_lockfile(mut self, packages: Vec<Package>) -> Self {
                self.packages = packages;
                self
            }

            pub(crate) fn with_lockfile_and_deps(
                mut self,
                packages: Vec<Package>,
                deps: HashMap<String, Vec<String>>,
            ) -> Self {
                self.packages = packages;
                self.deps = deps;
                self
            }

            pub(crate) fn with_group_roots(mut self, roots: GroupRoots) -> Self {
                self.group_roots = roots;
                self
            }

            pub(crate) fn with_project_name(mut self, name: impl Into<String>) -> Self {
                self.project_name = name.into();
                self
            }

            pub(crate) fn with_vuln_repo(mut self) -> Self {
                self.vuln = Some(MockVulnerabilityRepository::new());
                self
            }

            pub(crate) fn with_maintenance_repo(mut self, repo: MockMaintenanceRepository) -> Self {
                self.maint = Some(repo);
                self
            }

            pub(crate) fn with_python_compat_repo(
                mut self,
                repo: MockPythonCompatibilityRepository,
            ) -> Self {
                self.pyc = Some(repo);
                self
            }

            pub(crate) fn with_simulator(mut self, sim: MockUvLockSimulator) -> Self {
                self.sim = Some(sim);
                self
            }

            pub(crate) fn with_source_map(mut self, map: PackageSourceMap) -> Self {
                self.source_map = map;
                self
            }

            pub(crate) fn build(self) -> TestUseCase {
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

        pub(crate) fn default_request() -> SbomRequest {
            SbomRequest::builder()
                .project_path("/test/project")
                .build()
                .unwrap()
        }

        pub(crate) fn pkg(name: &str, version: &str) -> Package {
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
        async fn test_execute_with_explain_package_populates_response_view() {
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
                .explain_package(Some("urllib3".to_string()))
                .build()
                .unwrap();

            let response = use_case.execute(request).await.unwrap();

            let view = response.explain_view.expect("explain_package set → Some");
            assert!(view.found);
            assert!(!view.is_direct);
            assert_eq!(
                view.paths,
                vec![vec!["requests".to_string(), "urllib3".to_string()]]
            );
        }

        #[tokio::test]
        async fn test_execute_without_explain_package_leaves_view_none() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("certifi", "2024.8.30")])
                .build();

            let response = use_case.execute(default_request()).await.unwrap();

            assert!(response.explain_view.is_none());
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
}
