use super::*;
use crate::application::use_cases::test_doubles::{
    MockMaintenanceRepository, MockVulnerabilityRepository,
};
use crate::ports::outbound::{LockfileParseResult, PyPiMetadata};
use crate::sbom_generation::domain::Package;
use std::collections::HashMap;
use std::path::Path;

struct MockLockfileReader {
    packages: Vec<Package>,
    deps: HashMap<String, Vec<String>>,
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
    >;

    pub(super) struct UseCaseBuilder {
        packages: Vec<Package>,
        deps: HashMap<String, Vec<String>>,
        project_name: String,
        vuln: Option<MockVulnerabilityRepository>,
        maint: Option<MockMaintenanceRepository>,
    }

    impl Default for UseCaseBuilder {
        fn default() -> Self {
            Self {
                packages: Vec::new(),
                deps: HashMap::new(),
                project_name: "test-project".to_string(),
                vuln: None,
                maint: None,
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

        pub(super) fn build(self) -> TestUseCase {
            GenerateSbomUseCase::new(
                MockLockfileReader {
                    packages: self.packages,
                    deps: self.deps,
                },
                MockProjectConfigReader {
                    project_name: self.project_name,
                },
                MockLicenseRepository,
                MockProgressReporter,
                self.vuln,
                self.maint,
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

        let response = use_case.build_response(enriched_packages, None, None, None, None, None);

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
