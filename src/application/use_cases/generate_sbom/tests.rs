use super::*;
use crate::application::use_cases::test_doubles::{
    MockPythonCompatibilityRepository, MockUvLockSimulator,
};
use crate::ports::outbound::PackageSourceMap;
use crate::sbom_generation::domain::services::{ThresholdConfig, VulnerabilityCheckResult};
use crate::sbom_generation::domain::{EnrichedPackage, SimulationResult, UpgradeRecommendation};
use std::collections::HashMap;

mod tests_response {
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;

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
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;

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
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;
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
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;
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
mod tests_non_pypi {
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;
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
    use super::*;
    use crate::adapters::outbound::formatters::MarkdownFormatter;
    use crate::application::read_models::SbomReadModelBuilder;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;
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
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;
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
