use super::*;
use crate::application::use_cases::test_doubles::{
    MockPythonCompatibilityRepository, MockUvLockSimulator,
};
use crate::sbom_generation::domain::{EnrichedPackage, SimulationResult, UpgradeRecommendation};
use std::collections::HashMap;

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
