use super::GenerateSbomUseCase;
use crate::application::dto::SbomRequest;
use crate::application::use_cases::SimulateUpgradesUseCase;
use crate::i18n::Messages;
use crate::ports::outbound::{
    LicenseRepository, LockfileReader, MaintenanceRepository, ProgressReporter,
    ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
};
use crate::sbom_generation::domain::services::{ResolutionAnalyzer, UpgradeAdvisor};
use crate::sbom_generation::domain::{
    DependencyGraph, EnrichedPackage, PackageVulnerabilities, UpgradeRecommendation,
    UvLockSimulator,
};

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
    /// Runs the UpgradeAdvisor when `suggest_fix` is true and the required context is available
    ///
    /// Returns `None` when `suggest_fix` is false (no overhead).
    /// Returns `Some(vec)` when the advisor runs, even if the vector is empty.
    pub(super) async fn advise_upgrades_if_requested(
        &self,
        request: &SbomRequest,
        dependency_graph: Option<&DependencyGraph>,
        vulnerability_report: Option<&[PackageVulnerabilities]>,
        enriched_packages: &[EnrichedPackage],
    ) -> Option<Vec<UpgradeRecommendation>> {
        if !request.suggest_fix {
            return None;
        }

        let (Some(graph), Some(vuln_report)) = (dependency_graph, vulnerability_report) else {
            return Some(vec![]);
        };

        let entries = ResolutionAnalyzer::analyze(graph, vuln_report, enriched_packages);
        if entries.is_empty() {
            return Some(vec![]);
        }

        let msgs = Messages::for_locale(self.locale);

        let unique_dep_count = entries
            .iter()
            .flat_map(|e| e.introduced_by())
            .map(|i| i.package_name())
            .collect::<std::collections::HashSet<_>>()
            .len();
        let unit = if unique_dep_count == 1 {
            msgs.label_dependency_singular
        } else {
            msgs.label_dependency_plural
        };
        self.progress_reporter.report(&Messages::format(
            msgs.progress_analyzing_upgrade_paths,
            &[&unique_dep_count.to_string(), unit],
        ));

        // `None` is unreachable in production (the CLI composition root always
        // injects a real simulator); it exists only for tests that deliberately
        // omit one.
        let recommendations = match self.uv_lock_simulator.as_ref() {
            Some(simulator) => {
                let simulation_outcomes = SimulateUpgradesUseCase::new(simulator)
                    .run(&entries, &request.project_path)
                    .await;
                UpgradeAdvisor::advise(&entries, &simulation_outcomes)
            }
            None => Vec::new(),
        };

        for rec in &recommendations {
            match rec {
                UpgradeRecommendation::Upgradable {
                    direct_dep_name,
                    direct_dep_target_version,
                    transitive_dep_name,
                    transitive_resolved_version,
                    vulnerability_id,
                    ..
                } => {
                    self.progress_reporter.report(&Messages::format(
                        msgs.progress_upgrade_resolves,
                        &[
                            direct_dep_name,
                            direct_dep_target_version,
                            transitive_dep_name,
                            transitive_resolved_version,
                            vulnerability_id,
                        ],
                    ));
                }
                UpgradeRecommendation::Unresolvable {
                    direct_dep_name,
                    reason,
                    vulnerability_id,
                } => {
                    self.progress_reporter.report(&Messages::format(
                        msgs.progress_upgrade_unresolvable,
                        &[direct_dep_name, reason, vulnerability_id],
                    ));
                }
                UpgradeRecommendation::SimulationFailed {
                    direct_dep_name,
                    error,
                } => {
                    self.progress_reporter.report(&Messages::format(
                        msgs.progress_upgrade_simulation_failed,
                        &[direct_dep_name, error],
                    ));
                }
            }
        }

        Some(recommendations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;
    use crate::application::use_cases::test_doubles::MockUvLockSimulator;
    use crate::sbom_generation::domain::SimulationResult;
    use std::collections::HashMap;

    mod tests_upgrade_advisor {
        use super::*;
        use crate::sbom_generation::domain::vulnerability::{CvssScore, Severity, Vulnerability};
        use crate::sbom_generation::domain::{
            DependencyGraph, PackageName, PackageVulnerabilities,
        };

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
                    resolved_versions: HashMap::from([(
                        "vuln-lib".to_string(),
                        "2.0.0".to_string(),
                    )]),
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
}
