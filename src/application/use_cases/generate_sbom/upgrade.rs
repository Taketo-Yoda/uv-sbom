use std::collections::HashMap;

use super::GenerateSbomUseCase;
use crate::application::dto::SbomRequest;
use crate::application::use_cases::SimulateUpgradesUseCase;
use crate::i18n::Messages;
use crate::ports::outbound::{
    ExploitabilityRepository, LicenseRepository, LockfileReader, MaintenanceRepository,
    ProgressReporter, ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
};
use crate::sbom_generation::domain::services::upgrade_advisor::map_constraint_outcome;
use crate::sbom_generation::domain::services::{ResolutionAnalyzer, UpgradeAdvisor};
use crate::sbom_generation::domain::upgrade_recommendation::{
    ConstraintOutcome, ConstraintSuggestion,
};
use crate::sbom_generation::domain::{
    DependencyGraph, EnrichedPackage, PackageVulnerabilities, UpgradeRecommendation,
    UvLockSimulator,
};

impl<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO, USIM, EREPO>
    GenerateSbomUseCase<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO, USIM, EREPO>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    LREPO: LicenseRepository + Clone,
    PR: ProgressReporter,
    VREPO: VulnerabilityRepository + Clone,
    MREPO: MaintenanceRepository + Clone,
    PCREPO: PythonCompatibilityRepository + Clone,
    USIM: UvLockSimulator,
    EREPO: ExploitabilityRepository,
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
                let recs = UpgradeAdvisor::advise(&entries, &simulation_outcomes);

                self.run_constraint_simulations(simulator, &request.project_path, recs)
                    .await
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
                    ..
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

    /// Runs constraint simulations for Unresolvable items and attaches the
    /// results in-place. Each unique (transitive_dep, fixed_version) pair is
    /// simulated at most once.
    async fn run_constraint_simulations(
        &self,
        simulator: &USIM,
        project_path: &std::path::Path,
        mut recommendations: Vec<UpgradeRecommendation>,
    ) -> Vec<UpgradeRecommendation> {
        let mut cache: HashMap<(String, String), ConstraintOutcome> = HashMap::new();

        // Collect unique pairs first to determine simulation work.
        let unique_pairs: Vec<(String, String)> = recommendations
            .iter()
            .filter_map(|rec| match rec {
                UpgradeRecommendation::Unresolvable {
                    transitive_dep_name,
                    fixed_version,
                    ..
                } => Some((transitive_dep_name.clone(), fixed_version.clone())),
                _ => None,
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Run simulations sequentially (one `uv lock` at a time).
        for (pkg, ver) in &unique_pairs {
            let outcome = match simulator
                .simulate_with_constraints(project_path, &[(pkg.as_str(), ver.as_str())])
                .await
            {
                Ok(sim_result) => map_constraint_outcome(&sim_result, pkg, ver),
                Err(e) => ConstraintOutcome::SimulationFailed {
                    error: e.to_string(),
                },
            };
            cache.insert((pkg.clone(), ver.clone()), outcome);
        }

        // Attach cached outcomes to Unresolvable items.
        for rec in &mut recommendations {
            if let UpgradeRecommendation::Unresolvable {
                transitive_dep_name,
                fixed_version,
                constraint_suggestion,
                ..
            } = rec
            {
                if let Some(outcome) =
                    cache.get(&(transitive_dep_name.clone(), fixed_version.clone()))
                {
                    *constraint_suggestion = Some(ConstraintSuggestion {
                        package_name: transitive_dep_name.clone(),
                        min_version: fixed_version.clone(),
                        outcome: outcome.clone(),
                    });
                }
            }
        }

        recommendations
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
                vec![],
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

        #[tokio::test]
        async fn test_unresolvable_gets_verified_constraint_suggestion() {
            let simulator = MockUvLockSimulator::with_result(
                "app-dep",
                SimulationResult {
                    upgraded_to_version: "3.0.0".to_string(),
                    resolved_versions: HashMap::from([(
                        "vuln-lib".to_string(),
                        "1.5.0".to_string(),
                    )]),
                },
            )
            .with_constraint_result(
                &[("vuln-lib", "2.0.0")],
                Ok(SimulationResult {
                    upgraded_to_version: String::new(),
                    resolved_versions: HashMap::from([(
                        "vuln-lib".to_string(),
                        "2.1.0".to_string(),
                    )]),
                }),
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

            let recs = result.expect("suggest_fix enabled → Some");
            assert_eq!(recs.len(), 1);
            match &recs[0] {
                UpgradeRecommendation::Unresolvable {
                    constraint_suggestion: Some(cs),
                    ..
                } => {
                    assert_eq!(cs.package_name, "vuln-lib");
                    assert_eq!(cs.min_version, "2.0.0");
                    assert!(matches!(
                        cs.outcome,
                        ConstraintOutcome::Verified {
                            resolved_version: ref v
                        } if v == "2.1.0"
                    ));
                }
                other => panic!(
                    "expected Unresolvable with constraint_suggestion, got {:?}",
                    other
                ),
            }
        }

        #[tokio::test]
        async fn test_unresolvable_gets_simulation_failed_constraint_suggestion() {
            let simulator = MockUvLockSimulator::with_result(
                "app-dep",
                SimulationResult {
                    upgraded_to_version: "3.0.0".to_string(),
                    resolved_versions: HashMap::from([(
                        "vuln-lib".to_string(),
                        "1.5.0".to_string(),
                    )]),
                },
            )
            .with_constraint_result(
                &[("vuln-lib", "2.0.0")],
                Err("uv lock timed out".to_string()),
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

            let recs = result.expect("suggest_fix enabled → Some");
            assert_eq!(recs.len(), 1);
            match &recs[0] {
                UpgradeRecommendation::Unresolvable {
                    constraint_suggestion: Some(cs),
                    ..
                } => {
                    assert!(matches!(
                        cs.outcome,
                        ConstraintOutcome::SimulationFailed { .. }
                    ));
                }
                other => panic!(
                    "expected Unresolvable with SimulationFailed, got {:?}",
                    other
                ),
            }
        }

        #[tokio::test]
        async fn test_constraint_simulation_deduplicates_by_package_version() {
            use crate::sbom_generation::domain::vulnerability::{
                CvssScore, Severity, Vulnerability,
            };
            use crate::sbom_generation::domain::{
                DependencyGraph, PackageName, PackageVulnerabilities,
            };

            let direct = vec![
                PackageName::new("dep-a".to_string()).unwrap(),
                PackageName::new("dep-b".to_string()).unwrap(),
            ];
            let transitive = HashMap::from([
                (
                    PackageName::new("dep-a".to_string()).unwrap(),
                    vec![PackageName::new("vuln-lib".to_string()).unwrap()],
                ),
                (
                    PackageName::new("dep-b".to_string()).unwrap(),
                    vec![PackageName::new("vuln-lib".to_string()).unwrap()],
                ),
            ]);
            let graph = DependencyGraph::new(direct, transitive, HashMap::new());

            let vuln = Vulnerability::new(
                "CVE-2024-0001".to_string(),
                Some(CvssScore::new(7.5).unwrap()),
                Severity::High,
                Some("2.0.0".to_string()),
                None,
                vec![],
            )
            .unwrap();
            let vulns = vec![PackageVulnerabilities::new(
                "vuln-lib".to_string(),
                "1.0.0".to_string(),
                vec![vuln],
            )];
            let enriched = vec![
                EnrichedPackage::new(pkg("dep-a", "1.0.0"), Some("MIT".to_string()), None),
                EnrichedPackage::new(pkg("dep-b", "1.0.0"), Some("MIT".to_string()), None),
            ];

            let results = HashMap::from([
                (
                    "dep-a".to_string(),
                    SimulationResult {
                        upgraded_to_version: "2.0.0".to_string(),
                        resolved_versions: HashMap::from([(
                            "vuln-lib".to_string(),
                            "1.5.0".to_string(),
                        )]),
                    },
                ),
                (
                    "dep-b".to_string(),
                    SimulationResult {
                        upgraded_to_version: "2.0.0".to_string(),
                        resolved_versions: HashMap::from([(
                            "vuln-lib".to_string(),
                            "1.5.0".to_string(),
                        )]),
                    },
                ),
            ]);

            let simulator = MockUvLockSimulator::with_results_and_errors(results, HashMap::new())
                .with_constraint_result(
                    &[("vuln-lib", "2.0.0")],
                    Ok(SimulationResult {
                        upgraded_to_version: String::new(),
                        resolved_versions: HashMap::from([(
                            "vuln-lib".to_string(),
                            "2.1.0".to_string(),
                        )]),
                    }),
                );

            let use_case = UseCaseBuilder::default().with_simulator(simulator).build();
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .suggest_fix(true)
                .build()
                .unwrap();

            let result = use_case
                .advise_upgrades_if_requested(&request, Some(&graph), Some(&vulns), &enriched)
                .await;

            let recs = result.expect("suggest_fix enabled → Some");
            let unresolvable_with_suggestion: Vec<_> = recs
                .iter()
                .filter_map(|r| match r {
                    UpgradeRecommendation::Unresolvable {
                        constraint_suggestion: Some(cs),
                        ..
                    } => Some(cs),
                    _ => None,
                })
                .collect();
            // Both Unresolvable entries share the same (vuln-lib, 2.0.0) pair,
            // so both should get a constraint suggestion with the same outcome.
            assert_eq!(unresolvable_with_suggestion.len(), 2);
            for cs in &unresolvable_with_suggestion {
                assert_eq!(cs.package_name, "vuln-lib");
                assert_eq!(cs.min_version, "2.0.0");
                assert!(matches!(cs.outcome, ConstraintOutcome::Verified { .. }));
            }
        }
    }
}
