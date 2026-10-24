//! Evaluation of locked packages against one advisory: range match,
//! dependency position, release status, verdict, and next action. Shared by
//! the single-project and workspace entry points.

use super::{ProjectScope, RespondToIncidentUseCase};
use crate::application::read_models::incident_report::{IncidentFinding, IncidentGuidance};
use crate::i18n::Messages;
use crate::ports::outbound::{
    AdvisoryRepository, LockfileReader, PackageSourceKind, PackageSourceMap, ProjectConfigReader,
    ReleaseRepository,
};
use crate::sbom_generation::domain::advisory::{Advisory, IncidentVerdict, ReleaseStatus};
use crate::sbom_generation::domain::services::advisory_range_matcher::AdvisoryRangeMatcher;
use crate::sbom_generation::domain::{
    DependencyGraph, Package, PackageName, TargetedSimulationOutcome, UvLockSimulator,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

/// Outcome of one version-targeted dry-run resolution; an `Err` carries the
/// simulator's error message.
type SimulationAttempt = std::result::Result<TargetedSimulationOutcome, String>;

/// Cache key: `(package name, fixed version)`.
type FixKey = (String, String);

/// The suggested command and guidance for one finding.
struct NextAction {
    upgrade_command: Option<String>,
    command_verified: bool,
    guidance: Option<IncidentGuidance>,
}

impl NextAction {
    /// No command and no guidance (the package is not affected).
    fn none() -> Self {
        Self::guidance(None)
    }

    /// Guidance only, with no command.
    fn guidance(guidance: Option<IncidentGuidance>) -> Self {
        Self {
            upgrade_command: None,
            command_verified: false,
            guidance,
        }
    }
}

/// Result of looking up the release status of a fixed version.
#[derive(Debug, Clone)]
enum ReleaseLookup {
    /// The package is not sourced from PyPI; no lookup was made.
    NotFromPyPi,
    /// The lookup succeeded.
    Found(ReleaseStatus),
    /// The lookup failed with this (English) error message.
    Failed(String),
}

impl ReleaseLookup {
    fn status(&self) -> Option<ReleaseStatus> {
        match self {
            Self::Found(status) => Some(*status),
            Self::NotFromPyPi | Self::Failed(_) => None,
        }
    }
}

/// Lookup caches keyed by `(package, fixed version)`: one per `execute`, and
/// one shared by every member in `execute_workspace`.
#[derive(Default)]
pub(super) struct EvaluationCaches {
    release: HashMap<FixKey, ReleaseLookup>,
    simulation: HashMap<FixKey, SimulationAttempt>,
}

impl<LR, PCR, AR, RR, USIM> RespondToIncidentUseCase<LR, PCR, AR, RR, USIM>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    AR: AdvisoryRepository,
    RR: ReleaseRepository,
    USIM: UvLockSimulator,
{
    /// Evaluates every in-scope package the advisory names (one finding per
    /// locked `(package, version)`), sorts the findings, and derives the
    /// overall verdict. Dry-run resolutions run in `simulation_root`.
    pub(super) async fn evaluate_scope(
        &self,
        scope: &ProjectScope,
        sources: &PackageSourceMap,
        advisory: &Advisory,
        simulation_root: &Path,
        caches: &mut EvaluationCaches,
        msgs: &Messages,
    ) -> (Vec<IncidentFinding>, IncidentVerdict) {
        let mut seen: HashSet<(String, String)> = HashSet::new();
        let mut findings: Vec<IncidentFinding> = Vec::new();
        let mut verdicts: Vec<IncidentVerdict> = Vec::new();
        for package in candidates(&scope.packages, advisory, sources) {
            if !seen.insert((package.name().to_string(), package.version().to_string())) {
                continue;
            }
            let (finding, verdict) = self
                .evaluate_package(
                    package,
                    advisory,
                    &scope.graph,
                    sources,
                    simulation_root,
                    caches,
                    msgs,
                )
                .await;
            findings.push(finding);
            verdicts.push(verdict);
        }

        findings.sort_by(|a, b| {
            (&a.package_name, &a.locked_version).cmp(&(&b.package_name, &b.locked_version))
        });
        (findings, AdvisoryRangeMatcher::overall(&verdicts))
    }

    /// Evaluates one locked package against `advisory`: range match, dependency
    /// position, release status of the fixed version, verdict, and next action.
    #[allow(clippy::too_many_arguments)]
    async fn evaluate_package(
        &self,
        package: &Package,
        advisory: &Advisory,
        graph: &DependencyGraph,
        sources: &PackageSourceMap,
        simulation_root: &Path,
        caches: &mut EvaluationCaches,
        msgs: &Messages,
    ) -> (IncidentFinding, IncidentVerdict) {
        let name = package.name();
        let locked_version = package.version();

        let matched = AdvisoryRangeMatcher::match_package(advisory, name, locked_version);
        let fixed_version = matched.as_ref().and_then(|m| m.fixed_version.clone());
        let (is_direct, paths) = dependency_position(graph, name);

        let lookup = match fixed_version.as_deref() {
            Some(fixed) => Some(
                self.cached_release_lookup(&mut caches.release, sources, name, fixed, msgs)
                    .await,
            ),
            None => None,
        };
        let release_status = lookup.as_ref().and_then(ReleaseLookup::status);
        let verdict = AdvisoryRangeMatcher::verdict(matched.as_ref(), release_status);

        let action = match (verdict, fixed_version.as_deref()) {
            (IncidentVerdict::NotAffected, _) => NextAction::none(),
            (IncidentVerdict::AffectedFixReleased, Some(fixed)) => {
                let outcome = self
                    .cached_simulation(&mut caches.simulation, simulation_root, name, fixed)
                    .await;
                next_action(name, fixed, outcome, is_direct, &paths)
            }
            _ => NextAction::guidance(Some(unreleased_guidance(lookup.as_ref()))),
        };

        let finding = IncidentFinding {
            package_name: name.to_string(),
            locked_version: locked_version.to_string(),
            is_direct,
            paths,
            fixed_version,
            release_status: release_status.map(Into::into),
            verdict: verdict.into(),
            upgrade_command: action.upgrade_command,
            command_verified: action.command_verified,
            guidance: action.guidance,
        };
        (finding, verdict)
    }

    /// Returns the release status lookup of `fixed` for `name`, querying PyPI
    /// at most once per `(name, fixed)`. Non-PyPI packages are never looked
    /// up. A failed lookup is soft-failed: a localized warning is printed once
    /// and the failure reason is cached so every finding of the package gets
    /// the same guidance.
    async fn cached_release_lookup(
        &self,
        cache: &mut HashMap<FixKey, ReleaseLookup>,
        sources: &PackageSourceMap,
        name: &str,
        fixed: &str,
        msgs: &Messages,
    ) -> ReleaseLookup {
        if !is_pypi_sourced(sources, name) {
            return ReleaseLookup::NotFromPyPi;
        }
        let key = (name.to_string(), fixed.to_string());
        if let Some(lookup) = cache.get(&key) {
            return lookup.clone();
        }
        let lookup = match self.release_repository.release_status(name, fixed).await {
            Ok(status) => ReleaseLookup::Found(status),
            Err(e) => {
                let reason = e.to_string();
                eprintln!(
                    "{}",
                    Messages::format(
                        msgs.warn_incident_release_lookup_failed,
                        &[name, fixed, &reason]
                    )
                );
                ReleaseLookup::Failed(reason)
            }
        };
        cache.insert(key, lookup.clone());
        lookup
    }

    /// Runs the version-targeted dry-run resolution at most once per
    /// `(name, fixed)`. An `Err` from the simulator is kept as its message.
    async fn cached_simulation(
        &self,
        cache: &mut HashMap<FixKey, SimulationAttempt>,
        project_path: &Path,
        name: &str,
        fixed: &str,
    ) -> SimulationAttempt {
        let key = (name.to_string(), fixed.to_string());
        if let Some(outcome) = cache.get(&key) {
            return outcome.clone();
        }
        let outcome = self
            .simulator
            .simulate_upgrade_to(name, fixed, project_path)
            .await
            .map_err(|e| e.to_string());
        cache.insert(key, outcome.clone());
        outcome
    }
}

/// Guidance for an affected finding without a released fix. Distinguishes a
/// package not sourced from PyPI and a failed lookup from a fix that is
/// genuinely unreleased (not found, yanked) or absent.
fn unreleased_guidance(lookup: Option<&ReleaseLookup>) -> IncidentGuidance {
    match lookup {
        Some(ReleaseLookup::NotFromPyPi) => IncidentGuidance::NotFromPyPi,
        Some(ReleaseLookup::Failed(reason)) => IncidentGuidance::ReleaseLookupFailed {
            reason: reason.clone(),
        },
        Some(ReleaseLookup::Found(_)) | None => IncidentGuidance::NoReleasedFix,
    }
}

/// In-scope packages the advisory names, excluding workspace members and
/// local-path packages (they are the project's own code, not PyPI releases).
fn candidates<'a>(
    scoped: &'a [Package],
    advisory: &'a Advisory,
    sources: &'a PackageSourceMap,
) -> impl Iterator<Item = &'a Package> + 'a {
    scoped.iter().filter(move |package| {
        AdvisoryRangeMatcher::names_package(advisory, package.name())
            && !matches!(
                sources.get(package.name()),
                Some(PackageSourceKind::WorkspaceMember | PackageSourceKind::LocalPath(_))
            )
    })
}

/// A package with no source entry is treated as coming from PyPI.
fn is_pypi_sourced(sources: &PackageSourceMap, name: &str) -> bool {
    matches!(sources.get(name), None | Some(PackageSourceKind::PyPi))
}

/// Direct/transitive classification and every path from a direct dependency
/// to `name`, reusing `DependencyGraph::find_paths_to` exactly as `--explain`
/// does (#768). An invalid name yields `(false, [])`.
fn dependency_position(graph: &DependencyGraph, name: &str) -> (bool, Vec<Vec<String>>) {
    let Ok(package_name) = PackageName::new(name.to_string()) else {
        return (false, Vec::new());
    };
    let is_direct = graph.direct_dependencies().contains(&package_name);
    let paths = graph
        .find_paths_to(&package_name)
        .into_iter()
        .map(|path| path.iter().map(|p| p.as_str().to_string()).collect())
        .collect();
    (is_direct, paths)
}

/// Maps a simulation outcome to the finding's command and guidance. The
/// command always targets the vulnerable package itself, even when transitive.
fn next_action(
    name: &str,
    fixed: &str,
    outcome: SimulationAttempt,
    is_direct: bool,
    paths: &[Vec<String>],
) -> NextAction {
    let command = |verified: bool| NextAction {
        upgrade_command: Some(format!("uv lock --upgrade-package {}=={}", name, fixed)),
        command_verified: verified,
        guidance: None,
    };
    match outcome {
        Ok(TargetedSimulationOutcome::Resolved { .. }) => command(true),
        Ok(TargetedSimulationOutcome::SimulatorUnavailable) => command(false),
        Ok(TargetedSimulationOutcome::ResolutionFailed { .. }) => {
            NextAction::guidance(Some(IncidentGuidance::ResolutionBlocked {
                direct_roots: direct_roots(name, is_direct, paths),
            }))
        }
        Err(reason) => NextAction::guidance(Some(IncidentGuidance::SimulationError { reason })),
    }
}

/// The direct dependencies at the root of each path (plus the package itself
/// when it is direct), sorted and deduplicated. Falls back to the package
/// itself when no root is known.
fn direct_roots(name: &str, is_direct: bool, paths: &[Vec<String>]) -> Vec<String> {
    let mut roots: BTreeSet<String> = paths.iter().filter_map(|p| p.first().cloned()).collect();
    if is_direct || roots.is_empty() {
        roots.insert(name.to_string());
    }
    roots.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::incident_report::IncidentVerdictView;
    use crate::application::use_cases::respond_to_incident::tests::*;
    use crate::application::use_cases::test_doubles::MockUvLockSimulator;

    #[tokio::test]
    async fn test_fix_unreleased_not_found_and_yanked() {
        for status in [ReleaseStatus::NotFound, ReleaseStatus::Yanked] {
            let uc = use_case(
                direct_requests_lock(),
                ghsa_repo("requests"),
                MockReleaseRepository::default().with("requests", "2.31.0", Ok(status)),
                MockUvLockSimulator::default(),
            );

            let report = uc.execute(request(GHSA)).await.unwrap();

            let finding = &report.findings[0];
            assert_eq!(finding.verdict, IncidentVerdictView::AffectedFixUnreleased);
            assert_eq!(finding.release_status, Some(status.into()));
            assert_eq!(finding.upgrade_command, None);
            assert_eq!(finding.guidance, Some(IncidentGuidance::NoReleasedFix));
            assert!(uc.simulator.targeted_call_log().is_empty());
        }
    }

    #[tokio::test]
    async fn test_release_lookup_error_is_soft_failed_as_unreleased() {
        let uc = use_case(
            direct_requests_lock(),
            ghsa_repo("requests"),
            MockReleaseRepository::default().with("requests", "2.31.0", Err("timeout".into())),
            MockUvLockSimulator::default(),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        let finding = &report.findings[0];
        assert_eq!(finding.release_status, None);
        assert_eq!(finding.verdict, IncidentVerdictView::AffectedFixUnreleased);
        assert_eq!(finding.upgrade_command, None);
        assert_eq!(
            finding.guidance,
            Some(IncidentGuidance::ReleaseLookupFailed {
                reason: "timeout".to_string()
            })
        );
        assert!(uc.simulator.targeted_call_log().is_empty());
    }

    #[tokio::test]
    async fn test_release_lookup_failure_is_cached_for_every_finding() {
        let lock = lock(
            vec![pkg("requests", "2.25.0"), pkg("requests", "2.20.0")],
            &[(PROJECT, &["requests"])],
        );
        let uc = use_case(
            lock,
            ghsa_repo("requests"),
            MockReleaseRepository::default().with("requests", "2.31.0", Err("timeout".into())),
            MockUvLockSimulator::default(),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        assert_eq!(report.findings.len(), 2);
        for finding in &report.findings {
            assert_eq!(
                finding.guidance,
                Some(IncidentGuidance::ReleaseLookupFailed {
                    reason: "timeout".to_string()
                })
            );
        }
        assert_eq!(uc.release_repository.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_no_fix_skips_release_lookup_and_simulation() {
        let advisories = MockAdvisoryRepository::default().with(
            GHSA,
            Ok(Some(advisory(GHSA, &[], vec![affected("requests", None)]))),
        );
        let uc = use_case(
            direct_requests_lock(),
            advisories,
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        let finding = &report.findings[0];
        assert_eq!(finding.verdict, IncidentVerdictView::AffectedNoFix);
        assert_eq!(finding.fixed_version, None);
        assert_eq!(finding.guidance, Some(IncidentGuidance::NoReleasedFix));
        assert!(uc.release_repository.calls.lock().unwrap().is_empty());
        assert!(uc.simulator.targeted_call_log().is_empty());
        assert_eq!(report.overall, IncidentVerdictView::AffectedNoFix);
    }

    #[tokio::test]
    async fn test_resolution_failure_names_blocking_direct_dependency() {
        let lock = lock(
            vec![pkg("flask", "3.0.0"), pkg("requests", "2.25.0")],
            &[(PROJECT, &["flask"]), ("flask", &["requests"])],
        );
        let uc = use_case(
            lock,
            ghsa_repo("requests"),
            released("requests"),
            MockUvLockSimulator::default().with_targeted(
                "requests",
                Ok(TargetedSimulationOutcome::ResolutionFailed {
                    reason: "conflict".to_string(),
                }),
            ),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        let finding = &report.findings[0];
        assert_eq!(finding.verdict, IncidentVerdictView::AffectedFixReleased);
        assert_eq!(finding.upgrade_command, None);
        assert!(!finding.command_verified);
        assert_eq!(
            finding.guidance,
            Some(IncidentGuidance::ResolutionBlocked {
                direct_roots: vec!["flask".to_string()]
            })
        );
    }

    #[tokio::test]
    async fn test_simulator_unavailable_yields_unverified_command() {
        let uc = use_case(
            direct_requests_lock(),
            ghsa_repo("requests"),
            released("requests"),
            MockUvLockSimulator::default().with_targeted(
                "requests",
                Ok(TargetedSimulationOutcome::SimulatorUnavailable),
            ),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        let finding = &report.findings[0];
        assert_eq!(
            finding.upgrade_command.as_deref(),
            Some("uv lock --upgrade-package requests==2.31.0")
        );
        assert!(!finding.command_verified);
        assert_eq!(finding.guidance, None);
    }

    #[tokio::test]
    async fn test_simulator_error_is_soft_failed() {
        let uc = use_case(
            direct_requests_lock(),
            ghsa_repo("requests"),
            released("requests"),
            MockUvLockSimulator::default().with_targeted("requests", Err("uv timed out".into())),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        let finding = &report.findings[0];
        assert_eq!(finding.upgrade_command, None);
        assert!(!finding.command_verified);
        assert_eq!(
            finding.guidance,
            Some(IncidentGuidance::SimulationError {
                reason: "uv timed out".to_string()
            })
        );
    }

    #[tokio::test]
    async fn test_present_but_outside_range_is_not_affected_finding() {
        let lock = lock(vec![pkg("requests", "2.31.0")], &[(PROJECT, &["requests"])]);
        let uc = use_case(
            lock,
            ghsa_repo("requests"),
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        let finding = &report.findings[0];
        assert_eq!(finding.locked_version, "2.31.0");
        assert_eq!(finding.verdict, IncidentVerdictView::NotAffected);
        assert_eq!(finding.fixed_version, None);
        assert_eq!(finding.guidance, None);
        assert_eq!(report.overall, IncidentVerdictView::NotAffected);
        assert!(uc.release_repository.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_two_locked_versions_share_one_release_lookup() {
        let lock = lock(
            vec![pkg("requests", "2.25.0"), pkg("requests", "2.20.0")],
            &[(PROJECT, &["requests"])],
        );
        let uc = use_case(
            lock,
            ghsa_repo("requests"),
            released("requests"),
            MockUvLockSimulator::default().with_targeted("requests", resolved()),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].locked_version, "2.20.0");
        assert_eq!(report.findings[1].locked_version, "2.25.0");
        assert_eq!(uc.release_repository.calls.lock().unwrap().len(), 1);
        assert_eq!(uc.simulator.targeted_call_log().len(), 1);
    }

    #[tokio::test]
    async fn test_non_pypi_source_skips_release_lookup() {
        let mut lock = direct_requests_lock();
        lock.source_map.insert(
            "requests".to_string(),
            PackageSourceKind::Git("https://github.com/psf/requests".to_string()),
        );
        let uc = use_case(
            lock,
            ghsa_repo("requests"),
            released("requests"),
            MockUvLockSimulator::default(),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        let finding = &report.findings[0];
        assert_eq!(finding.release_status, None);
        assert_eq!(finding.verdict, IncidentVerdictView::AffectedFixUnreleased);
        assert_eq!(finding.upgrade_command, None);
        assert_eq!(finding.guidance, Some(IncidentGuidance::NotFromPyPi));
        assert!(uc.release_repository.calls.lock().unwrap().is_empty());
        assert!(uc.simulator.targeted_call_log().is_empty());
    }

    #[tokio::test]
    async fn test_workspace_member_is_never_a_candidate() {
        let uc = use_case(
            direct_requests_lock(),
            MockAdvisoryRepository::default().with(
                GHSA,
                Ok(Some(advisory(GHSA, &[], vec![affected(PROJECT, None)]))),
            ),
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        assert!(report.findings.is_empty());
        assert_eq!(report.overall, IncidentVerdictView::NotAffected);
    }

    #[test]
    fn test_direct_roots_dedup_sorted_and_fallback() {
        let paths = vec![
            vec!["b".to_string(), "x".to_string()],
            vec!["a".to_string(), "y".to_string(), "x".to_string()],
            vec!["b".to_string(), "z".to_string(), "x".to_string()],
        ];
        assert_eq!(direct_roots("x", false, &paths), vec!["a", "b"]);
        assert_eq!(direct_roots("x", true, &paths), vec!["a", "b", "x"]);
        assert_eq!(direct_roots("x", false, &[]), vec!["x"]);
    }
}
