use crate::application::dto::IncidentRequest;
use crate::application::read_models::incident_report::{
    IncidentFinding, IncidentGuidance, IncidentReport, IncidentVerdictView,
};
use crate::application::read_models::vulnerability_view::SeverityView;
use crate::application::use_cases::project_scope;
use crate::i18n::{Locale, Messages};
use crate::ports::outbound::{
    AdvisoryRepository, LockfileReader, PackageSourceKind, PackageSourceMap, ProjectConfigReader,
    ReleaseRepository,
};
use crate::sbom_generation::domain::advisory::{Advisory, IncidentVerdict, ReleaseStatus};
use crate::sbom_generation::domain::services::advisory_range_matcher::{
    normalize_name, AdvisoryRangeMatcher,
};
use crate::sbom_generation::domain::{
    DependencyGraph, Package, PackageName, TargetedSimulationOutcome, UvLockSimulator,
};
use crate::sbom_generation::services::DependencyAnalyzer;
use crate::shared::Result;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

/// Alias prefixes tried, in order, when the requested advisory record lists no
/// PyPI package. GHSA and PYSEC records describe the same advisory, so the
/// first one with a PyPI entry is used and they are never merged.
const ALIAS_PREFIXES: [&str; 2] = ["GHSA-", "PYSEC-"];

/// Typed errors returned by `RespondToIncidentUseCase`.
///
/// The English `Display` text is the library contract; the CLI (#968) maps
/// each variant to a localized message and an exit code.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IncidentError {
    /// The OSV database has no record for the requested advisory ID.
    #[error("advisory {advisory_id} was not found in the OSV database")]
    AdvisoryNotFound {
        /// The advisory ID as supplied by the user.
        advisory_id: String,
    },
}

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

/// The in-scope packages of the project and what is needed to evaluate them.
struct ProjectScope {
    /// Packages left after the `--exclude` / `--exclude-groups` filters.
    packages: Vec<Package>,
    /// Graph used for paths and direct/transitive classification.
    graph: DependencyGraph,
    /// Source of every locked package (release status is only looked up on PyPI).
    sources: PackageSourceMap,
}

/// The advisory record used for evaluation, plus report metadata.
struct ResolvedAdvisory {
    /// The record actually used (an alias when one was followed).
    advisory: Advisory,
    /// The user-supplied ID when an alias was followed.
    resolved_from: Option<String>,
    severity: Option<SeverityView>,
    summary: Option<String>,
    /// Affected package names, deduplicated by PEP 503 name (first spelling kept).
    affected_packages: Vec<String>,
}

/// Per-`execute` lookup caches, keyed by `(package, fixed version)`.
#[derive(Default)]
struct EvaluationCaches {
    release: HashMap<FixKey, ReleaseLookup>,
    simulation: HashMap<FixKey, SimulationAttempt>,
}

/// Orchestrates `--incident <ADVISORY_ID>` mode: evaluates one advisory
/// against the project's `uv.lock` and builds an `IncidentReport` answering
/// (1) whether the project is affected and through which path, (2) whether the
/// fix is released, and (3) what to run next.
///
/// The scope filters `--exclude`, `--exclude-groups`, and `--production-only`
/// are honoured through `project_scope`, the same helpers
/// `GenerateSbomUseCase` uses. Vulnerability-report filters (`--ignore-cve`,
/// baseline, severity/CVSS thresholds) are not applied.
///
/// # Type Parameters
/// * `LR` - LockfileReader implementation
/// * `PCR` - ProjectConfigReader implementation (project name for the dependency graph)
/// * `AR` - AdvisoryRepository implementation (OSV)
/// * `RR` - ReleaseRepository implementation (PyPI)
/// * `USIM` - UvLockSimulator implementation; only borrowed, so no `Clone` bound (#704)
pub struct RespondToIncidentUseCase<LR, PCR, AR, RR, USIM>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    AR: AdvisoryRepository,
    RR: ReleaseRepository,
    USIM: UvLockSimulator,
{
    lockfile_reader: LR,
    project_config_reader: PCR,
    advisory_repository: AR,
    release_repository: RR,
    simulator: USIM,
    locale: Locale,
}

impl<LR, PCR, AR, RR, USIM> RespondToIncidentUseCase<LR, PCR, AR, RR, USIM>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    AR: AdvisoryRepository,
    RR: ReleaseRepository,
    USIM: UvLockSimulator,
{
    /// Creates a new `RespondToIncidentUseCase` with injected dependencies.
    pub fn new(
        lockfile_reader: LR,
        project_config_reader: PCR,
        advisory_repository: AR,
        release_repository: RR,
        simulator: USIM,
        locale: Locale,
    ) -> Self {
        Self {
            lockfile_reader,
            project_config_reader,
            advisory_repository,
            release_repository,
            simulator,
            locale,
        }
    }

    /// Builds the incident report for `request.advisory_id`.
    ///
    /// 1. Reads the lockfile and applies the scope filters (an empty scope is
    ///    not an error — it yields a not-affected report), builds the
    ///    dependency graph, and reads package sources.
    /// 2. Fetches the advisory, following GHSA, then PYSEC aliases when the
    ///    record lists no PyPI package.
    /// 3. Evaluates every in-scope package the advisory names. Release status
    ///    is looked up once per `(package, fixed version)`, and only for
    ///    packages sourced from PyPI; a non-PyPI package yields
    ///    `IncidentGuidance::NotFromPyPi`, and a failed lookup yields
    ///    `IncidentGuidance::ReleaseLookupFailed` plus a warning. For a
    ///    released fix, the upgrade is verified with a dry-run
    ///    `uv lock --upgrade-package <name>==<fixed>`; simulator errors are
    ///    soft-failed into `IncidentGuidance::SimulationError`.
    /// 4. Sorts the findings and derives the overall verdict.
    ///
    /// # Errors
    /// Returns `IncidentError::AdvisoryNotFound` (wrapped in `anyhow::Error`)
    /// when the requested ID has no OSV record. Also returns an error when the
    /// lockfile, group roots, package sources, or project name cannot be read,
    /// when an exclusion pattern is invalid, or when an advisory or alias
    /// lookup fails.
    pub async fn execute(&self, request: IncidentRequest) -> Result<IncidentReport> {
        let msgs = Messages::for_locale(self.locale);

        // 1. Scope, dependency graph, and package sources.
        let scope = self.load_scope(&request, msgs)?;

        // 2. Advisory (following aliases) and metadata.
        let resolved = self.resolve_advisory(&request).await?;

        // 3. One finding per in-scope locked (package, version).
        let mut caches = EvaluationCaches::default();
        let mut seen: HashSet<(String, String)> = HashSet::new();
        let mut findings: Vec<IncidentFinding> = Vec::new();
        let mut verdicts: Vec<IncidentVerdict> = Vec::new();
        for package in candidates(&scope.packages, &resolved.advisory, &scope.sources) {
            if !seen.insert((package.name().to_string(), package.version().to_string())) {
                continue;
            }
            let (finding, verdict) = self
                .evaluate_package(
                    package,
                    &resolved.advisory,
                    &scope,
                    &request,
                    &mut caches,
                    msgs,
                )
                .await;
            findings.push(finding);
            verdicts.push(verdict);
        }

        // 4. Ordering and overall verdict.
        findings.sort_by(|a, b| {
            (&a.package_name, &a.locked_version).cmp(&(&b.package_name, &b.locked_version))
        });
        let overall: IncidentVerdictView = AdvisoryRangeMatcher::overall(&verdicts).into();

        Ok(IncidentReport {
            advisory_id: resolved.advisory.id.clone(),
            resolved_from: resolved.resolved_from,
            aliases: resolved.advisory.aliases.clone(),
            severity: resolved.severity,
            summary: resolved.summary,
            affected_packages: resolved.affected_packages,
            findings,
            overall,
        })
    }

    /// Reads the lockfile, applies the scope filters, builds the dependency
    /// graph, and reads package sources, printing unmatched-pattern and
    /// truncated-chain warnings. The dependency map is never filtered (#206).
    fn load_scope(&self, request: &IncidentRequest, msgs: &Messages) -> Result<ProjectScope> {
        let project_path = request.project_path.as_path();

        let (packages, dependency_map) =
            self.lockfile_reader.read_and_parse_lockfile(project_path)?;
        let pattern_outcome =
            project_scope::filter_by_patterns(packages, &request.exclude_patterns)?;
        for pattern in &pattern_outcome.unmatched_patterns {
            eprintln!(
                "{}",
                Messages::format(msgs.warn_exclude_pattern_unmatched, &[pattern])
            );
        }
        let packages = project_scope::filter_by_groups(
            &self.lockfile_reader,
            project_path,
            pattern_outcome.packages,
            &dependency_map,
            &request.exclude_groups,
        )?;

        let project_name = project_scope::read_project_name_localized(
            &self.project_config_reader,
            project_path,
            msgs,
        )?;
        let (graph, truncated_chains) =
            DependencyAnalyzer::analyze(&PackageName::new(project_name)?, &dependency_map)?;
        for record in &truncated_chains {
            eprintln!(
                "{}",
                Messages::format(
                    msgs.warn_dependency_chain_truncated,
                    &[&record.max_depth.to_string(), &record.package_name],
                )
            );
        }

        let sources = self
            .lockfile_reader
            .read_and_parse_package_sources(project_path)?;

        Ok(ProjectScope {
            packages,
            graph,
            sources,
        })
    }

    /// Fetches the requested advisory, follows aliases when it lists no PyPI
    /// package, and collects the report metadata (severity and summary fall
    /// back to the requested record when the alias record lacks them).
    ///
    /// # Errors
    /// `IncidentError::AdvisoryNotFound` when the requested ID has no record;
    /// any advisory or alias lookup error.
    async fn resolve_advisory(&self, request: &IncidentRequest) -> Result<ResolvedAdvisory> {
        let primary = self
            .advisory_repository
            .fetch_advisory(&request.advisory_id)
            .await?
            .ok_or_else(|| IncidentError::AdvisoryNotFound {
                advisory_id: request.advisory_id.clone(),
            })?;
        let (advisory, resolved_from) = match self.follow_aliases(&primary).await? {
            Some(alias_record) => (alias_record, Some(request.advisory_id.clone())),
            None => (primary.clone(), None),
        };

        let severity = advisory
            .severity
            .or(primary.severity)
            .map(SeverityView::from);
        let summary = advisory.summary.clone().or_else(|| primary.summary.clone());
        let affected_packages = dedup_by_normalized_name(&advisory);

        Ok(ResolvedAdvisory {
            advisory,
            resolved_from,
            severity,
            summary,
            affected_packages,
        })
    }

    /// Evaluates one locked package against `advisory`: range match, dependency
    /// position, release status of the fixed version, verdict, and next action.
    async fn evaluate_package(
        &self,
        package: &Package,
        advisory: &Advisory,
        scope: &ProjectScope,
        request: &IncidentRequest,
        caches: &mut EvaluationCaches,
        msgs: &Messages,
    ) -> (IncidentFinding, IncidentVerdict) {
        let name = package.name();
        let locked_version = package.version();

        let matched = AdvisoryRangeMatcher::match_package(advisory, name, locked_version);
        let fixed_version = matched.as_ref().and_then(|m| m.fixed_version.clone());
        let (is_direct, paths) = dependency_position(&scope.graph, name);

        let lookup = match fixed_version.as_deref() {
            Some(fixed) => Some(
                self.cached_release_lookup(&mut caches.release, &scope.sources, name, fixed, msgs)
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
                    .cached_simulation(
                        &mut caches.simulation,
                        request.project_path.as_path(),
                        name,
                        fixed,
                    )
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

    /// When `primary` lists no PyPI package, tries its `GHSA-` aliases, then
    /// its `PYSEC-` aliases, in listed order, and returns the first record that
    /// lists one. Returns `None` when `primary` already lists a PyPI package or
    /// no alias does. Missing alias records are skipped.
    ///
    /// # Errors
    /// Propagates any alias lookup error.
    async fn follow_aliases(&self, primary: &Advisory) -> Result<Option<Advisory>> {
        if !primary.affected.is_empty() {
            return Ok(None);
        }
        for alias in alias_candidates(primary) {
            match self.advisory_repository.fetch_advisory(alias).await? {
                Some(record) if !record.affected.is_empty() => return Ok(Some(record)),
                _ => continue,
            }
        }
        Ok(None)
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

/// Affected package names of `advisory`, deduplicated by PEP 503-normalized
/// name, keeping the first-seen spelling in listed order.
fn dedup_by_normalized_name(advisory: &Advisory) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    advisory
        .affected
        .iter()
        .filter(|package| seen.insert(normalize_name(&package.name)))
        .map(|package| package.name.clone())
        .collect()
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

/// Aliases of `primary` worth following: every `GHSA-` alias in listed order,
/// then every `PYSEC-` alias, compared case-insensitively and skipping
/// `primary`'s own ID.
fn alias_candidates(primary: &Advisory) -> Vec<&str> {
    ALIAS_PREFIXES
        .iter()
        .flat_map(|prefix| {
            primary.aliases.iter().filter(move |alias| {
                alias
                    .get(..prefix.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
                    && !alias.eq_ignore_ascii_case(&primary.id)
            })
        })
        .map(String::as_str)
        .collect()
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
    use crate::application::read_models::incident_report::ReleaseStatusView;
    use crate::application::use_cases::test_doubles::{
        MockLockfileReader, MockProjectConfigReader, MockUvLockSimulator,
    };
    use crate::sbom_generation::domain::advisory::{AffectedPackage, AffectedRange};
    use crate::sbom_generation::domain::Severity;
    use async_trait::async_trait;
    use std::path::PathBuf;
    use std::sync::Mutex;

    // ---- local mocks ----

    /// Advisory lookups keyed by ID; an unconfigured ID is `Ok(None)`.
    #[derive(Default)]
    struct MockAdvisoryRepository {
        responses: HashMap<String, std::result::Result<Option<Advisory>, String>>,
        calls: Mutex<Vec<String>>,
    }

    impl MockAdvisoryRepository {
        fn with(
            mut self,
            id: &str,
            response: std::result::Result<Option<Advisory>, String>,
        ) -> Self {
            self.responses.insert(id.to_string(), response);
            self
        }
    }

    #[async_trait]
    impl AdvisoryRepository for MockAdvisoryRepository {
        async fn fetch_advisory(&self, advisory_id: &str) -> Result<Option<Advisory>> {
            self.calls.lock().unwrap().push(advisory_id.to_string());
            match self.responses.get(advisory_id) {
                Some(Ok(advisory)) => Ok(advisory.clone()),
                Some(Err(msg)) => Err(anyhow::anyhow!("{}", msg)),
                None => Ok(None),
            }
        }
    }

    /// Release lookups keyed by `(name, version)`; an unconfigured pair errors.
    #[derive(Default)]
    struct MockReleaseRepository {
        responses: HashMap<(String, String), std::result::Result<ReleaseStatus, String>>,
        calls: Mutex<Vec<(String, String)>>,
    }

    impl MockReleaseRepository {
        fn with(
            mut self,
            name: &str,
            version: &str,
            response: std::result::Result<ReleaseStatus, String>,
        ) -> Self {
            self.responses
                .insert((name.to_string(), version.to_string()), response);
            self
        }
    }

    #[async_trait]
    impl ReleaseRepository for MockReleaseRepository {
        async fn release_status(&self, package_name: &str, version: &str) -> Result<ReleaseStatus> {
            let key = (package_name.to_string(), version.to_string());
            self.calls.lock().unwrap().push(key.clone());
            match self.responses.get(&key) {
                Some(Ok(status)) => Ok(*status),
                Some(Err(msg)) => Err(anyhow::anyhow!("{}", msg)),
                None => Err(anyhow::anyhow!("not configured: {:?}", key)),
            }
        }
    }

    type TestUseCase = RespondToIncidentUseCase<
        MockLockfileReader,
        MockProjectConfigReader,
        MockAdvisoryRepository,
        MockReleaseRepository,
        MockUvLockSimulator,
    >;

    // ---- fixtures ----

    const PROJECT: &str = "myapp";
    const GHSA: &str = "GHSA-j8r2-6x86-q33q";
    const CVE: &str = "CVE-2023-32681";
    const PYSEC: &str = "PYSEC-2023-74";

    fn pkg(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
    }

    fn range(introduced: &str, fixed: Option<&str>) -> AffectedRange {
        AffectedRange {
            introduced: Some(introduced.to_string()),
            fixed: fixed.map(str::to_string),
            last_affected: None,
        }
    }

    fn advisory(id: &str, aliases: &[&str], affected: Vec<AffectedPackage>) -> Advisory {
        Advisory {
            id: id.to_string(),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            summary: Some("Leak of Proxy-Authorization header".to_string()),
            severity: Some(Severity::Medium),
            affected,
        }
    }

    fn affected(name: &str, fixed: Option<&str>) -> AffectedPackage {
        AffectedPackage {
            name: name.to_string(),
            ranges: vec![range("0", fixed)],
            versions: vec![],
        }
    }

    /// `name` affected below 2.31.0 (fixed in 2.31.0).
    fn ghsa_for(name: &str) -> Advisory {
        advisory(GHSA, &[CVE, PYSEC], vec![affected(name, Some("2.31.0"))])
    }

    /// Lockfile with `myapp` (workspace member) plus `packages`, and edges.
    fn lock(packages: Vec<Package>, edges: &[(&str, &[&str])]) -> MockLockfileReader {
        let mut all = vec![pkg(PROJECT, "0.1.0")];
        all.extend(packages);
        let mut deps: HashMap<String, Vec<String>> = HashMap::new();
        for package in &all {
            deps.entry(package.name().to_string()).or_default();
        }
        for (parent, children) in edges {
            deps.insert(
                parent.to_string(),
                children.iter().map(|c| c.to_string()).collect(),
            );
        }
        MockLockfileReader {
            packages: all,
            deps,
            group_roots: HashMap::new(),
            source_map: HashMap::from([(PROJECT.to_string(), PackageSourceKind::WorkspaceMember)]),
        }
    }

    fn direct_requests_lock() -> MockLockfileReader {
        lock(vec![pkg("requests", "2.25.0")], &[(PROJECT, &["requests"])])
    }

    fn use_case(
        lock: MockLockfileReader,
        advisories: MockAdvisoryRepository,
        releases: MockReleaseRepository,
        simulator: MockUvLockSimulator,
    ) -> TestUseCase {
        RespondToIncidentUseCase::new(
            lock,
            MockProjectConfigReader {
                project_name: PROJECT.to_string(),
                pyproject_missing: false,
            },
            advisories,
            releases,
            simulator,
            Locale::En,
        )
    }

    fn request(id: &str) -> IncidentRequest {
        IncidentRequest {
            advisory_id: id.to_string(),
            project_path: PathBuf::from("/test/project"),
            exclude_patterns: vec![],
            exclude_groups: vec![],
        }
    }

    fn resolved() -> std::result::Result<TargetedSimulationOutcome, String> {
        Ok(TargetedSimulationOutcome::Resolved {
            resolved_version: "2.31.0".to_string(),
        })
    }

    fn released(name: &str) -> MockReleaseRepository {
        MockReleaseRepository::default().with(name, "2.31.0", Ok(ReleaseStatus::Released))
    }

    fn ghsa_repo(name: &str) -> MockAdvisoryRepository {
        MockAdvisoryRepository::default().with(GHSA, Ok(Some(ghsa_for(name))))
    }

    // ---- tests ----

    #[tokio::test]
    async fn test_direct_hit_released_fix_verified_command() {
        let uc = use_case(
            direct_requests_lock(),
            ghsa_repo("requests"),
            released("requests"),
            MockUvLockSimulator::default().with_targeted("requests", resolved()),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        assert_eq!(report.advisory_id, GHSA);
        assert_eq!(report.resolved_from, None);
        assert_eq!(report.aliases, vec![CVE.to_string(), PYSEC.to_string()]);
        assert_eq!(report.severity, Some(SeverityView::Medium));
        assert_eq!(report.affected_packages, vec!["requests".to_string()]);
        assert_eq!(report.overall, IncidentVerdictView::AffectedFixReleased);
        assert_eq!(
            report.findings,
            vec![IncidentFinding {
                package_name: "requests".to_string(),
                locked_version: "2.25.0".to_string(),
                is_direct: true,
                paths: vec![],
                fixed_version: Some("2.31.0".to_string()),
                release_status: Some(ReleaseStatusView::Released),
                verdict: IncidentVerdictView::AffectedFixReleased,
                upgrade_command: Some("uv lock --upgrade-package requests==2.31.0".to_string()),
                command_verified: true,
                guidance: None,
            }]
        );
        assert_eq!(
            uc.simulator.targeted_call_log(),
            vec![("requests".to_string(), "2.31.0".to_string())]
        );
    }

    #[tokio::test]
    async fn test_transitive_multi_hop_paths_and_command_targets_package() {
        let lock = lock(
            vec![
                pkg("flask", "3.0.0"),
                pkg("werkzeug", "3.0.0"),
                pkg("x", "1.0.0"),
            ],
            &[
                (PROJECT, &["flask"]),
                ("flask", &["werkzeug"]),
                ("werkzeug", &["x"]),
            ],
        );
        let uc = use_case(
            lock,
            ghsa_repo("x"),
            released("x"),
            MockUvLockSimulator::default().with_targeted("x", resolved()),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        let finding = &report.findings[0];
        assert_eq!(finding.package_name, "x");
        assert!(!finding.is_direct);
        assert_eq!(
            finding.paths,
            vec![vec![
                "flask".to_string(),
                "werkzeug".to_string(),
                "x".to_string()
            ]]
        );
        assert_eq!(
            finding.upgrade_command.as_deref(),
            Some("uv lock --upgrade-package x==2.31.0")
        );
        assert!(finding.command_verified);
    }

    #[tokio::test]
    async fn test_alias_resolution_prefers_ghsa_over_pysec() {
        let advisories = MockAdvisoryRepository::default()
            .with(CVE, Ok(Some(advisory(CVE, &[PYSEC, GHSA], vec![]))))
            .with(GHSA, Ok(Some(ghsa_for("requests"))))
            .with(
                PYSEC,
                Ok(Some(advisory(
                    PYSEC,
                    &[],
                    vec![affected("requests", Some("2.31.0"))],
                ))),
            );
        let uc = use_case(
            direct_requests_lock(),
            advisories,
            released("requests"),
            MockUvLockSimulator::default().with_targeted("requests", resolved()),
        );

        let report = uc.execute(request(CVE)).await.unwrap();

        assert_eq!(report.advisory_id, GHSA);
        assert_eq!(report.resolved_from.as_deref(), Some(CVE));
        assert_eq!(
            *uc.advisory_repository.calls.lock().unwrap(),
            vec![CVE.to_string(), GHSA.to_string()],
            "PYSEC must not be fetched once GHSA has a PyPI entry"
        );
        assert_eq!(report.overall, IncidentVerdictView::AffectedFixReleased);
    }

    #[tokio::test]
    async fn test_alias_resolution_falls_back_to_pysec() {
        for ghsa_response in [Ok(None), Ok(Some(advisory(GHSA, &[], vec![])))] {
            let advisories = MockAdvisoryRepository::default()
                .with(CVE, Ok(Some(advisory(CVE, &[GHSA, PYSEC], vec![]))))
                .with(GHSA, ghsa_response)
                .with(
                    PYSEC,
                    Ok(Some(advisory(
                        PYSEC,
                        &[],
                        vec![affected("requests", Some("2.31.0"))],
                    ))),
                );
            let uc = use_case(
                direct_requests_lock(),
                advisories,
                released("requests"),
                MockUvLockSimulator::default().with_targeted("requests", resolved()),
            );

            let report = uc.execute(request(CVE)).await.unwrap();

            assert_eq!(report.advisory_id, PYSEC);
            assert_eq!(report.resolved_from.as_deref(), Some(CVE));
            assert_eq!(report.findings.len(), 1);
        }
    }

    #[tokio::test]
    async fn test_no_pypi_package_yields_not_affected_report() {
        let advisories = MockAdvisoryRepository::default()
            .with(CVE, Ok(Some(advisory(CVE, &["GHSA-none"], vec![]))));
        let uc = use_case(
            direct_requests_lock(),
            advisories,
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );

        let report = uc.execute(request(CVE)).await.unwrap();

        assert_eq!(report.advisory_id, CVE);
        assert_eq!(report.resolved_from, None);
        assert!(report.affected_packages.is_empty());
        assert!(report.findings.is_empty());
        assert_eq!(report.overall, IncidentVerdictView::NotAffected);
    }

    #[tokio::test]
    async fn test_advisory_not_found_is_typed_error() {
        let uc = use_case(
            direct_requests_lock(),
            MockAdvisoryRepository::default(),
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );

        let err = uc.execute(request("GHSA-missing")).await.unwrap_err();

        assert_eq!(
            err.downcast_ref::<IncidentError>(),
            Some(&IncidentError::AdvisoryNotFound {
                advisory_id: "GHSA-missing".to_string()
            })
        );
        assert_eq!(
            err.to_string(),
            "advisory GHSA-missing was not found in the OSV database"
        );
    }

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
    async fn test_exclude_groups_removing_only_package_yields_not_affected() {
        let mut lock = lock(vec![pkg("requests", "2.25.0")], &[]);
        lock.group_roots = HashMap::from([("dev".to_string(), vec!["requests".to_string()])]);
        let uc = use_case(
            lock,
            ghsa_repo("requests"),
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );
        let mut req = request(GHSA);
        req.exclude_groups = vec!["dev".to_string()];

        let report = uc.execute(req).await.unwrap();

        assert!(report.findings.is_empty());
        assert_eq!(report.affected_packages, vec!["requests".to_string()]);
        assert_eq!(report.overall, IncidentVerdictView::NotAffected);
    }

    #[tokio::test]
    async fn test_exclude_pattern_removes_package() {
        let uc = use_case(
            direct_requests_lock(),
            ghsa_repo("requests"),
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );
        let mut req = request(GHSA);
        req.exclude_patterns = vec!["requests".to_string()];

        let report = uc.execute(req).await.unwrap();

        assert!(report.findings.is_empty());
        assert_eq!(report.overall, IncidentVerdictView::NotAffected);
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
    async fn test_affected_packages_deduplicated_by_pep503_name() {
        let advisories = MockAdvisoryRepository::default().with(
            GHSA,
            Ok(Some(advisory(
                GHSA,
                &[],
                vec![
                    affected("Flask_Login", Some("0.6.3")),
                    affected("requests", Some("2.31.0")),
                    affected("flask-login", Some("0.7.0")),
                    affected("Flask.Login", None),
                ],
            ))),
        );
        let uc = use_case(
            lock(vec![], &[]),
            advisories,
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );

        let report = uc.execute(request(GHSA)).await.unwrap();

        assert_eq!(
            report.affected_packages,
            vec!["Flask_Login".to_string(), "requests".to_string()]
        );
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
    fn test_alias_candidates_order_and_case() {
        let primary = advisory(
            CVE,
            &["pysec-1", "GHSA-a", "OTHER-1", "ghsa-b", "PYSEC-2", CVE],
            vec![],
        );

        assert_eq!(
            alias_candidates(&primary),
            vec!["GHSA-a", "ghsa-b", "pysec-1", "PYSEC-2"]
        );
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
