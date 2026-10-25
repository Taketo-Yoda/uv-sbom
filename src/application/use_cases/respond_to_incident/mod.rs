//! `--incident <ADVISORY_ID>` use case (#967; workspace mode #969; manual
//! range specs #963).
//!
//! `mod.rs` holds the use case struct, the single-project entry point, and
//! advisory resolution (an OSV lookup, or a synthetic advisory built from a
//! manual range spec); `evaluation.rs` evaluates packages against the
//! advisory (release lookup, dry-run, verdict, next action); `workspace.rs`
//! holds the workspace entry point.

mod evaluation;
mod workspace;

use crate::application::dto::IncidentRequest;
use crate::application::read_models::incident_report::{
    IncidentFinding, IncidentReport, IncidentSource, MemberIncidentResult, WorkspaceIncidentReport,
};
use crate::application::read_models::vulnerability_view::SeverityView;
use crate::application::use_cases::project_scope;
use crate::i18n::{Locale, Messages};
use crate::ports::outbound::lockfile_reader::DependencyMap;
use crate::ports::outbound::{
    AdvisoryRepository, LockfileReader, PackageSourceMap, ProjectConfigReader, ReleaseRepository,
};
use crate::sbom_generation::domain::advisory::{Advisory, IncidentVerdict};
use crate::sbom_generation::domain::incident_target::{IncidentTarget, ManualAffectedSpec};
use crate::sbom_generation::domain::services::advisory_range_matcher::normalize_name;
use crate::sbom_generation::domain::{DependencyGraph, Package, PackageName, UvLockSimulator};
use crate::sbom_generation::services::DependencyAnalyzer;
use crate::shared::Result;
use evaluation::EvaluationCaches;
use std::collections::HashSet;

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

/// The in-scope packages of a project (or workspace member) and the graph
/// used to place them. Package sources are kept separately because every
/// workspace member shares the same lockfile's sources.
struct ProjectScope {
    /// Packages left after the `--exclude` / `--exclude-groups` filters.
    packages: Vec<Package>,
    /// Graph used for paths and direct/transitive classification.
    graph: DependencyGraph,
}

/// The advisory record used for evaluation, plus report metadata.
struct ResolvedAdvisory {
    /// The record actually used (an alias when one was followed, or the
    /// synthetic record built from a manual spec).
    advisory: Advisory,
    /// Where the record came from.
    source: IncidentSource,
    /// The user-supplied ID when an alias was followed.
    resolved_from: Option<String>,
    severity: Option<SeverityView>,
    summary: Option<String>,
    /// Affected package names, deduplicated by PEP 503 name (first spelling kept).
    affected_packages: Vec<String>,
}

impl ResolvedAdvisory {
    /// The synthetic advisory for a user-supplied range spec (#963): no
    /// aliases, severity, or summary, and no OSV lookup.
    fn manual(spec: &ManualAffectedSpec) -> Self {
        let advisory = spec.to_advisory();
        let affected_packages = dedup_by_normalized_name(&advisory);
        Self {
            advisory,
            source: IncidentSource::Manual,
            resolved_from: None,
            severity: None,
            summary: None,
            affected_packages,
        }
    }

    /// The single-project report for this advisory.
    fn into_report(
        self,
        findings: Vec<IncidentFinding>,
        overall: IncidentVerdict,
    ) -> IncidentReport {
        IncidentReport {
            advisory_id: self.advisory.id,
            source: self.source,
            resolved_from: self.resolved_from,
            aliases: self.advisory.aliases,
            severity: self.severity,
            summary: self.summary,
            affected_packages: self.affected_packages,
            findings,
            overall: overall.into(),
        }
    }

    /// The workspace report for this advisory (#969).
    fn into_workspace_report(
        self,
        members: Vec<MemberIncidentResult>,
        overall: IncidentVerdict,
    ) -> WorkspaceIncidentReport {
        WorkspaceIncidentReport {
            advisory_id: self.advisory.id,
            source: self.source,
            resolved_from: self.resolved_from,
            aliases: self.advisory.aliases,
            severity: self.severity,
            summary: self.summary,
            affected_packages: self.affected_packages,
            members,
            overall: overall.into(),
        }
    }
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

    /// Builds the incident report for `request.target`.
    ///
    /// 1. Reads the lockfile and applies the scope filters (an empty scope is
    ///    not an error — it yields a not-affected report), builds the
    ///    dependency graph, and reads package sources.
    /// 2. Fetches the advisory, following GHSA, then PYSEC aliases when the
    ///    record lists no PyPI package. A manual range spec is converted into
    ///    a synthetic advisory instead, and OSV is not queried (#963).
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
        let (scope, sources) = self.load_scope(&request, msgs)?;

        // 2. Advisory (following aliases, or built from a manual spec) and metadata.
        let resolved = self.resolve_target(&request.target).await?;

        // 3-4. Findings, ordering, and overall verdict.
        let mut caches = EvaluationCaches::default();
        let (findings, overall) = self
            .evaluate_scope(
                &scope,
                &sources,
                &resolved.advisory,
                request.project_path.as_path(),
                &mut caches,
                msgs,
            )
            .await;

        Ok(resolved.into_report(findings, overall))
    }

    /// Reads the lockfile, applies the scope filters, builds the dependency
    /// graph, and reads package sources, printing unmatched-pattern and
    /// truncated-chain warnings. The dependency map is never filtered (#206).
    fn load_scope(
        &self,
        request: &IncidentRequest,
        msgs: &Messages,
    ) -> Result<(ProjectScope, PackageSourceMap)> {
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
        let graph = build_graph(project_name, &dependency_map, msgs)?;

        let sources = self
            .lockfile_reader
            .read_and_parse_package_sources(project_path)?;

        Ok((ProjectScope { packages, graph }, sources))
    }

    /// Resolves the advisory to evaluate: an OSV lookup for an advisory ID, or
    /// the synthetic advisory for a manual range spec, which makes no
    /// `AdvisoryRepository` call (#963).
    ///
    /// # Errors
    /// The same as `resolve_advisory`, for an advisory ID only.
    async fn resolve_target(&self, target: &IncidentTarget) -> Result<ResolvedAdvisory> {
        match target {
            IncidentTarget::AdvisoryId(id) => self.resolve_advisory(id).await,
            IncidentTarget::ManualSpec(spec) => Ok(ResolvedAdvisory::manual(spec)),
        }
    }

    /// Fetches the requested advisory, follows aliases when it lists no PyPI
    /// package, and collects the report metadata (severity and summary fall
    /// back to the requested record when the alias record lacks them).
    ///
    /// # Errors
    /// `IncidentError::AdvisoryNotFound` when the requested ID has no record;
    /// any advisory or alias lookup error.
    async fn resolve_advisory(&self, advisory_id: &str) -> Result<ResolvedAdvisory> {
        let msgs = Messages::for_locale(self.locale);
        eprintln!(
            "{}",
            Messages::format(msgs.progress_incident_fetching_advisory, &[advisory_id])
        );
        let primary = self
            .advisory_repository
            .fetch_advisory(advisory_id)
            .await?
            .ok_or_else(|| IncidentError::AdvisoryNotFound {
                advisory_id: advisory_id.to_string(),
            })?;
        let (advisory, resolved_from) = match self.follow_aliases(&primary).await? {
            Some(alias_record) => (alias_record, Some(advisory_id.to_string())),
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
            source: IncidentSource::Osv,
            resolved_from,
            severity,
            summary,
            affected_packages,
        })
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
        let msgs = Messages::for_locale(self.locale);
        for alias in alias_candidates(primary) {
            eprintln!(
                "{}",
                Messages::format(msgs.progress_incident_following_alias, &[alias])
            );
            match self.advisory_repository.fetch_advisory(alias).await? {
                Some(record) if !record.affected.is_empty() => return Ok(Some(record)),
                _ => continue,
            }
        }
        Ok(None)
    }
}

/// Builds the dependency graph rooted at `root_name`, printing a warning for
/// every truncated chain.
fn build_graph(
    root_name: String,
    dependency_map: &DependencyMap,
    msgs: &Messages,
) -> Result<DependencyGraph> {
    let (graph, truncated_chains) =
        DependencyAnalyzer::analyze(&PackageName::new(root_name)?, dependency_map)?;
    for record in &truncated_chains {
        eprintln!(
            "{}",
            Messages::format(
                msgs.warn_dependency_chain_truncated,
                &[&record.max_depth.to_string(), &record.package_name],
            )
        );
    }
    Ok(graph)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::incident_report::{
        IncidentVerdictView, ReleaseStatusView,
    };
    use crate::application::use_cases::test_doubles::{
        MockLockfileReader, MockProjectConfigReader, MockUvLockSimulator,
    };
    use crate::ports::outbound::PackageSourceKind;
    use crate::sbom_generation::domain::advisory::{AffectedPackage, AffectedRange, ReleaseStatus};
    use crate::sbom_generation::domain::Severity;
    use crate::sbom_generation::domain::TargetedSimulationOutcome;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Mutex;

    // ---- local mocks ----

    /// Advisory lookups keyed by ID; an unconfigured ID is `Ok(None)`.
    #[derive(Default)]
    pub(super) struct MockAdvisoryRepository {
        pub(super) responses: HashMap<String, std::result::Result<Option<Advisory>, String>>,
        pub(super) calls: Mutex<Vec<String>>,
    }

    impl MockAdvisoryRepository {
        pub(super) fn with(
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
    pub(super) struct MockReleaseRepository {
        pub(super) responses: HashMap<(String, String), std::result::Result<ReleaseStatus, String>>,
        pub(super) calls: Mutex<Vec<(String, String)>>,
    }

    impl MockReleaseRepository {
        pub(super) fn with(
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

    pub(super) type TestUseCase = RespondToIncidentUseCase<
        MockLockfileReader,
        MockProjectConfigReader,
        MockAdvisoryRepository,
        MockReleaseRepository,
        MockUvLockSimulator,
    >;

    // ---- fixtures ----

    pub(super) const PROJECT: &str = "myapp";
    pub(super) const GHSA: &str = "GHSA-j8r2-6x86-q33q";
    pub(super) const CVE: &str = "CVE-2023-32681";
    pub(super) const PYSEC: &str = "PYSEC-2023-74";

    pub(super) fn pkg(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
    }

    pub(super) fn range(introduced: &str, fixed: Option<&str>) -> AffectedRange {
        AffectedRange {
            introduced: Some(introduced.to_string()),
            fixed: fixed.map(str::to_string),
            last_affected: None,
        }
    }

    pub(super) fn advisory(id: &str, aliases: &[&str], affected: Vec<AffectedPackage>) -> Advisory {
        Advisory {
            id: id.to_string(),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            summary: Some("Leak of Proxy-Authorization header".to_string()),
            severity: Some(Severity::Medium),
            affected,
        }
    }

    pub(super) fn affected(name: &str, fixed: Option<&str>) -> AffectedPackage {
        AffectedPackage {
            name: name.to_string(),
            ranges: vec![range("0", fixed)],
            versions: vec![],
        }
    }

    /// `name` affected below 2.31.0 (fixed in 2.31.0).
    pub(super) fn ghsa_for(name: &str) -> Advisory {
        advisory(GHSA, &[CVE, PYSEC], vec![affected(name, Some("2.31.0"))])
    }

    /// Lockfile with `myapp` (workspace member) plus `packages`, and edges.
    pub(super) fn lock(packages: Vec<Package>, edges: &[(&str, &[&str])]) -> MockLockfileReader {
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
            member_lockfile: None,
        }
    }

    pub(super) fn direct_requests_lock() -> MockLockfileReader {
        lock(vec![pkg("requests", "2.25.0")], &[(PROJECT, &["requests"])])
    }

    pub(super) fn use_case(
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

    pub(super) fn request(id: &str) -> IncidentRequest {
        IncidentRequest {
            target: IncidentTarget::AdvisoryId(id.to_string()),
            project_path: PathBuf::from("/test/project"),
            exclude_patterns: vec![],
            exclude_groups: vec![],
        }
    }

    pub(super) fn resolved() -> std::result::Result<TargetedSimulationOutcome, String> {
        Ok(TargetedSimulationOutcome::Resolved {
            resolved_version: "2.31.0".to_string(),
        })
    }

    pub(super) fn released(name: &str) -> MockReleaseRepository {
        MockReleaseRepository::default().with(name, "2.31.0", Ok(ReleaseStatus::Released))
    }

    pub(super) fn ghsa_repo(name: &str) -> MockAdvisoryRepository {
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
        assert_eq!(report.source, IncidentSource::Osv);
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

    pub(super) fn manual(spec: &str) -> IncidentTarget {
        IncidentTarget::ManualSpec(ManualAffectedSpec::parse(spec).unwrap())
    }

    #[tokio::test]
    async fn test_manual_spec_skips_advisory_repository_and_verifies_command() {
        let uc = use_case(
            direct_requests_lock(),
            MockAdvisoryRepository::default(),
            released("requests"),
            MockUvLockSimulator::default().with_targeted("requests", resolved()),
        );
        let request = IncidentRequest {
            target: manual("requests<2.31.0"),
            ..request(GHSA)
        };

        let report = uc.execute(request).await.unwrap();

        assert!(uc.advisory_repository.calls.lock().unwrap().is_empty());
        assert_eq!(report.source, IncidentSource::Manual);
        assert_eq!(report.advisory_id, "requests<2.31.0");
        assert_eq!(report.resolved_from, None);
        assert!(report.aliases.is_empty());
        assert_eq!(report.severity, None);
        assert_eq!(report.summary, None);
        assert_eq!(report.affected_packages, vec!["requests".to_string()]);
        assert_eq!(report.overall, IncidentVerdictView::AffectedFixReleased);
        let finding = &report.findings[0];
        assert_eq!(finding.fixed_version.as_deref(), Some("2.31.0"));
        assert_eq!(
            finding.upgrade_command.as_deref(),
            Some("uv lock --upgrade-package requests==2.31.0")
        );
        assert!(finding.command_verified);
    }

    #[tokio::test]
    async fn test_manual_spec_last_affected_is_no_fix_without_release_lookup() {
        let uc = use_case(
            direct_requests_lock(),
            MockAdvisoryRepository::default(),
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );
        let request = IncidentRequest {
            target: manual("requests<=2.30.0"),
            ..request(GHSA)
        };

        let report = uc.execute(request).await.unwrap();

        assert!(uc.advisory_repository.calls.lock().unwrap().is_empty());
        assert!(uc.release_repository.calls.lock().unwrap().is_empty());
        assert_eq!(report.overall, IncidentVerdictView::AffectedNoFix);
        assert_eq!(report.findings[0].upgrade_command, None);
    }

    #[tokio::test]
    async fn test_manual_spec_outside_range_is_not_affected() {
        let uc = use_case(
            direct_requests_lock(),
            MockAdvisoryRepository::default(),
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );
        let request = IncidentRequest {
            target: manual("requests>=2.26,<2.31.0"),
            ..request(GHSA)
        };

        let report = uc.execute(request).await.unwrap();

        assert!(uc.advisory_repository.calls.lock().unwrap().is_empty());
        assert_eq!(report.overall, IncidentVerdictView::NotAffected);
        assert_eq!(report.findings[0].verdict, IncidentVerdictView::NotAffected);
    }
}
