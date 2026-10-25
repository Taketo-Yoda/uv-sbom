//! Workspace entry point for `--incident --workspace` (#969).

use super::evaluation::EvaluationCaches;
use super::{build_graph, ProjectScope, RespondToIncidentUseCase};
use crate::application::dto::WorkspaceIncidentRequest;
use crate::application::read_models::incident_report::{
    MemberIncidentResult, WorkspaceIncidentReport,
};
use crate::application::use_cases::project_scope;
use crate::i18n::Messages;
use crate::ports::outbound::lockfile_reader::DependencyMap;
use crate::ports::outbound::{
    AdvisoryRepository, LockfileReader, ProjectConfigReader, ReleaseRepository,
};
use crate::sbom_generation::domain::advisory::IncidentVerdict;
use crate::sbom_generation::domain::services::advisory_range_matcher::AdvisoryRangeMatcher;
use crate::sbom_generation::domain::UvLockSimulator;
use crate::shared::Result;

impl<LR, PCR, AR, RR, USIM> RespondToIncidentUseCase<LR, PCR, AR, RR, USIM>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    AR: AdvisoryRepository,
    RR: ReleaseRepository,
    USIM: UvLockSimulator,
{
    /// Builds the incident report for every member of a uv workspace (#969).
    ///
    /// The workspace shares one `uv.lock`, so members differ only in which
    /// packages they reach:
    ///
    /// 1. Reads package sources and the full dependency map once from the
    ///    workspace root, then, per member, the member-scoped packages with
    ///    the scope filters applied. Each member's graph is built from the
    ///    full map rooted at the member, so paths start at the member's own
    ///    direct dependencies. An `--exclude` pattern is reported as unmatched
    ///    only when it matches nothing in any member.
    /// 2. Resolves the advisory once, as `execute` does (an OSV lookup
    ///    following aliases, or a manual range spec with no lookup).
    /// 3. Evaluates every member with one shared set of caches, so each
    ///    `(package, fixed version)` gets at most one release lookup and one
    ///    dry-run resolution, which runs in the workspace root.
    /// 4. Derives the workspace verdict from the member verdicts with the same
    ///    precedence as `execute`.
    ///
    /// # Errors
    /// The same as `execute`, plus an error when a member is not found in the
    /// lockfile or a member name is not a valid package name.
    pub async fn execute_workspace(
        &self,
        request: WorkspaceIncidentRequest,
    ) -> Result<WorkspaceIncidentReport> {
        let msgs = Messages::for_locale(self.locale);
        let root = request.workspace_root.as_path();

        // 1. Shared sources and dependency map, then one scope per member.
        let (_, full_map) = self.lockfile_reader.read_and_parse_lockfile(root)?;
        let sources = self.lockfile_reader.read_and_parse_package_sources(root)?;
        let mut scopes: Vec<(&str, ProjectScope)> = Vec::new();
        let mut unmatched_per_member: Vec<Vec<String>> = Vec::new();
        for member in &request.member_names {
            let (scope, unmatched) = self.load_member_scope(&request, member, &full_map, msgs)?;
            unmatched_per_member.push(unmatched);
            scopes.push((member.as_str(), scope));
        }
        for pattern in unmatched_in_every_member(unmatched_per_member) {
            eprintln!(
                "{}",
                Messages::format(msgs.warn_exclude_pattern_unmatched, &[&pattern])
            );
        }

        // 2. Advisory, resolved once for the whole workspace.
        let resolved = self.resolve_target(&request.target).await?;

        // 3. Per-member evaluation with shared caches.
        let mut caches = EvaluationCaches::default();
        let mut members: Vec<MemberIncidentResult> = Vec::new();
        let mut verdicts: Vec<IncidentVerdict> = Vec::new();
        for (name, scope) in &scopes {
            let (findings, overall) = self
                .evaluate_scope(scope, &sources, &resolved.advisory, root, &mut caches, msgs)
                .await;
            verdicts.push(overall);
            members.push(MemberIncidentResult {
                name: name.to_string(),
                findings,
                overall: overall.into(),
            });
        }

        // 4. Workspace verdict.
        let overall = AdvisoryRangeMatcher::overall(&verdicts);
        Ok(resolved.into_workspace_report(members, overall))
    }

    /// Reads one workspace member's packages and applies the scope filters
    /// against the member-scoped dependency map. The graph is built from
    /// `full_map` rooted at the member, so every edge is runtime-only as in
    /// single-project mode (the member-scoped map also carries `dev` edges of
    /// local packages it reaches); the member map is used only for group
    /// filtering. Returns the `--exclude` patterns that matched nothing in
    /// this member; the caller decides whether to warn.
    fn load_member_scope(
        &self,
        request: &WorkspaceIncidentRequest,
        member: &str,
        full_map: &DependencyMap,
        msgs: &Messages,
    ) -> Result<(ProjectScope, Vec<String>)> {
        let root = request.workspace_root.as_path();
        let (packages, member_map) = self
            .lockfile_reader
            .read_and_parse_lockfile_for_member(root, member)?;
        let pattern_outcome =
            project_scope::filter_by_patterns(packages, &request.exclude_patterns)?;
        let packages = project_scope::filter_by_groups_for_member(
            &self.lockfile_reader,
            root,
            member,
            pattern_outcome.packages,
            &member_map,
            &request.exclude_groups,
        )?;
        let graph = build_graph(member.to_string(), full_map, msgs)?;
        Ok((
            ProjectScope { packages, graph },
            pattern_outcome.unmatched_patterns,
        ))
    }
}

/// The `--exclude` patterns that matched nothing in any member: the
/// intersection of every member's unmatched patterns, in the first member's
/// order. A pattern that matched in at least one member is not reported.
fn unmatched_in_every_member(per_member: Vec<Vec<String>>) -> Vec<String> {
    let mut members = per_member.into_iter();
    let Some(first) = members.next() else {
        return Vec::new();
    };
    members.fold(first, |kept, unmatched| {
        kept.into_iter()
            .filter(|pattern| unmatched.contains(pattern))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::incident_report::{IncidentSource, IncidentVerdictView};
    use crate::application::use_cases::respond_to_incident::tests::*;
    use crate::application::use_cases::respond_to_incident::IncidentError;
    use crate::application::use_cases::test_doubles::{
        MockProjectConfigReader, MockUvLockSimulator,
    };
    use crate::i18n::Locale;
    use crate::ports::outbound::{PackageSourceKind, PackageSourceMap};
    use crate::sbom_generation::domain::incident_target::IncidentTarget;
    use crate::sbom_generation::domain::Package;
    use std::collections::{BTreeSet, HashMap};
    use std::path::{Path, PathBuf};

    const WS_ROOT: &str = "/test/workspace";

    /// Workspace lockfile: `full` is the root-level dependency map (member
    /// keys included); a member read returns only the packages reachable from
    /// the member's direct dependencies, plus the member's own root entry in
    /// the map (never in the packages) — mirroring
    /// `parse_lockfile_content_for_member`. `dev` holds each member's `dev`
    /// group: followed by the member read, but absent from `full` and from the
    /// runtime-only root entry, as in a real lockfile. `group_roots` holds
    /// each member's own group roots, as a revision-3 lockfile does.
    struct MockWorkspaceLockfileReader {
        packages: Vec<Package>,
        full: HashMap<String, Vec<String>>,
        dev: HashMap<String, Vec<String>>,
        group_roots: HashMap<String, crate::ports::outbound::GroupRoots>,
        sources: PackageSourceMap,
    }

    impl LockfileReader for MockWorkspaceLockfileReader {
        fn read_lockfile(&self, _path: &Path) -> Result<String> {
            Ok(String::new())
        }

        fn read_and_parse_lockfile(
            &self,
            _path: &Path,
        ) -> Result<crate::ports::outbound::LockfileParseResult> {
            Ok((self.packages.clone(), self.full.clone()))
        }

        fn read_and_parse_lockfile_for_member(
            &self,
            _path: &Path,
            member_name: &str,
        ) -> Result<crate::ports::outbound::LockfileParseResult> {
            let mut visited: BTreeSet<String> = BTreeSet::new();
            let Some(roots) = self.full.get(member_name) else {
                anyhow::bail!("Workspace member '{}' not found in uv.lock", member_name);
            };
            let mut queue: Vec<String> = roots.clone();
            queue.extend(self.dev.get(member_name).cloned().unwrap_or_default());
            while let Some(name) = queue.pop() {
                if visited.insert(name.clone()) {
                    queue.extend(self.full.get(&name).cloned().unwrap_or_default());
                }
            }
            let packages = self
                .packages
                .iter()
                .filter(|p| visited.contains(p.name()))
                .cloned()
                .collect();
            let mut map: HashMap<String, Vec<String>> = visited
                .iter()
                .map(|name| (name.clone(), self.full[name].clone()))
                .collect();
            map.insert(member_name.to_string(), roots.clone());
            Ok((packages, map))
        }

        fn read_and_parse_group_roots(
            &self,
            _path: &Path,
        ) -> Result<crate::ports::outbound::GroupRoots> {
            unreachable!("workspace mode must read each member's own group roots (#992)")
        }

        fn read_and_parse_group_roots_for_member(
            &self,
            _path: &Path,
            member_name: &str,
        ) -> Result<crate::ports::outbound::GroupRoots> {
            Ok(self
                .group_roots
                .get(member_name)
                .cloned()
                .unwrap_or_default())
        }

        fn read_and_parse_package_sources(&self, _path: &Path) -> Result<PackageSourceMap> {
            Ok(self.sources.clone())
        }
    }

    type WorkspaceUseCase = RespondToIncidentUseCase<
        MockWorkspaceLockfileReader,
        MockProjectConfigReader,
        MockAdvisoryRepository,
        MockReleaseRepository,
        MockUvLockSimulator,
    >;

    /// `api -> fastapi -> starlette`, `api -> requests -> urllib3`,
    /// `worker -> celery -> urllib3`. Only `api` reaches `starlette`; both
    /// members reach `urllib3`.
    fn workspace_lock() -> MockWorkspaceLockfileReader {
        let edges: [(&str, &[&str]); 7] = [
            ("api", &["fastapi", "requests"]),
            ("worker", &["celery"]),
            ("fastapi", &["starlette"]),
            ("requests", &["urllib3"]),
            ("celery", &["urllib3"]),
            ("starlette", &[]),
            ("urllib3", &[]),
        ];
        MockWorkspaceLockfileReader {
            packages: vec![
                pkg("api", "0.1.0"),
                pkg("worker", "0.1.0"),
                pkg("fastapi", "0.100.0"),
                pkg("starlette", "0.27.0"),
                pkg("requests", "2.31.0"),
                pkg("celery", "5.3.0"),
                pkg("urllib3", "1.26.0"),
            ],
            full: edges
                .iter()
                .map(|(k, v)| (k.to_string(), v.iter().map(|c| c.to_string()).collect()))
                .collect(),
            dev: HashMap::new(),
            group_roots: HashMap::new(),
            sources: HashMap::from([
                ("api".to_string(), PackageSourceKind::WorkspaceMember),
                ("worker".to_string(), PackageSourceKind::WorkspaceMember),
            ]),
        }
    }

    fn workspace_use_case(
        lock: MockWorkspaceLockfileReader,
        advisories: MockAdvisoryRepository,
        releases: MockReleaseRepository,
        simulator: MockUvLockSimulator,
    ) -> WorkspaceUseCase {
        RespondToIncidentUseCase::new(
            lock,
            MockProjectConfigReader {
                project_name: "workspace-root".to_string(),
                pyproject_missing: false,
            },
            advisories,
            releases,
            simulator,
            Locale::En,
        )
    }

    fn workspace_request(id: &str) -> WorkspaceIncidentRequest {
        WorkspaceIncidentRequest {
            target: IncidentTarget::AdvisoryId(id.to_string()),
            workspace_root: PathBuf::from(WS_ROOT),
            member_names: vec!["api".to_string(), "worker".to_string()],
            exclude_patterns: vec![],
            exclude_groups: vec![],
        }
    }

    fn member_result<'a>(
        report: &'a WorkspaceIncidentReport,
        name: &str,
    ) -> &'a MemberIncidentResult {
        report.members.iter().find(|m| m.name == name).unwrap()
    }

    #[tokio::test]
    async fn test_workspace_only_reaching_member_is_affected() {
        let uc = workspace_use_case(
            workspace_lock(),
            ghsa_repo("starlette"),
            released("starlette"),
            MockUvLockSimulator::default().with_targeted("starlette", resolved()),
        );

        let report = uc.execute_workspace(workspace_request(GHSA)).await.unwrap();

        let names: Vec<&str> = report.members.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["api", "worker"]);
        let api = member_result(&report, "api");
        assert_eq!(api.overall, IncidentVerdictView::AffectedFixReleased);
        assert_eq!(api.findings.len(), 1);
        assert!(!api.findings[0].is_direct);
        // Paths start at the member's own direct dependency, so the member's
        // root entry missing from the member-scoped map does not empty them.
        assert_eq!(
            api.findings[0].paths,
            vec![vec!["fastapi".to_string(), "starlette".to_string()]]
        );
        let worker = member_result(&report, "worker");
        assert_eq!(worker.overall, IncidentVerdictView::NotAffected);
        assert!(worker.findings.is_empty());
        assert_eq!(report.overall, IncidentVerdictView::AffectedFixReleased);
        assert_eq!(report.affected_member_names(), vec!["api"]);
    }

    #[tokio::test]
    async fn test_workspace_fetches_advisory_release_and_simulation_once() {
        let advisories = ghsa_repo("urllib3");
        let releases = released("urllib3");
        let simulator = MockUvLockSimulator::default().with_targeted("urllib3", resolved());
        let uc = workspace_use_case(workspace_lock(), advisories, releases, simulator);

        let report = uc.execute_workspace(workspace_request(GHSA)).await.unwrap();

        assert_eq!(
            *uc.advisory_repository.calls.lock().unwrap(),
            vec![GHSA.to_string()]
        );
        assert_eq!(uc.release_repository.calls.lock().unwrap().len(), 1);
        assert_eq!(uc.simulator.targeted_call_log().len(), 1);
        assert_eq!(
            uc.simulator.targeted_path_log(),
            vec![PathBuf::from(WS_ROOT)]
        );
        assert_eq!(
            member_result(&report, "api").findings[0].paths,
            vec![vec!["requests".to_string(), "urllib3".to_string()]]
        );
        assert_eq!(
            member_result(&report, "worker").findings[0].paths,
            vec![vec!["celery".to_string(), "urllib3".to_string()]]
        );
        assert_eq!(report.affected_member_names(), vec!["api", "worker"]);
    }

    #[tokio::test]
    async fn test_workspace_overall_uses_most_actionable_member_verdict() {
        let mixed = advisory(
            GHSA,
            &[],
            vec![
                affected("starlette", Some("2.31.0")),
                affected("urllib3", None),
            ],
        );
        let uc = workspace_use_case(
            workspace_lock(),
            MockAdvisoryRepository::default().with(GHSA, Ok(Some(mixed))),
            released("starlette"),
            MockUvLockSimulator::default().with_targeted("starlette", resolved()),
        );

        let report = uc.execute_workspace(workspace_request(GHSA)).await.unwrap();

        assert_eq!(
            member_result(&report, "api").overall,
            IncidentVerdictView::AffectedFixReleased
        );
        assert_eq!(
            member_result(&report, "worker").overall,
            IncidentVerdictView::AffectedNoFix
        );
        assert_eq!(report.overall, IncidentVerdictView::AffectedFixReleased);
    }

    #[tokio::test]
    async fn test_workspace_overall_no_fix_and_not_affected() {
        let no_fix = advisory(GHSA, &[], vec![affected("urllib3", None)]);
        let uc = workspace_use_case(
            workspace_lock(),
            MockAdvisoryRepository::default().with(GHSA, Ok(Some(no_fix))),
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );
        let report = uc.execute_workspace(workspace_request(GHSA)).await.unwrap();
        assert_eq!(report.overall, IncidentVerdictView::AffectedNoFix);

        let uc = workspace_use_case(
            workspace_lock(),
            ghsa_repo("not-in-lock"),
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );
        let report = uc.execute_workspace(workspace_request(GHSA)).await.unwrap();
        assert_eq!(report.overall, IncidentVerdictView::NotAffected);
        assert!(report.members.iter().all(|m| m.findings.is_empty()));
    }

    #[tokio::test]
    async fn test_workspace_unknown_advisory_is_typed_error() {
        let uc = workspace_use_case(
            workspace_lock(),
            MockAdvisoryRepository::default(),
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );

        let err = uc
            .execute_workspace(workspace_request(GHSA))
            .await
            .unwrap_err();

        assert_eq!(
            err.downcast_ref::<IncidentError>(),
            Some(&IncidentError::AdvisoryNotFound {
                advisory_id: GHSA.to_string()
            })
        );
    }

    #[tokio::test]
    async fn test_workspace_exclude_groups_applies_per_member() {
        let mut lock = workspace_lock();
        // Make `celery` a dev-only dependency of `worker`.
        lock.full.insert("worker".to_string(), Vec::new());
        lock.dev = HashMap::from([("worker".to_string(), vec!["celery".to_string()])]);
        lock.group_roots = HashMap::from([(
            "worker".to_string(),
            HashMap::from([("dev".to_string(), vec!["celery".to_string()])]),
        )]);
        let uc = workspace_use_case(
            lock,
            ghsa_repo("urllib3"),
            released("urllib3"),
            MockUvLockSimulator::default().with_targeted("urllib3", resolved()),
        );
        let mut req = workspace_request(GHSA);
        req.exclude_groups = vec!["dev".to_string()];

        let report = uc.execute_workspace(req).await.unwrap();

        // `urllib3` is reachable only through the excluded group in `worker`,
        // but through production `requests` in `api`.
        assert_eq!(report.affected_member_names(), vec!["api"]);
    }

    #[tokio::test]
    async fn test_workspace_exclude_groups_uses_each_members_own_group_roots() {
        let mut lock = workspace_lock();
        // `api` reaches `urllib3` only through its dev root `requests`, and
        // `worker` only through its dev root `celery`.
        lock.full
            .insert("api".to_string(), vec!["fastapi".to_string()]);
        lock.full.insert("worker".to_string(), Vec::new());
        lock.dev = HashMap::from([
            ("api".to_string(), vec!["requests".to_string()]),
            ("worker".to_string(), vec!["celery".to_string()]),
        ]);
        lock.group_roots = HashMap::from([
            (
                "api".to_string(),
                HashMap::from([("dev".to_string(), vec!["requests".to_string()])]),
            ),
            (
                "worker".to_string(),
                HashMap::from([("dev".to_string(), vec!["celery".to_string()])]),
            ),
        ]);
        let uc = workspace_use_case(
            lock,
            ghsa_repo("urllib3"),
            released("urllib3"),
            MockUvLockSimulator::default().with_targeted("urllib3", resolved()),
        );
        let mut req = workspace_request(GHSA);
        req.exclude_groups = vec!["dev".to_string()];

        let report = uc.execute_workspace(req).await.unwrap();

        // With one member's roots applied to both, the other member would
        // keep its dev path to `urllib3` and be reported as affected.
        assert!(report.affected_member_names().is_empty());
        assert_eq!(report.overall, IncidentVerdictView::NotAffected);
    }

    #[test]
    fn test_unmatched_in_every_member_keeps_only_patterns_unmatched_everywhere() {
        let per_member = vec![
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            vec!["c".to_string(), "a".to_string()],
        ];
        assert_eq!(unmatched_in_every_member(per_member), vec!["a", "c"]);
        assert!(unmatched_in_every_member(vec![]).is_empty());
    }

    #[tokio::test]
    async fn test_workspace_unknown_member_is_error() {
        let uc = workspace_use_case(
            workspace_lock(),
            ghsa_repo("starlette"),
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );
        let mut req = workspace_request(GHSA);
        req.member_names.push("ghost".to_string());

        let err = uc.execute_workspace(req).await.unwrap_err();

        assert!(err.to_string().contains("ghost"), "{err}");
        assert!(uc.advisory_repository.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_workspace_manual_spec_skips_advisory_repository() {
        let uc = workspace_use_case(
            workspace_lock(),
            MockAdvisoryRepository::default(),
            MockReleaseRepository::default(),
            MockUvLockSimulator::default(),
        );
        let request = WorkspaceIncidentRequest {
            target: manual("starlette<=0.27.0"),
            ..workspace_request(GHSA)
        };

        let report = uc.execute_workspace(request).await.unwrap();

        assert!(uc.advisory_repository.calls.lock().unwrap().is_empty());
        assert_eq!(report.source, IncidentSource::Manual);
        assert_eq!(report.advisory_id, "starlette<=0.27.0");
        assert_eq!(
            member_result(&report, "api").overall,
            IncidentVerdictView::AffectedNoFix
        );
        assert_eq!(
            member_result(&report, "worker").overall,
            IncidentVerdictView::NotAffected
        );
        assert_eq!(report.overall, IncidentVerdictView::AffectedNoFix);
    }
}
