mod abandoned;
mod license;
mod non_pypi;
mod vulnerabilities;

use super::GenerateSbomUseCase;
use crate::application::dto::SbomRequest;
use crate::application::read_models::dependency_tree_view::{
    DependencyTreeNodeView, DependencyTreeView,
};
use crate::application::read_models::explain_view::ExplainView;
use crate::application::read_models::python_compatibility::PythonCompatibilityReport;
use crate::application::use_cases::CheckPythonCompatibilityUseCase;
use crate::i18n::Messages;
use crate::ports::outbound::{
    ExploitabilityRepository, LicenseRepository, LockfileReader, MaintenanceRepository,
    ProgressReporter, ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
};
use crate::sbom_generation::domain::services::{DependencyTreeBuilder, TreeNode};
use crate::sbom_generation::domain::{
    DependencyGraph, EnrichedPackage, Package, PackageName, UvLockSimulator,
};
use crate::shared::Result;
use std::collections::{HashMap, HashSet};

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
    /// Checks package compatibility against `target_python` if requested.
    ///
    /// Returns `None` when `target_python` is unset or no compatibility
    /// repository is configured. When `dependency_graph` is `None`, `is_direct`
    /// defaults to `false` for all packages — consistent with the existing
    /// pattern in `check_abandoned_if_requested`.
    pub(super) async fn check_python_compatibility_if_requested(
        &self,
        request: &SbomRequest,
        packages: &[Package],
        dependency_graph: Option<&DependencyGraph>,
    ) -> Result<Option<PythonCompatibilityReport>> {
        let Some(target) = &request.target_python else {
            return Ok(None);
        };
        let Some(repo) = &self.compatibility_repository else {
            return Ok(None);
        };

        let msgs = Messages::for_locale(self.locale);
        self.progress_reporter
            .report(msgs.progress_fetching_python_compat);

        let direct_names = Self::resolve_direct_names(dependency_graph);
        let compat_use_case = CheckPythonCompatibilityUseCase::new(repo.clone());
        let report = compat_use_case
            .check_with_progress(packages.to_vec(), target, &direct_names)
            .await?;

        eprintln!(); // newline after progress bar

        if report.is_empty() {
            self.progress_reporter.report(&Messages::format(
                msgs.progress_python_compat_none,
                &[&report.target_python],
            ));
        } else {
            self.progress_reporter.report(&Messages::format(
                msgs.progress_python_compat_found,
                &[
                    &report.total_count().to_string(),
                    &report.target_python,
                    &report.direct_count().to_string(),
                    &report.transitive_count().to_string(),
                ],
            ));
        }

        Ok(Some(report))
    }

    /// Builds the `--explain` dependency-path view when `explain_package` is set.
    ///
    /// Returns `None` when the flag is absent, or when no dependency graph was
    /// built (`include_dependency_info` was false, e.g. non-Markdown output):
    /// with no graph the question is unanswerable, and reporting `found: false`
    /// would wrongly claim the package is absent from the project.
    ///
    /// An invalid package name yields `Some(found: false)` rather than an error —
    /// a bad `--explain` argument must never abort SBOM generation. No new
    /// BFS/traversal logic is written here; `DependencyGraph::find_paths_to` is
    /// reused exactly as `ResolutionAnalyzer::analyze` does for CVE-affected
    /// packages.
    pub(super) fn build_explain_view_if_requested(
        &self,
        request: &SbomRequest,
        dependency_graph: Option<&DependencyGraph>,
    ) -> Option<ExplainView> {
        let target = request.explain_package.as_ref()?;
        let graph = dependency_graph?;

        let Ok(pkg_name) = PackageName::new(target.clone()) else {
            return Some(ExplainView {
                target_package: target.clone(),
                found: false,
                is_direct: false,
                paths: Vec::new(),
            });
        };

        let is_direct = graph.direct_dependencies().contains(&pkg_name);
        let paths: Vec<Vec<String>> = graph
            .find_paths_to(&pkg_name)
            .into_iter()
            .map(|path| path.iter().map(|p| p.as_str().to_string()).collect())
            .collect();

        Some(ExplainView {
            target_package: target.clone(),
            found: is_direct || !paths.is_empty(),
            is_direct,
            paths,
        })
    }

    /// Builds the `--show-dependency-tree` visualization when `show_dependency_tree` is set.
    ///
    /// Returns `None` when the flag is off, or when no dependency graph was built
    /// (`include_dependency_info` was false, e.g. non-Markdown output) — same
    /// rationale as `build_explain_view_if_requested`: with no graph there is
    /// nothing to render.
    ///
    /// `DependencyGraph` carries no version data, so each node's `version` is
    /// joined here from `enriched_packages` (the domain `TreeNode` has no such
    /// field — see its doc comment). A package absent from `enriched_packages`
    /// (e.g. excluded by an earlier filter) yields `version: None` rather than
    /// dropping the node, matching the "graph-faithful" behavior of `--explain`.
    pub(super) fn build_dependency_tree_if_requested(
        &self,
        request: &SbomRequest,
        dependency_graph: Option<&DependencyGraph>,
        enriched_packages: &[EnrichedPackage],
    ) -> Option<DependencyTreeView> {
        if !request.show_dependency_tree {
            return None;
        }
        let graph = dependency_graph?;

        let versions: HashMap<&str, &str> = enriched_packages
            .iter()
            .map(|ep| (ep.package.name(), ep.package.version()))
            .collect();

        let max_depth = request.dependency_tree_depth;
        let roots = DependencyTreeBuilder::build(graph, max_depth)
            .into_iter()
            .map(|node| Self::convert_tree_node(node, &versions))
            .collect();

        Some(DependencyTreeView { roots, max_depth })
    }

    /// Recursively converts a domain `TreeNode` into a `DependencyTreeNodeView`,
    /// joining in the resolved version for each node's name.
    fn convert_tree_node(node: TreeNode, versions: &HashMap<&str, &str>) -> DependencyTreeNodeView {
        DependencyTreeNodeView {
            version: versions.get(node.name.as_str()).map(|v| v.to_string()),
            children: node
                .children
                .into_iter()
                .map(|child| Self::convert_tree_node(child, versions))
                .collect(),
            truncated: node.truncated,
            name: node.name,
        }
    }

    /// Returns the set of direct dependency names from the graph.
    ///
    /// When `dependency_graph` is `None`, returns an empty set so every package
    /// is treated as transitive — consistent across all `check_*_if_requested` methods.
    fn resolve_direct_names(dependency_graph: Option<&DependencyGraph>) -> HashSet<&str> {
        dependency_graph
            .map(|g| g.direct_dependencies().iter().map(|p| p.as_str()).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;

    mod tests_python_compatibility {
        use super::*;
        use crate::application::use_cases::test_doubles::MockPythonCompatibilityRepository;
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

    mod tests_explain {
        use super::*;
        use crate::sbom_generation::domain::{DependencyGraph, PackageName};
        use std::collections::HashMap;

        fn pn(name: &str) -> PackageName {
            PackageName::new(name.to_string()).unwrap()
        }

        fn make_graph(direct: Vec<&str>, edges: Vec<(&str, Vec<&str>)>) -> DependencyGraph {
            let direct_deps = direct.into_iter().map(pn).collect();
            let package_edges: HashMap<PackageName, Vec<PackageName>> = edges
                .into_iter()
                .map(|(parent, children)| (pn(parent), children.into_iter().map(pn).collect()))
                .collect();
            DependencyGraph::new(direct_deps, HashMap::new(), package_edges)
        }

        fn explain_request(target: &str) -> SbomRequest {
            SbomRequest::builder()
                .project_path("/test/project")
                .include_dependency_info(true)
                .explain_package(Some(target.to_string()))
                .build()
                .unwrap()
        }

        #[test]
        fn test_explain_disabled_returns_none() {
            let use_case = UseCaseBuilder::default().build();
            let graph = make_graph(vec!["requests"], vec![]);

            let result = use_case.build_explain_view_if_requested(&default_request(), Some(&graph));

            assert!(result.is_none());
        }

        #[test]
        fn test_explain_no_dependency_graph_returns_none() {
            let use_case = UseCaseBuilder::default().build();

            let result =
                use_case.build_explain_view_if_requested(&explain_request("requests"), None);

            assert!(result.is_none());
        }

        #[test]
        fn test_explain_direct_dependency() {
            let use_case = UseCaseBuilder::default().build();
            let graph = make_graph(vec!["requests"], vec![]);

            let view = use_case
                .build_explain_view_if_requested(&explain_request("requests"), Some(&graph))
                .expect("explain_package set → Some");

            assert_eq!(view.target_package, "requests");
            assert!(view.found);
            assert!(view.is_direct);
            assert!(view.paths.is_empty());
        }

        #[test]
        fn test_explain_transitive_single_path() {
            let use_case = UseCaseBuilder::default().build();
            let graph = make_graph(vec!["requests"], vec![("requests", vec!["urllib3"])]);

            let view = use_case
                .build_explain_view_if_requested(&explain_request("urllib3"), Some(&graph))
                .expect("explain_package set → Some");

            assert!(view.found);
            assert!(!view.is_direct);
            assert_eq!(
                view.paths,
                vec![vec!["requests".to_string(), "urllib3".to_string()]]
            );
        }

        #[test]
        fn test_explain_transitive_diamond_multi_path() {
            let use_case = UseCaseBuilder::default().build();
            let graph = make_graph(
                vec!["requests", "httpx"],
                vec![("requests", vec!["urllib3"]), ("httpx", vec!["urllib3"])],
            );

            let view = use_case
                .build_explain_view_if_requested(&explain_request("urllib3"), Some(&graph))
                .expect("explain_package set → Some");

            assert!(view.found);
            assert!(!view.is_direct);
            assert_eq!(view.paths.len(), 2);
            assert!(view
                .paths
                .contains(&vec!["requests".to_string(), "urllib3".to_string()]));
            assert!(view
                .paths
                .contains(&vec!["httpx".to_string(), "urllib3".to_string()]));
        }

        #[test]
        fn test_explain_not_found() {
            let use_case = UseCaseBuilder::default().build();
            let graph = make_graph(vec!["requests"], vec![("requests", vec!["urllib3"])]);

            let view = use_case
                .build_explain_view_if_requested(&explain_request("nonexistent"), Some(&graph))
                .expect("explain_package set → Some");

            assert!(!view.found);
            assert!(!view.is_direct);
            assert!(view.paths.is_empty());
        }

        #[test]
        fn test_explain_invalid_package_name_does_not_abort() {
            let use_case = UseCaseBuilder::default().build();
            let graph = make_graph(vec!["requests"], vec![]);

            let view = use_case
                .build_explain_view_if_requested(&explain_request(""), Some(&graph))
                .expect("explain_package set → Some");

            assert!(!view.found);
            assert!(!view.is_direct);
            assert!(view.paths.is_empty());
        }
    }

    mod tests_dependency_tree {
        use super::*;
        use crate::sbom_generation::domain::{DependencyGraph, PackageName};
        use std::collections::HashMap;

        fn pn(name: &str) -> PackageName {
            PackageName::new(name.to_string()).unwrap()
        }

        fn make_graph(direct: Vec<&str>, edges: Vec<(&str, Vec<&str>)>) -> DependencyGraph {
            let direct_deps = direct.into_iter().map(pn).collect();
            let package_edges: HashMap<PackageName, Vec<PackageName>> = edges
                .into_iter()
                .map(|(parent, children)| (pn(parent), children.into_iter().map(pn).collect()))
                .collect();
            DependencyGraph::new(direct_deps, HashMap::new(), package_edges)
        }

        fn tree_request(depth: usize) -> SbomRequest {
            SbomRequest::builder()
                .project_path("/test/project")
                .include_dependency_info(true)
                .show_dependency_tree(true)
                .dependency_tree_depth(depth)
                .build()
                .unwrap()
        }

        fn enriched(name: &str, version: &str) -> EnrichedPackage {
            EnrichedPackage::new(pkg(name, version), Some("MIT".to_string()), None)
        }

        #[test]
        fn test_dependency_tree_disabled_returns_none() {
            let use_case = UseCaseBuilder::default().build();
            let graph = make_graph(vec!["requests"], vec![]);

            let result =
                use_case.build_dependency_tree_if_requested(&default_request(), Some(&graph), &[]);

            assert!(result.is_none());
        }

        #[test]
        fn test_dependency_tree_no_dependency_graph_returns_none() {
            let use_case = UseCaseBuilder::default().build();

            let result = use_case.build_dependency_tree_if_requested(&tree_request(3), None, &[]);

            assert!(result.is_none());
        }

        #[test]
        fn test_dependency_tree_populates_roots_with_joined_version() {
            let use_case = UseCaseBuilder::default().build();
            let graph = make_graph(vec!["requests"], vec![("requests", vec!["urllib3"])]);
            let packages = vec![enriched("requests", "2.31.0"), enriched("urllib3", "2.0.0")];

            let view = use_case
                .build_dependency_tree_if_requested(&tree_request(3), Some(&graph), &packages)
                .expect("show_dependency_tree set → Some");

            assert_eq!(view.max_depth, 3);
            assert_eq!(view.roots.len(), 1);
            let root = &view.roots[0];
            assert_eq!(root.name, "requests");
            assert_eq!(root.version.as_deref(), Some("2.31.0"));
            assert!(!root.truncated);
            assert_eq!(root.children.len(), 1);
            assert_eq!(root.children[0].name, "urllib3");
            assert_eq!(root.children[0].version.as_deref(), Some("2.0.0"));
        }

        #[test]
        fn test_dependency_tree_unresolved_version_is_none() {
            let use_case = UseCaseBuilder::default().build();
            let graph = make_graph(vec!["requests"], vec![]);

            let view = use_case
                .build_dependency_tree_if_requested(&tree_request(3), Some(&graph), &[])
                .expect("show_dependency_tree set → Some");

            assert!(view.roots[0].version.is_none());
        }

        #[test]
        fn test_dependency_tree_respects_depth_truncation() {
            let use_case = UseCaseBuilder::default().build();
            let graph = make_graph(vec!["requests"], vec![("requests", vec!["urllib3"])]);

            let view = use_case
                .build_dependency_tree_if_requested(&tree_request(0), Some(&graph), &[])
                .expect("show_dependency_tree set → Some");

            assert!(view.roots[0].truncated);
            assert!(view.roots[0].children.is_empty());
        }
    }
}
