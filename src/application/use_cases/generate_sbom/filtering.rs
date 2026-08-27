use super::GenerateSbomUseCase;
use crate::application::dto::SbomRequest;
use crate::i18n::Messages;
use crate::ports::outbound::{
    LicenseRepository, LockfileReader, MaintenanceRepository, ProgressReporter,
    ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
};
use crate::sbom_generation::domain::services::GroupReachabilityAnalyzer;
use crate::sbom_generation::domain::{DependencyGraph, Package, PackageName, UvLockSimulator};
use crate::sbom_generation::services::{DependencyAnalyzer, PackageFilter};
use crate::shared::Result;

/// Type alias for package list with dependency map
/// Used to simplify complex return types and satisfy clippy::type_complexity
pub(super) type PackagesWithDependencyMap =
    (Vec<Package>, std::collections::HashMap<String, Vec<String>>);

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
    /// Reads and parses the lockfile, reporting progress
    ///
    /// # Arguments
    /// * `request` - The SBOM request containing project path
    ///
    /// # Returns
    /// Tuple of (packages, dependency_map)
    pub(super) fn read_and_report_lockfile(
        &self,
        request: &SbomRequest,
    ) -> Result<PackagesWithDependencyMap> {
        let msgs = Messages::for_locale(self.locale);
        self.progress_reporter.report(&Messages::format(
            msgs.progress_loading_lockfile,
            &[&request.project_path.display().to_string()],
        ));

        let (packages, dependency_map) = self
            .lockfile_reader
            .read_and_parse_lockfile(&request.project_path)?;

        self.progress_reporter.report(&Messages::format(
            msgs.progress_detected_packages,
            &[&packages.len().to_string()],
        ));

        Ok((packages, dependency_map))
    }

    /// Applies exclusion filters to packages
    ///
    /// Note: This method intentionally does NOT filter the dependency_map.
    /// The dependency_map is preserved to maintain correct dependency classification
    /// (direct vs transitive) even when the root project is excluded from the package list.
    /// See issue #206 for details.
    ///
    /// # Arguments
    /// * `packages` - Original packages from lockfile
    /// * `request` - The SBOM request containing exclusion patterns
    ///
    /// # Returns
    /// Filtered packages list
    ///
    /// # Errors
    /// Returns an error if all packages are excluded
    pub(super) fn apply_exclusion_filters(
        &self,
        packages: Vec<Package>,
        request: &SbomRequest,
    ) -> Result<Vec<Package>> {
        if request.exclude_patterns.is_empty() {
            return Ok(packages);
        }

        let filter = PackageFilter::new(request.exclude_patterns.clone())?;
        let original_count = packages.len();
        let filtered_pkgs = filter.filter_packages(packages);

        let excluded_count = original_count - filtered_pkgs.len();
        if excluded_count > 0 {
            self.progress_reporter.report(&format!(
                "🚫 Excluded {} package(s) based on filters",
                excluded_count
            ));
        }

        // Check if all packages were excluded
        if filtered_pkgs.is_empty() {
            anyhow::bail!(
                "All {} package(s) were excluded by the provided filters. \
                     The SBOM would be empty. Please adjust your exclusion patterns.",
                original_count
            );
        }

        // Warn about unmatched patterns
        let unmatched_patterns = filter.get_unmatched_patterns();
        for pattern in unmatched_patterns {
            self.progress_reporter.report_error(&format!(
                "⚠️  Warning: Exclude pattern '{}' did not match any dependencies.",
                pattern
            ));
        }

        Ok(filtered_pkgs)
    }

    /// Applies group reachability filtering when `exclude_groups` is non-empty.
    ///
    /// Reads `[manifest.dependency-groups]` from the lockfile, then delegates to
    /// `GroupReachabilityAnalyzer::filter_excluded_groups` to remove packages that are
    /// exclusively reachable from the specified groups.
    ///
    /// `dependency_map` is intentionally NOT filtered — Step 3 relies on the full map
    /// to classify direct vs transitive dependencies (issue #206 invariant).
    pub(super) fn apply_group_filter(
        &self,
        packages: Vec<Package>,
        dependency_map: &std::collections::HashMap<String, Vec<String>>,
        request: &SbomRequest,
    ) -> Result<Vec<Package>> {
        if request.exclude_groups.is_empty() {
            return Ok(packages);
        }

        let group_roots = self
            .lockfile_reader
            .read_and_parse_group_roots(&request.project_path)?;

        let original_count = packages.len();
        let filtered = GroupReachabilityAnalyzer::filter_excluded_groups(
            &packages,
            dependency_map,
            &group_roots,
            &request.exclude_groups,
        );

        let excluded_count = original_count - filtered.len();
        if excluded_count > 0 {
            let msgs = Messages::for_locale(self.locale);
            let group_names = request.exclude_groups.join(", ");
            self.progress_reporter.report(&Messages::format(
                msgs.progress_excluded_groups,
                &[&excluded_count.to_string(), &group_names],
            ));
        }

        Ok(filtered)
    }

    /// Analyzes dependencies if requested in the SBOM request
    ///
    /// # Arguments
    /// * `request` - The SBOM request
    /// * `dependency_map` - Map of package dependencies
    ///
    /// # Returns
    /// Optional DependencyGraph if analysis was requested
    pub(super) fn analyze_dependencies_if_requested(
        &self,
        request: &SbomRequest,
        dependency_map: &std::collections::HashMap<String, Vec<String>>,
    ) -> Result<Option<DependencyGraph>> {
        if !request.include_dependency_info {
            return Ok(None);
        }

        let msgs = Messages::for_locale(self.locale);
        self.progress_reporter.report(msgs.progress_parsing_deps);

        let project_name = self
            .project_config_reader
            .read_project_name(&request.project_path)?;
        let project_package_name = PackageName::new(project_name)?;

        let graph = DependencyAnalyzer::analyze(&project_package_name, dependency_map)?;

        self.progress_reporter.report(&Messages::format(
            msgs.progress_direct_deps,
            &[&graph.direct_dependency_count().to_string()],
        ));
        self.progress_reporter.report(&Messages::format(
            msgs.progress_transitive_deps,
            &[&graph.transitive_dependency_count().to_string()],
        ));

        Ok(Some(graph))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;
    use crate::ports::outbound::GroupRoots;
    use std::collections::HashMap;

    mod tests_exclusion {
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

    mod tests_group_exclusion {
        use super::*;

        fn make_dep_graph(edges: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
            let mut map: HashMap<String, Vec<String>> = HashMap::new();
            for &(parent, deps) in edges {
                let entry = map.entry(parent.to_string()).or_default();
                for &dep in deps {
                    entry.push(dep.to_string());
                }
                for &dep in deps {
                    map.entry(dep.to_string()).or_default();
                }
            }
            map
        }

        fn make_group_roots(groups: &[(&str, &[&str])]) -> GroupRoots {
            groups
                .iter()
                .map(|&(g, roots)| (g.to_string(), roots.iter().map(|s| s.to_string()).collect()))
                .collect()
        }

        #[tokio::test]
        async fn test_empty_exclude_groups_returns_all_packages() {
            let packages = vec![
                pkg("myapp", "1.0.0"),
                pkg("requests", "2.0.0"),
                pkg("pytest", "7.0.0"),
            ];
            let deps =
                make_dep_graph(&[("myapp", &["requests"]), ("requests", &[]), ("pytest", &[])]);
            let group_roots = make_group_roots(&[("dev", &["pytest"])]);

            let use_case = UseCaseBuilder::default()
                .with_lockfile_and_deps(packages, deps)
                .with_group_roots(group_roots)
                .build();

            let response = use_case.execute(default_request()).await.unwrap();

            assert_eq!(response.enriched_packages.len(), 3);
        }

        #[tokio::test]
        async fn test_dev_only_package_excluded_via_execute() {
            let packages = vec![
                pkg("myapp", "1.0.0"),
                pkg("requests", "2.0.0"),
                pkg("pytest", "7.0.0"),
                pkg("iniconfig", "2.0.0"),
            ];
            let deps = make_dep_graph(&[
                ("myapp", &["requests"]),
                ("requests", &[]),
                ("pytest", &["iniconfig"]),
                ("iniconfig", &[]),
            ]);
            let group_roots = make_group_roots(&[("dev", &["pytest"])]);

            let use_case = UseCaseBuilder::default()
                .with_lockfile_and_deps(packages, deps)
                .with_group_roots(group_roots)
                .build();

            let request = SbomRequest::builder()
                .project_path("/test/project")
                .exclude_groups(vec!["dev".to_string()])
                .build()
                .unwrap();

            let response = use_case.execute(request).await.unwrap();

            let names: Vec<&str> = response
                .enriched_packages
                .iter()
                .map(|ep| ep.package.name())
                .collect();
            assert!(!names.contains(&"pytest"), "dev root must be excluded");
            assert!(
                !names.contains(&"iniconfig"),
                "dev transitive must be excluded"
            );
            assert!(names.contains(&"requests"));
            assert!(names.contains(&"myapp"));
        }

        #[tokio::test]
        async fn test_shared_package_retained() {
            let packages = vec![
                pkg("myapp", "1.0.0"),
                pkg("requests", "2.0.0"),
                pkg("certifi", "2024.1.1"),
                pkg("pytest", "7.0.0"),
            ];
            let deps = make_dep_graph(&[
                ("myapp", &["requests"]),
                ("requests", &["certifi"]),
                ("pytest", &["certifi"]),
                ("certifi", &[]),
            ]);
            let group_roots = make_group_roots(&[("dev", &["pytest"])]);

            let use_case = UseCaseBuilder::default()
                .with_lockfile_and_deps(packages, deps)
                .with_group_roots(group_roots)
                .build();

            let request = SbomRequest::builder()
                .project_path("/test/project")
                .exclude_groups(vec!["dev".to_string()])
                .build()
                .unwrap();

            let response = use_case.execute(request).await.unwrap();

            let names: Vec<&str> = response
                .enriched_packages
                .iter()
                .map(|ep| ep.package.name())
                .collect();
            assert!(
                names.contains(&"certifi"),
                "shared package must be retained"
            );
            assert!(!names.contains(&"pytest"), "dev-only root must be excluded");
        }

        #[tokio::test]
        async fn test_unknown_group_name_is_ignored() {
            let packages = vec![pkg("myapp", "1.0.0"), pkg("requests", "2.0.0")];
            let deps = make_dep_graph(&[("myapp", &["requests"]), ("requests", &[])]);

            let use_case = UseCaseBuilder::default()
                .with_lockfile_and_deps(packages, deps)
                .with_group_roots(HashMap::new())
                .build();

            let request = SbomRequest::builder()
                .project_path("/test/project")
                .exclude_groups(vec!["nonexistent".to_string()])
                .build()
                .unwrap();

            let response = use_case.execute(request).await.unwrap();

            assert_eq!(response.enriched_packages.len(), 2);
        }
    }
}
