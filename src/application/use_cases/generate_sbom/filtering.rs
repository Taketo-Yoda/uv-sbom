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
