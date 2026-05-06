use crate::adapters::outbound::uv::UvLockAdapter;
use crate::application::dto::{SbomRequest, SbomResponse};
use crate::application::read_models::abandoned_package::{
    AbandonedPackageView, AbandonedPackagesReport,
};
use crate::application::use_cases::{
    CheckAbandonedPackagesUseCase, CheckVulnerabilitiesUseCase, FetchLicensesUseCase,
};
use crate::i18n::{Locale, Messages};
use crate::ports::outbound::{
    EnrichedPackage, LicenseRepository, LockfileReader, MaintenanceRepository, ProgressReporter,
    ProjectConfigReader, VulnerabilityRepository,
};
use crate::sbom_generation::domain::license_policy::LicenseComplianceResult;
use crate::sbom_generation::domain::services::{
    LicenseComplianceChecker, ResolutionAnalyzer, ThresholdConfig, UpgradeAdvisor,
    VulnerabilityCheckResult, VulnerabilityChecker,
};
use crate::sbom_generation::domain::{
    DependencyGraph, Package, PackageName, UpgradeRecommendation,
};
use crate::sbom_generation::services::{DependencyAnalyzer, PackageFilter, SbomGenerator};
use crate::shared::Result;
use chrono::Utc;
use std::cmp::Reverse;
use std::collections::HashSet;

/// Type alias for package list with dependency map
/// Used to simplify complex return types and satisfy clippy::type_complexity
type PackagesWithDependencyMap = (Vec<Package>, std::collections::HashMap<String, Vec<String>>);

/// GenerateSbomUseCase - Core use case for SBOM generation
///
/// This use case orchestrates the SBOM generation workflow using
/// generic dependency injection for all infrastructure dependencies.
///
/// # Type Parameters
/// * `LR` - LockfileReader implementation
/// * `PCR` - ProjectConfigReader implementation
/// * `LREPO` - LicenseRepository implementation
/// * `PR` - ProgressReporter implementation
/// * `VREPO` - VulnerabilityRepository implementation (optional)
/// * `MREPO` - MaintenanceRepository implementation (optional)
pub struct GenerateSbomUseCase<LR, PCR, LREPO, PR, VREPO, MREPO> {
    lockfile_reader: LR,
    project_config_reader: PCR,
    license_repository: LREPO,
    progress_reporter: PR,
    vulnerability_repository: Option<VREPO>,
    maintenance_repository: Option<MREPO>,
    locale: Locale,
}

impl<LR, PCR, LREPO, PR, VREPO, MREPO> GenerateSbomUseCase<LR, PCR, LREPO, PR, VREPO, MREPO>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    LREPO: LicenseRepository + Clone,
    PR: ProgressReporter,
    VREPO: VulnerabilityRepository + Clone,
    MREPO: MaintenanceRepository + Clone,
{
    /// Creates a new GenerateSbomUseCase with injected dependencies
    pub fn new(
        lockfile_reader: LR,
        project_config_reader: PCR,
        license_repository: LREPO,
        progress_reporter: PR,
        vulnerability_repository: Option<VREPO>,
        maintenance_repository: Option<MREPO>,
        locale: Locale,
    ) -> Self {
        Self {
            lockfile_reader,
            project_config_reader,
            license_repository,
            progress_reporter,
            vulnerability_repository,
            maintenance_repository,
            locale,
        }
    }

    /// Executes the SBOM generation use case
    ///
    /// # Arguments
    /// * `request` - SBOM generation request containing project path and options
    ///
    /// # Returns
    /// SbomResponse containing enriched packages, optional dependency graph, and metadata
    pub async fn execute(&self, request: SbomRequest) -> Result<SbomResponse> {
        // Step 1: Read and parse lockfile
        let (packages, dependency_map) = self.read_and_report_lockfile(&request)?;

        // Step 2: Apply exclusion filters to packages only
        // Note: We pass dependency_map by reference to preserve it for dependency analysis.
        // The root project may be excluded from packages but we still need its entry
        // in dependency_map to correctly identify direct vs transitive dependencies.
        let filtered_packages = self.apply_exclusion_filters(packages, &request)?;

        // Early return for dry-run mode (validation only)
        if request.dry_run {
            return self.build_dry_run_response();
        }

        // Step 3: Analyze dependencies if requested
        // Use original dependency_map to preserve dependency classification even when
        // root project is excluded from the package list (fixes #206)
        let dependency_graph = self.analyze_dependencies_if_requested(&request, &dependency_map)?;

        // Step 4: Enrich packages with license information
        let enriched_packages = self.fetch_license_info(filtered_packages.clone()).await?;

        // Step 5: CVE check if requested
        let vulnerability_report = self
            .check_vulnerabilities_if_requested(&request, &filtered_packages)
            .await?;

        // Step 6: Apply threshold evaluation if vulnerabilities were found
        let vulnerability_check_result = vulnerability_report.as_ref().map(|report| {
            let threshold_config = Self::build_threshold_config(&request);
            VulnerabilityChecker::check(report.clone(), threshold_config, &request.ignore_cves)
        });

        // Step 7: License compliance check if requested
        let license_compliance_result =
            self.check_license_compliance_if_requested(&request, &enriched_packages);

        // Step 8: Upgrade advisor if requested
        let upgrade_recommendations = self
            .advise_upgrades_if_requested(
                &request,
                dependency_graph.as_ref(),
                vulnerability_report.as_deref(),
                &enriched_packages,
            )
            .await;

        // Step 9: Abandoned package check if requested
        let abandoned_packages_report = self
            .check_abandoned_if_requested(&request, &filtered_packages, dependency_graph.as_ref())
            .await?;

        // Step 10: Build and return response
        Ok(self.build_response(
            enriched_packages,
            dependency_graph,
            vulnerability_check_result,
            license_compliance_result,
            upgrade_recommendations,
            abandoned_packages_report,
        ))
    }

    /// Checks for abandoned packages if `check_abandoned` is enabled.
    ///
    /// Returns `None` when the check is disabled or no maintenance repository is configured.
    /// When `dependency_graph` is `None` (e.g. JSON output without dep analysis),
    /// `is_direct` defaults to `false` for all packages — consistent with the existing
    /// pattern for the resolution guide.
    async fn check_abandoned_if_requested(
        &self,
        request: &SbomRequest,
        packages: &[Package],
        dependency_graph: Option<&DependencyGraph>,
    ) -> Result<Option<AbandonedPackagesReport>> {
        if !request.check_abandoned {
            return Ok(None);
        }
        let Some(repo) = &self.maintenance_repository else {
            return Ok(None);
        };

        let msgs = Messages::for_locale(self.locale);
        self.progress_reporter
            .report(msgs.progress_fetching_abandoned);

        let maint_use_case = CheckAbandonedPackagesUseCase::new(repo.clone());
        let (results, errors) = maint_use_case
            .fetch_with_progress(packages.to_vec())
            .await?;

        eprintln!(); // newline after progress bar

        for (pkg_name, error_msg) in &errors {
            self.progress_reporter.report_error(&Messages::format(
                msgs.warn_abandoned_fetch_failed,
                &[pkg_name, error_msg],
            ));
        }

        let today = Utc::now().date_naive();
        let direct_names: HashSet<&str> = dependency_graph
            .map(|g| g.direct_dependencies().iter().map(|p| p.as_str()).collect())
            .unwrap_or_default();

        let threshold = request.abandoned_threshold_days as i64;
        let mut abandoned_packages: Vec<AbandonedPackageView> = results
            .into_iter()
            .filter_map(|(pkg, info)| {
                let release_date = info.last_release_date?;
                let days_inactive = (today - release_date).num_days();
                if days_inactive < threshold {
                    return None;
                }
                Some(AbandonedPackageView {
                    name: pkg.name().to_string(),
                    version: pkg.version().to_string(),
                    last_release_date: release_date,
                    days_inactive,
                    is_direct: direct_names.contains(pkg.name()),
                })
            })
            .collect();

        abandoned_packages.sort_by_key(|p| Reverse(p.days_inactive));

        let report = AbandonedPackagesReport {
            packages: abandoned_packages,
            threshold_days: request.abandoned_threshold_days,
        };

        if report.is_empty() {
            self.progress_reporter.report(&Messages::format(
                msgs.progress_abandoned_none,
                &[&report.threshold_days.to_string()],
            ));
        } else {
            self.progress_reporter.report(&Messages::format(
                msgs.progress_abandoned_found,
                &[
                    &report.total_count().to_string(),
                    &report.direct_count().to_string(),
                    &report.transitive_count().to_string(),
                    &report.threshold_days.to_string(),
                ],
            ));
        }

        Ok(Some(report))
    }

    /// Reads and parses the lockfile, reporting progress
    ///
    /// # Arguments
    /// * `request` - The SBOM request containing project path
    ///
    /// # Returns
    /// Tuple of (packages, dependency_map)
    fn read_and_report_lockfile(&self, request: &SbomRequest) -> Result<PackagesWithDependencyMap> {
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
    fn apply_exclusion_filters(
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

    /// Builds a response for dry-run mode (validation only)
    fn build_dry_run_response(&self) -> Result<SbomResponse> {
        self.progress_reporter
            .report_completion("Success: Configuration validated. No issues found.");
        let metadata = SbomGenerator::generate_default_metadata();
        Ok(SbomResponse::builder()
            .metadata(metadata)
            .build()
            .expect("dry-run response build should not fail"))
    }

    /// Analyzes dependencies if requested in the SBOM request
    ///
    /// # Arguments
    /// * `request` - The SBOM request
    /// * `dependency_map` - Map of package dependencies
    ///
    /// # Returns
    /// Optional DependencyGraph if analysis was requested
    fn analyze_dependencies_if_requested(
        &self,
        request: &SbomRequest,
        dependency_map: &std::collections::HashMap<String, Vec<String>>,
    ) -> Result<Option<crate::sbom_generation::domain::DependencyGraph>> {
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

    /// Fetches license information for packages
    ///
    /// # Arguments
    /// * `packages` - Packages to enrich with license info
    ///
    /// # Returns
    /// Vector of EnrichedPackage with license information
    async fn fetch_license_info(&self, packages: Vec<Package>) -> Result<Vec<EnrichedPackage>> {
        let msgs = Messages::for_locale(self.locale);
        self.progress_reporter
            .report(msgs.progress_fetching_license);

        let fetch_use_case = FetchLicensesUseCase::new(self.license_repository.clone());
        let (enriched, errors) = fetch_use_case.fetch_with_progress(packages).await?;

        eprintln!(); // Add newline after progress bar

        for (package_name, error_msg) in &errors {
            self.progress_reporter.report_error(&Messages::format(
                msgs.warn_license_fetch_failed,
                &[package_name, error_msg],
            ));
        }

        let (successful, total, failed) =
            FetchLicensesUseCase::<LREPO>::summarize(&enriched, &errors);
        self.progress_reporter.report_completion(&Messages::format(
            msgs.progress_license_complete,
            &[
                &successful.to_string(),
                &total.to_string(),
                &failed.to_string(),
            ],
        ));

        Ok(enriched)
    }

    /// Checks vulnerabilities if CVE check is requested
    ///
    /// This method delegates to CheckVulnerabilitiesUseCase for the actual
    /// vulnerability fetching, ensuring single source of truth for vulnerability
    /// checking logic.
    ///
    /// # Arguments
    /// * `request` - The SBOM request
    /// * `packages` - Packages to check for vulnerabilities
    ///
    /// # Returns
    /// Optional vulnerability report
    async fn check_vulnerabilities_if_requested(
        &self,
        request: &SbomRequest,
        packages: &[Package],
    ) -> Result<Option<Vec<crate::sbom_generation::domain::PackageVulnerabilities>>> {
        if !request.check_cve {
            return Ok(None);
        }

        let Some(repo) = &self.vulnerability_repository else {
            // No repository configured - skip CVE check
            return Ok(None);
        };

        // Report start of vulnerability check
        let msgs = Messages::for_locale(self.locale);
        self.progress_reporter.report(msgs.progress_fetching_vulns);

        // Delegate to CheckVulnerabilitiesUseCase for vulnerability fetching
        let vuln_use_case = CheckVulnerabilitiesUseCase::new(repo.clone());
        let vulnerabilities = vuln_use_case.check_with_progress(packages.to_vec()).await?;

        // Report completion based on results
        let (total_vulns, affected_packages) =
            CheckVulnerabilitiesUseCase::<VREPO>::summarize(&vulnerabilities);
        eprintln!(); // Add newline after progress bar
        if total_vulns > 0 {
            self.progress_reporter.report_completion(&Messages::format(
                msgs.progress_vuln_found,
                &[&total_vulns.to_string(), &affected_packages.to_string()],
            ));
        } else {
            self.progress_reporter
                .report_completion(msgs.progress_vuln_none);
        }

        // Return Some even if empty (indicates check was performed)
        Ok(Some(vulnerabilities))
    }

    /// Builds ThresholdConfig from SbomRequest options
    ///
    /// # Arguments
    /// * `request` - The SBOM request containing threshold options
    ///
    /// # Returns
    /// ThresholdConfig based on request options
    fn build_threshold_config(request: &SbomRequest) -> ThresholdConfig {
        match (&request.severity_threshold, &request.cvss_threshold) {
            (Some(severity), None) => ThresholdConfig::Severity(*severity),
            (None, Some(cvss)) => ThresholdConfig::Cvss(*cvss),
            // Both None or unreachable (clap group prevents both being set)
            _ => ThresholdConfig::None,
        }
    }

    /// Runs the UpgradeAdvisor when `suggest_fix` is true and the required context is available
    ///
    /// Returns `None` when `suggest_fix` is false (no overhead).
    /// Returns `Some(vec)` when the advisor runs, even if the vector is empty.
    async fn advise_upgrades_if_requested(
        &self,
        request: &SbomRequest,
        dependency_graph: Option<&crate::sbom_generation::domain::DependencyGraph>,
        vulnerability_report: Option<&[crate::sbom_generation::domain::PackageVulnerabilities]>,
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

        let simulator = UvLockAdapter::new();
        let recommendations =
            UpgradeAdvisor::advise(&simulator, &entries, &request.project_path).await;

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

    /// Checks license compliance if requested
    fn check_license_compliance_if_requested(
        &self,
        request: &SbomRequest,
        enriched_packages: &[EnrichedPackage],
    ) -> Option<LicenseComplianceResult> {
        if !request.check_license {
            return None;
        }
        let policy = request.license_policy.as_ref()?;

        let packages: Vec<(String, String, Option<String>)> = enriched_packages
            .iter()
            .map(|ep| {
                (
                    ep.package.name().to_string(),
                    ep.package.version().to_string(),
                    ep.license.clone(),
                )
            })
            .collect();

        let result = LicenseComplianceChecker::check(&packages, policy);

        // Report results
        let msgs = Messages::for_locale(self.locale);
        if result.has_violations() {
            self.progress_reporter.report(&Messages::format(
                msgs.progress_license_violations_found,
                &[&result.violations.len().to_string()],
            ));
        } else {
            self.progress_reporter
                .report(msgs.progress_license_no_violations);
        }

        if !result.warnings.is_empty() {
            self.progress_reporter.report(&Messages::format(
                msgs.progress_license_unknown_packages,
                &[&result.warnings.len().to_string()],
            ));
        }

        Some(result)
    }

    /// Builds the final SBOM response
    fn build_response(
        &self,
        enriched_packages: Vec<EnrichedPackage>,
        dependency_graph: Option<DependencyGraph>,
        vulnerability_check_result: Option<VulnerabilityCheckResult>,
        license_compliance_result: Option<LicenseComplianceResult>,
        upgrade_recommendations: Option<Vec<UpgradeRecommendation>>,
        abandoned_packages_report: Option<AbandonedPackagesReport>,
    ) -> SbomResponse {
        let metadata = SbomGenerator::generate_default_metadata();

        // Use threshold check result if available, otherwise check if any vulnerabilities exist
        let has_vulnerabilities_above_threshold = vulnerability_check_result
            .as_ref()
            .map(|result| result.threshold_exceeded)
            .unwrap_or(false);

        let has_license_violations = license_compliance_result
            .as_ref()
            .map(|result| result.has_violations())
            .unwrap_or(false);

        let mut builder = SbomResponse::builder()
            .enriched_packages(enriched_packages)
            .metadata(metadata)
            .has_vulnerabilities_above_threshold(has_vulnerabilities_above_threshold)
            .has_license_violations(has_license_violations);

        if let Some(graph) = dependency_graph {
            builder = builder.dependency_graph(graph);
        }
        if let Some(result) = vulnerability_check_result {
            builder = builder.vulnerability_check_result(result);
        }
        if let Some(result) = license_compliance_result {
            builder = builder.license_compliance_result(result);
        }
        if let Some(recommendations) = upgrade_recommendations {
            builder = builder.upgrade_recommendations(recommendations);
        }
        if let Some(report) = abandoned_packages_report {
            builder = builder.abandoned_packages_report(report);
        }

        builder.build().expect("response build should not fail")
    }
}

#[cfg(test)]
mod tests;
