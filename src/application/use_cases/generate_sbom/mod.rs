mod checks;
mod filtering;
mod response;
mod upgrade;

use crate::application::dto::{SbomRequest, SbomResponse};
use crate::i18n::Locale;
use crate::ports::outbound::{
    LicenseRepository, LockfileReader, MaintenanceRepository, ProgressReporter,
    ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
};
use crate::sbom_generation::domain::services::VulnerabilityChecker;
use crate::sbom_generation::domain::UvLockSimulator;
use crate::shared::Result;

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
/// * `PCREPO` - PythonCompatibilityRepository implementation (optional)
/// * `USIM` - UvLockSimulator implementation (optional)
pub struct GenerateSbomUseCase<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO = (), USIM = ()> {
    lockfile_reader: LR,
    project_config_reader: PCR,
    license_repository: LREPO,
    progress_reporter: PR,
    vulnerability_repository: Option<VREPO>,
    maintenance_repository: Option<MREPO>,
    compatibility_repository: Option<PCREPO>,
    uv_lock_simulator: Option<USIM>,
    locale: Locale,
}

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
    /// Creates a new GenerateSbomUseCase with injected dependencies
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lockfile_reader: LR,
        project_config_reader: PCR,
        license_repository: LREPO,
        progress_reporter: PR,
        vulnerability_repository: Option<VREPO>,
        maintenance_repository: Option<MREPO>,
        compatibility_repository: Option<PCREPO>,
        uv_lock_simulator: Option<USIM>,
        locale: Locale,
    ) -> Self {
        Self {
            lockfile_reader,
            project_config_reader,
            license_repository,
            progress_reporter,
            vulnerability_repository,
            maintenance_repository,
            compatibility_repository,
            uv_lock_simulator,
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

        // Step 2b: Apply group reachability filter when exclude_groups is non-empty.
        // dependency_map is borrowed (not filtered) to preserve direct/transitive classification.
        let filtered_packages =
            self.apply_group_filter(filtered_packages, &dependency_map, &request)?;

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

        // Step 10: Non-PyPI source detection if requested
        let non_pypi_packages_report = self.check_non_pypi_if_requested(
            &request,
            &filtered_packages,
            dependency_graph.as_ref(),
        )?;

        // Step 11: Python version compatibility check if requested
        let python_compatibility_report = self
            .check_python_compatibility_if_requested(
                &request,
                &filtered_packages,
                dependency_graph.as_ref(),
            )
            .await?;

        // Step 12: Build and return response
        Ok(self.build_response(
            enriched_packages,
            dependency_graph,
            vulnerability_check_result,
            license_compliance_result,
            upgrade_recommendations,
            abandoned_packages_report,
            non_pypi_packages_report,
            python_compatibility_report,
            request.exclude_groups.clone(),
        ))
    }
}

#[cfg(test)]
mod tests;
