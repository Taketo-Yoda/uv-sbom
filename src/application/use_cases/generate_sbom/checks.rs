use super::GenerateSbomUseCase;
use crate::application::dto::SbomRequest;
use crate::application::read_models::abandoned_package::{
    AbandonedPackageView, AbandonedPackagesReport,
};
use crate::application::read_models::non_pypi_package::{
    NonPyPiPackageView, NonPyPiPackagesReport,
};
use crate::application::read_models::python_compatibility::PythonCompatibilityReport;
use crate::application::use_cases::{
    CheckAbandonedPackagesUseCase, CheckPythonCompatibilityUseCase, CheckVulnerabilitiesUseCase,
    FetchLicensesUseCase,
};
use crate::i18n::Messages;
use crate::ports::outbound::{
    LicenseRepository, LockfileReader, MaintenanceRepository, ProgressReporter,
    ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
};
use crate::sbom_generation::domain::license_policy::LicenseComplianceResult;
use crate::sbom_generation::domain::services::{LicenseComplianceChecker, ThresholdConfig};
use crate::sbom_generation::domain::{DependencyGraph, EnrichedPackage, Package, UvLockSimulator};
use crate::shared::Result;
use chrono::Utc;
use std::cmp::Reverse;
use std::collections::HashSet;

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
    /// Checks for abandoned packages if `check_abandoned` is enabled.
    ///
    /// Returns `None` when the check is disabled or no maintenance repository is configured.
    /// When `dependency_graph` is `None` (e.g. JSON output without dep analysis),
    /// `is_direct` defaults to `false` for all packages — consistent with the existing
    /// pattern for the resolution guide.
    pub(super) async fn check_abandoned_if_requested(
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
        let direct_names = Self::resolve_direct_names(dependency_graph);

        let threshold = request.abandoned_threshold_days as i64;
        let mut abandoned_packages: Vec<AbandonedPackageView> = results
            .into_iter()
            .filter_map(|(pkg, info)| {
                // Packages with no recorded release date are excluded: their
                // maintenance status cannot be determined, so we do not classify
                // them as abandoned.
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

    /// Detects packages sourced from non-PyPI origins when `check_non_pypi` is enabled.
    ///
    /// When `dependency_graph` is `None` (e.g. non-Markdown output without dep analysis),
    /// `is_direct` defaults to `false` for all packages — consistent with the existing
    /// pattern in `check_abandoned_if_requested`.
    pub(super) fn check_non_pypi_if_requested(
        &self,
        request: &SbomRequest,
        packages: &[Package],
        dependency_graph: Option<&DependencyGraph>,
    ) -> Result<Option<NonPyPiPackagesReport>> {
        if !request.check_non_pypi {
            return Ok(None);
        }

        let source_map = self
            .lockfile_reader
            .read_and_parse_package_sources(&request.project_path)?;

        let direct_names = Self::resolve_direct_names(dependency_graph);

        let mut views: Vec<NonPyPiPackageView> = packages
            .iter()
            .filter_map(|pkg| {
                let kind = source_map.get(pkg.name())?;
                if !kind.is_non_pypi_external() {
                    return None;
                }
                Some(NonPyPiPackageView {
                    name: pkg.name().to_string(),
                    version: pkg.version().to_string(),
                    source_label: kind.label().to_string(),
                    source_location: kind.value().to_string(),
                    is_direct: direct_names.contains(pkg.name()),
                })
            })
            .collect();
        views.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(Some(NonPyPiPackagesReport { packages: views }))
    }

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

    /// Returns the set of direct dependency names from the graph.
    ///
    /// When `dependency_graph` is `None`, returns an empty set so every package
    /// is treated as transitive — consistent across all `check_*_if_requested` methods.
    fn resolve_direct_names(dependency_graph: Option<&DependencyGraph>) -> HashSet<&str> {
        dependency_graph
            .map(|g| g.direct_dependencies().iter().map(|p| p.as_str()).collect())
            .unwrap_or_default()
    }

    /// Fetches license information for packages
    ///
    /// # Arguments
    /// * `packages` - Packages to enrich with license info
    ///
    /// # Returns
    /// Vector of EnrichedPackage with license information
    pub(super) async fn fetch_license_info(
        &self,
        packages: Vec<Package>,
    ) -> Result<Vec<EnrichedPackage>> {
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
    pub(super) async fn check_vulnerabilities_if_requested(
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
    pub(super) fn build_threshold_config(request: &SbomRequest) -> ThresholdConfig {
        match (&request.severity_threshold, &request.cvss_threshold) {
            (Some(severity), None) => ThresholdConfig::Severity(*severity),
            (None, Some(cvss)) => ThresholdConfig::Cvss(*cvss),
            // Both None or unreachable (clap group prevents both being set)
            _ => ThresholdConfig::None,
        }
    }

    /// Checks license compliance if requested
    pub(super) fn check_license_compliance_if_requested(
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
}
