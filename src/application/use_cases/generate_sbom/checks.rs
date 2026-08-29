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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;

    mod tests_vulnerabilities {
        use super::*;

        #[tokio::test]
        async fn test_fetch_license_info() {
            let use_case = UseCaseBuilder::default().build();
            let packages = vec![pkg("pkg1", "1.0.0"), pkg("pkg2", "2.0.0")];

            let enriched = use_case.fetch_license_info(packages).await.unwrap();

            assert_eq!(enriched.len(), 2);
            assert!(enriched[0].license.is_some());
            assert_eq!(enriched[0].license.as_ref().unwrap(), "MIT");
        }

        #[tokio::test]
        async fn test_check_vulnerabilities_if_requested_disabled() {
            let use_case = UseCaseBuilder::default().with_vuln_repo().build();
            let packages = vec![pkg("pkg1", "1.0.0")];

            let result = use_case
                .check_vulnerabilities_if_requested(&default_request(), &packages)
                .await
                .unwrap();

            assert!(result.is_none());
        }

        #[tokio::test]
        async fn test_check_vulnerabilities_if_requested_enabled() {
            let use_case = UseCaseBuilder::default().with_vuln_repo().build();
            let packages = vec![pkg("pkg1", "1.0.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_cve(true)
                .build()
                .unwrap();

            let result = use_case
                .check_vulnerabilities_if_requested(&request, &packages)
                .await
                .unwrap();

            assert!(result.is_some());
        }

        #[test]
        fn test_build_threshold_config_none() {
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_cve(true)
                .build()
                .unwrap();

            let config = TestUseCase::build_threshold_config(&request);

            assert_eq!(config, ThresholdConfig::None);
        }

        #[test]
        fn test_build_threshold_config_severity() {
            use crate::sbom_generation::domain::vulnerability::Severity;

            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_cve(true)
                .severity_threshold_opt(Some(Severity::High))
                .build()
                .unwrap();

            let config = TestUseCase::build_threshold_config(&request);

            assert_eq!(config, ThresholdConfig::Severity(Severity::High));
        }

        #[test]
        fn test_build_threshold_config_cvss() {
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_cve(true)
                .cvss_threshold_opt(Some(7.0))
                .build()
                .unwrap();

            let config = TestUseCase::build_threshold_config(&request);

            assert_eq!(config, ThresholdConfig::Cvss(7.0));
        }
    }

    mod tests_abandoned {
        use super::*;
        use crate::application::use_cases::test_doubles::MockMaintenanceRepository;
        use crate::ports::outbound::MaintenanceInfo;
        use chrono::NaiveDate;

        #[tokio::test]
        async fn test_check_abandoned_disabled_returns_none() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();
            let packages = [pkg("requests", "2.31.0")];

            let result = use_case
                .check_abandoned_if_requested(&default_request(), &packages, None)
                .await
                .unwrap();

            assert!(result.is_none());
        }

        #[tokio::test]
        async fn test_check_abandoned_no_repo_returns_none() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();
            let packages = [pkg("requests", "2.31.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_abandoned(true)
                .build()
                .unwrap();

            let result = use_case
                .check_abandoned_if_requested(&request, &packages, None)
                .await
                .unwrap();

            assert!(result.is_none());
        }

        #[tokio::test]
        async fn test_check_abandoned_with_old_package_returns_report() {
            let old_date = NaiveDate::from_ymd_opt(2020, 1, 1).unwrap();
            let maint_repo = MockMaintenanceRepository::with_responses([Ok(MaintenanceInfo {
                last_release_date: Some(old_date),
            })]);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .with_maintenance_repo(maint_repo)
                .build();
            let packages = [pkg("requests", "2.31.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_abandoned(true)
                .abandoned_threshold_days(365)
                .build()
                .unwrap();

            let result = use_case
                .check_abandoned_if_requested(&request, &packages, None)
                .await
                .unwrap();

            assert!(result.is_some());
            let report = result.unwrap();
            assert_eq!(report.total_count(), 1);
            assert_eq!(report.packages[0].name, "requests");
            assert!(report.packages[0].days_inactive >= 365);
            assert_eq!(report.threshold_days, 365);
            assert_eq!(report.direct_count(), 0); // no graph supplied → all non-direct
            assert_eq!(report.transitive_count(), 1);
        }

        #[tokio::test]
        async fn test_check_abandoned_recent_package_produces_empty_report() {
            use chrono::Utc;
            let recent_date = Utc::now().date_naive();
            let maint_repo = MockMaintenanceRepository::with_responses([Ok(MaintenanceInfo {
                last_release_date: Some(recent_date),
            })]);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .with_maintenance_repo(maint_repo)
                .build();
            let packages = [pkg("requests", "2.31.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_abandoned(true)
                .abandoned_threshold_days(365)
                .build()
                .unwrap();

            let result = use_case
                .check_abandoned_if_requested(&request, &packages, None)
                .await
                .unwrap();

            assert!(result.is_some());
            assert!(result.unwrap().is_empty());
        }

        #[tokio::test]
        async fn test_check_abandoned_unknown_release_date_excluded() {
            let maint_repo = MockMaintenanceRepository::with_responses([Ok(MaintenanceInfo {
                last_release_date: None,
            })]);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("old-pkg", "1.0.0")])
                .with_maintenance_repo(maint_repo)
                .build();
            let packages = [pkg("old-pkg", "1.0.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_abandoned(true)
                .abandoned_threshold_days(1)
                .build()
                .unwrap();

            let result = use_case
                .check_abandoned_if_requested(&request, &packages, None)
                .await
                .unwrap();

            // Package with unknown release date is excluded from the report
            assert!(result.is_some());
            assert!(result.unwrap().is_empty());
        }

        #[tokio::test]
        async fn test_check_abandoned_sorted_by_days_inactive_descending() {
            let older_date = NaiveDate::from_ymd_opt(2018, 1, 1).unwrap();
            let newer_date = NaiveDate::from_ymd_opt(2021, 1, 1).unwrap();
            let maint_repo = MockMaintenanceRepository::with_responses([
                Ok(MaintenanceInfo {
                    last_release_date: Some(newer_date),
                }),
                Ok(MaintenanceInfo {
                    last_release_date: Some(older_date),
                }),
            ]);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("newer-pkg", "1.0.0"), pkg("older-pkg", "1.0.0")])
                .with_maintenance_repo(maint_repo)
                .build();
            let packages = [pkg("newer-pkg", "1.0.0"), pkg("older-pkg", "1.0.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_abandoned(true)
                .abandoned_threshold_days(365)
                .build()
                .unwrap();

            let result = use_case
                .check_abandoned_if_requested(&request, &packages, None)
                .await
                .unwrap();

            assert!(result.is_some());
            let report = result.unwrap();
            assert_eq!(report.total_count(), 2);
            // Sorted descending: older-pkg (more days inactive) should be first
            assert!(report.packages[0].days_inactive >= report.packages[1].days_inactive);
        }
    }

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

    // Tests for issue #206: Excluding root project preserves dependency classification
    mod tests_non_pypi {
        use super::*;
        use crate::ports::outbound::lockfile_reader::PackageSourceKind;
        use crate::ports::outbound::PackageSourceMap;

        #[test]
        fn test_check_non_pypi_disabled_returns_none() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();
            let packages = [pkg("requests", "2.31.0")];

            let result = use_case
                .check_non_pypi_if_requested(&default_request(), &packages, None)
                .unwrap();

            assert!(result.is_none());
        }

        #[test]
        fn test_check_non_pypi_empty_source_map_returns_empty_report() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();
            let packages = [pkg("requests", "2.31.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_non_pypi(true)
                .build()
                .unwrap();

            let result = use_case
                .check_non_pypi_if_requested(&request, &packages, None)
                .unwrap();

            let report = result.expect("check enabled → Some");
            assert!(report.is_empty());
        }

        #[test]
        fn test_check_non_pypi_pypi_packages_excluded() {
            let mut source_map = PackageSourceMap::new();
            source_map.insert("requests".to_string(), PackageSourceKind::PyPi);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .with_source_map(source_map)
                .build();
            let packages = [pkg("requests", "2.31.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_non_pypi(true)
                .build()
                .unwrap();

            let result = use_case
                .check_non_pypi_if_requested(&request, &packages, None)
                .unwrap()
                .expect("check enabled → Some");

            assert!(result.is_empty(), "PyPI packages must not appear in report");
        }

        #[test]
        fn test_check_non_pypi_git_package_detected() {
            let mut source_map = PackageSourceMap::new();
            source_map.insert(
                "my-lib".to_string(),
                PackageSourceKind::Git("https://github.com/user/my-lib?rev=abc123".to_string()),
            );
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("my-lib", "0.1.0")])
                .with_source_map(source_map)
                .build();
            let packages = [pkg("my-lib", "0.1.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_non_pypi(true)
                .build()
                .unwrap();

            let result = use_case
                .check_non_pypi_if_requested(&request, &packages, None)
                .unwrap()
                .expect("check enabled → Some");

            assert_eq!(result.total_count(), 1);
            let view = &result.packages[0];
            assert_eq!(view.name, "my-lib");
            assert_eq!(view.source_label, "Git");
            assert_eq!(
                view.source_location,
                "https://github.com/user/my-lib?rev=abc123"
            );
            assert!(!view.is_direct, "no graph → is_direct defaults to false");
        }

        #[test]
        fn test_check_non_pypi_is_direct_from_dependency_graph() {
            use crate::sbom_generation::domain::{DependencyGraph, PackageName};

            let mut source_map = PackageSourceMap::new();
            source_map.insert(
                "internal".to_string(),
                PackageSourceKind::PrivateRegistry(
                    "https://internal.example.com/simple".to_string(),
                ),
            );

            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("internal", "1.0.0")])
                .with_source_map(source_map)
                .build();
            let packages = [pkg("internal", "1.0.0")];

            let direct = vec![PackageName::new("internal".to_string()).unwrap()];
            let graph = DependencyGraph::new(direct, Default::default(), Default::default());

            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_non_pypi(true)
                .build()
                .unwrap();

            let result = use_case
                .check_non_pypi_if_requested(&request, &packages, Some(&graph))
                .unwrap()
                .expect("check enabled → Some");

            assert_eq!(result.direct_count(), 1);
            assert_eq!(result.transitive_count(), 0);
            assert!(result.packages[0].is_direct);
        }
    }
}
