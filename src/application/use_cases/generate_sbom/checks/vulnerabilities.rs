use super::super::GenerateSbomUseCase;
use crate::application::dto::SbomRequest;
use crate::application::use_cases::CheckVulnerabilitiesUseCase;
use crate::i18n::Messages;
use crate::ports::outbound::{
    ExploitabilityRepository, LicenseRepository, LockfileReader, MaintenanceRepository,
    ProgressReporter, ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
    YankedStatusRepository,
};
use crate::sbom_generation::domain::services::ThresholdConfig;
use crate::sbom_generation::domain::{Package, UvLockSimulator};
use crate::shared::Result;

impl<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO, USIM, EREPO, YREPO>
    GenerateSbomUseCase<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO, USIM, EREPO, YREPO>
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
    YREPO: YankedStatusRepository + Clone,
{
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
    pub(in crate::application::use_cases::generate_sbom) async fn check_vulnerabilities_if_requested(
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

    /// Enriches vulnerability results with EPSS scores and CISA KEV status.
    ///
    /// Skipped when `check_exploitability` is disabled, no exploitability repository
    /// is configured, or no vulnerabilities were found. Soft-fails: network errors
    /// produce an empty result rather than aborting the run.
    pub(in crate::application::use_cases::generate_sbom) async fn enrich_exploitability_if_requested(
        &self,
        request: &SbomRequest,
        vulnerability_report: &mut Option<
            Vec<crate::sbom_generation::domain::PackageVulnerabilities>,
        >,
    ) {
        if !request.check_exploitability {
            return;
        }
        let Some(repo) = &self.exploitability_repository else {
            return;
        };
        let Some(report) = vulnerability_report.as_mut() else {
            return;
        };

        let mut all_cve_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

        for pv in report.iter() {
            for vuln in pv.vulnerabilities() {
                let id = vuln.id().to_string();
                if id.starts_with("CVE-") {
                    all_cve_ids.insert(id);
                }
                for alias in vuln.aliases() {
                    if alias.starts_with("CVE-") {
                        all_cve_ids.insert(alias.clone());
                    }
                }
            }
        }

        if all_cve_ids.is_empty() {
            return;
        }

        let msgs = Messages::for_locale(self.locale);
        self.progress_reporter
            .report(msgs.progress_fetching_exploitability);

        let cve_ids: Vec<String> = all_cve_ids.into_iter().collect();
        let exploitability_map = match repo.fetch_exploitability(cve_ids).await {
            Ok(map) => map,
            Err(_) => return,
        };

        for pv in report.iter_mut() {
            for vuln in pv.vulnerabilities_mut() {
                if let Some(info) = exploitability_map.get(vuln.id()) {
                    vuln.set_exploitability(Some(*info));
                    continue;
                }
                for alias in vuln.aliases() {
                    if let Some(info) = exploitability_map.get(alias.as_str()) {
                        vuln.set_exploitability(Some(*info));
                        break;
                    }
                }
            }
        }
    }

    /// Builds ThresholdConfig from SbomRequest options
    ///
    /// # Arguments
    /// * `request` - The SBOM request containing threshold options
    ///
    /// # Returns
    /// ThresholdConfig based on request options
    pub(in crate::application::use_cases::generate_sbom) fn build_threshold_config(
        request: &SbomRequest,
    ) -> ThresholdConfig {
        match (&request.severity_threshold, &request.cvss_threshold) {
            (Some(severity), None) => ThresholdConfig::Severity(*severity),
            (None, Some(cvss)) => ThresholdConfig::Cvss(*cvss),
            // Both None or unreachable (clap group prevents both being set)
            _ => ThresholdConfig::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;

    mod tests_vulnerabilities {
        use super::*;

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
}
