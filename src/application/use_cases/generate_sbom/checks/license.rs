use super::super::GenerateSbomUseCase;
use crate::application::dto::SbomRequest;
use crate::application::use_cases::FetchLicensesUseCase;
use crate::i18n::Messages;
use crate::ports::outbound::{
    ExploitabilityRepository, LicenseRepository, LockfileReader, MaintenanceRepository,
    ProgressReporter, ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
};
use crate::sbom_generation::domain::license_policy::LicenseComplianceResult;
use crate::sbom_generation::domain::services::LicenseComplianceChecker;
use crate::sbom_generation::domain::{EnrichedPackage, Package, UvLockSimulator};
use crate::shared::Result;

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
    /// Fetches license information for packages
    ///
    /// # Arguments
    /// * `packages` - Packages to enrich with license info
    ///
    /// # Returns
    /// Vector of EnrichedPackage with license information
    pub(in crate::application::use_cases::generate_sbom) async fn fetch_license_info(
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

    /// Checks license compliance if requested
    pub(in crate::application::use_cases::generate_sbom) fn check_license_compliance_if_requested(
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
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;

    mod tests_license {
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
    }
}
