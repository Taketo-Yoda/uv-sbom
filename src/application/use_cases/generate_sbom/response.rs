use super::GenerateSbomUseCase;
use crate::application::dto::SbomResponse;
use crate::application::read_models::abandoned_package::AbandonedPackagesReport;
use crate::application::read_models::explain_view::ExplainView;
use crate::application::read_models::non_pypi_package::NonPyPiPackagesReport;
use crate::application::read_models::python_compatibility::PythonCompatibilityReport;
use crate::ports::outbound::{
    LicenseRepository, LockfileReader, MaintenanceRepository, ProgressReporter,
    ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
};
use crate::sbom_generation::domain::license_policy::LicenseComplianceResult;
use crate::sbom_generation::domain::services::VulnerabilityCheckResult;
use crate::sbom_generation::domain::{
    DependencyGraph, EnrichedPackage, UpgradeRecommendation, UvLockSimulator,
};
use crate::sbom_generation::services::SbomGenerator;
use crate::shared::Result;

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
    /// Builds a response for dry-run mode (validation only)
    pub(super) fn build_dry_run_response(&self) -> Result<SbomResponse> {
        self.progress_reporter
            .report_completion("Success: Configuration validated. No issues found.");
        let metadata = SbomGenerator::generate_default_metadata();
        Ok(SbomResponse::builder()
            .metadata(metadata)
            .build()
            .expect("dry-run response build should not fail"))
    }

    /// Builds the final SBOM response
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_response(
        &self,
        enriched_packages: Vec<EnrichedPackage>,
        dependency_graph: Option<DependencyGraph>,
        vulnerability_check_result: Option<VulnerabilityCheckResult>,
        license_compliance_result: Option<LicenseComplianceResult>,
        upgrade_recommendations: Option<Vec<UpgradeRecommendation>>,
        abandoned_packages_report: Option<AbandonedPackagesReport>,
        non_pypi_packages_report: Option<NonPyPiPackagesReport>,
        python_compatibility_report: Option<PythonCompatibilityReport>,
        explain_view: Option<ExplainView>,
        exclude_groups: Vec<String>,
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
            .has_license_violations(has_license_violations)
            .applied_group_filter(exclude_groups);

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
        if let Some(report) = non_pypi_packages_report {
            builder = builder.non_pypi_packages_report(report);
        }
        if let Some(report) = python_compatibility_report {
            builder = builder.python_compatibility_report(report);
        }
        if let Some(view) = explain_view {
            builder = builder.explain_view(view);
        }

        builder.build().expect("response build should not fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;

    mod tests_response {
        use super::*;

        #[test]
        fn test_build_response() {
            let use_case = UseCaseBuilder::default().build();
            let enriched_packages = vec![EnrichedPackage::new(
                pkg("test-pkg", "1.0.0"),
                Some("MIT".to_string()),
                Some("Test description".to_string()),
            )];

            let response = use_case.build_response(
                enriched_packages,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                vec![],
            );

            assert_eq!(response.enriched_packages.len(), 1);
            assert!(response.dependency_graph.is_none());
            assert!(response.vulnerability_check_result.is_none());
            assert!(!response.metadata.serial_number().is_empty());
            assert!(!response.metadata.timestamp().is_empty());
            assert!(response.explain_view.is_none());
        }

        #[test]
        fn test_build_response_with_threshold_exceeded() {
            use crate::sbom_generation::domain::vulnerability::{
                CvssScore, Severity, Vulnerability,
            };

            let use_case = UseCaseBuilder::default().build();
            let enriched_packages = vec![EnrichedPackage::new(
                pkg("test-pkg", "1.0.0"),
                Some("MIT".to_string()),
                Some("Test description".to_string()),
            )];
            let vuln = Vulnerability::new(
                "CVE-2024-001".to_string(),
                Some(CvssScore::new(9.0).unwrap()),
                Severity::Critical,
                None,
                None,
            )
            .unwrap();
            let pkg_vulns = crate::sbom_generation::domain::PackageVulnerabilities::new(
                "test-pkg".to_string(),
                "1.0.0".to_string(),
                vec![vuln],
            );
            let check_result = VulnerabilityCheckResult {
                above_threshold: vec![pkg_vulns],
                below_threshold: vec![],
                threshold_exceeded: true,
            };

            let response = use_case.build_response(
                enriched_packages,
                None,
                Some(check_result),
                None,
                None,
                None,
                None,
                None,
                None,
                vec![],
            );

            assert!(response.has_vulnerabilities_above_threshold);
            assert!(
                response
                    .vulnerability_check_result
                    .unwrap()
                    .threshold_exceeded
            );
        }

        #[test]
        fn test_build_response_with_threshold_not_exceeded() {
            use crate::sbom_generation::domain::vulnerability::{
                CvssScore, Severity, Vulnerability,
            };

            let use_case = UseCaseBuilder::default().build();
            let enriched_packages = vec![EnrichedPackage::new(
                pkg("test-pkg", "1.0.0"),
                Some("MIT".to_string()),
                Some("Test description".to_string()),
            )];
            let vuln = Vulnerability::new(
                "CVE-2024-001".to_string(),
                Some(CvssScore::new(3.0).unwrap()),
                Severity::Low,
                None,
                None,
            )
            .unwrap();
            let pkg_vulns = crate::sbom_generation::domain::PackageVulnerabilities::new(
                "test-pkg".to_string(),
                "1.0.0".to_string(),
                vec![vuln],
            );
            let check_result = VulnerabilityCheckResult {
                above_threshold: vec![],
                below_threshold: vec![pkg_vulns],
                threshold_exceeded: false,
            };

            let response = use_case.build_response(
                enriched_packages,
                None,
                Some(check_result),
                None,
                None,
                None,
                None,
                None,
                None,
                vec![],
            );

            assert!(!response.has_vulnerabilities_above_threshold);
            assert!(
                !response
                    .vulnerability_check_result
                    .unwrap()
                    .threshold_exceeded
            );
        }
    }
}
