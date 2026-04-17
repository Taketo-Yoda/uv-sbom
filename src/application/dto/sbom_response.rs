use crate::ports::outbound::EnrichedPackage;
use crate::sbom_generation::domain::license_policy::LicenseComplianceResult;
use crate::sbom_generation::domain::services::VulnerabilityCheckResult;
use crate::sbom_generation::domain::vulnerability::PackageVulnerabilities;
use crate::sbom_generation::domain::{DependencyGraph, SbomMetadata, UpgradeRecommendation};
use crate::shared::error::SbomError;

/// SbomResponse - Internal response DTO from SBOM generation use case
///
/// This DTO contains the rich data structures produced by the use case,
/// which adapters can then format into the appropriate output format.
#[derive(Debug, Clone)]
pub struct SbomResponse {
    /// Packages enriched with license information
    pub enriched_packages: Vec<EnrichedPackage>,
    /// Optional dependency graph (only present when requested)
    pub dependency_graph: Option<DependencyGraph>,
    /// SBOM metadata (timestamp, tool info, serial number)
    pub metadata: SbomMetadata,
    /// Optional vulnerability report (only present when CVE check is enabled)
    /// None = not checked, Some(vec) = checked (empty vec means no vulnerabilities found)
    #[allow(dead_code)] // Reserved for Issue #486: public DTO field for library consumers
    pub vulnerability_report: Option<Vec<PackageVulnerabilities>>,
    /// Whether vulnerabilities above threshold were detected
    /// Used to determine exit code for CI integration
    pub has_vulnerabilities_above_threshold: bool,
    /// Optional vulnerability check result with threshold evaluation
    /// Contains above/below threshold separation for formatting
    pub vulnerability_check_result: Option<VulnerabilityCheckResult>,
    /// Optional license compliance result (only present when license check is enabled)
    pub license_compliance_result: Option<LicenseComplianceResult>,
    /// Whether license violations were detected
    pub has_license_violations: bool,
    /// Upgrade recommendations for vulnerable transitive dependencies.
    /// Populated only when `suggest_fix` was true in the request.
    pub upgrade_recommendations: Option<Vec<UpgradeRecommendation>>,
}

impl SbomResponse {
    pub fn builder() -> SbomResponseBuilder {
        SbomResponseBuilder::new()
    }
}

pub struct SbomResponseBuilder {
    enriched_packages: Vec<EnrichedPackage>,
    dependency_graph: Option<DependencyGraph>,
    metadata: Option<SbomMetadata>,
    vulnerability_report: Option<Vec<PackageVulnerabilities>>,
    has_vulnerabilities_above_threshold: bool,
    vulnerability_check_result: Option<VulnerabilityCheckResult>,
    license_compliance_result: Option<LicenseComplianceResult>,
    has_license_violations: bool,
    upgrade_recommendations: Option<Vec<UpgradeRecommendation>>,
}

impl SbomResponseBuilder {
    pub fn new() -> Self {
        Self {
            enriched_packages: Vec::new(),
            dependency_graph: None,
            metadata: None,
            vulnerability_report: None,
            has_vulnerabilities_above_threshold: false,
            vulnerability_check_result: None,
            license_compliance_result: None,
            has_license_violations: false,
            upgrade_recommendations: None,
        }
    }

    pub fn enriched_packages(mut self, packages: Vec<EnrichedPackage>) -> Self {
        self.enriched_packages = packages;
        self
    }

    #[cfg(test)]
    pub fn add_enriched_package(mut self, package: EnrichedPackage) -> Self {
        self.enriched_packages.push(package);
        self
    }

    pub fn dependency_graph(mut self, graph: DependencyGraph) -> Self {
        self.dependency_graph = Some(graph);
        self
    }

    pub fn metadata(mut self, metadata: SbomMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn vulnerability_report(mut self, report: Vec<PackageVulnerabilities>) -> Self {
        self.vulnerability_report = Some(report);
        self
    }

    pub fn has_vulnerabilities_above_threshold(mut self, value: bool) -> Self {
        self.has_vulnerabilities_above_threshold = value;
        self
    }

    pub fn vulnerability_check_result(mut self, result: VulnerabilityCheckResult) -> Self {
        self.vulnerability_check_result = Some(result);
        self
    }

    pub fn license_compliance_result(mut self, result: LicenseComplianceResult) -> Self {
        self.license_compliance_result = Some(result);
        self
    }

    pub fn has_license_violations(mut self, value: bool) -> Self {
        self.has_license_violations = value;
        self
    }

    pub fn upgrade_recommendations(mut self, recommendations: Vec<UpgradeRecommendation>) -> Self {
        self.upgrade_recommendations = Some(recommendations);
        self
    }

    pub fn build(self) -> Result<SbomResponse, SbomError> {
        let metadata = self.metadata.ok_or_else(|| SbomError::Validation {
            message: "metadata is required".into(),
        })?;

        Ok(SbomResponse {
            enriched_packages: self.enriched_packages,
            dependency_graph: self.dependency_graph,
            metadata,
            vulnerability_report: self.vulnerability_report,
            has_vulnerabilities_above_threshold: self.has_vulnerabilities_above_threshold,
            vulnerability_check_result: self.vulnerability_check_result,
            license_compliance_result: self.license_compliance_result,
            has_license_violations: self.has_license_violations,
            upgrade_recommendations: self.upgrade_recommendations,
        })
    }
}

impl Default for SbomResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::Package;
    use crate::sbom_generation::services::SbomGenerator;

    fn create_test_enriched_package(name: &str, version: &str) -> EnrichedPackage {
        let package = Package::new(name.to_string(), version.to_string()).unwrap();
        EnrichedPackage::new(package, Some("MIT".to_string()), None)
    }

    #[test]
    fn test_builder_with_metadata_only() {
        let metadata = SbomGenerator::generate_default_metadata();
        let response = SbomResponse::builder()
            .metadata(metadata)
            .build()
            .expect("should build with metadata only");

        assert!(response.enriched_packages.is_empty());
        assert!(response.dependency_graph.is_none());
        assert!(response.vulnerability_report.is_none());
        assert!(!response.has_vulnerabilities_above_threshold);
        assert!(response.vulnerability_check_result.is_none());
        assert!(response.license_compliance_result.is_none());
        assert!(!response.has_license_violations);
    }

    #[test]
    fn test_builder_fails_without_metadata() {
        let result = SbomResponse::builder().build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("metadata is required"));
    }

    #[test]
    fn test_builder_with_enriched_packages() {
        let response = SbomResponse::builder()
            .add_enriched_package(create_test_enriched_package("requests", "2.31.0"))
            .add_enriched_package(create_test_enriched_package("certifi", "2024.2.2"))
            .metadata(SbomGenerator::generate_default_metadata())
            .build()
            .expect("should build with packages");

        assert_eq!(response.enriched_packages.len(), 2);
    }

    #[test]
    fn test_builder_enriched_packages_bulk() {
        let packages = vec![
            create_test_enriched_package("pkg1", "1.0.0"),
            create_test_enriched_package("pkg2", "2.0.0"),
        ];

        let response = SbomResponse::builder()
            .enriched_packages(packages)
            .metadata(SbomGenerator::generate_default_metadata())
            .build()
            .expect("should build with bulk packages");

        assert_eq!(response.enriched_packages.len(), 2);
    }

    #[test]
    fn test_builder_with_vulnerability_flags() {
        let response = SbomResponse::builder()
            .metadata(SbomGenerator::generate_default_metadata())
            .has_vulnerabilities_above_threshold(true)
            .has_license_violations(true)
            .build()
            .expect("should build with flags");

        assert!(response.has_vulnerabilities_above_threshold);
        assert!(response.has_license_violations);
    }

    #[test]
    fn test_builder_default() {
        let builder = SbomResponseBuilder::default();
        let result = builder
            .metadata(SbomGenerator::generate_default_metadata())
            .build();
        assert!(result.is_ok());
    }
}
