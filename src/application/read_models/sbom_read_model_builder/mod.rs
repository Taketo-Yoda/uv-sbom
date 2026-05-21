//! Builder for constructing SbomReadModel from domain objects
//!
//! This module provides the builder that transforms domain objects into
//! the query-optimized read model.

mod component_builder;
mod dependency_builder;
mod license_compliance_builder;
mod metadata_builder;
mod resolution_guide_builder;
mod upgrade_recommendation_builder;
mod vulnerability_builder;

use super::abandoned_package::AbandonedPackagesReport;
use super::resolution_guide_view::ResolutionGuideView;
use super::sbom_read_model::SbomReadModel;
use crate::ports::outbound::EnrichedPackage;
use crate::sbom_generation::domain::license_policy::LicenseComplianceResult;
use crate::sbom_generation::domain::services::{ResolutionAnalyzer, VulnerabilityCheckResult};
use crate::sbom_generation::domain::vulnerability::PackageVulnerabilities;
use crate::sbom_generation::domain::{DependencyGraph, SbomMetadata, UpgradeRecommendation};

/// Builder for constructing SbomReadModel from domain objects
///
/// This builder transforms domain objects into a query-optimized read model.
/// Initial implementation focuses on metadata and components, with dependencies
/// and vulnerabilities being handled in future iterations.
pub struct SbomReadModelBuilder;

impl SbomReadModelBuilder {
    /// Builds a SbomReadModel from domain objects with optional project metadata component
    #[allow(clippy::too_many_arguments)]
    pub fn build_with_project(
        packages: Vec<EnrichedPackage>,
        metadata: &SbomMetadata,
        dependency_graph: Option<&DependencyGraph>,
        vulnerability_result: Option<&VulnerabilityCheckResult>,
        license_compliance_result: Option<&LicenseComplianceResult>,
        project_component: Option<(&str, &str)>,
        upgrade_recommendations: Option<&[UpgradeRecommendation]>,
        abandoned_packages_report: Option<&AbandonedPackagesReport>,
    ) -> SbomReadModel {
        let metadata_view = metadata_builder::build_metadata(metadata, project_component);
        let components = component_builder::build_components(&packages, dependency_graph);

        let dependencies = dependency_graph
            .map(|graph| dependency_builder::build_dependencies(graph, &components));
        let vulnerabilities = vulnerability_result
            .map(|result| vulnerability_builder::build_vulnerabilities(result, &components));
        let license_compliance =
            license_compliance_result.map(license_compliance_builder::build_license_compliance);

        let resolution_guide = Self::build_resolution_guide_if_applicable(
            dependency_graph,
            vulnerability_result,
            &packages,
        );

        let upgrade_recommendations = upgrade_recommendations
            .map(upgrade_recommendation_builder::build_upgrade_recommendations);

        let abandoned_packages = abandoned_packages_report.cloned();

        SbomReadModel {
            metadata: metadata_view,
            components,
            dependencies,
            vulnerabilities,
            license_compliance,
            resolution_guide,
            upgrade_recommendations,
            abandoned_packages,
        }
    }

    fn build_resolution_guide_if_applicable(
        dependency_graph: Option<&DependencyGraph>,
        vulnerability_result: Option<&VulnerabilityCheckResult>,
        packages: &[EnrichedPackage],
    ) -> Option<ResolutionGuideView> {
        let (graph, vuln_result) = (dependency_graph?, vulnerability_result?);
        let all_vulns: Vec<PackageVulnerabilities> = vuln_result
            .above_threshold
            .iter()
            .chain(vuln_result.below_threshold.iter())
            .cloned()
            .collect();
        let entries = ResolutionAnalyzer::analyze(graph, &all_vulns, packages);
        if entries.is_empty() {
            None
        } else {
            Some(resolution_guide_builder::build_resolution_guide(&entries))
        }
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::ports::outbound::EnrichedPackage;
    use crate::sbom_generation::domain::resolution_guide::{IntroducedBy, ResolutionEntry};
    use crate::sbom_generation::domain::vulnerability::{
        CvssScore, PackageVulnerabilities, Severity, Vulnerability,
    };
    use crate::sbom_generation::domain::{DependencyGraph, Package, PackageName, SbomMetadata};
    use std::collections::HashMap;

    pub(crate) fn metadata() -> SbomMetadata {
        SbomMetadata::new(
            "2024-01-15T10:30:00Z".to_string(),
            "uv-sbom".to_string(),
            "0.1.0".to_string(),
            "urn:uuid:12345678-1234-1234-1234-123456789012".to_string(),
        )
    }

    pub(crate) fn package(name: &str, version: &str) -> EnrichedPackage {
        EnrichedPackage::new(
            Package::new(name.to_string(), version.to_string()).unwrap(),
            Some("MIT".to_string()),
            Some("A test package".to_string()),
        )
    }

    pub(crate) fn graph() -> DependencyGraph {
        let direct_deps = vec![PackageName::new("requests".to_string()).unwrap()];
        let transitive: HashMap<PackageName, Vec<PackageName>> = HashMap::new();
        DependencyGraph::new(direct_deps, transitive, HashMap::new())
    }

    pub(crate) fn vulnerability(id: &str, cvss: Option<f32>, severity: Severity) -> Vulnerability {
        let cvss_score = cvss.and_then(|s| CvssScore::new(s).ok());
        Vulnerability::new(id.to_string(), cvss_score, severity, None, None).unwrap()
    }

    pub(crate) fn vulnerability_with_fix(
        id: &str,
        cvss: Option<f32>,
        severity: Severity,
        fixed_version: &str,
    ) -> Vulnerability {
        let cvss_score = cvss.and_then(|s| CvssScore::new(s).ok());
        Vulnerability::new(
            id.to_string(),
            cvss_score,
            severity,
            Some(fixed_version.to_string()),
            None,
        )
        .unwrap()
    }

    pub(crate) fn package_vulnerabilities(
        name: &str,
        version: &str,
        vulnerabilities: Vec<Vulnerability>,
    ) -> PackageVulnerabilities {
        PackageVulnerabilities::new(name.to_string(), version.to_string(), vulnerabilities)
    }

    pub(crate) fn resolution_entry(
        pkg: &str,
        current: &str,
        fixed: Option<&str>,
        severity: Severity,
        cve: &str,
        introducers: &[(&str, &str)],
    ) -> ResolutionEntry {
        ResolutionEntry::new(
            pkg.to_string(),
            current.to_string(),
            fixed.map(str::to_string),
            severity,
            cve.to_string(),
            introducers
                .iter()
                .map(|(name, version)| IntroducedBy::new(name.to_string(), version.to_string()))
                .collect(),
            vec![],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::vulnerability::Severity;
    use crate::sbom_generation::domain::PackageName;
    use std::collections::HashMap;

    use super::test_helpers as th;

    #[test]
    fn test_build_full_read_model() {
        let packages = vec![
            th::package("requests", "2.31.0"),
            th::package("urllib3", "2.0.0"),
        ];
        let metadata = th::metadata();
        let graph = th::graph();

        let read_model = SbomReadModelBuilder::build_with_project(
            packages,
            &metadata,
            Some(&graph),
            None,
            None,
            None,
            None,
            None,
        );

        assert_eq!(read_model.metadata.tool_name, "uv-sbom");
        assert_eq!(read_model.components.len(), 2);
        assert!(read_model.dependencies.is_some());
        let deps = read_model.dependencies.unwrap();
        assert_eq!(deps.direct.len(), 1);
        assert_eq!(deps.direct[0], "requests-2.31.0");
        assert!(read_model.vulnerabilities.is_none());
    }

    #[test]
    fn test_build_with_empty_packages() {
        let packages: Vec<EnrichedPackage> = vec![];
        let metadata = th::metadata();

        let read_model = SbomReadModelBuilder::build_with_project(
            packages, &metadata, None, None, None, None, None, None,
        );

        assert!(read_model.components.is_empty());
    }

    #[test]
    fn test_build_full_read_model_with_vulnerabilities() {
        let packages = vec![th::package("requests", "2.31.0")];
        let metadata = th::metadata();

        let vuln = th::vulnerability("CVE-2024-1234", Some(9.8), Severity::Critical);
        let pkg_vuln = th::package_vulnerabilities("requests", "2.31.0", vec![vuln]);

        let vuln_result = VulnerabilityCheckResult {
            above_threshold: vec![pkg_vuln],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let read_model = SbomReadModelBuilder::build_with_project(
            packages,
            &metadata,
            None,
            Some(&vuln_result),
            None,
            None,
            None,
            None,
        );

        assert!(read_model.vulnerabilities.is_some());
        let vulns = read_model.vulnerabilities.unwrap();
        assert_eq!(vulns.actionable.len(), 1);
        assert_eq!(vulns.actionable[0].id, "CVE-2024-1234");
    }

    #[test]
    fn test_build_full_model_resolution_guide_when_both_graph_and_vulns() {
        let packages = vec![
            th::package("requests", "2.28.0"),
            th::package("urllib3", "1.26.5"),
        ];
        let metadata = th::metadata();

        let mut transitive = HashMap::new();
        transitive.insert(
            PackageName::new("requests".to_string()).unwrap(),
            vec![PackageName::new("urllib3".to_string()).unwrap()],
        );
        let graph = DependencyGraph::new(
            vec![PackageName::new("requests".to_string()).unwrap()],
            transitive,
            HashMap::new(),
        );

        let vuln = th::vulnerability("CVE-2023-43804", Some(7.5), Severity::High);
        let pkg_vuln = th::package_vulnerabilities("urllib3", "1.26.5", vec![vuln]);
        let vuln_result = VulnerabilityCheckResult {
            above_threshold: vec![pkg_vuln],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let read_model = SbomReadModelBuilder::build_with_project(
            packages,
            &metadata,
            Some(&graph),
            Some(&vuln_result),
            None,
            None,
            None,
            None,
        );

        assert!(read_model.resolution_guide.is_some());
        let guide = read_model.resolution_guide.unwrap();
        assert_eq!(guide.entries.len(), 1);
        assert_eq!(guide.entries[0].vulnerable_package, "urllib3");
        assert_eq!(guide.entries[0].introduced_by[0].package_name, "requests");
    }

    #[test]
    fn test_build_full_model_resolution_guide_none_without_graph() {
        let packages = vec![th::package("requests", "2.31.0")];
        let metadata = th::metadata();

        let vuln = th::vulnerability("CVE-2024-1234", Some(9.8), Severity::Critical);
        let pkg_vuln = th::package_vulnerabilities("requests", "2.31.0", vec![vuln]);
        let vuln_result = VulnerabilityCheckResult {
            above_threshold: vec![pkg_vuln],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let read_model = SbomReadModelBuilder::build_with_project(
            packages,
            &metadata,
            None,
            Some(&vuln_result),
            None,
            None,
            None,
            None,
        );

        assert!(read_model.resolution_guide.is_none());
    }

    #[test]
    fn test_build_full_model_resolution_guide_none_without_vulns() {
        let packages = vec![th::package("requests", "2.31.0")];
        let metadata = th::metadata();
        let graph = th::graph();

        let read_model = SbomReadModelBuilder::build_with_project(
            packages,
            &metadata,
            Some(&graph),
            None,
            None,
            None,
            None,
            None,
        );

        assert!(read_model.resolution_guide.is_none());
    }

    #[test]
    fn test_build_full_model_resolution_guide_none_when_no_transitive_vulns() {
        let packages = vec![th::package("requests", "2.31.0")];
        let metadata = th::metadata();
        let graph = th::graph(); // requests is direct

        let vuln = th::vulnerability("CVE-2024-1234", Some(9.8), Severity::Critical);
        let pkg_vuln = th::package_vulnerabilities("requests", "2.31.0", vec![vuln]);
        let vuln_result = VulnerabilityCheckResult {
            above_threshold: vec![pkg_vuln],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let read_model = SbomReadModelBuilder::build_with_project(
            packages,
            &metadata,
            Some(&graph),
            Some(&vuln_result),
            None,
            None,
            None,
            None,
        );

        // requests is a direct dep, so ResolutionAnalyzer skips it → empty → None
        assert!(read_model.resolution_guide.is_none());
    }

    #[test]
    fn test_build_with_project_includes_metadata_component() {
        let packages = vec![th::package("requests", "2.31.0")];
        let metadata = th::metadata();

        let read_model = SbomReadModelBuilder::build_with_project(
            packages,
            &metadata,
            None,
            None,
            None,
            Some(("my-project", "1.0.0")),
            None,
            None,
        );

        assert!(read_model.metadata.component.is_some());
        let component = read_model.metadata.component.unwrap();
        assert_eq!(component.name, "my-project");
        assert_eq!(component.version, "1.0.0");
    }
}
