//! Builder for constructing SbomReadModel from domain objects
//!
//! This module provides the builder that transforms domain objects into
//! the query-optimized read model.

use super::component_view::{ComponentView, LicenseView};
use super::dependency_view::DependencyView;
use super::sbom_read_model::{SbomMetadataView, SbomReadModel};
use super::vulnerability_view::{
    SeverityView, VulnerabilityReportView, VulnerabilitySummary, VulnerabilityView,
};
use crate::ports::outbound::EnrichedPackage;
use crate::sbom_generation::domain::services::VulnerabilityCheckResult;
use crate::sbom_generation::domain::vulnerability::{
    PackageVulnerabilities, Severity, Vulnerability,
};
use crate::sbom_generation::domain::{DependencyGraph, SbomMetadata};
use std::collections::{HashMap, HashSet};

/// Builder for constructing SbomReadModel from domain objects
///
/// This builder transforms domain objects into a query-optimized read model.
/// Initial implementation focuses on metadata and components, with dependencies
/// and vulnerabilities being handled in future iterations.
#[allow(dead_code)]
pub struct SbomReadModelBuilder;

#[allow(dead_code)]
impl SbomReadModelBuilder {
    /// Builds a SbomReadModel from domain objects
    ///
    /// # Arguments
    /// * `packages` - List of enriched packages with license information
    /// * `metadata` - SBOM metadata (timestamp, tool info, serial number)
    /// * `dependency_graph` - Optional dependency graph for determining direct dependencies
    /// * `_vulnerability_result` - Optional vulnerability check result (reserved for future use)
    ///
    /// # Returns
    /// A fully constructed SbomReadModel
    pub fn build(
        packages: Vec<EnrichedPackage>,
        metadata: &SbomMetadata,
        dependency_graph: Option<&DependencyGraph>,
        vulnerability_result: Option<&VulnerabilityCheckResult>,
    ) -> SbomReadModel {
        let metadata_view = Self::build_metadata(metadata);
        let components = Self::build_components(&packages, dependency_graph);

        let dependencies =
            dependency_graph.map(|graph| Self::build_dependencies(graph, &components));
        let vulnerabilities =
            vulnerability_result.map(|result| Self::build_vulnerabilities(result, &components));

        SbomReadModel {
            metadata: metadata_view,
            components,
            dependencies,
            vulnerabilities,
        }
    }

    /// Converts domain metadata to view representation
    fn build_metadata(metadata: &SbomMetadata) -> SbomMetadataView {
        SbomMetadataView {
            timestamp: metadata.timestamp().to_string(),
            tool_name: metadata.tool_name().to_string(),
            tool_version: metadata.tool_version().to_string(),
            serial_number: metadata.serial_number().to_string(),
        }
    }

    /// Converts enriched packages to component views
    ///
    /// Generates bom-ref and purl for each package, and determines
    /// whether it is a direct dependency based on the dependency graph.
    fn build_components(
        packages: &[EnrichedPackage],
        graph: Option<&DependencyGraph>,
    ) -> Vec<ComponentView> {
        packages
            .iter()
            .map(|enriched| {
                let name = enriched.package.name();
                let version = enriched.package.version();

                let bom_ref = format!("{}-{}", name, version);
                let purl = format!("pkg:pypi/{}@{}", name, version);

                let is_direct = graph
                    .map(|g| {
                        g.direct_dependencies()
                            .iter()
                            .any(|dep| dep.as_str() == name)
                    })
                    .unwrap_or(false);

                let license = enriched.license.as_ref().map(|license_str| LicenseView {
                    spdx_id: Some(license_str.clone()),
                    name: license_str.clone(),
                    url: None,
                });

                ComponentView {
                    bom_ref,
                    name: name.to_string(),
                    version: version.to_string(),
                    purl,
                    license,
                    description: enriched.description.clone(),
                    sha256_hash: None,
                    is_direct_dependency: is_direct,
                }
            })
            .collect()
    }

    /// Builds dependency view from dependency graph
    ///
    /// Maps direct dependencies to bom-refs and builds transitive dependency map.
    fn build_dependencies(graph: &DependencyGraph, components: &[ComponentView]) -> DependencyView {
        // Create a lookup map from package name to bom-ref
        let name_to_bom_ref: HashMap<&str, &str> = components
            .iter()
            .map(|c| (c.name.as_str(), c.bom_ref.as_str()))
            .collect();

        // Map direct dependencies to bom-refs
        let direct: Vec<String> = graph
            .direct_dependencies()
            .iter()
            .filter_map(|dep| name_to_bom_ref.get(dep.as_str()).map(|s| s.to_string()))
            .collect();

        // Build transitive dependency map
        let transitive: HashMap<String, Vec<String>> = graph
            .transitive_dependencies()
            .iter()
            .filter_map(|(parent, children)| {
                let parent_bom_ref = name_to_bom_ref.get(parent.as_str())?;
                let child_bom_refs: Vec<String> = children
                    .iter()
                    .filter_map(|child| name_to_bom_ref.get(child.as_str()).map(|s| s.to_string()))
                    .collect();
                if child_bom_refs.is_empty() {
                    None
                } else {
                    Some((parent_bom_ref.to_string(), child_bom_refs))
                }
            })
            .collect();

        DependencyView { direct, transitive }
    }

    /// Builds vulnerability report view from vulnerability check result
    ///
    /// Converts above_threshold to actionable and below_threshold to informational.
    /// Uses existing VulnerabilityCheckResult semantic methods.
    fn build_vulnerabilities(
        result: &VulnerabilityCheckResult,
        components: &[ComponentView],
    ) -> VulnerabilityReportView {
        // Convert above_threshold to actionable vulnerabilities
        let actionable: Vec<VulnerabilityView> = result
            .above_threshold
            .iter()
            .flat_map(|pkg| Self::build_vulnerability_views_for_package(pkg, components))
            .collect();

        // Convert below_threshold to informational vulnerabilities
        let informational: Vec<VulnerabilityView> = result
            .below_threshold
            .iter()
            .flat_map(|pkg| Self::build_vulnerability_views_for_package(pkg, components))
            .collect();

        // Calculate unique affected packages
        let affected_packages: HashSet<&str> = result
            .above_threshold
            .iter()
            .chain(result.below_threshold.iter())
            .map(|pkg| pkg.package_name())
            .collect();

        let summary = VulnerabilitySummary {
            total_count: result.actionable_count() + result.informational_count(),
            actionable_count: result.actionable_count(),
            informational_count: result.informational_count(),
            affected_package_count: affected_packages.len(),
        };

        VulnerabilityReportView {
            actionable,
            informational,
            threshold_exceeded: result.threshold_exceeded,
            summary,
        }
    }

    /// Builds vulnerability views for all vulnerabilities in a package
    fn build_vulnerability_views_for_package(
        package: &PackageVulnerabilities,
        components: &[ComponentView],
    ) -> Vec<VulnerabilityView> {
        package
            .vulnerabilities()
            .iter()
            .map(|vuln| Self::build_vulnerability_view(vuln, package, components))
            .collect()
    }

    /// Converts domain vulnerability to view
    fn build_vulnerability_view(
        vuln: &Vulnerability,
        package: &PackageVulnerabilities,
        components: &[ComponentView],
    ) -> VulnerabilityView {
        // Find the component bom-ref for this package
        let component = components
            .iter()
            .find(|c| c.name == package.package_name() && c.version == package.current_version());

        let affected_component = component
            .map(|c| c.bom_ref.clone())
            .unwrap_or_else(|| format!("{}-{}", package.package_name(), package.current_version()));

        // Generate vulnerability bom-ref
        let bom_ref = format!("{}-{}", vuln.id(), affected_component);

        VulnerabilityView {
            bom_ref,
            id: vuln.id().to_string(),
            affected_component,
            affected_component_name: package.package_name().to_string(),
            affected_version: package.current_version().to_string(),
            cvss_score: vuln.cvss_score().map(|s| s.value()),
            cvss_vector: None, // OSV API doesn't provide vector in our current implementation
            severity: Self::map_severity(&vuln.severity()),
            fixed_version: vuln.fixed_version().map(|s| s.to_string()),
            description: None, // Summary is not exposed in Vulnerability, could be added later
            source_url: None,  // Not available in current domain model
        }
    }

    /// Converts domain Severity to SeverityView
    fn map_severity(severity: &Severity) -> SeverityView {
        match severity {
            Severity::Critical => SeverityView::Critical,
            Severity::High => SeverityView::High,
            Severity::Medium => SeverityView::Medium,
            Severity::Low => SeverityView::Low,
            Severity::None => SeverityView::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::vulnerability::CvssScore;
    use crate::sbom_generation::domain::{Package, PackageName};

    fn create_test_metadata() -> SbomMetadata {
        SbomMetadata::new(
            "2024-01-15T10:30:00Z".to_string(),
            "uv-sbom".to_string(),
            "0.1.0".to_string(),
            "urn:uuid:12345678-1234-1234-1234-123456789012".to_string(),
        )
    }

    fn create_test_package(name: &str, version: &str) -> EnrichedPackage {
        EnrichedPackage::new(
            Package::new(name.to_string(), version.to_string()).unwrap(),
            Some("MIT".to_string()),
            Some("A test package".to_string()),
        )
    }

    fn create_test_graph() -> DependencyGraph {
        let direct_deps = vec![PackageName::new("requests".to_string()).unwrap()];
        let transitive: HashMap<PackageName, Vec<PackageName>> = HashMap::new();
        DependencyGraph::new(direct_deps, transitive)
    }

    #[test]
    fn test_build_metadata() {
        let metadata = create_test_metadata();
        let view = SbomReadModelBuilder::build_metadata(&metadata);

        assert_eq!(view.timestamp, "2024-01-15T10:30:00Z");
        assert_eq!(view.tool_name, "uv-sbom");
        assert_eq!(view.tool_version, "0.1.0");
        assert_eq!(
            view.serial_number,
            "urn:uuid:12345678-1234-1234-1234-123456789012"
        );
    }

    #[test]
    fn test_build_components_generates_bom_ref() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let components = SbomReadModelBuilder::build_components(&packages, None);

        assert_eq!(components.len(), 1);
        assert_eq!(components[0].bom_ref, "requests-2.31.0");
    }

    #[test]
    fn test_build_components_generates_purl() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let components = SbomReadModelBuilder::build_components(&packages, None);

        assert_eq!(components[0].purl, "pkg:pypi/requests@2.31.0");
    }

    #[test]
    fn test_build_components_with_license() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let components = SbomReadModelBuilder::build_components(&packages, None);

        let license = components[0].license.as_ref().unwrap();
        assert_eq!(license.name, "MIT");
        assert_eq!(license.spdx_id, Some("MIT".to_string()));
    }

    #[test]
    fn test_build_components_with_description() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let components = SbomReadModelBuilder::build_components(&packages, None);

        assert_eq!(
            components[0].description,
            Some("A test package".to_string())
        );
    }

    #[test]
    fn test_build_components_is_direct_dependency_with_graph() {
        let packages = vec![
            create_test_package("requests", "2.31.0"),
            create_test_package("urllib3", "2.0.0"),
        ];
        let graph = create_test_graph();
        let components = SbomReadModelBuilder::build_components(&packages, Some(&graph));

        // requests is in direct_dependencies
        let requests = components.iter().find(|c| c.name == "requests").unwrap();
        assert!(requests.is_direct_dependency);

        // urllib3 is not in direct_dependencies
        let urllib3 = components.iter().find(|c| c.name == "urllib3").unwrap();
        assert!(!urllib3.is_direct_dependency);
    }

    #[test]
    fn test_build_components_is_direct_dependency_without_graph() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let components = SbomReadModelBuilder::build_components(&packages, None);

        // Without graph, all packages default to not direct
        assert!(!components[0].is_direct_dependency);
    }

    #[test]
    fn test_build_full_read_model() {
        let packages = vec![
            create_test_package("requests", "2.31.0"),
            create_test_package("urllib3", "2.0.0"),
        ];
        let metadata = create_test_metadata();
        let graph = create_test_graph();

        let read_model = SbomReadModelBuilder::build(packages, &metadata, Some(&graph), None);

        // Check metadata
        assert_eq!(read_model.metadata.tool_name, "uv-sbom");

        // Check components
        assert_eq!(read_model.components.len(), 2);

        // Check dependencies are built when graph is provided
        assert!(read_model.dependencies.is_some());
        let deps = read_model.dependencies.unwrap();
        assert_eq!(deps.direct.len(), 1);
        assert_eq!(deps.direct[0], "requests-2.31.0");

        // Check vulnerabilities are None when not provided
        assert!(read_model.vulnerabilities.is_none());
    }

    #[test]
    fn test_build_with_empty_packages() {
        let packages: Vec<EnrichedPackage> = vec![];
        let metadata = create_test_metadata();

        let read_model = SbomReadModelBuilder::build(packages, &metadata, None, None);

        assert!(read_model.components.is_empty());
    }

    #[test]
    fn test_build_components_without_license() {
        let package = EnrichedPackage::new(
            Package::new("requests".to_string(), "2.31.0".to_string()).unwrap(),
            None,
            None,
        );
        let components = SbomReadModelBuilder::build_components(&[package], None);

        assert!(components[0].license.is_none());
        assert!(components[0].description.is_none());
    }

    // Tests for build_dependencies

    #[test]
    fn test_build_dependencies_maps_direct_to_bom_refs() {
        let packages = vec![
            create_test_package("requests", "2.31.0"),
            create_test_package("urllib3", "2.0.0"),
        ];
        let components = SbomReadModelBuilder::build_components(&packages, None);

        let direct_deps = vec![
            PackageName::new("requests".to_string()).unwrap(),
            PackageName::new("urllib3".to_string()).unwrap(),
        ];
        let graph = DependencyGraph::new(direct_deps, HashMap::new());

        let deps = SbomReadModelBuilder::build_dependencies(&graph, &components);

        assert_eq!(deps.direct.len(), 2);
        assert!(deps.direct.contains(&"requests-2.31.0".to_string()));
        assert!(deps.direct.contains(&"urllib3-2.0.0".to_string()));
    }

    #[test]
    fn test_build_dependencies_builds_transitive_map() {
        let packages = vec![
            create_test_package("requests", "2.31.0"),
            create_test_package("urllib3", "2.0.0"),
            create_test_package("certifi", "2023.7.22"),
        ];
        let components = SbomReadModelBuilder::build_components(&packages, None);

        let direct_deps = vec![PackageName::new("requests".to_string()).unwrap()];
        let mut transitive = HashMap::new();
        transitive.insert(
            PackageName::new("requests".to_string()).unwrap(),
            vec![
                PackageName::new("urllib3".to_string()).unwrap(),
                PackageName::new("certifi".to_string()).unwrap(),
            ],
        );
        let graph = DependencyGraph::new(direct_deps, transitive);

        let deps = SbomReadModelBuilder::build_dependencies(&graph, &components);

        assert_eq!(deps.direct.len(), 1);
        assert!(deps.transitive.contains_key("requests-2.31.0"));
        let requests_deps = deps.transitive.get("requests-2.31.0").unwrap();
        assert_eq!(requests_deps.len(), 2);
        assert!(requests_deps.contains(&"urllib3-2.0.0".to_string()));
        assert!(requests_deps.contains(&"certifi-2023.7.22".to_string()));
    }

    #[test]
    fn test_build_dependencies_filters_unknown_packages() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let components = SbomReadModelBuilder::build_components(&packages, None);

        // unknown-pkg is not in components
        let direct_deps = vec![
            PackageName::new("requests".to_string()).unwrap(),
            PackageName::new("unknown-pkg".to_string()).unwrap(),
        ];
        let graph = DependencyGraph::new(direct_deps, HashMap::new());

        let deps = SbomReadModelBuilder::build_dependencies(&graph, &components);

        // Only requests should be included
        assert_eq!(deps.direct.len(), 1);
        assert!(deps.direct.contains(&"requests-2.31.0".to_string()));
    }

    #[test]
    fn test_build_dependencies_empty_graph() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let components = SbomReadModelBuilder::build_components(&packages, None);
        let graph = DependencyGraph::new(vec![], HashMap::new());

        let deps = SbomReadModelBuilder::build_dependencies(&graph, &components);

        assert!(deps.direct.is_empty());
        assert!(deps.transitive.is_empty());
    }

    // Tests for map_severity

    #[test]
    fn test_map_severity_all_levels() {
        assert_eq!(
            SbomReadModelBuilder::map_severity(&Severity::Critical),
            SeverityView::Critical
        );
        assert_eq!(
            SbomReadModelBuilder::map_severity(&Severity::High),
            SeverityView::High
        );
        assert_eq!(
            SbomReadModelBuilder::map_severity(&Severity::Medium),
            SeverityView::Medium
        );
        assert_eq!(
            SbomReadModelBuilder::map_severity(&Severity::Low),
            SeverityView::Low
        );
        assert_eq!(
            SbomReadModelBuilder::map_severity(&Severity::None),
            SeverityView::None
        );
    }

    // Helper functions for vulnerability tests

    fn create_vulnerability(id: &str, cvss: Option<f32>, severity: Severity) -> Vulnerability {
        let cvss_score = cvss.and_then(|s| CvssScore::new(s).ok());
        Vulnerability::new(id.to_string(), cvss_score, severity, None, None).unwrap()
    }

    fn create_vulnerability_with_fix(
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

    fn create_package_vulnerabilities(
        name: &str,
        version: &str,
        vulnerabilities: Vec<Vulnerability>,
    ) -> PackageVulnerabilities {
        PackageVulnerabilities::new(name.to_string(), version.to_string(), vulnerabilities)
    }

    // Tests for build_vulnerability_view

    #[test]
    fn test_build_vulnerability_view_basic() {
        let vuln = create_vulnerability("CVE-2024-1234", Some(9.8), Severity::Critical);
        let pkg = create_package_vulnerabilities("requests", "2.31.0", vec![vuln.clone()]);
        let components = vec![ComponentView {
            bom_ref: "requests-2.31.0".to_string(),
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            purl: "pkg:pypi/requests@2.31.0".to_string(),
            license: None,
            description: None,
            sha256_hash: None,
            is_direct_dependency: true,
        }];

        let view = SbomReadModelBuilder::build_vulnerability_view(&vuln, &pkg, &components);

        assert_eq!(view.id, "CVE-2024-1234");
        assert_eq!(view.affected_component, "requests-2.31.0");
        assert_eq!(view.affected_component_name, "requests");
        assert_eq!(view.affected_version, "2.31.0");
        assert_eq!(view.cvss_score, Some(9.8));
        assert_eq!(view.severity, SeverityView::Critical);
        assert_eq!(view.bom_ref, "CVE-2024-1234-requests-2.31.0");
    }

    #[test]
    fn test_build_vulnerability_view_with_fixed_version() {
        let vuln =
            create_vulnerability_with_fix("CVE-2024-5678", Some(7.5), Severity::High, "3.0.0");
        let pkg = create_package_vulnerabilities("requests", "2.31.0", vec![vuln.clone()]);
        let components = vec![];

        let view = SbomReadModelBuilder::build_vulnerability_view(&vuln, &pkg, &components);

        assert_eq!(view.fixed_version, Some("3.0.0".to_string()));
    }

    #[test]
    fn test_build_vulnerability_view_without_cvss() {
        let vuln = create_vulnerability("GHSA-xxxx-yyyy-zzzz", None, Severity::High);
        let pkg = create_package_vulnerabilities("requests", "2.31.0", vec![vuln.clone()]);
        let components = vec![];

        let view = SbomReadModelBuilder::build_vulnerability_view(&vuln, &pkg, &components);

        assert_eq!(view.cvss_score, None);
        assert_eq!(view.severity, SeverityView::High);
    }

    #[test]
    fn test_build_vulnerability_view_component_not_found() {
        let vuln = create_vulnerability("CVE-2024-1234", Some(9.8), Severity::Critical);
        let pkg = create_package_vulnerabilities("unknown-pkg", "1.0.0", vec![vuln.clone()]);
        let components = vec![]; // Empty components

        let view = SbomReadModelBuilder::build_vulnerability_view(&vuln, &pkg, &components);

        // Should generate bom-ref from package name and version
        assert_eq!(view.affected_component, "unknown-pkg-1.0.0");
        assert_eq!(view.bom_ref, "CVE-2024-1234-unknown-pkg-1.0.0");
    }

    // Tests for build_vulnerabilities

    #[test]
    fn test_build_vulnerabilities_actionable_and_informational() {
        let vuln_critical = create_vulnerability("CVE-2024-001", Some(9.8), Severity::Critical);
        let vuln_low = create_vulnerability("CVE-2024-002", Some(2.0), Severity::Low);

        let above_pkg =
            create_package_vulnerabilities("critical-pkg", "1.0.0", vec![vuln_critical]);
        let below_pkg = create_package_vulnerabilities("low-pkg", "1.0.0", vec![vuln_low]);

        let result = VulnerabilityCheckResult {
            above_threshold: vec![above_pkg],
            below_threshold: vec![below_pkg],
            threshold_exceeded: true,
        };

        let components = vec![];
        let report = SbomReadModelBuilder::build_vulnerabilities(&result, &components);

        assert_eq!(report.actionable.len(), 1);
        assert_eq!(report.actionable[0].id, "CVE-2024-001");
        assert_eq!(report.informational.len(), 1);
        assert_eq!(report.informational[0].id, "CVE-2024-002");
        assert!(report.threshold_exceeded);
    }

    #[test]
    fn test_build_vulnerabilities_summary_statistics() {
        let vuln1 = create_vulnerability("CVE-2024-001", Some(9.8), Severity::Critical);
        let vuln2 = create_vulnerability("CVE-2024-002", Some(8.0), Severity::High);
        let vuln3 = create_vulnerability("CVE-2024-003", Some(3.0), Severity::Low);

        let above_pkg = create_package_vulnerabilities("critical-pkg", "1.0.0", vec![vuln1, vuln2]);
        let below_pkg = create_package_vulnerabilities("low-pkg", "1.0.0", vec![vuln3]);

        let result = VulnerabilityCheckResult {
            above_threshold: vec![above_pkg],
            below_threshold: vec![below_pkg],
            threshold_exceeded: true,
        };

        let components = vec![];
        let report = SbomReadModelBuilder::build_vulnerabilities(&result, &components);

        assert_eq!(report.summary.total_count, 3);
        assert_eq!(report.summary.actionable_count, 2);
        assert_eq!(report.summary.informational_count, 1);
        assert_eq!(report.summary.affected_package_count, 2);
    }

    #[test]
    fn test_build_vulnerabilities_empty_result() {
        let result = VulnerabilityCheckResult {
            above_threshold: vec![],
            below_threshold: vec![],
            threshold_exceeded: false,
        };

        let components = vec![];
        let report = SbomReadModelBuilder::build_vulnerabilities(&result, &components);

        assert!(report.actionable.is_empty());
        assert!(report.informational.is_empty());
        assert!(!report.threshold_exceeded);
        assert_eq!(report.summary.total_count, 0);
        assert_eq!(report.summary.affected_package_count, 0);
    }

    #[test]
    fn test_build_vulnerabilities_multiple_vulns_per_package() {
        let vuln1 = create_vulnerability("CVE-2024-001", Some(9.8), Severity::Critical);
        let vuln2 = create_vulnerability("CVE-2024-002", Some(8.5), Severity::High);
        let vuln3 = create_vulnerability("CVE-2024-003", Some(7.0), Severity::High);

        let pkg =
            create_package_vulnerabilities("multi-vuln-pkg", "1.0.0", vec![vuln1, vuln2, vuln3]);

        let result = VulnerabilityCheckResult {
            above_threshold: vec![pkg],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let components = vec![];
        let report = SbomReadModelBuilder::build_vulnerabilities(&result, &components);

        assert_eq!(report.actionable.len(), 3);
        // All should reference the same package
        for vuln_view in &report.actionable {
            assert_eq!(vuln_view.affected_component_name, "multi-vuln-pkg");
            assert_eq!(vuln_view.affected_version, "1.0.0");
        }
    }

    #[test]
    fn test_build_full_read_model_with_vulnerabilities() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let metadata = create_test_metadata();

        let vuln = create_vulnerability("CVE-2024-1234", Some(9.8), Severity::Critical);
        let pkg_vuln = create_package_vulnerabilities("requests", "2.31.0", vec![vuln]);

        let vuln_result = VulnerabilityCheckResult {
            above_threshold: vec![pkg_vuln],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let read_model = SbomReadModelBuilder::build(packages, &metadata, None, Some(&vuln_result));

        assert!(read_model.vulnerabilities.is_some());
        let vulns = read_model.vulnerabilities.unwrap();
        assert_eq!(vulns.actionable.len(), 1);
        assert_eq!(vulns.actionable[0].id, "CVE-2024-1234");
        assert!(vulns.threshold_exceeded);
    }
}
