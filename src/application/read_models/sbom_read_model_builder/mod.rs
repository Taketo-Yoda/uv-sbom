//! Builder for constructing SbomReadModel from domain objects
//!
//! This module provides the builder that transforms domain objects into
//! the query-optimized read model.

mod component_builder;
mod dependency_builder;
mod license_compliance_builder;
mod metadata_builder;
mod vulnerability_builder;

use super::resolution_guide_view::{IntroducedByView, ResolutionEntryView, ResolutionGuideView};
use super::sbom_read_model::SbomReadModel;
use super::upgrade_recommendation_view::{UpgradeEntryView, UpgradeRecommendationView};
use crate::ports::outbound::EnrichedPackage;
use crate::sbom_generation::domain::license_policy::LicenseComplianceResult;
use crate::sbom_generation::domain::resolution_guide::ResolutionEntry;
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
    /// Builds a SbomReadModel without project metadata component (backwards compatible)
    #[allow(dead_code)]
    pub fn build(
        packages: Vec<EnrichedPackage>,
        metadata: &SbomMetadata,
        dependency_graph: Option<&DependencyGraph>,
        vulnerability_result: Option<&VulnerabilityCheckResult>,
        license_compliance_result: Option<&LicenseComplianceResult>,
    ) -> SbomReadModel {
        Self::build_with_project(
            packages,
            metadata,
            dependency_graph,
            vulnerability_result,
            license_compliance_result,
            None,
            None,
        )
    }

    /// Builds a SbomReadModel from domain objects with optional project metadata component
    pub fn build_with_project(
        packages: Vec<EnrichedPackage>,
        metadata: &SbomMetadata,
        dependency_graph: Option<&DependencyGraph>,
        vulnerability_result: Option<&VulnerabilityCheckResult>,
        license_compliance_result: Option<&LicenseComplianceResult>,
        project_component: Option<(&str, &str)>,
        upgrade_recommendations: Option<&[UpgradeRecommendation]>,
    ) -> SbomReadModel {
        let metadata_view = metadata_builder::build_metadata(metadata, project_component);
        let components = component_builder::build_components(&packages, dependency_graph);

        let dependencies = dependency_graph
            .map(|graph| dependency_builder::build_dependencies(graph, &components));
        let vulnerabilities = vulnerability_result
            .map(|result| vulnerability_builder::build_vulnerabilities(result, &components));
        let license_compliance =
            license_compliance_result.map(license_compliance_builder::build_license_compliance);

        // Build resolution guide only when BOTH dependency graph and vulnerability data exist
        let resolution_guide = match (dependency_graph, vulnerability_result) {
            (Some(graph), Some(vuln_result)) => {
                let all_vulns: Vec<PackageVulnerabilities> = vuln_result
                    .above_threshold
                    .iter()
                    .chain(vuln_result.below_threshold.iter())
                    .cloned()
                    .collect();
                let entries = ResolutionAnalyzer::analyze(graph, &all_vulns, &packages);
                if entries.is_empty() {
                    None
                } else {
                    Some(Self::build_resolution_guide(&entries))
                }
            }
            _ => None,
        };

        let upgrade_recommendations =
            upgrade_recommendations.map(Self::build_upgrade_recommendations);

        SbomReadModel {
            metadata: metadata_view,
            components,
            dependencies,
            vulnerabilities,
            license_compliance,
            resolution_guide,
            upgrade_recommendations,
        }
    }

    /// Builds resolution guide view from domain resolution entries
    ///
    /// Converts domain `ResolutionEntry` values into view-optimized
    /// `ResolutionEntryView` structs.
    fn build_resolution_guide(entries: &[ResolutionEntry]) -> ResolutionGuideView {
        let entry_views: Vec<ResolutionEntryView> = entries
            .iter()
            .map(Self::build_resolution_entry_view)
            .collect();

        ResolutionGuideView {
            entries: entry_views,
        }
    }

    /// Maps a slice of domain UpgradeRecommendation to an UpgradeRecommendationView
    fn build_upgrade_recommendations(
        recommendations: &[UpgradeRecommendation],
    ) -> UpgradeRecommendationView {
        let entries = recommendations
            .iter()
            .map(|rec| match rec {
                UpgradeRecommendation::Upgradable {
                    direct_dep_name,
                    direct_dep_current_version,
                    direct_dep_target_version,
                    transitive_dep_name,
                    transitive_resolved_version,
                    vulnerability_id,
                } => UpgradeEntryView::Upgradable {
                    direct_dep: direct_dep_name.clone(),
                    current_version: direct_dep_current_version.clone(),
                    target_version: direct_dep_target_version.clone(),
                    transitive_dep: transitive_dep_name.clone(),
                    resolved_version: transitive_resolved_version.clone(),
                    vulnerability_id: vulnerability_id.clone(),
                },
                UpgradeRecommendation::Unresolvable {
                    direct_dep_name,
                    reason,
                    vulnerability_id,
                } => UpgradeEntryView::Unresolvable {
                    direct_dep: direct_dep_name.clone(),
                    reason: reason.clone(),
                    vulnerability_id: vulnerability_id.clone(),
                },
                UpgradeRecommendation::SimulationFailed {
                    direct_dep_name,
                    error,
                } => UpgradeEntryView::SimulationFailed {
                    direct_dep: direct_dep_name.clone(),
                    error: error.clone(),
                },
            })
            .collect();

        UpgradeRecommendationView { entries }
    }

    /// Converts a single domain ResolutionEntry to a view
    fn build_resolution_entry_view(entry: &ResolutionEntry) -> ResolutionEntryView {
        let introduced_by: Vec<IntroducedByView> = entry
            .introduced_by()
            .iter()
            .map(|ib| IntroducedByView {
                package_name: ib.package_name().to_string(),
                version: ib.version().to_string(),
            })
            .collect();

        ResolutionEntryView {
            vulnerable_package: entry.vulnerable_package().to_string(),
            current_version: entry.current_version().to_string(),
            fixed_version: entry.fixed_version().map(|v| v.to_string()),
            severity: vulnerability_builder::map_severity(&entry.severity()),
            vulnerability_id: entry.vulnerability_id().to_string(),
            introduced_by,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::component_view::ComponentView;
    use super::super::vulnerability_view::SeverityView;
    use super::*;
    use crate::sbom_generation::domain::vulnerability::{CvssScore, Severity, Vulnerability};
    use crate::sbom_generation::domain::{Package, PackageName};
    use std::collections::HashMap;

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
        let view = metadata_builder::build_metadata(&metadata, None);

        assert_eq!(view.timestamp, "2024-01-15T10:30:00Z");
        assert_eq!(view.tool_name, "uv-sbom");
        assert_eq!(view.tool_version, "0.1.0");
        assert_eq!(
            view.serial_number,
            "urn:uuid:12345678-1234-1234-1234-123456789012"
        );
        assert!(view.component.is_none());
    }

    #[test]
    fn test_build_components_generates_bom_ref() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);

        assert_eq!(components.len(), 1);
        assert_eq!(components[0].bom_ref, "requests-2.31.0");
    }

    #[test]
    fn test_build_components_generates_purl() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);

        assert_eq!(components[0].purl, "pkg:pypi/requests@2.31.0");
    }

    #[test]
    fn test_build_components_with_license() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);

        let license = components[0].license.as_ref().unwrap();
        assert_eq!(license.name, "MIT");
        assert_eq!(license.spdx_id, Some("MIT".to_string()));
    }

    #[test]
    fn test_build_components_with_description() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);

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
        let components = component_builder::build_components(&packages, Some(&graph));

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
        let components = component_builder::build_components(&packages, None);

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

        let read_model = SbomReadModelBuilder::build(packages, &metadata, Some(&graph), None, None);

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

        let read_model = SbomReadModelBuilder::build(packages, &metadata, None, None, None);

        assert!(read_model.components.is_empty());
    }

    #[test]
    fn test_build_components_without_license() {
        let package = EnrichedPackage::new(
            Package::new("requests".to_string(), "2.31.0".to_string()).unwrap(),
            None,
            None,
        );
        let components = component_builder::build_components(&[package], None);

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
        let components = component_builder::build_components(&packages, None);

        let direct_deps = vec![
            PackageName::new("requests".to_string()).unwrap(),
            PackageName::new("urllib3".to_string()).unwrap(),
        ];
        let graph = DependencyGraph::new(direct_deps, HashMap::new());

        let deps = dependency_builder::build_dependencies(&graph, &components);

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
        let components = component_builder::build_components(&packages, None);

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

        let deps = dependency_builder::build_dependencies(&graph, &components);

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
        let components = component_builder::build_components(&packages, None);

        // unknown-pkg is not in components
        let direct_deps = vec![
            PackageName::new("requests".to_string()).unwrap(),
            PackageName::new("unknown-pkg".to_string()).unwrap(),
        ];
        let graph = DependencyGraph::new(direct_deps, HashMap::new());

        let deps = dependency_builder::build_dependencies(&graph, &components);

        // Only requests should be included
        assert_eq!(deps.direct.len(), 1);
        assert!(deps.direct.contains(&"requests-2.31.0".to_string()));
    }

    #[test]
    fn test_build_dependencies_empty_graph() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);
        let graph = DependencyGraph::new(vec![], HashMap::new());

        let deps = dependency_builder::build_dependencies(&graph, &components);

        assert!(deps.direct.is_empty());
        assert!(deps.transitive.is_empty());
    }

    // Tests for map_severity

    #[test]
    fn test_map_severity_all_levels() {
        assert_eq!(
            vulnerability_builder::map_severity(&Severity::Critical),
            SeverityView::Critical
        );
        assert_eq!(
            vulnerability_builder::map_severity(&Severity::High),
            SeverityView::High
        );
        assert_eq!(
            vulnerability_builder::map_severity(&Severity::Medium),
            SeverityView::Medium
        );
        assert_eq!(
            vulnerability_builder::map_severity(&Severity::Low),
            SeverityView::Low
        );
        assert_eq!(
            vulnerability_builder::map_severity(&Severity::None),
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

        let view = vulnerability_builder::build_vulnerability_view(&vuln, &pkg, &components);

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

        let view = vulnerability_builder::build_vulnerability_view(&vuln, &pkg, &components);

        assert_eq!(view.fixed_version, Some("3.0.0".to_string()));
    }

    #[test]
    fn test_build_vulnerability_view_without_cvss() {
        let vuln = create_vulnerability("GHSA-xxxx-yyyy-zzzz", None, Severity::High);
        let pkg = create_package_vulnerabilities("requests", "2.31.0", vec![vuln.clone()]);
        let components = vec![];

        let view = vulnerability_builder::build_vulnerability_view(&vuln, &pkg, &components);

        assert_eq!(view.cvss_score, None);
        assert_eq!(view.severity, SeverityView::High);
    }

    #[test]
    fn test_build_vulnerability_view_component_not_found() {
        let vuln = create_vulnerability("CVE-2024-1234", Some(9.8), Severity::Critical);
        let pkg = create_package_vulnerabilities("unknown-pkg", "1.0.0", vec![vuln.clone()]);
        let components = vec![]; // Empty components

        let view = vulnerability_builder::build_vulnerability_view(&vuln, &pkg, &components);

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
        let report = vulnerability_builder::build_vulnerabilities(&result, &components);

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
        let report = vulnerability_builder::build_vulnerabilities(&result, &components);

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
        let report = vulnerability_builder::build_vulnerabilities(&result, &components);

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
        let report = vulnerability_builder::build_vulnerabilities(&result, &components);

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

        let read_model =
            SbomReadModelBuilder::build(packages, &metadata, None, Some(&vuln_result), None);

        assert!(read_model.vulnerabilities.is_some());
        let vulns = read_model.vulnerabilities.unwrap();
        assert_eq!(vulns.actionable.len(), 1);
        assert_eq!(vulns.actionable[0].id, "CVE-2024-1234");
        assert!(vulns.threshold_exceeded);
    }

    // Tests for resolution guide builder

    #[test]
    fn test_build_resolution_guide_converts_entries() {
        let entries = vec![ResolutionEntry::new(
            "urllib3".to_string(),
            "1.26.5".to_string(),
            Some("1.26.18".to_string()),
            Severity::High,
            "CVE-2023-43804".to_string(),
            vec![
                crate::sbom_generation::domain::resolution_guide::IntroducedBy::new(
                    "requests".to_string(),
                    "2.28.0".to_string(),
                ),
            ],
        )];

        let guide = SbomReadModelBuilder::build_resolution_guide(&entries);

        assert_eq!(guide.entries.len(), 1);
        assert_eq!(guide.entries[0].vulnerable_package, "urllib3");
        assert_eq!(guide.entries[0].current_version, "1.26.5");
        assert_eq!(guide.entries[0].fixed_version, Some("1.26.18".to_string()));
        assert_eq!(guide.entries[0].severity, SeverityView::High);
        assert_eq!(guide.entries[0].vulnerability_id, "CVE-2023-43804");
        assert_eq!(guide.entries[0].introduced_by.len(), 1);
        assert_eq!(guide.entries[0].introduced_by[0].package_name, "requests");
        assert_eq!(guide.entries[0].introduced_by[0].version, "2.28.0");
    }

    #[test]
    fn test_build_resolution_guide_without_fixed_version() {
        let entries = vec![ResolutionEntry::new(
            "vulnerable-pkg".to_string(),
            "0.1.0".to_string(),
            None,
            Severity::Critical,
            "CVE-2024-0001".to_string(),
            vec![
                crate::sbom_generation::domain::resolution_guide::IntroducedBy::new(
                    "parent-pkg".to_string(),
                    "1.0.0".to_string(),
                ),
            ],
        )];

        let guide = SbomReadModelBuilder::build_resolution_guide(&entries);

        assert_eq!(guide.entries.len(), 1);
        assert_eq!(guide.entries[0].fixed_version, None);
        assert_eq!(guide.entries[0].severity, SeverityView::Critical);
    }

    #[test]
    fn test_build_resolution_guide_multiple_introduced_by() {
        let entries = vec![ResolutionEntry::new(
            "urllib3".to_string(),
            "1.26.5".to_string(),
            Some("1.26.18".to_string()),
            Severity::High,
            "CVE-2023-43804".to_string(),
            vec![
                crate::sbom_generation::domain::resolution_guide::IntroducedBy::new(
                    "httpx".to_string(),
                    "0.23.0".to_string(),
                ),
                crate::sbom_generation::domain::resolution_guide::IntroducedBy::new(
                    "requests".to_string(),
                    "2.28.0".to_string(),
                ),
            ],
        )];

        let guide = SbomReadModelBuilder::build_resolution_guide(&entries);

        assert_eq!(guide.entries[0].introduced_by.len(), 2);
        assert_eq!(guide.entries[0].introduced_by[0].package_name, "httpx");
        assert_eq!(guide.entries[0].introduced_by[1].package_name, "requests");
    }

    #[test]
    fn test_build_full_model_resolution_guide_when_both_graph_and_vulns() {
        let packages = vec![
            create_test_package("requests", "2.28.0"),
            create_test_package("urllib3", "1.26.5"),
        ];
        let metadata = create_test_metadata();

        let mut transitive = HashMap::new();
        transitive.insert(
            PackageName::new("requests".to_string()).unwrap(),
            vec![PackageName::new("urllib3".to_string()).unwrap()],
        );
        let graph = DependencyGraph::new(
            vec![PackageName::new("requests".to_string()).unwrap()],
            transitive,
        );

        let vuln = create_vulnerability("CVE-2023-43804", Some(7.5), Severity::High);
        let pkg_vuln = create_package_vulnerabilities("urllib3", "1.26.5", vec![vuln]);
        let vuln_result = VulnerabilityCheckResult {
            above_threshold: vec![pkg_vuln],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let read_model = SbomReadModelBuilder::build(
            packages,
            &metadata,
            Some(&graph),
            Some(&vuln_result),
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
        let packages = vec![create_test_package("requests", "2.31.0")];
        let metadata = create_test_metadata();

        let vuln = create_vulnerability("CVE-2024-1234", Some(9.8), Severity::Critical);
        let pkg_vuln = create_package_vulnerabilities("requests", "2.31.0", vec![vuln]);
        let vuln_result = VulnerabilityCheckResult {
            above_threshold: vec![pkg_vuln],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let read_model =
            SbomReadModelBuilder::build(packages, &metadata, None, Some(&vuln_result), None);

        assert!(read_model.resolution_guide.is_none());
    }

    #[test]
    fn test_build_full_model_resolution_guide_none_without_vulns() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let metadata = create_test_metadata();
        let graph = create_test_graph();

        let read_model = SbomReadModelBuilder::build(packages, &metadata, Some(&graph), None, None);

        assert!(read_model.resolution_guide.is_none());
    }

    #[test]
    fn test_build_full_model_resolution_guide_none_when_no_transitive_vulns() {
        // Only direct dependency has vulnerabilities — resolution guide should be None
        let packages = vec![create_test_package("requests", "2.31.0")];
        let metadata = create_test_metadata();
        let graph = create_test_graph(); // requests is direct

        let vuln = create_vulnerability("CVE-2024-1234", Some(9.8), Severity::Critical);
        let pkg_vuln = create_package_vulnerabilities("requests", "2.31.0", vec![vuln]);
        let vuln_result = VulnerabilityCheckResult {
            above_threshold: vec![pkg_vuln],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let read_model = SbomReadModelBuilder::build(
            packages,
            &metadata,
            Some(&graph),
            Some(&vuln_result),
            None,
        );

        // requests is a direct dep, so ResolutionAnalyzer skips it → empty → None
        assert!(read_model.resolution_guide.is_none());
    }

    // ============================================================
    // SHA-256 hash wiring tests
    // ============================================================

    #[test]
    fn test_build_components_with_sha256_hash() {
        let mut package = create_test_package("requests", "2.31.0");
        package.sha256_hash = Some("abc123def456".to_string());
        let components = component_builder::build_components(&[package], None);

        assert_eq!(components[0].sha256_hash, Some("abc123def456".to_string()));
    }

    #[test]
    fn test_build_components_without_sha256_hash() {
        let package = create_test_package("requests", "2.31.0");
        let components = component_builder::build_components(&[package], None);

        assert!(components[0].sha256_hash.is_none());
    }

    // ============================================================
    // Metadata component tests
    // ============================================================

    #[test]
    fn test_build_metadata_with_project_component() {
        let metadata = create_test_metadata();
        let view = metadata_builder::build_metadata(&metadata, Some(("my-project", "1.0.0")));

        assert!(view.component.is_some());
        let component = view.component.unwrap();
        assert_eq!(component.name, "my-project");
        assert_eq!(component.version, "1.0.0");
    }

    #[test]
    fn test_build_metadata_without_project_component() {
        let metadata = create_test_metadata();
        let view = metadata_builder::build_metadata(&metadata, None);

        assert!(view.component.is_none());
    }

    #[test]
    fn test_build_with_project_includes_metadata_component() {
        let packages = vec![create_test_package("requests", "2.31.0")];
        let metadata = create_test_metadata();

        let read_model = SbomReadModelBuilder::build_with_project(
            packages,
            &metadata,
            None,
            None,
            None,
            Some(("my-project", "1.0.0")),
            None,
        );

        assert!(read_model.metadata.component.is_some());
        let component = read_model.metadata.component.unwrap();
        assert_eq!(component.name, "my-project");
        assert_eq!(component.version, "1.0.0");
    }
}
