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

        let resolution_guide = Self::build_resolution_guide_if_applicable(
            dependency_graph,
            vulnerability_result,
            &packages,
        );

        let upgrade_recommendations = upgrade_recommendations
            .map(upgrade_recommendation_builder::build_upgrade_recommendations);

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
mod tests {
    use super::super::component_view::ComponentView;
    use super::super::vulnerability_view::SeverityView;
    use super::*;
    use crate::sbom_generation::domain::vulnerability::Severity;
    use crate::sbom_generation::domain::{Package, PackageName};
    use std::collections::HashMap;

    mod test_helpers {
        use super::*;
        use crate::sbom_generation::domain::resolution_guide::{IntroducedBy, ResolutionEntry};
        use crate::sbom_generation::domain::vulnerability::{CvssScore, Severity, Vulnerability};
        use crate::sbom_generation::domain::{Package, PackageName};
        use std::collections::HashMap;

        pub(super) fn metadata() -> SbomMetadata {
            SbomMetadata::new(
                "2024-01-15T10:30:00Z".to_string(),
                "uv-sbom".to_string(),
                "0.1.0".to_string(),
                "urn:uuid:12345678-1234-1234-1234-123456789012".to_string(),
            )
        }

        pub(super) fn package(name: &str, version: &str) -> EnrichedPackage {
            EnrichedPackage::new(
                Package::new(name.to_string(), version.to_string()).unwrap(),
                Some("MIT".to_string()),
                Some("A test package".to_string()),
            )
        }

        pub(super) fn graph() -> DependencyGraph {
            let direct_deps = vec![PackageName::new("requests".to_string()).unwrap()];
            let transitive: HashMap<PackageName, Vec<PackageName>> = HashMap::new();
            DependencyGraph::new(direct_deps, transitive, HashMap::new())
        }

        pub(super) fn vulnerability(
            id: &str,
            cvss: Option<f32>,
            severity: Severity,
        ) -> Vulnerability {
            let cvss_score = cvss.and_then(|s| CvssScore::new(s).ok());
            Vulnerability::new(id.to_string(), cvss_score, severity, None, None).unwrap()
        }

        pub(super) fn vulnerability_with_fix(
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

        pub(super) fn package_vulnerabilities(
            name: &str,
            version: &str,
            vulnerabilities: Vec<Vulnerability>,
        ) -> PackageVulnerabilities {
            PackageVulnerabilities::new(name.to_string(), version.to_string(), vulnerabilities)
        }

        pub(super) fn resolution_entry(
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

    use test_helpers as th;

    #[test]
    fn test_build_metadata() {
        let metadata = th::metadata();
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
        let packages = vec![th::package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);

        assert_eq!(components.len(), 1);
        assert_eq!(components[0].bom_ref, "requests-2.31.0");
    }

    #[test]
    fn test_build_components_generates_purl() {
        let packages = vec![th::package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);

        assert_eq!(components[0].purl, "pkg:pypi/requests@2.31.0");
    }

    #[test]
    fn test_build_components_with_license() {
        let packages = vec![th::package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);

        let license = components[0].license.as_ref().unwrap();
        assert_eq!(license.name, "MIT");
        assert_eq!(license.spdx_id, Some("MIT".to_string()));
    }

    #[test]
    fn test_build_components_with_description() {
        let packages = vec![th::package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);

        assert_eq!(
            components[0].description,
            Some("A test package".to_string())
        );
    }

    #[test]
    fn test_build_components_is_direct_dependency_with_graph() {
        let packages = vec![
            th::package("requests", "2.31.0"),
            th::package("urllib3", "2.0.0"),
        ];
        let graph = th::graph();
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
        let packages = vec![th::package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);

        assert!(!components[0].is_direct_dependency);
    }

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
            packages, &metadata, None, None, None, None, None,
        );

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

    #[test]
    fn test_build_dependencies_maps_direct_to_bom_refs() {
        let packages = vec![
            th::package("requests", "2.31.0"),
            th::package("urllib3", "2.0.0"),
        ];
        let components = component_builder::build_components(&packages, None);

        let direct_deps = vec![
            PackageName::new("requests".to_string()).unwrap(),
            PackageName::new("urllib3".to_string()).unwrap(),
        ];
        let graph = DependencyGraph::new(direct_deps, HashMap::new(), HashMap::new());

        let deps = dependency_builder::build_dependencies(&graph, &components);

        assert_eq!(deps.direct.len(), 2);
        assert!(deps.direct.contains(&"requests-2.31.0".to_string()));
        assert!(deps.direct.contains(&"urllib3-2.0.0".to_string()));
    }

    #[test]
    fn test_build_dependencies_builds_transitive_map() {
        let packages = vec![
            th::package("requests", "2.31.0"),
            th::package("urllib3", "2.0.0"),
            th::package("certifi", "2023.7.22"),
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
        let graph = DependencyGraph::new(direct_deps, transitive, HashMap::new());

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
        let packages = vec![th::package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);

        // unknown-pkg is not in components
        let direct_deps = vec![
            PackageName::new("requests".to_string()).unwrap(),
            PackageName::new("unknown-pkg".to_string()).unwrap(),
        ];
        let graph = DependencyGraph::new(direct_deps, HashMap::new(), HashMap::new());

        let deps = dependency_builder::build_dependencies(&graph, &components);

        assert_eq!(deps.direct.len(), 1);
        assert!(deps.direct.contains(&"requests-2.31.0".to_string()));
    }

    #[test]
    fn test_build_dependencies_empty_graph() {
        let packages = vec![th::package("requests", "2.31.0")];
        let components = component_builder::build_components(&packages, None);
        let graph = DependencyGraph::new(vec![], HashMap::new(), HashMap::new());

        let deps = dependency_builder::build_dependencies(&graph, &components);

        assert!(deps.direct.is_empty());
        assert!(deps.transitive.is_empty());
    }

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

    #[test]
    fn test_build_vulnerability_view_basic() {
        let vuln = th::vulnerability("CVE-2024-1234", Some(9.8), Severity::Critical);
        let pkg = th::package_vulnerabilities("requests", "2.31.0", vec![vuln.clone()]);
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
        let vuln = th::vulnerability_with_fix("CVE-2024-5678", Some(7.5), Severity::High, "3.0.0");
        let pkg = th::package_vulnerabilities("requests", "2.31.0", vec![vuln.clone()]);
        let components = vec![];

        let view = vulnerability_builder::build_vulnerability_view(&vuln, &pkg, &components);

        assert_eq!(view.fixed_version, Some("3.0.0".to_string()));
    }

    #[test]
    fn test_build_vulnerability_view_without_cvss() {
        let vuln = th::vulnerability("GHSA-xxxx-yyyy-zzzz", None, Severity::High);
        let pkg = th::package_vulnerabilities("requests", "2.31.0", vec![vuln.clone()]);
        let components = vec![];

        let view = vulnerability_builder::build_vulnerability_view(&vuln, &pkg, &components);

        assert_eq!(view.cvss_score, None);
        assert_eq!(view.severity, SeverityView::High);
    }

    #[test]
    fn test_build_vulnerability_view_component_not_found() {
        let vuln = th::vulnerability("CVE-2024-1234", Some(9.8), Severity::Critical);
        let pkg = th::package_vulnerabilities("unknown-pkg", "1.0.0", vec![vuln.clone()]);
        let components = vec![];

        let view = vulnerability_builder::build_vulnerability_view(&vuln, &pkg, &components);

        assert_eq!(view.affected_component, "unknown-pkg-1.0.0");
        assert_eq!(view.bom_ref, "CVE-2024-1234-unknown-pkg-1.0.0");
    }

    #[test]
    fn test_build_vulnerabilities_actionable_and_informational() {
        let vuln_critical = th::vulnerability("CVE-2024-001", Some(9.8), Severity::Critical);
        let vuln_low = th::vulnerability("CVE-2024-002", Some(2.0), Severity::Low);

        let above_pkg = th::package_vulnerabilities("critical-pkg", "1.0.0", vec![vuln_critical]);
        let below_pkg = th::package_vulnerabilities("low-pkg", "1.0.0", vec![vuln_low]);

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
    }

    #[test]
    fn test_build_vulnerabilities_summary_statistics() {
        let vuln1 = th::vulnerability("CVE-2024-001", Some(9.8), Severity::Critical);
        let vuln2 = th::vulnerability("CVE-2024-002", Some(8.0), Severity::High);
        let vuln3 = th::vulnerability("CVE-2024-003", Some(3.0), Severity::Low);

        let above_pkg = th::package_vulnerabilities("critical-pkg", "1.0.0", vec![vuln1, vuln2]);
        let below_pkg = th::package_vulnerabilities("low-pkg", "1.0.0", vec![vuln3]);

        let result = VulnerabilityCheckResult {
            above_threshold: vec![above_pkg],
            below_threshold: vec![below_pkg],
            threshold_exceeded: true,
        };

        let components = vec![];
        let report = vulnerability_builder::build_vulnerabilities(&result, &components);

        assert_eq!(report.summary.total_count, 3);
        assert_eq!(report.actionable.len(), 2);
        assert_eq!(report.informational.len(), 1);
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
        assert_eq!(report.summary.total_count, 0);
        assert_eq!(report.summary.affected_package_count, 0);
    }

    #[test]
    fn test_build_vulnerabilities_multiple_vulns_per_package() {
        let vuln1 = th::vulnerability("CVE-2024-001", Some(9.8), Severity::Critical);
        let vuln2 = th::vulnerability("CVE-2024-002", Some(8.5), Severity::High);
        let vuln3 = th::vulnerability("CVE-2024-003", Some(7.0), Severity::High);

        let pkg = th::package_vulnerabilities("multi-vuln-pkg", "1.0.0", vec![vuln1, vuln2, vuln3]);

        let result = VulnerabilityCheckResult {
            above_threshold: vec![pkg],
            below_threshold: vec![],
            threshold_exceeded: true,
        };

        let components = vec![];
        let report = vulnerability_builder::build_vulnerabilities(&result, &components);

        assert_eq!(report.actionable.len(), 3);
        for vuln_view in &report.actionable {
            assert_eq!(vuln_view.affected_component_name, "multi-vuln-pkg");
            assert_eq!(vuln_view.affected_version, "1.0.0");
        }
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
        );

        assert!(read_model.vulnerabilities.is_some());
        let vulns = read_model.vulnerabilities.unwrap();
        assert_eq!(vulns.actionable.len(), 1);
        assert_eq!(vulns.actionable[0].id, "CVE-2024-1234");
    }

    #[test]
    fn test_build_resolution_guide_converts_entries() {
        let entries = vec![th::resolution_entry(
            "urllib3",
            "1.26.5",
            Some("1.26.18"),
            Severity::High,
            "CVE-2023-43804",
            &[("requests", "2.28.0")],
        )];

        let guide = resolution_guide_builder::build_resolution_guide(&entries);

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
        let entries = vec![th::resolution_entry(
            "vulnerable-pkg",
            "0.1.0",
            None,
            Severity::Critical,
            "CVE-2024-0001",
            &[("parent-pkg", "1.0.0")],
        )];

        let guide = resolution_guide_builder::build_resolution_guide(&entries);

        assert_eq!(guide.entries.len(), 1);
        assert_eq!(guide.entries[0].fixed_version, None);
        assert_eq!(guide.entries[0].severity, SeverityView::Critical);
    }

    #[test]
    fn test_build_resolution_guide_multiple_introduced_by() {
        let entries = vec![th::resolution_entry(
            "urllib3",
            "1.26.5",
            Some("1.26.18"),
            Severity::High,
            "CVE-2023-43804",
            &[("httpx", "0.23.0"), ("requests", "2.28.0")],
        )];

        let guide = resolution_guide_builder::build_resolution_guide(&entries);

        assert_eq!(guide.entries[0].introduced_by.len(), 2);
        assert_eq!(guide.entries[0].introduced_by[0].package_name, "httpx");
        assert_eq!(guide.entries[0].introduced_by[1].package_name, "requests");
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
        );

        // requests is a direct dep, so ResolutionAnalyzer skips it → empty → None
        assert!(read_model.resolution_guide.is_none());
    }

    #[test]
    fn test_build_components_with_sha256_hash() {
        let mut package = th::package("requests", "2.31.0");
        package.sha256_hash = Some("abc123def456".to_string());
        let components = component_builder::build_components(&[package], None);

        assert_eq!(components[0].sha256_hash, Some("abc123def456".to_string()));
    }

    #[test]
    fn test_build_components_without_sha256_hash() {
        let package = th::package("requests", "2.31.0");
        let components = component_builder::build_components(&[package], None);

        assert!(components[0].sha256_hash.is_none());
    }

    #[test]
    fn test_build_metadata_with_project_component() {
        let metadata = th::metadata();
        let view = metadata_builder::build_metadata(&metadata, Some(("my-project", "1.0.0")));

        assert!(view.component.is_some());
        let component = view.component.unwrap();
        assert_eq!(component.name, "my-project");
        assert_eq!(component.version, "1.0.0");
    }

    #[test]
    fn test_build_metadata_without_project_component() {
        let metadata = th::metadata();
        let view = metadata_builder::build_metadata(&metadata, None);

        assert!(view.component.is_none());
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
        );

        assert!(read_model.metadata.component.is_some());
        let component = read_model.metadata.component.unwrap();
        assert_eq!(component.name, "my-project");
        assert_eq!(component.version, "1.0.0");
    }
}
