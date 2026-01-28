//! Builder for constructing SbomReadModel from domain objects
//!
//! This module provides the builder that transforms domain objects into
//! the query-optimized read model.

use super::component_view::{ComponentView, LicenseView};
use super::sbom_read_model::{SbomMetadataView, SbomReadModel};
use crate::ports::outbound::EnrichedPackage;
use crate::sbom_generation::domain::services::VulnerabilityCheckResult;
use crate::sbom_generation::domain::{DependencyGraph, SbomMetadata};

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
        _vulnerability_result: Option<&VulnerabilityCheckResult>,
    ) -> SbomReadModel {
        let metadata_view = Self::build_metadata(metadata);
        let components = Self::build_components(&packages, dependency_graph);

        SbomReadModel {
            metadata: metadata_view,
            components,
            dependencies: None,
            vulnerabilities: None,
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
}

#[cfg(test)]
mod tests {
    use super::*;
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

        // Check dependencies and vulnerabilities are None (initial implementation)
        assert!(read_model.dependencies.is_none());
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
}
