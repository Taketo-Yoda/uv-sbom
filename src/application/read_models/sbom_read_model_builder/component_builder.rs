use crate::ports::outbound::EnrichedPackage;
use crate::sbom_generation::domain::DependencyGraph;
use crate::sbom_generation::policies::spdx_license_map;

use super::super::component_view::{ComponentView, LicenseView};

pub(super) fn build_components(
    packages: &[EnrichedPackage],
    graph: Option<&DependencyGraph>,
) -> Vec<ComponentView> {
    packages
        .iter()
        .map(|enriched| build_component(enriched, graph))
        .collect()
}

fn build_component(enriched: &EnrichedPackage, graph: Option<&DependencyGraph>) -> ComponentView {
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

    let license = enriched.license.as_ref().map(|license_str| {
        let spdx_id = spdx_license_map::get_spdx_id(license_str);
        LicenseView {
            spdx_id,
            name: license_str.clone(),
        }
    });

    ComponentView {
        bom_ref,
        name: name.to_string(),
        version: version.to_string(),
        purl,
        license,
        description: enriched.description.clone(),
        sha256_hash: enriched.sha256_hash.clone(),
        is_direct_dependency: is_direct,
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers as th;
    use super::*;
    use crate::ports::outbound::EnrichedPackage;
    use crate::sbom_generation::domain::Package;

    #[test]
    fn test_build_components_generates_bom_ref() {
        let packages = vec![th::package("requests", "2.31.0")];
        let components = build_components(&packages, None);

        assert_eq!(components.len(), 1);
        assert_eq!(components[0].bom_ref, "requests-2.31.0");
    }

    #[test]
    fn test_build_components_generates_purl() {
        let packages = vec![th::package("requests", "2.31.0")];
        let components = build_components(&packages, None);

        assert_eq!(components[0].purl, "pkg:pypi/requests@2.31.0");
    }

    #[test]
    fn test_build_components_with_license() {
        let packages = vec![th::package("requests", "2.31.0")];
        let components = build_components(&packages, None);

        let license = components[0].license.as_ref().unwrap();
        assert_eq!(license.name, "MIT");
        assert_eq!(license.spdx_id, Some("MIT".to_string()));
    }

    #[test]
    fn test_build_components_without_license() {
        let package = EnrichedPackage::new(
            Package::new("requests".to_string(), "2.31.0".to_string()).unwrap(),
            None,
            None,
        );
        let components = build_components(&[package], None);

        assert!(components[0].license.is_none());
        assert!(components[0].description.is_none());
    }

    #[test]
    fn test_build_components_with_description() {
        let packages = vec![th::package("requests", "2.31.0")];
        let components = build_components(&packages, None);

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
        let components = build_components(&packages, Some(&graph));

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
        let components = build_components(&packages, None);

        assert!(!components[0].is_direct_dependency);
    }

    #[test]
    fn test_build_components_with_sha256_hash() {
        let mut package = th::package("requests", "2.31.0");
        package.sha256_hash = Some("abc123def456".to_string());
        let components = build_components(&[package], None);

        assert_eq!(components[0].sha256_hash, Some("abc123def456".to_string()));
    }

    #[test]
    fn test_build_components_without_sha256_hash() {
        let package = th::package("requests", "2.31.0");
        let components = build_components(&[package], None);

        assert!(components[0].sha256_hash.is_none());
    }
}
