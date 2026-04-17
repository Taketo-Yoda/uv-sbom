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
