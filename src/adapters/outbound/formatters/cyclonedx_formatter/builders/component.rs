use super::super::schema::{Component, Hash, License, LicenseContent};
use crate::application::read_models::{ComponentView, LicenseView};

/// Build a list of CycloneDX [`Component`] entries from a [`ComponentView`] slice.
pub(in super::super) fn build_all(components: &[ComponentView]) -> Vec<Component> {
    components
        .iter()
        .map(|c| {
            let licenses = c.license.as_ref().map(build_license);
            let hashes = c.sha256_hash.as_ref().map(|hash| {
                vec![Hash {
                    alg: "SHA-256".to_string(),
                    content: hash.clone(),
                }]
            });
            Component {
                component_type: "library".to_string(),
                bom_ref: c.bom_ref.clone(),
                group: "pypi".to_string(),
                name: c.name.clone(),
                version: c.version.clone(),
                description: c.description.clone(),
                hashes,
                licenses,
                purl: c.purl.clone(),
            }
        })
        .collect()
}

/// Build license from LicenseView.
///
/// When a SPDX license ID is available, outputs `id` only (CycloneDX spec preference).
/// Falls back to `name` when no SPDX mapping exists.
fn build_license(license: &LicenseView) -> Vec<License> {
    vec![License {
        license: if license.spdx_id.is_some() {
            LicenseContent {
                id: license.spdx_id.clone(),
                name: None,
            }
        } else {
            LicenseContent {
                id: None,
                name: Some(license.name.clone()),
            }
        },
    }]
}
