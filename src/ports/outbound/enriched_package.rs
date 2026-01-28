use crate::sbom_generation::domain::Package;

/// EnrichedPackage represents a package with its license information
///
/// This is used to pass package data with license info from the use case
/// to the read model builder.
#[derive(Debug, Clone)]
pub struct EnrichedPackage {
    pub package: Package,
    pub license: Option<String>,
    pub description: Option<String>,
}

impl EnrichedPackage {
    pub fn new(package: Package, license: Option<String>, description: Option<String>) -> Self {
        Self {
            package,
            license,
            description,
        }
    }
}
