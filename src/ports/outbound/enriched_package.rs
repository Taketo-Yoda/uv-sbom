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
    pub sha256_hash: Option<String>,
}

impl EnrichedPackage {
    pub fn new(package: Package, license: Option<String>, description: Option<String>) -> Self {
        Self {
            package,
            license,
            description,
            sha256_hash: None,
        }
    }

    pub fn with_sha256_hash(mut self, sha256_hash: Option<String>) -> Self {
        self.sha256_hash = sha256_hash;
        self
    }
}
