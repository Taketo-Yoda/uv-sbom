//! Component view structs for read model
//!
//! These structs provide a flattened, query-optimized view of component data.

/// View representation of a software component
#[derive(Debug, Clone)]
pub struct ComponentView {
    /// BOM reference identifier
    pub bom_ref: String,
    /// Component name
    pub name: String,
    /// Component version
    pub version: String,
    /// Package URL (purl)
    pub purl: String,
    /// License information
    pub license: Option<LicenseView>,
    /// Component description
    pub description: Option<String>,
    /// SHA256 hash of the component
    #[allow(dead_code)]
    pub sha256_hash: Option<String>,
    /// Whether this is a direct dependency
    #[allow(dead_code)]
    pub is_direct_dependency: bool,
}

/// View representation of license information
#[derive(Debug, Clone)]
pub struct LicenseView {
    /// SPDX license identifier
    pub spdx_id: Option<String>,
    /// License name
    pub name: String,
    /// URL to license text
    #[allow(dead_code)]
    pub url: Option<String>,
}
