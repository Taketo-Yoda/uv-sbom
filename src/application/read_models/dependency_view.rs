//! Dependency view structs for read model
//!
//! These structs provide a query-optimized view of dependency relationships.

use std::collections::HashMap;

/// View representation of dependency information
///
/// Provides a flattened view of direct and transitive dependencies
/// for efficient querying.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct DependencyView {
    /// BOM references of direct dependencies
    pub direct: Vec<String>,
    /// Transitive dependencies mapped by their parent bom-ref
    pub transitive: HashMap<String, Vec<String>>,
}
