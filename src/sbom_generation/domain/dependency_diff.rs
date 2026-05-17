// Types for the dependency-diff feature; wired to the binary in a subsequent CLI integration subtask of #224.
#![allow(dead_code)]

/// Classification of how a package changed between two dependency snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeType {
    Added,
    Removed,
    Updated,
    Unchanged,
}

/// Per-package record describing how one package changed.
///
/// `old_version` / `new_version` semantics:
/// - Added:     old = None,          new = Some(version)
/// - Removed:   old = Some(version), new = None
/// - Updated:   old = Some(_),       new = Some(_)  (versions differ)
/// - Unchanged: old = Some(v),       new = Some(v)  (same version)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageChange {
    pub package_name: String,
    pub change_type: ChangeType,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
    pub license: Option<String>,
    pub vulnerability_count: usize,
}

/// Aggregate counts across all changes in a diff.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiffSummary {
    pub added: usize,
    pub removed: usize,
    pub updated: usize,
    pub unchanged: usize,
}

/// Result of comparing two dependency snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyDiff {
    pub base_ref: String,
    pub changes: Vec<PackageChange>,
    pub summary: DiffSummary,
}
