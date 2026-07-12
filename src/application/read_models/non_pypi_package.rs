//! Non-PyPI package view structs for read model
//!
//! These structs provide a query-optimized view of packages sourced from
//! registries, VCS, or URLs other than the canonical PyPI registry.

/// View representation of a single package sourced from a non-PyPI origin.
///
/// All classification fields are pre-computed at construction time so consumers
/// (formatters, presenters) do not need access to port types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonPyPiPackageView {
    /// Package name as listed in the lockfile
    pub name: String,
    /// Package version as listed in the lockfile
    pub version: String,
    /// Stable category label derived from `PackageSourceKind::label()`.
    /// Examples: "Private Registry", "Git", "Direct URL".
    pub source_label: String,
    /// Location string derived from `PackageSourceKind::value()`.
    /// Empty for kinds that carry no explicit location.
    pub source_location: String,
    /// Whether the package is a direct dependency of the current project.
    pub is_direct: bool,
}

/// View representation of a non-PyPI packages report.
///
/// Holds the pre-categorized list of packages whose source is external but
/// not the canonical PyPI registry.
#[derive(Debug, Clone, Default)]
pub struct NonPyPiPackagesReport {
    /// Packages sourced from non-PyPI external origins.
    pub packages: Vec<NonPyPiPackageView>,
}

impl NonPyPiPackagesReport {
    /// Returns the total number of non-PyPI packages.
    pub fn total_count(&self) -> usize {
        self.packages.len()
    }

    /// Returns the number of non-PyPI packages that are direct dependencies.
    pub fn direct_count(&self) -> usize {
        self.packages.iter().filter(|p| p.is_direct).count()
    }

    /// Returns the number of non-PyPI packages that are transitive dependencies.
    pub fn transitive_count(&self) -> usize {
        self.packages.iter().filter(|p| !p.is_direct).count()
    }

    /// Returns `true` when no non-PyPI packages were found.
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_view(name: &str, is_direct: bool) -> NonPyPiPackageView {
        NonPyPiPackageView {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            source_label: "Git".to_string(),
            source_location: "https://github.com/example/repo".to_string(),
            is_direct,
        }
    }

    #[test]
    fn test_default_report_is_empty() {
        let report = NonPyPiPackagesReport::default();
        assert!(report.is_empty());
        assert_eq!(report.total_count(), 0);
        assert_eq!(report.direct_count(), 0);
        assert_eq!(report.transitive_count(), 0);
    }

    #[test]
    fn test_total_count() {
        let report = NonPyPiPackagesReport {
            packages: vec![
                make_view("a", true),
                make_view("b", false),
                make_view("c", false),
            ],
        };
        assert_eq!(report.total_count(), 3);
        assert!(!report.is_empty());
    }

    #[test]
    fn test_direct_and_transitive_counts() {
        let report = NonPyPiPackagesReport {
            packages: vec![
                make_view("a", true),
                make_view("b", true),
                make_view("c", false),
            ],
        };
        assert_eq!(report.direct_count(), 2);
        assert_eq!(report.transitive_count(), 1);
    }

    #[test]
    fn test_view_clone_and_eq() {
        let a = make_view("my-pkg", true);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
