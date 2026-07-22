//! Python compatibility view structs for read model
//!
//! These structs provide a query-optimized view of the result of a Python
//! compatibility check against a target Python version, independent of how
//! the underlying `requires_python` data is fetched.

/// View representation of a single package incompatible with the target Python version
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonIncompatibilityView {
    /// Package name as listed in the lockfile
    pub name: String,
    /// Package version as listed in the lockfile
    pub version: String,
    /// PEP 440 `requires_python` specifier reported by PyPI for this package version.
    ///
    /// `None` when PyPI declares no constraint (a package with no constraint is never
    /// classified as incompatible, so in practice this is always `Some` for entries
    /// that appear in a report, but the type mirrors the upstream
    /// `PythonCompatibilityInfo.requires_python` field for consistency).
    pub requires_python: Option<String>,
    /// Whether the package is a direct dependency of the current project
    pub is_direct: bool,
}

/// View representation of a Python compatibility report
///
/// Holds the list of packages incompatible with the target Python version
/// along with the target version string used to classify them.
#[derive(Debug, Clone)]
pub struct PythonCompatibilityReport {
    /// Target Python version the report was checked against (e.g. "3.13")
    pub target_python: String,
    /// Packages incompatible with `target_python`
    pub incompatible: Vec<PythonIncompatibilityView>,
}

impl PythonCompatibilityReport {
    /// Returns `true` when no packages were classified as incompatible.
    pub fn is_empty(&self) -> bool {
        self.incompatible.is_empty()
    }

    /// Returns the total number of incompatible packages.
    pub fn total_count(&self) -> usize {
        self.incompatible.len()
    }

    /// Returns the number of incompatible packages that are direct dependencies.
    pub fn direct_count(&self) -> usize {
        self.incompatible.iter().filter(|p| p.is_direct).count()
    }

    /// Returns the number of incompatible packages that are transitive dependencies.
    pub fn transitive_count(&self) -> usize {
        self.incompatible.iter().filter(|p| !p.is_direct).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_view(name: &str, is_direct: bool) -> PythonIncompatibilityView {
        PythonIncompatibilityView {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            requires_python: Some(">=3.9".to_string()),
            is_direct,
        }
    }

    #[test]
    fn test_empty_report() {
        let report = PythonCompatibilityReport {
            target_python: "3.13".to_string(),
            incompatible: vec![],
        };
        assert!(report.is_empty());
        assert_eq!(report.total_count(), 0);
        assert_eq!(report.direct_count(), 0);
        assert_eq!(report.transitive_count(), 0);
    }

    #[test]
    fn test_total_count() {
        let report = PythonCompatibilityReport {
            target_python: "3.13".to_string(),
            incompatible: vec![
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
        let report = PythonCompatibilityReport {
            target_python: "3.13".to_string(),
            incompatible: vec![
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
        let a = make_view("requests", true);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_target_python_preserved() {
        let report = PythonCompatibilityReport {
            target_python: "3.12".to_string(),
            incompatible: vec![],
        };
        assert_eq!(report.target_python, "3.12");
    }
}
