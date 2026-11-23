//! Yanked package view structs for read model
//!
//! These structs provide a query-optimized view of packages whose locked
//! versions have been yanked on PyPI, independent of how the yanked status
//! is fetched.

/// View representation of a single package whose locked version is yanked
#[allow(dead_code)] // WIRE(#1155): remove when GenerateSbomUseCase calls CheckYankedPackagesUseCase
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YankedPackageView {
    /// Package name as listed in the lockfile
    pub name: String,
    /// Package version as listed in the lockfile
    pub version: String,
    /// Maintainer-provided reason for yanking; `None` when no reason was given
    pub reason: Option<String>,
    /// Whether the package is a direct dependency of the current project
    pub is_direct: bool,
}

/// View representation of a yanked packages report
///
/// Holds the list of packages whose locked versions are yanked on PyPI.
#[allow(dead_code)] // WIRE(#1155): remove when GenerateSbomUseCase calls CheckYankedPackagesUseCase
#[derive(Debug, Clone)]
pub struct YankedPackagesReport {
    /// Packages whose locked versions are yanked, sorted: direct first, then alphabetically
    pub packages: Vec<YankedPackageView>,
}

impl YankedPackagesReport {
    /// Returns `true` when no yanked packages were found.
    #[allow(dead_code)] // WIRE(#1155): remove when GenerateSbomUseCase calls CheckYankedPackagesUseCase
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    /// Returns the total number of yanked packages.
    #[allow(dead_code)] // WIRE(#1155): remove when GenerateSbomUseCase calls CheckYankedPackagesUseCase
    pub fn total_count(&self) -> usize {
        self.packages.len()
    }

    /// Returns the number of yanked packages that are direct dependencies.
    #[allow(dead_code)] // WIRE(#1155): remove when GenerateSbomUseCase calls CheckYankedPackagesUseCase
    pub fn direct_count(&self) -> usize {
        self.packages.iter().filter(|p| p.is_direct).count()
    }

    /// Returns the number of yanked packages that are transitive dependencies.
    #[allow(dead_code)] // WIRE(#1155): remove when GenerateSbomUseCase calls CheckYankedPackagesUseCase
    pub fn transitive_count(&self) -> usize {
        self.packages.iter().filter(|p| !p.is_direct).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_view(name: &str, is_direct: bool) -> YankedPackageView {
        YankedPackageView {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            reason: Some("security fix".to_string()),
            is_direct,
        }
    }

    #[test]
    fn test_empty_report() {
        let report = YankedPackagesReport {
            packages: vec![],
        };
        assert!(report.is_empty());
        assert_eq!(report.total_count(), 0);
        assert_eq!(report.direct_count(), 0);
        assert_eq!(report.transitive_count(), 0);
    }

    #[test]
    fn test_total_count() {
        let report = YankedPackagesReport {
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
        let report = YankedPackagesReport {
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
        let a = make_view("requests", true);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
