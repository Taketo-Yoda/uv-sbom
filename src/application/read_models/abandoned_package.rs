//! Abandoned package view structs for read model
//!
//! These structs provide a query-optimized view of abandoned-package data
//! with pre-computed inactivity duration for efficient reporting.

use chrono::NaiveDate;

/// View representation of a single abandoned package
///
/// All fields are pre-computed at construction time so consumers (formatters,
/// presenters) do not need to perform date arithmetic or re-derive directness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonedPackageView {
    /// Package name as listed in the lockfile
    pub name: String,
    /// Package version as listed in the lockfile
    pub version: String,
    /// Date of the most recent upstream release.
    ///
    /// Packages whose `MaintenanceInfo.last_release_date` is `None` (unknown release
    /// date) are excluded at report construction time and never appear in this struct.
    pub last_release_date: NaiveDate,
    /// Number of days between `last_release_date` and the report's reference date.
    ///
    /// Uses `i64` to match `chrono::Duration::num_days()` return type directly,
    /// avoiding a lossy cast in the use case. Negative values are theoretically
    /// possible for future-dated releases but are never classified as abandoned.
    pub days_inactive: i64,
    /// Whether the package is a direct dependency of the current project
    pub is_direct: bool,
}

/// View representation of an abandoned-packages report
///
/// Holds the pre-categorized list of abandoned packages along with the
/// threshold used to classify them. The threshold is captured so downstream
/// formatters can render messages like "abandoned (>730 days inactive)".
#[derive(Debug, Clone)]
pub struct AbandonedPackagesReport {
    /// Packages classified as abandoned
    pub packages: Vec<AbandonedPackageView>,
    /// Inactivity threshold (in days) used to build this report
    pub threshold_days: u64,
}

impl Default for AbandonedPackagesReport {
    /// Returns a report with no packages and the standard 730-day threshold.
    ///
    /// The threshold matches the application default configured in `MergedConfig`.
    /// Use explicit construction when a different threshold is required.
    fn default() -> Self {
        Self {
            packages: Vec::new(),
            threshold_days: 730,
        }
    }
}

impl AbandonedPackagesReport {
    /// Returns the total number of abandoned packages.
    pub fn total_count(&self) -> usize {
        self.packages.len()
    }

    /// Returns the number of abandoned packages that are direct dependencies.
    pub fn direct_count(&self) -> usize {
        self.packages.iter().filter(|p| p.is_direct).count()
    }

    /// Returns the number of abandoned packages that are transitive dependencies.
    pub fn transitive_count(&self) -> usize {
        self.packages.iter().filter(|p| !p.is_direct).count()
    }

    /// Returns `true` when no packages were classified as abandoned.
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_view(name: &str, days_inactive: i64, is_direct: bool) -> AbandonedPackageView {
        AbandonedPackageView {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            last_release_date: NaiveDate::from_ymd_opt(2020, 1, 1).unwrap(),
            days_inactive,
            is_direct,
        }
    }

    #[test]
    fn test_default_report_is_empty() {
        let report = AbandonedPackagesReport::default();
        assert!(report.is_empty());
        assert_eq!(report.total_count(), 0);
        assert_eq!(report.direct_count(), 0);
        assert_eq!(report.transitive_count(), 0);
        assert_eq!(report.threshold_days, 730);
    }

    #[test]
    fn test_total_count() {
        let report = AbandonedPackagesReport {
            packages: vec![
                make_view("a", 400, true),
                make_view("b", 500, false),
                make_view("c", 600, false),
            ],
            threshold_days: 365,
        };
        assert_eq!(report.total_count(), 3);
        assert!(!report.is_empty());
    }

    #[test]
    fn test_direct_and_transitive_counts() {
        let report = AbandonedPackagesReport {
            packages: vec![
                make_view("a", 400, true),
                make_view("b", 500, true),
                make_view("c", 600, false),
            ],
            threshold_days: 365,
        };
        assert_eq!(report.direct_count(), 2);
        assert_eq!(report.transitive_count(), 1);
    }

    #[test]
    fn test_view_clone_and_eq() {
        let a = make_view("requests", 800, true);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_threshold_days_preserved() {
        let report = AbandonedPackagesReport {
            packages: vec![],
            threshold_days: 730,
        };
        assert_eq!(report.threshold_days, 730);
    }
}
