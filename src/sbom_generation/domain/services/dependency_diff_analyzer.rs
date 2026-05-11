use std::collections::HashMap;

use crate::sbom_generation::domain::dependency_diff::{
    ChangeType, DependencyDiff, DiffSummary, PackageChange,
};
use crate::sbom_generation::domain::package::Package;

/// Stateless domain service that produces a `DependencyDiff` by comparing
/// two snapshots of resolved packages (e.g., base branch vs current branch).
///
/// All inputs and outputs are pure value objects — no I/O is performed.
///
/// Note: `base_ref` is set to `"base"` in this implementation. Subsequent
/// subtasks of the dependency-diff feature (#224) will introduce an entry
/// point that accepts the actual git ref.
// Foundation service for the dependency-diff feature; used by subsequent subtasks of #224.
#[allow(dead_code)]
pub struct DependencyDiffAnalyzer;

impl DependencyDiffAnalyzer {
    /// Compare two flat lists of packages and produce a fully populated `DependencyDiff`.
    #[allow(dead_code)]
    pub fn analyze(base: &[Package], current: &[Package]) -> DependencyDiff {
        let base_map: HashMap<&str, &Package> =
            base.iter().map(|p| (p.name(), p)).collect();
        let current_map: HashMap<&str, &Package> =
            current.iter().map(|p| (p.name(), p)).collect();

        let mut changes: Vec<PackageChange> = Vec::new();

        for pkg in current {
            match base_map.get(pkg.name()) {
                None => changes.push(PackageChange {
                    package_name: pkg.name().to_string(),
                    change_type: ChangeType::Added,
                    old_version: None,
                    new_version: Some(pkg.version().to_string()),
                    license: None,
                    vulnerability_count: 0,
                }),
                Some(base_pkg) if base_pkg.version() != pkg.version() => {
                    changes.push(PackageChange {
                        package_name: pkg.name().to_string(),
                        change_type: ChangeType::Updated,
                        old_version: Some(base_pkg.version().to_string()),
                        new_version: Some(pkg.version().to_string()),
                        license: None,
                        vulnerability_count: 0,
                    })
                }
                Some(base_pkg) => changes.push(PackageChange {
                    package_name: pkg.name().to_string(),
                    change_type: ChangeType::Unchanged,
                    old_version: Some(base_pkg.version().to_string()),
                    new_version: Some(pkg.version().to_string()),
                    license: None,
                    vulnerability_count: 0,
                }),
            }
        }

        for pkg in base {
            if !current_map.contains_key(pkg.name()) {
                changes.push(PackageChange {
                    package_name: pkg.name().to_string(),
                    change_type: ChangeType::Removed,
                    old_version: Some(pkg.version().to_string()),
                    new_version: None,
                    license: None,
                    vulnerability_count: 0,
                });
            }
        }

        changes.sort_by(|a, b| {
            let group_order = |c: &ChangeType| -> u8 {
                match c {
                    ChangeType::Added => 0,
                    ChangeType::Updated => 1,
                    ChangeType::Removed => 2,
                    ChangeType::Unchanged => 3,
                }
            };
            let primary = group_order(&a.change_type).cmp(&group_order(&b.change_type));
            if primary != std::cmp::Ordering::Equal {
                return primary;
            }
            if a.change_type == ChangeType::Updated {
                let jump_a = version_jump(a.old_version.as_deref(), a.new_version.as_deref());
                let jump_b = version_jump(b.old_version.as_deref(), b.new_version.as_deref());
                let by_jump = jump_b.cmp(&jump_a);
                if by_jump != std::cmp::Ordering::Equal {
                    return by_jump;
                }
            }
            a.package_name.cmp(&b.package_name)
        });

        let mut summary = DiffSummary::default();
        for c in &changes {
            match c.change_type {
                ChangeType::Added => summary.added += 1,
                ChangeType::Removed => summary.removed += 1,
                ChangeType::Updated => summary.updated += 1,
                ChangeType::Unchanged => summary.unchanged += 1,
            }
        }

        DependencyDiff {
            base_ref: "base".to_string(),
            changes,
            summary,
        }
    }
}

/// Magnitude of a version change for sort ordering (larger = bigger jump).
///
/// Parses dot-separated numeric segments (PEP 440 style) and weights earlier
/// segments much higher so a major bump always outranks a patch bump.
/// Falls back to `1` when segments cannot be parsed, and `0` for equal versions.
#[allow(dead_code)]
fn version_jump(old: Option<&str>, new: Option<&str>) -> u64 {
    let (old, new) = match (old, new) {
        (Some(o), Some(n)) => (o, n),
        _ => return 0,
    };
    let parse = |v: &str| -> Vec<u64> {
        v.split('.').filter_map(|s| s.parse::<u64>().ok()).collect()
    };
    let o = parse(old);
    let n = parse(new);
    if o.is_empty() || n.is_empty() {
        return if old == new { 0 } else { 1 };
    }
    let weights = [1_000_000_u64, 1_000_u64, 1_u64];
    let max_len = o.len().max(n.len());
    let mut score: u64 = 0;
    for i in 0..max_len {
        let a = o.get(i).copied().unwrap_or(0);
        let b = n.get(i).copied().unwrap_or(0);
        let w = weights.get(i).copied().unwrap_or(1);
        score = score.saturating_add(a.abs_diff(b).saturating_mul(w));
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
    }

    #[test]
    fn test_added_package_detected() {
        let base = vec![];
        let current = vec![pkg("requests", "2.31.0")];
        let diff = DependencyDiffAnalyzer::analyze(&base, &current);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change_type, ChangeType::Added);
        assert_eq!(diff.changes[0].package_name, "requests");
        assert_eq!(diff.changes[0].old_version, None);
        assert_eq!(
            diff.changes[0].new_version,
            Some("2.31.0".to_string())
        );
        assert_eq!(diff.summary.added, 1);
        assert_eq!(diff.summary.removed, 0);
        assert_eq!(diff.summary.updated, 0);
        assert_eq!(diff.summary.unchanged, 0);
    }

    #[test]
    fn test_removed_package_detected() {
        let base = vec![pkg("requests", "2.31.0")];
        let current = vec![];
        let diff = DependencyDiffAnalyzer::analyze(&base, &current);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change_type, ChangeType::Removed);
        assert_eq!(diff.changes[0].old_version, Some("2.31.0".to_string()));
        assert_eq!(diff.changes[0].new_version, None);
        assert_eq!(diff.summary.removed, 1);
    }

    #[test]
    fn test_updated_package_detected() {
        let base = vec![pkg("urllib3", "1.26.5")];
        let current = vec![pkg("urllib3", "2.0.7")];
        let diff = DependencyDiffAnalyzer::analyze(&base, &current);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change_type, ChangeType::Updated);
        assert_eq!(
            diff.changes[0].old_version,
            Some("1.26.5".to_string())
        );
        assert_eq!(
            diff.changes[0].new_version,
            Some("2.0.7".to_string())
        );
        assert_eq!(diff.summary.updated, 1);
    }

    #[test]
    fn test_unchanged_package_detected() {
        let base = vec![pkg("certifi", "2024.2.2")];
        let current = vec![pkg("certifi", "2024.2.2")];
        let diff = DependencyDiffAnalyzer::analyze(&base, &current);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change_type, ChangeType::Unchanged);
        assert_eq!(
            diff.changes[0].old_version,
            Some("2024.2.2".to_string())
        );
        assert_eq!(
            diff.changes[0].new_version,
            Some("2024.2.2".to_string())
        );
        assert_eq!(diff.summary.unchanged, 1);
    }

    #[test]
    fn test_mixed_changes_sorted_added_updated_removed_unchanged() {
        let base = vec![
            pkg("a", "1.0"),
            pkg("b", "1.0"),
            pkg("c", "1.0"),
            pkg("d", "1.0"),
        ];
        let current = vec![
            pkg("a", "1.0"),
            pkg("b", "2.0"),
            pkg("d", "1.0"),
            pkg("e", "1.0"),
        ];
        let diff = DependencyDiffAnalyzer::analyze(&base, &current);
        assert_eq!(diff.summary.added, 1);
        assert_eq!(diff.summary.updated, 1);
        assert_eq!(diff.summary.removed, 1);
        assert_eq!(diff.summary.unchanged, 2);
        let names: Vec<&str> = diff.changes.iter().map(|c| c.package_name.as_str()).collect();
        assert_eq!(names, vec!["e", "b", "c", "a", "d"]);
        assert_eq!(diff.changes[0].change_type, ChangeType::Added);
        assert_eq!(diff.changes[1].change_type, ChangeType::Updated);
        assert_eq!(diff.changes[2].change_type, ChangeType::Removed);
        assert_eq!(diff.changes[3].change_type, ChangeType::Unchanged);
        assert_eq!(diff.changes[4].change_type, ChangeType::Unchanged);
    }

    #[test]
    fn test_updated_largest_jump_first() {
        let base = vec![
            pkg("minor-bump", "1.2.0"),
            pkg("major-bump", "1.0.0"),
            pkg("patch-bump", "1.0.0"),
        ];
        let current = vec![
            pkg("minor-bump", "1.3.0"),
            pkg("major-bump", "2.0.0"),
            pkg("patch-bump", "1.0.1"),
        ];
        let diff = DependencyDiffAnalyzer::analyze(&base, &current);
        assert_eq!(diff.summary.updated, 3);
        let names: Vec<&str> = diff.changes.iter().map(|c| c.package_name.as_str()).collect();
        assert_eq!(names, vec!["major-bump", "minor-bump", "patch-bump"]);
    }

    #[test]
    fn test_empty_inputs_returns_empty_diff() {
        let diff = DependencyDiffAnalyzer::analyze(&[], &[]);
        assert!(diff.changes.is_empty());
        assert_eq!(diff.summary, DiffSummary::default());
        assert_eq!(diff.base_ref, "base");
    }

    #[test]
    fn test_added_package_fields_default_to_none_zero() {
        let diff = DependencyDiffAnalyzer::analyze(&[], &[pkg("foo", "1.0.0")]);
        let change = &diff.changes[0];
        assert_eq!(change.license, None);
        assert_eq!(change.vulnerability_count, 0);
    }

    #[test]
    fn test_non_numeric_version_string_does_not_panic() {
        let base = vec![pkg("foo", "abc")];
        let current = vec![pkg("foo", "xyz")];
        let diff = DependencyDiffAnalyzer::analyze(&base, &current);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change_type, ChangeType::Updated);
    }
}
