//! Project-scope helpers shared by use cases that honour `--exclude`,
//! `--exclude-groups`, and `--production-only`.
//!
//! These functions hold the filtering and project-name logic only; reporting
//! (progress lines, warnings, "everything excluded" errors) stays with each
//! caller, because callers differ in what an empty scope means. `GenerateSbomUseCase`
//! refuses to produce an empty SBOM, while `RespondToIncidentUseCase` treats an
//! empty scope as "not affected".
//!
//! None of these helpers filter the dependency map: it must stay complete so
//! direct vs transitive classification remains correct (issue #206 invariant).

use crate::i18n::Messages;
use crate::ports::outbound::lockfile_reader::DependencyMap;
use crate::ports::outbound::{GroupRoots, LockfileReader, ProjectConfigError, ProjectConfigReader};
use crate::sbom_generation::domain::services::GroupReachabilityAnalyzer;
use crate::sbom_generation::domain::Package;
use crate::sbom_generation::services::PackageFilter;
use crate::shared::Result;
use std::path::Path;

/// Result of applying `--exclude` patterns to a package list.
#[derive(Debug)]
pub(crate) struct PatternFilterOutcome {
    /// Packages that survived the exclusion patterns.
    pub packages: Vec<Package>,
    /// Number of packages removed by the patterns.
    pub excluded_count: usize,
    /// Patterns that matched no package, in their original order.
    pub unmatched_patterns: Vec<String>,
}

/// Removes packages matching any of `patterns`.
///
/// An empty `patterns` slice is the identity: the packages are returned
/// unchanged with `excluded_count == 0` and no unmatched patterns.
///
/// # Errors
/// Returns an error if the patterns are invalid (see `PackageFilter::new`).
pub(crate) fn filter_by_patterns(
    packages: Vec<Package>,
    patterns: &[String],
) -> Result<PatternFilterOutcome> {
    if patterns.is_empty() {
        return Ok(PatternFilterOutcome {
            packages,
            excluded_count: 0,
            unmatched_patterns: Vec::new(),
        });
    }

    let filter = PackageFilter::new(patterns.to_vec())?;
    let original_count = packages.len();
    let filtered = filter.filter_packages(packages);
    let excluded_count = original_count - filtered.len();

    Ok(PatternFilterOutcome {
        packages: filtered,
        excluded_count,
        unmatched_patterns: filter.get_unmatched_patterns(),
    })
}

/// Removes packages reachable only from the dependency groups in `exclude_groups`.
///
/// An empty `exclude_groups` slice is the identity and performs no I/O (the
/// group roots are not read). Otherwise reads the group roots through `reader`
/// and delegates to `GroupReachabilityAnalyzer::filter_excluded_groups`, so a
/// package that any non-excluded group reaches is kept (#1005).
/// `dependency_map` is only read, never filtered (issue #206 invariant).
///
/// # Errors
/// Returns an error if the group roots cannot be read from the lockfile.
pub(crate) fn filter_by_groups<LR: LockfileReader>(
    reader: &LR,
    project_path: &Path,
    packages: Vec<Package>,
    dependency_map: &DependencyMap,
    exclude_groups: &[String],
) -> Result<Vec<Package>> {
    filter_by_group_roots(packages, dependency_map, exclude_groups, || {
        reader.read_and_parse_group_roots(project_path)
    })
}

/// [`filter_by_groups`] for one workspace member: the group roots are read
/// from `member_name`'s own entry, so a revision-3 lockfile does not apply
/// another member's `[package.dev-dependencies]` (#992).
///
/// A package that any of the member's non-excluded groups reaches is kept
/// (#1001): the workspace-wide manifest groups are merged into every member's
/// groups (#999), so excluding one of them must not drop a package the member
/// still uses through its own group.
///
/// # Errors
/// Returns an error if the group roots cannot be read from the lockfile.
pub(crate) fn filter_by_groups_for_member<LR: LockfileReader>(
    reader: &LR,
    project_path: &Path,
    member_name: &str,
    packages: Vec<Package>,
    dependency_map: &DependencyMap,
    exclude_groups: &[String],
) -> Result<Vec<Package>> {
    filter_by_group_roots(packages, dependency_map, exclude_groups, || {
        reader.read_and_parse_group_roots_for_member(project_path, member_name)
    })
}

fn filter_by_group_roots(
    packages: Vec<Package>,
    dependency_map: &DependencyMap,
    exclude_groups: &[String],
    read_roots: impl FnOnce() -> Result<GroupRoots>,
) -> Result<Vec<Package>> {
    if exclude_groups.is_empty() {
        return Ok(packages);
    }

    let group_roots = read_roots()?;
    Ok(GroupReachabilityAnalyzer::filter_excluded_groups(
        &packages,
        dependency_map,
        &group_roots,
        exclude_groups,
    ))
}

/// Reads the project name, localizing a missing `pyproject.toml`.
///
/// The adapter returns a typed `ProjectConfigError` rather than localized text
/// (#870); it is localized here with `msgs`. The error is replaced (not wrapped
/// with `.context()`) so the English `Display` text is not printed as a cause.
///
/// # Errors
/// Returns the localized `error_pyproject_not_found` message when
/// `pyproject.toml` is missing, or the reader's own error otherwise.
pub(crate) fn read_project_name_localized<PCR: ProjectConfigReader>(
    reader: &PCR,
    project_path: &Path,
    msgs: &Messages,
) -> Result<String> {
    reader.read_project_name(project_path).map_err(|e| {
        match e.downcast_ref::<ProjectConfigError>() {
            Some(ProjectConfigError::PyprojectNotFound) => {
                anyhow::anyhow!("{}", msgs.error_pyproject_not_found)
            }
            None => e,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::test_doubles::{
        MockLockfileReader, MockProjectConfigReader,
    };
    use crate::i18n::Locale;
    use std::collections::HashMap;

    fn pkg(name: &str, version: &str) -> Package {
        Package::new(name.to_string(), version.to_string()).unwrap()
    }

    fn names(packages: &[Package]) -> Vec<&str> {
        packages.iter().map(|p| p.name()).collect()
    }

    fn reader_with_groups(group_roots: GroupRoots) -> MockLockfileReader {
        MockLockfileReader {
            group_roots,
            ..MockLockfileReader::default()
        }
    }

    #[test]
    fn test_filter_by_patterns_empty_is_identity() {
        let outcome = filter_by_patterns(vec![pkg("a", "1.0.0"), pkg("b", "1.0.0")], &[]).unwrap();

        assert_eq!(names(&outcome.packages), vec!["a", "b"]);
        assert_eq!(outcome.excluded_count, 0);
        assert!(outcome.unmatched_patterns.is_empty());
    }

    #[test]
    fn test_filter_by_patterns_reports_excluded_and_unmatched() {
        let outcome = filter_by_patterns(
            vec![pkg("requests", "1.0.0"), pkg("urllib3", "2.0.0")],
            &["requests".to_string(), "nomatch".to_string()],
        )
        .unwrap();

        assert_eq!(names(&outcome.packages), vec!["urllib3"]);
        assert_eq!(outcome.excluded_count, 1);
        assert_eq!(outcome.unmatched_patterns, vec!["nomatch".to_string()]);
    }

    #[test]
    fn test_filter_by_patterns_may_exclude_everything() {
        let outcome = filter_by_patterns(vec![pkg("a", "1.0.0")], &["a".to_string()]).unwrap();

        assert!(outcome.packages.is_empty());
        assert_eq!(outcome.excluded_count, 1);
    }

    #[test]
    fn test_filter_by_groups_empty_is_identity() {
        let reader = reader_with_groups(HashMap::new());
        let filtered = filter_by_groups(
            &reader,
            Path::new("/p"),
            vec![pkg("a", "1.0.0")],
            &HashMap::new(),
            &[],
        )
        .unwrap();

        assert_eq!(names(&filtered), vec!["a"]);
    }

    #[test]
    fn test_filter_by_groups_removes_group_only_packages() {
        let reader = reader_with_groups(HashMap::from([(
            "dev".to_string(),
            vec!["pytest".to_string()],
        )]));
        let deps: DependencyMap = HashMap::from([
            ("app".to_string(), vec!["requests".to_string()]),
            ("requests".to_string(), vec![]),
            ("pytest".to_string(), vec![]),
        ]);

        let filtered = filter_by_groups(
            &reader,
            Path::new("/p"),
            vec![
                pkg("app", "1.0.0"),
                pkg("requests", "2.0.0"),
                pkg("pytest", "7.0.0"),
            ],
            &deps,
            &["dev".to_string()],
        )
        .unwrap();

        assert_eq!(names(&filtered), vec!["app", "requests"]);
    }

    #[test]
    fn test_filter_by_groups_for_member_removes_group_only_packages() {
        let reader = reader_with_groups(HashMap::from([(
            "dev".to_string(),
            vec!["pytest".to_string()],
        )]));
        let deps: DependencyMap = HashMap::from([
            ("app".to_string(), vec!["requests".to_string()]),
            ("requests".to_string(), vec![]),
            ("pytest".to_string(), vec![]),
        ]);

        let filtered = filter_by_groups_for_member(
            &reader,
            Path::new("/ws"),
            "app",
            vec![pkg("requests", "2.0.0"), pkg("pytest", "7.0.0")],
            &deps,
            &["dev".to_string()],
        )
        .unwrap();

        assert_eq!(names(&filtered), vec!["requests"]);
    }

    /// `docs` and `lint` share the root `sphinx`; only `docs` is excluded (#1001, #1005).
    fn shared_root_scope() -> (MockLockfileReader, DependencyMap, Vec<Package>) {
        let reader = reader_with_groups(HashMap::from([
            ("docs".to_string(), vec!["sphinx".to_string()]),
            ("lint".to_string(), vec!["sphinx".to_string()]),
        ]));
        let deps: DependencyMap = HashMap::from([
            ("app".to_string(), vec!["requests".to_string()]),
            ("requests".to_string(), vec![]),
            ("sphinx".to_string(), vec![]),
        ]);
        let packages = vec![pkg("requests", "2.0.0"), pkg("sphinx", "7.0.0")];
        (reader, deps, packages)
    }

    #[test]
    fn test_filter_by_groups_for_member_keeps_root_shared_with_kept_group() {
        let (reader, deps, packages) = shared_root_scope();

        let filtered = filter_by_groups_for_member(
            &reader,
            Path::new("/ws"),
            "app",
            packages,
            &deps,
            &["docs".to_string()],
        )
        .unwrap();

        assert_eq!(names(&filtered), vec!["requests", "sphinx"]);
    }

    #[test]
    fn test_filter_by_groups_keeps_root_shared_with_kept_group() {
        // Single-project mode now matches member scope (#1005).
        let (reader, deps, packages) = shared_root_scope();

        let filtered = filter_by_groups(
            &reader,
            Path::new("/p"),
            packages,
            &deps,
            &["docs".to_string()],
        )
        .unwrap();

        assert_eq!(names(&filtered), vec!["requests", "sphinx"]);
    }

    #[test]
    fn test_read_project_name_localized_success() {
        let reader = MockProjectConfigReader {
            project_name: "myapp".to_string(),
            pyproject_missing: false,
        };
        let name =
            read_project_name_localized(&reader, Path::new("/p"), Messages::for_locale(Locale::En))
                .unwrap();

        assert_eq!(name, "myapp");
    }

    #[test]
    fn test_read_project_name_localized_missing_pyproject_ja() {
        let reader = MockProjectConfigReader {
            project_name: String::new(),
            pyproject_missing: true,
        };
        let err =
            read_project_name_localized(&reader, Path::new("/p"), Messages::for_locale(Locale::Ja))
                .unwrap_err();

        assert_eq!(err.chain().count(), 1);
        assert_eq!(
            err.to_string(),
            "プロジェクトディレクトリに pyproject.toml が見つかりません。"
        );
    }
}
