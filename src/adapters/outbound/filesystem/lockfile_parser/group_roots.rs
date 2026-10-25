use super::toml_schema::{Manifest, UvDependency, UvLock, UvPackage};
use crate::ports::outbound::GroupRoots;
use crate::shared::error::SbomError;
use crate::shared::Result;
use std::collections::HashMap;
use std::path::Path;

/// Parse dependency-group roots from uv.lock content.
///
/// Returns a map of group name → list of root package names.
/// Returns an empty map when no group information is present.
///
/// Supports two lockfile formats:
///
/// **Revision ≤ 2** (`[manifest.dependency-groups]`):
/// ```toml
/// [manifest.dependency-groups]
/// dev = [{ name = "pytest" }, { name = "mypy" }]
/// lint = [{ name = "ruff" }]
/// ```
///
/// **Revision 3** (`[package.dev-dependencies]` on the local project package):
/// ```toml
/// [[package]]
/// name = "my-app"
/// source = { virtual = "." }
///
/// [package.dev-dependencies]
/// dev  = [{ name = "mypy" }, { name = "ruff" }]
/// test = [{ name = "pytest" }]
/// ```
///
/// In a workspace every member is a local package, so the revision-3 fallback
/// picks the first one; use [`parse_group_roots_for_member`] to read a specific
/// member's groups.
///
/// # Errors
///
/// Returns `SbomError::LockfileParseError` if `content` is not valid `uv.lock` TOML.
pub fn parse_group_roots(content: &str, project_path: &Path) -> Result<GroupRoots> {
    parse_group_roots_impl(content, project_path, None)
}

/// Parse dependency-group roots for the workspace member named `member_name`.
///
/// Revision ≤ 2 `[manifest.dependency-groups]` are workspace-wide, so they are
/// returned as by [`parse_group_roots`]. The revision-3 fallback reads the
/// `[package.dev-dependencies]` of the local package whose `name == member_name`
/// (the same match `parse_lockfile_content_for_member` uses), and returns an
/// empty map when there is no such package — never another member's groups.
///
/// # Errors
///
/// Returns `SbomError::LockfileParseError` if `content` is not valid `uv.lock` TOML.
pub fn parse_group_roots_for_member(
    content: &str,
    project_path: &Path,
    member_name: &str,
) -> Result<GroupRoots> {
    parse_group_roots_impl(content, project_path, Some(member_name))
}

fn parse_group_roots_impl(
    content: &str,
    project_path: &Path,
    member: Option<&str>,
) -> Result<GroupRoots> {
    let lockfile: UvLock = toml::from_str(content).map_err(|e| SbomError::LockfileParseError {
        path: project_path.join("uv.lock"),
        details: e.to_string(),
    })?;

    let UvLock { package, manifest } = lockfile;

    // Revision ≤ 2: prefer [manifest.dependency-groups] when present and non-empty.
    let manifest_groups = manifest_groups_v2(manifest);
    if !manifest_groups.is_empty() {
        return Ok(manifest_groups);
    }

    // Revision 3 fallback: read [package.dev-dependencies] from the local project package.
    Ok(package_dev_dependencies_v3(package, member))
}

/// Revision ≤ 2: reads `[manifest.dependency-groups]`.
fn manifest_groups_v2(manifest: Option<Manifest>) -> GroupRoots {
    manifest
        .map(|m| deps_map_to_group_roots(m.dependency_groups))
        .unwrap_or_default()
}

/// Revision 3 fallback: reads `[package.dev-dependencies]` from a local package
/// (`source.virtual` or `source.editable`): the one named `member` when given,
/// otherwise the first local package.
fn package_dev_dependencies_v3(
    packages: Option<Vec<UvPackage>>,
    member: Option<&str>,
) -> GroupRoots {
    packages
        .unwrap_or_default()
        .into_iter()
        .find(|pkg| match member {
            Some(name) => pkg.is_local_named(name),
            None => pkg.is_local(),
        })
        .and_then(|pkg| pkg.dev_dependencies)
        .map(deps_map_to_group_roots)
        .unwrap_or_default()
}

/// Flattens a group name → dependency-entry map into a group name → package-name map.
fn deps_map_to_group_roots(groups: HashMap<String, Vec<UvDependency>>) -> GroupRoots {
    groups
        .into_iter()
        .map(|(group, deps)| (group, deps.into_iter().map(|d| d.name).collect()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> UvLock {
        toml::from_str(content).unwrap()
    }

    const LOCK_WITH_GROUPS: &str = r#"
version = 1
requires-python = ">=3.11"

[manifest]
members = ["my-app"]

[manifest.dependency-groups]
dev = [{ name = "pytest" }, { name = "mypy" }]
lint = [{ name = "ruff" }]

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
"#;

    const LOCK_WITH_MANIFEST_NO_GROUPS: &str = r#"
version = 1
requires-python = ">=3.11"

[manifest]
members = ["my-app"]

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
"#;

    const LOCK_WITHOUT_MANIFEST: &str = r#"
version = 1
requires-python = ">=3.8"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    #[test]
    fn test_parse_group_roots_extracts_multiple_groups() {
        let roots = parse_group_roots(LOCK_WITH_GROUPS, Path::new("/project")).unwrap();

        assert_eq!(roots.len(), 2);

        let mut dev = roots["dev"].clone();
        dev.sort();
        assert_eq!(dev, vec!["mypy", "pytest"]);

        assert_eq!(roots["lint"], vec!["ruff"]);
    }

    #[test]
    fn test_parse_group_roots_returns_empty_when_manifest_has_no_groups() {
        let roots = parse_group_roots(LOCK_WITH_MANIFEST_NO_GROUPS, Path::new("/project")).unwrap();
        assert!(roots.is_empty());
    }

    #[test]
    fn test_parse_group_roots_returns_empty_when_no_manifest_section() {
        let roots = parse_group_roots(LOCK_WITHOUT_MANIFEST, Path::new("/project")).unwrap();
        assert!(roots.is_empty());
    }

    #[test]
    fn test_parse_group_roots_returns_error_on_invalid_toml() {
        let result = parse_group_roots("invalid [[[ toml", Path::new("/project"));
        assert!(result.is_err());
    }

    // Unlike `parse_lockfile_content` / `parse_lockfile_content_for_member`, a `uv.lock`
    // with no `[[package]]` array at all is not an error for `parse_group_roots` — it
    // simply yields no group roots. This asymmetry predates the shared `UvLock` schema
    // (see `toml_schema::UvLock::package`'s doc comment) and must not regress.
    #[test]
    fn test_parse_group_roots_returns_empty_when_no_package_section_at_all() {
        let roots = parse_group_roots("version = 1\n", Path::new("/project")).unwrap();
        assert!(roots.is_empty());
    }

    // --- parse_group_roots revision 3 tests ---

    const LOCK_REV3_SINGLE_GROUP: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }

[package.dev-dependencies]
dev = [{ name = "mypy" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    const LOCK_REV3_MULTIPLE_GROUPS: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "requests" }]

[package.dev-dependencies]
dev = [{ name = "mypy" }, { name = "ruff" }]
test = [{ name = "pytest" }, { name = "pytest-cov" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    const LOCK_REV3_MIXED_WITH_PROD_DEPS: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "certifi" },
    { name = "requests" },
]

[package.dev-dependencies]
dev = [{ name = "mypy" }]

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    const LOCK_REV3_EDITABLE_SOURCE: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "my-app"
version = "0.1.0"
source = { editable = "." }

[package.dev-dependencies]
dev = [{ name = "ruff" }]
"#;

    const LOCK_REV3_NO_PROJECT_PACKAGE: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "urllib3"
version = "2.0.7"
source = { registry = "https://pypi.org/simple" }
"#;

    #[test]
    fn test_parse_group_roots_rev3_single_group() {
        let roots = parse_group_roots(LOCK_REV3_SINGLE_GROUP, Path::new("/project")).unwrap();

        assert_eq!(roots.len(), 1);
        assert_eq!(roots["dev"], vec!["mypy"]);
    }

    #[test]
    fn test_parse_group_roots_rev3_multiple_groups() {
        let roots = parse_group_roots(LOCK_REV3_MULTIPLE_GROUPS, Path::new("/project")).unwrap();

        assert_eq!(roots.len(), 2);

        let mut dev = roots["dev"].clone();
        dev.sort();
        assert_eq!(dev, vec!["mypy", "ruff"]);

        let mut test_group = roots["test"].clone();
        test_group.sort();
        assert_eq!(test_group, vec!["pytest", "pytest-cov"]);
    }

    #[test]
    fn test_parse_group_roots_rev3_mixed_with_production_deps() {
        let roots =
            parse_group_roots(LOCK_REV3_MIXED_WITH_PROD_DEPS, Path::new("/project")).unwrap();

        assert_eq!(roots.len(), 1);
        assert_eq!(roots["dev"], vec!["mypy"]);
        assert!(
            !roots.contains_key("requests"),
            "production dep must not appear in group roots"
        );
        assert!(
            !roots.contains_key("certifi"),
            "production dep must not appear in group roots"
        );
    }

    #[test]
    fn test_parse_group_roots_rev3_editable_source() {
        let roots = parse_group_roots(LOCK_REV3_EDITABLE_SOURCE, Path::new("/project")).unwrap();

        assert_eq!(roots.len(), 1);
        assert_eq!(roots["dev"], vec!["ruff"]);
    }

    #[test]
    fn test_parse_group_roots_rev3_returns_empty_when_no_project_package() {
        let roots = parse_group_roots(LOCK_REV3_NO_PROJECT_PACKAGE, Path::new("/project")).unwrap();
        assert!(roots.is_empty());
    }

    // --- manifest_groups_v2 unit tests ---

    #[test]
    fn test_manifest_groups_v2_extracts_groups() {
        let roots = manifest_groups_v2(parse(LOCK_WITH_GROUPS).manifest);

        assert_eq!(roots.len(), 2);
        let mut dev = roots["dev"].clone();
        dev.sort();
        assert_eq!(dev, vec!["mypy", "pytest"]);
        assert_eq!(roots["lint"], vec!["ruff"]);
    }

    #[test]
    fn test_manifest_groups_v2_returns_empty_when_manifest_is_none() {
        let roots = manifest_groups_v2(None);
        assert!(roots.is_empty());
    }

    #[test]
    fn test_manifest_groups_v2_ignores_package_dev_dependencies() {
        // A revision-3 lockfile has no [manifest.dependency-groups] section, so the
        // v2 helper must return empty even though the package array carries dev deps.
        let roots = manifest_groups_v2(parse(LOCK_REV3_SINGLE_GROUP).manifest);
        assert!(roots.is_empty());
    }

    // --- package_dev_dependencies_v3 unit tests ---

    #[test]
    fn test_package_dev_dependencies_v3_reads_local_project_package() {
        let roots = package_dev_dependencies_v3(parse(LOCK_REV3_MULTIPLE_GROUPS).package, None);

        assert_eq!(roots.len(), 2);
        let mut dev = roots["dev"].clone();
        dev.sort();
        assert_eq!(dev, vec!["mypy", "ruff"]);
    }

    #[test]
    fn test_package_dev_dependencies_v3_returns_empty_when_packages_is_none() {
        let roots = package_dev_dependencies_v3(None, None);
        assert!(roots.is_empty());
    }

    #[test]
    fn test_package_dev_dependencies_v3_returns_empty_when_no_local_package() {
        let roots = package_dev_dependencies_v3(parse(LOCK_REV3_NO_PROJECT_PACKAGE).package, None);
        assert!(roots.is_empty());
    }

    #[test]
    fn test_package_dev_dependencies_v3_accepts_editable_source() {
        let roots = package_dev_dependencies_v3(parse(LOCK_REV3_EDITABLE_SOURCE).package, None);
        assert_eq!(roots["dev"], vec!["ruff"]);
    }

    // --- fallback ordering regression tests ---

    const LOCK_BOTH_MANIFEST_AND_PACKAGE_GROUPS: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = ["my-app"]

[manifest.dependency-groups]
dev = [{ name = "mypy" }]

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }

[package.dev-dependencies]
dev = [{ name = "ruff" }]
"#;

    #[test]
    fn test_parse_group_roots_prefers_manifest_groups_over_package_dev_dependencies() {
        let roots = parse_group_roots(LOCK_BOTH_MANIFEST_AND_PACKAGE_GROUPS, Path::new("/project"))
            .unwrap();

        assert_eq!(
            roots["dev"],
            vec!["mypy"],
            "manifest groups must take priority over package dev-dependencies"
        );
    }

    const LOCK_EMPTY_MANIFEST_GROUPS_WITH_PACKAGE_GROUPS: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = ["my-app"]

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }

[package.dev-dependencies]
dev = [{ name = "ruff" }]
"#;

    #[test]
    fn test_parse_group_roots_falls_back_when_manifest_groups_section_is_empty() {
        let roots = parse_group_roots(
            LOCK_EMPTY_MANIFEST_GROUPS_WITH_PACKAGE_GROUPS,
            Path::new("/project"),
        )
        .unwrap();

        assert_eq!(
            roots["dev"],
            vec!["ruff"],
            "must fall back to package dev-dependencies when manifest has a [manifest] \
             section but no non-empty dependency-groups"
        );
    }

    // --- parse_group_roots_for_member tests (#992) ---

    // Revision-3 workspace: every member is a local package, listed in name order.
    const LOCK_REV3_WORKSPACE_TWO_MEMBERS: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = ["a", "b"]

[[package]]
name = "a"
version = "0.1.0"
source = { editable = "packages/a" }

[package.dev-dependencies]
dev = [{ name = "mypy" }]

[[package]]
name = "b"
version = "0.1.0"
source = { editable = "packages/b" }

[package.dev-dependencies]
dev = [{ name = "ruff" }]
lint = [{ name = "black" }]

[[package]]
name = "black"
version = "24.1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "mypy"
version = "1.8.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "ruff"
version = "0.3.0"
source = { registry = "https://pypi.org/simple" }
"#;

    #[test]
    fn test_parse_group_roots_for_member_reads_each_members_own_groups() {
        let path = Path::new("/ws");

        let a = parse_group_roots_for_member(LOCK_REV3_WORKSPACE_TWO_MEMBERS, path, "a").unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a["dev"], vec!["mypy"]);

        let b = parse_group_roots_for_member(LOCK_REV3_WORKSPACE_TWO_MEMBERS, path, "b").unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!(b["dev"], vec!["ruff"]);
        assert_eq!(b["lint"], vec!["black"]);
    }

    #[test]
    fn test_parse_group_roots_for_member_returns_empty_for_unknown_member() {
        let roots =
            parse_group_roots_for_member(LOCK_REV3_WORKSPACE_TWO_MEMBERS, Path::new("/ws"), "c")
                .unwrap();
        assert!(
            roots.is_empty(),
            "an unknown member must not fall back to another member's groups"
        );
    }

    #[test]
    fn test_parse_group_roots_for_member_ignores_registry_package_with_member_name() {
        // Only a local package can be a member root, as in `parse_lockfile_content_for_member`.
        let roots =
            parse_group_roots_for_member(LOCK_REV3_WORKSPACE_TWO_MEMBERS, Path::new("/ws"), "ruff")
                .unwrap();
        assert!(roots.is_empty());
    }

    #[test]
    fn test_parse_group_roots_for_member_returns_manifest_groups_for_any_member() {
        // Revision ≤ 2 manifest groups are workspace-wide by design.
        let roots =
            parse_group_roots_for_member(LOCK_WITH_GROUPS, Path::new("/project"), "other").unwrap();
        assert_eq!(roots.len(), 2);
        assert_eq!(roots["lint"], vec!["ruff"]);
    }

    #[test]
    fn test_parse_group_roots_for_member_returns_error_on_invalid_toml() {
        let result = parse_group_roots_for_member("invalid [[[ toml", Path::new("/ws"), "a");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_group_roots_single_project_still_reads_first_local_package() {
        // Single-project mode keeps the first-local-package fallback.
        let roots = parse_group_roots(LOCK_REV3_WORKSPACE_TWO_MEMBERS, Path::new("/ws")).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots["dev"], vec!["mypy"]);
    }

    #[test]
    fn test_package_dev_dependencies_v3_selects_named_member() {
        let roots =
            package_dev_dependencies_v3(parse(LOCK_REV3_WORKSPACE_TWO_MEMBERS).package, Some("b"));
        assert_eq!(roots["dev"], vec!["ruff"]);
    }
}
