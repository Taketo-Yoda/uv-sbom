mod graph;
mod group_roots;
mod member_scope;
mod source_classifier;
mod toml_schema;

#[cfg(test)]
use crate::ports::outbound::PackageSourceKind;
use crate::ports::outbound::{LockfileParseResult, PackageSourceMap};
use crate::sbom_generation::domain::Package;
use crate::shared::error::SbomError;
use crate::shared::Result;
pub use group_roots::parse_group_roots;
pub use member_scope::parse_lockfile_content_for_member;
use std::collections::HashMap;
use std::path::Path;
use toml_schema::UvLock;

/// Parse uv.lock TOML content into (packages, dependency_map).
///
/// Pure function: no I/O, no `&self`. Suitable for reuse by any adapter
/// that has the raw lockfile bytes (filesystem, git blob, in-memory, etc.).
pub fn parse_lockfile_content(content: &str, project_path: &Path) -> Result<LockfileParseResult> {
    let lockfile: UvLock = toml::from_str(content).map_err(|e| SbomError::LockfileParseError {
        path: project_path.join("uv.lock"),
        details: e.to_string(),
    })?;

    let packages = lockfile
        .package
        .ok_or_else(|| SbomError::LockfileParseError {
            path: project_path.join("uv.lock"),
            details: "missing field `package`".to_string(),
        })?;

    let mut result_packages = Vec::new();
    let mut dependency_map = HashMap::new();

    for pkg in packages {
        result_packages.push(Package::new(pkg.name.clone(), pkg.version.clone())?);

        let deps: Vec<String> = pkg.dependencies.iter().map(|d| d.name.clone()).collect();
        dependency_map.insert(pkg.name, deps);
    }

    Ok((result_packages, dependency_map))
}

/// Parse `uv.lock` content into a map of package name → source classification.
///
/// Packages whose `[[package]]` entry has no `source` field are omitted from
/// the returned map. Invalid TOML returns an error.
pub fn parse_package_sources(content: &str, project_path: &Path) -> Result<PackageSourceMap> {
    let lockfile: UvLock = toml::from_str(content).map_err(|e| SbomError::LockfileParseError {
        path: project_path.join("uv.lock"),
        details: e.to_string(),
    })?;

    let mut map = PackageSourceMap::new();
    for pkg in lockfile.package.unwrap_or_default() {
        if let Some(source) = pkg.source {
            map.insert(pkg.name, source.to_kind());
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::path::Path;

    const SIMPLE_LOCK: &str = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
  { name = "urllib3" },
]

[[package]]
name = "urllib3"
version = "2.0.7"
source = { registry = "https://pypi.org/simple" }
"#;

    // Revision-3 lockfile with dev-dependency groups on the local project package.
    // Production dep: requests. Dev groups: dev=[mypy, ruff], test=[pytest].
    const LOCK_REV3_WITH_DEV_GROUPS: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[package.dev-dependencies]
dev = [{ name = "mypy" }, { name = "ruff" }]
test = [{ name = "pytest" }]

[[package]]
name = "mypy"
version = "1.8.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "ruff"
version = "0.3.0"
source = { registry = "https://pypi.org/simple" }
"#;

    #[test]
    fn test_parse_lockfile_content_dev_group_packages_not_added_to_dep_map_as_children() {
        let (_packages, dep_map) =
            parse_lockfile_content(LOCK_REV3_WITH_DEV_GROUPS, Path::new("/project")).unwrap();

        let root_deps = &dep_map["my-app"];
        assert!(
            root_deps.contains(&"requests".to_string()),
            "production dep must remain a child of root"
        );
        assert!(
            !root_deps.contains(&"mypy".to_string()),
            "dev-group package must NOT be a child of root"
        );
        assert!(!root_deps.contains(&"ruff".to_string()));
        assert!(!root_deps.contains(&"pytest".to_string()));

        // Dev packages are orphan roots: no package in the map points to them.
        let has_parent: HashSet<&String> = dep_map.values().flatten().collect();
        for orphan in ["mypy", "ruff", "pytest"] {
            assert!(
                !has_parent.contains(&orphan.to_string()),
                "{orphan} must be an orphan root (no parent edge)"
            );
        }
    }

    #[test]
    fn test_parse_lockfile_content_all_packages_present_without_group_filter() {
        let (packages, _dep_map) =
            parse_lockfile_content(LOCK_REV3_WITH_DEV_GROUPS, Path::new("/project")).unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();
        for expected in ["my-app", "requests", "mypy", "ruff", "pytest"] {
            assert!(
                names.contains(expected),
                "{expected} must still appear in the packages list"
            );
        }
    }

    #[test]
    fn test_parse_lockfile_content_basic_returns_packages_and_deps() {
        let (packages, dep_map) =
            parse_lockfile_content(SIMPLE_LOCK, Path::new("/project")).unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();
        assert!(names.contains("requests"));
        assert!(names.contains("urllib3"));
        assert_eq!(dep_map["requests"], vec!["urllib3"]);
        assert!(dep_map["urllib3"].is_empty());
    }

    #[test]
    fn test_parse_lockfile_content_invalid_toml_returns_error() {
        let result = parse_lockfile_content("not valid toml [[[", Path::new("/project"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_lockfile_content_empty_lockfile_returns_no_packages() {
        let content = "version = 1\n";
        let result = parse_lockfile_content(content, Path::new("/project"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_package_sources_returns_empty_when_no_package_section_at_all() {
        let map = parse_package_sources("version = 1\n", Path::new("/project")).unwrap();
        assert!(map.is_empty());
    }

    // --- PackageSourceKind and parse_package_sources tests ---

    const MIXED_SOURCES_LOCK: &str = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "private-pkg"
version = "1.0.0"
source = { registry = "https://private.example.com/simple" }

[[package]]
name = "git-pkg"
version = "0.1.0"
source = { git = "https://github.com/user/repo?rev=abc123" }

[[package]]
name = "local-pkg"
version = "0.2.0"
source = { path = "/some/local/path" }

[[package]]
name = "url-pkg"
version = "0.3.0"
source = { url = "https://example.com/package.tar.gz" }

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "my-lib"
version = "0.1.0"
source = { editable = "packages/my-lib" }

[[package]]
name = "no-source-pkg"
version = "1.0.0"
"#;

    #[test]
    fn test_parse_package_sources_classifies_pypi_registry() {
        let map = parse_package_sources(MIXED_SOURCES_LOCK, Path::new("/project")).unwrap();
        assert_eq!(map["requests"], PackageSourceKind::PyPi);
    }

    #[test]
    fn test_parse_package_sources_classifies_private_registry() {
        let map = parse_package_sources(MIXED_SOURCES_LOCK, Path::new("/project")).unwrap();
        assert_eq!(
            map["private-pkg"],
            PackageSourceKind::PrivateRegistry("https://private.example.com/simple".to_string())
        );
    }

    #[test]
    fn test_parse_package_sources_classifies_git() {
        let map = parse_package_sources(MIXED_SOURCES_LOCK, Path::new("/project")).unwrap();
        assert_eq!(
            map["git-pkg"],
            PackageSourceKind::Git("https://github.com/user/repo?rev=abc123".to_string())
        );
    }

    #[test]
    fn test_parse_package_sources_classifies_local_path() {
        let map = parse_package_sources(MIXED_SOURCES_LOCK, Path::new("/project")).unwrap();
        assert_eq!(
            map["local-pkg"],
            PackageSourceKind::LocalPath("/some/local/path".to_string())
        );
    }

    #[test]
    fn test_parse_package_sources_classifies_direct_url() {
        let map = parse_package_sources(MIXED_SOURCES_LOCK, Path::new("/project")).unwrap();
        assert_eq!(
            map["url-pkg"],
            PackageSourceKind::DirectUrl("https://example.com/package.tar.gz".to_string())
        );
    }

    #[test]
    fn test_parse_package_sources_classifies_virtual_as_workspace_member() {
        let map = parse_package_sources(MIXED_SOURCES_LOCK, Path::new("/project")).unwrap();
        assert_eq!(map["my-app"], PackageSourceKind::WorkspaceMember);
    }

    #[test]
    fn test_parse_package_sources_classifies_editable_as_workspace_member() {
        let map = parse_package_sources(MIXED_SOURCES_LOCK, Path::new("/project")).unwrap();
        assert_eq!(map["my-lib"], PackageSourceKind::WorkspaceMember);
    }

    #[test]
    fn test_parse_package_sources_omits_packages_without_source() {
        let map = parse_package_sources(MIXED_SOURCES_LOCK, Path::new("/project")).unwrap();
        assert!(!map.contains_key("no-source-pkg"));
    }

    #[test]
    fn test_parse_package_sources_invalid_toml_returns_error() {
        let result = parse_package_sources("invalid [[[ toml", Path::new("/project"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_package_sources_pypi_trailing_slash_normalized() {
        let content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple/" }
"#;
        let map = parse_package_sources(content, Path::new("/project")).unwrap();
        assert_eq!(map["requests"], PackageSourceKind::PyPi);
    }

    #[test]
    fn test_package_source_kind_is_non_pypi_external() {
        assert!(!PackageSourceKind::PyPi.is_non_pypi_external());
        assert!(PackageSourceKind::PrivateRegistry("url".to_string()).is_non_pypi_external());
        assert!(PackageSourceKind::Git("url".to_string()).is_non_pypi_external());
        assert!(!PackageSourceKind::LocalPath("path".to_string()).is_non_pypi_external());
        assert!(PackageSourceKind::DirectUrl("url".to_string()).is_non_pypi_external());
        assert!(!PackageSourceKind::WorkspaceMember.is_non_pypi_external());
    }

    #[test]
    fn test_package_source_kind_label() {
        assert_eq!(PackageSourceKind::PyPi.label(), "PyPI");
        assert_eq!(
            PackageSourceKind::PrivateRegistry("url".to_string()).label(),
            "Private Registry"
        );
        assert_eq!(PackageSourceKind::Git("url".to_string()).label(), "Git");
        assert_eq!(
            PackageSourceKind::LocalPath("path".to_string()).label(),
            "Local Path"
        );
        assert_eq!(
            PackageSourceKind::DirectUrl("url".to_string()).label(),
            "Direct URL"
        );
        assert_eq!(
            PackageSourceKind::WorkspaceMember.label(),
            "Workspace Member"
        );
    }

    #[test]
    fn test_package_source_kind_value() {
        assert_eq!(PackageSourceKind::PyPi.value(), "");
        assert_eq!(
            PackageSourceKind::PrivateRegistry("https://example.com".to_string()).value(),
            "https://example.com"
        );
        assert_eq!(
            PackageSourceKind::Git("https://github.com/u/r".to_string()).value(),
            "https://github.com/u/r"
        );
        assert_eq!(
            PackageSourceKind::LocalPath("/path/to/pkg".to_string()).value(),
            "/path/to/pkg"
        );
        assert_eq!(
            PackageSourceKind::DirectUrl("https://example.com/pkg.tar.gz".to_string()).value(),
            "https://example.com/pkg.tar.gz"
        );
        assert_eq!(PackageSourceKind::WorkspaceMember.value(), "");
    }
}
