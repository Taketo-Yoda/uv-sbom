use super::graph::{bfs_reachable, collect_all_deps};
use super::toml_schema::UvLock;
use crate::ports::outbound::LockfileParseResult;
use crate::sbom_generation::domain::Package;
use crate::shared::error::SbomError;
use crate::shared::Result;
use std::collections::HashMap;
use std::path::Path;

/// Parse uv.lock TOML content and return only packages reachable from
/// the workspace member named `member_name` (root excluded).
///
/// Identifies the member root package by matching `name == member_name` with either
/// `source.editable` or `source.virtual` set (uv < 0.5 uses `editable`; uv >= 0.5
/// uses `virtual` for packages without a build system), then performs BFS over the
/// dependency graph to collect all transitively reachable packages. The member root
/// itself is excluded.
pub fn parse_lockfile_content_for_member(
    content: &str,
    project_path: &Path,
    member_name: &str,
) -> Result<LockfileParseResult> {
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

    let mut full_dep_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut pkg_lookup: HashMap<String, (String, String)> = HashMap::new();
    let mut member_direct_deps: Option<Vec<String>> = None;

    for pkg in &packages {
        let deps = collect_all_deps(&pkg.dependencies, pkg.dev_group());

        let is_member_root =
            pkg.name == member_name && pkg.source.as_ref().map(|s| s.is_local()).unwrap_or(false);

        if is_member_root {
            member_direct_deps = Some(deps.clone());
        }

        full_dep_map.insert(pkg.name.clone(), deps);
        pkg_lookup.insert(pkg.name.clone(), (pkg.name.clone(), pkg.version.clone()));
    }

    let direct_deps = member_direct_deps.ok_or_else(|| {
        anyhow::anyhow!(
            "Workspace member '{}' not found in uv.lock (no package with source.editable or source.virtual set)",
            member_name
        )
    })?;

    let visited = bfs_reachable(&full_dep_map, direct_deps);

    let mut packages = Vec::new();
    let mut dependency_map = HashMap::new();

    for name in &visited {
        if let Some((pkg_name, pkg_version)) = pkg_lookup.get(name) {
            packages.push(Package::new(pkg_name.clone(), pkg_version.clone())?);
            if let Some(deps) = full_dep_map.get(name) {
                dependency_map.insert(pkg_name.clone(), deps.clone());
            }
        }
    }

    Ok((packages, dependency_map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // Workspace lock fixture used by member-scoped filtering tests.
    //
    // Dependency graph:
    //   alpha (editable) -> requests, certifi
    //   beta  (editable) -> urllib3
    //   requests         -> urllib3
    //   urllib3          -> (none)
    //   certifi          -> (none)
    //   shared-lib       -> certifi
    const WORKSPACE_LOCK_FOR_MEMBER: &str = r#"
version = 1
requires-python = ">=3.11"

[manifest]
members = [
    "packages/alpha",
    "packages/beta",
]

[[package]]
name = "alpha"
version = "0.1.0"
source = { editable = "packages/alpha" }
dependencies = [
  { name = "certifi" },
  { name = "requests" },
]

[[package]]
name = "beta"
version = "0.2.0"
source = { editable = "packages/beta" }
dependencies = [
  { name = "urllib3" },
]

[[package]]
name = "certifi"
version = "2024.1.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
  { name = "urllib3" },
]

[[package]]
name = "shared-lib"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
  { name = "certifi" },
]

[[package]]
name = "urllib3"
version = "2.0.7"
source = { registry = "https://pypi.org/simple" }
"#;

    #[test]
    fn test_parse_lockfile_for_member_returns_correct_subtree_for_alpha() {
        let (packages, dep_map) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_FOR_MEMBER,
            Path::new("/workspace"),
            "alpha",
        )
        .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();

        assert!(!names.contains("alpha"), "member root must be excluded");
        assert!(!names.contains("beta"), "sibling member must be excluded");
        assert!(
            !names.contains("shared-lib"),
            "unreachable package must be excluded"
        );

        assert!(names.contains("requests"));
        assert!(names.contains("urllib3"));
        assert!(names.contains("certifi"));

        assert!(dep_map.contains_key("requests"));
        assert!(dep_map.contains_key("urllib3"));
        assert!(dep_map.contains_key("certifi"));
    }

    #[test]
    fn test_parse_lockfile_for_member_returns_correct_subtree_for_beta() {
        let (packages, _dep_map) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_FOR_MEMBER,
            Path::new("/workspace"),
            "beta",
        )
        .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();

        assert!(!names.contains("beta"), "member root must be excluded");
        assert!(!names.contains("alpha"), "sibling member must be excluded");
        assert!(!names.contains("requests"), "unreachable from beta");
        assert!(!names.contains("certifi"), "unreachable from beta");
        assert!(!names.contains("shared-lib"), "unreachable from beta");

        assert!(names.contains("urllib3"));
    }

    #[test]
    fn test_parse_lockfile_for_member_member_root_excluded() {
        let (packages, _) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_FOR_MEMBER,
            Path::new("/workspace"),
            "alpha",
        )
        .unwrap();

        let names: Vec<String> = packages.iter().map(|p| p.name().to_string()).collect();
        assert!(
            !names.contains(&"alpha".to_string()),
            "member root must not appear in result"
        );
    }

    #[test]
    fn test_parse_lockfile_for_member_nonexistent_member_returns_error() {
        let result = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_FOR_MEMBER,
            Path::new("/workspace"),
            "nonexistent-member",
        );

        assert!(result.is_err());
        let err_string = result.unwrap_err().to_string();
        assert!(
            err_string.contains("nonexistent-member"),
            "error must mention the missing member name"
        );
    }

    // Like `parse_lockfile_content` (see `test_parse_lockfile_content_empty_lockfile_returns_no_packages`
    // in `mod.rs`), a `uv.lock` with no `[[package]]` array at all is a parse error for
    // `parse_lockfile_content_for_member`, unlike `parse_group_roots`/`parse_package_sources`
    // which treat it as empty. See `toml_schema::UvLock::package`'s doc comment.
    #[test]
    fn test_parse_lockfile_for_member_no_package_section_at_all_returns_error() {
        let result =
            parse_lockfile_content_for_member("version = 1\n", Path::new("/workspace"), "my-app");
        assert!(result.is_err());
    }

    // uv >= 0.5 workspace lock fixture using `source.virtual` instead of `source.editable`.
    //
    // Dependency graph:
    //   api    (virtual at packages/api)    -> requests, fastapi
    //   worker (virtual at packages/worker) -> celery
    const WORKSPACE_LOCK_VIRTUAL_FORMAT: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = [
    "api",
    "worker",
]

[[package]]
name = "api"
version = "0.1.0"
source = { virtual = "packages/api" }
dependencies = [
  { name = "fastapi" },
  { name = "requests" },
]

[[package]]
name = "celery"
version = "5.4.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "fastapi"
version = "0.115.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "worker"
version = "0.1.0"
source = { virtual = "packages/worker" }
dependencies = [
  { name = "celery" },
]
"#;

    #[test]
    fn test_parse_lockfile_for_member_handles_virtual_source_for_api() {
        let (packages, _) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_VIRTUAL_FORMAT,
            Path::new("/workspace"),
            "api",
        )
        .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();

        assert!(!names.contains("api"), "member root must be excluded");
        assert!(!names.contains("worker"), "sibling member must be excluded");
        assert!(names.contains("requests"));
        assert!(names.contains("fastapi"));
        assert!(!names.contains("celery"), "unreachable from api");
    }

    #[test]
    fn test_parse_lockfile_for_member_handles_virtual_source_for_worker() {
        let (packages, _) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_VIRTUAL_FORMAT,
            Path::new("/workspace"),
            "worker",
        )
        .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();

        assert!(!names.contains("worker"), "member root must be excluded");
        assert!(!names.contains("api"), "sibling member must be excluded");
        assert!(names.contains("celery"));
        assert!(!names.contains("requests"), "unreachable from worker");
        assert!(!names.contains("fastapi"), "unreachable from worker");
    }

    // Member-scoped traversal only folds the `dev` group of `[package.dev-dependencies]`
    // into the reachability graph (via `UvPackage::dev_group`); other named groups (e.g.
    // `test`) must stay excluded, exactly like the pre-split `DevDependencies { dev }`
    // struct behaved.
    const WORKSPACE_LOCK_MULTI_DEV_GROUPS: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = ["my-app"]

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "requests" }]

[package.dev-dependencies]
dev = [{ name = "mypy" }]
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
"#;

    #[test]
    fn test_parse_lockfile_for_member_includes_dev_group_but_not_other_groups() {
        let (packages, _) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_MULTI_DEV_GROUPS,
            Path::new("/project"),
            "my-app",
        )
        .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();
        assert!(
            names.contains("requests"),
            "production dep must be reachable"
        );
        assert!(names.contains("mypy"), "dev group must be reachable");
        assert!(
            !names.contains("pytest"),
            "test group must NOT be reachable"
        );
    }
}
