use crate::ports::outbound::{GroupRoots, LockfileParseResult};
use crate::sbom_generation::domain::Package;
use crate::shared::error::SbomError;
use crate::shared::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

// Shared TOML deserialization structs.
// Module-scoped so both parse functions share the same definitions.

#[derive(Debug, Deserialize)]
struct UvDependency {
    name: String,
}

#[derive(Debug, Deserialize)]
struct DevDependencies {
    #[serde(default)]
    dev: Vec<UvDependency>,
}

#[derive(Debug, Deserialize)]
struct PackageSource {
    editable: Option<String>,
    #[serde(rename = "virtual")]
    virtual_path: Option<String>,
}

impl PackageSource {
    fn is_local(&self) -> bool {
        self.editable.is_some() || self.virtual_path.is_some()
    }
}

/// Parse uv.lock TOML content into (packages, dependency_map).
///
/// Pure function: no I/O, no `&self`. Suitable for reuse by any adapter
/// that has the raw lockfile bytes (filesystem, git blob, in-memory, etc.).
pub fn parse_lockfile_content(content: &str, project_path: &Path) -> Result<LockfileParseResult> {
    #[derive(Debug, Deserialize)]
    struct UvPackage {
        name: String,
        version: String,
        #[serde(default)]
        dependencies: Vec<UvDependency>,
        #[serde(default, rename = "dev-dependencies")]
        dev_dependencies: Option<DevDependencies>,
    }

    #[derive(Debug, Deserialize)]
    struct UvLock {
        package: Vec<UvPackage>,
    }

    let lockfile: UvLock = toml::from_str(content).map_err(|e| SbomError::LockfileParseError {
        path: project_path.join("uv.lock"),
        details: e.to_string(),
    })?;

    let mut packages = Vec::new();
    let mut dependency_map = HashMap::new();

    for pkg in lockfile.package {
        packages.push(Package::new(pkg.name.clone(), pkg.version.clone())?);

        let mut deps = Vec::new();
        for dep in &pkg.dependencies {
            deps.push(dep.name.clone());
        }
        if let Some(dev_deps) = &pkg.dev_dependencies {
            for dep in &dev_deps.dev {
                deps.push(dep.name.clone());
            }
        }
        dependency_map.insert(pkg.name, deps);
    }

    Ok((packages, dependency_map))
}

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
    #[derive(Debug, Deserialize)]
    struct UvPackage {
        name: String,
        version: String,
        #[serde(default)]
        dependencies: Vec<UvDependency>,
        #[serde(default, rename = "dev-dependencies")]
        dev_dependencies: Option<DevDependencies>,
        source: Option<PackageSource>,
    }

    #[derive(Debug, Deserialize)]
    struct UvLock {
        package: Vec<UvPackage>,
    }

    let lockfile: UvLock = toml::from_str(content).map_err(|e| SbomError::LockfileParseError {
        path: project_path.join("uv.lock"),
        details: e.to_string(),
    })?;

    let mut full_dep_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut pkg_lookup: HashMap<String, (String, String)> = HashMap::new();
    let mut member_direct_deps: Option<Vec<String>> = None;

    for pkg in &lockfile.package {
        let deps = collect_all_deps(&pkg.dependencies, pkg.dev_dependencies.as_ref());

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

/// Parse `[manifest.dependency-groups]` from uv.lock content.
///
/// Returns a map of group name → list of root package names.
/// Returns an empty map when no `[manifest.dependency-groups]` section is present.
///
/// The uv.lock format (not pyproject.toml) encodes dependency groups as a flat map:
/// ```toml
/// [manifest.dependency-groups]
/// dev = [{ name = "pytest" }, { name = "mypy" }]
/// lint = [{ name = "ruff" }]
/// ```
pub fn parse_group_roots(content: &str, project_path: &Path) -> Result<GroupRoots> {
    #[derive(Debug, Deserialize)]
    struct UvLock {
        #[serde(default)]
        manifest: Option<Manifest>,
    }

    #[derive(Debug, Deserialize)]
    struct Manifest {
        #[serde(default, rename = "dependency-groups")]
        dependency_groups: HashMap<String, Vec<UvDependency>>,
    }

    let lockfile: UvLock = toml::from_str(content).map_err(|e| SbomError::LockfileParseError {
        path: project_path.join("uv.lock"),
        details: e.to_string(),
    })?;

    let group_roots = match lockfile.manifest {
        None => HashMap::new(),
        Some(manifest) => manifest
            .dependency_groups
            .into_iter()
            .map(|(group, deps)| (group, deps.into_iter().map(|d| d.name).collect()))
            .collect(),
    };

    Ok(group_roots)
}

/// Collect all dependency names from a package (runtime + dev).
fn collect_all_deps(
    dependencies: &[UvDependency],
    dev_dependencies: Option<&DevDependencies>,
) -> Vec<String> {
    let mut deps: Vec<String> = dependencies.iter().map(|d| d.name.clone()).collect();
    if let Some(dev_deps) = dev_dependencies {
        for dep in &dev_deps.dev {
            deps.push(dep.name.clone());
        }
    }
    deps
}

/// BFS traversal starting from `seeds`, returning all transitively reachable package names.
fn bfs_reachable(dep_map: &HashMap<String, Vec<String>>, seeds: Vec<String>) -> HashSet<String> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    for dep in seeds {
        if !visited.contains(&dep) {
            visited.insert(dep.clone());
            queue.push_back(dep);
        }
    }

    while let Some(current) = queue.pop_front() {
        if let Some(deps) = dep_map.get(&current) {
            for dep in deps {
                if !visited.contains(dep) {
                    visited.insert(dep.clone());
                    queue.push_back(dep.clone());
                }
            }
        }
    }

    visited
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

    // --- parse_group_roots tests ---

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
}
