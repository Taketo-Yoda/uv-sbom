use crate::ports::outbound::{
    GroupRoots, LockfileParseResult, PackageSourceKind, PackageSourceMap,
};
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
    #[allow(dead_code)]
    // WIRE(#627): remove when read_and_parse_package_sources is invoked from application code
    registry: Option<String>,
    #[allow(dead_code)]
    // WIRE(#627): remove when read_and_parse_package_sources is invoked from application code
    git: Option<String>,
    #[allow(dead_code)]
    // WIRE(#627): remove when read_and_parse_package_sources is invoked from application code
    path: Option<String>,
    #[allow(dead_code)]
    // WIRE(#627): remove when read_and_parse_package_sources is invoked from application code
    url: Option<String>,
}

impl PackageSource {
    fn is_local(&self) -> bool {
        self.editable.is_some() || self.virtual_path.is_some()
    }

    /// Classify this source into a `PackageSourceKind`.
    ///
    /// Priority when multiple fields are set (uv.lock sets exactly one in practice):
    /// WorkspaceMember > Git > LocalPath > DirectUrl > Registry.
    /// A registry URL of `"https://pypi.org/simple"` (with or without trailing slash)
    /// maps to `PyPi`; all other registry URLs map to `PrivateRegistry`.
    ///
    /// If none of the known fields are set (e.g., a future uv.lock source type or
    /// a `source = {}` empty table), falls back to `PyPi` as a non-flagging default.
    /// Callers should treat this fallback as "unknown / assumed PyPI" until a richer
    /// classification can be confirmed.
    #[allow(dead_code)] // WIRE(#627): remove when read_and_parse_package_sources is invoked from application code
    fn to_kind(&self) -> PackageSourceKind {
        if self.is_local() {
            return PackageSourceKind::WorkspaceMember;
        }
        if let Some(git) = &self.git {
            return PackageSourceKind::Git(git.clone());
        }
        if let Some(path) = &self.path {
            return PackageSourceKind::LocalPath(path.clone());
        }
        if let Some(url) = &self.url {
            return PackageSourceKind::DirectUrl(url.clone());
        }
        if let Some(reg) = &self.registry {
            let normalized = reg.trim_end_matches('/');
            if normalized == "https://pypi.org/simple" {
                return PackageSourceKind::PyPi;
            }
            return PackageSourceKind::PrivateRegistry(reg.clone());
        }
        // No source field set — treat as PyPI (non-flagging default).
        PackageSourceKind::PyPi
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

        let deps: Vec<String> = pkg.dependencies.iter().map(|d| d.name.clone()).collect();
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
pub fn parse_group_roots(content: &str, project_path: &Path) -> Result<GroupRoots> {
    #[derive(Debug, Deserialize)]
    struct UvLock {
        #[serde(default)]
        manifest: Option<Manifest>,
        #[serde(default)]
        package: Vec<UvPackage>,
    }

    #[derive(Debug, Deserialize)]
    struct Manifest {
        #[serde(default, rename = "dependency-groups")]
        dependency_groups: HashMap<String, Vec<UvDependency>>,
    }

    #[derive(Debug, Deserialize)]
    struct UvPackage {
        source: Option<PackageSource>,
        #[serde(default, rename = "dev-dependencies")]
        dev_dependencies: Option<HashMap<String, Vec<UvDependency>>>,
    }

    let lockfile: UvLock = toml::from_str(content).map_err(|e| SbomError::LockfileParseError {
        path: project_path.join("uv.lock"),
        details: e.to_string(),
    })?;

    // Revision ≤ 2: prefer [manifest.dependency-groups] when present and non-empty.
    let manifest_groups: GroupRoots = lockfile
        .manifest
        .map(|m| {
            m.dependency_groups
                .into_iter()
                .map(|(group, deps)| (group, deps.into_iter().map(|d| d.name).collect()))
                .collect()
        })
        .unwrap_or_default();

    if !manifest_groups.is_empty() {
        return Ok(manifest_groups);
    }

    // Revision 3 fallback: read [package.dev-dependencies] from the local project package
    // (identified by source.virtual or source.editable pointing to ".").
    let package_groups: GroupRoots = lockfile
        .package
        .into_iter()
        .find(|pkg| pkg.source.as_ref().map(|s| s.is_local()).unwrap_or(false))
        .and_then(|pkg| pkg.dev_dependencies)
        .map(|groups| {
            groups
                .into_iter()
                .map(|(group, deps)| (group, deps.into_iter().map(|d| d.name).collect()))
                .collect()
        })
        .unwrap_or_default();

    Ok(package_groups)
}

/// Parse `uv.lock` content into a map of package name → source classification.
///
/// Packages whose `[[package]]` entry has no `source` field are omitted from
/// the returned map. Invalid TOML returns an error.
#[allow(dead_code)] // WIRE(#627): remove when read_and_parse_package_sources is invoked from application code
pub fn parse_package_sources(content: &str, project_path: &Path) -> Result<PackageSourceMap> {
    #[derive(Debug, Deserialize)]
    struct UvPackage {
        name: String,
        source: Option<PackageSource>,
    }

    #[derive(Debug, Deserialize)]
    struct UvLock {
        #[serde(default)]
        package: Vec<UvPackage>,
    }

    let lockfile: UvLock = toml::from_str(content).map_err(|e| SbomError::LockfileParseError {
        path: project_path.join("uv.lock"),
        details: e.to_string(),
    })?;

    let mut map = PackageSourceMap::new();
    for pkg in lockfile.package {
        if let Some(source) = pkg.source {
            map.insert(pkg.name, source.to_kind());
        }
    }
    Ok(map)
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

    #[test]
    fn test_to_kind_workspace_member_takes_priority_over_registry() {
        let source = PackageSource {
            editable: Some(".".to_string()),
            virtual_path: None,
            registry: Some("https://pypi.org/simple".to_string()),
            git: None,
            path: None,
            url: None,
        };
        assert_eq!(source.to_kind(), PackageSourceKind::WorkspaceMember);
    }
}
