use super::graph::bfs_reachable;
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
/// uses `virtual` for packages without a build system), then performs BFS seeded
/// with the member's runtime dependencies and the roots of every group in its own
/// `[package.dev-dependencies]`. Every other package contributes only its runtime
/// edges, so a sibling member reached as a dependency never brings in its own
/// groups. Workspace-wide `[manifest.dependency-groups]` are not followed: they
/// belong to the workspace root, not to any member. The member root itself is
/// excluded from `packages`.
///
/// The returned dependency map holds every reachable package's entry plus the
/// member root's own entry, so callers can pass the member name to
/// `DependencyAnalyzer::analyze`. Every entry, the root included, lists runtime
/// dependencies only, matching `parse_lockfile_content`, so group packages are
/// parentless roots: they are not reported as direct dependencies and
/// `--exclude-groups` can still exclude them.
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
    let mut member_seeds: Option<Vec<String>> = None;
    let mut member_runtime_deps: Vec<String> = Vec::new();

    for pkg in &packages {
        let deps = pkg.runtime_dep_names();

        if pkg.is_local_named(member_name) {
            member_runtime_deps = deps.clone();
            let mut seeds = deps.clone();
            seeds.extend(pkg.group_dep_names().map(str::to_string));
            member_seeds = Some(seeds);
        }

        full_dep_map.insert(pkg.name.clone(), deps);
        pkg_lookup.insert(pkg.name.clone(), (pkg.name.clone(), pkg.version.clone()));
    }

    let seeds = member_seeds.ok_or_else(|| {
        anyhow::anyhow!(
            "Workspace member '{}' not found in uv.lock (no package with source.editable or source.virtual set)",
            member_name
        )
    })?;

    let visited = bfs_reachable(&full_dep_map, seeds);

    let mut packages = Vec::new();
    let mut dependency_map = HashMap::new();

    for name in &visited {
        // A sibling member can depend back on this member; it is still not a component.
        if name == member_name {
            continue;
        }
        if let Some((pkg_name, pkg_version)) = pkg_lookup.get(name) {
            packages.push(Package::new(pkg_name.clone(), pkg_version.clone())?);
            if let Some(deps) = full_dep_map.get(name) {
                dependency_map.insert(pkg_name.clone(), deps.clone());
            }
        }
    }
    dependency_map.insert(member_name.to_string(), member_runtime_deps);

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

    // Member-scoped traversal seeds every group of the member's own
    // `[package.dev-dependencies]` (via `UvPackage::group_dep_names`), not only `dev`,
    // matching single-project mode, where group-only packages are listed too (#997).
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
    fn test_parse_lockfile_for_member_includes_all_of_members_groups() {
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
        assert!(names.contains("pytest"), "test group must be reachable");
    }

    // --- member root entry (#986) ---

    fn sorted(deps: &[String]) -> Vec<String> {
        let mut deps = deps.to_vec();
        deps.sort();
        deps
    }

    #[test]
    fn test_parse_lockfile_for_member_dep_map_contains_member_root_entry() {
        let (packages, dep_map) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_VIRTUAL_FORMAT,
            Path::new("/workspace"),
            "api",
        )
        .unwrap();

        assert_eq!(
            sorted(dep_map.get("api").expect("member root entry must exist")),
            vec!["fastapi".to_string(), "requests".to_string()]
        );
        assert!(
            !packages.iter().any(|p| p.name() == "api"),
            "member root must stay out of packages"
        );

        let (_, dep_map) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_FOR_MEMBER,
            Path::new("/workspace"),
            "alpha",
        )
        .unwrap();
        assert_eq!(
            sorted(dep_map.get("alpha").expect("member root entry must exist")),
            vec!["certifi".to_string(), "requests".to_string()]
        );
    }

    #[test]
    fn test_parse_lockfile_for_member_dependency_analyzer_finds_direct_deps() {
        use crate::sbom_generation::domain::PackageName;
        use crate::sbom_generation::services::DependencyAnalyzer;

        let (_, dep_map) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_FOR_MEMBER,
            Path::new("/workspace"),
            "alpha",
        )
        .unwrap();

        let (graph, _) =
            DependencyAnalyzer::analyze(&PackageName::new("alpha".to_string()).unwrap(), &dep_map)
                .unwrap();

        let mut direct: Vec<&str> = graph
            .direct_dependencies()
            .iter()
            .map(|n| n.as_str())
            .collect();
        direct.sort();
        assert_eq!(direct, vec!["certifi", "requests"]);
        assert!(
            graph
                .transitive_dependencies()
                .values()
                .flatten()
                .any(|n| n.as_str() == "urllib3"),
            "urllib3 must be transitive through requests"
        );
    }

    #[test]
    fn test_parse_lockfile_for_member_root_entry_is_runtime_only() {
        let (packages, dep_map) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_MULTI_DEV_GROUPS,
            Path::new("/project"),
            "my-app",
        )
        .unwrap();

        // Matches `parse_lockfile_content`: the root entry lists runtime deps only,
        // while dev-group packages are still collected as components.
        assert_eq!(dep_map.get("my-app"), Some(&vec!["requests".to_string()]));
        assert!(packages.iter().any(|p| p.name() == "mypy"));
    }

    fn exclude_dev(content: &str, member: &str) -> HashSet<String> {
        exclude(content, member, &["dev"])
    }

    fn exclude(content: &str, member: &str, groups: &[&str]) -> HashSet<String> {
        use super::super::parse_group_roots_for_member;
        use crate::sbom_generation::domain::services::{
            GroupReachabilityAnalyzer, SharedRootPolicy,
        };

        let (packages, dep_map) =
            parse_lockfile_content_for_member(content, Path::new("/project"), member).unwrap();
        let group_roots =
            parse_group_roots_for_member(content, Path::new("/project"), member).unwrap();
        GroupReachabilityAnalyzer::filter_excluded_groups(
            &packages,
            &dep_map,
            &group_roots,
            &groups.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
            SharedRootPolicy::KeptGroupWins,
        )
        .iter()
        .map(|p| p.name().to_string())
        .collect()
    }

    #[test]
    fn test_parse_lockfile_for_member_exclude_dev_group_still_excludes_dev_packages() {
        let names = exclude_dev(WORKSPACE_LOCK_MULTI_DEV_GROUPS, "my-app");
        assert!(names.contains("requests"));
        assert!(
            !names.contains("mypy"),
            "dev group package must be excluded"
        );
    }

    // Revision-3 workspace where each member declares a different `dev` group.
    // `a` sorts first, so a first-local-package lookup would use `a`'s groups for `b`.
    const WORKSPACE_LOCK_REV3_PER_MEMBER_DEV: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = ["a", "b"]

[[package]]
name = "a"
version = "0.1.0"
source = { editable = "packages/a" }
dependencies = [{ name = "requests" }]

[package.dev-dependencies]
dev = [{ name = "mypy" }]

[[package]]
name = "b"
version = "0.1.0"
source = { editable = "packages/b" }
dependencies = [{ name = "requests" }]

[package.dev-dependencies]
dev = [{ name = "ruff" }]

[[package]]
name = "mypy"
version = "1.8.0"
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

    // Regression (#992): `--workspace --exclude-groups dev` must use each member's
    // own `[package.dev-dependencies]`, not the first local package's.
    #[test]
    fn test_parse_lockfile_for_member_exclude_dev_uses_members_own_groups_rev3() {
        let a = exclude_dev(WORKSPACE_LOCK_REV3_PER_MEMBER_DEV, "a");
        assert!(a.contains("requests"));
        assert!(!a.contains("mypy"), "a's dev package must be excluded");

        let b = exclude_dev(WORKSPACE_LOCK_REV3_PER_MEMBER_DEV, "b");
        assert!(b.contains("requests"));
        assert!(!b.contains("ruff"), "b's dev package must be excluded");
    }

    // `requests` is both a runtime dependency and a `dev` group root.
    const WORKSPACE_LOCK_RUNTIME_AND_DEV_OVERLAP: &str = r#"
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
dev = [{ name = "mypy" }, { name = "requests" }]

[[package]]
name = "mypy"
version = "1.8.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    #[test]
    fn test_parse_lockfile_for_member_exclude_dev_group_keeps_runtime_dep_also_in_dev() {
        let names = exclude_dev(WORKSPACE_LOCK_RUNTIME_AND_DEV_OVERLAP, "my-app");
        assert!(
            names.contains("requests"),
            "a runtime dependency must survive excluding a group that also lists it"
        );
        assert!(!names.contains("mypy"));
    }

    // `lib` (another workspace member) depends back on `app`.
    const WORKSPACE_LOCK_MEMBER_CYCLE: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = ["app", "lib"]

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "packages/app" }
dependencies = [{ name = "lib" }]

[package.dev-dependencies]
dev = [{ name = "mypy" }]

[[package]]
name = "lib"
version = "0.1.0"
source = { virtual = "packages/lib" }
dependencies = [{ name = "app" }]

[[package]]
name = "mypy"
version = "1.8.0"
source = { registry = "https://pypi.org/simple" }
"#;

    #[test]
    fn test_parse_lockfile_for_member_cycle_back_to_member_keeps_it_out_of_packages() {
        let (packages, dep_map) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_MEMBER_CYCLE,
            Path::new("/workspace"),
            "app",
        )
        .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();
        assert!(
            !names.contains("app"),
            "member root must stay out of packages"
        );
        assert!(names.contains("lib"));
        assert_eq!(dep_map.get("app"), Some(&vec!["lib".to_string()]));
    }

    // Revision-3 workspace where member `b` has a non-`dev` group (#997).
    const WORKSPACE_LOCK_REV3_NON_DEV_GROUP: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = ["a", "b"]

[[package]]
name = "a"
version = "0.1.0"
source = { editable = "packages/a" }
dependencies = [{ name = "requests" }]

[[package]]
name = "b"
version = "0.1.0"
source = { editable = "packages/b" }
dependencies = [{ name = "requests" }]

[package.dev-dependencies]
dev = [{ name = "mypy" }]
lint = [{ name = "black" }]

[[package]]
name = "black"
version = "24.1.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "click" }]

[[package]]
name = "click"
version = "8.1.7"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "mypy"
version = "1.8.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    // Regression (#997): a member's non-`dev` group packages are listed, and the
    // root entry stays runtime-only so they are not direct dependencies.
    #[test]
    fn test_parse_lockfile_for_member_includes_non_dev_group_packages() {
        let (packages, dep_map) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_REV3_NON_DEV_GROUP,
            Path::new("/workspace"),
            "b",
        )
        .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();
        assert!(names.contains("black"), "lint group root must be listed");
        assert!(
            names.contains("click"),
            "lint group transitive dep must be listed"
        );
        assert!(names.contains("mypy"));
        assert_eq!(dep_map.get("b"), Some(&vec!["requests".to_string()]));

        let (packages, _) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_REV3_NON_DEV_GROUP,
            Path::new("/workspace"),
            "a",
        )
        .unwrap();
        assert!(
            !packages.iter().any(|p| p.name() == "black"),
            "another member's group must not be listed"
        );
    }

    #[test]
    fn test_parse_lockfile_for_member_exclude_non_dev_group_excludes_its_packages() {
        let names = exclude(WORKSPACE_LOCK_REV3_NON_DEV_GROUP, "b", &["lint"]);
        assert!(names.contains("requests"));
        assert!(names.contains("mypy"), "dev group is not excluded");
        assert!(!names.contains("black"), "lint group root must be excluded");
        assert!(
            !names.contains("click"),
            "lint group subtree must be excluded"
        );

        let names = exclude_dev(WORKSPACE_LOCK_REV3_NON_DEV_GROUP, "b");
        assert!(names.contains("black"), "lint group is not excluded");
        assert!(!names.contains("mypy"));
    }

    // `app` depends on sibling member `lib`, which has its own `dev` group (#993).
    const WORKSPACE_LOCK_SIBLING_DEV: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = ["app", "lib"]

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "packages/app" }
dependencies = [{ name = "lib" }]

[[package]]
name = "lib"
version = "0.1.0"
source = { virtual = "packages/lib" }
dependencies = [{ name = "requests" }]

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;

    // Regression (#993): a sibling member reached as a dependency contributes only
    // its runtime dependencies, not its `dev` group.
    #[test]
    fn test_parse_lockfile_for_member_excludes_sibling_members_dev_group() {
        let (packages, dep_map) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_SIBLING_DEV,
            Path::new("/workspace"),
            "app",
        )
        .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();
        assert!(names.contains("lib"));
        assert!(names.contains("requests"));
        assert!(
            !names.contains("pytest"),
            "sibling member's dev group must not be listed"
        );
        assert_eq!(dep_map.get("lib"), Some(&vec!["requests".to_string()]));

        let (packages, _) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_SIBLING_DEV,
            Path::new("/workspace"),
            "lib",
        )
        .unwrap();
        assert!(
            packages.iter().any(|p| p.name() == "pytest"),
            "the scanned member's own dev group is still listed"
        );
    }

    // Workspace-wide `[manifest.dependency-groups]` belong to the workspace root.
    const WORKSPACE_LOCK_MANIFEST_GROUPS: &str = r#"
version = 1
requires-python = ">=3.11"

[manifest]
members = ["app"]

[manifest.dependency-groups]
lint = [{ name = "ruff" }]

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "packages/app" }
dependencies = [{ name = "requests" }]

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
    fn test_parse_lockfile_for_member_does_not_seed_manifest_groups() {
        let (packages, _) = parse_lockfile_content_for_member(
            WORKSPACE_LOCK_MANIFEST_GROUPS,
            Path::new("/workspace"),
            "app",
        )
        .unwrap();

        let names: HashSet<String> = packages.iter().map(|p| p.name().to_string()).collect();
        assert!(names.contains("requests"));
        assert!(
            !names.contains("ruff"),
            "workspace-wide manifest groups must not be seeded"
        );
    }

    // Manifest groups alongside a member-only group: excluding the member's
    // own group must still work (#999).
    const WORKSPACE_LOCK_MANIFEST_AND_MEMBER_GROUPS: &str = r#"
version = 1
revision = 3
requires-python = ">=3.11"

[manifest]
members = ["a", "b"]

[manifest.dependency-groups]
docs = [{ name = "sphinx" }]

[[package]]
name = "a"
version = "0.1.0"
source = { editable = "packages/a" }

[[package]]
name = "b"
version = "0.1.0"
source = { editable = "packages/b" }
dependencies = [{ name = "requests" }]

[package.dev-dependencies]
lint = [{ name = "black" }]

[[package]]
name = "black"
version = "24.1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "sphinx"
version = "7.2.6"
source = { registry = "https://pypi.org/simple" }
"#;

    #[test]
    fn test_parse_lockfile_for_member_exclude_own_group_with_manifest_groups_present() {
        let names = exclude(WORKSPACE_LOCK_MANIFEST_AND_MEMBER_GROUPS, "b", &[]);
        assert!(names.contains("black"), "lint group is listed by default");

        let names = exclude(WORKSPACE_LOCK_MANIFEST_AND_MEMBER_GROUPS, "b", &["lint"]);
        assert!(names.contains("requests"));
        assert!(
            !names.contains("black"),
            "member-only group must be excludable when manifest groups exist"
        );
    }
}
