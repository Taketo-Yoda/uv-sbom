use serde::Deserialize;
use std::collections::HashMap;

/// The single dependency-group name that member-scoped dependency-graph traversal
/// (`parse_lockfile_content_for_member`) folds into the reachability graph. Other
/// groups (e.g. `test`, `lint`) are intentionally excluded — this matches
/// pre-existing behavior, not a new restriction.
pub(super) const DEV_GROUP: &str = "dev";

#[derive(Debug, Deserialize)]
pub(super) struct UvDependency {
    pub(super) name: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct Manifest {
    #[serde(default, rename = "dependency-groups")]
    pub(super) dependency_groups: HashMap<String, Vec<UvDependency>>,
}

/// Canonical `uv.lock` top-level shape, shared by all four parse functions.
///
/// `package` is `Option` (not `#[serde(default)]`-backed `Vec`) because the four
/// parse functions disagree on whether a lockfile missing `[[package]]` entirely is
/// an error: `parse_lockfile_content` / `parse_lockfile_content_for_member` treat it
/// as a parse error, while `parse_group_roots` / `parse_package_sources` treat it as
/// "no packages" and continue. Keeping the field optional lets each call site decide
/// via `.ok_or_else(...)` vs `.unwrap_or_default()` without diverging the schema.
#[derive(Debug, Deserialize)]
pub(super) struct UvLock {
    pub(super) package: Option<Vec<UvPackage>>,
    pub(super) manifest: Option<Manifest>,
}

/// Canonical `[[package]]` entry shape, shared by all four parse functions.
///
/// Not every field is relevant to every caller: `parse_group_roots` only reads
/// `source` and `dev_dependencies`; `parse_package_sources` only reads `name` and
/// `source`. Consolidating onto one struct means `name`/`version` are now required
/// fields for those two functions as well, where the pre-split per-function structs
/// didn't declare them at all. In practice every `[[package]]` entry in a real
/// `uv.lock` always carries `name` and `version`, so this is a low-risk widening of
/// what counts as valid input, not an observed behavior change.
#[derive(Debug, Deserialize)]
pub(super) struct UvPackage {
    pub(super) name: String,
    pub(super) version: String,
    #[serde(default)]
    pub(super) dependencies: Vec<UvDependency>,
    /// Every named dependency group under `[package.dev-dependencies]` (e.g. `dev`,
    /// `test`, `lint`), keyed by group name. `parse_group_roots` uses the full map;
    /// `parse_lockfile_content_for_member` uses only the `dev` entry via
    /// [`UvPackage::dev_group`].
    #[serde(rename = "dev-dependencies")]
    pub(super) dev_dependencies: Option<HashMap<String, Vec<UvDependency>>>,
    pub(super) source: Option<PackageSource>,
}

impl UvPackage {
    /// The legacy `dev` group of `[package.dev-dependencies]`, if present.
    pub(super) fn dev_group(&self) -> Option<&[UvDependency]> {
        self.dev_dependencies
            .as_ref()?
            .get(DEV_GROUP)
            .map(Vec::as_slice)
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct PackageSource {
    pub(super) editable: Option<String>,
    #[serde(rename = "virtual")]
    pub(super) virtual_path: Option<String>,
    pub(super) registry: Option<String>,
    pub(super) git: Option<String>,
    pub(super) path: Option<String>,
    pub(super) url: Option<String>,
}
