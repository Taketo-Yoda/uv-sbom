use serde::Deserialize;
use std::collections::HashMap;

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
    /// `parse_lockfile_content_for_member` seeds its traversal with every group's
    /// roots via [`UvPackage::group_dep_names`].
    #[serde(rename = "dev-dependencies")]
    pub(super) dev_dependencies: Option<HashMap<String, Vec<UvDependency>>>,
    pub(super) source: Option<PackageSource>,
}

impl UvPackage {
    /// Names of the runtime `dependencies`.
    pub(super) fn runtime_dep_names(&self) -> Vec<String> {
        self.dependencies.iter().map(|d| d.name.clone()).collect()
    }

    /// Root names of every group in `[package.dev-dependencies]` (all groups,
    /// not only `dev`).
    pub(super) fn group_dep_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.dev_dependencies
            .iter()
            .flat_map(|groups| groups.values().flatten())
            .map(|d| d.name.as_str())
    }

    /// Whether this is a local (`source.editable` / `source.virtual`) package.
    pub(super) fn is_local(&self) -> bool {
        self.source.as_ref().map(|s| s.is_local()).unwrap_or(false)
    }

    /// Whether this is the local package named `name` — how a workspace
    /// member's root entry is identified.
    pub(super) fn is_local_named(&self, name: &str) -> bool {
        self.name == name && self.is_local()
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
