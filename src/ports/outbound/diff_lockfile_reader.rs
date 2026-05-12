use crate::sbom_generation::domain::Package;
use crate::shared::Result;
use std::path::{Path, PathBuf};

/// Identifies where a base `uv.lock` should be read from for diff comparison.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffSource {
    /// A git ref (branch, tag, or commit SHA). The lockfile is read from
    /// that revision of the repository.
    GitRef(String),
    /// A path on the local filesystem pointing directly to a `uv.lock` file.
    FilePath(PathBuf),
}

/// Outbound port for retrieving a "base" set of packages to diff against
/// the current project's `uv.lock`.
///
/// Implementations:
/// - `GitLockfileReader` (future, Issue #224) for `DiffSource::GitRef`
/// - A filesystem-backed reader (future) for `DiffSource::FilePath`
#[allow(dead_code)]
pub trait DiffLockfileReader {
    /// Read the lockfile identified by `source` (interpreted relative to
    /// `project_path` when applicable) and return its packages.
    ///
    /// # Errors
    /// Returns an error if the source cannot be resolved, the lockfile cannot
    /// be read, or TOML parsing fails.
    fn read_base_packages(
        &self,
        source: &DiffSource,
        project_path: &Path,
    ) -> Result<Vec<Package>>;
}
