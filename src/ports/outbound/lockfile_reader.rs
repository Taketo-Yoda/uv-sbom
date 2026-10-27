use crate::sbom_generation::domain::Package;
use crate::shared::Result;
use std::collections::HashMap;
use std::path::Path;

/// Type alias for dependency map: package name -> list of dependency names
pub type DependencyMap = HashMap<String, Vec<String>>;

/// Type alias for lockfile parsing result: (packages, dependency map)
pub type LockfileParseResult = (Vec<Package>, DependencyMap);

/// Group name -> list of root package names declared for that dependency group.
///
/// Extracted from `[manifest.dependency-groups]` in `uv.lock` (a single project's
/// groups in revision ≤ 2, a virtual workspace root's groups in every revision), or
/// from a local package's `[package.dev-dependencies]` (revision 3).
/// Empty map when neither is present.
pub type GroupRoots = HashMap<String, Vec<String>>;

/// Classification of a package's `source` field in `uv.lock`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageSourceKind {
    /// Standard PyPI registry (`https://pypi.org/simple`).
    PyPi,
    /// A registry URL other than the canonical PyPI registry.
    PrivateRegistry(String),
    /// Git repository (plain URL string, may include `?rev=` fragment).
    Git(String),
    /// Local filesystem path (`path = "..."`).
    LocalPath(String),
    /// Direct URL to an archive or wheel (`url = "..."`).
    DirectUrl(String),
    /// Workspace member (`editable` or `virtual` source).
    WorkspaceMember,
}

impl PackageSourceKind {
    /// Returns `true` for sources that are external but not the canonical PyPI registry.
    ///
    /// `PrivateRegistry`, `Git`, and `DirectUrl` are considered non-PyPI external.
    /// `LocalPath` and `WorkspaceMember` are local; `PyPi` is the canonical registry.
    pub fn is_non_pypi_external(&self) -> bool {
        matches!(
            self,
            Self::PrivateRegistry(_) | Self::Git(_) | Self::DirectUrl(_)
        )
    }

    /// Stable human-readable category label suitable for reports and output.
    pub fn label(&self) -> &str {
        match self {
            Self::PyPi => "PyPI",
            Self::PrivateRegistry(_) => "Private Registry",
            Self::Git(_) => "Git",
            Self::LocalPath(_) => "Local Path",
            Self::DirectUrl(_) => "Direct URL",
            Self::WorkspaceMember => "Workspace Member",
        }
    }

    /// The associated location string (URL or path).
    ///
    /// Returns `""` for `PyPi` and `WorkspaceMember`, which carry no explicit URL.
    pub fn value(&self) -> &str {
        match self {
            Self::PrivateRegistry(s) | Self::Git(s) | Self::LocalPath(s) | Self::DirectUrl(s) => s,
            Self::PyPi | Self::WorkspaceMember => "",
        }
    }
}

/// Package name → source classification.
///
/// Keyed by the package name as it appears in `uv.lock`. Packages without a
/// `source` field are omitted from the map.
pub type PackageSourceMap = HashMap<String, PackageSourceKind>;

/// LockfileReader port for reading and parsing lockfile contents
///
/// This port abstracts the file system operations and TOML parsing
/// needed to extract package information from uv.lock files.
pub trait LockfileReader {
    /// Reads the uv.lock file from the specified project directory
    ///
    /// # Arguments
    /// * `project_path` - Path to the project directory containing uv.lock
    ///
    /// # Returns
    /// The raw content of the uv.lock file as a string
    ///
    /// # Errors
    /// Returns an error if:
    /// - The uv.lock file does not exist
    /// - The file cannot be read due to permissions or I/O errors
    fn read_lockfile(&self, project_path: &Path) -> Result<String>;

    /// Reads and parses the uv.lock file from the specified project directory
    ///
    /// # Arguments
    /// * `project_path` - Path to the project directory containing uv.lock
    ///
    /// # Returns
    /// A tuple of (packages, dependency_map) where:
    /// - packages: Vector of Package domain objects
    /// - dependency_map: Map of package name to its dependencies
    ///
    /// # Errors
    /// Returns an error if:
    /// - The uv.lock file does not exist or cannot be read
    /// - The TOML parsing fails
    /// - The lockfile has invalid structure
    fn read_and_parse_lockfile(&self, project_path: &Path) -> Result<LockfileParseResult>;

    /// Parse the lockfile and return only packages reachable from the given member.
    ///
    /// Performs a BFS traversal starting from the `[[package]]` entry whose
    /// `name == member_name` and `source.editable` (uv < 0.5) or `source.virtual`
    /// (uv >= 0.5) is set, collecting all packages transitively reachable from its
    /// runtime dependencies and from every group of its own
    /// `[package.dev-dependencies]`. Other packages contribute runtime edges only.
    /// The member package itself is excluded from the result.
    ///
    /// # Arguments
    /// * `project_path` - Path to the project directory containing uv.lock
    /// * `member_name` - The workspace member name to scope the result to
    ///
    /// # Returns
    /// A tuple of (packages, dependency_map). `packages` contains only packages
    /// reachable from the specified member (excluding the member itself).
    /// `dependency_map` contains each of those packages' entries plus the
    /// member's own root entry, so the member name can be passed to
    /// `DependencyAnalyzer::analyze` as the project root. Every entry, the root
    /// included, lists runtime dependencies only, as in `read_and_parse_lockfile`.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The uv.lock file does not exist or cannot be read
    /// - The TOML parsing fails
    /// - No package with `name == member_name` and `source.editable` or `source.virtual` set is found
    fn read_and_parse_lockfile_for_member(
        &self,
        project_path: &Path,
        member_name: &str,
    ) -> Result<LockfileParseResult>;

    /// Extract dependency-group roots from `uv.lock`.
    ///
    /// Reads `[manifest.dependency-groups]` (revision ≤ 2), falling back to the
    /// `[package.dev-dependencies]` of the first local package (revision 3).
    /// Returns an empty map when no group information is present, preserving
    /// backward compatibility with lock files that have no groups.
    ///
    /// In a workspace the revision-3 fallback picks an arbitrary member; use
    /// `read_and_parse_group_roots_for_member` to scope to one member.
    fn read_and_parse_group_roots(&self, project_path: &Path) -> Result<GroupRoots>;

    /// Extract dependency-group roots for the workspace member `member_name`.
    ///
    /// Returns the union of the workspace-wide `[manifest.dependency-groups]` and
    /// the `[package.dev-dependencies]` of the local package whose
    /// `name == member_name` (the same match as `read_and_parse_lockfile_for_member`),
    /// merged per group name (manifest roots first, then the member's own roots not
    /// already listed), so every group the member's traversal follows can be
    /// excluded. A member that is not a local package gets the manifest groups
    /// only — never another member's groups.
    ///
    /// The manifest groups apply to every member. Member-scoped exclusion
    /// (`project_scope::filter_by_groups_for_member`) keeps whatever one of the
    /// member's non-excluded groups reaches, so excluding a group drops a package
    /// only when no runtime dependency and no non-excluded group of the member
    /// reaches it (#1001).
    ///
    /// # Errors
    /// Returns an error if the uv.lock file cannot be read or parsed.
    fn read_and_parse_group_roots_for_member(
        &self,
        project_path: &Path,
        member_name: &str,
    ) -> Result<GroupRoots>;

    /// Extract the virtual workspace root's own dependency-group roots.
    ///
    /// Reads `[manifest.dependency-groups]` only, in any lockfile revision, and
    /// never falls back to a local package's `[package.dev-dependencies]` (which
    /// in a workspace belongs to a member). Returns an empty map when the root
    /// declares no groups, or when the root has a `[project]`: it is then a
    /// member, and uv records its groups on its own `[[package]]`.
    ///
    /// Member traversal never follows these groups, so `--workspace` warns
    /// about the ones not excluded (#1009).
    ///
    /// # Errors
    /// Returns an error if the uv.lock file cannot be read or parsed.
    fn read_and_parse_virtual_root_group_roots(&self, project_path: &Path) -> Result<GroupRoots>;

    /// Read `uv.lock` and classify each package's `source` field.
    ///
    /// Returns a map of package name → `PackageSourceKind`. Packages whose
    /// `[[package]]` entry has no `source` field are omitted from the map.
    fn read_and_parse_package_sources(&self, project_path: &Path) -> Result<PackageSourceMap>;
}

#[cfg(test)]
mod tests {
    use super::*;

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
