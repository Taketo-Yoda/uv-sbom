use crate::sbom_generation::domain::Package;
use crate::shared::Result;
use std::collections::HashMap;
use std::path::Path;

/// Type alias for dependency map: package name -> list of dependency names
pub type DependencyMap = HashMap<String, Vec<String>>;

/// Type alias for lockfile parsing result: (packages, dependency map)
pub type LockfileParseResult = (Vec<Package>, DependencyMap);

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
}
