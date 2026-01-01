use crate::shared::Result;
use std::path::Path;

/// LockfileReader port for reading lockfile contents
///
/// This port abstracts the file system operations needed to read
/// the uv.lock file from a project directory.
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
}
