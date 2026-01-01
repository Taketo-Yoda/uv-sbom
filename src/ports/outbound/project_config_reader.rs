use crate::shared::Result;
use std::path::Path;

/// ProjectConfigReader port for reading project configuration
///
/// This port abstracts the file system operations needed to read
/// project metadata from configuration files (e.g., pyproject.toml).
pub trait ProjectConfigReader {
    /// Reads the project name from the project configuration
    ///
    /// # Arguments
    /// * `project_path` - Path to the project directory
    ///
    /// # Returns
    /// The project name as defined in the project configuration
    ///
    /// # Errors
    /// Returns an error if:
    /// - The configuration file (pyproject.toml) does not exist
    /// - The file cannot be parsed
    /// - The project name field is missing
    fn read_project_name(&self, project_path: &Path) -> Result<String>;
}
