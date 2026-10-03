use crate::shared::Result;
use std::path::Path;

/// Typed errors raised by `ProjectConfigReader` implementations that callers may
/// want to recognize (e.g. to render a localized message).
///
/// The `#[error(...)]` text is the English `Display` contract. Adapters return this
/// type instead of building localized text themselves; callers that hold a `Locale`
/// (such as `GenerateSbomUseCase`) downcast and localize it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProjectConfigError {
    /// `pyproject.toml` does not exist in the project directory.
    #[error("pyproject.toml not found in project directory")]
    PyprojectNotFound,
}

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
    ///   ([`ProjectConfigError::PyprojectNotFound`])
    /// - The file cannot be parsed
    /// - The project name field is missing
    fn read_project_name(&self, project_path: &Path) -> Result<String>;
}
