use crate::shared::Result;
use std::path::Path;

/// Request parameters for SBOM generation
#[derive(Debug, Clone)]
pub struct SbomGenerationRequest {
    /// Path to the project directory
    pub project_path: std::path::PathBuf,
    /// Whether to include dependency graph information
    pub include_dependency_info: bool,
}

impl SbomGenerationRequest {
    pub fn new(project_path: std::path::PathBuf, include_dependency_info: bool) -> Self {
        Self {
            project_path,
            include_dependency_info,
        }
    }
}

/// Response from SBOM generation
///
/// This contains the formatted SBOM output ready for presentation.
#[derive(Debug, Clone)]
pub struct SbomGenerationResponse {
    /// The formatted SBOM content
    pub content: String,
}

impl SbomGenerationResponse {
    pub fn new(content: String) -> Self {
        Self { content }
    }
}

/// SbomGenerationPort - Inbound port for SBOM generation use case
///
/// This port defines the interface that external adapters (CLI, API, etc.)
/// use to trigger SBOM generation. It represents the application's public API.
pub trait SbomGenerationPort {
    /// Generates an SBOM for the specified project
    ///
    /// # Arguments
    /// * `request` - Request parameters containing project path and options
    ///
    /// # Returns
    /// A response containing the formatted SBOM content
    ///
    /// # Errors
    /// Returns an error if:
    /// - The project directory does not exist or is invalid
    /// - The lockfile cannot be read or parsed
    /// - License information cannot be fetched
    /// - SBOM formatting fails
    fn generate_sbom(&self, request: SbomGenerationRequest) -> Result<SbomGenerationResponse>;

    /// Validates a project path
    ///
    /// # Arguments
    /// * `path` - Path to validate
    ///
    /// # Returns
    /// Success if the path is a valid project directory
    ///
    /// # Errors
    /// Returns an error if the path is invalid
    fn validate_project_path(&self, path: &Path) -> Result<()>;
}
