use crate::application::read_models::SbomReadModel;
use crate::shared::Result;

/// SbomFormatter port for formatting SBOM output
///
/// This port abstracts the formatting logic for different SBOM formats
/// (CycloneDX JSON, Markdown, etc.).
pub trait SbomFormatter {
    /// Formats SBOM output using the unified read model
    ///
    /// # Arguments
    /// * `model` - The unified SBOM read model containing metadata, components,
    ///   dependencies, and vulnerability information
    ///
    /// # Returns
    /// Formatted SBOM content as a string
    ///
    /// # Errors
    /// Returns an error if formatting or serialization fails
    fn format(&self, model: &SbomReadModel) -> Result<String>;
}
