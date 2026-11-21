use crate::application::read_models::SbomReadModel;
use crate::shared::Result;

/// Application-owned output port for formatting SBOM output.
///
/// This trait lives in the application layer rather than `crate::ports::outbound`
/// because its only parameter is an application read model (`SbomReadModel`).
/// Placing it here keeps the dependency direction valid: adapters depend on
/// the application layer, and this trait depends on a sibling module within
/// the same layer.
pub trait SbomFormatter {
    /// Formats SBOM output using the unified read model.
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
