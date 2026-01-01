use crate::shared::Result;

/// OutputPresenter port for presenting final output
///
/// This port abstracts the output destination (stdout, file, etc.)
/// where the formatted SBOM content is presented.
pub trait OutputPresenter {
    /// Presents the formatted SBOM content to the output destination
    ///
    /// # Arguments
    /// * `content` - The formatted SBOM content to present
    ///
    /// # Returns
    /// Success or error if presentation fails
    ///
    /// # Errors
    /// Returns an error if:
    /// - Writing to the output destination fails
    /// - File permissions prevent writing
    /// - Disk space is insufficient
    fn present(&self, content: &str) -> Result<()>;
}
