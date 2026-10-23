use crate::sbom_generation::domain::advisory::Advisory;
use crate::shared::Result;
use async_trait::async_trait;

/// Port for fetching a single security advisory by its ID
///
/// Used by `--incident` mode, which queries one advisory (GHSA-, PYSEC-, or
/// CVE- ID) rather than batch-querying packages like `VulnerabilityRepository`.
///
/// # Security Considerations
/// - The advisory ID is user input; implementations must validate it before
///   embedding it in a URL
/// - Implementations should have timeout mechanisms
///
/// # Implementation Notes
/// - An advisory that does not exist (HTTP 404) is `Ok(None)`, not an error
/// - Any other HTTP status, network failure, or invalid response is an error
#[async_trait]
pub trait AdvisoryRepository: Send + Sync {
    /// Fetches one advisory by ID
    ///
    /// # Arguments
    /// * `advisory_id` - Advisory identifier (e.g. `GHSA-j8r2-6x86-q33q`)
    ///
    /// # Returns
    /// `Some(Advisory)` when found, `None` when the advisory does not exist.
    ///
    /// # Errors
    /// Returns error if:
    /// - The advisory ID is not a valid URL component
    /// - Network request fails or times out
    /// - The API returns a non-404 error status
    /// - API response is invalid
    async fn fetch_advisory(&self, advisory_id: &str) -> Result<Option<Advisory>>;
}
