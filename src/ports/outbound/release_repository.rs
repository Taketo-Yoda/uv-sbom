use crate::sbom_generation::domain::advisory::ReleaseStatus;
use crate::shared::Result;
use async_trait::async_trait;

/// Port for querying the release status of a specific package version
///
/// Used by `--incident` mode to answer "is the fixed version installable?".
/// `--check-yanked` (#957) needs the same per-version data and should reuse
/// this port rather than introducing its own.
///
/// # Security Considerations
/// - Callers must pass only packages sourced from the public index; an
///   implementation queries whatever name it is given, so filtering out
///   internal/private package names is the caller's responsibility
/// - Implementations should have timeout mechanisms
///
/// # Implementation Notes
/// - Only a definitive "not published" answer (HTTP 404) maps to
///   `ReleaseStatus::NotFound`. Network failures and other error statuses are
///   errors, never `NotFound`.
#[async_trait]
pub trait ReleaseRepository: Send + Sync {
    /// Returns whether `version` of `package_name` is released, yanked, or missing
    ///
    /// # Arguments
    /// * `package_name` - Package name (case-insensitive on PyPI)
    /// * `version` - Exact version string
    ///
    /// # Errors
    /// Returns error if:
    /// - The name or version is not a valid URL component
    /// - Network request fails or times out
    /// - The API returns a non-404 error status
    /// - API response is invalid
    async fn release_status(&self, package_name: &str, version: &str) -> Result<ReleaseStatus>;
}
