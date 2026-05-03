use crate::shared::Result;
use async_trait::async_trait;
use chrono::NaiveDate;

/// Maintenance information for a single package
///
/// Captures the latest signal of upstream activity used to detect
/// abandoned/unmaintained packages.
///
/// # Notes
/// - `last_release_date` is `None` when the package has no published releases
///   on the upstream registry (extremely rare for installed packages, but
///   possible for yanked-only or pre-release-only packages).
// Consumed by the PyPI maintenance adapter (#553) and use case integration (#555).
// Suppressed here because this is a foundational subtask with no binary consumer yet.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceInfo {
    /// Date of the most recent release on the upstream registry (UTC).
    /// `None` when no release date is available.
    pub last_release_date: Option<NaiveDate>,
}

/// Port for fetching package maintenance information from external sources
///
/// This trait defines the interface for querying upstream registries
/// (e.g., PyPI JSON API) to determine when a package was last released,
/// which is used to detect abandoned/unmaintained dependencies.
///
/// # Security Considerations
/// - Implementations must not send internal/private package names to public APIs
/// - Implementations should implement rate limiting to prevent DoS
/// - Implementations should have timeout mechanisms
///
/// # Implementation Notes
/// - All methods are async to enable parallel fetching across packages
/// - Implementations should treat "package not found" as an error, not as
///   `MaintenanceInfo { last_release_date: None }`
///
/// # Example
/// ```no_run
/// # use uv_sbom::ports::outbound::MaintenanceRepository;
/// # use async_trait::async_trait;
/// # struct MockRepo;
/// # #[async_trait]
/// # impl MaintenanceRepository for MockRepo {
/// #     async fn fetch_maintenance_info(
/// #         &self,
/// #         _package_name: &str,
/// #     ) -> uv_sbom::shared::Result<uv_sbom::ports::outbound::MaintenanceInfo> {
/// #         Ok(uv_sbom::ports::outbound::MaintenanceInfo { last_release_date: None })
/// #     }
/// # }
/// # async fn example() -> uv_sbom::shared::Result<()> {
/// # let repo = MockRepo;
/// let info = repo.fetch_maintenance_info("requests").await?;
/// if let Some(date) = info.last_release_date {
///     println!("Last released on {}", date);
/// }
/// # Ok(())
/// # }
/// ```
// Implemented by PyPiMaintenanceRepository in #553; used in GenerateSbomUseCase in #555.
#[allow(dead_code)]
#[async_trait]
pub trait MaintenanceRepository: Send + Sync {
    /// Fetches maintenance information for a single package
    ///
    /// # Arguments
    /// * `package_name` - Canonical package name (case-insensitive on PyPI)
    ///
    /// # Returns
    /// `MaintenanceInfo` describing the package's most recent upstream activity.
    ///
    /// # Errors
    /// Returns error if:
    /// - Network request fails
    /// - Package is not found on the upstream registry
    /// - API response is invalid
    /// - Timeout occurs
    async fn fetch_maintenance_info(&self, package_name: &str) -> Result<MaintenanceInfo>;
}

/// Dummy implementation of MaintenanceRepository for the unit type.
/// Mirrors the `impl ... for ()` pattern in `VulnerabilityRepository`,
/// allowing `Option<()>` when no maintenance checking is configured.
#[async_trait]
impl MaintenanceRepository for () {
    async fn fetch_maintenance_info(&self, _package_name: &str) -> Result<MaintenanceInfo> {
        unreachable!("MaintenanceRepository not configured")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maintenance_info_with_date() {
        let info = MaintenanceInfo {
            last_release_date: Some(NaiveDate::from_ymd_opt(2024, 1, 15).unwrap()),
        };
        assert_eq!(
            info.last_release_date,
            Some(NaiveDate::from_ymd_opt(2024, 1, 15).unwrap())
        );
    }

    #[test]
    fn test_maintenance_info_without_date() {
        let info = MaintenanceInfo {
            last_release_date: None,
        };
        assert!(info.last_release_date.is_none());
    }

    #[test]
    fn test_maintenance_info_clone_and_eq() {
        let a = MaintenanceInfo {
            last_release_date: Some(NaiveDate::from_ymd_opt(2025, 6, 1).unwrap()),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
