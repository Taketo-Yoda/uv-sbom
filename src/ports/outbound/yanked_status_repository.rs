use crate::shared::Result;
use async_trait::async_trait;

/// Yanked status and optional reason for a single package version
///
/// Captures PyPI's version-level `info.yanked` and `info.yanked_reason`.
/// Unlike `ReleaseStatus::Yanked`, this type carries the maintainer's reason
/// string, which `--check-yanked` renders in its report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YankedStatus {
    /// Whether PyPI marks the version as yanked (`info.yanked`)
    pub yanked: bool,
    /// Maintainer-provided reason for yanking; `None` when PyPI gives `null`
    /// or an empty string
    pub reason: Option<String>,
}

/// Port for querying the yanked status of a specific package version
///
/// Used by `--check-yanked` to detect locked versions that were yanked on PyPI.
/// The same `PyPiReleaseClient` adapter implements both this port and
/// `ReleaseRepository`, but they are separate traits because:
/// - `ReleaseStatus::Yanked` carries no reason, while `YankedStatus` does
/// - `--incident`'s `ReleaseRepository` classifies "yanked" as `info.yanked ||
///   all files yanked`, while `--check-yanked` uses only the version-level
///   `info.yanked` (per-file yank status is out of scope in #957)
///
/// # Security Considerations
/// - Callers must pass only packages sourced from the public index; an
///   implementation queries whatever name it is given, so filtering out
///   internal/private package names is the caller's responsibility
/// - Implementations should have timeout mechanisms
///
/// # Implementation Notes
/// - HTTP 404 (deleted release) is returned as an error, not as
///   `YankedStatus { yanked: false, .. }`. A locked version PyPI does not
///   know about is not "not yanked".
#[async_trait]
#[allow(dead_code)] // WIRE(#1155): remove when GenerateSbomUseCase consumes YankedStatusRepository
pub trait YankedStatusRepository: Send + Sync {
    /// Returns whether `version` of `package_name` is yanked, with the reason
    ///
    /// # Arguments
    /// * `package_name` - Package name (case-insensitive on PyPI)
    /// * `version` - Exact version string
    ///
    /// # Errors
    /// Returns error if:
    /// - The name or version is not a valid URL component
    /// - Network request fails or times out
    /// - The version is not found on PyPI (HTTP 404)
    /// - API response is invalid
    async fn fetch_yanked_status(&self, package_name: &str, version: &str) -> Result<YankedStatus>;
}

/// Dummy implementation for the unit type, mirroring `impl ReleaseRepository for ()`.
/// Used when `--check-yanked` is not enabled: `Option<()>` avoids a real client.
#[async_trait]
impl YankedStatusRepository for () {
    async fn fetch_yanked_status(
        &self,
        _package_name: &str,
        _version: &str,
    ) -> Result<YankedStatus> {
        unreachable!("YankedStatusRepository not configured")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yanked_status_clone_and_eq() {
        let a = YankedStatus {
            yanked: true,
            reason: Some("security fix".to_string()),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_yanked_status_not_yanked() {
        let status = YankedStatus {
            yanked: false,
            reason: None,
        };
        assert!(!status.yanked);
        assert!(status.reason.is_none());
    }
}
