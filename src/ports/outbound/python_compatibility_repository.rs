use crate::shared::Result;
use async_trait::async_trait;
use pep440_rs::{Version, VersionSpecifiers};
use std::str::FromStr;

/// Python version compatibility metadata for a single package version
///
/// Captures the upstream `Requires-Python` constraint (PEP 440) used to
/// determine whether a package is installable on a target Python interpreter.
///
/// # Notes
/// - `requires_python` is `None` when the package publishes no
///   `Requires-Python` constraint on the upstream registry. A `None` value
///   MUST be treated as "compatible with every target" (see
///   [`PythonCompatibilityInfo::is_incompatible_with`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // WIRE(#681): remove when wired into GenerateSbomUseCase and main.rs
pub struct PythonCompatibilityInfo {
    /// Raw PEP 440 `Requires-Python` specifier string (e.g. ">=3.8,<3.12").
    /// `None` when the package declares no constraint.
    pub requires_python: Option<String>,
}

impl PythonCompatibilityInfo {
    /// Returns `true` iff this package is incompatible with `target`.
    ///
    /// A `None` `requires_python` is always treated as compatible.
    #[allow(dead_code)] // WIRE(#681): remove when wired into GenerateSbomUseCase and main.rs
    pub fn is_incompatible_with(&self, target: &str) -> bool {
        self.requires_python
            .as_deref()
            .is_some_and(|requires_python| is_incompatible(requires_python, target))
    }
}

/// Port for fetching Python version compatibility information from external sources
///
/// This trait defines the interface for querying upstream registries
/// (e.g., PyPI JSON API) to determine the `Requires-Python` constraint of a
/// specific package version, which is used to detect dependencies that would
/// break under a target Python version upgrade.
///
/// # Security Considerations
/// - Implementations must not send internal/private package names to public APIs
/// - Implementations should implement rate limiting to prevent DoS
/// - Implementations should have timeout mechanisms
///
/// # Implementation Notes
/// - All methods are async to enable parallel fetching across packages
/// - Implementations should treat "package/version not found" as an error, not
///   as `PythonCompatibilityInfo { requires_python: None }`
///
/// # Example
/// ```no_run
/// # use uv_sbom::ports::outbound::PythonCompatibilityRepository;
/// # use async_trait::async_trait;
/// # struct MockRepo;
/// # #[async_trait]
/// # impl PythonCompatibilityRepository for MockRepo {
/// #     async fn fetch_python_compatibility(
/// #         &self,
/// #         _package_name: &str,
/// #         _package_version: &str,
/// #     ) -> uv_sbom::shared::Result<uv_sbom::ports::outbound::PythonCompatibilityInfo> {
/// #         Ok(uv_sbom::ports::outbound::PythonCompatibilityInfo { requires_python: None })
/// #     }
/// # }
/// # async fn example() -> uv_sbom::shared::Result<()> {
/// # let repo = MockRepo;
/// let info = repo.fetch_python_compatibility("requests", "2.31.0").await?;
/// if let Some(requires_python) = info.requires_python {
///     println!("Requires Python {}", requires_python);
/// }
/// # Ok(())
/// # }
/// ```
#[async_trait]
#[allow(dead_code)] // WIRE(#681): remove when wired into GenerateSbomUseCase and main.rs
pub trait PythonCompatibilityRepository: Send + Sync {
    /// Fetches the `Requires-Python` constraint for a specific package version
    ///
    /// # Arguments
    /// * `package_name` - Canonical package name (case-insensitive on PyPI)
    /// * `package_version` - Exact locked version (e.g. from uv.lock)
    ///
    /// # Returns
    /// `PythonCompatibilityInfo` describing the package version's declared
    /// `Requires-Python` constraint.
    ///
    /// # Errors
    /// Returns error if:
    /// - Network request fails
    /// - Package or version is not found on the upstream registry
    /// - API response is invalid
    /// - Timeout occurs
    async fn fetch_python_compatibility(
        &self,
        package_name: &str,
        package_version: &str,
    ) -> Result<PythonCompatibilityInfo>;
}

/// Dummy implementation of PythonCompatibilityRepository for the unit type.
/// Mirrors the `impl ... for ()` pattern in `MaintenanceRepository`,
/// allowing `Option<()>` when no target-python checking is configured.
#[async_trait]
impl PythonCompatibilityRepository for () {
    async fn fetch_python_compatibility(
        &self,
        _package_name: &str,
        _package_version: &str,
    ) -> Result<PythonCompatibilityInfo> {
        unreachable!("PythonCompatibilityRepository not configured")
    }
}

/// Returns `true` iff `target` is excluded by the `requires_python` PEP 440
/// specifier — i.e. the package is incompatible with that Python version.
///
/// # Conservative fallbacks (both return `false`, meaning "assume compatible")
/// - `requires_python` fails to parse as a PEP 440 `VersionSpecifiers` string.
/// - `target` fails to parse as a PEP 440 `Version` string.
///
/// This never panics: parse failures degrade to "compatible" so a malformed
/// upstream constraint can never produce a false-positive incompatibility.
#[allow(dead_code)] // WIRE(#681): remove when wired into GenerateSbomUseCase and main.rs
pub fn is_incompatible(requires_python: &str, target: &str) -> bool {
    let (Ok(specifiers), Ok(version)) = (
        VersionSpecifiers::from_str(requires_python),
        Version::from_str(target),
    ) else {
        return false;
    };
    !specifiers.contains(&version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_incompatible_major_version_mismatch() {
        assert!(is_incompatible(">=3", "2.7"));
    }

    #[test]
    fn test_is_incompatible_minor_version_mismatch() {
        assert!(is_incompatible(">=3.12", "3.11"));
    }

    #[test]
    fn test_is_incompatible_range_specifier_outside_range() {
        assert!(is_incompatible(">=3.8,<3.12", "3.13"));
    }

    #[test]
    fn test_is_incompatible_range_specifier_within_range() {
        assert!(!is_incompatible(">=3.8,<3.12", "3.10"));
    }

    #[test]
    fn test_is_incompatible_open_ended_specifier() {
        assert!(!is_incompatible(">=3.8", "3.13"));
    }

    #[test]
    fn test_is_incompatible_unparseable_specifier_treated_as_compatible() {
        assert!(!is_incompatible("not-a-specifier", "3.11"));
    }

    #[test]
    fn test_is_incompatible_unparseable_target_treated_as_compatible() {
        assert!(!is_incompatible(">=3.8", "not-a-version"));
    }

    #[test]
    fn test_python_compatibility_info_none_requires_python_is_compatible() {
        let info = PythonCompatibilityInfo {
            requires_python: None,
        };
        assert!(!info.is_incompatible_with("3.13"));
    }

    #[test]
    fn test_python_compatibility_info_some_requires_python_delegates_to_is_incompatible() {
        let info = PythonCompatibilityInfo {
            requires_python: Some(">=3.8,<3.12".to_string()),
        };
        assert!(info.is_incompatible_with("3.13"));
        assert!(!info.is_incompatible_with("3.10"));
    }

    #[test]
    fn test_python_compatibility_info_clone_and_eq() {
        let a = PythonCompatibilityInfo {
            requires_python: Some(">=3.9".to_string()),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
