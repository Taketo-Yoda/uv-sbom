use pep440_rs::{Version, VersionSpecifiers};
use std::str::FromStr;

/// Stateless domain service evaluating PEP 440 `Requires-Python` constraints
/// against a target Python version.
///
/// Operates on the raw `requires_python` string (as carried by
/// `PythonCompatibilityInfo::requires_python` in `ports::outbound`) rather
/// than the DTO itself, so this module has no dependency on `ports/`.
pub struct PythonCompatibilityChecker;

impl PythonCompatibilityChecker {
    /// Returns `true` iff `target` is excluded by `requires_python` — i.e.
    /// the package is incompatible with that Python version.
    ///
    /// A `None` `requires_python` always means "compatible with every
    /// target" (the package publishes no `Requires-Python` constraint).
    pub fn is_incompatible(requires_python: Option<&str>, target: &str) -> bool {
        requires_python
            .is_some_and(|requires_python| excluded_by_specifier(requires_python, target))
    }
}

/// Returns `true` iff `target` is excluded by the `requires_python` PEP 440
/// specifier.
///
/// # Conservative fallbacks (both return `false`, meaning "assume compatible")
/// - `requires_python` fails to parse as a PEP 440 `VersionSpecifiers` string.
/// - `target` fails to parse as a PEP 440 `Version` string.
///
/// This never panics: parse failures degrade to "compatible" so a malformed
/// upstream constraint can never produce a false-positive incompatibility.
fn excluded_by_specifier(requires_python: &str, target: &str) -> bool {
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
        assert!(PythonCompatibilityChecker::is_incompatible(
            Some(">=3"),
            "2.7"
        ));
    }

    #[test]
    fn test_is_incompatible_minor_version_mismatch() {
        assert!(PythonCompatibilityChecker::is_incompatible(
            Some(">=3.12"),
            "3.11"
        ));
    }

    #[test]
    fn test_is_incompatible_range_specifier_outside_range() {
        assert!(PythonCompatibilityChecker::is_incompatible(
            Some(">=3.8,<3.12"),
            "3.13"
        ));
    }

    #[test]
    fn test_is_incompatible_range_specifier_within_range() {
        assert!(!PythonCompatibilityChecker::is_incompatible(
            Some(">=3.8,<3.12"),
            "3.10"
        ));
    }

    #[test]
    fn test_is_incompatible_open_ended_specifier() {
        assert!(!PythonCompatibilityChecker::is_incompatible(
            Some(">=3.8"),
            "3.13"
        ));
    }

    #[test]
    fn test_is_incompatible_unparseable_specifier_treated_as_compatible() {
        assert!(!PythonCompatibilityChecker::is_incompatible(
            Some("not-a-specifier"),
            "3.11"
        ));
    }

    #[test]
    fn test_is_incompatible_unparseable_target_treated_as_compatible() {
        assert!(!PythonCompatibilityChecker::is_incompatible(
            Some(">=3.8"),
            "not-a-version"
        ));
    }

    #[test]
    fn test_is_incompatible_none_requires_python_is_compatible() {
        assert!(!PythonCompatibilityChecker::is_incompatible(None, "3.13"));
    }

    #[test]
    fn test_is_incompatible_some_requires_python_delegates_to_specifier_check() {
        assert!(PythonCompatibilityChecker::is_incompatible(
            Some(">=3.8,<3.12"),
            "3.13"
        ));
        assert!(!PythonCompatibilityChecker::is_incompatible(
            Some(">=3.8,<3.12"),
            "3.10"
        ));
    }
}
