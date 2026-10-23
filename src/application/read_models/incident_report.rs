//! Read model for `--incident <ADVISORY_ID>` mode (#967).
//!
//! `IncidentReport` answers three questions about one advisory and one
//! `uv.lock`: is the project affected (and through which path), is the fix
//! released, and what should be run next. It is consumed by
//! `IncidentMarkdownFormatter` and `IncidentJsonFormatter`.
//!
//! Unlike the other read models, these types derive `serde::Serialize`: the
//! JSON output is a direct serialization of the read model, so field and
//! variant names here are the stable JSON contract (snake_case keys, verdicts
//! and release statuses as snake_case strings, `null` for absent options).
//! The domain enums are mirrored by view enums so the domain layer stays free
//! of serde.

use crate::application::read_models::vulnerability_view::SeverityView;
use crate::sbom_generation::domain::advisory::{IncidentVerdict, ReleaseStatus};
use serde::{Serialize, Serializer};

/// Result of evaluating one advisory against a project's `uv.lock`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IncidentReport {
    /// ID of the advisory record actually used (an alias when one was followed).
    pub advisory_id: String,
    /// The ID the user supplied, when an alias was followed to find a record
    /// with PyPI entries; `None` when the supplied ID was used directly.
    pub resolved_from: Option<String>,
    /// Aliases listed by the advisory record that was used.
    pub aliases: Vec<String>,
    /// Advisory severity, serialized as its upper-case label (e.g. `"HIGH"`),
    /// the same spelling the diff JSON output uses.
    #[serde(serialize_with = "serialize_severity")]
    pub severity: Option<SeverityView>,
    /// One-line advisory summary (untrusted text from OSV).
    pub summary: Option<String>,
    /// PyPI package names the advisory lists, deduplicated. Empty means the
    /// advisory affects no PyPI package at all.
    pub affected_packages: Vec<String>,
    /// One finding per in-scope locked `(package, version)` the advisory
    /// names, sorted by package name then version.
    pub findings: Vec<IncidentFinding>,
    /// The most actionable verdict across all findings.
    pub overall: IncidentVerdictView,
}

/// Evaluation of one locked package version against the advisory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IncidentFinding {
    /// Package name as it appears in `uv.lock`.
    pub package_name: String,
    /// Version locked in `uv.lock`.
    pub locked_version: String,
    /// Whether the package is a direct dependency of the project.
    pub is_direct: bool,
    /// Every path from a direct dependency to the package, ordered
    /// `[direct_dep, ..., package]`. Empty for a direct dependency with no
    /// other path, or for a package reachable only from a dependency group.
    pub paths: Vec<Vec<String>>,
    /// The smallest fixed version above the locked version, as written in the
    /// advisory. `None` when the package is not affected or no fix exists.
    pub fixed_version: Option<String>,
    /// PyPI release status of `fixed_version`. `None` when there is no fixed
    /// version, the lookup failed (`guidance` is `ReleaseLookupFailed`), or the
    /// package does not come from PyPI (`guidance` is `NotFromPyPi`).
    pub release_status: Option<ReleaseStatusView>,
    /// Verdict for this finding.
    pub verdict: IncidentVerdictView,
    /// Suggested upgrade command, e.g. `uv lock --upgrade-package requests==2.31.0`.
    pub upgrade_command: Option<String>,
    /// Whether `upgrade_command` was verified by a dry-run resolution.
    pub command_verified: bool,
    /// Explanation shown when there is no command (or the command could not
    /// be verified because of an error).
    pub guidance: Option<IncidentGuidance>,
}

/// View of the domain `IncidentVerdict`, serialized as a snake_case string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentVerdictView {
    /// The locked version is outside every affected range.
    NotAffected,
    /// Affected, and the fixed version is released on PyPI.
    AffectedFixReleased,
    /// Affected, but the fixed version is not (or not confirmed to be) released.
    AffectedFixUnreleased,
    /// Affected, and the advisory names no fixed version.
    AffectedNoFix,
}

impl From<IncidentVerdict> for IncidentVerdictView {
    fn from(verdict: IncidentVerdict) -> Self {
        match verdict {
            IncidentVerdict::NotAffected => Self::NotAffected,
            IncidentVerdict::AffectedFixReleased => Self::AffectedFixReleased,
            IncidentVerdict::AffectedFixUnreleased => Self::AffectedFixUnreleased,
            IncidentVerdict::AffectedNoFix => Self::AffectedNoFix,
        }
    }
}

/// View of the domain `ReleaseStatus`, serialized as a snake_case string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatusView {
    /// The version is published on PyPI and installable.
    Released,
    /// The version is published but yanked.
    Yanked,
    /// The version is not published on PyPI.
    NotFound,
}

impl From<ReleaseStatus> for ReleaseStatusView {
    fn from(status: ReleaseStatus) -> Self {
        match status {
            ReleaseStatus::Released => Self::Released,
            ReleaseStatus::Yanked => Self::Yanked,
            ReleaseStatus::NotFound => Self::NotFound,
        }
    }
}

/// Structured guidance for a finding; formatters render it in the user's
/// locale. Serialized as an object tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IncidentGuidance {
    /// The upgrade to the fixed version could not be resolved. `direct_roots`
    /// are the direct dependencies at the root of each path — the likely
    /// holders of the blocking constraint.
    ResolutionBlocked {
        /// Sorted, deduplicated direct dependency names.
        direct_roots: Vec<String>,
    },
    /// No released fix exists yet: the fixed version is not published or is
    /// yanked on PyPI, or the advisory names no fixed version at all.
    NoReleasedFix,
    /// The PyPI release status of the fixed version could not be looked up,
    /// so whether a released fix exists is unknown.
    ReleaseLookupFailed {
        /// The lookup error message (English, from the adapter).
        reason: String,
    },
    /// The package is not installed from PyPI, so the release status of the
    /// fixed version was not checked.
    #[serde(rename = "not_from_pypi")]
    NotFromPyPi,
    /// The dry-run resolution failed with an infrastructure error, so no
    /// command could be verified.
    SimulationError {
        /// The error message (English, from the adapter).
        reason: String,
    },
}

/// Serializes the severity as its upper-case label, or `null`.
fn serialize_severity<S: Serializer>(
    severity: &Option<SeverityView>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match severity {
        Some(severity) => serializer.serialize_some(severity.as_str()),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn finding() -> IncidentFinding {
        IncidentFinding {
            package_name: "requests".to_string(),
            locked_version: "2.25.0".to_string(),
            is_direct: true,
            paths: vec![],
            fixed_version: Some("2.31.0".to_string()),
            release_status: Some(ReleaseStatusView::Released),
            verdict: IncidentVerdictView::AffectedFixReleased,
            upgrade_command: Some("uv lock --upgrade-package requests==2.31.0".to_string()),
            command_verified: true,
            guidance: None,
        }
    }

    fn report(severity: Option<SeverityView>) -> IncidentReport {
        IncidentReport {
            advisory_id: "GHSA-j8r2-6x86-q33q".to_string(),
            resolved_from: None,
            aliases: vec!["CVE-2023-32681".to_string()],
            severity,
            summary: None,
            affected_packages: vec!["requests".to_string()],
            findings: vec![finding()],
            overall: IncidentVerdictView::AffectedFixReleased,
        }
    }

    #[test]
    fn test_verdict_from_domain_maps_every_variant() {
        let pairs = [
            (
                IncidentVerdict::NotAffected,
                IncidentVerdictView::NotAffected,
            ),
            (
                IncidentVerdict::AffectedFixReleased,
                IncidentVerdictView::AffectedFixReleased,
            ),
            (
                IncidentVerdict::AffectedFixUnreleased,
                IncidentVerdictView::AffectedFixUnreleased,
            ),
            (
                IncidentVerdict::AffectedNoFix,
                IncidentVerdictView::AffectedNoFix,
            ),
        ];
        for (domain, view) in pairs {
            assert_eq!(IncidentVerdictView::from(domain), view);
        }
    }

    #[test]
    fn test_release_status_from_domain_maps_every_variant() {
        assert_eq!(
            ReleaseStatusView::from(ReleaseStatus::Released),
            ReleaseStatusView::Released
        );
        assert_eq!(
            ReleaseStatusView::from(ReleaseStatus::Yanked),
            ReleaseStatusView::Yanked
        );
        assert_eq!(
            ReleaseStatusView::from(ReleaseStatus::NotFound),
            ReleaseStatusView::NotFound
        );
    }

    #[test]
    fn test_enums_serialize_as_snake_case_strings() {
        assert_eq!(
            serde_json::to_value(IncidentVerdictView::AffectedFixUnreleased).unwrap(),
            json!("affected_fix_unreleased")
        );
        assert_eq!(
            serde_json::to_value(ReleaseStatusView::NotFound).unwrap(),
            json!("not_found")
        );
    }

    #[test]
    fn test_guidance_serializes_with_kind_tag() {
        assert_eq!(
            serde_json::to_value(IncidentGuidance::ResolutionBlocked {
                direct_roots: vec!["flask".to_string()],
            })
            .unwrap(),
            json!({"kind": "resolution_blocked", "direct_roots": ["flask"]})
        );
        assert_eq!(
            serde_json::to_value(IncidentGuidance::NoReleasedFix).unwrap(),
            json!({"kind": "no_released_fix"})
        );
        assert_eq!(
            serde_json::to_value(IncidentGuidance::SimulationError {
                reason: "boom".to_string(),
            })
            .unwrap(),
            json!({"kind": "simulation_error", "reason": "boom"})
        );
        assert_eq!(
            serde_json::to_value(IncidentGuidance::ReleaseLookupFailed {
                reason: "timeout".to_string(),
            })
            .unwrap(),
            json!({"kind": "release_lookup_failed", "reason": "timeout"})
        );
        assert_eq!(
            serde_json::to_value(IncidentGuidance::NotFromPyPi).unwrap(),
            json!({"kind": "not_from_pypi"})
        );
    }

    #[test]
    fn test_severity_serializes_as_upper_case_label_or_null() {
        let with: Value = serde_json::to_value(report(Some(SeverityView::High))).unwrap();
        assert_eq!(with["severity"], json!("HIGH"));

        let without: Value = serde_json::to_value(report(None)).unwrap();
        assert_eq!(without["severity"], Value::Null);
    }

    #[test]
    fn test_none_options_serialize_as_null() {
        let value: Value = serde_json::to_value(report(None)).unwrap();
        assert_eq!(value["resolved_from"], Value::Null);
        assert_eq!(value["summary"], Value::Null);
        assert_eq!(value["findings"][0]["guidance"], Value::Null);
    }
}
