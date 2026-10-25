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
use std::collections::{BTreeMap, BTreeSet};

/// Result of evaluating one advisory against a project's `uv.lock`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IncidentReport {
    /// ID of the advisory record actually used (an alias when one was followed);
    /// the user-supplied range spec when `source` is `Manual` (#963).
    pub advisory_id: String,
    /// Where the affected range came from (#963).
    pub source: IncidentSource,
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

/// Where the affected range of a report came from (#963), serialized as a
/// snake_case string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSource {
    /// An OSV advisory record.
    Osv,
    /// A version-range spec supplied by the user, not verified against any
    /// vulnerability database.
    Manual,
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
    /// The package is itself a direct dependency and the upgrade to the fixed
    /// version could not be resolved: the project's own version requirement
    /// in `pyproject.toml` likely excludes the fix (#984). The package name
    /// and fixed version are the finding's own fields.
    DirectPinBlocksUpgrade,
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

/// Result of evaluating one advisory against every member of a uv workspace
/// (`--incident --workspace`, #969).
///
/// The advisory metadata is shared; each member carries its own findings,
/// because members differ in which packages they reach (they share one
/// `uv.lock`, so locked versions never differ). Serialized as the workspace
/// JSON output: the advisory fields, a `members` array, and `overall`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceIncidentReport {
    /// ID of the advisory record actually used (an alias when one was followed);
    /// the user-supplied range spec when `source` is `Manual` (#963).
    pub advisory_id: String,
    /// Where the affected range came from (#963).
    pub source: IncidentSource,
    /// The ID the user supplied, when an alias was followed.
    pub resolved_from: Option<String>,
    /// Aliases listed by the advisory record that was used.
    pub aliases: Vec<String>,
    /// Advisory severity, serialized as its upper-case label.
    #[serde(serialize_with = "serialize_severity")]
    pub severity: Option<SeverityView>,
    /// One-line advisory summary (untrusted text from OSV).
    pub summary: Option<String>,
    /// PyPI package names the advisory lists, deduplicated.
    pub affected_packages: Vec<String>,
    /// One result per workspace member, in workspace order.
    pub members: Vec<MemberIncidentResult>,
    /// The most actionable verdict across all members.
    pub overall: IncidentVerdictView,
}

/// Evaluation of the advisory against one workspace member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemberIncidentResult {
    /// Workspace member name as it appears in `uv.lock`.
    pub name: String,
    /// Findings for the packages this member reaches, sorted by package name
    /// then version. Paths start at the member's own direct dependencies.
    pub findings: Vec<IncidentFinding>,
    /// The most actionable verdict across this member's findings.
    pub overall: IncidentVerdictView,
}

impl WorkspaceIncidentReport {
    /// Findings across all members, deduplicated by `(package, version)` and
    /// sorted by package name then version. Release status, verdict, and
    /// command do not depend on the member; only the dependency position does,
    /// so the first member's position is kept and the `direct_roots` of
    /// `ResolutionBlocked` guidance are unioned (sorted, deduplicated). A
    /// member's `DirectPinBlocksUpgrade` replaces another member's
    /// `ResolutionBlocked`: members share one `uv.lock`, so that member's own
    /// requirement blocks the upgrade for the whole workspace. Only the
    /// guidance is replaced; `is_direct` and `paths` stay the first member's.
    pub fn deduplicated_findings(&self) -> Vec<IncidentFinding> {
        let mut merged: BTreeMap<(String, String), IncidentFinding> = BTreeMap::new();
        for finding in self.members.iter().flat_map(|m| &m.findings) {
            let key = (finding.package_name.clone(), finding.locked_version.clone());
            match merged.get_mut(&key) {
                None => {
                    merged.insert(key, finding.clone());
                }
                Some(existing) => match (&mut existing.guidance, &finding.guidance) {
                    (
                        Some(IncidentGuidance::ResolutionBlocked { direct_roots }),
                        Some(IncidentGuidance::ResolutionBlocked {
                            direct_roots: other,
                        }),
                    ) => {
                        let union: BTreeSet<String> =
                            direct_roots.iter().chain(other).cloned().collect();
                        *direct_roots = union.into_iter().collect();
                    }
                    (
                        guidance @ Some(IncidentGuidance::ResolutionBlocked { .. }),
                        Some(IncidentGuidance::DirectPinBlocksUpgrade),
                    ) => *guidance = Some(IncidentGuidance::DirectPinBlocksUpgrade),
                    _ => {}
                },
            }
        }
        merged.into_values().collect()
    }

    /// Names of the members whose verdict is not `NotAffected`, in workspace order.
    pub fn affected_member_names(&self) -> Vec<&str> {
        self.members
            .iter()
            .filter(|m| m.overall != IncidentVerdictView::NotAffected)
            .map(|m| m.name.as_str())
            .collect()
    }
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
            source: IncidentSource::Osv,
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
            serde_json::to_value(IncidentGuidance::DirectPinBlocksUpgrade).unwrap(),
            json!({"kind": "direct_pin_blocks_upgrade"})
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

    fn member(name: &str, findings: Vec<IncidentFinding>) -> MemberIncidentResult {
        let overall = findings
            .iter()
            .map(|f| f.verdict)
            .find(|v| *v != IncidentVerdictView::NotAffected)
            .unwrap_or(IncidentVerdictView::NotAffected);
        MemberIncidentResult {
            name: name.to_string(),
            findings,
            overall,
        }
    }

    fn workspace(members: Vec<MemberIncidentResult>) -> WorkspaceIncidentReport {
        WorkspaceIncidentReport {
            advisory_id: "GHSA-j8r2-6x86-q33q".to_string(),
            source: IncidentSource::Osv,
            resolved_from: None,
            aliases: vec![],
            severity: None,
            summary: None,
            affected_packages: vec!["requests".to_string()],
            members,
            overall: IncidentVerdictView::AffectedFixReleased,
        }
    }

    fn blocked(roots: &[&str]) -> IncidentFinding {
        IncidentFinding {
            upgrade_command: None,
            command_verified: false,
            guidance: Some(IncidentGuidance::ResolutionBlocked {
                direct_roots: roots.iter().map(|r| r.to_string()).collect(),
            }),
            ..finding()
        }
    }

    #[test]
    fn test_deduplicated_findings_merges_same_package_version_across_members() {
        let other = IncidentFinding {
            package_name: "certifi".to_string(),
            ..finding()
        };
        let report = workspace(vec![
            member("api", vec![finding()]),
            member("worker", vec![finding(), other]),
        ]);

        let merged = report.deduplicated_findings();

        let names: Vec<&str> = merged.iter().map(|f| f.package_name.as_str()).collect();
        assert_eq!(names, vec!["certifi", "requests"]);
    }

    #[test]
    fn test_deduplicated_findings_unions_resolution_blocked_roots() {
        let report = workspace(vec![
            member("api", vec![blocked(&["httpx"])]),
            member("worker", vec![blocked(&["celery", "httpx"])]),
        ]);

        let merged = report.deduplicated_findings();

        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].guidance,
            Some(IncidentGuidance::ResolutionBlocked {
                direct_roots: vec!["celery".to_string(), "httpx".to_string()],
            })
        );
    }

    #[test]
    fn test_deduplicated_findings_prefers_direct_pin_in_either_member_order() {
        let pinned = IncidentFinding {
            is_direct: true,
            upgrade_command: None,
            command_verified: false,
            guidance: Some(IncidentGuidance::DirectPinBlocksUpgrade),
            ..finding()
        };
        for members in [
            vec![
                member("api", vec![pinned.clone()]),
                member("worker", vec![blocked(&["httpx"])]),
            ],
            vec![
                member("worker", vec![blocked(&["httpx"])]),
                member("api", vec![pinned.clone()]),
            ],
        ] {
            let merged = workspace(members).deduplicated_findings();

            assert_eq!(merged.len(), 1);
            assert_eq!(
                merged[0].guidance,
                Some(IncidentGuidance::DirectPinBlocksUpgrade)
            );
        }
    }

    #[test]
    fn test_affected_member_names_keeps_workspace_order() {
        let report = workspace(vec![
            member("worker", vec![finding()]),
            member("api", vec![]),
            member("admin", vec![finding()]),
        ]);

        assert_eq!(report.affected_member_names(), vec!["worker", "admin"]);
    }

    #[test]
    fn test_workspace_report_json_shape() {
        let value: Value =
            serde_json::to_value(workspace(vec![member("api", vec![finding()])])).unwrap();

        let keys: BTreeSet<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from([
                "advisory_id",
                "source",
                "resolved_from",
                "aliases",
                "severity",
                "summary",
                "affected_packages",
                "members",
                "overall",
            ])
        );
        let member_keys: BTreeSet<&str> = value["members"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(member_keys, BTreeSet::from(["name", "findings", "overall"]));
        assert_eq!(value["overall"], json!("affected_fix_released"));
        assert_eq!(
            value["members"][0]["overall"],
            json!("affected_fix_released")
        );
    }
}
