//! Aggregation and rendering for the `--workspace` mode aggregate summary.
//!
//! This module extracts per-member check results from a `SbomResponse` before
//! it is consumed by rendering/output, then renders an aggregate summary
//! covering only the checks that were actually enabled for the run.

use crate::application::dto::SbomResponse;
use crate::cli::config_resolver::MergedConfig;
use crate::i18n::Messages;

/// Per-member check results extracted from a `SbomResponse`.
///
/// Must be built from `response` before it is moved into `render_and_present`,
/// since that call consumes the response by value.
#[derive(Debug, Clone)]
pub struct MemberFindings {
    pub member_name: String,
    pub actionable_cve_count: usize,
    pub has_license_violations: bool,
    pub has_abandoned_packages: bool,
    pub has_non_pypi_packages: bool,
    pub has_python_incompatibilities: bool,
}

impl MemberFindings {
    /// Extracts per-member findings from a completed `SbomResponse`, before it
    /// is moved into `render_and_present`.
    pub fn from_response(member_name: &str, response: &SbomResponse) -> Self {
        Self {
            member_name: member_name.to_string(),
            actionable_cve_count: response
                .vulnerability_check_result
                .as_ref()
                .map(|r| r.actionable_count())
                .unwrap_or(0),
            has_license_violations: response.has_license_violations,
            has_abandoned_packages: response
                .abandoned_packages_report
                .as_ref()
                .is_some_and(|r| !r.is_empty()),
            has_non_pypi_packages: response
                .non_pypi_packages_report
                .as_ref()
                .is_some_and(|r| !r.is_empty()),
            has_python_incompatibilities: response
                .python_compatibility_report
                .as_ref()
                .is_some_and(|r| !r.is_empty()),
        }
    }
}

/// Which checks were actually requested for this workspace run.
///
/// Aggregate-summary line visibility is gated on this — not on whether a given
/// member's `Option` report field ended up `Some` — because a per-member check
/// can legitimately return `Ok(None)` even when enabled for the run (e.g. no
/// repository was wired for that check). Deriving visibility from report
/// presence would silently drop an enabled check's line, the inverse of the
/// Issue #669 failure mode (fabricated output for a check that never ran).
#[derive(Debug, Clone, Copy)]
pub struct EnabledChecks {
    pub cve: bool,
    pub license: bool,
    pub abandoned: bool,
    pub non_pypi: bool,
    pub python_compatibility: bool,
}

impl EnabledChecks {
    /// Reads which checks were actually requested for this run from the resolved config.
    pub fn from_merged(merged: &MergedConfig) -> Self {
        Self {
            cve: merged.check_cve,
            license: merged.check_license,
            abandoned: merged.check_abandoned,
            non_pypi: merged.check_non_pypi,
            python_compatibility: merged.target_python.is_some(),
        }
    }

    fn any_enabled(&self) -> bool {
        self.cve || self.license || self.abandoned || self.non_pypi || self.python_compatibility
    }
}

fn format_member_list(names: &[&str], msgs: &Messages) -> String {
    if names.is_empty() {
        msgs.workspace_aggregate_none.to_string()
    } else {
        names.join(", ")
    }
}

/// Renders a "Members with <check>: a, b" line for members matching `predicate`,
/// substituted into `message_template` via [`Messages::format`].
fn render_member_list_line(
    findings: &[MemberFindings],
    predicate: impl Fn(&MemberFindings) -> bool,
    message_template: &str,
    msgs: &Messages,
) -> String {
    let names: Vec<&str> = findings
        .iter()
        .filter(|f| predicate(f))
        .map(|f| f.member_name.as_str())
        .collect();
    Messages::format(message_template, &[&format_member_list(&names, msgs)])
}

/// Renders the workspace aggregate summary as printable lines: a header, a
/// separator, one line per enabled check, and a closing separator.
///
/// Returns an empty `Vec` when no check was enabled for this run, so callers
/// can skip printing the section entirely.
pub fn render_workspace_aggregate(
    findings: &[MemberFindings],
    enabled: &EnabledChecks,
    msgs: &Messages,
) -> Vec<String> {
    if !enabled.any_enabled() {
        return Vec::new();
    }

    let separator = "─".repeat(60);
    let mut lines = vec![
        msgs.workspace_aggregate_header.to_string(),
        separator.clone(),
    ];

    if enabled.cve {
        let total: usize = findings.iter().map(|f| f.actionable_cve_count).sum();
        lines.push(Messages::format(
            msgs.workspace_aggregate_total_cves,
            &[&total.to_string()],
        ));
    }
    if enabled.license {
        lines.push(render_member_list_line(
            findings,
            |f| f.has_license_violations,
            msgs.workspace_aggregate_license_violations,
            msgs,
        ));
    }
    if enabled.abandoned {
        lines.push(render_member_list_line(
            findings,
            |f| f.has_abandoned_packages,
            msgs.workspace_aggregate_abandoned,
            msgs,
        ));
    }
    if enabled.non_pypi {
        lines.push(render_member_list_line(
            findings,
            |f| f.has_non_pypi_packages,
            msgs.workspace_aggregate_non_pypi,
            msgs,
        ));
    }
    if enabled.python_compatibility {
        lines.push(render_member_list_line(
            findings,
            |f| f.has_python_incompatibilities,
            msgs.workspace_aggregate_python_incompatible,
            msgs,
        ));
    }

    lines.push(separator);
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::read_models::abandoned_package::AbandonedPackagesReport;
    use crate::application::read_models::non_pypi_package::NonPyPiPackagesReport;
    use crate::application::read_models::python_compatibility::PythonCompatibilityReport;
    use crate::i18n::Locale;
    use crate::sbom_generation::domain::services::VulnerabilityCheckResult;
    use crate::sbom_generation::domain::vulnerability::PackageVulnerabilities;
    use crate::sbom_generation::domain::vulnerability::{Severity, Vulnerability};
    use crate::sbom_generation::services::SbomGenerator;

    fn findings(member_name: &str, cve: usize, license: bool) -> MemberFindings {
        MemberFindings {
            member_name: member_name.to_string(),
            actionable_cve_count: cve,
            has_license_violations: license,
            has_abandoned_packages: false,
            has_non_pypi_packages: false,
            has_python_incompatibilities: false,
        }
    }

    fn disabled_checks() -> EnabledChecks {
        EnabledChecks {
            cve: false,
            license: false,
            abandoned: false,
            non_pypi: false,
            python_compatibility: false,
        }
    }

    #[test]
    fn test_render_sums_cve_across_members() {
        let msgs = Messages::for_locale(Locale::En);
        let members = vec![
            findings("api", 2, false),
            findings("worker", 0, false),
            findings("gateway", 5, false),
        ];
        let enabled = EnabledChecks {
            cve: true,
            ..disabled_checks()
        };

        let lines = render_workspace_aggregate(&members, &enabled, msgs);

        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "📊 Workspace Aggregate Summary");
        assert_eq!(lines[2], "Total actionable CVEs: 7");
    }

    #[test]
    fn test_render_only_includes_enabled_check_lines() {
        let msgs = Messages::for_locale(Locale::En);
        let members = vec![findings("api", 3, true)];
        let enabled = EnabledChecks {
            cve: true,
            ..disabled_checks()
        };

        let lines = render_workspace_aggregate(&members, &enabled, msgs);

        assert!(!lines.iter().any(|l| l.contains("license")));
        assert!(!lines.iter().any(|l| l.contains("abandoned")));
        assert!(!lines.iter().any(|l| l.contains("non-PyPI")));
        assert!(!lines.iter().any(|l| l.contains("Python-incompatible")));
    }

    #[test]
    fn test_render_empty_violator_list_renders_none() {
        let msgs = Messages::for_locale(Locale::En);
        let members = vec![findings("api", 0, false), findings("worker", 0, false)];
        let enabled = EnabledChecks {
            license: true,
            ..disabled_checks()
        };

        let lines = render_workspace_aggregate(&members, &enabled, msgs);

        assert_eq!(lines[2], "Members with license policy violations: none");
    }

    #[test]
    fn test_render_lists_violating_members() {
        let msgs = Messages::for_locale(Locale::En);
        let members = vec![
            findings("api", 0, false),
            findings("worker", 0, true),
            findings("gateway", 0, true),
        ];
        let enabled = EnabledChecks {
            license: true,
            ..disabled_checks()
        };

        let lines = render_workspace_aggregate(&members, &enabled, msgs);

        assert_eq!(
            lines[2],
            "Members with license policy violations: worker, gateway"
        );
    }

    #[test]
    fn test_render_returns_empty_when_no_check_enabled() {
        let msgs = Messages::for_locale(Locale::En);
        let members = vec![findings("api", 0, false)];

        let lines = render_workspace_aggregate(&members, &disabled_checks(), msgs);

        assert!(lines.is_empty());
    }

    #[test]
    fn test_from_response_defaults_to_false_and_zero_when_reports_absent() {
        let response = SbomResponse::builder()
            .metadata(SbomGenerator::generate_default_metadata())
            .build()
            .expect("should build minimal response");

        let findings = MemberFindings::from_response("api", &response);

        assert_eq!(findings.actionable_cve_count, 0);
        assert!(!findings.has_license_violations);
        assert!(!findings.has_abandoned_packages);
        assert!(!findings.has_non_pypi_packages);
        assert!(!findings.has_python_incompatibilities);
    }

    #[test]
    fn test_from_response_reports_false_for_empty_reports() {
        let response = SbomResponse::builder()
            .metadata(SbomGenerator::generate_default_metadata())
            .abandoned_packages_report(AbandonedPackagesReport::default())
            .non_pypi_packages_report(NonPyPiPackagesReport::default())
            .python_compatibility_report(PythonCompatibilityReport {
                target_python: "3.13".to_string(),
                incompatible: vec![],
            })
            .build()
            .expect("should build response with empty reports");

        let findings = MemberFindings::from_response("api", &response);

        assert!(!findings.has_abandoned_packages);
        assert!(!findings.has_non_pypi_packages);
        assert!(!findings.has_python_incompatibilities);
    }

    #[test]
    fn test_from_response_extracts_actionable_cve_count() {
        let vulnerability = Vulnerability::new(
            "CVE-2024-0001".to_string(),
            None,
            Severity::High,
            None,
            None,
        )
        .expect("valid vulnerability");
        let above_threshold = vec![PackageVulnerabilities::new(
            "requests".to_string(),
            "2.31.0".to_string(),
            vec![vulnerability],
        )];
        let vulnerability_check_result = VulnerabilityCheckResult {
            above_threshold,
            below_threshold: Vec::new(),
            threshold_exceeded: true,
            ..Default::default()
        };

        let response = SbomResponse::builder()
            .metadata(SbomGenerator::generate_default_metadata())
            .vulnerability_check_result(vulnerability_check_result)
            .build()
            .expect("should build response with vulnerability result");

        let findings = MemberFindings::from_response("api", &response);

        assert_eq!(findings.actionable_cve_count, 1);
    }

    #[test]
    fn test_enabled_checks_from_merged_reflects_run_flags() {
        let checks = EnabledChecks {
            cve: true,
            license: false,
            abandoned: true,
            non_pypi: false,
            python_compatibility: true,
        };

        assert!(checks.any_enabled());

        let none_enabled = disabled_checks();
        assert!(!none_enabled.any_enabled());
    }
}
