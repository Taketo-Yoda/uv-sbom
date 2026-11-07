//! CLI-layer helpers for `--incident` mode (#968; target parsing #963).
//!
//! Pure functions, kept out of `main.rs` so they can be unit tested without
//! network access.

use crate::application::dto::OutputFormat;
use crate::application::read_models::incident_report::IncidentVerdictView;
use crate::sbom_generation::domain::incident_target::{
    IncidentTarget, ManualAffectedSpec, ManualSpecError,
};
use crate::shared::error::ExitCode;

/// Advisory ID prefixes accepted by `--incident`, in their canonical case.
const ADVISORY_ID_PREFIXES: [&str; 5] = ["GHSA-", "PYSEC-", "CVE-", "OSV-", "MAL-"];

/// Characters that appear in a version-range spec but never in an advisory ID.
const SPEC_OPERATOR_CHARS: [char; 6] = ['<', '>', '=', '!', '~', ','];

/// A rejected `--incident` value (#963): neither an advisory ID nor a valid
/// manual range spec. The English `Display` is kept for completeness; the CLI
/// renders it in the user's locale with `render_incident_target_error`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Invalid advisory ID or version-range spec: '{input}'. {reason}")]
pub struct IncidentTargetError {
    /// The value as supplied by the user.
    pub input: String,
    /// Why it was not accepted as a manual range spec.
    pub reason: ManualSpecError,
}

/// Classifies and validates an `--incident` value (#963).
///
/// A value starting with an advisory ID prefix (case-insensitive) followed by
/// at least one character, and containing no range operator characters, is an
/// `AdvisoryId` with its prefix normalized to upper case. Only the prefix is
/// normalized, because OSV IDs can be case-sensitive (GHSA suffixes are lower
/// case). Anything else is parsed as a manual range spec.
///
/// # Errors
/// Returns `IncidentTargetError` when the value is not a valid range spec.
pub fn parse_incident_target(raw: &str) -> Result<IncidentTarget, IncidentTargetError> {
    if let Some(id) = normalize_advisory_id(raw) {
        return Ok(IncidentTarget::AdvisoryId(id));
    }
    ManualAffectedSpec::parse(raw)
        .map(IncidentTarget::ManualSpec)
        .map_err(|reason| IncidentTargetError {
            input: raw.to_string(),
            reason,
        })
}

/// The advisory ID with its prefix in canonical case, or `None` when `raw` is
/// not shaped like an advisory ID.
fn normalize_advisory_id(raw: &str) -> Option<String> {
    let id = raw.trim();
    if id.contains(SPEC_OPERATOR_CHARS) {
        return None;
    }
    ADVISORY_ID_PREFIXES.iter().find_map(|prefix| {
        let head = id.get(..prefix.len())?;
        let rest = &id[prefix.len()..];
        (head.eq_ignore_ascii_case(prefix) && !rest.is_empty())
            .then(|| format!("{}{}", prefix, rest))
    })
}

/// Maps the report's overall verdict to the process exit code.
///
/// Errors (exit 3) are mapped by the caller; this covers successful reports only.
/// An advisory that names no PyPI package yields `NotAffected` and so exits 0.
pub fn incident_exit_code(verdict: IncidentVerdictView) -> ExitCode {
    match verdict {
        IncidentVerdictView::NotAffected => ExitCode::Success,
        IncidentVerdictView::AffectedFixReleased => ExitCode::VulnerabilitiesDetected,
        IncidentVerdictView::AffectedFixUnreleased | IncidentVerdictView::AffectedNoFix => {
            ExitCode::AffectedNoReleasedFix
        }
    }
}

/// Resolves the incident output format: the CLI value, else Markdown.
///
/// Takes no config parameter on purpose: incident mode never reads the config
/// file's `format`, which exists for SBOM output.
pub fn resolve_incident_format(cli: Option<OutputFormat>) -> OutputFormat {
    cli.unwrap_or(OutputFormat::Markdown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advisory_id(raw: &str) -> String {
        match parse_incident_target(raw).unwrap() {
            IncidentTarget::AdvisoryId(id) => id,
            other => panic!("{raw}: expected an advisory ID, got {other:?}"),
        }
    }

    fn manual_spec(raw: &str) -> ManualAffectedSpec {
        match parse_incident_target(raw).unwrap() {
            IncidentTarget::ManualSpec(spec) => spec,
            other => panic!("{raw}: expected a manual spec, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_incident_target_accepts_each_prefix() {
        for id in [
            "GHSA-j8r2-6x86-q33q",
            "PYSEC-2023-74",
            "CVE-2023-32681",
            "OSV-2020-111",
            "MAL-2024-1234",
        ] {
            assert_eq!(advisory_id(id), id);
        }
    }

    #[test]
    fn test_parse_incident_target_normalizes_prefix_only() {
        assert_eq!(advisory_id("ghsa-j8r2-6x86-q33q"), "GHSA-j8r2-6x86-q33q");
        assert_eq!(advisory_id("cve-2023-32681"), "CVE-2023-32681");
        assert_eq!(advisory_id("Pysec-2023-74"), "PYSEC-2023-74");
    }

    #[test]
    fn test_parse_incident_target_trims_whitespace() {
        assert_eq!(advisory_id("  CVE-2023-32681 "), "CVE-2023-32681");
    }

    #[test]
    fn test_parse_incident_target_manual_spec() {
        let spec = manual_spec("requests>=2.26,<2.31.0");
        assert_eq!(spec.package_name, "requests");
        assert_eq!(spec.introduced.as_deref(), Some("2.26"));
        assert_eq!(spec.fixed.as_deref(), Some("2.31.0"));
    }

    #[test]
    fn test_parse_incident_target_prefixed_package_name_with_operator_is_spec() {
        assert_eq!(manual_spec("osv-foo<2").package_name, "osv-foo");
        assert_eq!(manual_spec("mal-foo<=1.0").package_name, "mal-foo");
    }

    #[test]
    fn test_parse_incident_target_rejects_invalid() {
        for raw in [
            "foo",
            "",
            "CVE-",
            "GHSA",
            "CVE2023-32681",
            "XCVE-2023-1",
            "日本語",
            "requests==2.25.0",
            "requests>2.0",
        ] {
            let err = parse_incident_target(raw).unwrap_err();
            assert_eq!(err.input, raw);
            assert!(
                err.to_string()
                    .starts_with("Invalid advisory ID or version-range spec"),
                "{raw}: {err}"
            );
        }
    }

    #[test]
    fn test_parse_incident_target_error_carries_reason() {
        assert_eq!(
            parse_incident_target("requests").unwrap_err().reason,
            ManualSpecError::MissingSpecifier {
                package: "requests".to_string()
            }
        );
    }

    #[test]
    fn test_incident_exit_code_not_affected_returns_success() {
        assert_eq!(
            incident_exit_code(IncidentVerdictView::NotAffected),
            ExitCode::Success
        );
    }

    #[test]
    fn test_incident_exit_code_fix_released_returns_vulnerabilities_detected() {
        assert_eq!(
            incident_exit_code(IncidentVerdictView::AffectedFixReleased),
            ExitCode::VulnerabilitiesDetected
        );
    }

    #[test]
    fn test_incident_exit_code_fix_unreleased_returns_no_released_fix() {
        assert_eq!(
            incident_exit_code(IncidentVerdictView::AffectedFixUnreleased),
            ExitCode::AffectedNoReleasedFix
        );
    }

    #[test]
    fn test_incident_exit_code_no_fix_returns_no_released_fix() {
        assert_eq!(
            incident_exit_code(IncidentVerdictView::AffectedNoFix),
            ExitCode::AffectedNoReleasedFix
        );
    }

    #[test]
    fn test_resolve_incident_format_none_defaults_to_markdown() {
        assert_eq!(resolve_incident_format(None), OutputFormat::Markdown);
    }

    #[test]
    fn test_resolve_incident_format_some_returns_cli_value() {
        assert_eq!(
            resolve_incident_format(Some(OutputFormat::Json)),
            OutputFormat::Json
        );
        assert_eq!(
            resolve_incident_format(Some(OutputFormat::Markdown)),
            OutputFormat::Markdown
        );
    }
}
