//! CLI-layer helpers for `--incident` mode (#968).
//!
//! Pure functions, kept out of `main.rs` so they can be unit tested without
//! network access.

use crate::application::dto::OutputFormat;
use crate::application::read_models::incident_report::IncidentVerdictView;
use crate::shared::error::ExitCode;

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
