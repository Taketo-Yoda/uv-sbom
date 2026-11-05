use owo_colors::OwoColorize;

use crate::application::dto::OutputFormat;
use crate::i18n::Messages;
use crate::shared::Result;

pub fn display_banner() {
    let version = env!("CARGO_PKG_VERSION");
    eprintln!(
        "{} {} {}",
        "🚀".bright_yellow(),
        "uv-sbom".bright_cyan().bold(),
        format!("v{}", version).bright_green()
    );
    eprintln!();
}

/// Resolves the effective value of `suggest_fix` after pre-flight validation.
///
/// Returns `false` immediately when `suggest_fix` is `false`.
/// When `suggest_fix` is `true`, verifies that:
/// - the `uv` CLI is available in PATH
/// - `pyproject.toml` exists in the given project directory
///
/// Prints a warning and returns `false` on the first failing condition.
pub fn resolve_suggest_fix(
    suggest_fix: bool,
    project_path: &std::path::Path,
    msgs: &Messages,
) -> bool {
    if !suggest_fix {
        return false;
    }
    let uv_available = std::process::Command::new("uv")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !uv_available {
        eprintln!("{}", msgs.warn_suggest_fix_requires_uv);
        return false;
    }
    if !project_path.join("pyproject.toml").exists() {
        eprintln!("{}", msgs.warn_suggest_fix_requires_pyproject);
        return false;
    }
    true
}

/// Validates that the project path is a valid directory.
///
/// This delegates to `validate_directory_path` in `shared::security`,
/// which provides comprehensive security validation including:
/// - Existence check
/// - Symlink rejection
/// - Directory type verification
/// - Path canonicalization for traversal prevention
pub fn validate_project_path(path: &std::path::Path) -> Result<()> {
    crate::shared::security::validate_directory_path(path)
}

/// Version in which the SBOM default output format changes to Markdown (#1071).
const FORMAT_DEFAULT_CHANGE_VERSION: &str = "5.0.0";

/// Returns `true` when neither `--format` nor the config file's `format` key is
/// set, i.e. `resolve_format` falls through to the JSON default.
///
/// Presence-based on purpose: a config `format` value that does not parse still
/// counts as set, so it suppresses the warning (validating that value is #1072).
fn format_was_defaulted(cli: Option<OutputFormat>, config_format: Option<&str>) -> bool {
    cli.is_none() && config_format.is_none()
}

/// Prints the localized warning that the default output format changes from
/// JSON to Markdown in v5.0.0, when the format was defaulted (#1070).
///
/// Called only from the non-incident paths (`run`, `run_workspace`, `run_diff`);
/// `--incident` already defaults to Markdown.
pub fn warn_if_format_defaulted(
    cli: Option<OutputFormat>,
    config_format: Option<&str>,
    msgs: &Messages,
) {
    if format_was_defaulted(cli, config_format) {
        eprintln!(
            "{}",
            Messages::format(
                msgs.warn_format_default_changing,
                &[FORMAT_DEFAULT_CHANGE_VERSION]
            )
        );
        eprintln!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Locale;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_validate_project_path_valid_directory() {
        let temp_dir = TempDir::new().unwrap();
        let result = validate_project_path(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_project_path_nonexistent() {
        let nonexistent_path = PathBuf::from("/nonexistent/path/that/does/not/exist");
        let result = validate_project_path(&nonexistent_path);
        assert!(result.is_err());

        let err = result.unwrap_err();
        let err_string = format!("{}", err);
        assert!(err_string.contains("Directory does not exist"));
    }

    #[test]
    fn test_validate_project_path_file_not_directory() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file.txt");
        fs::write(&file_path, "test content").unwrap();

        let result = validate_project_path(&file_path);
        assert!(result.is_err());

        let err = result.unwrap_err();
        let err_string = format!("{}", err);
        assert!(err_string.contains("Not a directory"));
    }

    #[test]
    fn test_validate_project_path_current_directory() {
        let current_dir = std::env::current_dir().unwrap();
        let result = validate_project_path(&current_dir);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_suggest_fix_disabled() {
        let temp_dir = TempDir::new().unwrap();
        let msgs = Messages::for_locale(Locale::En);
        // When suggest_fix is false, always returns false without checking anything
        assert!(!resolve_suggest_fix(false, temp_dir.path(), msgs));
    }

    #[test]
    fn test_resolve_suggest_fix_missing_pyproject_toml() {
        let temp_dir = TempDir::new().unwrap();
        let msgs = Messages::for_locale(Locale::En);
        // No pyproject.toml in temp dir; only meaningful when uv is available
        let uv_available = std::process::Command::new("uv")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if uv_available {
            assert!(!resolve_suggest_fix(true, temp_dir.path(), msgs));
        }
    }

    #[test]
    fn test_resolve_suggest_fix_with_pyproject_toml() {
        let temp_dir = TempDir::new().unwrap();
        let msgs = Messages::for_locale(Locale::En);
        fs::write(
            temp_dir.path().join("pyproject.toml"),
            "[project]\nname = \"test\"\n",
        )
        .unwrap();
        let uv_available = std::process::Command::new("uv")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        // Result should match uv availability
        assert_eq!(
            resolve_suggest_fix(true, temp_dir.path(), msgs),
            uv_available
        );
    }

    #[test]
    fn test_format_was_defaulted_when_cli_and_config_unset() {
        assert!(format_was_defaulted(None, None));
    }

    #[test]
    fn test_format_was_defaulted_false_with_cli_format() {
        assert!(!format_was_defaulted(Some(OutputFormat::Json), None));
        assert!(!format_was_defaulted(Some(OutputFormat::Markdown), None));
    }

    #[test]
    fn test_format_was_defaulted_false_with_config_format() {
        assert!(!format_was_defaulted(None, Some("json")));
        assert!(!format_was_defaulted(None, Some("markdown")));
    }

    #[test]
    fn test_format_was_defaulted_false_with_unparseable_config_format() {
        // Presence-based: an invalid value still suppresses the warning (#1072).
        assert!(!format_was_defaulted(None, Some("xml")));
    }

    #[test]
    fn test_format_was_defaulted_false_with_cli_and_config() {
        assert!(!format_was_defaulted(
            Some(OutputFormat::Json),
            Some("markdown")
        ));
    }
}
