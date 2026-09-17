use crate::application::dto::OutputFormat;
use crate::sbom_generation::domain::vulnerability::Severity;
use crate::shared::Result;
use pep440_rs::Version;
use std::str::FromStr;

/// Resolve `target_python` from CLI (highest priority) or config file, then validate
/// that the resolved value parses as a PEP 440 version. This is the single point where
/// CLI-supplied and config-file-supplied values converge, so it catches typos from
/// either source with one code path, before any network calls are made.
///
/// # Errors
/// Returns an error if the resolved value does not parse as a valid PEP 440 version.
pub(super) fn resolve_target_python(
    cli: Option<&String>,
    config: Option<&String>,
) -> Result<Option<String>> {
    let resolved = cli.or(config).cloned();
    if let Some(ref version) = resolved {
        Version::from_str(version).map_err(|e| {
            anyhow::anyhow!(
                "Invalid Python version: '{}': {}. Example: --target-python 3.13",
                version,
                e
            )
        })?;
    }
    Ok(resolved)
}

/// Resolve a boolean opt-in flag: CLI flag wins if set, otherwise the config value
/// (defaulting to `false` if the config doesn't specify it).
///
/// Shared by `check_license`, `suggest_fix`, `check_abandoned`, and `check_non_pypi`,
/// which all follow this exact `cli || config.unwrap_or(false)` shape.
pub(super) fn resolve_flag(cli_flag: bool, config_value: Option<bool>) -> bool {
    cli_flag || config_value.unwrap_or(false)
}

/// Resolve `format`: CLI > config > default (json).
///
/// clap always provides a default value for `--format` (default "json"), so we can't
/// distinguish "user explicitly passed --format json" from "user passed nothing" —
/// `cli` is always populated. Convention: CLI wins whenever it differs from the clap
/// default; when it equals the default, config is allowed to override it. This means
/// an explicit `--format json` loses to a config value other than json.
pub(super) fn resolve_format(cli: OutputFormat, config: Option<&str>) -> OutputFormat {
    let Some(config_format) = config else {
        return cli;
    };
    if cli != OutputFormat::Json {
        cli
    } else {
        config_format.parse::<OutputFormat>().unwrap_or(cli)
    }
}

/// Resolve `check_cve`: CLI opt-out (`--no-check-cve`) takes highest priority;
/// otherwise use the config value (default `true`).
pub(super) fn resolve_check_cve(cli_opt_out: bool, config: Option<bool>) -> bool {
    if cli_opt_out {
        false
    } else {
        config.unwrap_or(true)
    }
}

/// Resolve `severity_threshold`: CLI > config > `None`.
pub(super) fn resolve_severity_threshold(
    cli: Option<Severity>,
    config: Option<&str>,
) -> Option<Severity> {
    cli.or_else(|| {
        config.and_then(|s| match s.to_lowercase().as_str() {
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        })
    })
}

/// Resolve `cvss_threshold`: CLI > config > `None`.
pub(super) fn resolve_cvss_threshold(cli: Option<f32>, config: Option<f64>) -> Option<f32> {
    cli.or(config.map(|v| v as f32))
}

/// Default inactivity threshold (in days) for abandoned-package detection when
/// neither CLI nor config specifies one.
pub(super) const DEFAULT_ABANDONED_THRESHOLD_DAYS: u64 = 730;

/// Resolve `abandoned_threshold_days`: CLI > config > default.
///
/// `cli` is `None` when the flag was not passed and `Some` when the user explicitly
/// provided a value, cleanly expressing "not provided" vs. "provided."
pub(super) fn resolve_abandoned_threshold_days(cli: Option<u64>, config: Option<u64>) -> u64 {
    cli.or(config).unwrap_or(DEFAULT_ABANDONED_THRESHOLD_DAYS)
}

/// Resolve `exclude_groups`: CLI overrides config entirely (not merged/deduplicated
/// like `exclude_patterns`).
///
/// `--production-only` is resolved in `main.rs` after lockfile I/O; when it is set,
/// `cli` is guaranteed empty by clap's `conflicts_with`, so this resolves to the
/// config value or empty.
pub(super) fn resolve_exclude_groups(cli: &[String], config: Option<&[String]>) -> Vec<String> {
    if !cli.is_empty() {
        cli.to_vec()
    } else {
        config.map(<[String]>::to_vec).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- resolve_target_python ---

    #[test]
    fn test_resolve_target_python_none() {
        let result = resolve_target_python(None, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_target_python_from_cli() {
        let cli = "3.13".to_string();
        let result = resolve_target_python(Some(&cli), None).unwrap();
        assert_eq!(result.as_deref(), Some("3.13"));
    }

    #[test]
    fn test_resolve_target_python_from_config() {
        let config = "3.11".to_string();
        let result = resolve_target_python(None, Some(&config)).unwrap();
        assert_eq!(result.as_deref(), Some("3.11"));
    }

    #[test]
    fn test_resolve_target_python_cli_wins_over_config() {
        let cli = "3.13".to_string();
        let config = "3.11".to_string();
        let result = resolve_target_python(Some(&cli), Some(&config)).unwrap();
        assert_eq!(result.as_deref(), Some("3.13"));
    }

    #[test]
    fn test_resolve_target_python_invalid_value_errors() {
        let cli = "3.x".to_string();
        let result = resolve_target_python(Some(&cli), None);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.starts_with("Invalid Python version: '3.x': "));
        assert!(err.ends_with("Example: --target-python 3.13"));
    }

    // --- resolve_flag ---

    #[test]
    fn test_resolve_flag_cli_true() {
        assert!(resolve_flag(true, None));
        assert!(resolve_flag(true, Some(false)));
    }

    #[test]
    fn test_resolve_flag_config_true() {
        assert!(resolve_flag(false, Some(true)));
    }

    #[test]
    fn test_resolve_flag_both_false_or_absent() {
        assert!(!resolve_flag(false, None));
        assert!(!resolve_flag(false, Some(false)));
    }

    // --- resolve_format ---

    #[test]
    fn test_resolve_format_no_config_returns_cli() {
        assert_eq!(
            resolve_format(OutputFormat::Markdown, None),
            OutputFormat::Markdown
        );
    }

    #[test]
    fn test_resolve_format_cli_non_json_wins() {
        assert_eq!(
            resolve_format(OutputFormat::Markdown, Some("json")),
            OutputFormat::Markdown
        );
    }

    #[test]
    fn test_resolve_format_cli_json_yields_to_config() {
        assert_eq!(
            resolve_format(OutputFormat::Json, Some("markdown")),
            OutputFormat::Markdown
        );
    }

    #[test]
    fn test_resolve_format_unparseable_config_falls_back_to_cli() {
        assert_eq!(
            resolve_format(OutputFormat::Json, Some("not-a-format")),
            OutputFormat::Json
        );
    }

    // --- resolve_check_cve ---

    #[test]
    fn test_resolve_check_cve_opt_out_wins() {
        assert!(!resolve_check_cve(true, Some(true)));
    }

    #[test]
    fn test_resolve_check_cve_config_false() {
        assert!(!resolve_check_cve(false, Some(false)));
    }

    #[test]
    fn test_resolve_check_cve_default_true() {
        assert!(resolve_check_cve(false, None));
    }

    // --- resolve_severity_threshold ---

    #[test]
    fn test_resolve_severity_threshold_cli_wins() {
        assert_eq!(
            resolve_severity_threshold(Some(Severity::Critical), Some("low")),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn test_resolve_severity_threshold_config_case_insensitive() {
        assert_eq!(
            resolve_severity_threshold(None, Some("HIGH")),
            Some(Severity::High)
        );
    }

    #[test]
    fn test_resolve_severity_threshold_unknown_string_is_none() {
        assert_eq!(
            resolve_severity_threshold(None, Some("not-a-severity")),
            None
        );
    }

    #[test]
    fn test_resolve_severity_threshold_none() {
        assert_eq!(resolve_severity_threshold(None, None), None);
    }

    // --- resolve_cvss_threshold ---

    #[test]
    fn test_resolve_cvss_threshold_cli_wins() {
        assert_eq!(resolve_cvss_threshold(Some(8.5), Some(5.0)), Some(8.5));
    }

    #[test]
    fn test_resolve_cvss_threshold_config_cast_to_f32() {
        assert_eq!(resolve_cvss_threshold(None, Some(6.0)), Some(6.0));
    }

    #[test]
    fn test_resolve_cvss_threshold_none() {
        assert_eq!(resolve_cvss_threshold(None, None), None);
    }

    // --- resolve_abandoned_threshold_days ---

    #[test]
    fn test_resolve_abandoned_threshold_days_cli_wins() {
        assert_eq!(resolve_abandoned_threshold_days(Some(90), Some(365)), 90);
    }

    #[test]
    fn test_resolve_abandoned_threshold_days_config_wins_over_default() {
        assert_eq!(resolve_abandoned_threshold_days(None, Some(365)), 365);
    }

    #[test]
    fn test_resolve_abandoned_threshold_days_default() {
        assert_eq!(
            resolve_abandoned_threshold_days(None, None),
            DEFAULT_ABANDONED_THRESHOLD_DAYS
        );
        assert_eq!(DEFAULT_ABANDONED_THRESHOLD_DAYS, 730);
    }

    // --- resolve_exclude_groups ---

    #[test]
    fn test_resolve_exclude_groups_cli_overrides_config_entirely() {
        let cli = vec!["dev".to_string()];
        let config = vec!["lint".to_string()];
        let result = resolve_exclude_groups(&cli, Some(&config));
        assert_eq!(result, vec!["dev"]);
    }

    #[test]
    fn test_resolve_exclude_groups_config_only() {
        let config = vec!["dev".to_string(), "lint".to_string()];
        let result = resolve_exclude_groups(&[], Some(&config));
        assert_eq!(result, vec!["dev", "lint"]);
    }

    #[test]
    fn test_resolve_exclude_groups_both_empty() {
        let result = resolve_exclude_groups(&[], None);
        assert!(result.is_empty());
    }
}
