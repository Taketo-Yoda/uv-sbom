use crate::application::dto::OutputFormat;
use crate::sbom_generation::domain::license_policy::{LicensePolicy, UnknownLicenseHandling};
use crate::sbom_generation::domain::vulnerability::Severity;
use crate::shared::Result;
use pep440_rs::Version;
use std::collections::HashSet;
use std::str::FromStr;
use uv_sbom::config::{self, ConfigFile, IgnoreCve};

use super::Args;

/// Merged configuration after combining CLI arguments and config file values.
#[derive(Debug)]
pub struct MergedConfig {
    pub format: OutputFormat,
    pub exclude_patterns: Vec<String>,
    pub check_cve: bool,
    pub severity_threshold: Option<Severity>,
    pub cvss_threshold: Option<f32>,
    pub ignore_cves: Vec<IgnoreCve>,
    pub check_license: bool,
    pub license_policy: Option<LicensePolicy>,
    pub suggest_fix: bool,
    pub check_abandoned: bool,
    pub abandoned_threshold_days: u64,
    pub check_non_pypi: bool,
    /// Dependency groups whose exclusively-reachable packages should be excluded from the SBOM.
    /// Populated from `--exclude-groups` (CLI) or `exclude_groups` (config file).
    /// When `--production-only` is set, `main.rs` overrides this with all group names from the
    /// lockfile, since that resolution requires I/O that config_resolver must not perform.
    pub exclude_groups: Vec<String>,
    /// Target Python version for compatibility checking (PEP 440 format).
    /// Populated from `--target-python` (CLI) or `target_python` (config file).
    pub target_python: Option<String>,
}

/// Load a config file from an explicit path or via auto-discovery.
pub fn load_config(args: &Args, project_path: &std::path::Path) -> Result<Option<ConfigFile>> {
    if let Some(ref config_path) = args.config {
        let path = std::path::Path::new(config_path);
        let cfg = config::load_config_from_path(path)?;
        eprintln!("📄 Loaded config from: {}", path.display());
        Ok(Some(cfg))
    } else {
        let cfg = config::discover_config(project_path)?;
        if cfg.is_some() {
            eprintln!("📄 Auto-discovered config file in project directory.");
        }
        Ok(cfg)
    }
}

/// Merge two string lists and deduplicate.
pub fn merge_string_lists(cli: &[String], config: &Option<Vec<String>>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    // CLI values first (higher priority)
    for item in cli {
        if seen.insert(item.clone()) {
            result.push(item.clone());
        }
    }

    // Then config values
    if let Some(config_items) = config {
        for item in config_items {
            if seen.insert(item.clone()) {
                result.push(item.clone());
            }
        }
    }

    result
}

/// Merge two ignore_cves lists and deduplicate by ID (CLI entries take precedence).
pub fn merge_ignore_cves(cli: &[IgnoreCve], config: &Option<Vec<IgnoreCve>>) -> Vec<IgnoreCve> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    // CLI values first (higher priority)
    for cve in cli {
        if seen.insert(cve.id.clone()) {
            result.push(cve.clone());
        }
    }

    // Then config values
    if let Some(config_cves) = config {
        for cve in config_cves {
            if seen.insert(cve.id.clone()) {
                result.push(cve.clone());
            }
        }
    }

    result
}

/// Resolve `target_python` from CLI (highest priority) or config file, then validate
/// that the resolved value parses as a PEP 440 version. This is the single point where
/// CLI-supplied and config-file-supplied values converge, so it catches typos from
/// either source with one code path, before any network calls are made.
///
/// # Errors
/// Returns an error if the resolved value does not parse as a valid PEP 440 version.
fn resolve_target_python(cli: Option<&String>, config: Option<&String>) -> Result<Option<String>> {
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
fn resolve_flag(cli_flag: bool, config_value: Option<bool>) -> bool {
    cli_flag || config_value.unwrap_or(false)
}

/// Resolve `format`: CLI > config > default (json).
///
/// clap always provides a default value for `--format` (default "json"), so we can't
/// distinguish "user explicitly passed --format json" from "user passed nothing" —
/// `cli` is always populated. Convention: CLI wins whenever it differs from the clap
/// default; when it equals the default, config is allowed to override it. This means
/// an explicit `--format json` loses to a config value other than json.
fn resolve_format(cli: OutputFormat, config: Option<&str>) -> OutputFormat {
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
fn resolve_check_cve(cli_opt_out: bool, config: Option<bool>) -> bool {
    if cli_opt_out {
        false
    } else {
        config.unwrap_or(true)
    }
}

/// Resolve `severity_threshold`: CLI > config > `None`.
fn resolve_severity_threshold(cli: Option<Severity>, config: Option<&str>) -> Option<Severity> {
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
fn resolve_cvss_threshold(cli: Option<f32>, config: Option<f64>) -> Option<f32> {
    cli.or(config.map(|v| v as f32))
}

/// Resolve the `unknown` license handling from its config string representation.
/// Unrecognized or unspecified values default to `Warn`. Config-file values are
/// already validated at load time (`config.rs`), so the fallback here is defensive.
fn resolve_unknown_license_handling(config: Option<&str>) -> UnknownLicenseHandling {
    config
        .map(|s| match s.to_lowercase().as_str() {
            "deny" => UnknownLicenseHandling::Deny,
            "allow" => UnknownLicenseHandling::Allow,
            _ => UnknownLicenseHandling::Warn,
        })
        .unwrap_or_default()
}

/// Resolve `license_policy`. `check_license` must be the already-resolved merged
/// value (not re-derived here), since config-only activation
/// (`config.check_license = true`) must also pick up the CLI-supplied lists.
///
/// If `check_license` is enabled and CLI allow/deny lists are non-empty, they
/// override the config policy entirely. Otherwise, the config policy is used if
/// present, falling back to an empty policy (default `Warn` unknown-handling).
fn resolve_license_policy(
    check_license: bool,
    cli_allow: &[String],
    cli_deny: &[String],
    config: Option<&config::LicensePolicyConfig>,
) -> Option<LicensePolicy> {
    if !check_license {
        return None;
    }
    if !cli_allow.is_empty() || !cli_deny.is_empty() {
        // CLI provides policy — override config entirely
        return Some(LicensePolicy::new(
            cli_allow,
            cli_deny,
            UnknownLicenseHandling::default(),
        ));
    }
    if let Some(lp_config) = config {
        // Use config policy
        let unknown = resolve_unknown_license_handling(lp_config.unknown.as_deref());
        let allow = lp_config.allow.clone().unwrap_or_default();
        let deny = lp_config.deny.clone().unwrap_or_default();
        return Some(LicensePolicy::new(&allow, &deny, unknown));
    }
    // check_license enabled but no policy specified
    Some(LicensePolicy::new(
        &[],
        &[],
        UnknownLicenseHandling::default(),
    ))
}

/// Default inactivity threshold (in days) for abandoned-package detection when
/// neither CLI nor config specifies one.
const DEFAULT_ABANDONED_THRESHOLD_DAYS: u64 = 730;

/// Resolve `abandoned_threshold_days`: CLI > config > default.
///
/// `cli` is `None` when the flag was not passed and `Some` when the user explicitly
/// provided a value, cleanly expressing "not provided" vs. "provided."
fn resolve_abandoned_threshold_days(cli: Option<u64>, config: Option<u64>) -> u64 {
    cli.or(config).unwrap_or(DEFAULT_ABANDONED_THRESHOLD_DAYS)
}

/// Resolve `exclude_groups`: CLI overrides config entirely (not merged/deduplicated
/// like `exclude_patterns`).
///
/// `--production-only` is resolved in `main.rs` after lockfile I/O; when it is set,
/// `cli` is guaranteed empty by clap's `conflicts_with`, so this resolves to the
/// config value or empty.
fn resolve_exclude_groups(cli: &[String], config: Option<&[String]>) -> Vec<String> {
    if !cli.is_empty() {
        cli.to_vec()
    } else {
        config.map(<[String]>::to_vec).unwrap_or_default()
    }
}

/// Merge CLI arguments with config file values.
///
/// Priority: CLI > config file > defaults.
/// List fields (exclude_patterns, ignore_cves) are merged and deduplicated.
/// Scalar fields use CLI value if present, otherwise config value, otherwise default.
///
/// # Errors
/// Returns an error if `target_python` is set (via CLI or config) but does not parse
/// as a valid PEP 440 version.
pub fn merge_config(args: &Args, config: &Option<ConfigFile>) -> Result<MergedConfig> {
    let cfg = config.as_ref();

    let target_python = resolve_target_python(
        args.target_python.as_ref(),
        cfg.and_then(|c| c.target_python.as_ref()),
    )?;

    // Merge exclude_patterns: combine both sources, deduplicate
    let exclude_patterns =
        merge_string_lists(&args.exclude, &cfg.and_then(|c| c.exclude_packages.clone()));

    // Merge ignore_cves: combine both sources, deduplicate by ID
    let cli_ignore_cves: Vec<IgnoreCve> = args
        .ignore_cve
        .iter()
        .map(|id| IgnoreCve {
            id: id.clone(),
            reason: None,
        })
        .collect();
    let ignore_cves = merge_ignore_cves(&cli_ignore_cves, &cfg.and_then(|c| c.ignore_cves.clone()));

    let format = resolve_format(args.format, cfg.and_then(|c| c.format.as_deref()));
    let check_cve = resolve_check_cve(args.no_check_cve, cfg.and_then(|c| c.check_cve));
    let severity_threshold = resolve_severity_threshold(
        args.severity_threshold,
        cfg.and_then(|c| c.severity_threshold.as_deref()),
    );
    let cvss_threshold =
        resolve_cvss_threshold(args.cvss_threshold, cfg.and_then(|c| c.cvss_threshold));
    let check_license = resolve_flag(args.check_license, cfg.and_then(|c| c.check_license));
    let license_policy = resolve_license_policy(
        check_license,
        &args.license_allow,
        &args.license_deny,
        cfg.and_then(|c| c.license_policy.as_ref()),
    );
    let suggest_fix = resolve_flag(args.suggest_fix, cfg.and_then(|c| c.suggest_fix));
    let check_abandoned = resolve_flag(args.check_abandoned, cfg.and_then(|c| c.check_abandoned));
    let check_non_pypi = resolve_flag(args.check_non_pypi, cfg.and_then(|c| c.check_non_pypi));
    let abandoned_threshold_days = resolve_abandoned_threshold_days(
        args.abandoned_threshold_days,
        cfg.and_then(|c| c.abandoned_threshold_days),
    );
    let exclude_groups = resolve_exclude_groups(
        &args.exclude_groups,
        cfg.and_then(|c| c.exclude_groups.as_deref()),
    );

    Ok(MergedConfig {
        format,
        exclude_patterns,
        check_cve,
        severity_threshold,
        cvss_threshold,
        ignore_cves,
        check_license,
        license_policy,
        suggest_fix,
        check_abandoned,
        abandoned_threshold_days,
        check_non_pypi,
        exclude_groups,
        target_python,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // --- merge_config tests ---

    #[test]
    fn test_merge_config_no_config_file() {
        let args = Args::parse_from(["uv-sbom"]);
        let result = merge_config(&args, &None).unwrap();
        assert_eq!(result.format, OutputFormat::Json);
        assert!(result.exclude_patterns.is_empty());
        assert!(result.check_cve); // CVE check is enabled by default
        assert!(result.severity_threshold.is_none());
        assert!(result.cvss_threshold.is_none());
        assert!(result.ignore_cves.is_empty());
        assert!(!result.check_abandoned);
        assert_eq!(result.abandoned_threshold_days, 730);
    }

    #[test]
    fn test_merge_config_config_provides_defaults() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            format: Some("markdown".to_string()),
            exclude_packages: Some(vec!["pkg-a".to_string()]),
            check_cve: Some(true),
            severity_threshold: Some("high".to_string()),
            cvss_threshold: Some(7.0),
            ignore_cves: Some(vec![IgnoreCve {
                id: "CVE-2024-1".to_string(),
                reason: Some("not applicable".to_string()),
            }]),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.format, OutputFormat::Markdown);
        assert_eq!(result.exclude_patterns, vec!["pkg-a"]);
        assert!(result.check_cve);
        assert_eq!(result.severity_threshold, Some(Severity::High));
        assert_eq!(result.cvss_threshold, Some(7.0));
        assert_eq!(result.ignore_cves.len(), 1);
        assert_eq!(result.ignore_cves[0].id, "CVE-2024-1");
        assert!(!result.check_abandoned);
        assert_eq!(result.abandoned_threshold_days, 730);
    }

    #[test]
    fn test_merge_config_cli_overrides_format() {
        let args = Args::parse_from(["uv-sbom", "--format", "markdown"]);
        let config = Some(ConfigFile {
            format: Some("json".to_string()),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.format, OutputFormat::Markdown);
    }

    #[test]
    fn test_merge_config_no_check_cve_cli_flag() {
        let args = Args::parse_from(["uv-sbom", "--no-check-cve"]);
        let config = Some(ConfigFile {
            check_cve: Some(true),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(!result.check_cve);
    }

    #[test]
    fn test_merge_config_no_check_cve_overrides_config() {
        // CLI opt-out wins over config.check_cve = Some(true)
        let args = Args::parse_from(["uv-sbom", "--no-check-cve"]);
        let config = Some(ConfigFile {
            check_cve: Some(true),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(!result.check_cve);
    }

    #[test]
    fn test_merge_config_check_cve_from_config() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            check_cve: Some(true),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.check_cve);
    }

    #[test]
    fn test_merge_config_exclude_patterns_merged() {
        let args = Args::parse_from(["uv-sbom", "-e", "cli-pkg"]);
        let config = Some(ConfigFile {
            exclude_packages: Some(vec!["config-pkg".to_string(), "cli-pkg".to_string()]),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.exclude_patterns, vec!["cli-pkg", "config-pkg"]);
    }

    #[test]
    fn test_merge_config_ignore_cves_merged() {
        let args = Args::parse_from(["uv-sbom", "-i", "CVE-2024-1"]);
        let config = Some(ConfigFile {
            ignore_cves: Some(vec![
                IgnoreCve {
                    id: "CVE-2024-1".to_string(),
                    reason: Some("config reason".to_string()),
                },
                IgnoreCve {
                    id: "CVE-2024-2".to_string(),
                    reason: None,
                },
            ]),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.ignore_cves.len(), 2);
        // CLI entry takes precedence (no reason)
        assert_eq!(result.ignore_cves[0].id, "CVE-2024-1");
        assert!(result.ignore_cves[0].reason.is_none());
        assert_eq!(result.ignore_cves[1].id, "CVE-2024-2");
    }

    #[test]
    fn test_merge_config_severity_threshold_cli_wins() {
        let args = Args::parse_from(["uv-sbom", "--severity-threshold", "critical"]);
        let config = Some(ConfigFile {
            severity_threshold: Some("low".to_string()),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.severity_threshold, Some(Severity::Critical));
    }

    #[test]
    fn test_merge_config_severity_threshold_from_config() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            severity_threshold: Some("medium".to_string()),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.severity_threshold, Some(Severity::Medium));
    }

    #[test]
    fn test_merge_config_cvss_threshold_cli_wins() {
        let args = Args::parse_from(["uv-sbom", "--cvss-threshold", "8.5"]);
        let config = Some(ConfigFile {
            cvss_threshold: Some(5.0),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.cvss_threshold, Some(8.5));
    }

    #[test]
    fn test_merge_config_cvss_threshold_from_config() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            cvss_threshold: Some(6.0),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.cvss_threshold, Some(6.0));
    }

    // --- format edge case: explicit CLI value vs config (characterization) ---
    // clap always provides a value for `--format` (default "json"), so `merge_config`
    // cannot distinguish "user explicitly passed --format json" from "user passed
    // nothing". The current, intentionally-preserved behavior: config wins whenever
    // `args.format == Json`, even if the user explicitly typed `--format json`.

    #[test]
    fn test_merge_config_format_explicit_json_cli_loses_to_config() {
        let args = Args::parse_from(["uv-sbom", "--format", "json"]);
        let config = Some(ConfigFile {
            format: Some("markdown".to_string()),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.format, OutputFormat::Markdown);
    }

    #[test]
    fn test_merge_config_format_invalid_config_value_falls_back_to_cli() {
        let args = Args::parse_from(["uv-sbom", "--format", "markdown"]);
        let config = Some(ConfigFile {
            format: Some("not-a-format".to_string()),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.format, OutputFormat::Markdown);
    }

    // --- early-return branch (no config file) coverage for fields not yet exercised ---

    #[test]
    fn test_merge_config_no_config_file_severity_threshold_from_cli() {
        let args = Args::parse_from(["uv-sbom", "--severity-threshold", "high"]);
        let result = merge_config(&args, &None).unwrap();
        assert_eq!(result.severity_threshold, Some(Severity::High));
    }

    #[test]
    fn test_merge_config_no_config_file_cvss_threshold_from_cli() {
        let args = Args::parse_from(["uv-sbom", "--cvss-threshold", "9.0"]);
        let result = merge_config(&args, &None).unwrap();
        assert_eq!(result.cvss_threshold, Some(9.0));
    }

    #[test]
    fn test_merge_config_no_config_file_suggest_fix_from_cli() {
        let args = Args::parse_from(["uv-sbom", "--suggest-fix"]);
        let result = merge_config(&args, &None).unwrap();
        assert!(result.suggest_fix);
    }

    // --- license_policy merge tests (check_license / license_policy) ---

    #[test]
    fn test_merge_config_check_license_default_false_no_policy() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile::default());
        let result = merge_config(&args, &config).unwrap();
        assert!(!result.check_license);
        assert!(result.license_policy.is_none());
    }

    #[test]
    fn test_merge_config_check_license_cli_flag_no_lists_empty_policy() {
        // --check-license alone (no allow/deny) → Some(empty policy), Warn handling
        let args = Args::parse_from(["uv-sbom", "--check-license"]);
        let config = Some(ConfigFile::default());
        let result = merge_config(&args, &config).unwrap();
        assert!(result.check_license);
        let policy = result.license_policy.expect("policy should be Some");
        assert!(policy.allow.is_empty());
        assert!(policy.deny.is_empty());
        assert_eq!(policy.unknown, UnknownLicenseHandling::Warn);
    }

    #[test]
    fn test_merge_config_check_license_from_config_true_uses_config_policy() {
        // check_license enabled via config only; config supplies allow/deny/unknown
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            check_license: Some(true),
            license_policy: Some(uv_sbom::config::LicensePolicyConfig {
                allow: Some(vec!["MIT".to_string()]),
                deny: Some(vec!["GPL-3.0".to_string()]),
                unknown: Some("deny".to_string()),
            }),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.check_license);
        let policy = result.license_policy.expect("policy should be Some");
        assert_eq!(policy.allow.len(), 1);
        assert_eq!(policy.allow[0].as_str(), "MIT");
        assert_eq!(policy.deny.len(), 1);
        assert_eq!(policy.deny[0].as_str(), "GPL-3.0");
        assert_eq!(policy.unknown, UnknownLicenseHandling::Deny);
    }

    #[test]
    fn test_merge_config_check_license_config_unknown_allow() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            check_license: Some(true),
            license_policy: Some(uv_sbom::config::LicensePolicyConfig {
                allow: None,
                deny: None,
                unknown: Some("allow".to_string()),
            }),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        let policy = result.license_policy.expect("policy should be Some");
        assert_eq!(policy.unknown, UnknownLicenseHandling::Allow);
    }

    #[test]
    fn test_merge_config_check_license_cli_lists_override_config_policy_entirely() {
        // CLI --license-allow/--license-deny provided → CLI overrides config policy entirely,
        // even though config also has check_license=true and its own policy.
        let args = Args::parse_from([
            "uv-sbom",
            "--check-license",
            "--license-allow",
            "Apache-2.0",
        ]);
        let config = Some(ConfigFile {
            check_license: Some(true),
            license_policy: Some(uv_sbom::config::LicensePolicyConfig {
                allow: Some(vec!["MIT".to_string()]),
                deny: Some(vec!["GPL-3.0".to_string()]),
                unknown: Some("deny".to_string()),
            }),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        let policy = result.license_policy.expect("policy should be Some");
        assert_eq!(policy.allow.len(), 1);
        assert_eq!(policy.allow[0].as_str(), "Apache-2.0");
        assert!(policy.deny.is_empty());
        // CLI-only construction always uses default (Warn) unknown handling
        assert_eq!(policy.unknown, UnknownLicenseHandling::Warn);
    }

    #[test]
    fn test_merge_config_check_license_cli_flag_enables_even_when_config_false() {
        // config.check_license = false, but CLI --check-license wins (OR semantics)
        let args = Args::parse_from(["uv-sbom", "--check-license", "--license-deny", "GPL-3.0"]);
        let config = Some(ConfigFile {
            check_license: Some(false),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.check_license);
        let policy = result.license_policy.expect("policy should be Some");
        assert_eq!(policy.deny.len(), 1);
    }

    #[test]
    fn test_merge_config_no_config_file_check_license_cli_only_policy() {
        // Early-return branch: no config file, CLI supplies check_license + lists
        let args = Args::parse_from(["uv-sbom", "--check-license", "--license-allow", "MIT"]);
        let result = merge_config(&args, &None).unwrap();
        assert!(result.check_license);
        let policy = result.license_policy.expect("policy should be Some");
        assert_eq!(policy.allow.len(), 1);
        assert_eq!(policy.allow[0].as_str(), "MIT");
    }

    #[test]
    fn test_merge_config_no_config_file_check_license_cli_flag_only_empty_policy() {
        // Early-return branch: no config file, --check-license alone → empty policy
        let args = Args::parse_from(["uv-sbom", "--check-license"]);
        let result = merge_config(&args, &None).unwrap();
        assert!(result.check_license);
        let policy = result.license_policy.expect("policy should be Some");
        assert!(policy.allow.is_empty());
        assert!(policy.deny.is_empty());
    }

    #[test]
    fn test_merge_config_no_config_file_check_license_false_no_policy() {
        // Early-return branch: no config file, no --check-license → None
        let args = Args::parse_from(["uv-sbom"]);
        let result = merge_config(&args, &None).unwrap();
        assert!(!result.check_license);
        assert!(result.license_policy.is_none());
    }

    // --- suggest_fix merge tests ---

    #[test]
    fn test_merge_config_suggest_fix_from_config() {
        // suggest_fix: true in config, no CLI flag → merged value is true
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            suggest_fix: Some(true),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.suggest_fix);
    }

    #[test]
    fn test_merge_config_suggest_fix_cli_flag() {
        // suggest_fix: true via CLI flag (CVE enabled by default) → merged value is true
        let args = Args::parse_from(["uv-sbom", "--suggest-fix"]);
        let config = Some(ConfigFile {
            suggest_fix: Some(true),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.suggest_fix);
    }

    #[test]
    fn test_merge_config_suggest_fix_cli_wins_over_config_false() {
        // suggest_fix: false in config, --suggest-fix CLI flag → CLI wins, merged value is true
        let args = Args::parse_from(["uv-sbom", "--suggest-fix"]);
        let config = Some(ConfigFile {
            suggest_fix: Some(false),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.suggest_fix);
    }

    #[test]
    fn test_merge_config_suggest_fix_default_false() {
        // No CLI flag, no config → default false
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(!result.suggest_fix);
    }

    // --- Merge logic tests ---

    #[test]
    fn test_merge_string_lists_both_empty() {
        let result = merge_string_lists(&[], &None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_merge_string_lists_cli_only() {
        let cli = vec!["a".to_string(), "b".to_string()];
        let result = merge_string_lists(&cli, &None);
        assert_eq!(result, vec!["a", "b"]);
    }

    #[test]
    fn test_merge_string_lists_config_only() {
        let config = Some(vec!["x".to_string(), "y".to_string()]);
        let result = merge_string_lists(&[], &config);
        assert_eq!(result, vec!["x", "y"]);
    }

    #[test]
    fn test_merge_string_lists_deduplication() {
        let cli = vec!["a".to_string(), "b".to_string()];
        let config = Some(vec!["b".to_string(), "c".to_string()]);
        let result = merge_string_lists(&cli, &config);
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_merge_ignore_cves_both_empty() {
        let result = merge_ignore_cves(&[], &None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_merge_ignore_cves_cli_only() {
        let cli = vec![IgnoreCve {
            id: "CVE-2024-1".to_string(),
            reason: None,
        }];
        let result = merge_ignore_cves(&cli, &None);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "CVE-2024-1");
    }

    #[test]
    fn test_merge_ignore_cves_config_only() {
        let config = Some(vec![IgnoreCve {
            id: "CVE-2024-2".to_string(),
            reason: Some("reason".to_string()),
        }]);
        let result = merge_ignore_cves(&[], &config);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "CVE-2024-2");
        assert_eq!(result[0].reason.as_deref(), Some("reason"));
    }

    #[test]
    fn test_merge_ignore_cves_deduplication_cli_wins() {
        let cli = vec![IgnoreCve {
            id: "CVE-2024-1".to_string(),
            reason: Some("cli reason".to_string()),
        }];
        let config = Some(vec![
            IgnoreCve {
                id: "CVE-2024-1".to_string(),
                reason: Some("config reason".to_string()),
            },
            IgnoreCve {
                id: "CVE-2024-2".to_string(),
                reason: None,
            },
        ]);
        let result = merge_ignore_cves(&cli, &config);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "CVE-2024-1");
        assert_eq!(result[0].reason.as_deref(), Some("cli reason"));
        assert_eq!(result[1].id, "CVE-2024-2");
    }

    // --- check_abandoned / abandoned_threshold_days merge tests ---

    #[test]
    fn test_merge_config_check_abandoned_default_false() {
        // No CLI flag, no config → defaults: check_abandoned=false, threshold=730
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(!result.check_abandoned);
        assert_eq!(result.abandoned_threshold_days, 730);
    }

    #[test]
    fn test_merge_config_check_abandoned_from_config() {
        // config: true, no CLI flag → check_abandoned=true
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            check_abandoned: Some(true),
            abandoned_threshold_days: Some(365),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.check_abandoned);
        assert_eq!(result.abandoned_threshold_days, 365);
    }

    #[test]
    fn test_merge_config_check_abandoned_cli_flag() {
        // CLI: --check-abandoned, no config → check_abandoned=true, threshold=730 (default)
        let args = Args::parse_from(["uv-sbom", "--check-abandoned"]);
        let config = Some(ConfigFile {
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.check_abandoned);
        assert_eq!(result.abandoned_threshold_days, 730);
    }

    #[test]
    fn test_merge_config_check_abandoned_cli_wins_over_config_false() {
        // CLI flag + config: false → CLI wins, check_abandoned=true
        let args = Args::parse_from(["uv-sbom", "--check-abandoned"]);
        let config = Some(ConfigFile {
            check_abandoned: Some(false),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.check_abandoned);
    }

    #[test]
    fn test_merge_config_abandoned_threshold_from_config() {
        // config: 365, no explicit CLI → uses config value
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            abandoned_threshold_days: Some(365),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.abandoned_threshold_days, 365);
    }

    #[test]
    fn test_merge_config_abandoned_threshold_cli_wins() {
        // CLI: --abandoned-threshold-days 90 + config: 365 → CLI wins (Some(90) overrides config)
        let args = Args::parse_from([
            "uv-sbom",
            "--check-abandoned",
            "--abandoned-threshold-days",
            "90",
        ]);
        let config = Some(ConfigFile {
            check_abandoned: Some(true),
            abandoned_threshold_days: Some(365),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.abandoned_threshold_days, 90);
    }

    #[test]
    fn test_merge_config_abandoned_threshold_default_when_neither() {
        // No CLI, no config → default 730
        let args = Args::parse_from(["uv-sbom"]);
        let result = merge_config(&args, &None).unwrap();
        assert_eq!(result.abandoned_threshold_days, 730);
    }

    #[test]
    fn test_merge_config_no_config_file_uses_cli_abandoned() {
        // No config file; exercises the early-return branch
        let args = Args::parse_from([
            "uv-sbom",
            "--check-abandoned",
            "--abandoned-threshold-days",
            "180",
        ]);
        let result = merge_config(&args, &None).unwrap();
        assert!(result.check_abandoned);
        assert_eq!(result.abandoned_threshold_days, 180);
    }

    // --- exclude_groups merge tests ---

    #[test]
    fn test_merge_config_exclude_groups_default_empty() {
        // No CLI flag, no config → exclude_groups is empty
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.exclude_groups.is_empty());
    }

    #[test]
    fn test_merge_config_exclude_groups_from_cli() {
        // --exclude-groups dev,test → populated from CLI
        let args = Args::parse_from(["uv-sbom", "--exclude-groups", "dev,test"]);
        let config = Some(ConfigFile {
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.exclude_groups, vec!["dev", "test"]);
    }

    #[test]
    fn test_merge_config_exclude_groups_from_config() {
        // No CLI flag, config provides exclude_groups
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            exclude_groups: Some(vec!["dev".to_string(), "lint".to_string()]),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.exclude_groups, vec!["dev", "lint"]);
    }

    #[test]
    fn test_merge_config_exclude_groups_cli_overrides_config() {
        // CLI wins entirely — does NOT merge with config (unlike exclude_patterns)
        let args = Args::parse_from(["uv-sbom", "--exclude-groups", "dev"]);
        let config = Some(ConfigFile {
            exclude_groups: Some(vec!["lint".to_string()]),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.exclude_groups, vec!["dev"]);
        assert!(!result.exclude_groups.contains(&"lint".to_string()));
    }

    #[test]
    fn test_merge_config_no_config_file_exclude_groups() {
        // No config file; exercises the early-return branch with --exclude-groups
        let args = Args::parse_from(["uv-sbom", "--exclude-groups", "dev,test,lint"]);
        let result = merge_config(&args, &None).unwrap();
        assert_eq!(result.exclude_groups, vec!["dev", "test", "lint"]);
    }

    #[test]
    fn test_merge_config_no_config_file_exclude_groups_default_empty() {
        // No CLI, no config file → empty (early-return branch)
        let args = Args::parse_from(["uv-sbom"]);
        let result = merge_config(&args, &None).unwrap();
        assert!(result.exclude_groups.is_empty());
    }

    // --- check_non_pypi merge tests ---

    #[test]
    fn test_merge_config_check_non_pypi_default_false() {
        // No CLI flag, no config → default false
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(!result.check_non_pypi);
    }

    #[test]
    fn test_merge_config_check_non_pypi_from_config_true() {
        // config: true, no CLI flag → check_non_pypi=true
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            check_non_pypi: Some(true),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.check_non_pypi);
    }

    #[test]
    fn test_merge_config_check_non_pypi_cli_flag_true() {
        // CLI: --check-non-pypi, default config → check_non_pypi=true
        let args = Args::parse_from(["uv-sbom", "--check-non-pypi"]);
        let config = Some(ConfigFile {
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.check_non_pypi);
    }

    #[test]
    fn test_merge_config_check_non_pypi_cli_wins_over_config_false() {
        // CLI flag + config: false → CLI wins, check_non_pypi=true
        let args = Args::parse_from(["uv-sbom", "--check-non-pypi"]);
        let config = Some(ConfigFile {
            check_non_pypi: Some(false),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.check_non_pypi);
    }

    #[test]
    fn test_merge_config_no_config_file_check_non_pypi_cli_flag_true() {
        // No config file; exercises the early-return branch with --check-non-pypi
        let args = Args::parse_from(["uv-sbom", "--check-non-pypi"]);
        let result = merge_config(&args, &None).unwrap();
        assert!(result.check_non_pypi);
    }

    // --- target_python resolution/validation tests ---

    #[test]
    fn test_merge_config_target_python_default_none() {
        // No CLI flag, no config → None
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert!(result.target_python.is_none());
    }

    #[test]
    fn test_merge_config_target_python_no_config_file_default_none() {
        // No config file; exercises the early-return branch
        let args = Args::parse_from(["uv-sbom"]);
        let result = merge_config(&args, &None).unwrap();
        assert!(result.target_python.is_none());
    }

    #[test]
    fn test_merge_config_target_python_from_cli() {
        let args = Args::parse_from(["uv-sbom", "--target-python", "3.13"]);
        let config = Some(ConfigFile {
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.target_python.as_deref(), Some("3.13"));
    }

    #[test]
    fn test_merge_config_target_python_no_config_file_from_cli() {
        // No config file; exercises the early-return branch with --target-python
        let args = Args::parse_from(["uv-sbom", "--target-python", "3.13.0"]);
        let result = merge_config(&args, &None).unwrap();
        assert_eq!(result.target_python.as_deref(), Some("3.13.0"));
    }

    #[test]
    fn test_merge_config_target_python_from_config() {
        // No CLI flag, config provides target_python
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            target_python: Some("3.11".to_string()),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.target_python.as_deref(), Some("3.11"));
    }

    #[test]
    fn test_merge_config_target_python_cli_overrides_config() {
        let args = Args::parse_from(["uv-sbom", "--target-python", "3.13"]);
        let config = Some(ConfigFile {
            target_python: Some("3.11".to_string()),
            ..Default::default()
        });
        let result = merge_config(&args, &config).unwrap();
        assert_eq!(result.target_python.as_deref(), Some("3.13"));
    }

    #[test]
    fn test_merge_config_target_python_valid_full_version() {
        let args = Args::parse_from(["uv-sbom", "--target-python", "3.13.0"]);
        let result = merge_config(&args, &None).unwrap();
        assert_eq!(result.target_python.as_deref(), Some("3.13.0"));
    }

    #[test]
    fn test_merge_config_target_python_invalid_cli_value_errors() {
        let args = Args::parse_from(["uv-sbom", "--target-python", "3.x"]);
        let result = merge_config(&args, &None);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.starts_with("Invalid Python version: '3.x': "));
        assert!(err.ends_with("Example: --target-python 3.13"));
    }

    #[test]
    fn test_merge_config_target_python_invalid_config_only_value_errors() {
        // Config-file-only typo (no CLI flag) must be caught by the same code path.
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            target_python: Some("3.x".to_string()),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.starts_with("Invalid Python version: '3.x': "));
        assert!(err.ends_with("Example: --target-python 3.13"));
    }
}
