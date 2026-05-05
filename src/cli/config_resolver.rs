use crate::application::dto::OutputFormat;
use crate::sbom_generation::domain::license_policy::{LicensePolicy, UnknownLicenseHandling};
use crate::sbom_generation::domain::vulnerability::Severity;
use crate::shared::Result;
use std::collections::HashSet;
use uv_sbom::config::{self, ConfigFile, IgnoreCve};

use super::Args;

/// Merged configuration after combining CLI arguments and config file values.
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

/// Merge CLI arguments with config file values.
///
/// Priority: CLI > config file > defaults.
/// List fields (exclude_patterns, ignore_cves) are merged and deduplicated.
/// Scalar fields use CLI value if present, otherwise config value, otherwise default.
pub fn merge_config(args: &Args, config: &Option<ConfigFile>) -> MergedConfig {
    let config = match config {
        Some(c) => c,
        None => {
            // No config file — use CLI values directly
            let license_policy = if args.check_license
                && (!args.license_allow.is_empty() || !args.license_deny.is_empty())
            {
                Some(LicensePolicy::new(
                    &args.license_allow,
                    &args.license_deny,
                    UnknownLicenseHandling::default(),
                ))
            } else if args.check_license {
                Some(LicensePolicy::new(
                    &[],
                    &[],
                    UnknownLicenseHandling::default(),
                ))
            } else {
                None
            };

            return MergedConfig {
                format: args.format,
                exclude_patterns: args.exclude.clone(),
                check_cve: !args.no_check_cve,
                severity_threshold: args.severity_threshold,
                cvss_threshold: args.cvss_threshold,
                ignore_cves: args
                    .ignore_cve
                    .iter()
                    .map(|id| IgnoreCve {
                        id: id.clone(),
                        reason: None,
                    })
                    .collect(),
                check_license: args.check_license,
                license_policy,
                suggest_fix: args.suggest_fix,
                check_abandoned: args.check_abandoned,
                abandoned_threshold_days: args.abandoned_threshold_days.unwrap_or(730),
            };
        }
    };

    // Merge exclude_patterns: combine both sources, deduplicate
    let exclude_patterns = merge_string_lists(&args.exclude, &config.exclude_packages);

    // Merge ignore_cves: combine both sources, deduplicate by ID
    let cli_ignore_cves: Vec<IgnoreCve> = args
        .ignore_cve
        .iter()
        .map(|id| IgnoreCve {
            id: id.clone(),
            reason: None,
        })
        .collect();
    let ignore_cves = merge_ignore_cves(&cli_ignore_cves, &config.ignore_cves);

    // Format: CLI > config > default (json)
    // Note: clap always provides a default value for format, so we check if user explicitly
    // provided it by comparing against the default. However, since clap's default_value means
    // args.format is always set, we use config only when format is json (default) and config
    // provides a different value.
    let format = if let Some(ref config_format) = config.format {
        // If user didn't explicitly pass --format, use config value
        // clap default is "json", so if args.format == Json, config might override
        // But we can't distinguish "user passed --format json" from "default json"
        // Convention: CLI always wins since clap provides the value
        if args.format != OutputFormat::Json {
            args.format
        } else {
            config_format.parse::<OutputFormat>().unwrap_or(args.format)
        }
    } else {
        args.format
    };

    // check_cve: CLI opt-out takes highest priority; otherwise use config value (default true)
    let check_cve = if args.no_check_cve {
        false
    } else {
        config.check_cve.unwrap_or(true)
    };

    // severity_threshold: CLI > config > None
    let severity_threshold = args.severity_threshold.or_else(|| {
        config
            .severity_threshold
            .as_ref()
            .and_then(|s| match s.to_lowercase().as_str() {
                "low" => Some(Severity::Low),
                "medium" => Some(Severity::Medium),
                "high" => Some(Severity::High),
                "critical" => Some(Severity::Critical),
                _ => None,
            })
    });

    // cvss_threshold: CLI > config > None
    let cvss_threshold = args
        .cvss_threshold
        .or(config.cvss_threshold.map(|v| v as f32));

    // check_license: CLI flag || config value
    let check_license = args.check_license || config.check_license.unwrap_or(false);

    // license_policy: CLI args override config entirely if any CLI args provided
    let license_policy = if check_license {
        if !args.license_allow.is_empty() || !args.license_deny.is_empty() {
            // CLI provides policy — override config entirely
            Some(LicensePolicy::new(
                &args.license_allow,
                &args.license_deny,
                UnknownLicenseHandling::default(),
            ))
        } else if let Some(ref lp_config) = config.license_policy {
            // Use config policy
            let unknown = lp_config
                .unknown
                .as_ref()
                .map(|s| match s.to_lowercase().as_str() {
                    "deny" => UnknownLicenseHandling::Deny,
                    "allow" => UnknownLicenseHandling::Allow,
                    _ => UnknownLicenseHandling::Warn,
                })
                .unwrap_or_default();
            let allow = lp_config.allow.clone().unwrap_or_default();
            let deny = lp_config.deny.clone().unwrap_or_default();
            Some(LicensePolicy::new(&allow, &deny, unknown))
        } else {
            // check_license enabled but no policy specified
            Some(LicensePolicy::new(
                &[],
                &[],
                UnknownLicenseHandling::default(),
            ))
        }
    } else {
        None
    };

    // suggest_fix: CLI flag takes priority over config value
    let suggest_fix = args.suggest_fix || config.suggest_fix.unwrap_or(false);

    // check_abandoned: CLI flag || config value (mirrors check_license / suggest_fix)
    let check_abandoned = args.check_abandoned || config.check_abandoned.unwrap_or(false);

    // abandoned_threshold_days: CLI > config > default 730.
    // args.abandoned_threshold_days is Option<u64>: None when the flag was not passed, Some when
    // the user explicitly provided a value. This cleanly expresses "not provided" vs "provided."
    let abandoned_threshold_days = args
        .abandoned_threshold_days
        .or(config.abandoned_threshold_days)
        .unwrap_or(730);

    MergedConfig {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // --- merge_config tests ---

    #[test]
    fn test_merge_config_no_config_file() {
        let args = Args::parse_from(["uv-sbom"]);
        let result = merge_config(&args, &None);
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
        let result = merge_config(&args, &config);
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
        let result = merge_config(&args, &config);
        assert_eq!(result.format, OutputFormat::Markdown);
    }

    #[test]
    fn test_merge_config_no_check_cve_cli_flag() {
        let args = Args::parse_from(["uv-sbom", "--no-check-cve"]);
        let config = Some(ConfigFile {
            check_cve: Some(true),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
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
        let result = merge_config(&args, &config);
        assert!(!result.check_cve);
    }

    #[test]
    fn test_merge_config_check_cve_from_config() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            check_cve: Some(true),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert!(result.check_cve);
    }

    #[test]
    fn test_merge_config_exclude_patterns_merged() {
        let args = Args::parse_from(["uv-sbom", "-e", "cli-pkg"]);
        let config = Some(ConfigFile {
            exclude_packages: Some(vec!["config-pkg".to_string(), "cli-pkg".to_string()]),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
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
        let result = merge_config(&args, &config);
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
        let result = merge_config(&args, &config);
        assert_eq!(result.severity_threshold, Some(Severity::Critical));
    }

    #[test]
    fn test_merge_config_severity_threshold_from_config() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            severity_threshold: Some("medium".to_string()),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert_eq!(result.severity_threshold, Some(Severity::Medium));
    }

    #[test]
    fn test_merge_config_cvss_threshold_cli_wins() {
        let args = Args::parse_from(["uv-sbom", "--cvss-threshold", "8.5"]);
        let config = Some(ConfigFile {
            cvss_threshold: Some(5.0),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert_eq!(result.cvss_threshold, Some(8.5));
    }

    #[test]
    fn test_merge_config_cvss_threshold_from_config() {
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            cvss_threshold: Some(6.0),
            ..Default::default()
        });
        let result = merge_config(&args, &config);
        assert_eq!(result.cvss_threshold, Some(6.0));
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
        let result = merge_config(&args, &config);
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
        let result = merge_config(&args, &config);
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
        let result = merge_config(&args, &config);
        assert!(result.suggest_fix);
    }

    #[test]
    fn test_merge_config_suggest_fix_default_false() {
        // No CLI flag, no config → default false
        let args = Args::parse_from(["uv-sbom"]);
        let config = Some(ConfigFile {
            ..Default::default()
        });
        let result = merge_config(&args, &config);
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
        let result = merge_config(&args, &config);
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
        let result = merge_config(&args, &config);
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
        let result = merge_config(&args, &config);
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
        let result = merge_config(&args, &config);
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
        let result = merge_config(&args, &config);
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
        let result = merge_config(&args, &config);
        assert_eq!(result.abandoned_threshold_days, 90);
    }

    #[test]
    fn test_merge_config_abandoned_threshold_default_when_neither() {
        // No CLI, no config → default 730
        let args = Args::parse_from(["uv-sbom"]);
        let result = merge_config(&args, &None);
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
        let result = merge_config(&args, &None);
        assert!(result.check_abandoned);
        assert_eq!(result.abandoned_threshold_days, 180);
    }
}
