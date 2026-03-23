use crate::application::dto::OutputFormat;
use crate::sbom_generation::domain::license_policy::LicensePolicy;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
