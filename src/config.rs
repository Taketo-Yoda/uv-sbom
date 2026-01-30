//! Configuration file support for uv-sbom.
//!
//! Provides YAML-based configuration through `uv-sbom.config.yml` files,
//! including data structures, file loading, and validation.

use anyhow::{bail, Context};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use crate::shared::Result;

const CONFIG_FILENAME: &str = "uv-sbom.config.yml";

/// Top-level configuration file schema.
#[derive(Debug, Deserialize, Default)]
pub struct ConfigFile {
    pub format: Option<String>,
    pub exclude_packages: Option<Vec<String>>,
    pub check_cve: Option<bool>,
    pub severity_threshold: Option<String>,
    pub cvss_threshold: Option<f64>,
    pub ignore_cves: Option<Vec<IgnoreCve>>,
    /// Captures unknown fields for warnings.
    #[serde(flatten)]
    pub unknown_fields: HashMap<String, serde_yml::Value>,
}

/// A CVE entry to ignore during vulnerability checks.
#[derive(Debug, Deserialize)]
pub struct IgnoreCve {
    pub id: String,
    pub reason: Option<String>,
}

/// Load config from an explicit path. Returns an error if the file is not found.
pub fn load_config_from_path(path: &Path) -> Result<ConfigFile> {
    let content = std::fs::read_to_string(path).with_context(|| {
        format!(
            "Failed to read config file: {}\n\n💡 Hint: Check that the file exists and is readable.",
            path.display()
        )
    })?;

    let config: ConfigFile = serde_yml::from_str(&content).with_context(|| {
        format!(
            "Failed to parse config file: {}\n\n💡 Hint: Ensure the file contains valid YAML syntax.",
            path.display()
        )
    })?;

    validate_config(&config)?;
    warn_unknown_fields(&config);

    Ok(config)
}

/// Auto-discover config in a directory. Returns `None` silently if not found.
pub fn discover_config(dir: &Path) -> Result<Option<ConfigFile>> {
    let config_path = dir.join(CONFIG_FILENAME);

    if !config_path.exists() {
        return Ok(None);
    }

    let config = load_config_from_path(&config_path)?;
    Ok(Some(config))
}

/// Validate the loaded configuration.
fn validate_config(config: &ConfigFile) -> Result<()> {
    if let Some(ref ignore_cves) = config.ignore_cves {
        for (i, entry) in ignore_cves.iter().enumerate() {
            if entry.id.trim().is_empty() {
                bail!(
                    "Invalid config: ignore_cves[{}].id must not be empty.\n\n\
                     💡 Hint: Each ignore_cves entry must have a non-empty 'id' field (e.g., \"CVE-2024-1234\").",
                    i
                );
            }
        }
    }
    Ok(())
}

/// Warn about unknown fields in the config file.
fn warn_unknown_fields(config: &ConfigFile) {
    for key in config.unknown_fields.keys() {
        eprintln!(
            "⚠️  Warning: Unknown config field '{}' will be ignored.",
            key
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_load_valid_config() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.yml");
        fs::write(
            &config_path,
            r#"
format: markdown
exclude_packages:
  - setuptools
  - pip
check_cve: true
severity_threshold: HIGH
cvss_threshold: 7.0
ignore_cves:
  - id: CVE-2024-1234
    reason: "Not applicable to our usage"
  - id: CVE-2024-5678
"#,
        )
        .unwrap();

        let config = load_config_from_path(&config_path).unwrap();
        assert_eq!(config.format.as_deref(), Some("markdown"));
        assert_eq!(
            config.exclude_packages.as_deref(),
            Some(&["setuptools".to_string(), "pip".to_string()][..])
        );
        assert_eq!(config.check_cve, Some(true));
        assert_eq!(config.severity_threshold.as_deref(), Some("HIGH"));
        assert_eq!(config.cvss_threshold, Some(7.0));
        let cves = config.ignore_cves.unwrap();
        assert_eq!(cves.len(), 2);
        assert_eq!(cves[0].id, "CVE-2024-1234");
        assert_eq!(
            cves[0].reason.as_deref(),
            Some("Not applicable to our usage")
        );
        assert_eq!(cves[1].id, "CVE-2024-5678");
        assert!(cves[1].reason.is_none());
    }

    #[test]
    fn test_discover_config_found() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(CONFIG_FILENAME);
        fs::write(
            &config_path,
            r#"
format: json
check_cve: false
"#,
        )
        .unwrap();

        let config = discover_config(dir.path()).unwrap();
        assert!(config.is_some());
        let config = config.unwrap();
        assert_eq!(config.format.as_deref(), Some("json"));
        assert_eq!(config.check_cve, Some(false));
    }

    #[test]
    fn test_discover_config_not_found() {
        let dir = TempDir::new().unwrap();
        let config = discover_config(dir.path()).unwrap();
        assert!(config.is_none());
    }

    #[test]
    fn test_load_config_missing_file() {
        let result = load_config_from_path(Path::new("/nonexistent/config.yml"));
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("Failed to read config file"));
    }

    #[test]
    fn test_load_config_parse_error() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("bad.yml");
        fs::write(&config_path, "invalid: yaml: [[[broken").unwrap();

        let result = load_config_from_path(&config_path);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("Failed to parse config file"));
    }

    #[test]
    fn test_empty_cve_id_validation_error() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.yml");
        fs::write(
            &config_path,
            r#"
ignore_cves:
  - id: ""
    reason: "empty id"
"#,
        )
        .unwrap();

        let result = load_config_from_path(&config_path);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn test_whitespace_only_cve_id_validation_error() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.yml");
        fs::write(
            &config_path,
            r#"
ignore_cves:
  - id: "   "
    reason: "whitespace only"
"#,
        )
        .unwrap();

        let result = load_config_from_path(&config_path);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn test_unknown_fields_warning() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.yml");
        fs::write(
            &config_path,
            r#"
format: json
unknown_field: true
another_unknown: value
"#,
        )
        .unwrap();

        let config = load_config_from_path(&config_path).unwrap();
        assert_eq!(config.unknown_fields.len(), 2);
        assert!(config.unknown_fields.contains_key("unknown_field"));
        assert!(config.unknown_fields.contains_key("another_unknown"));
    }

    #[test]
    fn test_default_config() {
        let config = ConfigFile::default();
        assert!(config.format.is_none());
        assert!(config.exclude_packages.is_none());
        assert!(config.check_cve.is_none());
        assert!(config.severity_threshold.is_none());
        assert!(config.cvss_threshold.is_none());
        assert!(config.ignore_cves.is_none());
        assert!(config.unknown_fields.is_empty());
    }
}
