//! Configuration file support for uv-sbom.
//!
//! Provides YAML-based configuration through `uv-sbom.config.yml` files,
//! including data structures, file loading, and validation.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const CONFIG_FILENAME: &str = "uv-sbom.config.yml";

/// Errors produced while generating, loading, or validating a config file.
///
/// Variants carry structured data only; the `#[error(...)]` templates below are
/// the English rendering and the library's `Display` contract (matched
/// byte-for-byte by existing tests). The locale-aware rendering used by the CLI
/// lives in `src/cli/error_display.rs`, not here — this module must stay free
/// of any `i18n` dependency (see `.claude/CLAUDE.md` → "Error Message
/// Localization Policy", decided in #832).
///
/// Defined here rather than as new `SbomError` variants in `src/shared/error.rs`
/// because `src/main.rs` declares its own `mod shared;` while also importing
/// `uv_sbom::config`, making `shared::error::SbomError` (binary copy) and
/// `uv_sbom::shared::error::SbomError` (library copy) distinct types; a
/// downcast-based renderer in the CLI layer would silently fail depending on
/// which copy raised the error. `ConfigError` lives only in the library, with
/// no binary-side shadow type, avoiding that pitfall entirely.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// `generate_config_template` was asked to write `filename` into `dir`, but
    /// a file with that name already exists there.
    #[error("{filename} already exists in {dir}. Use a different directory or remove the existing file.")]
    TemplateAlreadyExists {
        filename: &'static str,
        dir: PathBuf,
    },

    /// `generate_config_template` failed to write the template file to `path`.
    #[error("Failed to write config template to: {path}")]
    TemplateWriteFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// `load_config_from_path` failed to read the config file at `path`.
    #[error("Failed to read config file: {path}\n\n💡 Hint: Check that the file exists and is readable.")]
    ReadFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// `load_config_from_path` read `path` successfully but its contents are
    /// not valid YAML matching [`ConfigFile`]'s schema.
    #[error("Failed to parse config file: {path}\n\n💡 Hint: Ensure the file contains valid YAML syntax.")]
    ParseFailed {
        path: PathBuf,
        #[source]
        source: serde_yaml_ng::Error,
    },

    /// `validate_config` found an `ignore_cves` entry at `index` whose `id`
    /// field is empty or whitespace-only.
    #[error(
        "Invalid config: ignore_cves[{index}].id must not be empty.\n\n\
         💡 Hint: Each ignore_cves entry must have a non-empty 'id' field (e.g., \"CVE-2024-1234\")."
    )]
    EmptyIgnoreCveId { index: usize },

    /// `validate_config` found a `license_policy.unknown` value that is not
    /// one of `warn`, `deny`, or `allow`.
    #[error(
        "Invalid config: license_policy.unknown must be one of: warn, deny, allow. Got: \"{value}\""
    )]
    InvalidUnknownLicenseHandling { value: String },
}

/// Template content for `uv-sbom.config.yml`.
const CONFIG_TEMPLATE: &str = r#"# uv-sbom configuration file
# Documentation: https://github.com/Taketo-Yoda/uv-sbom#configuration

# Output format: json | markdown
# format: json

# Package exclusion patterns (supports wildcards)
# exclude_packages:
#   - "debug-*"
#   - "test-*"

# Disable CVE vulnerability checking (enabled by default; set to false to opt out)
# check_cve: true

# Severity threshold: low | medium | high | critical
# severity_threshold: high

# CVSS score threshold (0.0 - 10.0)
# cvss_threshold: 7.0

# CVEs to ignore during vulnerability checks
# ignore_cves:
#   - id: CVE-2024-1234
#     reason: "False positive: code path not reachable"
#   - id: CVE-2024-5678

# Enable license compliance checking
# check_license: false

# License compliance policy
# license_policy:
#   allow:
#     - "MIT"
#     - "Apache-2.0"
#     - "BSD-*"
#   deny:
#     - "AGPL-*"
#     - "GPL-*"
#   unknown: warn

# Suggest upgrade paths to fix vulnerable transitive dependencies (requires check_cve: true)
# suggest_fix: false

# Enable workspace mode: generate per-member SBOMs for uv workspaces (equivalent to --workspace flag)
# workspace: false

# Enable abandoned/unmaintained package detection
# check_abandoned: false

# Inactivity threshold in days for abandoned-package detection (default: 730)
# abandoned_threshold_days: 730

# Detect packages sourced from non-PyPI origins (git, path, url, private registries)
# check_non_pypi: false

# Enrich CVE results with EPSS scores and CISA KEV status (requires check_cve: true)
# check_exploitability: false

# Dependency groups to exclude from the SBOM (e.g. dev, test, lint)
# exclude_groups:
#   - "dev"
#   - "test"

# Target Python version for compatibility checking (PEP 440 format, e.g. 3.13)
# target_python: "3.13"
"#;

/// Generate a config template file in the specified directory.
///
/// Returns the absolute path of the created file on success.
/// Returns an error if the file already exists.
pub fn generate_config_template(dir: &Path) -> Result<PathBuf, ConfigError> {
    let file_path = dir.join(CONFIG_FILENAME);

    if file_path.exists() {
        let abs_path = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        return Err(ConfigError::TemplateAlreadyExists {
            filename: CONFIG_FILENAME,
            dir: abs_path,
        });
    }

    std::fs::write(&file_path, CONFIG_TEMPLATE).map_err(|source| {
        ConfigError::TemplateWriteFailed {
            path: file_path.clone(),
            source,
        }
    })?;

    let abs_path = file_path
        .canonicalize()
        .unwrap_or_else(|_| file_path.clone());
    Ok(abs_path)
}

/// Top-level configuration file schema.
#[derive(Debug, Deserialize, Default)]
pub struct ConfigFile {
    pub format: Option<String>,
    pub exclude_packages: Option<Vec<String>>,
    pub check_cve: Option<bool>,
    pub severity_threshold: Option<String>,
    pub cvss_threshold: Option<f64>,
    pub ignore_cves: Option<Vec<IgnoreCve>>,
    pub check_license: Option<bool>,
    pub license_policy: Option<LicensePolicyConfig>,
    pub suggest_fix: Option<bool>,
    pub check_abandoned: Option<bool>,
    pub abandoned_threshold_days: Option<u64>,
    pub check_non_pypi: Option<bool>,
    pub check_exploitability: Option<bool>,
    pub exclude_groups: Option<Vec<String>>,
    pub target_python: Option<String>,
    /// Captures unknown fields for warnings.
    #[serde(flatten)]
    pub unknown_fields: HashMap<String, serde_yaml_ng::Value>,
}

/// License policy configuration from config file.
#[derive(Debug, Clone, PartialEq, Deserialize, Default)]
pub struct LicensePolicyConfig {
    pub allow: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
    pub unknown: Option<String>,
}

/// A CVE entry to ignore during vulnerability checks.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct IgnoreCve {
    pub id: String,
    pub reason: Option<String>,
}

impl IgnoreCve {
    /// Returns the reason for ignoring this CVE, if provided
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

/// Load config from an explicit path. Returns an error if the file is not found.
///
/// Unknown fields are captured in [`ConfigFile::unknown_fields`] but are *not*
/// warned about here: this function has no `Locale`, so emitting a localized,
/// user-facing warning is the caller's responsibility (see
/// `cli::config_resolver::loader::load_config`).
pub fn load_config_from_path(path: &Path) -> Result<ConfigFile, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFailed {
        path: path.to_path_buf(),
        source,
    })?;

    let config: ConfigFile =
        serde_yaml_ng::from_str(&content).map_err(|source| ConfigError::ParseFailed {
            path: path.to_path_buf(),
            source,
        })?;

    validate_config(&config)?;

    Ok(config)
}

/// Auto-discover config in a directory. Returns `None` silently if not found.
pub fn discover_config(dir: &Path) -> Result<Option<ConfigFile>, ConfigError> {
    let config_path = dir.join(CONFIG_FILENAME);

    if !config_path.exists() {
        return Ok(None);
    }

    let config = load_config_from_path(&config_path)?;
    Ok(Some(config))
}

/// Validate the loaded configuration.
fn validate_config(config: &ConfigFile) -> Result<(), ConfigError> {
    if let Some(ref ignore_cves) = config.ignore_cves {
        for (i, entry) in ignore_cves.iter().enumerate() {
            if entry.id.trim().is_empty() {
                return Err(ConfigError::EmptyIgnoreCveId { index: i });
            }
        }
    }

    if let Some(ref lp) = config.license_policy {
        if let Some(ref unknown) = lp.unknown {
            let valid = ["warn", "deny", "allow"];
            if !valid.contains(&unknown.to_lowercase().as_str()) {
                return Err(ConfigError::InvalidUnknownLicenseHandling {
                    value: unknown.clone(),
                });
            }
        }
    }

    Ok(())
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
    fn test_unknown_fields_captured() {
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
        assert!(config.check_abandoned.is_none());
        assert!(config.abandoned_threshold_days.is_none());
        assert!(config.check_non_pypi.is_none());
        assert!(config.exclude_groups.is_none());
        assert!(config.target_python.is_none());
        assert!(config.unknown_fields.is_empty());
    }

    #[test]
    fn test_load_config_with_exclude_groups() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.yml");
        fs::write(
            &config_path,
            r#"
exclude_groups:
  - dev
  - test
  - lint
"#,
        )
        .unwrap();

        let config = load_config_from_path(&config_path).unwrap();
        let groups = config.exclude_groups.unwrap();
        assert_eq!(groups, vec!["dev", "test", "lint"]);
    }

    #[test]
    fn test_template_is_valid_yaml_when_uncommented() {
        // Remove comment markers from YAML config lines (skip header comments)
        let uncommented: String = CONFIG_TEMPLATE
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim_start();
                if let Some(content) = trimmed.strip_prefix("# ") {
                    // Skip non-YAML header lines (no colon = not a key-value pair or list item)
                    if content.contains(':')
                        || content.starts_with("  - ")
                        || content.starts_with("- ")
                    {
                        Some(content.to_string())
                    } else {
                        None
                    }
                } else if trimmed == "#" {
                    None
                } else {
                    Some(line.to_string())
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let result: std::result::Result<ConfigFile, _> = serde_yaml_ng::from_str(&uncommented);
        assert!(
            result.is_ok(),
            "Template should be valid YAML when uncommented: {:?}\nContent:\n{}",
            result.err(),
            uncommented
        );
    }

    #[test]
    fn test_generate_config_template_creates_file() {
        let dir = TempDir::new().unwrap();
        let result = generate_config_template(dir.path());
        assert!(result.is_ok());

        let created_path = result.unwrap();
        assert!(created_path.exists());

        let content = fs::read_to_string(&created_path).unwrap();
        assert!(content.contains("uv-sbom configuration file"));
        assert!(content.contains("format: json"));
        assert!(content.contains("exclude_packages:"));
        assert!(content.contains("check_cve:"));
        assert!(content.contains("ignore_cves:"));
    }

    #[test]
    fn test_generate_config_template_fails_if_exists() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(CONFIG_FILENAME);
        fs::write(&config_path, "existing content").unwrap();

        let result = generate_config_template(dir.path());
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("already exists"));
    }
}
