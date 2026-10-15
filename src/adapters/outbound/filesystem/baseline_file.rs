use crate::ports::outbound::baseline_repository::BaselineRepository;
use crate::sbom_generation::domain::baseline::{BaselineEntry, VulnerabilityBaseline};
use crate::shared::security::{read_file_with_security, validate_not_symlink, MAX_FILE_SIZE};
use crate::shared::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

const SUPPORTED_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct BaselineFileDto {
    version: u32,
    entries: Vec<BaselineEntryDto>,
}

#[derive(Serialize, Deserialize)]
struct BaselineEntryDto {
    package: String,
    version: String,
    id: String,
}

impl From<&BaselineEntry> for BaselineEntryDto {
    fn from(entry: &BaselineEntry) -> Self {
        Self {
            package: entry.package.clone(),
            version: entry.version.clone(),
            id: entry.id.clone(),
        }
    }
}

impl From<BaselineEntryDto> for BaselineEntry {
    fn from(dto: BaselineEntryDto) -> Self {
        Self {
            package: dto.package,
            version: dto.version,
            id: dto.id,
        }
    }
}

/// Filesystem adapter that loads and saves a `VulnerabilityBaseline`
/// as a versioned JSON file.
#[allow(dead_code)] // WIRE(#938): remove when --baseline is wired into GenerateSbomUseCase
pub struct BaselineFileRepository;

impl Default for BaselineFileRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)] // WIRE(#938): remove when --baseline is wired into GenerateSbomUseCase
impl BaselineFileRepository {
    pub fn new() -> Self {
        Self
    }
}

impl BaselineRepository for BaselineFileRepository {
    fn load(&self, path: &Path) -> Result<Option<VulnerabilityBaseline>> {
        if !path.exists() {
            return Ok(None);
        }

        let content = read_file_with_security(path, "vulnerability baseline", MAX_FILE_SIZE)?;

        let dto: BaselineFileDto = serde_json::from_str(&content).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse vulnerability baseline file {}: {}",
                path.display(),
                e
            )
        })?;

        if dto.version != SUPPORTED_VERSION {
            anyhow::bail!(
                "Unsupported vulnerability baseline file version {} in {}; supported version: {}",
                dto.version,
                path.display(),
                SUPPORTED_VERSION
            );
        }

        let entries = dto.entries.into_iter().map(BaselineEntry::from);
        Ok(Some(VulnerabilityBaseline::from_entries(entries)))
    }

    fn save(&self, path: &Path, baseline: &VulnerabilityBaseline) -> Result<()> {
        if path.exists() {
            validate_not_symlink(path, "write")?;
        }

        let dto = BaselineFileDto {
            version: SUPPORTED_VERSION,
            entries: baseline.entries().iter().map(|e| (*e).into()).collect(),
        };

        let json = serde_json::to_string_pretty(&dto).map_err(|e| {
            anyhow::anyhow!(
                "Failed to serialize vulnerability baseline to {}: {}",
                path.display(),
                e
            )
        })?;

        std::fs::write(path, format!("{json}\n")).map_err(|e| {
            anyhow::anyhow!(
                "Failed to write vulnerability baseline file {}: {}",
                path.display(),
                e
            )
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_baseline(entries: Vec<(&str, &str, &str)>) -> VulnerabilityBaseline {
        VulnerabilityBaseline::from_entries(entries.into_iter().map(|(p, v, id)| BaselineEntry {
            package: p.into(),
            version: v.into(),
            id: id.into(),
        }))
    }

    #[test]
    fn test_save_and_load_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baseline.json");

        let baseline = make_baseline(vec![
            ("requests", "2.31.0", "CVE-2024-001"),
            ("flask", "2.3.0", "CVE-2024-002"),
        ]);

        let repo = BaselineFileRepository::new();
        repo.save(&path, &baseline).unwrap();
        let loaded = repo.load(&path).unwrap().unwrap();

        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains("requests", "2.31.0", "CVE-2024-001"));
        assert!(loaded.contains("flask", "2.3.0", "CVE-2024-002"));
    }

    #[test]
    fn test_load_missing_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.json");

        let repo = BaselineFileRepository::new();
        let result = repo.load(&path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_malformed_json_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baseline.json");
        std::fs::write(&path, "not json at all").unwrap();

        let repo = BaselineFileRepository::new();
        let result = repo.load(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to parse"));
    }

    #[test]
    fn test_load_unsupported_version_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baseline.json");
        std::fs::write(&path, r#"{"version": 2, "entries": []}"#).unwrap();

        let repo = BaselineFileRepository::new();
        let result = repo.load(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unsupported vulnerability baseline file version 2"));
        assert!(err.contains("supported version: 1"));
    }

    #[test]
    fn test_deterministic_output() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baseline.json");

        let baseline = make_baseline(vec![
            ("zlib", "1.0.0", "CVE-2024-002"),
            ("aiohttp", "3.9.0", "CVE-2024-001"),
        ]);

        let repo = BaselineFileRepository::new();
        repo.save(&path, &baseline).unwrap();
        let first = std::fs::read_to_string(&path).unwrap();

        repo.save(&path, &baseline).unwrap();
        let second = std::fs::read_to_string(&path).unwrap();

        assert_eq!(first, second);

        let dto: BaselineFileDto = serde_json::from_str(&first).unwrap();
        assert_eq!(dto.entries[0].package, "aiohttp");
        assert_eq!(dto.entries[1].package, "zlib");
    }

    #[cfg(unix)]
    #[test]
    fn test_load_symlink_rejected() {
        let dir = TempDir::new().unwrap();
        let real_path = dir.path().join("real_baseline.json");
        let link_path = dir.path().join("link_baseline.json");

        std::fs::write(&real_path, r#"{"version": 1, "entries": []}"#).unwrap();
        std::os::unix::fs::symlink(&real_path, &link_path).unwrap();

        let repo = BaselineFileRepository::new();
        let result = repo.load(&link_path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("symbolic link"));
    }

    #[cfg(unix)]
    #[test]
    fn test_save_symlink_rejected() {
        let dir = TempDir::new().unwrap();
        let real_path = dir.path().join("real_baseline.json");
        let link_path = dir.path().join("link_baseline.json");

        std::fs::write(&real_path, "").unwrap();
        std::os::unix::fs::symlink(&real_path, &link_path).unwrap();

        let repo = BaselineFileRepository::new();
        let baseline = make_baseline(vec![]);
        let result = repo.save(&link_path, &baseline);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("symbolic link"));
    }
}
