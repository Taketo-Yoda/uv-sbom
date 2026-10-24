use std::path::PathBuf;

/// IncidentRequest - Internal request DTO for `RespondToIncidentUseCase` (#967).
///
/// Carries the advisory to look up and the project scope to evaluate it
/// against. `--production-only` is expanded into `exclude_groups` by the CLI,
/// exactly as it is for `SbomRequest`. Vulnerability-report filters
/// (`--ignore-cve`, baseline, severity/CVSS thresholds) do not apply here.
#[derive(Debug, Clone)]
pub struct IncidentRequest {
    /// Advisory ID as supplied by the user (CVE, GHSA, PYSEC, ...).
    pub advisory_id: String,
    /// Project root holding `uv.lock` and `pyproject.toml`.
    pub project_path: PathBuf,
    /// `--exclude` patterns; matching packages are out of scope.
    pub exclude_patterns: Vec<String>,
    /// `--exclude-groups` names; packages reachable only from these groups are out of scope.
    pub exclude_groups: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_request_clone_preserves_fields() {
        let req = IncidentRequest {
            advisory_id: "CVE-2023-32681".to_string(),
            project_path: PathBuf::from("/project"),
            exclude_patterns: vec!["internal-*".to_string()],
            exclude_groups: vec!["dev".to_string()],
        };

        let cloned = req.clone();

        assert_eq!(cloned.advisory_id, "CVE-2023-32681");
        assert_eq!(cloned.project_path, PathBuf::from("/project"));
        assert_eq!(cloned.exclude_patterns, vec!["internal-*".to_string()]);
        assert_eq!(cloned.exclude_groups, vec!["dev".to_string()]);
    }
}
