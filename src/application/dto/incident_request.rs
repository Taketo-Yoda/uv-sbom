use crate::sbom_generation::domain::incident_target::IncidentTarget;
use std::path::PathBuf;

/// IncidentRequest - Internal request DTO for `RespondToIncidentUseCase` (#967).
///
/// Carries the incident to evaluate (an advisory ID, or a manual range spec,
/// #963) and the project scope to evaluate it
/// against. `--production-only` is expanded into `exclude_groups` by the CLI,
/// exactly as it is for `SbomRequest`. Vulnerability-report filters
/// (`--ignore-cve`, baseline, severity/CVSS thresholds) do not apply here.
#[derive(Debug, Clone)]
pub struct IncidentRequest {
    /// The advisory ID or manual range spec to evaluate.
    pub target: IncidentTarget,
    /// Project root holding `uv.lock` and `pyproject.toml`.
    pub project_path: PathBuf,
    /// `--exclude` patterns; matching packages are out of scope.
    pub exclude_patterns: Vec<String>,
    /// `--exclude-groups` names; packages reachable only from these groups are out of scope.
    pub exclude_groups: Vec<String>,
}

/// WorkspaceIncidentRequest - Internal request DTO for
/// `RespondToIncidentUseCase::execute_workspace` (#969).
///
/// A uv workspace has one `uv.lock`, so the advisory is evaluated once per
/// member against that shared lockfile. The CLI reads the member list from the
/// lockfile and expands `--production-only` into `exclude_groups`, as it does
/// for `IncidentRequest`.
#[derive(Debug, Clone)]
pub struct WorkspaceIncidentRequest {
    /// The advisory ID or manual range spec to evaluate.
    pub target: IncidentTarget,
    /// Workspace root holding the shared `uv.lock`; also the directory the
    /// upgrade dry-run is resolved in.
    pub workspace_root: PathBuf,
    /// Workspace member names, in the order the report lists them.
    pub member_names: Vec<String>,
    /// `--exclude` patterns; matching packages are out of scope in every member.
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
            target: IncidentTarget::AdvisoryId("CVE-2023-32681".to_string()),
            project_path: PathBuf::from("/project"),
            exclude_patterns: vec!["internal-*".to_string()],
            exclude_groups: vec!["dev".to_string()],
        };

        let cloned = req.clone();

        assert_eq!(
            cloned.target,
            IncidentTarget::AdvisoryId("CVE-2023-32681".to_string())
        );
        assert_eq!(cloned.project_path, PathBuf::from("/project"));
        assert_eq!(cloned.exclude_patterns, vec!["internal-*".to_string()]);
        assert_eq!(cloned.exclude_groups, vec!["dev".to_string()]);
    }
}
