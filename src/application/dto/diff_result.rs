use crate::application::read_models::cve_delta_view::CveDeltaView;
use crate::sbom_generation::domain::dependency_diff::DependencyDiff;

/// Application-layer result of running the diff use case.
///
/// Bundles the pure domain `DependencyDiff` with the optional application
/// read model `CveDeltaView`, keeping the domain layer free of read-model
/// dependencies.
#[derive(Debug, Clone)]
pub struct DiffResult {
    pub diff: DependencyDiff,
    pub cve_delta: Option<CveDeltaView>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbom_generation::domain::dependency_diff::{DependencyDiff, DiffSummary};

    #[test]
    fn test_diff_result_cve_delta_defaults_to_none() {
        let diff = DependencyDiff {
            base_ref: "main".to_string(),
            changes: vec![],
            summary: DiffSummary::default(),
        };
        let result = DiffResult {
            diff,
            cve_delta: None,
        };
        assert!(result.cve_delta.is_none());
    }
}
