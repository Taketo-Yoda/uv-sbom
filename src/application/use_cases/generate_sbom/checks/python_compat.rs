use super::super::GenerateSbomUseCase;
use crate::application::dto::SbomRequest;
use crate::application::read_models::python_compatibility::PythonCompatibilityReport;
use crate::application::use_cases::CheckPythonCompatibilityUseCase;
use crate::i18n::Messages;
use crate::ports::outbound::{
    ExploitabilityRepository, LicenseRepository, LockfileReader, MaintenanceRepository,
    ProgressReporter, ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
    YankedStatusRepository,
};
use crate::sbom_generation::domain::{DependencyGraph, Package, UvLockSimulator};
use crate::shared::Result;

impl<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO, USIM, EREPO, YREPO>
    GenerateSbomUseCase<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO, USIM, EREPO, YREPO>
where
    LR: LockfileReader,
    PCR: ProjectConfigReader,
    LREPO: LicenseRepository + Clone,
    PR: ProgressReporter,
    VREPO: VulnerabilityRepository + Clone,
    MREPO: MaintenanceRepository + Clone,
    PCREPO: PythonCompatibilityRepository + Clone,
    USIM: UvLockSimulator,
    EREPO: ExploitabilityRepository,
    YREPO: YankedStatusRepository + Clone,
{
    /// Checks package compatibility against `target_python` if requested.
    ///
    /// Returns `None` when `target_python` is unset or no compatibility
    /// repository is configured. When `dependency_graph` is `None`, `is_direct`
    /// defaults to `false` for all packages — consistent with the existing
    /// pattern in `check_abandoned_if_requested`.
    pub(in crate::application::use_cases::generate_sbom) async fn check_python_compatibility_if_requested(
        &self,
        request: &SbomRequest,
        packages: &[Package],
        dependency_graph: Option<&DependencyGraph>,
    ) -> Result<Option<PythonCompatibilityReport>> {
        let Some(target) = &request.target_python else {
            return Ok(None);
        };
        let Some(repo) = &self.compatibility_repository else {
            return Ok(None);
        };

        let msgs = Messages::for_locale(self.locale);
        self.progress_reporter
            .report(msgs.progress_fetching_python_compat);

        let direct_names = Self::resolve_direct_names(dependency_graph);
        let compat_use_case = CheckPythonCompatibilityUseCase::new(repo.clone());
        let report = compat_use_case
            .check_with_progress(packages.to_vec(), target, &direct_names)
            .await?;

        eprintln!(); // newline after progress bar

        if report.is_empty() {
            self.progress_reporter.report(&Messages::format(
                msgs.progress_python_compat_none,
                &[&report.target_python],
            ));
        } else {
            self.progress_reporter.report(&Messages::format(
                msgs.progress_python_compat_found,
                &[
                    &report.total_count().to_string(),
                    &report.target_python,
                    &report.direct_count().to_string(),
                    &report.transitive_count().to_string(),
                ],
            ));
        }

        Ok(Some(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;

    mod tests_python_compatibility {
        use super::*;
        use crate::application::use_cases::test_doubles::MockPythonCompatibilityRepository;
        use crate::ports::outbound::PythonCompatibilityInfo;

        #[tokio::test]
        async fn test_python_compat_target_unset_returns_none() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();
            let packages = [pkg("requests", "2.31.0")];

            let result = use_case
                .check_python_compatibility_if_requested(&default_request(), &packages, None)
                .await
                .unwrap();

            assert!(result.is_none());
        }

        #[tokio::test]
        async fn test_python_compat_no_repo_returns_none() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();
            let packages = [pkg("requests", "2.31.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .target_python(Some("3.13".to_string()))
                .build()
                .unwrap();

            let result = use_case
                .check_python_compatibility_if_requested(&request, &packages, None)
                .await
                .unwrap();

            assert!(result.is_none());
        }

        #[tokio::test]
        async fn test_python_compat_with_incompatible_package_returns_report() {
            let pyc_repo = MockPythonCompatibilityRepository::with_responses([(
                "legacy-lib".to_string(),
                Ok(PythonCompatibilityInfo {
                    requires_python: Some(">=3.8,<3.12".to_string()),
                }),
            )]);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("legacy-lib", "1.0.0")])
                .with_python_compat_repo(pyc_repo)
                .build();
            let packages = [pkg("legacy-lib", "1.0.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .target_python(Some("3.13".to_string()))
                .build()
                .unwrap();

            let result = use_case
                .check_python_compatibility_if_requested(&request, &packages, None)
                .await
                .unwrap();

            assert!(result.is_some());
            let report = result.unwrap();
            assert_eq!(report.total_count(), 1);
            assert_eq!(report.incompatible[0].name, "legacy-lib");
            assert_eq!(report.target_python, "3.13");
        }

        #[tokio::test]
        async fn test_python_compat_all_compatible_produces_empty_report() {
            let pyc_repo = MockPythonCompatibilityRepository::with_responses([(
                "requests".to_string(),
                Ok(PythonCompatibilityInfo {
                    requires_python: Some(">=3.7".to_string()),
                }),
            )]);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .with_python_compat_repo(pyc_repo)
                .build();
            let packages = [pkg("requests", "2.31.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .target_python(Some("3.13".to_string()))
                .build()
                .unwrap();

            let result = use_case
                .check_python_compatibility_if_requested(&request, &packages, None)
                .await
                .unwrap();

            assert!(result.is_some());
            assert!(result.unwrap().is_empty());
        }

        /// End-to-end integration test: exercises the `target_python` path through
        /// `execute()`, verifying `SbomResponse.python_compatibility_report` is
        /// populated from a mock `PythonCompatibilityRepository`.
        #[tokio::test]
        async fn test_execute_with_target_python_populates_response_report() {
            let pyc_repo = MockPythonCompatibilityRepository::with_responses([(
                "legacy-lib".to_string(),
                Ok(PythonCompatibilityInfo {
                    requires_python: Some(">=3.8,<3.12".to_string()),
                }),
            )]);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("legacy-lib", "1.0.0")])
                .with_python_compat_repo(pyc_repo)
                .build();

            let request = SbomRequest::builder()
                .project_path("/test/project")
                .target_python(Some("3.13".to_string()))
                .build()
                .unwrap();

            let response = use_case.execute(request).await.unwrap();

            assert!(response.python_compatibility_report.is_some());
            let report = response.python_compatibility_report.unwrap();
            assert_eq!(report.total_count(), 1);
            assert_eq!(report.incompatible[0].name, "legacy-lib");
        }

        #[tokio::test]
        async fn test_execute_without_target_python_leaves_report_none() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();

            let response = use_case.execute(default_request()).await.unwrap();

            assert!(response.python_compatibility_report.is_none());
        }
    }
}
