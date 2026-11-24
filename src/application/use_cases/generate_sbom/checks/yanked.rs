use super::super::GenerateSbomUseCase;
use crate::application::dto::SbomRequest;
use crate::application::read_models::yanked_package::YankedPackagesReport;
use crate::application::use_cases::CheckYankedPackagesUseCase;
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
    /// Checks for yanked package versions when `check_yanked` is enabled.
    ///
    /// Returns `None` when the check is disabled or no yanked-status repository
    /// is configured. When `dependency_graph` is `None`, `is_direct` defaults to
    /// `false` for all packages — consistent with the existing pattern in
    /// `check_abandoned_if_requested`.
    pub(in crate::application::use_cases::generate_sbom) async fn check_yanked_if_requested(
        &self,
        request: &SbomRequest,
        packages: &[Package],
        dependency_graph: Option<&DependencyGraph>,
    ) -> Result<Option<YankedPackagesReport>> {
        if !request.check_yanked {
            return Ok(None);
        }
        let Some(repo) = &self.yanked_repository else {
            return Ok(None);
        };

        let msgs = Messages::for_locale(self.locale);
        self.progress_reporter.report(msgs.progress_fetching_yanked);

        let source_map = self
            .lockfile_reader
            .read_and_parse_package_sources(&request.project_path)?;
        let direct_names = Self::resolve_direct_names(dependency_graph);

        let yanked_use_case = CheckYankedPackagesUseCase::new(repo.clone());
        let report = yanked_use_case
            .check_with_progress(packages.to_vec(), &source_map, &direct_names)
            .await?;

        eprintln!(); // newline after progress bar

        if report.is_empty() {
            self.progress_reporter
                .report_completion(msgs.progress_yanked_none);
        } else {
            self.progress_reporter.report_error(&Messages::format(
                msgs.progress_yanked_found,
                &[
                    &report.total_count().to_string(),
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

    mod tests_yanked {
        use super::*;

        #[tokio::test]
        async fn test_check_yanked_disabled_returns_none() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();

            let result = use_case
                .check_yanked_if_requested(&default_request(), &[pkg("requests", "2.31.0")], None)
                .await
                .unwrap();

            assert!(result.is_none());
        }

        #[tokio::test]
        async fn test_check_yanked_no_repo_returns_none() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_yanked(true)
                .build()
                .unwrap();

            let result = use_case
                .check_yanked_if_requested(&request, &[pkg("requests", "2.31.0")], None)
                .await
                .unwrap();

            assert!(result.is_none(), "No yanked repository configured → None");
        }
    }
}
