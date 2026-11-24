use super::super::GenerateSbomUseCase;
use crate::application::dto::SbomRequest;
use crate::application::read_models::abandoned_package::{
    AbandonedPackageView, AbandonedPackagesReport,
};
use crate::application::use_cases::CheckAbandonedPackagesUseCase;
use crate::i18n::Messages;
use crate::ports::outbound::{
    ExploitabilityRepository, LicenseRepository, LockfileReader, MaintenanceRepository,
    ProgressReporter, ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
    YankedStatusRepository,
};
use crate::sbom_generation::domain::{DependencyGraph, Package, UvLockSimulator};
use crate::shared::Result;
use chrono::Utc;
use std::cmp::Reverse;

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
    /// Checks for abandoned packages if `check_abandoned` is enabled.
    ///
    /// Returns `None` when the check is disabled or no maintenance repository is configured.
    /// When `dependency_graph` is `None` (e.g. JSON output without dep analysis),
    /// `is_direct` defaults to `false` for all packages — consistent with the existing
    /// pattern for the resolution guide.
    pub(in crate::application::use_cases::generate_sbom) async fn check_abandoned_if_requested(
        &self,
        request: &SbomRequest,
        packages: &[Package],
        dependency_graph: Option<&DependencyGraph>,
    ) -> Result<Option<AbandonedPackagesReport>> {
        if !request.check_abandoned {
            return Ok(None);
        }
        let Some(repo) = &self.maintenance_repository else {
            return Ok(None);
        };

        let msgs = Messages::for_locale(self.locale);
        self.progress_reporter
            .report(msgs.progress_fetching_abandoned);

        let maint_use_case = CheckAbandonedPackagesUseCase::new(repo.clone());
        let (results, errors) = maint_use_case
            .fetch_with_progress(packages.to_vec())
            .await?;

        eprintln!(); // newline after progress bar

        for (pkg_name, error_msg) in &errors {
            self.progress_reporter.report_error(&Messages::format(
                msgs.warn_abandoned_fetch_failed,
                &[pkg_name, error_msg],
            ));
        }

        let today = Utc::now().date_naive();
        let direct_names = Self::resolve_direct_names(dependency_graph);

        let threshold = request.abandoned_threshold_days as i64;
        let mut abandoned_packages: Vec<AbandonedPackageView> = results
            .into_iter()
            .filter_map(|(pkg, info)| {
                // Packages with no recorded release date are excluded: their
                // maintenance status cannot be determined, so we do not classify
                // them as abandoned.
                let release_date = info.last_release_date?;
                let days_inactive = (today - release_date).num_days();
                if days_inactive < threshold {
                    return None;
                }
                Some(AbandonedPackageView {
                    name: pkg.name().to_string(),
                    version: pkg.version().to_string(),
                    last_release_date: release_date,
                    days_inactive,
                    is_direct: direct_names.contains(pkg.name()),
                })
            })
            .collect();

        abandoned_packages.sort_by_key(|p| Reverse(p.days_inactive));

        let report = AbandonedPackagesReport {
            packages: abandoned_packages,
            threshold_days: request.abandoned_threshold_days,
        };

        if report.is_empty() {
            self.progress_reporter.report(&Messages::format(
                msgs.progress_abandoned_none,
                &[&report.threshold_days.to_string()],
            ));
        } else {
            self.progress_reporter.report(&Messages::format(
                msgs.progress_abandoned_found,
                &[
                    &report.total_count().to_string(),
                    &report.direct_count().to_string(),
                    &report.transitive_count().to_string(),
                    &report.threshold_days.to_string(),
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

    mod tests_abandoned {
        use super::*;
        use crate::application::use_cases::test_doubles::MockMaintenanceRepository;
        use crate::ports::outbound::MaintenanceInfo;
        use chrono::NaiveDate;

        #[tokio::test]
        async fn test_check_abandoned_disabled_returns_none() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();
            let packages = [pkg("requests", "2.31.0")];

            let result = use_case
                .check_abandoned_if_requested(&default_request(), &packages, None)
                .await
                .unwrap();

            assert!(result.is_none());
        }

        #[tokio::test]
        async fn test_check_abandoned_no_repo_returns_none() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();
            let packages = [pkg("requests", "2.31.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_abandoned(true)
                .build()
                .unwrap();

            let result = use_case
                .check_abandoned_if_requested(&request, &packages, None)
                .await
                .unwrap();

            assert!(result.is_none());
        }

        #[tokio::test]
        async fn test_check_abandoned_with_old_package_returns_report() {
            let old_date = NaiveDate::from_ymd_opt(2020, 1, 1).unwrap();
            let maint_repo = MockMaintenanceRepository::with_responses([Ok(MaintenanceInfo {
                last_release_date: Some(old_date),
            })]);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .with_maintenance_repo(maint_repo)
                .build();
            let packages = [pkg("requests", "2.31.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_abandoned(true)
                .abandoned_threshold_days(365)
                .build()
                .unwrap();

            let result = use_case
                .check_abandoned_if_requested(&request, &packages, None)
                .await
                .unwrap();

            assert!(result.is_some());
            let report = result.unwrap();
            assert_eq!(report.total_count(), 1);
            assert_eq!(report.packages[0].name, "requests");
            assert!(report.packages[0].days_inactive >= 365);
            assert_eq!(report.threshold_days, 365);
            assert_eq!(report.direct_count(), 0); // no graph supplied → all non-direct
            assert_eq!(report.transitive_count(), 1);
        }

        #[tokio::test]
        async fn test_check_abandoned_recent_package_produces_empty_report() {
            use chrono::Utc;
            let recent_date = Utc::now().date_naive();
            let maint_repo = MockMaintenanceRepository::with_responses([Ok(MaintenanceInfo {
                last_release_date: Some(recent_date),
            })]);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .with_maintenance_repo(maint_repo)
                .build();
            let packages = [pkg("requests", "2.31.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_abandoned(true)
                .abandoned_threshold_days(365)
                .build()
                .unwrap();

            let result = use_case
                .check_abandoned_if_requested(&request, &packages, None)
                .await
                .unwrap();

            assert!(result.is_some());
            assert!(result.unwrap().is_empty());
        }

        #[tokio::test]
        async fn test_check_abandoned_unknown_release_date_excluded() {
            let maint_repo = MockMaintenanceRepository::with_responses([Ok(MaintenanceInfo {
                last_release_date: None,
            })]);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("old-pkg", "1.0.0")])
                .with_maintenance_repo(maint_repo)
                .build();
            let packages = [pkg("old-pkg", "1.0.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_abandoned(true)
                .abandoned_threshold_days(1)
                .build()
                .unwrap();

            let result = use_case
                .check_abandoned_if_requested(&request, &packages, None)
                .await
                .unwrap();

            // Package with unknown release date is excluded from the report
            assert!(result.is_some());
            assert!(result.unwrap().is_empty());
        }

        #[tokio::test]
        async fn test_check_abandoned_sorted_by_days_inactive_descending() {
            let older_date = NaiveDate::from_ymd_opt(2018, 1, 1).unwrap();
            let newer_date = NaiveDate::from_ymd_opt(2021, 1, 1).unwrap();
            let maint_repo = MockMaintenanceRepository::with_responses([
                Ok(MaintenanceInfo {
                    last_release_date: Some(newer_date),
                }),
                Ok(MaintenanceInfo {
                    last_release_date: Some(older_date),
                }),
            ]);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("newer-pkg", "1.0.0"), pkg("older-pkg", "1.0.0")])
                .with_maintenance_repo(maint_repo)
                .build();
            let packages = [pkg("newer-pkg", "1.0.0"), pkg("older-pkg", "1.0.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_abandoned(true)
                .abandoned_threshold_days(365)
                .build()
                .unwrap();

            let result = use_case
                .check_abandoned_if_requested(&request, &packages, None)
                .await
                .unwrap();

            assert!(result.is_some());
            let report = result.unwrap();
            assert_eq!(report.total_count(), 2);
            // Sorted descending: older-pkg (more days inactive) should be first
            assert!(report.packages[0].days_inactive >= report.packages[1].days_inactive);
        }
    }
}
