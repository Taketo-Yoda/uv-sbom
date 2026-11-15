use super::super::GenerateSbomUseCase;
use crate::application::dto::SbomRequest;
use crate::application::read_models::non_pypi_package::{
    NonPyPiPackageView, NonPyPiPackagesReport,
};
use crate::ports::outbound::{
    ExploitabilityRepository, LicenseRepository, LockfileReader, MaintenanceRepository,
    ProgressReporter, ProjectConfigReader, PythonCompatibilityRepository, VulnerabilityRepository,
};
use crate::sbom_generation::domain::{DependencyGraph, Package, UvLockSimulator};
use crate::shared::Result;

impl<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO, USIM, EREPO>
    GenerateSbomUseCase<LR, PCR, LREPO, PR, VREPO, MREPO, PCREPO, USIM, EREPO>
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
{
    /// Detects packages sourced from non-PyPI origins when `check_non_pypi` is enabled.
    ///
    /// When `dependency_graph` is `None` (e.g. non-Markdown output without dep analysis),
    /// `is_direct` defaults to `false` for all packages — consistent with the existing
    /// pattern in `check_abandoned_if_requested`.
    pub(in crate::application::use_cases::generate_sbom) fn check_non_pypi_if_requested(
        &self,
        request: &SbomRequest,
        packages: &[Package],
        dependency_graph: Option<&DependencyGraph>,
    ) -> Result<Option<NonPyPiPackagesReport>> {
        if !request.check_non_pypi {
            return Ok(None);
        }

        let source_map = self
            .lockfile_reader
            .read_and_parse_package_sources(&request.project_path)?;

        let direct_names = Self::resolve_direct_names(dependency_graph);

        let mut views: Vec<NonPyPiPackageView> = packages
            .iter()
            .filter_map(|pkg| {
                let kind = source_map.get(pkg.name())?;
                if !kind.is_non_pypi_external() {
                    return None;
                }
                Some(NonPyPiPackageView {
                    name: pkg.name().to_string(),
                    version: pkg.version().to_string(),
                    source_label: kind.label().to_string(),
                    source_location: kind.value().to_string(),
                    is_direct: direct_names.contains(pkg.name()),
                })
            })
            .collect();
        views.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(Some(NonPyPiPackagesReport { packages: views }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;

    mod tests_non_pypi {
        use super::*;
        use crate::ports::outbound::lockfile_reader::PackageSourceKind;
        use crate::ports::outbound::PackageSourceMap;

        #[test]
        fn test_check_non_pypi_disabled_returns_none() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();
            let packages = [pkg("requests", "2.31.0")];

            let result = use_case
                .check_non_pypi_if_requested(&default_request(), &packages, None)
                .unwrap();

            assert!(result.is_none());
        }

        #[test]
        fn test_check_non_pypi_empty_source_map_returns_empty_report() {
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .build();
            let packages = [pkg("requests", "2.31.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_non_pypi(true)
                .build()
                .unwrap();

            let result = use_case
                .check_non_pypi_if_requested(&request, &packages, None)
                .unwrap();

            let report = result.expect("check enabled → Some");
            assert!(report.is_empty());
        }

        #[test]
        fn test_check_non_pypi_pypi_packages_excluded() {
            let mut source_map = PackageSourceMap::new();
            source_map.insert("requests".to_string(), PackageSourceKind::PyPi);
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("requests", "2.31.0")])
                .with_source_map(source_map)
                .build();
            let packages = [pkg("requests", "2.31.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_non_pypi(true)
                .build()
                .unwrap();

            let result = use_case
                .check_non_pypi_if_requested(&request, &packages, None)
                .unwrap()
                .expect("check enabled → Some");

            assert!(result.is_empty(), "PyPI packages must not appear in report");
        }

        #[test]
        fn test_check_non_pypi_git_package_detected() {
            let mut source_map = PackageSourceMap::new();
            source_map.insert(
                "my-lib".to_string(),
                PackageSourceKind::Git("https://github.com/user/my-lib?rev=abc123".to_string()),
            );
            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("my-lib", "0.1.0")])
                .with_source_map(source_map)
                .build();
            let packages = [pkg("my-lib", "0.1.0")];
            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_non_pypi(true)
                .build()
                .unwrap();

            let result = use_case
                .check_non_pypi_if_requested(&request, &packages, None)
                .unwrap()
                .expect("check enabled → Some");

            assert_eq!(result.total_count(), 1);
            let view = &result.packages[0];
            assert_eq!(view.name, "my-lib");
            assert_eq!(view.source_label, "Git");
            assert_eq!(
                view.source_location,
                "https://github.com/user/my-lib?rev=abc123"
            );
            assert!(!view.is_direct, "no graph → is_direct defaults to false");
        }

        #[test]
        fn test_check_non_pypi_is_direct_from_dependency_graph() {
            use crate::sbom_generation::domain::{DependencyGraph, PackageName};

            let mut source_map = PackageSourceMap::new();
            source_map.insert(
                "internal".to_string(),
                PackageSourceKind::PrivateRegistry(
                    "https://internal.example.com/simple".to_string(),
                ),
            );

            let use_case = UseCaseBuilder::default()
                .with_lockfile(vec![pkg("internal", "1.0.0")])
                .with_source_map(source_map)
                .build();
            let packages = [pkg("internal", "1.0.0")];

            let direct = vec![PackageName::new("internal".to_string()).unwrap()];
            let graph = DependencyGraph::new(direct, Default::default(), Default::default());

            let request = SbomRequest::builder()
                .project_path("/test/project")
                .check_non_pypi(true)
                .build()
                .unwrap();

            let result = use_case
                .check_non_pypi_if_requested(&request, &packages, Some(&graph))
                .unwrap()
                .expect("check enabled → Some");

            assert_eq!(result.direct_count(), 1);
            assert_eq!(result.transitive_count(), 0);
            assert!(result.packages[0].is_direct);
        }
    }
}
