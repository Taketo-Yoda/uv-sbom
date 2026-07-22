/// Integration tests for the non-PyPI packages Markdown section (`--check-non-pypi`).
use std::path::PathBuf;
use uv_sbom::prelude::*;

fn create_test_license_repository() -> impl LicenseRepository + Clone {
    #[derive(Clone)]
    struct TestLicenseRepository;

    #[async_trait::async_trait]
    impl LicenseRepository for TestLicenseRepository {
        async fn fetch_license_info(
            &self,
            _package_name: &str,
            _version: &str,
        ) -> Result<(
            Option<String>,
            Option<String>,
            Vec<String>,
            Option<String>,
            Option<String>,
        )> {
            Ok((None, None, vec![], None, None))
        }
    }

    TestLicenseRepository
}

#[tokio::test]
async fn test_non_pypi_section_rendered_when_check_non_pypi_enabled() {
    let project_path = PathBuf::from("tests/fixtures/non_pypi_project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new(uv_sbom::i18n::Locale::En);

    let use_case: GenerateSbomUseCase<_, _, _, _, (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder()
        .project_path(project_path)
        .include_dependency_info(true)
        .check_non_pypi(true)
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    assert!(result.is_ok(), "execute failed: {:?}", result.err());
    let response = result.unwrap();

    let applied_group_filter = response.applied_group_filter.clone();
    let read_model = uv_sbom::application::read_models::SbomReadModelBuilder::build_with_project(
        response.enriched_packages,
        &response.metadata,
        response.dependency_graph.as_ref(),
        response.vulnerability_check_result.as_ref(),
        response.license_compliance_result.as_ref(),
        None,
        None,
        None,
        response.non_pypi_packages_report.as_ref(),
        None,
        &applied_group_filter,
    );

    let formatter = MarkdownFormatter::new(uv_sbom::i18n::Locale::En);
    let markdown = formatter.format(&read_model).unwrap();

    assert!(markdown.contains("## ⚠️ Non-PyPI Package Sources"));

    // Private registry, git, and direct-URL packages are non-PyPI external and must appear.
    assert!(markdown.contains("my-internal-lib"));
    assert!(markdown.contains("Private Registry"));
    assert!(markdown.contains("https://internal.company.com/simple"));
    assert!(markdown.contains("dev-tool"));
    assert!(markdown.contains("Git"));
    assert!(markdown.contains("https://github.com/user/repo?rev=abc123"));
    assert!(markdown.contains("remote-archive"));
    assert!(markdown.contains("Direct URL"));
    assert!(markdown.contains("https://example.com/remote-archive-3.0.0-py3-none-any.whl"));

    // PyPI, local-path, and workspace-member packages must NOT appear in the section.
    // (local-lib is intentionally excluded by existing domain logic: PackageSourceKind::LocalPath
    // is not classified as "non-pypi external".)
    assert!(!markdown.contains("| local-lib |"));
    assert!(!markdown.contains("| standard-lib |"));
    assert!(!markdown.contains("| internal-workspace-pkg |"));

    // Direct/transitive breakdown: my-internal-lib is a direct dependency of the root project;
    // dev-tool and remote-archive are transitive (pulled in via standard-lib).
    assert!(markdown.contains(
        "3 packages are sourced from outside the official PyPI registry (1 direct, 2 transitive)."
    ));
}

#[tokio::test]
async fn test_non_pypi_section_absent_when_check_non_pypi_disabled() {
    let project_path = PathBuf::from("tests/fixtures/non_pypi_project");

    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let license_repository = create_test_license_repository();
    let progress_reporter = StderrProgressReporter::new(uv_sbom::i18n::Locale::En);

    let use_case: GenerateSbomUseCase<_, _, _, _, (), ()> = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        None,
        None,
        None,
        uv_sbom::i18n::Locale::En,
    );

    let request = SbomRequest::builder()
        .project_path(project_path)
        .include_dependency_info(true)
        .build()
        .unwrap();
    let result = use_case.execute(request).await;

    assert!(result.is_ok(), "execute failed: {:?}", result.err());
    let response = result.unwrap();

    assert!(response.non_pypi_packages_report.is_none());

    let applied_group_filter = response.applied_group_filter.clone();
    let read_model = uv_sbom::application::read_models::SbomReadModelBuilder::build_with_project(
        response.enriched_packages,
        &response.metadata,
        response.dependency_graph.as_ref(),
        response.vulnerability_check_result.as_ref(),
        response.license_compliance_result.as_ref(),
        None,
        None,
        None,
        response.non_pypi_packages_report.as_ref(),
        None,
        &applied_group_filter,
    );

    let formatter = MarkdownFormatter::new(uv_sbom::i18n::Locale::En);
    let markdown = formatter.format(&read_model).unwrap();

    assert!(!markdown.contains("## ⚠️ Non-PyPI Package Sources"));
    assert!(!markdown.contains("Non-PyPI"));
}
