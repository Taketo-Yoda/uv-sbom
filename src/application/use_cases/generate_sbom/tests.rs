use super::*;
use crate::application::use_cases::test_doubles::MockPythonCompatibilityRepository;

mod tests_python_compat_markdown {
    use super::*;
    use crate::adapters::outbound::formatters::MarkdownFormatter;
    use crate::application::read_models::SbomReadModelBuilder;
    use crate::application::use_cases::generate_sbom::tests::test_helpers::*;
    use crate::i18n::Locale;
    use crate::ports::outbound::{PythonCompatibilityInfo, SbomFormatter};

    fn format_markdown(response: &crate::application::dto::SbomResponse) -> String {
        let read_model = SbomReadModelBuilder::build_with_project(
            response.enriched_packages.clone(),
            &response.metadata,
            response.dependency_graph.as_ref(),
            response.vulnerability_check_result.as_ref(),
            response.license_compliance_result.as_ref(),
            None,
            response.upgrade_recommendations.as_deref(),
            response.abandoned_packages_report.as_ref(),
            response.non_pypi_packages_report.as_ref(),
            response.python_compatibility_report.as_ref(),
            &response.applied_group_filter,
        );
        MarkdownFormatter::new(Locale::En)
            .format(&read_model)
            .unwrap()
    }

    #[tokio::test]
    async fn test_markdown_renders_python_compat_issues_table() {
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
        let markdown = format_markdown(&response);

        assert!(markdown.contains("## ⚠️ Python 3.13 Compatibility Issues"));
        assert!(markdown.contains("| Package | Version | Requires-Python | Type |"));
        assert!(markdown.contains("| legacy-lib | 1.0.0 | >=3.8,<3.12 |"));
    }

    #[tokio::test]
    async fn test_markdown_renders_python_compat_all_clear() {
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
        let request = SbomRequest::builder()
            .project_path("/test/project")
            .target_python(Some("3.13".to_string()))
            .build()
            .unwrap();

        let response = use_case.execute(request).await.unwrap();
        let markdown = format_markdown(&response);

        assert!(markdown.contains("## ✅ Python 3.13 Compatibility"));
        assert!(!markdown.contains("Compatibility Issues"));
    }
}
