use super::*;
use crate::ports::outbound::LockfileParseResult;
use crate::sbom_generation::domain::Package;
use std::collections::HashMap;
use std::path::Path;

// Mock implementations for testing
struct MockLockfileReader {
    content: String,
}

impl LockfileReader for MockLockfileReader {
    fn read_lockfile(&self, _path: &Path) -> Result<String> {
        Ok(self.content.clone())
    }

    fn read_and_parse_lockfile(&self, _path: &Path) -> Result<LockfileParseResult> {
        // Parse the mock content
        use serde::Deserialize;

        #[derive(Debug, Deserialize)]
        struct UvLock {
            package: Vec<UvPackage>,
        }

        #[derive(Debug, Deserialize)]
        struct UvPackage {
            name: String,
            version: String,
            #[serde(default)]
            dependencies: Vec<UvDependency>,
            #[serde(default, rename = "dev-dependencies")]
            dev_dependencies: Option<DevDependencies>,
        }

        #[derive(Debug, Deserialize)]
        struct UvDependency {
            name: String,
        }

        #[derive(Debug, Deserialize)]
        struct DevDependencies {
            #[serde(default)]
            dev: Vec<UvDependency>,
        }

        let lockfile: UvLock = toml::from_str(&self.content)?;

        let mut packages = Vec::new();
        let mut dependency_map = HashMap::new();

        for pkg in lockfile.package {
            packages.push(Package::new(pkg.name.clone(), pkg.version.clone())?);

            let mut deps = Vec::new();
            for dep in &pkg.dependencies {
                deps.push(dep.name.clone());
            }
            if let Some(dev_deps) = &pkg.dev_dependencies {
                for dep in &dev_deps.dev {
                    deps.push(dep.name.clone());
                }
            }
            dependency_map.insert(pkg.name, deps);
        }

        Ok((packages, dependency_map))
    }
}

struct MockProjectConfigReader {
    project_name: String,
}

impl ProjectConfigReader for MockProjectConfigReader {
    fn read_project_name(&self, _path: &Path) -> Result<String> {
        Ok(self.project_name.clone())
    }
}

use crate::ports::outbound::PyPiMetadata;

struct MockLicenseRepository;

#[async_trait::async_trait]
impl LicenseRepository for MockLicenseRepository {
    async fn fetch_license_info(
        &self,
        _package_name: &str,
        _version: &str,
    ) -> Result<PyPiMetadata> {
        Ok((
            Some("MIT".to_string()),
            None,
            vec![],
            Some("A test package".to_string()),
        ))
    }
}

struct MockProgressReporter;

impl ProgressReporter for MockProgressReporter {
    fn report(&self, _message: &str) {}
    fn report_error(&self, _message: &str) {}
    fn report_completion(&self, _message: &str) {}
}

#[tokio::test]
async fn test_execute_without_dependencies() {
    let lockfile_content = r#"
[[package]]
name = "certifi"
version = "2024.8.30"

[[package]]
name = "charset-normalizer"
version = "3.4.0"
"#;

    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
        GenerateSbomUseCase::new(
            MockLockfileReader {
                content: lockfile_content.to_string(),
            },
            MockProjectConfigReader {
                project_name: "test-project".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            None,
        );

    let request = SbomRequest::builder()
        .project_path("/test/project")
        .build()
        .unwrap();

    let response = use_case.execute(request).await.unwrap();

    assert_eq!(response.enriched_packages.len(), 2);
    assert!(response.dependency_graph.is_none());
    assert!(!response.metadata.serial_number().is_empty());
}

#[tokio::test]
async fn test_execute_with_dependencies() {
    let lockfile_content = r#"
[[package]]
name = "myproject"
version = "1.0.0"
dependencies = [
    { name = "requests" }
]

[[package]]
name = "requests"
version = "2.31.0"
dependencies = [
    { name = "urllib3" }
]

[[package]]
name = "urllib3"
version = "1.26.0"
"#;

    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
        GenerateSbomUseCase::new(
            MockLockfileReader {
                content: lockfile_content.to_string(),
            },
            MockProjectConfigReader {
                project_name: "myproject".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            None,
        );

    let request = SbomRequest::builder()
        .project_path("/test/project")
        .include_dependency_info(true)
        .build()
        .unwrap();

    let response = use_case.execute(request).await.unwrap();

    assert_eq!(response.enriched_packages.len(), 3);
    assert!(response.dependency_graph.is_some());

    let graph = response.dependency_graph.unwrap();
    assert_eq!(graph.direct_dependency_count(), 1);
    assert_eq!(graph.transitive_dependency_count(), 1);
}

#[derive(Clone)]
struct MockVulnerabilityRepository;

#[async_trait::async_trait]
impl VulnerabilityRepository for MockVulnerabilityRepository {
    async fn fetch_vulnerabilities(
        &self,
        _packages: Vec<Package>,
    ) -> Result<Vec<crate::sbom_generation::domain::PackageVulnerabilities>> {
        Ok(vec![])
    }
}

#[tokio::test]
async fn test_execute_with_cve_check_enabled() {
    let lockfile_content = r#"
[[package]]
name = "certifi"
version = "2024.8.30"

[[package]]
name = "charset-normalizer"
version = "3.4.0"
"#;

    let use_case = GenerateSbomUseCase::new(
        MockLockfileReader {
            content: lockfile_content.to_string(),
        },
        MockProjectConfigReader {
            project_name: "test-project".to_string(),
        },
        MockLicenseRepository,
        MockProgressReporter,
        Some(MockVulnerabilityRepository),
    );

    let request = SbomRequest::builder()
        .project_path("/test/project")
        .check_cve(true)
        .build()
        .unwrap();

    let response = use_case.execute(request).await.unwrap();

    assert_eq!(response.enriched_packages.len(), 2);
    assert!(response.vulnerability_report.is_some());
}

#[tokio::test]
async fn test_execute_with_cve_check_but_no_repository() {
    let lockfile_content = r#"
[[package]]
name = "certifi"
version = "2024.8.30"
"#;

    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
        GenerateSbomUseCase::new(
            MockLockfileReader {
                content: lockfile_content.to_string(),
            },
            MockProjectConfigReader {
                project_name: "test-project".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            None, // No vulnerability repository
        );

    let request = SbomRequest::builder()
        .project_path("/test/project")
        .check_cve(true)
        .build()
        .unwrap();

    let response = use_case.execute(request).await.unwrap();

    assert_eq!(response.enriched_packages.len(), 1);
    assert!(response.vulnerability_report.is_none());
}

#[tokio::test]
async fn test_execute_with_cve_check_disabled() {
    let lockfile_content = r#"
[[package]]
name = "certifi"
version = "2024.8.30"
"#;

    let use_case = GenerateSbomUseCase::new(
        MockLockfileReader {
            content: lockfile_content.to_string(),
        },
        MockProjectConfigReader {
            project_name: "test-project".to_string(),
        },
        MockLicenseRepository,
        MockProgressReporter,
        Some(MockVulnerabilityRepository),
    );

    let request = SbomRequest::builder()
        .project_path("/test/project")
        .build()
        .unwrap();

    let response = use_case.execute(request).await.unwrap();

    assert_eq!(response.enriched_packages.len(), 1);
    assert!(response.vulnerability_report.is_none());
}

#[tokio::test]
async fn test_execute_with_cve_check_in_dry_run_mode() {
    let lockfile_content = r#"
[[package]]
name = "certifi"
version = "2024.8.30"
"#;

    let use_case = GenerateSbomUseCase::new(
        MockLockfileReader {
            content: lockfile_content.to_string(),
        },
        MockProjectConfigReader {
            project_name: "test-project".to_string(),
        },
        MockLicenseRepository,
        MockProgressReporter,
        Some(MockVulnerabilityRepository),
    );

    let request = SbomRequest::builder()
        .project_path("/test/project")
        .dry_run(true)
        .check_cve(true)
        .build()
        .unwrap();

    let response = use_case.execute(request).await.unwrap();

    assert_eq!(response.enriched_packages.len(), 0); // dry-run returns empty
    assert!(response.vulnerability_report.is_none()); // CVE check skipped
}

// ===== Tests for extracted methods =====

#[test]
fn test_apply_exclusion_filters_empty_patterns() {
    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
        GenerateSbomUseCase::new(
            MockLockfileReader {
                content: String::new(),
            },
            MockProjectConfigReader {
                project_name: "test".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            None,
        );

    let packages = vec![
        Package::new("pkg1".to_string(), "1.0.0".to_string()).unwrap(),
        Package::new("pkg2".to_string(), "2.0.0".to_string()).unwrap(),
    ];
    let dependency_map: HashMap<String, Vec<String>> = HashMap::new();
    let request = SbomRequest::builder()
        .project_path("/test/project")
        .build()
        .unwrap();

    let (filtered_pkgs, _filtered_deps) = use_case
        .apply_exclusion_filters(packages.clone(), dependency_map, &request)
        .unwrap();

    assert_eq!(filtered_pkgs.len(), 2);
}

#[test]
fn test_apply_exclusion_filters_with_patterns() {
    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
        GenerateSbomUseCase::new(
            MockLockfileReader {
                content: String::new(),
            },
            MockProjectConfigReader {
                project_name: "test".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            None,
        );

    let packages = vec![
        Package::new("requests".to_string(), "1.0.0".to_string()).unwrap(),
        Package::new("urllib3".to_string(), "2.0.0".to_string()).unwrap(),
        Package::new("certifi".to_string(), "3.0.0".to_string()).unwrap(),
    ];
    let dependency_map: HashMap<String, Vec<String>> = HashMap::new();
    let request = SbomRequest::builder()
        .project_path("/test/project")
        .add_exclude_pattern("requests")
        .build()
        .unwrap();

    let (filtered_pkgs, _filtered_deps) = use_case
        .apply_exclusion_filters(packages, dependency_map, &request)
        .unwrap();

    assert_eq!(filtered_pkgs.len(), 2);
    assert!(!filtered_pkgs.iter().any(|p| p.name() == "requests"));
}

#[test]
fn test_apply_exclusion_filters_all_excluded_error() {
    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
        GenerateSbomUseCase::new(
            MockLockfileReader {
                content: String::new(),
            },
            MockProjectConfigReader {
                project_name: "test".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            None,
        );

    let packages = vec![Package::new("pkg1".to_string(), "1.0.0".to_string()).unwrap()];
    let dependency_map: HashMap<String, Vec<String>> = HashMap::new();
    let request = SbomRequest::builder()
        .project_path("/test/project")
        .add_exclude_pattern("pkg1")
        .build()
        .unwrap();

    let result = use_case.apply_exclusion_filters(packages, dependency_map, &request);

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("All 1 package(s) were excluded"));
}

#[test]
fn test_analyze_dependencies_disabled() {
    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
        GenerateSbomUseCase::new(
            MockLockfileReader {
                content: String::new(),
            },
            MockProjectConfigReader {
                project_name: "test".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            None,
        );

    let request = SbomRequest::builder()
        .project_path("/test/project")
        .build()
        .unwrap();
    let dependency_map: HashMap<String, Vec<String>> = HashMap::new();

    let result = use_case
        .analyze_dependencies_if_requested(&request, &dependency_map)
        .unwrap();

    assert!(result.is_none());
}

#[test]
fn test_analyze_dependencies_enabled() {
    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
        GenerateSbomUseCase::new(
            MockLockfileReader {
                content: String::new(),
            },
            MockProjectConfigReader {
                project_name: "myproject".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            None,
        );

    let request = SbomRequest::builder()
        .project_path("/test/project")
        .include_dependency_info(true)
        .build()
        .unwrap();
    let mut dependency_map: HashMap<String, Vec<String>> = HashMap::new();
    dependency_map.insert("myproject".to_string(), vec!["requests".to_string()]);
    dependency_map.insert("requests".to_string(), vec![]);

    let result = use_case
        .analyze_dependencies_if_requested(&request, &dependency_map)
        .unwrap();

    assert!(result.is_some());
    let graph = result.unwrap();
    assert_eq!(graph.direct_dependency_count(), 1);
}

#[test]
fn test_build_response() {
    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
        GenerateSbomUseCase::new(
            MockLockfileReader {
                content: String::new(),
            },
            MockProjectConfigReader {
                project_name: "test".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            None,
        );

    let package = Package::new("test-pkg".to_string(), "1.0.0".to_string()).unwrap();
    let enriched_packages = vec![EnrichedPackage::new(
        package,
        Some("MIT".to_string()),
        Some("Test description".to_string()),
    )];

    let response = use_case.build_response(enriched_packages.clone(), None, None, None);

    assert_eq!(response.enriched_packages.len(), 1);
    assert!(response.dependency_graph.is_none());
    assert!(response.vulnerability_report.is_none());
    assert!(response.vulnerability_check_result.is_none());
    assert!(!response.metadata.serial_number().is_empty());
    assert!(!response.metadata.timestamp().is_empty());
}

#[tokio::test]
async fn test_fetch_license_info() {
    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
        GenerateSbomUseCase::new(
            MockLockfileReader {
                content: String::new(),
            },
            MockProjectConfigReader {
                project_name: "test".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            None,
        );

    let packages = vec![
        Package::new("pkg1".to_string(), "1.0.0".to_string()).unwrap(),
        Package::new("pkg2".to_string(), "2.0.0".to_string()).unwrap(),
    ];

    let enriched = use_case.fetch_license_info(packages).await.unwrap();

    assert_eq!(enriched.len(), 2);
    // MockLicenseRepository always returns MIT license
    assert!(enriched[0].license.is_some());
    assert_eq!(enriched[0].license.as_ref().unwrap(), "MIT");
}

#[tokio::test]
async fn test_check_vulnerabilities_if_requested_disabled() {
    let use_case = GenerateSbomUseCase::new(
        MockLockfileReader {
            content: String::new(),
        },
        MockProjectConfigReader {
            project_name: "test".to_string(),
        },
        MockLicenseRepository,
        MockProgressReporter,
        Some(MockVulnerabilityRepository),
    );

    let request = SbomRequest::builder()
        .project_path("/test/project")
        .build()
        .unwrap();
    let packages = vec![Package::new("pkg1".to_string(), "1.0.0".to_string()).unwrap()];

    let result = use_case
        .check_vulnerabilities_if_requested(&request, &packages)
        .await
        .unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn test_check_vulnerabilities_if_requested_enabled() {
    let use_case = GenerateSbomUseCase::new(
        MockLockfileReader {
            content: String::new(),
        },
        MockProjectConfigReader {
            project_name: "test".to_string(),
        },
        MockLicenseRepository,
        MockProgressReporter,
        Some(MockVulnerabilityRepository),
    );

    let request = SbomRequest::builder()
        .project_path("/test/project")
        .check_cve(true)
        .build()
        .unwrap();
    let packages = vec![Package::new("pkg1".to_string(), "1.0.0".to_string()).unwrap()];

    let result = use_case
        .check_vulnerabilities_if_requested(&request, &packages)
        .await
        .unwrap();

    assert!(result.is_some());
}

// ===== Tests for threshold configuration =====

#[test]
fn test_build_threshold_config_none() {
    let request = SbomRequest::builder()
        .project_path("/test/project")
        .check_cve(true)
        .build()
        .unwrap();

    let config = GenerateSbomUseCase::<
        MockLockfileReader,
        MockProjectConfigReader,
        MockLicenseRepository,
        MockProgressReporter,
        MockVulnerabilityRepository,
    >::build_threshold_config(&request);

    assert_eq!(config, ThresholdConfig::None);
}

#[test]
fn test_build_threshold_config_severity() {
    use crate::sbom_generation::domain::vulnerability::Severity;

    let request = SbomRequest::builder()
        .project_path("/test/project")
        .check_cve(true)
        .severity_threshold(Severity::High)
        .build()
        .unwrap();

    let config = GenerateSbomUseCase::<
        MockLockfileReader,
        MockProjectConfigReader,
        MockLicenseRepository,
        MockProgressReporter,
        MockVulnerabilityRepository,
    >::build_threshold_config(&request);

    assert_eq!(config, ThresholdConfig::Severity(Severity::High));
}

#[test]
fn test_build_threshold_config_cvss() {
    let request = SbomRequest::builder()
        .project_path("/test/project")
        .check_cve(true)
        .cvss_threshold(7.0)
        .build()
        .unwrap();

    let config = GenerateSbomUseCase::<
        MockLockfileReader,
        MockProjectConfigReader,
        MockLicenseRepository,
        MockProgressReporter,
        MockVulnerabilityRepository,
    >::build_threshold_config(&request);

    assert_eq!(config, ThresholdConfig::Cvss(7.0));
}

#[test]
fn test_build_response_with_threshold_exceeded() {
    use crate::sbom_generation::domain::vulnerability::{CvssScore, Severity, Vulnerability};

    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
        GenerateSbomUseCase::new(
            MockLockfileReader {
                content: String::new(),
            },
            MockProjectConfigReader {
                project_name: "test".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            None,
        );

    let package = Package::new("test-pkg".to_string(), "1.0.0".to_string()).unwrap();
    let enriched_packages = vec![EnrichedPackage::new(
        package,
        Some("MIT".to_string()),
        Some("Test description".to_string()),
    )];

    // Create a vulnerability check result with threshold exceeded
    let vuln = Vulnerability::new(
        "CVE-2024-001".to_string(),
        Some(CvssScore::new(9.0).unwrap()),
        Severity::Critical,
        None,
        None,
    )
    .unwrap();
    let pkg_vulns = crate::sbom_generation::domain::PackageVulnerabilities::new(
        "test-pkg".to_string(),
        "1.0.0".to_string(),
        vec![vuln],
    );
    let check_result = VulnerabilityCheckResult {
        above_threshold: vec![pkg_vulns],
        below_threshold: vec![],
        threshold_exceeded: true,
    };

    let response = use_case.build_response(enriched_packages, None, None, Some(check_result));

    assert!(response.has_vulnerabilities_above_threshold);
    assert!(response.vulnerability_check_result.is_some());
    assert!(
        response
            .vulnerability_check_result
            .unwrap()
            .threshold_exceeded
    );
}

#[test]
fn test_build_response_with_threshold_not_exceeded() {
    use crate::sbom_generation::domain::vulnerability::{CvssScore, Severity, Vulnerability};

    let use_case: GenerateSbomUseCase<_, _, _, _, MockVulnerabilityRepository> =
        GenerateSbomUseCase::new(
            MockLockfileReader {
                content: String::new(),
            },
            MockProjectConfigReader {
                project_name: "test".to_string(),
            },
            MockLicenseRepository,
            MockProgressReporter,
            None,
        );

    let package = Package::new("test-pkg".to_string(), "1.0.0".to_string()).unwrap();
    let enriched_packages = vec![EnrichedPackage::new(
        package,
        Some("MIT".to_string()),
        Some("Test description".to_string()),
    )];

    // Create a vulnerability check result with threshold NOT exceeded
    let vuln = Vulnerability::new(
        "CVE-2024-001".to_string(),
        Some(CvssScore::new(3.0).unwrap()),
        Severity::Low,
        None,
        None,
    )
    .unwrap();
    let pkg_vulns = crate::sbom_generation::domain::PackageVulnerabilities::new(
        "test-pkg".to_string(),
        "1.0.0".to_string(),
        vec![vuln],
    );
    let check_result = VulnerabilityCheckResult {
        above_threshold: vec![],
        below_threshold: vec![pkg_vulns],
        threshold_exceeded: false,
    };

    let response = use_case.build_response(enriched_packages, None, None, Some(check_result));

    assert!(!response.has_vulnerabilities_above_threshold);
    assert!(response.vulnerability_check_result.is_some());
    assert!(
        !response
            .vulnerability_check_result
            .unwrap()
            .threshold_exceeded
    );
}
