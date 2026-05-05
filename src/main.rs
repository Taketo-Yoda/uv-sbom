mod adapters;
mod application;
mod cli;
mod i18n;
mod ports;
mod sbom_generation;
mod shared;

use adapters::outbound::console::StderrProgressReporter;
use adapters::outbound::filesystem::FileSystemReader;
use adapters::outbound::network::{CachingPyPiLicenseRepository, OsvClient, PyPiLicenseRepository};
use adapters::outbound::uv::UvWorkspaceReader;
use application::dto::{OutputFormat, SbomRequest};
use application::factories::{FormatterFactory, PresenterFactory, PresenterType};
use application::read_models::SbomReadModelBuilder;
use application::use_cases::GenerateSbomUseCase;
use clap::Parser;
use cli::config_resolver::{load_config, merge_config};
use cli::runner::{display_banner, resolve_suggest_fix, validate_project_path};
use cli::Args;
use i18n::Messages;
use ports::outbound::{LockfileParseResult, LockfileReader, ProjectConfigReader, WorkspaceReader};
use shared::error::ExitCode;
use shared::Result;
use std::path::{Path, PathBuf};
use std::process;
use uv_sbom::config;

/// A LockfileReader adapter that reads the workspace-root uv.lock but returns
/// only packages reachable from the specified workspace member.
///
/// This adapter is used in workspace mode to scope the SBOM generation to a
/// single workspace member, delegating to `read_and_parse_lockfile_for_member`.
struct MemberScopedLockfileReader {
    inner: FileSystemReader,
    workspace_root: PathBuf,
    member_name: String,
}

impl MemberScopedLockfileReader {
    fn new(workspace_root: PathBuf, member_name: String) -> Self {
        Self {
            inner: FileSystemReader::new(),
            workspace_root,
            member_name,
        }
    }
}

impl LockfileReader for MemberScopedLockfileReader {
    fn read_lockfile(&self, _project_path: &Path) -> Result<String> {
        self.inner.read_lockfile(&self.workspace_root)
    }

    fn read_and_parse_lockfile(&self, _project_path: &Path) -> Result<LockfileParseResult> {
        self.inner
            .read_and_parse_lockfile_for_member(&self.workspace_root, &self.member_name)
    }

    fn read_and_parse_lockfile_for_member(
        &self,
        _project_path: &Path,
        member_name: &str,
    ) -> Result<LockfileParseResult> {
        self.inner
            .read_and_parse_lockfile_for_member(&self.workspace_root, member_name)
    }
}

#[tokio::main]
async fn main() {
    // Parse command-line arguments first to catch argument errors early
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(e) => {
            // Print the error message (clap formats these nicely)
            let _ = e.print();

            // Use exit code 0 for help/version, exit code 2 for actual argument errors
            let exit_code = if e.use_stderr() {
                ExitCode::InvalidArguments
            } else {
                ExitCode::Success
            };
            process::exit(exit_code.as_i32());
        }
    };

    // Handle --workspace mode before normal flow
    if args.workspace {
        let workspace_root = PathBuf::from(args.path.as_deref().unwrap_or("."));
        match run_workspace(args, workspace_root).await {
            Ok(()) => process::exit(ExitCode::Success.as_i32()),
            Err(e) => {
                eprintln!("\n❌ An error occurred:\n");
                eprintln!("{}", e);
                let mut source = e.source();
                while let Some(err) = source {
                    eprintln!("\nCaused by: {}", err);
                    source = err.source();
                }
                eprintln!();
                process::exit(ExitCode::ApplicationError.as_i32());
            }
        }
    }

    // Handle --init before normal flow
    if args.init {
        let dir = args.path.as_deref().unwrap_or(".");
        let dir_path = std::path::Path::new(dir);
        match config::generate_config_template(dir_path) {
            Ok(abs_path) => {
                eprintln!(
                    "Created {} in {}",
                    config::CONFIG_FILENAME,
                    abs_path.parent().unwrap_or(dir_path).display()
                );
                process::exit(ExitCode::Success.as_i32());
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(ExitCode::ApplicationError.as_i32());
            }
        }
    }

    // Run the main application logic
    match run(args).await {
        Ok(has_vulnerabilities) => {
            if has_vulnerabilities {
                process::exit(ExitCode::VulnerabilitiesDetected.as_i32());
            }
            process::exit(ExitCode::Success.as_i32());
        }
        Err(e) => {
            eprintln!("\n❌ An error occurred:\n");
            eprintln!("{}", e);

            // Display error chain
            let mut source = e.source();
            while let Some(err) = source {
                eprintln!("\nCaused by: {}", err);
                source = err.source();
            }

            eprintln!();
            process::exit(ExitCode::ApplicationError.as_i32());
        }
    }
}

/// Runs the main application logic.
///
/// Returns `Ok(true)` if vulnerabilities were detected above threshold,
/// `Ok(false)` if no vulnerabilities (or all below threshold),
/// or `Err` for application errors.
async fn run(args: Args) -> Result<bool> {
    // Display startup banner
    display_banner();

    let locale = args.lang;
    let msgs = Messages::for_locale(locale);

    // Warn if deprecated --check-cve flag is used
    if args.check_cve {
        eprintln!("Warning: --check-cve is deprecated and will be removed in a future release. CVE checking is now enabled by default. Use --no-check-cve to opt out.");
    }

    // Warn if CVE check is active with JSON format
    if !args.no_check_cve && args.format == OutputFormat::Json {
        eprintln!("{}", msgs.warn_check_cve_no_effect);
        eprintln!("   Vulnerability data is not included in JSON output.");
        eprintln!("   Use --format markdown to see vulnerability report.");
        eprintln!();
    }

    // Warn if check_license is used with JSON format
    if args.check_license && args.format == OutputFormat::Json {
        eprintln!("{}", msgs.warn_check_license_no_effect);
        eprintln!("   License compliance data is not included in JSON output.");
        eprintln!("   Use --format markdown to see license compliance report.");
        eprintln!();
    }

    // Warn if verify_links is used with JSON format
    if args.verify_links && args.format == OutputFormat::Json {
        eprintln!("{}", msgs.warn_verify_links_no_effect);
        eprintln!("   PyPI link verification only applies to Markdown output.");
        eprintln!("   Use --format markdown to use link verification.");
        eprintln!();
    }

    // Validate project directory
    let project_dir = args.path.as_deref().unwrap_or(".");
    let project_path = PathBuf::from(project_dir);

    validate_project_path(&project_path)?;

    // Load config file (explicit path or auto-discovery)
    let config = load_config(&args, &project_path)?;

    // Merge CLI and config values
    let merged = merge_config(&args, &config);

    // Create adapters (Dependency Injection)
    let lockfile_reader = FileSystemReader::new();
    let project_config_reader = FileSystemReader::new();
    let pypi_repository = PyPiLicenseRepository::new()?;
    let license_repository = CachingPyPiLicenseRepository::new(pypi_repository);
    let progress_reporter = StderrProgressReporter::new(locale);

    // Create vulnerability repository if CVE check is requested
    let vulnerability_repository = if merged.check_cve {
        Some(OsvClient::new()?)
    } else {
        None
    };

    // Create use case with injected dependencies
    let use_case = GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        vulnerability_repository,
        locale,
    );

    // Pre-flight check for --suggest-fix
    let suggest_fix = resolve_suggest_fix(merged.suggest_fix, &project_path);

    // Create request using builder pattern
    let include_dependency_info = matches!(merged.format, OutputFormat::Markdown);
    let request = SbomRequest::builder()
        .project_path(project_path.clone())
        .include_dependency_info(include_dependency_info)
        .exclude_patterns(merged.exclude_patterns)
        .dry_run(args.dry_run)
        .check_cve(merged.check_cve)
        .severity_threshold_opt(merged.severity_threshold)
        .cvss_threshold_opt(merged.cvss_threshold)
        .ignore_cves(merged.ignore_cves)
        .check_license(merged.check_license)
        .license_policy(merged.license_policy)
        .suggest_fix(suggest_fix)
        .check_abandoned(merged.check_abandoned)
        .abandoned_threshold_days(merged.abandoned_threshold_days)
        .locale(locale)
        .build()?;

    // Re-bind locale from the validated request to ensure consistency
    let locale = request.locale;

    // Execute use case
    let response = use_case.execute(request).await?;

    // Skip output generation for dry-run mode
    if args.dry_run {
        return Ok(false);
    }

    // Display progress message
    eprintln!(
        "{}",
        FormatterFactory::progress_message(merged.format, locale)
    );

    // Determine project component for CycloneDX metadata
    let project_reader = FileSystemReader::new();
    let project_component_info = project_reader
        .read_project_name(&project_path)
        .ok()
        .and_then(|name| {
            let version = response
                .enriched_packages
                .iter()
                .find(|ep| ep.package.name() == name)
                .map(|ep| ep.package.version().to_string());
            version.map(|v| (name, v))
        });

    // Build read model first so we can extract package names for verification
    let read_model = SbomReadModelBuilder::build_with_project(
        response.enriched_packages,
        &response.metadata,
        response.dependency_graph.as_ref(),
        response.vulnerability_check_result.as_ref(),
        response.license_compliance_result.as_ref(),
        project_component_info
            .as_ref()
            .map(|(n, v)| (n.as_str(), v.as_str())),
        response.upgrade_recommendations.as_deref(),
    );

    // Verify PyPI links if requested
    let verified_packages = if args.verify_links && merged.format == OutputFormat::Markdown {
        eprintln!("{}", msgs.progress_verifying_links);
        let pypi_verifier = PyPiLicenseRepository::new()?;
        let package_names: Vec<String> = read_model
            .components
            .iter()
            .map(|c| c.name.clone())
            .collect();
        Some(pypi_verifier.verify_packages(&package_names).await)
    } else {
        None
    };

    // Create formatter using factory with optional verified packages
    let formatter = FormatterFactory::create(merged.format, verified_packages, locale);
    let formatted_output = formatter.format(&read_model)?;

    // Create presenter using factory
    let presenter_type = if let Some(output_path) = args.output {
        PresenterType::File(PathBuf::from(output_path))
    } else {
        PresenterType::Stdout
    };

    let presenter = PresenterFactory::create(presenter_type, locale);
    presenter.present(&formatted_output)?;

    // Determine if vulnerabilities or license violations were detected
    let has_issues =
        response.has_vulnerabilities_above_threshold || response.has_license_violations;

    Ok(has_issues)
}

/// Runs workspace mode: generates one SBOM per workspace member.
///
/// Reads `[manifest].members` from `workspace_root/uv.lock`, then for each
/// member runs `GenerateSbomUseCase` scoped to that member and writes the
/// output to `{member_path}/sbom.{ext}`. Prints a summary table when done.
async fn run_workspace(args: Args, workspace_root: PathBuf) -> Result<()> {
    display_banner();

    validate_project_path(&workspace_root)?;

    let workspace_reader = UvWorkspaceReader::new();
    let members = workspace_reader.read_workspace_members(&workspace_root)?;

    if members.is_empty() {
        anyhow::bail!("No workspace members found. Is this a uv workspace?");
    }

    let locale = args.lang;
    let msgs = Messages::for_locale(locale);
    eprintln!(
        "{}\n",
        Messages::format(
            msgs.workspace_mode_members_found,
            &[&members.len().to_string()]
        )
    );

    let config = load_config(&args, &workspace_root)?;
    let merged = merge_config(&args, &config);

    let format_ext = match merged.format {
        OutputFormat::Json => "json",
        OutputFormat::Markdown => "md",
    };

    let mut summary: Vec<(String, PathBuf)> = Vec::new();

    for member in &members {
        eprintln!(
            "{}",
            Messages::format(msgs.workspace_processing_member, &[&member.name])
        );

        let lockfile_reader =
            MemberScopedLockfileReader::new(workspace_root.clone(), member.name.clone());
        let project_config_reader = FileSystemReader::new();
        let pypi_repository = PyPiLicenseRepository::new()?;
        let license_repository = CachingPyPiLicenseRepository::new(pypi_repository);
        let progress_reporter = StderrProgressReporter::new(locale);

        let vulnerability_repository = if merged.check_cve {
            Some(OsvClient::new()?)
        } else {
            None
        };

        let use_case = GenerateSbomUseCase::new(
            lockfile_reader,
            project_config_reader,
            license_repository,
            progress_reporter,
            vulnerability_repository,
            locale,
        );

        let include_dependency_info = matches!(merged.format, OutputFormat::Markdown);
        let request = SbomRequest::builder()
            .project_path(member.absolute_path.clone())
            .include_dependency_info(include_dependency_info)
            .exclude_patterns(merged.exclude_patterns.clone())
            .check_cve(merged.check_cve)
            .severity_threshold_opt(merged.severity_threshold)
            .cvss_threshold_opt(merged.cvss_threshold)
            .ignore_cves(merged.ignore_cves.clone())
            .check_license(merged.check_license)
            .license_policy(merged.license_policy.clone())
            .suggest_fix(false)
            .check_abandoned(merged.check_abandoned)
            .abandoned_threshold_days(merged.abandoned_threshold_days)
            .locale(locale)
            .build()?;

        let response = use_case.execute(request).await?;

        let read_model = SbomReadModelBuilder::build_with_project(
            response.enriched_packages,
            &response.metadata,
            response.dependency_graph.as_ref(),
            response.vulnerability_check_result.as_ref(),
            response.license_compliance_result.as_ref(),
            None,
            response.upgrade_recommendations.as_deref(),
        );

        let formatter = FormatterFactory::create(merged.format, None, locale);
        let formatted_output = formatter.format(&read_model)?;

        let output_path = member.absolute_path.join(format!("sbom.{}", format_ext));
        let presenter = PresenterFactory::create(PresenterType::File(output_path.clone()), locale);
        presenter.present(&formatted_output)?;

        summary.push((member.name.clone(), output_path));
    }

    // Print summary table
    eprintln!("\n{}", msgs.workspace_summary_header);
    eprintln!("{}", "─".repeat(60));
    eprintln!(
        "{:<20} {}",
        msgs.workspace_col_member, msgs.workspace_col_output_file
    );
    eprintln!("{}", "─".repeat(60));
    for (name, path) in &summary {
        eprintln!("{:<20} {}", name, path.display());
    }
    eprintln!("{}", "─".repeat(60));

    Ok(())
}
