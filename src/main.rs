mod adapters;
mod application;
mod cli;
mod i18n;
mod ports;
mod sbom_generation;
mod shared;

use adapters::outbound::console::StderrProgressReporter;
use adapters::outbound::filesystem::{determine_diff_source, FileSystemReader, GitLockfileReader};
use adapters::outbound::formatters::{DiffJsonFormatter, DiffMarkdownFormatter};
use adapters::outbound::network::{
    CachingPyPiLicenseRepository, OsvClient, PyPiCompatibilityClient, PyPiLicenseRepository,
    PyPiMaintenanceRepository,
};
use adapters::outbound::uv::{UvLockAdapter, UvWorkspaceReader};
use application::dto::{DiffRequest, OutputFormat, SbomRequest, SbomResponse};
use application::factories::{FormatterFactory, PresenterFactory, PresenterType};
use application::read_models::SbomReadModelBuilder;
use application::use_cases::{GenerateDiffUseCase, GenerateSbomUseCase};
use clap::Parser;
use cli::config_resolver::{load_config, merge_config, MergedConfig};
use cli::runner::{display_banner, resolve_suggest_fix, validate_project_path};
use cli::workspace_summary::{render_workspace_aggregate, EnabledChecks, MemberFindings};
use cli::{Args, DEFAULT_DEPENDENCY_TREE_DEPTH};
use i18n::{Locale, Messages};
use ports::outbound::{
    DiffSource, GroupRoots, LockfileParseResult, LockfileReader, PackageSourceMap,
    ProjectConfigReader, WorkspaceReader,
};
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

    fn read_and_parse_group_roots(&self, _project_path: &Path) -> Result<GroupRoots> {
        self.inner.read_and_parse_group_roots(&self.workspace_root)
    }

    fn read_and_parse_package_sources(&self, _project_path: &Path) -> Result<PackageSourceMap> {
        self.inner
            .read_and_parse_package_sources(&self.workspace_root)
    }
}

/// The fully-wired `GenerateSbomUseCase` type produced by [`build_use_case`].
///
/// Only the `LockfileReader` varies between call sites: normal mode uses
/// `FileSystemReader`, workspace mode uses `MemberScopedLockfileReader`.
type WiredSbomUseCase<LR> = GenerateSbomUseCase<
    LR,
    FileSystemReader,
    CachingPyPiLicenseRepository<PyPiLicenseRepository>,
    StderrProgressReporter,
    OsvClient,
    PyPiMaintenanceRepository,
    PyPiCompatibilityClient,
    UvLockAdapter,
>;

/// Builds a fully-wired `GenerateSbomUseCase` from the resolved config.
///
/// Only the `LockfileReader` differs between normal mode and workspace mode,
/// so it is injected by the caller; every other adapter is constructed here.
fn build_use_case<LR: LockfileReader>(
    lockfile_reader: LR,
    locale: Locale,
    merged: &MergedConfig,
) -> Result<WiredSbomUseCase<LR>> {
    let project_config_reader = FileSystemReader::new();
    let pypi_repository = PyPiLicenseRepository::new()?;
    let license_repository = CachingPyPiLicenseRepository::new(pypi_repository);
    let progress_reporter = StderrProgressReporter::new(locale);

    // Create vulnerability repository if CVE check is requested
    let vulnerability_repository = if merged.check_cve {
        Some(OsvClient::new(locale)?)
    } else {
        None
    };

    // Create maintenance repository if abandoned check is requested
    let maintenance_repository = if merged.check_abandoned {
        Some(PyPiMaintenanceRepository::new()?)
    } else {
        None
    };

    // Create Python compatibility repository if --target-python is set
    let compatibility_repository = if merged.target_python.is_some() {
        Some(PyPiCompatibilityClient::new()?)
    } else {
        None
    };

    // Upgrade simulator: unconditionally injected. `UvLockAdapter::new()` is
    // infallible and constructs a zero-sized struct with no I/O, so there is
    // nothing to gate on here (unlike the repositories above, which build real
    // HTTP clients). Whether it is actually used is decided later by
    // `SbomRequest::suggest_fix`, which is resolved by the caller after this
    // function returns.
    let uv_lock_simulator = Some(UvLockAdapter::new());

    Ok(GenerateSbomUseCase::new(
        lockfile_reader,
        project_config_reader,
        license_repository,
        progress_reporter,
        vulnerability_repository,
        maintenance_repository,
        compatibility_repository,
        uv_lock_simulator,
        locale,
    ))
}

/// Prints deprecation/no-effect warnings for CLI flags that don't apply given the
/// rest of the invocation (e.g. `--verify-links` combined with `--format json`).
///
/// Gates on the resolved `format` (`MergedConfig.format`) rather than the raw CLI
/// `args.format`, so a `format: markdown` set only via config file (no `--format`
/// flag) correctly suppresses these warnings (fixed in #822; previously gated on
/// `args.format`, which stays at its `Json` default when no `--format` flag is
/// passed, regardless of the config file).
///
/// `check_license` must be the resolved `MergedConfig.check_license`, not the raw
/// CLI `args.check_license` (fixed in #828; previously gated on `args.check_license`,
/// which stays `false` when no `--check-license` flag is passed, even if the config
/// file enables it via `check_license: true`). `verify_links` stays sourced from the
/// raw CLI flag since `MergedConfig` has no config-file tier for it — `args.verify_links`
/// is already the fully resolved value.
fn print_startup_warnings(
    check_license: bool,
    verify_links: bool,
    format: OutputFormat,
    msgs: &Messages,
) {
    // Warn if check_license is used with JSON format
    if check_license && format == OutputFormat::Json {
        eprintln!("{}", msgs.warn_check_license_no_effect);
        eprintln!("{}", msgs.warn_check_license_json_detail);
        eprintln!("{}", msgs.warn_check_license_json_hint);
        eprintln!();
    }

    // Warn if verify_links is used with JSON format
    if verify_links && format == OutputFormat::Json {
        eprintln!("{}", msgs.warn_verify_links_no_effect);
        eprintln!("{}", msgs.warn_verify_links_json_detail);
        eprintln!("{}", msgs.warn_verify_links_json_hint);
        eprintln!();
    }
}

/// Prints an error and its full `source()` chain to stderr, localized via `msgs`.
///
/// Extracted from three identical `Err(e)` arms in `main()` (workspace mode,
/// diff mode, and normal mode) to avoid triplicating the same i18n-routed
/// error-reporting logic.
fn print_error_chain(e: &anyhow::Error, msgs: &Messages) {
    eprintln!("\n{}\n", msgs.error_header);
    eprintln!("{}", e);

    let mut source = e.source();
    while let Some(err) = source {
        let cause = err.to_string();
        eprintln!("\n{}", Messages::format(msgs.error_caused_by, &[&cause]));
        source = err.source();
    }

    eprintln!();
}

/// CLI-only `SbomRequest` fields that intentionally have no config-file tier
/// (see Issue #767 for `explain_package`; `--show-dependency-tree` /
/// `--dependency-tree-depth` follow the same rationale — one-off diagnostic/
/// visualization requests, not persistent policy settings). Grouped into a
/// struct rather than passed as separate `build_sbom_request` parameters to
/// keep that function's argument count from growing unbounded as more such
/// flags are added.
struct CliOnlyRequestOptions {
    explain_package: Option<String>,
    show_dependency_tree: bool,
    dependency_tree_depth: Option<u32>,
}

/// Builds an `SbomRequest` via the builder pattern, shared between normal mode
/// (`run()`) and workspace mode (`run_workspace()`'s per-member loop).
///
/// `exclude_groups`, `suggest_fix`, and `dry_run` are taken as explicit
/// parameters rather than derived from `&Args`/`&MergedConfig` internally,
/// since each varies between the two call sites: `exclude_groups` requires I/O
/// rooted at a different path per mode, workspace mode always passes
/// `suggest_fix(false)`, and only normal mode supports `--dry-run`.
///
/// `cli_only` groups fields sourced straight from the raw `Args`, not
/// `MergedConfig`: `MergedConfig` only exists to express the CLI > config
/// file > defaults merge, which doesn't apply to CLI-only values.
fn build_sbom_request(
    project_path: PathBuf,
    merged: &MergedConfig,
    exclude_groups: Vec<String>,
    suggest_fix: bool,
    dry_run: bool,
    cli_only: CliOnlyRequestOptions,
    locale: Locale,
) -> Result<SbomRequest> {
    let include_dependency_info = matches!(merged.format, OutputFormat::Markdown);
    let dependency_tree_depth = cli_only
        .dependency_tree_depth
        .unwrap_or(DEFAULT_DEPENDENCY_TREE_DEPTH) as usize;
    SbomRequest::builder()
        .project_path(project_path)
        .include_dependency_info(include_dependency_info)
        .exclude_patterns(merged.exclude_patterns.clone())
        .dry_run(dry_run)
        .check_cve(merged.check_cve)
        .severity_threshold_opt(merged.severity_threshold)
        .cvss_threshold_opt(merged.cvss_threshold)
        .ignore_cves(merged.ignore_cves.clone())
        .check_license(merged.check_license)
        .license_policy(merged.license_policy.clone())
        .suggest_fix(suggest_fix)
        .check_abandoned(merged.check_abandoned)
        .abandoned_threshold_days(merged.abandoned_threshold_days)
        .check_non_pypi(merged.check_non_pypi)
        .exclude_groups(exclude_groups)
        .target_python(merged.target_python.clone())
        .explain_package(cli_only.explain_package)
        .show_dependency_tree(cli_only.show_dependency_tree)
        .dependency_tree_depth(dependency_tree_depth)
        .locale(locale)
        .build()
}

/// Resolves the project's own name/version from the lockfile response, for use
/// as CycloneDX metadata.
///
/// Must be called before `response.enriched_packages` is moved into the read
/// model, since it needs to search `&response.enriched_packages` for the
/// project's own version.
fn resolve_project_component(
    response: &SbomResponse,
    project_path: &Path,
) -> Option<(String, String)> {
    let project_reader = FileSystemReader::new();
    project_reader
        .read_project_name(project_path)
        .ok()
        .and_then(|name| {
            let version = response
                .enriched_packages
                .iter()
                .find(|ep| ep.package.name() == name)
                .map(|ep| ep.package.version().to_string());
            version.map(|v| (name, v))
        })
}

/// Builds the read model, optionally verifies PyPI links, formats, and writes
/// the output via the given presenter. Returns whether vulnerabilities,
/// license violations, or abandoned packages were detected above threshold.
///
/// `presenter_type` and `verify_links` are taken as explicit parameters rather
/// than derived from `&Args` internally: normal mode derives `presenter_type`
/// from `args.output` (file or stdout) while workspace mode always writes to
/// `{member_path}/sbom.{ext}`, and only normal mode supports `--verify-links`.
async fn render_and_present(
    response: SbomResponse,
    project_component_info: Option<(String, String)>,
    presenter_type: PresenterType,
    format: OutputFormat,
    verify_links: bool,
    locale: Locale,
) -> Result<bool> {
    // Extract applied_group_filter before moving other response fields
    let applied_group_filter = response.applied_group_filter;

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
        response.abandoned_packages_report.as_ref(),
        response.non_pypi_packages_report.as_ref(),
        response.python_compatibility_report.as_ref(),
        response.explain_view.as_ref(),
        response.dependency_tree.as_ref(),
        &applied_group_filter,
    );

    // Verify PyPI links if requested
    let verified_packages = if verify_links && format == OutputFormat::Markdown {
        let msgs = Messages::for_locale(locale);
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
    let formatter = FormatterFactory::create(format, verified_packages, locale);
    let formatted_output = formatter.format(&read_model)?;

    // Create presenter using factory
    let presenter = PresenterFactory::create(presenter_type, locale);
    presenter.present(&formatted_output)?;

    // Determine if vulnerabilities, license violations, or abandoned packages were detected
    let has_abandoned = response
        .abandoned_packages_report
        .as_ref()
        .map(|r| !r.is_empty())
        .unwrap_or(false);
    let has_issues = response.has_vulnerabilities_above_threshold
        || response.has_license_violations
        || has_abandoned;

    Ok(has_issues)
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

    // Captured before `args` is moved into run_workspace/run_diff/run below, so
    // the error and --init messages can still be localized.
    let msgs = Messages::for_locale(args.lang);

    // Handle --workspace mode before normal flow
    if args.workspace {
        let workspace_root = PathBuf::from(args.path.as_deref().unwrap_or("."));
        match run_workspace(args, workspace_root).await {
            Ok(()) => process::exit(ExitCode::Success.as_i32()),
            Err(e) => {
                print_error_chain(&e, msgs);
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
                let dir_display = abs_path.parent().unwrap_or(dir_path).display().to_string();
                eprintln!(
                    "{}",
                    Messages::format(
                        msgs.info_config_template_created,
                        &[config::CONFIG_FILENAME, &dir_display],
                    )
                );
                process::exit(ExitCode::Success.as_i32());
            }
            Err(e) => {
                let err_text = e.to_string();
                eprintln!("{}", Messages::format(msgs.error_init_failed, &[&err_text]));
                process::exit(ExitCode::ApplicationError.as_i32());
            }
        }
    }

    // Handle --diff before normal flow
    if let Some(ref diff_arg) = args.diff {
        let source = determine_diff_source(diff_arg);
        match run_diff(args, source).await {
            Ok(has_vulnerabilities) => {
                if has_vulnerabilities {
                    process::exit(ExitCode::VulnerabilitiesDetected.as_i32());
                }
                process::exit(ExitCode::Success.as_i32());
            }
            Err(e) => {
                print_error_chain(&e, msgs);
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
            print_error_chain(&e, msgs);
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

    // Validate project directory
    let project_dir = args.path.as_deref().unwrap_or(".");
    let project_path = PathBuf::from(project_dir);

    validate_project_path(&project_path)?;

    // Load config file (explicit path or auto-discovery)
    let config = load_config(&args, &project_path, locale)?;

    // Merge CLI and config values
    let merged = merge_config(&args, &config)?;

    // Print startup warnings using the resolved format and check_license, so a
    // `format: markdown` (#822) or `check_license: true` (#828) set only via config
    // file (no corresponding CLI flag) is still correctly reflected.
    print_startup_warnings(merged.check_license, args.verify_links, merged.format, msgs);

    // Create use case with injected dependencies
    let use_case = build_use_case(FileSystemReader::new(), locale, &merged)?;

    // Pre-flight check for --suggest-fix
    let suggest_fix = resolve_suggest_fix(merged.suggest_fix, &project_path, msgs);

    // Resolve exclude_groups: --production-only expands to all group names in the lockfile.
    // This requires lockfile I/O so it lives here rather than in config_resolver.
    let exclude_groups = if args.production_only {
        FileSystemReader::new()
            .read_and_parse_group_roots(&project_path)?
            .into_keys()
            .collect::<Vec<_>>()
    } else {
        merged.exclude_groups.clone()
    };

    // Create request using shared builder helper
    let request = build_sbom_request(
        project_path.clone(),
        &merged,
        exclude_groups,
        suggest_fix,
        args.dry_run,
        CliOnlyRequestOptions {
            explain_package: args.explain.clone(),
            show_dependency_tree: args.show_dependency_tree,
            dependency_tree_depth: args.dependency_tree_depth,
        },
        locale,
    )?;

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

    // Determine project component for CycloneDX metadata before response is moved
    let project_component_info = resolve_project_component(&response, &project_path);

    let presenter_type = if let Some(output_path) = args.output {
        PresenterType::File(PathBuf::from(output_path))
    } else {
        PresenterType::Stdout
    };

    let verify_links = args.verify_links && merged.format == OutputFormat::Markdown;

    render_and_present(
        response,
        project_component_info,
        presenter_type,
        merged.format,
        verify_links,
        locale,
    )
    .await
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

    let config = load_config(&args, &workspace_root, locale)?;
    let merged = merge_config(&args, &config)?;

    // Resolve exclude_groups for workspace mode: --production-only reads group roots from
    // the workspace-root lockfile. --exclude-groups / config value is used otherwise.
    let workspace_exclude_groups = if args.production_only {
        FileSystemReader::new()
            .read_and_parse_group_roots(&workspace_root)?
            .into_keys()
            .collect::<Vec<_>>()
    } else {
        merged.exclude_groups.clone()
    };

    let format_ext = match merged.format {
        OutputFormat::Json => "json",
        OutputFormat::Markdown => "md",
    };

    let mut summary: Vec<(String, PathBuf)> = Vec::new();
    let mut member_findings: Vec<MemberFindings> = Vec::new();

    for member in &members {
        eprintln!(
            "{}",
            Messages::format(msgs.workspace_processing_member, &[&member.name])
        );

        let lockfile_reader =
            MemberScopedLockfileReader::new(workspace_root.clone(), member.name.clone());
        let use_case = build_use_case(lockfile_reader, locale, &merged)?;

        let request = build_sbom_request(
            member.absolute_path.clone(),
            &merged,
            workspace_exclude_groups.clone(),
            false,
            false,
            CliOnlyRequestOptions {
                // --explain is conflicts_with = "workspace"; clap rejects the
                // combination at parse time, so this is provably always None here.
                explain_package: None,
                show_dependency_tree: args.show_dependency_tree,
                dependency_tree_depth: args.dependency_tree_depth,
            },
            locale,
        )?;

        let response = use_case.execute(request).await?;

        member_findings.push(MemberFindings::from_response(&member.name, &response));

        let output_path = member.absolute_path.join(format!("sbom.{}", format_ext));
        let presenter_type = PresenterType::File(output_path.clone());

        let _has_issues =
            render_and_present(response, None, presenter_type, merged.format, false, locale)
                .await?;

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

    let enabled_checks = EnabledChecks::from_merged(&merged);
    let aggregate_lines = render_workspace_aggregate(&member_findings, &enabled_checks, msgs);
    if !aggregate_lines.is_empty() {
        eprintln!();
        for line in aggregate_lines {
            eprintln!("{}", line);
        }
    }

    Ok(())
}

/// Runs --diff mode: compares the current uv.lock against a base source.
///
/// Returns `Ok(true)` if vulnerabilities were detected in new/updated packages
/// and CVE checking is enabled, `Ok(false)` otherwise.
async fn run_diff(args: Args, source: DiffSource) -> Result<bool> {
    display_banner();

    let locale = args.lang;
    let project_dir = args.path.as_deref().unwrap_or(".");
    let project_path = PathBuf::from(project_dir);
    validate_project_path(&project_path)?;

    let config = load_config(&args, &project_path, locale)?;
    let merged = merge_config(&args, &config)?;

    let check_cve = merged.check_cve;
    let request = DiffRequest {
        source,
        project_path: project_path.clone(),
        check_cve,
        severity_threshold: merged.severity_threshold,
        cvss_threshold: merged.cvss_threshold,
    };

    let vulnerability_repository = if check_cve {
        Some(OsvClient::new(locale)?)
    } else {
        None
    };
    let use_case = GenerateDiffUseCase::new(
        FileSystemReader::new(),
        GitLockfileReader::new(),
        vulnerability_repository,
        locale,
    );
    let result = use_case.execute(request).await?;
    let diff = &result.diff;
    let cve_delta = result.cve_delta.as_ref();

    let formatted = match merged.format {
        OutputFormat::Markdown => DiffMarkdownFormatter::new(locale).format(diff, cve_delta),
        OutputFormat::Json => DiffJsonFormatter::new().format(diff, cve_delta)?,
    };

    let presenter_type = if let Some(output_path) = args.output {
        PresenterType::File(PathBuf::from(output_path))
    } else {
        PresenterType::Stdout
    };
    let presenter = PresenterFactory::create(presenter_type, locale);
    presenter.present(&formatted)?;

    Ok(check_cve && cve_delta.is_some_and(|d| !d.new.is_empty()))
}
