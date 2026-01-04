//! uv-sbom - SBOM generation tool for uv projects
//!
//! This library provides functionality to generate Software Bill of Materials (SBOM)
//! from uv.lock files, following hexagonal architecture and Domain-Driven Design principles.
//!
//! # Architecture
//!
//! The library is organized into the following layers:
//!
//! - **Domain Layer** (`sbom_generation`): Pure business logic and domain models
//! - **Application Layer** (`application`): Use cases and application services
//! - **Ports** (`ports`): Interface definitions for infrastructure
//! - **Adapters** (`adapters`): Concrete implementations of ports
//! - **Shared** (`shared`): Common utilities and error types
//!
//! # Example
//!
//! ```no_run
//! use uv_sbom::prelude::*;
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<()> {
//! // Create adapters
//! let lockfile_reader = FileSystemReader::new();
//! let project_config_reader = FileSystemReader::new();
//! let license_repository = PyPiLicenseRepository::new()?;
//! let progress_reporter = StderrProgressReporter::new();
//!
//! // Create use case
//! let use_case = GenerateSbomUseCase::new(
//!     lockfile_reader,
//!     project_config_reader,
//!     license_repository,
//!     progress_reporter,
//! );
//!
//! // Execute
//! let request = SbomRequest::new(PathBuf::from("."), false, vec![]);
//! let response = use_case.execute(request)?;
//!
//! // Format output
//! let formatter = CycloneDxFormatter::new();
//! let output = formatter.format(response.enriched_packages, &response.metadata)?;
//! println!("{}", output);
//! # Ok(())
//! # }
//! ```

pub mod adapters;
pub mod application;
pub mod ports;
pub mod sbom_generation;
pub mod shared;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::adapters::outbound::console::StderrProgressReporter;
    pub use crate::adapters::outbound::filesystem::{
        FileSystemReader, FileSystemWriter, StdoutPresenter,
    };
    pub use crate::adapters::outbound::formatters::{CycloneDxFormatter, MarkdownFormatter};
    pub use crate::adapters::outbound::network::PyPiLicenseRepository;
    pub use crate::application::dto::{SbomRequest, SbomResponse};
    pub use crate::application::use_cases::GenerateSbomUseCase;
    pub use crate::ports::outbound::{
        EnrichedPackage, LicenseRepository, LockfileParseResult, LockfileReader, OutputPresenter,
        ProgressReporter, ProjectConfigReader, SbomFormatter,
    };
    pub use crate::sbom_generation::domain::{
        DependencyGraph, LicenseInfo, Package, PackageName, SbomMetadata,
    };
    pub use crate::sbom_generation::policies::LicensePriority;
    pub use crate::sbom_generation::services::{DependencyAnalyzer, SbomGenerator};
    pub use crate::shared::Result;
}
