use crate::sbom_generation::domain::baseline::VulnerabilityBaseline;
use crate::shared::Result;
use std::path::Path;

/// Outbound port for loading and saving a vulnerability baseline.
///
/// Implementations handle the file format and I/O safety checks
/// (symlink rejection, size validation). The use case decides how to
/// handle a missing file (e.g. warn and proceed with an empty baseline).
#[allow(dead_code)] // WIRE(#938): remove when --baseline is wired into GenerateSbomUseCase
pub trait BaselineRepository {
    /// Loads a baseline from `path`.
    ///
    /// Returns `Ok(None)` when no file exists at `path`, so the caller
    /// can warn (in the appropriate locale) and substitute an empty baseline.
    fn load(&self, path: &Path) -> Result<Option<VulnerabilityBaseline>>;

    /// Saves a baseline to `path`.
    fn save(&self, path: &Path, baseline: &VulnerabilityBaseline) -> Result<()>;
}

/// No-op implementation for when the baseline feature is not active.
#[allow(dead_code)] // WIRE(#938): remove when --baseline is wired into GenerateSbomUseCase
impl BaselineRepository for () {
    fn load(&self, _path: &Path) -> Result<Option<VulnerabilityBaseline>> {
        Ok(None)
    }

    fn save(&self, _path: &Path, _baseline: &VulnerabilityBaseline) -> Result<()> {
        Ok(())
    }
}
