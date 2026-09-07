/// Use cases module containing application business logic orchestration
mod check_abandoned_packages;
mod check_python_compatibility;
mod check_vulnerabilities;
mod fetch_licenses;
mod generate_diff;
mod generate_sbom;
mod progress_bar;
mod simulate_upgrades;

#[cfg(test)]
pub(crate) mod test_doubles;

pub use check_abandoned_packages::CheckAbandonedPackagesUseCase;
pub use check_python_compatibility::CheckPythonCompatibilityUseCase;
pub use check_vulnerabilities::CheckVulnerabilitiesUseCase;
pub use fetch_licenses::FetchLicensesUseCase;
pub use generate_diff::GenerateDiffUseCase;
pub use generate_sbom::GenerateSbomUseCase;
pub use simulate_upgrades::SimulateUpgradesUseCase;
