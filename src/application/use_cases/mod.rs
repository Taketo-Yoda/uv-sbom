/// Use cases module containing application business logic orchestration
mod check_abandoned_packages;
mod check_python_compatibility;
mod check_vulnerabilities;
mod fetch_licenses;
mod generate_diff;
mod generate_sbom;
mod progress_bar;

#[cfg(test)]
pub(crate) mod test_doubles;

pub use check_abandoned_packages::CheckAbandonedPackagesUseCase;
#[allow(unused_imports)] // WIRE(#681): remove when wired into GenerateSbomUseCase and main.rs
pub use check_python_compatibility::CheckPythonCompatibilityUseCase;
pub use check_vulnerabilities::CheckVulnerabilitiesUseCase;
pub use fetch_licenses::FetchLicensesUseCase;
pub use generate_diff::GenerateDiffUseCase;
pub use generate_sbom::GenerateSbomUseCase;
