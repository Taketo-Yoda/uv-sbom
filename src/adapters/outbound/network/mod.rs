/// Network adapters for external API calls
mod caching_pypi_client;
mod epss_kev_client;
mod osv_client;
mod pypi_client;
mod pypi_compatibility_client;
mod pypi_maintenance_client;
#[allow(dead_code)] // WIRE(#968): remove when --incident is wired into main.rs
mod pypi_release_client;

pub use caching_pypi_client::CachingPyPiLicenseRepository;
pub use epss_kev_client::EpssKevClient;
pub use osv_client::OsvClient;
pub use pypi_client::PyPiLicenseRepository;
pub use pypi_compatibility_client::PyPiCompatibilityClient;
pub use pypi_maintenance_client::PyPiMaintenanceRepository;
#[allow(unused_imports)] // WIRE(#968): remove when --incident is wired into main.rs
pub use pypi_release_client::PyPiReleaseClient;
