/// Network adapters for external API calls
mod osv_client;
mod pypi_client;

// Note: This will be used in subsequent subtasks for CVE check feature
#[allow(unused_imports)]
pub use osv_client::OsvClient;
pub use pypi_client::PyPiLicenseRepository;
