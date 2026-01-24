/// Data Transfer Objects for application layer
///
/// DTOs are used to transfer data between the application layer
/// and adapters, keeping the domain layer isolated.
mod output_format;
mod sbom_request;
mod sbom_response;

pub use output_format::OutputFormat;
#[allow(unused_imports)]
pub use sbom_request::{SbomRequest, SbomRequestBuilder};
pub use sbom_response::SbomResponse;
