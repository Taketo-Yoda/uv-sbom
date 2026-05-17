/// Data Transfer Objects for application layer
///
/// DTOs are used to transfer data between the application layer
/// and adapters, keeping the domain layer isolated.
mod diff_request;
mod output_format;
mod sbom_request;
mod sbom_response;

pub use diff_request::DiffRequest;
pub use output_format::OutputFormat;
pub use sbom_request::SbomRequest;
#[allow(unused_imports)]
pub use sbom_request::SbomRequestBuilder;
pub use sbom_response::SbomResponse;
