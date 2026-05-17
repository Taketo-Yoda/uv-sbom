/// Data Transfer Objects for application layer
///
/// DTOs are used to transfer data between the application layer
/// and adapters, keeping the domain layer isolated.
mod diff_request;
mod output_format;
mod sbom_request;
mod sbom_response;

// Note: Will be wired to the binary in a subsequent CLI integration subtask of #224.
#[allow(unused_imports)]
pub use diff_request::DiffRequest;
pub use output_format::OutputFormat;
#[allow(unused_imports)]
pub use sbom_request::{SbomRequest, SbomRequestBuilder};
pub use sbom_response::SbomResponse;
