/// Data Transfer Objects for application layer
///
/// DTOs are used to transfer data between the application layer
/// and adapters, keeping the domain layer isolated.
mod sbom_request;
mod sbom_response;

pub use sbom_request::SbomRequest;
pub use sbom_response::SbomResponse;
