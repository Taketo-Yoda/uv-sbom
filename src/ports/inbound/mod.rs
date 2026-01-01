/// Inbound ports (Driving ports) - Use case interfaces
///
/// These ports define the interfaces that external adapters (e.g., CLI)
/// use to interact with the application core.
pub mod sbom_generation_port;

pub use sbom_generation_port::SbomGenerationPort;
