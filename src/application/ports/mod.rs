/// Application-owned output ports.
///
/// These are port traits that live in the application layer because their
/// signatures reference application-layer types (such as read models).
/// Infrastructure adapters implement these traits, which is valid because
/// adapters are allowed to depend on the application layer.
///
/// This is distinct from `crate::ports::outbound`, which holds port traits
/// whose signatures reference only domain-layer and shared types.
mod formatter;

pub use formatter::SbomFormatter;
