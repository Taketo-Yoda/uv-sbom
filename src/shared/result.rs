/// Type alias for Result with anyhow::Error as the error type.
/// This provides a consistent error handling pattern across the codebase.
pub type Result<T> = std::result::Result<T, anyhow::Error>;
