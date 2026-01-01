/// ProgressReporter port for reporting progress during operations
///
/// This port abstracts progress reporting (e.g., to stderr)
/// to provide user feedback during long-running operations.
pub trait ProgressReporter {
    /// Reports a progress message
    ///
    /// # Arguments
    /// * `message` - The progress message to report
    fn report(&self, message: &str);

    /// Reports progress with a percentage
    ///
    /// # Arguments
    /// * `current` - Current progress value
    /// * `total` - Total expected value
    /// * `message` - Optional message to include
    fn report_progress(&self, current: usize, total: usize, message: Option<&str>);

    /// Reports an error or warning message
    ///
    /// # Arguments
    /// * `message` - The error/warning message
    fn report_error(&self, message: &str);

    /// Reports completion of an operation
    ///
    /// # Arguments
    /// * `message` - Completion message
    fn report_completion(&self, message: &str);
}
