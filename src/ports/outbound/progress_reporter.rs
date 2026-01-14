/// Progress callback for operations that need to report progress
///
/// This is a generic callback type that can be used by any operation
/// that needs to report progress updates. It follows the Observer pattern
/// to decouple progress reporting from the operation itself.
///
/// # Arguments
/// * `current` - Current progress value (e.g., items processed)
/// * `total` - Total expected value (e.g., total items to process)
///
/// # Example
/// ```ignore
/// let callback: ProgressCallback = Box::new(|current, total| {
///     println!("Progress: {}/{}", current, total);
/// });
/// callback(5, 10); // Prints: Progress: 5/10
/// ```
pub type ProgressCallback<'a> = Box<dyn Fn(usize, usize) + 'a>;

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
