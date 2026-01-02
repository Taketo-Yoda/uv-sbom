use crate::ports::outbound::ProgressReporter;

/// StderrProgressReporter adapter for reporting progress to stderr
///
/// This adapter implements the ProgressReporter port, writing progress
/// information to stderr so it doesn't interfere with stdout output.
pub struct StderrProgressReporter;

impl StderrProgressReporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StderrProgressReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressReporter for StderrProgressReporter {
    fn report(&self, message: &str) {
        eprintln!("{}", message);
    }

    fn report_progress(&self, current: usize, total: usize, message: Option<&str>) {
        let msg = message.unwrap_or("");
        eprint!(
            "\r   Progress: {}/{} ({:.1}%) - {}",
            current,
            total,
            (current as f64 / total as f64) * 100.0,
            msg
        );
    }

    fn report_error(&self, message: &str) {
        eprintln!("\n{}", message);
    }

    fn report_completion(&self, message: &str) {
        eprintln!();
        eprintln!("{}", message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_reporter_creation() {
        let reporter = StderrProgressReporter::new();
        // Can't easily test stderr output, but verify it doesn't panic
        reporter.report("Test message");
        reporter.report_progress(5, 10, Some("test"));
        reporter.report_error("Test error");
        reporter.report_completion("Test completion");
    }

    #[test]
    fn test_progress_reporter_default() {
        let reporter = StderrProgressReporter;
        reporter.report("Test message");
    }
}
