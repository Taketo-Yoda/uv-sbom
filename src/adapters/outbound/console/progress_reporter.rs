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

    fn report_error(&self, message: &str) {
        eprintln!("{}", message);
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
        reporter.report_error("Test error");
        reporter.report_completion("Test completion");
    }

    #[test]
    fn test_progress_reporter_default() {
        let reporter: StderrProgressReporter = Default::default();
        reporter.report("Test message");
    }
}
