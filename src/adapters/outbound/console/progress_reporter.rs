use crate::i18n::Locale;
use crate::ports::outbound::ProgressReporter;

/// StderrProgressReporter adapter for reporting progress to stderr
///
/// This adapter implements the ProgressReporter port, writing progress
/// information to stderr so it doesn't interfere with stdout output.
/// The reporter emits messages as-is; locale-aware string selection is
/// handled by the caller.
pub struct StderrProgressReporter;

impl StderrProgressReporter {
    pub fn new(_locale: Locale) -> Self {
        Self
    }
}

impl Default for StderrProgressReporter {
    fn default() -> Self {
        Self::new(Locale::En)
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
    use crate::i18n::Locale;

    #[test]
    fn test_progress_reporter_creation() {
        let reporter = StderrProgressReporter::new(Locale::En);
        // Can't easily test stderr output, but verify it doesn't panic
        reporter.report("Test message");
        reporter.report_error("Test error");
        reporter.report_completion("Test completion");
    }

    #[test]
    fn test_progress_reporter_creation_ja() {
        let reporter = StderrProgressReporter::new(Locale::Ja);
        reporter.report("テストメッセージ");
    }

    #[test]
    fn test_progress_reporter_default() {
        let reporter: StderrProgressReporter = Default::default();
        reporter.report("Test message");
    }
}
