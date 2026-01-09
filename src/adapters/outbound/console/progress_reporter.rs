use crate::ports::outbound::ProgressReporter;
use indicatif::{ProgressBar, ProgressStyle};
use std::cell::RefCell;

/// StderrProgressReporter adapter for reporting progress to stderr
///
/// This adapter implements the ProgressReporter port, writing progress
/// information to stderr so it doesn't interfere with stdout output.
/// Uses indicatif for rich progress bar display.
pub struct StderrProgressReporter {
    progress_bar: RefCell<Option<ProgressBar>>,
}

impl StderrProgressReporter {
    pub fn new() -> Self {
        Self {
            progress_bar: RefCell::new(None),
        }
    }

    fn get_or_create_progress_bar(&self, total: usize) -> ProgressBar {
        let mut pb_option = self.progress_bar.borrow_mut();
        if let Some(pb) = pb_option.as_ref() {
            pb.clone()
        } else {
            let pb = ProgressBar::new(total as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template(
                        "   {spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) - {msg}",
                    )
                    .expect("Failed to set progress bar template")
                    .progress_chars("=>-"),
            );
            *pb_option = Some(pb.clone());
            pb
        }
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
        let pb = self.get_or_create_progress_bar(total);
        pb.set_position(current as u64);
        if let Some(msg) = message {
            pb.set_message(msg.to_string());
        }
    }

    fn report_error(&self, message: &str) {
        // Finish progress bar if it exists
        if let Some(pb) = self.progress_bar.borrow().as_ref() {
            pb.finish_and_clear();
        }
        eprintln!("{}", message);
    }

    fn report_completion(&self, message: &str) {
        // Finish progress bar if it exists
        if let Some(pb) = self.progress_bar.borrow().as_ref() {
            pb.finish_and_clear();
        }
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
        let reporter = StderrProgressReporter::default();
        reporter.report("Test message");
    }
}
