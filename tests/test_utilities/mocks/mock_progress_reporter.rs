use uv_sbom::prelude::*;

/// Mock ProgressReporter for testing that captures messages
#[derive(Default, Clone)]
pub struct MockProgressReporter {
    pub messages: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl MockProgressReporter {
    pub fn new() -> Self {
        Self {
            messages: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn get_messages(&self) -> Vec<String> {
        self.messages.lock().unwrap().clone()
    }

    pub fn message_count(&self) -> usize {
        self.messages.lock().unwrap().len()
    }
}

impl ProgressReporter for MockProgressReporter {
    fn report(&self, message: &str) {
        self.messages.lock().unwrap().push(message.to_string());
    }

    fn report_progress(&self, current: usize, total: usize, message: Option<&str>) {
        let msg = if let Some(m) = message {
            format!("Progress: {}/{} - {}", current, total, m)
        } else {
            format!("Progress: {}/{}", current, total)
        };
        self.messages.lock().unwrap().push(msg);
    }

    fn report_error(&self, message: &str) {
        self.messages
            .lock()
            .unwrap()
            .push(format!("Error: {}", message));
    }

    fn report_completion(&self, message: &str) {
        self.messages
            .lock()
            .unwrap()
            .push(format!("Completed: {}", message));
    }
}
