use std::path::Path;
use uv_sbom::prelude::*;

/// Mock LockfileReader for testing
pub struct MockLockfileReader {
    pub content: String,
    pub should_fail: bool,
}

impl MockLockfileReader {
    pub fn new(content: String) -> Self {
        Self {
            content,
            should_fail: false,
        }
    }

    pub fn with_failure() -> Self {
        Self {
            content: String::new(),
            should_fail: true,
        }
    }
}

impl LockfileReader for MockLockfileReader {
    fn read_lockfile(&self, _project_path: &Path) -> Result<String> {
        if self.should_fail {
            anyhow::bail!("Mock lockfile read failure");
        }
        Ok(self.content.clone())
    }
}
