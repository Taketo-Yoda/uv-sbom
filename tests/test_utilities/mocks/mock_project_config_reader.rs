use std::path::Path;
use uv_sbom::prelude::*;

/// Mock ProjectConfigReader for testing
pub struct MockProjectConfigReader {
    pub project_name: String,
    pub should_fail: bool,
}

impl MockProjectConfigReader {
    pub fn new(project_name: String) -> Self {
        Self {
            project_name,
            should_fail: false,
        }
    }

    pub fn with_failure() -> Self {
        Self {
            project_name: String::new(),
            should_fail: true,
        }
    }
}

impl ProjectConfigReader for MockProjectConfigReader {
    fn read_project_name(&self, _project_path: &Path) -> Result<String> {
        if self.should_fail {
            anyhow::bail!("Mock project config read failure");
        }
        Ok(self.project_name.clone())
    }
}
