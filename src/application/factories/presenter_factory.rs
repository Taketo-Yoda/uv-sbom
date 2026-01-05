use crate::adapters::outbound::filesystem::{FileSystemWriter, StdoutPresenter};
use crate::ports::outbound::OutputPresenter;
use std::path::PathBuf;

/// Presenter type enumeration for factory pattern
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenterType {
    Stdout,
    File(PathBuf),
}

/// Factory for creating output presenters
///
/// This factory encapsulates the creation logic for different presenter implementations,
/// following the Factory Pattern. It belongs in the application layer as it orchestrates
/// the selection of infrastructure adapters based on application needs.
pub struct PresenterFactory;

impl PresenterFactory {
    /// Creates a presenter instance for the specified type
    ///
    /// # Arguments
    /// * `presenter_type` - The type of presenter to create
    ///
    /// # Returns
    /// A boxed OutputPresenter trait object appropriate for the specified type
    ///
    /// # Examples
    /// ```
    /// use uv_sbom::application::factories::{PresenterFactory, PresenterType};
    ///
    /// let presenter = PresenterFactory::create(PresenterType::Stdout);
    /// ```
    pub fn create(presenter_type: PresenterType) -> Box<dyn OutputPresenter> {
        match presenter_type {
            PresenterType::Stdout => Box::new(StdoutPresenter::new()),
            PresenterType::File(path) => Box::new(FileSystemWriter::new(path)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_stdout_presenter() {
        let presenter = PresenterFactory::create(PresenterType::Stdout);
        // Verify it doesn't panic when created
        assert!(std::mem::size_of_val(&presenter) > 0);
    }

    #[test]
    fn test_create_file_presenter() {
        let path = PathBuf::from("/tmp/test_output.json");
        let presenter = PresenterFactory::create(PresenterType::File(path));
        assert!(std::mem::size_of_val(&presenter) > 0);
    }

    #[test]
    fn test_presenter_type_equality() {
        let stdout1 = PresenterType::Stdout;
        let stdout2 = PresenterType::Stdout;
        assert_eq!(stdout1, stdout2);

        let file1 = PresenterType::File(PathBuf::from("/tmp/output1.json"));
        let file2 = PresenterType::File(PathBuf::from("/tmp/output1.json"));
        assert_eq!(file1, file2);

        let file3 = PresenterType::File(PathBuf::from("/tmp/output2.json"));
        assert_ne!(file1, file3);
    }

    #[test]
    fn test_presenter_type_clone() {
        let original = PresenterType::File(PathBuf::from("/tmp/test.json"));
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}
