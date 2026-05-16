/// Filesystem adapters for file I/O operations
mod file_reader;
mod file_writer;
mod git_lockfile_reader;
mod lockfile_parser;

pub use file_reader::FileSystemReader;
pub use file_writer::{FileSystemWriter, StdoutPresenter};
// Note: Will be used in a subsequent CLI integration subtask of the dependency-diff feature (#224)
#[allow(unused_imports)]
pub use git_lockfile_reader::{determine_diff_source, GitLockfileReader};
