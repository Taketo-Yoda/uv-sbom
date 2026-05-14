/// Filesystem adapters for file I/O operations
mod file_reader;
mod file_writer;
mod lockfile_parser;

pub use file_reader::FileSystemReader;
pub use file_writer::{FileSystemWriter, StdoutPresenter};
