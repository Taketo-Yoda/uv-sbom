/// uv CLI adapters for lock file simulation
mod uv_lock_adapter;
mod workspace_reader;

// Note: Will be used in a subsequent subtask for uv lock simulation
#[allow(unused_imports)]
pub use uv_lock_adapter::UvLockAdapter;
// Note: Will be used in a subsequent subtask for workspace detection
#[allow(unused_imports)]
pub use workspace_reader::UvWorkspaceReader;
