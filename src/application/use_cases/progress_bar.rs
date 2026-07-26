use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// A background-thread-driven progress bar shared by use cases that fetch
/// per-package data (sequentially or concurrently) and want a live progress
/// display without blocking the fetch loop on terminal I/O.
///
/// The bar polls an `AtomicUsize` counter on a separate OS thread every 50ms;
/// callers advance the counter as each item completes and call [`Self::finish`]
/// once all work is done.
pub(super) struct ProgressBarHandle {
    current: Arc<AtomicUsize>,
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ProgressBarHandle {
    /// Spawns the progress bar thread. `message` is an internal, untranslated
    /// progress-bar label (never shown as a formal user-facing message).
    pub(super) fn spawn(total: usize, message: &'static str) -> Self {
        let current = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicBool::new(false));

        let thread = {
            let cur = current.clone();
            let done = done.clone();
            thread::spawn(move || {
                let pb = ProgressBar::new(total as u64);
                pb.set_style(
                    ProgressStyle::default_bar()
                        .template("   {spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} - {msg}")
                        .expect("Failed to set progress bar template")
                        .progress_chars("=>-"),
                );
                pb.set_message(message);
                while !done.load(Ordering::Relaxed) {
                    pb.set_position(cur.load(Ordering::Relaxed) as u64);
                    thread::sleep(Duration::from_millis(50));
                }
                pb.finish_and_clear();
            })
        };

        Self {
            current,
            done,
            thread: Some(thread),
        }
    }

    /// Returns a clonable handle to the position counter; callers advance it
    /// (e.g. via `fetch_add`/`store`) as items complete.
    pub(super) fn counter(&self) -> Arc<AtomicUsize> {
        self.current.clone()
    }

    /// Signals the bar to stop and blocks until its thread has finished
    /// clearing the terminal line.
    pub(super) fn finish(mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
