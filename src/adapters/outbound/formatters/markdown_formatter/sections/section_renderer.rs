use crate::application::read_models::SbomReadModel;
use crate::i18n::Messages;

/// Common interface for section renderers in the `sections` module.
///
/// Each section renderer takes a read model and a message catalog and returns
/// a rendered Markdown string. Concrete implementations will be introduced in
/// subsequent subtasks (#428, #429) as the remaining functions are moved out of
/// `section.rs`.
#[allow(dead_code)] // Scaffold for subtasks #428 and #429; implementations pending.
pub(super) trait SectionRenderer {
    fn render(&self, model: &SbomReadModel, messages: &'static Messages) -> String;
}
