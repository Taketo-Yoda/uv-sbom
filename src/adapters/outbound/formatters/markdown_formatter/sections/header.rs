use crate::i18n::Messages;

/// Renders the SBOM header section into `output`.
pub(in super::super) fn render(messages: &'static Messages, output: &mut String) {
    output.push_str(messages.section_sbom_title);
    output.push_str("\n\n");
}
