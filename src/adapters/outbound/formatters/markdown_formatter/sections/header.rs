use crate::i18n::Messages;

/// Renders the SBOM header section into `output`.
pub(in super::super) fn render(messages: &'static Messages, output: &mut String) {
    output.push_str(messages.section_sbom_title);
    output.push_str("\n\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Locale;

    #[test]
    fn test_title_en() {
        let msgs = Messages::for_locale(Locale::En);
        let mut output = String::new();
        render(msgs, &mut output);
        assert!(output.contains("# Software Bill of Materials (SBOM)"));
        assert!(!output.contains("ソフトウェア部品表"));
    }

    #[test]
    fn test_title_ja() {
        let msgs = Messages::for_locale(Locale::Ja);
        let mut output = String::new();
        render(msgs, &mut output);
        assert!(output.contains("# ソフトウェア部品表 (SBOM)"));
        assert!(!output.contains("# Software Bill of Materials (SBOM)"));
    }
}
