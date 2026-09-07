use crate::application::read_models::ExplainView;
use crate::i18n::Messages;

/// Renders the `--explain` dependency explanation section.
///
/// Like `python_compatibility`, callers do NOT need to pre-check anything:
/// all three `ExplainView` states (transitive-with-paths, direct dependency,
/// not found) are meaningful and each renders its own body under a single
/// shared `## Dependency Explanation` heading. The caller only decides
/// `Some` vs `None`.
///
/// `is_direct` and `paths.is_empty()` are branched on directly rather than
/// `view.found` — `found` is derived as `is_direct || !paths.is_empty()`
/// (see `ExplainView` doc comment), so branching on it here would make this
/// function's correctness depend on that derivation staying in sync.
pub(in super::super) fn render(
    messages: &'static Messages,
    output: &mut String,
    view: &ExplainView,
) {
    output.push('\n');
    output.push_str(messages.section_explain);
    output.push_str("\n\n");

    if !view.found {
        output.push_str(&Messages::format(
            messages.summary_explain_not_found,
            &[&sanitize_target(&view.target_package)],
        ));
        output.push('\n');
        return;
    }

    if view.is_direct {
        output.push_str(&Messages::format(
            messages.summary_explain_direct,
            &[&view.target_package],
        ));
        output.push('\n');

        if !view.paths.is_empty() {
            output.push('\n');
            output.push_str(&Messages::format(
                messages.summary_explain_also_transitive,
                &[&view.paths.len().to_string()],
            ));
            output.push_str("\n\n");
            render_bullets(output, &view.paths);
        }
    } else if !view.paths.is_empty() {
        output.push_str(&Messages::format(
            messages.summary_explain_paths,
            &[&view.target_package, &view.paths.len().to_string()],
        ));
        output.push_str("\n\n");
        render_bullets(output, &view.paths);
    }

    output.push('\n');
}

/// Renders each path as a bullet, wrapping each package name in backticks —
/// matching the existing Dependency Chains subsection's path notation
/// (`resolution_guide.rs`) rather than the plain `a → b` example in the
/// originating Issue, so path notation stays consistent across the document.
fn render_bullets(output: &mut String, paths: &[Vec<String>]) {
    for path in paths {
        let rendered = path
            .iter()
            .map(|node| format!("`{node}`"))
            .collect::<Vec<_>>()
            .join(" → ");
        output.push_str(&format!("- {rendered}\n"));
    }
}

/// Strips characters that could break out of the surrounding Markdown when
/// rendering a not-found message: unlike path node names (which come from
/// validated `PackageName`s), `target_package` may carry the user's raw
/// `--explain` argument verbatim when it failed `PackageName` validation.
/// Covers newline/carriage-return (line breaks) and the CommonMark inline
/// syntax characters that could prematurely close the surrounding `**bold**`
/// span or inject a fake emphasis/link/HTML span into the generated document.
fn sanitize_target(target: &str) -> String {
    target.replace(['\n', '\r', '`', '*', '_', '[', ']', '<', '>'], "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{Locale, Messages};

    fn render_en(view: &ExplainView) -> String {
        let mut output = String::new();
        render(Messages::for_locale(Locale::En), &mut output, view);
        output
    }

    fn render_ja(view: &ExplainView) -> String {
        let mut output = String::new();
        render(Messages::for_locale(Locale::Ja), &mut output, view);
        output
    }

    fn transitive_view(paths: Vec<Vec<&str>>) -> ExplainView {
        ExplainView {
            target_package: "urllib3".to_string(),
            found: true,
            is_direct: false,
            paths: paths
                .into_iter()
                .map(|p| p.into_iter().map(str::to_string).collect())
                .collect(),
        }
    }

    #[test]
    fn test_transitive_single_path_en() {
        let view = transitive_view(vec![vec!["requests", "urllib3"]]);
        let output = render_en(&view);
        assert!(output.contains("## Dependency Explanation"));
        assert!(output.contains("**urllib3** is included via 1 path(s):"));
        assert!(output.contains("- `requests` → `urllib3`"));
    }

    #[test]
    fn test_transitive_diamond_multiple_paths_renders_all_bullets() {
        let view = transitive_view(vec![
            vec!["requests", "urllib3"],
            vec!["httpx", "httpcore", "urllib3"],
        ]);
        let output = render_en(&view);
        assert!(output.contains("**urllib3** is included via 2 path(s):"));
        assert!(output.contains("- `requests` → `urllib3`"));
        assert!(output.contains("- `httpx` → `httpcore` → `urllib3`"));
    }

    #[test]
    fn test_direct_dependency_only_en() {
        let view = ExplainView {
            target_package: "requests".to_string(),
            found: true,
            is_direct: true,
            paths: vec![],
        };
        let output = render_en(&view);
        assert!(output.contains("## Dependency Explanation"));
        assert!(output.contains("**requests** is a direct dependency of this project."));
        assert!(!output.contains("also reachable"));
        assert!(!output.contains("- `"));
    }

    #[test]
    fn test_direct_and_transitive_compound_case_shows_both() {
        let view = ExplainView {
            target_package: "urllib3".to_string(),
            found: true,
            is_direct: true,
            paths: vec![
                vec!["requests".to_string(), "urllib3".to_string()],
                vec![
                    "httpx".to_string(),
                    "httpcore".to_string(),
                    "urllib3".to_string(),
                ],
            ],
        };
        let output = render_en(&view);
        assert!(output.contains("**urllib3** is a direct dependency of this project."));
        assert!(output.contains("It is also reachable through 2 transitive path(s):"));
        assert!(output.contains("- `requests` → `urllib3`"));
        assert!(output.contains("- `httpx` → `httpcore` → `urllib3`"));
    }

    #[test]
    fn test_not_found_en() {
        let view = ExplainView {
            target_package: "nonexistent".to_string(),
            found: false,
            is_direct: false,
            paths: vec![],
        };
        let output = render_en(&view);
        assert!(output.contains("## Dependency Explanation"));
        assert!(output
            .contains("Package **nonexistent** was not found in this project's dependencies."));
    }

    #[test]
    fn test_not_found_sanitizes_raw_user_input() {
        let view = ExplainView {
            target_package: "evil`\ninjected".to_string(),
            found: false,
            is_direct: false,
            paths: vec![],
        };
        let output = render_en(&view);
        assert!(!output.contains('`'));
        assert!(!output.contains("evil`\ninjected"));
        assert!(output.contains("evilinjected"));
    }

    #[test]
    fn test_not_found_sanitizes_markdown_emphasis_and_link_syntax() {
        let view = ExplainView {
            target_package: "x** [click](javascript:evil) <script>".to_string(),
            found: false,
            is_direct: false,
            paths: vec![],
        };
        let output = render_en(&view);
        assert!(output.contains("Package **x click(javascript:evil) script** was not found"));
    }

    #[test]
    fn test_transitive_single_path_ja() {
        let view = transitive_view(vec![vec!["requests", "urllib3"]]);
        let output = render_ja(&view);
        assert!(output.contains("## 依存関係の説明"));
        assert!(output.contains("**urllib3** は 1 個の経路で含まれています:"));
        assert!(output.contains("- `requests` → `urllib3`"));
    }

    #[test]
    fn test_direct_dependency_only_ja() {
        let view = ExplainView {
            target_package: "requests".to_string(),
            found: true,
            is_direct: true,
            paths: vec![],
        };
        let output = render_ja(&view);
        assert!(output.contains("## 依存関係の説明"));
        assert!(output.contains("**requests** はこのプロジェクトの直接依存パッケージです。"));
    }

    #[test]
    fn test_not_found_ja() {
        let view = ExplainView {
            target_package: "nonexistent".to_string(),
            found: false,
            is_direct: false,
            paths: vec![],
        };
        let output = render_ja(&view);
        assert!(output.contains("## 依存関係の説明"));
        assert!(output.contains(
            "パッケージ **nonexistent** はこのプロジェクトの依存関係に見つかりませんでした。"
        ));
    }
}
