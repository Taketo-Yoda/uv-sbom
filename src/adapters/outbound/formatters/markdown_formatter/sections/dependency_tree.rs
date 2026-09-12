use crate::application::read_models::{DependencyTreeNodeView, DependencyTreeView};
use crate::i18n::Messages;

/// Renders the `--show-dependency-tree` visualization as an ASCII-connector tree.
///
/// Like `explain` and `python_compatibility`, callers do NOT need to pre-check
/// anything: an empty `roots` list is a meaningful "no direct dependencies"
/// result and renders its own placeholder line. The caller only decides
/// `Some` vs `None`.
///
/// The tree body is wrapped in a fenced ` ```text ` code block. Under
/// CommonMark, consecutive non-blank lines collapse into a single paragraph
/// and box-drawing indentation would be destroyed without a fence — this is
/// required for the connectors to render at all, not a style choice.
///
/// Package names are emitted verbatim, with no Markdown escaping: unlike
/// `--explain`'s `target_package` (which may carry a raw, unvalidated CLI
/// argument), every name here comes from `PackageName`, which rejects
/// backticks, newlines, and every other character that could break out of
/// the surrounding fence (see `sbom_generation::domain::package`).
pub(in super::super) fn render(
    messages: &'static Messages,
    output: &mut String,
    view: &DependencyTreeView,
) {
    output.push('\n');
    output.push_str(messages.section_dependency_tree);
    output.push_str("\n\n");

    if view.roots.is_empty() {
        output.push_str(messages.label_dependency_tree_empty);
        output.push('\n');
        return;
    }

    output.push_str("```text\n");
    let mut any_truncated = false;
    let last_index = view.roots.len() - 1;
    for (i, root) in view.roots.iter().enumerate() {
        render_node(
            messages,
            output,
            root,
            "",
            i == last_index,
            &mut any_truncated,
        );
    }
    output.push_str("```\n");

    if any_truncated {
        output.push('\n');
        output.push_str(&Messages::format(
            messages.note_dependency_tree_truncated,
            &[&view.max_depth.to_string()],
        ));
        output.push('\n');
    }

    output.push('\n');
}

/// Recursively renders one node and its children.
///
/// `prefix` is the accumulated indentation contributed by all ancestors: a
/// non-last ancestor contributes `"│   "` (the rail continues past it),
/// a last ancestor contributes `"    "` (nothing follows it, so no rail).
/// `is_last` decides this node's own connector (`└── ` vs `├── `) and the
/// prefix it hands down to its own children.
///
/// A `truncated` node is treated as one extra trailing pseudo-child so that
/// last-sibling bookkeeping (and therefore connector choice) stays correct
/// in one place. Today `DependencyTreeBuilder` only sets `truncated` on
/// childless nodes, so this can never actually compete with a real child for
/// "last" — but computing it this way costs nothing and stays correct if
/// that invariant ever changes.
fn render_node(
    messages: &'static Messages,
    output: &mut String,
    node: &DependencyTreeNodeView,
    prefix: &str,
    is_last: bool,
    any_truncated: &mut bool,
) {
    let connector = if is_last { "└── " } else { "├── " };
    output.push_str(prefix);
    output.push_str(connector);
    output.push_str(&node_label(node));
    output.push('\n');

    let child_prefix = format!("{prefix}{}", if is_last { "    " } else { "│   " });

    let total_entries = node.children.len() + usize::from(node.truncated);
    for (i, child) in node.children.iter().enumerate() {
        render_node(
            messages,
            output,
            child,
            &child_prefix,
            i + 1 == total_entries,
            any_truncated,
        );
    }

    if node.truncated {
        *any_truncated = true;
        output.push_str(&child_prefix);
        output.push_str("└── ");
        output.push_str(messages.label_dependency_tree_truncated);
        output.push('\n');
    }
}

/// `"name (version)"`, or bare `name` when the version could not be resolved
/// (e.g. the package was excluded by a filter that ran before this view was
/// built — see `DependencyTreeNodeView`'s doc comment).
fn node_label(node: &DependencyTreeNodeView) -> String {
    match &node.version {
        Some(version) => format!("{} ({})", node.name, version),
        None => node.name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{Locale, Messages};

    fn render_en(view: &DependencyTreeView) -> String {
        let mut output = String::new();
        render(Messages::for_locale(Locale::En), &mut output, view);
        output
    }

    fn render_ja(view: &DependencyTreeView) -> String {
        let mut output = String::new();
        render(Messages::for_locale(Locale::Ja), &mut output, view);
        output
    }

    fn leaf(name: &str, version: &str) -> DependencyTreeNodeView {
        DependencyTreeNodeView {
            name: name.to_string(),
            version: Some(version.to_string()),
            children: Vec::new(),
            truncated: false,
        }
    }

    #[test]
    fn test_empty_roots_renders_placeholder_en() {
        let view = DependencyTreeView {
            roots: vec![],
            max_depth: 3,
        };
        let output = render_en(&view);
        assert!(output.contains("## Dependency Tree"));
        assert!(output.contains("_No direct dependencies found._"));
        assert!(!output.contains("```"));
    }

    #[test]
    fn test_empty_roots_renders_placeholder_ja() {
        let view = DependencyTreeView {
            roots: vec![],
            max_depth: 3,
        };
        let output = render_ja(&view);
        assert!(output.contains("## 依存関係ツリー"));
        assert!(output.contains("_直接依存パッケージが見つかりません。_"));
    }

    #[test]
    fn test_single_root_leaf_wrapped_in_fence() {
        let view = DependencyTreeView {
            roots: vec![leaf("requests", "2.31.0")],
            max_depth: 3,
        };
        let output = render_en(&view);
        assert!(output.contains("```text\n└── requests (2.31.0)\n```\n"));
    }

    #[test]
    fn test_two_roots_use_branch_and_last_connectors() {
        let view = DependencyTreeView {
            roots: vec![leaf("requests", "2.31.0"), leaf("httpx", "0.27.0")],
            max_depth: 3,
        };
        let output = render_en(&view);
        assert!(output.contains("├── requests (2.31.0)\n└── httpx (0.27.0)\n"));
    }

    #[test]
    fn test_nested_children_prefix_accumulation() {
        let view = DependencyTreeView {
            roots: vec![DependencyTreeNodeView {
                name: "requests".to_string(),
                version: Some("2.31.0".to_string()),
                children: vec![
                    leaf("urllib3", "2.0.7"),
                    leaf("certifi", "2024.2.2"),
                    leaf("idna", "3.6"),
                ],
                truncated: false,
            }],
            max_depth: 3,
        };
        let output = render_en(&view);
        let expected = "\
└── requests (2.31.0)
    ├── urllib3 (2.0.7)
    ├── certifi (2024.2.2)
    └── idna (3.6)
";
        assert!(output.contains(expected));
    }

    #[test]
    fn test_diamond_style_two_roots_with_deep_nesting() {
        // Mirrors the Issue's example shape: two roots, one with a deeper chain.
        let view = DependencyTreeView {
            roots: vec![
                DependencyTreeNodeView {
                    name: "requests".to_string(),
                    version: Some("2.31.0".to_string()),
                    children: vec![
                        leaf("urllib3", "2.0.7"),
                        leaf("certifi", "2024.2.2"),
                        leaf("idna", "3.6"),
                    ],
                    truncated: false,
                },
                DependencyTreeNodeView {
                    name: "httpx".to_string(),
                    version: Some("0.27.0".to_string()),
                    children: vec![
                        DependencyTreeNodeView {
                            name: "httpcore".to_string(),
                            version: Some("1.0.4".to_string()),
                            children: vec![],
                            truncated: true,
                        },
                        leaf("anyio", "4.3.0"),
                    ],
                    truncated: false,
                },
            ],
            max_depth: 2,
        };
        let output = render_en(&view);
        let expected = "\
├── requests (2.31.0)
│   ├── urllib3 (2.0.7)
│   ├── certifi (2024.2.2)
│   └── idna (3.6)
└── httpx (0.27.0)
    ├── httpcore (1.0.4)
    │   └── ... (truncated)
    └── anyio (4.3.0)
";
        assert!(output.contains(expected));
        assert!(output.contains("_Tree truncated at depth 2."));
    }

    #[test]
    fn test_truncation_note_absent_when_nothing_truncated() {
        let view = DependencyTreeView {
            roots: vec![leaf("requests", "2.31.0")],
            max_depth: 3,
        };
        let output = render_en(&view);
        assert!(!output.contains("truncated"));
    }

    #[test]
    fn test_truncated_leaf_renders_marker_as_last_child() {
        let view = DependencyTreeView {
            roots: vec![DependencyTreeNodeView {
                name: "requests".to_string(),
                version: Some("2.31.0".to_string()),
                children: vec![],
                truncated: true,
            }],
            max_depth: 0,
        };
        let output = render_en(&view);
        assert!(output.contains("└── requests (2.31.0)\n    └── ... (truncated)\n"));
        assert!(output.contains(
            "_Tree truncated at depth 0. Use `--dependency-tree-depth <DEPTH>` to show more levels._"
        ));
    }

    #[test]
    fn test_node_with_unresolved_version_renders_bare_name() {
        let view = DependencyTreeView {
            roots: vec![DependencyTreeNodeView {
                name: "mystery-pkg".to_string(),
                version: None,
                children: vec![],
                truncated: false,
            }],
            max_depth: 3,
        };
        let output = render_en(&view);
        assert!(output.contains("└── mystery-pkg\n"));
        assert!(!output.contains("mystery-pkg ("));
    }

    #[test]
    fn test_ja_locale_uses_japanese_truncation_note() {
        let view = DependencyTreeView {
            roots: vec![DependencyTreeNodeView {
                name: "requests".to_string(),
                version: Some("2.31.0".to_string()),
                children: vec![],
                truncated: true,
            }],
            max_depth: 1,
        };
        let output = render_ja(&view);
        assert!(output.contains("└── ... (省略)"));
        assert!(output.contains("_深さ 1 で省略されています。"));
    }
}
