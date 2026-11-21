//! Architecture test: enforces the hexagonal layer import rules.
//!
//! This file is the enforced source of truth for which top-level module of
//! `src/` may depend on which other one (see `.claude/CLAUDE.md` →
//! "Important Invariants"). It uses [archaven](https://crates.io/crates/archaven),
//! which parses every file under `src/` with `syn` and checks each
//! crate-internal path (`use crate::...`, fully qualified `crate::...`
//! expressions, `super::` paths) against the rules in [`LAYERS`].
//!
//! # Pitfall: never start a pattern with `crate::`
//!
//! archaven strips the `crate` root before matching, so module paths look like
//! `sbom_generation::domain::package`. A pattern such as
//! `crate::sbom_generation::**` matches nothing, and a rule built from it
//! passes silently. The canary test (`test_layer_rules_fixture_reports_planted_violations`)
//! exists to catch this.
//!
//! # How the rules are built
//!
//! archaven's `Rule::deny_all()` applies to every dependency in the graph, so
//! a plain `Rule` cannot be scoped to one source layer. [`Scoped`] wraps a
//! `Rule` and runs it only over the dependencies whose source matches the
//! layer. Each layer then gets a deny-all rule that allows only its own module
//! and the modules listed in its row. A newly added top-level module is
//! therefore forbidden as a target, and any crate-internal import it makes
//! is reported as coming from an unknown source, until it is added to
//! [`LAYERS`] or [`COMPOSITION_ROOTS`].
//!
//! `src/lib.rs` and `src/main.rs` have an empty module path, so no rule
//! matches them: together with `cli`, they are the unrestricted composition
//! root.
//!
//! # Adding a layer
//!
//! Add a [`Layer`] row (and update the rows of layers that may depend on it),
//! then add a fixture file under `tests/fixtures/architecture/` with one
//! forbidden import and extend the canary's expected set.
//!
//! # Existing violations
//!
//! Each entry in [`ARCH_EXCEPTIONS`] allows one file to reach exact target
//! paths, and carries an `ARCH-EXCEPTION(#N): remove when <condition>` comment
//! naming the Issue that removes it. `test_layer_rules_without_exceptions_reports_exactly_allowlisted`
//! fails when an exception no longer matches a real violation, so the fixing
//! Issue must delete its entry.
//!
//! # Known limitation
//!
//! Paths inside `macro_rules!` bodies are not detected by archaven.

use std::collections::BTreeSet;

use archaven::{
    Access, Archaven, ArchavenError, DependencyGraph, PathPattern, Rule, RuleSet, Violations,
};

/// One row of the layer rule table.
struct Layer {
    /// Top-level module name under `src/` (no `crate::` prefix).
    root: &'static str,
    /// Other top-level modules this layer may depend on. Its own module, `std`,
    /// and external crates are always allowed.
    may_depend_on: &'static [&'static str],
    /// One-line reason shown in violation messages.
    because: &'static str,
}

const LAYERS: &[Layer] = &[
    Layer {
        root: "sbom_generation",
        may_depend_on: &["shared"],
        because: "the domain layer depends only on shared utilities",
    },
    Layer {
        root: "ports",
        may_depend_on: &["sbom_generation", "shared"],
        because: "port traits speak in domain types only",
    },
    Layer {
        root: "application",
        may_depend_on: &["sbom_generation", "ports", "shared", "config", "i18n"],
        because: "use cases reach infrastructure only through port traits",
    },
    Layer {
        root: "adapters",
        may_depend_on: &["application", "ports", "sbom_generation", "shared", "i18n"],
        because: "adapters implement ports and never depend on the CLI or config file",
    },
    Layer {
        root: "shared",
        may_depend_on: &[],
        because: "shared utilities sit below every layer",
    },
    Layer {
        root: "config",
        may_depend_on: &[],
        because: "the config file struct stays free of any i18n or layer dependency",
    },
    Layer {
        root: "i18n",
        may_depend_on: &[],
        because: "message catalogs depend on nothing crate-internal",
    },
];

/// Top-level modules with no import restriction (besides `lib.rs`/`main.rs`).
const COMPOSITION_ROOTS: &[&str] = &["cli"];

/// An allowed existing violation: `source` (a file's module path) may reach
/// exactly `targets`.
struct ArchException {
    source: &'static str,
    targets: &'static [&'static str],
}

const ARCH_EXCEPTIONS: &[ArchException] = &[
    // ARCH-EXCEPTION(#1150): remove when the `SbomFormatter` port no longer imports `SbomReadModel`
    ArchException {
        source: "ports::outbound::formatter",
        targets: &["application::read_models::SbomReadModel"],
    },
    // ARCH-EXCEPTION(#1151): remove when `FormatterFactory` no longer constructs adapters
    ArchException {
        source: "application::factories::formatter_factory",
        targets: &[
            "adapters::outbound::formatters::CycloneDxFormatter",
            "adapters::outbound::formatters::MarkdownFormatter",
        ],
    },
    // ARCH-EXCEPTION(#1151): remove when `PresenterFactory` no longer constructs adapters
    ArchException {
        source: "application::factories::presenter_factory",
        targets: &[
            "adapters::outbound::filesystem::FileSystemWriter",
            "adapters::outbound::filesystem::StdoutPresenter",
        ],
    },
];

/// Runs `rule` only over the dependencies whose source matches `sources`.
struct Scoped {
    sources: Vec<PathPattern>,
    rule: Rule,
}

impl Scoped {
    fn new(sources: &[String], rule: Rule) -> Self {
        let sources = sources
            .iter()
            .map(|pattern| PathPattern::parse(pattern).expect("valid source pattern"))
            .collect();
        Self { sources, rule }
    }
}

impl RuleSet for Scoped {
    fn check(&self, graph: &DependencyGraph) -> Result<Violations, ArchavenError> {
        let scoped = DependencyGraph::from_dependencies(
            graph
                .dependencies()
                .iter()
                .filter(|dependency| {
                    self.sources
                        .iter()
                        .any(|pattern| pattern.matches(dependency.source()))
                })
                .cloned(),
        );
        self.rule.check(&scoped)
    }
}

/// `root` itself and everything below it.
fn module_and_children(root: &str) -> [String; 2] {
    [root.to_owned(), format!("{root}::**")]
}

/// Builds the full rule set. Every test uses this one helper.
fn layer_rules(exceptions: &[ArchException]) -> Archaven {
    let mut archaven = Archaven::new();

    for layer in LAYERS {
        let allowed_targets: Vec<String> = std::iter::once(layer.root)
            .chain(layer.may_depend_on.iter().copied())
            .flat_map(module_and_children)
            .collect();
        let mut rule = Rule::new()
            .named(format!("layer `{}`", layer.root))
            .because(layer.because)
            .deny_all()
            .allow(Access::from("**").to_any(allowed_targets));
        for exception in exceptions
            .iter()
            .filter(|exception| exception.source.split("::").next() == Some(layer.root))
        {
            rule = rule
                .allow(Access::from(exception.source).to_any(exception.targets.iter().copied()));
        }
        archaven = archaven.rule(Scoped::new(&module_and_children(layer.root), rule));
    }

    // Every non-root source must belong to a known layer or composition root.
    let mut known = Rule::new()
        .named("known top-level module")
        .because(
            "add new top-level modules to LAYERS or COMPOSITION_ROOTS in tests/architecture.rs",
        )
        .deny_all();
    for root in LAYERS
        .iter()
        .map(|layer| layer.root)
        .chain(COMPOSITION_ROOTS.iter().copied())
    {
        for pattern in module_and_children(root) {
            known = known.allow(Access::from(pattern).to("**"));
        }
    }
    archaven.rule(Scoped::new(&["**".to_owned()], known))
}

fn check(root: &str, exceptions: &[ArchException]) -> Violations {
    layer_rules(exceptions)
        .check(root)
        .expect("source tree is scannable")
}

/// `(source, target)` pairs of all reported violations.
fn pairs(violations: &Violations) -> BTreeSet<(String, String)> {
    violations
        .iter()
        .map(|violation| {
            (
                violation.source().to_string(),
                violation.target().to_string(),
            )
        })
        .collect()
}

const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/architecture");

#[test]
fn test_layer_rules_src_tree_no_violations() {
    let violations = check(SRC, ARCH_EXCEPTIONS);
    assert!(violations.is_empty(), "{violations}");
}

#[test]
fn test_layer_rules_without_exceptions_reports_exactly_allowlisted() {
    let violations = check(SRC, &[]);
    let expected: BTreeSet<(String, String)> = ARCH_EXCEPTIONS
        .iter()
        .flat_map(|exception| {
            exception
                .targets
                .iter()
                .map(|target| (exception.source.to_owned(), (*target).to_owned()))
        })
        .collect();
    assert_eq!(
        pairs(&violations),
        expected,
        "ARCH_EXCEPTIONS must list exactly the existing violations; \
         delete an entry once its Issue removes the violation\n{violations}"
    );
    assert_eq!(violations.len(), 5, "{violations}");
}

#[test]
fn test_layer_rules_fixture_reports_planted_violations() {
    let violations = check(FIXTURE, &[]);
    let expected: BTreeSet<(String, String)> = [
        ("sbom_generation::domain", "adapters::outbound::Writer"),
        ("sbom_generation::domain", "config::IgnoreCve"),
        ("ports::port", "application::read_models::ReadModel"),
        ("application::use_case", "adapters::outbound::Writer"),
        ("adapters::adapter", "cli::Args"),
        ("shared", "config::ConfigFile"),
        ("config", "i18n::Messages"),
        ("i18n", "shared::Result"),
        ("newlayer", "shared::Result"),
    ]
    .into_iter()
    .map(|(source, target)| (source.to_owned(), target.to_owned()))
    .collect();
    assert_eq!(pairs(&violations), expected, "{violations}");
}
