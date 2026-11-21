// Architecture canary fixture (tests/architecture.rs). Parsed, never compiled.
use crate::shared::Result; // allowed
use crate::adapters::outbound::Writer; // forbidden

fn uses_config(_: crate::config::IgnoreCve) {} // forbidden
