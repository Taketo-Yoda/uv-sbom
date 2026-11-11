//! Upgrade recommendation view model for query operations
//!
//! This module provides view-optimized structs for rendering upgrade recommendations
//! produced by the UpgradeAdvisor domain service.

/// View model aggregating all upgrade recommendation entries
#[derive(Debug, Clone)]
pub struct UpgradeRecommendationView {
    pub entries: Vec<UpgradeEntryView>,
}

/// Outcome of a constraint simulation, as seen by formatters
#[derive(Debug, Clone)]
pub enum ConstraintOutcomeView {
    Verified { resolved_version: String },
    DoesNotResolve { reason: String },
    SimulationFailed { error: String },
}

/// View model for a constraint-dependency suggestion
#[derive(Debug, Clone)]
pub struct ConstraintSuggestionView {
    pub package_name: String,
    pub min_version: String,
    pub outcome: ConstraintOutcomeView,
}

/// Individual upgrade recommendation entry view
#[derive(Debug, Clone)]
pub enum UpgradeEntryView {
    /// Upgrading the direct dependency resolves the vulnerability
    Upgradable {
        direct_dep: String,
        target_version: String,
        transitive_dep: String,
        resolved_version: String,
        vulnerability_id: String,
    },
    /// Upgrading the direct dependency does NOT resolve the vulnerability
    Unresolvable {
        direct_dep_name: String,
        transitive_dep_name: String,
        fixed_version: String,
        reason: String,
        vulnerability_id: String,
        constraint_suggestion: Option<ConstraintSuggestionView>,
    },
    /// Simulation could not be performed for this dependency
    SimulationFailed { direct_dep: String, error: String },
}
