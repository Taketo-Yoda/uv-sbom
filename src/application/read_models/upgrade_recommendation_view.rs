//! Upgrade recommendation view model for query operations
//!
//! This module provides view-optimized structs for rendering upgrade recommendations
//! produced by the UpgradeAdvisor domain service.

/// View model aggregating all upgrade recommendation entries
#[derive(Debug, Clone)]
pub struct UpgradeRecommendationView {
    pub entries: Vec<UpgradeEntryView>,
}

/// Individual upgrade recommendation entry view
#[derive(Debug, Clone)]
#[allow(dead_code)] // Reserved for Issue #486: enum variant fields unused in binary but read by library consumers/formatters
pub enum UpgradeEntryView {
    /// Upgrading the direct dependency resolves the vulnerability
    Upgradable {
        direct_dep: String,
        current_version: String,
        target_version: String,
        transitive_dep: String,
        resolved_version: String,
        vulnerability_id: String,
    },
    /// Upgrading the direct dependency does NOT resolve the vulnerability
    Unresolvable {
        direct_dep: String,
        reason: String,
        vulnerability_id: String,
    },
    /// Simulation could not be performed for this dependency
    SimulationFailed { direct_dep: String, error: String },
}
