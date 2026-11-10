/// Outcome of simulating resolution with a `>=fixed_version` constraint
/// injected into `[tool.uv].constraint-dependencies`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintOutcome {
    /// The constraint resolved successfully and the vulnerable package
    /// reached the required fixed version (or newer).
    #[allow(dead_code)]
    // WIRE(#1117): remove when suggest-fix orchestrator constructs this variant
    Verified { resolved_version: String },
    /// `uv lock` could not resolve with the constraint, or the resolved
    /// version still did not satisfy the fixed version.
    #[allow(dead_code)]
    // WIRE(#1117): remove when suggest-fix orchestrator constructs this variant
    DoesNotResolve { reason: String },
    /// The simulation infrastructure failed (e.g. uv not available,
    /// temp-dir I/O error, timeout).
    #[allow(dead_code)]
    // WIRE(#1117): remove when suggest-fix orchestrator constructs this variant
    SimulationFailed { error: String },
}

/// A suggestion to add a `>=fixed_version` constraint-dependency to
/// work around an unresolvable transitive vulnerability.
#[derive(Debug, Clone)]
pub struct ConstraintSuggestion {
    #[allow(dead_code)] // WIRE(#1117): remove when suggest-fix read model reads this field
    pub package_name: String,
    #[allow(dead_code)] // WIRE(#1117): remove when suggest-fix read model reads this field
    pub min_version: String,
    #[allow(dead_code)] // WIRE(#1117): remove when suggest-fix read model reads this field
    pub outcome: ConstraintOutcome,
}

/// Result of analyzing whether upgrading a direct dep fixes a transitive vulnerability
#[derive(Debug, Clone)]
pub enum UpgradeRecommendation {
    /// Upgrading the direct dep resolves the vulnerability
    Upgradable {
        /// Direct dependency to upgrade (e.g., "requests")
        direct_dep_name: String,
        /// Recommended version to upgrade to (e.g., "2.32.3")
        direct_dep_target_version: String,
        /// Vulnerable transitive dep name (e.g., "urllib3")
        transitive_dep_name: String,
        /// Version of transitive dep after upgrade (e.g., "2.2.1")
        transitive_resolved_version: String,
        /// Vulnerability ID (e.g., "CVE-2024-XXXXX")
        vulnerability_id: String,
    },
    /// Upgrading the direct dep does NOT resolve the vulnerability
    Unresolvable {
        direct_dep_name: String,
        /// Vulnerable transitive dep name (e.g., "idna")
        transitive_dep_name: String,
        /// Version that would fix the vulnerability (e.g., "3.7")
        fixed_version: String,
        /// Why upgrade doesn't help (e.g., "upgrading httpx still resolves idna to 3.6 which does not satisfy >= 3.7")
        reason: String,
        vulnerability_id: String,
        /// Populated by Subtask 4 (#1117) when constraint simulation completes.
        /// `None` until then.
        #[allow(dead_code)]
        // WIRE(#1117): remove when suggest-fix orchestrator populates this field
        constraint_suggestion: Option<ConstraintSuggestion>,
    },
    /// Simulation could not be performed (uv not available, timeout, etc.)
    SimulationFailed {
        direct_dep_name: String,
        /// Error description
        error: String,
    },
}
