//! Stable health counters for decompiler ASTs.
//!
//! These are diagnostics, not semantic transforms.  They measure the AST that
//! each pass hands to the next pass, using the same identifier collector and
//! definition oracle as the production renderer.  Keeping the counters on the
//! AST avoids brittle regular expressions over formatted C.

use serde::Serialize;

use crate::ir::ast::Function;

/// Control-flow fidelity of the region that is actually lowered to the AST.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CfgHealth {
    /// Real CFG edges that the emitted region does not express.
    pub uncovered_cfg_edges: usize,
    /// Region-implied edges that do not exist in the recovered CFG.
    pub invented_cfg_edges: usize,
    /// Whether verified recovery rejected an unsound candidate and used labelled CFG.
    pub structure_fallbacks: usize,
    /// Successor edges whose kind the block's terminator does not explain.
    ///
    /// Zero is the expected reading. A non-zero count means the graph handed to
    /// structuring contains a transfer nothing in the instruction stream accounts
    /// for — read the function before relaxing anything, because the previous
    /// behaviour was to give that edge a plausible label instead of a count.
    pub unknown_cfg_edges: usize,
    /// Ways control leaves the function, summed over the blocks of this region.
    ///
    /// The denominator for the two counters below: "three unknown exits" means
    /// nothing without knowing whether the function has four exits or four hundred.
    pub terminal_edges: usize,
    /// Terminal transfers whose destination class could not be proven at all.
    pub unknown_terminal_edges: usize,
    /// Computed transfers (`jmp *%rax`) whose destinations were never recovered.
    ///
    /// Not a defect on its own — an unresolved dispatch is a fact about the binary.
    /// It is here because the alternative was an empty successor list, which reads
    /// downstream exactly like a function that ended.
    pub unresolved_indirect_edges: usize,
}

impl CfgHealth {
    /// Fold in the edge census for the graph this region was built over.
    ///
    /// Kept separate from [`cfg_health_from_accounting`] because the two answer
    /// different questions: accounting asks what the region tree failed to express
    /// about the CFG, and this asks what the CFG itself failed to prove about the
    /// program. A region can account for every edge of a graph that is missing half
    /// the program's control flow.
    pub(crate) fn with_edge_census(
        mut self,
        edges: &[Vec<crate::ir::cfg_edges::Edge>],
        terminals: &[Vec<crate::ir::cfg_edges::TerminalEdge>],
    ) -> Self {
        use crate::ir::cfg_edges::{EdgeKind, TerminalKind};

        self.unknown_cfg_edges = edges
            .iter()
            .flatten()
            .filter(|edge| edge.kind == EdgeKind::Unknown)
            .count();
        self.terminal_edges = terminals.iter().map(Vec::len).sum();
        self.unknown_terminal_edges = terminals
            .iter()
            .flatten()
            .filter(|edge| edge.kind == TerminalKind::Unknown)
            .count();
        self.unresolved_indirect_edges = terminals
            .iter()
            .flatten()
            .filter(|edge| edge.kind == TerminalKind::Indirect)
            .count();
        self
    }
}

/// Output-risk counters at one point in the decompiler pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AstHealth {
    /// Number of ABI parameters referenced by the AST.
    pub parameters: usize,
    /// Number of local declarations the C renderer must emit.
    pub declarations: usize,
    /// Number of generated value/predicate temporaries.
    pub temporaries: usize,
    /// Number of unique raw machine registers still exposed as C locals.
    pub physical_registers: usize,
    /// Number of definition-before-use violations.
    pub undefined_uses: usize,
    /// Number of explicit direct goto statements.
    pub gotos: usize,
    /// Real CFG edges that the emitted control-flow region does not express.
    pub uncovered_cfg_edges: usize,
    /// Control-flow edges implied by the emitted region but absent from the CFG.
    pub invented_cfg_edges: usize,
    /// Number of verified-structuring safety fallbacks used for this function.
    pub structure_fallbacks: usize,
    /// Successor edges the block terminator does not explain.
    pub unknown_cfg_edges: usize,
    /// Ways control leaves the function, summed over this function's blocks.
    pub terminal_edges: usize,
    /// Terminal transfers whose destination class could not be proven.
    pub unknown_terminal_edges: usize,
    /// Computed transfers whose destinations were never recovered.
    pub unresolved_indirect_edges: usize,
    /// Number of indirect transfers or unsupported instructions.
    pub unresolved_transfers: usize,
    /// Recursive AST statement count.
    pub statements: usize,
}

/// One machine-readable snapshot emitted at a named pipeline boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PassHealthEvent {
    /// Event schema; consumers reject unknown versions rather than guessing.
    pub schema: &'static str,
    /// Stable pass boundary name.
    pub pass: String,
    /// Recovered function name at this boundary.
    pub function: String,
    /// Hexadecimal virtual address, avoiding JSON integer-width ambiguity.
    pub entry_va: String,
    /// Health counters measured on the unchanged AST.
    pub health: AstHealth,
    /// Named definition violations present at this boundary.
    pub violations: Vec<HealthViolation>,
}

/// Stable, renderer-independent spelling of a definition violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthViolation {
    /// Value identity read unsafely.
    pub name: String,
    /// Stable snake-case violation kind.
    pub kind: &'static str,
}

/// Measure one function without changing it.
pub fn measure(function: &Function) -> AstHealth {
    measure_with_cfg(function, CfgHealth::default())
}

/// Measure one function and attach immutable CFG fidelity from region recovery.
pub fn measure_with_cfg(function: &Function, cfg: CfgHealth) -> AstHealth {
    measure_with_undefined_count(function, crate::ir::verify_defs::check(function).len(), cfg)
}

fn measure_with_undefined_count(
    function: &Function,
    undefined_uses: usize,
    cfg: CfgHealth,
) -> AstHealth {
    let identifiers = crate::ir::ast::health_identifiers(function);
    AstHealth {
        parameters: identifiers.parameters,
        declarations: identifiers.declarations,
        temporaries: identifiers.temporaries,
        physical_registers: identifiers.physical_registers,
        undefined_uses,
        gotos: identifiers.gotos,
        uncovered_cfg_edges: cfg.uncovered_cfg_edges,
        invented_cfg_edges: cfg.invented_cfg_edges,
        structure_fallbacks: cfg.structure_fallbacks,
        unknown_cfg_edges: cfg.unknown_cfg_edges,
        terminal_edges: cfg.terminal_edges,
        unknown_terminal_edges: cfg.unknown_terminal_edges,
        unresolved_indirect_edges: cfg.unresolved_indirect_edges,
        unresolved_transfers: identifiers.unresolved_transfers,
        statements: identifiers.statements,
    }
}

/// Construct a pass-health event without emitting it.
pub fn snapshot(pass: &str, function: &Function) -> PassHealthEvent {
    snapshot_with_cfg(pass, function, CfgHealth::default())
}

/// Construct a pass-health event with structure fidelity from verified recovery.
pub fn snapshot_with_cfg(pass: &str, function: &Function, cfg: CfgHealth) -> PassHealthEvent {
    let violations = crate::ir::verify_defs::check(function);
    PassHealthEvent {
        schema: "glaurung-pass-health-v1",
        pass: pass.to_string(),
        function: function.name.clone(),
        entry_va: format!("{:#x}", function.entry_va),
        health: measure_with_undefined_count(function, violations.len(), cfg),
        violations: violations
            .into_iter()
            .map(|violation| HealthViolation {
                name: violation.name,
                kind: match violation.kind {
                    crate::ir::verify_defs::ViolationKind::NeverDefined => "never_defined",
                    crate::ir::verify_defs::ViolationKind::UsedBeforeDefinition => {
                        "used_before_definition"
                    }
                    crate::ir::verify_defs::ViolationKind::UndefinedValue => "undefined_value",
                    crate::ir::verify_defs::ViolationKind::UninitialisedFramePointer => {
                        "uninitialised_frame_pointer"
                    }
                },
            })
            .collect(),
    }
}

/// Emit one JSON-line health event when `GLAURUNG_PASS_HEALTH` is set.
///
/// Serialization failure is reported as an explicit diagnostic rather than
/// panicking in the analyst's decompilation path.
pub fn trace_pass(pass: &str, function: &Function, cfg: CfgHealth) {
    if std::env::var_os("GLAURUNG_PASS_HEALTH").is_none() {
        return;
    }
    match serde_json::to_string(&snapshot_with_cfg(pass, function, cfg)) {
        Ok(event) => eprintln!("[glaurung-pass-health] {event}"),
        Err(error) => eprintln!(
            "[glaurung-pass-health-error] pass={pass} function={} error={error}",
            function.name
        ),
    }
}

/// Summarize the exact output region's edge accounting.
pub(crate) fn cfg_health_from_accounting(
    accounting: &[crate::ir::structure_accounting::AccountError],
    used_fallback: bool,
) -> CfgHealth {
    use crate::ir::structure_accounting::AccountError;

    CfgHealth {
        uncovered_cfg_edges: accounting
            .iter()
            .filter(|finding| matches!(finding, AccountError::EdgeUnaccounted { .. }))
            .count(),
        invented_cfg_edges: accounting
            .iter()
            .filter(|finding| matches!(finding, AccountError::ImpliedEdgeAbsent { .. }))
            .count(),
        structure_fallbacks: usize::from(used_fallback),
        ..CfgHealth::default()
    }
}

/// Whether an identifier is a raw register spelling from a lifted ISA.
pub fn is_machine_register(name: &str) -> bool {
    crate::ir::machine_register::is_machine_register_name(name)
}
