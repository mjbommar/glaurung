//! The vocabulary the analysis produces: bindings, definitions, uses, edges.
//!
//! Split from the analysis itself so a consumer can name a [`Definition`] or
//! match on a [`DefKind`] without pulling in the syntax walk or the fixpoint,
//! and so the two halves have one reason to change apiece.

use crate::syntax::ids::Span;

/// Which variable an event is about: an index into the function's binding
/// table, or [`Binding::FREE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Binding(pub u32);

impl Binding {
    /// The binding every unresolved name shares: a global, an `extern`, a
    /// function, or a name whose declaration the parser did not recover.
    ///
    /// Sharing one binding across all of them is deliberate. Two reads of the
    /// same global must see each other's writes, and giving each unresolved
    /// name its own binding would silently drop those edges. The cost is that
    /// two *different* globals are conflated, which over-approximates in the
    /// same safe direction as everything else here.
    pub const FREE: Binding = Binding(u32::MAX);

    /// Whether this is the shared unresolved binding.
    pub fn is_free(self) -> bool {
        self == Binding::FREE
    }
}

/// One write of a variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// The variable written.
    pub binding: Binding,
    /// The variable's spelling, for a label.
    pub name: String,
    /// The CFG node the write happens on.
    pub node: u32,
    /// The source the write covers: the target's own name.
    pub span: Span,
    /// The offset at which the write becomes visible to a later read.
    ///
    /// **Not** the end of [`Definition::span`]. C evaluates the right-hand
    /// side first, so in `sum = sum + i` the read of `sum` sees whatever
    /// reached the statement, not the value this statement is about to store.
    /// Ordering same-node events by the target's position instead gets that
    /// backwards and silently drops the loop-carried dependence.
    pub effect_at: u32,
    /// How the write was spelled.
    pub kind: DefKind,
}

/// One read of a variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Use {
    /// The variable read.
    pub binding: Binding,
    /// The variable's spelling, for a label.
    pub name: String,
    /// The CFG node the read happens on.
    pub node: u32,
    /// The source the read covers.
    pub span: Span,
}

/// How a definition was written, which a reader wants and a fixpoint does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DefKind {
    /// A parameter, defined at the function entry.
    Parameter,
    /// A declarator, with or without an initializer.
    Declaration,
    /// The left side of `=`.
    Assignment,
    /// The left side of a compound assignment, which also reads.
    CompoundAssignment,
    /// The operand of `++` or `--`, which also reads.
    IncDec,
    /// The operand of `&`. Taking an address is how C spells an out
    /// parameter, so the callee may write through it and the value after the
    /// call is unknown. Recorded as a definition for that reason, not because
    /// `&x` stores anything itself.
    AddressTaken,
}

impl DefKind {
    /// This kind's stable name, for a serialized attribute.
    pub const fn name(self) -> &'static str {
        match self {
            DefKind::Parameter => "parameter",
            DefKind::Declaration => "declaration",
            DefKind::Assignment => "assignment",
            DefKind::CompoundAssignment => "compound_assignment",
            DefKind::IncDec => "inc_dec",
            DefKind::AddressTaken => "address_taken",
        }
    }
}

/// One data-dependence edge: a definition a use can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEdge {
    /// Index into [`DataFlow::definitions`].
    pub def: u32,
    /// Index into [`DataFlow::uses`].
    pub use_: u32,
    /// The variable, so an edge is readable without dereferencing either end.
    pub name: String,
}

/// One function's reaching-definition analysis.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataFlow {
    /// The function's declared name.
    pub name: String,
    /// Every write, in source order.
    pub definitions: Vec<Definition>,
    /// Every read, in source order.
    pub uses: Vec<Use>,
    /// Every (definition, use) pair the control-flow graph allows.
    pub edges: Vec<FlowEdge>,
    /// Uses no definition reaches: a global, a parameter of an unrecovered
    /// declarator, or a genuine read-before-write.
    ///
    /// This is the headline defect number the analysis produces, and it is the
    /// same question `defuse_baseline.json` asks of the decompiler's output
    /// from the other side.
    pub unresolved_uses: Vec<u32>,
    /// Definitions no use reads: a dead store.
    ///
    /// The other direction of the same relation, and the one the reaching
    /// analysis gets for free. A decompiler that invents a temporary, assigns
    /// it and never reads it produces one of these per invention, so the count
    /// is a readability measure the execution differential cannot see --- goto
    /// soup and dead stores both pass a test that only checks the return
    /// value.
    ///
    /// A parameter that is never read is deliberately **not** counted: the
    /// caller wrote it, the signature is the contract, and an unused parameter
    /// is a style question rather than a recovered-code defect.
    pub dead_stores: Vec<u32>,
}

impl DataFlow {
    /// Definitions that reach `use_index`.
    pub fn definitions_reaching(&self, use_index: u32) -> impl Iterator<Item = &Definition> {
        self.edges
            .iter()
            .filter(move |edge| edge.use_ == use_index)
            .filter_map(|edge| self.definitions.get(edge.def as usize))
    }

    /// Whether `def_index` is a dead store.
    pub fn is_dead_store(&self, def_index: u32) -> bool {
        self.dead_stores.contains(&def_index)
    }

    /// Uses that `def_index` reaches.
    pub fn uses_reached(&self, def_index: u32) -> impl Iterator<Item = &Use> {
        self.edges
            .iter()
            .filter(move |edge| edge.def == def_index)
            .filter_map(|edge| self.uses.get(edge.use_ as usize))
    }
}

