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

/// A C type as the source spells it.
///
/// **As written, not resolved.** This front end reads one translation unit and
/// does not process `#include` (`REQ-GEN`), so a typedef from a header is an
/// opaque name and is recorded as one: `uint32_t` is stored as `uint32_t`, and
/// nothing here claims to know it is four bytes. Storing the spelling is
/// useful; claiming a width we cannot derive would not be.
///
/// Deliberately **not** built on [`crate::metrics::type_name::normalize_type`].
/// That function reproduces four defects in DecBench's reference
/// implementation on purpose --- it emits the non-C spelling `long long long`,
/// and turns `_Bool` into `_bool` --- because parity with the benchmark is its
/// contract. A general consumer wants the type the programmer wrote, so this
/// reads the specifier text directly and leaves that module to its own job.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CType {
    /// The declaration specifiers, whitespace-collapsed: `unsigned long`,
    /// `struct point`, `const char`. Empty when the declaration had none the
    /// parser recovered.
    pub specifiers: String,
    /// How many `*` sit between the specifiers and the name. `char *argv` is
    /// 1; `char **argv` is 2.
    pub pointer_depth: u32,
    /// How many `[...]` suffixes follow the name. `int m[4][4]` is 2.
    pub array_rank: u32,
    /// `const` appears in the specifiers.
    pub is_const: bool,
    /// `volatile` appears in the specifiers. Load-bearing for a reader: a
    /// `volatile` read cannot be elided, so a dead store to one is not dead.
    pub is_volatile: bool,
    /// `static` appears in the specifiers.
    pub is_static: bool,
    /// `extern` appears in the specifiers.
    pub is_extern: bool,
}

impl CType {
    /// Whether anything was recovered at all.
    pub fn is_empty(&self) -> bool {
        self.specifiers.is_empty() && self.pointer_depth == 0 && self.array_rank == 0
    }

    /// The type as one string: specifiers, then stars, then array brackets.
    ///
    /// A display form, not a canonical one --- two spellings of the same type
    /// render differently, which is why comparison goes through
    /// [`CType::same_shape`] rather than through this.
    pub fn render(&self) -> String {
        let mut out = self.specifiers.clone();
        if self.pointer_depth > 0 {
            if !out.is_empty() {
                out.push(' ');
            }
            for _ in 0..self.pointer_depth {
                out.push('*');
            }
        }
        for _ in 0..self.array_rank {
            out.push_str("[]");
        }
        out
    }

    /// Whether two types agree on everything a dataflow consumer can check.
    ///
    /// Compares the specifier text with qualifiers stripped, plus the pointer
    /// depth and array rank. It is a *shape* test, not a type-equality test:
    /// without `#include` resolution, `uint32_t` and `unsigned int` are two
    /// opaque names and this reports them as different, which is the honest
    /// answer rather than a guess.
    pub fn same_shape(&self, other: &CType) -> bool {
        self.pointer_depth == other.pointer_depth
            && self.array_rank == other.array_rank
            && strip_qualifiers(&self.specifiers) == strip_qualifiers(&other.specifiers)
    }
}

/// The specifier text with storage-class and qualifier words removed, so
/// `const char` and `char` compare equal.
fn strip_qualifiers(specifiers: &str) -> String {
    specifiers
        .split_whitespace()
        .filter(|word| {
            !matches!(
                *word,
                "const" | "volatile" | "restrict" | "__restrict" | "__restrict__"
                    | "static" | "extern" | "register" | "auto" | "inline" | "_Atomic"
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// One call in a function body, as the syntax walk saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRecord {
    /// The callee's name, or `None` when the call was indirect --- through a
    /// pointer or a struct member, which names no function.
    pub callee: Option<String>,
    /// The binding at each argument position, in order. A position holding an
    /// expression rather than a bare name is [`Binding::FREE`], which no real
    /// binding equals, so it neither propagates a value nor blocks one.
    pub arguments: Vec<Binding>,
    /// Bindings the call's result is assigned to, when it is assigned at all.
    pub results: Vec<Binding>,
    /// Whether the call's result is returned directly: `return g(x);`.
    pub result_is_returned: bool,
    /// Where the call sits, for a label.
    pub span: Span,
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
    /// The type declared at *this* site, when the write is a declaration or a
    /// parameter. `None` for an assignment, which declares nothing.
    ///
    /// Separate from [`DataFlow::types`] on purpose: that is the binding's
    /// type, and this is what one site said. In well-typed C they agree; in a
    /// decompiler's output they need not, which is what
    /// [`DataFlow::type_conflicts`] looks for.
    pub declared: Option<CType>,
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
    /// Every call this function makes, in source order.
    ///
    /// Recorded during the syntax walk because that is the only place the
    /// argument *positions* are visible: by the time the analysis has a
    /// dependence graph, `g(a, b)` is two reads with no record of which was
    /// first. Interprocedural summaries need the position.
    pub calls: Vec<CallRecord>,
    /// The spelling of each binding, in binding order.
    ///
    /// A binding that is declared and never mentioned again appears in neither
    /// [`DataFlow::definitions`] nor [`DataFlow::uses`] --- `int *b;` writes
    /// nothing and reads nothing --- so without this there is no way to ask
    /// about it at all. It is also what makes an unused local reportable.
    pub names: Vec<String>,
    /// The declared type of each binding, in binding order.
    ///
    /// Indexed by [`Binding`]'s inner value, so `types[b.0 as usize]` is the
    /// type of binding `b`. [`Binding::FREE`] has no entry: it is the shared
    /// binding for every unresolved name, and a global's type is not knowable
    /// from one translation unit.
    pub types: Vec<CType>,
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

    /// Every call this function makes, in the shape a summary consumes.
    pub fn call_sites(&self) -> Vec<crate::csource::dataflow::interproc::CallSite> {
        use crate::csource::dataflow::interproc::CallSite;
        self.calls
            .iter()
            .map(|record| CallSite {
                callee: record.callee.clone(),
                arguments: record.arguments.clone(),
                results: record.results.clone(),
                result_is_returned: record.result_is_returned,
            })
            .collect()
    }

    /// The binding named `name`, when this function declares one.
    ///
    /// The innermost is not distinguishable here: two shadowed declarations of
    /// one name are two bindings and this returns the first. A caller that
    /// cares about shadowing walks [`DataFlow::names`] itself.
    pub fn binding_named(&self, name: &str) -> Option<Binding> {
        self.names
            .iter()
            .position(|candidate| candidate == name)
            .map(|index| Binding(index as u32))
    }

    /// Bindings that are declared and never read.
    ///
    /// Distinct from a dead store: `int *b;` is not a store at all, so it is
    /// not in [`DataFlow::dead_stores`], but it is still a local nothing uses.
    /// A parameter is excluded for the same reason it is there --- the
    /// signature is the contract.
    pub fn unused_bindings(&self) -> Vec<Binding> {
        (0..self.names.len() as u32)
            .map(Binding)
            .filter(|binding| {
                !self.uses.iter().any(|use_| use_.binding == *binding)
                    && !self
                        .definitions
                        .iter()
                        .any(|d| d.binding == *binding && d.kind == DefKind::Parameter)
            })
            .collect()
    }

    /// The declared type of `binding`, when one was recovered.
    pub fn type_of(&self, binding: Binding) -> Option<&CType> {
        if binding.is_free() {
            return None;
        }
        self.types.get(binding.0 as usize).filter(|ty| !ty.is_empty())
    }

    /// Bindings whose reaching definitions disagree about type.
    ///
    /// The shape of a decompiler's type-recovery failure, findable in the
    /// recovered C without the binary. Empty for well-typed source, because a
    /// C compiler would have rejected the disagreement.
    pub fn type_conflicts(&self) -> Vec<Binding> {
        let mut out: Vec<Binding> = Vec::new();
        for (index, ty) in self.types.iter().enumerate() {
            if ty.is_empty() {
                continue;
            }
            let binding = Binding(index as u32);
            let mut seen: Option<&CType> = None;
            for definition in &self.definitions {
                if definition.binding != binding {
                    continue;
                }
                let Some(other) = definition.declared.as_ref() else {
                    continue;
                };
                match seen {
                    None => seen = Some(other),
                    Some(first) if !first.same_shape(other) => {
                        out.push(binding);
                        break;
                    }
                    _ => {}
                }
            }
        }
        out
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

