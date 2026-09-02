//! Resolving an indirect branch's target set **at the dispatch site**.
//!
//! # Why this exists
//!
//! `analysis::jump_table::discover_jump_tables` already finds the tables. Its
//! results were used for one thing: seeding *function discovery*, so each arm was
//! offered as a possible new function entry. Nothing ever bound a table to the
//! `jmp` that reads it, so inside the dispatching function the indirect jump
//! contributed **no successors at all**:
//!
//! ```text
//! lea    0xedb(%rip),%rcx      # rcx = 0x2000, the table
//! movslq (%rcx,%rax,4),%rax    # rax = (i32)table[idx]
//! add    %rcx,%rax             # rax = table + offset
//! jmp    *%rax                 # <- eight arms; the CFG got none of them
//! ```
//!
//! The consequences compound, and each looked like a different bug:
//!
//! * the case arms are not in the function, so `switch` never structures;
//! * the dispatch renders as an indirect *call* through a table entry;
//! * `ir::cfg_edges` decides what a dispatch is by counting successors
//!   (`succ_count > 2`), so with zero successors it is not a dispatch and its
//!   arms cannot be `EdgeKind::SwitchCase`;
//! * `ir::structure_accounting` compares the region tree against the CFG, so it
//!   reports the truncated graph as perfectly accounted — **a clean verdict on a
//!   function that lost thirty instructions**.
//!
//! That last point is why this belongs here and not further downstream. No
//! structuring, typing, or rendering fix can recover a block the graph never had,
//! and no verifier that checks the tree against the graph can notice.
//!
//! # What it does
//!
//! A small abstract interpretation over the block being decoded, tracking what
//! each register is known to hold. It is deliberately *not* a match against the
//! four-instruction sequence above: compilers reorder these, use different
//! registers, fold the `lea`, and gcc emits a different shape for the same
//! construct. Modelling the arithmetic means the shapes fall out of one rule set
//! rather than accumulating a template per compiler — the pattern-per-shape
//! approach is what made the structurer unmaintainable.
//!
//! # What it reports when it fails
//!
//! [`Resolution::Unresolved`], with a reason. An indirect transfer whose targets
//! cannot be recovered means **the CFG is not the program**, and that has to be a
//! representable fact rather than a silently empty successor list. It is the
//! input to CFG-completeness reporting.

use std::collections::{BTreeMap, HashMap};

use crate::core::instruction::{Access, Instruction};

mod arm_tables;
mod memory_guard;
mod registers;

pub use arm_tables::{ArmPcMode, ArmWordTableBranch};
pub use memory_guard::MemKey;
use memory_guard::MemoryBounds;
use registers::{ascii_lower, canon, canon_ref};

/// What a register holds, as far as dispatch resolution is concerned.
///
/// A lattice with no join: this runs over a single block, straight-line, so a
/// register is either tracked or it is not. Anything unmodelled resets to
/// `Unknown`, which is the safe direction — it yields
/// [`Resolution::Unresolved`], never a wrong target set.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Val {
    /// An absolute address materialised in the register: `lea rD,[rip+d]` or
    /// `mov rD, imm`.
    Addr(u64),
    /// A guarded switch index multiplied by its table-entry stride.
    ///
    /// GCC -O0 commonly materialises this as a separate address component
    /// (`lea rdx,[rax*4]`) before adding the table base in the load itself.
    /// Keeping the bound attached to the value lets the later load recognize
    /// the same expression without matching register names or instruction
    /// positions.
    ScaledIndex { bound: Option<u64>, scale: u64 },
    /// `(i32)*(table + idx*4)`, sign-extended — a table-relative offset.
    ///
    /// `bound` is the inclusive maximum of the register that INDEXED the table,
    /// captured at the moment of the read.
    ///
    /// Captured, not looked up later, because the table read usually overwrites
    /// the index register with the loaded offset — `movslq (%rcx,%rax,4),%rax`
    /// destroys `rax`'s bound in the same instruction that uses it. Reading the
    /// bound at resolve time therefore always found nothing.
    ///
    /// It is per-value rather than per-register for the same reason the whole
    /// `bounded` map exists: `sub $0x8,%rsp` in a prologue must never supply an
    /// extent to the next dispatch it happens to precede.
    TableOffset { table: u64, bound: Option<u64> },
    /// `table + (i32)*(table + idx*4)` — a dispatch target. Jumping through this
    /// register reaches exactly the table's entries.
    TableTarget { table: u64, bound: Option<u64> },
}

/// Why an indirect transfer's targets could not be recovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unresolved {
    /// The jump register was never tracked to a table-derived value.
    UnknownBase,
    /// The register resolved to a table-derived value, but no table could be
    /// read at that address. Distinct from `UnknownBase` because it means
    /// the *dispatch* was understood and the *table scan* came up short — a
    /// different defect, and one worth reporting separately.
    ///
    /// `decline` names which of the decoder's checks refused. Without it this
    /// variant answers "no table" for a dozen unrelated situations — an address
    /// in no section, a target outside `.text`, an extent above the entry
    /// ceiling — and a consumer cannot tell a mapping problem from a budget one.
    NoTableAt {
        table: u64,
        decline: crate::analysis::jump_table::TableDecline,
    },
    /// The dispatch and its table were both found, but no range check bounded
    /// the index, so the table's entry count is unknown.
    ///
    /// Reported rather than guessed. The rodata scan cannot find a table's end —
    /// it over-runs into the following table — so using its length here attaches
    /// dozens of foreign blocks to the function. This is the most *recoverable*
    /// of the three: it names a table that exists and only wants an extent.
    NoBound(u64),
}

impl Unresolved {
    /// A stable histogram key. `NoTableAt` folds its decline in, because that is
    /// where the interesting variation lives: without it the bucket is one
    /// undifferentiated pile and ranks no work.
    pub fn label(&self) -> String {
        match self {
            Self::UnknownBase => "unknown_base".to_string(),
            Self::NoTableAt { decline, .. } => format!("no_table_at:{}", decline.label()),
            Self::NoBound(_) => "no_bound".to_string(),
        }
    }

    /// The table address this decline is about, when it names one.
    pub fn table_va(&self) -> Option<u64> {
        match self {
            Self::UnknownBase => None,
            Self::NoTableAt { table, .. } | Self::NoBound(table) => Some(*table),
        }
    }

    /// Human-readable detail, paired with [`Self::label`] the way
    /// [`crate::analysis::cfg::ScanRejection`] pairs `reason` with `detail`.
    pub fn detail(&self) -> String {
        match self {
            Self::UnknownBase => "jump register never tracked to a table-derived value".to_string(),
            Self::NoTableAt { table, decline } => format!("table {table:#x}: {decline}"),
            Self::NoBound(table) => {
                format!("table {table:#x} found, no range check bounds the index")
            }
        }
    }
}

/// What a guard established, carried across its in-range edge.
///
/// All three halves are needed: clang -O2 keeps the checked value in a register,
/// clang -O0 spills it to a frame slot before the check and reloads it after,
/// and gcc -O2 compares the table-driven selector *in memory* and never lands
/// it in a register until after the branch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bounds {
    pub regs: HashMap<String, u64>,
    pub slots: HashMap<(String, i64), u64>,
    /// Memory locations proved to hold a value in `[0, max]`; see
    /// [`memory_guard`].
    pub mems: HashMap<MemKey, u64>,
}

/// A Thumb-2 `tbb`/`tbh` table branch, and the extent its guard proves.
///
/// Kept separate from [`Resolution`] because a table branch names its table in
/// the *instruction*, not in a tracked register: `pc` is the base, so the table
/// address is a decode-time constant and only the entry COUNT is a dataflow
/// fact. There is no `UnknownBase` case to report, and pretending there is would
/// mean threading a register through that the encoding does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThumbTableBranch {
    /// VA of the inline table — the value `pc` reads at this instruction, which
    /// in Thumb state is its own address plus 4 and therefore the byte
    /// immediately after the 4-byte `tbb`/`tbh` encoding.
    pub table_va: u64,
    /// 1 for `tbb`, 2 for `tbh`.
    pub entry_size: u8,
    /// Entries the range check proves. `None` when the index reached this
    /// dispatch unbounded — the same fail-closed position `Unresolved::NoBound`
    /// takes, and for the same reason: past the last entry lie the case bodies,
    /// whose instruction bytes read as perfectly plausible table entries.
    pub entry_count: Option<usize>,
}

/// The outcome of resolving one indirect transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Targets recovered from the jump table at `table_va`.
    Table { table_va: u64, targets: Vec<u64> },
    /// Targets not recoverable. The resulting CFG is incomplete and must say so.
    Unresolved(Unresolved),
}

/// Streaming register tracker for one basic block.
///
/// Driven by the block walker as it decodes, so no instruction is buffered and
/// nothing is decoded twice. [`Self::reset`] at each block start — values must
/// never cross a block boundary, because a predecessor is not guaranteed.
#[derive(Debug, Default)]
pub struct DispatchTracker {
    regs: HashMap<String, Val>,
    /// Registers known to hold a range-limited value, as `register -> inclusive max`.
    ///
    /// Boundedness is tracked as a **propagating dataflow fact**, not as the name
    /// of whatever register was compared last. That distinction is the whole
    /// difference between resolving 3 of 24 real dispatches and resolving most of
    /// them: compilers routinely check the index in one register and read the
    /// table with another. clang -O0 spills the checked value to its frame slot
    /// and reloads it into a different register; clang -O2 copies it
    /// (`cmp $7,%edi ... mov %edi,%ecx ... movslq (%rsi,%rcx,4),%rcx`). Matching
    /// register names declined every one of those.
    bounded: HashMap<String, u64>,
    /// Stack slots holding a bounded value, so a spill/reload carries the bound.
    /// Keyed by `(base register, displacement)`.
    bounded_slots: HashMap<(String, i64), u64>,
    /// Identity of the value currently held by each register. Copies share an
    /// identity; every other write creates a new one.
    reg_values: HashMap<String, u64>,
    /// Identity of the value currently held by each tracked stack slot. Needed
    /// because clang -O0 spills the switch value BEFORE the guard runs:
    ///
    /// ```text
    /// mov -0x8(%rbp),%eax     ; the switch value
    /// mov %rax,-0x18(%rbp)    ; spilled — not bounded yet
    /// sub $0x7,%rax           ; NOW bounded
    /// ja  default
    /// mov -0x18(%rbp),%rcx    ; reloaded into another register
    /// ```
    ///
    /// The guard proves the PRE-`sub` value lies in `[0, 7]`, and that is exactly
    /// the value sitting in the slot. Value identity, rather than register name,
    /// preserves this through compiler-inserted copies before the spill.
    slot_values: HashMap<(String, i64), u64>,
    next_value_id: u64,
    /// The most recent `cmp`/`sub` against an immediate, for the walker to hand
    /// to the guard's in-range successor.
    last_cmp: Option<(String, u64)>,
    /// GCC -O0 commonly compares a spilled switch value directly in its frame
    /// slot (`cmp [rbp-4], N`).  Keep that proof distinct from register facts so
    /// the fallthrough block can inherit it and bind a later reload.
    last_slot_cmp: Option<((String, i64), u64)>,
    /// Range checks made against a memory location rather than a register: the
    /// gcc -O2 shape where the compared value never reaches one. See
    /// [`memory_guard`].
    memory: MemoryBounds,
    /// How `pc` reads as a source operand, when this block is 32-bit ARM.
    ///
    /// `None` on every other architecture *and* on ARM when the execution state
    /// could not be established — in which case `add rD, pc, #imm` produces no
    /// address rather than a guessed one.
    arm_pc_mode: Option<ArmPcMode>,
}

impl DispatchTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare how `pc` reads as a source operand for this block.
    ///
    /// Must be set before observing ARM instructions; without it a
    /// `pc`-relative address materialisation is declined, not approximated.
    pub fn set_arm_pc_mode(&mut self, mode: Option<ArmPcMode>) {
        self.arm_pc_mode = mode;
    }

    pub fn reset(&mut self) {
        self.regs.clear();
        self.bounded.clear();
        self.bounded_slots.clear();
        self.reg_values.clear();
        self.slot_values.clear();
        self.last_cmp = None;
        self.last_slot_cmp = None;
        self.memory.clear();
    }

    /// The inclusive maximum index this block's guard admits, if its predecessor
    /// established one.
    ///
    /// # Why the table's extent has to come from here
    ///
    /// A jump table has no header and no terminator. Scanning `.rodata` for
    /// "a run of offsets that all land in executable memory" cannot find the
    /// END of one: the entries of the *next* table, read relative to the
    /// *previous* table's base, still land in `.text`. On the fixture corpus
    /// that produced a single 65-entry table where there are eight, and wiring
    /// it into the CFG dragged fifty-two blocks of four unrelated functions into
    /// `dense_jumptable`.
    ///
    /// The dispatching code knows exactly. `sub $0x7,%eax; ja default` says the
    /// index is in `[0, 7]`, so the table has eight entries — a fact, not a
    /// heuristic. It lives in the *predecessor* block, so the walker carries it
    /// across the guard's in-range edge, which is sound precisely because that
    /// edge is the one the check admits.
    pub fn inherit_bound(&mut self, bound: Option<Bounds>) {
        if let Some(b) = bound {
            self.bounded.extend(b.regs);
            self.bounded_slots.extend(b.slots);
            self.memory.inherit(b.mems);
        }
    }

    /// Seed address constants that reach this block on every predecessor seen
    /// by the CFG walker.
    ///
    /// Compilers commonly materialise a jump-table base in a loop preheader and
    /// use it in a later dispatch block. Resetting all register facts at every
    /// block loses that invariant and makes an otherwise explicit table jump
    /// unrecoverable. The walker merges these maps by intersection, so a value
    /// is inherited only while all incoming paths agree on the same address.
    pub fn inherit_addresses(&mut self, addresses: Option<&HashMap<String, u64>>) {
        if let Some(addresses) = addresses {
            for (register, address) in addresses {
                self.regs.insert(register.clone(), Val::Addr(*address));
            }
        }
    }

    /// Address constants still valid at the end of the current block.
    ///
    /// Table offsets/targets are deliberately excluded: only concrete address
    /// values are stable enough to merge across CFG edges.
    pub fn export_addresses(&self) -> HashMap<String, u64> {
        self.regs
            .iter()
            .filter_map(|(register, value)| match value {
                Val::Addr(address) => Some((register.clone(), *address)),
                Val::ScaledIndex { .. } | Val::TableOffset { .. } | Val::TableTarget { .. } => None,
            })
            .collect()
    }

    /// The limit a range check just established, for the caller to hand the
    /// exported register/slot facts to the in-range successor. `cmp $N, value`
    /// followed by an unsigned-above branch means the fallthrough has
    /// `value <= N`, whether `value` currently lives in a register or frame slot.
    pub fn pending_bound(&self) -> Option<u64> {
        self.last_cmp
            .as_ref()
            .map(|(_, limit)| *limit)
            .or_else(|| self.last_slot_cmp.as_ref().map(|(_, limit)| *limit))
            .or_else(|| self.memory.pending_limit())
    }

    fn get(&self, reg: &str) -> Option<Val> {
        self.regs.get(canon_ref(reg).as_ref()).cloned()
    }

    fn set(&mut self, reg: &str, v: Val) {
        self.regs.insert(canon(reg), v);
    }

    fn clear(&mut self, reg: &str) {
        self.regs.remove(canon_ref(reg).as_ref());
    }

    /// Absolute VA of a RIP-relative memory operand, as the adapters report it
    /// (`base == "rip"` with the displacement already resolved).
    fn rip_target(ins: &Instruction) -> Option<u64> {
        ins.operands.iter().find_map(|op| {
            let d = op.displacement?;
            (op.base.as_deref() == Some("rip") && d >= 0).then_some(d as u64)
        })
    }

    /// The register operand 0 *writes*, if it writes one.
    ///
    /// The access class comes from the decoder rather than being assumed. The
    /// distinction is load-bearing and not cosmetic: `jmp rax` has `rax` as
    /// operand 0 but only READS it. Treating operand 0 as a definition made
    /// [`Self::observe`] clear the very register the jump was about to be
    /// resolved through, so every dispatch came back
    /// [`Unresolved::UnknownBase`] — while the unit tests passed, because their
    /// synthetic operands were all `ReadWrite`.
    fn dest_reg(ins: &Instruction) -> Option<&str> {
        let op = ins.operands.first()?;
        matches!(op.access, Access::Write | Access::ReadWrite)
            .then(|| op.register.as_deref())
            .flatten()
    }

    /// Recover `table + index*4` from the effective address of a table load.
    ///
    /// Both x86 encodings are accepted as value expressions:
    ///
    /// * clang: `[table_base + bounded_index*4]`
    /// * GCC -O0: `[scaled_index + table_base]`, after
    ///   `scaled_index = bounded_index*4`
    ///
    /// The displacement must be zero and the total index scale exactly four;
    /// broader address arithmetic is not enough evidence for a relative-offset
    /// jump table.
    fn table_load_on_entry(&self, ins: &Instruction) -> Option<(u64, Option<u64>)> {
        let memory = ins
            .operands
            .iter()
            .find(|operand| operand.displacement.is_some())?;
        if memory.displacement != Some(0) {
            return None;
        }

        let mut table = None;
        let mut index_bound = None;
        let mut components = Vec::with_capacity(2);
        if let Some(base) = memory.base.as_deref().filter(|base| *base != "rip") {
            components.push((base, 1u64));
        }
        if let Some(index) = memory.index.as_deref() {
            components.push((index, u64::from(memory.scale.unwrap_or(1))));
        }
        for (register, address_scale) in components {
            match self.get(register) {
                Some(Val::Addr(address)) if address_scale == 1 && table.is_none() => {
                    table = Some(address);
                }
                Some(Val::ScaledIndex { bound, scale })
                    if address_scale.checked_mul(scale) == Some(4) && index_bound.is_none() =>
                {
                    index_bound = Some(bound);
                }
                _ if address_scale == 4 && index_bound.is_none() => {
                    index_bound = Some(self.bounded.get(canon_ref(register).as_ref()).copied());
                }
                _ => {}
            }
        }
        Some((table?, index_bound?))
    }

    fn fresh_value(&mut self) -> u64 {
        self.next_value_id = self.next_value_id.wrapping_add(1);
        self.next_value_id
    }

    fn value_of(&mut self, reg: &str) -> u64 {
        let key = canon_ref(reg);
        if let Some(value) = self.reg_values.get(key.as_ref()) {
            *value
        } else {
            let value = self.fresh_value();
            self.reg_values.insert(key.into_owned(), value);
            value
        }
    }

    fn define_fresh_value(&mut self, reg: &str) {
        let key = canon_ref(reg);
        let value = self.fresh_value();
        self.bounded.remove(key.as_ref());
        self.reg_values.insert(key.into_owned(), value);
    }

    /// Record that a value is in `[0, max]` for every register and stack slot
    /// that still holds that exact value.
    fn bound_value(&mut self, reg: &str, max: u64) {
        let value = self.value_of(reg);
        for (register, register_value) in &self.reg_values {
            if *register_value == value {
                self.bounded.insert(register.clone(), max);
            }
        }
        let slots: Vec<_> = self
            .slot_values
            .iter()
            .filter(|(_, slot_value)| **slot_value == value)
            .map(|(k, _)| k.clone())
            .collect();
        for k in slots {
            self.bounded_slots.insert(k, max);
        }
    }

    /// Record the same range fact for every live alias of a stack-slot value.
    fn bound_slot_value(&mut self, key: &(String, i64), max: u64) {
        if let Some(value) = self.slot_values.get(key).copied() {
            for (register, register_value) in &self.reg_values {
                if *register_value == value {
                    self.bounded.insert(register.clone(), max);
                }
            }
            let aliases: Vec<_> = self
                .slot_values
                .iter()
                .filter(|(_, slot_value)| **slot_value == value)
                .map(|(alias, _)| alias.clone())
                .collect();
            for alias in aliases {
                self.bounded_slots.insert(alias, max);
            }
        }
        self.bounded_slots.insert(key.clone(), max);
    }

    /// Everything this block established, for its in-range successor to inherit.
    pub fn export_bounds(&self) -> Bounds {
        Bounds {
            regs: self.bounded.clone(),
            slots: self.bounded_slots.clone(),
            mems: self.memory.export(),
        }
    }

    /// Bounds established by value-producing instructions, excluding the
    /// assumption made by the last comparison in this block.
    ///
    /// A `cmp index, N; ja default` proves the bound only on the fallthrough
    /// edge.  In contrast, `xor state,state`, `mov state,1`, and
    /// `sete state_byte; or state,2` produce bounded values on every outgoing
    /// edge.  Keeping the two classes separate lets CFG dataflow carry compiler
    /// generated enum/state values through loops without leaking a conditional
    /// guard onto its taken edge.
    pub fn export_stable_bounds(&self) -> Bounds {
        let mut stable = self.export_bounds();
        // The comparison's own assumption never leaves on an unguarded edge:
        // keep exactly what was inherited and survived this block.
        stable.mems = self.memory.proved();
        if let Some((register, _)) = &self.last_cmp {
            if let Some(value) = self.reg_values.get(register) {
                stable
                    .regs
                    .retain(|candidate, _| self.reg_values.get(candidate) != Some(value));
                stable
                    .slots
                    .retain(|slot, _| self.slot_values.get(slot) != Some(value));
            } else {
                stable.regs.remove(register);
            }
        }
        if let Some((slot, _)) = &self.last_slot_cmp {
            if let Some(value) = self.slot_values.get(slot) {
                stable
                    .regs
                    .retain(|candidate, _| self.reg_values.get(candidate) != Some(value));
                stable
                    .slots
                    .retain(|candidate, _| self.slot_values.get(candidate) != Some(value));
            } else {
                stable.slots.remove(slot);
            }
        }
        stable
    }

    /// Update the tracked state with one decoded instruction.
    ///
    /// [`memory_guard`] brackets the body because it needs state the body
    /// destroys: a store invalidates memory facts BEFORE the instruction is
    /// interpreted, a load's bound is read from the pre-write state (its
    /// destination is routinely the address's own base), and the register it
    /// defines invalidates every fact whose address mentions it.
    pub fn observe(&mut self, ins: &Instruction) {
        self.memory.forget_stores(ins);
        let loaded = self.memory.load_bound(ins);
        let defined = Self::dest_reg(ins).map(canon);
        self.observe_instruction(ins);
        if let (Some(destination), Some(bound)) = (Self::dest_reg(ins), loaded) {
            // Never loosen a bound the body already proved: the tightest
            // surviving proof decides the table's extent.
            let known = self.bounded.get(canon_ref(destination).as_ref()).copied();
            self.bound_value(destination, known.map_or(bound, |old| old.min(bound)));
        }
        if let Some(defined) = defined {
            self.memory.forget_through(&defined);
        }
    }

    fn observe_instruction(&mut self, ins: &Instruction) {
        let m = ascii_lower(&ins.mnemonic);

        // Snapshot the whole effective-address expression before the
        // destination write kills an aliased index or table-base register.
        let table_load_on_entry = self.table_load_on_entry(ins);

        // --- boundedness, tracked as a propagating fact -----------------------
        //
        // Every rule here answers one question: "is this value known to lie in
        // [0, N]?" A jump table's entry count is exactly that, and the value is
        // usually not still in the register that was compared.
        let reg0 = ins.operands.first().and_then(|o| o.register.as_deref());
        let imm1 = ins.operands.get(1).and_then(|o| o.immediate);
        match m.as_ref() {
            // The range check itself. `cmp` leaves the register alone; `sub`
            // rebases it so in-range values become `[0, N]`. Recorded for the
            // walker to carry across the guard's in-range edge, and applied here
            // too so a guard in the dispatch's own block also counts.
            "cmp" | "sub" => {
                self.last_cmp = None;
                self.last_slot_cmp = None;
                // `cmp <memory>, imm` bounds the LOCATION, not a register:
                // gcc -O2 compares a switch selector in place and materialises
                // it only after the branch, so the effective address is the
                // only thing the guard and the load share.
                if m == "cmp" {
                    self.memory.record_comparison(ins, imm1);
                } else {
                    self.memory.clear_comparison();
                }
                if let (Some(r), Some(n)) = (reg0, imm1) {
                    if n >= 0 {
                        self.last_cmp = Some((canon(r), n as u64));
                        self.bound_value(canon_ref(r).as_ref(), n as u64);
                    }
                } else if m == "cmp" {
                    let stack_slot = ins.operands.first().and_then(|operand| {
                        let base = canon_ref(operand.base.as_deref()?);
                        let displacement = operand.displacement?;
                        (matches!(base.as_ref(), "rbp" | "rsp") && operand.index.is_none())
                            .then(|| (base.into_owned(), displacement))
                    });
                    if let (Some(key), Some(n)) = (stack_slot, imm1) {
                        if n >= 0 {
                            self.last_slot_cmp = Some((key.clone(), n as u64));
                            self.bound_slot_value(&key, n as u64);
                        }
                    }
                }
            }
            _ => {}
        }
        // A spill carries the bound into the frame slot; the matching reload
        // carries it back out, possibly into a different register. This is the
        // clang -O0 switch shape, and it is 11 of the 21 dispatches the
        // name-matching version declined.
        if matches!(m.as_ref(), "mov" | "movq" | "movl") {
            let dst_mem = ins
                .operands
                .first()
                .and_then(|o| o.displacement.map(|d| (o.base.as_deref(), d)));
            let src_reg = ins.operands.get(1).and_then(|o| o.register.as_deref());
            let src_mem = ins
                .operands
                .get(1)
                .and_then(|o| o.displacement.map(|d| (o.base.as_deref(), d)));
            match (dst_mem, src_reg, src_mem, reg0) {
                // store: [base+disp] <- reg
                (Some((Some(b), d)), Some(sr), _, _) => {
                    let key = (canon(b), d);
                    let value = self.value_of(sr);
                    self.slot_values.insert(key.clone(), value);
                    match self.bounded.get(canon_ref(sr).as_ref()).copied() {
                        Some(n) => {
                            self.bounded_slots.insert(key, n);
                        }
                        None => {
                            self.bounded_slots.remove(&key);
                        }
                    }
                }
                // load: reg <- [base+disp]
                (None, None, Some((Some(b), d)), Some(dr)) => {
                    let key = (canon(b), d);
                    let destination = canon_ref(dr);
                    if let Some(value) = self.slot_values.get(&key).copied() {
                        self.reg_values
                            .insert(destination.clone().into_owned(), value);
                    } else {
                        self.define_fresh_value(dr);
                    }
                    match self.bounded_slots.get(&key).copied() {
                        Some(n) => {
                            self.bounded.insert(destination.into_owned(), n);
                        }
                        None => {
                            self.bounded.remove(destination.as_ref());
                        }
                    }
                }
                // copy: reg <- reg
                (None, Some(sr), None, Some(dr)) => {
                    let value = self.value_of(sr);
                    let destination = canon_ref(dr);
                    self.reg_values
                        .insert(destination.clone().into_owned(), value);
                    match self.bounded.get(canon_ref(sr).as_ref()).copied() {
                        Some(n) => {
                            self.bounded.insert(destination.into_owned(), n);
                        }
                        None => {
                            self.bounded.remove(destination.as_ref());
                        }
                    }
                }
                _ => {
                    if let Some(dr) = Self::dest_reg(ins) {
                        self.define_fresh_value(dr);
                        if let Some(value) = imm1.filter(|value| *value >= 0) {
                            self.bound_value(dr, value as u64);
                        }
                    }
                }
            }
        } else if let Some(d) = Self::dest_reg(ins) {
            let previous_bound = self.bounded.get(canon_ref(d).as_ref()).copied();
            let zero_extended_bound = m
                .starts_with("movz")
                .then(|| {
                    ins.operands
                        .get(1)
                        .and_then(|operand| operand.register.as_deref())
                        .and_then(|source| self.bounded.get(canon_ref(source).as_ref()).copied())
                })
                .flatten();
            // Synthetic instruction adapters may mark `cmp`'s first operand as
            // ReadWrite even though the machine instruction does not write it.
            // Preserve its identity just as the real decoder does.
            if m == "cmp" {
                // No value definition.
            } else {
                // `sub` first bounds its pre-write aliases above, then creates
                // a distinct destination value. Preserve the historical bound
                // on that result too: some adapters model a range check and
                // subsequent table index through the same register.
                self.define_fresh_value(d);
            }
            if m == "xor"
                && ins
                    .operands
                    .get(1)
                    .and_then(|operand| operand.register.as_deref())
                    .is_some_and(|source| canon_ref(source) == canon_ref(d))
            {
                self.bound_value(d, 0);
            } else if m.starts_with("set") {
                if let Some(previous) = previous_bound {
                    // SETcc replaces only the low byte.  The highest possible
                    // upper-byte prefix is inherited from the old value; the
                    // new low byte is exactly zero or one.
                    let upper = previous & !0xff;
                    if let Some(bound) = upper.checked_add(1) {
                        self.bound_value(d, bound);
                    }
                }
            } else if m == "or" {
                if let (Some(previous), Some(mask)) =
                    (previous_bound, imm1.filter(|value| *value >= 0))
                {
                    // x | mask <= x + mask for non-negative integers.
                    if let Some(bound) = previous.checked_add(mask as u64) {
                        self.bound_value(d, bound);
                    }
                }
            } else if m == "and" {
                if let Some(n) = imm1
                    .filter(|n| *n > 0 && (*n as u64).count_zeros() == (*n as u64).leading_zeros())
                {
                    self.bound_value(d, n as u64);
                }
            } else if m == "sub" {
                if let Some(n) = imm1.filter(|n| *n >= 0) {
                    self.bound_value(d, n as u64);
                }
            } else if let Some(bound) = zero_extended_bound {
                self.bound_value(d, bound);
            }
        }

        // ARM `add rD, pc, #imm` — the assembler's `adr`, and the only way a
        // jump table's base reaches a register on 32-bit ARM.
        //
        // Handled ahead of the `dest_reg` guard because that guard cannot see
        // an ARM definition at all: Capstone's ARM detail marks EVERY operand
        // `Access::Read` (the same limitation `kill_register` exists for), so
        // `dest_reg` returns `None` for every ARM instruction and every rule
        // below it is x86-only in practice. The destination is therefore taken
        // from operand 0 by position, which is what the encoding guarantees.
        if let Some(address) = self.arm_adr_target(ins) {
            if let Some(destination) = ins.operands.first().and_then(|o| o.register.as_deref()) {
                self.set(destination, Val::Addr(address));
                return;
            }
        }

        let Some(dest) = Self::dest_reg(ins) else {
            return;
        };

        match m.as_ref() {
            // `lea rD, [rip+d]` materialises an absolute address — how position-
            // independent code names a table.
            "lea" => {
                if let Some(va) = Self::rip_target(ins) {
                    self.set(dest, Val::Addr(va));
                } else if let Some(memory) = ins
                    .operands
                    .iter()
                    .find(|operand| operand.displacement.is_some())
                {
                    let scale = u64::from(memory.scale.unwrap_or(1));
                    let scaled_bound = memory
                        .index
                        .as_deref()
                        .map(canon)
                        .and_then(|index| self.bounded.get(&index).copied());
                    if memory.base.is_none()
                        && memory.displacement == Some(0)
                        && memory.index.is_some()
                        && scale > 1
                    {
                        self.set(
                            dest,
                            Val::ScaledIndex {
                                bound: scaled_bound,
                                scale,
                            },
                        );
                    } else {
                        self.clear(dest);
                    }
                } else {
                    self.clear(dest);
                }
            }
            // A sign-extending load indexed off a tracked table base is the table
            // read. The index is deliberately not tracked: every entry is a
            // possible outcome, which is exactly the successor set we want.
            "movslq" | "movsxd" | "movsx" => match table_load_on_entry {
                Some((table, bound)) => self.set(dest, Val::TableOffset { table, bound }),
                _ => self.clear(dest),
            },
            // offset + base == target. Either operand order.
            "add" => {
                let src = ins.operands.get(1).and_then(|o| o.register.as_deref());
                let dv = self.get(dest);
                let sv = src.and_then(|s| self.get(s));
                match (dv, sv) {
                    (Some(Val::TableOffset { table: a, bound }), Some(Val::Addr(b)))
                    | (Some(Val::Addr(b)), Some(Val::TableOffset { table: a, bound }))
                        if a == b =>
                    {
                        self.set(dest, Val::TableTarget { table: a, bound })
                    }
                    _ => self.clear(dest),
                }
            }
            "mov" | "movq" | "movl" => {
                // Register-to-register copy propagates; anything else (a load, an
                // immediate that is not an address) drops the destination. An
                // immediate is kept as a candidate address so non-PIC tables,
                // which name the table with a plain `mov`, still resolve.
                let src = ins.operands.get(1);
                if let Some((table, bound)) = table_load_on_entry {
                    self.set(dest, Val::TableOffset { table, bound });
                } else if let Some(v) = src
                    .and_then(|o| o.register.as_deref())
                    .and_then(|r| self.get(r))
                {
                    self.set(dest, v);
                } else if let Some(imm) = src.and_then(|o| o.immediate) {
                    if imm > 0 {
                        self.set(dest, Val::Addr(imm as u64));
                    } else {
                        self.clear(dest);
                    }
                } else {
                    self.clear(dest);
                }
            }
            // Every other write is unmodelled. Dropping the destination is the
            // safe direction: it costs a resolution, never invents one.
            _ => self.clear(dest),
        }
    }

    /// Forget everything known about `register`, for a caller that must model
    /// definitions itself.
    ///
    /// [`Self::observe`] discovers definitions through `Access::Write` on
    /// operand 0, and Capstone's ARM detail marks **every** operand `Read` (see
    /// `disasm::capstone`). On ARM32 that leaves `observe` unable to see any
    /// write at all, so a range bound would survive the very instruction that
    /// overwrote the index — `sub.w r5, r5, #0x3000` between the guard and the
    /// dispatch is exactly that shape, and it appears in betaflight. The ARM
    /// block walker therefore identifies definitions from the mnemonic and
    /// reports them here.
    pub fn kill_register(&mut self, register: &str) {
        self.define_fresh_value(register);
        let key = canon_ref(register);
        self.regs.remove(key.as_ref());
        self.memory.forget_through(key.as_ref());
    }

    /// Resolve an indirect transfer, given the tables discovered in this binary.
    ///
    /// `Some` for a register-indirect transfer (whether or not it resolved);
    /// `None` when this instruction is not one, so the caller can tell "not a
    /// dispatch" from "a dispatch I could not read".
    pub fn resolve(
        &self,
        ins: &Instruction,
        tables: &BTreeMap<u64, Vec<u64>>,
    ) -> Option<Resolution> {
        self.resolve_with(ins, tables, |_table, _entry_count| {
            Err(crate::analysis::jump_table::TableDecline::DecodeNotAttempted)
        })
    }

    /// Resolve a dispatch, decoding an exact bounded table on demand when the
    /// whole-section scan did not expose this table's starting address.
    ///
    /// `decode_bounded` reports *which* check refused rather than a bare
    /// `None`, so the reason reaches [`Unresolved::NoTableAt`] instead of being
    /// reconstructed as a guess here.
    pub fn resolve_with<F>(
        &self,
        ins: &Instruction,
        tables: &BTreeMap<u64, Vec<u64>>,
        decode_bounded: F,
    ) -> Option<Resolution>
    where
        F: FnOnce(u64, usize) -> Result<Vec<u64>, crate::analysis::jump_table::TableDecline>,
    {
        let reg = ins.operands.first()?.register.as_deref()?;
        Some(match self.get(reg) {
            Some(Val::TableTarget { table, bound }) => match bound {
                // The scan cannot see where a table ends; the guard can. Without a
                // guard there is NO safe entry count, so this fails closed.
                //
                // It used to fall back to the whole scanned run, which is the
                // single worst decision in this module's history: the rodata scan
                // returns 65 entries for an 8-entry table (the next table's
                // offsets, read against the previous table's base, still land in
                // `.text`), so every unguarded dispatch gained ~57 successors
                // belonging to other functions. Measured cost: DecBench GED
                // 10.24 -> 12.73 across 56 cells, 34 of them worse.
                //
                // An unrecovered jump table is honest and costs one function; a
                // 65-arm one is confidently wrong and corrupts every function it
                // reaches into.
                Some(bound) => {
                    let entry_count = usize::try_from(bound)
                        .ok()
                        .and_then(|bound| bound.checked_add(1));
                    let Some(entry_count) = entry_count else {
                        return Some(Resolution::Unresolved(Unresolved::NoTableAt {
                            table,
                            decline:
                                crate::analysis::jump_table::TableDecline::BoundExceedsAddressSpace {
                                    bound,
                                },
                        }));
                    };
                    let scanned = tables
                        .get(&table)
                        .and_then(|targets| targets.get(..entry_count))
                        .map(<[u64]>::to_vec);
                    match scanned
                        .ok_or(())
                        .or_else(|()| decode_bounded(table, entry_count))
                    {
                        Ok(targets) => Resolution::Table {
                            table_va: table,
                            targets,
                        },
                        Err(decline) => {
                            Resolution::Unresolved(Unresolved::NoTableAt { table, decline })
                        }
                    }
                }
                None if tables.contains_key(&table) => {
                    Resolution::Unresolved(Unresolved::NoBound(table))
                }
                None => Resolution::Unresolved(Unresolved::NoTableAt {
                    table,
                    decline: crate::analysis::jump_table::TableDecline::ScanFoundNoTable,
                }),
            },
            _ => Resolution::Unresolved(Unresolved::UnknownBase),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::instruction::{Access, Operand, OperandKind};

    /// A written register operand. Access is modelled because the tracker keys
    /// definitions off it — see `dest_reg`.
    fn reg_op(name: &str) -> Operand {
        reg_op_access(name, Access::ReadWrite)
    }

    /// A register the instruction only READS — what `jmp rax` has.
    fn reg_read(name: &str) -> Operand {
        reg_op_access(name, Access::Read)
    }

    fn reg_op_access(name: &str, access: Access) -> Operand {
        Operand {
            kind: OperandKind::Register,
            size: 64,
            access,
            text: name.to_string(),
            register: Some(name.to_string()),
            immediate: None,
            displacement: None,
            segment: None,
            scale: None,
            base: None,
            index: None,
            vector_shape: None,
            vector_index: None,
        }
    }

    fn mem_op(base: Option<&str>, disp: i64, index: Option<&str>) -> Operand {
        mem_op_scale(base, disp, index, 4)
    }

    fn mem_op_scale(base: Option<&str>, disp: i64, index: Option<&str>, scale: u8) -> Operand {
        Operand {
            kind: OperandKind::Memory,
            size: 64,
            access: Access::Read,
            text: String::new(),
            register: None,
            immediate: None,
            displacement: Some(disp),
            segment: None,
            scale: Some(scale),
            base: base.map(str::to_string),
            index: index.map(str::to_string),
            vector_shape: None,
            vector_index: None,
        }
    }

    fn imm_op(v: i64) -> Operand {
        Operand {
            kind: OperandKind::Immediate,
            size: 64,
            access: Access::Read,
            text: String::new(),
            register: None,
            immediate: Some(v),
            displacement: None,
            segment: None,
            scale: None,
            base: None,
            index: None,
            vector_shape: None,
            vector_index: None,
        }
    }

    fn ins(mnemonic: &str, operands: Vec<Operand>) -> Instruction {
        use crate::core::address::{Address, AddressKind};
        Instruction {
            address: Address::new(AddressKind::VA, 0x1000, 64, None, None).unwrap(),
            bytes: Vec::new(),
            mnemonic: mnemonic.to_string(),
            operands,
            length: 4,
            arch: "x86_64".to_string(),
            semantics: None,
            side_effects: None,
            prefixes: None,
            groups: None,
        }
    }

    fn tables() -> BTreeMap<u64, Vec<u64>> {
        BTreeMap::from([(0x2000, vec![0x112e, 0x113a, 0x1146, 0x1152])])
    }

    /// An `Instruction` at a chosen address and length — ARM `pc` arithmetic
    /// and table placement both depend on both.
    fn ins_at(mnemonic: &str, operands: Vec<Operand>, va: u64, length: u16) -> Instruction {
        let mut instruction = ins(mnemonic, operands);
        instruction.address = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            va,
            32,
            None,
            None,
        )
        .unwrap();
        instruction.length = length;
        instruction.arch = "arm".to_string();
        instruction
    }

    /// The ARM table dispatch every one of the 321 sites in the frozen
    /// DecBench sample-set takes.
    ///
    /// Transcribed byte-exactly from `bin_001.elf` at `0x0800d48e`, a Cortex-M
    /// firmware image in the sample-set:
    ///
    /// ```text
    /// 800d490:  cmp   r2, #4
    /// 800d492:  bhi.n 0x800d500
    /// 800d494:  add   r3, pc, #4        @ (adr r3, 0x800d49c)   -- 2 bytes
    /// 800d496:  ldr.w pc, [r3, r2, lsl #2]                      -- 4 bytes
    /// 800d49c:  <5 absolute word entries, Thumb bit set>
    /// ```
    ///
    /// Thumb `pc` at `0x800d494` reads `(0x800d494 + 4) & !3 == 0x800d498`, so
    /// `+ 4` names `0x800d49c`. An A32 reading of the same instruction would
    /// name `0x800d4a0` and decode four bytes of the wrong thing without
    /// complaining, which is why the execution state is declared rather than
    /// inferred.
    #[test]
    fn the_real_thumb2_absolute_word_table_dispatch_resolves() {
        let mut tracker = DispatchTracker::new();
        tracker.set_arm_pc_mode(Some(ArmPcMode::Thumb));
        // The guard sits in the preceding block; the walker carries its proof
        // across the in-range (fall-through) edge of `bhi`.
        tracker.inherit_bound(Some(Bounds {
            regs: HashMap::from([("r2".to_string(), 4)]),
            slots: HashMap::new(),
            mems: HashMap::new(),
        }));
        // Capstone reports the 16-bit Thumb encoding as `adr r3, #4` — two
        // operands, `pc` implicit. Transcribed from the real decode, not from
        // objdump's `add r3, pc, #4` rendering of the same two bytes.
        tracker.observe(&ins_at(
            "adr",
            vec![reg_read("r3"), imm_op(4)],
            0x0800_d494,
            2,
        ));

        let branch = tracker
            .arm_word_table_branch(&ins_at(
                "ldr.w",
                vec![reg_read("pc"), mem_op_scale(Some("r3"), 0, Some("r2"), 4)],
                0x0800_d496,
                4,
            ))
            .expect("`ldr pc, [rBase, rIdx, lsl #2]` off a materialised base is a table branch");

        assert_eq!(
            branch.table_va, 0x0800_d49c,
            "Thumb `add r3, pc, #4` at 0x800d494 names 0x800d49c"
        );
        assert_eq!(
            branch.entry_count,
            Some(5),
            "`cmp r2, #4` proves five entries, not four"
        );
    }

    /// The A32 spelling of the same operation: `add rD, pc, #imm`, three
    /// operands with `pc` named. Both encodings must reach the same address.
    #[test]
    fn the_a32_add_pc_spelling_materialises_the_same_base() {
        let mut tracker = DispatchTracker::new();
        tracker.set_arm_pc_mode(Some(ArmPcMode::A32));
        tracker.inherit_bound(Some(Bounds {
            regs: HashMap::from([("r0".to_string(), 7)]),
            slots: HashMap::new(),
            mems: HashMap::new(),
        }));
        // `add r3, pc, #0` at 0x0800000c: A32 `pc` reads 0x08000014.
        tracker.observe(&ins_at(
            "add",
            vec![reg_read("r3"), reg_read("pc"), imm_op(0)],
            0x0800_000c,
            4,
        ));
        let branch = tracker
            .arm_word_table_branch(&ins_at(
                "ldr",
                vec![reg_read("pc"), mem_op_scale(Some("r3"), 0, Some("r0"), 4)],
                0x0800_0010,
                4,
            ))
            .expect("the A32 spelling resolves too");
        assert_eq!(branch.table_va, 0x0800_0014);
        assert_eq!(branch.entry_count, Some(8));
    }

    /// Without a declared execution state the base is never materialised, so
    /// the dispatch declines instead of naming a table four bytes off.
    #[test]
    fn an_arm_dispatch_without_a_declared_pc_mode_declines() {
        let mut tracker = DispatchTracker::new();
        tracker.inherit_bound(Some(Bounds {
            regs: HashMap::from([("r2".to_string(), 4)]),
            slots: HashMap::new(),
            mems: HashMap::new(),
        }));
        tracker.observe(&ins_at(
            "adr",
            vec![reg_read("r3"), imm_op(4)],
            0x0800_d494,
            2,
        ));
        assert_eq!(
            tracker.arm_word_table_branch(&ins_at(
                "ldr.w",
                vec![reg_read("pc"), mem_op_scale(Some("r3"), 0, Some("r2"), 4)],
                0x0800_d496,
                4,
            )),
            None
        );
    }

    /// A32 and Thumb disagree about `pc`, and the difference is a real table
    /// address. Pin both.
    #[test]
    fn a32_and_thumb_pc_readings_differ_and_both_are_exact() {
        assert_eq!(ArmPcMode::A32.pc_value(0x0800_d494), Some(0x0800_d49c));
        assert_eq!(ArmPcMode::Thumb.pc_value(0x0800_d494), Some(0x0800_d498));
        // Thumb rounds DOWN to a word boundary: an `adr` at an odd halfword
        // reads the same `pc` as one at the preceding even halfword.
        assert_eq!(ArmPcMode::Thumb.pc_value(0x0800_d496), Some(0x0800_d498));
        assert_eq!(ArmPcMode::Thumb.pc_value(0x0800_d498), Some(0x0800_d49c));
    }

    /// An ordinary indexed load into a general register is not a branch, and a
    /// non-word stride is a table this decoder cannot read.
    #[test]
    fn only_a_word_strided_load_into_pc_is_a_table_branch() {
        let mut tracker = DispatchTracker::new();
        tracker.set_arm_pc_mode(Some(ArmPcMode::Thumb));
        tracker.observe(&ins_at(
            "adr",
            vec![reg_read("r3"), imm_op(4)],
            0x0800_d494,
            2,
        ));
        // Destination is r0, not pc.
        assert_eq!(
            tracker.arm_word_table_branch(&ins_at(
                "ldr.w",
                vec![reg_read("r0"), mem_op_scale(Some("r3"), 0, Some("r2"), 4)],
                0x0800_d496,
                4,
            )),
            None
        );
        // Halfword stride.
        assert_eq!(
            tracker.arm_word_table_branch(&ins_at(
                "ldr.w",
                vec![reg_read("pc"), mem_op_scale(Some("r3"), 0, Some("r2"), 2)],
                0x0800_d496,
                4,
            )),
            None
        );
        // Base register holds no proven address.
        assert_eq!(
            tracker.arm_word_table_branch(&ins_at(
                "ldr.w",
                vec![reg_read("pc"), mem_op_scale(Some("r9"), 0, Some("r2"), 4)],
                0x0800_d496,
                4,
            )),
            None
        );
    }

    #[test]
    fn the_real_gcc_o0_scaled_index_shape_resolves() {
        let mut tracker = DispatchTracker::new();
        tracker.inherit_bound(Some(Bounds {
            regs: HashMap::from([("rax".to_string(), 3)]),
            slots: HashMap::new(),
            mems: HashMap::new(),
        }));
        tracker.observe(&ins("mov", vec![reg_op("rax"), reg_read("rax")]));
        tracker.observe(&ins(
            "lea",
            vec![reg_op("rdx"), mem_op_scale(None, 0, Some("rax"), 4)],
        ));
        tracker.observe(&ins(
            "lea",
            vec![reg_op("rax"), mem_op(Some("rip"), 0x2000, None)],
        ));
        tracker.observe(&ins(
            "mov",
            vec![reg_op("rax"), mem_op_scale(Some("rdx"), 0, Some("rax"), 1)],
        ));
        // The real `cdqe` has implicit operands, so observing it leaves the
        // table-offset fact on the canonical rax/eax register.
        tracker.observe(&ins("cdqe", Vec::new()));
        tracker.observe(&ins(
            "lea",
            vec![reg_op("rdx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        tracker.observe(&ins("add", vec![reg_op("rax"), reg_op("rdx")]));

        match tracker.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()) {
            Some(Resolution::Table { targets, .. }) => assert_eq!(targets.len(), 4),
            other => panic!("the GCC -O0 scaled-index shape must resolve, got {other:?}"),
        }
    }

    #[test]
    fn a_gcc_o0_stack_slot_guard_bounds_the_reloaded_dispatch_index() {
        // GCC 15 -O0 compares the spilled source value in memory, not a
        // register: `cmp DWORD PTR [rbp-4],4; ja default`.  The in-range edge
        // then reloads that exact slot before forming the relative table read.
        let mut guard = DispatchTracker::new();
        guard.observe(&ins(
            "mov",
            vec![mem_op(Some("rbp"), -4, None), reg_read("rdi")],
        ));
        guard.observe(&ins("cmp", vec![mem_op(Some("rbp"), -4, None), imm_op(4)]));
        assert!(
            guard.pending_bound().is_some(),
            "the unsigned guard must expose an in-range fact"
        );

        let mut tracker = DispatchTracker::new();
        tracker.inherit_bound(Some(guard.export_bounds()));
        tracker.observe(&ins(
            "mov",
            vec![reg_op("rax"), mem_op(Some("rbp"), -4, None)],
        ));
        tracker.observe(&ins(
            "lea",
            vec![reg_op("rdx"), mem_op_scale(None, 0, Some("rax"), 4)],
        ));
        tracker.observe(&ins(
            "lea",
            vec![reg_op("rax"), mem_op(Some("rip"), 0x2000, None)],
        ));
        tracker.observe(&ins(
            "mov",
            vec![reg_op("rax"), mem_op_scale(Some("rdx"), 0, Some("rax"), 1)],
        ));
        tracker.observe(&ins("cdqe", Vec::new()));
        tracker.observe(&ins(
            "lea",
            vec![reg_op("rdx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        tracker.observe(&ins("add", vec![reg_op("rax"), reg_op("rdx")]));

        let tables = BTreeMap::from([(0x2000, vec![0x1213, 0x1224, 0x1235, 0x1246, 0x1257])]);
        match tracker.resolve(&ins("jmp", vec![reg_read("rax")]), &tables) {
            Some(Resolution::Table { targets, .. }) => assert_eq!(targets.len(), 5),
            other => panic!("the stack-slot guard must resolve, got {other:?}"),
        }
    }

    #[test]
    fn iced_decoded_gcc_o0_scaled_index_shape_resolves() {
        use crate::core::address::{Address, AddressKind};
        use crate::core::binary::Endianness;
        use crate::core::disassembler::{Architecture, Disassembler};
        use crate::disasm::registry;

        // GCC 11.4 -O0 `dense_compute`, from the first instruction after its
        // range guard through the computed jump.
        let bytes = [
            0x89, 0xc0, 0x48, 0x8d, 0x14, 0x85, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x05, 0x85,
            0x0e, 0x00, 0x00, 0x8b, 0x04, 0x02, 0x48, 0x98, 0x48, 0x8d, 0x15, 0x79, 0x0e, 0x00,
            0x00, 0x48, 0x01, 0xd0, 0x3e, 0xff, 0xe0,
        ];
        let decoder =
            registry::for_arch(Architecture::X86_64, Endianness::Little).expect("x86-64 decoder");
        let mut tracker = DispatchTracker::new();
        tracker.inherit_bound(Some(Bounds {
            regs: HashMap::from([("rax".to_string(), 3)]),
            slots: HashMap::new(),
            mems: HashMap::new(),
        }));
        let mut offset = 0usize;
        let mut jump = None;
        while offset < bytes.len() {
            let address =
                Address::new(AddressKind::VA, 0x118a + offset as u64, 64, None, None).unwrap();
            let instruction = decoder
                .disassemble_instruction(&address, &bytes[offset..])
                .expect("decode real GCC dispatch instruction");
            offset += instruction.length as usize;
            tracker.observe(&instruction);
            if instruction.mnemonic == "jmp" {
                jump = Some(instruction);
                break;
            }
        }

        let decoded_tables = BTreeMap::from([(0x2020, vec![0x112e, 0x113a, 0x1146, 0x1152])]);
        match tracker.resolve(jump.as_ref().expect("computed jump"), &decoded_tables) {
            Some(Resolution::Table { targets, .. }) => assert_eq!(targets.len(), 4),
            other => panic!("the decoded GCC -O0 shape must resolve, got {other:?}"),
        }
    }

    /// A memory operand at a chosen access width, so a test can say "the byte
    /// at `[base + index*scale + disp]`" the way the encoding does.
    fn mem_op_sized(
        base: Option<&str>,
        disp: i64,
        index: Option<&str>,
        scale: u8,
        size: u8,
    ) -> Operand {
        let mut operand = mem_op_scale(base, disp, index, scale);
        operand.size = size;
        operand
    }

    fn reg_write_sized(name: &str, size: u8) -> Operand {
        let mut operand = reg_op_access(name, Access::Write);
        operand.size = size;
        operand
    }

    fn imm_sized(value: i64, size: u8) -> Operand {
        let mut operand = imm_op(value);
        operand.size = size;
        operand
    }

    /// The real GCC 14 -O2 `adt204_switch_a`, verbatim from
    /// `tests/decompiler_fixtures/src/204_adjacent_dispatch_tables.c`:
    ///
    /// ```text
    /// lea    0xf15(%rip),%rax        ; the permutation table
    /// and    $0x7,%edi
    /// cmpb   $0x6,(%rax,%rdi,1)      ; the guard — on an INDEXED MEMORY operand
    /// ja     default                 ; ---- block boundary ----
    /// movzbl (%rax,%rdi,1),%eax      ; the SAME effective address
    /// lea    0xe81(%rip),%rdx ; movslq (%rdx,%rax,4),%rax ; add %rdx,%rax ; jmp *%rax
    /// ```
    ///
    /// There is no register holding the compared value on either side of the
    /// branch, so a rule keyed on a register name proves nothing here. The
    /// bound has to be carried on the effective-address expression, which the
    /// `movzbl` reads component-for-component unchanged.
    #[test]
    fn the_real_gcc_o2_indexed_memory_guard_resolves_across_the_edge() {
        use crate::core::address::{Address, AddressKind};
        use crate::core::binary::Endianness;
        use crate::core::disassembler::{Architecture, Disassembler};
        use crate::disasm::registry;

        let guard_bytes = [
            0x48, 0x8d, 0x05, 0x15, 0x0f, 0x00, 0x00, // lea 0xf15(%rip),%rax
            0x83, 0xe7, 0x07, // and $0x7,%edi
            0x80, 0x3c, 0x38, 0x06, // cmpb $0x6,(%rax,%rdi,1)
        ];
        let dispatch_bytes = [
            0x0f, 0xb6, 0x04, 0x38, // movzbl (%rax,%rdi,1),%eax
            0x48, 0x8d, 0x15, 0x81, 0x0e, 0x00, 0x00, // lea 0xe81(%rip),%rdx
            0x48, 0x63, 0x04, 0x82, // movslq (%rdx,%rax,4),%rax
            0x48, 0x01, 0xd0, // add %rdx,%rax
            0x3e, 0xff, 0xe0, // notrack jmp *%rax
        ];
        let decoder =
            registry::for_arch(Architecture::X86_64, Endianness::Little).expect("x86-64 decoder");
        let mut replay = |tracker: &mut DispatchTracker, base: u64, bytes: &[u8]| {
            let mut offset = 0usize;
            let mut last = None;
            while offset < bytes.len() {
                let address =
                    Address::new(AddressKind::VA, base + offset as u64, 64, None, None).unwrap();
                let instruction = decoder
                    .disassemble_instruction(&address, &bytes[offset..])
                    .expect("decode real GCC -O2 dispatch instruction");
                offset += instruction.length as usize;
                tracker.observe(&instruction);
                last = Some(instruction);
            }
            last.expect("at least one instruction")
        };

        let mut guard_block = DispatchTracker::new();
        replay(&mut guard_block, 0x1164, &guard_bytes);
        assert_eq!(
            guard_block.pending_bound(),
            Some(6),
            "`cmpb $0x6,(%rax,%rdi,1)` is the range check; without a pending \
             bound the walker never records anything on the in-range edge"
        );
        let carried = guard_block.export_bounds();
        assert!(
            !carried.mems.is_empty(),
            "the proof lives on the address expression, not on a register"
        );
        assert!(
            guard_block.export_stable_bounds().mems.is_empty(),
            "the comparison's assumption holds only on the guard's in-range \
             edge, so it must not leave on an unguarded one"
        );

        // The dispatch is a DIFFERENT block. Nothing survives except what the
        // in-range edge carries.
        let mut dispatch_block = DispatchTracker::new();
        dispatch_block.inherit_bound(Some(carried));
        // `lea 0xf15(%rip),%rax` is in the guard block, so the table base
        // reaches this block the same way the real walker delivers it.
        dispatch_block.inherit_addresses(Some(&HashMap::from([("rax".to_string(), 0x2080u64)])));
        let jump = replay(&mut dispatch_block, 0x1174, &dispatch_bytes);
        assert_eq!(jump.mnemonic, "jmp");

        let decoded = BTreeMap::from([(
            0x2000,
            vec![
                0x11a0, 0x11a8, 0x11b0, 0x11c0, 0x11c8, 0x1190, 0x1198, 0x11cc,
            ],
        )]);
        match dispatch_block.resolve(&jump, &decoded) {
            Some(Resolution::Table { targets, .. }) => assert_eq!(
                targets.len(),
                7,
                "`<= 6` is seven entries, and the eighth belongs to the next \
                 table in `.rodata`"
            ),
            other => panic!("the real GCC -O2 indexed-memory guard must resolve, got {other:?}"),
        }
    }

    /// The bound is attributed to an effective address, so every component of
    /// that address is part of the identity. Change any one of them and the
    /// load is reading somewhere else.
    #[test]
    fn a_load_from_a_different_effective_address_inherits_nothing() {
        let bounded = |cmp: Operand| {
            let mut guard = DispatchTracker::new();
            guard.observe(&ins("cmp", vec![cmp, imm_sized(6, 8)]));
            guard.export_bounds()
        };
        let guarded = mem_op_sized(Some("rax"), 0, Some("rdi"), 1, 8);
        let cases: Vec<(&str, Operand)> = vec![
            (
                "a different base",
                mem_op_sized(Some("rcx"), 0, Some("rdi"), 1, 8),
            ),
            (
                "a different index",
                mem_op_sized(Some("rax"), 0, Some("rcx"), 1, 8),
            ),
            (
                "a different scale",
                mem_op_sized(Some("rax"), 0, Some("rdi"), 4, 8),
            ),
            (
                "a different displacement",
                mem_op_sized(Some("rax"), 1, Some("rdi"), 1, 8),
            ),
            (
                "a different access width",
                mem_op_sized(Some("rax"), 0, Some("rdi"), 1, 32),
            ),
            ("no index at all", mem_op_sized(Some("rax"), 0, None, 1, 8)),
        ];
        for (what, load_from) in cases {
            let mut dispatch = DispatchTracker::new();
            dispatch.inherit_bound(Some(bounded(guarded.clone())));
            dispatch.observe(&ins("movzx", vec![reg_write_sized("ecx", 32), load_from]));
            assert_eq!(
                dispatch.export_bounds().regs.get("rcx"),
                None,
                "{what} is a different location; a bound proved about \
                 (%rax,%rdi,1) must not reach it"
            );
        }
    }

    /// The same address expression names a different location once anything
    /// could have written a component of it, or the memory behind it.
    #[test]
    fn an_intervening_write_refuses_the_memory_bound() {
        let guarded = mem_op_sized(Some("rax"), 0, Some("rdi"), 1, 8);
        let interventions: Vec<(&str, Instruction)> = vec![
            (
                "the base is redefined",
                ins("mov", vec![reg_op("rax"), reg_read("rsi")]),
            ),
            (
                "the index is redefined",
                ins("add", vec![reg_op("rdi"), imm_op(1)]),
            ),
            (
                "a store could have aliased the location",
                ins("mov", vec![mem_op(Some("rsp"), 8, None), reg_read("rsi")]),
            ),
            (
                "an unmodelled instruction could have written anything",
                ins("call", vec![reg_read("rsi")]),
            ),
            (
                "a push writes memory the allowlist does not model",
                ins("push", vec![reg_read("rsi")]),
            ),
        ];
        for (what, intervening) in interventions {
            let mut guard = DispatchTracker::new();
            guard.observe(&ins("cmp", vec![guarded.clone(), imm_sized(6, 8)]));
            let mut dispatch = DispatchTracker::new();
            dispatch.inherit_bound(Some(guard.export_bounds()));
            dispatch.observe(&intervening);
            dispatch.observe(&ins(
                "movzx",
                vec![reg_write_sized("ecx", 32), guarded.clone()],
            ));
            assert_eq!(
                dispatch.export_bounds().regs.get("rcx"),
                None,
                "{what}, so the guard proved nothing about what the load reads"
            );
        }
    }

    /// A comparison in the dispatch's OWN block has proved nothing: the branch
    /// that acts on its flags has not been taken. Only an inherited fact — one
    /// that crossed a guard's in-range edge — may bind a load.
    #[test]
    fn a_memory_comparison_binds_no_load_in_its_own_block() {
        let guarded = mem_op_sized(Some("rax"), 0, Some("rdi"), 1, 8);
        let mut block = DispatchTracker::new();
        block.observe(&ins("cmp", vec![guarded.clone(), imm_sized(6, 8)]));
        block.observe(&ins("movzx", vec![reg_write_sized("ecx", 32), guarded]));
        assert_eq!(
            block.export_bounds().regs.get("rcx"),
            None,
            "without the branch there is no in-range edge and no proof"
        );
    }

    /// The real clang -O0 switch, verbatim from `switch_jt.clang.O0@0x1100`:
    /// the value is spilled to its frame slot BEFORE the guard runs, the guard
    /// then bounds the register, and the dispatch block (a separate block, after
    /// the guard's branch) reloads the slot into a different register.
    ///
    /// ```text
    /// mov -0x8(%rbp),%eax     ; the switch value
    /// mov %rax,-0x18(%rbp)    ; spill — NOT bounded yet
    /// sub $0x7,%rax           ; now bounded
    /// ja  default             ; ---- block boundary ----
    /// mov -0x18(%rbp),%rcx    ; reload into another register
    /// lea 0xedb(%rip),%rax ; movslq (%rax,%rcx,4),%rcx ; add %rcx,%rax ; jmp *%rax
    /// ```
    ///
    /// The guard proves the PRE-`sub` value is in `[0,7]`, and the slot holds
    /// exactly that value — so the bound has to reach the slot backwards through
    /// the alias, then forwards across the block edge.
    #[test]
    fn the_real_clang_o0_shape_resolves_across_the_guard_edge() {
        let mut guard_block = DispatchTracker::new();
        guard_block.observe(&ins(
            "mov",
            vec![reg_op("rax"), mem_op(Some("rbp"), -8, None)],
        ));
        guard_block.observe(&ins(
            "mov",
            vec![mem_op(Some("rbp"), -24, None), reg_read("rax")],
        )); // spill, before the guard
        guard_block.observe(&ins("sub", vec![reg_op("rax"), imm_op(3)])); // guard
        let carried = guard_block.export_bounds();

        // The dispatch is a DIFFERENT block; state does not survive except via
        // the guard's in-range edge.
        let mut t = DispatchTracker::new();
        t.inherit_bound(Some(carried));
        t.observe(&ins(
            "mov",
            vec![reg_op("rcx"), mem_op(Some("rbp"), -24, None)],
        )); // reload
        t.observe(&ins(
            "lea",
            vec![reg_op("rax"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rcx"), mem_op(Some("rax"), 0, Some("rcx"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        match t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()) {
            Some(Resolution::Table { targets, .. }) => assert_eq!(targets.len(), 4),
            other => panic!("the clang -O0 shape must resolve, got {other:?}"),
        }
    }

    /// clang -O0's switch: the checked value is spilled to its frame slot and
    /// reloaded into a DIFFERENT register before the table read.
    ///
    /// 11 of the 24 real dispatches in the fixture corpus have this shape
    /// (`04_switch_shapes.clang.O0@0x112a`, `switch_jt.clang.O0@0x112c`,
    /// `statemachine.clang.O0@0x1152`, ...). Matching the guard's register name
    /// against the index's declined every one of them.
    #[test]
    fn a_bound_survives_a_spill_and_reload_into_another_register() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("sub", vec![reg_op("rax"), imm_op(3)])); // guard on rax
        t.observe(&ins(
            "mov",
            vec![mem_op(Some("rbp"), -16, None), reg_read("rax")],
        )); // spill
        t.observe(&ins(
            "mov",
            vec![reg_op("rcx"), mem_op(Some("rbp"), -16, None)],
        )); // reload -> rcx
        t.observe(&ins(
            "lea",
            vec![reg_op("rax"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rcx"), mem_op(Some("rax"), 0, Some("rcx"))],
        ));
        t.observe(&ins("add", vec![reg_op("rcx"), reg_op("rax")]));
        match t.resolve(&ins("jmp", vec![reg_read("rcx")]), &tables()) {
            Some(Resolution::Table { targets, .. }) => assert_eq!(targets.len(), 4),
            other => panic!("spilled index must keep its bound, got {other:?}"),
        }
    }

    /// clang -O2's copy shape: `cmp $N,%edi ... mov %edi,%ecx ... movslq (%rsi,%rcx,4)`.
    #[test]
    fn a_bound_follows_a_register_copy() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("cmp", vec![reg_op("rdi"), imm_op(3)]));
        t.observe(&ins("mov", vec![reg_op("rcx"), reg_op("rdi")]));
        t.observe(&ins(
            "lea",
            vec![reg_op("rsi"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rcx"), mem_op(Some("rsi"), 0, Some("rcx"))],
        ));
        t.observe(&ins("add", vec![reg_op("rcx"), reg_op("rsi")]));
        assert!(matches!(
            t.resolve(&ins("jmp", vec![reg_read("rcx")]), &tables()),
            Some(Resolution::Table { .. })
        ));
    }

    #[test]
    fn a_bound_survives_zero_extension_of_the_guarded_subregister() {
        let mut guard = DispatchTracker::new();
        guard.observe(&ins("cmp", vec![reg_op("al"), imm_op(3)]));

        let mut dispatch = DispatchTracker::new();
        dispatch.inherit_bound(Some(guard.export_bounds()));
        dispatch.inherit_addresses(Some(&HashMap::from([("rdx".to_string(), 0x2000)])));
        dispatch.observe(&ins(
            "movzx",
            vec![reg_write_sized("eax", 32), reg_read("al")],
        ));
        dispatch.observe(&ins(
            "movsxd",
            vec![reg_op("rax"), mem_op(Some("rdx"), 0, Some("rax"))],
        ));
        dispatch.observe(&ins("add", vec![reg_op("rax"), reg_op("rdx")]));

        assert!(matches!(
            dispatch.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()),
            Some(Resolution::Table { ref targets, .. }) if targets.len() == 4
        ));
    }

    #[test]
    fn a_table_base_can_be_exported_to_a_later_dispatch_block() {
        let mut preheader = DispatchTracker::new();
        preheader.observe(&ins(
            "lea",
            vec![reg_op("rsi"), mem_op(Some("rip"), 0x2000, None)],
        ));
        let addresses = preheader.export_addresses();

        let mut dispatch = DispatchTracker::new();
        dispatch.inherit_addresses(Some(&addresses));
        dispatch.observe(&ins("cmp", vec![reg_op("rdx"), imm_op(3)]));
        dispatch.observe(&ins("mov", vec![reg_op("r10"), reg_op("rdx")]));
        dispatch.observe(&ins(
            "movsxd",
            vec![reg_op("r10"), mem_op(Some("rsi"), 0, Some("r10"))],
        ));
        dispatch.observe(&ins("add", vec![reg_op("r10"), reg_op("rsi")]));
        assert!(matches!(
            dispatch.resolve(&ins("jmp", vec![reg_read("r10")]), &tables()),
            Some(Resolution::Table { .. })
        ));
    }

    #[test]
    fn a_write_kills_an_inherited_table_base() {
        let addresses = HashMap::from([("rsi".to_string(), 0x2000)]);
        let mut dispatch = DispatchTracker::new();
        dispatch.inherit_addresses(Some(&addresses));
        dispatch.observe(&ins("xor", vec![reg_op("rsi"), reg_op("rsi")]));
        assert!(dispatch.export_addresses().is_empty());
    }

    /// A power-of-two switch is lowered as `and $2^k-1` and then NO comparison
    /// is emitted at all — the mask is the range proof. Both compilers do this
    /// at -O2 (`04_switch_shapes` gcc and clang).
    #[test]
    fn a_power_of_two_mask_is_itself_a_bound() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("and", vec![reg_op("rdi"), imm_op(3)])); // index in [0,3]
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rdx"), mem_op(Some("rcx"), 0, Some("rdi"))],
        ));
        t.observe(&ins("add", vec![reg_op("rdx"), reg_op("rcx")]));
        match t.resolve(&ins("jmp", vec![reg_read("rdx")]), &tables()) {
            Some(Resolution::Table { targets, .. }) => assert_eq!(targets.len(), 4),
            other => panic!("a 2^k-1 mask bounds the index, got {other:?}"),
        }
    }

    #[test]
    fn stable_bounds_follow_compiler_generated_state_values() {
        let mut state = DispatchTracker::new();
        state.observe(&ins("xor", vec![reg_op("r8d"), reg_read("r8d")]));
        assert_eq!(state.export_stable_bounds().regs.get("r8"), Some(&0));

        // Clang emits `xor r8d,r8d; sete r8b; or $2,r8d` for the enum
        // transition whose only possible results are 2 and 3.
        state.observe(&ins("sete", vec![reg_op("r8b")]));
        state.observe(&ins("or", vec![reg_op("r8d"), imm_op(2)]));
        assert_eq!(state.export_stable_bounds().regs.get("r8"), Some(&3));
    }

    #[test]
    fn stable_bounds_exclude_a_branch_local_comparison_assumption() {
        let mut guard = DispatchTracker::new();
        guard.observe(&ins("cmp", vec![reg_op("rdi"), imm_op(3)]));
        assert_eq!(guard.export_bounds().regs.get("rdi"), Some(&3));
        assert!(
            !guard.export_stable_bounds().regs.contains_key("rdi"),
            "a comparison bounds only its in-range edge, not every successor"
        );
    }

    /// A non-power-of-two mask constrains the value but is not a dense index
    /// range, so it must NOT be treated as an entry count.
    #[test]
    fn an_arbitrary_mask_is_not_a_bound() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("and", vec![reg_op("rdi"), imm_op(0x0f0f)]));
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rdx"), mem_op(Some("rcx"), 0, Some("rdi"))],
        ));
        t.observe(&ins("add", vec![reg_op("rdx"), reg_op("rcx")]));
        assert!(matches!(
            t.resolve(&ins("jmp", vec![reg_read("rdx")]), &tables()),
            Some(Resolution::Unresolved(Unresolved::NoBound(_)))
        ));
    }

    /// The prologue's `sub $0x8,%rsp` must never supply an extent to a dispatch
    /// that follows it. This is what per-value boundedness buys over name matching.
    #[test]
    fn a_stack_adjust_does_not_bound_an_unrelated_dispatch() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("sub", vec![reg_op("rsp"), imm_op(8)]));
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        assert!(matches!(
            t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()),
            Some(Resolution::Unresolved(Unresolved::NoBound(_)))
        ));
    }

    /// **The safety property this module exists to hold.**
    ///
    /// With no range check there is no way to know how many entries the table
    /// has, and the rodata scan's answer is wrong — it over-runs into the next
    /// table. Falling back to it cost DecBench GED 10.24 -> 12.73 across 56
    /// cells. An unresolved dispatch is a bounded loss; an over-long one
    /// corrupts every function its phantom arms reach into.
    #[test]
    fn an_unbounded_dispatch_does_not_resolve() {
        let mut t = DispatchTracker::new();
        // No `cmp`/`sub` guard anywhere — just the dispatch itself.
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        assert_eq!(
            t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()),
            Some(Resolution::Unresolved(Unresolved::NoBound(0x2000))),
            "an unbounded table must not resolve to the whole scanned run"
        );
    }

    /// The bound clamps to the guard even when the scan found far more entries —
    /// the case that made `dense_jumptable` drag in 52 foreign blocks.
    #[test]
    fn the_guard_clamps_an_overlong_scan() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("sub", vec![reg_op("rax"), imm_op(1)])); // index in [0, 1]
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        match t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()) {
            Some(Resolution::Table { targets, .. }) => {
                assert_eq!(
                    targets.len(),
                    2,
                    "the guard admits two indices, so two arms"
                )
            }
            other => panic!("expected a clamped table, got {other:?}"),
        }
    }

    /// The clang -O0 dense switch, which is the shape that lost thirty
    /// instructions of `dense_jumptable` to a CFG that never saw them.
    #[test]
    fn the_clang_lea_movslq_add_jmp_sequence_resolves() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("sub", vec![reg_op("rax"), imm_op(3)])); // switch guard: index in [0,3]
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        let r = t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables());
        assert_eq!(
            r,
            Some(Resolution::Table {
                table_va: 0x2000,
                targets: vec![0x112e, 0x113a, 0x1146, 0x1152],
            })
        );
    }

    /// The block walker observes every decoded instruction *including the
    /// terminator*, then resolves. So `observe` must not treat `jmp rax`'s
    /// operand as a definition — doing so cleared the very register the jump was
    /// about to be resolved through, and every dispatch in the corpus came back
    /// `UnknownBase`.
    ///
    /// The unit tests did not catch it: their synthetic operands were all
    /// `ReadWrite`, so the fixture disagreed with what the decoder actually
    /// reports. Only the round trip showed it.
    #[test]
    fn observing_the_terminator_does_not_clear_the_register_it_reads() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("sub", vec![reg_op("rax"), imm_op(3)])); // switch guard: index in [0,3]
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        let jmp = ins("jmp", vec![reg_read("rax")]);
        t.observe(&jmp); // exactly what the walker does before resolving
        assert!(
            matches!(
                t.resolve(&jmp, &tables()),
                Some(Resolution::Table {
                    table_va: 0x2000,
                    ..
                })
            ),
            "observing the jump must not destroy its own operand"
        );
    }

    /// Operand order is a codegen choice, not a semantic one.
    #[test]
    fn the_add_resolves_with_either_operand_order() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("sub", vec![reg_op("rdx"), imm_op(3)])); // guard on the index
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rdx"))],
        ));
        // add rcx, rax  — base += offset, the other way round
        t.observe(&ins("add", vec![reg_op("rcx"), reg_op("rax")]));
        assert!(matches!(
            t.resolve(&ins("jmp", vec![reg_read("rcx")]), &tables()),
            Some(Resolution::Table {
                table_va: 0x2000,
                ..
            })
        ));
    }

    /// Width views of one register are one location. `movslq` writes `%rax`
    /// while the index arrives in `%eax`; treating them separately breaks the
    /// chain silently.
    #[test]
    fn register_width_views_are_the_same_location() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("sub", vec![reg_op("rax"), imm_op(3)])); // switch guard: index in [0,3]
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("eax"), mem_op(Some("rcx"), 0, Some("eax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("ecx")]));
        assert!(matches!(
            t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()),
            Some(Resolution::Table { .. })
        ));
    }

    /// A copy carries the resolution: compilers stage the target through a
    /// scratch register often enough that not following it loses real dispatches.
    #[test]
    fn a_register_copy_carries_the_resolution() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("sub", vec![reg_op("rax"), imm_op(3)])); // switch guard: index in [0,3]
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        t.observe(&ins("mov", vec![reg_op("rdx"), reg_op("rax")]));
        assert!(matches!(
            t.resolve(&ins("jmp", vec![reg_read("rdx")]), &tables()),
            Some(Resolution::Table { .. })
        ));
    }

    /// The safety property. An unmodelled write must drop the register, so the
    /// analysis loses a resolution rather than inventing a target set — a wrong
    /// successor list is far worse than a missing one, because it produces
    /// confident, wrong C.
    #[test]
    fn an_unmodelled_write_drops_the_register() {
        let mut t = DispatchTracker::new();
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        t.observe(&ins("xor", vec![reg_op("rax"), reg_op("rax")]));
        assert_eq!(
            t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()),
            Some(Resolution::Unresolved(Unresolved::UnknownBase))
        );
    }

    /// An offset added to a DIFFERENT address is not a dispatch target. Without
    /// the `a == b` check this would resolve to whatever table the offset came
    /// from and jump somewhere the program never does.
    #[test]
    fn an_offset_added_to_an_unrelated_base_does_not_resolve() {
        let mut t = DispatchTracker::new();
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "lea",
            vec![reg_op("rbx"), mem_op(Some("rip"), 0x3000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rbx")]));
        assert_eq!(
            t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()),
            Some(Resolution::Unresolved(Unresolved::UnknownBase))
        );
    }

    /// Understanding the dispatch but finding no table is a DIFFERENT failure
    /// from not understanding it, and reporting them apart is what makes the
    /// completeness signal actionable: one is a table-scan gap, the other a
    /// dataflow gap.
    #[test]
    fn a_dispatch_with_no_discovered_table_reports_the_address() {
        let mut t = DispatchTracker::new();
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x9999, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        assert_eq!(
            t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()),
            Some(Resolution::Unresolved(Unresolved::NoTableAt {
                table: 0x9999,
                // No guard bounded the index and the scan holds no table here,
                // so no bounded decode was even possible — which is a different
                // decline from a decode that ran and refused, and now says so.
                decline: crate::analysis::jump_table::TableDecline::ScanFoundNoTable,
            }))
        );
    }

    /// Unmerged state must not cross a block boundary: the predecessor that set
    /// it up is not guaranteed to be the one that runs. Cross-block address
    /// facts use the explicit export/intersection/inherit path above.
    #[test]
    fn reset_clears_state_between_blocks() {
        let mut t = DispatchTracker::new();
        t.observe(&ins(
            "lea",
            vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)],
        ));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        t.reset();
        assert_eq!(
            t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()),
            Some(Resolution::Unresolved(Unresolved::UnknownBase))
        );
    }

    /// A non-register jump target is not this analysis's business, and saying so
    /// with `None` keeps "not a dispatch" distinct from "an unreadable dispatch"
    /// — the caller reports the second and ignores the first.
    #[test]
    fn a_non_register_operand_is_not_a_dispatch() {
        let t = DispatchTracker::new();
        assert_eq!(
            t.resolve(&ins("jmp", vec![imm_op(0x1234)]), &tables()),
            None
        );
    }

    /// Non-PIC codegen names the table with a plain immediate move.
    #[test]
    fn an_absolute_table_address_from_an_immediate_resolves() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("sub", vec![reg_op("rax"), imm_op(3)])); // switch guard: index in [0,3]
        t.observe(&ins("mov", vec![reg_op("rcx"), imm_op(0x2000)]));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        assert!(matches!(
            t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()),
            Some(Resolution::Table { .. })
        ));
    }
}
