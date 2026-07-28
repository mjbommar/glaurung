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
    /// The register resolved to a table-derived value, but no table was
    /// discovered at that address. Distinct from `UnknownBase` because it means
    /// the *dispatch* was understood and the *table scan* came up short — a
    /// different defect, and one worth reporting separately.
    NoTableAt(u64),
    /// The dispatch and its table were both found, but no range check bounded
    /// the index, so the table's entry count is unknown.
    ///
    /// Reported rather than guessed. The rodata scan cannot find a table's end —
    /// it over-runs into the following table — so using its length here attaches
    /// dozens of foreign blocks to the function. This is the most *recoverable*
    /// of the three: it names a table that exists and only wants an extent.
    NoBound(u64),
}

/// What a guard established, carried across its in-range edge.
///
/// Both halves are needed: clang -O2 keeps the checked value in a register, and
/// clang -O0 spills it to a frame slot before the check and reloads it after.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bounds {
    pub regs: HashMap<String, u64>,
    pub slots: HashMap<(String, i64), u64>,
}

/// The outcome of resolving one indirect transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Targets recovered from the jump table at `table_va`.
    Table { table_va: u64, targets: Vec<u64> },
    /// Targets not recoverable. The resulting CFG is incomplete and must say so.
    Unresolved(Unresolved),
}

/// x86 register aliases, narrowed to the 64-bit parent so `%eax` and `%rax` are
/// one location. Dispatch sequences mix widths freely — clang's `movslq` writes
/// the 64-bit register while the index arrives in a 32-bit one — and treating
/// them as distinct silently loses the chain.
fn canon(reg: &str) -> String {
    let r = reg.trim_start_matches('%').to_ascii_lowercase();
    let full = match r.as_str() {
        "rax" | "eax" | "ax" | "al" | "ah" => "rax",
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx",
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx",
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx",
        "rsi" | "esi" | "si" | "sil" => "rsi",
        "rdi" | "edi" | "di" | "dil" => "rdi",
        "rbp" | "ebp" | "bp" | "bpl" => "rbp",
        "rsp" | "esp" | "sp" | "spl" => "rsp",
        other => {
            // r8..r15 and their d/w/b views.
            if let Some(rest) = other.strip_prefix('r') {
                let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if !digits.is_empty() {
                    return format!("r{digits}");
                }
            }
            return other.to_string();
        }
    };
    full.to_string()
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
    /// Slots that currently hold a copy of a register's value, recorded at the
    /// spill. Needed because clang -O0 spills the switch value BEFORE the guard
    /// runs:
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
    /// the value sitting in the slot. So bounding a register must also bound any
    /// slot still aliasing it. An alias is dropped as soon as the register is
    /// written by anything else, since the slot then holds a different value.
    slot_alias: HashMap<(String, i64), String>,
    /// The most recent `cmp`/`sub` against an immediate, for the walker to hand
    /// to the guard's in-range successor.
    last_cmp: Option<(String, u64)>,
}

impl DispatchTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.regs.clear();
        self.bounded.clear();
        self.bounded_slots.clear();
        self.slot_alias.clear();
        self.last_cmp = None;
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
        }
    }

    /// The register/limit pair a range check just established, for the caller to
    /// hand to the in-range successor. `cmp $N, r` / `sub $N, r` followed by an
    /// unsigned-above branch means the fallthrough has `r <= N`.
    pub fn pending_bound(&self) -> Option<(String, u64)> {
        self.last_cmp.clone()
    }

    fn get(&self, reg: &str) -> Option<Val> {
        self.regs.get(&canon(reg)).cloned()
    }

    fn set(&mut self, reg: &str, v: Val) {
        self.regs.insert(canon(reg), v);
    }

    fn clear(&mut self, reg: &str) {
        self.regs.remove(&canon(reg));
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

    /// A memory operand's base register, if it has one that is not `rip`.
    fn mem_base(ins: &Instruction) -> Option<&str> {
        ins.operands.iter().find_map(|op| {
            op.displacement?;
            let b = op.base.as_deref()?;
            (b != "rip").then_some(b)
        })
    }

    /// A memory operand's index register, if it has one.
    fn mem_index(ins: &Instruction) -> Option<&str> {
        ins.operands.iter().find_map(|op| op.index.as_deref())
    }

    /// Record that a value is in `[0, max]`, for the register holding it and for
    /// any stack slot still aliasing that register. See [`Self::slot_alias`].
    fn bound_value(&mut self, reg: &str, max: u64) {
        self.bounded.insert(reg.to_string(), max);
        let slots: Vec<_> = self
            .slot_alias
            .iter()
            .filter(|(_, r)| r.as_str() == reg)
            .map(|(k, _)| k.clone())
            .collect();
        for k in slots {
            self.bounded_slots.insert(k, max);
        }
    }

    /// Everything this block established, for its in-range successor to inherit.
    pub fn export_bounds(&self) -> Bounds {
        Bounds {
            regs: self.bounded.clone(),
            slots: self.bounded_slots.clone(),
        }
    }

    /// Update the tracked state with one decoded instruction.
    pub fn observe(&mut self, ins: &Instruction) {
        let m = ins.mnemonic.to_ascii_lowercase();

        // Snapshot the index register's bound BEFORE any rule below mutates
        // state. `movslq (%rcx,%rax,4),%rax` both reads `rax` as the index and
        // writes it, so a capture that ran after the write-clears-bound rule
        // always found nothing.
        let index_bound_on_entry = Self::mem_index(ins)
            .and_then(|i| self.bounded.get(&canon(i)).copied());

        // --- boundedness, tracked as a propagating fact -----------------------
        //
        // Every rule here answers one question: "is this value known to lie in
        // [0, N]?" A jump table's entry count is exactly that, and the value is
        // usually not still in the register that was compared.
        let reg0 = ins.operands.first().and_then(|o| o.register.as_deref());
        let imm1 = ins.operands.get(1).and_then(|o| o.immediate);
        match m.as_str() {
            // The range check itself. `cmp` leaves the register alone; `sub`
            // rebases it so in-range values become `[0, N]`. Recorded for the
            // walker to carry across the guard's in-range edge, and applied here
            // too so a guard in the dispatch's own block also counts.
            "cmp" | "sub" => {
                if let (Some(r), Some(n)) = (reg0, imm1) {
                    if n >= 0 {
                        self.last_cmp = Some((canon(r), n as u64));
                        self.bound_value(&canon(r), n as u64);
                    }
                }
            }
            // `and $2^k-1, reg` IS a range proof — it is how a power-of-two
            // switch is lowered, and clang/gcc then emit NO comparison at all
            // (`04_switch_shapes` at -O2 in both). Restricted to masks of the
            // form 2^k-1; an arbitrary mask bounds the value but not as a dense
            // index range.
            "and" => {
                if let (Some(r), Some(n)) = (reg0, imm1) {
                    if n > 0 && (n as u64).count_zeros() == (n as u64).leading_zeros() {
                        self.bound_value(&canon(r), n as u64);
                    } else {
                        self.bounded.remove(&canon(r));
                    }
                }
            }
            _ => {}
        }
        // A spill carries the bound into the frame slot; the matching reload
        // carries it back out, possibly into a different register. This is the
        // clang -O0 switch shape, and it is 11 of the 21 dispatches the
        // name-matching version declined.
        if matches!(m.as_str(), "mov" | "movq" | "movl") {
            let dst_mem = ins
                .operands
                .first()
                .and_then(|o| o.displacement.map(|d| (o.base.clone(), d)));
            let src_reg = ins.operands.get(1).and_then(|o| o.register.as_deref());
            let src_mem = ins
                .operands
                .get(1)
                .and_then(|o| o.displacement.map(|d| (o.base.clone(), d)));
            match (dst_mem, src_reg, src_mem, reg0) {
                // store: [base+disp] <- reg
                (Some((Some(b), d)), Some(sr), _, _) => {
                    let key = (canon(&b), d);
                    self.slot_alias.insert(key.clone(), canon(sr));
                    match self.bounded.get(&canon(sr)).copied() {
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
                    match self.bounded_slots.get(&(canon(&b), d)).copied() {
                        Some(n) => {
                            self.bounded.insert(canon(dr), n);
                        }
                        None => {
                            self.bounded.remove(&canon(dr));
                        }
                    }
                }
                // copy: reg <- reg
                (None, Some(sr), None, Some(dr)) => {
                    match self.bounded.get(&canon(sr)).copied() {
                        Some(n) => {
                            self.bounded.insert(canon(dr), n);
                        }
                        None => {
                            self.bounded.remove(&canon(dr));
                        }
                    }
                }
                _ => {}
            }
        } else if let Some(d) = Self::dest_reg(ins) {
            // Any other write destroys the bound unless the rules above set it.
            if !matches!(m.as_str(), "cmp" | "sub" | "and") {
                self.bounded.remove(&canon(d));
            }
        }

        let Some(dest) = Self::dest_reg(ins) else {
            return;
        };

        match m.as_str() {
            // `lea rD, [rip+d]` materialises an absolute address — how position-
            // independent code names a table.
            "lea" => {
                if let Some(va) = Self::rip_target(ins) {
                    self.set(dest, Val::Addr(va));
                } else {
                    self.clear(dest);
                }
            }
            // A sign-extending load indexed off a tracked table base is the table
            // read. The index is deliberately not tracked: every entry is a
            // possible outcome, which is exactly the successor set we want.
            "movslq" | "movsxd" | "movsx" => {
                let base = Self::mem_base(ins).and_then(|b| self.get(b));
                match base {
                    Some(Val::Addr(t)) => {
                        self.set(
                            dest,
                            Val::TableOffset {
                                table: t,
                                bound: index_bound_on_entry,
                            },
                        )
                    }
                    _ => self.clear(dest),
                }
            }
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
                if let Some(v) = src.and_then(|o| o.register.as_deref()).and_then(|r| self.get(r)) {
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
        let reg = ins.operands.first()?.register.as_deref()?;
        Some(match self.get(reg) {
            Some(Val::TableTarget { table, bound }) => match tables.get(&table) {
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
                Some(targets) => match bound {
                    Some(b) => Resolution::Table {
                        table_va: table,
                        targets: targets[..targets.len().min(b as usize + 1)].to_vec(),
                    },
                    None => Resolution::Unresolved(Unresolved::NoBound(table)),
                },
                None => Resolution::Unresolved(Unresolved::NoTableAt(table)),
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
        }
    }

    fn mem_op(base: Option<&str>, disp: i64, index: Option<&str>) -> Operand {
        Operand {
            kind: OperandKind::Memory,
            size: 64,
            access: Access::Read,
            text: String::new(),
            register: None,
            immediate: None,
            displacement: Some(disp),
            segment: None,
            scale: Some(4),
            base: base.map(str::to_string),
            index: index.map(str::to_string),
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
        guard_block.observe(&ins("mov", vec![reg_op("rax"), mem_op(Some("rbp"), -8, None)]));
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
        t.observe(&ins("mov", vec![reg_op("rcx"), mem_op(Some("rbp"), -24, None)])); // reload
        t.observe(&ins("lea", vec![reg_op("rax"), mem_op(Some("rip"), 0x2000, None)]));
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
        t.observe(&ins("sub", vec![reg_op("rax"), imm_op(3)]));      // guard on rax
        t.observe(&ins("mov", vec![mem_op(Some("rbp"), -16, None), reg_read("rax")])); // spill
        t.observe(&ins("mov", vec![reg_op("rcx"), mem_op(Some("rbp"), -16, None)]));   // reload -> rcx
        t.observe(&ins("lea", vec![reg_op("rax"), mem_op(Some("rip"), 0x2000, None)]));
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
        t.observe(&ins("lea", vec![reg_op("rsi"), mem_op(Some("rip"), 0x2000, None)]));
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

    /// A power-of-two switch is lowered as `and $2^k-1` and then NO comparison
    /// is emitted at all — the mask is the range proof. Both compilers do this
    /// at -O2 (`04_switch_shapes` gcc and clang).
    #[test]
    fn a_power_of_two_mask_is_itself_a_bound() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("and", vec![reg_op("rdi"), imm_op(3)])); // index in [0,3]
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
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

    /// A non-power-of-two mask constrains the value but is not a dense index
    /// range, so it must NOT be treated as an entry count.
    #[test]
    fn an_arbitrary_mask_is_not_a_bound() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("and", vec![reg_op("rdi"), imm_op(0x0f0f)]));
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
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
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
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
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
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
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        match t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()) {
            Some(Resolution::Table { targets, .. }) => {
                assert_eq!(targets.len(), 2, "the guard admits two indices, so two arms")
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
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
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
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
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
                Some(Resolution::Table { table_va: 0x2000, .. })
            ),
            "observing the jump must not destroy its own operand"
        );
    }

    /// Operand order is a codegen choice, not a semantic one.
    #[test]
    fn the_add_resolves_with_either_operand_order() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("sub", vec![reg_op("rdx"), imm_op(3)])); // guard on the index
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rdx"))],
        ));
        // add rcx, rax  — base += offset, the other way round
        t.observe(&ins("add", vec![reg_op("rcx"), reg_op("rax")]));
        assert!(matches!(
            t.resolve(&ins("jmp", vec![reg_read("rcx")]), &tables()),
            Some(Resolution::Table { table_va: 0x2000, .. })
        ));
    }

    /// Width views of one register are one location. `movslq` writes `%rax`
    /// while the index arrives in `%eax`; treating them separately breaks the
    /// chain silently.
    #[test]
    fn register_width_views_are_the_same_location() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("sub", vec![reg_op("rax"), imm_op(3)])); // switch guard: index in [0,3]
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
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
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
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
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
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
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
        t.observe(&ins("lea", vec![reg_op("rbx"), mem_op(Some("rip"), 0x3000, None)]));
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
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x9999, None)]));
        t.observe(&ins(
            "movslq",
            vec![reg_op("rax"), mem_op(Some("rcx"), 0, Some("rax"))],
        ));
        t.observe(&ins("add", vec![reg_op("rax"), reg_op("rcx")]));
        assert_eq!(
            t.resolve(&ins("jmp", vec![reg_read("rax")]), &tables()),
            Some(Resolution::Unresolved(Unresolved::NoTableAt(0x9999)))
        );
    }

    /// State must not cross a block boundary: the predecessor that set it up is
    /// not guaranteed to be the one that runs.
    #[test]
    fn reset_clears_state_between_blocks() {
        let mut t = DispatchTracker::new();
        t.observe(&ins("lea", vec![reg_op("rcx"), mem_op(Some("rip"), 0x2000, None)]));
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
        assert_eq!(t.resolve(&ins("jmp", vec![imm_op(0x1234)]), &tables()), None);
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
