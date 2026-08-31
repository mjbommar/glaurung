//! Return-register definitions that must keep an unversioned spelling.
//!
//! Downstream naming maps a bare ABI register to the `ret` role. A
//! definition that still reaches an operand-free return, or whose value is
//! read back through a sub-register alias SSA does not unify, therefore has
//! to survive value numbering unversioned. The reaching-return proofs and
//! the set they populate are one owner: the set means nothing without them,
//! and they exist for nothing else.

use std::collections::HashMap;

use crate::ir::call_args::CallConv;
use crate::ir::types::{LlirFunction, Op, VReg};
use crate::ir::use_def::{def_ref, for_each_use, InstrAddr};

/// The registers that carry a return value under `cc` (all width sub-names).
fn return_reg_names(cc: CallConv) -> &'static [&'static str] {
    crate::ir::abi::return_registers(cc)
}

/// `(register, version)` pairs kept bare despite version ≥ 1 — the value a
/// return register holds when it reaches a `Return`, so downstream naming still
/// maps it to `ret` rather than a scratch `varN`.
/// Canonical register names whose listed SSA versions must keep a bare
/// spelling.
///
/// Keyed by name rather than by `(name, version)` so a membership test can be
/// asked with a borrowed `&str`. As a `HashSet<(String, u32)>` the only way to
/// probe it was to clone the register spelling for the lookup key — and
/// `tagging::tag_phys` asks once per register operand.
#[derive(Debug, Default)]
pub(crate) struct KeepBare(HashMap<String, Vec<u32>>);

impl KeepBare {
    fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, name: String, version: u32) {
        let versions = self.0.entry(name).or_default();
        if !versions.contains(&version) {
            versions.push(version);
        }
    }

    pub(crate) fn contains(&self, name: &str, version: u32) -> bool {
        self.0
            .get(name)
            .is_some_and(|versions| versions.contains(&version))
    }
}

/// The return-register definitions of `lf` that must keep a bare spelling.
///
/// Keep bare only return-register defs which still reach an operand-free
/// return. This compatibility path is required until prototype recovery can
/// resolve every output. Explicit `ReturnValue` uses participate in ordinary
/// SSA and must retain their exact versions; keeping those definitions bare
/// would throw away the identity this pipeline just proved.
pub(crate) fn definitions(
    lf: &LlirFunction,
    ssa: &crate::ir::ssa::SsaInfo,
    cc: CallConv,
) -> KeepBare {
    let ret_names = return_reg_names(cc);
    let va_to_idx: std::collections::HashMap<u64, usize> = lf
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start_va, i))
        .collect();
    let mut keep: KeepBare = KeepBare::new();
    for (bi, block) in lf.blocks.iter().enumerate() {
        for (ii, ins) in block.instrs.iter().enumerate() {
            if let Some(VReg::Phys(n)) = def_ref(&ins.op) {
                if ret_names.contains(&n.as_str())
                    && (def_reaches_unresolved_return(lf, ret_names, &va_to_idx, bi, ii)
                        || def_read_by_alias_before_redef(lf, ret_names, bi, ii, n))
                {
                    let v = ssa.def_version(
                        lf,
                        InstrAddr {
                            block_idx: bi,
                            instr_idx: ii,
                        },
                    );
                    // Key by the canonical (64-bit) name to match tag_phys.
                    let canon = crate::ir::ssa::parent64(n)
                        .map(str::to_string)
                        .unwrap_or_else(|| n.clone());
                    keep.insert(canon, v);
                }
            }
        }
    }
    keep
}

/// Does `op` define a return register under `ret_names`?
fn defs_return_reg(op: &Op, ret_names: &[&str]) -> bool {
    matches!(def_ref(op), Some(VReg::Phys(n)) if ret_names.contains(&n.as_str()))
}

/// Can the return-register def at (`def_bi`, `def_ii`) reach a return
/// without an intervening return-register def overwriting it? Such a def is a
/// value the function actually returns (the `if (c) ret=A; else ret=B; return`
/// shape has TWO of them, both reaching the return via the join). A return
/// register reused purely as scratch — a loop-address `rax` overwritten (or
/// replaced by the real return load) before any `Return` — does NOT reach, so
/// it stays foldable.
pub(crate) fn def_reaches_return(
    lf: &LlirFunction,
    ret_names: &[&str],
    va_to_idx: &std::collections::HashMap<u64, usize>,
    def_bi: usize,
    def_ii: usize,
) -> bool {
    def_reaches_return_kind(lf, ret_names, va_to_idx, def_bi, def_ii, false)
}

pub(crate) fn def_reaches_unresolved_return(
    lf: &LlirFunction,
    ret_names: &[&str],
    va_to_idx: &std::collections::HashMap<u64, usize>,
    def_bi: usize,
    def_ii: usize,
) -> bool {
    def_reaches_return_kind(lf, ret_names, va_to_idx, def_bi, def_ii, true)
}

fn def_reaches_return_kind(
    lf: &LlirFunction,
    ret_names: &[&str],
    va_to_idx: &std::collections::HashMap<u64, usize>,
    def_bi: usize,
    def_ii: usize,
    unresolved_only: bool,
) -> bool {
    // Rest of the def's own block first.
    for ins in &lf.blocks[def_bi].instrs[def_ii + 1..] {
        if ins.op.is_return() {
            return !unresolved_only || ins.op.is_unresolved_return();
        }
        if defs_return_reg(&ins.op, ret_names) {
            return false; // overwritten before any return
        }
    }
    // Fell off the end of the block — BFS the successors.
    let succ_idx = |b: usize| -> Vec<usize> {
        lf.blocks[b]
            .succs
            .iter()
            .filter_map(|va| va_to_idx.get(va).copied())
            .collect()
    };
    let mut visited = std::collections::HashSet::new();
    let mut stack = succ_idx(def_bi);
    while let Some(b) = stack.pop() {
        if !visited.insert(b) {
            continue;
        }
        let mut killed = false;
        for ins in &lf.blocks[b].instrs {
            if ins.op.is_return() {
                if !unresolved_only || ins.op.is_unresolved_return() {
                    return true;
                }
                // This path terminates at an explicit return, but another
                // queued CFG path may still reach an unresolved one.
                killed = true;
                break;
            }
            if defs_return_reg(&ins.op, ret_names) {
                killed = true;
                break;
            }
        }
        if !killed {
            stack.extend(succ_idx(b));
        }
    }
    false
}

/// True when the return-register def at (`def_bi`, `def_ii`) — whose register is
/// `def_name` — has its value read via a DIFFERENT-name family alias (a
/// sub-register, e.g. a `%eax` def read back as `%al`) before the next
/// return-register def in the same block.
///
/// Such a def must stay BARE: value_number renames a scratch def by SSA version
/// (`%eax` -> `%eax#1`) but the SSA tracks `al`/`ax`/`eax` as independent
/// registers, so a bare sub-register read is NOT renamed with it — and the later
/// naming pass then maps that orphaned `%al` to the `ret` role, producing a
/// use-before-def (`local_1 = ret` before `ret` is assigned). Keeping the def
/// bare matches the correct register-level lowering. Same-name reuse (a loop
/// address `%rax` read as `%rax`) is unaffected, so address-chain folding stays.
fn def_read_by_alias_before_redef(
    lf: &LlirFunction,
    ret_names: &[&str],
    def_bi: usize,
    def_ii: usize,
    def_name: &str,
) -> bool {
    for ins in &lf.blocks[def_bi].instrs[def_ii + 1..] {
        // Two independent exemptions, both needed. An explicit return's
        // register view is resolved by SSA itself (`eax` write then
        // `ReturnValue(rax)` is the zero-extending result edge). And a
        // cross-alias use `parent64` ALREADY unifies is not one: `%eax`
        // canonicalises onto `%rax`, so keeping that definition bare collapsed
        // it with the NEXT `%eax` definition and both reads saw one name —
        // `argument_sink(0, low, split - 1, depth - 1)` became
        // `..., split - 1, split - 1)`, the reduced form of the lost recursion
        // bound in `36_quicksort`. The rule exists for `%al`/`%ax`, which
        // `parent64` deliberately does not canonicalise.
        if ins.op.returned_value().is_none() {
            let mut aliased = false;
            for_each_use(&ins.op, |u| {
                if let VReg::Phys(n) = u {
                    if ret_names.contains(&n.as_str())
                        && n != def_name
                        && !ssa_unifies_aliases(n, def_name)
                    {
                        aliased = true;
                    }
                }
            });
            if aliased {
                return true;
            }
        }
        if defs_return_reg(&ins.op, ret_names) {
            return false;
        }
    }
    false
}

/// Whether SSA already gives these two register spellings ONE version.
///
/// [`crate::ir::ssa::parent64`] canonicalises a 32-bit view onto its 64-bit
/// parent, so a value written `%eax` and read back as `%rax` is already one
/// value at one version and needs no help from the keep-bare rule above. It
/// deliberately does NOT canonicalise `%al`/`%ax`, whose writes preserve the
/// parent's other bits — those are the aliases the rule exists for.
///
/// Checking this is what stops the rule from firing on ordinary scratch use of
/// the return register. `mov -0x24(%rbp),%eax ; lea -0x1(%rax),%ecx` is an
/// `%eax` def read as `%rax`; keeping it bare collapsed it with the NEXT
/// `%eax` def, and both `lea`s then read the same name. In
/// `81_call_argument_identity` that turned `argument_sink(0, low, split - 1,
/// depth - 1)` into `..., split - 1, split - 1)` — the reduced form of a lost
/// recursion-depth bound in `36_quicksort`.
fn ssa_unifies_aliases(read_name: &str, def_name: &str) -> bool {
    let read_parent = crate::ir::ssa::parent64(read_name);
    read_parent.is_some() && read_parent == crate::ir::ssa::parent64(def_name)
}
