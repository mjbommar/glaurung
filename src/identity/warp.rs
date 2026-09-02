//! WARP-compatible function GUIDs (the L0 rung of the identity ladder).
//!
//! WARP is Vector 35's interchange format for function information
//! (<https://github.com/Vector35/warp>, Apache-2.0). Its identity primitive is
//! a UUIDv5 over *relocation-masked* instruction bytes, which makes it an
//! exact-match scheme that survives relinking and rebasing but nothing else.
//! It answers one question -- "is this exactly a known build of a known
//! function?" -- in O(1), and it is the scheme
//! `docs/research/program-measures-2026-09-02.md` names as L0.
//!
//! # The spec, as implemented
//!
//! Three published namespaces, taken verbatim from the WARP README and from
//! `rust/src/signature/{basic_block,function,constraint}.rs` in that repository:
//!
//! | Object | Namespace |
//! |---|---|
//! | Basic block | `0192a178-7a5f-7936-8653-3cbaa7d6afe7` |
//! | Function | `0192a179-61ac-7cef-88ed-012296e9492f` |
//! | Constraint | `019701f3-e89c-7afa-9181-371a5e98a576` |
//!
//! **Basic-block GUID** = UUIDv5 over the block's instruction bytes in
//! execution order, after three transforms:
//!
//! 1. *Zero every relocatable instruction.* An instruction is relocatable when
//!    an operand is a constant pointer into a mapped region, or computes one
//!    with a constant offset. See [`Disposition`] for the exact x86 rules.
//! 2. *Drop NOPs.*
//! 3. *Drop effectively-NOP self-moves* -- `mov reg, reg` -- which compilers
//!    inject as hot-patch space. This one is architecture-sensitive: on x86-64
//!    a 32-bit register write zero-extends into the full 64-bit register, so
//!    `mov edi, edi` is **not** a NOP there and is kept, while the same
//!    encoding in 32-bit mode is a NOP and is dropped.
//!
//! **Function GUID** = UUIDv5 over the concatenated 16-byte block GUIDs,
//! blocks sorted by start address **highest to lowest**.
//!
//! **Constraint GUID** = UUIDv5 over a function GUID's bytes, a symbol name's
//! bytes, or a `u64`'s little-endian bytes. A constraint pairs that GUID with
//! an optional signed offset that gives it locality.
//!
//! # Verification
//!
//! The `warp` crate is Apache-2.0 but is **not published on crates.io** -- the
//! crates.io `warp` is an unrelated HTTP framework -- so depending on it would
//! mean a git dependency in a shipped crate. It also could not do the whole
//! job: `BasicBlockGUID::from(&[u8])` hashes bytes that are *already* masked,
//! and the masking itself lives in Binary Ninja's closed core, not in the
//! open crate. So instead of a crate cross-check this module asserts
//! upstream's own published vectors directly, which is the stronger test of
//! the two: [`tests::matches_the_warp_readme_worked_example`] and
//! [`tests::matches_the_warp_crate_unit_test_vector`] reproduce the README's
//! example and `rust/tests/signature.rs`'s expected GUID byte for byte.
//!
//! The block sort direction is the one rule with no open-source referent: the
//! README states "sorted highest to lowest start address" and the survey
//! (`docs/research/program-measures-2026-09-02/01-binary-similarity-literature.md`,
//! entry 8) reads it the same way, but the sort happens in Binary Ninja's
//! closed core, so it is documented prose rather than read code.
//! [`sort_blocks_for_function_guid`] is the single place that decision lives.
//!
//! # Architecture support
//!
//! x86 and x86-64 via iced-x86. AArch64 and ARM32 are a **TODO**: their
//! relocatable-operand rule is materially harder than x86's because a pointer
//! is materialised across two or more instructions (`adrp` + `add`, the
//! README's own `add x1, x1, #0xf10` example), which needs a small constant
//! propagation over the block rather than a per-instruction predicate.
//! [`warp_functions_from_bytes`] returns [`WarpError::UnsupportedArchitecture`]
//! for them rather than emitting a GUID that would not be WARP-compatible.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use object::{Architecture, Object, ObjectSection, ObjectSegment};
use uuid::Uuid;

use crate::core::function::Function;

/// UUIDv5 namespace for basic-block GUIDs (`0192a178-7a5f-7936-8653-3cbaa7d6afe7`).
pub const NAMESPACE_BASIC_BLOCK: Uuid = Uuid::from_u128(0x0192a178_7a5f_7936_8653_3cbaa7d6afe7);

/// UUIDv5 namespace for function GUIDs (`0192a179-61ac-7cef-88ed-012296e9492f`).
pub const NAMESPACE_FUNCTION: Uuid = Uuid::from_u128(0x0192a179_61ac_7cef_88ed_012296e9492f);

/// UUIDv5 namespace for constraint GUIDs (`019701f3-e89c-7afa-9181-371a5e98a576`).
pub const NAMESPACE_CONSTRAINT: Uuid = Uuid::from_u128(0x019701f3_e89c_7afa_9181_371a5e98a576);

/// The `scheme` string this module writes into `function_identity`.
pub const SCHEME: &str = "warp-function-guid-v1";

/// The lowest constant treated as a possible pointer into the image.
///
/// One page. Every mainstream loader leaves the first page unmapped so that a
/// null dereference faults, so no real pointer lands below it -- while small
/// integers below it are everywhere. See [`MaskContext::is_mapped`] for what
/// went wrong without this.
pub const MIN_PLAUSIBLE_POINTER: u64 = 0x1000;

/// Why a WARP GUID could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarpError {
    /// The bytes are not an object file we can parse.
    UnparseableObject(String),
    /// The object's architecture has no relocatable-instruction rule here yet.
    UnsupportedArchitecture(String),
}

impl std::fmt::Display for WarpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnparseableObject(why) => write!(f, "cannot parse object: {why}"),
            Self::UnsupportedArchitecture(arch) => write!(
                f,
                "WARP GUIDs are implemented for x86 and x86-64 only; {arch} needs a \
                 multi-instruction pointer-materialisation rule (see module docs)"
            ),
        }
    }
}

impl std::error::Error for WarpError {}

/// What the masking pass decides to do with one decoded instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Contribute the instruction's bytes unchanged.
    Keep,
    /// Contribute the instruction's length in zero bytes: some operand is a
    /// constant pointer into a mapped region, so the linker chose those bytes.
    Zero,
    /// Contribute nothing: a NOP, or a self-move that is a NOP on this ISA.
    Drop,
}

/// One basic block's contribution to a function GUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpBasicBlock {
    /// Start VA of the block. Only used to order blocks; never hashed.
    pub start_va: u64,
    /// UUIDv5 of the masked instruction bytes.
    pub guid: Uuid,
}

/// What a constraint records about a neighbouring function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConstraintKind {
    /// A function this one calls.
    Callee,
    /// A function that calls this one.
    Caller,
    /// The function immediately before or after this one by address.
    Adjacent,
}

impl ConstraintKind {
    /// The stable lowercase tag used in serialized form and in Python.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Callee => "callee",
            Self::Caller => "caller",
            Self::Adjacent => "adjacent",
        }
    }
}

/// One WARP constraint: a GUID plus an optional signed locality offset.
///
/// WARP stores "unrelated" as `i64::MAX` in its flatbuffer; we keep it as
/// `None` and convert only at a serialization boundary, because `i64::MAX` is
/// a legal offset value in principle and conflating the two loses information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpConstraint {
    /// UUIDv5 under [`NAMESPACE_CONSTRAINT`].
    pub guid: Uuid,
    /// Signed byte offset relative to this function's entry, when meaningful.
    pub offset: Option<i64>,
    /// Which relation produced this constraint.
    pub kind: ConstraintKind,
    /// The name the constraint was derived from, for human-readable evidence.
    /// Never hashed -- two builds of the same function must agree on the GUID
    /// even when one of them is stripped.
    pub label: Option<String>,
}

/// A function's WARP identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarpFunction {
    /// The entry VA the identity was computed at. A *label*, not part of the
    /// identity: WARP's per-block construction tolerates non-contiguous
    /// functions and multiple entry points.
    pub entry_va: u64,
    /// The name discovery gave the function (often `sub_<hex>`).
    pub name: String,
    /// UUIDv5 over the sorted block GUIDs.
    pub guid: Uuid,
    /// Block GUIDs in the order they were hashed (highest start VA first).
    pub blocks: Vec<WarpBasicBlock>,
    /// Callee, caller and adjacency constraints, in a deterministic order.
    pub constraints: Vec<WarpConstraint>,
}

/// The mapped image, plus the decode width, as the masker needs to see it.
///
/// "Mapped region" is WARP's own wording: an operand is relocatable when it is
/// or computes a constant pointer *into a mapped region*. Anything outside the
/// loaded image is an ordinary constant and stays in the hash.
#[derive(Debug, Clone)]
pub struct MaskContext {
    /// 16, 32 or 64.
    pub bitness: u32,
    /// Sorted, non-overlapping `(start, end)` VA ranges of the loaded image.
    mapped: Vec<(u64, u64)>,
}

impl MaskContext {
    /// Build a context from an explicit bitness and VA ranges.
    ///
    /// Ranges are normalised (sorted, empty ones dropped) so that
    /// [`Self::is_mapped`] is a binary search and the result does not depend
    /// on the caller's iteration order.
    pub fn new(bitness: u32, ranges: impl IntoIterator<Item = (u64, u64)>) -> Self {
        let mut mapped: Vec<(u64, u64)> = ranges.into_iter().filter(|(s, e)| e > s).collect();
        mapped.sort_unstable();
        Self { bitness, mapped }
    }

    /// Derive a context from a parsed object: segments if it has any, else
    /// sections, which is what a relocatable `.o` gives.
    pub fn from_object(obj: &object::File<'_>) -> Result<Self, WarpError> {
        let bitness = match obj.architecture() {
            Architecture::X86_64 | Architecture::X86_64_X32 => 64,
            Architecture::I386 => 32,
            other => return Err(WarpError::UnsupportedArchitecture(format!("{other:?}"))),
        };
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for seg in obj.segments() {
            if seg.size() > 0 {
                ranges.push((seg.address(), seg.address().saturating_add(seg.size())));
            }
        }
        if ranges.is_empty() {
            for sec in obj.sections() {
                if sec.size() > 0 {
                    ranges.push((sec.address(), sec.address().saturating_add(sec.size())));
                }
            }
        }
        Ok(Self::new(bitness, ranges))
    }

    /// Does `va` look like a constant pointer into the loaded image?
    ///
    /// Not simply "is it inside a segment". A PIE's first `LOAD` starts at
    /// virtual address 0 and covers the ELF header, so a literal `1` -- `mov
    /// eax, 1` -- is inside a mapped range there and outside one in the
    /// non-PIE build of the same object. Masking on that basis made
    /// `mathlib_version_major`, whose ten bytes are byte-for-byte identical in
    /// both builds, produce two different GUIDs. Anything below
    /// [`MIN_PLAUSIBLE_POINTER`] is therefore a constant, not an address.
    ///
    /// This is a syntactic approximation of a semantic rule -- WARP's own
    /// wording is "an operand *used as* a constant pointer", which needs to
    /// know how the value flows. The threshold is the price of not having
    /// that, and it is stated rather than hidden because it is wrong for a
    /// firmware image whose code genuinely lives in the first page.
    pub fn is_mapped(&self, va: u64) -> bool {
        if va < MIN_PLAUSIBLE_POINTER {
            return false;
        }
        match self.mapped.binary_search_by(|(s, _)| s.cmp(&va)) {
            Ok(_) => true,
            Err(0) => false,
            Err(i) => {
                let (_, end) = self.mapped[i - 1];
                va < end
            }
        }
    }
}

/// UUIDv5 of one basic block's already-masked instruction bytes.
pub fn basic_block_guid(masked_bytes: &[u8]) -> Uuid {
    Uuid::new_v5(&NAMESPACE_BASIC_BLOCK, masked_bytes)
}

/// UUIDv5 of a function, over its block GUIDs in the order given.
///
/// The caller is responsible for the order, exactly as `warp`'s
/// `FunctionGUID::from_basic_blocks` is; use [`sort_blocks_for_function_guid`]
/// to get WARP's order.
pub fn function_guid_from_blocks(block_guids: &[Uuid]) -> Uuid {
    let mut bytes = Vec::with_capacity(block_guids.len() * 16);
    for guid in block_guids {
        bytes.extend_from_slice(guid.as_bytes());
    }
    Uuid::new_v5(&NAMESPACE_FUNCTION, &bytes)
}

/// Put blocks in WARP's hashing order: **descending** start address.
///
/// This is the one rule in the spec with no open-source referent; see the
/// module docs. Isolating it here means a correction is a one-line change
/// with a name to search for, not a hunt through the hashing code.
pub fn sort_blocks_for_function_guid(blocks: &mut [WarpBasicBlock]) {
    blocks.sort_by(|a, b| b.start_va.cmp(&a.start_va).then(a.guid.cmp(&b.guid)));
}

/// Constraint GUID over another function's GUID.
pub fn constraint_guid_from_function(guid: &Uuid) -> Uuid {
    Uuid::new_v5(&NAMESPACE_CONSTRAINT, guid.as_bytes())
}

/// Constraint GUID over a symbol name.
pub fn constraint_guid_from_symbol(name: &str) -> Uuid {
    Uuid::new_v5(&NAMESPACE_CONSTRAINT, name.as_bytes())
}

/// Constraint GUID over a `u64`, hashed little-endian as WARP does.
pub fn constraint_guid_from_value(value: u64) -> Uuid {
    Uuid::new_v5(&NAMESPACE_CONSTRAINT, &value.to_le_bytes())
}

/// Is this `mov reg, reg` a true NOP on this ISA?
///
/// On x86-64 a write to a 32-bit register zero-extends into the full 64-bit
/// register, so `mov edi, edi` *changes* `rdi` and is not a NOP. Every other
/// width, and every width in 32-bit mode, leaves the architectural state
/// unchanged. This is the distinction the WARP README calls out by name.
fn is_effective_nop_self_move(instr: &Instruction, bitness: u32) -> bool {
    if instr.mnemonic() != Mnemonic::Mov || instr.op_count() != 2 {
        return false;
    }
    if instr.op0_kind() != OpKind::Register || instr.op1_kind() != OpKind::Register {
        return false;
    }
    let dst = instr.op0_register();
    if dst != instr.op1_register() {
        return false;
    }
    if bitness == 64 && dst.is_gpr32() {
        return false;
    }
    matches!(
        dst,
        r if r.is_gpr8() || r.is_gpr16() || r.is_gpr32() || r.is_gpr64()
    )
}

/// Does this instruction carry a constant pointer into the mapped image?
///
/// Four x86 shapes, in the order the README describes them:
///
/// 1. A direct `call`/`jmp` with a `rel8`/`rel16`/`rel32` displacement whose
///    resolved target is mapped -- the README's own `e8b55b0100` example.
/// 2. A RIP/EIP-relative memory operand: the displacement encodes a distance
///    the linker chose, and the *effective address* is what matters.
/// 3. An absolute memory operand (no base, no index) whose displacement is
///    mapped -- non-PIE data references.
/// 4. An immediate that is itself a mapped address -- `mov edi, offset str`.
fn is_relocatable(instr: &Instruction, ctx: &MaskContext) -> bool {
    for i in 0..instr.op_count() {
        match instr.op_kind(i) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                if ctx.is_mapped(instr.near_branch_target()) {
                    return true;
                }
            }
            OpKind::FarBranch16 | OpKind::FarBranch32 => {
                if ctx.is_mapped(u64::from(instr.far_branch32())) {
                    return true;
                }
            }
            // Only the widths that can hold a pointer. A sign-extended 8-bit
            // immediate cannot name a mapped address on any target we support,
            // and admitting it would mask arithmetic constants out of the hash.
            OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64 => {
                if ctx.is_mapped(instr.immediate(i)) {
                    return true;
                }
            }
            OpKind::Memory => {
                if instr.is_ip_rel_memory_operand() {
                    return true;
                }
                if instr.memory_base() == Register::None
                    && instr.memory_index() == Register::None
                    && ctx.is_mapped(instr.memory_displacement64())
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Classify one decoded instruction under the WARP rules.
pub fn classify_instruction(instr: &Instruction, ctx: &MaskContext) -> Disposition {
    if instr.mnemonic() == Mnemonic::Nop {
        return Disposition::Drop;
    }
    if is_effective_nop_self_move(instr, ctx.bitness) {
        return Disposition::Drop;
    }
    if is_relocatable(instr, ctx) {
        return Disposition::Zero;
    }
    Disposition::Keep
}

/// Apply the three WARP transforms to one block's bytes.
///
/// `code` is the block's bytes and `va` its start address. Decoding stops at
/// the end of `code`; a truncated trailing instruction contributes nothing,
/// which is the same choice the decoder makes when it reports an invalid
/// instruction.
pub fn mask_block_bytes(code: &[u8], va: u64, ctx: &MaskContext) -> Vec<u8> {
    let mut out = Vec::with_capacity(code.len());
    let mut decoder = Decoder::with_ip(ctx.bitness, code, va, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    while decoder.can_decode() {
        let pos = decoder.position();
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        let len = instr.len();
        if pos + len > code.len() {
            break;
        }
        match classify_instruction(&instr, ctx) {
            Disposition::Keep => out.extend_from_slice(&code[pos..pos + len]),
            Disposition::Zero => out.extend(std::iter::repeat_n(0u8, len)),
            Disposition::Drop => {}
        }
    }
    out
}

/// The direct-call targets inside one block, as `(call site VA, target VA)`.
fn direct_call_targets(code: &[u8], va: u64, ctx: &MaskContext) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut decoder = Decoder::with_ip(ctx.bitness, code, va, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            break;
        }
        if instr.mnemonic() == Mnemonic::Call
            && matches!(
                instr.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        {
            out.push((instr.ip(), instr.near_branch_target()));
        }
    }
    out
}

/// A VA range to file-offset projection for one parsed object.
struct VaMap {
    /// `(vm_start, vm_size, file_offset)`, sorted by `vm_start`.
    spans: Vec<(u64, u64, u64)>,
}

impl VaMap {
    fn from_object(obj: &object::File<'_>) -> Self {
        let mut spans: Vec<(u64, u64, u64)> = Vec::new();
        for seg in obj.segments() {
            let (faddr, fsize) = seg.file_range();
            if fsize == 0 || seg.size() == 0 {
                continue;
            }
            spans.push((seg.address(), seg.size().min(fsize), faddr));
        }
        if spans.is_empty() {
            for sec in obj.sections() {
                if sec.size() == 0 {
                    continue;
                }
                if let Some((faddr, flen)) = sec.file_range() {
                    spans.push((sec.address(), sec.size().min(flen), faddr));
                }
            }
        }
        spans.sort_unstable();
        Self { spans }
    }

    /// The file bytes for `[va, va + len)`, when the whole range is backed.
    fn slice<'d>(&self, data: &'d [u8], va: u64, len: u64) -> Option<&'d [u8]> {
        for (vstart, vsize, foff) in &self.spans {
            if va < *vstart || va >= vstart + vsize {
                continue;
            }
            let delta = va - vstart;
            if delta + len > *vsize {
                return None;
            }
            let start = usize::try_from(foff + delta).ok()?;
            let end = start.checked_add(usize::try_from(len).ok()?)?;
            return data.get(start..end);
        }
        None
    }
}

/// Compute WARP GUIDs for every function `functions` describes.
///
/// Split out from [`warp_functions_from_bytes`] so a caller that already has a
/// function list -- the Python binding, a KB writer, a test with hand-built
/// blocks -- does not pay for discovery twice.
pub fn warp_functions_from_discovered(
    data: &[u8],
    obj: &object::File<'_>,
    functions: &[Function],
) -> Result<Vec<WarpFunction>, WarpError> {
    let ctx = MaskContext::from_object(obj)?;
    let vamap = VaMap::from_object(obj);

    // Pass 1: block GUIDs and function GUIDs.
    let mut entries: Vec<(u64, String, Uuid, Vec<WarpBasicBlock>)> = Vec::new();
    let mut call_edges: Vec<(u64, u64, u64)> = Vec::new(); // (caller entry, site, target)
    for f in functions {
        let entry_va = f.entry_point.value;
        let mut blocks: Vec<WarpBasicBlock> = Vec::new();
        for bb in &f.basic_blocks {
            let start = bb.start_address.value;
            let end = bb.end_address.value;
            if end <= start {
                continue;
            }
            let Some(code) = vamap.slice(data, start, end - start) else {
                continue;
            };
            blocks.push(WarpBasicBlock {
                start_va: start,
                guid: basic_block_guid(&mask_block_bytes(code, start, &ctx)),
            });
            for (site, target) in direct_call_targets(code, start, &ctx) {
                call_edges.push((entry_va, site, target));
            }
        }
        if blocks.is_empty() {
            continue;
        }
        sort_blocks_for_function_guid(&mut blocks);
        let guid = function_guid_from_blocks(&blocks.iter().map(|b| b.guid).collect::<Vec<_>>());
        entries.push((entry_va, f.name.clone(), guid, blocks));
    }

    // Pass 2: constraints, which need every function's GUID to exist first.
    let by_entry: HashMap<u64, (Uuid, &str)> = entries
        .iter()
        .map(|(va, name, guid, _)| (*va, (*guid, name.as_str())))
        .collect();
    let ordered: Vec<u64> = {
        let mut v: Vec<u64> = entries.iter().map(|(va, ..)| *va).collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    // Caller edges, keyed by callee entry, so the reverse direction is one pass.
    let mut callers: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for (caller, _site, target) in &call_edges {
        if by_entry.contains_key(target) {
            callers.entry(*target).or_default().insert(*caller);
        }
    }

    let mut out: Vec<WarpFunction> = Vec::with_capacity(entries.len());
    for (entry_va, name, guid, blocks) in entries.iter() {
        let mut constraints: Vec<WarpConstraint> = Vec::new();

        // Callees: offset is the call site relative to this function's entry,
        // which is the locality WARP's `(GUID, 48)` example encodes.
        let mut seen_callee: BTreeSet<(u64, i64)> = BTreeSet::new();
        for (caller, site, target) in &call_edges {
            if caller != entry_va {
                continue;
            }
            let Some((target_guid, target_name)) = by_entry.get(target) else {
                continue;
            };
            let offset = (*site as i64).wrapping_sub(*entry_va as i64);
            if !seen_callee.insert((*target, offset)) {
                continue;
            }
            constraints.push(WarpConstraint {
                guid: constraint_guid_from_function(target_guid),
                offset: Some(offset),
                kind: ConstraintKind::Callee,
                label: Some((*target_name).to_string()),
            });
        }

        // Callers: no offset. A caller's call site is an offset into the
        // *caller*, not into us, and rebasing the pair does not preserve any
        // distance between the two entries, so there is nothing honest to put
        // here. WARP's flatbuffer spells that `i64::MAX`; we spell it `None`.
        for caller in callers.get(entry_va).into_iter().flatten() {
            let Some((caller_guid, caller_name)) = by_entry.get(caller) else {
                continue;
            };
            constraints.push(WarpConstraint {
                guid: constraint_guid_from_function(caller_guid),
                offset: None,
                kind: ConstraintKind::Caller,
                label: Some((*caller_name).to_string()),
            });
        }

        // Adjacent: the function immediately before and after by entry VA,
        // with the signed distance between the two entries.
        let idx = ordered.partition_point(|va| va < entry_va);
        for neighbour in [
            idx.checked_sub(1).map(|i| ordered[i]),
            ordered.get(idx + 1).copied(),
        ]
        .into_iter()
        .flatten()
        {
            let Some((n_guid, n_name)) = by_entry.get(&neighbour) else {
                continue;
            };
            constraints.push(WarpConstraint {
                guid: constraint_guid_from_function(n_guid),
                offset: Some((neighbour as i64).wrapping_sub(*entry_va as i64)),
                kind: ConstraintKind::Adjacent,
                label: Some((*n_name).to_string()),
            });
        }

        constraints.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then(a.guid.cmp(&b.guid))
                .then(a.offset.cmp(&b.offset))
        });
        constraints.dedup_by(|a, b| a.kind == b.kind && a.guid == b.guid && a.offset == b.offset);

        out.push(WarpFunction {
            entry_va: *entry_va,
            name: name.clone(),
            guid: *guid,
            blocks: blocks.clone(),
            constraints,
        });
    }
    out.sort_by_key(|f| f.entry_va);
    Ok(out)
}

/// Discover functions in `data` and compute a WARP identity for each.
pub fn warp_functions_from_bytes(data: &[u8]) -> Result<Vec<WarpFunction>, WarpError> {
    let obj = object::File::parse(data).map_err(|e| WarpError::UnparseableObject(e.to_string()))?;
    // Fail fast on an unsupported architecture before paying for discovery.
    MaskContext::from_object(&obj)?;
    let budgets = crate::analysis::cfg::Budgets::default();
    let (functions, _cg) = crate::analysis::cfg::analyze_functions_bytes(data, &budgets);
    warp_functions_from_discovered(data, &obj, &functions)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The WARP README's worked example, byte for byte.
    ///
    /// Three published block GUIDs, one published function GUID. If this fails
    /// our GUIDs are not WARP GUIDs, whatever else is true.
    #[test]
    fn matches_the_warp_readme_worked_example() {
        let blocks = [
            Uuid::parse_str("036cccf0-8239-5b84-a811-60efc2d7eeb0").unwrap(),
            Uuid::parse_str("3ed5c023-658d-5511-9710-40814f31af50").unwrap(),
            Uuid::parse_str("8a076c92-0ba0-540d-b724-7fd5838da9df").unwrap(),
        ];
        assert_eq!(
            function_guid_from_blocks(&blocks).to_string(),
            "7a55be03-76b7-5cb5-bae9-4edcf47795ac"
        );
    }

    /// The `warp` crate's own unit-test vector (`rust/tests/signature.rs`).
    #[test]
    fn matches_the_warp_crate_unit_test_vector() {
        let blocks = [
            Uuid::parse_str("e930c560-7b77-4f73-8b59-2ef6da75dcd4").unwrap(),
            Uuid::parse_str("3a4bf915-666f-44ad-8a7e-a2fea8f3a62a").unwrap(),
            Uuid::parse_str("0ffbfcd4-ac77-4b47-9696-006fa040167c").unwrap(),
        ];
        assert_eq!(
            function_guid_from_blocks(&blocks).to_string(),
            "1bef6187-74d9-5ebe-a0eb-4dbe6a97e578"
        );
    }

    #[test]
    fn namespaces_match_the_published_constants() {
        assert_eq!(
            NAMESPACE_BASIC_BLOCK.to_string(),
            "0192a178-7a5f-7936-8653-3cbaa7d6afe7"
        );
        assert_eq!(
            NAMESPACE_FUNCTION.to_string(),
            "0192a179-61ac-7cef-88ed-012296e9492f"
        );
        assert_eq!(
            NAMESPACE_CONSTRAINT.to_string(),
            "019701f3-e89c-7afa-9181-371a5e98a576"
        );
    }

    /// Every GUID this module emits must be a v5 UUID; a v4 would mean the
    /// `uuid` feature list regressed and the values became random.
    #[test]
    fn emitted_guids_are_version_five() {
        assert_eq!(basic_block_guid(b"\xc3").get_version_num(), 5);
        assert_eq!(function_guid_from_blocks(&[]).get_version_num(), 5);
        assert_eq!(constraint_guid_from_value(7).get_version_num(), 5);
    }

    fn ctx64() -> MaskContext {
        MaskContext::new(64, [(0x1000, 0x3000)])
    }

    /// The README's `mov edi, edi` case, both ways round.
    #[test]
    fn a_self_move_drops_on_x86_and_stays_on_x86_64() {
        let code = [0x89u8, 0xff, 0xc3]; // mov edi, edi ; ret
        let x86 = MaskContext::new(32, [(0x1000, 0x3000)]);
        assert_eq!(mask_block_bytes(&code, 0x1000, &x86), vec![0xc3]);
        assert_eq!(
            mask_block_bytes(&code, 0x1000, &ctx64()),
            vec![0x89, 0xff, 0xc3]
        );
    }

    /// A 64-bit self-move has no implicit extension, so it drops in both modes.
    #[test]
    fn a_sixty_four_bit_self_move_drops_even_on_x86_64() {
        let code = [0x48u8, 0x89, 0xff, 0xc3]; // mov rdi, rdi ; ret
        assert_eq!(mask_block_bytes(&code, 0x1000, &ctx64()), vec![0xc3]);
    }

    #[test]
    fn nops_are_dropped_including_multi_byte_ones() {
        // nop ; nop dword ptr [rax+rax] (4-byte) ; ret
        let code = [0x90u8, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xc3];
        assert_eq!(mask_block_bytes(&code, 0x1000, &ctx64()), vec![0xc3]);
    }

    /// A direct call into the image is zeroed; the same call to an unmapped
    /// address is an ordinary constant and survives.
    #[test]
    fn a_direct_call_into_the_image_is_zeroed() {
        // call rel32 -> 0x1010 from 0x1000 (5-byte instruction), then ret.
        let code = [0xe8u8, 0x0b, 0x00, 0x00, 0x00, 0xc3];
        assert_eq!(
            mask_block_bytes(&code, 0x1000, &ctx64()),
            vec![0, 0, 0, 0, 0, 0xc3]
        );
        let unmapped = MaskContext::new(64, [(0x900000, 0x901000)]);
        assert_eq!(mask_block_bytes(&code, 0x1000, &unmapped), code.to_vec());
    }

    /// A RIP-relative load is always relocation-bearing, mapped or not: the
    /// displacement is a distance the linker chose.
    #[test]
    fn a_rip_relative_lea_is_zeroed() {
        // lea rdi, [rip + 0x10]  ; ret
        let code = [0x48u8, 0x8d, 0x3d, 0x10, 0x00, 0x00, 0x00, 0xc3];
        assert_eq!(
            mask_block_bytes(&code, 0x1000, &ctx64()),
            vec![0, 0, 0, 0, 0, 0, 0, 0xc3]
        );
    }

    /// The masking is exactly what makes the identity survive a relink: the
    /// same instructions with different resolved targets hash the same.
    #[test]
    fn two_link_layouts_of_the_same_code_share_a_block_guid() {
        let ctx = MaskContext::new(64, [(0x1000, 0x9000)]);
        // call rel32 ; push rbp ; mov rbp, rsp ; ret -- the rel32 differs.
        let a = [0xe8u8, 0x40, 0x00, 0x00, 0x00, 0x55, 0x48, 0x89, 0xe5, 0xc3];
        let b = [0xe8u8, 0x90, 0x10, 0x00, 0x00, 0x55, 0x48, 0x89, 0xe5, 0xc3];
        assert_ne!(a, b);
        assert_eq!(
            basic_block_guid(&mask_block_bytes(&a, 0x1000, &ctx)),
            basic_block_guid(&mask_block_bytes(&b, 0x2000, &ctx)),
        );
    }

    /// Different code must not collide just because both ends are masked.
    #[test]
    fn different_code_does_not_share_a_block_guid() {
        let ctx = ctx64();
        let a = [0x55u8, 0xc3]; // push rbp ; ret
        let b = [0x53u8, 0xc3]; // push rbx ; ret
        assert_ne!(
            basic_block_guid(&mask_block_bytes(&a, 0x1000, &ctx)),
            basic_block_guid(&mask_block_bytes(&b, 0x1000, &ctx)),
        );
    }

    /// Descending order is the documented rule, and the two directions must
    /// not accidentally agree -- if they did, this test could not detect a
    /// regression in [`sort_blocks_for_function_guid`].
    #[test]
    fn block_order_is_descending_by_start_address_and_matters() {
        let mut blocks = vec![
            WarpBasicBlock {
                start_va: 0x1000,
                guid: basic_block_guid(b"a"),
            },
            WarpBasicBlock {
                start_va: 0x2000,
                guid: basic_block_guid(b"b"),
            },
        ];
        sort_blocks_for_function_guid(&mut blocks);
        assert_eq!(blocks[0].start_va, 0x2000);
        let descending = function_guid_from_blocks(&[blocks[0].guid, blocks[1].guid]);
        let ascending = function_guid_from_blocks(&[blocks[1].guid, blocks[0].guid]);
        assert_ne!(descending, ascending);
    }

    /// A PIE's first `LOAD` starts at virtual address 0, so without a floor
    /// every small integer in the program reads as a pointer -- and does so in
    /// the PIE build only, which is precisely how two byte-identical copies of
    /// `mathlib_version_major` got different GUIDs.
    #[test]
    fn small_constants_are_not_pointers_even_when_a_segment_starts_at_zero() {
        let ctx = MaskContext::new(64, [(0x0, 0x3000)]);
        assert!(!ctx.is_mapped(0));
        assert!(!ctx.is_mapped(1));
        assert!(!ctx.is_mapped(MIN_PLAUSIBLE_POINTER - 1));
        assert!(ctx.is_mapped(MIN_PLAUSIBLE_POINTER));
        assert!(ctx.is_mapped(0x2fff));
        assert!(!ctx.is_mapped(0x3000));
    }

    /// The same instruction must mask the same way whether the image is a PIE
    /// (base 0) or not (base 0x400000). This is the regression that the floor
    /// exists for, stated at the level the GUID is computed at.
    #[test]
    fn a_small_immediate_masks_identically_in_pie_and_non_pie_images() {
        let code = [0xf3u8, 0x0f, 0x1e, 0xfa, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];
        let pie = MaskContext::new(64, [(0x0, 0x3000)]);
        let non_pie = MaskContext::new(64, [(0x400000, 0x403000)]);
        assert_eq!(
            basic_block_guid(&mask_block_bytes(&code, 0x1180, &pie)),
            basic_block_guid(&mask_block_bytes(&code, 0x401180, &non_pie)),
        );
    }

    #[test]
    fn an_unsupported_architecture_is_named_rather_than_guessed() {
        let err = WarpError::UnsupportedArchitecture("Aarch64".to_string());
        assert!(err.to_string().contains("Aarch64"));
        assert!(err.to_string().contains("x86-64"));
    }
}
