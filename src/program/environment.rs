//! Program-level semantic facts recovered from cross-function use sites.
//!
//! A function body cannot reveal a source parameter that optimization erased.
//! Registration APIs can: a code pointer stored in `struct sigaction.sa_handler`
//! has the contract `void (*)(int)` even when the handler never reads the signal
//! number.  This module recovers that evidence once per [`ProgramSession`](super::session::ProgramSession)
//! and keeps it separate from function-local LLIR/type recovery.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::analysis::cfg::{discover_function_image_at, Budgets};
use crate::core::binary::{Arch, Endianness};
use crate::ir::call_args::CallConv;
use crate::ir::lift_function::lift_function_from_image;
use crate::ir::types::{BinOp, CallTarget, LlirFunction, MemOp, Op, VReg, Value};
use crate::ir::types_recover::{RecoveredOutputKind, TypeHint};
use crate::program::image::ProgramImage;

const MAX_CODE_TARGETS: usize = 8;
const LINUX_SA_SIGINFO: i64 = 4;

/// Proven source-level function contract owned by the program environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionPrototypeFact {
    /// Source-ordered scalar parameter declarations.
    pub parameter_hints: Vec<Option<TypeHint>>,
    /// Whether `parameter_hints.len()` is a proven complete source arity.
    ///
    /// Literal-format observations can prove individual parameter types but
    /// cannot prove that an unobserved trailing parameter does not exist.
    pub parameter_arity_is_exact: bool,
    /// Source-level output class.
    pub output_kind: Option<RecoveredOutputKind>,
    /// Stable provenance label for diagnostics and future confidence policies.
    pub source: &'static str,
}

/// Immutable program-level facts shared by decompilation queries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramEnvironment {
    prototypes: HashMap<u64, FunctionPrototypeFact>,
}

impl ProgramEnvironment {
    /// Contract for one normalized function entry, if program evidence proves it.
    pub fn prototype_for(&self, function_va: u64) -> Option<&FunctionPrototypeFact> {
        self.prototypes.get(&function_va)
    }

    /// Number of non-conflicting function contracts in this environment.
    pub fn prototype_count(&self) -> usize {
        self.prototypes.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AbstractValue {
    Stack(i64),
    Scalar(i64),
    Data(u64),
    Code(BTreeSet<u64>),
    Parameter(usize),
    FormatParameter(usize),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct CallbackState {
    pub(super) registers: HashMap<String, AbstractValue>,
    stack: BTreeMap<i64, AbstractValue>,
    pub(super) written_registers: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CallSemantics {
    MessageIdentity { argument_index: usize },
}

fn register_key(register: &VReg) -> Option<String> {
    match register {
        VReg::Phys(name) => {
            let name = crate::ir::abi::ssa_base(name);
            Some(crate::ir::ssa::parent64(name).unwrap_or(name).to_string())
        }
        VReg::Temp(id) => Some(format!("%t{id}")),
        VReg::Flag(flag) => Some(format!("%{}", flag.ident())),
        VReg::FlagValue { flag, version } => Some(format!("%{}#{version}", flag.ident())),
    }
}

fn value_fact(value: &Value, state: &CallbackState, image: &ProgramImage) -> Option<AbstractValue> {
    match value {
        Value::Reg(register) => {
            register_key(register).and_then(|register| state.registers.get(&register).cloned())
        }
        Value::Const(value) => Some(AbstractValue::Scalar(*value)),
        Value::Addr(address)
            if image
                .executable_ranges()
                .any(|range| range.contains(address)) =>
        {
            Some(AbstractValue::Code(BTreeSet::from([
                image.normalize_function_entry(*address)
            ])))
        }
        Value::Addr(address) => Some(AbstractValue::Data(*address)),
    }
}

fn add_signed(base: i64, displacement: i64) -> Option<i64> {
    base.checked_add(displacement)
}

fn memory_location(address: &MemOp, state: &CallbackState) -> Option<i64> {
    if address.segment.is_some() || address.index.is_some() {
        return None;
    }
    let base = address.base.as_ref().and_then(register_key)?;
    let AbstractValue::Stack(offset) = state.registers.get(&base)? else {
        return None;
    };
    add_signed(*offset, address.disp)
}

fn merge_value(values: impl Iterator<Item = AbstractValue>) -> Option<AbstractValue> {
    let values = values.collect::<Vec<_>>();
    let first = values.first()?.clone();
    if values.iter().all(|value| value == &first) {
        return Some(first);
    }
    if values
        .iter()
        .all(|value| matches!(value, AbstractValue::Code(_)))
    {
        let targets = values
            .into_iter()
            .filter_map(|value| match value {
                AbstractValue::Code(targets) => Some(targets),
                _ => None,
            })
            .flatten()
            .collect::<BTreeSet<_>>();
        if targets.len() <= MAX_CODE_TARGETS {
            return Some(AbstractValue::Code(targets));
        }
    }
    None
}

fn merge_pair(left: Option<AbstractValue>, right: Option<AbstractValue>) -> Option<AbstractValue> {
    match (left, right) {
        (Some(left), Some(right)) => merge_value([left, right].into_iter()),
        _ => None,
    }
}

fn message_identity_result(
    state: &CallbackState,
    cc: CallConv,
    argument_index: usize,
) -> Option<AbstractValue> {
    let register = crate::ir::abi::argument_registers(cc).get(argument_index)?;
    match state.registers.get(*register) {
        Some(AbstractValue::Parameter(index)) | Some(AbstractValue::FormatParameter(index)) => {
            Some(AbstractValue::FormatParameter(*index))
        }
        Some(value @ (AbstractValue::Data(_) | AbstractValue::Scalar(_))) => Some(value.clone()),
        _ => None,
    }
}

fn merge_states(states: &[&CallbackState]) -> CallbackState {
    let Some(first) = states.first().copied() else {
        return CallbackState::default();
    };
    let register_keys = first
        .registers
        .keys()
        .filter(|key| {
            states
                .iter()
                .all(|state| state.registers.contains_key(*key))
        })
        .cloned()
        .collect::<Vec<_>>();
    let stack_keys = first
        .stack
        .keys()
        .filter(|key| states.iter().all(|state| state.stack.contains_key(*key)))
        .copied()
        .collect::<Vec<_>>();
    let registers = register_keys
        .into_iter()
        .filter_map(|key| {
            merge_value(
                states
                    .iter()
                    .filter_map(|state| state.registers.get(&key).cloned()),
            )
            .map(|value| (key, value))
        })
        .collect();
    let stack = stack_keys
        .into_iter()
        .filter_map(|key| {
            merge_value(
                states
                    .iter()
                    .filter_map(|state| state.stack.get(&key).cloned()),
            )
            .map(|value| (key, value))
        })
        .collect();
    let written_registers = first
        .written_registers
        .iter()
        .filter(|register| {
            states
                .iter()
                .all(|state| state.written_registers.contains(*register))
        })
        .cloned()
        .collect();
    CallbackState {
        registers,
        stack,
        written_registers,
    }
}

fn set_register(state: &mut CallbackState, register: &VReg, value: Option<AbstractValue>) {
    let Some(register) = register_key(register) else {
        return;
    };
    state.written_registers.insert(register.clone());
    if let Some(value) = value {
        state.registers.insert(register, value);
    } else {
        state.registers.remove(&register);
    }
}

pub(super) fn transfer_instruction(
    instruction: &Op,
    state: &mut CallbackState,
    image: &ProgramImage,
    cc: CallConv,
    call_semantics: &HashMap<u64, CallSemantics>,
) {
    match instruction {
        Op::Assign { dst, src } => {
            let value = value_fact(src, state, image);
            set_register(state, dst, value);
        }
        Op::Bin { dst, op, lhs, rhs } => {
            let left = value_fact(lhs, state, image);
            let right = value_fact(rhs, state, image);
            let self_xor = matches!(op, BinOp::Xor)
                && match (lhs, rhs) {
                    (Value::Reg(left), Value::Reg(right)) => {
                        register_key(left) == register_key(right)
                    }
                    _ => false,
                };
            let value = if self_xor {
                Some(AbstractValue::Scalar(0))
            } else {
                match (op, left, right) {
                    (
                        BinOp::Add,
                        Some(AbstractValue::Stack(base)),
                        Some(AbstractValue::Scalar(add)),
                    ) => add_signed(base, add).map(AbstractValue::Stack),
                    (
                        BinOp::Sub,
                        Some(AbstractValue::Stack(base)),
                        Some(AbstractValue::Scalar(sub)),
                    ) => sub
                        .checked_neg()
                        .and_then(|displacement| add_signed(base, displacement))
                        .map(AbstractValue::Stack),
                    (_, Some(AbstractValue::Scalar(left)), Some(AbstractValue::Scalar(right))) => {
                        let value = match op {
                            BinOp::Add => left.checked_add(right),
                            BinOp::Sub => left.checked_sub(right),
                            BinOp::And => Some(left & right),
                            BinOp::Or => Some(left | right),
                            BinOp::Xor => Some(left ^ right),
                            _ => None,
                        };
                        value.map(AbstractValue::Scalar)
                    }
                    _ => None,
                }
            };
            set_register(state, dst, value);
        }
        Op::Ite { dst, t, e, .. } => {
            let value = merge_pair(value_fact(t, state, image), value_fact(e, state, image));
            set_register(state, dst, value);
        }
        Op::Store { addr, src } => {
            if let Some(location) = memory_location(addr, state) {
                if let Some(value) = value_fact(src, state, image) {
                    state.stack.insert(location, value);
                } else {
                    state.stack.remove(&location);
                }
            }
        }
        Op::CondStore { addr, .. } => {
            if let Some(location) = memory_location(addr, state) {
                state.stack.remove(&location);
            }
        }
        Op::Load { dst, addr } => {
            let value = memory_location(addr, state)
                .and_then(|location| state.stack.get(&location).cloned());
            set_register(state, dst, value);
        }
        Op::CondLoad { dst, .. }
        | Op::Un { dst, .. }
        | Op::Cmp { dst, .. }
        | Op::Extract { dst, .. }
        | Op::Concat { dst, .. }
        | Op::Undef { dst, .. } => set_register(state, dst, None),
        Op::ZExt { dst, src, .. } | Op::SExt { dst, src, .. } | Op::Trunc { dst, src, .. } => {
            let value = match value_fact(src, state, image) {
                Some(AbstractValue::Scalar(0)) => Some(AbstractValue::Scalar(0)),
                _ => None,
            };
            set_register(state, dst, value);
        }
        Op::Call { target, .. } => {
            let semantic_result = match target {
                CallTarget::Direct(target) => call_semantics.get(target).and_then(|semantic| {
                    let CallSemantics::MessageIdentity { argument_index } = semantic;
                    message_identity_result(state, cc, *argument_index)
                }),
                CallTarget::Indirect(_) => None,
            };
            for register in crate::ir::abi::caller_saved_registers(cc) {
                state.registers.remove(*register);
            }
            if let Some(result) = semantic_result {
                let register = crate::ir::abi::return_register(cc).to_string();
                state.written_registers.insert(register.clone());
                state.registers.insert(register, result);
            }
        }
        Op::Intrinsic { outs, .. } => {
            for (register, _) in outs {
                set_register(state, register, None);
            }
        }
        other => {
            if let Some(definition) = crate::ir::use_def::def_uses(other).0 {
                set_register(state, &definition, None);
            }
        }
    }
}

fn stack_pointer(cc: CallConv) -> &'static str {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32 => "rsp",
        CallConv::Aarch64 => "sp",
        CallConv::Arm | CallConv::ArmHardFloat => "sp",
    }
}

pub(super) fn input_states_for_image(
    function: &LlirFunction,
    cc: CallConv,
    image: &ProgramImage,
    call_semantics: &HashMap<u64, CallSemantics>,
    track_parameters: bool,
) -> Vec<CallbackState> {
    let block_indices = function
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_va, index))
        .collect::<HashMap<_, _>>();
    let mut predecessors = vec![Vec::new(); function.blocks.len()];
    for (index, block) in function.blocks.iter().enumerate() {
        for successor in &block.succs {
            if let Some(successor) = block_indices.get(successor).copied() {
                predecessors[successor].push(index);
            }
        }
    }
    let entry = block_indices.get(&function.entry_va).copied();
    let mut inputs: Vec<Option<CallbackState>> = vec![None; function.blocks.len()];
    let mut outputs: Vec<Option<CallbackState>> = vec![None; function.blocks.len()];
    let mut entry_state = CallbackState::default();
    entry_state
        .registers
        .insert(stack_pointer(cc).to_string(), AbstractValue::Stack(0));
    if track_parameters {
        for (index, register) in crate::ir::abi::argument_registers(cc).iter().enumerate() {
            entry_state
                .registers
                .insert((*register).to_string(), AbstractValue::Parameter(index));
        }
    }
    for _ in 0..function.blocks.len().saturating_mul(4).max(1) {
        let mut changed = false;
        for (index, block) in function.blocks.iter().enumerate() {
            let input = if Some(index) == entry {
                Some(entry_state.clone())
            } else {
                let reachable = predecessors[index]
                    .iter()
                    .filter_map(|predecessor| outputs[*predecessor].as_ref())
                    .collect::<Vec<_>>();
                (!reachable.is_empty()).then(|| merge_states(&reachable))
            };
            let Some(mut output) = input.clone() else {
                continue;
            };
            for instruction in &block.instrs {
                transfer_instruction(&instruction.op, &mut output, image, cc, call_semantics);
            }
            if inputs[index].as_ref() != input.as_ref() {
                inputs[index] = input;
                changed = true;
            }
            if outputs[index].as_ref() != Some(&output) {
                outputs[index] = Some(output);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    inputs.into_iter().map(Option::unwrap_or_default).collect()
}

pub(super) fn clean_import_name(name: &str) -> &str {
    name.strip_suffix("@plt")
        .or_else(|| name.strip_suffix(".plt"))
        .unwrap_or(name)
        .split('@')
        .next()
        .unwrap_or(name)
}

pub(crate) fn callback_api_identity(
    address_names: &HashMap<u64, String>,
) -> Box<[(u64, &'static str)]> {
    let mut identity = address_names
        .iter()
        .filter_map(|(address, name)| match clean_import_name(name) {
            "sigaction" => Some((*address, "sigaction.sa_handler")),
            "signal" | "__sysv_signal" => Some((*address, "signal.handler")),
            _ => None,
        })
        .collect::<Vec<_>>();
    identity.sort_unstable();
    identity.dedup();
    identity.into_boxed_slice()
}

fn callback_api_targets(address_names: &HashMap<u64, String>) -> HashMap<u64, &'static str> {
    callback_api_identity(address_names)
        .iter()
        .copied()
        .collect()
}

fn read_instruction_word(image: &ProgramImage, bytes: &[u8], offset: usize) -> Option<u32> {
    let bytes = bytes.get(offset..offset + 4)?;
    Some(match image.endianness() {
        Endianness::Little => u32::from_le_bytes(bytes.try_into().ok()?),
        Endianness::Big => u32::from_be_bytes(bytes.try_into().ok()?),
    })
}

fn sign_extend(value: u64, bits: u8) -> i64 {
    let shift = 64 - u32::from(bits);
    ((value << shift) as i64) >> shift
}

fn direct_call_target(
    image: &ProgramImage,
    bytes: &[u8],
    offset: usize,
    va: u64,
) -> Option<(u64, u64)> {
    match image.arch() {
        Arch::X86 | Arch::X86_64 => {
            if bytes.get(offset).copied()? != 0xe8 {
                return None;
            }
            let displacement =
                i32::from_le_bytes(bytes.get(offset + 1..offset + 5)?.try_into().ok()?);
            let next = va.checked_add(5)?;
            let target = if displacement >= 0 {
                next.checked_add(displacement as u64)?
            } else {
                next.checked_sub(u64::from(displacement.unsigned_abs()))?
            };
            Some((target, 5))
        }
        Arch::AArch64 => {
            let instruction = read_instruction_word(image, bytes, offset)?;
            if instruction & 0xfc00_0000 != 0x9400_0000 {
                return None;
            }
            let displacement = sign_extend(u64::from(instruction & 0x03ff_ffff), 26) << 2;
            let target = if displacement >= 0 {
                va.checked_add(displacement as u64)?
            } else {
                va.checked_sub(displacement.unsigned_abs())?
            };
            Some((target, 4))
        }
        _ => None,
    }
}

fn contiguous_executable_bytes<'a>(
    image: &'a ProgramImage,
    range: &std::ops::Range<u64>,
) -> Option<&'a [u8]> {
    let length = usize::try_from(range.end.checked_sub(range.start)?).ok()?;
    if length == 0 {
        return Some(&[]);
    }
    let start = image.va_to_code_file_offset(range.start)?;
    let last = image.va_to_code_file_offset(range.end.checked_sub(1)?)?;
    if last != start.checked_add(length.checked_sub(1)?)? {
        return None;
    }
    image.bytes().get(start..start.checked_add(length)?)
}

pub(super) fn direct_call_sites(
    image: &ProgramImage,
    targets: &HashMap<u64, &'static str>,
) -> Vec<(u64, u64)> {
    let alignment = if image.arch() == Arch::AArch64 { 4 } else { 1 };
    let mut sites = Vec::new();
    for range in image.executable_ranges() {
        let Some(bytes) = contiguous_executable_bytes(image, range) else {
            continue;
        };
        let mut offset = 0;
        while offset < bytes.len() {
            let va = range.start.saturating_add(offset as u64);
            if let Some((target, size)) = direct_call_target(image, bytes, offset, va) {
                if targets.contains_key(&target) {
                    sites.push((va, target));
                }
                offset = offset.saturating_add(size.max(alignment) as usize);
            } else {
                offset = offset.saturating_add(alignment as usize);
            }
        }
    }
    sites
}

fn direct_code_reference(
    image: &ProgramImage,
    bytes: &[u8],
    offset: usize,
    va: u64,
) -> Option<(u64, u64)> {
    match image.arch() {
        Arch::X86 | Arch::X86_64 => {
            let rex = bytes
                .get(offset)
                .copied()
                .is_some_and(|byte| byte & 0xf0 == 0x40);
            let opcode_offset = offset + usize::from(rex);
            let opcode = bytes.get(opcode_offset).copied()?;
            if opcode == 0x8d {
                let modrm = bytes.get(opcode_offset + 1).copied()?;
                if modrm & 0xc7 != 0x05 {
                    return None;
                }
                let displacement = i32::from_le_bytes(
                    bytes
                        .get(opcode_offset + 2..opcode_offset + 6)?
                        .try_into()
                        .ok()?,
                );
                let size = u64::try_from(usize::from(rex) + 6).ok()?;
                let next = va.checked_add(size)?;
                let target = if displacement >= 0 {
                    next.checked_add(displacement as u64)?
                } else {
                    next.checked_sub(u64::from(displacement.unsigned_abs()))?
                };
                return Some((target, size));
            }
            if (0xb8..=0xbf).contains(&opcode) {
                if image.arch() == Arch::X86_64 && rex && bytes[offset] & 0x08 != 0 {
                    let value = u64::from_le_bytes(
                        bytes
                            .get(opcode_offset + 1..opcode_offset + 9)?
                            .try_into()
                            .ok()?,
                    );
                    return Some((value, 10));
                }
                let value = u32::from_le_bytes(
                    bytes
                        .get(opcode_offset + 1..opcode_offset + 5)?
                        .try_into()
                        .ok()?,
                );
                return Some((u64::from(value), 5));
            }
            None
        }
        // AArch64 ADRP+ADD and ARM literal-pool references span instructions.
        // The program environment remains sound but incomplete until the
        // architecture reference oracle exposes those pairs here.
        _ => None,
    }
}

fn referencing_owner_entries(
    image: &ProgramImage,
    requested_vas: &HashSet<u64>,
    fdes: &[crate::analysis::exception::EhFrameFunction],
) -> HashSet<u64> {
    if requested_vas.is_empty() {
        return HashSet::new();
    }
    let mut owners = HashSet::new();
    for range in image.executable_ranges() {
        let Some(bytes) = contiguous_executable_bytes(image, range) else {
            continue;
        };
        let mut offset = 0;
        while offset < bytes.len() {
            let va = range.start.saturating_add(offset as u64);
            if let Some((target, size)) = direct_code_reference(image, bytes, offset, va) {
                if requested_vas.contains(&image.normalize_function_entry(target)) {
                    if let Some(owner) = fdes
                        .iter()
                        .find(|function| function.start <= va && va < function.end)
                    {
                        owners.insert(owner.start);
                    }
                }
                offset = offset.saturating_add(size.max(1) as usize);
            } else {
                offset = offset.saturating_add(1);
            }
        }
    }
    owners
}

fn code_targets(value: Option<&AbstractValue>) -> Option<&BTreeSet<u64>> {
    match value {
        Some(AbstractValue::Code(targets)) => Some(targets),
        _ => None,
    }
}

fn callback_targets_at_call(
    api: &str,
    state: &CallbackState,
    cc: CallConv,
) -> Option<BTreeSet<u64>> {
    let argument = crate::ir::abi::argument_registers(cc).get(1)?;
    let value = state.registers.get(*argument)?;
    match api {
        "signal.handler" => code_targets(Some(value)).cloned(),
        "sigaction.sa_handler" => {
            let AbstractValue::Stack(base) = value else {
                return None;
            };
            let word = i64::from(crate::ir::abi::machine_word_bytes(cc));
            let flags_offset = base.checked_add(word)?.checked_add(128)?;
            let Some(AbstractValue::Scalar(flags)) = state.stack.get(&flags_offset) else {
                return None;
            };
            if flags & LINUX_SA_SIGINFO != 0 {
                return None;
            }
            code_targets(state.stack.get(base)).cloned()
        }
        _ => None,
    }
}

fn callback_targets(
    function: &LlirFunction,
    image: &ProgramImage,
    cc: CallConv,
    api_targets: &HashMap<u64, &'static str>,
) -> HashMap<u64, &'static str> {
    let call_semantics = HashMap::new();
    let inputs = input_states_for_image(function, cc, image, &call_semantics, false);
    let mut found = HashMap::new();
    for (block_index, block) in function.blocks.iter().enumerate() {
        let mut state = inputs[block_index].clone();
        for instruction in &block.instrs {
            if let Op::Call {
                target: CallTarget::Direct(target),
                ..
            } = instruction.op
            {
                if let Some(api) = api_targets.get(&target).copied() {
                    if std::env::var("GLAURUNG_DUMP_PASSES").is_ok() {
                        eprintln!(
                            "callback call 0x{:x} -> 0x{target:x} {api}: {state:#x?}",
                            instruction.va
                        );
                    }
                    if let Some(targets) = callback_targets_at_call(api, &state, cc) {
                        for target in targets {
                            found.insert(image.normalize_function_entry(target), api);
                        }
                    }
                }
            }
            transfer_instruction(&instruction.op, &mut state, image, cc, &call_semantics);
        }
    }
    found
}

fn merge_prototype_fact(
    prototypes: &mut HashMap<u64, FunctionPrototypeFact>,
    target: u64,
    incoming: FunctionPrototypeFact,
) {
    let Some(existing) = prototypes.get_mut(&target) else {
        prototypes.insert(target, incoming);
        return;
    };
    match (
        existing.parameter_arity_is_exact,
        incoming.parameter_arity_is_exact,
    ) {
        (true, true) if existing.parameter_hints.len() != incoming.parameter_hints.len() => {
            return;
        }
        (true, false) if incoming.parameter_hints.len() > existing.parameter_hints.len() => {
            return;
        }
        (false, true) if existing.parameter_hints.len() > incoming.parameter_hints.len() => {
            return;
        }
        (false, true) => existing.parameter_arity_is_exact = true,
        _ => {}
    }
    existing.parameter_hints.resize(
        existing
            .parameter_hints
            .len()
            .max(incoming.parameter_hints.len()),
        None,
    );
    for (index, hint) in incoming.parameter_hints.into_iter().enumerate() {
        existing.parameter_hints[index] = match (existing.parameter_hints[index], hint) {
            (None, incoming) => incoming,
            (current, None) => current,
            (Some(current), Some(incoming)) if current == incoming => Some(current),
            (Some(_), Some(_)) => None,
        };
    }
    existing.output_kind = match (existing.output_kind, incoming.output_kind) {
        (None, incoming) => incoming,
        (current, None) => current,
        (Some(current), Some(incoming)) if current == incoming => Some(current),
        (Some(_), Some(_)) => None,
    };
    existing.source = "program.environment";
}

/// Recover registration-proven callback contracts from the immutable image.
///
/// The initial byte scan is only a prefilter. Every candidate call site must be
/// inside an exact `.eh_frame` function interval and the lifted LLIR must contain
/// the matching direct call before any fact is emitted.
pub fn recover_program_environment(
    image: &ProgramImage,
    budgets: &Budgets,
    cc: CallConv,
    address_names: &HashMap<u64, String>,
    requested_vas: &[u64],
) -> ProgramEnvironment {
    let dump = std::env::var("GLAURUNG_DUMP_PASSES").is_ok();
    let api_targets = callback_api_targets(address_names);
    if dump {
        eprintln!("\n===== program callback API targets =====\n{api_targets:#x?}");
    }
    let has_format_sink = super::format_environment::has_format_consumer(address_names);
    let fdes = image.eh_frame_functions();
    if fdes.is_empty() {
        return ProgramEnvironment::default();
    }
    let requested_vas = requested_vas
        .iter()
        .map(|address| image.normalize_function_entry(*address))
        .collect::<HashSet<_>>();
    let referencing_owners = if api_targets.is_empty() {
        HashSet::new()
    } else {
        referencing_owner_entries(image, &requested_vas, fdes)
    };
    let call_sites = if referencing_owners.is_empty() {
        Vec::new()
    } else {
        direct_call_sites(image, &api_targets)
    };
    if dump {
        eprintln!("\n===== program callback call sites =====\n{call_sites:#x?}");
    }
    let owner_entries = call_sites
        .into_iter()
        .filter_map(|(site, _)| {
            fdes.iter()
                .find(|function| function.start <= site && site < function.end)
                .map(|function| function.start)
        })
        .filter(|owner| referencing_owners.contains(owner))
        .collect::<BTreeSet<_>>();
    let mut prototypes = HashMap::new();
    let mut conflicts = HashSet::new();
    let targeted_budgets = Budgets {
        max_functions: 1,
        ..*budgets
    };
    for owner in owner_entries {
        let Some(function) = discover_function_image_at(image, &targeted_budgets, owner) else {
            continue;
        };
        let Some(lifted) = lift_function_from_image(image, &function) else {
            continue;
        };
        let targets = callback_targets(&lifted, image, cc, &api_targets);
        if dump {
            eprintln!("callback owner 0x{owner:x}: {targets:#x?}");
        }
        for (target, source) in targets {
            let fact = FunctionPrototypeFact {
                parameter_hints: vec![Some(TypeHint::Int {
                    signed: true,
                    width: 4,
                })],
                parameter_arity_is_exact: true,
                output_kind: Some(RecoveredOutputKind::Void),
                source,
            };
            if prototypes
                .get(&target)
                .is_some_and(|existing| existing != &fact)
            {
                prototypes.remove(&target);
                conflicts.insert(target);
            } else if !conflicts.contains(&target) {
                prototypes.insert(target, fact);
            }
        }
    }
    for target in &requested_vas {
        if let Some(parameter_hints) = has_format_sink
            .then(|| {
                super::format_environment::recover_format_parameter_hints(
                    image,
                    budgets,
                    cc,
                    address_names,
                    fdes,
                    *target,
                )
            })
            .flatten()
        {
            merge_prototype_fact(
                &mut prototypes,
                *target,
                FunctionPrototypeFact {
                    parameter_hints,
                    parameter_arity_is_exact: false,
                    output_kind: None,
                    source: "literal-format callers",
                },
            );
        }
    }
    let caller_arities = super::caller_environment::recover_direct_caller_arities(
        image,
        budgets,
        cc,
        fdes,
        &requested_vas,
    );
    for (target, arity) in caller_arities {
        let parameter_hints = vec![None; arity];
        merge_prototype_fact(
            &mut prototypes,
            target,
            FunctionPrototypeFact {
                parameter_hints,
                parameter_arity_is_exact: true,
                output_kind: None,
                source: "agreeing direct caller stack bound",
            },
        );
    }
    ProgramEnvironment { prototypes }
}

#[cfg(test)]
mod tests;
