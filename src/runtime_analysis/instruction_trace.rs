//! Bounded instruction-step relations for observed runtime memory changes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "symbolic")]
use super::capsule::Sensitivity;
use super::capsule::{PageContent, ProcessCapsule, RuntimeObjectKind};
use super::correlation::{
    resolve_runtime_address, AddressResolution, InstructionRelation, OperationResolution,
    StaticCallTarget, StaticCodeResolution, StaticMemoryAccess, StaticOperation,
    StaticValueExpression,
};
use super::crash::Evidence;
use super::event_correlation::{operation_occurrence, OperationEffect, OperationOccurrence};
use super::input::{input_provenance, InputSourceIdentity};
use super::memory::RuntimeMemoryView;
use crate::analysis::cfg::{discover_function_image_at, Budgets};
use crate::core::binary::{Arch, Endianness};
use crate::debug::dwarf::DwarfStackBase;
use crate::exec::{Concrete, Domain, Flow, Machine, RegArch};
use crate::ir::lift_function::lift_function_from_image;
use crate::ir::types::{Endian, Flag, MemOp, Op, VReg, Value, Width};
use crate::program::image::ProgramImage;
#[cfg(feature = "symbolic")]
use crate::symbolic::{Expr, SolveResult, Symbolic};

pub const INSTRUCTION_TRACE_REPORT_SCHEMA: &str = "glaurung-runtime-instruction-trace-report-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedMemoryChange {
    pub start: u64,
    pub end: u64,
    pub before_hex: String,
    pub after_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct InstructionStepPayload {
    schema: String,
    changes: Vec<ObservedMemoryChange>,
    registers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct InstructionRegisterTracePayload {
    schema: String,
    steps: Vec<InstructionRegisterStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct InstructionRegisterStep {
    sequence: u64,
    address: u64,
    registers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedEffectiveAddress {
    pub base_register: Option<String>,
    pub base_value: Option<u64>,
    pub index_register: Option<String>,
    pub index_value: Option<u64>,
    pub scale: u8,
    pub displacement: i64,
    pub effective_address: u64,
    pub byte_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionTraceRelation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub changes: Evidence<Vec<ObservedMemoryChange>>,
    pub registers: Evidence<BTreeMap<String, u64>>,
    pub effective_address: Evidence<ObservedEffectiveAddress>,
    pub address_resolution: AddressResolution,
    pub operation_occurrence: Evidence<OperationOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MainImageAddressCoverage {
    pub image_sha256: String,
    pub observed_step_count: u64,
    pub exact_step_count: u64,
    pub failures: Vec<ObservedAddressCorrelationFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedAddressCorrelationFailure {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub resolution: AddressResolution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionTraceReport {
    pub schema: String,
    pub capture_id: String,
    pub image_sha256: String,
    pub coverage: InstructionTraceCoverage,
    pub main_image_address_coverage: Evidence<MainImageAddressCoverage>,
    pub relations: Vec<InstructionTraceRelation>,
    pub executed_stores: Vec<ExecutedStoreRelation>,
    pub executed_loads: Vec<ExecutedLoadRelation>,
    pub observed_blocks: Vec<ObservedBlockRelation>,
    pub replay_seeds: Vec<ReplaySeedRelation>,
    pub call_relations: Vec<InstructionCallRelation>,
    pub input_locations: Vec<RuntimeInputLocationRelation>,
    pub control_transfers: Vec<InstructionControlTransferRelation>,
    pub observed_indirect_targets: Vec<ObservedIndirectTargetRelation>,
    pub value_selections: Vec<InstructionValueSelectionRelation>,
    pub value_definitions: Vec<InstructionValueDefinitionRelation>,
    pub input_to_call_arguments: Vec<InputToCallArgumentRelation>,
    pub input_value_flows: Vec<InputValueFlowRelation>,
    pub solver_query_candidates: Vec<InputDependentBranch>,
}

/// One occurrence-scoped join between a contiguous native trace segment and
/// one immutable lifted block. Repeated executions of the same static block
/// remain separate relations because the sequence range is part of identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedBlockRelation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub relation: Evidence<ObservedBlockOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedBlockOccurrence {
    pub id: String,
    pub capture_id: String,
    pub process_id: String,
    pub thread_id: Option<String>,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub image_sha256: String,
    pub function_entry: u64,
    pub native_block_start: u64,
    pub native_block_end: u64,
    pub lift_profile: String,
    pub lifted_block_start: u64,
    pub steps: Vec<ObservedBlockStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedBlockStep {
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub static_va: u64,
    pub static_instruction_va: u64,
    pub static_instruction_end: u64,
    pub operation_indices: Vec<usize>,
    pub operation_kinds: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySeedRelation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub seed: Evidence<ReplaySeed>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySeed {
    pub id: String,
    pub capture_id: String,
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub observed_block_id: String,
    pub pc: u64,
    pub architecture: String,
    pub registers: BTreeMap<String, u64>,
    pub memory_ranges: Vec<ReplaySeedMemoryRange>,
    pub memory_reconstruction_from_sequence: u64,
    pub memory_reconstruction_through_sequence: u64,
    pub applied_memory_change_count: u64,
    pub verified_register_count: u64,
    pub verified_memory_byte_count: u64,
    pub unseeded_memory: String,
    pub bounded_replay: Evidence<BoundedBlockReplay>,
    pub first_divergence: Option<ReplayDivergence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySeedMemoryRange {
    pub snapshot_id: String,
    pub runtime_object_id: String,
    pub start: u64,
    pub byte_len: u64,
    pub source_snapshot_sha256: String,
    pub seeded_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedBlockReplay {
    pub observed_block_id: String,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub executed_operation_count: u64,
    pub terminal_flow: String,
    pub observed_successor_sequence: u64,
    pub observed_successor_runtime_va: u64,
    pub compared_registers: BTreeMap<String, u64>,
    pub address_normalized_registers: BTreeMap<String, AddressNormalizedRegisterComparison>,
    pub uncompared_registers: BTreeMap<String, String>,
    pub address_normalized_memory: Vec<AddressNormalizedMemoryComparison>,
    pub compared_memory_byte_count: u64,
    pub terminal_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressNormalizedRegisterComparison {
    pub replay_static_va: u64,
    pub observed_runtime_va: u64,
    pub mapping_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressNormalizedMemoryComparison {
    pub storage_runtime_va: u64,
    pub replay_static_va: u64,
    pub observed_runtime_va: u64,
    pub mapping_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayDivergenceKind {
    UnsupportedOperation,
    MissingEnvironment,
    ControlFlowMismatch,
    RegisterMismatch,
    MemoryMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayOperationAttribution {
    pub event_sequence: u64,
    pub static_instruction_va: u64,
    pub llir_block_start: u64,
    pub operation_index: usize,
    pub operation_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayDivergence {
    pub kind: ReplayDivergenceKind,
    pub reason: String,
    pub operation: Option<ReplayOperationAttribution>,
    pub state_component: Option<String>,
    pub replayed_value: Option<String>,
    pub observed_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputValueFlowRelation {
    pub source_id: String,
    pub source_name: String,
    pub relation: Evidence<InputValueFlow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputValueFlow {
    pub source_id: String,
    pub source_name: String,
    pub source_byte_len: u64,
    pub steps: Vec<InputValueFlowStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputValueFlowStep {
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub static_operation: StaticOperation,
    pub provenance: Vec<InputByteSpan>,
    pub source_memory_address: u64,
    pub source_load_occurrence: Evidence<OperationOccurrence>,
    pub transfer: ObservedValueTransfer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedLoadRelation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub registers: Evidence<BTreeMap<String, u64>>,
    pub effective_address: Evidence<ObservedEffectiveAddress>,
    pub address_resolution: AddressResolution,
    pub operation_occurrence: Evidence<OperationOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputByteSpan {
    pub source_id: String,
    pub source_offset: u64,
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputDependentBranch {
    pub source_id: String,
    pub source_name: String,
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub static_operation: StaticOperation,
    pub observed_edge: ObservedControlEdge,
    pub predicate_registers: Vec<String>,
    pub input_spans: Vec<InputByteSpan>,
    pub selection_reason: String,
    pub counterfactual: BranchCounterfactual,
}

struct PendingInputDependentBranch {
    source: RuntimeInputLocation,
    lineage_id: u64,
    source_id: String,
    source_name: String,
    process_id: String,
    thread_id: Option<String>,
    sequence: u64,
    runtime_instruction_va: u64,
    static_operation: StaticOperation,
    observed_edge: ObservedControlEdge,
    predicate_registers: Vec<String>,
    input_spans: Vec<InputByteSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BranchCounterfactual {
    Satisfiable {
        backend: String,
        asserted_path_conditions: u64,
        bounds: CounterfactualBounds,
        path_conditions: Vec<CounterfactualPathCondition>,
        predicted_branch_taken: bool,
        predicted_target_static_va: u64,
        mutations: Vec<InputByteMutation>,
    },
    Unsatisfiable {
        backend: String,
        asserted_path_conditions: u64,
        bounds: CounterfactualBounds,
        path_conditions: Vec<CounterfactualPathCondition>,
    },
    Unknown {
        reason_kind: CounterfactualUnknownReason,
        reason: String,
        proposition_status: CounterfactualPropositionStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bounds: Option<CounterfactualBounds>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        path_conditions: Vec<CounterfactualPathCondition>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualBounds {
    pub first_event_sequence: u64,
    pub last_event_sequence: u64,
    pub observed_instruction_count: u64,
    pub symbolic_input_byte_count: u64,
    pub memory_snapshot_sequence: u64,
    pub captured_memory_byte_count: u64,
    pub solver_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualPathCondition {
    pub sequence: u64,
    pub static_operation: StaticOperation,
    pub required_branch_taken: bool,
    pub role: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterfactualPropositionStatus {
    NotConstructed,
    Bounded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterfactualUnknownReason {
    NoSolver,
    SolverTimeout,
    SolverResourceLimit,
    SolverError,
    UnsupportedSemantics,
    SymbolicPointer,
    MissingEnvironment,
    PrivateInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputByteMutation {
    pub source_id: String,
    pub source_offset: u64,
    pub replacement_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInputLocation {
    pub source_id: String,
    pub source_name: String,
    pub process_id: String,
    pub mapping_id: String,
    pub page_start: u64,
    pub runtime_address: u64,
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInputLocationRelation {
    pub source_id: String,
    pub source_name: String,
    pub location: Evidence<RuntimeInputLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedStoreRelation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub registers: Evidence<BTreeMap<String, u64>>,
    pub effective_address: Evidence<ObservedEffectiveAddress>,
    pub source_pointer: Evidence<ExecutedStoreSourcePointer>,
    pub allocation_prefix: Evidence<ExecutedStoreAllocationPrefix>,
    pub allocation_tail: Evidence<ExecutedStoreAllocationTail>,
    pub object_transition: Evidence<ExecutedStoreObjectTransition>,
    pub address_resolution: AddressResolution,
    pub operation_occurrence: Evidence<OperationOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedStoreAllocationPrefix {
    pub runtime_object_id: String,
    pub extent_source_name: String,
    pub extent_c_type: String,
    pub extent_static_base: String,
    pub extent_static_offset: i64,
    pub allocation_argument_position: usize,
    pub allocation_abi_register: String,
    pub logical_prefix_byte_len: u64,
    pub reserved_tail_byte_len: u64,
    pub allocation_byte_len: u64,
    pub store_object_offset: u64,
    pub store_byte_len: u64,
    pub prefix_bytes_exceeded: u64,
    pub classification: String,
    pub allocation_occurrence: OperationOccurrence,
    pub store_occurrence: OperationOccurrence,
    pub source_pointer: ExecutedStoreSourcePointer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedStoreAllocationTail {
    pub runtime_object_id: String,
    pub source_name: String,
    pub c_type: String,
    pub function_entry: u64,
    pub static_base: String,
    pub static_offset: i64,
    pub pointer_byte_len: u8,
    pub pointer_value: u64,
    pub pointer_object_offset: u64,
    pub pointee_byte_len: u8,
    pub reserved_tail_byte_len: u64,
    pub store_overlap_byte_len: u64,
    pub before_snapshot_id: String,
    pub stored_snapshot_id: String,
    pub final_snapshot_id: String,
    pub before_hex: String,
    pub stored_hex: String,
    pub final_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedStoreSourcePointer {
    pub runtime_object_id: String,
    pub static_variable: crate::ir::function_ir::StaticVariable,
    pub static_type: crate::ir::function_ir::StaticType,
    pub semantic_binding: crate::ir::function_ir::SemanticValueVariableBinding,
    pub source_name: String,
    pub c_type: String,
    pub function_entry: u64,
    pub static_base: String,
    pub static_offset: i64,
    pub pointer_byte_len: u8,
    pub pointer_value: u64,
    pub pointer_object_offset: u64,
    pub store_offset_from_pointer: u64,
    pub effective_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedStoreObjectTransition {
    pub runtime_object_id: String,
    pub object_offset: u64,
    pub byte_len: u8,
    pub before_snapshot_id: String,
    pub stored_snapshot_id: String,
    pub final_snapshot_id: String,
    pub before_hex: String,
    pub stored_hex: String,
    pub final_hex: String,
    pub changed_after_store: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionCallRelation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub registers: Evidence<BTreeMap<String, u64>>,
    pub address_resolution: AddressResolution,
    pub static_target_va: Evidence<u64>,
    pub callee: Evidence<String>,
    pub return_occurrence: Evidence<ObservedCallReturn>,
    pub operation_occurrence: Evidence<OperationOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedCallReturn {
    pub sequence: u64,
    pub runtime_address: u64,
    pub return_register: String,
    pub return_value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionControlTransferRelation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub static_operation: Evidence<StaticOperation>,
    pub observed_successor: Evidence<u64>,
    pub successor_resolution: AddressResolution,
    pub edge: Evidence<ObservedControlEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedControlEdge {
    pub source_static_va: u64,
    pub target_static_va: u64,
    pub declared_target_static_va: u64,
    pub branch_taken: bool,
}

/// One observed target of an exact indirect LLIR control-transfer occurrence.
///
/// This relation does not add the target to the immutable static CFG and does
/// not imply that the observed target set is exhaustive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedIndirectTargetRelation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub static_operation: Evidence<StaticOperation>,
    pub observed_runtime_target: Evidence<u64>,
    pub target_resolution: AddressResolution,
    pub target: Evidence<ObservedIndirectTarget>,
    pub operation_occurrence: Evidence<OperationOccurrence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedIndirectTarget {
    pub source_static_va: u64,
    pub target_static_va: u64,
    pub transfer_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionValueSelectionRelation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub static_operation: Evidence<StaticOperation>,
    pub registers_before: Evidence<BTreeMap<String, u64>>,
    pub registers_after: Evidence<BTreeMap<String, u64>>,
    pub output: Evidence<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionValueDefinitionRelation {
    pub process_id: String,
    pub thread_id: Option<String>,
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub static_operation: StaticOperation,
    pub registers_before: Evidence<BTreeMap<String, u64>>,
    pub registers_after: Evidence<BTreeMap<String, u64>>,
    pub output: Evidence<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputToCallArgumentRelation {
    pub source_id: String,
    pub source_name: String,
    pub sink_sequence: u64,
    pub relation: Evidence<InputToCallArgumentSlice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputToCallArgumentSlice {
    pub source_id: String,
    pub source_name: String,
    pub comparison_occurrence: OperationOccurrence,
    pub comparison_return: ObservedCallReturn,
    pub propagation: InputToCallArgumentPropagation,
    pub sink_occurrence: OperationOccurrence,
    pub argument_name: String,
    pub argument_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InputToCallArgumentPropagation {
    BranchSelectedMemory {
        comparison_edge: ObservedControlEdge,
        predicate_call: StaticOperation,
        predicate_return: ObservedCallReturn,
        selection_edge: ObservedControlEdge,
        selected_write: OperationOccurrence,
    },
    ConditionalValue {
        selection: InstructionValueSelectionRelation,
    },
    BranchSelectedRegister {
        comparison_edge: ObservedControlEdge,
        selected_definition: InstructionValueDefinitionRelation,
    },
    SpilledPredicateReturnConditionalMemory {
        predicate_call: StaticOperation,
        predicate_return: ObservedCallReturn,
        comparison_to_predicate_return: ObservedCallResultFlow,
        selection: InstructionValueSelectionRelation,
        selected_write: OperationOccurrence,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedCallResultFlow {
    pub source_call_machine_va: u64,
    pub destination_register: String,
    pub destination_value: u64,
    pub steps: Vec<ObservedValueFlowStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedValueFlowStep {
    pub sequence: u64,
    pub runtime_instruction_va: u64,
    pub static_operation: StaticOperation,
    pub transfer: ObservedValueTransfer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservedValueTransfer {
    Register { register: String },
    MemoryWrite { address: u64, byte_len: u8 },
    MemoryRead { address: u64, byte_len: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionTraceCoverage {
    pub observed_steps: u64,
    pub steps_with_stack_changes: u64,
    pub compared_region: String,
    pub broader_runtime_state: String,
}

fn relate_main_image_address_coverage(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    image_sha256: &str,
) -> Evidence<MainImageAddressCoverage> {
    let module_ids = capsule
        .modules
        .iter()
        .filter(|module| module.artifact.sha256 == image_sha256)
        .map(|module| module.id.as_str())
        .collect::<BTreeSet<_>>();
    if module_ids.is_empty() {
        return Evidence::Unknown {
            reason: "captured modules do not contain the analyzed image identity".to_string(),
        };
    }
    let mappings = capsule
        .mappings
        .iter()
        .filter(|mapping| {
            mapping
                .module_id
                .as_deref()
                .is_some_and(|module_id| module_ids.contains(module_id))
        })
        .collect::<Vec<_>>();
    let events = capsule
        .events
        .iter()
        .filter(|event| event.kind == "instruction_step")
        .filter_map(|event| {
            let address = event.address?;
            mappings
                .iter()
                .any(|mapping| {
                    mapping.process_id == event.process_id
                        && mapping.start <= address
                        && address < mapping.end
                })
                .then_some((event, address))
        })
        .collect::<Vec<_>>();
    if events.is_empty() {
        return Evidence::Unknown {
            reason: "trace contains no instruction steps in the analyzed image".to_string(),
        };
    }
    let mut cache = BTreeMap::new();
    let mut exact_step_count = 0u64;
    let mut failures = Vec::new();
    for (event, runtime_instruction_va) in &events {
        let key = (event.process_id.clone(), *runtime_instruction_va);
        let resolution = cache
            .entry(key)
            .or_insert_with(|| {
                resolve_runtime_address(
                    capsule,
                    payloads,
                    image,
                    &event.process_id,
                    *runtime_instruction_va,
                )
            })
            .clone();
        if matches!(resolution, AddressResolution::Exact { .. }) {
            exact_step_count += 1;
        } else {
            failures.push(ObservedAddressCorrelationFailure {
                process_id: event.process_id.clone(),
                thread_id: event.thread_id.clone(),
                sequence: event.sequence,
                runtime_instruction_va: *runtime_instruction_va,
                resolution,
            });
        }
    }
    Evidence::Inferred {
        value: MainImageAddressCoverage {
            image_sha256: image_sha256.to_string(),
            observed_step_count: events.len() as u64,
            exact_step_count,
            failures,
        },
        source: "every traced PC in mappings bound to the exact analyzed image".to_string(),
    }
}

/// Correlate bounded instruction-step byte changes to exact LLIR stores.
pub fn analyze_instruction_trace(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
) -> InstructionTraceReport {
    let image_sha256 = hex::encode(Sha256::digest(image.bytes()));
    let main_image_address_coverage =
        relate_main_image_address_coverage(capsule, payloads, image, &image_sha256);
    let register_trace = parse_register_trace(capsule, payloads);
    let relations: Vec<InstructionTraceRelation> = capsule
        .events
        .iter()
        .filter(|event| event.kind == "instruction_step")
        .filter_map(|event| {
            event.fields.get("stack_changes_payload_id")?;
            let (changes, registers) = parse_step_evidence(event, payloads);
            let runtime_instruction_va = event.address.unwrap_or(0);
            let address_resolution = resolve_runtime_address(
                capsule,
                payloads,
                image,
                &event.process_id,
                runtime_instruction_va,
            );
            let operation_occurrence =
                make_store_occurrence(capsule, event, &changes, &address_resolution);
            let effective_address =
                derive_effective_address(&changes, &registers, &address_resolution);
            Some(InstructionTraceRelation {
                process_id: event.process_id.clone(),
                thread_id: event.thread_id.clone(),
                sequence: event.sequence,
                runtime_instruction_va,
                changes,
                registers,
                effective_address,
                address_resolution,
                operation_occurrence,
            })
        })
        .collect();
    let call_relations: Vec<InstructionCallRelation> = capsule
        .events
        .iter()
        .filter(|event| event.kind == "instruction_step")
        .filter(|event| {
            event.fields.get("control_transfer").map(String::as_str) == Some("direct_call")
        })
        .map(|event| {
            let runtime_instruction_va = event.address.unwrap_or(0);
            let registers = registers_for_step(&register_trace, event);
            let address_resolution = resolve_runtime_address(
                capsule,
                payloads,
                image,
                &event.process_id,
                runtime_instruction_va,
            );
            let (static_operation, static_target_va, callee) =
                resolve_call_semantics(&address_resolution);
            let return_occurrence = relate_call_return(
                capsule,
                &register_trace,
                event,
                runtime_instruction_va,
                &address_resolution,
            );
            let operation_occurrence = make_call_occurrence(
                capsule,
                payloads,
                event,
                &registers,
                static_operation,
                &callee,
                &return_occurrence,
            );
            InstructionCallRelation {
                process_id: event.process_id.clone(),
                thread_id: event.thread_id.clone(),
                sequence: event.sequence,
                runtime_instruction_va,
                registers,
                address_resolution,
                static_target_va,
                callee,
                return_occurrence,
                operation_occurrence,
            }
        })
        .collect();
    let executed_stores: Vec<ExecutedStoreRelation> = capsule
        .events
        .iter()
        .filter(|event| event.kind == "instruction_step")
        .filter_map(|event| {
            let runtime_instruction_va = event.address.unwrap_or(0);
            let registers = registers_for_step(&register_trace, event);
            let address_resolution = resolve_runtime_address(
                capsule,
                payloads,
                image,
                &event.process_id,
                runtime_instruction_va,
            );
            let static_operation = unique_store_operation(&address_resolution)?;
            let effective_address =
                derive_executed_effective_address(&registers, &address_resolution);
            let source_pointer = relate_executed_store_source_pointer(
                capsule,
                payloads,
                event,
                image,
                static_operation,
                &registers,
                &effective_address,
            );
            let object_transition = relate_executed_store_object_transition(
                capsule,
                payloads,
                event,
                static_operation,
                &effective_address,
            );
            let operation_occurrence = make_executed_store_occurrence(
                capsule,
                event,
                static_operation,
                &effective_address,
            );
            let allocation_prefix = relate_executed_store_allocation_prefix(
                capsule,
                image,
                &source_pointer,
                &operation_occurrence,
                &effective_address,
            );
            let allocation_tail = relate_executed_store_allocation_tail(
                capsule,
                payloads,
                event,
                image,
                &registers,
                &effective_address,
                &allocation_prefix,
                &object_transition,
            );
            Some(ExecutedStoreRelation {
                process_id: event.process_id.clone(),
                thread_id: event.thread_id.clone(),
                sequence: event.sequence,
                runtime_instruction_va,
                registers,
                effective_address,
                source_pointer,
                allocation_prefix,
                allocation_tail,
                object_transition,
                address_resolution,
                operation_occurrence,
            })
        })
        .collect();
    let executed_loads: Vec<ExecutedLoadRelation> = capsule
        .events
        .iter()
        .filter(|event| event.kind == "instruction_step")
        .filter_map(|event| {
            let runtime_instruction_va = event.address?;
            let registers = registers_for_step(&register_trace, event);
            let address_resolution = resolve_runtime_address(
                capsule,
                payloads,
                image,
                &event.process_id,
                runtime_instruction_va,
            );
            let static_operation = unique_load_operation(&address_resolution)?;
            let effective_address =
                derive_operation_effective_address(&registers, static_operation, "load");
            let operation_occurrence =
                make_executed_load_occurrence(capsule, event, static_operation, &effective_address);
            Some(ExecutedLoadRelation {
                process_id: event.process_id.clone(),
                thread_id: event.thread_id.clone(),
                sequence: event.sequence,
                runtime_instruction_va,
                registers,
                effective_address,
                address_resolution,
                operation_occurrence,
            })
        })
        .collect();
    let observed_blocks = relate_observed_blocks(capsule, payloads, image);
    let replay_seeds =
        relate_replay_seeds(capsule, payloads, image, &register_trace, &observed_blocks);
    let input_locations = locate_invocation_inputs(capsule, payloads);
    let input_value_flows = relate_input_value_flows(
        capsule,
        payloads,
        &relations,
        &executed_loads,
        &input_locations,
    );
    let control_transfers = relate_control_transfers(capsule, payloads, image);
    let observed_indirect_targets = relate_observed_indirect_targets(capsule, payloads, image);
    let solver_query_candidates = select_input_dependent_branches(
        capsule,
        payloads,
        image,
        &register_trace,
        &input_locations,
        &control_transfers,
    );
    let value_selections = relate_value_selections(capsule, payloads, image, &register_trace);
    let value_definitions = relate_value_definitions(capsule, payloads, image, &register_trace);
    let input_to_call_arguments = relate_input_to_call_arguments(
        capsule,
        payloads,
        image,
        &call_relations,
        &executed_stores,
        &control_transfers,
        &value_selections,
        &value_definitions,
    );
    InstructionTraceReport {
        schema: INSTRUCTION_TRACE_REPORT_SCHEMA.to_string(),
        capture_id: capsule.identity.capture_id.clone(),
        image_sha256,
        coverage: InstructionTraceCoverage {
            observed_steps: capsule
                .events
                .iter()
                .filter(|event| event.kind == "instruction_step")
                .count() as u64,
            steps_with_stack_changes: capsule
                .events
                .iter()
                .filter(|event| {
                    event.kind == "instruction_step"
                        && event.fields.contains_key("stack_changes_payload_id")
                })
                .count() as u64,
            compared_region: "fixed_bounded_stack_window".to_string(),
            broader_runtime_state: "partial".to_string(),
        },
        main_image_address_coverage,
        relations,
        executed_stores,
        executed_loads,
        observed_blocks,
        replay_seeds,
        call_relations,
        input_locations,
        control_transfers,
        observed_indirect_targets,
        value_selections,
        value_definitions,
        input_to_call_arguments,
        input_value_flows,
        solver_query_candidates,
    }
}

#[derive(Debug)]
struct PendingObservedBlock {
    process_id: String,
    thread_id: Option<String>,
    image_sha256: String,
    function_entry: u64,
    native_block_start: u64,
    native_block_end: u64,
    lift_profile: String,
    lifted_block_start: u64,
    steps: Vec<ObservedBlockStep>,
}

#[derive(Debug)]
struct ObservedBlockCandidate {
    process_id: String,
    thread_id: Option<String>,
    image_sha256: String,
    function_entry: u64,
    native_block_start: u64,
    native_block_end: u64,
    lift_profile: String,
    lifted_block_start: u64,
    step: ObservedBlockStep,
}

fn relate_observed_blocks(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
) -> Vec<ObservedBlockRelation> {
    let mut pending: BTreeMap<(String, Option<String>), PendingObservedBlock> = BTreeMap::new();
    let mut relations = Vec::new();
    for event in capsule
        .events
        .iter()
        .filter(|event| event.kind == "instruction_step")
    {
        let stream = (event.process_id.clone(), event.thread_id.clone());
        let candidate = observed_block_candidate(capsule, payloads, image, event);
        match candidate {
            Ok(candidate) => {
                let continues = pending.get(&stream).is_some_and(|current| {
                    current.image_sha256 == candidate.image_sha256
                        && current.function_entry == candidate.function_entry
                        && current.native_block_start == candidate.native_block_start
                        && current.native_block_end == candidate.native_block_end
                        && current.lift_profile == candidate.lift_profile
                        && current.lifted_block_start == candidate.lifted_block_start
                        && current.steps.last().is_some_and(|previous| {
                            previous.sequence.checked_add(1) == Some(candidate.step.sequence)
                                && previous.static_instruction_end
                                    == candidate.step.static_instruction_va
                        })
                });
                if continues {
                    if let Some(current) = pending.get_mut(&stream) {
                        current.steps.push(candidate.step);
                    }
                } else {
                    if let Some(current) = pending.remove(&stream) {
                        relations.push(finish_observed_block(capsule, current));
                    }
                    pending.insert(
                        stream,
                        PendingObservedBlock {
                            process_id: candidate.process_id,
                            thread_id: candidate.thread_id,
                            image_sha256: candidate.image_sha256,
                            function_entry: candidate.function_entry,
                            native_block_start: candidate.native_block_start,
                            native_block_end: candidate.native_block_end,
                            lift_profile: candidate.lift_profile,
                            lifted_block_start: candidate.lifted_block_start,
                            steps: vec![candidate.step],
                        },
                    );
                }
            }
            Err(reason) => {
                if let Some(current) = pending.remove(&stream) {
                    relations.push(finish_observed_block(capsule, current));
                }
                relations.push(ObservedBlockRelation {
                    process_id: event.process_id.clone(),
                    thread_id: event.thread_id.clone(),
                    first_sequence: event.sequence,
                    last_sequence: event.sequence,
                    relation: Evidence::Unknown { reason },
                });
            }
        }
    }
    relations.extend(
        pending
            .into_values()
            .map(|current| finish_observed_block(capsule, current)),
    );
    relations.sort_by(|left, right| {
        left.first_sequence
            .cmp(&right.first_sequence)
            .then_with(|| left.process_id.cmp(&right.process_id))
            .then_with(|| left.thread_id.cmp(&right.thread_id))
    });
    relations
}

fn observed_block_candidate(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    event: &super::capsule::EventRecord,
) -> Result<ObservedBlockCandidate, String> {
    let runtime_instruction_va = event.address.ok_or_else(|| {
        "observed block correlation requires a runtime instruction address".to_string()
    })?;
    let resolution = resolve_runtime_address(
        capsule,
        payloads,
        image,
        &event.process_id,
        runtime_instruction_va,
    );
    let AddressResolution::Exact { address } = resolution else {
        return Err(
            "observed block correlation requires exact static/runtime identity".to_string(),
        );
    };
    let function_entry = match &address.function {
        super::correlation::FunctionResolution::Exact { entry_va, .. }
        | super::correlation::FunctionResolution::Interior { entry_va, .. } => *entry_va,
        _ => {
            return Err(
                "observed block correlation requires one exact owning function".to_string(),
            );
        }
    };
    let StaticCodeResolution::Resolved {
        block_start,
        block_end,
        instruction_va,
        instruction_end,
        instruction_relation,
        operations,
        ..
    } = &address.code
    else {
        return Err("observed block correlation requires resolved static code".to_string());
    };
    if *instruction_relation != super::correlation::InstructionRelation::Exact {
        return Err("observed block correlation requires an exact instruction start".to_string());
    }
    let OperationResolution::Resolved { operations } = operations else {
        return Err("observed block correlation requires a resolved lifted block".to_string());
    };
    let Some(first_operation) = operations.first() else {
        return Err("observed block correlation requires a resolved lifted block".to_string());
    };
    if operations.iter().any(|operation| {
        operation.image_sha256 != address.image_sha256
            || operation.function_entry != function_entry
            || operation.machine_va != *instruction_va
            || operation.block_start != first_operation.block_start
            || operation.lift_profile != first_operation.lift_profile
    }) {
        return Err("observed instruction operations do not identify one lifted block".to_string());
    }
    Ok(ObservedBlockCandidate {
        process_id: event.process_id.clone(),
        thread_id: event.thread_id.clone(),
        image_sha256: address.image_sha256,
        function_entry,
        native_block_start: *block_start,
        native_block_end: *block_end,
        lift_profile: first_operation.lift_profile.clone(),
        lifted_block_start: first_operation.block_start,
        step: ObservedBlockStep {
            sequence: event.sequence,
            runtime_instruction_va,
            static_va: address.static_va,
            static_instruction_va: *instruction_va,
            static_instruction_end: *instruction_end,
            operation_indices: operations
                .iter()
                .map(|operation| operation.operation_index)
                .collect(),
            operation_kinds: operations
                .iter()
                .map(|operation| operation.kind.clone())
                .collect(),
        },
    })
}

fn finish_observed_block(
    capsule: &ProcessCapsule,
    pending: PendingObservedBlock,
) -> ObservedBlockRelation {
    let first_sequence = pending.steps.first().map(|step| step.sequence).unwrap_or(0);
    let last_sequence = pending.steps.last().map(|step| step.sequence).unwrap_or(0);
    let mut digest = Sha256::new();
    for component in [
        capsule.identity.capture_id.as_str(),
        pending.process_id.as_str(),
        pending.thread_id.as_deref().unwrap_or(""),
        &first_sequence.to_string(),
        &last_sequence.to_string(),
        pending.image_sha256.as_str(),
        &pending.function_entry.to_string(),
        &pending.native_block_start.to_string(),
        &pending.lifted_block_start.to_string(),
    ] {
        digest.update(component.as_bytes());
        digest.update([0]);
    }
    ObservedBlockRelation {
        process_id: pending.process_id.clone(),
        thread_id: pending.thread_id.clone(),
        first_sequence,
        last_sequence,
        relation: Evidence::Inferred {
            value: ObservedBlockOccurrence {
                id: format!("observed-block-{}", hex::encode(digest.finalize())),
                capture_id: capsule.identity.capture_id.clone(),
                process_id: pending.process_id,
                thread_id: pending.thread_id,
                first_sequence,
                last_sequence,
                image_sha256: pending.image_sha256,
                function_entry: pending.function_entry,
                native_block_start: pending.native_block_start,
                native_block_end: pending.native_block_end,
                lift_profile: pending.lift_profile,
                lifted_block_start: pending.lifted_block_start,
                steps: pending.steps,
            },
            source: "contiguous exact instruction occurrences joined to immutable native and LLIR blocks"
                .to_string(),
        },
    }
}

fn relate_replay_seeds(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    register_trace: &Result<BTreeMap<u64, BTreeMap<String, u64>>, String>,
    observed_blocks: &[ObservedBlockRelation],
) -> Vec<ReplaySeedRelation> {
    observed_blocks
        .iter()
        .filter(|relation| matches!(&relation.relation, Evidence::Inferred { .. }))
        .map(|relation| ReplaySeedRelation {
            process_id: relation.process_id.clone(),
            thread_id: relation.thread_id.clone(),
            sequence: relation.first_sequence,
            seed: make_replay_seed(capsule, payloads, image, register_trace, relation),
        })
        .collect()
}

fn make_replay_seed(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    register_trace: &Result<BTreeMap<u64, BTreeMap<String, u64>>, String>,
    block_relation: &ObservedBlockRelation,
) -> Evidence<ReplaySeed> {
    let Evidence::Inferred {
        value: observed_block,
        ..
    } = &block_relation.relation
    else {
        return Evidence::Unknown {
            reason: "replay seed requires an exact observed block occurrence".to_string(),
        };
    };
    if capsule.target.architecture != Arch::X86_64
        || capsule.target.endianness != Endianness::Little
    {
        return Evidence::Unknown {
            reason: "replay seed currently supports little-endian x86-64 only".to_string(),
        };
    }
    let Some(event) = capsule.events.iter().find(|event| {
        event.process_id == block_relation.process_id
            && event.thread_id == block_relation.thread_id
            && event.sequence == block_relation.first_sequence
            && event.kind == "instruction_step"
    }) else {
        return Evidence::Unknown {
            reason: "replay seed has no matching instruction event".to_string(),
        };
    };
    let registers = registers_for_step(register_trace, event);
    let Evidence::Observed {
        value: observed_registers,
        ..
    } = registers
    else {
        return Evidence::Unknown {
            reason: "replay seed requires hash-verified pre-instruction registers".to_string(),
        };
    };
    let Some(snapshot_sequence) = capsule
        .object_snapshots
        .iter()
        .filter(|snapshot| {
            snapshot.process_id == block_relation.process_id
                && snapshot.point.thread_id == block_relation.thread_id
                && snapshot.point.sequence < block_relation.first_sequence
        })
        .map(|snapshot| snapshot.point.sequence)
        .max()
    else {
        return Evidence::Unknown {
            reason: "replay seed requires a preceding memory snapshot".to_string(),
        };
    };
    let snapshots: Vec<_> = capsule
        .object_snapshots
        .iter()
        .filter(|snapshot| {
            snapshot.process_id == block_relation.process_id
                && snapshot.point.thread_id == block_relation.thread_id
                && snapshot.point.sequence == snapshot_sequence
        })
        .collect();
    if snapshots.is_empty() {
        return Evidence::Unknown {
            reason: "replay seed requires a captured memory snapshot".to_string(),
        };
    }
    if !capsule.completeness.iter().any(|record| {
        record.evidence == "instruction_step_change_payloads"
            && record.status == super::capsule::CompletenessStatus::Complete
            && record.requested
            && record.expected == Some(record.obtained)
    }) {
        return Evidence::Unknown {
            reason: "replay seed requires a complete instruction memory-change stream".to_string(),
        };
    }

    let mut machine = Machine::new_with_arch(Concrete, RegArch::X86_64);
    let mut seeded_registers = BTreeMap::new();
    for parent in crate::ir::regview::gp_views(RegArch::X86_64)
        .filter(|view| view.is_parent())
        .map(|view| view.parent)
    {
        let Some(value) = observed_registers.get(parent).copied() else {
            return Evidence::Unknown {
                reason: format!("replay seed is missing canonical register {parent}"),
            };
        };
        let register = VReg::Phys(parent.to_string());
        let concrete = machine.dom.constant(Width::W64, u128::from(value));
        machine.regs.write(&mut machine.dom, &register, concrete);
        seeded_registers.insert(parent.to_string(), value);
    }
    if let Some(eflags) = observed_registers.get("eflags").copied() {
        for (name, flag, bit) in [
            ("cf", Flag::C, 0u32),
            ("pf", Flag::P, 2),
            ("af", Flag::A, 4),
            ("zf", Flag::Z, 6),
            ("sf", Flag::S, 7),
            ("df", Flag::D, 10),
            ("of", Flag::O, 11),
        ] {
            let value = (eflags >> bit) & 1;
            let concrete = machine.dom.constant(Width::W1, u128::from(value));
            machine
                .regs
                .write(&mut machine.dom, &VReg::Flag(flag), concrete);
            seeded_registers.insert(format!("flag.{name}"), value);
        }
    }
    let Some(pc) = seeded_registers.get("rip").copied() else {
        return Evidence::Unknown {
            reason: "replay seed is missing the program counter".to_string(),
        };
    };
    if pc != observed_block.steps[0].runtime_instruction_va {
        return Evidence::Unknown {
            reason: "replay seed program counter disagrees with the observed block".to_string(),
        };
    }
    machine.pc = pc;

    let mut memory_ranges = Vec::new();
    let mut seeded_ranges: Vec<(u64, u64)> = Vec::new();
    let mut verification_ranges = Vec::new();
    let mut verified_memory_byte_count = 0u64;
    let mut applied_memory_change_count = 0u64;
    for snapshot in snapshots {
        let Some(object) = capsule.runtime_objects.iter().find(|object| {
            object.id == snapshot.object_id && object.process_id == snapshot.process_id
        }) else {
            return Evidence::Unknown {
                reason: format!("replay snapshot {} has no runtime object", snapshot.id),
            };
        };
        let Some(start) = object.start.checked_add(snapshot.object_offset) else {
            return Evidence::Unknown {
                reason: format!("replay snapshot {} address overflowed", snapshot.id),
            };
        };
        let Some(end) = start.checked_add(snapshot.byte_len) else {
            return Evidence::Unknown {
                reason: format!("replay snapshot {} range overflowed", snapshot.id),
            };
        };
        if seeded_ranges
            .iter()
            .any(|(other_start, other_end)| start < *other_end && *other_start < end)
        {
            return Evidence::Unknown {
                reason: "replay seed memory snapshots overlap".to_string(),
            };
        }
        let PageContent::Captured { payload } = &snapshot.content else {
            return Evidence::Unknown {
                reason: format!("replay snapshot {} bytes were omitted", snapshot.id),
            };
        };
        let Some(snapshot_bytes) = payloads.get(&payload.id) else {
            return Evidence::Unknown {
                reason: format!("replay snapshot payload {} is unavailable", payload.id),
            };
        };
        if snapshot_bytes.len() as u64 != snapshot.byte_len
            || snapshot_bytes.len() as u64 != payload.byte_len
            || hex::encode(Sha256::digest(snapshot_bytes)) != payload.sha256
        {
            return Evidence::Unknown {
                reason: format!(
                    "replay snapshot payload {} disagrees with its identity",
                    payload.id
                ),
            };
        }
        let mut bytes = snapshot_bytes.clone();
        for change_event in capsule.events.iter().filter(|candidate| {
            candidate.process_id == block_relation.process_id
                && candidate.thread_id == block_relation.thread_id
                && candidate.kind == "instruction_step"
                && snapshot_sequence < candidate.sequence
                && candidate.sequence < block_relation.first_sequence
                && candidate.fields.contains_key("stack_changes_payload_id")
        }) {
            let (changes, _) = parse_step_evidence(change_event, payloads);
            let Evidence::Observed { value: changes, .. } = changes else {
                return Evidence::Unknown {
                    reason: format!(
                        "replay seed cannot validate memory changes at sequence {}",
                        change_event.sequence
                    ),
                };
            };
            for change in changes {
                if change.end <= start || end <= change.start {
                    continue;
                }
                if change.start < start || end < change.end {
                    return Evidence::Unknown {
                        reason: "replay memory change crosses a seeded-range boundary".to_string(),
                    };
                }
                let offset = (change.start - start) as usize;
                let before = match hex::decode(&change.before_hex) {
                    Ok(value) => value,
                    Err(_) => {
                        return Evidence::Unknown {
                            reason: "replay memory change has malformed before bytes".to_string(),
                        };
                    }
                };
                let after = match hex::decode(&change.after_hex) {
                    Ok(value) => value,
                    Err(_) => {
                        return Evidence::Unknown {
                            reason: "replay memory change has malformed after bytes".to_string(),
                        };
                    }
                };
                if bytes.get(offset..offset + before.len()) != Some(before.as_slice()) {
                    return Evidence::Unknown {
                        reason: format!(
                            "replay memory change before bytes disagree at sequence {}",
                            change_event.sequence
                        ),
                    };
                }
                bytes[offset..offset + after.len()].copy_from_slice(&after);
                applied_memory_change_count += 1;
            }
        }
        for (offset, byte) in bytes.iter().copied().enumerate() {
            let address = start + offset as u64;
            let value = machine.dom.constant(Width::W8, u128::from(byte));
            machine
                .mem
                .store(&mut machine.dom, address, &value, 1, Endian::Little);
        }
        seeded_ranges.push((start, end));
        verification_ranges.push((snapshot.id.clone(), start, bytes.clone()));
        verified_memory_byte_count += snapshot.byte_len;
        memory_ranges.push(ReplaySeedMemoryRange {
            snapshot_id: snapshot.id.clone(),
            runtime_object_id: snapshot.object_id.clone(),
            start,
            byte_len: snapshot.byte_len,
            source_snapshot_sha256: payload.sha256.clone(),
            seeded_sha256: hex::encode(Sha256::digest(&bytes)),
        });
    }
    for (name, expected) in &seeded_registers {
        let register = match name.strip_prefix("flag.") {
            Some("cf") => VReg::Flag(Flag::C),
            Some("pf") => VReg::Flag(Flag::P),
            Some("af") => VReg::Flag(Flag::A),
            Some("zf") => VReg::Flag(Flag::Z),
            Some("sf") => VReg::Flag(Flag::S),
            Some("df") => VReg::Flag(Flag::D),
            Some("of") => VReg::Flag(Flag::O),
            Some(_) => continue,
            None => VReg::Phys(name.clone()),
        };
        if machine.regs.read(&mut machine.dom, &register) != u128::from(*expected) {
            return Evidence::Unknown {
                reason: format!("replay machine register {name} failed seed verification"),
            };
        }
    }
    for (snapshot_id, start, bytes) in &verification_ranges {
        for (offset, expected) in bytes.iter().copied().enumerate() {
            if machine
                .mem
                .load(&mut machine.dom, *start + offset as u64, 1, Endian::Little)
                != u128::from(expected)
            {
                return Evidence::Unknown {
                    reason: format!(
                        "replay machine memory range {} failed seed verification",
                        snapshot_id
                    ),
                };
            }
        }
    }
    let mut first_divergence = None;
    let bounded_replay = replay_observed_block(
        capsule,
        payloads,
        image,
        register_trace,
        observed_block,
        &mut machine,
        &seeded_ranges,
        &verification_ranges,
        &mut first_divergence,
    );

    let mut digest = Sha256::new();
    for component in [
        capsule.identity.capture_id.as_str(),
        block_relation.process_id.as_str(),
        block_relation.thread_id.as_deref().unwrap_or(""),
        &block_relation.first_sequence.to_string(),
        observed_block.id.as_str(),
    ] {
        digest.update(component.as_bytes());
        digest.update([0]);
    }
    Evidence::Inferred {
        value: ReplaySeed {
            id: format!("replay-seed-{}", hex::encode(digest.finalize())),
            capture_id: capsule.identity.capture_id.clone(),
            process_id: block_relation.process_id.clone(),
            thread_id: block_relation.thread_id.clone(),
            sequence: block_relation.first_sequence,
            observed_block_id: observed_block.id.clone(),
            pc,
            architecture: "x86_64".to_string(),
            verified_register_count: seeded_registers.len() as u64,
            registers: seeded_registers,
            memory_ranges,
            memory_reconstruction_from_sequence: snapshot_sequence,
            memory_reconstruction_through_sequence: block_relation.first_sequence - 1,
            applied_memory_change_count,
            verified_memory_byte_count,
            unseeded_memory: "unknown; replay must stop before reading outside seeded ranges"
                .to_string(),
            bounded_replay,
            first_divergence,
        },
        source: "hash-verified occurrence registers and time-adjacent runtime object snapshots seeded into exec::Machine<Concrete>"
            .to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn replay_observed_block(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    register_trace: &Result<BTreeMap<u64, BTreeMap<String, u64>>, String>,
    observed: &ObservedBlockOccurrence,
    machine: &mut Machine<Concrete>,
    seeded_ranges: &[(u64, u64)],
    seeded_bytes: &[(String, u64, Vec<u8>)],
    first_divergence: &mut Option<ReplayDivergence>,
) -> Evidence<BoundedBlockReplay> {
    let Some(function) =
        discover_function_image_at(image, &Budgets::default(), observed.function_entry)
    else {
        return Evidence::Unknown {
            reason: "bounded replay could not rediscover the observed function".to_string(),
        };
    };
    let lifted = match lift_function_from_image(image, &function) {
        Ok(lifted) => lifted,
        Err(error) => {
            return Evidence::Unknown {
                reason: format!("bounded replay could not lift the observed function: {error}"),
            };
        }
    };
    let Some(block) = lifted
        .blocks
        .iter()
        .find(|block| block.start_va == observed.lifted_block_start)
    else {
        return Evidence::Unknown {
            reason: "bounded replay could not find the observed LLIR block".to_string(),
        };
    };
    let Some(successor_event) = capsule.events.iter().find(|event| {
        event.process_id == observed.process_id
            && event.thread_id == observed.thread_id
            && event.kind == "instruction_step"
            && event.sequence == observed.last_sequence.saturating_add(1)
    }) else {
        return Evidence::Unknown {
            reason: "bounded replay requires the observed successor register state".to_string(),
        };
    };
    let Some(successor_runtime_va) = successor_event.address else {
        return Evidence::Unknown {
            reason: "bounded replay successor has no runtime instruction address".to_string(),
        };
    };
    let successor_registers = registers_for_step(register_trace, successor_event);
    let Evidence::Observed {
        value: successor_registers,
        ..
    } = successor_registers
    else {
        return Evidence::Unknown {
            reason: "bounded replay successor registers are unavailable".to_string(),
        };
    };
    let successor_resolution = resolve_runtime_address(
        capsule,
        payloads,
        image,
        &observed.process_id,
        successor_runtime_va,
    );
    let successor_static_va = match successor_resolution {
        AddressResolution::Exact { address } => Some(address.static_va),
        _ => None,
    };

    let mut executed_operation_count = 0u64;
    let mut defined_registers = BTreeSet::new();
    let mut register_definitions = BTreeMap::new();
    let mut last_operation = None;
    let mut terminal_flow = Flow::Next;
    for (step_position, step) in observed.steps.iter().enumerate() {
        let operations: Vec<_> = step
            .operation_indices
            .iter()
            .map(|index| {
                block
                    .instrs
                    .get(*index)
                    .filter(|instruction| instruction.va == step.static_instruction_va)
                    .map(|instruction| (*index, &instruction.op))
            })
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();
        if operations.len() != step.operation_indices.len() || operations.is_empty() {
            return Evidence::Unknown {
                reason: format!(
                    "bounded replay LLIR operations disagree at sequence {}",
                    step.sequence
                ),
            };
        }
        for (operation_position, (operation_index, operation)) in operations.iter().enumerate() {
            let attribution = ReplayOperationAttribution {
                event_sequence: step.sequence,
                static_instruction_va: step.static_instruction_va,
                llir_block_start: observed.lifted_block_start,
                operation_index: *operation_index,
                operation_kind: step.operation_kinds[operation_position].clone(),
            };
            last_operation = Some(attribution.clone());
            if let Some(memory) = operation_memory_operand(operation) {
                let Some((address, byte_len)) = replay_effective_address(machine, memory) else {
                    note_replay_divergence(
                        first_divergence,
                        ReplayDivergenceKind::MissingEnvironment,
                        format!("could not resolve memory at sequence {}", step.sequence),
                        Some(attribution.clone()),
                        Some("memory_address".to_string()),
                        None,
                        None,
                    );
                    return Evidence::Unknown {
                        reason: format!(
                            "bounded replay could not resolve memory at sequence {}",
                            step.sequence
                        ),
                    };
                };
                let Some(end) = address.checked_add(u64::from(byte_len)) else {
                    return Evidence::Unknown {
                        reason: "bounded replay memory range overflowed".to_string(),
                    };
                };
                if !seeded_ranges
                    .iter()
                    .any(|(start, range_end)| *start <= address && end <= *range_end)
                {
                    note_replay_divergence(
                        first_divergence,
                        ReplayDivergenceKind::MissingEnvironment,
                        "memory access is outside seeded coverage".to_string(),
                        Some(attribution.clone()),
                        Some("memory_coverage".to_string()),
                        Some(format!("{address:#x}..{end:#x}")),
                        None,
                    );
                    return Evidence::Unknown {
                        reason: format!(
                            "bounded replay memory access {address:#x}..{end:#x} is outside seeded coverage"
                        ),
                    };
                }
            } else if matches!(
                operation,
                Op::Intrinsic {
                    reads_mem: true,
                    ..
                } | Op::Intrinsic {
                    writes_mem: true,
                    ..
                }
            ) {
                note_replay_divergence(
                    first_divergence,
                    ReplayDivergenceKind::UnsupportedOperation,
                    "opaque memory intrinsic has no bounded replay model".to_string(),
                    Some(attribution.clone()),
                    None,
                    None,
                    None,
                );
                return Evidence::Unknown {
                    reason: format!(
                        "bounded replay reached an opaque memory intrinsic at sequence {}",
                        step.sequence
                    ),
                };
            }
            if let Some(definition) = crate::ir::use_def::def_ref(operation) {
                match definition {
                    VReg::Phys(name) => {
                        if let Some(parent) = crate::ir::regview::parent_of(RegArch::X86_64, name) {
                            defined_registers.insert(parent.to_string());
                            register_definitions.insert(parent.to_string(), attribution.clone());
                        }
                    }
                    VReg::Flag(flag) | VReg::FlagValue { flag, .. } => {
                        defined_registers.insert(format!("flag.{flag:?}").to_ascii_lowercase());
                        register_definitions.insert(
                            format!("flag.{flag:?}").to_ascii_lowercase(),
                            attribution.clone(),
                        );
                    }
                    VReg::Temp(_) => {}
                }
            }
            terminal_flow = machine.step(operation);
            executed_operation_count += 1;
            if let Flow::Halt(halt) = &terminal_flow {
                note_replay_divergence(
                    first_divergence,
                    ReplayDivergenceKind::UnsupportedOperation,
                    format!("execution halted on unsupported semantics: {halt:?}"),
                    Some(attribution),
                    None,
                    None,
                    None,
                );
                return Evidence::Unknown {
                    reason: format!("bounded replay halted on unsupported semantics: {halt:?}"),
                };
            }
            let is_final_operation = step_position + 1 == observed.steps.len()
                && operation_position + 1 == operations.len();
            if !matches!(terminal_flow, Flow::Next) && !is_final_operation {
                note_replay_divergence(
                    first_divergence,
                    ReplayDivergenceKind::ControlFlowMismatch,
                    "control flow terminated before the observed block ended".to_string(),
                    Some(attribution),
                    Some("control_flow".to_string()),
                    Some(format!("{terminal_flow:?}")),
                    Some("next".to_string()),
                );
                return Evidence::Unknown {
                    reason: format!(
                        "bounded replay produced control flow before the observed block ended at sequence {}",
                        step.sequence
                    ),
                };
            }
        }
    }
    if matches!(terminal_flow, Flow::Call(_)) {
        let Some(last_step) = observed.steps.last() else {
            return Evidence::Unknown {
                reason: "bounded replay call has no observed instruction".to_string(),
            };
        };
        let Some(call_offset) = image.va_to_code_file_offset(last_step.static_instruction_va)
        else {
            return Evidence::Unknown {
                reason: "bounded replay call has no static instruction bytes".to_string(),
            };
        };
        if image.bytes().get(call_offset) != Some(&0xe8) {
            return Evidence::Unknown {
                reason: "bounded replay currently supports x86 direct near call opcode 0xe8 only"
                    .to_string(),
            };
        }
        let stack_pointer = machine
            .regs
            .read(&mut machine.dom, &VReg::Phys("rsp".to_string()))
            as u64;
        let Some(pushed_stack_pointer) = stack_pointer.checked_sub(8) else {
            return Evidence::Unknown {
                reason: "bounded replay call stack range underflowed".to_string(),
            };
        };
        if !seeded_ranges
            .iter()
            .any(|(start, end)| *start <= pushed_stack_pointer && stack_pointer <= *end)
        {
            return Evidence::Unknown {
                reason: format!(
                    "bounded replay call stack write {pushed_stack_pointer:#x}..{stack_pointer:#x} is outside seeded coverage"
                ),
            };
        }
        let Some(instruction_len) = last_step
            .static_instruction_end
            .checked_sub(last_step.static_instruction_va)
            .filter(|len| *len > 0)
        else {
            return Evidence::Unknown {
                reason: "bounded replay call has an invalid instruction length".to_string(),
            };
        };
        let Some(runtime_return_va) = last_step
            .runtime_instruction_va
            .checked_add(instruction_len)
        else {
            return Evidence::Unknown {
                reason: "bounded replay call return address overflowed".to_string(),
            };
        };
        let return_value = machine
            .dom
            .constant(Width::W64, u128::from(runtime_return_va));
        machine.mem.store(
            &mut machine.dom,
            pushed_stack_pointer,
            &return_value,
            8,
            Endian::Little,
        );
        let pushed_rsp = machine
            .dom
            .constant(Width::W64, u128::from(pushed_stack_pointer));
        machine
            .regs
            .write(&mut machine.dom, &VReg::Phys("rsp".to_string()), pushed_rsp);
        defined_registers.insert("rsp".to_string());
        if let Some(attribution) = &last_operation {
            register_definitions.insert("rsp".to_string(), attribution.clone());
        }
    }
    let replay_return_target = if matches!(terminal_flow, Flow::Return) {
        let Some(last_step) = observed.steps.last() else {
            return Evidence::Unknown {
                reason: "bounded replay return has no observed instruction".to_string(),
            };
        };
        let Some(return_offset) = image.va_to_code_file_offset(last_step.static_instruction_va)
        else {
            return Evidence::Unknown {
                reason: "bounded replay return has no static instruction bytes".to_string(),
            };
        };
        if image.bytes().get(return_offset) != Some(&0xc3) {
            return Evidence::Unknown {
                reason: "bounded replay currently supports only near return opcode 0xc3"
                    .to_string(),
            };
        }
        let stack_pointer = machine
            .regs
            .read(&mut machine.dom, &VReg::Phys("rsp".to_string()))
            as u64;
        let Some(stack_end) = stack_pointer.checked_add(8) else {
            return Evidence::Unknown {
                reason: "bounded replay return stack range overflowed".to_string(),
            };
        };
        if !seeded_ranges
            .iter()
            .any(|(start, end)| *start <= stack_pointer && stack_end <= *end)
        {
            return Evidence::Unknown {
                reason: format!(
                    "bounded replay return address {stack_pointer:#x}..{stack_end:#x} is outside seeded coverage"
                ),
            };
        }
        let target = machine
            .mem
            .load(&mut machine.dom, stack_pointer, 8, Endian::Little) as u64;
        let advanced = machine.dom.constant(Width::W64, u128::from(stack_end));
        machine
            .regs
            .write(&mut machine.dom, &VReg::Phys("rsp".to_string()), advanced);
        defined_registers.insert("rsp".to_string());
        if let Some(attribution) = &last_operation {
            register_definitions.insert("rsp".to_string(), attribution.clone());
        }
        Some(target)
    } else {
        None
    };
    let flow_matches = match terminal_flow {
        Flow::Next => {
            successor_static_va
                == observed
                    .steps
                    .last()
                    .map(|step| step.static_instruction_end)
        }
        Flow::Jump(target) => successor_static_va == Some(target),
        Flow::Branch { target, taken } => {
            successor_static_va == Some(if taken { target } else { block.end_va })
        }
        Flow::Call(target) => target.is_some() && successor_static_va == target,
        Flow::Return => replay_return_target == Some(successor_runtime_va),
        Flow::Halt(ref halt) => {
            note_replay_divergence(
                first_divergence,
                ReplayDivergenceKind::UnsupportedOperation,
                format!("execution halted on unsupported semantics: {halt:?}"),
                last_operation.clone(),
                None,
                None,
                None,
            );
            return Evidence::Unknown {
                reason: format!("bounded replay halted on unsupported semantics: {halt:?}"),
            };
        }
    };
    if !flow_matches {
        note_replay_divergence(
            first_divergence,
            ReplayDivergenceKind::ControlFlowMismatch,
            "replayed control flow disagrees with the observed successor".to_string(),
            last_operation.clone(),
            Some("control_flow".to_string()),
            Some(format!("{terminal_flow:?}")),
            Some(format!("runtime:{successor_runtime_va:#x}")),
        );
        return Evidence::Unknown {
            reason: format!(
                "bounded replay control flow {:?} disagrees with observed successor: runtime={successor_runtime_va:#x}, static={successor_static_va:?}, block_end={:#x}, last_instruction_end={:?}",
                terminal_flow,
                block.end_va,
                observed
                    .steps
                    .last()
                    .map(|step| format!("{:#x}", step.static_instruction_end))
            ),
        };
    }

    let mut compared_registers = BTreeMap::new();
    let mut address_normalized_registers = BTreeMap::new();
    let mut uncompared_registers = BTreeMap::new();
    for name in defined_registers {
        let (register, expected) = if let Some(flag_name) = name.strip_prefix("flag.") {
            let Some((flag, bit)) = replay_flag(flag_name) else {
                continue;
            };
            let Some(eflags) = successor_registers.get("eflags").copied() else {
                return Evidence::Unknown {
                    reason: "bounded replay successor has no architectural flags".to_string(),
                };
            };
            (VReg::Flag(flag), (eflags >> bit) & 1)
        } else {
            let Some(expected) = successor_registers.get(&name).copied() else {
                return Evidence::Unknown {
                    reason: format!("bounded replay successor is missing register {name}"),
                };
            };
            (VReg::Phys(name.clone()), expected)
        };
        if let Some(reason) = machine.undefined_value_reason(&Value::Reg(register.clone())) {
            uncompared_registers.insert(name, reason);
            continue;
        }
        let actual = machine.regs.read(&mut machine.dom, &register) as u64;
        if actual != expected {
            match resolve_runtime_address(capsule, payloads, image, &observed.process_id, expected)
            {
                AddressResolution::Exact { address } if address.static_va == actual => {
                    address_normalized_registers.insert(
                        name.clone(),
                        AddressNormalizedRegisterComparison {
                            replay_static_va: actual,
                            observed_runtime_va: expected,
                            mapping_id: address.runtime.mapping_id,
                        },
                    );
                }
                _ => {
                    note_replay_divergence(
                        first_divergence,
                        ReplayDivergenceKind::RegisterMismatch,
                        format!("replayed register {name} disagrees with observation"),
                        register_definitions.get(&name).cloned(),
                        Some(format!("register:{name}")),
                        Some(format!("{actual:#x}")),
                        Some(format!("{expected:#x}")),
                    );
                    return Evidence::Unknown {
                        reason: format!(
                            "bounded replay register {name} diverged: replayed={actual:#x} observed={expected:#x}"
                        ),
                    };
                }
            }
        }
        compared_registers.insert(name, expected);
    }

    let mut expected_ranges = seeded_bytes.to_vec();
    for event in capsule.events.iter().filter(|event| {
        event.process_id == observed.process_id
            && event.thread_id == observed.thread_id
            && event.kind == "instruction_step"
            && observed.first_sequence <= event.sequence
            && event.sequence <= observed.last_sequence
            && event.fields.contains_key("stack_changes_payload_id")
    }) {
        let (changes, _) = parse_step_evidence(event, payloads);
        let Evidence::Observed { value: changes, .. } = changes else {
            return Evidence::Unknown {
                reason: format!(
                    "bounded replay cannot validate observed memory at sequence {}",
                    event.sequence
                ),
            };
        };
        for change in changes {
            for (_, start, bytes) in &mut expected_ranges {
                let end = *start + bytes.len() as u64;
                if change.start < *start || end < change.end {
                    continue;
                }
                let offset = (change.start - *start) as usize;
                let before = match hex::decode(&change.before_hex) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Evidence::Unknown {
                            reason: "bounded replay observed before bytes are malformed"
                                .to_string(),
                        };
                    }
                };
                let after = match hex::decode(&change.after_hex) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Evidence::Unknown {
                            reason: "bounded replay observed after bytes are malformed".to_string(),
                        };
                    }
                };
                if bytes.get(offset..offset + before.len()) != Some(before.as_slice()) {
                    return Evidence::Unknown {
                        reason: format!(
                            "bounded replay observed memory chain disagrees at sequence {}",
                            event.sequence
                        ),
                    };
                }
                bytes[offset..offset + after.len()].copy_from_slice(&after);
            }
        }
    }
    let mut compared_memory_byte_count = 0u64;
    let mut address_normalized_memory = Vec::new();
    for (_, start, expected) in expected_ranges {
        let mut offset = 0usize;
        while offset < expected.len() {
            if offset + 8 <= expected.len() {
                let actual_pointer =
                    machine
                        .mem
                        .load(&mut machine.dom, start + offset as u64, 8, Endian::Little)
                        as u64;
                let observed_pointer = u64::from_le_bytes(
                    expected[offset..offset + 8]
                        .try_into()
                        .expect("eight-byte slice"),
                );
                if actual_pointer != observed_pointer {
                    if let AddressResolution::Exact { address } = resolve_runtime_address(
                        capsule,
                        payloads,
                        image,
                        &observed.process_id,
                        observed_pointer,
                    ) {
                        if address.static_va == actual_pointer {
                            address_normalized_memory.push(AddressNormalizedMemoryComparison {
                                storage_runtime_va: start + offset as u64,
                                replay_static_va: actual_pointer,
                                observed_runtime_va: observed_pointer,
                                mapping_id: address.runtime.mapping_id,
                            });
                            compared_memory_byte_count += 8;
                            offset += 8;
                            continue;
                        }
                    }
                }
            }
            let expected_byte = expected[offset];
            let actual =
                machine
                    .mem
                    .load(&mut machine.dom, start + offset as u64, 1, Endian::Little)
                    as u8;
            if actual != expected_byte {
                let remaining = (expected.len() - offset).min(8);
                let replay_window: Vec<_> = (0..remaining)
                    .map(|delta| {
                        machine.mem.load(
                            &mut machine.dom,
                            start + (offset + delta) as u64,
                            1,
                            Endian::Little,
                        ) as u8
                    })
                    .collect();
                note_replay_divergence(
                    first_divergence,
                    ReplayDivergenceKind::MemoryMismatch,
                    "replayed memory byte disagrees with observation".to_string(),
                    last_operation.clone(),
                    Some(format!("memory:{:#x}", start + offset as u64)),
                    Some(format!("{actual:#04x}")),
                    Some(format!("{expected_byte:#04x}")),
                );
                return Evidence::Unknown {
                    reason: format!(
                        "bounded replay memory diverged at {:#x}: replayed={actual:#04x} observed={expected_byte:#04x}, replay_window={}, observed_window={}",
                        start + offset as u64,
                        hex::encode(replay_window),
                        hex::encode(&expected[offset..offset + remaining]),
                    ),
                };
            }
            compared_memory_byte_count += 1;
            offset += 1;
        }
    }
    Evidence::Inferred {
        value: BoundedBlockReplay {
            observed_block_id: observed.id.clone(),
            first_sequence: observed.first_sequence,
            last_sequence: observed.last_sequence,
            executed_operation_count,
            terminal_flow: replay_flow_name(&terminal_flow),
            observed_successor_sequence: successor_event.sequence,
            observed_successor_runtime_va: successor_runtime_va,
            compared_registers,
            address_normalized_registers,
            uncompared_registers,
            address_normalized_memory,
            compared_memory_byte_count,
            terminal_state: "matches_observation".to_string(),
        },
        source: "exec::Machine<Concrete> replay compared with the next observed register state and ordered memory deltas"
            .to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn note_replay_divergence(
    slot: &mut Option<ReplayDivergence>,
    kind: ReplayDivergenceKind,
    reason: String,
    operation: Option<ReplayOperationAttribution>,
    state_component: Option<String>,
    replayed_value: Option<String>,
    observed_value: Option<String>,
) {
    if slot.is_none() {
        *slot = Some(ReplayDivergence {
            kind,
            reason,
            operation,
            state_component,
            replayed_value,
            observed_value,
        });
    }
}

fn operation_memory_operand(operation: &Op) -> Option<&MemOp> {
    match operation {
        Op::Load { addr, .. }
        | Op::CondLoad { addr, .. }
        | Op::Store { addr, .. }
        | Op::CondStore { addr, .. } => Some(addr),
        _ => None,
    }
}

fn replay_effective_address(machine: &mut Machine<Concrete>, memory: &MemOp) -> Option<(u64, u8)> {
    let mut address = memory.disp as u64;
    if let Some(base) = &memory.base {
        address = address.wrapping_add(machine.regs.read(&mut machine.dom, base) as u64);
    }
    if let Some(index) = &memory.index {
        address = address.wrapping_add(
            (machine.regs.read(&mut machine.dom, index) as u64)
                .wrapping_mul(u64::from(memory.scale.max(1))),
        );
    }
    Some((address, memory.size))
}

fn replay_flag(name: &str) -> Option<(Flag, u32)> {
    Some(match name {
        "c" => (Flag::C, 0),
        "p" => (Flag::P, 2),
        "a" => (Flag::A, 4),
        "z" => (Flag::Z, 6),
        "s" => (Flag::S, 7),
        "d" => (Flag::D, 10),
        "o" => (Flag::O, 11),
        _ => return None,
    })
}

fn replay_flow_name(flow: &Flow) -> String {
    match flow {
        Flow::Next => "fallthrough",
        Flow::Jump(_) => "jump",
        Flow::Branch { taken: true, .. } => "branch_taken",
        Flow::Branch { taken: false, .. } => "branch_fallthrough",
        Flow::Call(_) => "call",
        Flow::Return => "return",
        Flow::Halt(_) => "halt",
    }
    .to_string()
}

fn relate_input_value_flows(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    stores: &[InstructionTraceRelation],
    loads: &[ExecutedLoadRelation],
    locations: &[RuntimeInputLocationRelation],
) -> Vec<InputValueFlowRelation> {
    locations
        .iter()
        .map(|located| {
            let relation = match evidence_value(&located.location) {
                Some(location) => input_value_flow(capsule, payloads, stores, loads, location),
                None => Evidence::Unknown {
                    reason: "input byte flow requires one exact runtime input location".to_string(),
                },
            };
            InputValueFlowRelation {
                source_id: located.source_id.clone(),
                source_name: located.source_name.clone(),
                relation,
            }
        })
        .collect()
}

fn input_value_flow(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    stores: &[InstructionTraceRelation],
    loads: &[ExecutedLoadRelation],
    source: &RuntimeInputLocation,
) -> Evidence<InputValueFlow> {
    let Ok(memory) = RuntimeMemoryView::new(capsule, payloads, &source.process_id) else {
        return Evidence::Unknown {
            reason: "input byte flow has no valid sparse runtime memory view".to_string(),
        };
    };
    let mut steps: Vec<InputValueFlowStep> = Vec::new();
    let mut memory_provenance = (0..source.byte_len)
        .filter_map(|offset| {
            source.runtime_address.checked_add(offset).map(|address| {
                (
                    address,
                    InputByteSpan {
                        source_id: source.source_id.clone(),
                        source_offset: offset,
                        byte_len: 1,
                    },
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    for store in stores {
        let (Some(occurrence), Some(changes), Some(registers)) = (
            evidence_value(&store.operation_occurrence),
            evidence_value(&store.changes),
            evidence_value(&store.registers),
        ) else {
            continue;
        };
        let [change] = changes.as_slice() else {
            continue;
        };
        let Some(write_len) = change.end.checked_sub(change.start) else {
            continue;
        };
        let Ok(write_len_u8) = u8::try_from(write_len) else {
            continue;
        };
        let operation = &occurrence.static_operation;
        let derived = operation.stored_value.as_ref().and_then(|expression| {
            expression_input_spans(expression, registers, &memory, &memory_provenance)
        });
        for address in change.start..change.end {
            memory_provenance.remove(&address);
        }
        let Some((source_address, spans)) = derived else {
            continue;
        };
        let source_bytes = spans
            .iter()
            .map(|span| {
                let address = source.runtime_address.checked_add(span.source_offset)?;
                memory
                    .read_runtime_bytes(address, usize::try_from(span.byte_len).ok()?)
                    .ok()
            })
            .collect::<Option<Vec<_>>>()
            .map(|parts| parts.into_iter().flatten().collect::<Vec<_>>());
        let Some(source_bytes) = source_bytes else {
            continue;
        };
        let Ok(after_bytes) = hex::decode(&change.after_hex) else {
            continue;
        };
        if write_len == 0
            || source_bytes != after_bytes
            || spans.iter().map(|span| span.byte_len).sum::<u64>() != write_len
        {
            continue;
        }
        let memory_version_sequence = steps
            .iter()
            .filter_map(|step| match step.transfer {
                ObservedValueTransfer::MemoryWrite { address, byte_len }
                    if address <= source_address
                        && source_address < address.saturating_add(u64::from(byte_len)) =>
                {
                    Some(step.sequence)
                }
                _ => None,
            })
            .max()
            .unwrap_or(0);
        let load_candidates = loads
            .iter()
            .filter(|load| {
                memory_version_sequence < load.sequence && load.sequence < store.sequence
            })
            .filter(|load| {
                evidence_value(&load.effective_address).is_some_and(|address| {
                    address.effective_address == source_address
                        && u64::from(address.byte_len) == write_len
                })
            })
            .filter_map(|load| evidence_value(&load.operation_occurrence))
            .collect::<Vec<_>>();
        let [source_load_occurrence] = load_candidates.as_slice() else {
            continue;
        };
        for (index, span) in spans
            .iter()
            .flat_map(|span| {
                (0..span.byte_len).map(move |offset| InputByteSpan {
                    source_id: span.source_id.clone(),
                    source_offset: span.source_offset + offset,
                    byte_len: 1,
                })
            })
            .enumerate()
        {
            let Some(address) = change.start.checked_add(index as u64) else {
                continue;
            };
            memory_provenance.insert(address, span);
        }
        steps.push(InputValueFlowStep {
            sequence: store.sequence,
            runtime_instruction_va: store.runtime_instruction_va,
            static_operation: operation.clone(),
            provenance: spans,
            source_memory_address: source_address,
            source_load_occurrence: Evidence::Inferred {
                value: (*source_load_occurrence).clone(),
                source: "one exact observed LLIR load consumes the current runtime memory version"
                    .to_string(),
            },
            transfer: ObservedValueTransfer::MemoryWrite {
                address: change.start,
                byte_len: write_len_u8,
            },
        });
    }
    if steps.is_empty() {
        return Evidence::Unknown {
            reason: "no observed LLIR store carries exact bytes from this input".to_string(),
        };
    }
    Evidence::Inferred {
        value: InputValueFlow {
            source_id: source.source_id.clone(),
            source_name: source.source_name.clone(),
            source_byte_len: source.byte_len,
            steps,
        },
        source: "hash-verified input bytes joined through immutable LLIR value semantics to an observed memory write".to_string(),
    }
}

fn expression_input_spans(
    expression: &StaticValueExpression,
    registers: &BTreeMap<String, u64>,
    memory: &RuntimeMemoryView<'_>,
    memory_provenance: &BTreeMap<u64, InputByteSpan>,
) -> Option<(u64, Vec<InputByteSpan>)> {
    match expression {
        StaticValueExpression::Load { address, byte_len } => {
            let address = evaluate_static_expression_memory(address, registers, memory)?;
            let bytes = (0..u64::from(*byte_len))
                .map(|offset| {
                    memory_provenance
                        .get(&address.checked_add(offset)?)
                        .cloned()
                })
                .collect::<Option<Vec<_>>>()?;
            Some((address, merge_input_byte_spans(bytes)))
        }
        StaticValueExpression::BitwiseAnd { left, right } => {
            let (value, mask) = match (&**left, &**right) {
                (value, StaticValueExpression::Constant { value: mask }) => (value, *mask),
                (StaticValueExpression::Constant { value: mask }, value) => (value, *mask),
                _ => return None,
            };
            let preserved = low_mask_byte_len(mask)?;
            let (address, mut spans) =
                expression_input_spans(value, registers, memory, memory_provenance)?;
            truncate_spans(&mut spans, preserved);
            (!spans.is_empty()).then_some((address, spans))
        }
        StaticValueExpression::BitwiseOr { left, right } => {
            for (candidate, other) in [(&**left, &**right), (&**right, &**left)] {
                let Some((address, spans)) =
                    expression_input_spans(candidate, registers, memory, memory_provenance)
                else {
                    continue;
                };
                let byte_len = spans.iter().map(|span| span.byte_len).sum::<u64>();
                let Some(mask) = byte_mask(byte_len) else {
                    continue;
                };
                if evaluate_static_expression_memory(other, registers, memory)
                    .is_some_and(|value| value & mask == 0)
                {
                    return Some((address, spans));
                }
            }
            None
        }
        StaticValueExpression::Truncate { value, to_bits, .. } => {
            let preserved = u64::from(*to_bits).div_ceil(8);
            let (address, mut spans) =
                expression_input_spans(value, registers, memory, memory_provenance)?;
            truncate_spans(&mut spans, preserved);
            (!spans.is_empty()).then_some((address, spans))
        }
        StaticValueExpression::Extract {
            value,
            high_bit: to_bits,
            low_bit: 0,
        } => {
            let preserved = u64::from(*to_bits).saturating_add(1).div_ceil(8);
            let (address, mut spans) =
                expression_input_spans(value, registers, memory, memory_provenance)?;
            truncate_spans(&mut spans, preserved);
            (!spans.is_empty()).then_some((address, spans))
        }
        StaticValueExpression::ZeroExtend { value, .. }
        | StaticValueExpression::SignExtend { value, .. } => {
            expression_input_spans(value, registers, memory, memory_provenance)
        }
        _ => None,
    }
}

fn merge_input_byte_spans(bytes: Vec<InputByteSpan>) -> Vec<InputByteSpan> {
    let mut spans: Vec<InputByteSpan> = Vec::new();
    for byte in bytes {
        if let Some(previous) = spans.last_mut() {
            if previous.source_id == byte.source_id
                && previous.source_offset + previous.byte_len == byte.source_offset
            {
                previous.byte_len += byte.byte_len;
                continue;
            }
        }
        spans.push(byte);
    }
    spans
}

fn low_mask_byte_len(mask: i64) -> Option<u64> {
    let mask = u64::try_from(mask).ok()?;
    (1..=8).find(|bytes| {
        let bits = bytes * 8;
        mask == if bits == 64 {
            u64::MAX
        } else {
            (1_u64 << bits) - 1
        }
    })
}

fn byte_mask(byte_len: u64) -> Option<u64> {
    match byte_len {
        1..=7 => Some((1_u64 << (byte_len * 8)) - 1),
        8 => Some(u64::MAX),
        _ => None,
    }
}

fn truncate_spans(spans: &mut Vec<InputByteSpan>, mut remaining: u64) {
    spans.retain_mut(|span| {
        span.byte_len = span.byte_len.min(remaining);
        remaining = remaining.saturating_sub(span.byte_len);
        span.byte_len != 0
    });
}

fn evaluate_static_expression_memory(
    expression: &StaticValueExpression,
    registers: &BTreeMap<String, u64>,
    memory: &RuntimeMemoryView<'_>,
) -> Option<u64> {
    match expression {
        StaticValueExpression::Load { address, byte_len } => {
            let address = evaluate_static_expression_memory(address, registers, memory)?;
            let bytes = memory
                .read_runtime_bytes(address, usize::from(*byte_len))
                .ok()?;
            (bytes.len() <= 8).then(|| {
                let mut value = [0_u8; 8];
                value[..bytes.len()].copy_from_slice(&bytes);
                u64::from_le_bytes(value)
            })
        }
        _ => evaluate_static_expression(expression, registers).or_else(|| match expression {
            StaticValueExpression::Add { left, right } => Some(
                evaluate_static_expression_memory(left, registers, memory)?
                    .wrapping_add(evaluate_static_expression_memory(right, registers, memory)?),
            ),
            StaticValueExpression::Subtract { left, right } => Some(
                evaluate_static_expression_memory(left, registers, memory)?
                    .wrapping_sub(evaluate_static_expression_memory(right, registers, memory)?),
            ),
            StaticValueExpression::Multiply { left, right } => Some(
                evaluate_static_expression_memory(left, registers, memory)?
                    .wrapping_mul(evaluate_static_expression_memory(right, registers, memory)?),
            ),
            StaticValueExpression::BitwiseAnd { left, right } => Some(
                evaluate_static_expression_memory(left, registers, memory)?
                    & evaluate_static_expression_memory(right, registers, memory)?,
            ),
            StaticValueExpression::BitwiseOr { left, right } => Some(
                evaluate_static_expression_memory(left, registers, memory)?
                    | evaluate_static_expression_memory(right, registers, memory)?,
            ),
            StaticValueExpression::BitwiseXor { left, right } => Some(
                evaluate_static_expression_memory(left, registers, memory)?
                    ^ evaluate_static_expression_memory(right, registers, memory)?,
            ),
            StaticValueExpression::Truncate { value, to_bits, .. }
            | StaticValueExpression::ZeroExtend { value, to_bits, .. } => {
                let value = evaluate_static_expression_memory(value, registers, memory)?;
                let mask = if *to_bits >= 64 {
                    u64::MAX
                } else {
                    (1_u64 << *to_bits) - 1
                };
                Some(value & mask)
            }
            _ => None,
        }),
    }
}

fn relate_input_to_call_arguments(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    calls: &[InstructionCallRelation],
    executed_stores: &[ExecutedStoreRelation],
    controls: &[InstructionControlTransferRelation],
    value_selections: &[InstructionValueSelectionRelation],
    value_definitions: &[InstructionValueDefinitionRelation],
) -> Vec<InputToCallArgumentRelation> {
    let invocation_sources = input_provenance(capsule)
        .sources
        .into_iter()
        .filter(|source| source.name.starts_with("argv[") && source.name.ends_with(']'))
        .collect::<Vec<_>>();
    calls
        .iter()
        .filter(|call| evidence_value(&call.callee).is_some_and(|callee| callee == "ioctl"))
        .flat_map(|sink| {
            invocation_sources
                .iter()
                .map(move |source| InputToCallArgumentRelation {
                    source_id: source.id.clone(),
                    source_name: source.name.clone(),
                    sink_sequence: sink.sequence,
                    relation: build_input_to_call_argument_slice(
                        source,
                        sink,
                        capsule,
                        payloads,
                        image,
                        calls,
                        executed_stores,
                        controls,
                        value_selections,
                        value_definitions,
                    ),
                })
        })
        .collect()
}

fn build_input_to_call_argument_slice(
    source: &InputSourceIdentity,
    sink: &InstructionCallRelation,
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    calls: &[InstructionCallRelation],
    executed_stores: &[ExecutedStoreRelation],
    controls: &[InstructionControlTransferRelation],
    value_selections: &[InstructionValueSelectionRelation],
    value_definitions: &[InstructionValueDefinitionRelation],
) -> Evidence<InputToCallArgumentSlice> {
    let comparisons = calls
        .iter()
        .filter(|call| evidence_value(&call.callee).is_some_and(|callee| callee == "strcmp"))
        .filter_map(|call| {
            let occurrence = evidence_value(&call.operation_occurrence)?;
            occurrence
                .introduced_input_sources
                .iter()
                .any(|candidate| candidate.id == source.id)
                .then_some((call, occurrence))
        })
        .collect::<Vec<_>>();
    let [(comparison, comparison_occurrence)] = comparisons.as_slice() else {
        return Evidence::Unknown {
            reason: "input-to-call relation requires one input-comparison occurrence".to_string(),
        };
    };
    let Some(comparison_return) = evidence_value(&comparison.return_occurrence) else {
        return Evidence::Unknown {
            reason: "input comparison has no observed return occurrence".to_string(),
        };
    };
    let Some(sink_occurrence) = evidence_value(&sink.operation_occurrence) else {
        return Evidence::Unknown {
            reason: "sink has no exact operation occurrence".to_string(),
        };
    };
    let Some(request_value) = sink_occurrence
        .inputs
        .get("request")
        .and_then(evidence_value)
    else {
        return Evidence::Unknown {
            reason: "sink occurrence has no observed request value".to_string(),
        };
    };
    let comparison_edges = controls
        .iter()
        .filter(|control| {
            control.sequence >= comparison_return.sequence
                && control.sequence < sink.sequence
                && control_depends_on_call(
                    control,
                    comparison_occurrence.static_operation.machine_va,
                )
        })
        .filter_map(|control| evidence_value(&control.edge).map(|edge| (control, edge)))
        .collect::<Vec<_>>();
    let [(comparison_control, comparison_edge)] = comparison_edges.as_slice() else {
        let direct_selection = conditional_value_propagation(
            capsule,
            payloads,
            image,
            comparison_occurrence,
            comparison_return,
            sink,
            sink_occurrence,
            request_value,
            value_selections,
        );
        if let Ok(propagation) = direct_selection.as_ref() {
            return inferred_input_to_call_argument_slice(
                source,
                comparison_occurrence,
                comparison_return,
                propagation.clone(),
                sink_occurrence,
                request_value,
                "captured input comparison joined through one observed LLIR conditional value selection to the exact sink argument",
            );
        }
        let predicate_selection = predicate_return_conditional_value_propagation(
            capsule,
            payloads,
            image,
            calls,
            executed_stores,
            comparison_occurrence,
            comparison_return,
            sink,
            sink_occurrence,
            request_value,
            value_selections,
        );
        if let Ok(propagation) = predicate_selection.as_ref() {
            return inferred_input_to_call_argument_slice(
                source,
                comparison_occurrence,
                comparison_return,
                propagation.clone(),
                sink_occurrence,
                request_value,
                "captured input comparison joined through one observed predicate return and one LLIR conditional value selection to the exact sink argument",
            );
        }
        let direct_error = match direct_selection {
            Err(error) => error,
            Ok(_) => "direct selection unexpectedly escaped its success path".to_string(),
        };
        let predicate_error = match predicate_selection {
            Err(error) => error,
            Ok(_) => "predicate selection unexpectedly escaped its success path".to_string(),
        };
        return Evidence::Unknown {
            reason: format!(
                "input comparison reaches neither a direct selection ({}) nor a predicate-return selection ({})",
                direct_error, predicate_error,
            ),
        };
    };
    if let Ok(propagation) = branch_selected_register_propagation(
        capsule,
        payloads,
        image,
        comparison_control,
        comparison_edge,
        sink,
        sink_occurrence,
        request_value,
        value_definitions,
    ) {
        return inferred_input_to_call_argument_slice(
            source,
            comparison_occurrence,
            comparison_return,
            propagation,
            sink_occurrence,
            request_value,
            "captured input comparison joined through one observed edge and one exact selected register definition to the sink argument",
        );
    }
    let predicate_calls = calls
        .iter()
        .filter(|call| {
            evidence_value(&call.static_target_va)
                == Some(&comparison_occurrence.static_operation.function_entry)
        })
        .filter(|call| {
            evidence_value(&call.return_occurrence).is_some_and(|value| {
                value.sequence > comparison_control.sequence && value.sequence < sink.sequence
            })
        })
        .collect::<Vec<_>>();
    let [predicate_call] = predicate_calls.as_slice() else {
        return Evidence::Unknown {
            reason: "comparison function does not return through one observed caller occurrence"
                .to_string(),
        };
    };
    let Some(predicate_return) = evidence_value(&predicate_call.return_occurrence) else {
        return Evidence::Unknown {
            reason: "predicate caller has no observed return occurrence".to_string(),
        };
    };
    let Some(predicate_operation) = unique_call_operation(&predicate_call.address_resolution)
    else {
        return Evidence::Unknown {
            reason: "predicate caller has no exact static call operation".to_string(),
        };
    };
    let selection_edges = controls
        .iter()
        .filter(|control| {
            control.sequence >= predicate_return.sequence
                && control.sequence < sink.sequence
                && control_depends_on_call(control, predicate_operation.machine_va)
        })
        .filter_map(|control| evidence_value(&control.edge).map(|edge| (control, edge)))
        .collect::<Vec<_>>();
    let [(selection_control, selection_edge)] = selection_edges.as_slice() else {
        return Evidence::Unknown {
            reason: "predicate return does not reach one observed request-selection edge"
                .to_string(),
        };
    };
    let Some(request_input) = predicate_call_input(sink_occurrence, 1) else {
        return Evidence::Unknown {
            reason: "sink has no statically sliced second argument".to_string(),
        };
    };
    let StaticValueExpression::Load {
        address: request_address,
        ..
    } = request_input
    else {
        return Evidence::Unknown {
            reason: "sink second argument is not loaded from a selected memory location"
                .to_string(),
        };
    };
    let selected_writes = executed_stores
        .iter()
        .filter(|step| step.sequence > selection_control.sequence && step.sequence < sink.sequence)
        .filter_map(|step| {
            let occurrence = evidence_value(&step.operation_occurrence)?;
            (occurrence.static_operation.kind == "store"
                && occurrence.static_operation.address_expression.as_ref()
                    == Some(request_address.as_ref()))
            .then_some((step, occurrence))
        })
        .collect::<Vec<_>>();
    let [(selected_step, selected_write)] = selected_writes.as_slice() else {
        return Evidence::Unknown {
            reason: "selection edge does not reach one write read by the sink argument".to_string(),
        };
    };
    let Some(stored_value) = selected_write
        .static_operation
        .stored_value
        .as_ref()
        .and_then(|expression| observed_expression_value(expression, &selected_step.registers))
    else {
        return Evidence::Unknown {
            reason: "selected write value cannot be evaluated from occurrence registers"
                .to_string(),
        };
    };
    if stored_value.to_string() != *request_value {
        return Evidence::Unknown {
            reason: "selected write value disagrees with the observed sink request".to_string(),
        };
    }
    inferred_input_to_call_argument_slice(
        source,
        comparison_occurrence,
        comparison_return,
        InputToCallArgumentPropagation::BranchSelectedMemory {
            comparison_edge: (*comparison_edge).clone(),
            predicate_call: predicate_operation.clone(),
            predicate_return: predicate_return.clone(),
            selection_edge: (*selection_edge).clone(),
            selected_write: (*selected_write).clone(),
        },
        sink_occurrence,
        request_value,
        "captured input comparison, two observed call-result-dependent edges, selected write, and exact sink argument load",
    )
}

#[allow(clippy::too_many_arguments)]
fn inferred_input_to_call_argument_slice(
    source: &InputSourceIdentity,
    comparison_occurrence: &OperationOccurrence,
    comparison_return: &ObservedCallReturn,
    propagation: InputToCallArgumentPropagation,
    sink_occurrence: &OperationOccurrence,
    request_value: &String,
    evidence_source: &str,
) -> Evidence<InputToCallArgumentSlice> {
    Evidence::Inferred {
        value: InputToCallArgumentSlice {
            source_id: source.id.clone(),
            source_name: source.name.clone(),
            comparison_occurrence: comparison_occurrence.clone(),
            comparison_return: comparison_return.clone(),
            propagation,
            sink_occurrence: sink_occurrence.clone(),
            argument_name: "request".to_string(),
            argument_value: request_value.clone(),
        },
        source: evidence_source.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn branch_selected_register_propagation(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    comparison_control: &InstructionControlTransferRelation,
    comparison_edge: &ObservedControlEdge,
    sink: &InstructionCallRelation,
    sink_occurrence: &OperationOccurrence,
    request_value: &String,
    value_definitions: &[InstructionValueDefinitionRelation],
) -> Result<InputToCallArgumentPropagation, String> {
    let request_expression = predicate_call_input(sink_occurrence, 1)
        .ok_or_else(|| "sink has no statically sliced second argument".to_string())?;
    let StaticValueExpression::Register {
        name: request_register,
    } = request_expression
    else {
        return Err("sink second argument is not supplied by one register".to_string());
    };
    let expected = request_value
        .parse::<u64>()
        .map_err(|_| "sink request value is not an unsigned scalar".to_string())?;
    let candidates = value_definitions
        .iter()
        .filter(|definition| {
            comparison_control.sequence < definition.sequence && definition.sequence < sink.sequence
        })
        .filter(|definition| {
            definition
                .static_operation
                .defined_register
                .as_ref()
                .is_some_and(|defined| same_x86_register(defined, request_register))
        })
        .filter(|definition| evidence_value(&definition.output) == Some(&expected))
        .filter(|definition| {
            intervening_steps_preserve_register(
                capsule,
                payloads,
                image,
                definition.sequence,
                sink.sequence,
                request_register,
            )
        })
        .collect::<Vec<_>>();
    let [selected_definition] = candidates.as_slice() else {
        return Err(
            "observed comparison edge reaches no unique sink-register definition".to_string(),
        );
    };
    Ok(InputToCallArgumentPropagation::BranchSelectedRegister {
        comparison_edge: comparison_edge.clone(),
        selected_definition: (*selected_definition).clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn conditional_value_propagation(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    comparison_occurrence: &OperationOccurrence,
    comparison_return: &ObservedCallReturn,
    sink: &InstructionCallRelation,
    sink_occurrence: &OperationOccurrence,
    request_value: &String,
    value_selections: &[InstructionValueSelectionRelation],
) -> Result<InputToCallArgumentPropagation, String> {
    let Some(request_expression) = predicate_call_input(sink_occurrence, 1) else {
        return Err("sink has no statically sliced second argument".to_string());
    };
    let StaticValueExpression::Register {
        name: request_register,
    } = request_expression
    else {
        return Err("sink second argument is not supplied by one register".to_string());
    };
    let expected = request_value
        .parse::<u64>()
        .map_err(|_| "sink request value is not an unsigned scalar".to_string())?;
    let candidates = value_selections
        .iter()
        .filter(|selection| {
            comparison_return.sequence <= selection.sequence && selection.sequence < sink.sequence
        })
        .filter(|selection| {
            evidence_value(&selection.static_operation).is_some_and(|operation| {
                operation.condition_call_results.iter().any(|origin| {
                    origin.machine_va == comparison_occurrence.static_operation.machine_va
                }) && operation.value_selection.as_ref().is_some_and(|value| {
                    same_x86_register(&value.output_register, request_register)
                })
            })
        })
        .filter(|selection| evidence_value(&selection.output) == Some(&expected))
        .filter(|selection| {
            intervening_steps_preserve_register(
                capsule,
                payloads,
                image,
                selection.sequence,
                sink.sequence,
                request_register,
            )
        })
        .collect::<Vec<_>>();
    let [selection] = candidates.as_slice() else {
        return Err(
            "comparison result does not reach one non-clobbered conditional value selection"
                .to_string(),
        );
    };
    Ok(InputToCallArgumentPropagation::ConditionalValue {
        selection: (*selection).clone(),
    })
}

#[allow(clippy::too_many_arguments)]
fn predicate_return_conditional_value_propagation(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    calls: &[InstructionCallRelation],
    executed_stores: &[ExecutedStoreRelation],
    comparison_occurrence: &OperationOccurrence,
    comparison_return: &ObservedCallReturn,
    sink: &InstructionCallRelation,
    sink_occurrence: &OperationOccurrence,
    request_value: &String,
    value_selections: &[InstructionValueSelectionRelation],
) -> Result<InputToCallArgumentPropagation, String> {
    let predicate_calls = calls
        .iter()
        .filter(|call| call.sequence < comparison_occurrence.event_sequence)
        .filter(|call| {
            evidence_value(&call.static_target_va)
                == Some(&comparison_occurrence.static_operation.function_entry)
        })
        .filter(|call| {
            evidence_value(&call.return_occurrence).is_some_and(|value| {
                value.sequence > comparison_return.sequence && value.sequence < sink.sequence
            })
        })
        .collect::<Vec<_>>();
    let [predicate_call] = predicate_calls.as_slice() else {
        return Err("comparison is not nested in one observed predicate call".to_string());
    };
    let predicate_operation = unique_call_operation(&predicate_call.address_resolution)
        .ok_or_else(|| "predicate caller has no exact static call operation".to_string())?;
    let predicate_return = evidence_value(&predicate_call.return_occurrence)
        .ok_or_else(|| "predicate caller has no observed return occurrence".to_string())?;
    let comparison_to_predicate_return = observed_call_result_flow(
        capsule,
        payloads,
        image,
        comparison_occurrence.static_operation.machine_va,
        comparison_occurrence.static_operation.function_entry,
        comparison_return,
        predicate_return,
    )?;
    let tainted_writes = comparison_to_predicate_return
        .steps
        .iter()
        .filter_map(|step| match &step.transfer {
            ObservedValueTransfer::MemoryWrite { address, byte_len } => Some((*address, *byte_len)),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let has_matching_spill_reload = comparison_to_predicate_return.steps.iter().any(|step| {
        matches!(
            &step.transfer,
            ObservedValueTransfer::MemoryRead { address, byte_len }
                if tainted_writes.contains(&(*address, *byte_len))
        )
    });
    if !has_matching_spill_reload {
        return Err("predicate return has no exact matching tainted spill and reload".to_string());
    }

    let Some(request_expression) = predicate_call_input(sink_occurrence, 1) else {
        return Err("sink has no statically sliced second argument".to_string());
    };
    let StaticValueExpression::Load {
        address: request_address,
        ..
    } = request_expression
    else {
        return Err("sink second argument is not loaded from memory".to_string());
    };
    let expected = request_value
        .parse::<u64>()
        .map_err(|_| "sink request value is not an unsigned scalar".to_string())?;
    let candidates = value_selections
        .iter()
        .filter(|selection| {
            predicate_return.sequence <= selection.sequence && selection.sequence < sink.sequence
        })
        .filter(|selection| {
            evidence_value(&selection.static_operation).is_some_and(|operation| {
                operation
                    .condition_call_results
                    .iter()
                    .any(|origin| origin.machine_va == predicate_operation.machine_va)
                    && operation.value_selection.is_some()
            })
        })
        .filter(|selection| evidence_value(&selection.output) == Some(&expected))
        .collect::<Vec<_>>();
    let [selection] = candidates.as_slice() else {
        return Err("predicate return does not reach one conditional value selection".to_string());
    };
    let selection_operation = evidence_value(&selection.static_operation)
        .ok_or_else(|| "conditional value selection has no exact static operation".to_string())?;
    let selection_register = &selection_operation
        .value_selection
        .as_ref()
        .ok_or_else(|| "conditional operation has no value-selection semantics".to_string())?
        .output_register;
    let selected_writes = executed_stores
        .iter()
        .filter(|step| step.sequence > selection.sequence && step.sequence < sink.sequence)
        .filter_map(|step| {
            let occurrence = evidence_value(&step.operation_occurrence)?;
            let operation = &occurrence.static_operation;
            (operation.address_expression.as_ref() == Some(request_address.as_ref())
                && operation
                    .stored_value_register
                    .as_ref()
                    .is_some_and(|stored| same_x86_register(stored, selection_register))
                && evidence_value(&step.registers)
                    .and_then(|registers| register_value(registers, selection_register))
                    == Some(expected)
                && intervening_steps_preserve_register(
                    capsule,
                    payloads,
                    image,
                    selection.sequence,
                    step.sequence,
                    selection_register,
                ))
            .then_some(occurrence)
        })
        .collect::<Vec<_>>();
    let [selected_write] = selected_writes.as_slice() else {
        return Err(
            "conditional value selection does not reach one exact sink-readable write".to_string(),
        );
    };
    Ok(
        InputToCallArgumentPropagation::SpilledPredicateReturnConditionalMemory {
            predicate_call: predicate_operation.clone(),
            predicate_return: predicate_return.clone(),
            comparison_to_predicate_return,
            selection: (*selection).clone(),
            selected_write: (*selected_write).clone(),
        },
    )
}

fn observed_call_result_flow(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    source_call_machine_va: u64,
    function_entry: u64,
    source_return: &ObservedCallReturn,
    destination_return: &ObservedCallReturn,
) -> Result<ObservedCallResultFlow, String> {
    if source_return.sequence >= destination_return.sequence {
        return Err("call-result flow has an empty or reversed occurrence range".to_string());
    }
    let register_trace = parse_register_trace(capsule, payloads);
    let mut tainted_registers = BTreeSet::from([source_return.return_register.clone()]);
    let mut tainted_memory = BTreeSet::<(u64, u8)>::new();
    let mut steps = Vec::new();
    let events = capsule
        .events
        .iter()
        .filter(|event| event.kind == "instruction_step")
        .filter(|event| {
            source_return.sequence <= event.sequence && event.sequence < destination_return.sequence
        })
        .collect::<Vec<_>>();
    if events.is_empty() {
        return Err("call-result flow has no observed instruction steps".to_string());
    }
    for event in events {
        let runtime_instruction_va = event
            .address
            .ok_or_else(|| "call-result flow step has no runtime address".to_string())?;
        let resolution = resolve_runtime_address(
            capsule,
            payloads,
            image,
            &event.process_id,
            runtime_instruction_va,
        );
        let AddressResolution::Exact { address } = &resolution else {
            return Err("call-result flow contains a non-exact static address".to_string());
        };
        let StaticCodeResolution::Resolved {
            operations: OperationResolution::Resolved { operations },
            instruction_relation: InstructionRelation::Exact,
            ..
        } = &address.code
        else {
            return Err("call-result flow contains unresolved LLIR operations".to_string());
        };
        if operations
            .iter()
            .any(|operation| operation.function_entry != function_entry)
        {
            return Err("call-result flow leaves the predicate function".to_string());
        }
        let registers = registers_for_step(&register_trace, event);
        let Evidence::Observed {
            value: registers, ..
        } = registers
        else {
            return Err("call-result flow step has no observed registers".to_string());
        };
        for operation in operations {
            if operation.kind == "call" {
                return Err("call-result flow crosses an intervening call".to_string());
            }
            let used_taint = operation
                .used_registers
                .iter()
                .any(|register| register_is_tainted(&tainted_registers, register));
            let memory = operation.memory_access.as_ref().and_then(|access| {
                evidence_value(&derive_x86_64_address(access, &registers, None))
                    .map(|address| (address.effective_address, address.byte_len))
            });
            let load_taint = operation.kind == "load"
                && memory.is_some_and(|range| tainted_memory.contains(&range));
            let result_taint = used_taint || load_taint;

            if operation.kind == "store" {
                let source_tainted = operation
                    .stored_value_register
                    .as_ref()
                    .is_some_and(|register| register_is_tainted(&tainted_registers, register));
                let range = memory.ok_or_else(|| {
                    "call-result flow store has no evaluable effective address".to_string()
                })?;
                if source_tainted {
                    tainted_memory.insert(range);
                    steps.push(ObservedValueFlowStep {
                        sequence: event.sequence,
                        runtime_instruction_va,
                        static_operation: operation.clone(),
                        transfer: ObservedValueTransfer::MemoryWrite {
                            address: range.0,
                            byte_len: range.1,
                        },
                    });
                } else {
                    tainted_memory.remove(&range);
                }
                continue;
            }

            let Some(defined) = operation.defined_register.as_ref() else {
                continue;
            };
            clear_register_taint(&mut tainted_registers, defined);
            if result_taint {
                tainted_registers.insert(defined.clone());
                steps.push(ObservedValueFlowStep {
                    sequence: event.sequence,
                    runtime_instruction_va,
                    static_operation: operation.clone(),
                    transfer: if load_taint {
                        let Some((address, byte_len)) = memory else {
                            return Err(
                                "tainted load has no evaluable effective address".to_string()
                            );
                        };
                        ObservedValueTransfer::MemoryRead { address, byte_len }
                    } else {
                        ObservedValueTransfer::Register {
                            register: defined.clone(),
                        }
                    },
                });
            }
        }
    }
    if !register_is_tainted(&tainted_registers, &destination_return.return_register) {
        return Err("comparison result does not reach the predicate return register".to_string());
    }
    Ok(ObservedCallResultFlow {
        source_call_machine_va,
        destination_register: destination_return.return_register.clone(),
        destination_value: destination_return.return_value,
        steps,
    })
}

fn register_is_tainted(tainted: &BTreeSet<String>, register: &str) -> bool {
    tainted
        .iter()
        .any(|candidate| same_x86_register(candidate, register))
}

fn clear_register_taint(tainted: &mut BTreeSet<String>, register: &str) {
    tainted.retain(|candidate| !same_x86_register(candidate, register));
}

fn intervening_steps_preserve_register(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    after_sequence: u64,
    before_sequence: u64,
    register: &str,
) -> bool {
    capsule
        .events
        .iter()
        .filter(|event| {
            event.kind == "instruction_step"
                && event.sequence > after_sequence
                && event.sequence < before_sequence
        })
        .all(|event| {
            let Some(runtime_va) = event.address else {
                return false;
            };
            let AddressResolution::Exact { address } =
                resolve_runtime_address(capsule, payloads, image, &event.process_id, runtime_va)
            else {
                return false;
            };
            let StaticCodeResolution::Resolved {
                operations: OperationResolution::Resolved { operations },
                instruction_relation: InstructionRelation::Exact,
                ..
            } = &address.code
            else {
                return false;
            };
            operations.iter().all(|operation| {
                operation
                    .defined_register
                    .as_ref()
                    .is_none_or(|defined| !same_x86_register(defined, register))
            })
        })
}

fn same_x86_register(left: &str, right: &str) -> bool {
    x86_parent_register(left) == x86_parent_register(right)
}

fn x86_parent_register(register: &str) -> &str {
    match register {
        "rax" | "eax" | "ax" | "al" | "ah" => "rax",
        "rsi" | "esi" | "si" | "sil" => "rsi",
        "rdi" | "edi" | "di" | "dil" => "rdi",
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx",
        other => other,
    }
}

fn register_value(registers: &BTreeMap<String, u64>, register: &str) -> Option<u64> {
    let value = registers.get(x86_parent_register(register)).copied()?;
    Some(match register {
        "eax" | "esi" | "edi" | "edx" => value & 0xffff_ffff,
        "ax" | "si" | "di" | "dx" => value & 0xffff,
        "al" | "sil" | "dil" | "dl" => value & 0xff,
        "ah" | "dh" => (value >> 8) & 0xff,
        _ => value,
    })
}

fn evidence_value<T>(evidence: &Evidence<T>) -> Option<&T> {
    match evidence {
        Evidence::Observed { value, .. } | Evidence::Inferred { value, .. } => Some(value),
        Evidence::Unknown { .. } => None,
    }
}

fn control_depends_on_call(control: &InstructionControlTransferRelation, machine_va: u64) -> bool {
    evidence_value(&control.static_operation).is_some_and(|operation| {
        operation
            .condition_call_results
            .iter()
            .any(|origin| origin.machine_va == machine_va)
    })
}

fn unique_call_operation(resolution: &AddressResolution) -> Option<&StaticOperation> {
    let AddressResolution::Exact { address } = resolution else {
        return None;
    };
    let StaticCodeResolution::Resolved {
        operations: OperationResolution::Resolved { operations },
        instruction_relation: InstructionRelation::Exact,
        ..
    } = &address.code
    else {
        return None;
    };
    let calls = operations
        .iter()
        .filter(|operation| operation.kind == "call")
        .collect::<Vec<_>>();
    let [operation] = calls.as_slice() else {
        return None;
    };
    Some(operation)
}

fn predicate_call_input(
    occurrence: &OperationOccurrence,
    position: usize,
) -> Option<&StaticValueExpression> {
    occurrence
        .static_operation
        .call_register_inputs
        .iter()
        .find(|input| input.position == position)
        .map(|input| &input.expression)
}

fn observed_expression_value(
    expression: &StaticValueExpression,
    registers: &Evidence<BTreeMap<String, u64>>,
) -> Option<u64> {
    let registers = evidence_value(registers)?;
    evaluate_static_expression(expression, registers)
}

fn evaluate_static_expression(
    expression: &StaticValueExpression,
    registers: &BTreeMap<String, u64>,
) -> Option<u64> {
    match expression {
        StaticValueExpression::Register { name } => register_value(registers, name),
        StaticValueExpression::Constant { value } => Some(*value as u64),
        StaticValueExpression::Address { value } => Some(*value),
        StaticValueExpression::Add { left, right } => Some(
            evaluate_static_expression(left, registers)?
                .wrapping_add(evaluate_static_expression(right, registers)?),
        ),
        StaticValueExpression::Subtract { left, right } => Some(
            evaluate_static_expression(left, registers)?
                .wrapping_sub(evaluate_static_expression(right, registers)?),
        ),
        StaticValueExpression::Multiply { left, right } => Some(
            evaluate_static_expression(left, registers)?
                .wrapping_mul(evaluate_static_expression(right, registers)?),
        ),
        StaticValueExpression::BitwiseAnd { left, right } => Some(
            evaluate_static_expression(left, registers)?
                & evaluate_static_expression(right, registers)?,
        ),
        StaticValueExpression::BitwiseOr { left, right } => Some(
            evaluate_static_expression(left, registers)?
                | evaluate_static_expression(right, registers)?,
        ),
        StaticValueExpression::BitwiseXor { left, right } => Some(
            evaluate_static_expression(left, registers)?
                ^ evaluate_static_expression(right, registers)?,
        ),
        _ => None,
    }
}

fn relate_control_transfers(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
) -> Vec<InstructionControlTransferRelation> {
    capsule
        .events
        .iter()
        .filter(|event| event.kind == "instruction_step")
        .filter_map(|event| {
            let runtime_instruction_va = event.address?;
            let source_resolution = resolve_runtime_address(
                capsule,
                payloads,
                image,
                &event.process_id,
                runtime_instruction_va,
            );
            let operation = unique_control_operation(&source_resolution)?;
            let observed_successor = event
                .fields
                .get("after_address")
                .and_then(|value| value.parse::<u64>().ok())
                .map_or_else(
                    || Evidence::Unknown {
                        reason: "instruction step has no valid observed successor".to_string(),
                    },
                    |value| Evidence::Observed {
                        value,
                        source: "ptrace post-step instruction pointer".to_string(),
                    },
                );
            let successor_resolution = match &observed_successor {
                Evidence::Observed { value, .. } => {
                    resolve_runtime_address(capsule, payloads, image, &event.process_id, *value)
                }
                _ => AddressResolution::Missing {
                    reason: "instruction step has no observed successor to resolve".to_string(),
                },
            };
            let edge = relate_control_edge(&source_resolution, operation, &successor_resolution);
            Some(InstructionControlTransferRelation {
                process_id: event.process_id.clone(),
                thread_id: event.thread_id.clone(),
                sequence: event.sequence,
                runtime_instruction_va,
                static_operation: Evidence::Inferred {
                    value: operation.clone(),
                    source: "one exact control-transfer LLIR operation".to_string(),
                },
                observed_successor,
                successor_resolution,
                edge,
            })
        })
        .collect()
}

fn relate_observed_indirect_targets(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
) -> Vec<ObservedIndirectTargetRelation> {
    capsule
        .events
        .iter()
        .filter(|event| event.kind == "instruction_step")
        .filter_map(|event| {
            let runtime_instruction_va = event.address?;
            let source_resolution = resolve_runtime_address(
                capsule,
                payloads,
                image,
                &event.process_id,
                runtime_instruction_va,
            );
            let operation = unique_indirect_control_operation(&source_resolution)?;
            let observed_runtime_target = event
                .fields
                .get("after_address")
                .and_then(|value| value.parse::<u64>().ok())
                .map_or_else(
                    || Evidence::Unknown {
                        reason: "indirect transfer has no valid observed successor".to_string(),
                    },
                    |value| Evidence::Observed {
                        value,
                        source: "ptrace post-step instruction pointer".to_string(),
                    },
                );
            let target_resolution = match &observed_runtime_target {
                Evidence::Observed { value, .. } => {
                    resolve_runtime_address(capsule, payloads, image, &event.process_id, *value)
                }
                _ => AddressResolution::Missing {
                    reason: "indirect transfer has no observed target to resolve".to_string(),
                },
            };
            let target = relate_indirect_target(&source_resolution, operation, &target_resolution);
            let operation_occurrence =
                make_indirect_control_occurrence(capsule, event, operation, &target);
            Some(ObservedIndirectTargetRelation {
                process_id: event.process_id.clone(),
                thread_id: event.thread_id.clone(),
                sequence: event.sequence,
                runtime_instruction_va,
                static_operation: Evidence::Inferred {
                    value: operation.clone(),
                    source: "one exact indirect-control LLIR operation".to_string(),
                },
                observed_runtime_target,
                target_resolution,
                target,
                operation_occurrence,
            })
        })
        .collect()
}

fn make_indirect_control_occurrence(
    capsule: &ProcessCapsule,
    event: &super::capsule::EventRecord,
    operation: &StaticOperation,
    target: &Evidence<ObservedIndirectTarget>,
) -> Evidence<OperationOccurrence> {
    let Evidence::Inferred { value: target, .. } = target else {
        return Evidence::Unknown {
            reason: "indirect control occurrence requires an exact observed target".to_string(),
        };
    };
    operation_occurrence(
        capsule,
        &event.process_id,
        event.thread_id.as_deref(),
        event.sequence,
        operation,
        BTreeMap::from([(
            "observed_target".to_string(),
            Evidence::Observed {
                value: target.target_static_va.to_string(),
                source: "resolved ptrace post-step instruction pointer".to_string(),
            },
        )]),
        Vec::new(),
        Evidence::Unknown {
            reason: "control transfer has no scalar output".to_string(),
        },
        vec![OperationEffect {
            kind: "control_transfer".to_string(),
            resource_id: None,
            runtime_object_id: None,
            errno: None,
            address: Some(target.target_static_va),
            byte_len: None,
            input_source_id: None,
        }],
        "single-stepped successor joined to one exact indirect LLIR operation",
    )
}

fn relate_value_selections(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    register_trace: &Result<BTreeMap<u64, BTreeMap<String, u64>>, String>,
) -> Vec<InstructionValueSelectionRelation> {
    capsule
        .events
        .iter()
        .filter(|event| event.kind == "instruction_step")
        .filter_map(|event| {
            let runtime_instruction_va = event.address?;
            let resolution = resolve_runtime_address(
                capsule,
                payloads,
                image,
                &event.process_id,
                runtime_instruction_va,
            );
            let operation = unique_value_selection_operation(&resolution)?;
            let registers_before = registers_for_step(register_trace, event);
            let next_event = capsule
                .events
                .iter()
                .filter(|candidate| {
                    candidate.kind == "instruction_step"
                        && candidate.process_id == event.process_id
                        && candidate.thread_id == event.thread_id
                        && candidate.sequence > event.sequence
                })
                .min_by_key(|candidate| candidate.sequence);
            let registers_after = next_event.map_or_else(
                || Evidence::Unknown {
                    reason: "value selection has no subsequent instruction-step registers"
                        .to_string(),
                },
                |candidate| registers_for_step(register_trace, candidate),
            );
            let output = operation.value_selection.as_ref().map_or_else(
                || Evidence::Unknown {
                    reason: "LLIR value selection has no output register".to_string(),
                },
                |selection| match evidence_value(&registers_after)
                    .and_then(|registers| registers.get(&selection.output_register).copied())
                {
                    Some(value) => Evidence::Observed {
                        value,
                        source: "hash-bound register trace after the LLIR value selection"
                            .to_string(),
                    },
                    None => Evidence::Unknown {
                        reason: "post-selection register trace lacks the output register"
                            .to_string(),
                    },
                },
            );
            Some(InstructionValueSelectionRelation {
                process_id: event.process_id.clone(),
                thread_id: event.thread_id.clone(),
                sequence: event.sequence,
                runtime_instruction_va,
                static_operation: Evidence::Inferred {
                    value: operation.clone(),
                    source: "one exact LLIR conditional value-selection operation".to_string(),
                },
                registers_before,
                registers_after,
                output,
            })
        })
        .collect()
}

fn unique_value_selection_operation(resolution: &AddressResolution) -> Option<&StaticOperation> {
    let AddressResolution::Exact { address } = resolution else {
        return None;
    };
    let StaticCodeResolution::Resolved {
        operations: OperationResolution::Resolved { operations },
        instruction_relation: InstructionRelation::Exact,
        ..
    } = &address.code
    else {
        return None;
    };
    let selections = operations
        .iter()
        .filter(|operation| operation.value_selection.is_some())
        .collect::<Vec<_>>();
    let [selection] = selections.as_slice() else {
        return None;
    };
    Some(selection)
}

fn relate_value_definitions(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    register_trace: &Result<BTreeMap<u64, BTreeMap<String, u64>>, String>,
) -> Vec<InstructionValueDefinitionRelation> {
    let mut relations = Vec::new();
    for event in capsule
        .events
        .iter()
        .filter(|event| event.kind == "instruction_step")
    {
        let Some(runtime_instruction_va) = event.address else {
            continue;
        };
        let resolution = resolve_runtime_address(
            capsule,
            payloads,
            image,
            &event.process_id,
            runtime_instruction_va,
        );
        let AddressResolution::Exact { address } = &resolution else {
            continue;
        };
        let StaticCodeResolution::Resolved {
            operations: OperationResolution::Resolved { operations },
            instruction_relation: InstructionRelation::Exact,
            ..
        } = &address.code
        else {
            continue;
        };
        let next_event = capsule
            .events
            .iter()
            .filter(|candidate| {
                candidate.kind == "instruction_step"
                    && candidate.process_id == event.process_id
                    && candidate.thread_id == event.thread_id
                    && candidate.sequence > event.sequence
            })
            .min_by_key(|candidate| candidate.sequence);
        let registers_before = registers_for_step(register_trace, event);
        let registers_after = next_event.map_or_else(
            || Evidence::Unknown {
                reason: "value definition has no subsequent instruction-step registers".to_string(),
            },
            |candidate| registers_for_step(register_trace, candidate),
        );
        for operation in operations.iter().filter(|operation| {
            operation.defined_value.is_some()
                && operation
                    .defined_register
                    .as_ref()
                    .is_some_and(|register| !register.starts_with('%'))
        }) {
            let output = match (
                operation.defined_register.as_ref(),
                operation.defined_value.as_ref(),
                evidence_value(&registers_after),
            ) {
                (Some(register), Some(expression), Some(after)) => {
                    let observed = register_value(after, register);
                    let expected = observed_expression_value(expression, &registers_before);
                    match (observed, expected) {
                        (Some(observed), Some(expected)) if observed == expected => {
                            Evidence::Observed {
                                value: observed,
                                source: "hash-bound post-step register agrees with immutable LLIR definition"
                                    .to_string(),
                            }
                        }
                        (Some(_), Some(_)) => Evidence::Unknown {
                            reason: "post-step register disagrees with LLIR definition".to_string(),
                        },
                        _ => Evidence::Unknown {
                            reason: "value definition cannot be evaluated from observed registers"
                                .to_string(),
                        },
                    }
                }
                _ => Evidence::Unknown {
                    reason: "value definition lacks static or post-step evidence".to_string(),
                },
            };
            relations.push(InstructionValueDefinitionRelation {
                process_id: event.process_id.clone(),
                thread_id: event.thread_id.clone(),
                sequence: event.sequence,
                runtime_instruction_va,
                static_operation: operation.clone(),
                registers_before: registers_before.clone(),
                registers_after: registers_after.clone(),
                output,
            });
        }
    }
    relations
}

fn unique_control_operation(resolution: &AddressResolution) -> Option<&StaticOperation> {
    let AddressResolution::Exact { address } = resolution else {
        return None;
    };
    let StaticCodeResolution::Resolved {
        operations: OperationResolution::Resolved { operations },
        instruction_relation: InstructionRelation::Exact,
        ..
    } = &address.code
    else {
        return None;
    };
    let candidates = operations
        .iter()
        .filter(|operation| matches!(operation.kind.as_str(), "cond_jump" | "jump"))
        .collect::<Vec<_>>();
    let [operation] = candidates.as_slice() else {
        return None;
    };
    Some(operation)
}

fn unique_indirect_control_operation(resolution: &AddressResolution) -> Option<&StaticOperation> {
    let AddressResolution::Exact { address } = resolution else {
        return None;
    };
    let StaticCodeResolution::Resolved {
        operations: OperationResolution::Resolved { operations },
        instruction_relation: InstructionRelation::Exact,
        ..
    } = &address.code
    else {
        return None;
    };
    let candidates = operations
        .iter()
        .filter(|operation| {
            operation.kind == "indirect_jump"
                || (operation.kind == "call"
                    && matches!(
                        operation.call_target,
                        Some(StaticCallTarget::Indirect { .. })
                    ))
        })
        .collect::<Vec<_>>();
    let [operation] = candidates.as_slice() else {
        return None;
    };
    Some(operation)
}

fn relate_indirect_target(
    source: &AddressResolution,
    operation: &StaticOperation,
    target: &AddressResolution,
) -> Evidence<ObservedIndirectTarget> {
    let AddressResolution::Exact { address: source } = source else {
        return Evidence::Unknown {
            reason: "indirect target requires exact source resolution".to_string(),
        };
    };
    let AddressResolution::Exact { address: target } = target else {
        return Evidence::Unknown {
            reason: "indirect target requires exact successor resolution".to_string(),
        };
    };
    let transfer_kind = if operation.kind == "indirect_jump" {
        "indirect_jump"
    } else {
        "indirect_call"
    };
    Evidence::Inferred {
        value: ObservedIndirectTarget {
            source_static_va: source.static_va,
            target_static_va: target.static_va,
            transfer_kind: transfer_kind.to_string(),
        },
        source: "exact indirect LLIR operation joined to observed post-step PC".to_string(),
    }
}

fn relate_control_edge(
    source: &AddressResolution,
    operation: &StaticOperation,
    successor: &AddressResolution,
) -> Evidence<ObservedControlEdge> {
    let Some(declared_target_static_va) = operation.control_target else {
        return Evidence::Unknown {
            reason: "static control operation has no declared direct target".to_string(),
        };
    };
    let AddressResolution::Exact { address: source } = source else {
        return Evidence::Unknown {
            reason: "control edge requires exact source resolution".to_string(),
        };
    };
    let AddressResolution::Exact { address: successor } = successor else {
        return Evidence::Unknown {
            reason: "control edge requires exact successor resolution".to_string(),
        };
    };
    let StaticCodeResolution::Resolved {
        instruction_end,
        instruction_relation: InstructionRelation::Exact,
        ..
    } = &source.code
    else {
        return Evidence::Unknown {
            reason: "control edge requires one exact source instruction extent".to_string(),
        };
    };
    let target_static_va = successor.static_va;
    let branch_taken = if target_static_va == declared_target_static_va {
        true
    } else if operation.kind == "cond_jump" && target_static_va == *instruction_end {
        false
    } else {
        return Evidence::Unknown {
            reason: "observed successor is neither the declared target nor conditional fallthrough"
                .to_string(),
        };
    };
    Evidence::Inferred {
        value: ObservedControlEdge {
            source_static_va: source.static_va,
            target_static_va,
            declared_target_static_va,
            branch_taken,
        },
        source: "exact static control operation joined to the observed post-step PC".to_string(),
    }
}

fn select_input_dependent_branches(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    register_trace: &Result<BTreeMap<u64, BTreeMap<String, u64>>, String>,
    input_locations: &[RuntimeInputLocationRelation],
    control_transfers: &[InstructionControlTransferRelation],
) -> Vec<InputDependentBranch> {
    let mut pending = Vec::<PendingInputDependentBranch>::new();
    let mut counterfactual_lineages =
        BTreeMap::<(String, String, Option<String>, u64, Vec<(u64, u64)>), u64>::new();
    let mut lineage_candidate_counts = BTreeMap::<u64, usize>::new();
    for located in input_locations {
        let Some(source) = evidence_value(&located.location) else {
            continue;
        };
        let mut memory_provenance = BTreeMap::<u64, BTreeSet<u64>>::new();
        for offset in 0..source.byte_len {
            if let Some(address) = source.runtime_address.checked_add(offset) {
                memory_provenance.insert(address, BTreeSet::from([offset]));
            }
        }
        let mut register_provenance = BTreeMap::<String, BTreeSet<u64>>::new();
        for event in capsule.events.iter().filter(|event| {
            event.kind == "instruction_step" && event.process_id == source.process_id
        }) {
            let Some(runtime_instruction_va) = event.address else {
                register_provenance.clear();
                memory_provenance.clear();
                continue;
            };
            let Evidence::Observed {
                value: registers, ..
            } = registers_for_step(register_trace, event)
            else {
                register_provenance.clear();
                memory_provenance.clear();
                continue;
            };
            let resolution = resolve_runtime_address(
                capsule,
                payloads,
                image,
                &event.process_id,
                runtime_instruction_va,
            );
            let AddressResolution::Exact { address } = &resolution else {
                if !register_provenance.is_empty() {
                    register_provenance.clear();
                    memory_provenance.clear();
                }
                continue;
            };
            let StaticCodeResolution::Resolved {
                operations: OperationResolution::Resolved { operations },
                instruction_relation: InstructionRelation::Exact,
                ..
            } = &address.code
            else {
                register_provenance.clear();
                memory_provenance.clear();
                continue;
            };
            for operation in operations {
                let used = operation
                    .used_registers
                    .iter()
                    .flat_map(|register| register_taint(&register_provenance, register).into_iter())
                    .collect::<BTreeSet<_>>();
                if operation.kind == "cond_jump" && !used.is_empty() {
                    if let Some(transfer) = control_transfers.iter().find(|transfer| {
                        transfer.process_id == event.process_id
                            && transfer.thread_id == event.thread_id
                            && transfer.sequence == event.sequence
                            && evidence_value(&transfer.static_operation)
                                .is_some_and(|candidate| candidate == operation)
                    }) {
                        if let Some(edge) = evidence_value(&transfer.edge) {
                            let predicate_registers = operation
                                .used_registers
                                .iter()
                                .filter(|register| {
                                    !register_taint(&register_provenance, register).is_empty()
                                })
                                .cloned()
                                .collect();
                            let input_spans = source_offsets_to_spans(&source.source_id, &used);
                            let lineage_key = (
                                source.source_id.clone(),
                                source.process_id.clone(),
                                event.thread_id.clone(),
                                operation.function_entry,
                                input_spans
                                    .iter()
                                    .map(|span| (span.source_offset, span.byte_len))
                                    .collect(),
                            );
                            let next_lineage_id = counterfactual_lineages.len() as u64;
                            let lineage_id = *counterfactual_lineages
                                .entry(lineage_key)
                                .or_insert(next_lineage_id);
                            *lineage_candidate_counts.entry(lineage_id).or_default() += 1;
                            pending.push(PendingInputDependentBranch {
                                source: source.clone(),
                                lineage_id,
                                source_id: source.source_id.clone(),
                                source_name: source.source_name.clone(),
                                process_id: event.process_id.clone(),
                                thread_id: event.thread_id.clone(),
                                sequence: event.sequence,
                                runtime_instruction_va,
                                static_operation: operation.clone(),
                                observed_edge: edge.clone(),
                                predicate_registers,
                                input_spans,
                            });
                        }
                    }
                }

                let memory = operation.memory_access.as_ref().and_then(|access| {
                    evidence_value(&derive_x86_64_address(access, &registers, None))
                        .map(|address| (address.effective_address, address.byte_len))
                });
                let loaded = if operation.kind == "load" {
                    memory
                        .map(|(start, byte_len)| {
                            (0..u64::from(byte_len))
                                .filter_map(|offset| memory_provenance.get(&(start + offset)))
                                .flatten()
                                .copied()
                                .collect::<BTreeSet<_>>()
                        })
                        .unwrap_or_default()
                } else {
                    BTreeSet::new()
                };
                if operation.kind == "store" {
                    if let Some((start, byte_len)) = memory {
                        let stored = operation
                            .stored_value_register
                            .as_ref()
                            .map(|register| register_taint(&register_provenance, register))
                            .unwrap_or_default();
                        for offset in 0..u64::from(byte_len) {
                            if stored.is_empty() {
                                memory_provenance.remove(&(start + offset));
                            } else {
                                memory_provenance.insert(start + offset, stored.clone());
                            }
                        }
                    }
                }
                if let Some(defined) = operation.defined_register.as_ref() {
                    clear_register_provenance(&mut register_provenance, defined);
                    let result = if operation.kind == "load" {
                        loaded
                    } else {
                        used.clone()
                    };
                    if !result.is_empty() && operation.kind != "undef" {
                        register_provenance.insert(defined.clone(), result);
                    }
                }
                if matches!(operation.kind.as_str(), "call" | "intrinsic" | "unknown") {
                    register_provenance.clear();
                }
            }
        }
    }
    let mut selected = pending
        .into_iter()
        .map(|pending| {
            let allow_retention = lineage_candidate_counts
                .get(&pending.lineage_id)
                .is_some_and(|count| *count > 1);
            let counterfactual = negate_observed_input_branch(
                capsule,
                payloads,
                image,
                register_trace,
                &pending.source,
                &pending.static_operation,
                &pending.observed_edge,
                pending.sequence,
                &pending.thread_id,
                &pending.input_spans,
                control_transfers,
                pending.lineage_id,
                allow_retention,
            );
            InputDependentBranch {
                source_id: pending.source_id,
                source_name: pending.source_name,
                process_id: pending.process_id,
                thread_id: pending.thread_id,
                sequence: pending.sequence,
                runtime_instruction_va: pending.runtime_instruction_va,
                static_operation: pending.static_operation,
                observed_edge: pending.observed_edge,
                predicate_registers: pending.predicate_registers,
                input_spans: pending.input_spans,
                selection_reason: "observed LLIR branch condition consumes input-tainted state"
                    .to_string(),
                counterfactual,
            }
        })
        .collect::<Vec<_>>();
    #[cfg(feature = "symbolic")]
    for lineage_id in counterfactual_lineages.into_values() {
        crate::symbolic::solver::close_runtime_solver_path(lineage_id);
    }
    selected.sort_by(|left, right| {
        left.sequence
            .cmp(&right.sequence)
            .then_with(|| left.source_id.cmp(&right.source_id))
    });
    selected
}

#[cfg(not(feature = "symbolic"))]
#[allow(clippy::too_many_arguments)]
fn negate_observed_input_branch(
    _capsule: &ProcessCapsule,
    _payloads: &BTreeMap<String, Vec<u8>>,
    _image: &ProgramImage,
    _register_trace: &Result<BTreeMap<u64, BTreeMap<String, u64>>, String>,
    _source: &RuntimeInputLocation,
    _operation: &StaticOperation,
    _edge: &ObservedControlEdge,
    _selected_sequence: u64,
    _selected_thread: &Option<String>,
    _input_spans: &[InputByteSpan],
    _control_transfers: &[InstructionControlTransferRelation],
    _lineage_id: u64,
    _allow_retention: bool,
) -> BranchCounterfactual {
    BranchCounterfactual::Unknown {
        reason_kind: CounterfactualUnknownReason::NoSolver,
        reason: "runtime counterfactuals require a build with the symbolic feature".to_string(),
        proposition_status: CounterfactualPropositionStatus::NotConstructed,
        bounds: None,
        path_conditions: Vec::new(),
    }
}

#[cfg(feature = "symbolic")]
fn counterfactual_solver_backend() -> String {
    if cfg!(feature = "solver-axeyum") {
        "axeyum-native".to_string()
    } else if cfg!(feature = "solver-z3") {
        unreachable!("solver-z3 implies the authoritative solver-axeyum feature")
    } else {
        "none".to_string()
    }
}

#[cfg(feature = "symbolic")]
fn counterfactual_unknown(
    reason_kind: CounterfactualUnknownReason,
    reason: impl Into<String>,
) -> BranchCounterfactual {
    BranchCounterfactual::Unknown {
        reason_kind,
        reason: reason.into(),
        proposition_status: CounterfactualPropositionStatus::NotConstructed,
        bounds: None,
        path_conditions: Vec::new(),
    }
}

#[cfg(feature = "symbolic")]
fn counterfactual_unknown_with_proposition(
    reason_kind: CounterfactualUnknownReason,
    reason: impl Into<String>,
    bounds: CounterfactualBounds,
    path_conditions: Vec<CounterfactualPathCondition>,
) -> BranchCounterfactual {
    BranchCounterfactual::Unknown {
        reason_kind,
        reason: reason.into(),
        proposition_status: CounterfactualPropositionStatus::Bounded,
        bounds: Some(bounds),
        path_conditions,
    }
}

#[cfg(feature = "symbolic")]
const fn counterfactual_solver_unknown_reason(
    reason: crate::symbolic::solver::SolveUnknownReason,
) -> CounterfactualUnknownReason {
    match reason {
        crate::symbolic::solver::SolveUnknownReason::WallTimeout => {
            CounterfactualUnknownReason::SolverTimeout
        }
        crate::symbolic::solver::SolveUnknownReason::ResourceLimit => {
            CounterfactualUnknownReason::SolverResourceLimit
        }
        crate::symbolic::solver::SolveUnknownReason::Other => {
            CounterfactualUnknownReason::SolverError
        }
    }
}

#[cfg(feature = "symbolic")]
fn exact_llir_operation(image: &ProgramImage, operation: &StaticOperation) -> Result<Op, String> {
    let function = discover_function_image_at(image, &Budgets::default(), operation.function_entry)
        .ok_or_else(|| "counterfactual could not rediscover the observed function".to_string())?;
    let lifted = lift_function_from_image(image, &function)
        .map_err(|error| format!("counterfactual could not lift the observed function: {error}"))?;
    let block = lifted
        .blocks
        .iter()
        .find(|block| block.start_va == operation.block_start)
        .ok_or_else(|| "counterfactual could not find the observed LLIR block".to_string())?;
    let instruction = block
        .instrs
        .get(operation.operation_index)
        .filter(|instruction| instruction.va == operation.machine_va)
        .ok_or_else(|| "counterfactual LLIR operation identity disagrees".to_string())?;
    Ok(instruction.op.clone())
}

#[cfg(feature = "symbolic")]
#[allow(clippy::too_many_arguments)]
fn negate_observed_input_branch(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    image: &ProgramImage,
    register_trace: &Result<BTreeMap<u64, BTreeMap<String, u64>>, String>,
    source: &RuntimeInputLocation,
    selected_operation: &StaticOperation,
    selected_edge: &ObservedControlEdge,
    selected_sequence: u64,
    selected_thread: &Option<String>,
    input_spans: &[InputByteSpan],
    control_transfers: &[InstructionControlTransferRelation],
    lineage_id: u64,
    allow_retention: bool,
) -> BranchCounterfactual {
    if capsule.target.architecture != Arch::X86_64
        || capsule.target.endianness != Endianness::Little
    {
        return counterfactual_unknown(
            CounterfactualUnknownReason::UnsupportedSemantics,
            "runtime counterfactuals currently support little-endian x86-64 only",
        );
    }
    let Some(input_identity) = capsule
        .provenance
        .input_bytes
        .iter()
        .find(|input| input.name == source.source_name)
    else {
        return counterfactual_unknown(
            CounterfactualUnknownReason::MissingEnvironment,
            "counterfactual input identity is absent",
        );
    };
    if input_identity.sensitivity != Sensitivity::Public {
        return counterfactual_unknown(
            CounterfactualUnknownReason::PrivateInput,
            "counterfactual witness bytes are withheld for a non-public input",
        );
    }
    let mut events = capsule
        .events
        .iter()
        .filter(|event| {
            event.kind == "instruction_step"
                && event.process_id == source.process_id
                && &event.thread_id == selected_thread
                && event.sequence <= selected_sequence
        })
        .collect::<Vec<_>>();
    events.sort_by_key(|event| event.sequence);
    let Some(first_exact_position) = events.iter().position(|event| {
        let Some(runtime_va) = event.address else {
            return false;
        };
        let AddressResolution::Exact { address } =
            resolve_runtime_address(capsule, payloads, image, &event.process_id, runtime_va)
        else {
            return false;
        };
        matches!(
            address.code,
            StaticCodeResolution::Resolved {
                operations: OperationResolution::Resolved { operations },
                instruction_relation: InstructionRelation::Exact,
                ..
            } if operations
                .iter()
                .any(|operation| operation.function_entry == selected_operation.function_entry)
        )
    }) else {
        return counterfactual_unknown(
            CounterfactualUnknownReason::MissingEnvironment,
            "counterfactual has no exact instruction in the selected function",
        );
    };
    events.drain(..first_exact_position);
    let Some(first_event) = events.first().copied() else {
        return counterfactual_unknown(
            CounterfactualUnknownReason::MissingEnvironment,
            "counterfactual has no observed instruction prefix",
        );
    };
    let observed_instruction_count = events.len() as u64;
    let first_event_sequence = first_event.sequence;
    let Evidence::Observed {
        value: initial_registers,
        ..
    } = registers_for_step(register_trace, first_event)
    else {
        return counterfactual_unknown(
            CounterfactualUnknownReason::MissingEnvironment,
            "counterfactual initial registers are unavailable",
        );
    };

    let mut machine = Machine::new_with_arch(Symbolic::new(), RegArch::X86_64);
    for parent in crate::ir::regview::gp_views(RegArch::X86_64)
        .filter(|view| view.is_parent())
        .map(|view| view.parent)
    {
        let Some(value) = initial_registers.get(parent).copied() else {
            return counterfactual_unknown(
                CounterfactualUnknownReason::MissingEnvironment,
                format!("counterfactual initial register {parent} is unavailable"),
            );
        };
        let value = machine.dom.constant(Width::W64, u128::from(value));
        machine
            .regs
            .write(&mut machine.dom, &VReg::Phys(parent.to_string()), value);
    }
    if let Some(eflags) = initial_registers.get("eflags").copied() {
        for (flag, bit) in [
            (Flag::C, 0u32),
            (Flag::P, 2),
            (Flag::A, 4),
            (Flag::Z, 6),
            (Flag::S, 7),
            (Flag::D, 10),
            (Flag::O, 11),
        ] {
            let value = machine
                .dom
                .constant(Width::W1, u128::from((eflags >> bit) & 1));
            machine
                .regs
                .write(&mut machine.dom, &VReg::Flag(flag), value);
        }
    }

    let Some(snapshot_sequence) = capsule
        .object_snapshots
        .iter()
        .filter(|snapshot| {
            snapshot.process_id == source.process_id
                && snapshot.point.thread_id == first_event.thread_id
                && snapshot.point.sequence < first_event.sequence
        })
        .map(|snapshot| snapshot.point.sequence)
        .max()
    else {
        return counterfactual_unknown(
            CounterfactualUnknownReason::MissingEnvironment,
            "counterfactual requires a preceding memory snapshot",
        );
    };
    let snapshots = capsule.object_snapshots.iter().filter(|snapshot| {
        snapshot.process_id == source.process_id
            && snapshot.point.thread_id == first_event.thread_id
            && snapshot.point.sequence == snapshot_sequence
    });
    let mut captured_memory_byte_count = 0u64;
    for snapshot in snapshots {
        let Some(object) = capsule.runtime_objects.iter().find(|object| {
            object.id == snapshot.object_id && object.process_id == snapshot.process_id
        }) else {
            return counterfactual_unknown(
                CounterfactualUnknownReason::MissingEnvironment,
                format!(
                    "counterfactual snapshot {} has no runtime object",
                    snapshot.id
                ),
            );
        };
        let Some(start) = object.start.checked_add(snapshot.object_offset) else {
            return counterfactual_unknown(
                CounterfactualUnknownReason::MissingEnvironment,
                "counterfactual snapshot address overflowed",
            );
        };
        let PageContent::Captured { payload } = &snapshot.content else {
            return counterfactual_unknown(
                CounterfactualUnknownReason::MissingEnvironment,
                format!("counterfactual snapshot {} bytes were omitted", snapshot.id),
            );
        };
        let Some(bytes) = payloads.get(&payload.id) else {
            return counterfactual_unknown(
                CounterfactualUnknownReason::MissingEnvironment,
                format!(
                    "counterfactual snapshot payload {} is unavailable",
                    payload.id
                ),
            );
        };
        if bytes.len() as u64 != snapshot.byte_len
            || bytes.len() as u64 != payload.byte_len
            || hex::encode(Sha256::digest(bytes)) != payload.sha256
        {
            return counterfactual_unknown(
                CounterfactualUnknownReason::MissingEnvironment,
                format!(
                    "counterfactual snapshot payload {} is inconsistent",
                    payload.id
                ),
            );
        }
        let Some(next_captured_memory_byte_count) =
            captured_memory_byte_count.checked_add(snapshot.byte_len)
        else {
            return counterfactual_unknown(
                CounterfactualUnknownReason::MissingEnvironment,
                "counterfactual captured-memory byte count overflowed",
            );
        };
        captured_memory_byte_count = next_captured_memory_byte_count;
        for (offset, byte) in bytes.iter().copied().enumerate() {
            let value = machine.dom.constant(Width::W8, u128::from(byte));
            machine.mem.store(
                &mut machine.dom,
                start + offset as u64,
                &value,
                1,
                Endian::Little,
            );
        }
    }

    let symbolic_offsets = input_spans
        .iter()
        .flat_map(|span| span.source_offset..span.source_offset + span.byte_len)
        .collect::<BTreeSet<_>>();
    let mut symbols = BTreeMap::<u32, (u64, u8)>::new();
    for offset in &symbolic_offsets {
        let Some(address) = source.runtime_address.checked_add(*offset) else {
            return counterfactual_unknown(
                CounterfactualUnknownReason::MissingEnvironment,
                "counterfactual input address overflowed",
            );
        };
        if !machine.mem.is_initialized(address, 1) {
            return counterfactual_unknown(
                CounterfactualUnknownReason::MissingEnvironment,
                format!("counterfactual input byte {offset} was not captured"),
            );
        }
        let original = machine
            .mem
            .load(&mut machine.dom, address, 1, Endian::Little);
        let Some(original) = machine.dom.as_u64(&original).map(|value| value as u8) else {
            return counterfactual_unknown(
                CounterfactualUnknownReason::MissingEnvironment,
                "counterfactual input snapshot was not concrete",
            );
        };
        let symbol = machine.dom.fresh(Width::W8);
        let Expr::Sym { id, .. } = *machine.dom.pool.get(symbol) else {
            unreachable!("fresh symbolic input did not produce a symbol")
        };
        machine
            .mem
            .store(&mut machine.dom, address, &symbol, 1, Endian::Little);
        symbols.insert(id, (*offset, original));
    }

    let mut assertions = Vec::new();
    let mut path_conditions = Vec::new();
    for event in events {
        let Some(runtime_va) = event.address else {
            return counterfactual_unknown(
                CounterfactualUnknownReason::MissingEnvironment,
                "counterfactual event has no instruction address",
            );
        };
        let resolution =
            resolve_runtime_address(capsule, payloads, image, &event.process_id, runtime_va);
        let AddressResolution::Exact { address } = resolution else {
            return counterfactual_unknown(
                CounterfactualUnknownReason::UnsupportedSemantics,
                format!(
                    "counterfactual instruction {} is not exactly resolved",
                    event.sequence
                ),
            );
        };
        let StaticCodeResolution::Resolved {
            operations: OperationResolution::Resolved { operations },
            instruction_relation: InstructionRelation::Exact,
            instruction_end,
            ..
        } = address.code
        else {
            return counterfactual_unknown(
                CounterfactualUnknownReason::UnsupportedSemantics,
                format!(
                    "counterfactual instruction {} has no exact LLIR",
                    event.sequence
                ),
            );
        };
        for operation in operations {
            let llir = match exact_llir_operation(image, &operation) {
                Ok(operation) => operation,
                Err(reason) => {
                    return counterfactual_unknown(
                        CounterfactualUnknownReason::UnsupportedSemantics,
                        reason,
                    )
                }
            };
            if let Op::CondJump { cond, inverted, .. } = &llir {
                let condition = machine.regs.read(&mut machine.dom, cond);
                let is_selected = operation == *selected_operation;
                let Some(edge) = (if is_selected {
                    Some(selected_edge)
                } else {
                    control_transfers
                        .iter()
                        .find(|transfer| {
                            transfer.process_id == event.process_id
                                && transfer.thread_id == event.thread_id
                                && transfer.sequence == event.sequence
                                && evidence_value(&transfer.static_operation)
                                    .is_some_and(|candidate| candidate == &operation)
                        })
                        .and_then(|transfer| evidence_value(&transfer.edge))
                }) else {
                    return counterfactual_unknown(
                        CounterfactualUnknownReason::MissingEnvironment,
                        "counterfactual branch has no exact observed edge",
                    );
                };
                let desired_taken = if is_selected {
                    !edge.branch_taken
                } else {
                    edge.branch_taken
                };
                assertions.push((condition, desired_taken != *inverted));
                path_conditions.push(CounterfactualPathCondition {
                    sequence: event.sequence,
                    static_operation: operation.clone(),
                    required_branch_taken: desired_taken,
                    role: if is_selected {
                        "negated_target".to_string()
                    } else {
                        "observed_prefix".to_string()
                    },
                });
                if is_selected {
                    let backend = counterfactual_solver_backend();
                    let asserted_path_conditions = assertions.len() as u64;
                    let bounds = CounterfactualBounds {
                        first_event_sequence,
                        last_event_sequence: event.sequence,
                        observed_instruction_count,
                        symbolic_input_byte_count: symbols.len() as u64,
                        memory_snapshot_sequence: snapshot_sequence,
                        captured_memory_byte_count,
                        solver_timeout_ms: crate::symbolic::check_timeout_ms(),
                    };
                    let persistent_assertions = assertions.len().saturating_sub(1);
                    let mut persistent_prefix =
                        crate::symbolic::solver::WarmAssertionPrefix::default();
                    for assertion in &assertions[..persistent_assertions] {
                        if let Err(error) =
                            persistent_prefix.push_native(&machine.dom.pool, *assertion)
                        {
                            return counterfactual_unknown_with_proposition(
                                CounterfactualUnknownReason::SolverError,
                                format!("counterfactual native prefix identity: {error}"),
                                bounds,
                                path_conditions,
                            );
                        }
                    }
                    return match crate::symbolic::solver::solve_runtime_for_path_delta_with_retention(
                        &machine.dom.pool,
                        &assertions,
                        lineage_id,
                        persistent_assertions,
                        &persistent_prefix,
                        allow_retention,
                    )
                    .0
                    {
                        SolveResult::Sat(model) => {
                            let mutations = symbols
                                .iter()
                                .filter_map(|(id, (offset, original))| {
                                    let replacement = model.values.get(id).copied()? as u8;
                                    (replacement != *original).then(|| InputByteMutation {
                                        source_id: source.source_id.clone(),
                                        source_offset: *offset,
                                        replacement_hex: format!("{replacement:02x}"),
                                    })
                                })
                                .collect::<Vec<_>>();
                            if mutations.is_empty() {
                                counterfactual_unknown_with_proposition(
                                    CounterfactualUnknownReason::SolverError,
                                    "satisfying model did not mutate any attributed input byte",
                                    bounds,
                                    path_conditions,
                                )
                            } else {
                                BranchCounterfactual::Satisfiable {
                                    backend,
                                    asserted_path_conditions,
                                    bounds,
                                    path_conditions,
                                    predicted_branch_taken: desired_taken,
                                    predicted_target_static_va: if desired_taken {
                                        edge.declared_target_static_va
                                    } else {
                                        instruction_end
                                    },
                                    mutations,
                                }
                            }
                        }
                        SolveResult::Unsat => BranchCounterfactual::Unsatisfiable {
                            backend,
                            asserted_path_conditions,
                            bounds,
                            path_conditions,
                        },
                        SolveResult::Unknown(reason) => counterfactual_unknown_with_proposition(
                            counterfactual_solver_unknown_reason(reason),
                            format!("counterfactual solver returned {reason:?}"),
                            bounds,
                            path_conditions,
                        ),
                        SolveResult::NoSolver => counterfactual_unknown_with_proposition(
                            CounterfactualUnknownReason::NoSolver,
                            "no counterfactual solver backend is available",
                            bounds,
                            path_conditions,
                        ),
                        SolveResult::Error(error) => counterfactual_unknown_with_proposition(
                            CounterfactualUnknownReason::SolverError,
                            format!("counterfactual solver failed: {error}"),
                            bounds,
                            path_conditions,
                        ),
                    };
                }
                continue;
            }
            if let Some(memory) = operation_memory_operand(&llir) {
                let address = machine.eval_addr(memory);
                let Some(address) = machine.dom.as_u64(&address) else {
                    return counterfactual_unknown(
                        CounterfactualUnknownReason::SymbolicPointer,
                        format!(
                            "counterfactual memory address is symbolic at sequence {}",
                            event.sequence
                        ),
                    );
                };
                if !(0..u64::from(memory.size))
                    .all(|offset| machine.mem.is_initialized(address + offset, 1))
                {
                    return counterfactual_unknown(
                        CounterfactualUnknownReason::MissingEnvironment,
                        format!(
                            "counterfactual memory is unavailable at sequence {}",
                            event.sequence
                        ),
                    );
                }
            }
            match machine.step(&llir) {
                Flow::Next | Flow::Jump(_) => {}
                Flow::Halt(reason) => {
                    return counterfactual_unknown(
                        CounterfactualUnknownReason::UnsupportedSemantics,
                        format!("counterfactual replay halted at sequence {}: {reason:?}", event.sequence),
                    )
                }
                Flow::Call(_) | Flow::Return | Flow::Branch { .. } => {
                    return counterfactual_unknown(
                        CounterfactualUnknownReason::UnsupportedSemantics,
                        format!("counterfactual replay crossed an unsupported control boundary at sequence {}", event.sequence),
                    )
                }
            }
        }
    }
    counterfactual_unknown(
        CounterfactualUnknownReason::MissingEnvironment,
        "selected branch was absent from its observed prefix",
    )
}

fn register_taint(provenance: &BTreeMap<String, BTreeSet<u64>>, register: &str) -> BTreeSet<u64> {
    provenance
        .iter()
        .filter(|(candidate, _)| same_x86_register(candidate, register))
        .flat_map(|(_, offsets)| offsets.iter().copied())
        .collect()
}

fn clear_register_provenance(provenance: &mut BTreeMap<String, BTreeSet<u64>>, register: &str) {
    provenance.retain(|candidate, _| !same_x86_register(candidate, register));
}

fn source_offsets_to_spans(source_id: &str, offsets: &BTreeSet<u64>) -> Vec<InputByteSpan> {
    let mut spans = Vec::new();
    let mut iter = offsets.iter().copied();
    let Some(mut start) = iter.next() else {
        return spans;
    };
    let mut end = start + 1;
    for offset in iter {
        if offset == end {
            end += 1;
        } else {
            spans.push(InputByteSpan {
                source_id: source_id.to_string(),
                source_offset: start,
                byte_len: end - start,
            });
            start = offset;
            end = offset + 1;
        }
    }
    spans.push(InputByteSpan {
        source_id: source_id.to_string(),
        source_offset: start,
        byte_len: end - start,
    });
    spans
}

fn locate_invocation_inputs(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
) -> Vec<RuntimeInputLocationRelation> {
    const MAX_HASH_WINDOWS: usize = 1 << 20;
    input_provenance(capsule)
        .sources
        .into_iter()
        .filter(|source| source.name.starts_with("argv[") && source.name.ends_with(']'))
        .map(|source| {
            if let Some(location) = locate_declared_invocation_input(capsule, payloads, &source) {
                return RuntimeInputLocationRelation {
                    source_id: source.id.clone(),
                    source_name: source.name.clone(),
                    location,
                };
            }
            let mut candidates = Vec::new();
            let mut examined = 0usize;
            let mut failure = None;
            if source.byte_len == 0 {
                failure =
                    Some("zero-length invocation input has no unique memory interval".to_string());
            }
            for page in &capsule.pages {
                if failure.is_some() {
                    break;
                }
                let PageContent::Captured { payload } = &page.content else {
                    continue;
                };
                let Some(bytes) = payloads.get(&payload.id) else {
                    failure = Some(format!(
                        "captured page payload {} is unavailable",
                        payload.id
                    ));
                    break;
                };
                if bytes.len() as u64 != page.byte_len
                    || payload.byte_len != page.byte_len
                    || hex::encode(Sha256::digest(bytes)) != payload.sha256
                {
                    failure = Some(format!(
                        "captured page payload {} disagrees with its identity",
                        payload.id
                    ));
                    break;
                }
                let Ok(byte_len) = usize::try_from(source.byte_len) else {
                    failure = Some("invocation input extent exceeds host limits".to_string());
                    break;
                };
                if byte_len == 0 || byte_len > bytes.len() {
                    continue;
                }
                let windows = bytes.len() - byte_len + 1;
                if examined.saturating_add(windows) > MAX_HASH_WINDOWS {
                    failure = Some(
                        "invocation input memory search exceeded its hash-window budget"
                            .to_string(),
                    );
                    break;
                }
                examined += windows;
                for (offset, window) in bytes.windows(byte_len).enumerate() {
                    if hex::encode(Sha256::digest(window)) == source.sha256 {
                        candidates.push(RuntimeInputLocation {
                            source_id: source.id.clone(),
                            source_name: source.name.clone(),
                            process_id: page.process_id.clone(),
                            mapping_id: page.mapping_id.clone(),
                            page_start: page.start,
                            runtime_address: page.start + offset as u64,
                            byte_len: source.byte_len,
                        });
                    }
                }
            }
            let location = failure.map_or_else(
                || match candidates.as_slice() {
                    [location] => Evidence::Inferred {
                        value: location.clone(),
                        source: "unique hash-and-length match in a captured runtime page"
                            .to_string(),
                    },
                    [] => Evidence::Unknown {
                        reason: "invocation input bytes are absent from captured pages".to_string(),
                    },
                    _ => Evidence::Unknown {
                        reason: "invocation input bytes have multiple captured-page matches"
                            .to_string(),
                    },
                },
                |reason| Evidence::Unknown { reason },
            );
            RuntimeInputLocationRelation {
                source_id: source.id,
                source_name: source.name,
                location,
            }
        })
        .collect()
}

fn locate_declared_invocation_input(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    source: &InputSourceIdentity,
) -> Option<Evidence<RuntimeInputLocation>> {
    let declarations = capsule
        .events
        .iter()
        .filter(|event| {
            event.kind == "capture_checkpoint"
                && event.fields.get("phase").map(String::as_str) == Some("trace_begin")
                && event.fields.get("input_source_name") == Some(&source.name)
        })
        .collect::<Vec<_>>();
    if declarations.is_empty() {
        return None;
    }
    let [event] = declarations.as_slice() else {
        return Some(Evidence::Unknown {
            reason: "invocation input has multiple provider location declarations".to_string(),
        });
    };
    if event
        .fields
        .get("input_location_provider")
        .map(String::as_str)
        != Some("linux_proc_stat_argument_bounds")
        || event.fields.get("input_sha256") != Some(&source.sha256)
    {
        return Some(Evidence::Unknown {
            reason: "invocation input location declaration disagrees with source identity"
                .to_string(),
        });
    }
    let Some(runtime_address) = event
        .fields
        .get("input_runtime_address")
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return Some(Evidence::Unknown {
            reason: "invocation input location declaration has no valid address".to_string(),
        });
    };
    let Some(byte_len) = event
        .fields
        .get("input_byte_len")
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return Some(Evidence::Unknown {
            reason: "invocation input location declaration has no valid length".to_string(),
        });
    };
    if byte_len != source.byte_len {
        return Some(Evidence::Unknown {
            reason: "invocation input location length disagrees with source identity".to_string(),
        });
    }
    let Some(end) = runtime_address.checked_add(byte_len) else {
        return Some(Evidence::Unknown {
            reason: "invocation input location range overflowed".to_string(),
        });
    };
    let pages = capsule
        .pages
        .iter()
        .filter(|page| {
            page.process_id == event.process_id
                && page.start <= runtime_address
                && page
                    .start
                    .checked_add(page.byte_len)
                    .is_some_and(|page_end| end <= page_end)
        })
        .collect::<Vec<_>>();
    let [page] = pages.as_slice() else {
        return Some(Evidence::Unknown {
            reason: "declared invocation input is not contained by one captured page".to_string(),
        });
    };
    let PageContent::Captured { payload } = &page.content else {
        return Some(Evidence::Unknown {
            reason: "declared invocation input page bytes are unavailable".to_string(),
        });
    };
    let Some(encoded) = payloads.get(&payload.id) else {
        return Some(Evidence::Unknown {
            reason: "declared invocation input page payload is missing".to_string(),
        });
    };
    if encoded.len() as u64 != payload.byte_len
        || hex::encode(Sha256::digest(encoded)) != payload.sha256
    {
        return Some(Evidence::Unknown {
            reason: "declared invocation input page payload is invalid".to_string(),
        });
    }
    let Ok(start_offset) = usize::try_from(runtime_address - page.start) else {
        return Some(Evidence::Unknown {
            reason: "declared invocation input page offset overflowed".to_string(),
        });
    };
    let Ok(end_offset) = usize::try_from(end - page.start) else {
        return Some(Evidence::Unknown {
            reason: "declared invocation input page end overflowed".to_string(),
        });
    };
    if encoded
        .get(start_offset..end_offset)
        .is_none_or(|bytes| hex::encode(Sha256::digest(bytes)) != source.sha256)
    {
        return Some(Evidence::Unknown {
            reason: "declared invocation input bytes disagree with source identity".to_string(),
        });
    }
    Some(Evidence::Inferred {
        value: RuntimeInputLocation {
            source_id: source.id.clone(),
            source_name: source.name.clone(),
            process_id: event.process_id.clone(),
            mapping_id: page.mapping_id.clone(),
            page_start: page.start,
            runtime_address,
            byte_len,
        },
        source: "Linux proc argument bounds joined to one hash-verified captured page".to_string(),
    })
}

fn relate_executed_store_source_pointer(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    event: &super::capsule::EventRecord,
    image: &ProgramImage,
    operation: &StaticOperation,
    registers: &Evidence<BTreeMap<String, u64>>,
    effective_address: &Evidence<ObservedEffectiveAddress>,
) -> Evidence<ExecutedStoreSourcePointer> {
    let Evidence::Inferred {
        value: effective_address,
        ..
    } = effective_address
    else {
        return Evidence::Unknown {
            reason: "store source pointer requires a resolved effective address".to_string(),
        };
    };
    let Some(address_expression) = operation.address_expression.as_ref() else {
        return Evidence::Unknown {
            reason: "store address has no bounded static expression".to_string(),
        };
    };
    let mut frame_loads = BTreeSet::new();
    collect_loaded_frame_pointers(address_expression, &mut frame_loads);
    if frame_loads.is_empty() {
        return Evidence::Unknown {
            reason: "store address has no bounded frame-slot load".to_string(),
        };
    }
    let functions = image.dwarf_functions();
    let Some(function) = functions
        .iter()
        .find(|function| function.entry_va == operation.function_entry)
    else {
        return Evidence::Unknown {
            reason: "store function has no DWARF local-variable contract".to_string(),
        };
    };
    let candidates = frame_loads
        .iter()
        .flat_map(|(register, static_offset, pointer_byte_len)| {
            function.stack_objects.iter().filter_map(move |candidate| {
                let candidate_offset = match candidate.base {
                    DwarfStackBase::Register(candidate_register)
                        if candidate_register == *register =>
                    {
                        candidate.offset
                    }
                    DwarfStackBase::CallFrameCfa if *register == 6 => {
                        candidate.offset.checked_add(16)?
                    }
                    _ => return None,
                };
                let source_name = candidate.source_name.as_ref()?;
                let c_type = candidate.c_type.as_ref()?;
                (candidate_offset == *static_offset
                    && u16::from(*pointer_byte_len) == candidate.byte_size
                    && c_type.contains('*'))
                .then_some((
                    candidate,
                    source_name,
                    c_type,
                    *pointer_byte_len,
                    *register,
                    *static_offset,
                ))
            })
        })
        .collect::<Vec<_>>();
    let [(candidate, source_name, c_type, pointer_byte_len, register, static_offset)] =
        candidates.as_slice()
    else {
        return Evidence::Unknown {
            reason: "store address does not identify one DWARF pointer local".to_string(),
        };
    };
    let (Some(declaration_offset), Some(type_offset)) = (
        candidate.declaration_debug_info_offset,
        candidate.type_debug_info_offset,
    ) else {
        return Evidence::Unknown {
            reason: "DWARF pointer local has no stable declaration or type identity".to_string(),
        };
    };
    let Some(semantic_value_id) = operation
        .semantic_values
        .iter()
        .find(|value| value.role == "memory_address")
        .map(|value| value.id.clone())
    else {
        return Evidence::Unknown {
            reason: "store address has no static semantic value identity".to_string(),
        };
    };
    let Evidence::Observed {
        value: registers, ..
    } = registers
    else {
        return Evidence::Unknown {
            reason: "store source pointer requires occurrence registers".to_string(),
        };
    };
    let Some(frame_base) = (*register == 6)
        .then(|| registers.get("rbp").copied())
        .flatten()
    else {
        return Evidence::Unknown {
            reason: "store source pointer frame register is unavailable".to_string(),
        };
    };
    let pointer_address = frame_base.wrapping_add_signed(*static_offset);
    let pointer_bytes = match read_stack_bytes_before_event(
        capsule,
        payloads,
        event,
        pointer_address,
        *pointer_byte_len,
    ) {
        Ok(value) => value,
        Err(reason) => return Evidence::Unknown { reason },
    };
    if pointer_bytes.is_empty() || pointer_bytes.len() > 8 {
        return Evidence::Unknown {
            reason: "store source pointer width is unsupported".to_string(),
        };
    }
    let mut encoded_pointer = [0u8; 8];
    encoded_pointer[..pointer_bytes.len()].copy_from_slice(&pointer_bytes);
    let pointer_value = u64::from_le_bytes(encoded_pointer);
    let matching_objects = capsule
        .runtime_objects
        .iter()
        .filter(|object| {
            object.process_id == event.process_id
                && object.start <= pointer_value
                && object
                    .start
                    .checked_add(object.byte_len)
                    .is_some_and(|end| pointer_value < end)
                && object.start <= effective_address.effective_address
                && object
                    .start
                    .checked_add(object.byte_len)
                    .is_some_and(|end| {
                        effective_address
                            .effective_address
                            .checked_add(u64::from(effective_address.byte_len))
                            .is_some_and(|write_end| write_end <= end)
                    })
        })
        .collect::<Vec<_>>();
    let [runtime_object] = matching_objects.as_slice() else {
        return Evidence::Unknown {
            reason: "store source pointer and effect do not share one runtime object".to_string(),
        };
    };
    let Some(store_offset_from_pointer) = effective_address
        .effective_address
        .checked_sub(pointer_value)
    else {
        return Evidence::Unknown {
            reason: "store effective address precedes its source pointer".to_string(),
        };
    };
    let static_type =
        crate::ir::function_ir::dwarf_static_type(&operation.image_sha256, type_offset, c_type);
    let static_variable = crate::ir::function_ir::dwarf_static_variable(
        &operation.image_sha256,
        &operation.function_id,
        declaration_offset,
        source_name,
        &static_type.id,
    );
    let semantic_binding = crate::ir::function_ir::semantic_value_variable_binding(
        &semantic_value_id,
        &static_variable.id,
        "reads_pointer_value_from",
    );
    Evidence::Inferred {
        value: ExecutedStoreSourcePointer {
            runtime_object_id: runtime_object.id.clone(),
            static_variable,
            static_type,
            semantic_binding,
            source_name: (*source_name).clone(),
            c_type: (*c_type).clone(),
            function_entry: function.entry_va,
            static_base: match candidate.base {
                DwarfStackBase::Register(value) => format!("dwarf_register_{value}"),
                DwarfStackBase::CallFrameCfa => "dwarf_call_frame_cfa".to_string(),
            },
            static_offset: candidate.offset,
            pointer_byte_len: *pointer_byte_len,
            pointer_value,
            pointer_object_offset: pointer_value - runtime_object.start,
            store_offset_from_pointer,
            effective_address: effective_address.effective_address,
        },
        source: "bounded LLIR store-address slice, occurrence-time stack bytes, and observed registers joined to one DWARF pointer local and runtime object"
            .to_string(),
    }
}

fn relate_executed_store_allocation_prefix(
    capsule: &ProcessCapsule,
    image: &ProgramImage,
    source_pointer: &Evidence<ExecutedStoreSourcePointer>,
    store_occurrence: &Evidence<OperationOccurrence>,
    effective_address: &Evidence<ObservedEffectiveAddress>,
) -> Evidence<ExecutedStoreAllocationPrefix> {
    let Evidence::Inferred {
        value: source_pointer,
        ..
    } = source_pointer
    else {
        return Evidence::Unknown {
            reason: "allocation prefix requires a resolved source pointer".to_string(),
        };
    };
    let Evidence::Inferred {
        value: store_occurrence,
        ..
    } = store_occurrence
    else {
        return Evidence::Unknown {
            reason: "allocation prefix requires one executed store occurrence".to_string(),
        };
    };
    let Evidence::Inferred {
        value: effective_address,
        ..
    } = effective_address
    else {
        return Evidence::Unknown {
            reason: "allocation prefix requires a resolved store address".to_string(),
        };
    };
    let Some(object) = capsule.runtime_objects.iter().find(|object| {
        object.id == source_pointer.runtime_object_id
            && object.process_id == store_occurrence.process_id
    }) else {
        return Evidence::Unknown {
            reason: "allocation prefix source object is absent".to_string(),
        };
    };
    if source_pointer.pointer_value != object.start || source_pointer.pointer_object_offset != 0 {
        return Evidence::Unknown {
            reason: "allocation prefix source pointer does not equal the runtime object start"
                .to_string(),
        };
    }
    let creation_callsite = super::corruption::resolve_allocation_callsite(capsule, image, object);
    let creation = super::corruption::make_allocation_operation_occurrence(
        capsule,
        object,
        &creation_callsite,
    );
    let Evidence::Inferred {
        value: allocation_occurrence,
        ..
    } = creation
    else {
        return Evidence::Unknown {
            reason: "allocation prefix requires one allocation occurrence".to_string(),
        };
    };
    let observed_input = |name: &str| {
        allocation_occurrence
            .inputs
            .get(name)
            .and_then(|evidence| match evidence {
                Evidence::Observed { value, .. } => value.parse::<u64>().ok(),
                _ => None,
            })
    };
    if observed_input("count") != Some(1) || observed_input("element_size") != Some(object.byte_len)
    {
        return Evidence::Unknown {
            reason: "allocation prefix requires calloc(1, object_byte_len)".to_string(),
        };
    }
    let arguments = allocation_occurrence
        .static_operation
        .call_register_inputs
        .iter()
        .filter(|argument| argument.position == 1 && argument.abi_register == "rsi")
        .collect::<Vec<_>>();
    let [argument] = arguments.as_slice() else {
        return Evidence::Unknown {
            reason: "allocation prefix call has no unique element-size input".to_string(),
        };
    };
    let Some((extent_load, reserved_tail_byte_len)) = additive_frame_load(&argument.expression)
    else {
        return Evidence::Unknown {
            reason: "allocation size is not one frame load plus a constant tail".to_string(),
        };
    };
    let Some(logical_prefix_byte_len) = object.byte_len.checked_sub(reserved_tail_byte_len) else {
        return Evidence::Unknown {
            reason: "allocation tail exceeds its runtime object".to_string(),
        };
    };
    let StaticValueExpression::Load {
        address,
        byte_len: extent_byte_len,
    } = extent_load
    else {
        return Evidence::Unknown {
            reason: "allocation prefix term is not one frame load".to_string(),
        };
    };
    let Some((extent_register, extent_static_offset)) = frame_address(address) else {
        return Evidence::Unknown {
            reason: "allocation prefix frame load has no bounded address".to_string(),
        };
    };
    let functions = image.dwarf_functions();
    let Some(function) = functions.iter().find(|function| {
        function.entry_va == allocation_occurrence.static_operation.function_entry
    }) else {
        return Evidence::Unknown {
            reason: "allocation function has no DWARF local-variable contract".to_string(),
        };
    };
    let extent_candidates = function
        .stack_objects
        .iter()
        .filter_map(|candidate| {
            let candidate_offset = match candidate.base {
                DwarfStackBase::Register(register) if register == extent_register => {
                    candidate.offset
                }
                DwarfStackBase::CallFrameCfa if extent_register == 6 => {
                    candidate.offset.checked_add(16)?
                }
                _ => return None,
            };
            let source_name = candidate.source_name.as_ref()?;
            let c_type = candidate.c_type.as_ref()?;
            (candidate_offset == extent_static_offset
                && u16::from(*extent_byte_len) == candidate.byte_size
                && !c_type.contains('*'))
            .then_some((candidate, source_name, c_type))
        })
        .collect::<Vec<_>>();
    let [(extent_candidate, extent_source_name, extent_c_type)] = extent_candidates.as_slice()
    else {
        return Evidence::Unknown {
            reason: "allocation prefix load does not identify one DWARF scalar local".to_string(),
        };
    };
    let store_object_offset = effective_address.effective_address - object.start;
    let store_byte_len = u64::from(effective_address.byte_len);
    let prefix_bytes_exceeded = store_object_offset
        .saturating_add(store_byte_len)
        .saturating_sub(logical_prefix_byte_len);
    Evidence::Inferred {
        value: ExecutedStoreAllocationPrefix {
            runtime_object_id: object.id.clone(),
            extent_source_name: (*extent_source_name).clone(),
            extent_c_type: (*extent_c_type).clone(),
            extent_static_base: match extent_candidate.base {
                DwarfStackBase::Register(value) => format!("dwarf_register_{value}"),
                DwarfStackBase::CallFrameCfa => "dwarf_call_frame_cfa".to_string(),
            },
            extent_static_offset: extent_candidate.offset,
            allocation_argument_position: argument.position,
            allocation_abi_register: argument.abi_register.clone(),
            logical_prefix_byte_len,
            reserved_tail_byte_len,
            allocation_byte_len: object.byte_len,
            store_object_offset,
            store_byte_len,
            prefix_bytes_exceeded,
            classification: if prefix_bytes_exceeded == 0 {
                "within_allocation_prefix"
            } else {
                "crosses_allocation_prefix_within_object"
            }
            .to_string(),
            allocation_occurrence,
            store_occurrence: store_occurrence.clone(),
            source_pointer: source_pointer.clone(),
        },
        source: "observed allocation and store occurrences joined through independent bounded LLIR slices, DWARF extent and pointer locals, and one runtime object"
            .to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn relate_executed_store_allocation_tail(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    event: &super::capsule::EventRecord,
    image: &ProgramImage,
    registers: &Evidence<BTreeMap<String, u64>>,
    effective_address: &Evidence<ObservedEffectiveAddress>,
    allocation_prefix: &Evidence<ExecutedStoreAllocationPrefix>,
    object_transition: &Evidence<ExecutedStoreObjectTransition>,
) -> Evidence<ExecutedStoreAllocationTail> {
    let Evidence::Inferred { value: prefix, .. } = allocation_prefix else {
        return Evidence::Unknown {
            reason: "allocation tail requires a resolved allocation prefix".to_string(),
        };
    };
    let Evidence::Inferred {
        value: effective_address,
        ..
    } = effective_address
    else {
        return Evidence::Unknown {
            reason: "allocation tail requires a resolved store address".to_string(),
        };
    };
    let Evidence::Inferred {
        value: transition, ..
    } = object_transition
    else {
        return Evidence::Unknown {
            reason: "allocation tail requires a resolved object transition".to_string(),
        };
    };
    let Evidence::Observed {
        value: registers, ..
    } = registers
    else {
        return Evidence::Unknown {
            reason: "allocation tail requires occurrence registers".to_string(),
        };
    };
    let Some(frame_pointer) = registers.get("rbp").copied() else {
        return Evidence::Unknown {
            reason: "allocation tail frame register is unavailable".to_string(),
        };
    };
    let Some(object) = capsule.runtime_objects.iter().find(|object| {
        object.id == prefix.runtime_object_id && object.process_id == event.process_id
    }) else {
        return Evidence::Unknown {
            reason: "allocation tail runtime object is absent".to_string(),
        };
    };
    let Some(tail_start) = object.start.checked_add(prefix.logical_prefix_byte_len) else {
        return Evidence::Unknown {
            reason: "allocation tail address overflowed".to_string(),
        };
    };
    let functions = image.dwarf_functions();
    let Some(function) = functions.iter().find(|function| {
        function.entry_va == prefix.store_occurrence.static_operation.function_entry
    }) else {
        return Evidence::Unknown {
            reason: "store function has no DWARF local-variable contract".to_string(),
        };
    };
    let mut matches = Vec::new();
    for candidate in &function.stack_objects {
        let (Some(source_name), Some(c_type)) =
            (candidate.source_name.as_ref(), candidate.c_type.as_ref())
        else {
            continue;
        };
        if !c_type.contains('*') || candidate.byte_size == 0 || candidate.byte_size > 8 {
            continue;
        }
        let pointer_address = match candidate.base {
            DwarfStackBase::Register(6) => frame_pointer.wrapping_add_signed(candidate.offset),
            DwarfStackBase::CallFrameCfa => frame_pointer
                .wrapping_add(16)
                .wrapping_add_signed(candidate.offset),
            DwarfStackBase::Register(_) => continue,
        };
        let pointer_byte_len = u8::try_from(candidate.byte_size).unwrap_or(0);
        let pointer_bytes = match read_stack_bytes_before_event(
            capsule,
            payloads,
            event,
            pointer_address,
            pointer_byte_len,
        ) {
            Ok(value) => value,
            Err(reason) => return Evidence::Unknown { reason },
        };
        let mut encoded_pointer = [0u8; 8];
        encoded_pointer[..pointer_bytes.len()].copy_from_slice(&pointer_bytes);
        let pointer_value = u64::from_le_bytes(encoded_pointer);
        if pointer_value != tail_start {
            continue;
        }
        let Some(pointee_byte_len) = fixed_width_pointer_pointee(c_type) else {
            continue;
        };
        if u64::from(pointee_byte_len) > prefix.reserved_tail_byte_len {
            continue;
        }
        matches.push((
            candidate,
            source_name,
            c_type,
            pointer_byte_len,
            pointer_value,
            pointee_byte_len,
        ));
    }
    let [(candidate, source_name, c_type, pointer_byte_len, pointer_value, pointee_byte_len)] =
        matches.as_slice()
    else {
        return Evidence::Unknown {
            reason: "allocation tail does not identify one occurrence-time DWARF pointer local"
                .to_string(),
        };
    };
    let snapshots = [
        transition.before_snapshot_id.as_str(),
        transition.stored_snapshot_id.as_str(),
        transition.final_snapshot_id.as_str(),
    ]
    .map(|id| {
        capsule.object_snapshots.iter().find(|snapshot| {
            snapshot.id == id
                && snapshot.process_id == event.process_id
                && snapshot.object_id == object.id
        })
    });
    let [Some(before), Some(stored), Some(final_snapshot)] = snapshots else {
        return Evidence::Unknown {
            reason: "allocation tail transition snapshots are absent".to_string(),
        };
    };
    let tail_offset = prefix.logical_prefix_byte_len;
    let before_bytes = match snapshot_range(before, payloads, tail_offset, *pointee_byte_len) {
        Ok(value) => value,
        Err(reason) => return Evidence::Unknown { reason },
    };
    let stored_bytes = match snapshot_range(stored, payloads, tail_offset, *pointee_byte_len) {
        Ok(value) => value,
        Err(reason) => return Evidence::Unknown { reason },
    };
    let final_bytes = match snapshot_range(final_snapshot, payloads, tail_offset, *pointee_byte_len)
    {
        Ok(value) => value,
        Err(reason) => return Evidence::Unknown { reason },
    };
    let store_start = effective_address.effective_address;
    let store_end = store_start.saturating_add(u64::from(effective_address.byte_len));
    let pointee_end = tail_start.saturating_add(u64::from(*pointee_byte_len));
    let store_overlap_byte_len = store_end
        .min(pointee_end)
        .saturating_sub(store_start.max(tail_start));
    Evidence::Inferred {
        value: ExecutedStoreAllocationTail {
            runtime_object_id: object.id.clone(),
            source_name: (*source_name).clone(),
            c_type: (*c_type).clone(),
            function_entry: function.entry_va,
            static_base: match candidate.base {
                DwarfStackBase::Register(value) => format!("dwarf_register_{value}"),
                DwarfStackBase::CallFrameCfa => "dwarf_call_frame_cfa".to_string(),
            },
            static_offset: candidate.offset,
            pointer_byte_len: *pointer_byte_len,
            pointer_value: *pointer_value,
            pointer_object_offset: tail_offset,
            pointee_byte_len: *pointee_byte_len,
            reserved_tail_byte_len: prefix.reserved_tail_byte_len,
            store_overlap_byte_len,
            before_snapshot_id: before.id.clone(),
            stored_snapshot_id: stored.id.clone(),
            final_snapshot_id: final_snapshot.id.clone(),
            before_hex: hex::encode(before_bytes),
            stored_hex: hex::encode(stored_bytes),
            final_hex: hex::encode(final_bytes),
        },
        source: "occurrence-time DWARF pointer value equal to the source-derived allocation tail, joined to three hash-verified runtime-object snapshots"
            .to_string(),
    }
}

fn fixed_width_pointer_pointee(c_type: &str) -> Option<u8> {
    match c_type.trim().trim_end_matches('*').trim() {
        "char" | "signed char" | "unsigned char" | "int8_t" | "uint8_t" => Some(1),
        "int16_t" | "uint16_t" => Some(2),
        "int32_t" | "uint32_t" => Some(4),
        "int64_t" | "uint64_t" => Some(8),
        _ => None,
    }
}

fn additive_frame_load(
    expression: &StaticValueExpression,
) -> Option<(&StaticValueExpression, u64)> {
    let (load, constant) = match expression {
        StaticValueExpression::Add { left, right } => match (&**left, &**right) {
            (
                load @ StaticValueExpression::Load { .. },
                StaticValueExpression::Constant { value },
            )
            | (
                StaticValueExpression::Constant { value },
                load @ StaticValueExpression::Load { .. },
            ) => (load, *value),
            _ => return None,
        },
        _ => return None,
    };
    Some((load, u64::try_from(constant).ok()?))
}

fn relate_executed_store_object_transition(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    event: &super::capsule::EventRecord,
    operation: &StaticOperation,
    effective_address: &Evidence<ObservedEffectiveAddress>,
) -> Evidence<ExecutedStoreObjectTransition> {
    let Evidence::Inferred {
        value: effective_address,
        ..
    } = effective_address
    else {
        return Evidence::Unknown {
            reason: "store transition requires a resolved effective address".to_string(),
        };
    };
    let objects = capsule
        .runtime_objects
        .iter()
        .filter(|object| {
            object.process_id == event.process_id
                && object.start <= effective_address.effective_address
                && object
                    .start
                    .checked_add(object.byte_len)
                    .is_some_and(|end| {
                        effective_address
                            .effective_address
                            .checked_add(u64::from(effective_address.byte_len))
                            .is_some_and(|write_end| write_end <= end)
                    })
        })
        .collect::<Vec<_>>();
    let [object] = objects.as_slice() else {
        return Evidence::Unknown {
            reason: "store transition requires one containing runtime object".to_string(),
        };
    };
    let mut snapshots = capsule
        .object_snapshots
        .iter()
        .filter(|snapshot| {
            snapshot.process_id == event.process_id
                && snapshot.object_id == object.id
                && snapshot.point.thread_id == event.thread_id
        })
        .collect::<Vec<_>>();
    snapshots.sort_by_key(|snapshot| snapshot.point.sequence);
    let before = snapshots
        .iter()
        .copied()
        .filter(|snapshot| snapshot.point.sequence < event.sequence)
        .next_back();
    let stored = snapshots
        .iter()
        .copied()
        .find(|snapshot| snapshot.point.sequence > event.sequence);
    let final_snapshot = snapshots.last().copied().filter(|snapshot| {
        stored.is_some_and(|stored| snapshot.point.sequence > stored.point.sequence)
    });
    let (Some(before), Some(stored), Some(final_snapshot)) = (before, stored, final_snapshot)
    else {
        return Evidence::Unknown {
            reason:
                "store transition requires snapshots before, after, and after subsequent execution"
                    .to_string(),
        };
    };
    let object_offset = effective_address.effective_address - object.start;
    let before_bytes =
        match snapshot_range(before, payloads, object_offset, effective_address.byte_len) {
            Ok(bytes) => bytes,
            Err(reason) => return Evidence::Unknown { reason },
        };
    let stored_bytes =
        match snapshot_range(stored, payloads, object_offset, effective_address.byte_len) {
            Ok(bytes) => bytes,
            Err(reason) => return Evidence::Unknown { reason },
        };
    let final_bytes = match snapshot_range(
        final_snapshot,
        payloads,
        object_offset,
        effective_address.byte_len,
    ) {
        Ok(bytes) => bytes,
        Err(reason) => return Evidence::Unknown { reason },
    };
    let Some(super::correlation::StaticValueExpression::Constant { value }) =
        operation.stored_value.as_ref()
    else {
        return Evidence::Unknown {
            reason: "store transition requires an immutable constant stored-value expression"
                .to_string(),
        };
    };
    let width = usize::from(effective_address.byte_len);
    if width == 0 || width > 8 || stored_bytes != &(*value as u64).to_le_bytes()[..width] {
        return Evidence::Unknown {
            reason: "post-store bytes disagree with the static stored-value expression".to_string(),
        };
    }
    Evidence::Inferred {
        value: ExecutedStoreObjectTransition {
            runtime_object_id: object.id.clone(),
            object_offset,
            byte_len: effective_address.byte_len,
            before_snapshot_id: before.id.clone(),
            stored_snapshot_id: stored.id.clone(),
            final_snapshot_id: final_snapshot.id.clone(),
            before_hex: hex::encode(before_bytes),
            stored_hex: hex::encode(stored_bytes),
            final_hex: hex::encode(final_bytes),
            changed_after_store: stored_bytes != final_bytes,
        },
        source: "one executed LLIR store and three ordered hash-verified runtime-object snapshots"
            .to_string(),
    }
}

fn snapshot_range<'a>(
    snapshot: &super::capsule::ObjectSnapshotRecord,
    payloads: &'a BTreeMap<String, Vec<u8>>,
    object_offset: u64,
    byte_len: u8,
) -> Result<&'a [u8], String> {
    let PageContent::Captured { payload } = &snapshot.content else {
        return Err(format!(
            "object snapshot {} bytes were omitted",
            snapshot.id
        ));
    };
    let bytes = payloads
        .get(&payload.id)
        .ok_or_else(|| format!("object snapshot {} payload is missing", snapshot.id))?;
    if bytes.len() as u64 != payload.byte_len
        || hex::encode(Sha256::digest(bytes)) != payload.sha256
    {
        return Err(format!(
            "object snapshot {} payload identity disagrees",
            snapshot.id
        ));
    }
    let relative = object_offset
        .checked_sub(snapshot.object_offset)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| format!("object snapshot {} starts after the store", snapshot.id))?;
    let end = relative
        .checked_add(usize::from(byte_len))
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| format!("object snapshot {} does not cover the store", snapshot.id))?;
    Ok(&bytes[relative..end])
}

fn read_stack_bytes_before_event(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    event: &super::capsule::EventRecord,
    address: u64,
    byte_len: u8,
) -> Result<Vec<u8>, String> {
    let end = address
        .checked_add(u64::from(byte_len))
        .ok_or_else(|| "store source pointer range overflowed".to_string())?;
    let candidates = capsule
        .runtime_objects
        .iter()
        .filter(|object| {
            object.process_id == event.process_id
                && object.kind == RuntimeObjectKind::Mapping
                && object.start <= address
                && object
                    .start
                    .checked_add(object.byte_len)
                    .is_some_and(|object_end| end <= object_end)
        })
        .flat_map(|object| {
            capsule.object_snapshots.iter().filter_map(move |snapshot| {
                let object_offset = address.checked_sub(object.start)?;
                (snapshot.process_id == event.process_id
                    && snapshot.object_id == object.id
                    && snapshot.point.thread_id == event.thread_id
                    && snapshot.point.sequence < event.sequence
                    && snapshot.object_offset <= object_offset
                    && snapshot
                        .object_offset
                        .checked_add(snapshot.byte_len)
                        .is_some_and(|snapshot_end| {
                            object_offset
                                .checked_add(u64::from(byte_len))
                                .is_some_and(|read_end| read_end <= snapshot_end)
                        }))
                .then_some((object, snapshot, object_offset))
            })
        })
        .collect::<Vec<_>>();
    let Some((_, snapshot, object_offset)) = candidates
        .iter()
        .max_by_key(|(_, snapshot, _)| snapshot.point.sequence)
        .copied()
    else {
        return Err("store source pointer has no preceding stack snapshot".to_string());
    };
    if candidates
        .iter()
        .filter(|(_, candidate, _)| candidate.point.sequence == snapshot.point.sequence)
        .count()
        != 1
    {
        return Err("store source pointer stack snapshot is ambiguous".to_string());
    }
    let mut bytes = snapshot_range(snapshot, payloads, object_offset, byte_len)?.to_vec();
    let mut prior_steps = capsule
        .events
        .iter()
        .filter(|candidate| {
            candidate.process_id == event.process_id
                && candidate.thread_id == event.thread_id
                && candidate.kind == "instruction_step"
                && snapshot.point.sequence < candidate.sequence
                && candidate.sequence < event.sequence
        })
        .collect::<Vec<_>>();
    prior_steps.sort_by_key(|candidate| candidate.sequence);
    for step in prior_steps {
        if !step.fields.contains_key("stack_changes_payload_id") {
            continue;
        }
        let (changes, _) = parse_step_evidence(step, payloads);
        let Evidence::Observed { value: changes, .. } = changes else {
            return Err(format!(
                "store source pointer cannot reconstruct stack step {}",
                step.sequence
            ));
        };
        for change in changes {
            let before = hex::decode(&change.before_hex)
                .map_err(|_| "store source pointer change bytes are malformed".to_string())?;
            let after = hex::decode(&change.after_hex)
                .map_err(|_| "store source pointer change bytes are malformed".to_string())?;
            let overlap_start = address.max(change.start);
            let overlap_end = end.min(change.end);
            if overlap_start >= overlap_end {
                continue;
            }
            for runtime_address in overlap_start..overlap_end {
                let pointer_index = usize::try_from(runtime_address - address)
                    .map_err(|_| "store source pointer offset overflowed".to_string())?;
                let change_index = usize::try_from(runtime_address - change.start)
                    .map_err(|_| "store source pointer change offset overflowed".to_string())?;
                if bytes[pointer_index] != before[change_index] {
                    return Err("store source pointer stack history disagrees".to_string());
                }
                bytes[pointer_index] = after[change_index];
            }
        }
    }
    Ok(bytes)
}

fn collect_loaded_frame_pointers(
    expression: &super::correlation::StaticValueExpression,
    loads: &mut BTreeSet<(u16, i64, u8)>,
) {
    use super::correlation::StaticValueExpression;
    match expression {
        StaticValueExpression::Load { address, byte_len } => {
            if let Some((register, offset)) = frame_address(address) {
                loads.insert((register, offset, *byte_len));
            }
            collect_loaded_frame_pointers(address, loads);
        }
        StaticValueExpression::Add { left, right }
        | StaticValueExpression::Subtract { left, right }
        | StaticValueExpression::Multiply { left, right }
        | StaticValueExpression::BitwiseAnd { left, right }
        | StaticValueExpression::BitwiseOr { left, right }
        | StaticValueExpression::BitwiseXor { left, right }
        | StaticValueExpression::Compare { left, right, .. } => {
            collect_loaded_frame_pointers(left, loads);
            collect_loaded_frame_pointers(right, loads);
        }
        StaticValueExpression::Truncate { value, .. }
        | StaticValueExpression::Extract { value, .. }
        | StaticValueExpression::ZeroExtend { value, .. }
        | StaticValueExpression::SignExtend { value, .. } => {
            collect_loaded_frame_pointers(value, loads);
        }
        StaticValueExpression::Register { .. }
        | StaticValueExpression::Constant { .. }
        | StaticValueExpression::Address { .. }
        | StaticValueExpression::CallResult { .. } => {}
    }
}

fn frame_address(expression: &super::correlation::StaticValueExpression) -> Option<(u16, i64)> {
    use super::correlation::StaticValueExpression;
    match expression {
        StaticValueExpression::Register { name } if name == "rbp" => Some((6, 0)),
        StaticValueExpression::Add { left, right } => match (&**left, &**right) {
            (address, StaticValueExpression::Constant { value })
            | (StaticValueExpression::Constant { value }, address) => {
                let (register, offset) = frame_address(address)?;
                Some((register, offset.checked_add(*value)?))
            }
            _ => None,
        },
        StaticValueExpression::Subtract { left, right } => {
            let StaticValueExpression::Constant { value } = &**right else {
                return None;
            };
            let (register, offset) = frame_address(left)?;
            Some((register, offset.checked_sub(*value)?))
        }
        _ => None,
    }
}

fn unique_store_operation(resolution: &AddressResolution) -> Option<&StaticOperation> {
    let AddressResolution::Exact { address } = resolution else {
        return None;
    };
    let StaticCodeResolution::Resolved {
        instruction_relation: InstructionRelation::Exact,
        operations: OperationResolution::Resolved { operations },
        ..
    } = &address.code
    else {
        return None;
    };
    let stores = operations
        .iter()
        .filter(|operation| operation.kind == "store")
        .collect::<Vec<_>>();
    let [store] = stores.as_slice() else {
        return None;
    };
    Some(store)
}

fn unique_load_operation(resolution: &AddressResolution) -> Option<&StaticOperation> {
    let AddressResolution::Exact { address } = resolution else {
        return None;
    };
    let StaticCodeResolution::Resolved {
        instruction_relation: InstructionRelation::Exact,
        operations: OperationResolution::Resolved { operations },
        ..
    } = &address.code
    else {
        return None;
    };
    let loads = operations
        .iter()
        .filter(|operation| operation.kind == "load")
        .collect::<Vec<_>>();
    let [load] = loads.as_slice() else {
        return None;
    };
    Some(load)
}

fn make_executed_load_occurrence(
    capsule: &ProcessCapsule,
    event: &super::capsule::EventRecord,
    static_operation: &StaticOperation,
    effective_address: &Evidence<ObservedEffectiveAddress>,
) -> Evidence<OperationOccurrence> {
    let Evidence::Inferred { value: address, .. } = effective_address else {
        return Evidence::Unknown {
            reason: "executed load occurrence requires a resolved effective address".to_string(),
        };
    };
    let containing_objects = capsule
        .runtime_objects
        .iter()
        .filter(|object| {
            object.process_id == event.process_id
                && object.start <= address.effective_address
                && object
                    .start
                    .checked_add(object.byte_len)
                    .is_some_and(|end| {
                        address
                            .effective_address
                            .checked_add(u64::from(address.byte_len))
                            .is_some_and(|read_end| read_end <= end)
                    })
                && object.created_at.sequence <= event.sequence
                && object
                    .ended_at
                    .as_ref()
                    .is_none_or(|ended| event.sequence < ended.sequence)
        })
        .collect::<Vec<_>>();
    let runtime_object_id = match containing_objects.as_slice() {
        [object] => Some(object.id.clone()),
        _ => None,
    };
    operation_occurrence(
        capsule,
        &event.process_id,
        event.thread_id.as_deref(),
        event.sequence,
        static_operation,
        BTreeMap::from([(
            "effective_address".to_string(),
            Evidence::Inferred {
                value: address.effective_address.to_string(),
                source:
                    "static LLIR memory operand evaluated with observed pre-instruction registers"
                        .to_string(),
            },
        )]),
        Vec::new(),
        Evidence::Unknown {
            reason: "load result is not yet joined to a post-instruction register".to_string(),
        },
        vec![OperationEffect {
            kind: "memory_read".to_string(),
            resource_id: None,
            runtime_object_id,
            errno: None,
            address: Some(address.effective_address),
            byte_len: Some(u64::from(address.byte_len)),
            input_source_id: None,
        }],
        "single-stepped instruction joined to one exact static LLIR load operation",
    )
}

fn make_executed_store_occurrence(
    capsule: &ProcessCapsule,
    event: &super::capsule::EventRecord,
    static_operation: &StaticOperation,
    effective_address: &Evidence<ObservedEffectiveAddress>,
) -> Evidence<OperationOccurrence> {
    let Evidence::Inferred { value: address, .. } = effective_address else {
        return Evidence::Unknown {
            reason: "executed store occurrence requires a resolved effective address".to_string(),
        };
    };
    let containing_objects = capsule
        .runtime_objects
        .iter()
        .filter(|object| {
            object.process_id == event.process_id
                && object.start <= address.effective_address
                && object
                    .start
                    .checked_add(object.byte_len)
                    .is_some_and(|end| {
                        address
                            .effective_address
                            .checked_add(u64::from(address.byte_len))
                            .is_some_and(|write_end| write_end <= end)
                    })
                && object.created_at.sequence <= event.sequence
                && object
                    .ended_at
                    .as_ref()
                    .is_none_or(|ended| event.sequence < ended.sequence)
        })
        .collect::<Vec<_>>();
    let runtime_object_id = match containing_objects.as_slice() {
        [object] => Some(object.id.clone()),
        _ => None,
    };
    operation_occurrence(
        capsule,
        &event.process_id,
        event.thread_id.as_deref(),
        event.sequence,
        static_operation,
        BTreeMap::from([(
            "effective_address".to_string(),
            Evidence::Inferred {
                value: address.effective_address.to_string(),
                source:
                    "static LLIR memory operand evaluated with observed pre-instruction registers"
                        .to_string(),
            },
        )]),
        Vec::new(),
        Evidence::Unknown {
            reason: "store operation has no scalar output".to_string(),
        },
        vec![OperationEffect {
            kind: "memory_write".to_string(),
            resource_id: None,
            runtime_object_id,
            errno: None,
            address: Some(address.effective_address),
            byte_len: Some(u64::from(address.byte_len)),
            input_source_id: None,
        }],
        "single-stepped instruction joined to one exact static LLIR store operation",
    )
}

fn parse_register_trace(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<u64, BTreeMap<String, u64>>, String> {
    let reference = capsule
        .extensions
        .get("provider.ptrace_single_step")
        .and_then(|value| value.get("register_trace"))
        .ok_or_else(|| "instruction register-trace payload reference is absent".to_string())?;
    let payload_id = reference
        .get("payload_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "instruction register-trace payload identity is absent".to_string())?;
    let expected_hash = reference
        .get("sha256")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "instruction register-trace payload hash is absent".to_string())?;
    let expected_len = reference
        .get("byte_len")
        .and_then(|value| value.as_u64())
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "instruction register-trace payload length is absent".to_string())?;
    let expected_steps = reference
        .get("step_count")
        .and_then(|value| value.as_u64())
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "instruction register-trace step count is absent".to_string())?;
    let encoded = payloads
        .get(payload_id)
        .ok_or_else(|| format!("instruction register-trace payload {payload_id} is unavailable"))?;
    if encoded.len() != expected_len || hex::encode(Sha256::digest(encoded)) != expected_hash {
        return Err("instruction register-trace payload disagrees with its identity".to_string());
    }
    let payload: InstructionRegisterTracePayload = serde_json::from_slice(encoded)
        .map_err(|_| "instruction register-trace payload is malformed".to_string())?;
    if payload.schema != "glaurung-instruction-register-trace-v1" {
        return Err("instruction register-trace schema is unsupported".to_string());
    }
    let events = capsule
        .events
        .iter()
        .filter(|event| event.kind == "instruction_step")
        .collect::<Vec<_>>();
    if payload.steps.len() != expected_steps || payload.steps.len() != events.len() {
        return Err("instruction register-trace count disagrees with public events".to_string());
    }
    let mut result = BTreeMap::new();
    for step in payload.steps {
        let event = events
            .iter()
            .find(|event| event.sequence == step.sequence)
            .ok_or_else(|| {
                "instruction register-trace sequence is absent from public events".to_string()
            })?;
        if event.address != Some(step.address) {
            return Err(
                "instruction register-trace address disagrees with public event".to_string(),
            );
        }
        let mut registers = BTreeMap::new();
        for (name, encoded) in step.registers {
            let value = u64::from_str_radix(&encoded, 16)
                .map_err(|_| format!("instruction register-trace register {name} is malformed"))?;
            registers.insert(name, value);
        }
        if registers.is_empty() {
            return Err("instruction register-trace register set is empty".to_string());
        }
        if result.insert(step.sequence, registers).is_some() {
            return Err("instruction register-trace sequence is duplicated".to_string());
        }
    }
    Ok(result)
}

fn registers_for_step(
    trace: &Result<BTreeMap<u64, BTreeMap<String, u64>>, String>,
    event: &super::capsule::EventRecord,
) -> Evidence<BTreeMap<String, u64>> {
    match trace {
        Ok(steps) => steps.get(&event.sequence).cloned().map_or_else(
            || Evidence::Unknown {
                reason: "instruction register-trace step is absent".to_string(),
            },
            |value| Evidence::Observed {
                value,
                source: "hash-bound ptrace pre-instruction register trace".to_string(),
            },
        ),
        Err(reason) => Evidence::Unknown {
            reason: reason.clone(),
        },
    }
}

fn resolve_call_semantics(
    resolution: &AddressResolution,
) -> (Option<&StaticOperation>, Evidence<u64>, Evidence<String>) {
    let AddressResolution::Exact { address } = resolution else {
        let reason = "call semantics require exact static address resolution".to_string();
        return (
            None,
            Evidence::Unknown {
                reason: reason.clone(),
            },
            Evidence::Unknown { reason },
        );
    };
    let StaticCodeResolution::Resolved {
        instruction_relation: InstructionRelation::Exact,
        operations: OperationResolution::Resolved { operations },
        ..
    } = &address.code
    else {
        let reason = "call step has no exact resolved LLIR operations".to_string();
        return (
            None,
            Evidence::Unknown {
                reason: reason.clone(),
            },
            Evidence::Unknown { reason },
        );
    };
    let calls = operations
        .iter()
        .filter(|operation| operation.kind == "call")
        .collect::<Vec<_>>();
    let [operation] = calls.as_slice() else {
        let reason = "call step does not identify exactly one LLIR call operation".to_string();
        return (
            None,
            Evidence::Unknown {
                reason: reason.clone(),
            },
            Evidence::Unknown { reason },
        );
    };
    let Some(StaticCallTarget::Direct { address, symbol }) = &operation.call_target else {
        let reason = "LLIR call has no direct static target".to_string();
        return (
            Some(operation),
            Evidence::Unknown {
                reason: reason.clone(),
            },
            Evidence::Unknown { reason },
        );
    };
    let target = Evidence::Inferred {
        value: *address,
        source: "exact LLIR direct call target".to_string(),
    };
    let callee = symbol.clone().map_or_else(
        || Evidence::Unknown {
            reason: "direct call target has no relocation-proven import name".to_string(),
        },
        |value| Evidence::Inferred {
            value,
            source: "ELF PLT relocation".to_string(),
        },
    );
    (Some(operation), target, callee)
}

fn relate_call_return(
    capsule: &ProcessCapsule,
    register_trace: &Result<BTreeMap<u64, BTreeMap<String, u64>>, String>,
    call_event: &super::capsule::EventRecord,
    runtime_instruction_va: u64,
    resolution: &AddressResolution,
) -> Evidence<ObservedCallReturn> {
    let AddressResolution::Exact { address } = resolution else {
        return Evidence::Unknown {
            reason: "call return requires exact static address resolution".to_string(),
        };
    };
    let StaticCodeResolution::Resolved {
        instruction_va,
        instruction_end,
        instruction_relation: InstructionRelation::Exact,
        ..
    } = &address.code
    else {
        return Evidence::Unknown {
            reason: "call return requires one exact static instruction extent".to_string(),
        };
    };
    let Some(instruction_byte_len) = instruction_end.checked_sub(*instruction_va) else {
        return Evidence::Unknown {
            reason: "static call instruction extent is inverted".to_string(),
        };
    };
    let Some(runtime_return_address) = runtime_instruction_va.checked_add(instruction_byte_len)
    else {
        return Evidence::Unknown {
            reason: "runtime call return address overflowed".to_string(),
        };
    };
    let mut returns = capsule
        .events
        .iter()
        .filter(|event| {
            event.kind == "instruction_step"
                && event.process_id == call_event.process_id
                && event.thread_id == call_event.thread_id
                && event.sequence > call_event.sequence
                && event.address == Some(runtime_return_address)
        })
        .collect::<Vec<_>>();
    returns.sort_by_key(|event| event.sequence);
    let Some(return_event) = returns.first() else {
        return Evidence::Unknown {
            reason: "bounded trace does not observe the call return address".to_string(),
        };
    };
    let Evidence::Observed {
        value: registers, ..
    } = registers_for_step(register_trace, return_event)
    else {
        return Evidence::Unknown {
            reason: "call return occurrence has no pre-instruction registers".to_string(),
        };
    };
    let Some(return_value) = registers.get("rax").copied() else {
        return Evidence::Unknown {
            reason: "call return occurrence has no x86-64 return register".to_string(),
        };
    };
    Evidence::Inferred {
        value: ObservedCallReturn {
            sequence: return_event.sequence,
            runtime_address: runtime_return_address,
            return_register: "rax".to_string(),
            return_value,
        },
        source: "exact static call extent joined to a later observed return-address occurrence"
            .to_string(),
    }
}

fn make_call_occurrence(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    event: &super::capsule::EventRecord,
    registers: &Evidence<BTreeMap<String, u64>>,
    operation: Option<&StaticOperation>,
    callee: &Evidence<String>,
    return_occurrence: &Evidence<ObservedCallReturn>,
) -> Evidence<OperationOccurrence> {
    let Some(operation) = operation else {
        return Evidence::Unknown {
            reason: "call occurrence requires one exact static LLIR operation".to_string(),
        };
    };
    let Evidence::Inferred { value: callee, .. } = callee else {
        return Evidence::Unknown {
            reason: "call occurrence requires a relocation-proven callee".to_string(),
        };
    };
    if callee == "ioctl" {
        return make_ioctl_call_occurrence(capsule, event, registers, operation);
    }
    if callee == "strcmp" {
        return make_string_compare_occurrence(
            capsule,
            payloads,
            event,
            registers,
            operation,
            return_occurrence,
        );
    }
    let Some(contract) = SemanticCallContract::for_callee(callee) else {
        return Evidence::Unknown {
            reason: format!("call occurrence semantics for {callee} are not implemented"),
        };
    };
    let Evidence::Observed {
        value: registers, ..
    } = registers
    else {
        return Evidence::Unknown {
            reason: format!("{callee} occurrence requires pre-instruction registers"),
        };
    };
    let source_register = if contract == SemanticCallContract::PercentSFormat {
        "rdx"
    } else {
        "rsi"
    };
    let (Some(destination), Some(source)) = (
        registers.get("rdi").copied(),
        registers.get(source_register).copied(),
    ) else {
        return Evidence::Unknown {
            reason: format!("{callee} occurrence is missing a SysV argument register"),
        };
    };
    let extent = match contract.derive_extent(
        capsule,
        payloads,
        &event.process_id,
        registers,
        destination,
        source,
        callee,
    ) {
        Ok(extent) => extent,
        Err(reason) => return Evidence::Unknown { reason },
    };
    let byte_len = extent.byte_len();
    let write_address = extent.write_address();
    let Some(end) = write_address.checked_add(byte_len) else {
        return Evidence::Unknown {
            reason: format!("{callee} destination range overflowed"),
        };
    };
    let objects = capsule
        .runtime_objects
        .iter()
        .filter(|object| {
            object.process_id == event.process_id
                && object.start <= write_address
                && object
                    .start
                    .checked_add(object.byte_len)
                    .is_some_and(|object_end| end <= object_end)
        })
        .collect::<Vec<_>>();
    let [object] = objects.as_slice() else {
        return Evidence::Unknown {
            reason: format!("{callee} destination does not belong to one runtime object"),
        };
    };
    let observed = |value: u64| Evidence::Observed {
        value: value.to_string(),
        source: "Linux x86-64 SysV pre-call register evidence".to_string(),
    };
    let mut inputs = BTreeMap::from([
        ("destination_address".to_string(), observed(destination)),
        ("byte_len".to_string(), observed(byte_len)),
    ]);
    if contract == SemanticCallContract::ByteFill {
        inputs.insert("fill_byte".to_string(), observed(source & 0xff));
    } else {
        inputs.insert("source_address".to_string(), observed(source));
    }
    if contract == SemanticCallContract::PercentSFormat {
        let Some(format_address) = registers.get("rsi").copied() else {
            return Evidence::Unknown {
                reason: format!("{callee} occurrence is missing the SysV format register"),
            };
        };
        inputs.insert("format_address".to_string(), observed(format_address));
    }
    for (name, value) in extent.semantic_inputs() {
        inputs.insert(name.to_string(), observed(value));
    }
    operation_occurrence(
        capsule,
        &event.process_id,
        event.thread_id.as_deref(),
        event.sequence,
        operation,
        inputs,
        Vec::new(),
        Evidence::Unknown {
            reason: format!("trace does not capture the {callee} return occurrence"),
        },
        vec![OperationEffect {
            kind: "memory_write".to_string(),
            resource_id: None,
            runtime_object_id: Some(object.id.clone()),
            errno: None,
            address: Some(write_address),
            byte_len: Some(byte_len),
            input_source_id: None,
        }],
        &format!("observed SysV call arguments joined to one exact static LLIR {callee} operation"),
    )
}

fn make_string_compare_occurrence(
    capsule: &ProcessCapsule,
    payloads: &BTreeMap<String, Vec<u8>>,
    event: &super::capsule::EventRecord,
    registers: &Evidence<BTreeMap<String, u64>>,
    operation: &StaticOperation,
    return_occurrence: &Evidence<ObservedCallReturn>,
) -> Evidence<OperationOccurrence> {
    let Evidence::Observed {
        value: registers, ..
    } = registers
    else {
        return Evidence::Unknown {
            reason: "strcmp occurrence requires pre-instruction registers".to_string(),
        };
    };
    let (Some(left), Some(right)) = (registers.get("rdi").copied(), registers.get("rsi").copied())
    else {
        return Evidence::Unknown {
            reason: "strcmp occurrence is missing a SysV argument register".to_string(),
        };
    };
    let sources = input_provenance(capsule).sources;
    let locations = locate_invocation_inputs(capsule, payloads);
    let candidates = locations
        .iter()
        .filter_map(|relation| {
            let Evidence::Inferred {
                value: location, ..
            } = &relation.location
            else {
                return None;
            };
            ((location.runtime_address == left || location.runtime_address == right)
                && sources.iter().any(|source| source.id == relation.source_id))
            .then_some((relation, location))
        })
        .collect::<Vec<_>>();
    let [(relation, location)] = candidates.as_slice() else {
        return Evidence::Unknown {
            reason: "strcmp arguments do not identify exactly one captured invocation input"
                .to_string(),
        };
    };
    let source = sources
        .iter()
        .find(|source| source.id == relation.source_id)
        .expect("candidate source was checked");
    let observed = |value: u64| Evidence::Observed {
        value: value.to_string(),
        source: "Linux x86-64 SysV pre-call register evidence".to_string(),
    };
    let output = match return_occurrence {
        Evidence::Inferred { value, .. } => Evidence::Inferred {
            value: i64::from(value.return_value as u32 as i32),
            source: "observed x86-64 return register at the inferred strcmp return occurrence"
                .to_string(),
        },
        Evidence::Observed { value, .. } => Evidence::Observed {
            value: i64::from(value.return_value as u32 as i32),
            source: "observed x86-64 return register at the strcmp return occurrence".to_string(),
        },
        Evidence::Unknown { reason } => Evidence::Unknown {
            reason: reason.clone(),
        },
    };
    operation_occurrence(
        capsule,
        &event.process_id,
        event.thread_id.as_deref(),
        event.sequence,
        operation,
        BTreeMap::from([
            ("left_address".to_string(), observed(left)),
            ("right_address".to_string(), observed(right)),
        ]),
        vec![source.clone()],
        output,
        vec![OperationEffect {
            kind: "input_compare_call".to_string(),
            resource_id: None,
            runtime_object_id: None,
            errno: None,
            address: Some(location.runtime_address),
            byte_len: Some(location.byte_len),
            input_source_id: Some(source.id.clone()),
        }],
        "captured invocation input joined to one exact static LLIR strcmp operation",
    )
}

fn make_ioctl_call_occurrence(
    capsule: &ProcessCapsule,
    event: &super::capsule::EventRecord,
    registers: &Evidence<BTreeMap<String, u64>>,
    operation: &StaticOperation,
) -> Evidence<OperationOccurrence> {
    let Evidence::Observed {
        value: registers, ..
    } = registers
    else {
        return Evidence::Unknown {
            reason: "ioctl occurrence requires pre-instruction registers".to_string(),
        };
    };
    let (Some(descriptor), Some(request), Some(argument)) = (
        registers.get("rdi").copied(),
        registers.get("rsi").copied(),
        registers.get("rdx").copied(),
    ) else {
        return Evidence::Unknown {
            reason: "ioctl occurrence is missing a SysV argument register".to_string(),
        };
    };
    let observed = |value: u64| Evidence::Observed {
        value: value.to_string(),
        source: "Linux x86-64 SysV pre-call register evidence".to_string(),
    };
    operation_occurrence(
        capsule,
        &event.process_id,
        event.thread_id.as_deref(),
        event.sequence,
        operation,
        BTreeMap::from([
            ("descriptor".to_string(), observed(descriptor)),
            ("request".to_string(), observed(request)),
            ("scalar_argument".to_string(), observed(argument)),
        ]),
        Vec::new(),
        Evidence::Unknown {
            reason: "instruction trace ends before the ioctl return occurrence".to_string(),
        },
        vec![OperationEffect {
            kind: "file_ioctl_call".to_string(),
            resource_id: None,
            runtime_object_id: None,
            errno: None,
            address: None,
            byte_len: None,
            input_source_id: None,
        }],
        "observed SysV call arguments joined to one exact static LLIR ioctl operation",
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SemanticCallContract {
    ExplicitLengthCopy,
    ByteFill,
    CStringCopy,
    CStringAppend,
    PercentSFormat,
}

impl SemanticCallContract {
    fn for_callee(callee: &str) -> Option<Self> {
        match callee {
            "memcpy" | "memmove" => Some(Self::ExplicitLengthCopy),
            "memset" => Some(Self::ByteFill),
            "strcpy" => Some(Self::CStringCopy),
            "strcat" => Some(Self::CStringAppend),
            "sprintf" => Some(Self::PercentSFormat),
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn derive_extent(
        self,
        capsule: &ProcessCapsule,
        payloads: &BTreeMap<String, Vec<u8>>,
        process_id: &str,
        registers: &BTreeMap<String, u64>,
        destination: u64,
        source: u64,
        callee: &str,
    ) -> Result<DerivedCallExtent, String> {
        match self {
            Self::ExplicitLengthCopy => registers
                .get("rdx")
                .copied()
                .map(|byte_len| DerivedCallExtent::ExplicitCopy {
                    write_address: destination,
                    byte_len,
                })
                .ok_or_else(|| format!("{callee} occurrence is missing a SysV length register")),
            Self::ByteFill => registers
                .get("rdx")
                .copied()
                .map(|byte_len| DerivedCallExtent::ByteFill {
                    write_address: destination,
                    byte_len,
                    fill_byte: source & 0xff,
                })
                .ok_or_else(|| format!("{callee} occurrence is missing a SysV length register")),
            Self::CStringCopy => {
                let source_bytes = captured_c_string_byte_len(
                    capsule, process_id, payloads, source, callee, "source",
                )?;
                Ok(DerivedCallExtent::CStringCopy {
                    write_address: destination,
                    source_bytes,
                })
            }
            Self::CStringAppend => {
                let source_bytes = captured_c_string_byte_len(
                    capsule, process_id, payloads, source, callee, "source",
                )?;
                let destination_bytes = captured_c_string_byte_len(
                    capsule,
                    process_id,
                    payloads,
                    destination,
                    callee,
                    "destination",
                )?;
                let existing_bytes = destination_bytes - 1;
                let write_address = destination
                    .checked_add(existing_bytes)
                    .ok_or_else(|| "strcat write address overflowed".to_string())?;
                let final_bytes = existing_bytes
                    .checked_add(source_bytes)
                    .ok_or_else(|| "strcat final byte extent overflowed".to_string())?;
                Ok(DerivedCallExtent::CStringAppend {
                    write_address,
                    append_bytes: source_bytes,
                    final_bytes,
                })
            }
            Self::PercentSFormat => {
                let format_address = registers.get("rsi").copied().ok_or_else(|| {
                    format!("{callee} occurrence is missing the SysV format register")
                })?;
                let format = captured_c_string_bytes(
                    capsule,
                    process_id,
                    payloads,
                    format_address,
                    callee,
                    "format",
                )?;
                if format != b"%s\0" {
                    return Err(format!(
                        "{callee} format semantics are only implemented for an exact captured %s format"
                    ));
                }
                let output_bytes = captured_c_string_byte_len(
                    capsule, process_id, payloads, source, callee, "source",
                )?;
                Ok(DerivedCallExtent::FormattedString {
                    write_address: destination,
                    output_bytes,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DerivedCallExtent {
    ExplicitCopy {
        write_address: u64,
        byte_len: u64,
    },
    ByteFill {
        write_address: u64,
        byte_len: u64,
        fill_byte: u64,
    },
    CStringCopy {
        write_address: u64,
        source_bytes: u64,
    },
    CStringAppend {
        write_address: u64,
        append_bytes: u64,
        final_bytes: u64,
    },
    FormattedString {
        write_address: u64,
        output_bytes: u64,
    },
}

impl DerivedCallExtent {
    fn write_address(self) -> u64 {
        match self {
            Self::ExplicitCopy { write_address, .. }
            | Self::ByteFill { write_address, .. }
            | Self::CStringCopy { write_address, .. }
            | Self::CStringAppend { write_address, .. }
            | Self::FormattedString { write_address, .. } => write_address,
        }
    }

    fn byte_len(self) -> u64 {
        match self {
            Self::ExplicitCopy { byte_len, .. } => byte_len,
            Self::ByteFill { byte_len, .. } => byte_len,
            Self::CStringCopy { source_bytes, .. } => source_bytes,
            Self::CStringAppend { append_bytes, .. } => append_bytes,
            Self::FormattedString { output_bytes, .. } => output_bytes,
        }
    }

    fn semantic_inputs(self) -> Vec<(&'static str, u64)> {
        match self {
            Self::ExplicitCopy { .. } => Vec::new(),
            Self::ByteFill { fill_byte, .. } => vec![("fill_byte", fill_byte)],
            Self::CStringCopy { source_bytes, .. } => {
                vec![("source_bytes", source_bytes)]
            }
            Self::CStringAppend {
                write_address,
                append_bytes,
                final_bytes,
            } => vec![
                ("append_bytes", append_bytes),
                ("write_address", write_address),
                ("final_bytes", final_bytes),
            ],
            Self::FormattedString { output_bytes, .. } => {
                vec![("output_bytes", output_bytes)]
            }
        }
    }
}

fn captured_c_string_byte_len(
    capsule: &ProcessCapsule,
    process_id: &str,
    payloads: &BTreeMap<String, Vec<u8>>,
    address: u64,
    operation: &str,
    role: &str,
) -> Result<u64, String> {
    let bytes = captured_c_string_bytes(capsule, process_id, payloads, address, operation, role)?;
    u64::try_from(bytes.len()).map_err(|_| format!("{operation} {role} byte length overflowed"))
}

fn captured_c_string_bytes(
    capsule: &ProcessCapsule,
    process_id: &str,
    payloads: &BTreeMap<String, Vec<u8>>,
    address: u64,
    operation: &str,
    role: &str,
) -> Result<Vec<u8>, String> {
    const MAX_STRING_BYTES: usize = 256;
    let object = capsule
        .runtime_objects
        .iter()
        .find(|object| {
            object.process_id == process_id
                && object.kind == RuntimeObjectKind::Mapping
                && object.start <= address
                && address < object.start.saturating_add(object.byte_len)
        })
        .ok_or_else(|| format!("{operation} {role} is outside captured runtime objects"))?;
    let snapshot = capsule
        .object_snapshots
        .iter()
        .filter(|snapshot| snapshot.object_id == object.id)
        .min_by_key(|snapshot| (snapshot.point.sequence, snapshot.id.as_str()))
        .ok_or_else(|| format!("{operation} {role} has no pre-call object snapshot"))?;
    let PageContent::Captured { payload } = &snapshot.content else {
        return Err(format!("{operation} {role} snapshot bytes were omitted"));
    };
    let bytes = payloads
        .get(&payload.id)
        .ok_or_else(|| format!("{operation} {role} payload {} is unavailable", payload.id))?;
    if bytes.len() as u64 != payload.byte_len
        || payload.byte_len != snapshot.byte_len
        || hex::encode(Sha256::digest(bytes)) != payload.sha256
    {
        return Err(format!(
            "{operation} {role} payload disagrees with its identity"
        ));
    }
    let snapshot_start = object
        .start
        .checked_add(snapshot.object_offset)
        .ok_or_else(|| format!("{operation} {role} snapshot range overflowed"))?;
    let offset = address
        .checked_sub(snapshot_start)
        .and_then(|offset| usize::try_from(offset).ok())
        .filter(|offset| *offset < bytes.len())
        .ok_or_else(|| format!("{operation} {role} is outside the pre-call snapshot"))?;
    let available = &bytes[offset..bytes.len().min(offset + MAX_STRING_BYTES)];
    let terminator = available
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("{operation} {role} has no captured bounded terminator"))?;
    Ok(available[..=terminator].to_vec())
}

fn derive_effective_address(
    changes: &Evidence<Vec<ObservedMemoryChange>>,
    registers: &Evidence<BTreeMap<String, u64>>,
    resolution: &AddressResolution,
) -> Evidence<ObservedEffectiveAddress> {
    let Evidence::Observed { value: changes, .. } = changes else {
        return Evidence::Unknown {
            reason: "effective address requires observed changed bytes".to_string(),
        };
    };
    let Evidence::Observed {
        value: registers, ..
    } = registers
    else {
        return Evidence::Unknown {
            reason: "effective address requires pre-instruction registers".to_string(),
        };
    };
    let AddressResolution::Exact { address } = resolution else {
        return Evidence::Unknown {
            reason: "effective address requires exact static address resolution".to_string(),
        };
    };
    let StaticCodeResolution::Resolved {
        instruction_relation: InstructionRelation::Exact,
        operations: OperationResolution::Resolved { operations },
        ..
    } = &address.code
    else {
        return Evidence::Unknown {
            reason: "effective address requires exact resolved LLIR operations".to_string(),
        };
    };
    let stores = operations
        .iter()
        .filter(|operation| operation.kind == "store")
        .collect::<Vec<_>>();
    let [store] = stores.as_slice() else {
        return Evidence::Unknown {
            reason: "effective address requires exactly one LLIR store".to_string(),
        };
    };
    let Some(access) = &store.memory_access else {
        return Evidence::Unknown {
            reason: "LLIR store has no static memory-access semantics".to_string(),
        };
    };
    derive_x86_64_address(access, registers, Some(changes))
}

fn derive_executed_effective_address(
    registers: &Evidence<BTreeMap<String, u64>>,
    resolution: &AddressResolution,
) -> Evidence<ObservedEffectiveAddress> {
    let Evidence::Observed {
        value: registers, ..
    } = registers
    else {
        return Evidence::Unknown {
            reason: "effective address requires pre-instruction registers".to_string(),
        };
    };
    let Some(store) = unique_store_operation(resolution) else {
        return Evidence::Unknown {
            reason: "effective address requires exactly one LLIR store".to_string(),
        };
    };
    let Some(access) = &store.memory_access else {
        return Evidence::Unknown {
            reason: "LLIR store has no static memory-access semantics".to_string(),
        };
    };
    derive_x86_64_address(access, registers, None)
}

fn derive_operation_effective_address(
    registers: &Evidence<BTreeMap<String, u64>>,
    operation: &StaticOperation,
    operation_name: &str,
) -> Evidence<ObservedEffectiveAddress> {
    let Evidence::Observed {
        value: registers, ..
    } = registers
    else {
        return Evidence::Unknown {
            reason: format!("{operation_name} address requires pre-instruction registers"),
        };
    };
    let Some(access) = &operation.memory_access else {
        return Evidence::Unknown {
            reason: format!("LLIR {operation_name} has no static memory-access semantics"),
        };
    };
    derive_x86_64_address(access, registers, None)
}

fn derive_x86_64_address(
    access: &StaticMemoryAccess,
    registers: &BTreeMap<String, u64>,
    changes: Option<&[ObservedMemoryChange]>,
) -> Evidence<ObservedEffectiveAddress> {
    if access.segment.is_some() {
        return Evidence::Unknown {
            reason: "segmented effective addresses are not supported".to_string(),
        };
    }
    let lookup = |name: &Option<String>| -> Option<Option<u64>> {
        match name {
            None => Some(None),
            Some(name) => registers.get(name).copied().map(Some),
        }
    };
    let Some(base_value) = lookup(&access.base_register) else {
        return Evidence::Unknown {
            reason: "effective-address base register is absent".to_string(),
        };
    };
    let Some(index_value) = lookup(&access.index_register) else {
        return Evidence::Unknown {
            reason: "effective-address index register is absent".to_string(),
        };
    };
    let effective_address = base_value
        .unwrap_or(0)
        .wrapping_add(
            index_value
                .unwrap_or(0)
                .wrapping_mul(u64::from(access.scale)),
        )
        .wrapping_add_signed(access.displacement);
    if changes.is_some_and(|changes| {
        !changes.iter().all(|change| {
            change.start == effective_address
                && change.end.checked_sub(change.start) == Some(u64::from(access.byte_len))
        })
    }) {
        return Evidence::Unknown {
            reason: "LLIR effective address disagrees with observed changed bytes".to_string(),
        };
    }
    Evidence::Inferred {
        value: ObservedEffectiveAddress {
            base_register: access.base_register.clone(),
            base_value,
            index_register: access.index_register.clone(),
            index_value,
            scale: access.scale,
            displacement: access.displacement,
            effective_address,
            byte_len: access.byte_len,
        },
        source: "static LLIR memory operand evaluated with observed pre-instruction registers"
            .to_string(),
    }
}

fn parse_step_evidence(
    event: &super::capsule::EventRecord,
    payloads: &BTreeMap<String, Vec<u8>>,
) -> (
    Evidence<Vec<ObservedMemoryChange>>,
    Evidence<BTreeMap<String, u64>>,
) {
    fn unknown(
        reason: impl Into<String>,
    ) -> (
        Evidence<Vec<ObservedMemoryChange>>,
        Evidence<BTreeMap<String, u64>>,
    ) {
        let reason = reason.into();
        (
            Evidence::Unknown {
                reason: reason.clone(),
            },
            Evidence::Unknown { reason },
        )
    }
    let Some(payload_id) = event.fields.get("stack_changes_payload_id") else {
        return unknown("instruction-step change payload identity is absent");
    };
    let Some(expected_sha256) = event.fields.get("stack_changes_sha256") else {
        return unknown("instruction-step change payload hash is absent");
    };
    let Some(expected_byte_len) = event
        .fields
        .get("stack_changes_byte_len")
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return unknown("instruction-step change payload length is absent or malformed");
    };
    let Some(encoded) = payloads.get(payload_id) else {
        return unknown(format!(
            "instruction-step change payload {payload_id} is unavailable"
        ));
    };
    if encoded.len() != expected_byte_len
        || hex::encode(Sha256::digest(encoded)) != *expected_sha256
    {
        return unknown("instruction-step change payload disagrees with its identity");
    }
    let Ok(payload) = serde_json::from_slice::<InstructionStepPayload>(encoded) else {
        return unknown("instruction-step evidence is malformed");
    };
    if payload.schema != "glaurung-instruction-step-evidence-v1" {
        return unknown("instruction-step evidence schema is unsupported");
    }
    let changes = payload.changes;
    if changes.is_empty() {
        return unknown("instruction-step memory change list is empty");
    }
    for change in &changes {
        let Some(byte_len) = change.end.checked_sub(change.start) else {
            return unknown("instruction-step memory change range is reversed");
        };
        let (Ok(before), Ok(after)) = (
            hex::decode(&change.before_hex),
            hex::decode(&change.after_hex),
        ) else {
            return unknown("instruction-step memory change bytes are malformed");
        };
        if byte_len == 0 || before.len() as u64 != byte_len || after.len() as u64 != byte_len {
            return unknown("instruction-step memory change length disagrees with its range");
        }
    }
    let mut registers = BTreeMap::new();
    for (name, encoded) in payload.registers {
        let Ok(value) = u64::from_str_radix(&encoded, 16) else {
            return unknown(format!("instruction-step register {name} is malformed"));
        };
        registers.insert(name, value);
    }
    if registers.is_empty() {
        return unknown("instruction-step register set is empty");
    }
    (
        Evidence::Observed {
            value: changes,
            source: "bounded ptrace single-step stack comparison".to_string(),
        },
        Evidence::Observed {
            value: registers,
            source: "ptrace register set captured before the instruction".to_string(),
        },
    )
}

fn make_store_occurrence(
    capsule: &ProcessCapsule,
    event: &super::capsule::EventRecord,
    changes: &Evidence<Vec<ObservedMemoryChange>>,
    resolution: &AddressResolution,
) -> Evidence<OperationOccurrence> {
    let Evidence::Observed { value: changes, .. } = changes else {
        return Evidence::Unknown {
            reason: "store occurrence requires valid observed memory changes".to_string(),
        };
    };
    let AddressResolution::Exact { address } = resolution else {
        return Evidence::Unknown {
            reason: "store occurrence requires an exact runtime/static address relation"
                .to_string(),
        };
    };
    let StaticCodeResolution::Resolved {
        instruction_relation: InstructionRelation::Exact,
        operations: OperationResolution::Resolved { operations },
        ..
    } = &address.code
    else {
        return Evidence::Unknown {
            reason: "instruction step has no exact resolved LLIR operations".to_string(),
        };
    };
    let stores = operations
        .iter()
        .filter(|operation| operation.kind == "store")
        .collect::<Vec<_>>();
    let [static_operation] = stores.as_slice() else {
        return Evidence::Unknown {
            reason: "instruction step does not identify exactly one LLIR store operation"
                .to_string(),
        };
    };
    let objects = capsule
        .runtime_objects
        .iter()
        .filter(|object| {
            object.process_id == event.process_id
                && object.kind == RuntimeObjectKind::Mapping
                && changes.iter().all(|change| {
                    object.start <= change.start
                        && object
                            .start
                            .checked_add(object.byte_len)
                            .is_some_and(|end| change.end <= end)
                })
        })
        .collect::<Vec<_>>();
    let [object] = objects.as_slice() else {
        return Evidence::Unknown {
            reason: "changed bytes do not belong to one captured runtime mapping object"
                .to_string(),
        };
    };
    let observed = |value: String| Evidence::Observed {
        value,
        source: "bounded ptrace single-step stack comparison".to_string(),
    };
    let inputs = changes
        .iter()
        .enumerate()
        .map(|(index, change)| {
            (
                format!("memory_before_{index}"),
                observed(format!(
                    "0x{:x}..0x{:x}:{}",
                    change.start, change.end, change.before_hex
                )),
            )
        })
        .collect();
    let effects = changes
        .iter()
        .map(|change| OperationEffect {
            kind: "memory_write".to_string(),
            resource_id: None,
            runtime_object_id: Some(object.id.clone()),
            errno: None,
            address: Some(change.start),
            byte_len: Some(change.end - change.start),
            input_source_id: None,
        })
        .collect();
    operation_occurrence(
        capsule,
        &event.process_id,
        event.thread_id.as_deref(),
        event.sequence,
        static_operation,
        inputs,
        Vec::new(),
        Evidence::Unknown {
            reason: "store operation has no scalar output".to_string(),
        },
        effects,
        "observed instruction-step bytes joined to one exact static LLIR store operation",
    )
}

#[cfg(test)]
mod tests {
    use super::{DerivedCallExtent, SemanticCallContract};

    #[cfg(feature = "symbolic")]
    #[test]
    fn counterfactual_solver_unknowns_keep_timeout_and_resource_limits_distinct() {
        use super::{counterfactual_solver_unknown_reason, CounterfactualUnknownReason};
        use crate::symbolic::solver::SolveUnknownReason;

        assert_eq!(
            counterfactual_solver_unknown_reason(SolveUnknownReason::WallTimeout),
            CounterfactualUnknownReason::SolverTimeout,
        );
        assert_eq!(
            counterfactual_solver_unknown_reason(SolveUnknownReason::ResourceLimit),
            CounterfactualUnknownReason::SolverResourceLimit,
        );
        assert_eq!(
            counterfactual_solver_unknown_reason(SolveUnknownReason::Other),
            CounterfactualUnknownReason::SolverError,
        );
    }

    #[test]
    fn semantic_call_contracts_preserve_distinct_extent_shapes() {
        assert_eq!(
            SemanticCallContract::for_callee("memcpy"),
            Some(SemanticCallContract::ExplicitLengthCopy)
        );
        assert_eq!(
            SemanticCallContract::for_callee("memmove"),
            Some(SemanticCallContract::ExplicitLengthCopy)
        );
        assert_eq!(
            SemanticCallContract::for_callee("memset"),
            Some(SemanticCallContract::ByteFill)
        );
        assert_eq!(
            SemanticCallContract::for_callee("strcpy"),
            Some(SemanticCallContract::CStringCopy)
        );
        assert_eq!(
            SemanticCallContract::for_callee("strcat"),
            Some(SemanticCallContract::CStringAppend)
        );
        assert_eq!(
            SemanticCallContract::for_callee("sprintf"),
            Some(SemanticCallContract::PercentSFormat)
        );
        assert_eq!(SemanticCallContract::for_callee("snprintf"), None);

        let append = DerivedCallExtent::CStringAppend {
            write_address: 0x1003,
            append_bytes: 9,
            final_bytes: 12,
        };
        assert_eq!(append.write_address(), 0x1003);
        assert_eq!(append.byte_len(), 9);
        assert_eq!(
            append.semantic_inputs(),
            vec![
                ("append_bytes", 9),
                ("write_address", 0x1003),
                ("final_bytes", 12),
            ]
        );

        let formatted = DerivedCallExtent::FormattedString {
            write_address: 0x2000,
            output_bytes: 13,
        };
        assert_eq!(formatted.byte_len(), 13);
        assert_eq!(formatted.semantic_inputs(), vec![("output_bytes", 13)]);
    }
}
