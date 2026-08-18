//! The recovered `.class` data model.
//!
//! Every type the parser hands back: the per-member records, the attribute
//! payloads, the constant-pool summary, the bytecode/xref records, the
//! top-level [`ClassInfo`], and the [`ClassError`] every reader returns.
//! Shape only -- no parsing lives here.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaMethod {
    pub access_flags: u16,
    pub name: String,
    pub descriptor: String,
    pub signature: Option<String>,
    pub attribute_names: Vec<String>,
    pub is_deprecated: bool,
    pub is_synthetic: bool,
    pub runtime_visible_type_annotation_count: u16,
    pub runtime_invisible_type_annotation_count: u16,
    pub constant_value: Option<JavaConstantValue>,
    pub exceptions: Vec<String>,
    pub annotations: Vec<JavaAnnotation>,
    pub method_parameters: Vec<JavaMethodParameter>,
    pub parameter_annotations: Vec<JavaParameterAnnotations>,
    pub annotation_default: Option<JavaAnnotationValue>,
    pub code: Option<JavaCode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaCode {
    pub max_stack: u16,
    pub max_locals: u16,
    pub code_length: u32,
    pub exception_table_len: u16,
    pub exception_handlers: Vec<JavaExceptionHandler>,
    pub attributes_count: u16,
    pub attribute_names: Vec<String>,
    pub instruction_count: u32,
    pub unknown_instruction_count: u32,
    pub stack_map_frame_count: u16,
    pub runtime_visible_type_annotation_count: u16,
    pub runtime_invisible_type_annotation_count: u16,
    pub line_numbers: Vec<JavaLineNumber>,
    pub local_variables: Vec<JavaLocalVariable>,
    pub local_variable_types: Vec<JavaLocalVariableType>,
    pub instructions: Vec<JavaInstruction>,
    pub xrefs: Vec<JavaXref>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaConstantValue {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JavaConstantPoolSummary {
    pub total_slots: u16,
    pub populated_entries: u16,
    pub empty_slots: u16,
    pub utf8_count: u16,
    pub integer_count: u16,
    pub float_count: u16,
    pub long_count: u16,
    pub double_count: u16,
    pub class_count: u16,
    pub string_count: u16,
    pub fieldref_count: u16,
    pub methodref_count: u16,
    pub interface_methodref_count: u16,
    pub name_and_type_count: u16,
    pub method_handle_count: u16,
    pub method_type_count: u16,
    pub dynamic_count: u16,
    pub invoke_dynamic_count: u16,
    pub module_count: u16,
    pub package_count: u16,
    pub other_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaBootstrapMethod {
    pub bootstrap_method_ref_index: u16,
    pub reference_kind: Option<u8>,
    pub reference_kind_name: Option<String>,
    pub reference_owner: Option<String>,
    pub reference_name: Option<String>,
    pub reference_descriptor: Option<String>,
    pub reference_target: Option<String>,
    pub argument_count: u16,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaExceptionHandler {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    pub catch_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaAnnotation {
    pub visibility: String,
    pub descriptor: String,
    pub elements: Vec<JavaAnnotationElement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaAnnotationElement {
    pub name: String,
    pub value: JavaAnnotationValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaAnnotationValue {
    pub tag: String,
    pub kind: String,
    pub value: Option<String>,
    pub type_name: Option<String>,
    pub const_name: Option<String>,
    pub values: Vec<JavaAnnotationValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaMethodParameter {
    pub name: Option<String>,
    pub access_flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaParameterAnnotations {
    pub parameter_index: u16,
    pub annotations: Vec<JavaAnnotation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaLineNumber {
    pub start_pc: u16,
    pub line_number: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaLocalVariable {
    pub start_pc: u16,
    pub length: u16,
    pub name: String,
    pub descriptor: String,
    pub index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaLocalVariableType {
    pub start_pc: u16,
    pub length: u16,
    pub name: String,
    pub signature: String,
    pub index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaInnerClass {
    pub inner_class: String,
    pub outer_class: Option<String>,
    pub inner_name: Option<String>,
    pub access_flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaEnclosingMethod {
    pub class_name: String,
    pub method_name: Option<String>,
    pub method_descriptor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaRecordComponent {
    pub name: String,
    pub descriptor: String,
    pub signature: Option<String>,
    pub annotations: Vec<JavaAnnotation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaModuleInfo {
    pub name: String,
    pub flags: u16,
    pub version: Option<String>,
    pub requires: Vec<JavaModuleRequire>,
    pub exports: Vec<JavaModuleExport>,
    pub opens: Vec<JavaModuleOpen>,
    pub uses: Vec<String>,
    pub provides: Vec<JavaModuleProvide>,
    pub packages: Vec<String>,
    pub main_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaModuleRequire {
    pub module: String,
    pub flags: u16,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaModuleExport {
    pub package: String,
    pub flags: u16,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaModuleOpen {
    pub package: String,
    pub flags: u16,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaModuleProvide {
    pub service: String,
    pub implementations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaInstruction {
    pub bci: u32,
    pub opcode: u8,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaXref {
    pub bci: u32,
    pub opcode: u8,
    pub kind: String,
    pub owner: String,
    pub name: String,
    pub descriptor: String,
    pub target: String,
    pub string_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassInfo {
    pub minor_version: u16,
    pub major_version: u16,
    pub access_flags: u16,
    pub class_name: String,
    pub super_class: String,
    pub source_file: Option<String>,
    pub signature: Option<String>,
    pub attribute_names: Vec<String>,
    pub is_deprecated: bool,
    pub is_synthetic: bool,
    pub runtime_visible_type_annotation_count: u16,
    pub runtime_invisible_type_annotation_count: u16,
    pub source_debug_extension_length: u32,
    pub source_debug_extension_sha256: Option<String>,
    pub constant_pool: JavaConstantPoolSummary,
    pub annotations: Vec<JavaAnnotation>,
    pub inner_classes: Vec<JavaInnerClass>,
    pub enclosing_method: Option<JavaEnclosingMethod>,
    pub nest_host: Option<String>,
    pub nest_members: Vec<String>,
    pub record_components: Vec<JavaRecordComponent>,
    pub permitted_subclasses: Vec<String>,
    pub module: Option<JavaModuleInfo>,
    pub bootstrap_method_count: u16,
    pub bootstrap_methods: Vec<JavaBootstrapMethod>,
    pub interfaces: Vec<String>,
    pub methods: Vec<JavaMethod>,
    pub fields: Vec<JavaMethod>, // same shape — name + descriptor + flags
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassError {
    BadMagic(u32),
    Truncated(&'static str),
    BadCpIndex(u16),
    BadCpTag(u8),
}
