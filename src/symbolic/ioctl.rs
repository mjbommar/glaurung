//! IOCTLance-style Windows-driver analysis on the symbolic engine.
//!
//! Seeds a **symbolic IRP** for a WDM `IRP_MJ_DEVICE_CONTROL` dispatch routine,
//! symbolically executes the handler, and reports attacker-controlled memory
//! writes (arbitrary-write primitives) with a concrete IOCTL input that triggers
//! each one. This is the symbolic successor to the static
//! [`ioctl_taint`](crate::analysis::ioctl_taint) pass: that pass cheaply
//! *nominates* candidate sinks; this one *confirms* reachability and emits a
//! witness.
//!
//! The IRP / `IO_STACK_LOCATION` field offsets and the dispatch ABI (`rcx` =
//! DeviceObject, `rdx` = Irp on x64) mirror `ioctl_taint` exactly.

use std::collections::BTreeMap;

use crate::exec::{Domain, Machine, RegArch};
use crate::ir::types::{Endian, LlirFunction, VReg, Width};
use crate::symbolic::explore::{
    find_sinks, find_sinks_stateful, find_sinks_with_arch, ApiSummary, CallModel, Sink, SinkKind,
    TaintSpec,
};
use crate::symbolic::{Expr, Symbolic};

// WDM IRP field offsets (x64), per src/analysis/ioctl_taint.rs::struct_field.
const IRP_SYSTEM_BUFFER: u64 = 0x18; // IRP.AssociatedIrp.SystemBuffer (METHOD_BUFFERED)
const IRP_USER_BUFFER: u64 = 0x30; // IRP.UserBuffer (METHOD_NEITHER)
const IRP_STACK_LOCATION: u64 = 0xB8; // IRP.Tail.Overlay.CurrentStackLocation
const SL_OUTPUT_LEN: u64 = 0x08; // Parameters.DeviceIoControl.OutputBufferLength
const SL_INPUT_LEN: u64 = 0x10; // Parameters.DeviceIoControl.InputBufferLength
const SL_IOCTL_CODE: u64 = 0x18; // Parameters.DeviceIoControl.IoControlCode
const SL_TYPE3_BUFFER: u64 = 0x20; // Parameters.DeviceIoControl.Type3InputBuffer

// Fixed concrete base addresses for the seeded structures (chosen well clear of
// each other so the handler can chase the Irp → IO_STACK_LOCATION pointer).
const DEVICE_OBJECT: u64 = 0x1_0000;
const IRP: u64 = 0x2_0000;
const STACK_LOC: u64 = 0x3_0000;
// Windows owns the kernel VA for METHOD_BUFFERED requests. Keep it well away
// from the synthetic IRP, stack-location, IAT, stack, and heap ranges.
const SYSTEM_BUFFER: u64 = 0x4_0000_0000;
// InputBufferLength and OutputBufferLength are 32-bit. Mark the maximum possible
// I/O-manager allocation as content-tainted; actual bounds remain a separate
// length-aware memory-safety analysis rather than pointer-control taint.
const SYSTEM_BUFFER_MAX_LEN: u64 = u32::MAX as u64 + 1;

// Linux AArch64 `file_operations::unlocked_ioctl` execution environment.
const LINUX_FILE: u64 = 0x5_0000_0000;
const LINUX_STACK: u64 = 0x6_0000_0000;
const LINUX_PCI_ENDPOINT_TEST: u64 = 0x5_1000_0000;
const LINUX_PCI_DEVICE: u64 = 0x5_2000_0000;

/// A named, reviewable kernel-object precondition for a Linux ioctl run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxIoctlEnvironment {
    /// Only the generic AAPCS64 file/cmd/arg and stack contract.
    Generic,
    /// Valid `file->private_data`, enclosing `pci_endpoint_test`, and non-AM654
    /// `pci_dev` for the registered PCI endpoint-test CVE row.
    PciEndpointTest,
}

impl LinuxIoctlEnvironment {
    pub const fn id(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::PciEndpointTest => "pci-endpoint-test",
        }
    }
}

/// Attacker-controlled inputs of Linux's AAPCS64 ioctl handler ABI:
/// `x0 = struct file *`, `w1 = cmd`, `x2 = arg`.
#[derive(Debug, Clone, Copy)]
pub struct LinuxIoctlSeed {
    pub cmd_sym: u32,
    pub arg_sym: u32,
}

impl LinuxIoctlSeed {
    pub fn taint_spec(&self) -> TaintSpec {
        let mut taint = TaintSpec::new();
        taint.mark(self.cmd_sym, "IoctlCmd");
        taint.mark(self.arg_sym, "IoctlArg");
        taint
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinuxIoctlSeedError {
    #[error("Linux ioctl seeding requires an AArch64 machine, found {0:?}")]
    WrongArchitecture(RegArch),
}

/// Seed one Linux AArch64 `unlocked_ioctl` invocation without reusing the
/// Windows IRP model. The kernel-owned `struct file *` and stack/frame pointers
/// are deterministic concrete environment values; the 32-bit command and
/// 64-bit user argument retain distinct symbolic widths and provenance.
pub fn seed_linux_ioctl(
    machine: &mut Machine<Symbolic>,
) -> Result<LinuxIoctlSeed, LinuxIoctlSeedError> {
    if machine.regs.arch() != RegArch::AArch64 {
        return Err(LinuxIoctlSeedError::WrongArchitecture(machine.regs.arch()));
    }
    Ok(seed_linux_ioctl_aarch64(machine))
}

fn seed_linux_ioctl_aarch64(machine: &mut Machine<Symbolic>) -> LinuxIoctlSeed {
    let file = machine.dom.constant(Width::W64, LINUX_FILE as u128);
    machine
        .regs
        .write(&mut machine.dom, &VReg::phys("x0"), file);

    let cmd = machine.dom.fresh(Width::W32);
    let cmd_sym = match machine.dom.pool.get(cmd) {
        Expr::Sym { id, .. } => *id,
        _ => unreachable!("fresh() returns a Sym"),
    };
    machine.regs.write(&mut machine.dom, &VReg::phys("w1"), cmd);

    let arg = machine.dom.fresh(Width::W64);
    let arg_sym = match machine.dom.pool.get(arg) {
        Expr::Sym { id, .. } => *id,
        _ => unreachable!("fresh() returns a Sym"),
    };
    machine.regs.write(&mut machine.dom, &VReg::phys("x2"), arg);

    for register in ["sp", "x29"] {
        let value = machine.dom.constant(Width::W64, LINUX_STACK as u128);
        machine
            .regs
            .write(&mut machine.dom, &VReg::phys(register), value);
    }
    LinuxIoctlSeed { cmd_sym, arg_sym }
}

fn seed_linux_ioctl_environment(
    machine: &mut Machine<Symbolic>,
    environment: LinuxIoctlEnvironment,
) {
    match environment {
        LinuxIoctlEnvironment::Generic => {}
        LinuxIoctlEnvironment::PciEndpointTest => {
            // `file->private_data` is the embedded `miscdevice` at test+0x90;
            // `to_endpoint_test()` subtracts that offset. The AArch64 object
            // reads `test->pdev` at +0 and `pdev->device` at +0x3e.
            store_const(
                machine,
                LINUX_FILE + 0x18,
                LINUX_PCI_ENDPOINT_TEST + 0x90,
                Width::W64,
            );
            store_const(
                machine,
                LINUX_PCI_ENDPOINT_TEST,
                LINUX_PCI_DEVICE,
                Width::W64,
            );
            // Any non-AM654 device keeps BAR_0 out of the target-specific
            // exclusion while retaining a valid `pci_dev` object.
            store_const(machine, LINUX_PCI_DEVICE + 0x3e, 0, Width::W16);
        }
    }
}

/// The free-symbol ids of the attacker-controlled IRP fields, so a witness
/// [`Model`](crate::symbolic::Model) can be interpreted (e.g. which value of the
/// IoControlCode reaches a sink).
#[derive(Debug, Clone, Copy)]
pub struct IrpSeed {
    pub ioctl_code_sym: u32,
    pub system_buffer_base: u64,
    pub input_len_sym: u32,
    pub output_len_sym: u32,
    pub type3_buffer_sym: u32,
    pub user_buffer_sym: u32,
}

impl IrpSeed {
    /// Build the [`TaintSpec`] labelling each seeded IRP field as attacker input,
    /// so sinks are reported with provenance (e.g. "address built from
    /// `SystemBuffer`") and undecorated internal symbols are not flagged.
    pub fn taint_spec(&self) -> TaintSpec {
        let mut t = TaintSpec::new();
        t.mark_memory_region(
            self.system_buffer_base,
            SYSTEM_BUFFER_MAX_LEN,
            "SystemBuffer",
        );
        t.mark(self.user_buffer_sym, "UserBuffer");
        t.mark(self.type3_buffer_sym, "Type3InputBuffer");
        t.mark(self.ioctl_code_sym, "IoControlCode");
        t.mark(self.input_len_sym, "InputBufferLength");
        t.mark(self.output_len_sym, "OutputBufferLength");
        t
    }
}

/// Store a fresh symbol of `width` at `addr`, returning its symbol id.
fn store_sym(m: &mut Machine<Symbolic>, addr: u64, width: Width) -> u32 {
    let e = m.dom.fresh(width);
    let id = match m.dom.pool.get(e) {
        Expr::Sym { id, .. } => *id,
        _ => unreachable!("fresh() returns a Sym"),
    };
    m.mem
        .store(&mut m.dom, addr, &e, width.bytes() as u8, Endian::Little);
    id
}

/// Store a concrete value of `width` at `addr`.
fn store_const(m: &mut Machine<Symbolic>, addr: u64, val: u64, width: Width) {
    let v = m.dom.constant(width, val as u128);
    m.mem
        .store(&mut m.dom, addr, &v, width.bytes() as u8, Endian::Little);
}

/// Seed a symbolic IRP for the dispatch routine: `rcx`=DeviceObject,
/// `rdx`=Irp (both concrete), with attacker-controlled scalar/request fields
/// symbolic. The Irp→IO_STACK_LOCATION pointer and I/O-manager-owned
/// `METHOD_BUFFERED` SystemBuffer pointer are concrete so the handler can chase
/// them. SystemBuffer *contents* are marked attacker-controlled separately.
pub fn seed_irp(m: &mut Machine<Symbolic>) -> IrpSeed {
    let dev = m.dom.constant(Width::W64, DEVICE_OBJECT as u128);
    m.regs.write(&mut m.dom, &VReg::phys("rcx"), dev);
    let irp = m.dom.constant(Width::W64, IRP as u128);
    m.regs.write(&mut m.dom, &VReg::phys("rdx"), irp);

    // IRP.Tail.Overlay.CurrentStackLocation → a concrete, chase-able pointer.
    store_const(m, IRP + IRP_STACK_LOCATION, STACK_LOC, Width::W64);

    store_const(m, IRP + IRP_SYSTEM_BUFFER, SYSTEM_BUFFER, Width::W64);
    let user_buffer_sym = store_sym(m, IRP + IRP_USER_BUFFER, Width::W64);
    let output_len_sym = store_sym(m, STACK_LOC + SL_OUTPUT_LEN, Width::W32);
    let input_len_sym = store_sym(m, STACK_LOC + SL_INPUT_LEN, Width::W32);
    let ioctl_code_sym = store_sym(m, STACK_LOC + SL_IOCTL_CODE, Width::W32);
    let type3_buffer_sym = store_sym(m, STACK_LOC + SL_TYPE3_BUFFER, Width::W64);

    IrpSeed {
        ioctl_code_sym,
        system_buffer_base: SYSTEM_BUFFER,
        input_len_sym,
        output_len_sym,
        type3_buffer_sym,
        user_buffer_sym,
    }
}

/// Symbolically execute the IOCTL dispatch handler `lf` with a symbolic IRP and
/// the given callee `apis` (e.g. resolved `memcpy`/`RtlCopyMemory` VAs), returning
/// every dangerous memory access (controlled read/write, null deref) with a
/// triggering witness — including primitives hidden inside summarized API calls.
pub fn find_ioctl_sinks_with_apis(
    lf: &LlirFunction,
    apis: &CallModel,
    max_states: usize,
) -> Vec<Sink> {
    find_sinks(
        lf,
        |m| {
            let spec = seed_irp(m).taint_spec();
            seed_iat(m, apis);
            spec
        },
        apis,
        max_states,
    )
}

/// Store a self-pointer at every modeled IAT slot: `mem[slot] = slot`. Real MSVC
/// drivers call imports as `mov reg, [rip+__imp_Api]; call reg`, so the callee
/// register holds the slot's contents. Seeding each slot with its own address
/// makes that loaded value resolve back to the slot VA, which the explorer looks
/// up in the [`CallModel`] — so register-indirect import calls are summarized
/// just like the `call [rip+__imp_Api]` form.
fn seed_iat(m: &mut Machine<Symbolic>, apis: &CallModel) {
    for &slot in apis.keys() {
        let v = m.dom.constant(Width::W64, slot as u128);
        m.mem.store(&mut m.dom, slot, &v, 8, Endian::Little);
    }
}

/// As [`find_ioctl_sinks_with_apis`] with no modeled callees (raw memory accesses
/// only).
pub fn find_ioctl_sinks(lf: &LlirFunction, max_states: usize) -> Vec<Sink> {
    find_ioctl_sinks_with_apis(lf, &CallModel::new(), max_states)
}

/// Execute a Linux AArch64 `unlocked_ioctl` handler with the exact AAPCS64 seed
/// and architecture-aware modeled-callee ABI. This does not reuse the WDM IRP
/// environment or the MS x64 return-address detector.
pub fn find_linux_ioctl_sinks_with_apis(
    lf: &LlirFunction,
    apis: &CallModel,
    max_states: usize,
) -> Vec<Sink> {
    find_sinks_with_arch(
        lf,
        RegArch::AArch64,
        |machine| seed_linux_ioctl_aarch64(machine).taint_spec(),
        apis,
        max_states,
    )
}

/// Execute a Linux AArch64 `unlocked_ioctl` handler for one registered command.
/// The argument remains symbolic and attacker-tainted; only `w1` is fixed. This
/// is an environment selection for a preregistered CVE row, not a search-policy
/// heuristic.
pub fn find_linux_ioctl_sinks_for_command_with_apis(
    lf: &LlirFunction,
    command: u32,
    environment: LinuxIoctlEnvironment,
    apis: &CallModel,
    max_states: usize,
) -> Vec<Sink> {
    find_sinks_with_arch(
        lf,
        RegArch::AArch64,
        |machine| {
            let seed = seed_linux_ioctl_aarch64(machine);
            let command = machine.dom.constant(Width::W32, command as u128);
            machine
                .regs
                .write(&mut machine.dom, &VReg::phys("w1"), command);
            seed_linux_ioctl_environment(machine, environment);
            seed.taint_spec()
        },
        apis,
        max_states,
    )
}

pub fn find_linux_ioctl_sinks(lf: &LlirFunction, max_states: usize) -> Vec<Sink> {
    find_linux_ioctl_sinks_with_apis(lf, &CallModel::new(), max_states)
}

/// Mark the four integer-argument registers (`rcx`/`rdx`/`r8`/`r9`) as attacker
/// input. Real dispatchers delegate to per-IOCTL helpers `ProcessX(UserBuffer,
/// len, ...)` reached by direct calls the engine does not yet follow; analyzing
/// each *helper* with its arguments assumed tainted (the assume-tainted-entry
/// model) recovers those sinks without inter-procedural exploration.
pub fn seed_tainted_args(m: &mut Machine<Symbolic>) -> TaintSpec {
    let mut t = TaintSpec::new();
    for (i, r) in ["rcx", "rdx", "r8", "r9"].iter().enumerate() {
        let s = m.dom.fresh(Width::W64);
        if let Expr::Sym { id, .. } = *m.dom.pool.get(s) {
            t.mark(id, format!("Arg{i}"));
        }
        m.regs.write(&mut m.dom, &VReg::phys(*r), s);
    }
    t
}

/// Explore `lf` as a standalone function whose arguments are attacker-controlled
/// (see [`seed_tainted_args`]), resolving `apis` calls. Complements
/// [`find_ioctl_sinks_with_apis`]: that seeds the dispatcher's IRP, this seeds the
/// per-IOCTL helper functions the dispatcher calls.
pub fn find_function_sinks_with_apis(
    lf: &LlirFunction,
    apis: &CallModel,
    max_states: usize,
) -> Vec<Sink> {
    find_sinks(
        lf,
        |m| {
            let t = seed_tainted_args(m);
            seed_iat(m, apis);
            t
        },
        apis,
        max_states,
    )
}

/// Stateful, multi-invocation version of [`find_function_sinks_with_apis`]: runs
/// the helper `rounds` times, carrying the heap/global state forward, so
/// *cross-invocation* lifecycle bugs are found — e.g. a block allocated on one
/// IOCTL (command 1), freed on another (command 2), and used or freed again on a
/// third (command 3) through a persisted global pointer. This is what catches the
/// use-after-free / double-free a single run structurally cannot.
pub fn find_function_stateful_sinks(
    lf: &LlirFunction,
    apis: &CallModel,
    max_states: usize,
    rounds: usize,
) -> Vec<Sink> {
    find_sinks_stateful(
        lf,
        |m| {
            let t = seed_tainted_args(m);
            seed_iat(m, apis);
            t
        },
        apis,
        max_states,
        rounds,
    )
}

/// Convenience: just the attacker-controlled *write* sinks (the classic
/// write-what-where primitive).
pub fn find_arbitrary_writes(lf: &LlirFunction, max_states: usize) -> Vec<Sink> {
    find_ioctl_sinks(lf, max_states)
        .into_iter()
        .filter(|s| s.kind == SinkKind::ControlledWrite)
        .collect()
}

/// Build a [`CallModel`] from resolved driver imports: `imports` maps an
/// (undecorated) Windows kernel-API name to the call-site VA the disassembler
/// targets (the IAT thunk). Each recognized API is attached to the
/// [`ApiSummary`] that lets the explorer detect the primitive it can expose —
/// `memcpy`/pool/probe/process/physical-memory/file/format-string. Unknown names
/// are ignored. This is the seam the PE import table fills to drive a real `.sys`.
pub fn driver_api_model(imports: &BTreeMap<String, u64>) -> CallModel {
    use SinkKind::*;
    let mut model = CallModel::new();
    for (name, &va) in imports {
        let summary = match name.as_str() {
            "memcpy" | "memmove" | "RtlCopyMemory" | "RtlMoveMemory" => ApiSummary::CopyMemory,
            "ExAllocatePool"
            | "ExAllocatePoolWithTag"
            | "ExAllocatePool2"
            | "ExAllocatePoolWithQuotaTag" => ApiSummary::Alloc { size_arg: 1 },
            "ExFreePool" | "ExFreePoolWithTag" => ApiSummary::Free { ptr_arg: 0 },
            "ProbeForRead" | "ProbeForWrite" => ApiSummary::Probe {
                addr_arg: 0,
                len_arg: 1,
            },
            "ZwTerminateProcess" | "NtTerminateProcess" => ApiSummary::DangerousCall {
                args: &[0],
                kind: ProcessTermination,
            },
            "MmMapIoSpace" | "MmMapIoSpaceEx" | "ZwMapViewOfSection" | "MmCopyMemory" => {
                ApiSummary::DangerousCall {
                    args: &[0, 1],
                    kind: PhysicalMemory,
                }
            }
            // File APIs: flag when an attacker-controlled parameter reaches the call.
            // Per-API arg lists target the value-carrying params an attacker steers
            // (DesiredAccess / CreateDisposition / CreateOptions / Buffer / Length /
            // OpenOptions), not the output handle. NOTE: the attacker FILENAME lives
            // in OBJECT_ATTRIBUTES.ObjectName->Buffer (tainted by reference, several
            // derefs deep) -- value-taint on the OA pointer arg does not fire, so a
            // pure-filename ZwDeleteFile is not yet caught; that needs struct-deref
            // taint. The disposition/options/access/buffer/length value-taint IS caught.
            "ZwCreateFile" | "IoCreateFile" => ApiSummary::DangerousCall {
                args: &[1, 2, 7, 8],
                kind: FileOperation,
            },
            "ZwOpenFile" => ApiSummary::DangerousCall {
                args: &[1, 2, 5],
                kind: FileOperation,
            },
            "ZwWriteFile" => ApiSummary::DangerousCall {
                args: &[5, 6],
                kind: FileOperation,
            },
            "ZwDeleteFile" => ApiSummary::DangerousCall {
                args: &[0],
                kind: FileOperation,
            },
            "sprintf" | "swprintf" | "vsprintf" | "vswprintf" | "_snprintf" | "_snwprintf" => {
                ApiSummary::DangerousCall {
                    args: &[1],
                    kind: FormatString,
                }
            }
            _ => continue,
        };
        model.insert(va, summary);
    }
    model
}

/// Build the narrow Linux kernel-call model used by admitted AArch64 ioctl
/// handlers. The frontend supplies deterministic target-VA to ELF-symbol names;
/// unsupported calls remain conservative return-value havoc in the explorer.
pub fn linux_driver_api_model(external_calls: &BTreeMap<u64, String>) -> CallModel {
    let mut model = CallModel::new();
    for (&va, name) in external_calls {
        let summary = match name.as_str() {
            // Synchronization is an explicit environment no-op for the
            // single-threaded handler run; the return is conservatively havoced.
            "mutex_lock" | "mutex_unlock" | "_printk" => ApiSummary::HavocReturn,
            "__arch_copy_from_user" | "copy_from_user" | "copy_to_user" | "memcpy" | "memmove" => {
                ApiSummary::CopyMemory
            }
            "__kmalloc_noprof" | "kmalloc" | "kzalloc" => ApiSummary::Alloc { size_arg: 0 },
            "memdup_user" => ApiSummary::Alloc { size_arg: 1 },
            "kfree" => ApiSummary::Free { ptr_arg: 0 },
            _ => continue,
        };
        model.insert(va, summary);
    }
    model
}

/// Build the narrow same-object helper model used by admitted Linux handlers.
/// Local helpers are never inferred by signature: each accepted symbol is an
/// explicit environment contract for the corresponding driver family.
pub fn linux_local_api_model(local_calls: &BTreeMap<u64, String>) -> CallModel {
    let mut model = CallModel::new();
    for (&va, name) in local_calls {
        let summary = match name.as_str() {
            // `enum pci_barno` has the valid signed range BAR_0..BAR_5. The
            // vulnerable helper uses this argument as a fixed-table index.
            "pci_endpoint_test_bar" => ApiSummary::BoundedSignedIndex {
                index_arg: 1,
                width: Width::W32,
                min: 0,
                max: 5,
            },
            _ => continue,
        };
        model.insert(va, summary);
    }
    model
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{
        BinOp, CallTarget, CmpOp, Flag, LlirBlock, LlirInstr, MemOp, Op, Value,
    };
    use crate::symbolic::explore::{ApiSummary, Severity, SinkKind};

    #[test]
    fn linux_ioctl_seed_uses_aapcs64_registers_and_precise_widths() {
        let mut machine = Machine::new_with_arch(Symbolic::new(), crate::exec::RegArch::AArch64);
        let seed = seed_linux_ioctl(&mut machine).expect("seed AArch64 ioctl ABI");

        assert_eq!(machine.regs.arch(), crate::exec::RegArch::AArch64);
        let x0 = machine.regs.read(&mut machine.dom, &VReg::phys("x0"));
        assert_eq!(machine.dom.as_u64(&x0), Some(LINUX_FILE));

        let w1 = machine.regs.read(&mut machine.dom, &VReg::phys("w1"));
        let mut cmd_symbols = BTreeMap::new();
        machine.dom.pool.collect_syms(w1, &mut cmd_symbols);
        assert_eq!(cmd_symbols.get(&seed.cmd_sym), Some(&Width::W32));
        assert_eq!(seed.taint_spec().label(seed.cmd_sym), Some("IoctlCmd"));

        let x2 = machine.regs.read(&mut machine.dom, &VReg::phys("x2"));
        let mut arg_symbols = BTreeMap::new();
        machine.dom.pool.collect_syms(x2, &mut arg_symbols);
        assert_eq!(arg_symbols.get(&seed.arg_sym), Some(&Width::W64));
        assert_eq!(seed.taint_spec().label(seed.arg_sym), Some("IoctlArg"));

        let sp = machine.regs.read(&mut machine.dom, &VReg::phys("sp"));
        assert_eq!(machine.dom.as_u64(&sp), Some(LINUX_STACK));
        let rcx = machine.regs.read(&mut machine.dom, &VReg::phys("rcx"));
        assert_eq!(machine.dom.as_u64(&rcx), Some(0));
    }

    #[test]
    fn linux_ioctl_explorer_uses_aapcs64_call_arguments() {
        let lf = func(vec![(
            0x1000,
            vec![
                Op::Call {
                    target: CallTarget::Direct(0x9000),
                },
                Op::Return,
            ],
            0x1008,
            vec![],
        )]);
        let mut apis = CallModel::new();
        apis.insert(
            0x9000,
            ApiSummary::DangerousCall {
                args: &[2],
                kind: SinkKind::PhysicalMemory,
            },
        );

        let sinks = find_linux_ioctl_sinks_with_apis(&lf, &apis, 32);
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].kind, SinkKind::PhysicalMemory);
        assert_eq!(sinks[0].tainted_by, vec!["IoctlArg".to_string()]);
    }

    #[test]
    fn linux_ioctl_path_accounting_rejects_implicit_call_havoc() {
        let lf = func(vec![(
            0x1000,
            vec![
                Op::Call {
                    target: CallTarget::Direct(0x9000),
                },
                Op::Return,
            ],
            0x1008,
            vec![],
        )]);

        crate::symbolic::reset_execution_path_stats();
        find_linux_ioctl_sinks(&lf, 32);
        let implicit = crate::symbolic::execution_path_stats();
        assert_eq!(implicit.unmodeled_calls.get(&0x1000), Some(&1));
        assert_eq!(implicit.incomplete_stops(), 1);

        let apis = CallModel::from([(0x9000, ApiSummary::HavocReturn)]);
        crate::symbolic::reset_execution_path_stats();
        find_linux_ioctl_sinks_with_apis(&lf, &apis, 32);
        let explicit = crate::symbolic::execution_path_stats();
        assert!(explicit.unmodeled_calls.is_empty());
        assert_eq!(explicit.incomplete_stops(), 0);
    }

    #[test]
    fn linux_ioctl_reports_path_controlled_null_page_deref() {
        let lf = func(vec![
            (
                0x1000,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("w1")),
                        rhs: Value::Const(6),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x2000,
                        inverted: false,
                    },
                ],
                0x1008,
                vec![0x1008, 0x2000],
            ),
            (0x1008, vec![Op::Return], 0x100c, vec![]),
            (
                0x2000,
                vec![
                    Op::Load {
                        dst: VReg::phys("w8"),
                        addr: MemOp::plain(None, None, 1, 0x20, 1),
                    },
                    Op::Return,
                ],
                0x2008,
                vec![],
            ),
        ]);
        let sinks = find_linux_ioctl_sinks(&lf, 32);
        let null = sinks
            .iter()
            .find(|sink| sink.kind == SinkKind::NullDeref)
            .expect("cmd-controlled low-page dereference");
        assert_eq!(null.tainted_by, vec!["IoctlCmd".to_string()]);
        assert_eq!(null.severity, Severity::Constrained);
    }

    #[test]
    fn linux_driver_api_model_recognizes_usercopy_alloc_and_free() {
        let calls = BTreeMap::from([
            (0x1000, "__arch_copy_from_user".to_string()),
            (0x2000, "memdup_user".to_string()),
            (0x3000, "kfree".to_string()),
            (0x4000, "mutex_lock".to_string()),
            (0x5000, "_printk".to_string()),
        ]);
        let model = linux_driver_api_model(&calls);
        assert_eq!(model.get(&0x1000), Some(&ApiSummary::CopyMemory));
        assert_eq!(model.get(&0x2000), Some(&ApiSummary::Alloc { size_arg: 1 }));
        assert_eq!(model.get(&0x3000), Some(&ApiSummary::Free { ptr_arg: 0 }));
        assert_eq!(model.get(&0x4000), Some(&ApiSummary::HavocReturn));
        assert_eq!(model.get(&0x5000), Some(&ApiSummary::HavocReturn));
    }

    #[test]
    fn linux_local_api_model_recognizes_registered_pci_bar_helper_only() {
        let calls = BTreeMap::from([
            (0x1000, "pci_endpoint_test_bar".to_string()),
            (0x2000, "unregistered_local_helper".to_string()),
        ]);
        let model = linux_local_api_model(&calls);
        assert_eq!(
            model.get(&0x1000),
            Some(&ApiSummary::BoundedSignedIndex {
                index_arg: 1,
                width: Width::W32,
                min: 0,
                max: 5,
            })
        );
        assert!(!model.contains_key(&0x2000));
    }

    #[test]
    fn registered_command_preserves_symbolic_ioctl_argument_for_local_summary() {
        let lf = func(vec![(
            0x1000,
            vec![
                Op::Assign {
                    dst: VReg::phys("w1"),
                    src: Value::Reg(VReg::phys("w2")),
                },
                Op::Call {
                    target: CallTarget::Direct(0x9000),
                },
                Op::Return,
            ],
            0x100c,
            vec![],
        )]);
        let mut apis = CallModel::new();
        apis.insert(
            0x9000,
            ApiSummary::BoundedSignedIndex {
                index_arg: 1,
                width: Width::W32,
                min: 0,
                max: 5,
            },
        );

        let sinks = find_linux_ioctl_sinks_for_command_with_apis(
            &lf,
            0x5001,
            LinuxIoctlEnvironment::Generic,
            &apis,
            32,
        );
        let sink = sinks
            .iter()
            .find(|sink| sink.kind == SinkKind::OutOfBoundsIndex)
            .expect("symbolic ioctl arg can violate registered helper range");
        assert_eq!(sink.tainted_by, vec!["IoctlArg".to_string()]);
    }

    fn kinds(sinks: &[Sink]) -> std::collections::BTreeSet<&'static str> {
        sinks.iter().map(|s| kind_str(s.kind)).collect()
    }

    fn kind_str(k: SinkKind) -> &'static str {
        match k {
            SinkKind::ControlledWrite => "write",
            SinkKind::ControlledRead => "read",
            SinkKind::NullDeref => "null",
            SinkKind::StackOverflow => "stack",
            SinkKind::UseAfterFree => "uaf",
            SinkKind::DoubleFree => "double_free",
            SinkKind::IntegerOverflow => "int_overflow",
            SinkKind::DoubleFetch => "double_fetch",
            SinkKind::Shellcode => "shellcode",
            SinkKind::FormatString => "format_string",
            SinkKind::PhysicalMemory => "phys_mem",
            SinkKind::ProbeBypass => "probe_bypass",
            SinkKind::ProcessTermination => "proc_term",
            SinkKind::FileOperation => "file_op",
            SinkKind::ArbitraryMsrWrite => "wrmsr",
            SinkKind::ArbitraryMsrRead => "rdmsr",
            SinkKind::PortAccess => "portio",
            SinkKind::OutOfBoundsIndex => "oob_index",
        }
    }

    fn func(blocks: Vec<(u64, Vec<Op>, u64, Vec<u64>)>) -> LlirFunction {
        let mut out = Vec::new();
        for (start, ops, end, succs) in blocks {
            out.push(LlirBlock {
                start_va: start,
                end_va: end,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(i, op)| LlirInstr {
                        va: start + i as u64 * 4,
                        op,
                    })
                    .collect(),
                succs,
            });
        }
        LlirFunction {
            entry_va: out[0].start_va,
            blocks: out,
        }
    }

    fn load(dst: &str, base: &str, disp: i64, size: u8) -> Op {
        Op::Load {
            dst: VReg::phys(dst),
            addr: MemOp::plain(Some(VReg::phys(base)), None, 1, disp, size),
        }
    }

    /// A synthetic vulnerable METHOD_NEITHER IOCTL handler:
    ///   stack = [Irp+0xB8]; code = [stack+0x18];
    ///   if (code == 0x803) { buf = [stack+0x20]; *buf = 0x41414141; } // arb write
    /// The engine must find the write and report the IOCTL code 0x803 as witness.
    #[test]
    fn finds_method_neither_arbitrary_write_with_ioctl_witness() {
        const MAGIC: i64 = 0x803;
        let lf = func(vec![
            // B0: load StackLoc + IoControlCode; branch on code == MAGIC
            (
                0x1000,
                vec![
                    load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
                    load("ecx", "r10", SL_IOCTL_CODE as i64, 4),
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("ecx")),
                        rhs: Value::Const(MAGIC),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1020, // vulnerable block
                        inverted: false,
                    },
                ],
                0x1010,
                vec![0x1020, 0x1010],
            ),
            // B_skip: safe path
            (0x1010, vec![Op::Return], 0x1014, vec![]),
            // B_vuln: write attacker value through the attacker-controlled buffer
            (
                0x1020,
                vec![
                    load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
                    load("rdi", "r10", SL_TYPE3_BUFFER as i64, 8),
                    Op::Store {
                        addr: MemOp::plain(Some(VReg::phys("rdi")), None, 1, 0, 8),
                        src: Value::Const(0x4141_4141),
                    },
                    Op::Return,
                ],
                0x1030,
                vec![],
            ),
        ]);

        // Seed and run, capturing the IOCTL-code symbol id for witness lookup.
        let mut probe = Machine::new(Symbolic::new());
        let seed = seed_irp(&mut probe);

        let writes = find_arbitrary_writes(&lf, 1000);
        assert_eq!(writes.len(), 1, "expected exactly one controlled write");
        let w = &writes[0];
        assert_eq!(w.va, 0x1028, "store VA");
        assert_eq!(
            w.witness.values.get(&seed.ioctl_code_sym).copied(),
            Some(MAGIC as u128),
            "witness must drive IoControlCode = {:#x}",
            MAGIC
        );
        // METHOD_NEITHER passes the raw caller pointer in Type3InputBuffer, so
        // the address is fully attacker-chosen (write-where).
        assert_eq!(w.severity, Severity::Arbitrary, "expected write-where");
        assert_eq!(w.tainted_by, vec!["Type3InputBuffer".to_string()]);
    }

    /// Positive control for the KMDF `WdfRequestRetrieveInputBuffer` model
    /// (`ApiSummary::RetrieveBuffer` via the call-site map). An UNGUARDED handler that
    /// retrieves the input buffer and writes through it must produce a `SystemBuffer`-
    /// tainted controlled write — proving the WDF-retrieved buffer flows as precise
    /// attacker taint, the KMDF analogue of `IRP.AssociatedIrp.SystemBuffer`.
    #[test]
    fn wdf_retrieve_input_buffer_taints_systembuffer() {
        use crate::symbolic::explore::set_call_site_summaries;
        // r9 = &buf (scratch local); call <retrieve> (taints *r9); rax = *r9; *rax = x
        let lf = func(vec![(
            0x2000,
            vec![
                Op::Assign {
                    dst: VReg::phys("r9"),
                    src: Value::Const(0x60000),
                }, // va 0x2000: r9 = &buf
                Op::Call {
                    target: CallTarget::Indirect(Value::Addr(0xDEAD)),
                }, // va 0x2004: WdfRequestRetrieveInputBuffer (call-site summarized)
                load("rax", "r9", 0, 8), // va 0x2008: rax = *r9 = tainted buffer ptr
                Op::Store {
                    addr: MemOp::plain(Some(VReg::phys("rax")), None, 1, 0, 8),
                    src: Value::Const(0x4141_4141),
                }, // va 0x200c: *buf = x  -> controlled write through SystemBuffer
                Op::Return,
            ],
            0x2014,
            vec![],
        )]);
        let mut m = std::collections::BTreeMap::new();
        m.insert(0x2004u64, ApiSummary::RetrieveBuffer { out_ptr_arg: 3 });
        set_call_site_summaries(m);
        let sinks = find_function_sinks_with_apis(&lf, &CallModel::new(), 1000);
        set_call_site_summaries(std::collections::BTreeMap::new()); // clear for other tests
        let w = sinks
            .iter()
            .find(|s| s.kind == SinkKind::ControlledWrite)
            .expect("expected a controlled write through the WDF-retrieved buffer");
        assert_eq!(
            w.tainted_by,
            vec!["SystemBuffer".to_string()],
            "WDF-retrieved buffer must carry SystemBuffer taint, got {:?}",
            w.tainted_by
        );
    }

    /// A handler that writes into a *concrete* scratch buffer at an attacker
    /// offset bounded to a 16-byte window: `dst = 0x50000 + (InputBufferLength & 0xF)`.
    /// The address is attacker-*derived* (so it is still flagged, with provenance)
    /// but cannot reach the sentinel, so it must be `Constrained`, not a
    /// write-where `Arbitrary`. This is the `0x87` precision gate doing its job.
    #[test]
    fn bounded_offset_write_is_constrained_not_arbitrary() {
        const BUF: i64 = 0x50000;
        let lf = func(vec![(
            0x1000,
            vec![
                load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
                load("ecx", "r10", SL_INPUT_LEN as i64, 4),
                Op::Bin {
                    dst: VReg::phys("rcx"),
                    op: BinOp::And,
                    lhs: Value::Reg(VReg::phys("rcx")),
                    rhs: Value::Const(0xF),
                },
                Op::Assign {
                    dst: VReg::phys("rdi"),
                    src: Value::Const(BUF),
                },
                Op::Bin {
                    dst: VReg::phys("rdi"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("rdi")),
                    rhs: Value::Reg(VReg::phys("rcx")),
                },
                Op::Store {
                    addr: MemOp::plain(Some(VReg::phys("rdi")), None, 1, 0, 8),
                    src: Value::Const(0x41),
                },
                Op::Return,
            ],
            0x1020,
            vec![],
        )]);

        let writes = find_arbitrary_writes(&lf, 1000);
        assert_eq!(writes.len(), 1, "the controlled write is still reported");
        let w = &writes[0];
        assert_eq!(
            w.severity,
            Severity::Constrained,
            "bounded offset into a fixed buffer is not write-where"
        );
        assert_eq!(w.tainted_by, vec!["InputBufferLength".to_string()]);
    }

    /// End-to-end on **real x86-64 machine bytes** (not hand-built LLIR): lift a
    /// tiny METHOD_NEITHER handler that reads the caller-controlled UserBuffer
    /// pointer and writes through it, then confirm the engine flags the controlled
    /// write. Proves the machine-code → lift → symbolic-detect pipeline.
    #[test]
    fn finds_method_neither_controlled_write_from_machine_bytes() {
        use crate::ir::lift_x86::lift_bytes;
        // mov rax, [rdx+0x30]      ; rax = IRP.UserBuffer (caller pointer)
        // mov qword ptr [rax], 0x41414141   ; *UserBuffer = ...  (controlled write)
        // ret
        let code: &[u8] = &[
            0x48, 0x8B, 0x42, 0x30, // mov rax, [rdx+0x30]
            0x48, 0xC7, 0x00, 0x41, 0x41, 0x41, 0x41, // mov qword [rax], 0x41414141
            0xC3, // ret
        ];
        let instrs = lift_bytes(code, 0x1000, 64);
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1000 + code.len() as u64,
                instrs,
                succs: vec![],
            }],
        };

        let writes = find_arbitrary_writes(&lf, 1000);
        assert_eq!(
            writes.len(),
            1,
            "expected the store through UserBuffer to be flagged"
        );
    }

    /// A read through a METHOD_NEITHER caller pointer is both an
    /// arbitrary-read primitive and (since the pointer is unconstrained) a
    /// null-deref. Both must be reported.
    #[test]
    fn read_through_type3_input_buffer_is_arbitrary_read_and_nulldef() {
        let lf = func(vec![(
            0x1000,
            vec![
                load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
                load("rax", "r10", SL_TYPE3_BUFFER as i64, 8),
                load("rbx", "rax", 0, 8), // rbx = *rax (symbolic addr)
                Op::Return,
            ],
            0x100C,
            vec![],
        )]);

        let sinks = find_ioctl_sinks(&lf, 1000);
        assert_eq!(kinds(&sinks), ["null", "read"].into_iter().collect());
        let read = sinks
            .iter()
            .find(|s| s.kind == SinkKind::ControlledRead)
            .unwrap();
        assert_eq!(read.severity, Severity::Arbitrary);
        assert_eq!(read.tainted_by, vec!["Type3InputBuffer".to_string()]);
        // No write sink for a pure read.
        assert!(find_arbitrary_writes(&lf, 1000).is_empty());
    }

    /// Regression for the complete Windows 11 `usbprint.sys` authority control.
    /// `AssociatedIrp.SystemBuffer` for a `METHOD_BUFFERED` request is an
    /// I/O-manager-owned kernel pointer, not an attacker-selected address.  Once
    /// the handler has rejected NULL and required at least three bytes, ordinary
    /// reads at offsets 2, 1, and 0 are neither controlled-address reads nor
    /// null dereferences.  Buffer *contents* remain attacker-controlled and are
    /// covered independently by the taint-through-memory tests below.
    #[test]
    fn guarded_method_buffered_reads_are_not_pointer_control_findings() {
        let lf = func(vec![
            (
                0x1000,
                vec![
                    load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
                    load("r15", "rdx", IRP_SYSTEM_BUFFER as i64, 8),
                    load("edi", "r10", SL_OUTPUT_LEN as i64, 4),
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("r15")),
                        rhs: Value::Const(0),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1030,
                        inverted: false,
                    },
                ],
                0x1018,
                vec![0x1030, 0x1018],
            ),
            (
                0x1018,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::C),
                        op: CmpOp::Ult,
                        lhs: Value::Reg(VReg::phys("edi")),
                        rhs: Value::Const(3),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::C),
                        target: 0x1030,
                        inverted: false,
                    },
                ],
                0x1020,
                vec![0x1030, 0x1020],
            ),
            (
                0x1020,
                vec![
                    load("eax", "r15", 2, 1),
                    load("r8d", "r15", 1, 1),
                    load("edx", "r15", 0, 1),
                    Op::Return,
                ],
                0x1030,
                vec![],
            ),
            (0x1030, vec![Op::Return], 0x1034, vec![]),
        ]);

        let sinks = find_ioctl_sinks(&lf, 1000);
        assert!(
            sinks.is_empty(),
            "kernel-owned guarded SystemBuffer reads must not be pointer-control findings: {sinks:?}"
        );
    }

    /// A handler that null-checks a METHOD_NEITHER pointer before dereferencing
    /// (`if (Type3InputBuffer == 0) return; *Type3InputBuffer = x;`) must NOT report a
    /// null deref on the storing path — the path condition already guards it
    /// non-null — while still reporting the controlled write. This is the
    /// path-sensitive guard suppression our static `ioctl_taint` approximates and
    /// IOCTLance does with manual global tracking.
    #[test]
    fn null_check_guard_suppresses_nulldef_but_keeps_write() {
        let lf = func(vec![
            (
                0x1000,
                vec![
                    load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
                    load("rax", "r10", SL_TYPE3_BUFFER as i64, 8),
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(0),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1010, // null → bail
                        inverted: false,
                    },
                ],
                0x1020,
                vec![0x1010, 0x1020],
            ),
            (0x1010, vec![Op::Return], 0x1014, vec![]),
            (
                0x1020,
                vec![
                    Op::Store {
                        addr: MemOp::plain(Some(VReg::phys("rax")), None, 1, 0, 8),
                        src: Value::Const(0x41),
                    },
                    Op::Return,
                ],
                0x1028,
                vec![],
            ),
        ]);

        let sinks = find_ioctl_sinks(&lf, 1000);
        assert_eq!(
            kinds(&sinks),
            ["write"].into_iter().collect(),
            "guarded deref: a controlled write, but no null deref"
        );
        assert_eq!(sinks[0].severity, Severity::Arbitrary);
    }

    /// The classic primitive that never appears as a raw symbolic store:
    /// `memcpy(UserBuffer, local, len)` — a controlled write hidden inside an
    /// API call. With the callee VA modeled as `CopyMemory`, the engine must
    /// flag the attacker-controlled destination.
    #[test]
    fn memcpy_to_method_neither_user_buffer_is_detected_via_api_summary() {
        const MEMCPY_VA: u64 = 0x9000;
        let lf = func(vec![(
            0x1000,
            vec![
                load("rcx", "rdx", IRP_USER_BUFFER as i64, 8), // dst = UserBuffer
                Op::Assign {
                    dst: VReg::phys("rdx"),
                    src: Value::Const(0x60000),
                }, // src = local buffer (concrete)
                Op::Call {
                    target: CallTarget::Direct(MEMCPY_VA),
                },
                Op::Return,
            ],
            0x1010,
            vec![],
        )]);

        let mut apis = CallModel::new();
        apis.insert(MEMCPY_VA, ApiSummary::CopyMemory);

        // Without the model, the call ends the path → nothing found.
        assert!(
            find_arbitrary_writes(&lf, 1000).is_empty(),
            "unmodeled call hides the primitive"
        );

        // With the model, the memcpy destination is flagged as a controlled write.
        let sinks = find_ioctl_sinks_with_apis(&lf, &apis, 1000);
        let writes: Vec<_> = sinks
            .iter()
            .filter(|s| s.kind == SinkKind::ControlledWrite)
            .collect();
        assert_eq!(writes.len(), 1, "memcpy dst should be one controlled write");
        let w = writes[0];
        assert_eq!(w.va, 0x1008, "the call site VA");
        assert_eq!(w.severity, Severity::Arbitrary);
        assert_eq!(w.tainted_by, vec!["UserBuffer".to_string()]);
        // The concrete `src` buffer is not attacker-derived → no read sink.
        assert!(!sinks.iter().any(|s| s.kind == SinkKind::ControlledRead));
    }

    /// Build a one-block handler ending in a direct call to `api_va`, preceded by
    /// `setup` ops (which stage the argument registers). VAs are 4-aligned.
    fn handler_calling(setup: Vec<Op>, api_va: u64) -> LlirFunction {
        let mut ops = setup;
        ops.push(Op::Call {
            target: CallTarget::Direct(api_va),
        });
        ops.push(Op::Return);
        let end = 0x1000 + ops.len() as u64 * 4;
        func(vec![(0x1000, ops, end, vec![])])
    }

    fn model(name: &str, va: u64) -> CallModel {
        let mut m = BTreeMap::new();
        m.insert(name.to_string(), va);
        driver_api_model(&m)
    }

    /// `ZwTerminateProcess(handle = attacker)` → process-termination finding.
    #[test]
    fn tainted_handle_to_zwterminateprocess() {
        const API: u64 = 0x9000;
        let lf = handler_calling(
            vec![
                load("rax", "rdx", IRP_SYSTEM_BUFFER as i64, 8),
                load("rcx", "rax", 0, 8), // arg0 = attacker-controlled buffer content
            ],
            API,
        );
        let sinks = find_ioctl_sinks_with_apis(&lf, &model("ZwTerminateProcess", API), 1000);
        assert_eq!(kinds(&sinks), ["proc_term"].into_iter().collect());
        assert_eq!(sinks[0].tainted_by, vec!["*SystemBuffer".to_string()]);
    }

    /// The full real-MSVC pattern, end to end: a handle read from buffer contents
    /// (`rcx = *SystemBuffer`, taint-through-memory) passed to an import called
    /// register-indirect (`mov rax,[__imp_ZwTerminateProcess]; call rax`). Both
    /// the IAT-self-pointer resolution and taint-through-memory must fire for the
    /// process-termination sink to appear. (Mirrors test_process_termination.sys.)
    #[test]
    fn register_indirect_import_with_buffer_derived_handle() {
        const SLOT: u64 = 0x40000; // __imp_ZwTerminateProcess IAT slot
        let lf = func(vec![(
            0x1000,
            vec![
                load("rax", "rdx", IRP_SYSTEM_BUFFER as i64, 8), // rax = SystemBuffer ptr
                Op::Load {
                    dst: VReg::phys("rcx"),
                    addr: MemOp::plain(Some(VReg::phys("rax")), None, 1, 0, 8),
                }, // rcx = *SystemBuffer (handle) -> taint-through-memory
                Op::Load {
                    dst: VReg::phys("rax"),
                    addr: MemOp::plain(None, None, 1, SLOT as i64, 8),
                }, // rax = mem[SLOT] = SLOT (seeded self-pointer)
                Op::Call {
                    target: CallTarget::Indirect(Value::Reg(VReg::phys("rax"))),
                },
                Op::Return,
            ],
            0x1014,
            vec![],
        )]);
        let sinks = find_ioctl_sinks_with_apis(&lf, &model("ZwTerminateProcess", SLOT), 1000);
        assert!(
            sinks.iter().any(|s| s.kind == SinkKind::ProcessTermination),
            "expected process-termination via buffer-derived handle, got {:?}",
            kinds(&sinks)
        );
    }

    /// `MmMapIoSpace(phys = attacker, size = attacker)` → physical-memory finding,
    /// provenance covering both tainted args.
    #[test]
    fn tainted_args_to_mmmapiospace() {
        const API: u64 = 0x9000;
        let lf = handler_calling(
            vec![
                load("rax", "rdx", IRP_SYSTEM_BUFFER as i64, 8),
                load("rcx", "rax", 0, 8), // arg0 = phys addr from buffer contents
                load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
                load("rdx", "r10", SL_INPUT_LEN as i64, 4), // arg1 = size
            ],
            API,
        );
        let sinks = find_ioctl_sinks_with_apis(&lf, &model("MmMapIoSpace", API), 1000);
        assert_eq!(kinds(&sinks), ["phys_mem"].into_iter().collect());
        assert_eq!(
            sinks[0].tainted_by,
            vec!["*SystemBuffer".to_string(), "InputBufferLength".to_string(),]
        );
    }

    /// `ZwCreateFile(path = attacker)` → file-operation finding.
    #[test]
    fn tainted_path_to_zwcreatefile() {
        const API: u64 = 0x9000;
        // rdx (arg1 = DesiredAccess) comes from SystemBuffer contents. (arg0 is
        // the output FileHandle and is no longer a trigger.)
        let lf = handler_calling(
            vec![
                load("rax", "rdx", IRP_SYSTEM_BUFFER as i64, 8),
                load("rdx", "rax", 0, 8),
            ],
            API,
        );
        let sinks = find_ioctl_sinks_with_apis(&lf, &model("ZwCreateFile", API), 1000);
        assert_eq!(kinds(&sinks), ["file_op"].into_iter().collect());
    }

    /// `sprintf(buf, fmt = attacker, …)` → format-string finding (fmt is arg1).
    #[test]
    fn tainted_format_string_to_sprintf() {
        const API: u64 = 0x9000;
        // rdx (arg1 = format) is a caller pointer read from SystemBuffer contents.
        let lf = handler_calling(
            vec![
                load("rax", "rdx", IRP_SYSTEM_BUFFER as i64, 8),
                load("rdx", "rax", 0, 8),
            ],
            API,
        );
        let sinks = find_ioctl_sinks_with_apis(&lf, &model("sprintf", API), 1000);
        assert_eq!(kinds(&sinks), ["format_string"].into_iter().collect());
    }

    /// `ProbeForRead(addr = SystemBuffer, len = attacker)`: the length can be 0, so
    /// the probe is bypassable; and the probe validates the pointer, so a *later*
    /// write through it is suppressed (no controlled-write false positive).
    #[test]
    fn zero_length_probe_is_bypass_and_validates_pointer() {
        const API: u64 = 0x9000;
        let mut ops = vec![
            load("rcx", "rdx", IRP_SYSTEM_BUFFER as i64, 8), // addr = SystemBuffer
            load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
            load("rdx", "r10", SL_INPUT_LEN as i64, 4), // len = InputBufferLength
            Op::Call {
                target: CallTarget::Direct(API),
            },
            // after the probe, write through the (now validated) pointer
            Op::Store {
                addr: MemOp::plain(Some(VReg::phys("rcx")), None, 1, 0, 8),
                src: Value::Const(0x41),
            },
            Op::Return,
        ];
        let end = 0x1000 + ops.len() as u64 * 4;
        let lf = func(vec![(0x1000, std::mem::take(&mut ops), end, vec![])]);

        let sinks = find_ioctl_sinks_with_apis(&lf, &model("ProbeForRead", API), 1000);
        assert_eq!(
            kinds(&sinks),
            ["probe_bypass"].into_iter().collect(),
            "bypass reported; the validated write is suppressed"
        );
    }

    /// An indirect call through an attacker-controlled function pointer is a
    /// control-flow hijack (shellcode).
    #[test]
    fn indirect_call_through_buffer_derived_pointer_is_shellcode() {
        let lf = func(vec![(
            0x1000,
            vec![
                load("rcx", "rdx", IRP_SYSTEM_BUFFER as i64, 8),
                load("rax", "rcx", 0, 8), // rax = attacker fn ptr from contents
                Op::Call {
                    target: CallTarget::Indirect(Value::Reg(VReg::phys("rax"))),
                },
                Op::Return,
            ],
            0x100C,
            vec![],
        )]);
        let sinks = find_ioctl_sinks(&lf, 1000);
        assert_eq!(kinds(&sinks), ["shellcode"].into_iter().collect());
        assert_eq!(sinks[0].severity, Severity::Arbitrary);
    }

    fn model_multi(entries: &[(&str, u64)]) -> CallModel {
        let mut m = BTreeMap::new();
        for (name, va) in entries {
            m.insert(name.to_string(), *va);
        }
        driver_api_model(&m)
    }

    fn assign(dst: &str, src: &str) -> Op {
        Op::Assign {
            dst: VReg::phys(dst),
            src: Value::Reg(VReg::phys(src)),
        }
    }

    fn call(va: u64) -> Op {
        Op::Call {
            target: CallTarget::Direct(va),
        }
    }

    /// `p = ExAllocatePoolWithTag(); ExFreePool(p); ExFreePool(p);` → double-free.
    /// The block saves the returned base in a callee-saved register (`rbx`) since
    /// the free summary havocs `rax`.
    #[test]
    fn double_free_is_detected() {
        const ALLOC: u64 = 0x9000;
        const FREE: u64 = 0x9100;
        let ops = vec![
            call(ALLOC), // rax = base
            assign("rbx", "rax"),
            assign("rcx", "rbx"), // arg0 = base
            call(FREE),           // free #1
            assign("rcx", "rbx"), // arg0 = base
            call(FREE),           // free #2 → double free
            Op::Return,
        ];
        let end = 0x1000 + ops.len() as u64 * 4;
        let lf = func(vec![(0x1000, ops, end, vec![])]);
        let apis = model_multi(&[("ExAllocatePoolWithTag", ALLOC), ("ExFreePool", FREE)]);
        let sinks = find_ioctl_sinks_with_apis(&lf, &apis, 1000);
        assert_eq!(kinds(&sinks), ["double_free"].into_iter().collect());
    }

    /// `p = ExAllocatePoolWithTag(); ExFreePool(p); memcpy(p, …);` → use-after-free
    /// (the freed block is written through the modeled copy).
    #[test]
    fn use_after_free_via_memcpy_is_detected() {
        const ALLOC: u64 = 0x9000;
        const FREE: u64 = 0x9100;
        const MEMCPY: u64 = 0x9200;
        let ops = vec![
            call(ALLOC), // rax = base
            assign("rbx", "rax"),
            assign("rcx", "rbx"),
            call(FREE),           // free
            assign("rcx", "rbx"), // dst = freed base
            Op::Assign {
                dst: VReg::phys("rdx"),
                src: Value::Const(0x60000),
            }, // src = scratch
            call(MEMCPY),         // use after free
            Op::Return,
        ];
        let end = 0x1000 + ops.len() as u64 * 4;
        let lf = func(vec![(0x1000, ops, end, vec![])]);
        let apis = model_multi(&[
            ("ExAllocatePoolWithTag", ALLOC),
            ("ExFreePool", FREE),
            ("memcpy", MEMCPY),
        ]);
        let sinks = find_ioctl_sinks_with_apis(&lf, &apis, 1000);
        assert!(
            sinks.iter().any(|s| s.kind == SinkKind::UseAfterFree),
            "expected a use-after-free, got {:?}",
            kinds(&sinks)
        );
    }

    /// Reading the same attacker pointer twice on one path is a double-fetch
    /// (TOCTOU): `*Type3InputBuffer` … `*Type3InputBuffer`.
    #[test]
    fn double_fetch_of_attacker_pointer() {
        let lf = func(vec![(
            0x1000,
            vec![
                load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
                load("rax", "r10", SL_TYPE3_BUFFER as i64, 8), // rax = Type3InputBuffer
                load("rbx", "rax", 0, 8),                      // fetch #1
                load("rcx", "rax", 0, 8),                      // fetch #2 → double-fetch
                Op::Return,
            ],
            0x1014,
            vec![],
        )]);
        let sinks = find_ioctl_sinks(&lf, 1000);
        assert!(
            sinks.iter().any(|s| s.kind == SinkKind::DoubleFetch),
            "expected a double-fetch, got {:?}",
            kinds(&sinks)
        );
    }

    /// `memcpy(stack_buffer, src, attacker_len)` — an attacker-controlled length
    /// copy onto the stack is a stack buffer overflow.
    #[test]
    fn attacker_length_memcpy_onto_stack_is_overflow() {
        const MEMCPY: u64 = 0x9200;
        let ops = vec![
            Op::Assign {
                dst: VReg::phys("rsp"),
                src: Value::Const(0x200000),
            },
            Op::Assign {
                dst: VReg::phys("rcx"),
                src: Value::Reg(VReg::phys("rsp")),
            }, // dst is structurally the stack pointer
            load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
            load("r8", "r10", SL_INPUT_LEN as i64, 4), // len = InputBufferLength (attacker, arg2)
            call(MEMCPY),
            Op::Return,
        ];
        let end = 0x1000 + ops.len() as u64 * 4;
        let lf = func(vec![(0x1000, ops, end, vec![])]);
        let sinks = find_ioctl_sinks_with_apis(&lf, &model("memcpy", MEMCPY), 1000);
        assert!(
            sinks.iter().any(|s| s.kind == SinkKind::StackOverflow),
            "expected a stack overflow, got {:?}",
            kinds(&sinks)
        );
    }

    /// Unchecked attacker-controlled size arithmetic that can wrap:
    /// `eax = InputBufferLength; ebx = eax + 0x1000` overflows when the length is
    /// near `UINT_MAX` — the classic precursor to an undersized allocation.
    #[test]
    fn attacker_size_arithmetic_can_overflow() {
        let lf = func(vec![(
            0x1000,
            vec![
                load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
                load("eax", "r10", SL_INPUT_LEN as i64, 4), // eax = InputBufferLength
                Op::Bin {
                    dst: VReg::phys("ebx"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("eax")),
                    rhs: Value::Const(0x1000),
                },
                Op::Return,
            ],
            0x1010,
            vec![],
        )]);
        let sinks = find_ioctl_sinks(&lf, 1000);
        assert!(
            sinks.iter().any(|s| s.kind == SinkKind::IntegerOverflow),
            "expected an integer overflow, got {:?}",
            kinds(&sinks)
        );
        let io = sinks
            .iter()
            .find(|s| s.kind == SinkKind::IntegerOverflow)
            .unwrap();
        assert_eq!(io.tainted_by, vec!["InputBufferLength".to_string()]);
    }

    /// Cross-invocation lifecycle: a block is allocated on one IOCTL (cmd 1) and
    /// its pointer saved to a *global*; freed on another (cmd 2); and used / freed
    /// again on a third (cmd 3). No single invocation sees alloc+free+use — only
    /// the stateful multi-invocation sweep, carrying the heap/global forward, can.
    /// Must report both use-after-free and double-free.
    #[test]
    fn cross_invocation_uaf_and_double_free() {
        const ALLOC: u64 = 0x40000;
        const FREE: u64 = 0x40008;
        const GLOBAL: i64 = 0x50000; // persisted pointer in ".data"
        let store_global = |reg: &str| Op::Store {
            addr: MemOp::plain(None, None, 1, GLOBAL, 8),
            src: Value::Reg(VReg::phys(reg)),
        };
        let load_global = |reg: &str| Op::Load {
            dst: VReg::phys(reg),
            addr: MemOp::plain(None, None, 1, GLOBAL, 8),
        };
        let cmp_jmp = |start: u64, n: i64, target: u64, end: u64, succs: Vec<u64>| {
            (
                start,
                vec![
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        op: CmpOp::Eq,
                        lhs: Value::Reg(VReg::phys("rcx")), // arg0 = command (tainted)
                        rhs: Value::Const(n),
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target,
                        inverted: false,
                    },
                ],
                end,
                succs,
            )
        };
        let lf = func(vec![
            // dispatch: command == 1 / 2 / 3
            cmp_jmp(0x1000, 1, 0x1100, 0x1008, vec![0x1100, 0x1008]),
            cmp_jmp(0x1008, 2, 0x1200, 0x1010, vec![0x1200, 0x1010]),
            cmp_jmp(0x1010, 3, 0x1300, 0x1018, vec![0x1300, 0x1018]),
            (0x1018, vec![Op::Return], 0x101c, vec![]),
            // cmd 1: g = ExAllocatePoolWithTag()
            (
                0x1100,
                vec![call(ALLOC), store_global("rax"), Op::Return],
                0x110c,
                vec![],
            ),
            // cmd 2: ExFreePoolWithTag(g)
            (
                0x1200,
                vec![load_global("rcx"), call(FREE), Op::Return],
                0x120c,
                vec![],
            ),
            // cmd 3: use *g
            (
                0x1300,
                vec![
                    load_global("rax"),
                    Op::Load {
                        dst: VReg::phys("rbx"),
                        addr: MemOp::plain(Some(VReg::phys("rax")), None, 1, 0, 8),
                    },
                    Op::Return,
                ],
                0x130c,
                vec![],
            ),
        ]);
        let apis = model_multi(&[
            ("ExAllocatePoolWithTag", ALLOC),
            ("ExFreePoolWithTag", FREE),
        ]);

        // Single invocation sees nothing (alloc/free/use are separate paths).
        assert!(
            !find_function_sinks_with_apis(&lf, &apis, 2000)
                .iter()
                .any(|s| matches!(s.kind, SinkKind::UseAfterFree | SinkKind::DoubleFree)),
            "a single invocation cannot observe the cross-invocation bug"
        );

        // Stateful multi-invocation recovers both.
        let sinks = find_function_stateful_sinks(&lf, &apis, 2000, 4);
        assert!(
            sinks.iter().any(|s| s.kind == SinkKind::UseAfterFree),
            "expected use-after-free, got {:?}",
            kinds(&sinks)
        );
        assert!(
            sinks.iter().any(|s| s.kind == SinkKind::DoubleFree),
            "expected double-free, got {:?}",
            kinds(&sinks)
        );
    }

    /// A handler with no attacker-controlled write must report nothing.
    #[test]
    fn no_write_no_finding() {
        let lf = func(vec![(
            0x1000,
            vec![
                load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
                load("ecx", "r10", SL_IOCTL_CODE as i64, 4),
                // benign: add code to a register, no store
                Op::Bin {
                    dst: VReg::phys("eax"),
                    op: BinOp::Add,
                    lhs: Value::Reg(VReg::phys("ecx")),
                    rhs: Value::Const(1),
                },
                Op::Return,
            ],
            0x1010,
            vec![],
        )]);
        assert!(find_arbitrary_writes(&lf, 1000).is_empty());
    }
}
