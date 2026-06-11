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

use crate::exec::{Domain, Machine};
use crate::ir::types::{Endian, LlirFunction, VReg, Width};
use crate::symbolic::explore::{find_sinks, ApiSummary, CallModel, Sink, SinkKind, TaintSpec};
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

/// The free-symbol ids of the attacker-controlled IRP fields, so a witness
/// [`Model`](crate::symbolic::Model) can be interpreted (e.g. which value of the
/// IoControlCode reaches a sink).
#[derive(Debug, Clone, Copy)]
pub struct IrpSeed {
    pub ioctl_code_sym: u32,
    pub system_buffer_sym: u32,
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
        t.mark(self.system_buffer_sym, "SystemBuffer");
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
/// `rdx`=Irp (both concrete), with the attacker-controlled IRP fields symbolic.
/// The Irp→IO_STACK_LOCATION pointer is concrete so the handler can chase it.
pub fn seed_irp(m: &mut Machine<Symbolic>) -> IrpSeed {
    let dev = m.dom.constant(Width::W64, DEVICE_OBJECT as u128);
    m.regs.write(&mut m.dom, &VReg::phys("rcx"), dev);
    let irp = m.dom.constant(Width::W64, IRP as u128);
    m.regs.write(&mut m.dom, &VReg::phys("rdx"), irp);

    // IRP.Tail.Overlay.CurrentStackLocation → a concrete, chase-able pointer.
    store_const(m, IRP + IRP_STACK_LOCATION, STACK_LOC, Width::W64);

    let system_buffer_sym = store_sym(m, IRP + IRP_SYSTEM_BUFFER, Width::W64);
    let user_buffer_sym = store_sym(m, IRP + IRP_USER_BUFFER, Width::W64);
    let output_len_sym = store_sym(m, STACK_LOC + SL_OUTPUT_LEN, Width::W32);
    let input_len_sym = store_sym(m, STACK_LOC + SL_INPUT_LEN, Width::W32);
    let ioctl_code_sym = store_sym(m, STACK_LOC + SL_IOCTL_CODE, Width::W32);
    let type3_buffer_sym = store_sym(m, STACK_LOC + SL_TYPE3_BUFFER, Width::W64);

    IrpSeed {
        ioctl_code_sym,
        system_buffer_sym,
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
            "ZwCreateFile" | "IoCreateFile" | "ZwOpenFile" | "ZwWriteFile" | "ZwDeleteFile" => {
                ApiSummary::DangerousCall {
                    args: &[0],
                    kind: FileOperation,
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{
        BinOp, CallTarget, CmpOp, Flag, LlirBlock, LlirInstr, MemOp, Op, Value,
    };
    use crate::symbolic::explore::{ApiSummary, Severity, SinkKind};

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

    /// A synthetic vulnerable IOCTL handler:
    ///   stack = [Irp+0xB8]; code = [stack+0x18];
    ///   if (code == 0x800) { buf = [Irp+0x18]; *buf = 0x41414141; }  // arb write
    /// The engine must find the write and report the IOCTL code 0x800 as witness.
    #[test]
    fn finds_arbitrary_write_with_ioctl_witness() {
        const MAGIC: i64 = 0x800;
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
                    load("rdi", "rdx", IRP_SYSTEM_BUFFER as i64, 8), // SystemBuffer (symbolic ptr)
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
        assert_eq!(w.va, 0x1024, "store VA");
        assert_eq!(
            w.witness.values.get(&seed.ioctl_code_sym).copied(),
            Some(MAGIC as u128),
            "witness must drive IoControlCode = {:#x}",
            MAGIC
        );
        // The store goes through the unconstrained SystemBuffer pointer → the
        // address is fully attacker-chosen (write-where), tagged with provenance.
        assert_eq!(w.severity, Severity::Arbitrary, "expected write-where");
        assert_eq!(w.tainted_by, vec!["SystemBuffer".to_string()]);
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
    /// tiny handler that reads the attacker-controlled SystemBuffer pointer and
    /// writes through it, then confirm the symbolic engine flags the controlled
    /// write. Proves the machine-code → lift → symbolic-detect pipeline.
    #[test]
    fn finds_controlled_write_from_machine_bytes() {
        use crate::ir::lift_x86::lift_bytes;
        // mov rax, [rdx+0x18]      ; rax = IRP.SystemBuffer (symbolic)
        // mov qword ptr [rax], 0x41414141   ; *SystemBuffer = ...  (controlled write)
        // ret
        let code: &[u8] = &[
            0x48, 0x8B, 0x42, 0x18, // mov rax, [rdx+0x18]
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
            "expected the store through SystemBuffer to be flagged"
        );
    }

    /// A read *through* the attacker-controlled SystemBuffer pointer is both an
    /// arbitrary-read primitive and (since the pointer is unconstrained) a
    /// null-deref. Both must be reported.
    #[test]
    fn read_through_system_buffer_is_arbitrary_read_and_nulldef() {
        let lf = func(vec![(
            0x1000,
            vec![
                load("rax", "rdx", IRP_SYSTEM_BUFFER as i64, 8), // rax = SystemBuffer
                load("rbx", "rax", 0, 8),                        // rbx = *rax (symbolic addr)
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
        assert_eq!(read.tainted_by, vec!["SystemBuffer".to_string()]);
        // No write sink for a pure read.
        assert!(find_arbitrary_writes(&lf, 1000).is_empty());
    }

    /// A handler that null-checks the pointer before dereferencing
    /// (`if (SystemBuffer == 0) return; *SystemBuffer = x;`) must NOT report a
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
                    load("rax", "rdx", IRP_SYSTEM_BUFFER as i64, 8),
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
    /// `memcpy(SystemBuffer, local, len)` — a controlled write hidden inside an
    /// API call. With the callee VA modeled as `CopyMemory`, the engine must
    /// flag the attacker-controlled destination.
    #[test]
    fn memcpy_to_system_buffer_is_detected_via_api_summary() {
        const MEMCPY_VA: u64 = 0x9000;
        let lf = func(vec![(
            0x1000,
            vec![
                load("rcx", "rdx", IRP_SYSTEM_BUFFER as i64, 8), // dst = SystemBuffer
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
        assert_eq!(w.tainted_by, vec!["SystemBuffer".to_string()]);
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
            vec![load("rcx", "rdx", IRP_SYSTEM_BUFFER as i64, 8)], // arg0 = SystemBuffer
            API,
        );
        let sinks = find_ioctl_sinks_with_apis(&lf, &model("ZwTerminateProcess", API), 1000);
        assert_eq!(kinds(&sinks), ["proc_term"].into_iter().collect());
        assert_eq!(sinks[0].tainted_by, vec!["SystemBuffer".to_string()]);
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
                load("rcx", "rdx", IRP_SYSTEM_BUFFER as i64, 8), // arg0 = phys addr
                load("r10", "rdx", IRP_STACK_LOCATION as i64, 8),
                load("rdx", "r10", SL_INPUT_LEN as i64, 4), // arg1 = size
            ],
            API,
        );
        let sinks = find_ioctl_sinks_with_apis(&lf, &model("MmMapIoSpace", API), 1000);
        assert_eq!(kinds(&sinks), ["phys_mem"].into_iter().collect());
        assert_eq!(
            sinks[0].tainted_by,
            vec!["InputBufferLength".to_string(), "SystemBuffer".to_string()]
        );
    }

    /// `ZwCreateFile(path = attacker)` → file-operation finding.
    #[test]
    fn tainted_path_to_zwcreatefile() {
        const API: u64 = 0x9000;
        let lf = handler_calling(vec![load("rcx", "rdx", IRP_SYSTEM_BUFFER as i64, 8)], API);
        let sinks = find_ioctl_sinks_with_apis(&lf, &model("ZwCreateFile", API), 1000);
        assert_eq!(kinds(&sinks), ["file_op"].into_iter().collect());
    }

    /// `sprintf(buf, fmt = attacker, …)` → format-string finding (fmt is arg1).
    #[test]
    fn tainted_format_string_to_sprintf() {
        const API: u64 = 0x9000;
        // rdx (arg1 = format) = SystemBuffer.
        let lf = handler_calling(vec![load("rdx", "rdx", IRP_SYSTEM_BUFFER as i64, 8)], API);
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
    fn indirect_call_through_attacker_pointer_is_shellcode() {
        let lf = func(vec![(
            0x1000,
            vec![
                load("rax", "rdx", IRP_SYSTEM_BUFFER as i64, 8), // rax = attacker fn ptr
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
                src: Value::Const(0x1F8000),
            }, // dst on the stack
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
