//! Glaurung-owned AArch64 instruction decoder.
//!
//! This is the first production slice of the Capstone replacement.  The
//! encoding masks are derived from the AArch64 instruction definitions shipped
//! in Capstone 5.0's LLVM-derived test corpus; see the module tests for exact
//! provenance.  The implementation and compact dispatch are native Rust.

use crate::core::address::Address;
use crate::core::binary::Endianness;
use crate::core::disassembler::{
    Architecture, Disassembler, DisassemblerError, DisassemblerResult,
};
use crate::core::instruction::{Access, Instruction, Operand, VectorShape};
use glaurung_disasm::aarch64_sysregs;
use glaurung_disasm::{aarch64::decode_logical_immediate_mask, sign_extend_scaled};

/// Decoder for the A64 instruction set.
///
/// Unsupported families deliberately return `UnsupportedInstruction` so the
/// migration backend can fall through to Capstone.  Invalid encodings inside a
/// family return `InvalidInstruction` and are not silently reinterpreted.
pub struct NativeAarch64Disassembler {
    endianness: Endianness,
}

impl NativeAarch64Disassembler {
    pub fn new(endianness: Endianness) -> Self {
        Self { endianness }
    }

    fn word(&self, bytes: &[u8]) -> DisassemblerResult<u32> {
        let raw: [u8; 4] = bytes
            .get(..4)
            .ok_or(DisassemblerError::InsufficientBytes())?
            .try_into()
            .expect("four-byte slice");
        Ok(match self.endianness {
            Endianness::Big => u32::from_be_bytes(raw),
            _ => u32::from_le_bytes(raw),
        })
    }

    fn signed_field(word: u32, low_bit: u32, width: u32, scale: u32) -> i64 {
        let field = u64::from((word >> low_bit) & ((1u32 << width) - 1));
        sign_extend_scaled(field, width, scale)
    }

    fn target(address: &Address, displacement: i64) -> i64 {
        address.value.wrapping_add_signed(displacement) as i64
    }

    fn general_register(is_64: bool, register: u32) -> String {
        match (is_64, register) {
            (false, 31) => "wzr".to_string(),
            (true, 29) => "fp".to_string(),
            (true, 30) => "lr".to_string(),
            (true, 31) => "xzr".to_string(),
            (false, n) => format!("w{n}"),
            (true, n) => format!("x{n}"),
        }
    }

    fn register_or_sp(is_64: bool, register: u32) -> String {
        if register == 31 {
            if is_64 {
                "sp".to_string()
            } else {
                "wsp".to_string()
            }
        } else {
            Self::general_register(is_64, register)
        }
    }

    fn simd_load_store_kind(word: u32) -> Option<(&'static str, u8, bool)> {
        let size = (word >> 30) & 0x3;
        let operation = (word >> 22) & 0x3;
        match (size, operation) {
            (0, 0) => Some(("b", 8, false)),
            (0, 1) => Some(("b", 8, true)),
            (0, 2) => Some(("q", 128, false)),
            (0, 3) => Some(("q", 128, true)),
            (1, 0) => Some(("h", 16, false)),
            (1, 1) => Some(("h", 16, true)),
            (2, 0) => Some(("s", 32, false)),
            (2, 1) => Some(("s", 32, true)),
            (3, 0) => Some(("d", 64, false)),
            (3, 1) => Some(("d", 64, true)),
            _ => None,
        }
    }

    /// Scalar floating-point register class selected by A64's `type` field.
    ///
    /// The `10` encoding is reserved.  Keeping this conversion in one place
    /// makes every scalar FP family reject that hole consistently rather than
    /// accidentally treating it as another SIMD spelling.
    fn scalar_fp_kind(word: u32) -> Option<(&'static str, u8)> {
        match (word >> 22) & 0x3 {
            0 => Some(("s", 32)),
            1 => Some(("d", 64)),
            3 => Some(("h", 16)),
            _ => None,
        }
    }

    fn scalar_fp_register(kind: &str, register: u32, access: Access) -> Operand {
        // Preserve the current Capstone-adapter contract during migration:
        // scalar FP width is carried by the register spelling while generic
        // register operands report size zero.
        Operand::register(format!("{kind}{register}"), 0, access)
    }

    fn scalar_simd_register(size: u32, register: u32, access: Access) -> Operand {
        let kind = ["b", "h", "s", "d"][size as usize];
        Operand::register(format!("{kind}{register}"), 0, access)
    }

    fn vector_register(register: u32, lanes: u8, element_bits: u8, access: Access) -> Operand {
        let mut operand = Operand::register(
            format!("v{register}"),
            lanes.saturating_mul(element_bits),
            access,
        );
        operand.vector_shape = Some(VectorShape {
            lanes,
            element_bits,
        });
        operand
    }

    fn vector_lane_register(
        register: u32,
        element_bits: u8,
        index: u32,
        access: Access,
    ) -> Operand {
        let mut operand = Self::vector_register(register, 1, element_bits, access);
        operand.vector_index = Some(index);
        operand
    }

    fn vector_fp_arrangement(word: u32) -> Option<(u8, u8)> {
        match (word & (1 << 30) != 0, word & (1 << 22) != 0) {
            (false, false) => Some((2, 32)),
            (true, false) => Some((4, 32)),
            (true, true) => Some((2, 64)),
            (false, true) => None,
        }
    }

    fn vector_integer_arrangement(word: u32, max_size: u32) -> Option<(u8, u8)> {
        let size = (word >> 22) & 0x3;
        let q = word & (1 << 30) != 0;
        if size > max_size || (size == 3 && !q) {
            return None;
        }
        let element_bits = 8_u8 << size;
        Some(((if q { 128 } else { 64 }) / element_bits, element_bits))
    }

    fn prefetch_operation(operation: u32) -> Option<&'static str> {
        const OPERATIONS: [&str; 18] = [
            "pldl1keep",
            "pldl1strm",
            "pldl2keep",
            "pldl2strm",
            "pldl3keep",
            "pldl3strm",
            "plil1keep",
            "plil1strm",
            "plil2keep",
            "plil2strm",
            "plil3keep",
            "plil3strm",
            "pstl1keep",
            "pstl1strm",
            "pstl2keep",
            "pstl2strm",
            "pstl3keep",
            "pstl3strm",
        ];
        let index = match operation {
            0..=5 => operation,
            8..=13 => operation - 2,
            16..=21 => operation - 4,
            _ => return None,
        };
        OPERATIONS.get(index as usize).copied()
    }

    fn instruction(
        address: &Address,
        bytes: &[u8],
        mnemonic: &str,
        operands: Vec<Operand>,
    ) -> Instruction {
        Instruction {
            address: address.clone(),
            bytes: bytes[..4].to_vec(),
            mnemonic: mnemonic.to_string(),
            operands,
            length: 4,
            arch: "arm64".to_string(),
            semantics: None,
            side_effects: None,
            prefixes: None,
            groups: None,
        }
    }

    fn decode_branch_immediate(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        if word & 0x7c00_0000 != 0x1400_0000 {
            return None;
        }
        let mnemonic = if word & 0x8000_0000 == 0 { "b" } else { "bl" };
        let displacement = Self::signed_field(word, 0, 26, 2);
        Some(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![Operand::immediate(Self::target(address, displacement), 0)],
        ))
    }

    fn decode_conditional_branch(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xff00_0010 != 0x5400_0000 {
            return None;
        }
        const CONDITIONS: [&str; 14] = [
            "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
        ];
        let condition = (word & 0xf) as usize;
        let Some(condition) = CONDITIONS.get(condition) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let displacement = Self::signed_field(word, 5, 19, 2);
        Some(Ok(Self::instruction(
            address,
            bytes,
            &format!("b.{condition}"),
            vec![Operand::immediate(Self::target(address, displacement), 0)],
        )))
    }

    fn decode_compare_branch(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        if word & 0x7e00_0000 != 0x3400_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let nonzero = word & 0x0100_0000 != 0;
        let register = word & 0x1f;
        let register = Self::general_register(is_64, register);
        let displacement = Self::signed_field(word, 5, 19, 2);
        Some(Self::instruction(
            address,
            bytes,
            if nonzero { "cbnz" } else { "cbz" },
            vec![
                // Preserve the current adapter contract during migration. The
                // architecture is encoded in the register name; Capstone's
                // ARM64 adapter reports size 0 for general registers.
                Operand::register(register, 0, Access::Read),
                Operand::immediate(Self::target(address, displacement), 0),
            ],
        ))
    }

    fn decode_branch_register(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        let mnemonic = match word & 0xffff_fc1f {
            0xd61f_0000 => "br",
            0xd63f_0000 => "blr",
            0xd65f_0000 => "ret",
            _ => return None,
        };
        let register = (word >> 5) & 0x1f;
        let operands = if mnemonic == "ret" && register == 30 {
            // AArch64's canonical spelling omits the default link register.
            Vec::new()
        } else {
            let register = Self::general_register(true, register);
            vec![Operand::register(register, 0, Access::Read)]
        };
        Some(Self::instruction(address, bytes, mnemonic, operands))
    }

    fn decode_test_branch(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        if word & 0x7e00_0000 != 0x3600_0000 {
            return None;
        }
        let bit = ((word >> 19) & 0x1f) | ((word >> 26) & 0x20);
        let register = word & 0x1f;
        let register = Self::general_register(bit >= 32, register);
        let displacement = Self::signed_field(word, 5, 14, 2);
        Some(Self::instruction(
            address,
            bytes,
            if word & 0x0100_0000 == 0 {
                "tbz"
            } else {
                "tbnz"
            },
            vec![
                Operand::register(register, 0, Access::Read),
                Operand::immediate(i64::from(bit), 0),
                Operand::immediate(Self::target(address, displacement), 0),
            ],
        ))
    }

    fn decode_exception_generation(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        let (mnemonic, omit_zero) = match word & 0xffe0_001f {
            0xd400_0001 => ("svc", false),
            0xd400_0002 => ("hvc", false),
            0xd400_0003 => ("smc", false),
            0xd420_0000 => ("brk", false),
            0xd440_0000 => ("hlt", false),
            0xd4a0_0001 => ("dcps1", true),
            0xd4a0_0002 => ("dcps2", true),
            0xd4a0_0003 => ("dcps3", true),
            _ => return None,
        };
        let immediate = i64::from((word >> 5) & 0xffff);
        let operands = if omit_zero && immediate == 0 {
            Vec::new()
        } else {
            vec![Operand::immediate(immediate, 0)]
        };
        Some(Self::instruction(address, bytes, mnemonic, operands))
    }

    fn decode_hint_or_barrier(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        if word & 0xffff_f01f == 0xd503_201f {
            let immediate = i64::from((word >> 5) & 0x7f);
            let mnemonic = ["nop", "yield", "wfe", "wfi", "sev", "sevl"]
                .get(immediate as usize)
                .copied()
                .unwrap_or("hint");
            let operands = if mnemonic == "hint" {
                vec![Operand::immediate(immediate, 0)]
            } else {
                Vec::new()
            };
            return Some(Self::instruction(address, bytes, mnemonic, operands));
        }

        let (mnemonic, named_options) = match word & 0xffff_f0ff {
            0xd503_305f => ("clrex", false),
            0xd503_309f => ("dsb", true),
            0xd503_30bf => ("dmb", true),
            0xd503_30df => ("isb", false),
            _ => return None,
        };
        let option = ((word >> 8) & 0xf) as usize;
        let operands = if option == 15 {
            if named_options {
                vec![Operand::register("sy".to_string(), 0, Access::Read)]
            } else {
                Vec::new()
            }
        } else if named_options {
            const OPTIONS: [Option<&str>; 16] = [
                None,
                Some("oshld"),
                Some("oshst"),
                Some("osh"),
                None,
                Some("nshld"),
                Some("nshst"),
                Some("nsh"),
                None,
                Some("ishld"),
                Some("ishst"),
                Some("ish"),
                None,
                Some("ld"),
                Some("st"),
                Some("sy"),
            ];
            OPTIONS[option].map_or_else(
                || vec![Operand::immediate(option as i64, 0)],
                |name| vec![Operand::register(name.to_string(), 0, Access::Read)],
            )
        } else {
            vec![Operand::immediate(option as i64, 0)]
        };
        Some(Self::instruction(address, bytes, mnemonic, operands))
    }

    fn decode_exception_return(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        let mnemonic = match word {
            0xd69f_03e0 => "eret",
            0xd6bf_03e0 => "drps",
            _ => return None,
        };
        Some(Self::instruction(address, bytes, mnemonic, Vec::new()))
    }

    fn generic_system_register_name(encoding: u16) -> String {
        let op0 = (encoding >> 14) & 0x3;
        let op1 = (encoding >> 11) & 0x7;
        let crn = (encoding >> 7) & 0xf;
        let crm = (encoding >> 3) & 0xf;
        let op2 = encoding & 0x7;
        format!("s{op0}_{op1}_c{crn}_c{crm}_{op2}")
    }

    fn decode_system_register_move(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        let read = match word & 0xfff0_0000 {
            0xd530_0000 => true,
            0xd510_0000 => false,
            _ => return None,
        };
        let encoding = ((word >> 5) & 0xffff) as u16;
        let system_register = aarch64_sysregs::lookup(encoding, read)
            .map(str::to_string)
            .unwrap_or_else(|| Self::generic_system_register_name(encoding));
        let general_register = Self::general_register(true, word & 0x1f);
        let operands = if read {
            vec![
                Operand::register(general_register, 64, Access::Write),
                Operand::register(system_register, 64, Access::Read),
            ]
        } else {
            vec![
                Operand::register(system_register, 64, Access::Write),
                Operand::register(general_register, 64, Access::Read),
            ]
        };
        Some(Self::instruction(
            address,
            bytes,
            if read { "mrs" } else { "msr" },
            operands,
        ))
    }

    fn decode_pstate_immediate(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xfff8_f01f != 0xd500_401f {
            return None;
        }
        let field = match ((word >> 16) & 0x7, (word >> 5) & 0x7) {
            (0, 3) => "uao",
            (0, 4) => "pan",
            (0, 5) => "spsel",
            (3, 6) => "daifset",
            (3, 7) => "daifclr",
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            "msr",
            vec![
                Operand::register(field.to_string(), 64, Access::Write),
                Operand::immediate(i64::from((word >> 8) & 0xf), 4),
            ],
        )))
    }

    fn decode_system_instruction(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        let reads_result = match word & 0xfff8_0000 {
            0xd508_0000 => false,
            0xd528_0000 => true,
            _ => return None,
        };
        let encoding = ((word >> 5) & 0x7fff) as u16;
        if !reads_result {
            if let Some((mnemonic, operation, has_register)) =
                aarch64_sysregs::lookup_alias(encoding)
            {
                let mut operands = vec![Operand::register(operation.to_string(), 0, Access::Read)];
                if has_register {
                    operands.push(Operand::register(
                        Self::general_register(true, word & 0x1f),
                        64,
                        Access::Read,
                    ));
                }
                return Some(Self::instruction(address, bytes, mnemonic, operands));
            }
        }

        let op1 = i64::from((word >> 16) & 0x7);
        let crn = (word >> 12) & 0xf;
        let crm = (word >> 8) & 0xf;
        let op2 = i64::from((word >> 5) & 0x7);
        let register = Operand::register(
            Self::general_register(true, word & 0x1f),
            64,
            if reads_result {
                Access::Write
            } else {
                Access::Read
            },
        );
        let fields = vec![
            Operand::immediate(op1, 3),
            Operand::register(format!("c{crn}"), 4, Access::Read),
            Operand::register(format!("c{crm}"), 4, Access::Read),
            Operand::immediate(op2, 3),
        ];
        let operands = if reads_result {
            let mut operands = Vec::with_capacity(5);
            operands.push(register);
            operands.extend(fields);
            operands
        } else {
            let mut operands = fields;
            operands.push(register);
            operands
        };
        Some(Self::instruction(
            address,
            bytes,
            if reads_result { "sysl" } else { "sys" },
            operands,
        ))
    }

    fn decode_pc_relative_address(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        if word & 0x1f00_0000 != 0x1000_0000 {
            return None;
        }
        let page_relative = word & 0x8000_0000 != 0;
        let immediate = (((word >> 5) & 0x7ffff) << 2) | ((word >> 29) & 0x3);
        let displacement =
            ((i64::from(immediate) << 43) >> 43) << if page_relative { 12 } else { 0 };
        let base = if page_relative {
            address.value & !0xfff
        } else {
            address.value
        };
        let target = base.wrapping_add_signed(displacement) as i64;
        let register = Self::general_register(true, word & 0x1f);
        Some(Self::instruction(
            address,
            bytes,
            if page_relative { "adrp" } else { "adr" },
            vec![
                Operand::register(register, 0, Access::Write),
                Operand::immediate(target, 0),
            ],
        ))
    }

    fn decode_add_sub_immediate(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        if word & 0x1f00_0000 != 0x1100_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let subtract = word & 0x4000_0000 != 0;
        let set_flags = word & 0x2000_0000 != 0;
        let destination = word & 0x1f;
        let source = (word >> 5) & 0x1f;
        let shift = if word & 0x0040_0000 != 0 { 12 } else { 0 };
        let immediate = i64::from((word >> 10) & 0xfff) << shift;
        let source = Self::register_or_sp(is_64, source);

        if set_flags && destination == 31 {
            return Some(Self::instruction(
                address,
                bytes,
                if subtract { "cmp" } else { "cmn" },
                vec![
                    Operand::register(source, 0, Access::Read),
                    Operand::immediate(immediate, 0),
                ],
            ));
        }

        if !subtract
            && !set_flags
            && shift == 0
            && immediate == 0
            && (destination == 31 || (word >> 5) & 0x1f == 31)
        {
            return Some(Self::instruction(
                address,
                bytes,
                "mov",
                vec![
                    Operand::register(Self::register_or_sp(is_64, destination), 0, Access::Write),
                    Operand::register(source, 0, Access::Read),
                ],
            ));
        }

        let destination = if set_flags {
            Self::general_register(is_64, destination)
        } else {
            Self::register_or_sp(is_64, destination)
        };
        let mnemonic = match (subtract, set_flags) {
            (false, false) => "add",
            (false, true) => "adds",
            (true, false) => "sub",
            (true, true) => "subs",
        };
        Some(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Operand::register(destination, 0, Access::Write),
                Operand::register(source, 0, Access::Read),
                Operand::immediate(immediate, 0),
            ],
        ))
    }

    fn decode_add_sub_extended_register(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x1fe0_0000 != 0x0b20_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let subtract = word & 0x4000_0000 != 0;
        let set_flags = word & 0x2000_0000 != 0;
        let source_two_number = (word >> 16) & 0x1f;
        let option = ((word >> 13) & 0x7) as usize;
        let shift = (word >> 10) & 0x7;
        let source_one_number = (word >> 5) & 0x1f;
        let destination_number = word & 0x1f;
        if shift > 4 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }

        let source_two_is_64 = is_64 && matches!(option, 3 | 7);
        let mut source_two = Operand::register(
            Self::general_register(source_two_is_64, source_two_number),
            if source_two_is_64 { 64 } else { 32 },
            Access::Read,
        );
        let natural_unsigned = option == if is_64 { 3 } else { 2 };
        let modifier = if natural_unsigned
            && (source_one_number == 31 || (!set_flags && destination_number == 31))
        {
            "lsl"
        } else {
            [
                "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx",
            ][option]
        };
        source_two.text = if shift == 0 {
            format!("{}, {modifier}", source_two.register.as_deref().unwrap())
        } else {
            format!(
                "{}, {modifier} #{shift}",
                source_two.register.as_deref().unwrap()
            )
        };

        let source_one = Operand::register(
            Self::register_or_sp(is_64, source_one_number),
            if is_64 { 64 } else { 32 },
            Access::Read,
        );
        if set_flags && destination_number == 31 {
            return Some(Ok(Self::instruction(
                address,
                bytes,
                if subtract { "cmp" } else { "cmn" },
                vec![source_one, source_two],
            )));
        }

        let destination = Operand::register(
            if set_flags {
                Self::general_register(is_64, destination_number)
            } else {
                Self::register_or_sp(is_64, destination_number)
            },
            if is_64 { 64 } else { 32 },
            Access::Write,
        );
        let mnemonic = match (subtract, set_flags) {
            (false, false) => "add",
            (false, true) => "adds",
            (true, false) => "sub",
            (true, true) => "subs",
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![destination, source_one, source_two],
        )))
    }

    fn decode_add_sub_shifted_register(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x1f20_0000 != 0x0b00_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let subtract = word & 0x4000_0000 != 0;
        let set_flags = word & 0x2000_0000 != 0;
        let shift_kind = ((word >> 22) & 0x3) as usize;
        let shift = (word >> 10) & 0x3f;
        if shift_kind == 3 || (!is_64 && shift >= 32) {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let bits = if is_64 { 64 } else { 32 };
        let source_one_number = (word >> 5) & 0x1f;
        let source_two_number = (word >> 16) & 0x1f;
        let destination_number = word & 0x1f;
        let source_one = Operand::register(
            Self::general_register(is_64, source_one_number),
            bits,
            Access::Read,
        );
        let mut source_two = Operand::register(
            Self::general_register(is_64, source_two_number),
            bits,
            Access::Read,
        );
        if shift_kind != 0 || shift != 0 {
            let modifier = ["lsl", "lsr", "asr"][shift_kind];
            source_two.text = format!(
                "{}, {modifier} #{shift}",
                source_two.register.as_deref().unwrap()
            );
        }
        if set_flags && destination_number == 31 {
            return Some(Ok(Self::instruction(
                address,
                bytes,
                if subtract { "cmp" } else { "cmn" },
                vec![source_one, source_two],
            )));
        }
        let destination = Operand::register(
            Self::general_register(is_64, destination_number),
            bits,
            Access::Write,
        );
        let mnemonic = match (subtract, set_flags) {
            (false, false) => "add",
            (false, true) => "adds",
            (true, false) => "sub",
            (true, true) => "subs",
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![destination, source_one, source_two],
        )))
    }

    fn decode_add_sub_with_carry(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        if word & 0x1fe0_fc00 != 0x1a00_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let subtract = word & 0x4000_0000 != 0;
        let set_flags = word & 0x2000_0000 != 0;
        let destination = word & 0x1f;
        let source_one = (word >> 5) & 0x1f;
        let source_two = (word >> 16) & 0x1f;
        let bits = if is_64 { 64 } else { 32 };
        let mut operands = vec![Operand::register(
            Self::general_register(is_64, destination),
            bits,
            Access::Write,
        )];
        let mnemonic = if subtract && source_one == 31 {
            operands.push(Operand::register(
                Self::general_register(is_64, source_two),
                bits,
                Access::Read,
            ));
            if set_flags {
                "ngcs"
            } else {
                "ngc"
            }
        } else {
            operands.push(Operand::register(
                Self::general_register(is_64, source_one),
                bits,
                Access::Read,
            ));
            operands.push(Operand::register(
                Self::general_register(is_64, source_two),
                bits,
                Access::Read,
            ));
            match (subtract, set_flags) {
                (false, false) => "adc",
                (false, true) => "adcs",
                (true, false) => "sbc",
                (true, true) => "sbcs",
            }
        };
        Some(Self::instruction(address, bytes, mnemonic, operands))
    }

    fn decode_conditional_select(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        if word & 0x3fe0_0800 != 0x1a80_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let operation = (((word >> 30) & 1) << 1) | ((word >> 10) & 1);
        let condition = (word >> 12) & 0xf;
        let destination_number = word & 0x1f;
        let source_one_number = (word >> 5) & 0x1f;
        let source_two_number = (word >> 16) & 0x1f;
        let bits = if is_64 { 64 } else { 32 };
        let destination = Operand::register(
            Self::general_register(is_64, destination_number),
            bits,
            Access::Write,
        );
        let source_one = || {
            Operand::register(
                Self::general_register(is_64, source_one_number),
                bits,
                Access::Read,
            )
        };
        let source_two = || {
            Operand::register(
                Self::general_register(is_64, source_two_number),
                bits,
                Access::Read,
            )
        };

        if condition < 14 && source_one_number == source_two_number {
            let alias = match (operation, source_one_number == 31) {
                (1, true) => Some(("cset", false)),
                (1, false) => Some(("cinc", true)),
                (2, true) => Some(("csetm", false)),
                (2, false) => Some(("cinv", true)),
                (3, false) => Some(("cneg", true)),
                _ => None,
            };
            if let Some((mnemonic, keeps_source)) = alias {
                let operands = if keeps_source {
                    vec![destination, source_one()]
                } else {
                    vec![destination]
                };
                return Some(Self::instruction(address, bytes, mnemonic, operands));
            }
        }

        Some(Self::instruction(
            address,
            bytes,
            ["csel", "csinc", "csinv", "csneg"][operation as usize],
            vec![destination, source_one(), source_two()],
        ))
    }

    fn decode_conditional_compare(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        if word & 0x3fe0_0410 != 0x3a40_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let compare = word & 0x4000_0000 != 0;
        let immediate_form = word & 0x0000_0800 != 0;
        let bits = if is_64 { 64 } else { 32 };
        let mut operands = vec![Operand::register(
            Self::general_register(is_64, (word >> 5) & 0x1f),
            bits,
            Access::Read,
        )];
        if immediate_form {
            operands.push(Operand::immediate(i64::from((word >> 16) & 0x1f), bits));
        } else {
            operands.push(Operand::register(
                Self::general_register(is_64, (word >> 16) & 0x1f),
                bits,
                Access::Read,
            ));
        }
        operands.push(Operand::immediate(i64::from(word & 0xf), 4));
        Some(Self::instruction(
            address,
            bytes,
            if compare { "ccmp" } else { "ccmn" },
            operands,
        ))
    }

    fn decode_multiply(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x7f00_0000 != 0x1b00_0000 {
            return None;
        }

        let destination_number = word & 0x1f;
        let source_one_number = (word >> 5) & 0x1f;
        let accumulator_number = (word >> 10) & 0x1f;
        let source_two_number = (word >> 16) & 0x1f;
        let subtract = word & 0x0000_8000 != 0;

        if word & 0x7fe0_0000 == 0x1b00_0000 {
            let is_64 = word & 0x8000_0000 != 0;
            let bits = if is_64 { 64 } else { 32 };
            let destination = Operand::register(
                Self::general_register(is_64, destination_number),
                bits,
                Access::Write,
            );
            let source_one = Operand::register(
                Self::general_register(is_64, source_one_number),
                bits,
                Access::Read,
            );
            let source_two = Operand::register(
                Self::general_register(is_64, source_two_number),
                bits,
                Access::Read,
            );
            if accumulator_number == 31 {
                return Some(Ok(Self::instruction(
                    address,
                    bytes,
                    if subtract { "mneg" } else { "mul" },
                    vec![destination, source_one, source_two],
                )));
            }
            return Some(Ok(Self::instruction(
                address,
                bytes,
                if subtract { "msub" } else { "madd" },
                vec![
                    destination,
                    source_one,
                    source_two,
                    Operand::register(
                        Self::general_register(is_64, accumulator_number),
                        bits,
                        Access::Read,
                    ),
                ],
            )));
        }

        if word & 0xff60_0000 == 0x9b20_0000 {
            let unsigned = word & 0x0080_0000 != 0;
            let destination = Operand::register(
                Self::general_register(true, destination_number),
                64,
                Access::Write,
            );
            let source_one = Operand::register(
                Self::general_register(false, source_one_number),
                32,
                Access::Read,
            );
            let source_two = Operand::register(
                Self::general_register(false, source_two_number),
                32,
                Access::Read,
            );
            if accumulator_number == 31 {
                let mnemonic = match (unsigned, subtract) {
                    (false, false) => "smull",
                    (false, true) => "smnegl",
                    (true, false) => "umull",
                    (true, true) => "umnegl",
                };
                return Some(Ok(Self::instruction(
                    address,
                    bytes,
                    mnemonic,
                    vec![destination, source_one, source_two],
                )));
            }
            let mnemonic = match (unsigned, subtract) {
                (false, false) => "smaddl",
                (false, true) => "smsubl",
                (true, false) => "umaddl",
                (true, true) => "umsubl",
            };
            return Some(Ok(Self::instruction(
                address,
                bytes,
                mnemonic,
                vec![
                    destination,
                    source_one,
                    source_two,
                    Operand::register(
                        Self::general_register(true, accumulator_number),
                        64,
                        Access::Read,
                    ),
                ],
            )));
        }

        if word & 0xff60_fc00 == 0x9b40_7c00 {
            let unsigned = word & 0x0080_0000 != 0;
            return Some(Ok(Self::instruction(
                address,
                bytes,
                if unsigned { "umulh" } else { "smulh" },
                vec![
                    Operand::register(
                        Self::general_register(true, destination_number),
                        64,
                        Access::Write,
                    ),
                    Operand::register(
                        Self::general_register(true, source_one_number),
                        64,
                        Access::Read,
                    ),
                    Operand::register(
                        Self::general_register(true, source_two_number),
                        64,
                        Access::Read,
                    ),
                ],
            )));
        }

        Some(Err(DisassemblerError::InvalidInstruction()))
    }

    fn decode_bitfield(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x1f80_0000 != 0x1300_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let n = word & 0x0040_0000 != 0;
        let operation = (word >> 29) & 0x3;
        let immr = (word >> 16) & 0x3f;
        let imms = (word >> 10) & 0x3f;
        if operation == 3 || n != is_64 || (!is_64 && (immr >= 32 || imms >= 32)) {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }

        let register_bits = if is_64 { 64_u8 } else { 32_u8 };
        let destination_number = word & 0x1f;
        let source_number = (word >> 5) & 0x1f;
        let mnemonic;
        let mut source_is_64 = is_64;
        let mut immediates = [0_i64; 2];
        let immediate_count;

        match operation {
            0 if immr == 0 && imms == 7 => {
                mnemonic = "sxtb";
                source_is_64 = false;
                immediate_count = 0;
            }
            0 if immr == 0 && imms == 15 => {
                mnemonic = "sxth";
                source_is_64 = false;
                immediate_count = 0;
            }
            0 if is_64 && immr == 0 && imms == 31 => {
                mnemonic = "sxtw";
                source_is_64 = false;
                immediate_count = 0;
            }
            0 if imms == u32::from(register_bits) - 1 => {
                mnemonic = "asr";
                immediates[0] = i64::from(immr);
                immediate_count = 1;
            }
            0 if imms < immr => {
                mnemonic = "sbfiz";
                immediates = [
                    i64::from(u32::from(register_bits) - immr),
                    i64::from(imms + 1),
                ];
                immediate_count = 2;
            }
            0 => {
                mnemonic = "sbfx";
                immediates = [i64::from(immr), i64::from(imms - immr + 1)];
                immediate_count = 2;
            }
            1 if imms < immr => {
                mnemonic = if source_number == 31 { "bfc" } else { "bfi" };
                immediates = [
                    i64::from(u32::from(register_bits) - immr),
                    i64::from(imms + 1),
                ];
                immediate_count = 2;
            }
            1 => {
                mnemonic = "bfxil";
                immediates = [i64::from(immr), i64::from(imms - immr + 1)];
                immediate_count = 2;
            }
            2 if !is_64 && immr == 0 && imms == 7 => {
                mnemonic = "uxtb";
                source_is_64 = false;
                immediate_count = 0;
            }
            2 if !is_64 && immr == 0 && imms == 15 => {
                mnemonic = "uxth";
                source_is_64 = false;
                immediate_count = 0;
            }
            2 if imms == u32::from(register_bits) - 1 => {
                mnemonic = "lsr";
                immediates[0] = i64::from(immr);
                immediate_count = 1;
            }
            2 if imms + 1 == immr => {
                mnemonic = "lsl";
                immediates[0] = i64::from(u32::from(register_bits) - immr);
                immediate_count = 1;
            }
            2 if imms < immr => {
                mnemonic = "ubfiz";
                immediates = [
                    i64::from(u32::from(register_bits) - immr),
                    i64::from(imms + 1),
                ];
                immediate_count = 2;
            }
            2 => {
                mnemonic = "ubfx";
                immediates = [i64::from(immr), i64::from(imms - immr + 1)];
                immediate_count = 2;
            }
            _ => unreachable!("reserved bitfield operation rejected above"),
        }

        let mut operands = vec![
            Operand::register(
                Self::general_register(is_64, destination_number),
                register_bits,
                if operation == 1 {
                    Access::ReadWrite
                } else {
                    Access::Write
                },
            ),
            Operand::register(
                Self::general_register(source_is_64, source_number),
                if source_is_64 { 64 } else { 32 },
                Access::Read,
            ),
        ];
        if mnemonic == "bfc" {
            operands.pop();
        }
        for immediate in &immediates[..immediate_count] {
            operands.push(Operand::immediate(*immediate, register_bits));
        }
        Some(Ok(Self::instruction(address, bytes, mnemonic, operands)))
    }

    fn decode_advanced_simd_bitwise(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let (mnemonic, destructive) = match word & 0xbfe0_fc00 {
            0x0e20_1c00 => ("and", false),
            0x0e60_1c00 => ("bic", false),
            0x0ea0_1c00 => ("orr", false),
            0x0ee0_1c00 => ("orn", false),
            0x2e20_1c00 => ("eor", false),
            0x2e60_1c00 => ("bsl", true),
            0x2ea0_1c00 => ("bit", true),
            0x2ee0_1c00 => ("bif", true),
            _ => return None,
        };
        let rd = word & 0x1f;
        let rn = (word >> 5) & 0x1f;
        let rm = (word >> 16) & 0x1f;
        let lanes = if word & (1 << 30) == 0 { 8 } else { 16 };
        if mnemonic == "orr" && rn == rm {
            return Some(Ok(Self::instruction(
                address,
                bytes,
                "mov",
                vec![
                    Self::vector_register(rd, lanes, 8, Access::Write),
                    Self::vector_register(rn, lanes, 8, Access::Read),
                ],
            )));
        }
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::vector_register(
                    rd,
                    lanes,
                    8,
                    if destructive {
                        Access::ReadWrite
                    } else {
                        Access::Write
                    },
                ),
                Self::vector_register(rn, lanes, 8, Access::Read),
                Self::vector_register(rm, lanes, 8, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_table_lookup(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let mnemonic = match word & 0xbfe0_9c00 {
            0x0e00_0000 => "tbl",
            0x0e00_1000 => "tbx",
            _ => return None,
        };
        let lanes = if word & (1 << 30) == 0 { 8 } else { 16 };
        let first = (word >> 5) & 0x1f;
        let count = ((word >> 13) & 0x3) + 1;
        let registers = (0..count)
            .map(|offset| format!("v{}", (first + offset) & 0x1f))
            .collect();
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::vector_register(
                    word & 0x1f,
                    lanes,
                    8,
                    if mnemonic == "tbx" {
                        Access::ReadWrite
                    } else {
                        Access::Write
                    },
                ),
                Operand::register_list(
                    registers,
                    128,
                    Access::Read,
                    Some(VectorShape {
                        lanes: 16,
                        element_bits: 8,
                    }),
                ),
                Self::vector_register((word >> 16) & 0x1f, lanes, 8, Access::Read),
            ],
        )))
    }

    fn decode_extract(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x1f80_0000 != 0x1380_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let n = word & 0x0040_0000 != 0;
        let operation = (word >> 29) & 0x3;
        let lsb = (word >> 10) & 0x3f;
        if operation != 0 || n != is_64 || (!is_64 && lsb >= 32) {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let bits = if is_64 { 64 } else { 32 };
        let first_source = (word >> 5) & 0x1f;
        let second_source = (word >> 16) & 0x1f;
        let mut operands = vec![
            Operand::register(
                Self::general_register(is_64, word & 0x1f),
                bits,
                Access::Write,
            ),
            Operand::register(
                Self::general_register(is_64, first_source),
                bits,
                Access::Read,
            ),
        ];
        let mnemonic = if first_source == second_source {
            "ror"
        } else {
            operands.push(Operand::register(
                Self::general_register(is_64, second_source),
                bits,
                Access::Read,
            ));
            "extr"
        };
        operands.push(Operand::immediate(i64::from(lsb), bits));
        Some(Ok(Self::instruction(address, bytes, mnemonic, operands)))
    }

    fn decode_data_processing_one_source(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x7fff_0000 != 0x5ac0_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let operation = (word >> 10) & 0x3f;
        let mnemonic = match (is_64, operation) {
            (_, 0) => "rbit",
            (_, 1) => "rev16",
            (false, 2) => "rev",
            (true, 2) => "rev32",
            (true, 3) => "rev",
            (_, 4) => "clz",
            (_, 5) => "cls",
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        let bits = if is_64 { 64 } else { 32 };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Operand::register(
                    Self::general_register(is_64, word & 0x1f),
                    bits,
                    Access::Write,
                ),
                Operand::register(
                    Self::general_register(is_64, (word >> 5) & 0x1f),
                    bits,
                    Access::Read,
                ),
            ],
        )))
    }

    fn decode_data_processing_two_source(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        let encoding = word & 0x7fe0_fc00;
        if matches!(encoding, 0x1ac0_4000..=0x1ac0_5c00) && encoding & 0x3ff == 0 {
            let operation = ((word >> 10) & 0x7) as usize;
            let mnemonics = [
                "crc32b", "crc32h", "crc32w", "crc32x", "crc32cb", "crc32ch", "crc32cw", "crc32cx",
            ];
            let source_two_is_64 = matches!(operation, 3 | 7);
            return Some(Self::instruction(
                address,
                bytes,
                mnemonics[operation],
                vec![
                    Operand::register(
                        Self::general_register(false, word & 0x1f),
                        32,
                        Access::Write,
                    ),
                    Operand::register(
                        Self::general_register(false, (word >> 5) & 0x1f),
                        32,
                        Access::Read,
                    ),
                    Operand::register(
                        Self::general_register(source_two_is_64, (word >> 16) & 0x1f),
                        if source_two_is_64 { 64 } else { 32 },
                        Access::Read,
                    ),
                ],
            ));
        }
        let mnemonic = match encoding {
            0x1ac0_0800 => "udiv",
            0x1ac0_0c00 => "sdiv",
            0x1ac0_2000 => "lsl",
            0x1ac0_2400 => "lsr",
            0x1ac0_2800 => "asr",
            0x1ac0_2c00 => "ror",
            _ => return None,
        };
        let is_64 = word & 0x8000_0000 != 0;
        let bits = if is_64 { 64 } else { 32 };
        Some(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Operand::register(
                    Self::general_register(is_64, word & 0x1f),
                    bits,
                    Access::Write,
                ),
                Operand::register(
                    Self::general_register(is_64, (word >> 5) & 0x1f),
                    bits,
                    Access::Read,
                ),
                Operand::register(
                    Self::general_register(is_64, (word >> 16) & 0x1f),
                    bits,
                    Access::Read,
                ),
            ],
        ))
    }

    fn decode_scalar_fp_one_source(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xff20_7c00 != 0x1e20_4000 {
            return None;
        }
        let Some((source_kind, _source_bits)) = Self::scalar_fp_kind(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let operation = (word >> 15) & 0x3f;
        let (mnemonic, destination_kind) = match operation {
            0 => ("fmov", source_kind),
            1 => ("fabs", source_kind),
            2 => ("fneg", source_kind),
            3 => ("fsqrt", source_kind),
            4 => ("fcvt", "s"),
            5 => ("fcvt", "d"),
            7 => ("fcvt", "h"),
            8 => ("frintn", source_kind),
            9 => ("frintp", source_kind),
            10 => ("frintm", source_kind),
            11 => ("frintz", source_kind),
            12 => ("frinta", source_kind),
            14 => ("frintx", source_kind),
            15 => ("frinti", source_kind),
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        if mnemonic == "fcvt" && destination_kind == source_kind {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_fp_register(destination_kind, word & 0x1f, Access::Write),
                Self::scalar_fp_register(source_kind, (word >> 5) & 0x1f, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_abs_neg(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let encoding = word & 0xdf3f_fc00;
        let size = (word >> 22) & 0x3;
        let unsigned = word & (1 << 29) != 0;
        let mnemonic = match encoding {
            0x5e20_b800 if size == 3 => {
                if unsigned {
                    "neg"
                } else {
                    "abs"
                }
            }
            0x5e20_b800 => return Some(Err(DisassemblerError::InvalidInstruction())),
            0x5e20_7800 => {
                if unsigned {
                    "sqneg"
                } else {
                    "sqabs"
                }
            }
            0x5e20_3800 => {
                if unsigned {
                    "usqadd"
                } else {
                    "suqadd"
                }
            }
            _ => return None,
        };
        let source = (word >> 5) & 0x1f;
        let destination = word & 0x1f;
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_simd_register(size, destination, Access::Write),
                Self::scalar_simd_register(size, source, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_fabd(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xff20_fc00 != 0x7e20_d400 {
            return None;
        }
        let size = (word >> 22) & 0x3;
        if size < 2 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let right = (word >> 16) & 0x1f;
        let left = (word >> 5) & 0x1f;
        let destination = word & 0x1f;
        Some(Ok(Self::instruction(
            address,
            bytes,
            "fabd",
            vec![
                Self::scalar_simd_register(size, destination, Access::Write),
                Self::scalar_simd_register(size, left, Access::Read),
                Self::scalar_simd_register(size, right, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_integer_three_source(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let unsigned = word & (1 << 29) != 0;
        let mnemonic = match word & 0xdf20_fc00 {
            0x5e20_8400 => {
                if unsigned {
                    "sub"
                } else {
                    "add"
                }
            }
            0x5e20_4400 => {
                if unsigned {
                    "ushl"
                } else {
                    "sshl"
                }
            }
            0x5e20_0c00 => {
                if unsigned {
                    "uqadd"
                } else {
                    "sqadd"
                }
            }
            0x5e20_2c00 => {
                if unsigned {
                    "uqsub"
                } else {
                    "sqsub"
                }
            }
            0x5e20_4c00 => {
                if unsigned {
                    "uqshl"
                } else {
                    "sqshl"
                }
            }
            0x5e20_5c00 => {
                if unsigned {
                    "uqrshl"
                } else {
                    "sqrshl"
                }
            }
            0x5e20_5400 => {
                if unsigned {
                    "urshl"
                } else {
                    "srshl"
                }
            }
            0x5e20_8c00 => {
                if unsigned {
                    "cmeq"
                } else {
                    "cmtst"
                }
            }
            0x5e20_3c00 => {
                if unsigned {
                    "cmhs"
                } else {
                    "cmge"
                }
            }
            0x5e20_3400 => {
                if unsigned {
                    "cmhi"
                } else {
                    "cmgt"
                }
            }
            _ => return None,
        };
        let size = (word >> 22) & 0x3;
        if matches!(
            word & 0xdf20_fc00,
            0x5e20_8400 | 0x5e20_4400 | 0x5e20_5400 | 0x5e20_8c00 | 0x5e20_3c00 | 0x5e20_3400
        ) && size != 3
        {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let right = (word >> 16) & 0x1f;
        let left = (word >> 5) & 0x1f;
        let destination = word & 0x1f;
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_simd_register(size, destination, Access::Write),
                Self::scalar_simd_register(size, left, Access::Read),
                Self::scalar_simd_register(size, right, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_pairwise(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let encoding = word & 0xff3f_fc00;
        let size = (word >> 22) & 0x3;
        let (mnemonic, destination_kind, lanes, element_bits) = match encoding {
            0x5e31_b800 if size == 3 => ("addp", "d", 2, 64),
            0x5e31_b800 => return Some(Err(DisassemblerError::InvalidInstruction())),
            0x7e30_d800 if size == 0 => ("faddp", "s", 2, 32),
            0x7e30_d800 if size == 1 => ("faddp", "d", 2, 64),
            0x7e30_d800 => return Some(Err(DisassemblerError::InvalidInstruction())),
            _ => return None,
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_fp_register(destination_kind, word & 0x1f, Access::Write),
                Self::vector_register((word >> 5) & 0x1f, lanes, element_bits, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_compare_zero(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let unsigned = word & (1 << 29) != 0;
        let mnemonic = match word & 0xdf3f_fc00 {
            0x5e20_9800 => {
                if unsigned {
                    "cmle"
                } else {
                    "cmeq"
                }
            }
            0x5e20_8800 => {
                if unsigned {
                    "cmge"
                } else {
                    "cmgt"
                }
            }
            0x5e20_a800 if !unsigned => "cmlt",
            0x5e20_a800 => return Some(Err(DisassemblerError::InvalidInstruction())),
            _ => return None,
        };
        let size = (word >> 22) & 0x3;
        if size != 3 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_simd_register(size, word & 0x1f, Access::Write),
                Self::scalar_simd_register(size, (word >> 5) & 0x1f, Access::Read),
                Operand::immediate(0, 0),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_fp_compare(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let broad = word & 0xdf20_fc00;
        let encoding = word & 0xffa0_fc00;
        let mnemonic = match encoding {
            0x5e20_e400 => "fcmeq",
            0x7e20_e400 => "fcmge",
            0x7ea0_e400 => "fcmgt",
            0x7e20_ec00 => "facge",
            0x7ea0_ec00 => "facgt",
            _ if matches!(broad, 0x5e20_e400 | 0x5e20_ec00) => {
                return Some(Err(DisassemblerError::InvalidInstruction()));
            }
            _ => return None,
        };
        let kind = if word & (1 << 22) == 0 { "s" } else { "d" };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_fp_register(kind, word & 0x1f, Access::Write),
                Self::scalar_fp_register(kind, (word >> 5) & 0x1f, Access::Read),
                Self::scalar_fp_register(kind, (word >> 16) & 0x1f, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_fp_compare_zero(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let unsigned = word & (1 << 29) != 0;
        let mnemonic = match word & 0xdf3f_fc00 {
            0x5e20_c800 => {
                if unsigned {
                    "fcmge"
                } else {
                    "fcmgt"
                }
            }
            0x5e20_d800 => {
                if unsigned {
                    "fcmle"
                } else {
                    "fcmeq"
                }
            }
            0x5e20_e800 if !unsigned => "fcmlt",
            0x5e20_e800 => return Some(Err(DisassemblerError::InvalidInstruction())),
            _ => return None,
        };
        let (kind, bits) = if word & (1 << 22) == 0 {
            ("s", 32)
        } else {
            ("d", 64)
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_fp_register(kind, word & 0x1f, Access::Write),
                Self::scalar_fp_register(kind, (word >> 5) & 0x1f, Access::Read),
                Operand::immediate(0, bits),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_extract_narrow(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let unsigned = word & (1 << 29) != 0;
        let mnemonic = match word & 0xdf3f_fc00 {
            0x5e21_2800 if unsigned => "sqxtun",
            0x5e21_2800 => return Some(Err(DisassemblerError::InvalidInstruction())),
            0x5e21_4800 => {
                if unsigned {
                    "uqxtn"
                } else {
                    "sqxtn"
                }
            }
            _ => return None,
        };
        let size = (word >> 22) & 0x3;
        if size == 3 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_simd_register(size, word & 0x1f, Access::Write),
                Self::scalar_simd_register(size + 1, (word >> 5) & 0x1f, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_reciprocal(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let exact_three = word & 0xffa0_fc00;
        let broad_three = word & 0xdfa0_fc00;
        let three_mnemonic = match exact_three {
            0x5e20_fc00 => Some("frecps"),
            0x5ea0_fc00 => Some("frsqrts"),
            _ if matches!(broad_three, 0x5e20_fc00 | 0x5ea0_fc00) => {
                return Some(Err(DisassemblerError::InvalidInstruction()));
            }
            _ => None,
        };
        let kind = if word & (1 << 22) == 0 { "s" } else { "d" };
        if let Some(mnemonic) = three_mnemonic {
            return Some(Ok(Self::instruction(
                address,
                bytes,
                mnemonic,
                vec![
                    Self::scalar_fp_register(kind, word & 0x1f, Access::Write),
                    Self::scalar_fp_register(kind, (word >> 5) & 0x1f, Access::Read),
                    Self::scalar_fp_register(kind, (word >> 16) & 0x1f, Access::Read),
                ],
            )));
        }

        let unsigned = word & (1 << 29) != 0;
        let mnemonic = match word & 0xdf3f_fc00 {
            0x5e21_d800 => {
                if unsigned {
                    "frsqrte"
                } else {
                    "frecpe"
                }
            }
            0x5e21_f800 if !unsigned => "frecpx",
            0x5e21_f800 => return Some(Err(DisassemblerError::InvalidInstruction())),
            _ => return None,
        };
        if (word >> 23) & 1 == 0 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_fp_register(kind, word & 0x1f, Access::Write),
                Self::scalar_fp_register(kind, (word >> 5) & 0x1f, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_multiply(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let unsigned = word & (1 << 29) != 0;
        let encoding = word & 0xdf20_fc00;
        let mnemonic = match encoding {
            0x5e20_b400 => {
                if unsigned {
                    "sqrdmulh"
                } else {
                    "sqdmulh"
                }
            }
            0x5e20_dc00 if !unsigned => "fmulx",
            0x5e20_9000 if !unsigned => "sqdmlal",
            0x5e20_b000 if !unsigned => "sqdmlsl",
            0x5e20_d000 if !unsigned => "sqdmull",
            0x5e20_dc00 | 0x5e20_9000 | 0x5e20_b000 | 0x5e20_d000 => {
                return Some(Err(DisassemblerError::InvalidInstruction()));
            }
            _ => return None,
        };
        let size = (word >> 22) & 0x3;
        if mnemonic == "fmulx" {
            if size >= 2 {
                return Some(Err(DisassemblerError::InvalidInstruction()));
            }
            let kind = if size == 0 { "s" } else { "d" };
            return Some(Ok(Self::instruction(
                address,
                bytes,
                mnemonic,
                vec![
                    Self::scalar_fp_register(kind, word & 0x1f, Access::Write),
                    Self::scalar_fp_register(kind, (word >> 5) & 0x1f, Access::Read),
                    Self::scalar_fp_register(kind, (word >> 16) & 0x1f, Access::Read),
                ],
            )));
        }
        if !(1..=2).contains(&size) {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let widening = matches!(mnemonic, "sqdmlal" | "sqdmlsl" | "sqdmull");
        let destination_size = if widening { size + 1 } else { size };
        let source_size = size;
        let destination_access = if matches!(mnemonic, "sqdmlal" | "sqdmlsl") {
            Access::ReadWrite
        } else {
            Access::Write
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_simd_register(destination_size, word & 0x1f, destination_access),
                Self::scalar_simd_register(source_size, (word >> 5) & 0x1f, Access::Read),
                Self::scalar_simd_register(source_size, (word >> 16) & 0x1f, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_by_element_multiply(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let broad = word & 0xdf00_f400;
        if !matches!(broad, 0x5f00_1000 | 0x5f00_5000 | 0x5f00_9000) {
            return None;
        }
        let size = (word >> 22) & 0x3;
        let (kind, element_bits, lane) = match size {
            2 => ("s", 32, (((word >> 11) & 1) << 1) | ((word >> 21) & 1)),
            3 if word & (1 << 21) == 0 => ("d", 64, (word >> 11) & 1),
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        let vector = ((word >> 16) & 0xf) | (((word >> 20) & 1) << 4);
        let mnemonic = match word & 0xff00_f400 {
            0x5f00_1000 => "fmla",
            0x5f00_5000 => "fmls",
            0x5f00_9000 => "fmul",
            0x7f00_9000 => "fmulx",
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        let destination_access = if matches!(mnemonic, "fmla" | "fmls") {
            Access::ReadWrite
        } else {
            Access::Write
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_fp_register(kind, word & 0x1f, destination_access),
                Self::scalar_fp_register(kind, (word >> 5) & 0x1f, Access::Read),
                Self::vector_lane_register(vector, element_bits, lane, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_by_element_saturating_mla(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let broad = word & 0xdf00_f400;
        if !matches!(broad, 0x5f00_3000 | 0x5f00_7000) {
            return None;
        }
        if word & (1 << 29) != 0 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let size = (word >> 22) & 0x3;
        let (vector, element_bits, lane) = match size {
            1 => (
                (word >> 16) & 0xf,
                16,
                (((word >> 11) & 1) << 2) | (((word >> 21) & 1) << 1) | ((word >> 20) & 1),
            ),
            2 => (
                ((word >> 16) & 0xf) | (((word >> 20) & 1) << 4),
                32,
                (((word >> 11) & 1) << 1) | ((word >> 21) & 1),
            ),
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        let mnemonic = if broad == 0x5f00_3000 {
            "sqdmlal"
        } else {
            "sqdmlsl"
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_simd_register(size + 1, word & 0x1f, Access::ReadWrite),
                Self::scalar_simd_register(size, (word >> 5) & 0x1f, Access::Read),
                Self::vector_lane_register(vector, element_bits, lane, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_by_element_saturating_multiply(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let broad = word & 0xdf00_f400;
        if !matches!(broad, 0x5f00_b000 | 0x5f00_c000 | 0x5f00_d000) {
            return None;
        }
        if word & (1 << 29) != 0 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let size = (word >> 22) & 0x3;
        let (vector, element_bits, lane) = match size {
            1 => (
                (word >> 16) & 0xf,
                16,
                (((word >> 11) & 1) << 2) | (((word >> 21) & 1) << 1) | ((word >> 20) & 1),
            ),
            2 => (
                ((word >> 16) & 0xf) | (((word >> 20) & 1) << 4),
                32,
                (((word >> 11) & 1) << 1) | ((word >> 21) & 1),
            ),
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        let (mnemonic, destination_size) = match broad {
            0x5f00_b000 => ("sqdmull", size + 1),
            0x5f00_c000 => ("sqdmulh", size),
            0x5f00_d000 => ("sqrdmulh", size),
            _ => unreachable!(),
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_simd_register(destination_size, word & 0x1f, Access::Write),
                Self::scalar_simd_register(size, (word >> 5) & 0x1f, Access::Read),
                Self::vector_lane_register(vector, element_bits, lane, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_copy(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xffe0_fc00 != 0x5e00_0400 {
            return None;
        }
        let imm5 = (word >> 16) & 0x1f;
        if imm5 == 0 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let size = imm5.trailing_zeros();
        if size > 3 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let element_bits = 8_u8 << size;
        let lane = imm5 >> (size + 1);
        Some(Ok(Self::instruction(
            address,
            bytes,
            "mov",
            vec![
                Self::scalar_simd_register(size, word & 0x1f, Access::Write),
                Self::vector_lane_register((word >> 5) & 0x1f, element_bits, lane, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_conversion(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xffff_fc00 == 0x7e61_6800 {
            return Some(Ok(Self::instruction(
                address,
                bytes,
                "fcvtxn",
                vec![
                    Self::scalar_simd_register(2, word & 0x1f, Access::Write),
                    Self::scalar_simd_register(3, (word >> 5) & 0x1f, Access::Read),
                ],
            )));
        }

        let fixed = word & 0xdf80_fc00;
        if matches!(fixed, 0x5f00_e400 | 0x5f00_fc00) {
            let immh = (word >> 16) & 0x7f;
            let (size, fractional_bits) = if immh & 0x40 != 0 {
                (3, 128 - immh)
            } else if immh & 0x20 != 0 {
                (2, 64 - immh)
            } else {
                return Some(Err(DisassemblerError::InvalidInstruction()));
            };
            let unsigned = word & (1 << 29) != 0;
            let mnemonic = match (fixed, unsigned) {
                (0x5f00_e400, false) => "scvtf",
                (0x5f00_e400, true) => "ucvtf",
                (0x5f00_fc00, false) => "fcvtzs",
                (0x5f00_fc00, true) => "fcvtzu",
                _ => unreachable!(),
            };
            return Some(Ok(Self::instruction(
                address,
                bytes,
                mnemonic,
                vec![
                    Self::scalar_simd_register(size, word & 0x1f, Access::Write),
                    Self::scalar_simd_register(size, (word >> 5) & 0x1f, Access::Read),
                    Operand::immediate(i64::from(fractional_bits), 0),
                ],
            )));
        }

        let encoding = word & 0xdfbf_fc00;
        let unsigned = word & (1 << 29) != 0;
        let mnemonic = match (encoding, unsigned) {
            (0x5e21_d800, false) => "scvtf",
            (0x5e21_d800, true) => "ucvtf",
            (0x5e21_c800, false) => "fcvtas",
            (0x5e21_c800, true) => "fcvtau",
            (0x5e21_b800, false) => "fcvtms",
            (0x5e21_b800, true) => "fcvtmu",
            (0x5ea1_b800, false) => "fcvtzs",
            (0x5ea1_b800, true) => "fcvtzu",
            (0x5e21_a800, false) => "fcvtns",
            (0x5e21_a800, true) => "fcvtnu",
            (0x5ea1_a800, false) => "fcvtps",
            (0x5ea1_a800, true) => "fcvtpu",
            _ => return None,
        };
        let size = if word & (1 << 22) == 0 { 2 } else { 3 };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_simd_register(size, word & 0x1f, Access::Write),
                Self::scalar_simd_register(size, (word >> 5) & 0x1f, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_scalar_shift_immediate(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xdf80_0400 != 0x5f00_0400 {
            return None;
        }
        let immh = (word >> 16) & 0x7f;
        if immh == 0 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let log2_bits = 31 - immh.leading_zeros();
        if log2_bits > 6 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let element_bits = 1_u32 << log2_bits;
        let size = log2_bits.saturating_sub(3);
        let unsigned = word & (1 << 29) != 0;
        let opcode = (word >> 11) & 0x1f;
        let (mnemonic, narrowing, left_shift, accumulating) = match (opcode, unsigned) {
            (0, false) => ("sshr", false, false, false),
            (0, true) => ("ushr", false, false, false),
            (2, false) => ("ssra", false, false, true),
            (2, true) => ("usra", false, false, true),
            (4, false) => ("srshr", false, false, false),
            (4, true) => ("urshr", false, false, false),
            (6, false) => ("srsra", false, false, true),
            (6, true) => ("ursra", false, false, true),
            (8, true) => ("sri", false, false, true),
            (10, false) => ("shl", false, true, false),
            (10, true) => ("sli", false, true, true),
            (12, true) => ("sqshlu", false, true, false),
            (14, false) => ("sqshl", false, true, false),
            (14, true) => ("uqshl", false, true, false),
            (16, true) => ("sqshrun", true, false, false),
            (17, true) => ("sqrshrun", true, false, false),
            (18, false) => ("sqshrn", true, false, false),
            (18, true) => ("uqshrn", true, false, false),
            (19, false) => ("sqrshrn", true, false, false),
            (19, true) => ("uqrshrn", true, false, false),
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        if narrowing {
            if log2_bits > 5 {
                return Some(Err(DisassemblerError::InvalidInstruction()));
            }
        } else if !matches!(opcode, 12 | 14) && log2_bits != 6 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let immediate = if left_shift {
            immh - element_bits
        } else {
            2 * element_bits - immh
        };
        let source_size = if narrowing { size + 1 } else { size };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_simd_register(
                    size,
                    word & 0x1f,
                    if accumulating {
                        Access::ReadWrite
                    } else {
                        Access::Write
                    },
                ),
                Self::scalar_simd_register(source_size, (word >> 5) & 0x1f, Access::Read),
                Operand::immediate(i64::from(immediate), 0),
            ],
        )))
    }

    fn decode_advanced_simd_extract(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xbfe0_8400 != 0x2e00_0000 {
            return None;
        }
        let lanes = if word & (1 << 30) == 0 { 8 } else { 16 };
        let index = (word >> 11) & 0xf;
        if index >= u32::from(lanes) {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        Some(Ok(Self::instruction(
            address,
            bytes,
            "ext",
            vec![
                Self::vector_register(word & 0x1f, lanes, 8, Access::Write),
                Self::vector_register((word >> 5) & 0x1f, lanes, 8, Access::Read),
                Self::vector_register((word >> 16) & 0x1f, lanes, 8, Access::Read),
                Operand::immediate(i64::from(index), 0),
            ],
        )))
    }

    fn decode_advanced_simd_reciprocal_step(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let encoding = word & 0xbf80_fc00;
        let mnemonic = match encoding {
            0x0e00_fc00 => "frecps",
            0x0e80_fc00 => "frsqrts",
            _ => return None,
        };
        let Some((lanes, element_bits)) = Self::vector_fp_arrangement(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::vector_register(word & 0x1f, lanes, element_bits, Access::Write),
                Self::vector_register((word >> 5) & 0x1f, lanes, element_bits, Access::Read),
                Self::vector_register((word >> 16) & 0x1f, lanes, element_bits, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_pairwise_add(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let encoding = word & 0xbf20_fc00;
        let q = word & (1 << 30) != 0;
        let (mnemonic, element_bits) = match encoding {
            0x0e20_bc00 => {
                let Some((_, bits)) = Self::vector_integer_arrangement(word, 3) else {
                    return Some(Err(DisassemblerError::InvalidInstruction()));
                };
                ("addp", bits)
            }
            0x2e20_d400 => {
                let Some((_, bits)) = Self::vector_fp_arrangement(word) else {
                    return Some(Err(DisassemblerError::InvalidInstruction()));
                };
                ("faddp", bits)
            }
            _ => return None,
        };
        let lanes = (if q { 128 } else { 64 }) / element_bits;
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::vector_register(word & 0x1f, lanes, element_bits, Access::Write),
                Self::vector_register((word >> 5) & 0x1f, lanes, element_bits, Access::Read),
                Self::vector_register((word >> 16) & 0x1f, lanes, element_bits, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_integer_three_same(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let (mnemonic, max_size, accumulating) = match word & 0xbf20_fc00 {
            0x0e20_1400 => ("srhadd", 2, false),
            0x2e20_1400 => ("urhadd", 2, false),
            0x0e20_4c00 => ("sqshl", 3, false),
            0x2e20_4c00 => ("uqshl", 3, false),
            0x0e20_5400 => ("srshl", 3, false),
            0x2e20_5400 => ("urshl", 3, false),
            0x0e20_5c00 => ("sqrshl", 3, false),
            0x2e20_5c00 => ("uqrshl", 3, false),
            0x0e20_8400 => ("add", 3, false),
            0x2e20_8400 => ("sub", 3, false),
            0x0e20_9400 => ("mla", 2, true),
            0x2e20_9400 => ("mls", 2, true),
            _ => return None,
        };
        let Some((lanes, element_bits)) = Self::vector_integer_arrangement(word, max_size) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::vector_register(
                    word & 0x1f,
                    lanes,
                    element_bits,
                    if accumulating {
                        Access::ReadWrite
                    } else {
                        Access::Write
                    },
                ),
                Self::vector_register((word >> 5) & 0x1f, lanes, element_bits, Access::Read),
                Self::vector_register((word >> 16) & 0x1f, lanes, element_bits, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_shift_left_long(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x9f80_fc00 != 0x0f00_a400 {
            return None;
        }
        let immh = (word >> 16) & 0x7f;
        if immh == 0 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let log2_bits = 31 - immh.leading_zeros();
        if !(3..=5).contains(&log2_bits) {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let source_bits = 1_u8 << log2_bits;
        let lanes = 64 / source_bits;
        let upper = word & (1 << 30) != 0;
        let unsigned = word & (1 << 29) != 0;
        let mnemonic = match (unsigned, upper) {
            (false, false) => "sshll",
            (false, true) => "sshll2",
            (true, false) => "ushll",
            (true, true) => "ushll2",
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::vector_register(word & 0x1f, lanes, source_bits * 2, Access::Write),
                Self::vector_register(
                    (word >> 5) & 0x1f,
                    if upper { lanes * 2 } else { lanes },
                    source_bits,
                    Access::Read,
                ),
                Operand::immediate(i64::from(immh - u32::from(source_bits)), 0),
            ],
        )))
    }

    fn decode_advanced_simd_absolute_compare(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let mnemonic = match word & 0xbfa0_fc00 {
            0x2e20_ec00 => "facge",
            0x2ea0_ec00 => "facgt",
            _ => return None,
        };
        let Some((lanes, element_bits)) = Self::vector_fp_arrangement(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::vector_register(word & 0x1f, lanes, element_bits, Access::Write),
                Self::vector_register((word >> 5) & 0x1f, lanes, element_bits, Access::Read),
                Self::vector_register((word >> 16) & 0x1f, lanes, element_bits, Access::Read),
            ],
        )))
    }

    fn decode_advanced_simd_crypto(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let rd = word & 0x1f;
        let rn = (word >> 5) & 0x1f;
        let rm = (word >> 16) & 0x1f;
        let (mnemonic, operands) = match word & 0xffff_fc00 {
            0x4e28_4800 => (
                "aese",
                vec![
                    Self::vector_register(rd, 16, 8, Access::ReadWrite),
                    Self::vector_register(rn, 16, 8, Access::Read),
                ],
            ),
            0x4e28_5800 => (
                "aesd",
                vec![
                    Self::vector_register(rd, 16, 8, Access::ReadWrite),
                    Self::vector_register(rn, 16, 8, Access::Read),
                ],
            ),
            0x4e28_6800 => (
                "aesmc",
                vec![
                    Self::vector_register(rd, 16, 8, Access::Write),
                    Self::vector_register(rn, 16, 8, Access::Read),
                ],
            ),
            0x4e28_7800 => (
                "aesimc",
                vec![
                    Self::vector_register(rd, 16, 8, Access::Write),
                    Self::vector_register(rn, 16, 8, Access::Read),
                ],
            ),
            0x5e28_0800 => (
                "sha1h",
                vec![
                    Self::scalar_simd_register(2, rd, Access::Write),
                    Self::scalar_simd_register(2, rn, Access::Read),
                ],
            ),
            0x5e28_1800 => (
                "sha1su1",
                vec![
                    Self::vector_register(rd, 4, 32, Access::ReadWrite),
                    Self::vector_register(rn, 4, 32, Access::Read),
                ],
            ),
            0x5e28_2800 => (
                "sha256su0",
                vec![
                    Self::vector_register(rd, 4, 32, Access::ReadWrite),
                    Self::vector_register(rn, 4, 32, Access::Read),
                ],
            ),
            _ => match word & 0xffe0_fc00 {
                0x5e00_0000 | 0x5e00_1000 | 0x5e00_2000 => {
                    let mnemonic = ["sha1c", "sha1p", "sha1m"][((word >> 12) & 0x3) as usize];
                    (
                        mnemonic,
                        vec![
                            Operand::register(format!("q{rd}"), 0, Access::ReadWrite),
                            Self::scalar_simd_register(2, rn, Access::Read),
                            Self::vector_register(rm, 4, 32, Access::Read),
                        ],
                    )
                }
                0x5e00_3000 | 0x5e00_6000 => (
                    if word & 0x4000 == 0 {
                        "sha1su0"
                    } else {
                        "sha256su1"
                    },
                    vec![
                        Self::vector_register(rd, 4, 32, Access::ReadWrite),
                        Self::vector_register(rn, 4, 32, Access::Read),
                        Self::vector_register(rm, 4, 32, Access::Read),
                    ],
                ),
                0x5e00_4000 | 0x5e00_5000 => (
                    if word & 0x1000 == 0 {
                        "sha256h"
                    } else {
                        "sha256h2"
                    },
                    vec![
                        Operand::register(format!("q{rd}"), 0, Access::ReadWrite),
                        Operand::register(format!("q{rn}"), 0, Access::Read),
                        Self::vector_register(rm, 4, 32, Access::Read),
                    ],
                ),
                _ => return None,
            },
        };
        Some(Ok(Self::instruction(address, bytes, mnemonic, operands)))
    }

    fn decode_advanced_simd_fp_three_same(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        let (mnemonic, accumulating) = match word & 0xbfa0_fc00 {
            0x0e20_cc00 => ("fmla", true),
            0x0ea0_cc00 => ("fmls", true),
            0x0e20_d400 => ("fadd", false),
            0x0ea0_d400 => ("fsub", false),
            _ => return None,
        };
        let Some((lanes, element_bits)) = Self::vector_fp_arrangement(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::vector_register(
                    word & 0x1f,
                    lanes,
                    element_bits,
                    if accumulating {
                        Access::ReadWrite
                    } else {
                        Access::Write
                    },
                ),
                Self::vector_register((word >> 5) & 0x1f, lanes, element_bits, Access::Read),
                Self::vector_register((word >> 16) & 0x1f, lanes, element_bits, Access::Read),
            ],
        )))
    }

    fn decode_scalar_fp_two_source(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xff20_0c00 != 0x1e20_0800 {
            return None;
        }
        let Some((kind, _bits)) = Self::scalar_fp_kind(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let mnemonic = match (word >> 12) & 0xf {
            0 => "fmul",
            1 => "fdiv",
            2 => "fadd",
            3 => "fsub",
            4 => "fmax",
            5 => "fmin",
            6 => "fmaxnm",
            7 => "fminnm",
            8 => "fnmul",
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_fp_register(kind, word & 0x1f, Access::Write),
                Self::scalar_fp_register(kind, (word >> 5) & 0x1f, Access::Read),
                Self::scalar_fp_register(kind, (word >> 16) & 0x1f, Access::Read),
            ],
        )))
    }

    fn decode_scalar_fp_three_source(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xff00_0000 != 0x1f00_0000 {
            return None;
        }
        let Some((kind, _bits)) = Self::scalar_fp_kind(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let mnemonic = match (word & 0x0020_0000 != 0, word & 0x0000_8000 != 0) {
            (false, false) => "fmadd",
            (false, true) => "fmsub",
            (true, false) => "fnmadd",
            (true, true) => "fnmsub",
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Self::scalar_fp_register(kind, word & 0x1f, Access::Write),
                Self::scalar_fp_register(kind, (word >> 5) & 0x1f, Access::Read),
                Self::scalar_fp_register(kind, (word >> 16) & 0x1f, Access::Read),
                Self::scalar_fp_register(kind, (word >> 10) & 0x1f, Access::Read),
            ],
        )))
    }

    fn decode_scalar_fp_compare(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xff20_fc07 != 0x1e20_2000 {
            return None;
        }
        let Some((kind, bits)) = Self::scalar_fp_kind(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let zero_form = word & 0x8 != 0;
        let source_two = (word >> 16) & 0x1f;
        if zero_form && source_two != 0 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let second = if zero_form {
            Operand::immediate(0, bits)
        } else {
            Self::scalar_fp_register(kind, source_two, Access::Read)
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            if word & 0x10 == 0 { "fcmp" } else { "fcmpe" },
            vec![
                Self::scalar_fp_register(kind, (word >> 5) & 0x1f, Access::Read),
                second,
            ],
        )))
    }

    fn decode_scalar_fp_conditional_compare(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xff20_0c00 != 0x1e20_0400 {
            return None;
        }
        let Some((kind, _bits)) = Self::scalar_fp_kind(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            if word & 0x10 == 0 { "fccmp" } else { "fccmpe" },
            vec![
                Self::scalar_fp_register(kind, (word >> 5) & 0x1f, Access::Read),
                Self::scalar_fp_register(kind, (word >> 16) & 0x1f, Access::Read),
                Operand::immediate(i64::from(word & 0xf), 0),
            ],
        )))
    }

    fn decode_scalar_fp_conditional_select(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xff20_0c00 != 0x1e20_0c00 {
            return None;
        }
        let Some((kind, _bits)) = Self::scalar_fp_kind(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            "fcsel",
            vec![
                Self::scalar_fp_register(kind, word & 0x1f, Access::Write),
                Self::scalar_fp_register(kind, (word >> 5) & 0x1f, Access::Read),
                Self::scalar_fp_register(kind, (word >> 16) & 0x1f, Access::Read),
            ],
        )))
    }

    fn decode_scalar_fp_fixed_conversion(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x5f20_0000 != 0x1e00_0000 {
            return None;
        }
        let operation = (word >> 16) & 0x1f;
        let mnemonic = match operation {
            2 => "scvtf",
            3 => "ucvtf",
            24 => "fcvtzs",
            25 => "fcvtzu",
            _ => return None,
        };
        let Some((fp_kind, _fp_bits)) = Self::scalar_fp_kind(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let integer_is_64 = word & 0x8000_0000 != 0;
        let integer_bits = if integer_is_64 { 64 } else { 32 };
        let scale = (word >> 10) & 0x3f;
        if !integer_is_64 && scale < 32 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let fractional_bits = 64 - scale;
        let integer = |register, access| {
            Operand::register(
                Self::general_register(integer_is_64, register),
                integer_bits,
                access,
            )
        };
        let operands = if operation <= 3 {
            vec![
                Self::scalar_fp_register(fp_kind, word & 0x1f, Access::Write),
                integer((word >> 5) & 0x1f, Access::Read),
                Operand::immediate(i64::from(fractional_bits), 0),
            ]
        } else {
            vec![
                integer(word & 0x1f, Access::Write),
                Self::scalar_fp_register(fp_kind, (word >> 5) & 0x1f, Access::Read),
                Operand::immediate(i64::from(fractional_bits), 0),
            ]
        };
        Some(Ok(Self::instruction(address, bytes, mnemonic, operands)))
    }

    fn decode_scalar_fp_integer_conversion(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x5f20_fc00 != 0x1e20_0000 {
            return None;
        }
        let operation = (word >> 16) & 0x1f;
        let mnemonic = match operation {
            0 => "fcvtns",
            1 => "fcvtnu",
            2 => "scvtf",
            3 => "ucvtf",
            4 => "fcvtas",
            5 => "fcvtau",
            6 | 7 => "fmov",
            8 => "fcvtps",
            9 => "fcvtpu",
            16 => "fcvtms",
            17 => "fcvtmu",
            24 => "fcvtzs",
            25 => "fcvtzu",
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        let Some((fp_kind, _fp_bits)) = Self::scalar_fp_kind(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let integer_is_64 = word & 0x8000_0000 != 0;
        let integer_bits = if integer_is_64 { 64 } else { 32 };
        if matches!(operation, 6 | 7)
            && ((integer_is_64 && fp_kind != "d") || (!integer_is_64 && fp_kind != "s"))
        {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let integer = |register, access| {
            Operand::register(
                Self::general_register(integer_is_64, register),
                integer_bits,
                access,
            )
        };
        let operands = if matches!(operation, 2 | 3 | 7) {
            vec![
                Self::scalar_fp_register(fp_kind, word & 0x1f, Access::Write),
                integer((word >> 5) & 0x1f, Access::Read),
            ]
        } else {
            vec![
                integer(word & 0x1f, Access::Write),
                Self::scalar_fp_register(fp_kind, (word >> 5) & 0x1f, Access::Read),
            ]
        };
        Some(Ok(Self::instruction(address, bytes, mnemonic, operands)))
    }

    fn decode_scalar_fp_immediate(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0xff20_1fe0 != 0x1e20_1000 {
            return None;
        }
        let Some((kind, bits)) = Self::scalar_fp_kind(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let immediate = (word >> 13) & 0xff;
        let sign = u64::from(immediate >> 7);
        let exponent_bit = u64::from((immediate >> 6) & 1);
        let exponent_low = u64::from((immediate >> 4) & 0x3);
        let fraction = u64::from(immediate & 0xf);
        let (exponent_bits, fraction_bits) = match bits {
            16 => (5, 10),
            32 => (8, 23),
            64 => (11, 52),
            _ => unreachable!("scalar_fp_kind returns architectural widths"),
        };
        let exponent_middle_width = exponent_bits - 3;
        let exponent_middle = if exponent_bit == 0 {
            0
        } else {
            (1_u64 << exponent_middle_width) - 1
        };
        let exponent =
            ((exponent_bit ^ 1) << (exponent_bits - 1)) | (exponent_middle << 2) | exponent_low;
        let payload =
            (sign << (bits - 1)) | (exponent << fraction_bits) | (fraction << (fraction_bits - 4));
        Some(Ok(Self::instruction(
            address,
            bytes,
            "fmov",
            vec![
                Self::scalar_fp_register(kind, word & 0x1f, Access::Write),
                Operand::immediate(payload as i64, bits),
            ],
        )))
    }

    fn decode_scalar_fp_lane_move(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<Instruction> {
        if word & 0xfffe_fc00 != 0x9eae_0000 {
            return None;
        }
        let to_vector = word & 0x0001_0000 != 0;
        let mut vector = Operand::register(
            format!(
                "v{}",
                if to_vector {
                    word & 0x1f
                } else {
                    (word >> 5) & 0x1f
                }
            ),
            64,
            if to_vector {
                Access::Write
            } else {
                Access::Read
            },
        );
        vector.vector_shape = Some(VectorShape {
            lanes: 1,
            element_bits: 64,
        });
        vector.vector_index = Some(1);
        let general = Operand::register(
            Self::general_register(
                true,
                if to_vector {
                    (word >> 5) & 0x1f
                } else {
                    word & 0x1f
                },
            ),
            64,
            if to_vector {
                Access::Read
            } else {
                Access::Write
            },
        );
        let operands = if to_vector {
            vec![vector, general]
        } else {
            vec![general, vector]
        };
        Some(Self::instruction(address, bytes, "fmov", operands))
    }

    fn decode_load_literal(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x3b00_0000 != 0x1800_0000 {
            return None;
        }
        let vector = word & 0x0400_0000 != 0;
        let operation = (word >> 30) & 0x3;
        let (mnemonic, register, bits) = match (vector, operation) {
            (false, 0) => ("ldr", Self::general_register(false, word & 0x1f), 32),
            (false, 1) => ("ldr", Self::general_register(true, word & 0x1f), 64),
            (false, 2) => ("ldrsw", Self::general_register(true, word & 0x1f), 64),
            (true, 0) => ("ldr", format!("s{}", word & 0x1f), 32),
            (true, 1) => ("ldr", format!("d{}", word & 0x1f), 64),
            (true, 2) => ("ldr", format!("q{}", word & 0x1f), 128),
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        let displacement = Self::signed_field(word, 5, 19, 2);
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Operand::register(register, bits, Access::Write),
                Operand::immediate(Self::target(address, displacement), 0),
            ],
        )))
    }

    fn decode_exclusive_or_ordered_load_store(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x3f00_0000 != 0x0800_0000 {
            return None;
        }
        let size = (word >> 30) & 0x3;
        let ordered = word & 0x0080_0000 != 0;
        let load = word & 0x0040_0000 != 0;
        let pair = word & 0x0020_0000 != 0;
        let acquire_release = word & 0x0000_8000 != 0;
        let status = (word >> 16) & 0x1f;
        let second = (word >> 10) & 0x1f;
        let base = (word >> 5) & 0x1f;
        let data = word & 0x1f;
        if ordered {
            if pair || !acquire_release || status != 31 || second != 31 {
                return Some(Err(DisassemblerError::InvalidInstruction()));
            }
        } else if (pair && size < 2) || (!pair && second != 31) || (load && status != 31) {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let bits = (8_u16 << size) as u8;
        let suffix = match size {
            0 => "b",
            1 => "h",
            _ => "",
        };
        let mnemonic = if ordered {
            format!("{}{}", if load { "ldar" } else { "stlr" }, suffix)
        } else if pair {
            match (load, acquire_release) {
                (false, false) => "stxp".to_string(),
                (false, true) => "stlxp".to_string(),
                (true, false) => "ldxp".to_string(),
                (true, true) => "ldaxp".to_string(),
            }
        } else {
            format!(
                "{}{}",
                match (load, acquire_release) {
                    (false, false) => "stxr",
                    (false, true) => "stlxr",
                    (true, false) => "ldxr",
                    (true, true) => "ldaxr",
                },
                suffix
            )
        };
        let data_is_64 = size == 3;
        let data_operand = |register, access| {
            Operand::register(
                Self::general_register(data_is_64, register),
                if data_is_64 { 64 } else { 32 },
                access,
            )
        };
        let memory = Operand::memory(
            bits,
            if load { Access::Read } else { Access::Write },
            Some(0),
            Some(Self::register_or_sp(true, base)),
            None,
            None,
        );
        let operands = if ordered {
            vec![
                data_operand(data, if load { Access::Write } else { Access::Read }),
                memory,
            ]
        } else if load {
            let mut operands = vec![data_operand(data, Access::Write)];
            if pair {
                operands.push(data_operand(second, Access::Write));
            }
            operands.push(memory);
            operands
        } else {
            let mut operands = vec![
                Operand::register(Self::general_register(false, status), 32, Access::Write),
                data_operand(data, Access::Read),
            ];
            if pair {
                operands.push(data_operand(second, Access::Read));
            }
            operands.push(memory);
            operands
        };
        Some(Ok(Self::instruction(address, bytes, &mnemonic, operands)))
    }

    fn decode_prefetch(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        #[derive(Clone, Copy)]
        enum Form {
            Unsigned,
            Unscaled,
            Register,
        }
        let form = if word & 0xffc0_0000 == 0xf980_0000 {
            Form::Unsigned
        } else if word & 0xffe0_0c00 == 0xf880_0000 {
            Form::Unscaled
        } else if word & 0xffe0_0c00 == 0xf8a0_0800 {
            Form::Register
        } else {
            return None;
        };
        let Some(operation) = Self::prefetch_operation(word & 0x1f) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let base = Self::register_or_sp(true, (word >> 5) & 0x1f);
        let memory = match form {
            Form::Unsigned => Operand::memory(
                0,
                Access::Read,
                Some(i64::from((word >> 10) & 0xfff) << 3),
                Some(base),
                None,
                None,
            ),
            Form::Unscaled => Operand::memory(
                0,
                Access::Read,
                Some(Self::signed_field(word, 12, 9, 0)),
                Some(base),
                None,
                None,
            ),
            Form::Register => {
                let option = ((word >> 13) & 0x7) as usize;
                if !matches!(option, 2 | 3 | 6 | 7) {
                    return Some(Err(DisassemblerError::InvalidInstruction()));
                }
                let index = Self::general_register(matches!(option, 3 | 7), (word >> 16) & 0x1f);
                let shift = if word & 0x1000 != 0 { 3 } else { 0 };
                let modifier = [
                    "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx",
                ][option];
                let mut memory = Operand::memory(
                    0,
                    Access::Read,
                    Some(0),
                    Some(base.clone()),
                    Some(index.clone()),
                    (shift != 0).then_some(1 << shift),
                );
                memory.text = if shift == 0 {
                    format!("[{base}, {index}, {modifier}]")
                } else {
                    format!("[{base}, {index}, {modifier} #{shift}]")
                };
                memory
            }
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            if matches!(form, Form::Unscaled) {
                "prfum"
            } else {
                "prfm"
            },
            vec![
                Operand::register(operation.to_string(), 0, Access::Read),
                memory,
            ],
        )))
    }

    fn decode_load_store_unsigned(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x3f00_0000 != 0x3900_0000 {
            return None;
        }
        let size = (word >> 30) & 0x3;
        let operation = (word >> 22) & 0x3;
        let register = word & 0x1f;
        let base = (word >> 5) & 0x1f;
        let displacement = i64::from((word >> 10) & 0xfff) << size;

        let decoded = match (size, operation) {
            (0, 0) => ("strb", false, false, 8),
            (0, 1) => ("ldrb", true, false, 8),
            (0, 2) => ("ldrsb", true, true, 8),
            (0, 3) => ("ldrsb", true, false, 8),
            (1, 0) => ("strh", false, false, 16),
            (1, 1) => ("ldrh", true, false, 16),
            (1, 2) => ("ldrsh", true, true, 16),
            (1, 3) => ("ldrsh", true, false, 16),
            (2, 0) => ("str", false, false, 32),
            (2, 1) => ("ldr", true, false, 32),
            (2, 2) => ("ldrsw", true, true, 32),
            (3, 0) => ("str", false, true, 64),
            (3, 1) => ("ldr", true, true, 64),
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        let (mnemonic, load, register_is_64, memory_bits) = decoded;
        let register = Self::general_register(register_is_64, register);
        let base = Self::register_or_sp(true, base);
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Operand::register(
                    register,
                    if register_is_64 { 64 } else { 32 },
                    if load { Access::Write } else { Access::Read },
                ),
                Operand::memory(
                    memory_bits,
                    if load { Access::Read } else { Access::Write },
                    Some(displacement),
                    Some(base),
                    None,
                    None,
                ),
            ],
        )))
    }

    fn decode_simd_load_store_unsigned(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x3f00_0000 != 0x3d00_0000 {
            return None;
        }
        let Some((prefix, bits, load)) = Self::simd_load_store_kind(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let displacement = i64::from((word >> 10) & 0xfff) * i64::from(bits / 8);
        Some(Ok(Self::instruction(
            address,
            bytes,
            if load { "ldr" } else { "str" },
            vec![
                Operand::register(
                    format!("{prefix}{}", word & 0x1f),
                    bits,
                    if load { Access::Write } else { Access::Read },
                ),
                Operand::memory(
                    bits,
                    if load { Access::Read } else { Access::Write },
                    Some(displacement),
                    Some(Self::register_or_sp(true, (word >> 5) & 0x1f)),
                    None,
                    None,
                ),
            ],
        )))
    }

    fn decode_load_store_unscaled_or_writeback(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x3f20_0000 != 0x3800_0000 {
            return None;
        }
        let mode = (word >> 10) & 0x3;
        let size = (word >> 30) & 0x3;
        let operation = (word >> 22) & 0x3;
        let decoded = match (size, operation) {
            (0, 0) => ("strb", "sturb", false, false, 8),
            (0, 1) => ("ldrb", "ldurb", true, false, 8),
            (0, 2) => ("ldrsb", "ldursb", true, true, 8),
            (0, 3) => ("ldrsb", "ldursb", true, false, 8),
            (1, 0) => ("strh", "sturh", false, false, 16),
            (1, 1) => ("ldrh", "ldurh", true, false, 16),
            (1, 2) => ("ldrsh", "ldursh", true, true, 16),
            (1, 3) => ("ldrsh", "ldursh", true, false, 16),
            (2, 0) => ("str", "stur", false, false, 32),
            (2, 1) => ("ldr", "ldur", true, false, 32),
            (2, 2) => ("ldrsw", "ldursw", true, true, 32),
            (3, 0) => ("str", "stur", false, true, 64),
            (3, 1) => ("ldr", "ldur", true, true, 64),
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        let (writeback_mnemonic, unscaled_mnemonic, load, register_is_64, memory_bits) = decoded;
        let mnemonic = match mode {
            0 => unscaled_mnemonic,
            2 => match unscaled_mnemonic {
                "sturb" => "sttrb",
                "ldurb" => "ldtrb",
                "ldursb" => "ldtrsb",
                "sturh" => "sttrh",
                "ldurh" => "ldtrh",
                "ldursh" => "ldtrsh",
                "stur" => "sttr",
                "ldur" => "ldtr",
                "ldursw" => "ldtrsw",
                _ => unreachable!("all scalar unscaled operations mapped above"),
            },
            _ => writeback_mnemonic,
        };
        let displacement = Self::signed_field(word, 12, 9, 0);
        let memory_displacement = if mode == 1 { 0 } else { displacement };
        let mut operands = vec![
            Operand::register(
                Self::general_register(register_is_64, word & 0x1f),
                if register_is_64 { 64 } else { 32 },
                if load { Access::Write } else { Access::Read },
            ),
            Operand::memory(
                memory_bits,
                if load { Access::Read } else { Access::Write },
                Some(memory_displacement),
                Some(Self::register_or_sp(true, (word >> 5) & 0x1f)),
                None,
                None,
            ),
        ];
        if mode == 1 || (mode == 3 && displacement != 0) {
            operands.push(Operand::immediate(displacement, 0));
        }
        Some(Ok(Self::instruction(address, bytes, mnemonic, operands)))
    }

    fn decode_load_store_register_offset(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x3f20_0c00 != 0x3820_0800 {
            return None;
        }
        let size = (word >> 30) & 0x3;
        let operation = (word >> 22) & 0x3;
        let decoded = match (size, operation) {
            (0, 0) => ("strb", false, false, 8),
            (0, 1) => ("ldrb", true, false, 8),
            (0, 2) => ("ldrsb", true, true, 8),
            (0, 3) => ("ldrsb", true, false, 8),
            (1, 0) => ("strh", false, false, 16),
            (1, 1) => ("ldrh", true, false, 16),
            (1, 2) => ("ldrsh", true, true, 16),
            (1, 3) => ("ldrsh", true, false, 16),
            (2, 0) => ("str", false, false, 32),
            (2, 1) => ("ldr", true, false, 32),
            (2, 2) => ("ldrsw", true, true, 32),
            (3, 0) => ("str", false, true, 64),
            (3, 1) => ("ldr", true, true, 64),
            _ => return Some(Err(DisassemblerError::InvalidInstruction())),
        };
        let option = (word >> 13) & 0x7;
        if !matches!(option, 2 | 3 | 6 | 7) {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let shift = if word & 0x1000 != 0 { size as u8 } else { 0 };
        let index_is_64 = matches!(option, 3 | 7);
        let index = Self::general_register(index_is_64, (word >> 16) & 0x1f);
        let base = Self::register_or_sp(true, (word >> 5) & 0x1f);
        let (mnemonic, load, register_is_64, memory_bits) = decoded;
        let mut memory = Operand::memory(
            memory_bits,
            if load { Access::Read } else { Access::Write },
            Some(0),
            Some(base.clone()),
            Some(index.clone()),
            if shift == 0 { None } else { Some(1 << shift) },
        );
        let modifier = ["", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"][option as usize];
        memory.text = if shift == 0 {
            format!("[{base}, {index}, {modifier}]")
        } else {
            format!("[{base}, {index}, {modifier} #{shift}]")
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Operand::register(
                    Self::general_register(register_is_64, word & 0x1f),
                    if register_is_64 { 64 } else { 32 },
                    if load { Access::Write } else { Access::Read },
                ),
                memory,
            ],
        )))
    }

    fn decode_simd_load_store_unscaled_or_writeback(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x3f20_0000 != 0x3c00_0000 {
            return None;
        }
        let mode = (word >> 10) & 0x3;
        if mode == 2 {
            return None;
        }
        let Some((prefix, bits, load)) = Self::simd_load_store_kind(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let displacement = Self::signed_field(word, 12, 9, 0);
        let mut operands = vec![
            Operand::register(
                format!("{prefix}{}", word & 0x1f),
                bits,
                if load { Access::Write } else { Access::Read },
            ),
            Operand::memory(
                bits,
                if load { Access::Read } else { Access::Write },
                Some(if mode == 1 { 0 } else { displacement }),
                Some(Self::register_or_sp(true, (word >> 5) & 0x1f)),
                None,
                None,
            ),
        ];
        if mode == 1 || (mode == 3 && displacement != 0) {
            operands.push(Operand::immediate(displacement, 0));
        }
        Some(Ok(Self::instruction(
            address,
            bytes,
            if mode == 0 {
                if load {
                    "ldur"
                } else {
                    "stur"
                }
            } else if load {
                "ldr"
            } else {
                "str"
            },
            operands,
        )))
    }

    fn decode_simd_load_store_register_offset(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x3f20_0c00 != 0x3c20_0800 {
            return None;
        }
        let Some((prefix, bits, load)) = Self::simd_load_store_kind(word) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let option = (word >> 13) & 0x7;
        if !matches!(option, 2 | 3 | 6 | 7) {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let encoded_shift = (bits / 8).trailing_zeros() as u8;
        let shift = if word & 0x1000 != 0 { encoded_shift } else { 0 };
        let index_is_64 = matches!(option, 3 | 7);
        let index = Self::general_register(index_is_64, (word >> 16) & 0x1f);
        let base = Self::register_or_sp(true, (word >> 5) & 0x1f);
        let modifier = ["", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"][option as usize];
        let mut memory = Operand::memory(
            bits,
            if load { Access::Read } else { Access::Write },
            Some(0),
            Some(base.clone()),
            Some(index.clone()),
            if shift == 0 { None } else { Some(1 << shift) },
        );
        memory.text = if shift == 0 {
            format!("[{base}, {index}, {modifier}]")
        } else {
            format!("[{base}, {index}, {modifier} #{shift}]")
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            if load { "ldr" } else { "str" },
            vec![
                Operand::register(
                    format!("{prefix}{}", word & 0x1f),
                    bits,
                    if load { Access::Write } else { Access::Read },
                ),
                memory,
            ],
        )))
    }

    fn decode_load_store_pair(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x3a00_0000 != 0x2800_0000 {
            return None;
        }
        let opc = (word >> 30) & 0x3;
        let vector = word & 0x0400_0000 != 0;
        let mode = (word >> 23) & 0x3;
        let load = word & 0x0040_0000 != 0;
        let decoded = if vector {
            match opc {
                0 => ("s", 32_u8, 32_u8),
                1 => ("d", 64_u8, 64_u8),
                2 => ("q", 128_u8, 128_u8),
                _ => return Some(Err(DisassemblerError::InvalidInstruction())),
            }
        } else {
            match (opc, load) {
                (0, _) => ("w", 32, 32),
                (1, true) if mode != 0 => ("x", 64, 32),
                (2, _) => ("x", 64, 64),
                _ => return Some(Err(DisassemblerError::InvalidInstruction())),
            }
        };
        let (register_prefix, register_bits, memory_bits) = decoded;
        let displacement = Self::signed_field(word, 15, 7, (memory_bits / 8).trailing_zeros());
        let first_number = word & 0x1f;
        let second_number = (word >> 10) & 0x1f;
        let base = Self::register_or_sp(true, (word >> 5) & 0x1f);
        let register_name = |number| {
            if vector {
                format!("{register_prefix}{number}")
            } else {
                Self::general_register(register_bits == 64, number)
            }
        };
        let register_access = if load { Access::Write } else { Access::Read };
        let mnemonic = if !vector && opc == 1 {
            "ldpsw"
        } else if mode == 0 {
            if load {
                "ldnp"
            } else {
                "stnp"
            }
        } else if load {
            "ldp"
        } else {
            "stp"
        };
        let memory_displacement = if mode == 1 { 0 } else { displacement };
        let mut operands = vec![
            Operand::register(register_name(first_number), register_bits, register_access),
            Operand::register(register_name(second_number), register_bits, register_access),
            Operand::memory(
                memory_bits,
                if load { Access::Read } else { Access::Write },
                Some(memory_displacement),
                Some(base),
                None,
                None,
            ),
        ];
        if mode == 1 || (mode == 3 && displacement != 0) {
            operands.push(Operand::immediate(displacement, 0));
        }
        Some(Ok(Self::instruction(address, bytes, mnemonic, operands)))
    }

    fn decode_move_wide(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x1f80_0000 != 0x1280_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let operation = (word >> 29) & 0x3;
        let halfword = (word >> 21) & 0x3;
        if operation == 1 || (!is_64 && halfword >= 2) {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let shift = halfword * 16;
        let raw_immediate = u64::from((word >> 5) & 0xffff);
        let shifted = raw_immediate << shift;
        let (mnemonic, immediate, access) = match operation {
            0 => {
                let value = if is_64 {
                    !shifted as i64
                } else {
                    i64::from(!(shifted as u32) as i32)
                };
                ("mov", value, Access::Write)
            }
            2 if shift == 0 => ("mov", shifted as i64, Access::Write),
            2 => ("movz", shifted as i64, Access::Write),
            3 => ("movk", shifted as i64, Access::ReadWrite),
            _ => unreachable!("reserved move-wide operation rejected above"),
        };
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Operand::register(
                    Self::general_register(is_64, word & 0x1f),
                    if is_64 { 64 } else { 32 },
                    access,
                ),
                Operand::immediate(immediate, if is_64 { 64 } else { 32 }),
            ],
        )))
    }

    fn decode_logical_immediate_mask(word: u32, is_64: bool) -> Option<u64> {
        decode_logical_immediate_mask(
            ((word >> 22) & 1) as u8,
            ((word >> 16) & 0x3f) as u8,
            ((word >> 10) & 0x3f) as u8,
            if is_64 { 64 } else { 32 },
        )
    }

    fn is_any_move_wide_alias(value: u64, is_64: bool) -> bool {
        let bits = if is_64 { 64 } else { 32 };
        let width_mask = if is_64 { u64::MAX } else { u64::from(u32::MAX) };
        let value = value & width_mask;
        (0..bits)
            .step_by(16)
            .any(|shift| value & !(0xffff_u64 << shift) == 0)
            || (0..bits)
                .step_by(16)
                .any(|shift| (!value & width_mask) & !(0xffff_u64 << shift) == 0)
    }

    fn decode_logical_immediate(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x1f80_0000 != 0x1200_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let Some(mask) = Self::decode_logical_immediate_mask(word, is_64) else {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        };
        let operation = (word >> 29) & 0x3;
        let source_number = (word >> 5) & 0x1f;
        let destination_number = word & 0x1f;
        let bits = if is_64 { 64 } else { 32 };
        let immediate = if is_64 {
            mask as i64
        } else {
            i64::from(mask as u32)
        };

        if operation == 3 && destination_number == 31 {
            return Some(Ok(Self::instruction(
                address,
                bytes,
                "tst",
                vec![
                    Operand::register(
                        Self::general_register(is_64, source_number),
                        bits,
                        Access::Read,
                    ),
                    Operand::immediate(immediate, bits),
                ],
            )));
        }
        if operation == 1
            && source_number == 31
            && !is_64
            && !Self::is_any_move_wide_alias(mask, is_64)
        {
            return Some(Ok(Self::instruction(
                address,
                bytes,
                "mov",
                vec![
                    Operand::register(
                        Self::register_or_sp(is_64, destination_number),
                        bits,
                        Access::Write,
                    ),
                    Operand::immediate(immediate, bits),
                ],
            )));
        }

        let mnemonic = ["and", "orr", "eor", "ands"][operation as usize];
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Operand::register(
                    if operation == 3 {
                        Self::general_register(is_64, destination_number)
                    } else {
                        Self::register_or_sp(is_64, destination_number)
                    },
                    bits,
                    Access::Write,
                ),
                Operand::register(
                    Self::general_register(is_64, source_number),
                    bits,
                    Access::Read,
                ),
                Operand::immediate(immediate, bits),
            ],
        )))
    }

    fn decode_logical_shifted_register(
        &self,
        address: &Address,
        bytes: &[u8],
        word: u32,
    ) -> Option<DisassemblerResult<Instruction>> {
        if word & 0x1f00_0000 != 0x0a00_0000 {
            return None;
        }
        let is_64 = word & 0x8000_0000 != 0;
        let operation = ((word >> 29) & 0x3) as usize;
        let invert = word & 0x0020_0000 != 0;
        let shift_kind = ((word >> 22) & 0x3) as usize;
        let shift = (word >> 10) & 0x3f;
        if !is_64 && shift >= 32 {
            return Some(Err(DisassemblerError::InvalidInstruction()));
        }
        let bits = if is_64 { 64 } else { 32 };
        let destination_number = word & 0x1f;
        let source_one_number = (word >> 5) & 0x1f;
        let source_two_number = (word >> 16) & 0x1f;
        let mut source_two = Operand::register(
            Self::general_register(is_64, source_two_number),
            bits,
            Access::Read,
        );
        if shift_kind != 0 || shift != 0 {
            let modifier = ["lsl", "lsr", "asr", "ror"][shift_kind];
            source_two.text = format!(
                "{}, {modifier} #{shift}",
                source_two.register.as_deref().unwrap()
            );
        }

        if operation == 3 && !invert && destination_number == 31 {
            return Some(Ok(Self::instruction(
                address,
                bytes,
                "tst",
                vec![
                    Operand::register(
                        Self::general_register(is_64, source_one_number),
                        bits,
                        Access::Read,
                    ),
                    source_two,
                ],
            )));
        }
        if operation == 1 && source_one_number == 31 && shift_kind == 0 && shift == 0 {
            return Some(Ok(Self::instruction(
                address,
                bytes,
                if invert { "mvn" } else { "mov" },
                vec![
                    Operand::register(
                        Self::general_register(is_64, destination_number),
                        bits,
                        Access::Write,
                    ),
                    source_two,
                ],
            )));
        }

        let mnemonic = [
            ["and", "bic"],
            ["orr", "orn"],
            ["eor", "eon"],
            ["ands", "bics"],
        ][operation][usize::from(invert)];
        Some(Ok(Self::instruction(
            address,
            bytes,
            mnemonic,
            vec![
                Operand::register(
                    Self::general_register(is_64, destination_number),
                    bits,
                    Access::Write,
                ),
                Operand::register(
                    Self::general_register(is_64, source_one_number),
                    bits,
                    Access::Read,
                ),
                source_two,
            ],
        )))
    }
}

impl Disassembler for NativeAarch64Disassembler {
    fn disassemble_instruction(
        &self,
        address: &Address,
        bytes: &[u8],
    ) -> DisassemblerResult<Instruction> {
        let word = self.word(bytes)?;
        if let Some(instruction) = self.decode_branch_immediate(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_conditional_branch(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_compare_branch(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_branch_register(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_test_branch(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_exception_generation(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_hint_or_barrier(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_exception_return(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_pstate_immediate(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_system_instruction(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_system_register_move(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_pc_relative_address(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_add_sub_immediate(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_add_sub_extended_register(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_add_sub_shifted_register(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_add_sub_with_carry(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_conditional_select(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_conditional_compare(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_multiply(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_bitfield(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_extract(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_data_processing_one_source(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_data_processing_two_source(address, bytes, word) {
            return Ok(instruction);
        }
        // Resolve this precise class before broader SIMD handlers that share
        // portions of its opcode space and reject non-members fail-closed.
        if let Some(instruction) = self.decode_advanced_simd_scalar_conversion(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) =
            self.decode_advanced_simd_scalar_shift_immediate(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_extract(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_reciprocal_step(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_pairwise_add(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) =
            self.decode_advanced_simd_integer_three_same(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_shift_left_long(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_absolute_compare(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_crypto(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_bitwise(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_table_lookup(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_fp_three_same(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_scalar_abs_neg(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_scalar_fabd(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) =
            self.decode_advanced_simd_scalar_integer_three_source(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_scalar_pairwise(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) =
            self.decode_advanced_simd_scalar_compare_zero(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_scalar_fp_compare(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) =
            self.decode_advanced_simd_scalar_fp_compare_zero(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) =
            self.decode_advanced_simd_scalar_extract_narrow(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_scalar_reciprocal(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_scalar_multiply(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) =
            self.decode_advanced_simd_scalar_by_element_multiply(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) =
            self.decode_advanced_simd_scalar_by_element_saturating_mla(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) =
            self.decode_advanced_simd_scalar_by_element_saturating_multiply(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) = self.decode_advanced_simd_scalar_copy(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_scalar_fp_one_source(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_scalar_fp_two_source(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_scalar_fp_three_source(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_scalar_fp_compare(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_scalar_fp_conditional_compare(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_scalar_fp_conditional_select(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_scalar_fp_lane_move(address, bytes, word) {
            return Ok(instruction);
        }
        if let Some(instruction) = self.decode_scalar_fp_immediate(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_scalar_fp_fixed_conversion(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_scalar_fp_integer_conversion(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_load_literal(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_exclusive_or_ordered_load_store(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) = self.decode_prefetch(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_load_store_unsigned(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_simd_load_store_unsigned(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) =
            self.decode_load_store_unscaled_or_writeback(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) =
            self.decode_simd_load_store_unscaled_or_writeback(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) = self.decode_load_store_register_offset(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_simd_load_store_register_offset(address, bytes, word)
        {
            return instruction;
        }
        if let Some(instruction) = self.decode_load_store_pair(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_move_wide(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_logical_immediate(address, bytes, word) {
            return instruction;
        }
        if let Some(instruction) = self.decode_logical_shifted_register(address, bytes, word) {
            return instruction;
        }
        Err(DisassemblerError::UnsupportedInstruction())
    }

    fn max_instruction_length(&self) -> usize {
        4
    }

    fn architecture(&self) -> Architecture {
        Architecture::ARM64
    }

    fn endianness(&self) -> Endianness {
        self.endianness
    }

    fn name(&self) -> &str {
        "glaurung-aarch64"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::AddressKind;
    use crate::core::instruction::OperandKind;
    use crate::disasm::capstone::CapstoneDisassembler;
    use serde::Deserialize;

    fn va(value: u64) -> Address {
        Address::new(AddressKind::VA, value, 64, None, None).unwrap()
    }

    #[derive(Deserialize)]
    struct Corpus {
        schema: String,
        upstream: Upstream,
        vectors: Vec<Vector>,
    }

    #[derive(Deserialize)]
    struct Upstream {
        project: String,
        version: String,
        #[serde(rename = "crate")]
        crate_name: String,
        path: String,
        licenses: Vec<String>,
    }

    #[derive(Deserialize)]
    struct Vector {
        line: u32,
        bytes: [u8; 4],
        mnemonic: String,
        operands: Vec<ExpectedOperand>,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ExpectedOperand {
        RegisterList {
            register_list: Vec<String>,
            vector_shape: VectorShape,
        },
        Register {
            register: String,
            #[serde(default)]
            modifier: Option<String>,
            #[serde(default)]
            shift: u8,
            #[serde(default)]
            vector_shape: Option<VectorShape>,
            #[serde(default)]
            vector_index: Option<u32>,
        },
        Immediate {
            immediate: i64,
        },
        Memory {
            memory: ExpectedMemory,
        },
    }

    #[derive(Deserialize)]
    struct ExpectedMemory {
        base: String,
        #[serde(default)]
        displacement: i64,
        #[serde(default)]
        index: Option<String>,
        #[serde(default)]
        modifier: Option<String>,
        #[serde(default)]
        shift: u8,
    }

    fn capstone_native_slice_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-native-slice.json"
        ))
        .expect("checked-in Capstone corpus must be valid")
    }

    fn capstone_gicv3_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-gicv3-regs.json"
        ))
        .expect("checked-in Capstone GICv3 corpus must be valid")
    }

    fn capstone_trace_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-trace-regs.json"
        ))
        .expect("checked-in Capstone trace-register corpus must be valid")
    }

    fn capstone_neon_scalar_abs_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-abs.json"
        ))
        .expect("checked-in Capstone scalar-absolute corpus must be valid")
    }

    fn capstone_neon_scalar_neg_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-neg.json"
        ))
        .expect("checked-in Capstone scalar-negate corpus must be valid")
    }

    fn capstone_neon_scalar_add_sub_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-add-sub.json"
        ))
        .expect("checked-in Capstone scalar-add-subtract corpus must be valid")
    }

    fn capstone_neon_scalar_shift_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-shift.json"
        ))
        .expect("checked-in Capstone scalar-shift corpus must be valid")
    }

    fn capstone_neon_scalar_reduce_pairwise_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-reduce-pairwise.json"
        ))
        .expect("checked-in Capstone scalar-pairwise corpus must be valid")
    }

    fn capstone_neon_scalar_saturating_add_sub_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-saturating-add-sub.json"
        ))
        .expect("checked-in Capstone scalar-saturating-add-subtract corpus must be valid")
    }

    fn capstone_neon_scalar_saturating_rounding_shift_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-saturating-rounding-shift.json"
        ))
        .expect("checked-in Capstone scalar-saturating-rounding-shift corpus must be valid")
    }

    fn capstone_neon_scalar_saturating_shift_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-saturating-shift.json"
        ))
        .expect("checked-in Capstone scalar-saturating-shift corpus must be valid")
    }

    fn capstone_neon_scalar_rounding_shift_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-rounding-shift.json"
        ))
        .expect("checked-in Capstone scalar-rounding-shift corpus must be valid")
    }

    fn capstone_neon_scalar_compare_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-compare.json"
        ))
        .expect("checked-in Capstone scalar-compare corpus must be valid")
    }

    fn capstone_neon_scalar_fp_compare_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-fp-compare.json"
        ))
        .expect("checked-in Capstone scalar-FP-compare corpus must be valid")
    }

    fn capstone_neon_scalar_extract_narrow_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-extract-narrow.json"
        ))
        .expect("checked-in Capstone scalar-extract-narrow corpus must be valid")
    }

    fn capstone_neon_scalar_recip_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-recip.json"
        ))
        .expect("checked-in Capstone scalar-reciprocal corpus must be valid")
    }

    fn capstone_neon_scalar_mul_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-mul.json"
        ))
        .expect("checked-in Capstone scalar-multiply corpus must be valid")
    }

    fn capstone_neon_scalar_by_element_mul_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-by-elem-mul.json"
        ))
        .expect("checked-in Capstone scalar-by-element-multiply corpus must be valid")
    }

    fn capstone_neon_scalar_by_element_mla_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-by-elem-mla.json"
        ))
        .expect("checked-in Capstone scalar-by-element-MLA corpus must be valid")
    }

    fn capstone_neon_scalar_by_element_saturating_mla_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-by-elem-saturating-mla.json"
        ))
        .expect("checked-in Capstone scalar-by-element-saturating-MLA corpus must be valid")
    }

    fn capstone_neon_scalar_by_element_saturating_mul_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-by-elem-saturating-mul.json"
        ))
        .expect("checked-in Capstone scalar-by-element-saturating-multiply corpus must be valid")
    }

    fn capstone_neon_scalar_dup_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-dup.json"
        ))
        .expect("checked-in Capstone scalar-copy corpus must be valid")
    }

    fn capstone_neon_scalar_cvt_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-cvt.json"
        ))
        .expect("checked-in Capstone scalar-conversion corpus must be valid")
    }

    fn capstone_neon_scalar_shift_immediate_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-scalar-shift-imm.json"
        ))
        .expect("checked-in Capstone scalar-immediate-shift corpus must be valid")
    }

    fn capstone_neon_extract_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-extract.json"
        ))
        .expect("checked-in Capstone vector-extract corpus must be valid")
    }

    fn capstone_neon_reciprocal_step_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-frsqrt-frecp.json"
        ))
        .expect("checked-in Capstone vector-reciprocal-step corpus must be valid")
    }

    fn capstone_neon_add_pairwise_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-add-pairwise.json"
        ))
        .expect("checked-in Capstone vector-pairwise-add corpus must be valid")
    }

    fn capstone_neon_rounding_halving_add_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-rounding-halving-add.json"
        ))
        .expect("checked-in Capstone vector-rounding-halving-add corpus must be valid")
    }

    fn capstone_neon_rounding_shift_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-rounding-shift.json"
        ))
        .expect("checked-in Capstone vector-rounding-shift corpus must be valid")
    }

    fn capstone_neon_saturating_shift_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-saturating-shift.json"
        ))
        .expect("checked-in Capstone vector-saturating-shift corpus must be valid")
    }

    fn capstone_neon_saturating_rounding_shift_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-saturating-rounding-shift.json"
        ))
        .expect("checked-in Capstone vector-saturating-rounding-shift corpus must be valid")
    }

    fn capstone_neon_shift_left_long_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-shift-left-long.json"
        ))
        .expect("checked-in Capstone vector-shift-left-long corpus must be valid")
    }

    fn capstone_neon_absolute_compare_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-facge-facgt.json"
        ))
        .expect("checked-in Capstone vector-absolute-compare corpus must be valid")
    }

    fn capstone_neon_crypto_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-crypto.json"
        ))
        .expect("checked-in Capstone vector-crypto corpus must be valid")
    }

    fn capstone_neon_bitwise_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-bitwise-instructions.json"
        ))
        .expect("checked-in Capstone vector-bitwise corpus must be valid")
    }

    fn capstone_neon_mla_mls_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-mla-mls-instructions.json"
        ))
        .expect("checked-in Capstone vector-MLA/MLS corpus must be valid")
    }

    fn capstone_neon_add_sub_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-add-sub-instructions.json"
        ))
        .expect("checked-in Capstone vector-add/sub corpus must be valid")
    }

    fn capstone_neon_table_lookup_corpus() -> Corpus {
        serde_json::from_str(include_str!(
            "../../tests/corpora/capstone/aarch64-neon-tbl.json"
        ))
        .expect("checked-in Capstone vector-table-lookup corpus must be valid")
    }

    fn word_is_move_wide(word: u32) -> bool {
        word & 0x1f80_0000 == 0x1280_0000
    }

    fn word_is_logical_immediate(word: u32) -> bool {
        word & 0x1f80_0000 == 0x1200_0000
    }

    fn word_is_logical_shifted_register(word: u32) -> bool {
        word & 0x1f00_0000 == 0x0a00_0000
    }

    fn word_is_add_sub_extended_register(word: u32) -> bool {
        word & 0x1fe0_0000 == 0x0b20_0000
    }

    fn word_is_add_sub_shifted_register(word: u32) -> bool {
        word & 0x1f20_0000 == 0x0b00_0000
    }

    fn word_is_add_sub_with_carry(word: u32) -> bool {
        word & 0x1fe0_fc00 == 0x1a00_0000
    }

    fn word_is_conditional_select(word: u32) -> bool {
        word & 0x3fe0_0800 == 0x1a80_0000
    }

    fn word_is_conditional_compare(word: u32) -> bool {
        word & 0x3fe0_0410 == 0x3a40_0000
    }

    fn word_is_multiply(word: u32) -> bool {
        word & 0x7f00_0000 == 0x1b00_0000
    }

    fn word_is_bitfield(word: u32) -> bool {
        word & 0x1f80_0000 == 0x1300_0000
    }

    fn word_is_extract(word: u32) -> bool {
        word & 0x1f80_0000 == 0x1380_0000
    }

    fn word_is_data_processing_one_source(word: u32) -> bool {
        word & 0x7fff_0000 == 0x5ac0_0000
    }

    fn word_is_data_processing_two_source(word: u32) -> bool {
        matches!(
            word & 0x7fe0_fc00,
            0x1ac0_0800 | 0x1ac0_0c00 | 0x1ac0_2000 | 0x1ac0_2400 | 0x1ac0_2800 | 0x1ac0_2c00
        ) || word & 0x7fe0_e000 == 0x1ac0_4000
    }

    fn word_is_scalar_fp(word: u32) -> bool {
        word & 0xff20_7c00 == 0x1e20_4000
            || word & 0xff20_0c00 == 0x1e20_0800
            || word & 0xff00_0000 == 0x1f00_0000
            || word & 0xff20_fc07 == 0x1e20_2000
            || word & 0xff20_0c00 == 0x1e20_0400
            || word & 0xff20_0c00 == 0x1e20_0c00
            || word & 0xff20_1fe0 == 0x1e20_1000
            || word & 0xfffe_fc00 == 0x9eae_0000
            || word & 0x5f20_0000 == 0x1e00_0000 && matches!((word >> 16) & 0x1f, 2 | 3 | 24 | 25)
            || word & 0x5f20_fc00 == 0x1e20_0000
    }

    fn word_is_advanced_simd_scalar(word: u32) -> bool {
        matches!(
            word & 0xdf00_f400,
            0x5f00_1000
                | 0x5f00_3000
                | 0x5f00_5000
                | 0x5f00_7000
                | 0x5f00_9000
                | 0x5f00_b000
                | 0x5f00_c000
                | 0x5f00_d000
        ) || word & 0xdf80_0400 == 0x5f00_0400
            || word & 0xffe0_fc00 == 0x5e00_0400
            || word & 0xffff_fc00 == 0x7e61_6800
            || matches!(word & 0xdf80_fc00, 0x5f00_e400 | 0x5f00_fc00)
            || matches!(
                word & 0xdfbf_fc00,
                0x5e21_a800 | 0x5ea1_a800 | 0x5e21_b800 | 0x5ea1_b800 | 0x5e21_c800 | 0x5e21_d800
            )
            || matches!(word & 0xdf3f_fc00, 0x5e20_b800 | 0x5e20_7800)
            || word & 0xff20_fc00 == 0x7e20_d400
            || matches!(
                word & 0xdf20_fc00,
                0x5e20_8400
                    | 0x5e20_4400
                    | 0x5e20_0c00
                    | 0x5e20_2c00
                    | 0x5e20_4c00
                    | 0x5e20_5c00
                    | 0x5e20_5400
                    | 0x5e20_8c00
                    | 0x5e20_3c00
                    | 0x5e20_3400
                    | 0x5e20_b400
                    | 0x5e20_dc00
                    | 0x5e20_9000
                    | 0x5e20_b000
                    | 0x5e20_d000
            )
            || matches!(
                word & 0xdf3f_fc00,
                0x5e20_3800 | 0x5e20_9800 | 0x5e20_8800 | 0x5e20_a800
            )
            || matches!(word & 0xdf20_fc00, 0x5e20_e400 | 0x5e20_ec00)
            || matches!(word & 0xdfa0_fc00, 0x5e20_fc00 | 0x5ea0_fc00)
            || matches!(
                word & 0xdf3f_fc00,
                0x5e20_c800
                    | 0x5e20_d800
                    | 0x5e20_e800
                    | 0x5e21_2800
                    | 0x5e21_4800
                    | 0x5e21_d800
                    | 0x5e21_f800
            )
            || matches!(word & 0xff3f_fc00, 0x5e31_b800 | 0x7e30_d800)
    }

    fn word_is_advanced_simd_vector(word: u32) -> bool {
        word & 0xbfe0_8400 == 0x2e00_0000
            || matches!(word & 0xbf80_fc00, 0x0e00_fc00 | 0x0e80_fc00)
            || matches!(word & 0xbf20_fc00, 0x0e20_bc00 | 0x2e20_d400)
            || matches!(
                word & 0xbf20_fc00,
                0x0e20_1400
                    | 0x2e20_1400
                    | 0x0e20_4c00
                    | 0x2e20_4c00
                    | 0x0e20_5400
                    | 0x2e20_5400
                    | 0x0e20_5c00
                    | 0x2e20_5c00
                    | 0x0e20_8400
                    | 0x2e20_8400
                    | 0x0e20_9400
                    | 0x2e20_9400
            )
            || word & 0x9f80_fc00 == 0x0f00_a400
            || word & 0xbf20_fc00 == 0x2e20_ec00
            || matches!(
                word & 0xbfa0_fc00,
                0x0e20_cc00 | 0x0ea0_cc00 | 0x0e20_d400 | 0x0ea0_d400
            )
    }

    fn word_is_advanced_simd_crypto(word: u32) -> bool {
        matches!(
            word & 0xffff_fc00,
            0x4e28_4800
                | 0x4e28_5800
                | 0x4e28_6800
                | 0x4e28_7800
                | 0x5e28_0800
                | 0x5e28_1800
                | 0x5e28_2800
        ) || matches!(
            word & 0xffe0_fc00,
            0x5e00_0000
                | 0x5e00_1000
                | 0x5e00_2000
                | 0x5e00_3000
                | 0x5e00_4000
                | 0x5e00_5000
                | 0x5e00_6000
        )
    }

    fn word_is_advanced_simd_bitwise(word: u32) -> bool {
        matches!(
            word & 0xbfe0_fc00,
            0x0e20_1c00
                | 0x0e60_1c00
                | 0x0ea0_1c00
                | 0x0ee0_1c00
                | 0x2e20_1c00
                | 0x2e60_1c00
                | 0x2ea0_1c00
                | 0x2ee0_1c00
        )
    }

    fn word_is_advanced_simd_table_lookup(word: u32) -> bool {
        matches!(word & 0xbfe0_9c00, 0x0e00_0000 | 0x0e00_1000)
    }

    fn word_is_load_store_pair(word: u32) -> bool {
        word & 0x3a00_0000 == 0x2800_0000
    }

    fn word_is_scalar_unscaled_or_writeback(word: u32) -> bool {
        word & 0x3f20_0000 == 0x3800_0000
    }

    fn word_is_load_literal(word: u32) -> bool {
        word & 0x3b00_0000 == 0x1800_0000
    }

    fn word_is_exclusive_or_ordered_load_store(word: u32) -> bool {
        word & 0x3f00_0000 == 0x0800_0000
    }

    fn word_is_prefetch(word: u32) -> bool {
        word & 0xffc0_0000 == 0xf980_0000
            || word & 0xffe0_0c00 == 0xf880_0000
            || word & 0xffe0_0c00 == 0xf8a0_0800
    }

    fn word_is_scalar_register_offset(word: u32) -> bool {
        word & 0x3f20_0c00 == 0x3820_0800
    }

    fn word_is_simd_unsigned(word: u32) -> bool {
        word & 0x3f00_0000 == 0x3d00_0000
    }

    fn word_is_simd_unscaled_or_writeback(word: u32) -> bool {
        word & 0x3f20_0000 == 0x3c00_0000 && (word >> 10) & 0x3 != 2
    }

    fn word_is_simd_register_offset(word: u32) -> bool {
        word & 0x3f20_0c00 == 0x3c20_0800
    }

    fn word_is_system_register_move(word: u32) -> bool {
        matches!(word & 0xfff0_0000, 0xd510_0000 | 0xd530_0000)
    }

    fn word_is_pstate_immediate(word: u32) -> bool {
        word & 0xfff8_f01f == 0xd500_401f
    }

    fn word_is_system_instruction(word: u32) -> bool {
        matches!(word & 0xfff8_0000, 0xd508_0000 | 0xd528_0000)
    }

    /// LLVM MC boundary encodings complement Capstone's checked-in corpus,
    /// which does not currently carry TBZ/TBNZ vectors.
    const LLVM_TEST_BRANCH_VECTORS: &[([u8; 4], &str, &[i64])] = &[
        ([0x20, 0x00, 0x00, 0x36], "tbz", &[0, 4]),
        ([0xff, 0xff, 0xff, 0x37], "tbnz", &[31, -4]),
        ([0xf4, 0xff, 0x03, 0xb6], "tbz", &[32, 32_764]),
        ([0x1e, 0x00, 0xfc, 0xb7], "tbnz", &[63, -32_768]),
    ];

    #[test]
    fn checked_in_capstone_native_slice_decodes() {
        let corpus = capstone_native_slice_corpus();
        assert_eq!(corpus.schema, "glaurung-capstone-mc-v1");
        assert_eq!(corpus.upstream.project, "capstone");
        assert_eq!(corpus.upstream.version, "5.0.0");
        assert_eq!(corpus.upstream.crate_name, "capstone-sys 0.16.0");
        assert_eq!(
            corpus.upstream.path,
            "suite/MC/AArch64/basic-a64-instructions.s.cs"
        );
        assert_eq!(corpus.upstream.licenses, ["BSD-3-Clause", "NCSA"]);

        let decoder = NativeAarch64Disassembler::new(Endianness::Little);
        for vector in corpus.vectors {
            let instruction = decoder
                .disassemble_instruction(&va(0), &vector.bytes)
                .unwrap_or_else(|error| panic!("upstream line {}: {error}", vector.line));
            assert_eq!(
                instruction.mnemonic, vector.mnemonic,
                "line {}",
                vector.line
            );
            assert_eq!(instruction.operands.len(), vector.operands.len());
            for (actual, expected) in instruction.operands.iter().zip(vector.operands) {
                match expected {
                    ExpectedOperand::RegisterList { .. } => {
                        panic!("base A64 corpus unexpectedly contains a register list")
                    }
                    ExpectedOperand::Register {
                        register,
                        modifier,
                        shift,
                        vector_shape,
                        vector_index,
                    } => {
                        assert_eq!(actual.register.as_deref(), Some(register.as_str()));
                        assert_eq!(actual.vector_shape, vector_shape);
                        assert_eq!(actual.vector_index, vector_index);
                        if let Some(modifier) = modifier {
                            let expected_text = if shift == 0
                                && !matches!(modifier.as_str(), "lsl" | "lsr" | "asr" | "ror")
                            {
                                format!("{register}, {modifier}")
                            } else {
                                format!("{register}, {modifier} #{shift}")
                            };
                            assert_eq!(actual.text, expected_text);
                        }
                    }
                    ExpectedOperand::Immediate { immediate } => {
                        assert_eq!(actual.immediate, Some(immediate))
                    }
                    ExpectedOperand::Memory { memory } => {
                        assert_eq!(actual.base.as_deref(), Some(memory.base.as_str()));
                        assert_eq!(actual.displacement, Some(memory.displacement));
                        assert_eq!(actual.index, memory.index);
                        let expected_scale = if memory.shift == 0 {
                            None
                        } else {
                            Some(1 << memory.shift)
                        };
                        assert_eq!(actual.scale, expected_scale);
                        if let Some(modifier) = memory.modifier {
                            assert!(actual.text.contains(&modifier));
                        }
                    }
                }
            }
            if matches!(
                instruction.mnemonic.as_str(),
                "adr" | "adrp" | "add" | "adds" | "sub" | "subs"
            ) {
                assert_eq!(instruction.operands[0].access, Access::Write);
            }
            if matches!(
                instruction.mnemonic.as_str(),
                "ldr" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrsw" | "str" | "strb" | "strh"
            ) && !word_is_load_literal(u32::from_le_bytes(vector.bytes))
            {
                let store = instruction.mnemonic.starts_with("str");
                assert_eq!(
                    instruction.operands[0].access,
                    if store { Access::Read } else { Access::Write }
                );
                assert_eq!(
                    instruction.operands[1].access,
                    if store { Access::Write } else { Access::Read }
                );
                assert_ne!(instruction.operands[0].size, 0);
                assert_ne!(instruction.operands[1].size, 0);
            }
            if word_is_scalar_unscaled_or_writeback(u32::from_le_bytes(vector.bytes))
                || word_is_simd_unscaled_or_writeback(u32::from_le_bytes(vector.bytes))
            {
                if word_is_prefetch(u32::from_le_bytes(vector.bytes)) {
                    continue;
                }
                let store = instruction.mnemonic.starts_with("st");
                assert_eq!(
                    instruction.operands[0].access,
                    if store { Access::Read } else { Access::Write }
                );
                assert_eq!(
                    instruction.operands[1].access,
                    if store { Access::Write } else { Access::Read }
                );
                assert_ne!(instruction.operands[0].size, 0);
                assert_ne!(instruction.operands[1].size, 0);
            }
            if word_is_scalar_register_offset(u32::from_le_bytes(vector.bytes))
                || word_is_simd_register_offset(u32::from_le_bytes(vector.bytes))
            {
                if word_is_prefetch(u32::from_le_bytes(vector.bytes)) {
                    continue;
                }
                let store = instruction.mnemonic.starts_with("st");
                assert_eq!(
                    instruction.operands[0].access,
                    if store { Access::Read } else { Access::Write }
                );
                assert_eq!(
                    instruction.operands[1].access,
                    if store { Access::Write } else { Access::Read }
                );
                assert_ne!(instruction.operands[0].size, 0);
                assert_ne!(instruction.operands[1].size, 0);
                assert!(instruction.operands[1].index.is_some());
            }
            if word_is_load_store_pair(u32::from_le_bytes(vector.bytes)) {
                let store = instruction.mnemonic.starts_with("st");
                assert_eq!(
                    instruction.operands[0].access,
                    if store { Access::Read } else { Access::Write }
                );
                assert_eq!(
                    instruction.operands[1].access,
                    instruction.operands[0].access
                );
                assert_eq!(
                    instruction.operands[2].access,
                    if store { Access::Write } else { Access::Read }
                );
                assert!(instruction.operands[..3]
                    .iter()
                    .all(|operand| operand.size != 0));
            }
            if word_is_system_register_move(u32::from_le_bytes(vector.bytes)) {
                let read = instruction.mnemonic == "mrs";
                assert_eq!(instruction.operands[0].size, 64);
                assert_eq!(instruction.operands[1].size, 64);
                assert_eq!(instruction.operands[0].access, Access::Write);
                assert_eq!(instruction.operands[1].access, Access::Read);
                if !read {
                    assert!(instruction.operands[0]
                        .register
                        .as_deref()
                        .is_some_and(|register| !register.starts_with('x')));
                }
            }
            if word_is_system_instruction(u32::from_le_bytes(vector.bytes)) {
                if matches!(instruction.mnemonic.as_str(), "sys" | "sysl") {
                    assert_eq!(
                        instruction
                            .operands
                            .iter()
                            .filter(|operand| operand
                                .register
                                .as_deref()
                                .is_some_and(|name| name.starts_with('c')))
                            .count(),
                        2
                    );
                } else {
                    assert!(instruction.operands[0].register.is_some());
                }
            }
            if word_is_add_sub_shifted_register(u32::from_le_bytes(vector.bytes)) {
                assert!(instruction.operands.iter().all(|operand| operand.size != 0));
            }
            if word_is_add_sub_with_carry(u32::from_le_bytes(vector.bytes)) {
                assert_eq!(instruction.operands[0].access, Access::Write);
                assert!(instruction.operands.iter().all(|operand| operand.size != 0));
            }
            if word_is_conditional_select(u32::from_le_bytes(vector.bytes)) {
                assert_eq!(instruction.operands[0].access, Access::Write);
                assert!(instruction.operands.iter().all(|operand| operand.size != 0));
            }
            if word_is_conditional_compare(u32::from_le_bytes(vector.bytes)) {
                assert!(instruction.operands.iter().all(|operand| operand.size != 0));
            }
            if word_is_multiply(u32::from_le_bytes(vector.bytes)) {
                assert_eq!(instruction.operands[0].access, Access::Write);
                assert!(instruction.operands.iter().all(|operand| operand.size != 0));
            }
            if word_is_bitfield(u32::from_le_bytes(vector.bytes)) {
                assert_eq!(
                    instruction.operands[0].access,
                    if matches!(instruction.mnemonic.as_str(), "bfc" | "bfi" | "bfxil") {
                        Access::ReadWrite
                    } else {
                        Access::Write
                    }
                );
                assert!(instruction.operands.iter().all(|operand| operand.size != 0));
            }
            if word_is_extract(u32::from_le_bytes(vector.bytes))
                || word_is_data_processing_one_source(u32::from_le_bytes(vector.bytes))
                || word_is_data_processing_two_source(u32::from_le_bytes(vector.bytes))
            {
                assert_eq!(instruction.operands[0].access, Access::Write);
                assert!(instruction.operands.iter().all(|operand| operand.size != 0));
            }
            if word_is_logical_shifted_register(u32::from_le_bytes(vector.bytes)) {
                assert!(instruction.operands.iter().all(|operand| operand.size != 0));
                if instruction.mnemonic != "tst" {
                    assert_eq!(instruction.operands[0].access, Access::Write);
                }
            }
            if word_is_move_wide(u32::from_le_bytes(vector.bytes)) {
                assert_eq!(
                    instruction.operands[0].access,
                    if instruction.mnemonic == "movk" {
                        Access::ReadWrite
                    } else {
                        Access::Write
                    }
                );
                assert_ne!(instruction.operands[0].size, 0);
                assert_ne!(instruction.operands[1].size, 0);
            }
            if word_is_logical_immediate(u32::from_le_bytes(vector.bytes)) {
                if instruction.mnemonic != "tst" {
                    assert_eq!(instruction.operands[0].access, Access::Write);
                }
                assert!(instruction.operands.iter().all(|operand| operand.size != 0));
            }
            if word_is_scalar_fp(u32::from_le_bytes(vector.bytes)) {
                let writes_destination = !matches!(
                    instruction.mnemonic.as_str(),
                    "fcmp" | "fcmpe" | "fccmp" | "fccmpe"
                );
                if writes_destination {
                    assert_eq!(instruction.operands[0].access, Access::Write);
                    assert!(instruction.operands[1..]
                        .iter()
                        .all(|operand| operand.access == Access::Read));
                } else {
                    assert!(instruction
                        .operands
                        .iter()
                        .all(|operand| operand.access == Access::Read));
                }
            }
        }
    }

    #[test]
    fn llvm_test_branch_boundaries_decode() {
        let decoder = NativeAarch64Disassembler::new(Endianness::Little);
        for &(bytes, mnemonic, immediates) in LLVM_TEST_BRANCH_VECTORS {
            let instruction = decoder.disassemble_instruction(&va(0), &bytes).unwrap();
            assert_eq!(instruction.mnemonic, mnemonic, "bytes {bytes:02x?}");
            let actual = instruction
                .operands
                .iter()
                .filter_map(|operand| operand.immediate)
                .collect::<Vec<_>>();
            assert_eq!(actual, immediates, "bytes {bytes:02x?}");
        }
    }

    #[test]
    fn checked_in_aarch64_extension_corpora_decode() {
        let decoder = NativeAarch64Disassembler::new(Endianness::Little);
        for (corpus, expected_path) in [
            (capstone_gicv3_corpus(), "suite/MC/AArch64/gicv3-regs.s.cs"),
            (capstone_trace_corpus(), "suite/MC/AArch64/trace-regs.s.cs"),
            (
                capstone_neon_scalar_abs_corpus(),
                "suite/MC/AArch64/neon-scalar-abs.s.cs",
            ),
            (
                capstone_neon_scalar_neg_corpus(),
                "suite/MC/AArch64/neon-scalar-neg.s.cs",
            ),
            (
                capstone_neon_scalar_add_sub_corpus(),
                "suite/MC/AArch64/neon-scalar-add-sub.s.cs",
            ),
            (
                capstone_neon_scalar_shift_corpus(),
                "suite/MC/AArch64/neon-scalar-shift.s.cs",
            ),
            (
                capstone_neon_scalar_reduce_pairwise_corpus(),
                "suite/MC/AArch64/neon-scalar-reduce-pairwise.s.cs",
            ),
            (
                capstone_neon_scalar_saturating_add_sub_corpus(),
                "suite/MC/AArch64/neon-scalar-saturating-add-sub.s.cs",
            ),
            (
                capstone_neon_scalar_saturating_rounding_shift_corpus(),
                "suite/MC/AArch64/neon-scalar-saturating-rounding-shift.s.cs",
            ),
            (
                capstone_neon_scalar_saturating_shift_corpus(),
                "suite/MC/AArch64/neon-scalar-saturating-shift.s.cs",
            ),
            (
                capstone_neon_scalar_rounding_shift_corpus(),
                "suite/MC/AArch64/neon-scalar-rounding-shift.s.cs",
            ),
            (
                capstone_neon_scalar_compare_corpus(),
                "suite/MC/AArch64/neon-scalar-compare.s.cs",
            ),
            (
                capstone_neon_scalar_fp_compare_corpus(),
                "suite/MC/AArch64/neon-scalar-fp-compare.s.cs",
            ),
            (
                capstone_neon_scalar_extract_narrow_corpus(),
                "suite/MC/AArch64/neon-scalar-extract-narrow.s.cs",
            ),
            (
                capstone_neon_scalar_recip_corpus(),
                "suite/MC/AArch64/neon-scalar-recip.s.cs",
            ),
            (
                capstone_neon_scalar_mul_corpus(),
                "suite/MC/AArch64/neon-scalar-mul.s.cs",
            ),
            (
                capstone_neon_scalar_by_element_mul_corpus(),
                "suite/MC/AArch64/neon-scalar-by-elem-mul.s.cs",
            ),
            (
                capstone_neon_scalar_by_element_mla_corpus(),
                "suite/MC/AArch64/neon-scalar-by-elem-mla.s.cs",
            ),
            (
                capstone_neon_scalar_by_element_saturating_mla_corpus(),
                "suite/MC/AArch64/neon-scalar-by-elem-saturating-mla.s.cs",
            ),
            (
                capstone_neon_scalar_by_element_saturating_mul_corpus(),
                "suite/MC/AArch64/neon-scalar-by-elem-saturating-mul.s.cs",
            ),
            (
                capstone_neon_scalar_dup_corpus(),
                "suite/MC/AArch64/neon-scalar-dup.s.cs",
            ),
            (
                capstone_neon_scalar_cvt_corpus(),
                "suite/MC/AArch64/neon-scalar-cvt.s.cs",
            ),
            (
                capstone_neon_scalar_shift_immediate_corpus(),
                "suite/MC/AArch64/neon-scalar-shift-imm.s.cs",
            ),
            (
                capstone_neon_extract_corpus(),
                "suite/MC/AArch64/neon-extract.s.cs",
            ),
            (
                capstone_neon_reciprocal_step_corpus(),
                "suite/MC/AArch64/neon-frsqrt-frecp.s.cs",
            ),
            (
                capstone_neon_add_pairwise_corpus(),
                "suite/MC/AArch64/neon-add-pairwise.s.cs",
            ),
            (
                capstone_neon_rounding_halving_add_corpus(),
                "suite/MC/AArch64/neon-rounding-halving-add.s.cs",
            ),
            (
                capstone_neon_rounding_shift_corpus(),
                "suite/MC/AArch64/neon-rounding-shift.s.cs",
            ),
            (
                capstone_neon_saturating_shift_corpus(),
                "suite/MC/AArch64/neon-saturating-shift.s.cs",
            ),
            (
                capstone_neon_saturating_rounding_shift_corpus(),
                "suite/MC/AArch64/neon-saturating-rounding-shift.s.cs",
            ),
            (
                capstone_neon_shift_left_long_corpus(),
                "suite/MC/AArch64/neon-shift-left-long.s.cs",
            ),
            (
                capstone_neon_absolute_compare_corpus(),
                "suite/MC/AArch64/neon-facge-facgt.s.cs",
            ),
            (
                capstone_neon_crypto_corpus(),
                "suite/MC/AArch64/neon-crypto.s.cs",
            ),
            (
                capstone_neon_bitwise_corpus(),
                "suite/MC/AArch64/neon-bitwise-instructions.s.cs",
            ),
            (
                capstone_neon_mla_mls_corpus(),
                "suite/MC/AArch64/neon-mla-mls-instructions.s.cs",
            ),
            (
                capstone_neon_add_sub_corpus(),
                "suite/MC/AArch64/neon-add-sub-instructions.s.cs",
            ),
            (
                capstone_neon_table_lookup_corpus(),
                "suite/MC/AArch64/neon-tbl.s.cs",
            ),
        ] {
            assert_eq!(corpus.schema, "glaurung-capstone-mc-v1");
            assert_eq!(corpus.upstream.project, "capstone");
            assert_eq!(corpus.upstream.version, "5.0.0");
            assert_eq!(corpus.upstream.crate_name, "capstone-sys 0.16.0");
            assert_eq!(corpus.upstream.path, expected_path);
            assert_eq!(corpus.upstream.licenses, ["BSD-3-Clause", "NCSA"]);
            for vector in corpus.vectors {
                let instruction = decoder
                    .disassemble_instruction(&va(0), &vector.bytes)
                    .unwrap_or_else(|error| panic!("{expected_path}:{}: {error}", vector.line));
                assert_eq!(instruction.mnemonic, vector.mnemonic);
                assert_eq!(instruction.operands.len(), vector.operands.len());
                for (actual, expected) in instruction.operands.iter().zip(vector.operands) {
                    match expected {
                        ExpectedOperand::RegisterList {
                            register_list,
                            vector_shape,
                        } => {
                            assert_eq!(actual.kind, OperandKind::RegisterList);
                            assert_eq!(actual.register_list.as_ref(), Some(&register_list));
                            assert_eq!(actual.vector_shape, Some(vector_shape));
                            assert_eq!(actual.size, vector_shape.total_bits().unwrap_or(0));
                        }
                        ExpectedOperand::Register {
                            register,
                            vector_shape,
                            vector_index,
                            ..
                        } => {
                            assert_eq!(actual.register.as_deref(), Some(register.as_str()));
                            assert_eq!(actual.vector_shape, vector_shape);
                            assert_eq!(actual.vector_index, vector_index);
                            if let Some(shape) = vector_shape {
                                assert_eq!(actual.size, shape.total_bits().unwrap_or(0));
                            }
                        }
                        ExpectedOperand::Immediate { immediate } => {
                            assert_eq!(actual.immediate, Some(immediate));
                        }
                        ExpectedOperand::Memory { .. } => {
                            panic!("register-only extension corpus unexpectedly contains memory")
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn scalar_pairwise_single_precision_preserves_source_shape() {
        let decoder = NativeAarch64Disassembler::new(Endianness::Little);
        let instruction = decoder
            .disassemble_instruction(&va(0), &0x7e30_d800_u32.to_le_bytes())
            .unwrap();
        assert_eq!(instruction.mnemonic, "faddp");
        assert_eq!(instruction.operands[0].register.as_deref(), Some("s0"));
        assert_eq!(instruction.operands[1].register.as_deref(), Some("v0"));
        assert_eq!(
            instruction.operands[1].vector_shape,
            Some(VectorShape {
                lanes: 2,
                element_bits: 32,
            })
        );
        assert_eq!(instruction.operands[1].size, 64);
    }

    #[test]
    fn conditional_select_aliases_match_capstone_canonicalization() {
        let native = NativeAarch64Disassembler::new(Endianness::Little);
        let capstone = CapstoneDisassembler::new(Architecture::ARM64, Endianness::Little).unwrap();
        for (word, expected_mnemonic, expected_operands) in [
            (0x1a9f_17e3_u32, "cset", 1),
            (0x1a85_d4a3_u32, "cinc", 2),
            (0x5a9f_03f4_u32, "csetm", 1),
            (0x5a85_d0a3_u32, "cinv", 2),
            (0x5a85_d4a3_u32, "cneg", 2),
        ] {
            let bytes = word.to_le_bytes();
            let ours = native.disassemble_instruction(&va(0), &bytes).unwrap();
            let reference = capstone.disassemble_instruction(&va(0), &bytes).unwrap();
            assert_eq!(ours.mnemonic, expected_mnemonic, "word {word:#010x}");
            assert_eq!(ours.mnemonic, reference.mnemonic, "word {word:#010x}");
            assert_eq!(ours.operands.len(), expected_operands, "word {word:#010x}");
            let mut normalized = ours.operands;
            for operand in &mut normalized {
                operand.size = 0;
                operand.access = Access::Read;
            }
            assert_eq!(normalized, reference.operands, "word {word:#010x}");
        }
    }

    #[test]
    fn extract_alias_matches_capstone_canonicalization() {
        let native = NativeAarch64Disassembler::new(Endianness::Little);
        let capstone = CapstoneDisassembler::new(Architecture::ARM64, Endianness::Little).unwrap();
        let word = 0x93c0_0000_u32 | (4 << 16) | (15 << 10) | (4 << 5) | 3;
        let bytes = word.to_le_bytes();
        let ours = native.disassemble_instruction(&va(0), &bytes).unwrap();
        let reference = capstone.disassemble_instruction(&va(0), &bytes).unwrap();
        assert_eq!(ours.mnemonic, "ror");
        assert_eq!(ours.operands.len(), 3);
        let mut normalized = ours.operands;
        for operand in &mut normalized {
            operand.size = 0;
            operand.access = Access::Read;
        }
        assert_eq!(ours.mnemonic, reference.mnemonic);
        assert_eq!(normalized, reference.operands);
    }

    #[test]
    fn vector_orr_alias_matches_capstone_canonicalization() {
        let native = NativeAarch64Disassembler::new(Endianness::Little);
        let capstone = CapstoneDisassembler::new(Architecture::ARM64, Endianness::Little).unwrap();
        let word = 0x4ea0_1c00_u32 | (30 << 16) | (30 << 5) | 31;
        let bytes = word.to_le_bytes();
        let ours = native.disassemble_instruction(&va(0), &bytes).unwrap();
        let reference = capstone.disassemble_instruction(&va(0), &bytes).unwrap();
        assert_eq!(ours.mnemonic, "mov");
        assert_eq!(ours.operands.len(), 2);
        let mut normalized = ours.operands;
        for operand in &mut normalized {
            operand.access = Access::Read;
        }
        assert_eq!(ours.mnemonic, reference.mnemonic);
        assert_eq!(normalized, reference.operands);
    }

    #[test]
    fn native_results_match_or_improve_current_capstone_adapter() {
        let native = NativeAarch64Disassembler::new(Endianness::Little);
        let capstone = CapstoneDisassembler::new(Architecture::ARM64, Endianness::Little).unwrap();
        let corpora = [
            capstone_native_slice_corpus(),
            capstone_gicv3_corpus(),
            capstone_trace_corpus(),
            capstone_neon_scalar_abs_corpus(),
            capstone_neon_scalar_neg_corpus(),
            capstone_neon_scalar_add_sub_corpus(),
            capstone_neon_scalar_shift_corpus(),
            capstone_neon_scalar_reduce_pairwise_corpus(),
            capstone_neon_scalar_saturating_add_sub_corpus(),
            capstone_neon_scalar_saturating_rounding_shift_corpus(),
            capstone_neon_scalar_saturating_shift_corpus(),
            capstone_neon_scalar_rounding_shift_corpus(),
            capstone_neon_scalar_compare_corpus(),
            capstone_neon_scalar_fp_compare_corpus(),
            capstone_neon_scalar_extract_narrow_corpus(),
            capstone_neon_scalar_recip_corpus(),
            capstone_neon_scalar_mul_corpus(),
            capstone_neon_scalar_by_element_mul_corpus(),
            capstone_neon_scalar_by_element_mla_corpus(),
            capstone_neon_scalar_by_element_saturating_mla_corpus(),
            capstone_neon_scalar_by_element_saturating_mul_corpus(),
            capstone_neon_scalar_dup_corpus(),
            capstone_neon_scalar_cvt_corpus(),
            capstone_neon_scalar_shift_immediate_corpus(),
            capstone_neon_extract_corpus(),
            capstone_neon_reciprocal_step_corpus(),
            capstone_neon_add_pairwise_corpus(),
            capstone_neon_rounding_halving_add_corpus(),
            capstone_neon_rounding_shift_corpus(),
            capstone_neon_saturating_shift_corpus(),
            capstone_neon_saturating_rounding_shift_corpus(),
            capstone_neon_shift_left_long_corpus(),
            capstone_neon_absolute_compare_corpus(),
            capstone_neon_crypto_corpus(),
            capstone_neon_bitwise_corpus(),
            capstone_neon_mla_mls_corpus(),
            capstone_neon_add_sub_corpus(),
            capstone_neon_table_lookup_corpus(),
        ];
        let capstone_vectors = corpora
            .iter()
            .flat_map(|corpus| corpus.vectors.iter().map(|vector| vector.bytes));
        let llvm_vectors = LLVM_TEST_BRANCH_VECTORS.iter().map(|vector| vector.0);
        for bytes in capstone_vectors.chain(llvm_vectors) {
            let address = va(0x1000);
            let ours = native.disassemble_instruction(&address, &bytes).unwrap();
            let reference = capstone.disassemble_instruction(&address, &bytes).unwrap();
            assert_eq!(ours.mnemonic, reference.mnemonic, "bytes {bytes:02x?}");
            let word = u32::from_le_bytes(bytes);
            if word_is_system_instruction(word) {
                // Capstone retains named alias operations but drops the CRn/
                // CRm fields from raw SYS/SYSL. Native retains them. Compare
                // the fields the adapter exposes in architectural order.
                let alias = if ours.mnemonic == "sysl" {
                    None
                } else {
                    aarch64_sysregs::lookup_alias(((word >> 5) & 0x7fff) as u16)
                };
                let mut normalized = if let Some((_, _, has_register)) = alias {
                    if has_register {
                        ours.operands.iter().skip(1).cloned().collect::<Vec<_>>()
                    } else {
                        ours.operands.clone()
                    }
                } else {
                    ours.operands
                        .iter()
                        .filter(|operand| {
                            !operand
                                .register
                                .as_deref()
                                .is_some_and(|name| name.starts_with('c'))
                        })
                        .cloned()
                        .collect::<Vec<_>>()
                };
                for operand in &mut normalized {
                    operand.size = 0;
                    operand.access = Access::Read;
                }
                assert_eq!(normalized, reference.operands, "bytes {bytes:02x?}");
            } else if word_is_system_register_move(word) || word_is_pstate_immediate(word) {
                // The textual Capstone fallback retains these operands but
                // cannot expose their widths or architectural access. For the
                // encoded general-register field it also spells register 29/30
                // as x29/x30, while native decoding consistently uses fp/lr.
                let mut normalized = ours.operands.clone();
                for operand in &mut normalized {
                    operand.size = 0;
                    operand.access = Access::Read;
                    if word_is_system_register_move(word) {
                        match operand.register.as_deref() {
                            Some("fp") => {
                                operand.register = Some("x29".to_string());
                                operand.text = "x29".to_string();
                            }
                            Some("lr") => {
                                operand.register = Some("x30".to_string());
                                operand.text = "x30".to_string();
                            }
                            _ => {}
                        }
                    }
                }
                assert_eq!(normalized, reference.operands, "bytes {bytes:02x?}");
            } else if word_is_load_store_pair(word) {
                // The current adapter drops pair register/memory widths and
                // reports every operand as Read. Native decoding preserves
                // the two destinations and store-memory access.
                let mut normalized = ours.operands.clone();
                for operand in &mut normalized {
                    operand.size = 0;
                    operand.access = Access::Read;
                }
                assert_eq!(normalized, reference.operands, "bytes {bytes:02x?}");
            } else if word_is_load_literal(word) {
                let mut normalized = ours.operands.clone();
                normalized[0].size = 0;
                normalized[0].access = Access::Read;
                assert_eq!(normalized, reference.operands, "bytes {bytes:02x?}");
            } else if word_is_exclusive_or_ordered_load_store(word) {
                let mut normalized = ours.operands.clone();
                for operand in &mut normalized {
                    operand.size = 0;
                    operand.access = Access::Read;
                }
                assert_eq!(normalized, reference.operands, "bytes {bytes:02x?}");
            } else if word_is_prefetch(word) {
                let mut normalized = ours.operands.iter().skip(1).cloned().collect::<Vec<_>>();
                if let Some(memory) = normalized.first_mut() {
                    memory.text = Operand::memory(
                        0,
                        Access::Read,
                        memory.displacement,
                        memory.base.clone(),
                        memory.index.clone(),
                        memory.scale,
                    )
                    .text;
                }
                assert_eq!(normalized, reference.operands, "bytes {bytes:02x?}");
            } else if word_is_scalar_register_offset(word) || word_is_simd_register_offset(word) {
                let mut normalized = ours.operands.clone();
                normalized[0].size = 0;
                normalized[0].access = Access::Read;
                normalized[1].size = 0;
                normalized[1].access = Access::Read;
                normalized[1].text = Operand::memory(
                    0,
                    Access::Read,
                    normalized[1].displacement,
                    normalized[1].base.clone(),
                    normalized[1].index.clone(),
                    normalized[1].scale,
                )
                .text;
                assert_eq!(normalized, reference.operands, "bytes {bytes:02x?}");
            } else if word & 0x3f00_0000 == 0x3900_0000
                || word_is_simd_unsigned(word)
                || word_is_scalar_unscaled_or_writeback(word)
                || word_is_simd_unscaled_or_writeback(word)
            {
                // The adapter discards scalar register/memory widths, marks
                // destinations as reads, and cannot represent store access.
                // The native form keeps all three while matching every other
                // structured field.
                let mut normalized = ours.operands.clone();
                normalized[0].size = 0;
                normalized[0].access = Access::Read;
                normalized[1].size = 0;
                normalized[1].access = Access::Read;
                assert_eq!(normalized, reference.operands, "bytes {bytes:02x?}");
            } else if word_is_logical_immediate(word) {
                let mut normalized = ours.operands.clone();
                for operand in &mut normalized {
                    operand.size = 0;
                    operand.access = Access::Read;
                }
                assert_eq!(normalized, reference.operands, "bytes {bytes:02x?}");
            } else if word_is_move_wide(word) {
                let mut normalized = ours.operands.clone();
                normalized[0].size = 0;
                normalized[0].access = Access::Read;
                normalized[1].size = 0;
                let shift = ((word >> 21) & 0x3) * 16;
                if shift != 0 {
                    let raw_immediate =
                        normalized[1].immediate.expect("move-wide immediate") >> shift;
                    normalized[1] = Operand::immediate(raw_immediate, 0);
                }
                assert_eq!(normalized, reference.operands, "bytes {bytes:02x?}");
            } else if word_is_logical_shifted_register(word)
                || word_is_add_sub_extended_register(word)
                || word_is_add_sub_shifted_register(word)
                || word_is_add_sub_with_carry(word)
                || word_is_conditional_select(word)
                || word_is_conditional_compare(word)
                || word_is_multiply(word)
                || word_is_bitfield(word)
                || word_is_extract(word)
                || word_is_data_processing_one_source(word)
                || word_is_data_processing_two_source(word)
            {
                // Capstone detail omits the register extension/shift and all
                // scalar widths/access. Native operands preserve them in the
                // register's structured identity plus lossless display text.
                let mut normalized = ours.operands.clone();
                for operand in &mut normalized {
                    operand.size = 0;
                    operand.access = Access::Read;
                    if let Some(register) = &operand.register {
                        operand.text.clone_from(register);
                    }
                }
                assert_eq!(normalized, reference.operands, "bytes {bytes:02x?}");
            } else if word_is_scalar_fp(word)
                || word_is_advanced_simd_scalar(word)
                || word_is_advanced_simd_vector(word)
                || word_is_advanced_simd_crypto(word)
                || word_is_advanced_simd_bitwise(word)
                || word_is_advanced_simd_table_lookup(word)
            {
                // Capstone's AArch64 detail adapter reports scalar FP
                // registers as size-zero reads. Native decoding preserves
                // destination access; normalize only that missing metadata.
                // capstone-rs 0.12 also exposes the compare-with-zero literal
                // twice through the legacy ARM64 operand union, despite the
                // disassembly text containing one `#0` operand.
                // Register lists are first-class native operands, while the
                // legacy adapter flattens their members into register operands.
                let mut normalized = ours
                    .operands
                    .iter()
                    .flat_map(|operand| {
                        if let Some(registers) = &operand.register_list {
                            registers
                                .iter()
                                .map(|register| {
                                    let mut flattened = Operand::register(
                                        register.clone(),
                                        operand.size,
                                        operand.access,
                                    );
                                    flattened.vector_shape = operand.vector_shape;
                                    flattened
                                })
                                .collect::<Vec<_>>()
                        } else {
                            vec![operand.clone()]
                        }
                    })
                    .collect::<Vec<_>>();
                for operand in &mut normalized {
                    if operand.register.is_some() && operand.vector_shape.is_none() {
                        operand.size = 0;
                    }
                    operand.access = Access::Read;
                }
                let mut reference_operands = reference.operands.clone();
                if matches!(word & 0xdf3f_fc00, 0x5e20_9800 | 0x5e20_8800 | 0x5e20_a800)
                    && reference_operands.len() == normalized.len() + 1
                    && reference_operands.last() == reference_operands.get(normalized.len() - 1)
                {
                    reference_operands.pop();
                }
                assert_eq!(normalized, reference_operands, "bytes {bytes:02x?}");
            } else if matches!(
                ours.mnemonic.as_str(),
                "adr" | "adrp" | "add" | "adds" | "sub" | "subs" | "cmp" | "cmn" | "mov"
            ) {
                // The legacy adapter hard-codes every AArch64 register operand
                // to Read and drops the LSL #12 modifier on immediate
                // arithmetic. Preserve every other adapter field exactly, but
                // keep the architectural access and effective value natively.
                let mut normalized = ours.operands.clone();
                if matches!(
                    ours.mnemonic.as_str(),
                    "adr" | "adrp" | "add" | "adds" | "sub" | "subs" | "mov"
                ) {
                    assert_eq!(ours.operands[0].access, Access::Write);
                    assert_eq!(reference.operands[0].access, Access::Read);
                    normalized[0].access = Access::Read;
                }
                if word & 0x1f00_0000 == 0x1100_0000 && word & 0x0040_0000 != 0 {
                    let raw_immediate = normalized
                        .last()
                        .and_then(|operand| operand.immediate)
                        .expect("add/sub immediate operand")
                        >> 12;
                    *normalized.last_mut().expect("add/sub immediate operand") =
                        Operand::immediate(raw_immediate, 0);
                }
                assert_eq!(normalized, reference.operands, "bytes {bytes:02x?}");
            } else {
                assert_eq!(ours.operands, reference.operands, "bytes {bytes:02x?}");
            }
            assert_eq!(ours.length, reference.length, "bytes {bytes:02x?}");
        }
    }

    #[test]
    fn unsupported_family_is_distinct_from_malformed_input() {
        let decoder = NativeAarch64Disassembler::new(Endianness::Little);
        assert_eq!(
            // UZP1 remains in a later vector-permutation family.
            decoder.disassemble_instruction(&va(0), &[0x20, 0x18, 0x02, 0x0e]),
            Err(DisassemblerError::UnsupportedInstruction())
        );
        assert_eq!(
            decoder.disassemble_instruction(&va(0), &[0, 0, 0]),
            Err(DisassemblerError::InsufficientBytes())
        );
    }

    #[test]
    fn invalid_encodings_inside_native_families_fail_closed() {
        let decoder = NativeAarch64Disassembler::new(Endianness::Little);
        for word in [
            0x3280_0000_u32, // reserved move-wide opc
            0x52c0_0000_u32, // 32-bit move-wide with hw >= 2
            0xf980_001f_u32, // reserved named prefetch operation
            0x1240_0000_u32, // 32-bit logical immediate with N set
            0x9240_fc00_u32, // logical immediate with an all-ones element
            0x0b20_1400_u32, // add extended-register with imm3 > 4
            0x6900_abe9_u32, // signed-word pair store is reserved
            0xec00_0000_u32, // SIMD pair with reserved opc
            0x0bc0_0000_u32, // add/sub shifted-register with reserved shift kind
            0x0b00_8000_u32, // 32-bit shifted-register with shift >= 32
            0x0a00_8000_u32, // 32-bit logical-register with shift >= 32
            0x9b60_0000_u32, // reserved data-processing three-source opcode
            0x7300_0000_u32, // reserved bitfield operation
            0x1340_0000_u32, // 32-bit bitfield with N set
            0x1320_0000_u32, // 32-bit bitfield with immr >= 32
            0x3380_0000_u32, // extract with reserved operation
            0x1380_8000_u32, // 32-bit extract with lsb >= 32
            0x5ac0_1800_u32, // reserved one-source operation
            0xf880_001f_u32, // reserved named unscaled prefetch operation
            0x3820_0800_u32, // register-offset load/store with reserved option
            0xf8a0_0800_u32, // register-offset prefetch with reserved option
            0x7d80_0000_u32, // reserved SIMD unsigned load/store size/opc pair
            0x7c80_0000_u32, // reserved SIMD unscaled load/store size/opc pair
            0x3c20_0800_u32, // SIMD register-offset load/store with reserved option
            0x7ca0_6800_u32, // reserved SIMD register-offset size/opc pair
            0x1ea0_4000_u32, // scalar FP one-source with reserved type
            0x1e26_c000_u32, // reserved scalar FP one-source operation
            0x1ea0_0800_u32, // scalar FP two-source with reserved type
            0x1e20_9800_u32, // reserved scalar FP two-source operation
            0x1f80_0000_u32, // scalar FP three-source with reserved type
            0x1ea0_2000_u32, // scalar FP compare with reserved type
            0x1ea0_0400_u32, // scalar FP conditional compare with reserved type
            0x1ea0_0c00_u32, // scalar FP conditional select with reserved type
            0x1e22_4000_u32, // FCVT with identical source/destination type
            0x1e82_0000_u32, // fixed conversion with reserved FP type
            0x1e02_0000_u32, // 32-bit fixed conversion with scale below 32
            0x1ea0_0000_u32, // integer conversion with reserved FP type
            0x1e2e_0000_u32, // reserved scalar FP/integer conversion operation
            0x1ea0_1000_u32, // scalar FP immediate with reserved type
            0x9e26_0000_u32, // FMOV integer/FP transfer with mismatched widths
            0x5ea0_b800_u32, // scalar integer ABS with non-64-bit element size
            0x7e34_d400_u32, // scalar FABD with byte element size
            0x5ea0_8400_u32, // scalar integer ADD with non-64-bit element size
            0x5ea0_4400_u32, // scalar variable shift with non-64-bit element size
            0x5ea0_5400_u32, // scalar rounding shift with non-64-bit element size
            0x5ea0_8c00_u32, // scalar integer compare with non-64-bit element size
            0x7ee0_a800_u32, // reserved unsigned form of scalar CMLT-zero class
            0x5ea0_e400_u32, // reserved non-U scalar FP greater-than register class
            0x5ea0_ec00_u32, // reserved non-U form of scalar FP absolute compare class
            0x7ea0_e800_u32, // reserved unsigned form of scalar FP CMLT-zero class
            0x5e21_2800_u32, // reserved non-U scalar SQXTUN class
            0x7ee1_2800_u32, // scalar SQXTUN with reserved destination width
            0x7ee1_4800_u32, // scalar UQXTN with reserved destination width
            0x7e20_fc00_u32, // reserved U form of scalar FRECPS class
            0x7ea0_fc00_u32, // reserved U form of scalar FRSQRTS class
            0x7e21_f800_u32, // reserved U form of scalar FRECPX class
            0x5e20_b400_u32, // scalar SQDMULH with reserved byte element size
            0x5ee0_b400_u32, // scalar SQDMULH with reserved double element size
            0x5ea0_dc00_u32, // scalar FMULX with reserved size selector
            0x7e60_9000_u32, // reserved U form of scalar SQDMLAL class
            0x5e20_d000_u32, // scalar SQDMULL with reserved byte source
            0x5f00_9000_u32, // scalar by-element FMUL with reserved size selector
            0x5fe0_9000_u32, // scalar by-element FMUL D form with reserved L bit
            0x7f00_1000_u32, // reserved U form of scalar by-element FMLA class
            0x5fe0_1000_u32, // scalar by-element FMLA D form with reserved L bit
            0x7f40_3000_u32, // reserved U form of scalar by-element SQDMLAL class
            0x5f00_3000_u32, // scalar by-element SQDMLAL with reserved byte source
            0x5fc0_3000_u32, // scalar by-element SQDMLAL with reserved double source
            0x7f40_b000_u32, // reserved U form of scalar by-element SQDMULL class
            0x5f00_c000_u32, // scalar by-element SQDMULH with reserved byte source
            0x5fc0_d000_u32, // scalar by-element SQRDMULH with reserved double source
            0x5e00_0400_u32, // scalar copy with a zero imm5 element selector
            0x5e10_0400_u32, // scalar copy with a reserved 128-bit element selector
            0x5f00_e400_u32, // scalar fixed conversion with an empty immediate prefix
            0x5f10_fc00_u32, // scalar fixed conversion with a sub-32-bit immediate prefix
            0x5f00_0400_u32, // scalar immediate shift with an empty immh prefix
            0x5f40_4400_u32, // reserved signed form of scalar SRI
            0x5f40_6400_u32, // reserved signed form of scalar SQSHLU
            0x5f40_9400_u32, // narrowing shift with a reserved 64-bit destination size
            0x2e02_4020_u32, // 64-bit vector EXT with an out-of-range byte index
            0x0e60_fc00_u32, // 64-bit vector reciprocal step with double elements
            0x0ee0_bc00_u32, // 64-bit integer pairwise add with double elements
            0x2e60_d400_u32, // 64-bit floating pairwise add with double elements
            0x0ee0_1400_u32, // signed rounding-halving add with reserved double elements
            0x0ee0_8400_u32, // 64-bit integer ADD with a reserved single double lane
            0x0ee0_9400_u32, // 64-bit integer MLA with reserved double elements
            0x0ee0_4c00_u32, // 64-bit saturating shift with a reserved single double lane
            0x0ee0_5400_u32, // 64-bit rounding shift with a reserved single double lane
            0x0ee0_5c00_u32, // 64-bit saturating rounding shift with a reserved single double lane
            0x0f00_a400_u32, // shift-left-long with an empty immediate prefix
            0x0f40_a400_u32, // shift-left-long with a reserved 64-bit source size
            0x2e60_ec00_u32, // 64-bit absolute compare with double elements
            0x0e60_cc00_u32, // 64-bit floating MLA with a reserved single double lane
            0x0e60_d400_u32, // 64-bit floating ADD with a reserved single double lane
            0x5eb1_b800_u32, // scalar integer ADDP with non-64-bit element size
            0x7eb0_d800_u32, // scalar floating ADDP with reserved element size
            0xd800_0000_u32, // reserved scalar literal-load operation
            0x0880_0000_u32, // ordered load/store without acquire/release bit
            0x0820_0000_u32, // byte-sized exclusive pair
            0x0840_0000_u32, // exclusive load with non-ZR status register
            0x0800_0000_u32, // exclusive single with non-ZR second register
        ] {
            assert_eq!(
                decoder.disassemble_instruction(&va(0), &word.to_le_bytes()),
                Err(DisassemblerError::InvalidInstruction()),
                "word {word:#010x}"
            );
        }
    }

    #[test]
    fn big_endian_uses_the_same_native_dispatch() {
        let decoder = NativeAarch64Disassembler::new(Endianness::Big);
        let instruction = decoder
            .disassemble_instruction(&va(0x1000), &0x9100_4000_u32.to_be_bytes())
            .unwrap();
        assert_eq!(instruction.mnemonic, "add");
        assert_eq!(instruction.operands[0].register.as_deref(), Some("x0"));
        assert_eq!(instruction.operands[1].register.as_deref(), Some("x0"));
        assert_eq!(instruction.operands[2].immediate, Some(16));
    }
}
