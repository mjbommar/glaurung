//! Linux kernel-driver IOCTL attack-surface mapping (the Linux analogue of the
//! Windows WDM/WDF work in [`crate::analysis::ioctl_surface`]).
//!
//! A Linux character/misc driver routes user `ioctl(fd, cmd, arg)` calls through
//! a `struct file_operations` whose `.unlocked_ioctl` (and `.compat_ioctl`) field
//! points at a handler that switches on `cmd`. This module statically recovers,
//! from a `.ko` (an `ET_REL` object) or a vmlinux-style image:
//!
//! 1. every `*_fops` `file_operations` instance,
//! 2. the `unlocked_ioctl` / `compat_ioctl` handler each wires up (resolved via
//!    the relocation on that struct slot), and
//! 3. the set of `cmd` values the handler compares against — decoded through the
//!    `_IOC(dir, type, nr, size)` scheme into the reachable command surface.
//!
//! That command surface is exactly the input the SELinux reachability check
//! needs ("can `untrusted_app` issue this ioctl on this device?").
//!
//! The command scanner currently targets AArch64 (the Android device tier).

use object::read::{Object, ObjectSection, ObjectSymbol};
use object::{RelocationTarget, SymbolKind};

/// Direction bits of an `_IOC`-encoded command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocDir {
    None,
    Write,
    Read,
    ReadWrite,
}

impl IocDir {
    fn from_bits(bits: u32) -> Self {
        match bits & 0b11 {
            0 => IocDir::None,
            1 => IocDir::Write,
            2 => IocDir::Read,
            _ => IocDir::ReadWrite,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            IocDir::None => "none",
            IocDir::Write => "write",
            IocDir::Read => "read",
            IocDir::ReadWrite => "readwrite",
        }
    }
}

/// A decoded `_IOC` command code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IocDecoded {
    pub raw: u32,
    pub dir: IocDir,
    /// The `type`/magic byte (e.g. driver's `'A'` or `0xB7`).
    pub type_: u8,
    /// The command ordinal within the type.
    pub nr: u8,
    /// The declared argument size in bytes (14-bit field).
    pub size: u16,
}

/// Decode a 32-bit `_IOC` command (standard Linux asm-generic layout:
/// `dir[31:30] | size[29:16] | type[15:8] | nr[7:0]`).
pub fn decode_ioc(raw: u32) -> IocDecoded {
    IocDecoded {
        raw,
        dir: IocDir::from_bits(raw >> 30),
        size: ((raw >> 16) & 0x3fff) as u16,
        type_: ((raw >> 8) & 0xff) as u8,
        nr: (raw & 0xff) as u8,
    }
}

/// Whether a raw 32-bit value plausibly is an `_IOC` command rather than an
/// arbitrary constant: a non-zero type byte and a non-huge size keep the false
/// positive rate down when scanning a handler's compare immediates.
pub fn is_ioctl_shaped(raw: u32) -> bool {
    let type_ = (raw >> 8) & 0xff;
    let size = (raw >> 16) & 0x3fff;
    type_ != 0 && size <= 0x2000
}

/// A resolved ioctl handler reachable through a `file_operations` slot.
#[derive(Debug, Clone)]
pub struct IoctlHandler {
    /// Name of the `file_operations` object (e.g. `foo_fops`).
    pub fops_symbol: String,
    /// Byte offset of the handled slot within the `file_operations` struct.
    pub slot_offset: u64,
    /// `true` for `compat_ioctl`, `false` for `unlocked_ioctl`.
    pub is_compat: bool,
    /// Name of the handler function the slot points to.
    pub handler_symbol: String,
    /// Address (section-relative for `ET_REL`) of the handler.
    pub handler_va: u64,
    /// Decoded command surface the handler compares against.
    pub commands: Vec<IocDecoded>,
}

/// The recovered ioctl attack surface of a driver object.
#[derive(Debug, Clone, Default)]
pub struct LinuxIoctlSurface {
    pub handlers: Vec<IoctlHandler>,
}

impl LinuxIoctlSurface {
    /// All distinct decoded commands across every handler.
    pub fn all_commands(&self) -> Vec<IocDecoded> {
        let mut out = Vec::new();
        for h in &self.handlers {
            for c in &h.commands {
                if !out.iter().any(|d: &IocDecoded| d.raw == c.raw) {
                    out.push(*c);
                }
            }
        }
        out
    }
}

/// Map the IOCTL surface of a Linux driver object (`.ko` / vmlinux).
///
/// Returns an empty surface (rather than erroring) for non-ELF input or a driver
/// with no `file_operations` ioctl wiring, so it is safe to call speculatively.
pub fn map_linux_ioctl_surface(data: &[u8]) -> LinuxIoctlSurface {
    map_inner(data).unwrap_or_default()
}

fn map_inner(data: &[u8]) -> Option<LinuxIoctlSurface> {
    let obj = object::read::File::parse(data).ok()?;
    let is_aarch64 = obj.architecture() == object::Architecture::Aarch64;

    // Index symbols by index for relocation-target resolution, and collect the
    // file_operations objects.
    let mut surface = LinuxIoctlSurface::default();

    for sym in obj.symbols() {
        let name = sym.name().unwrap_or("");
        // A `file_operations` instance is a data object conventionally named
        // `*_fops`. (Also accept `*fops` to be forgiving.)
        let looks_fops = sym.kind() == SymbolKind::Data
            && (name.ends_with("_fops") || name.ends_with("fops"));
        if !looks_fops {
            continue;
        }
        let Some(sec_index) = sym.section_index() else {
            continue;
        };
        let Ok(section) = obj.section_by_index(sec_index) else {
            continue;
        };
        let fops_addr = sym.address();
        let fops_size = sym.size();
        if fops_size == 0 {
            continue;
        }

        // Walk the relocations of the fops section that fall inside this struct.
        for (rel_off, reloc) in section.relocations() {
            if rel_off < fops_addr || rel_off >= fops_addr + fops_size {
                continue;
            }
            let RelocationTarget::Symbol(target_idx) = reloc.target() else {
                continue;
            };
            let Ok(target) = obj.symbol_by_index(target_idx) else {
                continue;
            };
            let target_name = target.name().unwrap_or("").to_string();
            // Identify the ioctl slots by the handler's name. Real .ko files
            // retain module-local symbols, so `*ioctl*` is a reliable tag.
            let lname = target_name.to_ascii_lowercase();
            if !lname.contains("ioctl") {
                continue;
            }
            let is_compat = lname.contains("compat");

            let handler_va = target.address();
            let commands = if is_aarch64 {
                handler_bytes(&obj, &target)
                    .map(|code| {
                        scan_aarch64_ioctl_cmds(&code)
                            .into_iter()
                            .filter(|&c| is_ioctl_shaped(c))
                            .map(decode_ioc)
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            surface.handlers.push(IoctlHandler {
                fops_symbol: name.to_string(),
                slot_offset: rel_off - fops_addr,
                is_compat,
                handler_symbol: target_name,
                handler_va,
                commands,
            });
        }
    }

    // Stable ordering: by fops name then slot.
    surface
        .handlers
        .sort_by(|a, b| a.fops_symbol.cmp(&b.fops_symbol).then(a.slot_offset.cmp(&b.slot_offset)));
    Some(surface)
}

/// Extract the raw bytes of a function symbol from its section.
fn handler_bytes<'a>(
    obj: &'a object::read::File<'a>,
    sym: &object::read::Symbol<'a, 'a>,
) -> Option<Vec<u8>> {
    let sec = obj.section_by_index(sym.section_index()?).ok()?;
    let data = sec.data().ok()?;
    let start = (sym.address() - sec.address()) as usize;
    let size = sym.size() as usize;
    let end = if size == 0 {
        data.len()
    } else {
        (start + size).min(data.len())
    };
    data.get(start..end).map(|s| s.to_vec())
}

/// Scan an AArch64 ioctl handler for the `cmd` values it compares against.
///
/// The `cmd` argument arrives in `w1` (AAPCS64 second integer parameter). The
/// scanner tracks:
/// * wide-immediate construction (`MOVZ`/`MOVN` + `MOVK`) per register, and
/// * which registers currently alias `cmd` (via `MOV Rd, Rn`),
///
/// and records the immediate whenever a `CMP`/`SUBS` puts the cmd register up
/// against a register holding a reconstructed constant (or an immediate form).
fn push_unique(found: &mut Vec<u32>, v: u64) {
    let v32 = v as u32;
    if !found.contains(&v32) {
        found.push(v32);
    }
}

pub fn scan_aarch64_ioctl_cmds(code: &[u8]) -> Vec<u32> {
    const CMD_REG: u8 = 1; // w1
    let mut reg_val: [Option<u64>; 32] = [None; 32];
    let mut is_cmd: [bool; 32] = [false; 32];
    is_cmd[CMD_REG as usize] = true;

    let mut found: Vec<u32> = Vec::new();

    for chunk in code.chunks_exact(4) {
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let rd = (w & 0x1f) as usize;

        // MOVZ / MOVN / MOVK: bits 28:23 == 0b100101.
        if (w >> 23) & 0x3f == 0x25 {
            let opc = (w >> 29) & 0x3;
            let hw = (w >> 21) & 0x3;
            let shift = hw * 16;
            let imm16 = ((w >> 5) & 0xffff) as u64;
            match opc {
                0b10 => {
                    // MOVZ: zero then set the slice.
                    reg_val[rd] = Some(imm16 << shift);
                }
                0b00 => {
                    // MOVN: bitwise-NOT of the shifted immediate.
                    reg_val[rd] = Some(!(imm16 << shift));
                }
                0b11 => {
                    // MOVK: keep other bits, replace the 16-bit slice.
                    let prev = reg_val[rd].unwrap_or(0);
                    reg_val[rd] = Some((prev & !(0xffffu64 << shift)) | (imm16 << shift));
                }
                _ => {}
            }
            // A move-wide redefines Rd, so it no longer aliases cmd.
            is_cmd[rd] = false;
            continue;
        }

        // ORR shifted-register (`MOV Rd, Rm` alias): bits 30:24 == 0b0101010.
        if (w >> 24) & 0x7f == 0x2a {
            let rm = ((w >> 16) & 0x1f) as usize;
            let rn = ((w >> 5) & 0x1f) as usize;
            let imm6 = (w >> 10) & 0x3f;
            if rn == 31 && imm6 == 0 {
                // mov Rd, Rm
                is_cmd[rd] = is_cmd[rm];
                reg_val[rd] = reg_val[rm];
                continue;
            }
        }

        // SUBS immediate (`CMP Rn, #imm`): bit30=1, bit29=1, bits28:24==0b10001.
        if (w >> 30) & 1 == 1 && (w >> 29) & 1 == 1 && (w >> 24) & 0x1f == 0x11 {
            if rd == 31 {
                let rn = ((w >> 5) & 0x1f) as usize;
                if is_cmd[rn] {
                    let sh = (w >> 22) & 1;
                    let imm12 = ((w >> 10) & 0xfff) as u64;
                    let imm = if sh == 1 { imm12 << 12 } else { imm12 };
                    push_unique(&mut found, imm);
                }
            }
            continue;
        }

        // SUBS shifted-register (`CMP Rn, Rm`): bit30=1, bit29=1, bits28:24==0b01011.
        if (w >> 30) & 1 == 1 && (w >> 29) & 1 == 1 && (w >> 24) & 0x1f == 0x0b {
            if rd == 31 {
                let rn = ((w >> 5) & 0x1f) as usize;
                let rm = ((w >> 16) & 0x1f) as usize;
                // Whichever side is the cmd register, read the constant on the
                // other side (if we reconstructed one).
                if is_cmd[rn] {
                    if let Some(v) = reg_val[rm] {
                        push_unique(&mut found, v);
                    }
                } else if is_cmd[rm] {
                    if let Some(v) = reg_val[rn] {
                        push_unique(&mut found, v);
                    }
                }
            }
            continue;
        }
    }

    found
}

#[cfg(test)]
mod tests;
