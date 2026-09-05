//! Architecture-qualified register roles.

use super::TargetId;

/// Register filled by a 32-bit x86 PIC PC-thunk body.
///
/// GCC emits `mov reg, [esp]; ret` helpers because i386 has no PC-relative
/// addressing mode. Match the bytes rather than a symbol so stripped binaries
/// retain the same machine fact. Writing `esp` is deliberately rejected.
pub fn x86_pc_thunk_register(body: &[u8]) -> Option<&'static str> {
    let [0x8b, modrm, 0x24, 0xc3, ..] = body else {
        return None;
    };
    if modrm & 0xc7 != 0x04 {
        return None;
    }
    match (modrm >> 3) & 7 {
        0 => Some("eax"),
        1 => Some("ecx"),
        2 => Some("edx"),
        3 => Some("ebx"),
        4 => None,
        5 => Some("ebp"),
        6 => Some("esi"),
        _ => Some("edi"),
    }
}

/// Register spellings that implement architectural roles for one target.
///
/// Lists include accepted aliases in canonical-first order. They are target
/// qualified because names such as `sp` are ambiguous across architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterRoles {
    stack_pointer: &'static [&'static str],
    frame_pointer: &'static [&'static str],
    link_register: &'static [&'static str],
    program_counter: &'static [&'static str],
}

impl RegisterRoles {
    pub(super) const fn for_target(target: TargetId) -> Self {
        match target {
            TargetId::X86_32 | TargetId::X86_64 => Self {
                stack_pointer: &["rsp", "esp"],
                frame_pointer: &["rbp", "ebp"],
                link_register: &[],
                program_counter: &["rip", "eip"],
            },
            TargetId::AArch64 => Self {
                stack_pointer: &["sp"],
                frame_pointer: &["x29", "fp"],
                link_register: &["x30", "lr"],
                program_counter: &["pc"],
            },
            TargetId::Arm32 => Self {
                stack_pointer: &["sp", "r13"],
                frame_pointer: &["r11", "r7", "fp"],
                link_register: &["lr", "r14"],
                program_counter: &["pc", "r15"],
            },
            TargetId::Unsupported(_) => Self {
                stack_pointer: &[],
                frame_pointer: &[],
                link_register: &[],
                program_counter: &[],
            },
        }
    }

    /// Stack-pointer spellings in canonical-first order.
    pub fn stack_pointer(self) -> &'static [&'static str] {
        self.stack_pointer
    }

    /// Frame-pointer spellings in canonical-first order.
    pub fn frame_pointer(self) -> &'static [&'static str] {
        self.frame_pointer
    }

    /// Link-register spellings in canonical-first order.
    pub fn link_register(self) -> &'static [&'static str] {
        self.link_register
    }

    /// Program-counter spellings in canonical-first order.
    pub fn program_counter(self) -> &'static [&'static str] {
        self.program_counter
    }

    /// Whether `name` is a stack-pointer spelling for this target.
    pub fn is_stack_pointer(self, name: &str) -> bool {
        self.stack_pointer.contains(&name)
    }

    /// Whether `name` is a frame-pointer spelling for this target.
    pub fn is_frame_pointer(self, name: &str) -> bool {
        self.frame_pointer.contains(&name)
    }
}
