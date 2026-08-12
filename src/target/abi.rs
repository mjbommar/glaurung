//! Calling-convention identities owned by the target layer.

/// Which calling convention a function obeys.
///
/// Register effects and storage layouts are currently exposed through
/// [`crate::ir::abi`]. Moving the identity here makes it a target fact while
/// allowing those consumers to migrate incrementally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum CallConv {
    /// System V AMD64 ABI.
    SysVAmd64,
    /// Microsoft x64 ABI.
    Win64,
    /// 32-bit x86 cdecl: stack arguments, EAX return value.
    Cdecl32,
    /// AArch64 procedure-call standard.
    Aarch64,
    /// ARM32 base/soft-float AAPCS.
    Arm,
    /// ARM32 AAPCS-VFP hard-float variant.
    ArmHardFloat,
}
