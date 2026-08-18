//! The convention-agnostic view of "which register holds the result".
//!
//! [`super::return_registers`], [`super::integer_return_registers`] and
//! [`super::float_return_registers`] answer a PER-CONVENTION question: given
//! `CallConv::SysVAmd64`, what does the ABI use? Three passes cannot ask it
//! that way. [`crate::ir::direct_output`] projects a body-written result
//! register onto a bare machine `Return { value: None }`, and its consumers
//! `crate::ir::ast::prepare`, `crate::ir::ast::lower_region` and
//! `crate::ir::ast::return_folds` have no `CallConv` in scope at all — they run
//! on an AST whose registers may already have been rewritten to the canonical
//! role name `ret` by `crate::ir::naming::apply_role_names`, at which point the
//! convention is no longer a discriminator anyway. So they match a FLAT list of
//! names, and this module owns it.
//!
//! # Why the flat list is not a union of the per-convention tables
//!
//! The two tiers below have DIFFERENT precedence, so collapsing them into one
//! table would change what a body writing both banks returns:
//!
//! * [`PROJECTED_RESULT_REGISTERS`] is matched first-writer-wins, in body
//!   order, by `direct_output::find_written_return_reg`.
//! * [`FALLBACK_RESULT_REGISTERS`] is consulted ONLY when the first tier
//!   matched nothing anywhere in the body. `xmm0` is also SysV's first float
//!   ARGUMENT register and the ordinary float scratch register, so an
//!   unconditional first-writer-wins match would return the function's own
//!   input. That is the same precedence [`super::return_registers`] documents
//!   for its own alias ORDER — integer names first, because a function writing
//!   both returns through the integer bank and used the vector bank on the way.
//!
//! Both tiers match UNVERSIONED names only. A versioned write is some interior
//! value of the register, and on the `-O0` float shape there is always one: the
//! body reloads its spilled argument into `xmm0#1` before computing the result
//! into the register's exit definition, so matching the SSA base would take the
//! reloaded argument. [`is_projected_result_storage`] is the deliberate
//! exception — see its own documentation.
//!
//! # The census this module exists to keep honest
//!
//! Until 2026-08-18 the first tier lived in `direct_output` as a private
//! `RETURN_REGS`, and nothing compared it to the ABI tables. ARM32's hard-float
//! `s0`/`d0` were in it and x86-64's `xmm0` was in neither list, so a
//! float-returning x86-64 function's recovered result had nothing for a bare
//! `ret` to attach to: `float negate(float v) { return -v; }` computed the
//! right value into `xmm0` and rendered `return 0;`. Eleven fixture cells, and
//! the reason it survived for months is that the two lists were in different
//! files and no test put them side by side.
//!
//! [`UNPROJECTED_RESULT_REGISTERS`] is that side-by-side, made mandatory: the
//! test at the foot of this file walks EVERY `CallConv` and every name in its
//! three ABI result tables, and fails unless each one is in a tier or is listed
//! there with a written reason. A new convention, or a new spelling added to
//! `float_return_registers`, cannot be a silent hole again.

/// Result storage projected onto a bare `ret` at first-write precedence.
///
/// Every name in [`super::integer_return_registers`] for every convention is
/// here — that invariant is asserted, not assumed. `s0`/`d0` are here too, and
/// they are the only FLOAT names at this tier; see
/// [`UNPROJECTED_RESULT_REGISTERS`] for why their x86-64 and i386 counterparts
/// are not, and for the asymmetry that remains.
pub const PROJECTED_RESULT_REGISTERS: &[&str] = &[
    "rax", "eax", "ax", "al", // x86 / x86-64 integer
    "x0", "w0", // AAPCS64 integer
    "r0", // ARM32 AAPCS integer
    "s0", "d0",  // ARM32 AAPCS hard-float result; also AAPCS64's scalar float views
    "ret", // canonical role name after `apply_role_names`
];

/// Result storage projected ONLY when the first tier matched nothing.
///
/// One entry, and the tier exists for the reason in the module documentation:
/// `xmm0` is result storage, first float argument register, and float scratch,
/// all three, so it may only be believed in the absence of any integer result
/// write.
pub const FALLBACK_RESULT_REGISTERS: &[&str] = &["xmm0"];

/// ABI result storage that NEITHER tier projects, each with its reason.
///
/// This is not a to-do list and not a suppression list — it is the record that
/// somebody looked. Every entry is a name that `super`'s per-convention tables
/// call result storage, so every entry is a place where a bare machine `ret`
/// gets no value projected onto it. Two of them (`st0`, `v0`) are the same
/// shape as the `xmm0` defect and are plausible real holes; the rest are
/// spellings the lifters are not known to emit at a return.
///
/// Adding a name here is a deliberate act with a measurement attached. Moving
/// one into a tier is a BEHAVIOUR change and needs fixture measurement, which
/// is exactly why the two operations look different.
pub const UNPROJECTED_RESULT_REGISTERS: &[(&str, &str)] = &[
    (
        "st0",
        "i386 returns float/double on the x87 stack, and `crate::ir::x87` lifts \
         the bottom absolute slot as this ordinary physical register. This is \
         the SAME shape as the `xmm0` defect, one convention over, and it is \
         unmeasured: no fixture lane has been shown to need it, and adding it \
         is a behaviour change, not a refactor.",
    ),
    (
        "v0",
        "AAPCS64's float result register. Its scalar views `d0`/`s0` ARE in the \
         first tier, so a float return spelled that way is projected; whether \
         the AArch64 lifter ever leaves the exit definition spelled `v0` at a \
         return has not been demonstrated either way.",
    ),
    (
        "q0",
        "AAPCS64 128-bit view. A vector-typed return is not a scalar result \
         projection and has its own path.",
    ),
    (
        "h0",
        "AAPCS64 16-bit float view. `_Float16` returns are not in the corpus.",
    ),
    (
        "b0",
        "AAPCS64 8-bit view. Listed by `float_return_registers` for bank \
         membership, never a scalar C result on its own.",
    ),
    (
        "ymm0",
        "AVX 256-bit view of `xmm0`. Listed by `float_return_registers` for \
         bank membership; a scalar float result is written through `xmm0`.",
    ),
    (
        "zmm0",
        "AVX-512 512-bit view of `xmm0`, same reason as `ymm0`.",
    ),
];

/// Whether an unversioned register name is first-tier result storage.
///
/// Rejects `rax#7` deliberately: a compatibility path projecting a bare machine
/// return must not infer a value merely because it sees a versioned write.
pub fn is_projected_result_register(name: &str) -> bool {
    PROJECTED_RESULT_REGISTERS.contains(&name)
}

/// Whether an unversioned register name is fallback-tier result storage.
pub fn is_fallback_result_register(name: &str) -> bool {
    FALLBACK_RESULT_REGISTERS.contains(&name)
}

/// Whether a name, SSA version and all, denotes first-tier result storage.
///
/// Unlike [`is_projected_result_register`] this accepts a version. The
/// distinction is intentional and is the difference between projecting a value
/// onto a return that has none and folding a writer into a return that already
/// names that exact version.
pub fn is_projected_result_storage(name: &str) -> bool {
    PROJECTED_RESULT_REGISTERS.contains(&super::ssa_base(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::abi::{float_return_registers, integer_return_registers, return_registers};
    use crate::ir::call_args::CallConv;

    /// Every calling convention, for exhaustive cross-checks.
    const EVERY_CALL_CONV: [CallConv; 6] = [
        CallConv::SysVAmd64,
        CallConv::Win64,
        CallConv::Cdecl32,
        CallConv::Aarch64,
        CallConv::Arm,
        CallConv::ArmHardFloat,
    ];

    /// Compile-time proof that [`EVERY_CALL_CONV`] is exhaustive: adding a
    /// `CallConv` variant fails to compile here rather than silently narrowing
    /// the census below to the conventions somebody remembered.
    fn conv_is_listed(cc: CallConv) -> bool {
        let named = match cc {
            CallConv::SysVAmd64 => CallConv::SysVAmd64,
            CallConv::Win64 => CallConv::Win64,
            CallConv::Cdecl32 => CallConv::Cdecl32,
            CallConv::Aarch64 => CallConv::Aarch64,
            CallConv::Arm => CallConv::Arm,
            CallConv::ArmHardFloat => CallConv::ArmHardFloat,
        };
        EVERY_CALL_CONV.contains(&named)
    }

    #[test]
    fn the_convention_list_is_exhaustive() {
        for cc in EVERY_CALL_CONV {
            assert!(conv_is_listed(cc), "{cc:?} missing from EVERY_CALL_CONV");
        }
        assert_eq!(EVERY_CALL_CONV.len(), 6);
    }

    /// The check the `xmm0` defect needed and did not have.
    ///
    /// Every name any convention calls result storage must be in a tier or
    /// carry a written reason for not being. There is no third outcome.
    #[test]
    fn every_abi_result_register_is_projected_or_documented_as_not() {
        let mut missing: Vec<(CallConv, &str)> = Vec::new();
        for cc in EVERY_CALL_CONV {
            let tables = [
                return_registers(cc),
                integer_return_registers(cc),
                float_return_registers(cc),
            ];
            for name in tables.iter().flat_map(|table| table.iter()) {
                let known = is_projected_result_register(name)
                    || is_fallback_result_register(name)
                    || UNPROJECTED_RESULT_REGISTERS
                        .iter()
                        .any(|(unprojected, _)| unprojected == name);
                if !known {
                    missing.push((cc, name));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "ABI result registers that no tier projects and no entry explains: \
             {missing:?}. Either add them to a tier (a BEHAVIOUR change — \
             measure it against tests/decompiler_fixtures/) or list them in \
             UNPROJECTED_RESULT_REGISTERS with the reason."
        );
    }

    /// The integer bank has no holes: this is the half that IS a strict
    /// superset of the per-convention tables, and it must stay that way.
    #[test]
    fn every_integer_result_register_is_first_tier() {
        for cc in EVERY_CALL_CONV {
            for name in integer_return_registers(cc) {
                assert!(
                    is_projected_result_register(name),
                    "{cc:?} returns integers in {name}, which no tier projects"
                );
            }
        }
    }

    /// The float bank is where the asymmetry lives, and this test PINS it
    /// rather than fixing it: `s0`/`d0` are projected at integer precedence
    /// while `xmm0` is fallback-only and `st0`/`v0` are not projected at all.
    /// Every one of those is a deliberate, measured state today. If this test
    /// fails, a float result register changed tier — which moves fixture cells
    /// and must be measured, not waved through.
    #[test]
    fn the_float_result_asymmetry_is_exactly_as_recorded() {
        let mut first_tier: Vec<&str> = Vec::new();
        let mut fallback: Vec<&str> = Vec::new();
        let mut unprojected: Vec<&str> = Vec::new();
        for cc in EVERY_CALL_CONV {
            for name in float_return_registers(cc) {
                let bucket = if is_projected_result_register(name) {
                    &mut first_tier
                } else if is_fallback_result_register(name) {
                    &mut fallback
                } else {
                    &mut unprojected
                };
                if !bucket.contains(name) {
                    bucket.push(name);
                }
            }
        }
        first_tier.sort_unstable();
        fallback.sort_unstable();
        unprojected.sort_unstable();

        assert_eq!(first_tier, ["d0", "s0"], "first-tier float result storage");
        assert_eq!(fallback, ["xmm0"], "fallback-tier float result storage");
        assert_eq!(
            unprojected,
            ["b0", "h0", "q0", "st0", "v0", "ymm0", "zmm0"],
            "float result storage no tier projects"
        );
    }

    #[test]
    fn every_unprojected_entry_is_real_abi_result_storage_and_has_a_reason() {
        for (name, reason) in UNPROJECTED_RESULT_REGISTERS {
            assert!(
                EVERY_CALL_CONV.iter().any(|cc| {
                    return_registers(*cc).contains(name)
                        || float_return_registers(*cc).contains(name)
                        || integer_return_registers(*cc).contains(name)
                }),
                "{name} is listed as unprojected result storage but no \
                 convention returns anything in it; delete the entry"
            );
            assert!(
                reason.len() > 40,
                "{name} needs a real reason, not {reason:?}"
            );
            assert!(
                !is_projected_result_register(name) && !is_fallback_result_register(name),
                "{name} is in a tier AND in UNPROJECTED_RESULT_REGISTERS"
            );
        }
    }

    #[test]
    fn the_two_tiers_do_not_overlap() {
        for name in FALLBACK_RESULT_REGISTERS {
            assert!(
                !is_projected_result_register(name),
                "{name} is in both tiers, so its precedence is whichever \
                 caller runs first"
            );
        }
    }

    #[test]
    fn versioned_names_are_first_tier_only_through_the_storage_predicate() {
        assert!(!is_projected_result_register("rax#7"));
        assert!(!is_projected_result_register("x0#2"));
        assert!(is_projected_result_storage("rax#7"));
        assert!(is_projected_result_storage("x0#2"));
        assert!(!is_projected_result_storage("local_18"));
        // The fallback tier has no versioned form at all: `xmm0#1` is the
        // reloaded ARGUMENT on the shape this tier exists for.
        assert!(!is_fallback_result_register("xmm0#1"));
        assert!(is_fallback_result_register("xmm0"));
    }

    /// `ret` is the one name in a tier that no ABI table mentions, and it is
    /// load-bearing: after `apply_role_names` the result register is spelled
    /// `ret` and nothing else identifies it.
    #[test]
    fn the_canonical_role_name_is_projected_and_is_not_an_abi_name() {
        assert!(is_projected_result_register("ret"));
        for cc in EVERY_CALL_CONV {
            assert!(
                !return_registers(cc).contains(&"ret"),
                "{cc:?} lists the role name as machine storage"
            );
        }
    }
}
