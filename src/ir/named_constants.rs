//! Symbolic names for the magic numbers passed to well-known system calls.
//!
//! # What this is for
//!
//! `mprotect(page, 4096, 5)` and `ptrace(0, 0, 0, 0)` are correct and nearly
//! unreadable. The 5 is `PROT_READ|PROT_EXEC` -- making a page executable,
//! which is the single most interesting thing a program can ask for during
//! triage -- and the 0 is `PTRACE_TRACEME`, the classic anti-debugging probe.
//! An analyst who has to look those up is being handed the machine's version
//! of the program rather than the source's.
//!
//! Ghidra prints `ptrace(PTRACE_TRACEME,0,0)` for exactly this reason. This
//! module is the same idea, and no more: a lookup table, no analysis.
//!
//! # Why a comment, and not the macro
//!
//! The decbench render is **recompiled** -- that is how the execution
//! differential proves a recovery correct -- so emitting a bare `PROT_READ`
//! would turn readable output into output that does not build, unless the
//! renderer also grew a header-include mechanism and got every feature-test
//! macro right on every target. The information is worth having; a broken
//! build is not worth paying for it.
//!
//! So the constant stays, and the name rides along beside it:
//!
//! ```text
//! mprotect(local_20, 4096, 5 /* PROT_READ|PROT_EXEC */)
//! ```
//!
//! which compiles exactly as before and tells the reader what 5 means.
//!
//! # Scope
//!
//! Deliberately small and POSIX-flavoured, covering the calls that carry
//! triage weight: memory protection, process tracing, file and socket
//! creation. A wrong name here is worse than no name, so every entry is a
//! value the named constant genuinely has on Linux, and anything not in the
//! table renders unchanged.

use crate::ir::ast::Expr;

/// How a parameter's integer values map to source-level names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decoder {
    /// Exactly one name per value: `ptrace`'s request, a socket's family.
    Enumerated(&'static [(i64, &'static str)]),
    /// A bitmask decomposed into an OR of names, with a distinguished name for
    /// zero: `PROT_NONE`, `O_RDONLY`.
    Flags {
        zero: &'static str,
        bits: &'static [(i64, &'static str)],
    },
}

/// `(callee, zero-based parameter index, decoder)`.
///
/// Matched on the callee's exact name, so a program's own `open` is not
/// decoded as the libc one unless it really is.
const TABLE: &[(&str, usize, Decoder)] = &[
    (
        "mprotect",
        2,
        Decoder::Flags {
            zero: "PROT_NONE",
            bits: &[(1, "PROT_READ"), (2, "PROT_WRITE"), (4, "PROT_EXEC")],
        },
    ),
    (
        "mmap",
        2,
        Decoder::Flags {
            zero: "PROT_NONE",
            bits: &[(1, "PROT_READ"), (2, "PROT_WRITE"), (4, "PROT_EXEC")],
        },
    ),
    (
        "mmap",
        3,
        Decoder::Flags {
            zero: "MAP_FILE",
            bits: &[
                (0x01, "MAP_SHARED"),
                (0x02, "MAP_PRIVATE"),
                (0x10, "MAP_FIXED"),
                (0x20, "MAP_ANONYMOUS"),
            ],
        },
    ),
    (
        "ptrace",
        0,
        Decoder::Enumerated(&[
            (0, "PTRACE_TRACEME"),
            (1, "PTRACE_PEEKTEXT"),
            (2, "PTRACE_PEEKDATA"),
            (3, "PTRACE_PEEKUSER"),
            (4, "PTRACE_POKETEXT"),
            (5, "PTRACE_POKEDATA"),
            (6, "PTRACE_POKEUSER"),
            (7, "PTRACE_CONT"),
            (8, "PTRACE_KILL"),
            (9, "PTRACE_SINGLESTEP"),
            (16, "PTRACE_ATTACH"),
            (17, "PTRACE_DETACH"),
        ]),
    ),
    (
        "open",
        1,
        Decoder::Flags {
            zero: "O_RDONLY",
            bits: &[
                (0x1, "O_WRONLY"),
                (0x2, "O_RDWR"),
                (0x40, "O_CREAT"),
                (0x80, "O_EXCL"),
                (0x200, "O_TRUNC"),
                (0x400, "O_APPEND"),
                (0x800, "O_NONBLOCK"),
            ],
        },
    ),
    (
        "socket",
        0,
        Decoder::Enumerated(&[
            (1, "AF_UNIX"),
            (2, "AF_INET"),
            (10, "AF_INET6"),
            (16, "AF_NETLINK"),
            (17, "AF_PACKET"),
        ]),
    ),
    (
        "socket",
        1,
        Decoder::Enumerated(&[
            (1, "SOCK_STREAM"),
            (2, "SOCK_DGRAM"),
            (3, "SOCK_RAW"),
            (5, "SOCK_SEQPACKET"),
        ]),
    ),
];

/// The source-level name for `value` at `parameter_index` of `callee`, if the
/// table describes one.
///
/// Returns the name only -- the caller decides how to present it. Today every
/// caller renders it as a trailing comment beside the literal; see the module
/// docs for why it is not substituted for the literal.
pub fn symbolic_name(callee: &str, parameter_index: usize, value: i64) -> Option<String> {
    let decoder = TABLE.iter().find_map(|(name, index, decoder)| {
        (*name == callee && *index == parameter_index).then_some(decoder)
    })?;
    match decoder {
        Decoder::Enumerated(entries) => entries
            .iter()
            .find_map(|(candidate, name)| (*candidate == value).then(|| (*name).to_string())),
        Decoder::Flags { zero, bits } => {
            if value == 0 {
                return Some((*zero).to_string());
            }
            if value < 0 {
                return None;
            }
            let mut remaining = value;
            let mut names = Vec::new();
            for (bit, name) in bits.iter() {
                if remaining & bit == *bit {
                    names.push(*name);
                    remaining &= !bit;
                }
            }
            // An unexplained bit means the table does not fully describe this
            // value, and a partial decode would be a claim we cannot support.
            // Better to print nothing than "PROT_READ" for a value that also
            // set something we have never heard of.
            if remaining != 0 || names.is_empty() {
                return None;
            }
            Some(names.join("|"))
        }
    }
}

/// The integer value of an argument that is a literal, seen through any casts.
///
/// A cast does not change which constant was passed, and the lifter routinely
/// wraps one: the third argument of `mprotect` arrives as
/// `(unsigned long)((unsigned int)(5))`.
pub fn constant_argument_value(expr: &Expr) -> Option<i64> {
    let mut current = expr;
    loop {
        match current {
            Expr::Const(value) => return Some(*value),
            Expr::Cast { expr, .. } => current = expr,
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_executable_page_request() {
        // The motivating case: `mprotect(page, 4096, 5)` in suspicious_linux.
        assert_eq!(
            symbolic_name("mprotect", 2, 5).as_deref(),
            Some("PROT_READ|PROT_EXEC")
        );
    }

    #[test]
    fn decodes_the_anti_debugging_probe() {
        assert_eq!(
            symbolic_name("ptrace", 0, 0).as_deref(),
            Some("PTRACE_TRACEME")
        );
    }

    #[test]
    fn zero_has_its_own_name_for_flag_parameters() {
        assert_eq!(
            symbolic_name("mprotect", 2, 0).as_deref(),
            Some("PROT_NONE")
        );
        assert_eq!(symbolic_name("open", 1, 0).as_deref(), Some("O_RDONLY"));
    }

    #[test]
    fn an_unexplained_bit_decodes_to_nothing() {
        // 5 is READ|EXEC; 8 is not in the table. A partial decode would claim
        // more than the table knows, so the whole value is left alone.
        assert_eq!(symbolic_name("mprotect", 2, 13), None);
    }

    #[test]
    fn unknown_callees_and_parameters_are_untouched() {
        assert_eq!(symbolic_name("my_own_function", 2, 5), None);
        assert_eq!(symbolic_name("mprotect", 0, 5), None);
        assert_eq!(symbolic_name("ptrace", 0, 999), None);
    }

    #[test]
    fn negative_flag_values_decode_to_nothing() {
        // A negative mask is not a flag set; it is a sign that the recovered
        // type is wrong, and naming it would hide that.
        assert_eq!(symbolic_name("mprotect", 2, -1), None);
    }

    #[test]
    fn every_table_entry_round_trips() {
        // Guards against a typo making an entry unreachable.
        for (callee, index, decoder) in TABLE {
            match decoder {
                Decoder::Enumerated(entries) => {
                    for (value, name) in entries.iter() {
                        assert_eq!(
                            symbolic_name(callee, *index, *value).as_deref(),
                            Some(*name),
                            "{callee} arg {index} value {value}"
                        );
                    }
                }
                Decoder::Flags { zero, bits } => {
                    assert_eq!(symbolic_name(callee, *index, 0).as_deref(), Some(*zero));
                    for (bit, name) in bits.iter() {
                        assert_eq!(
                            symbolic_name(callee, *index, *bit).as_deref(),
                            Some(*name),
                            "{callee} arg {index} bit {bit}"
                        );
                    }
                }
            }
        }
    }
}
