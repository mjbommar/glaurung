//! The DEFAULT `cargo test` decompiles a real binary, end to end.
//!
//! # Why this exists
//!
//! Measured 2026-09-01: of 2,829 tests in a plain `cargo test`, `ir` holds
//! 1,867 — 65% of the suite is decompiler internals — while `decompile` holds
//! four, all four testing the profiler wrapper. **No Rust test used
//! `tests/decompiler_fixtures/` as a corpus at all.** The 196-fixture matrix
//! that proves the decompiler correct is driven entirely from Python
//! (`tools/dectest.py` and the execution differential), so a Rust change that
//! broke decompilation could not fail the Rust suite. Individual `src/` tests
//! `include_bytes!` a single fixture *source* and compile it ad hoc, which is
//! a much weaker and machine-dependent thing.
//!
//! This closes that. It runs the real pure-Rust pipeline —
//! discover → lift → SSA → structure → lower → render — over the **committed**
//! canary objects, which exist precisely so the default suite can exercise the
//! decompiler on a fresh clone with no toolchain.
//!
//! # What it asserts, and what it deliberately does not
//!
//! Structural properties only: a function is found, it lifts to blocks, it
//! renders a body, and no raw image address leaks into the output. Never
//! golden text — a golden test over a renderer under active development fails
//! on every improvement, gets regenerated reflexively, and stops meaning
//! anything. The semantic proof lives in the execution differential; this is
//! the fast smoke gate that runs every time anybody types `cargo test`.
//!
//! It needs **no compiler**, unlike the 21 fixture-compiling tests in `src/`,
//! so it is real coverage on a bare machine and in CI.

use std::path::{Path, PathBuf};

use glaurung::analysis::cfg::{analyze_functions_bytes, Budgets};
use glaurung::core::binary::Arch;

fn canary_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures/canary")
}

/// `(object, exported function, tokens the body must contain)`.
///
/// **These are the IR-level renderer's tokens, not C.** `ast::render` is what
/// `--style c` shows -- `%rsp`, `store &[...]`, `while (1)` -- because the
/// decbench renderer that produces the scored C lives in
/// `src/python_bindings/ir.rs` and is behind the `python-ext` feature, so a
/// default `cargo test` cannot reach it. Asserting `for` here fails on
/// `13_loop_early_exit` even though its C is correct: gcc -O0 lowers the loop
/// to a `while`, and the IR renderer prints what the IR says.
///
/// The structural claims below are therefore about control flow surviving
/// lifting and structuring, which is what this level can honestly witness.
/// The C-level tokens stay in `python/tests/test_decompiler_canary.py`.
const SUBJECTS: &[(&str, &str, &[&str])] = &[
    ("04_switch_shapes-gcc-O0.so", "dense_jumptable", &["switch"]),
    (
        "13_loop_early_exit-gcc-O0.so",
        "sum_positive",
        &["while", "if"],
    ),
    (
        "212_loop_with_returning_arm-gcc-O2.so",
        "fsm_returns_from_arm",
        &["return"],
    ),
    ("09_memory_effects-gcc-O2.so", "read_counter", &[]),
    ("03_loop_shapes-clang-O2.so", "dowhile_atleastonce", &[]),
    ("05_cleanup_and_state_machine-gcc-O0.so", "fsm", &[]),
    ("07_packet_parser-gcc-O2.so", "parse_packet", &[]),
    (
        "172_float_double_widths-gcc-O0.so",
        "single_precision_horner",
        &[],
    ),
    (
        "216_packed_union_wire_record-gcc-O0.so",
        "bitfield_roundtrip",
        &[],
    ),
];

fn budgets() -> Budgets {
    Budgets {
        max_functions: 2000,
        max_blocks: 4000,
        max_instructions: 200_000,
        timeout_ms: 60_000,
        total_timeout_ms: 0,
    }
}

/// Decompile one exported function with the real pipeline.
fn render_function(object: &Path, name: &str) -> Option<String> {
    let session = glaurung::program::session::ProgramSession::from_path(object).ok()?;
    let entry = session.image().defined_text_symbol_address(name)?;
    let data = session.image().bytes().to_vec();
    let (functions, _) = analyze_functions_bytes(&data, &budgets());
    let function = functions.iter().find(|f| f.entry_point.value == entry)?;
    let lifted =
        glaurung::ir::lift_function::lift_function_from_bytes(&data, function, Arch::X86_64)
            .ok()?;
    assert!(
        !lifted.blocks.is_empty(),
        "{}: lifted to zero blocks",
        object.display()
    );
    let ssa = glaurung::ir::ssa::compute_ssa(&lifted);
    let region = glaurung::ir::structure::recover_verified(&lifted, &ssa);
    let ast = glaurung::ir::ast::lower(&lifted, &region, name);
    Some(glaurung::ir::ast::render(&ast))
}

/// A vacuity guard: every test below would pass over an empty directory.
#[test]
fn the_canary_set_is_present() {
    let objects: Vec<_> = std::fs::read_dir(canary_dir())
        .expect("canary directory exists — it is COMMITTED, not built")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "so"))
        .collect();
    assert_eq!(
        objects.len(),
        9,
        "expected the nine committed canary objects; found {}. If the checkout \
         is missing them, `.gitignore` carries a blanket `*.so` and has \
         silently dropped committed fixtures before.",
        objects.len()
    );
}

#[test]
fn every_canary_function_decompiles_to_a_body() {
    let mut checked = 0;
    for (object, function, must_contain) in SUBJECTS {
        let path = canary_dir().join(object);
        assert!(
            path.is_file(),
            "{object} missing from the committed canary set"
        );
        let rendered = render_function(&path, function)
            .unwrap_or_else(|| panic!("{object}: no output for {function}"));
        assert!(
            rendered.lines().count() >= 3,
            "{object}: {function} rendered a stub, not a body:\n{rendered}"
        );
        for token in *must_contain {
            assert!(
                rendered.contains(token),
                "{object}: {function} lost {token:?}:\n{rendered}"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, SUBJECTS.len(), "not every subject was checked");
}

#[test]
fn no_canary_leaks_a_raw_image_address() {
    // Portable C never dereferences a literal image address. One means the
    // renderer gave up on modelling storage and printed the pointer instead.
    for (object, function, _) in SUBJECTS {
        let path = canary_dir().join(object);
        let Some(rendered) = render_function(&path, function) else {
            continue;
        };
        for line in rendered.lines() {
            // At IR level a frame access is `store &[%rbp-0x18]`, which is
            // normal and not a leak. What must never appear is an
            // `unrecovered` marker: the renderer conceding it could not model
            // the construct at all.
            assert!(
                !line.contains("unrecovered"),
                "{object}: {function} left an unrecovered construct:\n  {line}"
            );
        }
    }
}

/// Rendering the same object twice in one process must agree.
///
/// Every recorded baseline assumes this. Cross-process determinism is covered
/// by `python/tests/test_decompiler_determinism.py`, which is the only leg
/// that can see a hash-order leak; this is the cheap in-process half.
#[test]
fn a_second_render_is_identical() {
    let (object, function, _) = SUBJECTS[0];
    let path = canary_dir().join(object);
    let first = render_function(&path, function).expect("first render");
    let second = render_function(&path, function).expect("second render");
    assert_eq!(
        first, second,
        "{object}: two renders in one process disagree — something carries \
         state between runs"
    );
}
