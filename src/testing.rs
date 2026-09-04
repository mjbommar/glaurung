//! Test-only support for the tests that shell out to a compiler.
//!
//! # The defect this exists to close
//!
//! Nineteen tests across `analysis/cfg.rs`, `ir/types_recover.rs`,
//! `ir/value_number.rs` and `ir/memory_objects/partition_tests.rs` compile a
//! fixture at test time. Each one used to handle a missing compiler like this:
//!
//! ```ignore
//! Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
//! ```
//!
//! A test that cannot find its compiler therefore returned `ok` having
//! asserted nothing. Not skipped, not reported — indistinguishable from a
//! pass. On a machine without cross-compilers an unknown fraction of the 2,829
//! passing tests was vacuous, and the total did not move to say so. That is
//! the same class of defect as the Python-side skips phase 1.6 made visible
//! with `-ra`, and worse: these are not skips, so no flag reveals them.
//!
//! # The contract
//!
//! [`missing_tool`] is called instead of returning silently. It:
//!
//! * **panics** when `GLAURUNG_REQUIRE_TOOLCHAINS=1`, so a fully-provisioned
//!   machine (and CI) turns a would-be silent skip into a loud failure. This
//!   is what makes "how much of the suite actually ran?" answerable: set the
//!   variable and the vacuous tests name themselves;
//! * otherwise records the skip and prints it, so `--nocapture` shows what was
//!   not tested.
//!
//! Local development without cross-compilers keeps working. What changes is
//! that the absence is now *stateable* rather than invisible.

use std::sync::atomic::{AtomicUsize, Ordering};

/// How many tests declined to run because a tool was absent, this process.
static SKIPPED: AtomicUsize = AtomicUsize::new(0);

/// Set `GLAURUNG_REQUIRE_TOOLCHAINS=1` to make an absent tool a failure.
pub const REQUIRE_ENV: &str = "GLAURUNG_REQUIRE_TOOLCHAINS";

/// Every external tool the `src/` test suite compiles fixtures with.
///
/// Kept explicit so `toolchain_probe_reports_every_declared_tool` can report
/// the provisioning of the machine it runs on, rather than each test
/// discovering its own absence in isolation.
pub const DECLARED_TOOLS: &[&str] = &["gcc", "clang", "arm-none-eabi-gcc"];

/// Record that a test could not run because `tool` is not installed.
///
/// Call this immediately before returning from the `NotFound` arm. It never
/// returns a value, so it composes with `return`, `return None`, and any other
/// early exit the call site needs.
///
/// # Panics
///
/// When `GLAURUNG_REQUIRE_TOOLCHAINS=1`, which is how a provisioned machine
/// asserts that no test is silently skipping.
pub fn missing_tool(tool: &str) {
    SKIPPED.fetch_add(1, Ordering::Relaxed);
    if std::env::var(REQUIRE_ENV).as_deref() == Ok("1") {
        panic!(
            "{tool} is not installed, and {REQUIRE_ENV}=1 demands it. This \
             test compiles a fixture at test time; without {tool} it would \
             report `ok` having asserted nothing. Install {tool} or unset \
             {REQUIRE_ENV} to allow the skip."
        );
    }
    eprintln!("SKIP: needs {tool}, which is not installed — this test asserted nothing");
}

/// Set `GLAURUNG_REQUIRE_FIXTURES=1` to make an absent fixture binary a failure.
pub const REQUIRE_FIXTURES_ENV: &str = "GLAURUNG_REQUIRE_FIXTURES";

/// Record that a test could not run because a compiled fixture is not present.
///
/// The twin of [`missing_tool`], for the tests that read a prebuilt binary out
/// of `tests/decompiler_fixtures/build/` rather than compiling one themselves.
/// That directory is gitignored and is produced by the fixture harness, so a
/// plain `git clone` does not have it; the tests that read it used to `expect`
/// and panic with a bare `NotFound`, which is why the `cargo test
/// --features python-ext` CI job could not pass.
///
/// # Panics
///
/// When `GLAURUNG_REQUIRE_FIXTURES=1`, which is how the Decompiler Fixture
/// Gate -- the workflow that actually builds the corpus -- asserts that these
/// tests really ran there.
pub fn missing_fixture(fixture: &str) {
    SKIPPED.fetch_add(1, Ordering::Relaxed);
    if std::env::var(REQUIRE_FIXTURES_ENV).as_deref() == Ok("1") {
        panic!(
            "the fixture `{fixture}` is not present under \
             tests/decompiler_fixtures/build/, and {REQUIRE_FIXTURES_ENV}=1 \
             demands it. Build the fixture corpus, or unset \
             {REQUIRE_FIXTURES_ENV} to allow the skip."
        );
    }
    eprintln!(
        "SKIP: needs the fixture {fixture}, which is not built \u{2014} this test asserted nothing"
    );
}

/// Tests skipped so far in this process for want of a tool or a fixture.
pub fn skipped_count() -> usize {
    SKIPPED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Source files whose tests compile fixtures. Scanned by the ratchet below.
    const SCANNED: &[&str] = &[
        "src/analysis/cfg.rs",
        "src/ir/types_recover.rs",
        "src/ir/value_number.rs",
        "src/ir/memory_objects/partition_tests.rs",
    ];

    /// Lines after the `NotFound` guard in which `missing_tool` must appear.
    /// Wide enough for a comment explaining the skip, narrow enough that it
    /// cannot accidentally match the next arm.
    const WINDOW: usize = 8;

    fn repo_root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }

    /// No test may handle a missing tool by returning silently.
    ///
    /// This is the ratchet, and it is deliberately a source scan rather than a
    /// behavioural assertion: the defect is invisible at runtime by
    /// construction — a silently-skipped test looks exactly like a passing one
    /// — so the only place to catch a new one is the text that creates it.
    #[test]
    fn no_test_skips_a_missing_toolchain_silently() {
        let mut offenders = Vec::new();
        for rel in SCANNED {
            let path = repo_root().join(rel);
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
            for (n, line) in text.lines().enumerate() {
                if !line.contains("ErrorKind::NotFound") {
                    continue;
                }
                // The arm must hand off to `missing_tool` somewhere in its
                // body. The window is generous because a converted arm carries
                // a comment explaining what the skip costs, and a checker that
                // only looked at the following line would flag exactly the
                // sites that were fixed most carefully.
                let handled = std::iter::once(line)
                    .chain(text.lines().skip(n + 1).take(WINDOW))
                    .any(|l| l.contains("missing_tool"));
                if !handled {
                    offenders.push(format!("{rel}:{}", n + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "these sites return silently when a compiler is absent, so the \
             test reports `ok` having asserted nothing:\n  {}\n\nRoute them \
             through `crate::testing::missing_tool(\"<tool>\")` so the skip is \
             recorded and `{REQUIRE_ENV}=1` can turn it into a failure.",
            offenders.join("\n  ")
        );
    }

    /// The declared tool list must match what the scanned files actually use.
    ///
    /// A tool that starts being used without being declared would not be
    /// demanded by `GLAURUNG_REQUIRE_TOOLCHAINS=1`, so its tests could go on
    /// skipping silently on a machine that believes it is fully provisioned.
    #[test]
    fn every_tool_the_tests_invoke_is_declared() {
        let mut used = std::collections::BTreeSet::new();
        for rel in SCANNED {
            let text = std::fs::read_to_string(repo_root().join(rel)).unwrap();
            let mut rest = text.as_str();
            while let Some(i) = rest.find("Command::new(\"") {
                rest = &rest[i + "Command::new(\"".len()..];
                if let Some(end) = rest.find('"') {
                    used.insert(rest[..end].to_string());
                }
            }
        }
        let declared: std::collections::BTreeSet<_> =
            DECLARED_TOOLS.iter().map(|s| s.to_string()).collect();
        let undeclared: Vec<_> = used.difference(&declared).cloned().collect();
        assert!(
            undeclared.is_empty(),
            "these tools are invoked by fixture-compiling tests but are not in \
             DECLARED_TOOLS, so {REQUIRE_ENV}=1 would not demand them: {undeclared:?}"
        );
    }

    /// No test may read a prebuilt fixture and skip silently when it is absent.
    ///
    /// The twin of `no_test_skips_a_missing_toolchain_silently`, and it exists
    /// because the untracked version of this defect actually shipped: eleven
    /// tests added on 2026-09-02 read `tests/decompiler_fixtures/build/` with a
    /// bare `expect`, and since that directory is gitignored and the
    /// `cargo test --features python-ext` CI job never builds it, that job
    /// could not pass on any commit. Four older sites had the opposite failure
    /// -- a silent `return` that asserted nothing and said so to no one.
    ///
    /// Scans the whole `src/` tree rather than a fixed list, because these
    /// reads are scattered and a new one must not be able to appear unnoticed.
    #[test]
    fn no_test_reads_a_fixture_and_skips_silently() {
        const NEEDLE: &str = "decompiler_fixtures/build";
        let mut offenders = Vec::new();
        let mut stack = vec![repo_root().join("src")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {dir:?}: {e}")) {
                let path = entry.expect("directory entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                // This file defines and documents the helper, so every mention
                // here is prose or the scanner itself.
                if path.ends_with("testing.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("read a source file");
                let lines: Vec<&str> = text.lines().collect();
                for (n, line) in lines.iter().enumerate() {
                    // Comments and doc comments merely name the corpus.
                    if !line.contains(NEEDLE) || line.trim_start().starts_with("//") {
                        continue;
                    }
                    let handled = lines[n..(n + WINDOW + 1).min(lines.len())]
                        .iter()
                        .any(|l| l.contains("missing_fixture"));
                    if !handled {
                        let rel = path.strip_prefix(repo_root()).unwrap_or(&path);
                        offenders.push(format!("{}:{}", rel.display(), n + 1));
                    }
                }
            }
        }
        offenders.sort();
        assert!(
            offenders.is_empty(),
            "these sites read a prebuilt fixture without routing its absence \
             through `crate::testing::missing_fixture(\"<name>\")`, so on a \
             checkout that has not built the corpus they either panic with a \
             bare NotFound or report `ok` having asserted nothing:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// Reports what this machine has. Never fails on absence by itself —
    /// `GLAURUNG_REQUIRE_TOOLCHAINS=1` is the switch that makes absence fatal.
    #[test]
    fn toolchain_probe_reports_every_declared_tool() {
        let mut missing = Vec::new();
        for tool in DECLARED_TOOLS {
            let found = std::process::Command::new(tool)
                .arg("--version")
                .output()
                .is_ok();
            eprintln!("  {tool}: {}", if found { "present" } else { "MISSING" });
            if !found {
                missing.push(*tool);
            }
        }
        if std::env::var(REQUIRE_ENV).as_deref() == Ok("1") {
            assert!(
                missing.is_empty(),
                "{REQUIRE_ENV}=1 but these are absent: {missing:?}. Every \
                 fixture-compiling test that needs them would report `ok` \
                 without asserting anything."
            );
        }
    }
}
