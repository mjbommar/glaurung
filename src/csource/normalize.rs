//! `F-1`, `F-2`, `F-3` --- the text normalization passes, ported byte-exactly.
//!
//! Spec: `docs/design/static-c-analysis/requirements.md` section 2
//! (`REQ-NORM-1` .. `REQ-NORM-4`). Reference implementation:
//! `decbench/utils/cfg.py`'s `strip_system_headers`, `sanitize_decompiled_c`,
//! `escape_literal_control_bytes` and the module-level regexes they use.
//!
//! These are pure text transforms with no parser behind them yet -- they run
//! *before* anything in `crate::syntax` sees the bytes, on both DecBench's own
//! side (a gcc-preprocessed `.i` translation unit) and the side under test (a
//! decompiler's `.c` output). A divergence from the Python here does not fail
//! loudly: it silently reshapes what the parser downstream receives, which
//! changes which functions parse at all and therefore every GED number that
//! follows. Byte-exactness is the whole point, so ports below favour a
//! character-by-character or line-by-line translation of the Python source
//! over an idiomatic rewrite wherever the two could diverge.
//!
//! **Encoding (REQ-NORM-4).** The Python originals read files with
//! `Path.read_text(errors="replace")`, i.e. invalid UTF-8 in the input file is
//! replaced (lossily) before any of this logic runs. A Rust `&str` is already
//! guaranteed valid UTF-8, so that replacement is necessarily the caller's
//! job (e.g. `String::from_utf8_lossy` at the point a file is read) --
//! nothing in this module can observe or need to handle invalid bytes, and
//! nothing here panics on any `&str` input.

use regex::Regex;
use std::sync::OnceLock;

/// Byte codes exempted from control-byte escaping inside a literal: tab and
/// newline are the emitted source's own layout, not literal payload, so they
/// pass through unescaped. Mirrors `_KEEP_RAW_BYTES` in the Python original.
const KEEP_RAW_BYTES: [u32; 2] = [0x09, 0x0A];

/// The compiled `# <line> "<file>"` gcc line-marker pattern, built once.
///
/// Matched against one line at a time (never the whole file), so an
/// unanchored-looking `^` here behaves exactly like Python's `re.match`: both
/// only ever test the start of the string handed in.
fn line_marker_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"^#\s+\d+\s+"([^"]*)""#).expect("line marker regex is a fixed valid pattern")
    })
}

/// The compiled aggregate/array-return-type pattern, built once.
///
/// `(?m)` reproduces Python's `re.M`: `^` matches at the start of the haystack
/// and immediately after every `\n` -- the same rule Python's `re.MULTILINE`
/// uses (unlike `str.splitlines`, only `\n` counts). Non-greedy `[\w ]*?` is
/// load-bearing: it is what keeps the match from swallowing past the first
/// `[`, and `regex` (like `re`) supports lazy quantifiers.
fn agg_return_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)^([A-Za-z_][\w ]*?)\s*\[\d+\]\s+([A-Za-z_]\w*\s*\()")
            .expect("aggregate-return regex is a fixed valid pattern")
    })
}

/// The compiled register-annotation pattern, built once.
fn reg_annotation_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\s*@\s*[a-z]\w+\b")
            .expect("register-annotation regex is a fixed valid pattern")
    })
}

/// Splits `s` on every boundary Python's `str.splitlines()` recognizes.
///
/// Rust's `str::lines()` only splits on `\n` / `\r\n`, but Python's
/// `splitlines()` (which `strip_system_headers` iterates with `for line in
/// preprocessed.splitlines()`) additionally treats `\r`, `\x0b`, `\x0c`,
/// `\x1c`, `\x1d`, `\x1e`, `\x85`, `\u{2028}` and `\u{2029}` as line
/// boundaries. A `.i` file is compiler output, so these are vanishingly
/// unlikely outside a string literal that embeds one of those raw bytes
/// verbatim -- but that is exactly the adversarial case REQ-NORM-3 exists
/// for, so this reproduces the full Python rule rather than the common-case
/// subset. Like Python's version: no trailing empty element for a
/// trailing terminator, and no native recursion (single linear scan).
fn python_splitlines(s: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let is_boundary = matches!(
            c,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !is_boundary {
            continue;
        }
        let end = i;
        let mut next_start = i + c.len_utf8();
        if c == '\r' {
            if let Some(&(j, '\n')) = chars.peek() {
                next_start = j + 1;
                chars.next();
            }
        }
        lines.push(&s[start..end]);
        start = next_start;
    }
    if start < s.len() {
        lines.push(&s[start..]);
    }
    lines
}

/// Escapes raw control bytes appearing inside string/char literals (F-2).
///
/// A decompiler that inlines `.rodata` verbatim emits e.g. an ANSI colour
/// sequence as a raw `0x1B`. That is valid C, but downstream (pyjoern's fast
/// parser reading JSON off a subprocess's stdout) a raw control byte makes the
/// output non-JSON, which voids the *whole file's* parse rather than just one
/// function's. Escaping to `\xNN` is the same bytes to a C compiler, so
/// nothing about control flow changes -- only whether the literal payload is
/// printable when this text is later written out and re-read as a text
/// stream.
///
/// Four-state scan (outside / in-string / in-char / pending-backslash), ported
/// character-by-character from `escape_literal_control_bytes` in
/// `decbench/utils/cfg.py`: a backslash while inside either literal kind
/// starts a one-character escape (so `"\\"` does not itself close the
/// string), and a quote character only toggles its *own* literal kind when
/// the other kind isn't already open (so a `'` inside a `"..."` string, or a
/// `"` inside a `'...'` char literal, does not end the literal early).
pub fn escape_literal_control_bytes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut in_char = false;
    let mut pending_escape = false;
    for ch in text.chars() {
        let code = ch as u32;
        if pending_escape {
            out.push(ch);
            pending_escape = false;
            continue;
        }
        if ch == '\\' && (in_string || in_char) {
            out.push(ch);
            pending_escape = true;
            continue;
        }
        if ch == '"' && !in_char {
            in_string = !in_string;
        } else if ch == '\'' && !in_string {
            in_char = !in_char;
        }
        let is_control = code < 0x20 || code == 0x7F;
        if (in_string || in_char) && !KEEP_RAW_BYTES.contains(&code) && is_control {
            out.push_str(&format!("\\x{code:02x}"));
        } else {
            out.push(ch);
        }
    }
    out
}

/// True if a preprocessor line-marker file is a system/toolchain header.
///
/// Covers glibc (`/usr/include`), gcc internals (`/usr/lib/gcc`), the
/// cross/mingw toolchains (also under `/usr/...`), and the preprocessor's
/// synthetic files (`<built-in>`, `<command-line>`, `stdc-predef.h`). Ported
/// from `_is_system_header` in `decbench/utils/cfg.py`.
fn is_system_header(path: &str) -> bool {
    path.is_empty()
        || path.starts_with('<')
        || path.starts_with("/usr/")
        || path.contains("/usr/lib/gcc")
        || path.ends_with("stdc-predef.h")
}

/// Drops inlined system-header code from a preprocessed (`.i`) translation
/// unit (F-1).
///
/// A `.i` file is the project source with every `#include` expanded inline,
/// so it is dominated (80-98%, per `joern-behavior.md` section 1.1) by
/// glibc/toolchain headers. Joern then either times out parsing megabytes of
/// headers or drowns the project's own functions in thousands of header
/// inlines. Using the `# <line> "<file>"` markers gcc emits, this keeps only
/// lines that came from the project's own files; `#ifdef` selection and macro
/// expansion have already been done by the real compiler, so the result is
/// exactly the code that was compiled -- the right `ifdef` branches, and
/// small.
///
/// Private: REQ-NORM-2 requires it be structurally impossible to run the
/// decompiler-only sanitizer over `.i` text, and the converse -- silently
/// dropping code from decompiled output because it happened to look like a
/// system-header path -- would be just as wrong. [`Dialect::normalize`] is
/// the only way to reach this from outside the module.
///
/// The initial state is *inside* a system header, so any text appearing
/// before the first marker is dropped -- ported as-is from the Python, which
/// starts `in_system = True` before its loop.
fn strip_system_headers(preprocessed: &str) -> String {
    let mut keep: Vec<&str> = Vec::new();
    let mut in_system = true;
    for line in python_splitlines(preprocessed) {
        if let Some(caps) = line_marker_regex().captures(line) {
            let path = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            in_system = is_system_header(path);
            continue;
        }
        if !in_system {
            keep.push(line);
        }
    }
    let mut result = keep.join("\n");
    result.push('\n');
    result
}

/// Cleans decompiler-specific C quirks that break Joern's parser (F-3).
///
/// GED only cares about CFG *structure*, so these edits are purely to make
/// the body parseable -- they never touch control flow. Four tool-specific
/// quirks, applied in this order because later rewrites can depend on earlier
/// ones having already run (the `__int128` rewrites, in particular, must not
/// be reordered relative to each other -- see the module tests):
///
/// * **Aggregate/array return type** (angr/ghidra): `T [N] name(...)` is
///   rewritten to `T name(...)`. Anchored to the start of a line so a real
///   in-body array declaration (`char buf[16];`) is never rewritten.
/// * **Register annotation** (binja): `` @ rax`` (and friends) is stripped --
///   `@` is not valid C.
/// * **128-bit types** (ida): `__int128` is widened to `long long` (the exact
///   width is irrelevant to the CFG). `unsigned __int128` is handled first so
///   it does not become `unsigned long long long`.
/// * **Raw control bytes in literals**: escaped via
///   [`escape_literal_control_bytes`], so a verbatim `.rodata` string cannot
///   make pyjoern's fast parser emit non-JSON and void the invocation.
///
/// Private: see [`strip_system_headers`]'s doc for why, and
/// [`Dialect::normalize`] for the one sanctioned way in.
fn sanitize_decompiled_c(text: &str) -> String {
    let text = agg_return_regex().replace_all(text, "$1 $2");
    let text = reg_annotation_regex().replace_all(&text, "");
    let text = text
        .replace("unsigned __int128", "unsigned long long")
        .replace("__int128", "long long");
    escape_literal_control_bytes(&text)
}

/// Which side of the DecBench text pipeline a piece of C-like source text
/// came from, and therefore which single normalization pass it is allowed to
/// go through.
///
/// REQ-NORM-2 states plainly: "It must be impossible to apply this pass
/// [`sanitize_decompiled_c`] to a `.i` input" -- sanitizing ground truth would
/// corrupt the very thing decompiled output is scored against. The Python
/// original enforces that only by convention: `extract_cfgs_from_source`
/// gates the call behind a `sanitize_decompiled: bool` parameter that a
/// caller must remember to pass correctly. A byte-exact port's job is to not
/// reintroduce that failure mode, so [`strip_system_headers`] and
/// [`sanitize_decompiled_c`] are private to this module -- there is no path
/// to either except through [`Dialect::normalize`], which the type itself
/// forces a caller to pick explicitly for every string it normalizes. Mixing
/// up which text is which is still possible (nothing stops a caller writing
/// `Dialect::Decompiled(preprocessed_text)`), but it is now a visible,
/// grep-able mislabeling at the one call site that does it, rather than a
/// silent extra parameter deep in a pipeline function that a future edit can
/// forget to thread through.
///
/// [`escape_literal_control_bytes`] (F-2) is not gated here: it is dialect-neutral
/// (there is no "wrong side" to run it on, and `sanitize_decompiled_c` already
/// applies it as its last step), so it stays a plain public function for reuse
/// and standalone testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect<'a> {
    /// A gcc-preprocessed translation unit (`.i`): normalized with
    /// [`strip_system_headers`] (F-1).
    Preprocessed(&'a str),
    /// Decompiler-emitted C, from any backend: normalized with
    /// [`sanitize_decompiled_c`] (F-3, which itself ends with F-2).
    Decompiled(&'a str),
}

impl<'a> Dialect<'a> {
    /// Runs the one normalization pass this dialect is allowed to go
    /// through. The only public entry point into F-1/F-3 -- see the enum's
    /// docs for why that is the point.
    pub fn normalize(self) -> String {
        match self {
            Dialect::Preprocessed(text) => strip_system_headers(text),
            Dialect::Decompiled(text) => sanitize_decompiled_c(text),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    // ---- F-2: escape_literal_control_bytes -------------------------------

    #[test]
    fn escape_empty_input() {
        assert_eq!(escape_literal_control_bytes(""), "");
    }

    #[test]
    fn escape_backslash_backslash_does_not_open_a_string() {
        // Python: `"\\"` is a complete, closed string literal (one escaped
        // backslash character). The trailing `x` after it must NOT be seen
        // as "inside a string" -- if the backslash state machine were wrong,
        // a control byte after this would get escaped when it shouldn't.
        let input = "\"\\\\\"\x01"; // the four chars "\\"  then a raw 0x01
        let out = escape_literal_control_bytes(input);
        // The string closed after the escaped backslash, so the raw 0x01
        // after it is untouched (outside any literal).
        assert_eq!(out, "\"\\\\\"\x01");
    }

    #[test]
    fn escape_single_quote_inside_double_quoted_string_is_inert() {
        // A `'` appearing while inside a `"..."` string must not toggle
        // in_char, so a control byte later in the same string is still
        // recognized as "inside a string" and gets escaped.
        let input = "\"it's\x01\"";
        let out = escape_literal_control_bytes(input);
        assert_eq!(out, "\"it's\\x01\"");
    }

    #[test]
    fn escape_double_quote_inside_char_literal_is_inert() {
        // Mirror case: a `"` while inside a `'...'` char literal must not
        // toggle in_string.
        let input = "'\"'\x01"; // char literal containing a double quote, then raw 0x01 outside
        let out = escape_literal_control_bytes(input);
        // The char literal '"' opens and closes correctly; the 0x01 after it
        // is outside any literal and stays raw.
        assert_eq!(out, "'\"'\x01");
    }

    #[test]
    fn escape_real_ansi_escape_in_string_becomes_hex() {
        let input = "\"\x1bpretty\""; // raw ESC (0x1b) inside a string
        let out = escape_literal_control_bytes(input);
        assert_eq!(out, "\"\\x1bpretty\"");
    }

    #[test]
    fn escape_tab_and_newline_survive_unescaped_inside_string() {
        let input = "\"a\tb\nc\"";
        let out = escape_literal_control_bytes(input);
        assert_eq!(out, "\"a\tb\nc\"");
    }

    #[test]
    fn escape_control_byte_outside_any_literal_is_untouched() {
        let input = "x\x01y";
        assert_eq!(escape_literal_control_bytes(input), "x\x01y");
    }

    #[test]
    fn escape_del_byte_0x7f_in_string_is_escaped() {
        let input = "\"\x7f\"";
        assert_eq!(escape_literal_control_bytes(input), "\"\\x7f\"");
    }

    // ---- F-1: strip_system_headers ----------------------------------------

    #[test]
    fn strip_empty_input() {
        assert_eq!(strip_system_headers(""), "\n");
    }

    #[test]
    fn strip_text_before_first_marker_is_dropped() {
        let input = "int leaked;\n# 1 \"proj.c\"\nint kept;\n";
        let out = strip_system_headers(input);
        assert_eq!(out, "int kept;\n");
    }

    #[test]
    fn strip_non_marker_hash_line_is_kept() {
        // A line that starts with '#' but is not a gcc line marker (e.g. a
        // stray preprocessor-shaped comment or pragma survivor) must be kept
        // like any other line once inside project code.
        let input = "# 1 \"proj.c\"\n#pragma weird\nint x;\n";
        let out = strip_system_headers(input);
        assert_eq!(out, "#pragma weird\nint x;\n");
    }

    #[test]
    fn strip_system_header_lines_are_dropped_project_lines_kept() {
        let input = concat!(
            "# 1 \"proj.c\"\n",
            "int a;\n",
            "# 1 \"/usr/include/stdio.h\" 1\n",
            "int leaked_from_libc;\n",
            "# 5 \"proj.c\" 2\n",
            "int b;\n",
        );
        let out = strip_system_headers(input);
        assert_eq!(out, "int a;\nint b;\n");
    }

    #[test]
    fn strip_builtin_and_stdc_predef_are_system() {
        let input = concat!(
            "# 1 \"<built-in>\"\n",
            "int leaked1;\n",
            "# 1 \"/some/path/stdc-predef.h\"\n",
            "int leaked2;\n",
            "# 1 \"proj.c\"\n",
            "int kept;\n",
        );
        let out = strip_system_headers(input);
        assert_eq!(out, "int kept;\n");
    }

    // ---- F-3: sanitize_decompiled_c ----------------------------------------

    #[test]
    fn sanitize_empty_input() {
        assert_eq!(sanitize_decompiled_c(""), "");
    }

    #[test]
    fn sanitize_in_body_array_decl_is_untouched() {
        let input = "void f(void) {\n    char buf[16];\n}\n";
        assert_eq!(sanitize_decompiled_c(input), input);
    }

    #[test]
    fn sanitize_line_start_aggregate_return_is_rewritten() {
        let input = "int [4] foo(int a)\n{\n    return a;\n}\n";
        let out = sanitize_decompiled_c(input);
        assert_eq!(out, "int foo(int a)\n{\n    return a;\n}\n");
    }

    #[test]
    fn sanitize_register_annotation_is_stripped() {
        let input = "int foo(void) @ rax\n{\n    return 1;\n}\n";
        let out = sanitize_decompiled_c(input);
        assert_eq!(out, "int foo(void)\n{\n    return 1;\n}\n");
    }

    #[test]
    fn sanitize_unsigned_int128_becomes_unsigned_long_long_not_triple_long() {
        let input = "unsigned __int128 x;\n__int128 y;\n";
        let out = sanitize_decompiled_c(input);
        assert_eq!(out, "unsigned long long x;\nlong long y;\n");
        assert!(!out.contains("long long long"));
    }

    #[test]
    fn sanitize_applies_control_byte_escaping_last() {
        let input = "char *s = \"\x01\";\n";
        let out = sanitize_decompiled_c(input);
        assert_eq!(out, "char *s = \"\\x01\";\n");
    }

    // ---- Dialect ------------------------------------------------------------

    #[test]
    fn dialect_preprocessed_runs_strip_system_headers() {
        let input = "# 1 \"proj.c\"\nint a;\n";
        assert_eq!(
            Dialect::Preprocessed(input).normalize(),
            strip_system_headers(input)
        );
    }

    #[test]
    fn dialect_decompiled_runs_sanitize_decompiled_c() {
        let input = "int [4] foo(void) @ rax\n{ return 0; }\n";
        assert_eq!(
            Dialect::Decompiled(input).normalize(),
            sanitize_decompiled_c(input)
        );
    }

    // ---- Real-file byte-exact comparison against the Python reference -------
    //
    // These files live outside the repository (a materialized DecBench
    // corpus) and the comparison shells out to a Python venv that also lives
    // outside the repository, so this is `#[ignore]`d: it never runs under
    // the plain `cargo test` gate, and it skips (rather than fails) when
    // either path is absent, per REQ instructions. Run explicitly with
    // `cargo test --features python-ext --lib csource::normalize:: -- --ignored`.
    #[test]
    #[ignore = "needs the materialized decbench-full tree and a decbench Python venv, both outside this repo"]
    fn sanitize_decompiled_c_matches_python_reference_on_real_files() {
        let decbench_dir = "/nas4/data/workspace-infosec/decbench";
        let python = PathBuf::from(decbench_dir).join(".venv/bin/python");
        let corpus_dir = Path::new(&std::env::var("HOME").unwrap_or_default())
            .join(".cache/glaurung/decbench-full/tree/O0/zlib/decompiled");

        if !python.is_file() || !corpus_dir.is_dir() {
            eprintln!(
                "skipping: python venv ({}) or corpus dir ({}) not present",
                python.display(),
                corpus_dir.display()
            );
            return;
        }

        let mut files: Vec<PathBuf> = std::fs::read_dir(&corpus_dir)
            .expect("read corpus dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("c"))
            .collect();
        files.sort();
        files.truncate(5);
        assert!(!files.is_empty(), "expected at least one .c fixture");

        let mut compared = 0usize;
        for file in &files {
            let rust_input = std::fs::read_to_string(file).expect("read fixture");
            let rust_out = sanitize_decompiled_c(&rust_input);

            let script = "import sys; sys.path.insert(0, sys.argv[2]); \
from decbench.utils.cfg import sanitize_decompiled_c; \
print(sanitize_decompiled_c(open(sys.argv[1]).read()), end='')";
            let output = Command::new(&python)
                .arg("-c")
                .arg(script)
                .arg(file)
                .arg(decbench_dir)
                .output()
                .expect("run python reference");
            assert!(
                output.status.success(),
                "python reference failed for {}: {}",
                file.display(),
                String::from_utf8_lossy(&output.stderr)
            );
            let python_out = String::from_utf8(output.stdout).expect("python stdout is utf-8");

            assert_eq!(rust_out, python_out, "byte mismatch for {}", file.display());
            compared += 1;
        }
        eprintln!("compared {compared} files byte-for-byte against the Python reference");
    }
}
