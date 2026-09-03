//! Criterion benchmarks for the C source front end.
//!
//! Spec: `docs/design/source-front-ends/benchmarks.md` §3.1 (these lanes),
//! §3.2 (the memory report below), §7 (reporting rules). Read that document
//! before touching this file — it explains why coverage outranks throughput
//! here and what "the corpora" means; this file only implements §3.1's
//! throughput axis.
//!
//! Following the two-tier convention `benches/ir_lift.rs` established:
//!
//! * **Micro** (`source_parse/lex/<shape>`) lexes one hand-cut window per
//!   benchmark, each isolating the scan path one lexer shape stresses:
//!   identifier scanning, number scanning, string/escape scanning, comment
//!   skipping, and the punctuator dispatch a deeply-parenthesized expression
//!   hammers. A regression that is invisible in an aggregate throughput
//!   number — say, a quadratic blow-up added only to `scan_string`, or an
//!   extra branch on every punctuator — shows up in exactly one of these and
//!   nowhere else. The windows are byte ranges cut verbatim out of real
//!   fixture files, never hand-typed C, per this repo's standing rule that a
//!   benchmark input is the format the component actually takes.
//! * **Realistic** (`source_parse/lex/corpus`) tokenizes whole files: the
//!   largest few under `tests/decompiler_fixtures/src/`, which are committed
//!   and therefore present on every machine that can build this crate. This
//!   is the shape `tokenize` is actually called on — one call per
//!   translation unit — so it is what the throughput number quoted anywhere
//!   outside this file should come from.
//!
//! A third, **optional** lane (`source_parse/lex/corpus_decompiled`) runs the
//! same tokenizer over the real decompiled-C corpus benchmarks.md §2
//! describes as the adversarial, ill-formed input that actually exercises
//! recovery — the ten largest `.c` artifacts under
//! `~/.cache/glaurung/decbench-full/tree/O0/zlib/decompiled/`. That tree is a
//! ~1.1 GB DecBench materialization, not part of this repository, and is
//! absent on most machines including CI, so this lane degrades to a skip
//! with a printed note rather than a failure when the directory is missing —
//! the same discipline `tests/source_cfg_ged.rs` uses for the same corpus.
//! **`cargo bench --bench source_parse` must complete without this tree**;
//! that is the property the smoke-mode verification below exercises.
//!
//! # What is not here, and why
//!
//! `source_parse/parse/<shape>`, `source_parse/parse/corpus` and
//! `source_parse/cfg/corpus` — the other three lanes benchmarks.md §3.1
//! specifies — are absent because `src/csource/parse/` does not exist yet; it
//! is being written concurrently with this file. Nothing here references it,
//! stubs it, or waits for it. When it lands, add the parser lanes as two more
//! `criterion_group!` entries reusing the plumbing already here:
//!
//! * `MICRO_WINDOWS` and `largest_c_files`/`sorted_c_files` are the same
//!   inputs a parser benchmark wants — re-tokenize each window with
//!   [`tokenize`] and feed the resulting [`Tokens`] to the parser's entry
//!   point, the same way `bench_lex_micro`/`bench_lex_corpus` do here for the
//!   lexer;
//! * `source_parse/parse/<shape>` wants its own shapes per benchmarks.md
//!   (`expression-heavy`, `statement-heavy`, `declaration-heavy`) rather than
//!   reusing the lexer's five — cut those from the same corpus files the same
//!   way `LEX_*` was cut below;
//! * `source_parse/cfg/corpus` times event→CFG construction with parsing
//!   excluded, so it needs the parse step done as setup outside `b.iter`,
//!   exactly like `ir_lift.rs`'s `analyze_functions_image` is run once before
//!   `lift_function_from_image` is timed;
//! * the optional decompiled-corpus lane's skip pattern
//!   (`decompiled_corpus_dir`, the `eprintln!` note) should be reused
//!   verbatim rather than re-derived — that is the exact failure mode this
//!   module doc warns about.
//!
//! # Memory (benchmarks.md §3.2)
//!
//! `report_memory_footprint` is not a criterion lane — there is nothing to
//! time, only to count — so it runs once as plain setup (inside
//! `bench_memory_footprint`, first in the group list below) and prints to
//! stdout. It measures the struct-of-arrays token buffer
//! (`glaurung::syntax::token::Tokens`: a `Vec<u16>` of kinds parallel to a
//! `Vec<u32>` of starts) against the array-of-structs control the module doc
//! on `Tokens` argues from — `size_of::<(u16, u32)>()` — over the whole
//! fixture corpus. Per this repo's reporting rule, the number is measured
//! here rather than restated from the design doc: that doc's own figure was
//! corrected once already (37.5% → 25%) the first time someone actually ran
//! it, which is the argument for never writing one down without the command
//! next to it.
//!
//! Per-byte and per-token throughput (ns/token, MiB/s) are deliberately
//! **not** written down in this doc comment, for the same reason: they are
//! criterion output, drift on every commit, and depend on which machine and
//! which build (`maturin develop` is debug; a release throughput number needs
//! `--release`). Read them from `cargo bench --bench source_parse`'s own
//! report — `target/criterion/source_parse/lex/**/report/index.html` — or
//! its stdout, not from here.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};

use glaurung::csource::lex::tokenize;

/// The crate root, resolved at compile time so these benchmarks find the
/// fixture corpus regardless of `cargo bench`'s working directory.
const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

// ---------------------------------------------------------------------------
// Micro windows -- hand-cut from real corpus files, never synthesized.
// ---------------------------------------------------------------------------

/// Dense identifiers: `tests/decompiler_fixtures/src/95_function_pointer_table.c`,
/// verbatim, in full (40 lines). Five distinctly-named static functions, a
/// typedef, a five-element dispatch table and two callers — almost entirely
/// identifier and keyword tokens, with the punctuators and few numeric
/// literals a real declaration carries. A regression in `scan_identifier` or
/// in the keyword table lookup that follows every identifier scan shows up
/// here first, because this window spends more of its bytes in that path
/// than any other.
const LEX_DENSE_IDENTIFIERS: &str = r#"#include <stdint.h>

/* An array of function pointers is an indirect call whose target is a loaded
 * value, not a relocation. Recovering the dispatch means recovering the table's
 * contents, its stride, and the bounds check that guards it. */

static int32_t op_add(int32_t a, int32_t b) { return (int32_t)((uint32_t)a + (uint32_t)b); }
static int32_t op_sub(int32_t a, int32_t b) { return (int32_t)((uint32_t)a - (uint32_t)b); }
static int32_t op_and(int32_t a, int32_t b) { return a & b; }
static int32_t op_xor(int32_t a, int32_t b) { return a ^ b; }
static int32_t op_max(int32_t a, int32_t b) { return a > b ? a : b; }

typedef int32_t (*BinaryOp)(int32_t, int32_t);

static BinaryOp const OPERATIONS[5] = {op_add, op_sub, op_and, op_xor, op_max};

__attribute__((noinline)) int32_t
dispatch_operation(int32_t which, int32_t a, int32_t b) {
    if (which < 0 || which >= 5) {
        return -1;
    }
    return OPERATIONS[which](a, b);
}

__attribute__((noinline)) int32_t
fold_operations(const int32_t *selectors, int32_t count, int32_t seed) {
    int32_t accumulator = seed;
    int32_t index;
    if (selectors == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        int32_t which = selectors[index];
        if (which < 0 || which >= 5) {
            continue;
        }
        accumulator = OPERATIONS[which](accumulator, index + 1);
    }
    return accumulator;
}
"#;

/// Dense numeric literals: `tests/decompiler_fixtures/src/155_long_dependency_chain.c`,
/// lines 1-60. A 320-step arithmetic chain whose body is almost entirely
/// `0x`-prefixed 32-bit hex constants with a `u` suffix, one per operator. A
/// regression in `scan_number` — a dropped suffix check, a hex-digit table
/// that stops early, a widened float-vs-int decision — costs the most cycles
/// of any shape on exactly this input.
const LEX_DENSE_NUMERIC_LITERALS: &str = r#"#include <stdint.h>

/* Scale stress: dependency-chain length.
 *
 * `chain155_scalar` is 320 arithmetic steps in a row, each one consuming
 * the result of the previous one. There is no parallelism to find and no
 * loop to roll up: the value at the end depends on every step in order, so
 * a single dropped, reordered or width-truncated step changes the answer.
 * Expression-tree builders that grow a term per step, and simplifiers that
 * try to normalise the whole chain, are quadratic here.
 *
 * `chain155_signed` runs 256 steps through an int32_t carrier with every
 * operation routed through uint32_t, so the widths keep changing while the
 * arithmetic stays defined. `chain155_buffered` threads 192 steps through a
 * 16-slot snapshot of a caller-owned buffer.
 *
 * Shift counts are constants in 1..31 and all wrapping goes through
 * unsigned, so nothing here is undefined. */

#define CHAIN155_SLOTS 16
#define CHAIN155_SCALAR_STEPS 320
#define CHAIN155_SIGNED_STEPS 256
#define CHAIN155_BUFFER_STEPS 192

__attribute__((noinline)) uint32_t chain155_scalar(uint32_t value) {
    uint32_t acc = value ^ 0x9E3779B9u;

    acc = acc * 1103515245u + 0x9E3779B1u;
    acc ^= acc >> 2u;
    acc = (acc << 3u) | (acc >> 29u);
    acc += 0x78DDE6C4u;
    acc ^= 0x17156075u;
    acc = (acc >> 6u) + (acc << 26u);
    acc = acc * 1103515413u + 0x538453D7u;
    acc ^= acc >> 8u;
    acc = (acc << 9u) | (acc >> 23u);
    acc += 0x2E2AC0EAu;
    acc ^= 0xCC623A9Bu;
    acc = (acc >> 12u) + (acc << 20u);
    acc = acc * 1103515581u + 0x08D12DFDu;
    acc ^= acc >> 14u;
    acc = (acc << 15u) | (acc >> 17u);
    acc += 0xE3779B10u;
    acc ^= 0x81AF14C1u;
    acc = (acc >> 18u) + (acc << 14u);
    acc = acc * 1103515749u + 0xBE1E0823u;
    acc ^= acc >> 20u;
    acc = (acc << 21u) | (acc >> 11u);
    acc += 0x98C47536u;
    acc ^= 0x36FBEEE7u;
    acc = (acc >> 24u) + (acc << 8u);
    acc = acc * 1103515917u + 0x736AE249u;
    acc ^= acc >> 26u;
    acc = (acc << 27u) | (acc >> 5u);
    acc += 0x4E114F5Cu;
    acc ^= 0xEC48C90Du;
    acc = (acc >> 30u) + (acc << 2u);
    acc = acc * 1103516085u + 0x28B7BC6Fu;
    acc ^= acc >> 1u;
    acc = (acc << 2u) | (acc >> 30u);
"#;

/// String-heavy: `tests/decompiler_fixtures/src/116_string_literals.c`,
/// verbatim, in full (48 lines). String and character literals, adjacent
/// literal concatenation, and `\t\n\\\0X` — an escape run ending in a NUL
/// escape before more characters follow, which is exactly the case
/// `scan_string`'s escape handling must not treat as an early terminator. A
/// regression in string or escape scanning is disproportionately expensive
/// here because so much of the byte count sits inside `"..."` and `'...'`.
const LEX_STRING_HEAVY: &str = r#"#include <stdint.h>

/* String literals: adjacent literals concatenate at translation phase 6, the
 * terminating NUL is part of the object, and sizeof counts it while a length
 * scan does not. The literal itself lands in read-only data. */

__attribute__((noinline)) int32_t literal_size_versus_length(void) {
    static const char greeting[] = "abc" "def";
    int32_t length = 0;
    while (greeting[length] != '\0') {
        length += 1;
    }
    return (int32_t)sizeof(greeting) * 100 + length;
}

__attribute__((noinline)) int32_t literal_index(int32_t index) {
    if (index < 0 || index > 5) {
        return -1;
    }
    return (int32_t)"HELLO!"[index];
}

__attribute__((noinline)) int32_t
count_matching(const uint8_t *text, int32_t length, int32_t target) {
    static const char vowels[] = "aeiou";
    int32_t matches = 0;
    int32_t index;
    int32_t vowel;
    if (text == 0 || length < 0 || length > 16) {
        return -1;
    }
    for (index = 0; index < length; ++index) {
        for (vowel = 0; vowel < 5; ++vowel) {
            if ((int32_t)text[index] == (int32_t)(uint8_t)vowels[vowel]) {
                matches += 1;
            }
        }
    }
    return matches + (target != 0);
}

__attribute__((noinline)) int32_t escape_sequences(int32_t which) {
    static const char escapes[] = "\t\n\\\0X";
    if (which < 0 || which > 4) {
        return -1;
    }
    return (int32_t)escapes[which];
}
"#;

/// Comment-heavy: `tests/decompiler_fixtures/src/02_integer_widths.c`, lines
/// 1-70. A block comment file header followed by a `/* ... */` doc comment
/// above almost every function, plus trailing `/* == x & 0xFF */`-style
/// line-end comments. Trivia is skipped, not tokenized
/// (`src/csource/lex/mod.rs`'s module doc), so this window spends most of its
/// bytes in `skip_trivia`'s block-comment arm rather than in `lex_one` at
/// all — a regression there (quadratic rescanning, an off-by-one on `*/`)
/// costs the most exactly here.
const LEX_COMMENT_HEAVY: &str = r#"/* 02_integer_widths.c
 *
 * Integer width / signedness fixture. Every function is a pure integer function
 * whose result depends on the EXACT bit width and signedness of the operations
 * a correct decompilation must recover. A width- or sign-broken lowering
 * (dropped 32-bit zero-extension, `>>` on the wrong signedness, a missing
 * truncation mask, a sign-extend where a zero-extend belonged) sends the return
 * value to a different constant, which an execution-differential test catches.
 *
 * Targets review #2 (integer width & sign). Keep every function pure (no
 * globals, no memory beyond passed-in pointers, no libc) and deterministic in
 * its integer arguments. Every function returns an int that differs between a
 * correct and a width-broken lowering.
 */
#include <stdint.h>

/* --- round-trips through each unsigned width --------------------------- */

/* uint8_t round-trip: value must survive an 8-bit store/load, i.e. be masked
 * to the low byte. A decompiler that widens the temporary loses the & 0xFF. */
int rt_u8(unsigned x) {
    uint8_t v = (uint8_t)x;
    return (int)v;                 /* == x & 0xFF */
}

/* uint16_t round-trip. */
int rt_u16(unsigned x) {
    uint16_t v = (uint16_t)x;
    return (int)v;                 /* == x & 0xFFFF */
}

/* uint32_t round-trip: return the full 32-bit value as a signed int. */
int rt_u32(unsigned x) {
    uint32_t v = (uint32_t)x;
    return (int)v;
}

/* uint64_t round-trip: pack a value into 64 bits, fold the halves back to an
 * int. If the high 32 bits are dropped the fold changes. */
int rt_u64(unsigned x) {
    uint64_t v = ((uint64_t)x << 20) | (uint64_t)x;
    return (int)((v >> 20) ^ (v & 0xFFFFFF));
}

/* --- sign extension ---------------------------------------------------- */

/* Return an int8_t param as int: the top bit must sign-extend. For x=0xFF the
 * result is -1, not 255. A zero-extend here is the classic bug. */
int sext_i8(int x) {
    int8_t v = (int8_t)x;
    return (int)v;
}

/* Sign-extend a 16-bit quantity. */
int sext_i16(int x) {
    int16_t v = (int16_t)x;
    return (int)v;
}

/* --- zero extension of architecture-defined 32-bit writes -------------- */

/* Write a 32-bit value into a 64-bit register: on x86-64 a 32-bit write
 * zero-extends the full 64-bit register. Compute in 64 bits and mask so the
 * value is unambiguous; a lowering that treats the write as sign-extending or
 * leaves the high bits dirty produces a different masked result. */
int zext_u32_to_u64(uint32_t x) {
    uint64_t r = x;                /* zero-extended by definition */
    r += 0x100000000ULL;           /* deposit into the high word */
    return (int)(r >> 32);         /* == 1 for every x if zero-extended */
}
"#;

/// Deeply nested parentheses: `tests/decompiler_fixtures/src/131_obfuscated_composite.c`,
/// verbatim, in full (34 lines). `nested_conditional_matrix`'s return
/// statement alone is eight levels of nested ternary and parens; the rest of
/// the file adds a statement-expression macro (`({ ... })`) and cast-heavy
/// expressions on top. This is the punctuator-dispatch shape: nearly every
/// other byte is `(` or `)`, so a regression in `punctuator`'s longest-match
/// dispatch (see its doc comment on why it is hand-written rather than
/// table-driven) shows up here, not in the identifier- or number-heavy
/// windows above.
const LEX_DEEPLY_NESTED_PARENS: &str = r#"#include <stdint.h>

/* An IOCCC-flavoured composition of everything this batch covers: a
 * function-pointer table indexed by a bit trick, a comma-operator loop header,
 * a statement expression, reversed subscripts, and a nested conditional. Dense
 * on purpose, and fully defined throughout. */

static int32_t twist(int32_t v) { return (int32_t)(((uint32_t)v << 3) ^ 0x9E37u); }
static int32_t fold(int32_t v) { return (int32_t)(((uint32_t)v >> 2) + 0x1234u); }

typedef int32_t (*Stage)(int32_t);
static Stage const STAGES[2] = {twist, fold};

#define PICK(v) ({ int32_t _v = (v); STAGES[(_v & 1)](_v); })

__attribute__((noinline)) int32_t
obfuscated_pipeline(int32_t *state, int32_t count, int32_t seed) {
    int32_t i;
    int32_t acc = seed;
    int32_t last = 0;
    if (state == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (i = 0; i < count; last = acc, acc = PICK(acc), i[state] = acc, ++i) {
        acc ^= (i & 3) ? (i << 1) : ~i;
    }
    return count ? ((count - 1)[state] ^ last) : acc;
}

__attribute__((noinline)) int32_t
nested_conditional_matrix(int32_t a, int32_t b, int32_t c, int32_t d) {
    return (a < b) ? ((c < d) ? ((a < c) ? a : c) : ((a < d) ? a : d))
                   : ((c < d) ? ((b < c) ? b : c) : ((b < d) ? b : d));
}
"#;

/// The five micro shapes, as `(bench id, window text)`.
const MICRO_WINDOWS: &[(&str, &str)] = &[
    ("dense-identifiers", LEX_DENSE_IDENTIFIERS),
    ("dense-numeric-literals", LEX_DENSE_NUMERIC_LITERALS),
    ("string-heavy", LEX_STRING_HEAVY),
    ("comment-heavy", LEX_COMMENT_HEAVY),
    ("deeply-nested-parens", LEX_DEEPLY_NESTED_PARENS),
];

fn bench_lex_micro(c: &mut Criterion) {
    let mut group = c.benchmark_group("source_parse/lex");
    for &(shape, text) in MICRO_WINDOWS {
        let parsed = tokenize(text);
        assert!(
            !parsed.value().is_empty(),
            "source_parse: window {shape} produced no tokens"
        );
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_function(shape, |b| b.iter(|| tokenize(black_box(text))));
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Corpus helpers -- shared by the realistic lane and the memory report.
// ---------------------------------------------------------------------------

/// Every `.c` file directly under `dir`, sorted by path.
///
/// Sorted rather than left in `read_dir` order, which is filesystem-defined
/// and not stable across machines or even across two runs on the same one —
/// an unsorted listing would make this benchmark measure a different corpus
/// every time, which is exactly the determinism trap benchmarks.md §3.5
/// exists to catch in the substrate itself.
fn sorted_c_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "c"))
        .collect();
    files.sort();
    files
}

/// The `limit` largest `.c` files directly under `dir`, largest first.
///
/// Ties break on path (via the stable sort over [`sorted_c_files`]'s already
/// sorted input), so the selection is deterministic even if two files in the
/// corpus happen to be exactly the same size.
fn largest_c_files(dir: &Path, limit: usize) -> Vec<PathBuf> {
    let mut files = sorted_c_files(dir);
    files.sort_by_key(|path| std::cmp::Reverse(fs::metadata(path).map(|m| m.len()).unwrap_or(0)));
    files.truncate(limit);
    files
}

/// Read `path` as text, tolerating non-UTF-8 bytes the way a decompiled
/// artifact can contain them.
///
/// Matches [`tokenize`]'s own contract (`src/csource/lex/mod.rs`'s module
/// doc): the lexer takes `&str`, and a caller reading bytes off disk is the
/// one responsible for the lossy conversion.
fn read_c_file(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_default();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// How many of the largest fixture files the realistic lane tokenizes.
///
/// "The largest few" per benchmarks.md §3.1; eight keeps the group's total
/// run time comparable to one micro-window group's while still spanning the
/// size range in `tests/decompiler_fixtures/src/` (784 bytes to 66 KB).
const REALISTIC_CORPUS_FILES: usize = 8;

/// `source_parse/lex/corpus` -- tokenize whole files, the shape `tokenize` is
/// actually called in: once per translation unit, not once per hand-cut
/// window. Sourced from `tests/decompiler_fixtures/src/` specifically (not
/// `tests/decbench_corpus/src/`, and not the external decompiled corpus
/// below) because that directory is committed and therefore guaranteed
/// present wherever this crate builds — this lane must never skip.
fn bench_lex_corpus(c: &mut Criterion) {
    let dir = Path::new(MANIFEST_DIR).join("tests/decompiler_fixtures/src");
    let files = largest_c_files(&dir, REALISTIC_CORPUS_FILES);
    if files.is_empty() {
        eprintln!(
            "source_parse: skipping source_parse/lex/corpus -- no .c files found under {}",
            dir.display()
        );
        return;
    }
    let mut group = c.benchmark_group("source_parse/lex/corpus");
    for path in &files {
        let text = read_c_file(path);
        let parsed = tokenize(&text);
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
        assert!(
            !parsed.value().is_empty(),
            "source_parse: corpus file {stem} produced no tokens"
        );
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_function(stem, |b| b.iter(|| tokenize(black_box(&text))));
    }
    group.finish();
}

/// The real decompiled-C corpus's directory, or `None` when this machine has
/// no materialized DecBench tree.
///
/// Mirrors `tests/source_cfg_ged.rs`'s `tree()`: read from the filesystem
/// rather than asserted, because the ~1.1 GB tree is not part of this
/// repository and most machines — including CI — do not have it.
fn decompiled_corpus_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let dir = PathBuf::from(home).join(".cache/glaurung/decbench-full/tree/O0/zlib/decompiled");
    dir.is_dir().then_some(dir)
}

/// `source_parse/lex/corpus_decompiled` -- the same tokenizer over the
/// corpus benchmarks.md §2 calls "robustness and throughput: adversarial,
/// ill-formed, and the input that actually matters". Optional and additive:
/// the required realistic lane is [`bench_lex_corpus`] above, which never
/// depends on this tree. When the tree is absent this prints a note and adds
/// no benchmarks, which is what keeps `cargo bench --bench source_parse`
/// runnable on a machine that has never run DecBench.
fn bench_lex_corpus_decompiled(c: &mut Criterion) {
    let Some(dir) = decompiled_corpus_dir() else {
        eprintln!(
            "source_parse: skipping source_parse/lex/corpus_decompiled -- \
             ~/.cache/glaurung/decbench-full is not materialized on this machine \
             (see docs/design/source-front-ends/benchmarks.md §2)"
        );
        return;
    };
    let files = largest_c_files(&dir, 10);
    if files.is_empty() {
        eprintln!(
            "source_parse: skipping source_parse/lex/corpus_decompiled -- no .c files found under {}",
            dir.display()
        );
        return;
    }
    let mut group = c.benchmark_group("source_parse/lex/corpus_decompiled");
    for path in &files {
        let text = read_c_file(path);
        // Unlike the fixture corpus, decompiled output is not guaranteed to
        // tokenize cleanly -- that is the point of measuring it -- so this
        // lane does not assert on the result, only times it.
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_function(stem, |b| b.iter(|| tokenize(black_box(&text))));
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Memory (benchmarks.md §3.2) -- a count, not a timing, so it is not a
// criterion lane. Runs once as plain setup and prints to stdout.
// ---------------------------------------------------------------------------

/// Directories making up the fixture corpus's correctness floor
/// (benchmarks.md §2): committed, clean, and always present.
fn fixture_corpus_dirs() -> [PathBuf; 2] {
    [
        Path::new(MANIFEST_DIR).join("tests/decompiler_fixtures/src"),
        Path::new(MANIFEST_DIR).join("tests/decbench_corpus/src"),
    ]
}

/// Tokenize the whole fixture corpus and print the struct-of-arrays token
/// buffer's footprint against the array-of-structs control, in total bytes
/// and per KLOC, per benchmarks.md §3.2.
///
/// `Tokens` (`src/syntax/token.rs`) keeps `kinds: Vec<u16>` parallel to
/// `starts: Vec<u32>` rather than one `Vec<(u16, u32)>`, both fields private.
/// [`glaurung::syntax::token::Tokens::len`] is public and excludes the
/// sentinel the buffer always carries, so the entry count used here is
/// `len() + 1` per file -- reconstructing exactly `kinds.len()` (== `starts.
/// len()`) without needing access to the private fields themselves.
fn report_memory_footprint() {
    let mut files = 0u64;
    let mut total_lines = 0u64;
    let mut total_entries = 0u64;
    for dir in fixture_corpus_dirs() {
        for path in sorted_c_files(&dir) {
            let text = read_c_file(&path);
            total_lines += text.lines().count() as u64;
            let parsed = tokenize(&text);
            total_entries += parsed.value().len() as u64 + 1;
            files += 1;
        }
    }
    if files == 0 || total_lines == 0 {
        eprintln!("source_parse: memory footprint report skipped -- no fixture corpus found");
        return;
    }

    let kloc = total_lines as f64 / 1000.0;
    // `kinds.len() * 2 + starts.len() * 4`: the struct-of-arrays buffer this
    // measures, reconstructed from the public entry count above.
    let soa_bytes = total_entries * 2 + total_entries * 4;
    // `size_of::<(u16, u32)>() * n`: the array-of-structs control -- a u32
    // wants 4-byte alignment, so the tuple pads to 8 bytes rather than the 6
    // its fields need, which is the padding the struct-of-arrays layout buys
    // back.
    let aos_bytes = total_entries * (std::mem::size_of::<(u16, u32)>() as u64);
    let savings_pct = 100.0 * (1.0 - soa_bytes as f64 / aos_bytes as f64);

    println!(
        "source_parse: memory report over {files} fixture files, {total_lines} lines \
         ({kloc:.3} KLOC), {total_entries} token-buffer entries (incl. one EOF sentinel/file)"
    );
    println!(
        "source_parse: struct-of-arrays (kinds:Vec<u16> + starts:Vec<u32>) = {soa_bytes} bytes \
         = {:.1} bytes/KLOC",
        soa_bytes as f64 / kloc
    );
    println!(
        "source_parse: array-of-structs control (Vec<(u16, u32)>, size_of = {}) = {aos_bytes} \
         bytes = {:.1} bytes/KLOC",
        std::mem::size_of::<(u16, u32)>(),
        aos_bytes as f64 / kloc
    );
    println!(
        "source_parse: struct-of-arrays saves {savings_pct:.1}% over the array-of-structs control"
    );
}

/// Registered first in [`criterion_group!`] below purely so its stdout lands
/// near the top of a `cargo bench` run. It adds no criterion benchmarks of
/// its own -- see [`report_memory_footprint`].
fn bench_memory_footprint(_c: &mut Criterion) {
    report_memory_footprint();
}

criterion_group!(
    benches,
    bench_memory_footprint,
    bench_lex_micro,
    bench_lex_corpus,
    bench_lex_corpus_decompiled,
);
criterion_main!(benches);
