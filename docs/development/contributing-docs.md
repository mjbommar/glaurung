# Contributing documentation

> **Kind:** guide · **Status:** maintained

How this documentation tree is organized, what the tests enforce, and the
evidence rules a document has to meet before it is written.

## Every document declares its kind

Line 3 of every live document under `docs/` is a single declaration:

```markdown
> **Kind:** guide · **Status:** maintained
```

Files under `docs/history/` declare a date instead of a status:

```markdown
> **Kind:** record · **Date:** 2026-09-02
```

`python/tests/test_docs_manifest.py` enforces the vocabulary and its presence.
It never asserts a *fact* about the code. That distinction is the whole point:
the tests this one replaced pinned literal prose, including a sentence saying a
build was failing, which meant the suite required a document to stay wrong
after the build had been fixed.

### Kinds, and where each lives

| Kind | What it is | Where it lives |
|---|---|---|
| `guide` | task-oriented instructions for a person doing something | `tutorial/`, `guides/`, `development/` |
| `reference` | a fact table: flags, variables, features, passes | `reference/` |
| `architecture` | how the code is actually built, written from source | `architecture/` |
| `decision` | one decision, its alternatives, and why they lost | `decisions/` |
| `design` | a live proposal for something not built yet | `design/` |
| `plan` | a work order with phases and gates | `development/roadmap/`, plan files under `development/` |
| `record` | dated evidence from a moment in time | `history/` only |

### Statuses

| Status | Meaning |
|---|---|
| `maintained` | someone keeps this true; report it when it is not |
| `generated` | produced by a tool in `tools/`; edit the tool, not the file |
| `proposed` | describes intended work, not shipped behavior |

### `history/` is never guidance

`docs/history/` is read-only evidence. Nothing under `docs/README.md` or
`docs/tutorial/` links into it as instruction, and a record is never revised to
become current — a superseding document is written instead.

To add one:

1. Put the file under the right dated topic directory in `docs/history/`.
2. Open it with `> **Kind:** record · **Date:** YYYY-MM-DD`.
3. Add one row to `docs/history/README.md` naming the file, what it recorded,
   and what superseded it.

`test_docs_manifest.py` fails when a history file is missing its record banner,
its date, or its index row.

## Generated reference pages

A table that drifts should be produced from the code that owns it. Each
generator follows the same convention, established by `tools/gen_native_stub.py`:

- it writes exactly one file and owns the whole of it;
- it takes `--check`, which exits non-zero when the checked-in file is stale;
- a test in `python/tests/` runs `--check`, so staleness is a red suite rather
  than a surprise.

| Tool | Writes | Reads |
|---|---|---|
| `tools/gen_native_stub.py` | `python/glaurung/_native/*.pyi` | the built extension module |
| `tools/gen_cli_reference.py` | `docs/reference/cli.md` | `cli/main.py`'s registry plus each command's parser help |
| `tools/gen_env_reference.py` | `docs/reference/environment-variables.md` | `os.environ` / `getenv` / `env::var` / `option_env!` across `python/`, `src/`, `tools/`, `scripts/`, `.github/` |
| `tools/gen_feature_reference.py` | `docs/reference/cargo-features.md` | `Cargo.toml` `[features]`, the `cfg` lines in `src/lib.rs`, `[tool.maturin]` |
| `tools/gen_provenance_reference.py` | `docs/reference/provenance.md` | `SET_BY_PRIORITY` in `python/glaurung/llm/kb/provenance.py` |
| `tools/gen_pass_reference.py` | `docs/reference/decompiler-passes.md` | the `pass!` names in `src/python_bindings/ir/pipeline.rs` and the refine chain in `decbench_render.rs` |

A generated page carries `**Status:** generated`. Do not hand-edit one; change
the code it reads, or the generator, and re-run it.

## The tests that keep the tree honest

### `python/tests/test_docs_manifest.py`

- every live `.md` under `docs/` (excluding `tutorial/_fixtures/` and
  `history/`) declares a `Kind:` from the allowed set and a `Status:` from
  `{maintained, generated, proposed}` within its first five lines;
- every file under `history/` declares `Kind: record` with a `Date:`, and
  appears in `history/README.md`;
- no live document declares itself historical in its banner zone.

### `python/tests/test_docs_links.py`

- every relative markdown link in `docs/` and in `README.md`, `CLAUDE.md` and
  `AGENTS.md` resolves to a file that exists;
- every `docs/...` string shaped like a path, appearing anywhere in `src/`,
  `python/glaurung/`, `python/tests/`, `tools/`, `scripts/`, `.github/`,
  `pytest.ini` or the three top-level files, resolves as well. Source comments
  and workflow headers cite documents by path and those citations do not move
  when the file does.

Both halves blank out fenced blocks and inline code before matching, because a
regex character class or a dispatch expression can look exactly like a markdown
link. `KNOWN_BROKEN` exists for temporary exceptions and every entry must carry
a reason; an entry that starts resolving is a failure, so the allowlist cannot
quietly become permanent.

### `scripts/verify_tutorial.py`

The tutorial is verified by execution, not by review. Every chapter is a
recipe in the `CHAPTERS` dict — a function returning `(label, command)` pairs —
and the harness runs each command against a real sample binary, merges stderr
into stdout, normalizes the result, and compares it with
`docs/tutorial/_fixtures/<chapter>/<label>.out`.

```bash
uv run python scripts/verify_tutorial.py --list                # chapter names
uv run python scripts/verify_tutorial.py --check               # compare only
uv run python scripts/verify_tutorial.py --chapter 01-install --capture
```

Facts worth knowing before touching it:

- **`--check` is the default** and never writes. `--capture` refreshes fixtures
  from a successful run; the two are mutually exclusive.
- **Fixtures map 1:1 to chapters.** Every directory under `_fixtures/` has
  exactly one recipe and every recipe has a directory. An orphan on either side
  is a bug.
- **`stable()` is the normalizer.** It strips trailing whitespace, replaces the
  repository path with `<repo>` and the scratch directory with a fixed display
  token, and blanks timestamps, elapsed-millisecond values, the Glaurung HEAD
  short SHA, and `created_at` epochs. Fixtures therefore compare across clones,
  worktrees and machines. If a new command emits something machine-specific,
  extend `stable()` rather than accepting a noisy fixture.
- **Scratch space honours `TMPDIR`**, falling back to
  `~/.cache/glaurung/tmp`. Each chapter gets a fresh `.glaurung` database so
  steps cannot bleed state.
- **`EXPECTED_RETURN_CODES` records the deliberate non-zero exits**, keyed by
  `(chapter, step)`: plain-text `detect-packer` returns 1 for a packed verdict
  and plain-text `diff` returns 1 when the binaries differ. Any other exit code
  is a failure.
- **The harness does not parse markdown.** Commands live in Python and the
  prose links to the resulting `.out` files, so prose and recipe can diverge
  silently. When you add a command to a chapter, add it to the recipe too.
- **Never hand-edit a fixture.** Regenerate with `--capture` and read the diff.

## Evidence rules

Adapted from the 2026-08-06 execution diary, and they apply to prose as much as
to a commit message:

1. Keep local tests, committed state, remote refs, and remote CI as four
   separate facts. "It passes" without saying where is not a claim.
2. Do not pair newly generated source artifacts with an old binary unless
   executable code identity is proved.
3. Do not call a metric unavailable until the current evaluator has actually
   been exercised.
4. Compare like-for-like keys against a preserved manifest, not against
   whatever the current run happened to produce.
5. Treat behavior, compilation, GED, type match, and byte match as distinct
   oracles. One being green says nothing about the others.

### Write the command next to the number

A count, percentage, or timing in a live document comes with the command that
produced it and the commit it was run at, or it is left out. Two tables in the
design tree turned out never to have been produced by any run, and both shaped
later decisions.

### No fabricated data — with one carve-out

Documentation examples use real checked-in binaries from `samples/`, `tests/`,
or `tests/fixtures/`, and real output. Do not invent output, APIs, or flags.

The carve-out is a **seeded generated corpus**: a generator whose seed is fixed
and whose output is committed is a deterministic test vector, not fake data,
because it exercises the real decoder, lifter and interpreter on real
encodings and is reviewable and reproducible. Hand-constructed *initial* state
to set up a real instruction stream is likewise fine — the input may be
constructed, the system under test may not. Expected values come from a trusted
source (real decrypted output, or a known-good run) and are committed beside
the fixture.

## Conventions

- **No dates in live filenames.** `history/` is organized by date and topic;
  everything else is named for its subject. A dated live filename ages the
  document whether or not its contents have.
- **No data or executable scripts under `docs/`.** Baselines live under
  `data/` or `tests/`, tools under `tools/`, scripts under `scripts/`. The one
  exception is `docs/tutorial/_fixtures/`, which is review evidence for the
  prose beside it.
- **One authority per fact.** When two documents disagree, the fix is deletion
  and a link, not a third document.
- **Corrections happen in the document.** Edit the sentence that is wrong; do
  not append a dated correction paragraph under it. Incidents belong in
  [traps.md](traps.md) or `history/`.
- **No sentence stating that a build or a gate is currently failing.** That
  fact expires the moment someone fixes it, and a test that pins it requires
  the document to stay wrong.
