# Fixtures & Corpus Policy

Per `CLAUDE.md`: **real binaries only** for analysis tests — no mock fixtures or
fabricated analysis output without explicit permission. Sources: `samples/`,
`tests/`, `tests/fixtures/`.

## Corpus kinds

| Corpus | Purpose | Determinism |
|---|---|---|
| **Generated instruction streams** | per-arch differential coverage (Phase 1–2) | seeded generator; committed artifact |
| **Real function slices** (`samples/`) | function-level emulation (Phase 1–3) | real bytes; fixed VA + initial state |
| **Library-calling functions** | OS/SimProcedure coverage (Phase 3) | real ELF/PE |
| **Constraint fixtures** | solver/concolic (Phase 4) | tiny hand-written or compiled-from-source-with-recorded-source |
| **Vulnerable-driver fixture** | IOCTL sink-finding (Phase 5/7) | a real driver with a known sink |
| **Decryption samples** | string-decrypt (Phase 7) | real obfuscated binary + recorded expected plaintext |

## Rules

- **No fabricated CPU state as the system-under-test.** Hand-constructed *initial*
  register/memory state to *set up* a real instruction stream is fine (it's the
  test input); the *binary/instructions being executed* must be real.
- **Generated instruction corpora** are acceptable because they exercise the real
  decoder+lifter+interpreter on real encodings; the generator is seeded and its
  output is committed so it's reviewable and reproducible — not "fake data", a
  deterministic test vector.
- **Expected values** for decryption/witness tests are recorded from a trusted
  source (the real decrypted output, or a known-good run) and committed alongside
  the fixture.
- **Minimal reproducers** from oracle divergences are committed as permanent
  regression tests.

## Layout (proposed)

```
tests/fixtures/exec/
├── corpus/x86_64/…           # seeded generated streams (committed)
├── corpus/arm64/…
├── slices/                   # real function slices + expected outputs
├── constraints/              # solver fixtures + expected models
├── decrypt/                  # obfuscated samples + expected plaintext
└── drivers/                  # vulnerable-driver fixture + expected witness
```

## Scorecard integration

`uv run python -m glaurung.bench` gains metrics: strings-recovered (7.1) and
indirect-edges-resolved (7.2) over a fixed sample set, so engine improvements are
tracked numerically across commits.
