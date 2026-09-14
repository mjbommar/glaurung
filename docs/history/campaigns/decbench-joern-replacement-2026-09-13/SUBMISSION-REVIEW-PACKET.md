# DecBench submission review packet

> **Kind:** internal review record · **Date:** 2026-09-14 · **Upstream action:** none

## Decision

The `e170a2b4` full-corpus result is strong and independently audited, but it is
**not yet a standards-compliant DecBench submission artifact**. DecBench's
documented external route remains its 250-function eval kit, its published
Glaurung column remains sample-set-only, and our full run predates DecBench's
new canonical resource-limit policy.

No DecBench issue, comment, pull request, email, upload, or repository change
was made. Contact and submission remain human-only under DecBench's rules.

## How Glaurung was previously submitted

The accepted August submission used the external eval-kit route:

1. DecBench supplied a frozen, anonymized 250-function kit spanning 224
   binaries.
2. Glaurung decompiled the requested addresses and wrote the prescribed C
   results.
3. The kit's `package.py` produced `results.zip`.
4. The package was returned for maintainer-side ingestion and scoring.
5. Maintainer PR #69 published it as the sample-set-only `glaurung` column at
   Glaurung revision `fb4ee6b`.

The published result was 69/246 GED-perfect, 22/235 type-perfect, 5/158
byte-perfect, and 82/250 Union-perfect: third on that historical sample set,
behind Codex and Claude Code. PR #69 records an exact manifest-fingerprint
match, zero off-manifest drops, and zero missing functions.

This was not a contributor-side full-corpus upload. DecBench gained an in-tree
Glaurung backend in PR #56, but its current documentation says the published
column came from the external kit and remains sample-set-only.

Historical local evidence includes the ordered manifest and score ledger in
`tests/decbench_scoreboard/`, plus these recorded packages:

- `glaurung-c1cfdc97-results.zip`, SHA-256
  `a2c5d731b532373315e16bbcd0458d4a5a2612780550120466569f7b46a24d38`;
- `glaurung-results-7a8c4b0.zip`, SHA-256
  `99478e4ef12881aff5f9d90ee821a63f68b3a72149dab8afd47ecfcbcbf3e12c`.

They are historical checkpoints, not today's candidate.

## What changed upstream

### External submission is still sample-set-only

At DecBench `5818d673`, the README still directs external competitors to the
250-function kit. `docs/decompilers.md` says the eval kit supports only
`--dataset sample-set` and explicitly marks Glaurung sample-set-only. Our
94,485-row result therefore has no documented contributor-side full-corpus
package or ingestion contract.

### Contact and AI policy changed

The current contact is `decbench@zionbasque.com`; the older
`decbench@mahaloz.re` address is obsolete. Commit `b909596` added the rule
against autonomous issues, commit comments, and pull requests, and the
maintainer separately requested human-written follow-up. A human must decide,
edit, and send any message.

### Resource limits changed after our pinned evaluator

PR #87 (`5818d673`) standardized production limits:

- 3,600 seconds per binary;
- 600 seconds per function where a watchdog exists;
- 16 GiB per concurrent binary process tree, with swap disabled;
- fail-closed cgroup enforcement in canonical drivers;
- explicit timeout/OOM classification and cleanup.

Our run used the same `--vas`/`--all` adapter shape, but a 20-second internal
function timeout, 600-second first-pass binary timeout, and 3,600-second
recovery for three binaries. It did not record canonical 16 GiB cgroup
enforcement. It is valuable evidence, but not proof of compliance with the
current protocol.

### Function discovery gained an opt-in mode

PR #86 added `DECBENCH_DWARF_ABSTRACT_ORIGIN=1` to expand C function discovery.
It defaults off and upstream verified default-off behavior as bit-identical to
the prior behavior; type-match ground truth is unchanged. A future run must
record this knob explicitly and must not mix populations silently.

### The adapter improved, but the published column did not rerun

The current in-tree adapter batches up to 400 addresses in one `--vas` call,
uses one `--all --limit 30000` call above that threshold, caches the result so
discovery does not decompile twice, derives its watchdog from the shared
600-second limit, and supports immutable source-revision recording. The public
sample-set column still describes the old `fb4ee6b` external submission.

## What our current evidence proves

| Item | Frozen value |
|---|---|
| Glaurung | `e170a2b4a8946b84808890fd5a09d46ce7cf6a66` |
| DecBench evaluator | `f76dae075d4d82004fb21132b3f15e43b680e179` |
| Dataset | `e5eb576d66ee36793b800a4dd45e291e0add4472` |
| Column | `glaurung-e170a2b4-exact-adapter` |
| Manifest | 803 binaries / 94,575 functions |
| Emitted and scored | 94,485 unique functions |
| Missing | 90 named identities; no duplicates or extras |

The independently recomputed shared-universe projection is:

| Metric | Perfect | Denominator | Rate | Local rank |
|---|---:|---:|---:|---:|
| GED | 34,512 | 91,288 | 37.805626% | 1 |
| Type match | 20,124 | 86,671 | 23.218839% | 1 |
| Byte match | 6,375 | 94,487 | 6.746960% | 1 |
| Union | 43,547 | 94,487 | 46.087822% | 1 |

These are sound internal projections against pinned published data. They are
not official ranks until DecBench accepts the column and recomputes it under
the selected current policy.

## Readiness matrix

| Requirement | State | Consequence |
|---|---|---|
| Exact Glaurung source/build identity | Ready | Commit and binary hashes recorded |
| Full raw/evaluated evidence | Ready | 803/803 binary artifacts retained |
| Independent score recount | Ready | Two audit JSONs are byte-identical |
| Coverage reconciliation | Ready with gap | 94,485/94,575; all 90 gaps listed |
| Documented external package | Not ready | Only the current 250-function kit qualifies |
| Current kit fingerprint | Ready | Fresh download inspected and hashed |
| Current DecBench revision | Not used | Run pinned `f76dae0`, before `5818d67` |
| Current CPU/RAM limits | Not proven | Controlled rerun or maintainer direction needed |
| Current sample-set ZIP | Not prepared | Regenerate, validate, package |
| Full-column publication permission | Unknown | Human must ask; do not infer |

## Recommended review package

### A. Valid submission-shaped candidate

Prepare a fresh 250-function `results.zip` from the eval kit currently linked
by DecBench, using the chosen clean Glaurung commit:

1. Record kit URL, retrieval time, ZIP hash, schema, and `manifest_sha256`.
2. Build release-mode from an immutable clean commit; record source commit, CLI
   and extension hashes, version output, compiler, host, and architecture.
3. Decompile the requested addresses once with batched `--vas`, without source,
   expected output, network, or LLM access.
4. Write only the kit-prescribed files and run its bundled `package.py`.
5. Re-open the ZIP; verify fingerprint, 250/250 targets, non-empty parseable C,
   no unexpected files, and byte-identical regeneration.
6. Record wall time, failures, timeouts, and peak memory separately from score.
7. Give the ZIP and checksum manifest to the human reviewer. Do not send it.

### B. Supplemental full-corpus evidence

Provide the audited `e170a2b4` reports and compact score JSONs, labelled as an
internal run on a pinned older evaluator with non-canonical limits. The human
can ask whether DecBench wants to reproduce a full column using its in-tree
backend or will accept a contributor-side full run under a specified schema.
Do not call the large derived `function_results.json` an ingest package.

## Human decisions required

1. Replace only the sample-set column, or also request a maintainer-run full
   column?
2. Submit `e170a2b4`, or wait for a newer clean release commit?
3. Keep `DECBENCH_DWARF_ABSTRACT_ORIGIN=0` for comparability, unless DecBench
   requests a newly recomputed population?
4. Permit generated-C republication, or request documented private-artifact
   treatment?
5. Treat existing timing as supplemental, or rerun under PR #87 first?

## Review inventory

| Artifact | Purpose | SHA-256/status |
|---|---|---|
| `CURRENT-FULL-RERUN.md` | Provenance, protocol, timing, scores | Reviewed record |
| `RESULT-VERIFICATION.md` | Independent identity/score audit | Reviewed record |
| `LEADERBOARD-SUBMISSION-STATUS.md` | Rank interpretation | Reviewed record |
| `~/.cache/glaurung/decbench-current-e170a2b4/function_results-e170a2b4.json` | Per-function results | `c1439af9a575fef649e612ce10c06fd7a3e4dcd69552a74e82c173323fab89d4` |
| `~/.cache/glaurung/decbench-current-e170a2b4/scoreboard-e170a2b4.toml` | Local scoreboard | `fd9a4fdb6df87650093629efd0aa26904bb29b52410de79559b778a42f04577c` |
| `~/.cache/glaurung/decbench-current-e170a2b4/audited-score-e170a2b4.json` | Merged audit | `b3549cfce21f75a40b6414e2287d94f6591164b35a5da129b3726d58bba2db58` |
| Fresh current eval-kit ZIP | Official input | `4584fa9823a589c6e98e3d24659a12e2933f7ff82d420402320e718ecfb7082c` |
| Fresh current `results.zip` | Human-review candidate | **Not yet generated** |

The current kit was downloaded from the README's Hugging Face URL at
`2026-09-14T10:47:40Z` to
`~/.cache/glaurung/decbench-submission-review-20260914/decbench-evalkit-sample-set.zip`.
It is format version 1, was created `2026-07-27T20:25:57+00:00`, contains 224
binaries and 250 targets, and declares manifest SHA-256
`dee8ac8d686d7563730452a3645fe030658b6f16914e3ec8a063e137a757257d`.
Its own README explicitly forbids executing the binaries; all preparation must
remain static analysis only.

## Human-only final checklist

- [ ] Personally read the current DecBench README and kit README.
- [ ] Make the five policy decisions above.
- [ ] Review representative C and every missing/error case.
- [ ] Verify the final package hash after a second extraction.
- [ ] Write any contact message in the submitter's own voice.
- [ ] Ask for an accepted full-corpus protocol rather than assuming one.
- [ ] Send/upload/open any issue only as the human submitter.

## Primary references

- Current README and external route: <https://github.com/Noelo-Lab/decbench/blob/5818d673b2ec91d0889897260ac6d7459e9ae326/README.md#compete-externally>
- External protocol: <https://github.com/Noelo-Lab/decbench/blob/5818d673b2ec91d0889897260ac6d7459e9ae326/docs/decompilers.md#part-iii--external-submissions-the-sample-set-eval-kit>
- Glaurung backend, PR #56: <https://github.com/Noelo-Lab/decbench/pull/56>
- Published Glaurung sample set, PR #69: <https://github.com/Noelo-Lab/decbench/pull/69>
- DWARF discovery option, PR #86: <https://github.com/Noelo-Lab/decbench/pull/86>
- Standard limits, PR #87: <https://github.com/Noelo-Lab/decbench/pull/87>
- AI-policy commit: <https://github.com/Noelo-Lab/decbench/commit/b9095966746fcf5ae52b7d79a4c643878fd079a6>
- Human-written follow-up request: <https://github.com/Noelo-Lab/decbench/issues/81#issuecomment-5486158431>
