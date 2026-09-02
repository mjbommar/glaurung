# Similarity hashing

Glaurung provides a native context-triggered piecewise hash (CTPH) for bounded
near-duplicate comparison and a PE import hash when applicable. CTPH is useful
for candidate clustering; it is not a cryptographic identity, semantic
equivalence proof, or malware-family attribution.

## Triage integration

`glaurung triage FILE --json` includes:

- `similarity.ctph` for analyzed inputs; and
- `similarity.imphash` for supported PE inputs with import data.

The CTPH digest is intentionally verbose. Store it as structured data rather
than displaying it in an analyst summary.

## Tested Python example

```python
from glaurung import similarity

paths = [
    "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/"
    "hello-gcc-O2",
    "samples/binaries/platforms/linux/amd64/export/native/clang/O2/"
    "hello-clang-O2",
]

digests = [similarity.ctph_hash_path(path) for path in paths]
score = similarity.ctph_similarity(digests[0], digests[1])
assert 0.0 <= score <= 1.0

pairs = similarity.ctph_pairwise_matrix(digests, max_pairs=10)
clusters = similarity.cluster_single_linkage(
    digests,
    threshold=0.85,
    max_pairs=10,
)
print(score, pairs, clusters)
```

For bytes already in memory:

```python
digest = similarity.ctph_hash_bytes(b"example payload" * 256)
assert isinstance(digest, str)
```

Other available helpers are:

- `ctph_recommended_params(size)` for the native size-based parameter choice;
- `ctph_top_k(query, candidates, k, min_score)` for nearest digests; and
- `cluster_single_linkage(digests, threshold, max_pairs)` for connected
  components over pairwise scores.

## Digest compatibility

The digest encodes its window and digest sizes. `ctph_similarity` compares block
sets only when those parameters are compatible. Generate corpus digests with the
same Glaurung revision and defaults when stable clustering matters.

The current size-based recommendations are:

| Input size | Window | Digest bytes | Rolling precision |
| --- | ---: | ---: | ---: |
| under 16 KiB | 8 | 4 | 8 |
| 16 KiB to under 1 MiB | 16 | 5 | 16 |
| 1 MiB and above | 32 | 6 | 16 |

These are implementation defaults, not universal similarity thresholds.
Calibrate `min_score` or clustering thresholds on labeled data from the target
corpus.

## Complexity and limits

Pairwise comparison is quadratic in the number of digests. Always set
`max_pairs` from an explicit resource budget. `ctph_pairwise_matrix` raises or
stops according to the native contract rather than silently claiming complete
coverage beyond that budget.

Treat a high score as a lead for deeper function-, import-, or behavior-level
comparison. Treat a low score as inconclusive when packing, relinking,
architecture, compiler, or large resource changes can dominate byte structure.

## Function-level identity is a different tool

CTPH is a **file**-level near-duplicate measure and is deliberately not
extended to function granularity: at that size it scores near chance, which is
the published behaviour of the byte-hash representation class, not a defect in
this implementation. For "which functions changed between two builds", use the
L1 structural invariants -- MD-index, small-primes product over mnemonics, and
the block/edge/loop/SCC counts -- documented in
[Structural function identity (L1)](../analysis/function-identity-structural.md)
and exposed as `glaurung.analysis.structural_signatures_path`. They are what
`glaurung diff` ranks its changed-function list by.
