Similarity Hashing

Overview
- Provides lightweight, license-friendly fuzzy hashing via Context-Triggered Piecewise Hashing (CTPH) for clustering and near-duplicate detection.
- Also reports PE import hash (imphash) when applicable.

CTPH Format
- Digest format: "<window_size>:<digest_size>:<block1>:<block2>:..."
- Blocks: short BLAKE3-XOF substrings emitted when a rolling hash trigger fires (or a safety length is reached).
- Similarity: Jaccard over block sets, only if window_size and digest_size match.

Default Parameters
- Small (< 16 KiB): window=8, digest=4, precision=8 (8-bit rolling)
- Medium (< 1 MiB): window=16, digest=5, precision=16
- Large (>= 1 MiB): window=32, digest=6, precision=16

Python Usage
```python
import glaurung as g

# Hash bytes
h1 = g.similarity.ctph_hash_bytes(data)

# Hash a file (bounded I/O)
h2 = g.similarity.ctph_hash_path("/path/to/file")

# Compare digests
score = g.similarity.ctph_similarity(h1, h2)  # 0.0..1.0

# Pairwise matrix (budgeted)
M = g.similarity.ctph_pairwise_matrix([h1, h2, ...], max_pairs=250_000)

# Top-K nearest digests
neighbors = g.similarity.ctph_top_k(h1, digest_list, k=5, min_score=0.6)
```

Triage Integration
- TriagedArtifact.similarity:
  - imphash: Optional (PE only)
  - ctph: Always computed over a bounded heuristics buffer

Notes
- CTPH here is MIT/Apache friendly and avoids GPL-encumbered ssdeep/sdhash.
- For best clustering, use consistent parameters across your corpus.
