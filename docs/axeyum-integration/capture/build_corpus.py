#!/usr/bin/env python3
"""Turn the raw glaurung query dump into axeyum's manifest-v1 corpus:
a small stratified `representative` tier + the `full` tier, classified by
structural family. Deterministic (no RNG)."""
import json, os, shutil, sys
from pathlib import Path

RAW = Path(sys.argv[1])            # dump dir with <hash>.smt2 + index.tsv
OUT = Path(sys.argv[2])           # deliverable dir (representative pack)
REP_PER_BUCKET = int(sys.argv[3]) if len(sys.argv) > 3 else 6
# Optional exclusion file: hashes axeyum's parser rejects (glaurung IR
# declared-vs-actual width edge cases). Dropped from both tiers.
EXCLUDE = set()
if len(sys.argv) > 4 and Path(sys.argv[4]).exists():
    EXCLUDE = set(Path(sys.argv[4]).read_text().split())

verdict = {}
for line in (RAW / "index.tsv").read_text().splitlines():
    h, v = line.split("\t")
    verdict[h] = v

def classify(text: str) -> str:
    if text.count("(assert") == 0:
        return "trivial"
    ex, co = "extract" in text, "concat" in text
    if ex and co:
        return "register-slice"          # the lifter-shape target class
    if ex or co:
        return "slice-partial"
    if "bvmul" in text or "bvadd" in text:
        return "arithmetic"
    if "bvult" in text or "bvule" in text or "bvslt" in text or "bvsle" in text:
        return "comparison"
    return "mixed"

def size_bucket(n: int) -> str:
    if n < 500: return "xs"
    if n < 4000: return "s"
    if n < 20000: return "m"
    if n < 80000: return "l"
    return "xl"

rows = []
for f in sorted(RAW.glob("*.smt2")):
    h = f.stem
    if h not in verdict or h in EXCLUDE:
        continue
    b = f.read_bytes()
    text = b.decode("utf-8", "replace")
    rows.append({
        "hash": h, "size": len(b), "expected": verdict[h],
        "family": classify(text), "bucket": size_bucket(len(b)),
        "declares": text.count("declare-const"), "asserts": text.count("(assert"),
    })

# Stratified representative sample: sorted-deterministic pick per
# (family, verdict, size-bucket) bucket, capped per bucket.
buckets = {}
for r in rows:
    buckets.setdefault((r["family"], r["expected"], r["bucket"]), []).append(r)
rep = set()
for key, items in sorted(buckets.items()):
    items.sort(key=lambda r: r["hash"])          # deterministic
    step = max(1, len(items) // REP_PER_BUCKET)
    for r in items[::step][:REP_PER_BUCKET]:
        rep.add(r["hash"])

# Emit representative pack (copied files) + manifest.
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "queries").mkdir(exist_ok=True)
files = []
for r in sorted(rows, key=lambda r: r["hash"]):
    tiers = ["full"]
    if r["hash"] in rep:
        tiers = ["representative", "full"]
        shutil.copy(RAW / f"{r['hash']}.smt2", OUT / "queries" / f"{r['hash']}.smt2")
    files.append({
        "path": f"queries/{r['hash']}.smt2",
        "content_hash": f"sha256:{r['hash']}",
        "expected": r["expected"],
        "family": r["family"],
        "tiers": tiers,
    })

manifest = {
    "version": 1,
    "name": "glaurung-qfbv-2026-07-v1",
    "source": ("Glaurung IOCTLance shadow-diff capture (solver-z3 trusted oracle); "
               "drivers win10-vwififlt, sqfs-intel-DptfDevGen, IntcSST; "
               "dedup by content hash; produced by build_corpus.py"),
    "logic": "QF_BV",
    "files": files,
}
# Full manifest (all files present in RAW) for the scheduled full-tier run.
(OUT / "manifest-representative-v1.json").write_text(json.dumps(
    {**manifest, "files": [f for f in files if "representative" in f["tiers"]]}, indent=2))
(OUT / "manifest-full-v1.json").write_text(json.dumps(manifest, indent=2))

# Report
from collections import Counter
fam = Counter(r["family"] for r in rows)
repfam = Counter(r["family"] for r in rows if r["hash"] in rep)
print(f"total distinct queries: {len(rows)}")
print(f"representative selected: {len(rep)}")
print("family distribution (full -> representative):")
for k in sorted(fam):
    print(f"  {k:16} full={fam[k]:6}  rep={repfam.get(k,0)}")
print("verdicts:", Counter(r["expected"] for r in rows))
rep_bytes = sum((OUT/'queries'/f"{h}.smt2").stat().st_size for h in rep)
print(f"representative pack size: {rep_bytes/1e6:.1f} MB")
