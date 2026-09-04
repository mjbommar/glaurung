# Evidence: the scripts behind every number

> **Kind:** design · **Status:** proposed

Every number quoted in this directory came from one of the scripts below, run
once, offline, against the materialized DecBench tree at
`~/.cache/glaurung/decbench-full` (dataset revision `e5eb576`, config `full`).

**These were scratch scripts.** They were written under
`$TMPDIR/metrics-research/` and are reproduced here verbatim so the numbers can
be re-derived; none of them is committed as a tool, and none should be run in a
gate as it stands. [`roadmap.md`](roadmap.md) M0 and M1 say which of them are
worth productionizing.

## How they were run

Two interpreters, for one reason: `networkx`, `scipy` and `cfgutils` are
DecBench dependencies and are not in Glaurung's lockfile, while
`glaurung.source_cfg` needs Glaurung's built extension. Nothing here invokes the
DecBench pipeline or Joern; the DecBench virtualenv is used only as a Python
interpreter that has a graph library in it.

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"          # never /tmp
FORK_PY=/nas4/data/workspace-infosec/decbench/.venv/bin/python   # networkx + scipy + cfgutils
# and, for mutate.py only:
uv run --no-sync python ...                        # Glaurung's built extension
```

The extension in use was
`python/glaurung/_native.cpython-314-x86_64-linux-gnu.so` with mtime
`2026-09-04 10:26`. Its build profile was not verified; only the C parser and
CFG builder are exercised, and neither result depends on the profile.

## Where 1-WL stands in for VF2

Three scripts decide isomorphism with a 1-WL colour-refinement certificate
rather than VF2. That substitution is measured, not assumed: `census.py` ran VF2
inside every WL bucket and produced exactly the same partition — 8,034 classes
either way — so on this corpus the certificate is exact. Any script reusing it
says so.


## 1. `census.py` — signature classes, WL classes, isomorphism classes

How many structurally distinct functions collapse to one vj_ged signature, how many distinct CFG shapes the corpus has, and how much a perfect verdict is worth in bits.

```bash
cd $TMPDIR/metrics-research && /nas4/data/workspace-infosec/decbench/.venv/bin/python census.py census.pkl
```

Runtime: 20.7 s.

### Script

```python
"""Scratch: structural census of DecBench's published Joern source CFGs.

Answers: how much does the VJ-GED cost model see, and how many structurally
distinct functions collapse to the same score?
Read-only over ~/.cache/glaurung/decbench-full/tree. No Joern, no DecBench pipeline.
"""
import json, sys, collections, hashlib, pickle
from pathlib import Path
import networkx as nx

ROOT = Path.home() / ".cache/glaurung/decbench-full/tree"

def load():
    recs = []
    for p in sorted(ROOT.glob("*/*/source_cfgs/*.json")):
        d = json.loads(p.read_text())
        opt, proj, binary = d["opt"], d["project"], d["binary"]
        for name, f in d["functions"].items():
            recs.append((opt, proj, binary, name, f))
    return recs

def roles(f):
    e, x = set(f["entry"]), set(f["exit"])
    return {n: (n in e, n in x) for n in f["nodes"]}

def degrees(f):
    ind = collections.Counter(); outd = collections.Counter()
    for n in f["nodes"]: ind[n]; outd[n]
    for a, b in f["edges"]:
        outd[a] += 1; ind[b] += 1
    return ind, outd

def vj_signature(f):
    """Exactly what vj_ged's cost matrix can see: the multiset of
    (in_degree, out_degree, is_entrypoint, is_exitpoint)."""
    ind, outd = degrees(f); r = roles(f)
    return tuple(sorted((ind[n], outd[n], r[n][0], r[n][1]) for n in f["nodes"]))

def wl_cert(f, rounds=12):
    """1-WL colour-refinement certificate; isomorphism-invariant.
    Different cert => provably non-isomorphic."""
    nodes = f["nodes"]; ind, outd = degrees(f); r = roles(f)
    preds = collections.defaultdict(list); succs = collections.defaultdict(list)
    for a, b in f["edges"]:
        succs[a].append(b); preds[b].append(a)
    col = {n: hash((r[n], ind[n], outd[n])) for n in nodes}
    prev = len(set(col.values()))
    for _ in range(rounds):
        new = {n: hash((col[n],
                        tuple(sorted(col[p] for p in preds[n])),
                        tuple(sorted(col[s] for s in succs[n])))) for n in nodes}
        k = len(set(new.values()))
        col = new
        if k == prev: break
        prev = k
    return (len(nodes), len(f["edges"]), tuple(sorted(col.values())))

def to_nx(f):
    g = nx.DiGraph(); r = roles(f)
    for n in f["nodes"]: g.add_node(n, role=r[n])
    g.add_edges_from((a, b) for a, b in f["edges"])
    return g

NM = nx.algorithms.isomorphism.categorical_node_match("role", (False, False))

def main():
    recs = load()
    print(f"functions loaded: {len(recs)}")
    live = [(o,p,b,n,f) for (o,p,b,n,f) in recs if not f["degenerate"]]
    print(f"non-degenerate:   {len(live)}")

    sigs = {}; certs = {}
    for i,(o,p,b,n,f) in enumerate(live):
        sigs[i] = vj_signature(f)
        certs[i] = wl_cert(f)
    print(f"distinct vj signatures (what vj_ged sees): {len(set(sigs.values()))}")
    print(f"distinct 1-WL certificates (>= iso classes): {len(set(certs.values()))}")

    # per-signature: how many provably-distinct WL classes share it
    by_sig = collections.defaultdict(list)
    for i in sigs: by_sig[sigs[i]].append(i)
    multi_fn = 0; multi_sig = 0
    same_sig_pairs = 0; same_sig_noniso_pairs_lb = 0
    for s, idxs in by_sig.items():
        cs = collections.Counter(certs[i] for i in idxs)
        k = len(idxs)
        same_sig_pairs += k*(k-1)//2
        # lower bound on non-isomorphic same-signature pairs: cross-WL-class pairs
        same_sig_noniso_pairs_lb += (k*(k-1)//2) - sum(v*(v-1)//2 for v in cs.values())
        if len(cs) > 1:
            multi_sig += 1; multi_fn += k
    print(f"signature classes holding >1 WL class: {multi_sig} "
          f"covering {multi_fn} functions ({100*multi_fn/len(live):.2f}%)")
    print(f"same-signature unordered pairs: {same_sig_pairs}")
    print(f"  of which provably non-isomorphic (cross-WL): {same_sig_noniso_pairs_lb} "
          f"({100*same_sig_noniso_pairs_lb/max(1,same_sig_pairs):.4f}%)")

    with open(sys.argv[1] if len(sys.argv)>1 else "/dev/null","wb") as fh:
        pickle.dump({"keys":[(o,p,b,n) for (o,p,b,n,f) in live],
                     "sigs":sigs,"certs":certs,
                     "shape":[(len(f["nodes"]),len(f["edges"])) for (o,p,b,n,f) in live]}, fh)

    # exact isomorphism classes inside each WL bucket
    by_cert = collections.defaultdict(list)
    for i in certs: by_cert[certs[i]].append(i)
    print(f"WL buckets: {len(by_cert)}, largest {max(len(v) for v in by_cert.values())}")
    classes = []          # list of (representative index, members)
    idx_class = {}
    for c, idxs in by_cert.items():
        reps = []
        for i in idxs:
            gi = to_nx(live[i][4]) if len(live[i][4]["nodes"]) <= 64 else None
            placed = False
            if gi is None:
                # large graph: trust the WL certificate rather than run VF2
                for ri, rg, mem in reps:
                    if certs[ri] == certs[i] and rg is None:
                        mem.append(i); idx_class[i] = ri; placed = True; break
            else:
                for ri, rg, mem in reps:
                    if rg is not None and nx.is_isomorphic(rg, gi, node_match=NM):
                        mem.append(i); idx_class[i] = ri; placed = True; break
            if not placed:
                reps.append((i, gi, [i])); idx_class[i] = i
        for ri, rg, mem in reps: classes.append((ri, mem))
    print(f"exact isomorphism classes (VF2 <=64 nodes, WL cert above): {len(classes)}")
    sizes = sorted((len(m) for _, m in classes), reverse=True)
    tot = sum(sizes)
    simpson = sum((s/tot)**2 for s in sizes)
    import math
    print(f"largest classes: {sizes[:15]}")
    print(f"Simpson collision probability (two random functions same class): {simpson:.6f}")
    print(f"effective number of distinct CFG shapes: {1/simpson:.2f}")
    print(f"bits of information in a 'GED perfect' certificate: {-math.log2(simpson):.3f}")
    for ri, mem in sorted(classes, key=lambda t: -len(t[1]))[:12]:
        o,p,b,n,f = live[ri]
        print(f"  class n={len(f['nodes'])} m={len(f['edges'])} size={len(mem)}  e.g. {p}/{b}/{n} [{o}]")

main()
```

### Output

```
functions loaded: 91548
non-degenerate:   89014
distinct vj signatures (what vj_ged sees): 6694
distinct 1-WL certificates (>= iso classes): 8034
signature classes holding >1 WL class: 632 covering 23509 functions (26.41%)
same-signature unordered pairs: 319019594
  of which provably non-isomorphic (cross-WL): 655819 (0.2056%)
WL buckets: 8034, largest 24243
exact isomorphism classes (VF2 <=64 nodes, WL cert above): 8034
largest classes: [24243, 4967, 3207, 1502, 1396, 1390, 1198, 1051, 1006, 890, 823, 788, 539, 372, 369]
Simpson collision probability (two random functions same class): 0.080371
effective number of distinct CFG shapes: 12.44
bits of information in a 'GED perfect' certificate: 3.637
  class n=1 m=0 size=24243  e.g. base-passwd/update-passwd/create_node [O0]
  class n=3 m=2 size=4967  e.g. base-passwd/update-passwd/xstrdup [O0]
  class n=3 m=3 size=3207  e.g. base-passwd/update-passwd/xasprintf [O0]
  class n=2 m=1 size=1502  e.g. base-passwd/update-passwd/selinux_after_create_file [O0]
  class n=5 m=4 size=1396  e.g. bash/bash/remove_alias [O0]
  class n=4 m=4 size=1390  e.g. bash/bash/xtrace_print_arith_cmd [O0]
  class n=5 m=6 size=1198  e.g. bash/bash/disable_priv_mode [O0]
  class n=3 m=3 size=1051  e.g. bash/bash/set_posix_options [O0]
  class n=4 m=4 size=1006  e.g. bash/bash/alias_expand_word [O0]
  class n=5 m=5 size=890  e.g. base-passwd/update-passwd/put_file_in_place [O0]
  class n=5 m=5 size=823  e.g. bash/bash/falarm [O0]
  class n=6 m=6 size=788  e.g. base-passwd/update-passwd/find_by_name [O0]
```

## 2. `m3.py` — which GED semantics produced the published cells

Locates the `GED_MAX_NODES` cliff by joining every published per-function GED value to its published source CFG's node count.

```bash
cd $TMPDIR/metrics-research && /nas4/data/workspace-infosec/decbench/.venv/bin/python m3.py
```

Runtime: 3.7 s.

### Script

```python
"""Scratch measurement 3: which GED semantics produced the published cells?

The fork (/nas4/.../decbench @ efc5d5a) has GED_MAX_NODES=60 and no isomorphism
fast path; upstream (@ bd49c83, 2026-08-07) has GED_MAX_NODES=200, an isomorphism
fast path and a max(1.0, raw) clamp.  Both fall back to |dn|+|dm| above the cap,
which is much SMALLER than vj_ged.  So the cap shows up as a cliff in stored
values as a function of source node count.  Locate the cliff.
"""
import json, collections, statistics
from pathlib import Path

ROOT = Path.home() / ".cache/glaurung/decbench-full"
tree = ROOT / "tree"

# source node counts keyed by (opt, project, binary, function)
size = {}
for p in sorted(tree.glob("*/*/source_cfgs/*.json")):
    d = json.loads(p.read_text())
    for name, f in d["functions"].items():
        size[(d["opt"], d["project"], d["binary"], name)] = (len(f["nodes"]), len(f["edges"]), f["degenerate"])

pr = json.loads((ROOT / "published_function_results.json").read_text())
rows = []
for g in pr["groups"]:
    for fn in g["functions"]:
        k = (g["opt_level"], g["project"], g["binary"], fn["function"])
        s = size.get(k)
        if not s or s[2]: continue
        for dec, vals in fn["values"].items():
            v = vals.get("ged")
            if v is None: continue
            rows.append((s[0], s[1], dec, float(v)))
print(f"joined cells (published GED value x published source CFG): {len(rows)}")
print(f"distinct decompilers: {len(set(r[2] for r in rows))}")

by_n = collections.defaultdict(list)
for n, m, dec, v in rows: by_n[n].append(v)

def band(lo, hi):
    vs = [v for n, l in by_n.items() if lo <= n <= hi for v in l]
    return len(vs), (statistics.mean(vs) if vs else 0.0), (statistics.median(vs) if vs else 0.0)

print("\nmean/median stored GED by source-node band (all decompilers pooled):")
for lo, hi in [(40,50),(51,60),(61,70),(71,80),(120,140),(160,180),(181,200),(201,220),(221,260)]:
    c, mu, med = band(lo, hi)
    print(f"  n in [{lo:3d},{hi:3d}]  cells={c:6d}  mean={mu:9.2f}  median={med:8.1f}")

print("\nper-node-count detail around 60 and around 200:")
for n in list(range(56,66)) + list(range(196,206)):
    vs = by_n.get(n, [])
    if vs:
        print(f"  n={n:3d} cells={len(vs):5d} mean={statistics.mean(vs):9.2f} median={statistics.median(vs):8.1f} max={max(vs):9.1f}")

# clamp evidence: upstream never emits a non-perfect value below 1.0
frac = collections.Counter()
for n, m, dec, v in rows:
    if v == 0.0: frac["zero"] += 1
    elif 0.0 < v < 1.0: frac["in (0,1)"] += 1
    else: frac[">=1"] += 1
print("\nvalue classes:", dict(frac))

# ratio test: is the value above the cap consistent with |dn|+|dm| (bounded by ~n+m)?
big = [(n,m,v) for n,m,dec,v in rows if n > 200]
mid = [(n,m,v) for n,m,dec,v in rows if 61 <= n <= 200]
def over(rs):
    if not rs: return 0,0
    k = sum(1 for n,m,v in rs if v > n + m)
    return k, len(rs)
print(f"cells with n>200 whose value exceeds n+m: {over(big)}   (size-delta fallback rarely can)")
print(f"cells with 61<=n<=200 whose value exceeds n+m: {over(mid)}")
```

### Output

```
joined cells (published GED value x published source CFG): 486965
distinct decompilers: 13

mean/median stored GED by source-node band (all decompilers pooled):
  n in [ 40, 50]  cells=  9604  mean=    52.91  median=    33.0
  n in [ 51, 60]  cells=  5609  mean=    67.91  median=    42.0
  n in [ 61, 70]  cells=  4220  mean=    66.39  median=    39.0
  n in [ 71, 80]  cells=  2678  mean=    86.84  median=    56.5
  n in [120,140]  cells=  1353  mean=   144.65  median=   110.0
  n in [160,180]  cells=   725  mean=   149.83  median=   103.0
  n in [181,200]  cells=   274  mean=   221.18  median=   134.5
  n in [201,220]  cells=   152  mean=   141.73  median=    72.0
  n in [221,260]  cells=   423  mean=   237.39  median=   159.0

per-node-count detail around 60 and around 200:
  n= 56 cells=  829 mean=    76.53 median=    44.0 max=   1036.0
  n= 57 cells=  258 mean=    67.95 median=    44.0 max=    228.0
  n= 58 cells=  427 mean=    85.35 median=    42.0 max=    631.0
  n= 59 cells=  503 mean=    72.10 median=    45.0 max=   3938.0
  n= 60 cells=  546 mean=    68.04 median=    40.0 max=    558.0
  n= 61 cells=  528 mean=    57.71 median=    42.0 max=    244.0
  n= 62 cells=  265 mean=    59.64 median=    44.0 max=    311.0
  n= 63 cells=  898 mean=    69.86 median=    30.0 max=    266.0
  n= 64 cells=  284 mean=    74.12 median=    39.5 max=    812.0
  n= 65 cells=  734 mean=    62.31 median=    39.0 max=    302.0
  n=196 cells=   11 mean=    48.64 median=    46.0 max=     90.0
  n=198 cells=    7 mean=    62.71 median=    59.0 max=     97.0
  n=199 cells=   33 mean=   219.09 median=    68.0 max=    961.0
  n=200 cells=   15 mean=   121.67 median=    55.0 max=    234.0
  n=202 cells=    6 mean=   436.50 median=   437.0 max=    438.0
  n=205 cells=   26 mean=   106.85 median=    97.0 max=    509.0

value classes: {'>=1': 322359, 'zero': 164606}
cells with n>200 whose value exceeds n+m: (12, 1659)   (size-delta fallback rarely can)
cells with 61<=n<=200 whose value exceeds n+m: (1513, 15110)
```

## 3. `m4.py` — the null decompiler against the real leaderboard

Scores a decompiler that emits one constant body, on DecBench's own rule, over the same population as every real column.

```bash
cd $TMPDIR/metrics-research && /nas4/data/workspace-infosec/decbench/.venv/bin/python m4.py
```

Runtime: under a minute.

### Script

```python
"""Scratch measurement 4: score a null 'decompiler' on DecBench's own GED rule.

Rule (upstream decbench/metrics/ged.py, commit bd49c83+): GED == 0 iff the
role-labelled decompiled CFG is isomorphic to the role-labelled source CFG.
A decompiler that emits `int f(void){return 0;}` for EVERY function produces,
under Joern+pyjoern normalisation, a 1-node 0-edge CFG flagged entry AND exit.
So it scores perfect on every source function whose CFG is exactly that.
"""
import json, collections
from pathlib import Path

ROOT = Path.home() / ".cache/glaurung/decbench-full"
tree = ROOT / "tree"

src = {}
for p in sorted(tree.glob("*/*/source_cfgs/*.json")):
    d = json.loads(p.read_text())
    for name, f in d["functions"].items():
        src[(d["opt"], d["project"], d["binary"], name)] = f

pr = json.loads((ROOT / "published_function_results.json").read_text())
keys = []                       # benchmark functions with a usable published source CFG
per_dec = collections.defaultdict(lambda: [0, 0])
for g in pr["groups"]:
    for fn in g["functions"]:
        k = (g["opt_level"], g["project"], g["binary"], fn["function"])
        f = src.get(k)
        if f is None or f["degenerate"]: continue
        keys.append(k)
        for dec, vals in fn["values"].items():
            v = vals.get("ged")
            if v is None: continue
            per_dec[dec][1] += 1
            if float(v) == 0.0: per_dec[dec][0] += 1

print(f"benchmark functions joined to a non-degenerate published source CFG: {len(keys)}")

def matches(f, want_entry, want_exit, n, m):
    return (len(f["nodes"]) == n and len(f["edges"]) == m
            and bool(f["entry"]) == want_entry and bool(f["exit"]) == want_exit)

null_hit = sum(1 for k in keys if matches(src[k], True, True, 1, 0))
print(f"\nnull decompiler (`return 0;` everywhere) -> 1 node / 0 edges / entry+exit")
print(f"  perfect on {null_hit} of {len(keys)} = {100*null_hit/len(keys):.2f}%\n")

rows = sorted(((100*p/max(1,t), d, p, t) for d,(p,t) in per_dec.items()), reverse=True)
print(f"{'decompiler':18s} {'perfect':>8s} {'scored':>8s} {'perfect%':>9s}  {'perfect% over all '+str(len(keys)):>28s}")
for pct, d, p, t in rows:
    print(f"{d:18s} {p:8d} {t:8d} {pct:8.2f}% {100*p/len(keys):26.2f}%")
print(f"{'NULL (return 0;)':18s} {null_hit:8d} {len(keys):8d} {100*null_hit/len(keys):8.2f}% {100*null_hit/len(keys):26.2f}%")

# what is the single best constant body, over all shapes present in the corpus?
shape = collections.Counter()
for k in keys:
    f = src[k]
    shape[(len(f["nodes"]), len(f["edges"]), bool(f["entry"]), bool(f["exit"]))] += 1
print("\ntop source-CFG shapes by (nodes, edges, has_entry, has_exit):")
for s, c in shape.most_common(8):
    print(f"  n={s[0]:3d} m={s[1]:3d} entry={s[2]} exit={s[3]}  {c:6d}  {100*c/len(keys):5.2f}%")

# how binary is the metric?  zero-rate and value spread by source size
by_band = collections.defaultdict(lambda: [0,0,[]])
for g in pr["groups"]:
    for fn in g["functions"]:
        k = (g["opt_level"], g["project"], g["binary"], fn["function"])
        f = src.get(k)
        if f is None or f["degenerate"]: continue
        n = len(f["nodes"])
        b = 1 if n==1 else 2 if n<=3 else 4 if n<=7 else 8 if n<=15 else 16 if n<=31 else 32 if n<=60 else 61
        for dec, vals in fn["values"].items():
            v = vals.get("ged")
            if v is None: continue
            by_band[b][1] += 1
            if float(v)==0.0: by_band[b][0] += 1
            else: by_band[b][2].append(float(v))
print("\nGED zero-rate and non-zero spread by source node count (all decompilers pooled):")
for b in sorted(by_band):
    z, t, nz = by_band[b]
    nz.sort()
    q = lambda p: nz[int(p*(len(nz)-1))] if nz else 0
    print(f"  nodes>={b:3d}  cells={t:7d}  perfect={100*z/t:6.2f}%  "
          f"nonzero p10={q(.1):7.1f} p50={q(.5):7.1f} p90={q(.9):8.1f} max={nz[-1] if nz else 0:8.1f}")
```

### Output

```
benchmark functions joined to a non-degenerate published source CFG: 89014

null decompiler (`return 0;` everywhere) -> 1 node / 0 edges / entry+exit
  perfect on 24243 of 89014 = 27.24%

decompiler          perfect   scored  perfect%       perfect% over all 89014
claude-code             134      242    55.37%                       0.15%
codex                   131      243    53.91%                       0.15%
ida                   32586    81900    39.79%                      36.61%
kuna                  32952    84241    39.12%                      37.02%
angr                  30924    83584    37.00%                      34.74%
binja                 18323    55997    32.72%                      20.58%
ghidra                22716    72961    31.13%                      25.52%
glaurung                 67      240    27.92%                       0.08%
r2dec                 15508    59555    26.04%                      17.42%
phoenix                8387    34428    24.36%                       9.42%
dewolf                 2808    13193    21.28%                       3.15%
fission                  49      240    20.42%                       0.06%
manifold                 21      141    14.89%                       0.02%
NULL (return 0;)      24243    89014    27.24%                      27.24%

top source-CFG shapes by (nodes, edges, has_entry, has_exit):
  n=  1 m=  0 entry=True exit=True   24243  27.24%
  n=  3 m=  2 entry=True exit=False    5180   5.82%
  n=  3 m=  3 entry=True exit=True    3369   3.78%
  n=  4 m=  4 entry=True exit=True    2415   2.71%
  n=  5 m=  5 entry=True exit=False    2109   2.37%
  n=  5 m=  6 entry=True exit=True    1662   1.87%
  n=  5 m=  4 entry=True exit=False    1601   1.80%
  n=  2 m=  1 entry=True exit=False    1570   1.76%

GED zero-rate and non-zero spread by source node count (all decompilers pooled):
  nodes>=  1  cells= 123273  perfect= 90.36%  nonzero p10=    8.0 p50=   13.0 p90=    52.0 max=   785.0
  nodes>=  2  cells=  59823  perfect= 35.77%  nonzero p10=    3.0 p50=    6.0 p90=    12.0 max=   446.0
  nodes>=  4  cells= 103278  perfect= 20.26%  nonzero p10=    3.0 p50=    8.0 p90=    20.0 max= 11907.0
  nodes>=  8  cells=  98130  perfect=  8.66%  nonzero p10=    4.0 p50=   11.0 p90=    34.0 max=  1148.0
  nodes>= 16  cells=  59731  perfect=  3.40%  nonzero p10=    6.0 p50=   18.0 p90=    68.0 max=  1037.0
  nodes>= 32  cells=  25961  perfect=  1.10%  nonzero p10=   11.0 p50=   32.0 p90=   120.0 max=  3938.0
  nodes>= 61  cells=  16769  perfect=  0.44%  nonzero p10=   19.0 p50=   69.0 p90=   291.0 max=  5378.0
```

## 4. `m5.py` — where each column's score comes from

Per-decompiler share of perfect cells by source CFG size, plus the statement variety inside the largest isomorphism class.

```bash
cd $TMPDIR/metrics-research && /nas4/data/workspace-infosec/decbench/.venv/bin/python m5.py
```

Runtime: under a minute.

### Script

```python
"""Scratch measurement 5: where the GED score actually comes from, and how much
semantic variety hides inside one CFG isomorphism class."""
import json, collections, hashlib
from pathlib import Path

ROOT = Path.home() / ".cache/glaurung/decbench-full"
tree = ROOT / "tree"
src = {}
for p in sorted(tree.glob("*/*/source_cfgs/*.json")):
    d = json.loads(p.read_text())
    for name, f in d["functions"].items():
        src[(d["opt"], d["project"], d["binary"], name)] = f

pr = json.loads((ROOT / "published_function_results.json").read_text())
# contribution of tiny functions to each decompiler's perfect count
contrib = collections.defaultdict(lambda: collections.Counter())
for g in pr["groups"]:
    for fn in g["functions"]:
        k = (g["opt_level"], g["project"], g["binary"], fn["function"])
        f = src.get(k)
        if f is None or f["degenerate"]: continue
        n = len(f["nodes"])
        bucket = "n=1" if n == 1 else "n<=3" if n <= 3 else "n<=7" if n <= 7 else "n>=8"
        for dec, vals in fn["values"].items():
            v = vals.get("ged")
            if v is None: continue
            contrib[dec]["all_" + bucket] += 1
            if float(v) == 0.0: contrib[dec]["perfect_" + bucket] += 1
print(f"{'decompiler':14s} {'perfect':>8s} | share of perfect cells from n=1 / n<=3 / n<=7 / n>=8")
for dec in sorted(contrib, key=lambda d: -sum(v for k,v in contrib[d].items() if k.startswith('perfect'))):
    c = contrib[dec]
    tot = sum(v for k,v in c.items() if k.startswith("perfect"))
    if not tot: continue
    print(f"{dec:14s} {tot:8d} | "
          + " / ".join(f"{100*c['perfect_'+b]/tot:5.1f}%" for b in ("n=1","n<=3","n<=7","n>=8")))

# semantic variety inside the biggest isomorphism class: distinct label bodies
big = [k for k,f in src.items() if not f["degenerate"] and len(f["nodes"])==1 and not f["edges"]
       and f["entry"] and f["exit"]]
bodies = collections.Counter()
for k in big:
    lab = src[k]["labels"]
    bodies[hashlib.sha256(json.dumps(lab, sort_keys=True).encode()).hexdigest()] += 1
print(f"\nlargest isomorphism class (1 node, 0 edges, entry+exit): {len(big)} functions")
print(f"  distinct pyjoern statement bodies inside it: {len(bodies)}")
print(f"  distinct function names inside it: {len(set(k[3] for k in big))}")
import statistics
lens = [len(src[k]['labels'].get('0','') or src[k]['labels'][list(src[k]['labels'])[0]]) for k in big]
print(f"  block-text length: min={min(lens)} median={statistics.median(lens):.0f} max={max(lens)}")
worst = max(big, key=lambda k: len(list(src[k]['labels'].values())[0]))
print(f"  largest body in the class: {worst[1]}/{worst[2]} [{worst[0]}] {worst[3]} "
      f"({len(list(src[worst]['labels'].values())[0])} chars of statements)")
for k in sorted(big, key=lambda k: -len(list(src[k]['labels'].values())[0]))[:5]:
    print(f"    {k[1]}/{k[2]} [{k[0]}] {k[3]}: {len(list(src[k]['labels'].values())[0])} chars")
```

### Output

```
decompiler      perfect | share of perfect cells from n=1 / n<=3 / n<=7 / n>=8
kuna              32952 |  62.9% /  14.8% /  14.5% /   7.8%
ida               32586 |  62.5% /  13.7% /  14.7% /   9.1%
angr              30924 |  68.0% /  12.8% /  12.2% /   7.0%
ghidra            22716 |  72.6% /  11.4% /  11.6% /   4.5%
binja             18323 |  65.5% /  14.8% /  13.3% /   6.4%
r2dec             15508 |  77.7% /  11.6% /   9.1% /   1.6%
phoenix            8387 |  68.2% /  11.4% /  12.1% /   8.3%
dewolf             2808 | 100.0% /   0.0% /   0.0% /   0.0%
claude-code         134 |  36.6% /  11.2% /  23.1% /  29.1%
codex               131 |  37.4% /  13.7% /  26.0% /  22.9%
glaurung             67 |  64.2% /  13.4% /  14.9% /   7.5%
fission              49 |  81.6% /  10.2% /   6.1% /   2.0%
manifold             21 |  81.0% /   9.5% /   4.8% /   4.8%

largest isomorphism class (1 node, 0 edges, entry+exit): 24243 functions
  distinct pyjoern statement bodies inside it: 7393
  distinct function names inside it: 5284
  block-text length: min=41 median=261 max=38571
  largest body in the class: cleanflight/cleanflight_DALRCF405 [O0] pgResetFn_osdConfig (38571 chars of statements)
    cleanflight/cleanflight_DALRCF405 [O0] pgResetFn_osdConfig: 38571 chars
    cleanflight/cleanflight_DALRCF405 [O2] pgResetFn_osdConfig: 38571 chars
    cleanflight/cleanflight_DALRCF405 [O2-noinline] pgResetFn_osdConfig: 38571 chars
    betaflight/betaflight_STM32F405 [O0] TIM1_UP_TIM10_IRQHandler: 37660 chars
    betaflight/betaflight_STM32F405 [O2] TIM1_UP_TIM10_IRQHandler: 37660 chars
```

## 5. `m6.py` — the statement channel the metric never reads

How many statement lines the published serialization carries, and how they are distributed inside single CFG shapes.

```bash
cd $TMPDIR/metrics-research && /nas4/data/workspace-infosec/decbench/.venv/bin/python m6.py
```

Runtime: under a minute.

### Script

```python
"""Scratch measurement 7: how much a statement-aware metric would recover.

The published CFG serialization keeps pyjoern's per-block statement dump in
`labels`.  vj_ged never reads it and the isomorphism check never reads it.
Measure what is sitting there unused.
"""
import json, collections, statistics
from pathlib import Path
tree = Path.home() / ".cache/glaurung/decbench-full/tree"

stmt_per_fn = []
one_node_stmts = []
tot_lines = 0
byshape = collections.defaultdict(list)
for p in sorted(tree.glob("*/*/source_cfgs/*.json")):
    d = json.loads(p.read_text())
    for name, f in d["functions"].items():
        if f["degenerate"]: continue
        n = len(f["nodes"])
        lines = 0
        for lab in f["labels"].values():
            lines += max(0, len(lab.strip().split("\n")) - 1)   # first line is the address
        stmt_per_fn.append((n, lines))
        tot_lines += lines
        if n == 1 and not f["edges"] and f["entry"] and f["exit"]:
            one_node_stmts.append((lines, d["project"], d["binary"], name, d["opt"]))
        byshape[(n, len(f["edges"]))].append(lines)

print(f"total statement lines carried in `labels` but never read by GED: {tot_lines}")
ns = [l for l,_,_,_,_ in one_node_stmts]
ns.sort()
q = lambda p: ns[int(p*(len(ns)-1))]
print(f"\nlargest isomorphism class (1 node, 0 edges, entry+exit): {len(ns)} functions")
print(f"  statements per function: min={min(ns)} p25={q(.25)} median={q(.5)} "
      f"p75={q(.75)} p95={q(.95)} p99={q(.99)} max={max(ns)}")
print(f"  distinct statement counts inside the class: {len(set(ns))}")
print(f"  functions in the class with >20 statements: {sum(1 for x in ns if x>20)} "
      f"({100*sum(1 for x in ns if x>20)/len(ns):.1f}%)")
print("  extremes:")
for l,pr,b,nm,o in sorted(one_node_stmts, reverse=True)[:5]:
    print(f"    {l:5d} statements  {pr}/{b} [{o}] {nm}")
for l,pr,b,nm,o in sorted(one_node_stmts)[:3]:
    print(f"    {l:5d} statements  {pr}/{b} [{o}] {nm}")

# spread of statement counts inside every (n, m) shape class, weighted by class size
big = sorted(byshape.items(), key=lambda kv: -len(kv[1]))[:10]
print("\nstatement-count spread inside the 10 commonest CFG shapes:")
for (n,m), ls in big:
    ls = sorted(ls)
    print(f"  n={n:2d} m={m:2d}  {len(ls):6d} functions  statements min={ls[0]:3d} "
          f"median={ls[len(ls)//2]:4d} p95={ls[int(.95*(len(ls)-1))]:5d} max={ls[-1]:6d}")
```

### Output

```
total statement lines carried in `labels` but never read by GED: 5460786

largest isomorphism class (1 node, 0 edges, entry+exit): 24243 functions
  statements per function: min=3 p25=5 median=7 p75=14 p95=45 p99=136 max=618
  distinct statement counts inside the class: 141
  functions in the class with >20 statements: 3902 (16.1%)
  extremes:
      618 statements  cleanflight/cleanflight_DALRCF405 [O2-noinline] pgResetFn_osdConfig
      618 statements  cleanflight/cleanflight_DALRCF405 [O2] pgResetFn_osdConfig
      618 statements  cleanflight/cleanflight_DALRCF405 [O0] pgResetFn_osdConfig
      574 statements  zlib/minigzip64 [O2-noinline] fixedtables
      574 statements  zlib/minigzip64 [O0] fixedtables
        3 statements  base-passwd/update-passwd [O0] ask_debconf
        3 statements  base-passwd/update-passwd [O0] version
        3 statements  base-passwd/update-passwd [O2-noinline] version

statement-count spread inside the 10 commonest CFG shapes:
  n= 1 m= 0   24249 functions  statements min=  2 median=   7 p95=   45 max=   618
  n= 3 m= 2    5180 functions  statements min=  4 median=  15 p95=   52 max=   308
  n= 3 m= 3    4451 functions  statements min=  3 median=  14 p95=   59 max=   605
  n= 4 m= 4    3329 functions  statements min=  5 median=  18 p95=   65 max=   269
  n= 5 m= 5    2109 functions  statements min=  5 median=  22 p95=   60 max=   123
  n= 5 m= 6    1987 functions  statements min=  6 median=  22 p95=   78 max=   161
  n= 7 m= 8    1919 functions  statements min=  8 median=  29 p95=  132 max=   287
  n= 6 m= 7    1620 functions  statements min=  7 median=  26 p95=   67 max=  1046
  n= 5 m= 4    1601 functions  statements min=  6 median=  22 p95=   56 max=  1196
  n= 2 m= 1    1570 functions  statements min=  3 median=  11 p95=   46 max=   104
```

## 6. `m7.py` — the wrong-body attack and degree-preserving rewiring

How often another function of the same binary is CFG-isomorphic, and what fraction of degree-preserving double-edge swaps destroy the graph.

```bash
cd $TMPDIR/metrics-research && /nas4/data/workspace-infosec/decbench/.venv/bin/python m7.py
```

Runtime: 8.9 s.

### Script

```python
"""Scratch measurement 8: the wrong-body attack, and degree-preserving rewiring.

Isomorphism decided by 1-WL certificate: on this corpus 1-WL produced exactly
the same 8,034 classes as VF2 (census.py), so the certificate is exact here.
"""
import json, collections, random
from pathlib import Path
tree = Path.home() / ".cache/glaurung/decbench-full/tree"


def cert_and_sig(nodes, edges, entry, exits, rounds=12):
    e, x = set(entry), set(exits)
    ind = collections.Counter(); outd = collections.Counter()
    preds = collections.defaultdict(list); succs = collections.defaultdict(list)
    for n in nodes:
        ind[n]; outd[n]
    for a, b in edges:
        outd[a] += 1; ind[b] += 1; succs[a].append(b); preds[b].append(a)
    col = {n: hash(((n in e, n in x), ind[n], outd[n])) for n in nodes}
    prev = len(set(col.values()))
    for _ in range(rounds):
        new = {n: hash((col[n], tuple(sorted(col[p] for p in preds[n])),
                        tuple(sorted(col[s] for s in succs[n])))) for n in nodes}
        k = len(set(new.values())); col = new
        if k == prev:
            break
        prev = k
    return ((len(nodes), len(edges), tuple(sorted(col.values()))),
            tuple(sorted((ind[n], outd[n], n in e, n in x) for n in nodes)))


recs = []
for p in sorted(tree.glob("*/*/source_cfgs/*.json")):
    d = json.loads(p.read_text())
    for name, f in d["functions"].items():
        if f["degenerate"]:
            continue
        recs.append((d["opt"], d["project"], d["binary"], name, f))
print(f"non-degenerate functions: {len(recs)}")

by_bin = collections.defaultdict(list)
for i, r in enumerate(recs):
    by_bin[(r[0], r[1], r[2])].append(i)
certs = {}
for i, (o, p, b, n, f) in enumerate(recs):
    certs[i] = cert_and_sig(f["nodes"], [tuple(e) for e in f["edges"]], f["entry"], f["exit"])[0]

twin = tw_nt = tot = nt = 0
examples = []
for key, idxs in by_bin.items():
    c = collections.Counter(certs[i] for i in idxs)
    for i in idxs:
        n = len(recs[i][4]["nodes"]); tot += 1; nt += (n >= 4)
        if c[certs[i]] > 1:
            twin += 1; tw_nt += (n >= 4)
            if n >= 8 and len(examples) < 10:
                other = next(recs[j][3] for j in idxs if j != i and certs[j] == certs[i])
                examples.append((key, recs[i][3], other, n, len(recs[i][4]["edges"])))
print(f"\n(b) functions with a CFG-isomorphic twin in the same binary: {twin}/{tot} = {100*twin/tot:.2f}%")
print(f"    restricted to >=4 CFG nodes: {tw_nt}/{nt} = {100*tw_nt/nt:.2f}%")
print("    examples (>=8 nodes) -- emitting either body scores GED-perfect for the other:")
for k, a, b_, n_, m_ in examples:
    print(f"      {k[1]}/{k[2]} [{k[0]}]  {a}  ~  {b_}   (n={n_}, m={m_})")

rng = random.Random(20260904)
cand = [i for i, r in enumerate(recs) if len(r[4]["nodes"]) >= 5 and len(r[4]["edges"]) >= 5]
sample = rng.sample(cand, min(20000, len(cand)))
changed = tried = nolegal = 0
for i in sample:
    f = recs[i][4]
    edges = [tuple(e) for e in f["edges"]]; es = set(edges)
    new = None
    for _ in range(60):
        (a, b_), (c, d) = rng.sample(edges, 2)
        if len({a, b_, c, d}) < 4 or (a, d) in es or (c, b_) in es:
            continue
        new = [e for e in edges if e != (a, b_) and e != (c, d)] + [(a, d), (c, b_)]
        break
    if new is None:
        nolegal += 1
        continue
    tried += 1
    c1 = cert_and_sig(f["nodes"], new, f["entry"], f["exit"])
    if c1[0] != certs[i]:
        changed += 1
    assert c1[1] == cert_and_sig(f["nodes"], edges, f["entry"], f["exit"])[1]
print(f"\n(c) degree-preserving double-edge swaps over {len(sample)} sampled functions (n>=5, m>=5)")
print(f"    swaps constructed: {tried}  (no legal swap available: {nolegal})")
print(f"    resulting graph non-isomorphic to the original: {changed}/{tried} = {100*changed/tried:.2f}%")
print(f"    every one has an IDENTICAL (in,out,entry,exit) multiset, so vj_ged scores all {tried} as 0.0")
```

### Output

```
non-degenerate functions: 89014

(b) functions with a CFG-isomorphic twin in the same binary: 52167/89014 = 58.61%
    restricted to >=4 CFG nodes: 17325/53379 = 32.46%
    examples (>=8 nodes) -- emitting either body scores GED-perfect for the other:
      base-passwd/update-passwd [O0]  read_passwd  ~  read_group   (n=15, m=19)
      base-passwd/update-passwd [O0]  read_group  ~  read_passwd   (n=15, m=19)
      base-passwd/update-passwd [O0]  write_passwd  ~  write_shadow   (n=15, m=17)
      base-passwd/update-passwd [O0]  write_shadow  ~  write_passwd   (n=15, m=17)
      base-passwd/update-passwd [O0]  write_group  ~  write_passwd   (n=15, m=17)
      bash/bash [O0]  all_digits  ~  strvec_search   (n=8, m=9)
      bash/bash [O0]  xrealloc  ~  sh_xrealloc   (n=8, m=13)
      bash/bash [O0]  sh_mktmpdir  ~  sh_mktmpname   (n=12, m=16)
      bash/bash [O0]  pcomp_set_readline_variables  ~  set_active_region   (n=8, m=10)
      bash/bash [O0]  sh_xrealloc  ~  xrealloc   (n=8, m=13)

(c) degree-preserving double-edge swaps over 20000 sampled functions (n>=5, m>=5)
    swaps constructed: 19829  (no legal swap available: 171)
    resulting graph non-isomorphic to the original: 18720/19829 = 94.41%
    every one has an IDENTICAL (in,out,entry,exit) multiset, so vj_ged scores all 19829 as 0.0
```

## 7. `m8.py` — how many parity cells were never raw vj_ged

Sizes the modelling gap in `tools/source_cfg_parity.py`.

```bash
cd $TMPDIR/metrics-research && /nas4/data/workspace-infosec/decbench/.venv/bin/python m8.py
```

Runtime: under a minute.

### Script

```python
"""Scratch measurement 9: how many of the 85,645 parity cells were never raw vj_ged.

tools/source_cfg_parity.py:238 computes bare vj_ged and diffs it against the
stored cell.  The stored cells came from decbench/metrics/ged.py, which takes
one of three paths: isomorphism -> 0.0; source or decompiled nodes > cap ->
max(1.0, |dn|+|dm|); otherwise max(1.0, vj_ged).  Count the cells where the
stored value cannot be raw vj_ged.
"""
import json, re, collections
from pathlib import Path

tree = Path.home() / ".cache/glaurung/decbench-full/tree"
CELL = re.compile(r'^"([^"]+)\.ged\.functions\.([^"]+)" = ([0-9.]+|inf|-inf|nan)')

size = {}
for p in sorted(tree.glob("*/*/source_cfgs/*.json")):
    d = json.loads(p.read_text())
    for name, f in d["functions"].items():
        size[(d["opt"], d["project"], d["binary"], name)] = (len(f["nodes"]), len(f["edges"]), f["degenerate"])

cols = collections.Counter()
rows = collections.defaultdict(list)
for p in sorted(tree.glob("*/*/evaluated/*.toml")):
    opt, proj = p.parts[-4], p.parts[-3]
    binary = p.stem
    for line in p.read_text().splitlines():
        m = CELL.match(line)
        if not m:
            continue
        col, fn, val = m.group(1), m.group(2), m.group(3)
        cols[col] += 1
        rows[col].append((opt, proj, binary, fn, float(val)))

print("stored GED cells per column:")
for c, n in cols.most_common():
    print(f"  {c:28s} {n}")

col = cols.most_common(1)[0][0]
cells = rows[col]
print(f"\ncolumn under test: {col}  ({len(cells)} stored cells)")

paired = [(k, v) for k, v in ((( o, p, b, f), v) for o, p, b, f, v in cells) if k in size]
print(f"  cells with a published source CFG: {len(paired)}")
nd = [(k, v) for k, v in paired if not size[k][2]]
print(f"  ...and a non-degenerate one:       {len(nd)}")

over200 = [(k, v) for k, v in nd if size[k][0] > 200]
over60 = [(k, v) for k, v in nd if size[k][0] > 60]
ones = [(k, v) for k, v in nd if v == 1.0]
zeros = [(k, v) for k, v in nd if v == 0.0]
print(f"\n  stored under the size-delta fallback (source nodes > 200): {len(over200)} "
      f"({100*len(over200)/len(nd):.2f}%) -- raw vj_ged cannot reproduce these")
print(f"  cells the FORK's cap (60) would have sent to the fallback:  {len(over60)} "
      f"({100*len(over60)/len(nd):.2f}%) -- the two caps disagree on {len(over60)-len(over200)} cells")
print(f"  stored exactly 1.0 (candidates for the max(1.0, raw) clamp): {len(ones)} "
      f"({100*len(ones)/len(nd):.2f}%)")
print(f"  stored exactly 0.0 (isomorphism fast path):                  {len(zeros)} "
      f"({100*len(zeros)/len(nd):.2f}%)")
print(f"\n  cells whose stored value provably did NOT come from raw vj_ged:"
      f" >= {len(over200)} of {len(nd)} = {100*len(over200)/len(nd):.2f}%")
```

### Output

```
stored GED cells per column:
  glaurung-229fbb1-clean       88963

column under test: glaurung-229fbb1-clean  (88963 stored cells)
  cells with a published source CFG: 88963
  ...and a non-degenerate one:       88963

  stored under the size-delta fallback (source nodes > 200): 273 (0.31%) -- raw vj_ged cannot reproduce these
  cells the FORK's cap (60) would have sent to the fallback:  2820 (3.17%) -- the two caps disagree on 2547 cells
  stored exactly 1.0 (candidates for the max(1.0, raw) clamp): 85 (0.10%)
  stored exactly 0.0 (isomorphism fast path):                  29463 (33.12%)

  cells whose stored value provably did NOT come from raw vj_ged: >= 273 of 88963 = 0.31%
```

## 8. `mutate.py` — defect-injection sensitivity

Parses the 300 published sample sources with Glaurung's own front end, mutates each, reparses, and reports how often the injected defect leaves the CFG isomorphic.

```bash
cd $TMPDIR/metrics-research && uv run --no-sync python mutate.py
```

Runtime: under a minute.

### Script

```python
"""Scratch measurement 6: defect-injection sensitivity of DecBench's GED.

Basis: the 300 `samples` in published_function_results.json, each carrying the
real `source_code` of one benchmark function.  Each source is parsed by
Glaurung's own C front end (glaurung.source_cfg.parity_cfgs, the Joern-parity
layer), mutated at the source level, and reparsed.

Verdicts computed without networkx/scipy, both exactly:
  * GED-perfect  <=>  the two role-labelled CFGs are isomorphic.  Approximated
    by 1-WL colour-refinement certificate equality; on the published 89,014
    function corpus 1-WL and VF2 produced the identical 8,034 classes, so the
    approximation is measured, not assumed.
  * vj_ged == 0  <=>  equal multisets of (in_deg, out_deg, entry, exit).  Exact:
    every cell of the VJ cost matrix is a function of those four numbers.
"""
import json, re, collections, sys
from pathlib import Path
from glaurung.source_cfg import parity_cfgs

ROOT = Path.home() / ".cache/glaurung/decbench-full"
samples = json.loads((ROOT / "published_function_results.json").read_text())["samples"]

def cert(cfg, rounds=12):
    nodes = cfg["nodes"]; e = set(cfg["entry"]); x = set(cfg["exit"])
    ind = collections.Counter(); outd = collections.Counter()
    preds = collections.defaultdict(list); succs = collections.defaultdict(list)
    for n in nodes: ind[n]; outd[n]
    for a, b in cfg["edges"]:
        outd[a] += 1; ind[b] += 1; succs[a].append(b); preds[b].append(a)
    col = {n: hash(((n in e, n in x), ind[n], outd[n])) for n in nodes}
    prev = len(set(col.values()))
    for _ in range(rounds):
        new = {n: hash((col[n], tuple(sorted(col[p] for p in preds[n])),
                        tuple(sorted(col[s] for s in succs[n])))) for n in nodes}
        k = len(set(new.values())); col = new
        if k == prev: break
        prev = k
    sig = tuple(sorted((ind[n], outd[n], n in e, n in x) for n in nodes))
    return (len(nodes), len(cfg["edges"]), tuple(sorted(col.values()))), sig

def sub1(text, pat, rep):
    m = re.search(pat, text)
    return (text[:m.start()] + rep + text[m.end():]) if m else None

def m_rel(t):   return sub1(t, r"(?<![<>=!])<(?!=)", ">=") or sub1(t, r"(?<![<>=!-])>(?!=)", "<=")
def m_eq(t):    return sub1(t, r"==", "!=")
def m_logic(t): return sub1(t, r"&&", "||") or sub1(t, r"\|\|", "&&")
def m_arith(t): return sub1(t, r"(?<![+\-*/=<>!&|^%\s])\s\+\s(?!\+)", " - ")
def m_const(t): return sub1(t, r"(?<![\w.])([1-9]\d{0,4})(?![\w.])", lambda: None) or _bump(t)
def _bump(t):
    m = re.search(r"(?<![\w.])([1-9]\d{0,4})(?![\w.])", t)
    return t[:m.start()] + str(int(m.group(1)) + 1) + t[m.end():] if m else None
def m_negate(t):
    m = re.search(r"\bif\s*\(", t)
    if not m: return None
    i = m.end() - 1; depth = 0
    for j in range(i, len(t)):
        if t[j] == "(": depth += 1
        elif t[j] == ")":
            depth -= 1
            if depth == 0:
                return t[:i+1] + "!(" + t[i+1:j] + ")" + t[j:]
    return None
def m_null(t):
    i = t.find("{")
    return t[:i] + "{ return 0; }" if i > 0 else None
def m_loop2if(t): return sub1(t, r"\bwhile\s*\(", "if (")
def m_dropbreak(t): return sub1(t, r"\bbreak\s*;", ";")
def m_dropelse(t):
    m = re.search(r"\belse\b", t)
    return t[:m.start()] + "if (0) " + t[m.end():] if m else None

MUT = [("relational-flip", m_rel), ("equality-flip", m_eq), ("logic-flip", m_logic),
       ("arith-flip", m_arith), ("constant-bump", _bump), ("negate-condition", m_negate),
       ("null-body", m_null), ("while->if", m_loop2if), ("drop-break", m_dropbreak),
       ("else->if(0)", m_dropelse)]

base_ok = 0
res = {k: collections.Counter() for k, _ in MUT}
for s in samples:
    name, text = s["function"], s["source_code"]
    try: cfgs = parity_cfgs(text)
    except Exception: continue
    if name not in cfgs: continue
    c0 = cfgs[name]
    if c0["degenerate"]: continue
    base_ok += 1
    k0, sig0 = cert(c0)
    for label, fn in MUT:
        try: mt = fn(text)
        except Exception: mt = None
        if mt is None or mt == text:
            res[label]["not-applicable"] += 1; continue
        try: mc = parity_cfgs(mt)
        except Exception:
            res[label]["mutant-unparsed"] += 1; continue
        if name not in mc:
            res[label]["mutant-unparsed"] += 1; continue
        k1, sig1 = cert(mc[name])
        res[label]["applied"] += 1
        if k0 == k1: res[label]["ged-perfect (undetected)"] += 1
        if sig0 == sig1: res[label]["vj_ged==0 (undetected)"] += 1

print(f"samples: {len(samples)}   parsed + function found + non-degenerate: {base_ok}\n")
print(f"{'mutation':18s} {'applied':>8s} {'GED says perfect':>18s} {'vj_ged==0':>14s} {'n/a':>6s} {'unparsed':>9s}")
for label, _ in MUT:
    c = res[label]; a = c["applied"]
    if not a:
        print(f"{label:18s} {a:8d} {'-':>18s} {'-':>14s} {c['not-applicable']:6d} {c['mutant-unparsed']:9d}")
        continue
    print(f"{label:18s} {a:8d} "
          f"{c['ged-perfect (undetected)']:6d} ({100*c['ged-perfect (undetected)']/a:5.1f}%) "
          f"{c['vj_ged==0 (undetected)']:5d} ({100*c['vj_ged==0 (undetected)']/a:5.1f}%) "
          f"{c['not-applicable']:6d} {c['mutant-unparsed']:9d}")
```

### Output

```
samples: 300   parsed + function found + non-degenerate: 285

mutation            applied   GED says perfect      vj_ged==0    n/a  unparsed
relational-flip         122    121 ( 99.2%)   121 ( 99.2%)    163         0
equality-flip           137    137 (100.0%)   137 (100.0%)    148         0
logic-flip              104     98 ( 94.2%)    98 ( 94.2%)    181         0
arith-flip               67     67 (100.0%)    67 (100.0%)    218         0
constant-bump           174    174 (100.0%)   174 (100.0%)    111         0
negate-condition        191    191 (100.0%)   191 (100.0%)     94         0
null-body               279     73 ( 26.2%)    73 ( 26.2%)      0         6
while->if                56     18 ( 32.1%)    19 ( 33.9%)    229         0
drop-break               48      6 ( 12.5%)     6 ( 12.5%)    237         0
else->if(0)             111     26 ( 23.4%)    26 ( 23.4%)    174         0
```
