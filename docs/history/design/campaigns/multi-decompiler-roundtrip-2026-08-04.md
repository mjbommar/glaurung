# Ten-sample multi-decompiler round-trip study — 2026-08-04

> **Kind:** record · **Date:** 2026-08-13

Ten DecBench projects, four decompilers, two compilers, two compile paths, every
figure re-measured on this host with the metric cache disabled. Roughly 6,000
functions.

**Tools that could be run here:** glaurung, angr 9.3.1, RetDec v5.0, r2dec
(r2 6.0.8). **Ghidra, IDA, Binja, Kuna and dewolf are not installed**, and no
reference decompiler output exists on disk — so *every* Ghidra/IDA/Binja number
in our documents is an imported figure that cannot be recomputed or checked here.
Reko cannot be built (`dotnet publish` fails on an unpinned `REKO_REF`).

---

## 1. The headline: what would happen if we submitted

On the like-for-like sets, at **gcc-13.4** (the compiler closest to the original
producer, gcc 11.4), with DecBench's harness bugs neutralised:

| sample | n | angr | glaurung | RetDec | r2dec |
|---|---:|---:|---:|---:|---:|
| libacl (spine) | 7 | **0.5248** | 0.3294 | 0.3392 | 0.000 |
| coreutils | 746 | **0.4277** | 0.3555 | 0.3594 | 0.0896 |
| diffutils | 417 | **0.4298** | 0.3248 | 0.2975 | 0.2069 |
| dpkg (common) | 523 | **0.4739** | 0.4091 | 0.3467 | — |
| shadow (common) | 46 | **0.4807** | 0.4401 | 0.3829 | 0.2000 |
| sysvinit (common) | 171 | **0.4367** | 0.4078 | 0.2760 | 0.1702 |
| zlib | 1272 | 0.3369 | **0.3459** | 0.3105 | 0.0754 |
| gnutls (spine) | 11 | 0.2419 | **0.2840** | 0.2234 | 0.000 |

**We beat RetDec and r2dec nearly everywhere. angr beats us on match quality on
six of eight comparable samples.** We lead decisively on *recovery* and *compile
rate* on every sample measured.

Two effects that no single number captures:

* **The ranking inverts with optimisation level.** Same source (`ls.c`), gcc-13:
  O0 `ls` — angr 0.6552, RetDec 0.5110, glaurung 0.3298. O2-noinline `vdir` —
  **glaurung 0.4101**, angr 0.3231, RetDec 0.3045. *We are the best tool at -O2
  and the worst at -O0.*
* **The ranking inverts with the host compiler.** See §2.

---

## 2. Most published numbers are measuring the toolchain, not the decompiler

**Under gcc-15.2 we appear to lead by 2.7–6.7x. Under gcc-13.4 we are third.**

| zlib, n=1272 | gcc-15.2 | gcc-13.4 |
|---|---:|---:|
| glaurung | 0.3072 | 0.3459 |
| angr | 0.0977 | 0.3369 |
| RetDec | 0.0956 | 0.3105 |

RetDec gains **+225%** and angr **+245%** from the compiler change alone. Two
post-GCC-13 tightenings do it: C23 makes `long f();` mean *zero* parameters, so
the fixup's synthesised fallback prototype errors; and `-Wint-conversion` became
an error in GCC 14.

Share of gcc-15 compile failures that are host-toolchain artifacts rather than
decompiler defects: **RetDec 95.7%, angr 81.9%, glaurung 21.2%** (libacl);
**83.9% overall** (diffutils).

Our robustness is real — we emit real prototypes for every callee, so the fixup
never synthesises the C23-fatal form — but it is a *different property* from
decompilation quality, and it does not hold everywhere: on dpkg our dominant
failure is a syntax error at both compilers, so we gain almost nothing from the
compiler change while the others gain enormously.

---

## 3. Defects in DecBench that change conclusions

Ordered by how much they distort results.

1. **RetDec is scored on a stripped binary's symbol table, so it recovers
   nothing.** `DockerizedDecompiler._build_result` resolves names via
   `elf_function_symbols()`, which returns **zero** symbols after
   `strip --strip-all`. RetDec names functions `function_<lowpc>`.
   * libacl executables: DecBench records **0/102**; truth **92/102**.
   * zlib: DecBench **176/1272 (13.8%)**; truth **1242/1272 (97.6%)**.
   * gnutls: DecBench **0** on every stripped binary.
   * `.so` files survive only via `.dynsym` — and that biases the mean *upward*
     (libacl: exported 0.3850 vs full 0.3447), because exported functions are
     easier. `R2DecDecompiler` already has the address-keyed lookup that fixes it.

2. **ARM32 is measured three ways wrong**, each worth more than the
   tool differences:
   * `_stripped_copy` **silently no-ops on ARM** — host `strip`/`objcopy` reject
     ARM ELF and all three fallbacks fail. 6,531,804 bytes in, 6,531,804 out.
     Every published ARM32 figure was taken with full symbols and DWARF present.
   * **Every Thumb function is extracted one byte off** — the ARM ABI sets bit 0
     of a Thumb `STT_FUNC` value, and both `_elf_function_bytes` and
     `_elf_object_function` slice at the odd address. 109/109 sized symbols in
     one binary are odd.
   * **Thumb-2 is disassembled in ARM mode** — `capstone_arch_mode`'s `thumb`
     parameter defaults to false; all 28 binaries are 100% Thumb-2.
   Together these manufacture false perfect scores (RetDec's `lcd_command`
   scores **1.0000** — 140 original bytes against 207 recompiled, garbage
   matching garbage) and destroy real ones. **Under a partial correction RetDec
   beats us; only the full correction restores our lead.**

3. **`_ARRAY_RET` corrupts valid C, and only ours.** `fixup.py:84`, meant for
   array *return types*, rewrites
   `static unsigned char g[16] __attribute__((aligned(16)));`
   into `static unsigned char g *__attribute__((aligned(16)));`.
   It accounts for **134 of our 192** gcc-13 compile failures on coreutils and
   **8 of 9** on gnutls, and fires **zero** times for the other three tools.
   Guarding it: coreutils 484/746 → **744/746** compiled, 0.2799 → 0.3555.

4. **`main` scores 0.0 at -O2 for every decompiler.** GCC places it in
   `.text.startup`; `object_text_bytes` reads the empty `.text` and returns zero
   bytes. Confirmed on five samples. Costs **4 of 13 spine functions on shadow
   (31%)**, 2 of 7 on libacl (29%), and ~+0.22 mean across 27 coreutils cells
   when read correctly. **Correction:** the mechanism is on the *recompiled*
   object, not the original — PIE linking merges the original's `main` into
   `.text`.

5. **Two silent measurement traps.**
   * `ByteMatchMetric._cached_value` keys on the compiler **name**, not version.
     A gcc-13 run after a gcc-15 run returns the gcc-15 numbers.
     `DECBENCH_NO_CACHE=1` is mandatory.
   * `fixup.py:61` snapshots `os.environ` into `_C_LOCALE_ENV` **at import
     time**. Mutating `os.environ["PATH"]` afterwards does not change which gcc
     runs. Set PATH before importing decbench.
   Both silently make a compiler A/B measure the same compiler twice.

6. **The harness penalty is real but NOT uniform, and the bzip2recover figure
   does not generalise.** Harness vs context-restored:
   bzip2recover RetDec **+135%**; zlib **+6.4%** for both whole-program tools;
   libacl RetDec **+20%**; sysvinit glaurung **−25.6%** (negative — the harness
   *protects* against `static`-global folding); diffutils ±0.04 mixed sign;
   coreutils, gnutls, dpkg **unmeasurable** (the whole-TU path does not exist at
   that scale — 1 of 48 cells compiles). The discriminator is whether a tool
   re-emits its declarations inside each body: we and angr do, RetDec does not.

---

## 4. Our own defects, ranked by measured cost

> ### CORRECTION, 2026-08-05 — item 1 below is WITHDRAWN
>
> The "+40% largest lever" is **0.0000 on the path DecBench actually scores.**
> `evalkit/ingest.py:361` slices every submission with `split_c_functions`,
> which starts each snippet at the signature line. Census over the whole holdout
> package: of 250 submitted functions, 88 reference a `glaurung_global_*`,
> **88/88 carry the in-body `extern`, and 0/250 carry the file-scope
> definition.** It never reaches a compiler there.
>
> End-to-end A/B, same build, 412 definitions emitted vs suppressed:
> **227/250 compile and byte_match 0.2005 both ways, 0 of 250 functions
> differing.** Suppressing them *breaks the x86-64 CONTROL lane*
> (`arch_roundtrip` 12 problems) and costs `fixture_harness` 4 cases.
>
> Every "+40%" figure below was measured on the **whole-TU** path, which
> DecBench does not use — `recompile_fidelity.py:142` and
> `diff_decompile.py:639` both compile the whole unit, so every sibling harness
> that reported it was unsliced. 20/25 holdout functions compile *smaller* whole-TU
> than sliced.
>
> A second inference was also wrong: "the submitted build shipped extern-only and
> master regressed." Ingest strips that line from **every** column, `00b72e3` and
> `24b3826` included. That was post-slice output read as a pre-slice property.
>
> What survives: the attribute-first spelling now in main is harmless and worth
> keeping (it fixes whole-TU consumers); and a real, separate correctness
> question — our execution differential compiles the whole unit, so it is partly
> exercising code whose guards GCC folded.

1. **Global objects emitted as file-scope `static` definitions instead of
   `extern` declarations.** DecBench compiles one function with `-c`; an
   uninitialised `static` array is provably zero, so GCC folds away every guard
   that reads it. `shadow::pwunconv::fail_exit`: 479 bytes / 106 instructions
   becomes **15 bytes / 5 instructions**, score 0.0091 → **0.6357**.
   Shadow-wide: **+40% mean byte_match** (0.2509 → 0.3523) over 157 functions.
   libacl `xquote`: **0.5909 → 0.9444**. gnutls three-way counterfactual:
   as-is fails to compile, attribute-first 0.0476/0.2304/0.1461, **extern
   0.4138/0.3582/0.3039**.
   *This is a regression*: the submitted build emits extern-only and compiles;
   master emits the `static` definition.

2. **Internal-callee pointer parameters collapse to `long *`.** dpkg: of 1037
   callees whose DWARF signature has a `char *`, **885 (85.3%)** are mistyped.
   Named libc callees are fine (987 correct) — internal `sub_<addr>` callees are
   **103 of 7681 (1.3%)**. We have libc prototypes and no interprocedural
   propagation. It blocks compilation: 123/123 of dpkg's remaining failures.
   Widening to `void *` is **codegen-neutral (measured: 613/614 bit-identical)**
   and recovers 99 of 123.

3. **Rip-relative addresses emitted as integer literals** — both code and data.
   `snprintf((char *)(0x82d0), 22, (const char *)(0x5864), arg0)` where angr
   emits `snprintf(&g_4082d0, 22, "%ld", a0)`. GCC emits `mov imm`; the original
   has `lea rip-rel`, and byte_match normalises `[rip+disp]` to `[rip+X]`, so a
   correct `lea` always matches and ours never can.
   libacl `user_name` **0.2286 vs angr 0.8293**; coreutils
   `rev_strcmp_df_mtime` **0.348 vs 0.867**.

4. **251 of 746 coreutils functions (33.6%) declare an uninitialised bare
   machine-register local (`long rbp;`) and read it.** Zero for all three
   competitors. UB in the emitted C, forces a spill the original never had, and
   at -O2 lets GCC fold branches — one diffutils function emits **51 bytes for a
   1058-byte original** because of it.

5. **ARM32 firmware: interrupt-vector-table entries are never seeded.** 20/31
   recovered on truly-stripped Cortex-M firmware; all 11 misses are unreachable
   from `e_entry` by direct branch. On unstripped input we get 29/29 — so it is
   *seeding*, not lifting. Every competitor finds them.

6. **ARM32 `lr`/`fp` are renamed to AArch64 `x30`/`x29` at width 64.**
   `ssa.rs:126` probes the x86-64 table then falls back to AArch64; there is no
   ARM32 table at all. A 32-bit link register is modelled at 64 bits.

7. **Our whole-file output is not a translation unit** on any sample: duplicate
   PLT-stub definitions (31–54 per TU) and per-call-site prototypes that
   disagree in arity (341 `conflicting types for '__fprintf_chk'` in one gnutls
   TU). Invisible on the harness path — the same per-function self-containment
   that makes us robust there makes us unbuildable as a file.

---

## 5. What we already do better than everyone

* **Compile rate**, on every sample: diffutils 417/417 vs angr 360/416, RetDec
  350/371, r2dec 152/373. We are the only tool with **zero** functions failing
  under both compilers.
* **Recovery**: 99.6–100% on every userland sample.
* **`_Noreturn`**: we already emit it (161/161 on zlib, 170/746 on coreutils);
  the other three emit it nowhere. It is worth +0.10 (zlib) to +0.02 (dpkg) to
  them, and **exactly 0 at -O0** — GCC does not exploit it unoptimised.
* **-O2 output quality**, where we lead on the one controlled comparison
  available (same source at O0 vs O2).

---

## 6. What byte_match cannot tell us

* It **penalises correct simplification**. RetDec folds `zlibCompileFlags` to
  `return 169;` — semantically exact — and scores 0.417 where our literal add
  chain scores 1.000.
* It **cannot reward opaque handles**. On gnutls, 16.3% of ground-truth
  variables are pointers to incomplete structs (`gnutls_session_t`) whose only
  binary evidence is "64-bit value in `rdi`". All four tools score 0 on every
  one — and angr's structurally-correct `struct_0 *` also scores 0, because the
  metric string-matches aggregates.
* **No tool materialises constant tables.** `yyparse` indexes nine named bison
  tables; array initialisers ≥60 chars in each tool's certtool TU: glaurung 0,
  RetDec 0, angr 0, r2dec 0.
* A single-function delta below **±0.20** is noise across compilers; on dpkg one
  function moved 0.9375 → 0.6000 on compiler version alone.

---

## 7. The rule

Every DecBench figure needs four tags: **build**, **metric version**,
**population**, and **compiler version**. Two numbers differing in any of them
are not comparable, however similar their names.
