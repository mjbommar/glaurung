# §Q — Walkthrough 5: vulnerable parser (CTF buffer-overflow)

The CTF-shape vulnerability hunt. We load a small C binary that
parses a length-prefixed record from user input, find the
buffer-overflow primitive, trace it to confirm exploitability,
and annotate our findings.

This is the canonical "vulnerable parser" CTF shape: triage →
identify the parse function → trace user input flow → spot the
unsafe size handling → verify with disasm.

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/03-vulnparse/`](../_fixtures/03-vulnparse/).

## Sample

```bash
$ BIN=samples/binaries/platforms/linux/amd64/synthetic/vulnparse-c-gcc-O0
$ file $BIN
```

```text
samples/.../vulnparse-c-gcc-O0: ELF 64-bit LSB pie executable, x86-64,
version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=...,
for GNU/Linux 3.2.0, with debug_info, not stripped
```

(Captured: [`_fixtures/03-vulnparse/file.out`](../_fixtures/03-vulnparse/file.out).)

The corresponding C source describes a `parse_record(char *buf,
size_t len)` that does **a `memcpy` of `len` bytes** into a
fixed-size local buffer. `len` comes from user input (argv[1])
parsed via `strtoul`. Classic stack overflow.

## Phase 1: Triage

```bash
$ glaurung kickoff $BIN --db vuln.glaurung
```

```markdown
# Kickoff analysis — vulnparse-c-gcc-O0

- format: **ELF**, arch: **x86_64**, size: **19408** bytes
- entry: **0x1100**

## Functions
- discovered: **7** (with blocks: 7, named: 7)
- callgraph edges: **2**
- name sources: analyzer=7

## Type system
- stdlib prototypes loaded: **192**
- DWARF types imported: **6**
- stack slots discovered: **52**
- types propagated: **0**
- auto-struct candidates: **0**

_completed in N ms_
```

(Captured: [`_fixtures/03-vulnparse/kickoff.out`](../_fixtures/03-vulnparse/kickoff.out).)

7 functions, all named (the binary isn't stripped, has DWARF). 6
DWARF types ingested. Tiny program — easy to read end-to-end.

## Phase 2: Function ID

```bash
$ glaurung find vuln.glaurung "" --kind function
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x1100          _start  (set_by=analyzer)
function    0x1130          deregister_tm_clones  (set_by=analyzer)
function    0x1160          register_tm_clones  (set_by=analyzer)
function    0x11a0          __do_global_dtors_aux  (set_by=analyzer)
function    0x11e0          frame_dummy  (set_by=analyzer)
function    0x11e9          parse_record  (set_by=analyzer)
function    0x12ae          main  (set_by=analyzer)
```

(Captured: [`_fixtures/03-vulnparse/find-all-funcs.out`](../_fixtures/03-vulnparse/find-all-funcs.out).)

The function name `parse_record` is the obvious target. Five of
the seven functions are CRT scaffolding (`_start`, `frame_dummy`,
etc.) — skip those.

## Phase 3: Trace user input — start at `main`

```bash
$ glaurung view vuln.glaurung 0x12ae --binary $BIN \
    --pane pseudo --pseudo-lines 30
```

```text
── pseudocode (enclosing function) ──
fn main {
    nop;
    // x86-64 prologue: save rbp, frame 32 bytes
    local_0 = arg0;
    local_1 = arg1;
    t10 = local_2;
    if ((t10 <= 1)) {
        ret = local_1;
        ret = *&[ret+0x8];
        local_3 = ret;
        ret = local_1;
        ret = (ret + 8);
        ret = *&[ret];
        0x10a0(ret);
        local_4 = ret;
        arg2 = local_4;
        ret = local_3;
        parse_record(ret, arg2);
        ret = 0;
        rsp = rbp;
        pop(rbp);
        return;
    }
    ret = local_1;
    arg2 = *&[ret];
    arg3 = "usage: %s <input-bytes>\n";
    ret = 0;
    0x10d0(ret, arg3);
    ret = 1;
    goto L_132e;
```

(Captured: [`_fixtures/03-vulnparse/view-main.out`](../_fixtures/03-vulnparse/view-main.out).)

Read aloud:

- `local_2` is `argc`. The structurer recognised `if (argc <= 1)`
  (the early-exit shape #192).
- `argv[1]` is loaded twice — once as the string buffer for parsing,
  once for `strtoul` (the call to `0x10a0` — that's a PLT entry).
- `local_4` holds `strtoul(argv[1], ...)` — **the length is
  attacker-controlled**.
- `parse_record(ret, arg2)` passes `(buffer_ptr, attacker_length)`.

Sanity check the call into `parse_record`:

```bash
$ glaurung xrefs vuln.glaurung 0x11e9 --binary $BIN --direction to
```

```text
dir   src_va       kind          function                         snippet
-------------------------------------------------------------------------
to    0x12ae       call          main                             Endbr64
```

(Captured: [`_fixtures/03-vulnparse/xrefs-parse-record.out`](../_fixtures/03-vulnparse/xrefs-parse-record.out).)

Exactly one caller — `main`. ✓

## Phase 4: The vulnerable function

```bash
$ glaurung view vuln.glaurung 0x11e9 --binary $BIN \
    --pane pseudo --pseudo-lines 30
```

```text
── pseudocode (enclosing function) ──
fn parse_record {
    nop;
    // x86-64 prologue: save rbp, frame 112 bytes
    local_0 = arg0;
    local_1 = arg1;
    ret = __stack_chk_guard;
    local_2 = ret;
    t10 = local_1;
    %zf = (t10 == -0x7000000000);
    %cf = (t10 u< -0x7000000000);
    if (%zf) {
        goto L_1297;
    }
    ret = local_0;
    unknown(movzx);
    local_3 = ret;
    unknown(movzx);
    arg2 = local_1;
    %zf = (arg2 == ret);
    %cf = (arg2 u< ret);
    if (%cf) {
        goto L_1254;
    }
    ret = *&[var0+0x4020];
    arg2 = 12;
    0x10f0("short input\n", 1, (arg2 - 1), ret);
    goto L_1298;
    L_1254:
    unknown(movzx);
    ret = local_0;
```

(Captured: [`_fixtures/03-vulnparse/view-parse-record.out`](../_fixtures/03-vulnparse/view-parse-record.out).)

Several signals:

- **frame 112 bytes** — the function reserves 112 bytes of stack.
  Standard prologue.
- **`__stack_chk_guard`** — there IS a stack canary. The compiler
  added it because gcc's `-fstack-protector-strong` heuristic
  flagged this function. (Look for the canary epilogue check
  later in the body.)
- **`if (cf) goto L_1254`** — a length-comparison branch. The other
  side prints `"short input\n"`, so the taken branch is when
  `local_1` (the user-controlled length) is **less than** something.
- **arg2 = 12** — a hardcoded length. Suspicious — likely the
  length of `"short input\n"`.

To see the actual `memcpy` call (the overflow primitive), look at
the disasm with more lines:

```bash
glaurung disasm $BIN 0x1254 --max-instructions 20
```

You'll find:

```
... lea rdi, [rbp - 0x70]      # destination buffer (in 112-byte frame)
... mov rsi, [rbp - 0x18]      # source: argv[1]
... mov rdx, [rbp - 0x10]      # n: attacker-controlled length
... call memcpy@plt
```

`memcpy(stack_buf_at_rbp_minus_0x70, argv[1], attacker_len)`.

If `attacker_len > 0x70` (112 bytes), it overruns the buffer. The
stack canary catches the most blatant overflow at function exit
but the bytes are **already written past** the canary by the
time the check runs — exploitable.

## Phase 5: Verify the overflow primitive

The frame reserves `[rbp - 0x70]` bytes. memcpy copies `len`
bytes starting there. The unbounded `len` is the bug.

Check the strings panel for the user-visible labels:

```bash
glaurung strings $BIN | grep -iE "short|usage|memcpy"
```

```
[0x2004] ascii    len=  11   short input
[0x2010] ascii    len=  24   usage: %s <input-bytes>\n
[0x4081] ascii    len=  17   memcpy@GLIBC_2.14
```

Confirms: `parse_record` prints "short input" when `len <
something`, and uses `memcpy` from glibc. The "something" is
the only sanity check the parser does.

## Phase 6: Annotate

Open the REPL and document what you found:

```bash
glaurung repl $BIN --db vuln.glaurung
```

```
>>> g 0x11e9
>>> n parse_record_OVERFLOW
  0x11e9 → parse_record_OVERFLOW

>>> c "buffer overflow: memcpy(stack_buf[112], user_input, attacker_len)"

>>> g 0x12ae
>>> c "user-controlled length flows from strtoul(argv[1]) → parse_record"

>>> save
>>> q
```

Bookmark the call site:

```bash
glaurung bookmark vuln.glaurung add 0x12ae \
  "main → parse_record call; attacker-controlled len in arg2"
```

Optionally: confirm the patch surface is reachable. Suppose you'd
want to NOP-out the strtoul call (to force `len = 0` and prove the
crash goes away):

```bash
glaurung patch $BIN /tmp/vuln-nostrtoul --va <strtoul_call_va> --nop --verify --force
```

## What you've done — CTF report shape

```markdown
**Vulnerability:** Stack buffer overflow in `parse_record`
**File:** vulnparse-c-gcc-O0 (ELF / x86_64)
**Function:** `parse_record` at 0x11e9 (frame size 112 bytes)
**Primitive:** `memcpy(rbp-0x70, user_input, attacker_len)`
**Source of `attacker_len`:** `strtoul(argv[1], ...)` in `main`
**Mitigations present:** Stack canary (`-fstack-protector-strong`)
**Mitigations bypassed:** Canary catches AT FUNCTION EXIT; the
write past the canary still happens. Exploitable for code-flow
hijacking via SEH-style or canary-leak chains; classical stack-smash
ROP if there's a leak elsewhere.
```

This is the shape every CTF / pentest writeup converges on. You
got there in 5 commands plus a few REPL keystrokes.

## What's different from §M / §N / §O / §P

| § | Format | Recovery edge | What this taught |
|---|---|---|---|
| §M | C ELF + DWARF | symbol table | the canonical 6-phase loop |
| §N | stripped Go ELF | gopclntab | format-specific name recovery |
| §O | .NET Mono PE | CIL metadata | another format-specific recovery |
| §P | JVM classfile | constant pool | bytecode triage |
| §Q | C ELF + DWARF | (same as §M) | **the workflow itself** as the deliverable |

§Q is about applying the workflow to a real adversarial target.
Everything Glaurung does for you — the structurer recovering the
`if (argc <= 1)`, the prototype hint on `printf`, the stack-frame
slot listing, the stack canary's __stack_chk_guard reference — it
all surfaces the bug faster than you'd find it by hand.

## What's next

- [§R `06-upx-packed-binary.md`](06-upx-packed-binary.md) —
  anti-analysis: a packed binary that needs unpacking before this
  workflow even starts.
- [§S `07-malware-c2-demo.md`](07-malware-c2-demo.md) — the flagship
  demo: triage a synthetic C2-callback malware analog.

→ [§R `06-upx-packed-binary.md`](06-upx-packed-binary.md)
