# §O — Walkthrough 3: managed .NET / Mono PE

The .NET counterpart to §N. Managed PEs are a distinct format
class — the executable code is CIL bytecode and method names live
in ECMA-335 metadata tables, not in the PE symbol table. Glaurung's
CIL parser (#210) walks those tables to recover method names with
their fully-qualified `Namespace.Type::Method` shape.

The same `kickoff` → `find` → `view` workflow you learned in §M / §N
works here — that's the point. The format-specific recovery is
plumbing; the analyst experience is the same.

> **Verified output.** Every block is captured by
> `scripts/verify_tutorial.py` and stored under
> [`_fixtures/03-dotnet-pe/`](../_fixtures/03-dotnet-pe/).

## Sample

```bash
$ BIN=samples/binaries/platforms/linux/amd64/export/dotnet/mono/Hello-mono.exe
$ file $BIN
```

```text
samples/.../Hello-mono.exe: PE32 executable for MS Windows 4.00 (console),
Intel i386 Mono/.Net assembly, 3 sections
```

(Captured: [`_fixtures/03-dotnet-pe/file.out`](../_fixtures/03-dotnet-pe/file.out).)

Note the `Mono/.Net assembly` marker — this is `file`'s way of
saying "the COM data directory is non-empty," which is what makes
it a managed PE.

The corresponding C# source is in
`samples/source/csharp/Hello.cs`:

```csharp
using System;

public class Hello
{
    public static void Main(string[] args)
    {
        Console.WriteLine("Hello from C# (Mono)!");
    }
}
```

So we expect to recover `Hello::.ctor` (the default constructor
the C# compiler always generates) and `Hello::Main` (the entry
point).

## Phase 1: Triage

```bash
glaurung triage $BIN | head -10
```

Triage flags it as PE (x86) without yet decoding the CIL —
`kickoff` does that.

## Phase 2: Load (`kickoff`)

```bash
$ glaurung kickoff $BIN --db dotnet.glaurung
```

```markdown
# Kickoff analysis — Hello-mono.exe

- format: **PE**, arch: **x86**, size: **3072** bytes
- entry: **0x40238e**

## Functions
- discovered: **1** (with blocks: 1, named: 0)
- callgraph edges: **0**
- name sources: cil=2, analyzer=1

## Type system
- stdlib prototypes loaded: **192**
- DWARF types imported: **0**
- stack slots discovered: **1**
- types propagated: **0**
- auto-struct candidates: **0**

_completed in N ms_
```

(Captured: [`_fixtures/03-dotnet-pe/kickoff.out`](../_fixtures/03-dotnet-pe/kickoff.out).)

The line that matters: **`name sources: cil=2`**.

The CFG analyzer found 1 native function (the small bootstrap stub
the .NET loader needs at `0x40238e`), but the **CIL metadata
parser walked the ECMA-335 tables and recovered 2 managed-method
names** with their fully-qualified shape.

## Phase 3: Function ID

```bash
$ glaurung find dotnet.glaurung Hello --kind function
```

```text
kind        location        snippet
--------------------------------------------------------------------------------
function    0x402050        Hello::.ctor  (set_by=cil)
function    0x402058        Hello::Main  (set_by=cil)
```

(Captured: [`_fixtures/03-dotnet-pe/find-hello.out`](../_fixtures/03-dotnet-pe/find-hello.out).)

Two methods recovered:

- `Hello::.ctor` at `0x402050` — the default constructor that every
  C# class has even if you don't write one. C# compilers emit it
  automatically.
- `Hello::Main` at `0x402058` — the static entry point we wrote.

The `set_by=cil` tag distinguishes these from native function names
(`set_by=analyzer`).

## Phase 4: String/logic trace

```bash
glaurung strings $BIN | head
```

The `Hello from C# (Mono)!` string should be there. CIL is
bytecode — the strings are in the metadata's `#US` (user-strings)
heap, which our triage doesn't decode yet, but the same string
appears as a UTF-16 literal in the binary.

## Phase 5: Verify

The metadata tables encode the relationship between methods and
types. We've recovered `Hello::.ctor` and `Hello::Main` — both
methods of the `Hello` class — which matches the C# source
exactly:

```csharp
public class Hello {
    // implicit Hello::.ctor()
    public static void Main(string[] args) { ... }
}
```

## Phase 6: Annotate

The recovered names are already idiomatic — no rename needed for
clarity. What you might do:

```bash
glaurung repl $BIN --db dotnet.glaurung
>>> g 0x402058
>>> c "C# Main entry — calls Console.WriteLine"
>>> save
>>> q
```

If you wanted to rename `Hello::Main` → `entry_point`:

```
>>> g 0x402058
>>> n entry_point
  0x402058 → entry_point
```

The manual rename wins over `set_by=cil`. A subsequent `kickoff`
re-run won't put it back.

## What you've done

1. **Triage** confirmed: managed .NET PE.
2. **Load (kickoff)** ran the CIL metadata-table walker:
   2 method names recovered with full `Namespace.Type::Method`
   shape.
3. **Function ID** via `glaurung find Hello`.
4. **String/logic trace** noted the recovered methods correspond
   exactly to the C# source (the implicit `.ctor` + the explicit
   `Main`).
5. **Verify** noted the precedence rule — manual > cil > analyzer.

## What's different from §N

§N recovered names from a Go-runtime metadata table. §O recovered
names from a .NET CLR metadata table. Both use the same
**non-VA-based discovery** model — names come from a parser that
reads the binary's own structured metadata, not from the
generic ELF/PE symbol table.

The pattern generalises:

- Stripped C / C++ ELF? Use FLIRT (#158) + DWARF (#157).
- Stripped Go ELF? Use gopclntab (#212).
- Managed .NET PE? Use CIL metadata tables (#210).
- Java `.class` / `.jar`? Use the JVM classfile parser (#209) — but
  the structure is different enough that we treat it as a separate
  command (`glaurung classfile`); see §P next.

## Caveats

- v0 of the CIL parser handles the 95% case: standard
  .NET Framework / .NET Core / Mono assemblies. Generic methods
  (MethodSpec) and obfuscation-friendly variants are filed for
  v1.
- The image base used to compute VAs is read from the PE optional
  header (`0x400000` for this sample). The `0x402050` /
  `0x402058` VAs above are `image_base + RVA` from the metadata.

## What's next

- [§P `04-jvm-classfile.md`](04-jvm-classfile.md) — JVM
  bytecode, the third managed-runtime format.
- [§Q `05-vulnerable-parser.md`](05-vulnerable-parser.md) — back
  to native ELF for a CTF-style buffer overflow walkthrough.

→ [§P `04-jvm-classfile.md`](04-jvm-classfile.md)
