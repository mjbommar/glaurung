# §O — Managed .NET PE

> **Kind:** guide · **Status:** maintained

Goal: recognize a managed PE and recover method names from CIL metadata without
misrepresenting the file as ordinary x86 native code.

## Set up

```bash
BIN=samples/binaries/platforms/linux/amd64/export/dotnet/mono/Hello-mono.exe
DB=hello-mono.glaurung
file "$BIN"
uv run glaurung kickoff "$BIN" --db "$DB"
```

`file` identifies a PE32 Mono/.NET assembly. Glaurung's kickoff records the PE
container and CIL-derived method names in the persistent project. See
[`file.out`](../_fixtures/03-dotnet-pe/file.out) and
[`kickoff.out`](../_fixtures/03-dotnet-pe/kickoff.out).

## Find managed methods

```bash
uv run glaurung find "$DB" Hello --kind function
```

The current project exposes `Hello::Main` and `Hello::.ctor` with `set_by=cil`.
That provenance distinguishes metadata-derived names from analyzer placeholders
or manual edits. See [`find-hello.out`](../_fixtures/03-dotnet-pe/find-hello.out).

## Keep the layers separate

- PE describes the outer executable container.
- CIL metadata describes managed types and methods.
- A native entry stub or loader does not make CIL bodies native x86 functions.
- Native decompiler examples from the preceding chapters should not be applied
  unchanged to managed method bodies.

For deeper managed recovery, inspect `uv run glaurung java --help` only for JVM
inputs; .NET remains a distinct metadata and execution model.

Continue to [§P — JVM classfile and JAR](04-jvm-classfile.md).
