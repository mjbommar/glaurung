# §N — Stripped Go binary

Goal: recover useful Go names from runtime metadata and distinguish recovered
name coverage from functions selected for deeper native analysis.

## Set up

```bash
BIN=samples/binaries/platforms/linux/amd64/export/go/hello-go
DB=hello-go.glaurung
file "$BIN"
uv run glaurung kickoff "$BIN" --db "$DB"
```

The input is a stripped, statically linked Go ELF. The current report recovers
gopclntab names and analyzes a large native-function subset; those are different
populations and their counts can evolve independently. See
[`file.out`](../_fixtures/03-stripped-go/file.out) and
[`kickoff.out`](../_fixtures/03-stripped-go/kickoff.out).

## Locate the program entry logic

```bash
uv run glaurung find "$DB" 'main.main$' \
  --regex --kind function
uv run glaurung find "$DB" 'main\.' \
  --regex --kind function --limit 20
```

Anchoring with `$` avoids unrelated suffix matches. The namespace query shows
other package-local functions. Current results are
[`find-main-main.out`](../_fixtures/03-stripped-go/find-main-main.out) and
[`find-main-namespace.out`](../_fixtures/03-stripped-go/find-main-namespace.out).

## Pivot through runtime names

```bash
uv run glaurung find "$DB" 'runtime.main$' \
  --regex --kind function
uv run glaurung find "$DB" 'runtime.gopanic$' \
  --regex --kind function
uv run glaurung find "$DB" internal/abi.Kind.String \
  --kind function
```

These lookups demonstrate that stripped does not mean nameless when Go runtime
metadata remains. See
[`find-runtime-main.out`](../_fixtures/03-stripped-go/find-runtime-main.out),
[`find-runtime-gopanic.out`](../_fixtures/03-stripped-go/find-runtime-gopanic.out),
and [`find-internal-abi.out`](../_fixtures/03-stripped-go/find-internal-abi.out).

## Interpretation limits

- A recovered gopclntab name is strong naming evidence, not proof that every
  function body was completely analyzed.
- Statically linked runtimes create a very large search space; narrow queries
  and bounded output are essential.
- Names can guide decompilation and xrefs, but important behavior still needs
  instruction- and callsite-level confirmation.

Continue to [§O — Managed .NET PE](03-managed-dotnet-pe.md).
