# §P — Walkthrough 4: JVM classfile + JAR triage

The third managed-runtime format. Java `.class` files and `.jar`
archives ship with full method metadata in the constant pool —
no VAs, no PE/ELF headers, just structured bytecode. Glaurung's
classfile parser (#209) decodes the constant pool, type table,
and method table to surface every class's full signature.

This walkthrough is the **shortest** in Tier 3 because the format
is the most self-describing — a Java `.class` file *is* the
analysis target, not a container that has to be triaged first.

## Sample

```bash
CLS=samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class
JAR=samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar
file $CLS
```

```
compiled Java class data, version 61.0 (Java SE 17)
```

The corresponding source is in
`samples/source/java/HelloWorld.java`:

```java
public class HelloWorld {
    private static final int GLOBAL_COUNTER = 42;
    private String message;
    private int counter;

    public HelloWorld(String message) { ... }
    public HelloWorld() { this("Hello, World from Java!"); }
    public void printMessage() { ... }
    public int getCounter() { return counter; }
    public static void printGlobalInfo() { ... }
    public static void main(String[] args) { ... }
}
```

So we expect: 3 fields, 6 methods (including 2 constructors).

## Phase 1: Triage

For class files, triage and load are the same step:

```bash
glaurung classfile $CLS
```

```
class HelloWorld  (Java 17 (classfile 61))
  extends java/lang/Object
  access: public
  fields: 3
    private static final     GLOBAL_COUNTER: I
    private                  message: Ljava/lang/String;
    private                  counter: I
  methods: 6
    public                   <init>(Ljava/lang/String;)V
    public                   <init>()V
    public                   printMessage()V
    public                   getCounter()I
    public static            printGlobalInfo()V
    public static            main([Ljava/lang/String;)V
```

Read every line:

- **`class HelloWorld`** — the class's name from the `this_class`
  constant-pool entry.
- **`(Java 17 (classfile 61))`** — Java SE 17 maps to classfile
  version 61 (the major-version byte at offset 6 of the
  classfile is `0x3D`).
- **`extends java/lang/Object`** — `super_class`'s constant-pool
  entry. (JVM uses `/` instead of `.` for namespace separation
  internally.)
- **`access: public`** — decoded from the `access_flags` u16.
- **fields** — every field row from the `fields[]` table. Each
  row prints its modifiers, name, and JVM type descriptor.
- **methods** — every method row from `methods[]`. Same shape:
  modifiers + name + JVM descriptor.

## JVM type descriptors

Reading the descriptor column is a skill that pays off across every
Java analysis tool:

| Descriptor | Java type |
|---|---|
| `I` | int |
| `J` | long |
| `Z` | boolean |
| `B` | byte |
| `S` | short |
| `C` | char |
| `F` | float |
| `D` | double |
| `V` | void |
| `Ljava/lang/String;` | java.lang.String |
| `[I` | int[] |
| `[Ljava/lang/String;` | String[] |

So `main([Ljava/lang/String;)V` is `public static void main(String[])`.
`printMessage()V` is `public void printMessage()`. Standard.

## Phase 2-6: Compressed

Because a class file is self-contained, the rest of the CTF shape
collapses:

- **Function ID** — the methods are right there in the listing.
- **String/logic trace** — `glaurung classfile` lists everything;
  if you need bytecode-level disassembly, use `javap -c
  HelloWorld` from the JDK (we don't ship a bytecode disassembler
  yet — see [#236 GAP](../../architecture/IDA_GHIDRA_PARITY.md)).
- **Verify** — the parsed structure should match the source. Six
  methods, three fields, name `HelloWorld`. ✓
- **Annotate** — class files don't have a `.glaurung` project file
  today (#236 GAP: there's no VA model for `.class` files, so
  function_names doesn't apply). You can keep notes in a separate
  journal.

## Walking a JAR

Jar / war / ear files are zip archives full of class entries:

```bash
glaurung classfile $JAR
```

```
# HelloWorld.jar: 1 class file(s)

class HelloWorld  (Java 17 (classfile 61))
  extends java/lang/Object
  ...

_parsed 1 class(es)_
```

The walker iterates every `.class` inside the archive and prints
the same per-class summary. For a JAR with 50+ classes, this is
a quick way to map the class hierarchy without unzipping.

## What's different from §M / §N / §O

| Walkthrough | Format | Recovery surface |
|---|---|---|
| §M hello-c-clang | ELF | DWARF + symbol table |
| §N stripped Go | ELF | gopclntab table walker |
| §O Mono PE | PE | ECMA-335 metadata tables |
| §P JVM | classfile / JAR | constant pool + method table |

All four are "structured metadata recovery." JVM is special only
because the recovery is so complete — every class's full signature
is right there in the constant pool — that there's nothing else
to triage.

## Caveats / GAPs

- **No KB integration yet.** Classfile parsing produces a structured
  printout, not a `.glaurung` project file. So `glaurung xrefs`,
  `glaurung view`, `glaurung find` don't work on `.class` files
  today. [#236 GAP](../../architecture/IDA_GHIDRA_PARITY.md) tracks
  the design for a `bytecode_methods` table.
- **No bytecode disassembly.** v0 of #209 doesn't decode the
  attribute body containing the JVM bytecode. For now, use
  `javap -c -p` from the JDK as a complement.
- **Modified UTF-8 strings.** The JVM Specification calls for
  "modified UTF-8" — same as standard UTF-8 except NUL is encoded
  as 0xC0 0x80 and supplementary characters use surrogate pairs.
  We use a lossy decode; class names and method names are nearly
  always ASCII so this rarely matters.

## What's next

- [§Q `05-vulnerable-parser.md`](05-vulnerable-parser.md) — back to
  native ELF for vulnerability hunting (CTF buffer-overflow shape).
- [§R `06-upx-packed-binary.md`](06-upx-packed-binary.md) —
  anti-analysis: UPX detection.
- [§S `07-malware-c2-demo.md`](07-malware-c2-demo.md) — the flagship
  demo.

→ [§Q `05-vulnerable-parser.md`](05-vulnerable-parser.md)
