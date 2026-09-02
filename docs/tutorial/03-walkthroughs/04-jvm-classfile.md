# §P — JVM classfile and JAR

> **Kind:** guide · **Status:** maintained

Goal: inspect JVM metadata directly and understand the difference between a
single classfile and an archive containing class entries.

## Inspect one class

```bash
CLASS=samples/binaries/platforms/linux/amd64/export/java/HelloWorld.class
file "$CLASS"
uv run glaurung classfile "$CLASS"
```

The checked input is Java 17 classfile version 61.0. `classfile` reports the
class name, superclass, access, fields, and method descriptors. See
[`file-class.out`](../_fixtures/03-jvm/file-class.out) and
[`classfile.out`](../_fixtures/03-jvm/classfile.out).

## Inspect the JAR

```bash
JAR=samples/binaries/platforms/linux/amd64/export/java/HelloWorld.jar
uv run glaurung classfile "$JAR"
```

For an archive, the command enumerates class entries and renders their metadata.
The shipped example currently contains one class; do not generalize that count
to arbitrary JARs. See
[`classfile-jar.out`](../_fixtures/03-jvm/classfile-jar.out).

## Choose the right Java surface

- `classfile` is deterministic metadata inspection for `.class` files and
  archives.
- `java triage`, `java security`, and `java recovery` are larger JVM workflows;
  inspect `uv run glaurung java --help` before use.
- `java-recovery-report` can invoke external recovery/build tooling and has its
  own output and network policies.

Class and method names are metadata facts. Higher-level source reconstruction
is a separate, fallible step and should retain validation evidence.

Continue to [§Q — Vulnerable parser](05-vulnerable-parser.md).
