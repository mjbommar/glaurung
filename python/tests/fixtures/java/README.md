# Java Test Fixtures

These Java sources are tiny regression fixtures authored for Glaurung tests. Tests
compile them locally into JARs instead of vendoring third-party or proprietary
archives.

- `recoverable/`: minimal Java source and resource fixture for recovery smoke tests.
- `corpus/modern/`: Java 17 fixture covering records, enums, JPMS module metadata,
  ServiceLoader metadata, and resources. Tests compile this source locally into a
  temporary JAR.
