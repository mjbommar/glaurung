# Mini-project 6: knowledge-base boundaries

> **Kind:** record · **Date:** 2026-08-13

## Problem

The SQLite knowledge-base layer spans persistent project state, xrefs, CFGs,
types, binary diffs, agent memory, and workflow-specific queries. Large modules
such as `xref_db.py` risk combining schema, migration, hydration, query policy,
and domain conversion. Those concerns need different compatibility guarantees.

## Target design

- `kb/schema/`: versioned migrations and integrity checks.
- `kb/storage/`: connection lifecycle, transactions, WAL, and bounded queries.
- `kb/repositories/`: narrow repositories for symbols, xrefs, CFG, types,
  annotations, and findings.
- `kb/domain/`: storage-independent records and provenance rules.
- `kb/services/`: cross-repository use cases and explicit unit-of-work scope.

Repositories return typed records or typed absence/incompleteness. They do not
return partially interpreted SQL rows to CLI, renderers, or agents.

## Phases

1. Document current schema versions, foreign keys, indexes, write paths, and
   eager hydration costs.
2. Add migration tests from every shipped schema version using durable fixture
   databases with sensitive content excluded.
3. Centralize connection and transaction policy.
4. Extract one repository at a time, beginning with types and xrefs because
   they feed the program semantic environment.
5. Move cross-repository operations into services with atomicity tests.
6. Add bounded pagination/streaming and measure large-project open/query costs.

## Required invariants

- Manual annotations always outrank automated evidence and are never deleted by
  refresh/reanalysis.
- Provenance survives round trips and migrations.
- Foreign keys and schema validation are enabled on every connection.
- Writes are transactional and interruption-safe.
- Unknown future schema versions fail with a clear error; they are never opened
  as if current.

## Exit evidence

- SQL appears only in migration/storage/repository modules.
- Agents and CLI code depend on services or repository protocols, not concrete
  SQLite connections.
- Clean-create, upgrade, rollback-on-failure, concurrent-reader, and manual-wins
  tests pass.
- Open time and memory use are recorded for representative real project files.
- Backup/recovery behavior is documented and exercised.

## Stop conditions

Stop if migration testing uses only a freshly created database, if a rewrite
loses provenance, or if repository extraction changes transaction boundaries
without an atomicity test.

