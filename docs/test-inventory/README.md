# Test inventory

> **Kind:** reference · **Status:** generated

A machine-readable index of every test, fixture, asset and harness in this
repository, with the field that matters most: **what actually runs it.**

Built by `tools/build_test_inventory.py` from five surveys that walked disjoint
territories against one schema. The merge refuses to publish if any entry fails
to parse, names a path that does not exist, or uses a domain outside the fixed
vocabulary — an inventory that quietly admits a stale path is worse than none,
because it reads as authority.

The plan that acts on what this inventory found is
[`docs/development/test-estate/`](../development/test-estate/README.md).

## Files

| file | what it is |
|---|---|
| `index.json` | the whole inventory, machine-readable |
| `index.yaml` | the same, for reading |
| `unreachable.json` | the subset nothing runs — the raw list |
| `unreachable-triage.md` | **that list classified into buckets that imply different actions** — read this first |
| `findings.md` | what the survey turned up, in prose |
| `coverage.md` | reach and domain tables |

Regenerate:

```bash
uv run python tools/build_test_inventory.py \
    --fragments <survey-fragments> --out docs/test-inventory
```

## Entry shape

```json
{
  "id": "python-tests/test_cfg.py",
  "kind": "python-test",
  "path": "python/tests/test_cfg.py",
  "title": "CFG construction and dominators",
  "subject": "One line: what this actually verifies or holds.",
  "domain": ["decompiler"],
  "count": 12, "count_of": "test functions",
  "markers": ["slow"], "features": ["python-ext"],
  "runs_by": "uv run pytest python/tests/test_cfg.py",
  "consumes": ["tests/decompiler_fixtures/build/*.so"],
  "gated_by": "default suite",
  "reach": "default-suite | ci | opt-in | unreachable",
  "notes": "Anything surprising: dead, unreferenced, duplicated, misfiled."
}
```

`reach` is derived from `gated_by`. The distinction it draws is not *how* a
thing runs but whether anything runs it **without a human deciding to**.

## Reading it

```bash
# what nothing runs
python3 -c "import json;[print(e['path']) for e in json.load(open('docs/test-inventory/unreachable.json'))['entries']]"

# everything in one domain
python3 -c "import json;[print(e['path']) for e in json.load(open('docs/test-inventory/index.json'))['entries'] if 'triage' in e['domain']]"

# what a fixture is consumed by
grep -l 'decompiler_fixtures/build' docs/test-inventory/index.json
```

## Scope and limits

The survey is a **point-in-time snapshot** at the commit recorded in
`index.json`. Counts were obtained by counting, not estimating, but `subject`
and `notes` are human judgements made while reading — treat them as a guide to
where to look, not as a contract.

Two things it deliberately does not do: it does not run anything, and it does
not judge whether a test is *good*. It answers what exists and what reaches it.
