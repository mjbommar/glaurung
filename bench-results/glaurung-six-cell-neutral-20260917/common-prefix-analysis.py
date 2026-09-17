#!/usr/bin/env python3
"""EXPLORATORY, NOT PREREGISTERED. When the five repetitions of a driver are not
fixed-work (a wall-clock budget cut exploration at different points), run the
registered analyzer's own statistics (same functions, same seeds) over the
common prefix of check occurrences whose identity is equal in all five
repetitions. Everything after the first divergence is discarded. Reports the
same four v2 contrasts plus per-cell sums, tails, and unknown counts."""
import importlib.util, json, pathlib, statistics, sys, collections
spec = importlib.util.spec_from_file_location("az", "/home/mjbommar/projects/personal/axeyum/scripts/analyze-glaurung-paired-traces.py")
az = importlib.util.module_from_spec(spec); sys.modules["az"] = az; spec.loader.exec_module(az)
import dataclasses

roots = [pathlib.Path(p) for p in sys.argv[1:-1]]
out = pathlib.Path(sys.argv[-1])
traces = [az.load_trace(r) for r in roots]
full_counts = [len(t.checks) for t in traces]
ids = [tuple(c.identity for c in t.checks) for t in traces]
prefix = 0
while all(prefix < len(i) for i in ids) and len({i[prefix] for i in ids}) == 1:
    prefix += 1
traces = [dataclasses.replace(t, checks=t.checks[:prefix]) for t in traces]
cells = az.FAIR_CELLS_V2
specs = (("cold_z3_over_axeyum", "z3_cold", "axeyum_cold"), ("warm_z3_over_axeyum", "z3_warm", "axeyum_warm"),
         ("z3_cold_over_warm", "z3_cold", "z3_warm"), ("axeyum_cold_over_warm", "axeyum_cold", "axeyum_warm"))
comparisons = {}
for offset, (name, num, den) in enumerate(specs):
    idx = az.stable_fair_cell_indices(traces, num, den)
    comparisons[name] = az.fair_cell_population_summary(traces, idx, num, den, 10_000, 100 + offset)
per_cell = {}
for cell in cells:
    vals = [int(getattr(c, f"{cell}_nanos")) for t in traces for c in t.checks]
    unknown = sum(getattr(c, f"{cell}_outcome") == "unknown" for t in traces for c in t.checks)
    per_cell[cell] = {"occurrences": len(vals), "unknown": unknown, "sum_nanos_all_reps": sum(vals),
                      **az.latency_summary(vals), "max": max(vals)}
# also full-trace per-cell sums (everything the processes did, prefix or not)
full = {}
for cell in cells:
    full[cell] = {"sum_nanos_per_rep": [sum(int(getattr(c, f"{cell}_nanos")) for c in az.load_trace(r).checks) for r in roots],
                  "unknown_per_rep": [sum(getattr(c, f"{cell}_outcome") == "unknown" for c in az.load_trace(r).checks) for r in roots]}
all_four = [i for i in range(prefix) if all(getattr(t.checks[i], f"{c}_outcome") in az.DECIDED for c in cells for t in traces)]
report = {
    "schema": "axeyum-glaurung-common-prefix-exploratory-v1",
    "preregistered": False,
    "reason": "repetitions are not fixed-work; the registered analyzer refuses the driver (fixed-work check identity drift)",
    "driver": {"label": traces[0].driver_label, "sha256": traces[0].driver_sha256},
    "trace_paths": [str(r) for r in roots],
    "checks_per_repetition_full": full_counts,
    "common_prefix_checks": prefix,
    "all_four_decided_in_prefix": len(all_four),
    "four_cell_comparisons_common_prefix": comparisons,
    "per_cell_latency_common_prefix": per_cell,
    "per_cell_full_trace": full,
    "methodology": "same functions and seeds as analyze-glaurung-paired-traces.py v2 path, applied to the common prefix only",
}
out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps({k: (round(v["per_occurrence_geomean_speedup"], 4), [round(x, 4) for x in v["bootstrap_95_percent_ci"]], round(v["per_run_geomean_speedup"]["coefficient_of_variation"], 4)) for k, v in comparisons.items()}))
print("prefix", prefix, "of", full_counts)
