# Glaurung canonical demos

Three end-to-end conversations showing what the agentic chat UI
delivers today. Each demo is grounded in a sample binary that ships
with the repo, so anyone can re-run the commands and see the same
output without external dependencies.

These demos drive priority calls on the roadmap: any task that
doesn't make at least one of these demos materially better can be
deferred. They are also the marketing deliverable for the Phase 5
chat UI launch (#203/#204).

| Demo | Sample binary | Status |
|---|---|---|
| 1. Malware triage | `samples/binaries/platforms/linux/amd64/export/native/clang/O0/c2_demo-clang-O0` | ✅ runnable today |
| 2. Vulnerability hunting | (synthetic vulnerable parser TBD) | 🚧 sample needed |
| 3. Patch analysis | `samples/binaries/platforms/linux/amd64/synthetic/switchy-c-gcc-O2{,-v2}` | ✅ runnable today |

See:
- [`demo-1-malware-triage.md`](./demo-1-malware-triage.md)
- [`demo-3-patch-analysis.md`](./demo-3-patch-analysis.md)
