# DRAFT — not submitted

**Target:** issue on `Noelo-Lab/decbench`

**Title:** `[CLAUDE] Glaurung now emits direct variable addresses without line mappings`

Glaurung now includes structured variables and direct instruction addresses in
its JSON decompiler output. This corrects one part of the Glaurung note in
[`docs/decompilers.md`](https://github.com/Noelo-Lab/decbench/blob/d59567c2b90215087113ac52b34898ba4448594c/docs/decompilers.md#L298-L375).

The note is still right about line mappings. Glaurung's final AST does not keep
instruction origins, so we cannot provide reliable `line_mappings` yet. Direct
addresses for stack variables do not need that AST link. Glaurung joins each
recovered stack variable to low-level intermediate representation (LLIR) memory
accesses with the same frame base and offset. The LLIR instruction supplies the
machine address.

The implementation is in
[`variable_addresses.rs`](https://github.com/mjbommar/glaurung/blob/81feb37295a4ba06c328af178871ed665531ce7a/src/ir/variable_addresses.rs).
The JSON output now has this form:

```json
{
  "name": "target",
  "entry_va": 4198400,
  "size": 64,
  "pseudocode": "long target(long arg0) { ... }",
  "variables": [
    {
      "name": "arg0",
      "type": "long",
      "kind": "arg",
      "arg_index": 0,
      "stack_offset": null,
      "size": null,
      "addresses": []
    },
    {
      "name": "count",
      "type": "int32_t",
      "kind": "stack",
      "arg_index": null,
      "stack_offset": -20,
      "size": 4,
      "addresses": [4198404, 4198412]
    }
  ]
}
```

An empty `addresses` list means that Glaurung makes no address claim. Arguments
are empty because tracking a register argument requires a live-range analysis,
not a frame-offset match. Stack variables are also left empty when the frame
coordinate is not stable or clear. The implementation uses exact matches and
drops uncertain evidence.

We checked 8,441 emitted addresses across ELF, PE, and Mach-O files on x86-64,
i386, and AArch64. We used `objdump` and `llvm-objdump` as independent checks.
Every address was an instruction start, and every instruction accessed the
reported stack slot. The test and audit code is in
[`test_variable_addresses.py`](https://github.com/mjbommar/glaurung/blob/81feb37295a4ba06c328af178871ed665531ce7a/python/tests/test_variable_addresses.py).

One detail may matter to DecBench's sanitizer: a function can have non-contiguous
code. We found two valid addresses in a `.cold` part placed below the main
function. A check limited to `[entry_va, entry_va + size)` will drop those
addresses. Dropping them is safe, but it loses valid evidence.

Running this over the full corpus costs nothing. Glaurung's decompiler is
deterministic and makes no network calls. Tracing a full `decompile --all` run
with `strace -f -e trace=socket,connect` records zero `socket()` calls, zero
`connect()` calls, and no `AF_INET`. No LLM client library is loaded from disk,
and the Rust crate has no HTTP dependency. The LLM agent in the project is a
separate optional surface that the decompile path never touches. The same holds
with a project database attached.

That removes the cost argument for keeping Glaurung on the sample set only. The
hidden full-corpus rows, such as 49/34,312, come from scoring a sample-only
submission against a full denominator. PR #48's own in-tree run reports
86,660/86,671 for Glaurung on the full corpus. We would like to move to a
full-corpus entry and can produce whatever a submission needs.

DecBench's current Glaurung adapter still sets `variables=[]` in
[`_build_function`](https://github.com/Noelo-Lab/decbench/blob/main/decbench/decompilers/raw/glaurung_raw.py#L539-L554).
The direct-address model and sanitizer are part of
[PR #48](https://github.com/Noelo-Lab/decbench/pull/48), which already handles
direct variable addresses without a line map for dewolf and Reko.
Would you accept a small PR that reads the new `variables` array while leaving
`line_mappings` empty? I can also update the Glaurung section of
`docs/decompilers.md` in the same PR.
