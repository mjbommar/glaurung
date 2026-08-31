## main_cold_eh_cleanup — Reviewer Note

### What the pipeline did
- Identified the function as a **compiler-generated `.cold` EH cleanup partition** of `main()` (produced by GCC's `-freorder-blocks-and-partition`), not user-authored code.
- Replaced the entire body — multiple landing-pad entry sequences containing thunk calls (`0x12a0`, `0x1300`, `0x1260`) and a `std::vector<std::string>::~vector` invocation — with a single `noreturn`/`cold` stub whose body is `__builtin_unreachable()`.
- Dropped all `rbp = var0` / `stack_N` reassignments as frame-pointer/optimizer artefacts.
- Renamed the symbol from `main.cold` to `main_cold` (the `.` is not legal in C identifiers).

### Assumptions not mechanically provable
- That `0x12a0`, `0x1300`, and `0x1260` are unwind/cleanup thunks (e.g. `_Unwind_Resume`, frame teardown helpers) rather than user functions with observable semantics. No disassembly of those targets is included.
- That this partition has **no semantics that need to be preserved at the C level** because the EH tables in `main()` reference it directly by address; reproducing it in C source is assumed unnecessary.
- That nothing else in the binary takes the address of `main.cold` or expects the exact symbol name (the rename to `main_cold` would break any such reference).

### Known divergences (acknowledged)
- The `std::vector<std::string>` destructor call and all thunk calls are **dropped** — if this stub were ever actually executed, no cleanup would run (potential leak; `_Unwind_Resume` would not be tail-called, so unwinding would terminate here instead of propagating).
- Multiple distinct landing-pad entry points with different call sequences are collapsed into one `unreachable`.

### Reviewer checklist
