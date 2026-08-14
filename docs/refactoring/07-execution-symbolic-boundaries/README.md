# Mini-project 7: execution and symbolic boundaries

## Problem

The concrete interpreter and symbolic subsystem share machine semantics, but
large symbolic modules also own exploration, ordered replay, IOCTL-specific
policy, and solver integration. Keeping these concerns adjacent is useful;
allowing them to share implicit state or duplicate instruction semantics is
not.

## Target design

```text
verified LLIR/MIR semantics
        |
 generic interpreter<StateDomain>
      /                     \
 concrete domain       symbolic domain
                             |
                    exploration strategy
                             |
                     solver adapter/policy
```

- Instruction effects have one implementation parameterized by a domain.
- Execution state, memory, path constraints, exploration scheduling, and solver
  selection have separate types and owners.
- Vulnerability-specific analyses consume trace/evidence APIs rather than
  embedding semantics or solver control.

## Proposed ownership

- `src/exec/machine/`: state, memory, step result, traps, limits.
- `src/exec/semantics/`: instruction effects shared by domains.
- `src/symbolic/domain/`: expressions, simplification, constraints.
- `src/symbolic/explore/`: search strategies and path budgets.
- `src/symbolic/solver/`: capability-based adapters and result validation.
- `src/symbolic/analyses/`: IOCTL and other security-specific consumers.
- `src/symbolic/replay/`: ordered trace capture/replay only.

## Phases

1. Inventory duplicated semantics and implicit global/environment policy.
2. Pin concrete behavior with differential tests against the development oracle
   where supported and real instruction fixtures everywhere else.
3. Define explicit step, trap, unknown, limit, and unsupported results.
4. Separate exploration scheduling from symbolic state transition.
5. Extract solver capabilities, timeout/budget handling, and checked results.
6. Move security analyses onto stable trace/evidence contracts.

## Exit evidence

- Concrete and symbolic execution call the same instruction-effect owner.
- Exploration strategies do not inspect solver implementation details.
- Solver `unknown`, timeout, unsupported theory, and invalid model remain
  distinct and fail closed.
- Feature combinations (`exec`, `symbolic`, solver backends, Python extension)
  compile and run their declared tests independently.
- Differential, replay-determinism, resource-limit, and malformed-input tests
  pass; performance baselines show no unexplained regression.

## Stop conditions

Stop if a refactor broadens supported semantics without oracle/fixture evidence,
maps unknown to satisfiable/unsatisfiable, weakens resource limits, or makes a
security-specific policy part of the generic interpreter.

