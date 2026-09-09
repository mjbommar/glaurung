# WP3 address-substitution origin transfer

> **Kind:** record · **Date:** 2026-09-10

## Outcome

Commit `9a417d69` makes exact captured-definition substitution accept an
attributed semantic register when replacing a `Lea` or PDB-field address base
or index. Because these address nodes store components as `VReg`, the
replacement expression's origins transfer to the enclosing address rather than
being discarded.

The rule remains narrow. Only a semantic bare-register replacement qualifies;
arithmetic or memory expressions still remain statement-rooted instead of being
forced into a register-only address component.

## Focused TDD

A new ownership contract was observed red: substitution returned false for an
attributed register definition. After repair:

```text
attributed_register_definition_substitutes_into_address_with_its_owner: pass
nonsubstitutable_address_dependency_stays_statement_rooted:             pass
a_value_numbered_argument_write_folds_into_the_call:                    pass
```

The positive contract additionally proves the enclosing address carries the
replacement owner after substitution.

An exact detached release build of `9a417d69` was fresh. The established ARM
call-argument regression passes:

```text
test_real_arm_hard_float_compare_does_not_erase_three_call_args: pass
```

No broad Rust, Python, fixture, DecBench, or Joern suite ran. The recent Hello
checkpoint was not repeated because this increment has a direct ARM real-binary
witness.

This closes one bounded substitution/ownership boundary, not WP3. Authoritative
identity, explicit invalidation, and the remaining semantic-consumer audit stay
open.
