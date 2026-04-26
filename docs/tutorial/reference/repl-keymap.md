# Glaurung REPL keymap

Every shortcut documented here is a single keystroke + arguments at the
`>>> ` prompt of `glaurung repl <binary> --db tutorial.glaurung`. Long
forms work too — both `n parse` and `rename parse` rename the function
at the cursor.

## Cursor / navigation

| Key | Long form | Action |
|---|---|---|
| `g <addr>` | `goto <addr>` | Jump cursor to address (hex `0x` or decimal) |
| `b` | `back` | Step back through cursor history |
| `f` | `forward` | Step forward through cursor history |

## Annotation (write to KB)

Every write here is `set_by="manual"` and enters the undo log (#228) —
`glaurung undo <db>` outside the REPL reverses it.

| Key | Long form | Action |
|---|---|---|
| `n <name>` | `rename <name>` | Rename the function at the cursor; auto-rerender shows callers updating (#220) |
| `n <addr> <name>` | `rename <addr> <name>` | Rename a specific function by entry VA |
| `y <c-type>` | `retype <c-type>` | Retype the data label at the cursor |
| `y <addr> <c-type>` | `retype <addr> <c-type>` | Retype a specific data label |
| `c <text>` | `comment <text>` | Comment at the cursor |
| `c <addr> <text>` | `comment <addr> <text>` | Comment at a specific VA |
| — | `label <addr> <name> [--type <c-type>]` | Set / retype a global data label |
| — | `proto <name> <return> <param-c-types...>` | Set a function prototype (used by call-site hints + propagation) |

## Inspection

| Key | Long form | Action |
|---|---|---|
| `x` | `xrefs` | Cross-references at cursor (callers / readers / writers / jumps) (#219) |
| `d` | `decomp` | Decompile the enclosing function with KB-aware rendering (named locals, prototype hints, signature comment) |
| `l` | `locals` | List stack-frame slots in the enclosing function |
| — | `locals discover` | Auto-populate slots from disasm operands (#191) |
| — | `locals rename <offset> <name>` | Rename a slot (manual) |
| `s` | `strings` | List triage-extracted strings (sample) |
| — | `functions` | List every named function in the KB |
| — | `types` | List every type in type_db |
| — | `show <type-name>` | Render a type's full body |
| — | `struct <field-list>` | Define an ad-hoc struct |

## Cross-binary + analysis

| Key | Long form | Action |
|---|---|---|
| — | `borrow <other.glaurung>` | Cross-binary symbol borrow (#170): pull names from a sibling KB |
| — | `propagate` | Run cross-function type propagation (#172/#195) over libc/winapi call sites |
| — | `recover-structs` | Run auto-struct recovery (#163) over heuristic `[reg+offset]` patterns |

## Agent (LLM, optional)

| Key | Long form | Action |
|---|---|---|
| — | `ask "<question>"` | LLM agent with full KB context; results cite evidence_log rows |

## Session

| Key | Long form | Action |
|---|---|---|
| `?` | `help` / `h` | Show the REPL help table |
| — | `save` | Persist KB to disk (run before `q` to lock in changes) |
| `q` | `quit` / `exit` | Exit the REPL |

## Cursor symbol conventions

When a command takes an `<addr>` and the cursor is set, the address
defaults to the cursor — most navigation/annotation commands work
without an explicit address:

```
>>> goto 0x1140
>>> n parse_packet      # renames the function at 0x1140
>>> x                   # xrefs at 0x1140
>>> c TODO: bounds check this
>>> save
```

## Undo from inside the REPL

Undo is a **CLI** subcommand, not a REPL command. After a session:

```bash
$ glaurung undo tutorial.glaurung
undo #5 function_names entry_va=0x1140  canonical: 'parse_packet' → 'sub_1140'
```

`save` (the REPL command) commits the undo log too, so the same DB is
inspectable from the CLI.

## See also

- [`cli-cheatsheet.md`](cli-cheatsheet.md) — the CLI surface
- [`set-by-precedence.md`](set-by-precedence.md) — why a manual rename can't be clobbered by an analyzer pass
- Tier 2 §E `naming-and-types.md` — the daily-basics rename loop
- Tier 2 §F `cross-references.md` — using `x` to navigate
