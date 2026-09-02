"""Decompile command — render a function's lifted LLIR as C-like pseudocode.

Thin wrapper around the native ``glaurung.ir.decompile_at`` /
``glaurung.ir.decompile_all`` bindings. The full decompiler pipeline
(cfg discovery → LLIR lift → SSA → structural analysis → AST lowering →
expression reconstruction → DCE → name resolution → call-arg reconstruction)
runs inside the Rust extension; this command is just the CLI frontend.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Optional

import glaurung as g
from glaurung.windows_config import load_windows_analysis_config

from .base import BaseCommand
from .. import cache as _cache
from ..kb_names import (
    load_analyst_comments,
    load_analyst_locals,
    load_analyst_names,
    load_analyst_prototype,
    locals_digest,
    overlay_digest,
    prototype_digest,
    render_comment_header,
)
from ..formatters.base import BaseFormatter, OutputFormat
from ..func_ref import (
    FuncResolutionError,
    parse_func_arg,
    resolve_func_to_va,
)

log = logging.getLogger(__name__)


def _decompile_at_cached(
    *,
    path: str,
    func_va: int,
    style: str,
    types: bool,
    timeout_ms: int,
    max_blocks: int,
    max_instructions: int,
    pdb_cache: str,
    cache_dir_arg: Optional[str],
    analyst_names: Optional[dict[int, str]] = None,
    analyst_locals: Optional[dict[int, tuple[str, str]]] = None,
    analyst_prototype: Optional[
        tuple[str, list[str], bool] | tuple[str, list[str], bool, list[str]]
    ] = None,
) -> str:
    """Run ``g.ir.decompile_at`` with optional persistent caching.

    Entries are keyed by (glaurung version, sha256(binary), VA, decompile
    flags). Cache logic is best-effort: any cache I/O failure logs a WARNING
    and falls through to the live decompile, so behaviour is identical to a
    direct ``decompile_at`` call when caching is disabled or unavailable.
    """
    cache_dir = _cache.resolve_cache_dir(cache_dir_arg)
    paths = None
    if cache_dir is not None:
        try:
            flags = _cache.canonical_flag_dict(
                [
                    ("style", style or "plain"),
                    ("types", bool(types)),
                    ("timeout_ms", int(timeout_ms)),
                    ("max_blocks", int(max_blocks)),
                    ("max_instructions", int(max_instructions)),
                    # The PDB cache *path* is a machine-local detail and must
                    # not enter the key, but its *presence* changes name
                    # resolution and therefore the output.
                    ("pdb_cache_present", bool(pdb_cache)),
                    # The analyst name overlay changes the rendered text, so a
                    # rename MUST invalidate the entry. Keying on a digest of
                    # the overlay rather than on its presence means renaming a
                    # function, renaming it back, and re-running all agree.
                    ("analyst_names", overlay_digest(analyst_names)),
                    ("analyst_locals", locals_digest(analyst_locals)),
                    ("analyst_prototype", prototype_digest(analyst_prototype)),
                    # Bump when the flag schema grows so old entries invalidate.
                    ("schema", 5),
                ]
            )
            paths = _cache.build_paths(
                cache_dir,
                namespace="decomp",
                binary_sha256=_cache.sha256_file(Path(path)),
                va=func_va,
                flags=flags,
                suffix=f".{style or 'plain'}.c",
            )
            hit = _cache.read_text(paths)
            if hit is not None:
                log.debug("decomp cache HIT %s", paths.file)
                return hit
            log.debug("decomp cache MISS %s", paths.file)
        except OSError as exc:
            log.warning(
                "decomp cache: setup failed (%s); falling back to live decompile",
                exc,
            )
            paths = None

    text = g.ir.decompile_at(
        path,
        int(func_va),
        max_blocks=max_blocks,
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
        types=types,
        style=style,
        pdb_cache=pdb_cache,
        analyst_names=analyst_names,
        analyst_locals=analyst_locals,
        analyst_prototype=analyst_prototype,
    )
    if paths is not None:
        _cache.write_text(paths, text)
    return text


class DecompileCommand(BaseCommand):
    """Produce pseudocode for one or more discovered functions."""

    def get_name(self) -> str:
        return "decompile"

    def get_help(self) -> str:
        return "Decompile one or more functions to pseudocode"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", help="Path to file")
        parser.add_argument(
            "--analysis-config",
            help=(
                "Optional Windows analysis config YAML/JSON. Defaults to "
                ".glaurung/windows-analysis.yaml or "
                "$GLAURUNG_WINDOWS_ANALYSIS_CONFIG when present."
            ),
        )
        parser.add_argument(
            "--func",
            dest="func",
            type=parse_func_arg,
            default=None,
            help="Function selector: hex VA (0x140001480), decimal, or a "
            "function name like 'main' resolved against analysis. If "
            "omitted, the detected entry point is used. Stripped "
            "binaries only have sub_<VA> names so VA is preferred.",
        )
        parser.add_argument(
            "--all",
            dest="all",
            action="store_true",
            help="Decompile up to --limit discovered functions instead of one.",
        )
        parser.add_argument(
            "--vas",
            dest="vas",
            default=None,
            metavar="VAS|@FILE|-",
            help="Decompile exactly these entry VAs (each hex 0x... or "
            "decimal) in a single analysis pass. Accepts an inline "
            "comma/space-separated list, @FILE to read them from a file, or "
            "- to read them from stdin; a file or stdin may also use one VA "
            "per line and may carry # comments. Emits a JSON list of "
            "{name, entry_va, pseudocode}. Intended for batch/benchmark "
            "harnesses that already know their target function set (e.g. "
            "DWARF low_pc addresses) -- @FILE and - carry no argv length "
            "bound, so a caller never has to split or cap a target set. "
            "Entries that recover no body are named on stderr and omitted "
            "from the list; exits 2 only when no requested entry recovers "
            "at all.",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=8,
            help="Max number of functions to decompile with --all (default: 8).",
        )
        parser.add_argument(
            "--no-types",
            dest="types",
            action="store_false",
            default=True,
            help="Disable type-annotation pass in the output.",
        )
        parser.add_argument(
            "--timeout-ms",
            type=int,
            default=None,
            help="Per-function analysis timeout in milliseconds. Defaults to analysis config.",
        )
        parser.add_argument(
            "--max-blocks",
            type=int,
            default=None,
            help="Per-function max basic blocks. Defaults to analysis config.",
        )
        parser.add_argument(
            "--max-instructions",
            type=int,
            default=None,
            help="Per-function max instructions. Defaults to analysis config.",
        )
        parser.add_argument(
            "--range-start",
            type=lambda x: int(x, 0),
            default=None,
            help="Explicit function range start VA for range-seeded decompile.",
        )
        parser.add_argument(
            "--range-end",
            type=lambda x: int(x, 0),
            default=None,
            help="Explicit exclusive function range end VA for range-seeded decompile.",
        )
        parser.add_argument(
            "--style",
            choices=["plain", "c", "decbench"],
            default="plain",
            help="Pseudocode style: 'plain' keeps the register-level detail "
            "(default); 'c' strips the %% prefix and annotations for a "
            "closer-to-C view; 'decbench' emits parseable C (a real "
            "'long name(long arg0, ...)' signature with declared locals) "
            "for external tooling that parses the output as C.",
        )
        parser.add_argument(
            "--pdb-cache",
            default="",
            help="Optional Microsoft-style PDB cache directory used to resolve "
            "PE/PDB public function names in decompile output.",
        )
        parser.add_argument(
            "--cache-dir",
            default=None,
            help="Optional persistent cache directory for single-function "
            "decompile output. Entries are keyed by (glaurung version, "
            "sha256(binary), VA, decompile flags). Falls back to "
            "$GLAURUNG_CACHE_DIR when unset. Append-only — clear the "
            "directory manually if disk fills up.",
        )
        parser.add_argument(
            "--db",
            default=None,
            help="Optional .glaurung project file. Function names recorded in "
            "the project (an analyst rename, a DWARF or FLIRT name) are "
            "applied to the decompiled output -- at the definition AND at "
            "every call site. Without it this command is blind to the "
            "project, so a renamed function still prints as sub_<hex>.",
        )

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        try:
            path = self.validate_file_path(args.path)
        except (FileNotFoundError, ValueError) as e:
            formatter.output_plain(f"Error: {e}")
            return 2

        as_json = formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL)

        try:
            config = load_windows_analysis_config(args.analysis_config).with_overrides(
                max_blocks=args.max_blocks,
                max_instructions=args.max_instructions,
                timeout_ms=args.timeout_ms,
                pdb_cache_dir=args.pdb_cache or None,
            )
            timeout_ms = config.timeout_ms
            max_blocks = config.max_blocks
            max_instructions = config.max_instructions
            # Native style token: "" (plain), "c" (register-view), or "decbench"
            # (parseable C). The public --style values map straight through.
            style = "" if args.style == "plain" else args.style

            # Batch-by-VA mode: decompile exactly the requested entry VAs in a
            # single analysis pass. Mirrors the JSON shape of --all.
            if args.vas is not None:
                try:
                    raw_vas, va_origin = _read_va_source(args.vas)
                    vas = _parse_va_list(raw_vas, va_origin)
                except ValueError as e:
                    formatter.output_plain(f"Error: {e}")
                    return 2
                results = g.ir.decompile_many(
                    str(path),
                    vas,
                    max_blocks=max_blocks,
                    max_instructions=max_instructions,
                    timeout_ms=timeout_ms,
                    types=args.types,
                    style=style,
                    pdb_cache=args.pdb_cache or config.pdb_cache_dir or "",
                    max_functions=_requested_function_budget(vas),
                )
                if as_json:
                    payload = [_function_record(rec) for rec in results]
                    print(json.dumps(payload, indent=2))
                else:
                    for rec in results:
                        formatter.output_plain(rec[2])
                _report_unverified_functions()
                return _report_unresolved_vas(vas, results)

            if args.all:
                results = g.ir.decompile_all(
                    str(path),
                    args.limit,
                    timeout_ms=timeout_ms,
                    pdb_cache=args.pdb_cache or config.pdb_cache_dir or "",
                    style=style,
                )
                if as_json:
                    payload = [_function_record(rec) for rec in results]
                    print(json.dumps(payload, indent=2))
                else:
                    for rec in results:
                        formatter.output_plain(rec[2])
                _report_unverified_functions()
                return 0

            # Single-function mode.
            func_va: Optional[int] = None
            if isinstance(args.func, int):
                func_va = args.func
            elif isinstance(args.func, str):
                # Name-resolution path. Run a bounded discovery pass so
                # the lookup terminates predictably on large binaries.
                try:
                    discovered = g.analysis.analyze_functions_path(
                        str(path),
                        max_functions=2000,
                    )[0]
                except Exception as e:
                    formatter.output_plain(
                        f"Error: --func name resolution failed during analysis: {e}"
                    )
                    return 2
                try:
                    func_va = resolve_func_to_va(args.func, discovered)
                except FuncResolutionError as e:
                    # The name the analyst just chose is the name they will
                    # type. Resolving `--func` against the binary alone means
                    # renaming a function makes it unreachable by its new name
                    # -- `decompile --func parse_packet_hdr --db p.glaurung`
                    # answered "no function named 'parse_packet_hdr' in this
                    # binary", which is true and useless. The project is
                    # consulted second, so a binary symbol still wins on a
                    # collision and this cannot change the no-`--db` behaviour.
                    func_va = None
                    for va, name in load_analyst_names(
                        getattr(args, "db", None), str(path)
                    ).items():
                        if name == args.func:
                            func_va = va
                            break
                    if func_va is None:
                        formatter.output_plain(f"Error: {e}")
                        return 2
            else:
                got = g.analysis.detect_entry_path(str(path))
                if got is None:
                    formatter.output_plain(
                        "Error: could not detect entry point; pass --func 0xVA"
                    )
                    return 2
                func_va = int(got[3])

            try:
                if args.range_end is not None or args.range_start is not None:
                    range_start = (
                        args.range_start
                        if args.range_start is not None
                        else int(func_va)
                    )
                    if args.range_end is None:
                        formatter.output_plain(
                            "Error: --range-end is required with --range-start"
                        )
                        return 2
                    text = g.ir.decompile_range_at(
                        str(path),
                        int(func_va),
                        int(range_start),
                        int(args.range_end),
                        max_blocks=max_blocks,
                        max_instructions=max_instructions,
                        timeout_ms=timeout_ms,
                        types=args.types,
                        style=style,
                        pdb_cache=args.pdb_cache or config.pdb_cache_dir or "",
                    )
                else:
                    text = _decompile_at_cached(
                        path=str(path),
                        func_va=int(func_va),
                        style=style,
                        types=args.types,
                        timeout_ms=timeout_ms,
                        max_blocks=max_blocks,
                        max_instructions=max_instructions,
                        pdb_cache=args.pdb_cache or config.pdb_cache_dir or "",
                        cache_dir_arg=args.cache_dir,
                        analyst_names=load_analyst_names(
                            getattr(args, "db", None), str(path)
                        ),
                        analyst_locals=load_analyst_locals(
                            getattr(args, "db", None), str(path), int(func_va)
                        ),
                        # Keyed by the name the function is CURRENTLY known by,
                        # which after a rename is the analyst's name.
                        analyst_prototype=load_analyst_prototype(
                            getattr(args, "db", None),
                            str(path),
                            (
                                load_analyst_names(
                                    getattr(args, "db", None), str(path)
                                ).get(int(func_va))
                                or (args.func if isinstance(args.func, str) else "")
                            ),
                        ),
                    )
            except ValueError as e:
                formatter.output_plain(f"Error: {e}")
                return 2

            # An analyst's notes belong ON the function they are about. The
            # entry comment renders above the signature, where it cannot be
            # orphaned by a change in the generated text; notes at other
            # addresses are LISTED with their addresses rather than guessed
            # into the body, because placing them needs an instruction-to-line
            # map the AST cannot supply yet and a plausible wrong placement
            # reads as fact.
            # Applied after `_decompile_at_cached` returns, so the comment
            # block is NOT part of the cached artifact and needs no cache-key
            # entry: a comment edit changes this header on every run, cached or
            # not. Names and locals are different -- they change the decompiled
            # text itself, so they are keyed.
            db_arg = getattr(args, "db", None)
            if db_arg:
                entry_comment, inside = load_analyst_comments(
                    db_arg,
                    str(path),
                    int(func_va),
                    _function_size(str(path), int(func_va))
                    if _has_other_comments(db_arg, str(path), int(func_va))
                    else None,
                )
                header = render_comment_header(entry_comment, inside, int(func_va))
                if header:
                    # After the `// glaurung: <name> @ <va>` banner, not before
                    # it: that line is what consumers anchor on
                    # (`tools/roundtrip3.py`), and the analyst's note reads
                    # better as an annotation ON the function than as a preamble
                    # to the file.
                    first, sep, rest = text.partition("\n")
                    if sep and first.startswith("// glaurung:"):
                        text = f"{first}\n{header}{rest}"
                    else:
                        text = header + text

            if as_json:
                # Best-effort name: only resolvable when --func was a name.
                name = args.func if isinstance(args.func, str) else ""
                print(
                    json.dumps(
                        {
                            "name": name,
                            "entry_va": int(func_va),
                            "pseudocode": text,
                            # Single-function mode goes through `decompile_at`,
                            # which does not return the structured inventory.
                            # Absent rather than empty: an empty list would claim
                            # "this function has no variables", which is a
                            # different and usually false statement.
                            "size": None,
                            "variables": [],
                        },
                        indent=2,
                    )
                )
            else:
                formatter.output_plain(text)
            _report_unverified_functions()
            return 0
        except Exception as e:  # pragma: no cover - surfaces as CLI error
            formatter.output_plain(f"Error: {e}")
            return 1


def _has_other_comments(db_path: str, binary: str, func_va: int) -> bool:
    """Whether the project holds any comment at an address other than the entry.

    Checked first because the answer decides whether to run a discovery pass to
    learn the function's extent. Reading the comment table is a SQLite query;
    discovery is not, and a user with only an entry comment -- the common case
    -- should not pay for it.
    """
    kb = None
    try:
        from glaurung.llm.kb.persistent import PersistentKnowledgeBase

        kb = PersistentKnowledgeBase.open(db_path, binary_path=binary)
        from glaurung.llm.kb import xref_db

        return any(
            int(va) != int(func_va) for va, body in xref_db.list_comments(kb) if body
        )
    except Exception:  # noqa: BLE001
        return False
    finally:
        if kb is not None:
            try:
                kb.close()
            except Exception:  # noqa: BLE001
                pass


def _function_size(path: str, func_va: int) -> Optional[int]:
    """Byte extent of the function at ``func_va``, or ``None``.

    Used only to decide which comments belong to this function. `None` means
    "unknown", and the caller then shows only the entry comment rather than
    guessing a range and attributing a neighbour's notes to this function.
    """
    try:
        discovered = g.analysis.analyze_functions_path(path, max_functions=2000)[0]
    except Exception:  # noqa: BLE001
        return None
    for fn in discovered:
        try:
            if int(fn.entry_point.value) != int(func_va):
                continue
        except Exception:  # noqa: BLE001
            continue
        size = getattr(fn, "size", None)
        if size:
            return int(size)
        blocks = getattr(fn, "basic_blocks", None) or []
        ends = []
        for block in blocks:
            try:
                ends.append(int(block.end_address.value))
            except Exception:  # noqa: BLE001
                continue
        if ends:
            return max(ends) - int(func_va)
        return None
    return None


def _report_unverified_functions() -> None:
    """Name, on stderr, every function whose recovered C failed def-before-use.

    The decompiler verifies the exact AST it is about to print
    (``ir::verify_defs::verify_before_render``). A violation means the emitted C
    reads a value the machine never produced, so the recompiled function returns
    garbage — a wrong-code bug, not a formatting one, and one that ``type_match``
    / ``GED`` / ``byte_match`` cannot see.

    Suppressing the body would destroy the only evidence of what went wrong, and
    aborting the run would fail a whole binary over one function. So the body is
    printed and the failure is named: design rule 8's "honest diagnostic".

    Stderr, not stdout, for the reason ``_report_unresolved_vas`` documents —
    stdout stays exactly the payload callers parse — and for one more: the
    decbench render is an artifact an external benchmark scores, and a note
    announcing our own bug does not belong inside the code being scored.
    """
    import sys

    try:
        report: dict = g.ir.take_render_verification()
    except AttributeError:  # pragma: no cover - extension predates the binding
        return
    unverified: int = int(report.get("unverified_functions", 0))
    if not unverified:
        return
    verdicts: list[dict] = list(report.get("unverified", []))
    named = ", ".join(
        f"{v['function']}@{v['entry_va']} ({v['undefined_uses']})" for v in verdicts[:8]
    )
    more = max(0, unverified - 8)
    total = int(report.get("verified_functions", 0)) + unverified
    reads = int(report.get("undefined_uses", 0))
    print(
        f"Warning: definition-before-use verification failed for "
        f"{unverified} of {total} rendered function(s), "
        f"{reads} undefined read(s). The recovered C reads "
        f"values the original never produced. Set GLAURUNG_VERIFY_DEFS=1 for the "
        f"per-violation detail. Affected: {named}"
        + (f", and {more} more" if more else ""),
        file=sys.stderr,
    )
    dropped = int(report.get("dropped_verdicts", 0))
    if dropped:
        print(
            f"Warning: {dropped} further unverified function(s) were counted but "
            "not recorded (verdict ledger full)",
            file=sys.stderr,
        )


def _read_va_source(raw: str) -> tuple[str, str]:
    """Resolve ``--vas`` to (text, origin) from an inline list, ``@FILE`` or ``-``.

    An argv-borne list is bounded by ``ARG_MAX``, which is why DecBench's own
    adapter carries a `_MAX_VAS_INLINE = 400` safety valve and falls back to
    whole-binary mode above it -- a different code path for the same question.
    ``@FILE`` and ``-`` have no such bound, so a caller never has to split, cap,
    or switch strategies on target count.

    ``origin`` names the source in error messages, because "invalid VA" is not
    actionable when the caller did not type the value.
    """
    import sys  # local, matching this module's convention

    if raw == "-":
        return sys.stdin.read(), "stdin"
    if raw.startswith("@"):
        path = Path(raw[1:]).expanduser()
        try:
            return path.read_text(), f"{path}"
        except OSError as e:
            raise ValueError(f"--vas {raw}: {e.strerror or e}") from e
    return raw, "--vas"


def _parse_va_list(raw: str, origin: str = "--vas") -> list[int]:
    """Parse entry VAs (hex ``0x..`` or decimal) from a list, file, or stdin.

    Tokens separate on commas or any whitespace, so one-VA-per-line files work
    unchanged. A ``#`` begins a comment to end of line, so a generated target
    file can carry its own provenance without a second file to keep in sync.

    Returns the de-duplicated VAs in first-seen order. Raises ``ValueError`` on
    any unparseable token so the caller can surface a clean CLI error.
    """
    seen: set[int] = set()
    out: list[int] = []
    stripped = "\n".join(line.split("#", 1)[0] for line in raw.splitlines())
    for tok in stripped.replace(",", " ").split():
        try:
            va = int(tok, 0)
        except ValueError as e:
            raise ValueError(f"invalid VA in {origin}: {tok!r}") from e
        if va not in seen:
            seen.add(va)
            out.append(va)
    if not out:
        raise ValueError(f"{origin} produced no VAs")
    return out


def _requested_function_budget(vas: list[int]) -> int:
    """Bound address-scoped discovery to the unique requested entries."""
    return max(len(set(vas)), 1)


def _function_record(record: tuple) -> dict:
    """One per-function JSON object from a `decompile_many`/`decompile_all` row.

    The row is `(name, entry_va, pseudocode, size, variables)`. `size` and
    `variables` are additive: every previously-emitted key keeps its name and
    meaning, so a consumer reading only the original three is unaffected.

    `variables` is the structured inventory from `ir::recovered_variables` --
    name, C type, storage kind, ABI argument index, frame offset, and the
    machine `addresses` the slot is read or written at, for each local the
    render actually emitted.

    `addresses` is EMPTY when unclaimed, never "there are none". It is populated
    by joining the slot's frame coordinate against the LLIR, which still carries
    both the coordinate and the machine VA -- see `ir::variable_addresses` for
    the fail-closed rules and for the two configurations (an omitted frame
    pointer, ARM32) where it is deliberately silent.

    There are still no LINE numbers. That needs AST-node-to-instruction lineage,
    which lowering discards, and is a different problem from this one.
    """
    name, entry_va, text = record[0], record[1], record[2]
    size = record[3] if len(record) > 3 else None
    variables = record[4] if len(record) > 4 else []
    return {
        "name": name,
        "entry_va": int(entry_va),
        "pseudocode": text,
        "size": int(size) if size is not None else None,
        "variables": variables,
    }


def _report_unresolved_vas(requested: list[int], results: list) -> int:
    """Name the ``--vas`` entries that produced no body; return the exit code.

    ``decompile_many`` walks *discovered* functions and skips any requested entry
    that discovery never resolved or whose lift bailed, so its result list can be
    shorter than the request with nothing to say so. That left a batch consumer
    unable to tell "this binary has no such function" from "we asked for fewer".

    Partial results still exit 0 — one unsupported function must not discard a
    whole binary's run — but an empty result set from a non-empty request is a
    failed run, not an empty one. Diagnostics go to stderr so stdout stays
    exactly the payload (JSON array or concatenated bodies) callers parse.
    """
    import sys

    produced = {int(record[1]) for record in results}
    # An ARM32 Thumb `.symtab` value carries the Thumb bit and is normalised away
    # before discovery, so the record comes back at the even address the caller
    # asked about with an odd one. See `program::image::normalize_function_entry`.
    missing = [
        va for va in requested if va not in produced and (va & ~1) not in produced
    ]
    if not missing:
        return 0
    listed = ", ".join(hex(va) for va in missing)
    if not produced:
        print(
            f"Error: no function body recovered for any requested VA ({listed})",
            file=sys.stderr,
        )
        return 2
    print(
        f"Warning: decompiled {len(produced)} of {len(requested)} requested VAs; "
        f"no body recovered for: {listed}",
        file=sys.stderr,
    )
    return 0
