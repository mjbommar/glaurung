"""Convert signature libraries between JSON and the ``gsig/1`` container.

JSON is the interchange format: it is what a harvester writes and what a
reviewer diffs. ``gsig/1`` is what a corpus *ships* in -- chunked, columnar,
interned and zstd-compressed, roughly 25x smaller. See the "The gsig/1
container" section of ``docs/reference/function-signature-libraries.md``.

Both directions go through the Rust reader and writer
(:mod:`glaurung.analysis`); nothing here parses container bytes in Python.

Usage:
    # JSON -> gsig
    python -m glaurung.tools.sig_convert to-gsig lib.flirt.json lib.flirt.gsig

    # gsig -> JSON, in the canonical on-disk form the builder writes
    python -m glaurung.tools.sig_convert to-json lib.flirt.gsig lib.flirt.json

    # What is in this file?  (works for either format)
    python -m glaurung.tools.sig_convert info lib.flirt.gsig

    # Prove the round trip is lossless for one library, or a whole directory
    python -m glaurung.tools.sig_convert roundtrip lib.flirt.json
    python -m glaurung.tools.sig_convert roundtrip ~/.cache/glaurung/sigs/
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

import glaurung as g

#: Codecs the shipped build always has. ``zstd-max`` needs the crate's
#: ``gsig-zstd`` feature and is rejected with a clear message without it.
CODECS = ("zstd", "store", "zstd-max")

#: The masked-pattern scheme -- FLIRT-shaped libraries.
FLIRT_SCHEME = "flirt-masked-pattern-v1"

#: The exact-match GUID scheme -- WARP-shaped libraries. Both live in the same
#: ``gsig/1`` container and fill different sections of it, so every entry
#: point here has to know which one it is holding before it reads a record.
WARP_SCHEME = "warp-function-guid-v1"

#: What ``--scheme`` accepts. ``auto`` is the default and is right nearly
#: always; the explicit spellings exist so a caller can *assert* what a file
#: is rather than discover it.
SCHEMES = ("auto", "flirt", "warp")

_SCHEME_ALIASES = {"flirt": FLIRT_SCHEME, "warp": WARP_SCHEME}


def detect_scheme(path: Path) -> str:
    """Which identity scheme the library at ``path`` is under.

    A ``gsig/1`` container states it in its header, which the reader returns.
    A JSON library states it in a top-level ``scheme`` key -- which only the
    WARP builder writes, so its absence means the masked-pattern schema.

    Args:
        path: A JSON or ``gsig/1`` signature library.

    Returns:
        :data:`FLIRT_SCHEME` or :data:`WARP_SCHEME`.

    Raises:
        OSError: the file cannot be read.
        ValueError: it is a container under a scheme this build cannot read.
    """
    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic == b"GSIG":
        scheme = str(g.analysis.flirt_library_info_path(str(path)).get("scheme", ""))
        if scheme not in (FLIRT_SCHEME, WARP_SCHEME):
            raise ValueError(f"{path}: unknown container scheme {scheme!r}")
        return scheme
    with path.open("r", encoding="utf-8") as handle:
        head = json.load(handle)
    return str(head.get("scheme") or FLIRT_SCHEME)


def _resolve_scheme(path: Path, scheme: str) -> str:
    """Turn a ``--scheme`` value into a scheme string, checking it if given."""
    if scheme == "auto":
        return detect_scheme(path)
    wanted = _SCHEME_ALIASES[scheme]
    found = detect_scheme(path)
    if found != wanted:
        raise ValueError(f"{path} is a {found} library, not {wanted}")
    return wanted


def canonical_json(library: dict[str, Any]) -> str:
    """The exact on-disk text ``build_flirt_library.py`` writes.

    ``sort_keys`` plus two-space indent plus a trailing newline. Both sides of
    a round-trip comparison go through this, so the comparison is about
    *content*, not about which serializer emitted it.

    Args:
        library: A JSON-shaped signature library.

    Returns:
        The canonical text, newline-terminated.
    """
    return json.dumps(library, indent=2, sort_keys=True) + "\n"


def read_library(path: Path, *, scheme: str = "auto") -> dict[str, Any]:
    """Read a signature library of either format and either scheme into a dict.

    Dispatches on the file's first four bytes inside the native reader, so a
    ``.gsig`` under a ``.json`` name still reads correctly, and on the
    container's declared scheme, so a WARP library is never read through the
    masked-pattern path -- which would return an empty, plausible-looking
    result rather than an error.

    Args:
        path: Path to a JSON or ``gsig/1`` library.
        scheme: One of :data:`SCHEMES`.

    Returns:
        The library as a dict.

    Raises:
        OSError: the file cannot be read.
        ValueError: it is neither format, or not the scheme asked for.
    """
    if _resolve_scheme(path, scheme) == WARP_SCHEME:
        return json.loads(g.analysis.warp_library_to_json_str(str(path)))
    return json.loads(g.analysis.flirt_library_to_json_str(str(path)))


def to_gsig(
    source: Path, output: Path, *, codec: str = "zstd", scheme: str = "auto"
) -> dict[str, Any]:
    """Write ``source`` (JSON or gsig) out as a ``gsig/1`` container.

    Args:
        source: The library to convert.
        output: Where to write the container.
        codec: ``"zstd"``, ``"store"`` or ``"zstd-max"``.
        scheme: One of :data:`SCHEMES`.

    Returns:
        The writer's report: ``bytes_written``, ``n_signatures``,
        ``n_strings``, ``chunk_count``, ``codec`` and ``sha256``.
    """
    resolved = _resolve_scheme(source, scheme)
    output.parent.mkdir(parents=True, exist_ok=True)
    if resolved == WARP_SCHEME:
        text = g.analysis.warp_library_to_json_str(str(source))
        return g.analysis.warp_gsig_write_from_json_str(text, str(output), codec)
    text = g.analysis.flirt_library_to_json_str(str(source))
    return g.analysis.flirt_gsig_write_from_json_str(text, str(output), codec)


def to_json(source: Path, output: Path, *, scheme: str = "auto") -> dict[str, Any]:
    """Write ``source`` (JSON or gsig) out as canonical JSON.

    Args:
        source: The library to convert.
        output: Where to write the JSON.
        scheme: One of :data:`SCHEMES`.

    Returns:
        A dict with ``bytes_written``, ``n_signatures`` and ``sha256``.
    """
    library = read_library(source, scheme=scheme)
    text = canonical_json(library)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text)
    return {
        "bytes_written": len(text.encode()),
        "n_signatures": len(library.get("entries", [])),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }


def roundtrip(
    source: Path, *, codec: str = "zstd", scheme: str = "auto"
) -> dict[str, Any]:
    """Convert JSON to gsig and back, and check both directions are exact.

    Two properties, and they are different properties:

    * **JSON to gsig to JSON is byte-identical** after canonical sorting --
      the container loses nothing.
    * **gsig to gsig is byte-identical** -- the container is deterministic,
      which is what lets a distribution address blobs by their hash.

    Args:
        source: A JSON or gsig library.
        codec: The codec to write with.
        scheme: One of :data:`SCHEMES`.

    Returns:
        A dict with ``path``, ``scheme``, ``json_bytes``, ``gsig_bytes``,
        ``n_signatures``, ``json_identical``, ``gsig_identical`` and
        ``sha256``.
    """
    resolved = _resolve_scheme(source, scheme)
    original = canonical_json(read_library(source, scheme=scheme))
    with tempfile.TemporaryDirectory() as tmp:
        first = Path(tmp) / "first.gsig"
        second = Path(tmp) / "second.gsig"
        report = to_gsig(source, first, codec=codec, scheme=scheme)
        back = canonical_json(read_library(first, scheme=scheme))
        to_gsig(first, second, codec=codec, scheme=scheme)
        return {
            "path": str(source),
            "scheme": resolved,
            "json_bytes": len(original.encode()),
            "gsig_bytes": report["bytes_written"],
            "n_signatures": report["n_signatures"],
            "json_identical": back == original,
            "gsig_identical": first.read_bytes() == second.read_bytes(),
            "sha256": report["sha256"],
        }


def _iter_libraries(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(
        p
        for p in root.rglob("*")
        if p.is_file()
        and (
            p.name.endswith(".flirt.json")
            or p.name.endswith(".warp.json")
            or p.suffix == ".gsig"
        )
    )


def _cmd_info(args: argparse.Namespace) -> int:
    info = g.analysis.flirt_library_info_path(str(args.path))
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


def _cmd_to_gsig(args: argparse.Namespace) -> int:
    report = to_gsig(args.source, args.output, codec=args.codec, scheme=args.scheme)
    if not args.quiet:
        print(
            f"wrote {args.output}  ({report['bytes_written']} bytes, "
            f"{report['n_signatures']} signatures, "
            f"{report['n_strings']} strings, "
            f"{report['chunk_count']} chunks, codec={report['codec']})",
            file=sys.stderr,
        )
    return 0


def _cmd_to_json(args: argparse.Namespace) -> int:
    report = to_json(args.source, args.output, scheme=args.scheme)
    if not args.quiet:
        print(
            f"wrote {args.output}  ({report['bytes_written']} bytes, "
            f"{report['n_signatures']} signatures)",
            file=sys.stderr,
        )
    return 0


def _cmd_roundtrip(args: argparse.Namespace) -> int:
    libraries = _iter_libraries(args.path)
    if not libraries:
        print(f"error: no signature libraries under {args.path}", file=sys.stderr)
        return 2
    failures = 0
    total_json = 0
    total_gsig = 0
    total_sigs = 0
    for path in libraries:
        result = roundtrip(path, codec=args.codec, scheme=args.scheme)
        total_json += result["json_bytes"]
        total_gsig += result["gsig_bytes"]
        total_sigs += result["n_signatures"]
        ok = result["json_identical"] and result["gsig_identical"]
        failures += 0 if ok else 1
        if not ok or args.verbose:
            print(
                f"{'ok  ' if ok else 'FAIL'} {path.name}  "
                f"json={result['json_bytes']} gsig={result['gsig_bytes']} "
                f"sigs={result['n_signatures']}",
                file=sys.stderr,
            )
    per_sig_json = total_json / total_sigs if total_sigs else 0.0
    per_sig_gsig = total_gsig / total_sigs if total_sigs else 0.0
    print(
        f"{len(libraries)} libraries, {total_sigs} signatures, {failures} failures\n"
        f"json {total_json} bytes ({per_sig_json:.0f} B/sig)\n"
        f"gsig {total_gsig} bytes ({per_sig_gsig:.0f} B/sig)"
        + (f"  {total_json / total_gsig:.1f}x smaller" if total_gsig else ""),
        file=sys.stderr,
    )
    return 1 if failures else 0


def main(argv: Optional[list[str]] = None) -> int:
    """Entry point for ``python -m glaurung.tools.sig_convert``.

    Args:
        argv: Command-line arguments; ``sys.argv[1:]`` when omitted.

    Returns:
        A process exit code.
    """
    parser = argparse.ArgumentParser(
        prog="python -m glaurung.tools.sig_convert",
        description="Convert signature libraries between JSON and gsig/1.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_info = sub.add_parser("info", help="Describe a library of either format.")
    p_info.add_argument("path", type=Path)
    p_info.set_defaults(func=_cmd_info)

    p_gsig = sub.add_parser("to-gsig", help="Write a gsig/1 container.")
    p_gsig.add_argument("source", type=Path)
    p_gsig.add_argument("output", type=Path)
    p_gsig.add_argument("--codec", choices=CODECS, default="zstd")
    p_gsig.add_argument("--scheme", choices=SCHEMES, default="auto")
    p_gsig.add_argument("--quiet", action="store_true")
    p_gsig.set_defaults(func=_cmd_to_gsig)

    p_json = sub.add_parser("to-json", help="Write canonical JSON.")
    p_json.add_argument("source", type=Path)
    p_json.add_argument("output", type=Path)
    p_json.add_argument("--scheme", choices=SCHEMES, default="auto")
    p_json.add_argument("--quiet", action="store_true")
    p_json.set_defaults(func=_cmd_to_json)

    p_rt = sub.add_parser(
        "roundtrip", help="Check JSON->gsig->JSON and gsig->gsig are exact."
    )
    p_rt.add_argument("path", type=Path, help="A library, or a directory of them.")
    p_rt.add_argument("--codec", choices=CODECS, default="zstd")
    p_rt.add_argument("--scheme", choices=SCHEMES, default="auto")
    p_rt.add_argument("--verbose", action="store_true")
    p_rt.set_defaults(func=_cmd_roundtrip)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
