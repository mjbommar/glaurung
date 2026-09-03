"""`glaurung sigs` -- the signature-set cache: list, fetch, verify, status, path.

The distribution channel's user surface. Everything here is deliberately
offline-capable: `list`, `status`, `path` and `verify` never touch the
network, and `fetch` is the only verb that can, which is what makes
`GLAURUNG_SIGS_OFFLINE=1` a complete answer rather than a partial one.

See `docs/reference/signature-distribution.md`.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .base import BaseCommand
from ..formatters.base import BaseFormatter, OutputFormat


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


class SigsCommand(BaseCommand):
    """Manage the signed, content-addressed signature-library cache."""

    def get_name(self) -> str:
        return "sigs"

    def get_help(self) -> str:
        return "Manage signature libraries: list, fetch, verify, status, path"

    def _add_common_child_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Repeat the shared output flags on each verb.

        `BaseCommand.setup_parser` puts them on the `sigs` parser, where
        argparse can only see them *before* the verb -- so `glaurung sigs
        status --json` would be "unrecognized arguments". `argparse.SUPPRESS`
        as the default is what lets both positions work: an absent child flag
        adds nothing to the namespace, so the parent's value survives. Same
        construction as `commands/pe.py`.
        """
        parser.add_argument(
            "--format",
            choices=["plain", "rich", "json", "jsonl"],
            default=argparse.SUPPRESS,
            help="Output format (default: plain)",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Alias for --format json",
        )
        parser.add_argument(
            "--no-color",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Disable colored output (forces plain format)",
        )
        parser.add_argument(
            "--quiet",
            "-q",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Suppress non-essential output",
        )
        parser.add_argument(
            "--verbose",
            "-v",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Enable verbose output",
        )

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        sub = parser.add_subparsers(dest="sigs_action", required=True)

        listing = sub.add_parser("list", help="List the blobs in the active manifest")
        self._add_common_child_arguments(listing)
        listing.add_argument(
            "--set",
            dest="set_name",
            default="base",
            help="Signature set name (default: base)",
        )
        listing.add_argument(
            "--cached-only", action="store_true", help="Only blobs present in the cache"
        )
        listing.add_argument(
            "--arch", default=None, help="Filter by the provenance architecture"
        )

        fetching = sub.add_parser("fetch", help="Download and verify a signature set")
        self._add_common_child_arguments(fetching)
        fetching.add_argument(
            "--set",
            dest="set_name",
            default="base",
            help="Signature set name (default: base)",
        )
        fetching.add_argument(
            "--manifest-url",
            default=None,
            help="Where the signed manifest is (default: GLAURUNG_SIGS_MANIFEST_URL, "
            "then the release URL). file:// is accepted.",
        )
        fetching.add_argument(
            "--offline",
            action="store_true",
            help="Forbid the network; use the cache, then the bundled set",
        )
        fetching.add_argument(
            "--key",
            action="append",
            default=None,
            dest="only",
            metavar="LIBRARY_KEY",
            help="Fetch only this library key; repeatable",
        )
        fetching.add_argument("--timeout", type=float, default=60.0)

        verifying = sub.add_parser(
            "verify", help="Re-verify the cached manifest signature and every blob"
        )
        self._add_common_child_arguments(verifying)
        verifying.add_argument(
            "--shallow",
            action="store_true",
            help="Check sizes only, not sha256 (fast; misses bit-rot)",
        )

        status = sub.add_parser(
            "status", help="What the cache holds and how it was verified"
        )
        self._add_common_child_arguments(status)

        pathing = sub.add_parser("path", help="Print resolved paths")
        self._add_common_child_arguments(pathing)
        pathing.add_argument(
            "library_key",
            nargs="?",
            default=None,
            help="Print the cached blob path for this key instead of the roots",
        )

    # -- execute ---------------------------------------------------------------

    def execute(self, args: argparse.Namespace, formatter: BaseFormatter) -> int:
        # Imported here, not at module scope: `glaurung --help` builds every
        # subparser, and `test_cli_startup_is_lazy.py` pins that a subcommand
        # does not pay for subsystems it is not running.
        from glaurung import sigs
        from glaurung.sigs import paths

        handler = {
            "list": self._list,
            "fetch": self._fetch,
            "verify": self._verify,
            "status": self._status,
            "path": self._path,
        }[args.sigs_action]
        try:
            return handler(args, formatter, sigs, paths)
        except sigs.FetchError as exc:
            formatter.output_plain(f"Error: {exc}")
            return 2

    # -- verbs -----------------------------------------------------------------

    def _active_manifest(self, sigs, paths):
        """The cached manifest if there is one, else the bundled fallback.

        Returned unverified for *listing*, because listing is not a trust
        decision; `verify` and `fetch` are where the signature is checked.
        """
        for candidate in (paths.cached_manifest_path(), paths.bundled_manifest_path()):
            if candidate.is_file():
                return sigs.Manifest.read(candidate), candidate
        return None, None

    def _list(self, args, formatter, sigs, paths) -> int:
        manifest, source = self._active_manifest(sigs, paths)
        if manifest is None:
            formatter.output_plain(
                "No manifest is cached and none is bundled. Run "
                "`glaurung sigs fetch` or reinstall."
            )
            return 1
        root = paths.cache_root()
        rows: list[dict[str, Any]] = []
        for blob in manifest.blobs:
            cached = (
                paths.blob_path(blob.sha256, root).is_file()
                or (paths.bundled_blob_dir() / blob.sha256).is_file()
            )
            if args.cached_only and not cached:
                continue
            if args.arch and blob.provenance.arch != args.arch:
                continue
            rows.append(
                {
                    "key": blob.key,
                    "sha256": blob.sha256,
                    "signatures": blob.signatures,
                    "size_bytes": blob.size_bytes,
                    "format": blob.format,
                    "kind": blob.kind,
                    "arch": blob.provenance.arch,
                    "cached": cached,
                }
            )

        if formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
            formatter.output_json(
                {
                    "set": manifest.set_name,
                    "set_version": manifest.set_version,
                    "serial": manifest.serial,
                    "source": str(source),
                    "blobs": rows,
                }
            )
            return 0

        lines = [
            f"set {manifest.set_name} {manifest.set_version} "
            f"(serial {manifest.serial}, from {source})",
            f"{'':<2}{'KEY':<48}{'SIGS':>8}{'SIZE':>12}  ARCH",
        ]
        for row in rows:
            mark = "*" if row["cached"] else " "
            lines.append(
                f"{mark} {row['key']:<48}{row['signatures']:>8}"
                f"{_human(row['size_bytes']):>12}  {row['arch']}"
            )
        cached_count = sum(1 for row in rows if row["cached"])
        lines.append("")
        lines.append(
            f"{len(rows)} blob(s), {cached_count} cached "
            f"(* = present locally). Cache root: {root}"
        )
        formatter.output_plain("\n".join(lines))
        return 0

    def _fetch(self, args, formatter, sigs, paths) -> int:
        result = sigs.fetch(
            args.set_name,
            args.manifest_url,
            offline=True if args.offline else None,
            only=args.only,
            timeout=args.timeout,
        )
        payload = {
            "set": result.manifest.set_name,
            "set_version": result.manifest.set_version,
            "serial": result.manifest.serial,
            "source": result.source,
            "verified_by_key_id": result.verified_by,
            "cache_root": str(result.root),
            "downloaded": result.downloaded,
            "already_cached": result.already_cached,
            "skipped": result.skipped,
            "bytes_downloaded": result.bytes_downloaded,
            "warnings": result.warnings,
        }
        if formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
            formatter.output_json(payload)
            return 0
        lines = [
            f"set {result.manifest.set_name} {result.manifest.set_version} "
            f"serial {result.manifest.serial}",
            f"  source     {result.source}",
            f"  signed by  {result.verified_by}",
            f"  cache      {result.root}",
            f"  downloaded {len(result.downloaded)} blob(s), "
            f"{_human(result.bytes_downloaded)}",
            f"  cached     {len(result.already_cached)} blob(s) already present",
        ]
        if result.skipped:
            lines.append(f"  skipped    {len(result.skipped)} blob(s)")
        for warning in result.warnings:
            lines.append(f"  warning:   {warning}")
        formatter.output_plain("\n".join(lines))
        return 0

    def _verify(self, args, formatter, sigs, paths) -> int:
        manifest, problems = sigs.verify_cache(deep=not args.shallow)
        payload = {
            "ok": manifest is not None and not problems,
            "set": manifest.set_name if manifest else None,
            "set_version": manifest.set_version if manifest else None,
            "serial": manifest.serial if manifest else None,
            "deep": not args.shallow,
            "problems": problems,
        }
        if formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
            formatter.output_json(payload)
            return 0 if payload["ok"] else 1
        if manifest is None:
            formatter.output_plain("Error: " + "; ".join(problems))
            return 1
        if problems:
            formatter.output_plain(
                f"set {manifest.set_name} {manifest.set_version}: "
                f"{len(problems)} problem(s)\n  " + "\n  ".join(problems)
            )
            return 1
        formatter.output_plain(
            f"set {manifest.set_name} {manifest.set_version} serial "
            f"{manifest.serial}: signature valid, "
            f"{len(manifest.blobs)} blob(s) consistent "
            f"({'sha256' if not args.shallow else 'size only'})"
        )
        return 0

    def _status(self, args, formatter, sigs, paths) -> int:
        root = paths.cache_root()
        catalog = sigs.Catalog.load(root)
        manifest, source = self._active_manifest(sigs, paths)
        cached = sum(
            1
            for entry in catalog.entries.values()
            if paths.blob_path(entry.sha256, root).is_file()
        )
        keys = sigs.load_trusted_keys()
        payload = {
            "cache_root": str(root),
            "cache_exists": root.is_dir(),
            "offline": sigs.is_offline(),
            "manifest_source": str(source) if source else None,
            "set": catalog.set_name or (manifest.set_name if manifest else None),
            "set_version": catalog.set_version
            or (manifest.set_version if manifest else None),
            "serial": catalog.serial or (manifest.serial if manifest else 0),
            "verified_utc": catalog.verified_utc,
            "verified_by_key_id": catalog.verified_by_key_id,
            "catalog_entries": len(catalog),
            "blobs_present": cached,
            "manifest_blobs": len(manifest.blobs) if manifest else 0,
            "expired": manifest.is_expired() if manifest else None,
            "bundled_data_dir": str(paths.bundled_data_dir()),
            "trusted_keys": [key.key_id_hex for key in keys],
        }
        if formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
            formatter.output_json(payload)
            return 0
        lines = [
            f"cache root      {payload['cache_root']}"
            f"{'' if payload['cache_exists'] else '  (does not exist yet)'}",
            f"offline         {payload['offline']}",
            f"manifest        {payload['manifest_source']}",
            f"set             {payload['set']} {payload['set_version'] or ''} "
            f"serial {payload['serial']}",
            f"verified        {payload['verified_utc'] or '(never)'}"
            + (
                f" by key {payload['verified_by_key_id']}"
                if payload["verified_by_key_id"]
                else ""
            ),
            f"blobs           {payload['blobs_present']} present of "
            f"{payload['manifest_blobs']} in the manifest",
            f"bundled data    {payload['bundled_data_dir']}",
            f"trusted keys    {', '.join(payload['trusted_keys']) or '(none)'}",
        ]
        if payload["expired"]:
            lines.append("warning         the active set is past its valid_until")
        formatter.output_plain("\n".join(lines))
        return 0

    def _path(self, args, formatter, sigs, paths) -> int:
        if args.library_key:
            resolved = sigs.resolve(args.library_key)
            if formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
                formatter.output_json(
                    {
                        "key": args.library_key,
                        "path": str(resolved) if resolved else None,
                    }
                )
                return 0 if resolved else 1
            if resolved is None:
                formatter.output_plain(
                    f"Error: {args.library_key!r} is not in the cache or the "
                    "bundled set"
                )
                return 1
            formatter.output_plain(str(resolved))
            return 0

        payload = {
            "cache_root": str(paths.cache_root()),
            "catalog": str(paths.catalog_path()),
            "bundled_data_dir": str(paths.bundled_data_dir()),
            "bundled_manifest": str(paths.bundled_manifest_path()),
            "trusted_keys_dir": str(paths.keys_dir()),
            "schema": str(paths.schema_path()),
        }
        if formatter.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
            formatter.output_json(payload)
            return 0
        formatter.output_plain(
            "\n".join(f"{name:<18}{value}" for name, value in payload.items())
        )
        return 0
