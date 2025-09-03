"""Command-line interface for Glaurung triage."""

import argparse
from pathlib import Path

import glaurung as g


def _human_bytes(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB"]
    f = float(n)
    i = 0
    while f >= 1024.0 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    if i == 0:
        return f"{int(f)} {units[i]}"
    return f"{f:.1f} {units[i]}"


def _hint_label(hints) -> str | None:
    # Prefer explicit label, then mime, then extension
    for h in hints:
        lbl = getattr(h, "label", None)
        if lbl:
            return lbl
    for h in hints:
        mime = getattr(h, "mime", None)
        if mime:
            return mime
    for h in hints:
        ext = getattr(h, "extension", None)
        if ext:
            return ext
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(prog="glaurung", description="Glaurung triage CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    triage = sub.add_parser("triage", help="Triage a file")
    triage.add_argument("path", help="Path to file")
    triage.add_argument("--json", action="store_true", help="Emit JSON")
    triage.add_argument(
        "--max-read-bytes", type=int, default=10_485_760, help="Max bytes to read"
    )
    triage.add_argument(
        "--max-file-size", type=int, default=104_857_600, help="Max file size"
    )
    triage.add_argument("--max-depth", type=int, default=1, help="Max recursion depth")
    triage.add_argument(
        "--sim", dest="sim", action="store_true", default=True, help="Print similarity fields"
    )
    triage.add_argument(
        "--no-sim", dest="sim", action="store_false", help="Hide similarity fields"
    )
    # Strings config
    triage.add_argument(
        "--str-min-len", type=int, default=4, help="Minimum string length"
    )
    triage.add_argument(
        "--str-max-samples", type=int, default=40, help="Max sampled strings"
    )
    triage.add_argument(
        "--str-lang",
        dest="str_lang",
        action="store_true",
        default=True,
        help="Enable language detection",
    )
    triage.add_argument(
        "--no-str-lang",
        dest="str_lang",
        action="store_false",
        help="Disable language detection",
    )
    triage.add_argument(
        "--str-max-lang-detect",
        type=int,
        default=100,
        help="Max strings to language-detect",
    )
    triage.add_argument(
        "--str-classify",
        dest="str_classify",
        action="store_true",
        default=True,
        help="Enable IOC classification",
    )
    triage.add_argument(
        "--no-str-classify",
        dest="str_classify",
        action="store_false",
        help="Disable IOC classification",
    )
    triage.add_argument(
        "--str-max-classify",
        type=int,
        default=200,
        help="Max strings to classify",
    )
    triage.add_argument(
        "--str-max-ioc-per-string",
        type=int,
        default=16,
        help="Max IOC matches counted per string",
    )

    # Symbols listing subcommand
    sym = sub.add_parser("symbols", help="List symbols (best-effort)")
    sym.add_argument("path", help="Path to file")
    sym.add_argument("--json", action="store_true", help="Emit JSON list")
    sym.add_argument(
        "--max-read-bytes", type=int, default=10_485_760, help="Max bytes to read"
    )
    sym.add_argument(
        "--max-file-size", type=int, default=104_857_600, help="Max file size"
    )

    args = parser.parse_args(argv)

    if args.cmd == "triage":
        p = Path(args.path)
        try:
            art = g.triage.analyze_path(
                str(p),
                args.max_read_bytes,
                args.max_file_size,
                args.max_depth,
                args.str_min_len,
                args.str_max_samples,
                args.str_lang,
                args.str_max_lang_detect,
                args.str_classify,
                args.str_max_classify,
                args.str_max_ioc_per_string,
            )
        except TypeError:
            # Backward-compatible fallback to older extension signature
            art = g.triage.analyze_path(
                str(p), args.max_read_bytes, args.max_file_size, args.max_depth
            )
        if args.json:
            print(art.to_json())
        else:
            lines = [
                f"path: {art.path}",
                f"size: {art.size_bytes} bytes ({_human_bytes(art.size_bytes)})",
                f"verdicts: {len(art.verdicts)}",
            ]
            if art.verdicts:
                top = art.verdicts[0]
                lines.append(
                    "_top_: "
                    f"format={top.format} arch={top.arch} {top.bits}-bit "
                    f"endianness={top.endianness} confidence={top.confidence:.2f}"
                )
            else:
                # No verdicts: provide a friendly hint
                hints = getattr(art, "hints", []) or []
                label = _hint_label(hints)
                if label:
                    lines.append(f"kind: {label}")
            # Children (containers / embedded payloads)
            children = getattr(art, "containers", None) or []
            if children:
                lines.append(f"children: {len(children)}")
                for c in children[:5]:  # limit list for readability
                    meta = getattr(c, "metadata", None)
                    meta_str = ""
                    if meta is not None:
                        fc = getattr(meta, "file_count", None)
                        tus = getattr(meta, "total_uncompressed_size", None)
                        tcs = getattr(meta, "total_compressed_size", None)
                        parts = []
                        if fc is not None:
                            parts.append(f"files={fc}")
                        if tus is not None:
                            parts.append(f"usize={tus}")
                        if tcs is not None:
                            parts.append(f"csize={tcs}")
                        if parts:
                            meta_str = " (" + ", ".join(parts) + ")"
                    lines.append(
                        f"- {c.type_name} @0x{c.offset:x} size={c.size} ({_human_bytes(c.size)}){meta_str}"
                    )
                if len(children) > 5:
                    lines.append(f"… and {len(children) - 5} more")
            # Symbols summary (imports/exports/libs + flags)
            symbols = getattr(art, "symbols", None)
            if symbols is not None:
                imp = getattr(symbols, "imports_count", 0)
                exp = getattr(symbols, "exports_count", 0)
                libs = getattr(symbols, "libs_count", 0)
                flags = []
                if getattr(symbols, "stripped", False):
                    flags.append("stripped")
                if getattr(symbols, "tls_used", False):
                    flags.append("tls")
                if getattr(symbols, "debug_info_present", False):
                    flags.append("debug")
                # Security posture flags if available
                if getattr(symbols, "nx", None) is True:
                    flags.append("nx")
                if getattr(symbols, "aslr", None) is True:
                    flags.append("aslr")
                if getattr(symbols, "relro", None) is True:
                    flags.append("relro")
                if getattr(symbols, "pie", None) is True:
                    flags.append("pie")
                if getattr(symbols, "cfg", None) is True:
                    flags.append("cfg")
                flag_str = f" flags: {','.join(flags)}" if flags else ""
                susp = getattr(symbols, "suspicious_imports", None)
                susp_str = ""
                if susp is not None:
                    try:
                        n = len(susp)
                    except Exception:
                        n = 0
                    if n:
                        susp_str = f"; suspicious={n}"
                lines.append(
                    f"symbols: imports={imp} exports={exp} libs={libs}{flag_str}{susp_str}"
                )
            # Strings summary (bounded); show one line of counts and IOCs
            strings = getattr(art, "strings", None)
            if strings is not None:
                counts = {
                    "ascii": getattr(strings, "ascii_count", 0),
                    "utf8": getattr(strings, "utf8_count", 0),
                    "u16le": getattr(strings, "utf16le_count", 0),
                    "u16be": getattr(strings, "utf16be_count", 0),
                }
                iocs = getattr(strings, "ioc_counts", None) or {}
                # pick a few high-signal IOC keys to show
                keys = ["url", "domain", "email", "ipv4", "ipv6"]
                ioc_bits = [f"{k}={iocs.get(k, 0)}" for k in keys if iocs.get(k, 0)]
                parts = [
                    f"strings: ascii={counts['ascii']} utf8={counts['utf8']} u16le={counts['u16le']} u16be={counts['u16be']}"
                ]
                if ioc_bits:
                    parts.append("ioc: " + ", ".join(ioc_bits))
                lines.append("; ".join(parts))
            # Similarity (optional)
            if args.sim:
                sim = getattr(art, "similarity", None)
                if sim is not None:
                    imphash = getattr(sim, "imphash", None)
                    ctph = getattr(sim, "ctph", None)
                    bits = []
                    if imphash:
                        bits.append(f"imphash={imphash}")
                    if ctph:
                        # Show only header of CTPH
                        header = ctph.split(":", 2)
                        if len(header) >= 2:
                            bits.append(f"ctph={header[0]}:{header[1]}:…")
                        else:
                            bits.append("ctph=<short>")
                    if bits:
                        lines.append("similarity: " + ", ".join(bits))
            # Errors (summary)
            errors = getattr(art, "errors", None) or []
            if errors:
                kinds = {}
                for e in errors:
                    k = getattr(e, "kind", None)
                    kstr = str(k) if k is not None else "Unknown"
                    kinds[kstr] = kinds.get(kstr, 0) + 1
                kind_str = ", ".join(f"{k}={v}" for k, v in kinds.items())
                lines.append(f"errors: {kind_str}")
            # Packers (signatures)
            packers = getattr(art, "packers", None) or []
            if packers:
                lines.append(f"packers: {len(packers)}")
                for m in packers:
                    lines.append(f"- {m.name} (confidence={m.confidence:.2f})")
            # Budgets
            budgets = getattr(art, "budgets", None)
            if budgets is not None:
                lines.append(
                    f"budgets: bytes_read={budgets.bytes_read} ({_human_bytes(budgets.bytes_read)}) time_ms={budgets.time_ms} depth={budgets.recursion_depth}"
                )
                hit = getattr(budgets, "hit_byte_limit", False)
                limit_b = getattr(budgets, "limit_bytes", None)
                if hit or limit_b is not None:
                    extra = f" hit_byte_limit={hit}"
                    if limit_b is not None:
                        extra += f" limit_bytes={limit_b}"
                    lines[-1] += extra
            print("\n".join(lines))
        return 0

    if args.cmd == "symbols":
        p = Path(args.path)
        try:
            # New native signature takes only the path; older versions accepted caps
            try:
                all_syms, dyn_syms, imports, exports, libs = g.triage.list_symbols(
                    str(p), args.max_read_bytes, args.max_file_size
                )
            except TypeError:
                all_syms, dyn_syms, imports, exports, libs = g.triage.list_symbols(
                    str(p)
                )
        except AttributeError:
            print("Native module missing list_symbols; please rebuild.")
            return 2
        if args.json:
            import json

            print(
                json.dumps(
                    {
                        "all": all_syms,
                        "dynamic": dyn_syms,
                        "imports": imports,
                        "exports": exports,
                        "libs": libs,
                    }
                )
            )
        else:
            print(f"symbols (all): {len(all_syms)}")
            for s in all_syms:
                print(f"  {s}")
            print(f"symbols (dynamic): {len(dyn_syms)}")
            for s in dyn_syms:
                print(f"  {s}")
            if imports:
                print(f"imports: {len(imports)}")
                for s in imports:
                    print(f"  {s}")
            if exports:
                print(f"exports: {len(exports)}")
                for s in exports:
                    print(f"  {s}")
            if libs:
                print(f"libs: {len(libs)}")
                for s in libs:
                    print(f"  {s}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
