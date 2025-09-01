"""Command-line interface for Glaurung triage."""

import argparse
from pathlib import Path

import glaurung as g


def main(argv=None):
    parser = argparse.ArgumentParser(prog="glaurung", description="Glaurung triage CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    triage = sub.add_parser("triage", help="Triage a file")
    triage.add_argument("path", help="Path to file")
    triage.add_argument("--json", action="store_true", help="Emit JSON")

    args = parser.parse_args(argv)

    if args.cmd == "triage":
        p = Path(args.path)
        art = g.triage.analyze_path(str(p))
        if args.json:
            print(art.to_json())
        else:
            summary = f"path: {art.path}\nsize: {art.size_bytes} bytes\nverdicts: {len(art.verdicts)}"
            if art.verdicts:
                top = art.verdicts[0]
                summary += (
                    f"\n_top_: format={top.format} arch={top.arch} {top.bits}-bit endianness={top.endianness}"
                    f" confidence={top.confidence:.2f}"
                )
            print(summary)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
