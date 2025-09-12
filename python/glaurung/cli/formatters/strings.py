"""Formatter for detailed strings analysis output."""

from typing import Any, Dict, List
from statistics import mean, median
from collections import Counter, defaultdict

import glaurung as g

from .base import BaseFormatter, OutputFormat
from ..utils.formatting import human_bytes, format_hex


class StringsFormatter(BaseFormatter):
    """Formatter for the strings command."""

    def format_output(self, data: Any) -> None:
        # Expect a dict with artifact + options
        if not isinstance(data, dict) or "artifact" not in data:
            # Fallback: just print repr
            return self.output_plain(str(data))

        art = data["artifact"]
        opts = data.get("options")

        analysis = self._analyze_strings(art, opts)

        if self.format_type == OutputFormat.JSON:
            self.output_json(analysis)
        elif self.format_type == OutputFormat.JSONL:
            # Emit key sections as JSONL
            self.output_jsonl({"type": "metadata", "data": analysis["metadata"]})
            self.output_jsonl({"type": "encodings", "data": analysis["encodings"]})
            self.output_jsonl(
                {"type": "languages", "data": analysis.get("languages", {})}
            )
            self.output_jsonl({"type": "scripts", "data": analysis.get("scripts", {})})
            self.output_jsonl({"type": "lengths", "data": analysis["lengths"]})
            self.output_jsonl({"type": "entropies", "data": analysis["entropies"]})
            for s in analysis.get("strings", []):
                self.output_jsonl({"type": "string", "data": s})
        elif self.format_type == OutputFormat.RICH:
            self._format_rich(analysis)
        else:
            self._format_plain(analysis)

    def _collect_strings(self, art) -> List[Dict[str, Any]]:
        strings = getattr(art, "strings", None)
        if not strings or not getattr(strings, "strings", None):
            return []
        items = []
        for s in strings.strings:
            text = s.text
            enc = s.encoding
            off = s.offset
            lang = getattr(s, "language", None)
            script = getattr(s, "script", None)
            conf = getattr(s, "confidence", None)
            length = len(text)
            items.append(
                {
                    "text": text,
                    "encoding": enc,
                    "offset": off,
                    "length": length,
                    "language": lang,
                    "script": script,
                    "confidence": conf,
                }
            )
        return items

    def _compute_entropy_stats(
        self, strings: List[Dict[str, Any]], compute_entropy: bool, bins: int
    ) -> Dict[str, Any]:
        if not compute_entropy or not strings:
            return {"count": len(strings), "stats": None, "histogram": None}

        ent_values = []
        for s in strings:
            try:
                e = g.triage.entropy_of_bytes(
                    s["text"].encode("utf-8", errors="ignore")
                )
            except Exception:
                e = None
            s["entropy"] = e
            if e is not None:
                ent_values.append(e)

        if not ent_values:
            return {"count": len(strings), "stats": None, "histogram": None}

        # Build histogram from 0..8
        max(1, bins)
        # Using integer bins across [0,8], last bin 8+
        bucket_counts = defaultdict(int)
        for v in ent_values:
            idx = int(v)
            if idx >= 8:
                idx = 8
            bucket_counts[idx] += 1
        # Normalize into ordered list
        hist = [
            {"bin": f"{i}-{i + 1}" if i < 8 else "8+", "count": bucket_counts.get(i, 0)}
            for i in range(0, 9)
        ]

        stats = {
            "min": min(ent_values),
            "max": max(ent_values),
            "mean": sum(ent_values) / len(ent_values),
            "p50": self._percentile(ent_values, 50),
            "p90": self._percentile(ent_values, 90),
            "p99": self._percentile(ent_values, 99),
        }
        return {"count": len(strings), "stats": stats, "histogram": hist}

    def _percentile(self, values: List[float], p: int) -> float:
        if not values:
            return 0.0
        vals = sorted(values)
        k = (len(vals) - 1) * (p / 100.0)
        f = int(k)
        c = min(f + 1, len(vals) - 1)
        if f == c:
            return vals[f]
        d0 = vals[f] * (c - k)
        d1 = vals[c] * (k - f)
        return d0 + d1

    def _compute_length_stats(self, strings: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not strings:
            return {
                "count": 0,
                "stats": None,
                "histogram": [],
                "by_length": {},
            }

        lengths = [s["length"] for s in strings]
        length_counts = Counter(lengths)
        # Default bins: 1–4, 5–9, 10–19, 20–39, 40–79, 80–159, 160–319, 320+
        bins = [(1, 4), (5, 9), (10, 19), (20, 39), (40, 79), (80, 159), (160, 319)]
        hist = []
        for lo, hi in bins:
            cnt = sum(1 for L in lengths if lo <= L <= hi)
            hist.append({"bin": f"{lo}-{hi}", "count": cnt})
        hist.append({"bin": "320+", "count": sum(1 for L in lengths if L >= 320)})

        stats = {
            "min": min(lengths),
            "max": max(lengths),
            "mean": mean(lengths),
            "median": median(lengths),
            "p90": self._percentile(sorted(map(float, lengths)), 90),
            "p99": self._percentile(sorted(map(float, lengths)), 99),
        }

        # Provide compact by_length mapping for smaller lengths (cap to 500 distinct lengths)
        by_len = dict(length_counts.most_common(500))

        return {
            "count": len(strings),
            "stats": stats,
            "histogram": hist,
            "by_length": by_len,
        }

    def _analyze_strings(self, art, opts) -> Dict[str, Any]:
        data = {
            "metadata": {
                "path": getattr(art, "path", None),
                "size_bytes": getattr(art, "size_bytes", 0),
            }
        }

        strings = getattr(art, "strings", None)
        enc = {
            "ascii": getattr(strings, "ascii_count", 0) if strings else 0,
            "utf8": getattr(strings, "utf8_count", 0) if strings else 0,
            "utf16le": getattr(strings, "utf16le_count", 0) if strings else 0,
            "utf16be": getattr(strings, "utf16be_count", 0) if strings else 0,
        }
        data["encodings"] = enc

        data["languages"] = getattr(strings, "language_counts", None) or {}
        data["scripts"] = getattr(strings, "script_counts", None) or {}
        data["iocs"] = getattr(strings, "ioc_counts", None) or {}

        items = self._collect_strings(art)
        # Optional filter: only strings with detected language
        if getattr(self, "only_lang", False):
            items = [s for s in items if s.get("language")]

        # Optionally compute entropy; always compute length stats
        ent = self._compute_entropy_stats(
            items,
            getattr(opts, "compute_entropy", True),
            getattr(opts, "entropy_bins", 8),
        )
        data["entropies"] = ent
        data["lengths"] = self._compute_length_stats(items)

        # Apply raw display limits for JSON to avoid blow-up if requested
        if items:
            if getattr(opts, "truncate_json_strings", False):
                width = getattr(opts, "raw_width", 160)
                for s in items:
                    if isinstance(s.get("text"), str) and len(s["text"]) > width:
                        s["text"] = s["text"][:width]
            data["strings"] = items
        else:
            data["strings"] = []

        # Include display preferences (if provided) for formatter use
        if opts is not None:
            data["display"] = {
                "raw_limit": getattr(opts, "raw_limit", 2000),
                "raw_width": getattr(opts, "raw_width", 160),
                "show_raw": getattr(opts, "show_raw", True),
            }

        return data

    def _format_rich(self, analysis: Dict[str, Any]) -> None:
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        meta_text = Text()
        meta_text.append("📄 Strings Analysis\n", style="bold cyan")
        meta_text.append("Path: ", style="bold")
        meta_text.append(f"{analysis['metadata']['path']}\n")
        size = analysis["metadata"].get("size_bytes", 0)
        meta_text.append("Size: ", style="bold")
        meta_text.append(f"{size} bytes ({human_bytes(size)})\n")
        self.output_rich(
            Panel(
                meta_text, title="[bold blue]Overview[/bold blue]", border_style="blue"
            )
        )

        # Encodings table
        enc_table = Table(title="[bold cyan]Encoding Counts[/bold cyan]")
        enc_table.add_column("Encoding", style="cyan")
        enc_table.add_column("Count", justify="right", style="yellow")
        for k in ["ascii", "utf8", "utf16le", "utf16be"]:
            enc_table.add_row(
                k.upper() if k.startswith("utf") else k.capitalize(),
                str(analysis["encodings"].get(k, 0)),
            )
        self.output_rich(enc_table)

        # Summary panel
        top_lang = next(
            iter(
                sorted(
                    (analysis.get("languages") or {}).items(),
                    key=lambda kv: (-kv[1], kv[0]),
                )
            ),
            (None, None),
        )
        top_script = next(
            iter(
                sorted(
                    (analysis.get("scripts") or {}).items(),
                    key=lambda kv: (-kv[1], kv[0]),
                )
            ),
            (None, None),
        )
        total_strings = analysis["lengths"].get("count", 0)
        ent_stats = analysis["entropies"].get("stats") or {}
        ent_mean = ent_stats.get("mean")
        len_stats = analysis["lengths"].get("stats") or {}
        len_median = len_stats.get("median")

        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        summary = Table.grid(padding=(0, 1))
        summary.add_column(justify="right", style="bold")
        summary.add_column()
        summary.add_row("Total Strings", str(total_strings))
        summary.add_row("Top Language", str(top_lang[0]) if top_lang[0] else "-")
        summary.add_row("Top Script", str(top_script[0]) if top_script[0] else "-")
        if len_median is not None:
            summary.add_row("Median Length", f"{len_median:.1f}")
        if ent_mean is not None:
            summary.add_row("Mean Entropy", f"{ent_mean:.2f}")
        self.output_rich(
            Panel(summary, title="[bold blue]Summary[/bold blue]", border_style="blue")
        )

        # Language / Script tables
        lang = analysis.get("languages") or {}
        lang_table = Table(title="[bold cyan]Language Distribution[/bold cyan]")
        lang_table.add_column("Language", style="cyan")
        lang_table.add_column("Count", justify="right", style="yellow")
        for k, v in sorted(lang.items(), key=lambda kv: (-kv[1], kv[0])):
            lang_table.add_row(str(k), str(v))
        self.output_rich(lang_table)

        scripts = analysis.get("scripts") or {}
        script_table = Table(title="[bold cyan]Script Distribution[/bold cyan]")
        script_table.add_column("Script", style="cyan")
        script_table.add_column("Count", justify="right", style="yellow")
        for k, v in sorted(scripts.items(), key=lambda kv: (-kv[1], kv[0])):
            script_table.add_row(str(k), str(v))
        self.output_rich(script_table)

        # Length stats
        lengths = analysis["lengths"]
        len_table = Table(title="[bold cyan]String Lengths[/bold cyan]")
        len_table.add_column("Bin", style="cyan")
        len_table.add_column("Count", justify="right", style="yellow")
        for b in lengths["histogram"]:
            len_table.add_row(b["bin"], str(b["count"]))
        self.output_rich(len_table)
        # Length stats panel
        if lengths.get("stats"):
            st = lengths["stats"]
            lt = Table(title="[bold cyan]Length Stats[/bold cyan]", show_header=False)
            for k in ["min", "median", "mean", "max", "p90", "p99"]:
                val = st.get(k) if k != "mean" else st.get("mean")
                if val is not None:
                    if isinstance(val, float):
                        lt.add_row(k, f"{val:.2f}")
                    else:
                        lt.add_row(k, str(val))
            self.output_rich(lt)

        # Entropy stats if present
        ent = analysis["entropies"]
        ent_hist = ent.get("histogram")
        if ent_hist:
            ent_table = Table(title="[bold cyan]Per-String Entropy[/bold cyan]")
            ent_table.add_column("Bin", style="cyan")
            ent_table.add_column("Count", justify="right", style="yellow")
            for b in ent_hist:
                ent_table.add_row(b["bin"], str(b["count"]))
            self.output_rich(ent_table)
            # Entropy stats panel
            if analysis["entropies"].get("stats"):
                st = analysis["entropies"]["stats"]
                et = Table(
                    title="[bold cyan]Entropy Stats[/bold cyan]", show_header=False
                )
                for k in ["min", "mean", "p50", "p90", "p99", "max"]:
                    val = st.get(k)
                    if val is not None:
                        et.add_row(k, f"{val:.2f}")
                self.output_rich(et)

        # IOC counts (including hashes if detected)
        iocs = analysis.get("iocs") or {}
        if any(v > 0 for v in iocs.values()):
            ioc_table = Table(title="[bold yellow]IOC / Hash Counts[/bold yellow]")
            ioc_table.add_column("Type", style="cyan")
            ioc_table.add_column("Count", justify="right", style="yellow")
            for k, v in sorted(iocs.items(), key=lambda kv: (-kv[1], kv[0])):
                ioc_table.add_row(k.upper(), str(v))
            self.output_rich(ioc_table)

        # Raw strings table (limited)
        # We cannot access options directly here, but JSON contains full list; for rich we cap visual output
        items = analysis.get("strings", [])
        disp = analysis.get("display", {})
        raw_limit = min(len(items), int(disp.get("raw_limit", 2000)))
        if disp.get("show_raw", True) and raw_limit > 0:
            raw = Table(
                title=f"[bold cyan]Raw Strings (showing {raw_limit} of {len(items)})[/bold cyan]",
                show_lines=False,
            )
            raw.add_column("Offset", style="cyan", no_wrap=True)
            raw.add_column("Enc", style="magenta", no_wrap=True)
            raw.add_column("Len", justify="right", style="yellow", no_wrap=True)
            raw.add_column("Entropy", justify="right", style="green", no_wrap=True)
            raw.add_column("Lang", style="cyan", no_wrap=True)
            raw.add_column("Script", style="cyan", no_wrap=True)
            raw.add_column("Text", style="white")
            width = int(disp.get("raw_width", 160))
            for s in items[:raw_limit]:
                off = s.get("offset")
                off_str = format_hex(off) if off is not None else "-"
                ent = s.get("entropy")
                ent_str = f"{ent:.2f}" if isinstance(ent, (int, float)) else "-"
                text = s.get("text", "")
                if isinstance(text, str) and len(text) > width:
                    text = text[:width]
                raw.add_row(
                    off_str,
                    s.get("encoding", ""),
                    str(s.get("length", 0)),
                    ent_str,
                    str(s.get("language", "")),
                    str(s.get("script", "")),
                    text,
                )
            self.output_rich(raw)

    def _format_plain(self, analysis: Dict[str, Any]) -> None:
        lines: List[str] = []
        lines.append(f"path: {analysis['metadata']['path']}")
        size = analysis["metadata"].get("size_bytes", 0)
        lines.append(f"size: {size} bytes ({human_bytes(size)})")

        enc = analysis["encodings"]
        lines.append(
            f"encodings: ascii={enc['ascii']} utf8={enc['utf8']} u16le={enc['utf16le']} u16be={enc['utf16be']}"
        )

        # Languages/scripts
        langs = analysis.get("languages") or {}
        if langs:
            lines.append(
                "languages: "
                + ", ".join(
                    f"{k}={v}"
                    for k, v in sorted(langs.items(), key=lambda kv: (-kv[1], kv[0]))
                )
            )
        else:
            lines.append("languages: (none)")
        scripts = analysis.get("scripts") or {}
        if scripts:
            lines.append(
                "scripts: "
                + ", ".join(
                    f"{k}={v}"
                    for k, v in sorted(scripts.items(), key=lambda kv: (-kv[1], kv[0]))
                )
            )
        else:
            lines.append("scripts: (none)")

        # Length stats compact
        ls = analysis["lengths"]
        if ls["stats"]:
            st = ls["stats"]
            lines.append(
                f"lengths: count={ls['count']} min={st['min']} max={st['max']} mean={st['mean']:.1f} median={st['median']:.1f} p90={st['p90']:.1f} p99={st['p99']:.1f}"
            )
        else:
            lines.append("lengths: no data")
        # Entropy stats compact
        es = analysis["entropies"]
        if es.get("stats"):
            st = es["stats"]
            lines.append(
                f"entropy: count={es['count']} min={st['min']:.2f} max={st['max']:.2f} mean={st['mean']:.2f} p90={st['p90']:.2f} p99={st['p99']:.2f}"
            )
        else:
            lines.append("entropy: no data")

        # Raw strings
        disp = analysis.get("display", {})
        raw_limit = int(disp.get("raw_limit", 2000))
        for s in analysis.get("strings", [])[:raw_limit]:
            off = s.get("offset")
            off_str = format_hex(off) if off is not None else "-"
            ent = s.get("entropy")
            ent_str = f" {ent:.2f}" if isinstance(ent, (int, float)) else ""
            lines.append(
                f"[{off_str}] {s.get('encoding', ''):<8} len={s.get('length', 0):>4}{ent_str} lang={s.get('language', '') or '-'} script={s.get('script', '') or '-'} | {s.get('text', '')}"
            )

        self.output_plain("\n".join(lines))
