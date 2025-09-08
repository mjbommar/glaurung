"""Formatter for triage command output."""

from typing import Any, Dict, List
from .base import BaseFormatter, OutputFormat
from ..utils.formatting import (
    human_bytes,
    format_hex,
)


class TriageFormatter(BaseFormatter):
    """Formatter for triage command output."""

    def format_output(self, artifact: Any) -> None:
        """Format and output triage artifact data."""
        if self.format_type == OutputFormat.JSON:
            import json

            try:
                if hasattr(artifact, "to_json"):
                    data = json.loads(artifact.to_json())
                elif hasattr(artifact, "to_dict"):
                    data = artifact.to_dict()
                else:
                    # Fallback to manual conversion
                    data = self._artifact_to_dict(artifact)
            except Exception:
                # As a last resort
                data = self._artifact_to_dict(artifact)

            # Optional filter: only strings with detected language
            if getattr(self, "strings_only_lang", False):
                s = data.get("strings") or {}
                if "strings" in s and isinstance(s["strings"], list):
                    s["strings"] = [d for d in s["strings"] if d.get("language")]
            self.output_json(data)
        elif self.format_type == OutputFormat.JSONL:
            # For triage, output key sections as separate JSON lines
            data = self._artifact_to_dict(artifact)
            if getattr(self, "strings_only_lang", False):
                s = data.get("strings") or {}
                if "strings" in s and isinstance(s["strings"], list):
                    s["strings"] = [d for d in s["strings"] if d.get("language")]
            self.output_jsonl(
                [
                    {"type": "metadata", "data": data.get("metadata", {})},
                    {"type": "verdicts", "data": data.get("verdicts", [])},
                    {"type": "symbols", "data": data.get("symbols", {})},
                    {"type": "strings", "data": data.get("strings", {})},
                    {"type": "containers", "data": data.get("containers", [])},
                ]
            )
        elif self.format_type == OutputFormat.RICH:
            self._format_rich(artifact)
        else:
            self._format_plain(artifact)

    def _artifact_to_dict(self, art) -> Dict:
        """Convert artifact to dictionary."""
        if hasattr(art, "to_dict"):
            return art.to_dict()

        # Try to convert from JSON if available
        if hasattr(art, "to_json"):
            import json

            return json.loads(art.to_json())

        # Manual conversion from artifact attributes
        result = {
            "metadata": {
                "path": getattr(art, "path", None),
                "size_bytes": getattr(art, "size_bytes", 0),
            }
        }

        # Add other sections if present
        if hasattr(art, "verdicts"):
            result["verdicts"] = [self._verdict_to_dict(v) for v in art.verdicts]
        if hasattr(art, "symbols"):
            result["symbols"] = self._symbols_to_dict(art.symbols)
        if hasattr(art, "strings"):
            result["strings"] = self._strings_to_dict(art.strings)
        if hasattr(art, "containers"):
            result["containers"] = [self._container_to_dict(c) for c in art.containers]

        return result

    def _verdict_to_dict(self, verdict) -> Dict:
        """Convert verdict to dictionary."""
        return {
            "format": str(getattr(verdict, "format", "")),
            "arch": str(getattr(verdict, "arch", "")),
            "bits": getattr(verdict, "bits", 0),
            "endianness": str(getattr(verdict, "endianness", "")),
            "confidence": getattr(verdict, "confidence", 0.0),
        }

    def _symbols_to_dict(self, symbols) -> Dict:
        """Convert symbols to dictionary."""
        if symbols is None:
            return {}

        return {
            "imports_count": getattr(symbols, "imports_count", 0),
            "exports_count": getattr(symbols, "exports_count", 0),
            "libs_count": getattr(symbols, "libs_count", 0),
            "flags": self._get_symbol_flags(symbols),
            "suspicious_imports": getattr(symbols, "suspicious_imports", []),
        }

    def _strings_to_dict(self, strings) -> Dict:
        """Convert strings to dictionary."""
        if strings is None:
            return {}

        return {
            "ascii_count": getattr(strings, "ascii_count", 0),
            "utf8_count": getattr(strings, "utf8_count", 0),
            "utf16le_count": getattr(strings, "utf16le_count", 0),
            "utf16be_count": getattr(strings, "utf16be_count", 0),
            # Include language/script histograms if present
            "language_counts": getattr(strings, "language_counts", {}),
            "script_counts": getattr(strings, "script_counts", {}),
            "ioc_counts": getattr(strings, "ioc_counts", {}),
        }

    def _container_to_dict(self, container) -> Dict:
        """Convert container to dictionary."""
        return {
            "type_name": getattr(container, "type_name", "unknown"),
            "offset": getattr(container, "offset", 0),
            "size": getattr(container, "size", 0),
        }

    def _get_symbol_flags(self, symbols) -> List[str]:
        """Extract symbol flags."""
        flags = []
        if getattr(symbols, "stripped", False):
            flags.append("stripped")
        if getattr(symbols, "tls_used", False):
            flags.append("tls")
        if getattr(symbols, "debug_info_present", False):
            flags.append("debug")
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
        return flags

    def _format_rich(self, art) -> None:
        """Format output using Rich with proper Layout grid structure."""
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
        from rich.tree import Tree
        from rich.layout import Layout
        from rich.console import Group

        def get_threat_level_bar(value: float, label: str, width: int = 20) -> Text:
            """Create a colored percentage bar with emoji indicator."""
            percentage = int(value * 100)
            filled = int((percentage / 100) * width)

            # Choose color and emoji based on threat level
            if percentage < 30:
                color = "green"
                emoji = "✅"
            elif percentage < 60:
                color = "yellow"
                emoji = "⚠️"
            elif percentage < 80:
                color = "orange3"
                emoji = "🔶"
            else:
                color = "red"
                emoji = "🚨"

            bar = f"{'█' * filled}{'░' * (width - filled)}"
            text = Text()
            text.append(f"{emoji} {label}: ", style="bold")
            text.append(bar, style=color)
            text.append(f" {percentage}%", style=f"bold {color}")
            return text

        def get_status_icon(
            condition: bool, true_icon: str = "✓", false_icon: str = "✗"
        ) -> Text:
            """Return colored status icon."""
            color = "green" if condition else "red"
            icon = true_icon if condition else false_icon
            return Text(icon, style=color)

        # Create the main layout structure
        layout = Layout()

        # Split into header (fixed), body (flexible), footer (fixed)
        layout.split_column(
            Layout(name="header", size=6),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3),
        )

        # Split header into 3 equal columns
        layout["header"].split_row(
            Layout(name="identity"), Layout(name="format"), Layout(name="threat")
        )

        # Split body into 2 rows
        layout["body"].split_column(
            Layout(name="top_row", ratio=1), Layout(name="bottom_row", ratio=1)
        )

        # Split top row into 3 columns
        layout["top_row"].split_row(
            Layout(name="security"), Layout(name="analysis"), Layout(name="strings")
        )

        # Split bottom row into 2 columns
        layout["bottom_row"].split_row(
            Layout(name="details", ratio=2), Layout(name="containers", ratio=1)
        )

        # Get data references
        symbols = getattr(art, "symbols", None)
        strings = getattr(art, "strings", None)

        # === HEADER: Identity ===
        id_text = Text()
        id_text.append("📂 ", style="bold")
        id_text.append(f"{art.path}\n", style="cyan")
        id_text.append(f"💾 {human_bytes(art.size_bytes)}", style="dim")

        sha256 = getattr(art, "sha256", None)
        if sha256:
            id_text.append(f"\n🔐 {sha256[:12]}...", style="dim italic")

        layout["identity"].update(
            Panel(id_text, title="[bold]File[/bold]", border_style="blue")
        )

        # === HEADER: Format ===
        if art.verdicts:
            top = art.verdicts[0]
            format_text = Text()
            format_text.append(f"{str(top.format).upper()}\n", style="bold yellow")
            format_text.append(f"{top.arch} {top.bits}-bit\n", style="cyan")
            conf_color = (
                "green"
                if top.confidence >= 0.9
                else ("yellow" if top.confidence >= 0.7 else "red")
            )
            format_text.append(
                f"Conf: {top.confidence:.1%}", style=f"bold {conf_color}"
            )

            layout["format"].update(
                Panel(format_text, title="[bold]Format[/bold]", border_style="yellow")
            )
        else:
            layout["format"].update(
                Panel(
                    Text("Unknown", style="dim"),
                    title="[bold]Format[/bold]",
                    border_style="dim",
                )
            )

        # === HEADER: Threat Score ===
        threat_score = 0.0
        threat_factors = []

        if symbols:
            if getattr(symbols, "stripped", False):
                threat_score += 0.15
                threat_factors.append("stripped")
            if len(getattr(symbols, "suspicious_imports", None) or []) > 0:
                threat_score += min(
                    0.3, len(getattr(symbols, "suspicious_imports", [])) * 0.05
                )
                threat_factors.append("suspicious")

        entropy = getattr(art, "entropy", None)
        if entropy and getattr(entropy, "overall", None) is not None:
            if getattr(entropy, "overall", 0) > 7.5:
                threat_score += 0.25
                threat_factors.append("high-entropy")

        if strings:
            iocs = getattr(strings, "ioc_counts", None) or {}
            if sum(iocs.values()) > 0:
                threat_score += min(0.2, sum(iocs.values()) * 0.02)
                threat_factors.append("iocs")

        threat_score = min(1.0, threat_score)
        threat_text = get_threat_level_bar(threat_score, "Risk", width=15)

        if threat_factors:
            threat_text.append(f"\n{', '.join(threat_factors[:3])}", style="dim italic")

        color = (
            "green"
            if threat_score < 0.3
            else ("yellow" if threat_score < 0.6 else "red")
        )
        layout["threat"].update(
            Panel(threat_text, title="[bold]Threat[/bold]", border_style=color)
        )

        # === BODY: Security ===
        sec_content = []

        if symbols:
            sec_table = Table(show_header=False, box=None)
            sec_table.add_column("Feature", style="cyan")
            sec_table.add_column("Status", justify="center")

            sec_table.add_row(
                "NX/DEP", get_status_icon(getattr(symbols, "nx", None) is True)
            )
            sec_table.add_row(
                "ASLR", get_status_icon(getattr(symbols, "aslr", None) is True)
            )
            sec_table.add_row(
                "PIE", get_status_icon(getattr(symbols, "pie", None) is True)
            )
            sec_table.add_row(
                "RELRO", get_status_icon(getattr(symbols, "relro", None) is True)
            )
            sec_table.add_row(
                "Stripped",
                get_status_icon(not getattr(symbols, "stripped", False), "✗", "✓"),
            )

            sec_content.append(sec_table)

        if sec_content:
            layout["security"].update(
                Panel(Group(*sec_content), title="🛡️ Security", border_style="green")
            )
        else:
            layout["security"].update(
                Panel(Text("No data", style="dim"), border_style="dim")
            )

        # === BODY: Analysis ===
        analysis_content = []

        if entropy:
            overall = getattr(entropy, "overall", None)
            if overall is not None:
                ent_text = Text()
                ent_color = (
                    "green" if overall < 6.0 else ("yellow" if overall < 7.5 else "red")
                )
                ent_text.append("Entropy: ", style="")
                ent_text.append(f"{overall:.2f}\n", style=ent_color)

                if getattr(entropy, "windows", None):
                    ent_text.append(f"Windows: {len(entropy.windows)}", style="dim")

                analysis_content.append(ent_text)

        if symbols:
            sym_text = Text()
            sym_text.append(f"Imports: {getattr(symbols, 'imports_count', 0)}\n")
            sym_text.append(f"Exports: {getattr(symbols, 'exports_count', 0)}\n")
            sym_text.append(f"Libraries: {getattr(symbols, 'libs_count', 0)}")

            susp = getattr(symbols, "suspicious_imports", None) or []
            if susp:
                sym_text.append(f"\n⚠️ Suspicious: {len(susp)}", style="bold red")

            analysis_content.append(sym_text)

        if analysis_content:
            layout["analysis"].update(
                Panel(
                    Group(*analysis_content), title="📊 Analysis", border_style="cyan"
                )
            )
        else:
            layout["analysis"].update(
                Panel(Text("No data", style="dim"), border_style="dim")
            )

        # === BODY: Strings ===
        string_content = []

        if strings:
            str_table = Table(show_header=False, box=None)
            str_table.add_column("Type", style="cyan")
            str_table.add_column("Count", justify="right")

            total = (
                getattr(strings, "ascii_count", 0)
                + getattr(strings, "utf8_count", 0)
                + getattr(strings, "utf16le_count", 0)
                + getattr(strings, "utf16be_count", 0)
            )

            str_table.add_row("Total", str(total))
            str_table.add_row("ASCII", str(getattr(strings, "ascii_count", 0)))

            # IOCs
            iocs = getattr(strings, "ioc_counts", None) or {}
            if any(iocs.values()):
                str_table.add_row("", "")
                # Add IOCs header as Text with bold style
                ioc_header = Text("IOCs", style="bold")
                str_table.add_row(ioc_header, "")
                for ioc_type, count in sorted(iocs.items(), key=lambda x: -x[1])[:5]:
                    if count > 0:
                        # Create Text object for count with appropriate color
                        color = (
                            "red"
                            if count > 10
                            else ("yellow" if count > 5 else "green")
                        )
                        count_text = Text(str(count), style=color)
                        str_table.add_row(f"  {ioc_type}", count_text)

            string_content.append(str_table)

        if string_content:
            layout["strings"].update(
                Panel(
                    Group(*string_content), title="📝 Strings", border_style="magenta"
                )
            )
        else:
            layout["strings"].update(
                Panel(Text("No data", style="dim"), border_style="dim")
            )

        # === BODY: Details (combines multiple artifact fields) ===
        detail_items = []

        # Suspicious imports
        if symbols:
            susp = getattr(symbols, "suspicious_imports", None) or []
            if susp:
                susp_text = Text()
                susp_text.append("⚠️ Suspicious imports:\n", style="bold yellow")
                for imp in susp[:5]:
                    susp_text.append(f"• {imp}\n", style="red")
                if len(susp) > 5:
                    susp_text.append(f"... (+{len(susp) - 5} more)", style="dim")
                detail_items.append(susp_text)

        # Hints
        hints = getattr(art, "hints", None) or []
        if hints:
            hint_text = Text()
            hint_text.append("💡 Hints:\n", style="bold")
            for hint in hints[:3]:
                hint_text.append(f"• {str(hint)[:60]}\n", style="blue")
            if len(hints) > 3:
                hint_text.append(f"... (+{len(hints) - 3} more)", style="dim")
            detail_items.append(hint_text)

        # Overlay
        overlay = getattr(art, "overlay", None)
        if overlay:
            ov_text = Text()
            ov_text.append("📄 Overlay: ", style="bold yellow")
            ov_text.append(
                f"{human_bytes(getattr(overlay, 'size', 0))} @ {format_hex(getattr(overlay, 'offset', 0))}\n"
            )
            detail_items.append(ov_text)

        if detail_items:
            layout["details"].update(
                Panel(Group(*detail_items), title="📋 Details", border_style="blue")
            )
        else:
            layout["details"].update(
                Panel(Text("No additional details", style="dim"), border_style="dim")
            )

        # === BODY: Containers ===
        containers = getattr(art, "containers", None) or []
        if containers:
            tree = Tree("📦")
            for c in containers[:5]:
                node = tree.add(f"{c.type_name} [{human_bytes(c.size)}]", style="cyan")
                children = getattr(c, "children", None) or []
                for child in children[:2]:
                    node.add(
                        f"{child.type_name} [{human_bytes(child.size)}]", style="dim"
                    )
                if len(children) > 2:
                    node.add(f"... +{len(children) - 2}", style="dim")

            if len(containers) > 5:
                tree.add(f"... +{len(containers) - 5}", style="dim")

            layout["containers"].update(
                Panel(tree, title="Containers", border_style="purple")
            )
        else:
            layout["containers"].update(
                Panel(Text("No containers", style="dim"), border_style="dim")
            )

        # === FOOTER ===
        footer_text = Text()

        # Add verdict count
        if len(art.verdicts) > 1:
            footer_text.append(f"📋 {len(art.verdicts)} format verdicts ", style="dim")

        # Add error count
        errors = getattr(art, "errors", None) or []
        if errors:
            footer_text.append(f"❌ {len(errors)} errors ", style="red")

        # Add schema version
        schema_version = getattr(art, "schema_version", None)
        if schema_version:
            footer_text.append(f"v{schema_version}", style="dim")

        if footer_text:
            layout["footer"].update(Panel(footer_text, border_style="dim"))
        else:
            layout["footer"].update(Text(""))

        # Print the complete layout
        self.console.print(layout)

    def _format_plain(self, art) -> None:
        """Format output as plain text."""
        lines = []

        lines.append(f"path: {art.path}")
        lines.append(f"size: {art.size_bytes} bytes ({human_bytes(art.size_bytes)})")
        lines.append(f"verdicts: {len(art.verdicts)}")

        if art.verdicts:
            top = art.verdicts[0]
            lines.append(
                f"format={top.format} arch={top.arch} {top.bits}-bit "
                f"endianness={top.endianness} confidence={top.confidence:.2f}"
            )

        # Symbols
        symbols = getattr(art, "symbols", None)
        if symbols:
            imp = getattr(symbols, "imports_count", 0)
            exp = getattr(symbols, "exports_count", 0)
            libs = getattr(symbols, "libs_count", 0)
            flags = self._get_symbol_flags(symbols)
            flag_str = f" flags: {','.join(flags)}" if flags else ""
            lines.append(f"symbols: imports={imp} exports={exp} libs={libs}{flag_str}")

        # Strings
        strings = getattr(art, "strings", None)
        if strings:
            lines.append(
                f"strings: ascii={getattr(strings, 'ascii_count', 0)} "
                f"utf8={getattr(strings, 'utf8_count', 0)} "
                f"u16le={getattr(strings, 'utf16le_count', 0)} "
                f"u16be={getattr(strings, 'utf16be_count', 0)}"
            )

            # Language/script histograms (compact one-liners)
            lang_counts = getattr(strings, "language_counts", None) or {}
            if lang_counts:
                top = ", ".join(
                    f"{k}={v}"
                    for k, v in sorted(
                        lang_counts.items(), key=lambda kv: (-kv[1], kv[0])
                    )[:6]
                )
                lines.append(f"languages: {top}")
            else:
                lines.append("languages: (none)")

            script_counts = getattr(strings, "script_counts", None) or {}
            if script_counts:
                top = ", ".join(
                    f"{k}={v}"
                    for k, v in sorted(
                        script_counts.items(), key=lambda kv: (-kv[1], kv[0])
                    )[:6]
                )
                lines.append(f"scripts: {top}")
            else:
                lines.append("scripts: (none)")

        # Entropy (plain)
        entropy = getattr(art, "entropy", None)
        if entropy and getattr(entropy, "overall", None) is not None:
            overall = getattr(entropy, "overall", None)
            if overall is not None:
                lines.append(f"entropy: overall={overall:.2f}")

        self.output_plain("\n".join(lines))
