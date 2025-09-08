"""Formatting utilities for CLI output."""

from typing import Optional, List, Dict, Any, Union
import datetime


def human_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    f = float(n)
    i = 0
    while f >= 1024.0 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    if i == 0:
        return f"{int(f)} {units[i]}"
    return f"{f:.1f} {units[i]}"


def human_time(ms: int) -> str:
    """Format milliseconds as human-readable time."""
    if ms < 1000:
        return f"{ms}ms"
    elif ms < 60000:
        return f"{ms / 1000:.1f}s"
    else:
        minutes = ms // 60000
        seconds = (ms % 60000) / 1000
        return f"{minutes}m {seconds:.1f}s"


def truncate_string(s: str, max_len: int = 50, suffix: str = "...") -> str:
    """Truncate a string to maximum length with suffix."""
    if len(s) <= max_len:
        return s
    return s[: max_len - len(suffix)] + suffix


def format_hex(value: Union[int, str], prefix: bool = True) -> str:
    """Format a value as hexadecimal."""
    if isinstance(value, str):
        if value.startswith("0x"):
            return value
        try:
            value = int(value, 16)
        except ValueError:
            return str(value)

    if prefix:
        return f"0x{value:x}"
    return f"{value:x}"


def format_percentage(value: float, precision: int = 1) -> str:
    """Format a float as percentage."""
    return f"{value * 100:.{precision}f}%"


def format_confidence(confidence: float) -> str:
    """Format confidence score with color hints for Rich."""
    if confidence >= 0.9:
        return f"[bold green]{confidence:.2f}[/bold green]"
    elif confidence >= 0.7:
        return f"[yellow]{confidence:.2f}[/yellow]"
    else:
        return f"[red]{confidence:.2f}[/red]"


def format_risk_level(risk: str) -> str:
    """Format risk level with color hints for Rich."""
    risk_lower = risk.lower()
    if risk_lower in ["benign", "safe", "low"]:
        return f"[green]{risk}[/green]"
    elif risk_lower in ["medium", "moderate"]:
        return f"[yellow]{risk}[/yellow]"
    elif risk_lower in ["high", "dangerous"]:
        return f"[red]{risk}[/red]"
    elif risk_lower in ["malicious", "critical"]:
        return f"[bold red]{risk}[/bold red]"
    else:
        return risk


def format_list_summary(
    items: List[Any], max_items: int = 5, name: str = "items"
) -> str:
    """Format a list with truncation if too long."""
    if not items:
        return f"No {name}"

    if len(items) <= max_items:
        return ", ".join(str(item) for item in items)

    shown = ", ".join(str(item) for item in items[:max_items])
    remaining = len(items) - max_items
    return f"{shown} (+{remaining} more)"


def format_count_dict(counts: Dict[str, int], keys: Optional[List[str]] = None) -> str:
    """Format a dictionary of counts as a summary string."""
    if not counts:
        return "none"

    if keys:
        # Use specific keys in order
        parts = [f"{k}={counts.get(k, 0)}" for k in keys if counts.get(k, 0) > 0]
    else:
        # Use all keys
        parts = [f"{k}={v}" for k, v in counts.items() if v > 0]

    return ", ".join(parts) if parts else "none"


def indent_text(text: str, indent: int = 2, prefix: str = " ") -> str:
    """Indent text lines."""
    indent_str = prefix * indent
    lines = text.splitlines()
    return "\n".join(indent_str + line if line else "" for line in lines)


def format_timestamp(ts: Optional[datetime.datetime] = None) -> str:
    """Format a timestamp in ISO format."""
    if ts is None:
        ts = datetime.datetime.now()
    return ts.isoformat()


def format_diff(
    old: Any, new: Any, label_old: str = "old", label_new: str = "new"
) -> str:
    """Format a simple diff between two values."""
    return f"{label_old}: {old} → {label_new}: {new}"
