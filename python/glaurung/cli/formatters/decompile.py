"""Minimal formatter for the decompile command.

Decompiled pseudocode is rendered to a string inside the native extension,
so the formatter's job is just to plumb `format_output`'s dict payload
through to the appropriate output channel. The command itself bypasses
this for the common plain-text path; this class exists to satisfy the
`BaseFormatter` contract and to handle the `--json` / `--format json`
dispatch consistently.
"""

from __future__ import annotations

import json
from typing import Any

from .base import BaseFormatter, OutputFormat


class DecompileFormatter(BaseFormatter):
    """Pass-through formatter — decompiled text is pre-rendered."""

    def format_output(self, data: Any) -> None:
        if self.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
            print(json.dumps(data, indent=2))
            return
        if isinstance(data, list):
            for entry in data:
                text = entry.get("pseudocode") if isinstance(entry, dict) else str(entry)
                if text:
                    self.output_plain(text)
            return
        if isinstance(data, dict):
            text = data.get("pseudocode", "")
            if text:
                self.output_plain(text)
            return
        self.output_plain(str(data))
