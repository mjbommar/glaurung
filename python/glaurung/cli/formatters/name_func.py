"""Minimal formatter for the name-func command."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseFormatter, OutputFormat


class NameFuncFormatter(BaseFormatter):
    """Pass-through formatter — name-func renders its own text."""

    def format_output(self, data: Any) -> None:
        if self.format_type in (OutputFormat.JSON, OutputFormat.JSONL):
            print(json.dumps(data, indent=2))
            return
        if isinstance(data, dict):
            for k, v in data.items():
                self.output_plain(f"{k}: {v}")
            return
        self.output_plain(str(data))
