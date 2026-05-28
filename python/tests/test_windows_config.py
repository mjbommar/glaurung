from __future__ import annotations

from pathlib import Path

import pytest

from glaurung.windows_config import WindowsAnalysisConfig, load_windows_analysis_config


def test_windows_analysis_config_loads_hyphenated_yaml(tmp_path: Path) -> None:
    config_path = tmp_path / "windows-analysis.yaml"
    config_path.write_text(
        """
max-read-bytes: 1234
max-file-size: 5678
max-functions: 9
timeout-ms: 250
pdb-cache-dir: symbols
""",
        encoding="utf-8",
    )

    config = load_windows_analysis_config(config_path)

    assert config.max_read_bytes == 1234
    assert config.max_file_size == 5678
    assert config.max_functions == 9
    assert config.timeout_ms == 250
    assert config.pdb_cache_dir == "symbols"


def test_windows_analysis_config_applies_optional_overrides() -> None:
    config = WindowsAnalysisConfig().with_overrides(
        max_read_bytes=2048,
        max_file_size=None,
    )

    assert config.max_read_bytes == 2048
    assert config.max_file_size == WindowsAnalysisConfig().max_file_size


def test_windows_analysis_config_rejects_unknown_keys(tmp_path: Path) -> None:
    config_path = tmp_path / "windows-analysis.yaml"
    config_path.write_text("unknown-key: true\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unknown Windows analysis key"):
        load_windows_analysis_config(config_path)
