"""Synchronize generated Windows API prototype bundles.

The sync path is deliberately opt-in. Normal analysis uses the checked-in
generated bundle and never touches the network. This module downloads pinned
NuGet packages, extracts `.winmd` metadata files, asks the Rust
``windows-metadata`` extractor to normalize P/Invoke prototypes, then writes
the canonical stdlib WinAPI prototype bundle plus a provenance manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import glaurung as g


REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_TYPES_DIR = REPO_ROOT / "data" / "types"
DEFAULT_LOCK_PATH = DATA_TYPES_DIR / "windows-api-sources.lock.json"
DEFAULT_OVERLAY_PATH = DATA_TYPES_DIR / "overlays" / "windows-api-semantics.json"
DEFAULT_OUTPUT_PATH = DATA_TYPES_DIR / "stdlib-winapi-protos.json"
DEFAULT_GENERATED_DIR = DATA_TYPES_DIR / "generated"
DEFAULT_CACHE_DIR = (
    Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    / "glaurung"
    / "windows-api-metadata"
)
NUGET_FLATCONTAINER = "https://api.nuget.org/v3-flatcontainer"


@dataclass(frozen=True)
class PackageSource:
    """Pinned NuGet metadata source from the source lock."""

    source_id: str
    package: str
    version: str
    winmd_path: str
    confidence: float
    source_url: str
    source_kind: str = "nuget_winmd"
    enabled: bool = True
    nupkg_sha256: str | None = None

    @property
    def package_lower(self) -> str:
        return self.package.lower()

    @property
    def version_lower(self) -> str:
        return self.version.lower()

    @property
    def nupkg_url(self) -> str:
        return (
            f"{NUGET_FLATCONTAINER}/{self.package_lower}/{self.version_lower}/"
            f"{self.package_lower}.{self.version_lower}.nupkg"
        )

    @property
    def cache_filename(self) -> str:
        return f"{self.package_lower}.{self.version}.nupkg"


def sync_windows_api_types(
    *,
    source_lock: Path = DEFAULT_LOCK_PATH,
    overlay_path: Path = DEFAULT_OVERLAY_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    generated_dir: Path = DEFAULT_GENERATED_DIR,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    offline: bool = False,
    include_overlays: bool = True,
    header_paths: list[Path] | None = None,
    clang: str = "clang",
    clang_args: list[str] | None = None,
) -> dict[str, Any]:
    """Download pinned Windows metadata and regenerate the WinAPI bundle.

    Args:
        source_lock: JSON lock file with pinned package versions.
        overlay_path: Curated semantic/prototype overlay file.
        output_path: Canonical bundle consumed by KB imports.
        generated_dir: Directory receiving manifest and snapshot copy.
        cache_dir: Persistent package/winmd cache.
        offline: Refuse network and require cached packages.
        include_overlays: Merge curated prototypes/semantics.
        header_paths: Optional local SDK/WDK headers to parse via Clang AST.
        clang: Clang executable for header augmentation.
        clang_args: Extra arguments passed to Clang before each header path.

    Returns:
        Manifest dictionary written to ``generated_dir / "MANIFEST.json"``.
    """

    lock = _load_json(source_lock)
    sources = _package_sources(lock)
    if not sources:
        raise ValueError(f"no enabled NuGet WinMD sources in {source_lock}")

    generated_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    all_prototypes: dict[str, dict[str, Any]] = {}
    source_results: list[dict[str, Any]] = []
    for source in sources:
        result = _sync_package_source(source, cache_dir=cache_dir, offline=offline)
        extracted = result.pop("extracted_winmd")
        export = _export_winmd(extracted)
        result.update(
            {
                "type_count": export.get("type_count", 0),
                "method_count": export.get("method_count", 0),
                "pinvoke_count": export.get("pinvoke_count", 0),
                "prototype_count": len(export.get("prototypes", [])),
                "status": "ok",
            }
        )
        source_results.append(result)
        _merge_source_prototypes(
            all_prototypes,
            export.get("prototypes", []),
            source=source,
            winmd_sha256=str(result["winmd_sha256"]),
            nupkg_sha256=str(result["nupkg_sha256"]),
        )

    header_results: list[dict[str, Any]] = []
    for header in header_paths or []:
        result = _sync_header_source(
            header,
            clang=clang,
            clang_args=clang_args or [],
        )
        header_results.append(result)
        _merge_header_prototypes(
            all_prototypes,
            result.get("prototypes", []),
            header=header,
            header_sha256=str(result["header_sha256"]),
            confidence=float(result["confidence"]),
        )
        result.pop("prototypes", None)

    overlay_summary: dict[str, Any] | None = None
    if include_overlays and overlay_path.exists():
        overlay = _load_json(overlay_path)
        overlay_summary = _apply_overlay(all_prototypes, overlay, overlay_path)

    prototypes = sorted(all_prototypes.values(), key=lambda p: p["name"].lower())
    generated_at = _now_iso()
    bundle = {
        "schema_version": "2",
        "bundle_name": "stdlib-winapi-protos",
        "description": (
            "Generated Windows API function prototypes from pinned Microsoft "
            "Win32/WDK metadata plus curated Glaurung overlays"
        ),
        "set_by": "stdlib",
        "generated": True,
        "source_lock": str(source_lock),
        "manifest": "generated/MANIFEST.json",
        "prototypes": prototypes,
    }
    _write_json(output_path, bundle)

    manifest_path = generated_dir / "MANIFEST.json"
    manifest = {
        "schema_version": "1",
        "generated_at": generated_at,
        "manifest_path": str(manifest_path),
        "source_lock": str(source_lock),
        "output_path": str(output_path),
        "generated_bundle_path": str(output_path),
        "bundle_sha256": _sha256_file(output_path),
        "prototype_count": len(prototypes),
        "source_results": source_results,
        "header_results": header_results,
        "overlay": overlay_summary,
        "optional_sources": lock.get("optional_sources", {}),
        "network_used": not offline,
        "analysis_network_policy": (
            "offline by default; only `glaurung types sync` downloads metadata"
        ),
    }
    _write_json(manifest_path, manifest)
    return manifest


def _sync_package_source(
    source: PackageSource, *, cache_dir: Path, offline: bool
) -> dict[str, Any]:
    package_path = cache_dir / source.cache_filename
    if not package_path.exists():
        if offline:
            raise FileNotFoundError(
                f"cached package missing for offline sync: {package_path}"
            )
        _download(source.nupkg_url, package_path)

    nupkg_sha256 = _sha256_file(package_path)
    if source.nupkg_sha256 and source.nupkg_sha256.lower() != nupkg_sha256:
        raise ValueError(
            f"sha256 mismatch for {package_path}: expected "
            f"{source.nupkg_sha256}, got {nupkg_sha256}"
        )

    extract_root = cache_dir / source.package_lower / source.version
    winmd_out = extract_root / source.winmd_path
    if not winmd_out.exists():
        extract_root.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(package_path) as zf:
            try:
                member = zf.getinfo(source.winmd_path)
            except KeyError as exc:
                raise FileNotFoundError(
                    f"{source.winmd_path} missing from {package_path}"
                ) from exc
            _safe_extract_member(zf, member, extract_root)

    return {
        "source_id": source.source_id,
        "source_kind": source.source_kind,
        "package": source.package,
        "version": source.version,
        "source_url": source.source_url,
        "nupkg_url": source.nupkg_url,
        "nupkg_path": str(package_path),
        "nupkg_sha256": nupkg_sha256,
        "winmd_path": source.winmd_path,
        "extracted_winmd_path": str(winmd_out),
        "winmd_sha256": _sha256_file(winmd_out),
        "confidence": source.confidence,
        "extracted_winmd": winmd_out,
    }


def _merge_source_prototypes(
    out: dict[str, dict[str, Any]],
    prototypes: Iterable[dict[str, Any]],
    *,
    source: PackageSource,
    winmd_sha256: str,
    nupkg_sha256: str,
) -> None:
    for raw in prototypes:
        name = str(raw.get("name", "")).strip()
        if not name:
            continue
        key = name.lower()
        if key in out:
            out[key].setdefault("alternate_sources", []).append(
                _prototype_provenance(raw, source)
            )
            continue
        proto = {
            "name": name,
            "return_type": str(raw.get("return_type") or "void"),
            "params": [
                {
                    "name": str(param.get("name") or f"arg{idx}"),
                    "c_type": str(param.get("c_type") or "void *"),
                }
                for idx, param in enumerate(raw.get("params", []) or [])
            ],
            "is_variadic": bool(raw.get("is_variadic", False)),
            "module": raw.get("module"),
            "calling_convention": raw.get("calling_convention"),
            "source": source.source_id,
            "source_kind": source.source_kind,
            "confidence": source.confidence,
            "provenance": _prototype_provenance(raw, source),
        }
        out[key] = proto


def _sync_header_source(
    header: Path,
    *,
    clang: str,
    clang_args: list[str],
) -> dict[str, Any]:
    if not header.exists():
        raise FileNotFoundError(f"header file not found: {header}")
    cmd = [
        clang,
        "-x",
        "c",
        "-fsyntax-only",
        "-Wno-everything",
        "-Xclang",
        "-ast-dump=json",
        *clang_args,
        str(header),
    ]
    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"clang failed for {header} with exit {proc.returncode}: "
            f"{proc.stderr.strip()[:2000]}"
        )
    ast = json.loads(proc.stdout)
    prototypes = list(_extract_function_decls(ast))
    return {
        "source_id": f"header:{header.name}",
        "source_kind": "clang_header_ast",
        "header_path": str(header),
        "header_sha256": _sha256_file(header),
        "clang": clang,
        "clang_args": clang_args,
        "confidence": 0.74,
        "prototype_count": len(prototypes),
        "status": "ok",
        "prototypes": prototypes,
    }


def _extract_function_decls(node: dict[str, Any]) -> Iterable[dict[str, Any]]:
    if node.get("kind") == "FunctionDecl" and node.get("name"):
        params = []
        for child in node.get("inner", []) or []:
            if child.get("kind") != "ParmVarDecl":
                continue
            params.append(
                {
                    "name": str(child.get("name") or f"arg{len(params)}"),
                    "c_type": _clean_header_type(child.get("type", {}).get("qualType")),
                }
            )
        yield {
            "name": str(node["name"]),
            "return_type": _function_return_type(
                str(node.get("type", {}).get("qualType") or "void")
            ),
            "params": params,
            "is_variadic": "..." in str(node.get("type", {}).get("qualType") or ""),
        }
    for child in node.get("inner", []) or []:
        if isinstance(child, dict):
            yield from _extract_function_decls(child)


def _function_return_type(qual_type: str) -> str:
    before_paren = qual_type.split("(", 1)[0].strip()
    return _clean_header_type(before_paren or "void")


def _clean_header_type(value: Any) -> str:
    text = str(value or "void").strip()
    return " ".join(text.replace(" *", "*").replace("*", " *").split())


def _merge_header_prototypes(
    out: dict[str, dict[str, Any]],
    prototypes: Iterable[dict[str, Any]],
    *,
    header: Path,
    header_sha256: str,
    confidence: float,
) -> None:
    for raw in prototypes:
        name = str(raw.get("name", "")).strip()
        if not name:
            continue
        key = name.lower()
        provenance = {
            "source_id": f"header:{header.name}",
            "header_path": str(header),
            "header_sha256": header_sha256,
        }
        if key in out:
            out[key].setdefault("alternate_sources", []).append(provenance)
            continue
        out[key] = {
            "name": name,
            "return_type": str(raw.get("return_type") or "void"),
            "params": [
                {
                    "name": str(param.get("name") or f"arg{idx}"),
                    "c_type": str(param.get("c_type") or "void *"),
                }
                for idx, param in enumerate(raw.get("params", []) or [])
            ],
            "is_variadic": bool(raw.get("is_variadic", False)),
            "source": f"header:{header.name}",
            "source_kind": "clang_header_ast",
            "confidence": confidence,
            "provenance": provenance,
        }


def _prototype_provenance(
    raw: dict[str, Any],
    source: PackageSource,
) -> dict[str, Any]:
    return {
        "source_id": source.source_id,
        "package": source.package,
        "version": source.version,
        "winmd_path": source.winmd_path,
        "namespace": raw.get("namespace"),
        "metadata_type": raw.get("metadata_type"),
        "import_name": raw.get("import_name"),
    }


def _apply_overlay(
    prototypes: dict[str, dict[str, Any]],
    overlay: dict[str, Any],
    overlay_path: Path,
) -> dict[str, Any]:
    added = 0
    updated = 0
    semantics = 0
    overlay_source = {
        "source": overlay.get("source", "glaurung-overlay"),
        "source_kind": overlay.get("source_kind", "curated_overlay"),
        "source_url": overlay.get("source_url"),
        "path": str(overlay_path),
        "sha256": _sha256_file(overlay_path),
    }

    for entry in overlay.get("prototype_overrides", []) or []:
        name = str(entry.get("name", "")).strip()
        if not name:
            continue
        key = name.lower()
        proto = {
            "name": name,
            "return_type": str(entry.get("return_type") or "void"),
            "params": [
                {
                    "name": str(param["name"]),
                    "c_type": str(param["c_type"]),
                    **(
                        {"role": str(param["role"])}
                        if param.get("role") is not None
                        else {}
                    ),
                }
                for param in entry.get("params", []) or []
            ],
            "is_variadic": bool(entry.get("is_variadic", False)),
            "module": entry.get("module"),
            "calling_convention": entry.get("calling_convention"),
            "source": overlay_source["source"],
            "source_kind": overlay_source["source_kind"],
            "confidence": float(
                entry.get("confidence", overlay.get("confidence", 0.85))
            ),
            "provenance": {
                **overlay_source,
                "notes": entry.get("notes"),
            },
        }
        existing = prototypes.get(key)
        if existing is None or bool(entry.get("replace", False)):
            prototypes[key] = proto
            added += 1 if existing is None else 0
            updated += 1 if existing is not None else 0
        else:
            existing.update({k: v for k, v in proto.items() if v is not None})
            updated += 1

    for entry in overlay.get("semantics", []) or []:
        name = str(entry.get("name", "")).strip()
        if not name:
            continue
        proto = prototypes.get(name.lower())
        if proto is None:
            continue
        proto["semantics"] = {
            key: value for key, value in entry.items() if key != "name"
        }
        proto.setdefault("semantic_provenance", overlay_source)
        semantics += 1

    return {
        "path": str(overlay_path),
        "sha256": overlay_source["sha256"],
        "prototype_added": added,
        "prototype_updated": updated,
        "semantics_attached": semantics,
    }


def _export_winmd(path: Path) -> dict[str, Any]:
    winmd = getattr(g, "winmd")
    raw = winmd.export_winmd_prototypes_json(str(path))
    data = json.loads(raw)
    if not isinstance(data.get("prototypes"), list):
        raise ValueError(f"native WinMD export missing prototypes list for {path}")
    return data


def _package_sources(lock: dict[str, Any]) -> list[PackageSource]:
    sources: list[PackageSource] = []
    for raw in lock.get("package_sources", []) or []:
        if raw.get("source_kind", "nuget_winmd") != "nuget_winmd":
            continue
        source = PackageSource(
            source_id=str(raw["id"]),
            package=str(raw["package"]),
            version=str(raw["version"]),
            winmd_path=str(raw["winmd_path"]),
            confidence=float(raw.get("confidence", 0.95)),
            source_url=str(raw.get("source_url", "")),
            source_kind=str(raw.get("source_kind", "nuget_winmd")),
            enabled=bool(raw.get("enabled", True)),
            nupkg_sha256=raw.get("nupkg_sha256"),
        )
        if source.enabled:
            sources.append(source)
    return sources


def _download(url: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(output.suffix + ".tmp")
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            with tmp.open("wb") as handle:
                shutil.copyfileobj(response, handle)
        tmp.replace(output)
    except urllib.error.URLError as exc:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"failed to download {url}: {exc}") from exc


def _safe_extract_member(
    zf: zipfile.ZipFile, member: zipfile.ZipInfo, destination: Path
) -> None:
    target = destination / member.filename
    target_parent = target.parent.resolve()
    destination_resolved = destination.resolve()
    if destination_resolved not in [target_parent, *target_parent.parents]:
        raise ValueError(f"refusing unsafe zip path: {member.filename}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with zf.open(member) as src:
        with tempfile.NamedTemporaryFile(
            "wb", dir=target.parent, delete=False
        ) as tmp_file:
            shutil.copyfileobj(src, tmp_file)
            tmp_path = Path(tmp_file.name)
    tmp_path.replace(target)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"expected object JSON in {path}")
    return data


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(data, indent=2, sort_keys=True)
    path.write_text(rendered + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
