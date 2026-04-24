"""Tool: flag imports that hint at common malware-ish capabilities.

A lightweight first-pass classifier so an agent investigating an
unknown binary can ask "what does this thing plausibly do?" without
first reading every imported function. Buckets follow the MITRE ATT&CK
sub-technique groupings you'd reach for during triage:

    network   — sockets, HTTP, DNS, resolve, sendto/recv, Winsock
    filesystem— create/open/read/write/delete/rename, directory walk
    process   — CreateProcess, fork, exec*, ptrace, spawn, debug
    registry  — Reg*, NtOpenKey (Windows persistence / config)
    crypto    — CryptAcquire, EVP_, AES_, BCrypt, libsodium
    injection — VirtualAlloc(Ex), WriteProcessMemory, mmap+mprotect, dlopen
    antidbg   — IsDebuggerPresent, CheckRemoteDebuggerPresent, ptrace,
                NtQueryInformationProcess, GetTickCount
    persist   — service install, scheduled task, autorun, systemd helpers
    util      — low-value matches (memcpy, strlen, etc.) — returned
                only when ``include_util=True``.

This is pattern matching, not detection — present the output as
*evidence for a human to weigh*, not a verdict.
"""

from __future__ import annotations

import re
from typing import Dict, List

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.models import Node, NodeKind, Edge
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


# Bucket definitions. Keys are case-insensitive substring hits; the
# buckets deliberately share some symbols (ptrace is both anti-debug and
# process-control) — multiple tags per import is a feature, not a bug.
_BUCKETS: Dict[str, List[str]] = {
    "network": [
        "socket", "connect", "bind", "listen", "accept", "sendto", "recvfrom",
        "send", "recv", "getaddrinfo", "gethostbyname", "res_init", "res_query",
        "inet_addr", "inet_pton", "curl_", "WSAStartup", "WSASocket", "InternetOpen",
        "HttpOpenRequest", "HttpSendRequest", "WinHttpOpen", "DnsQuery_", "getsockopt",
    ],
    "filesystem": [
        "fopen", "open", "openat", "read", "pread", "write", "pwrite", "close",
        "unlink", "rename", "creat", "mkstemp", "mkdtemp", "chmod", "fchmod",
        "stat", "lstat", "fstat", "readdir", "opendir", "closedir",
        "CreateFile", "ReadFile", "WriteFile", "DeleteFile", "MoveFile",
        "SetFileAttributes", "FindFirstFile", "FindNextFile",
    ],
    "process": [
        "fork", "vfork", "clone", "execv", "execvp", "execve", "execl", "system",
        "popen", "posix_spawn", "CreateProcess", "CreateThread", "CreateRemoteThread",
        "NtCreateUserProcess", "NtCreateThreadEx", "WinExec", "ShellExecute",
    ],
    "registry": [
        "RegOpenKey", "RegSetValue", "RegQueryValue", "RegCreateKey", "RegDeleteKey",
        "NtOpenKey", "NtQueryValueKey", "NtSetValueKey",
    ],
    "crypto": [
        "EVP_", "AES_", "DES_", "SHA", "MD5", "HMAC", "CryptAcquireContext",
        "CryptEncrypt", "CryptDecrypt", "BCrypt", "NCrypt", "libsodium",
        "crypto_", "RSA_", "RC4",
    ],
    "injection": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "NtMapViewOfSection",
        "NtUnmapViewOfSection", "SetWindowsHookEx", "QueueUserAPC",
        "mmap", "mprotect", "dlopen", "dlsym", "LoadLibrary", "GetProcAddress",
    ],
    "antidbg": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "GetTickCount", "QueryPerformanceCounter", "OutputDebugString",
        "ptrace",
    ],
    "persist": [
        "SetServiceStatus", "CreateService", "OpenSCManager", "schtasks",
        "RegisterServiceCtrlHandler", "systemd_", "sd_notify",
    ],
    "util": [
        "memcpy", "memmove", "memset", "strlen", "strcmp", "strncmp", "strcpy",
        "strncpy", "strcat", "printf", "fprintf", "sprintf", "snprintf", "puts",
        "malloc", "free", "calloc", "realloc", "abort", "exit",
    ],
}


class SuspiciousImportsArgs(BaseModel):
    include_util: bool = Field(
        False,
        description="Include the low-value 'util' bucket (libc string/memory "
                    "helpers). Off by default since these are noise during "
                    "malware triage.",
    )
    max_per_bucket: int = Field(
        32, description="Cap matches per bucket to keep prompts compact"
    )
    add_to_kb: bool = Field(
        True, description="Record an evidence node with the matches"
    )


class SuspiciousImport(BaseModel):
    name: str
    buckets: List[str] = Field(
        ..., description="All buckets this import landed in (multi-label)."
    )


class SuspiciousImportsResult(BaseModel):
    by_bucket: Dict[str, List[str]]
    tagged: List[SuspiciousImport]
    total_imports: int
    evidence_node_id: str | None = None


class ListSuspiciousImportsTool(
    MemoryTool[SuspiciousImportsArgs, SuspiciousImportsResult]
):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="list_suspicious_imports",
                description="Bucket imported symbols by suspected capability "
                            "(network / filesystem / process / registry / "
                            "crypto / injection / antidbg / persist). "
                            "Use for a quick 'what can this binary do?' read.",
                tags=("triage", "imports"),
            ),
            SuspiciousImportsArgs,
            SuspiciousImportsResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: SuspiciousImportsArgs,
    ) -> SuspiciousImportsResult:
        try:
            summary = g.symbols.list_symbols_demangled(
                ctx.file_path,
                ctx.budgets.max_read_bytes,
                ctx.budgets.max_file_size,
            )
            imports = list(summary.import_names or [])
            # Demangled names cover C++ / Rust symbols — merge so we can match
            # both 'EVP_EncryptInit' (C) and 'openssl::evp::init' (demangled).
            for dn in summary.demangled_import_names or []:
                if dn not in imports:
                    imports.append(dn)
        except Exception:
            imports = []

        # Compile subword-boundary regexes once.
        #
        # Needles with any uppercase letter (Windows API CamelCase, e.g.
        # ``CreateFile``) match as *prefixes* so that ``CreateFileA`` /
        # ``CreateFileW`` / ``CreateFileExW`` all land in the bucket. All
        # other needles must sit on a non-alnum boundary on both sides —
        # that's what prevents ``clone`` from matching ``tm_clones`` while
        # still letting ``printf`` match ``__printf_chk``.
        _NON_ALNUM = r"(?:^|(?<=[^A-Za-z0-9]))"
        _END_SUBWORD = r"(?=[^A-Za-z0-9]|$)"
        compiled: Dict[str, List[re.Pattern[str]]] = {}
        for bucket, needles in _BUCKETS.items():
            pats: List[re.Pattern[str]] = []
            for n in needles:
                escaped = re.escape(n)
                if any(c.isupper() for c in n):
                    pats.append(re.compile(_NON_ALNUM + escaped))
                else:
                    pats.append(
                        re.compile(_NON_ALNUM + escaped + _END_SUBWORD)
                    )
            compiled[bucket] = pats

        by_bucket: Dict[str, List[str]] = {b: [] for b in _BUCKETS}
        tagged_map: Dict[str, List[str]] = {}
        for sym in imports:
            for bucket, patterns in compiled.items():
                if bucket == "util" and not args.include_util:
                    continue
                for pat in patterns:
                    if pat.search(sym):
                        if len(by_bucket[bucket]) < args.max_per_bucket:
                            by_bucket[bucket].append(sym)
                        tagged_map.setdefault(sym, []).append(bucket)
                        break  # one bucket hit per needle-list is enough

        # Drop empty buckets and the util bucket when not requested.
        by_bucket = {
            k: v for k, v in by_bucket.items() if v and (args.include_util or k != "util")
        }
        tagged = [
            SuspiciousImport(name=name, buckets=sorted(set(buckets)))
            for name, buckets in sorted(tagged_map.items())
        ]

        ev_id = None
        if args.add_to_kb and tagged:
            ev = kb.add_node(
                Node(
                    kind=NodeKind.evidence,
                    label="suspicious_imports",
                    props={
                        "count": len(tagged),
                        "buckets": {k: len(v) for k, v in by_bucket.items()},
                    },
                )
            )
            ev_id = ev.id
            file_node = next((n for n in kb.nodes() if n.kind == NodeKind.file), None)
            if file_node:
                kb.add_edge(Edge(src=file_node.id, dst=ev.id, kind="has_evidence"))

        return SuspiciousImportsResult(
            by_bucket=by_bucket,
            tagged=tagged,
            total_imports=len(imports),
            evidence_node_id=ev_id,
        )


def build_tool() -> MemoryTool[SuspiciousImportsArgs, SuspiciousImportsResult]:
    return ListSuspiciousImportsTool()
