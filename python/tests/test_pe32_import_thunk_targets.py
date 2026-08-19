"""A 32-bit PE import thunk names an absolute IAT slot, not a RIP-relative one.

`FF /4 disp32` is `jmp [rip+disp32]` on x86-64 and `jmp [disp32]` -- a plain
absolute address -- in 32-bit mode, where RIP-relative addressing does not exist
at all. `classify_pe_thunk_head` took no architecture and applied the 64-bit
reading to both, and `classify_function_shapes` admits `BArch::X86` explicitly,
so every PE32 import thunk was recorded with `entry + 6 + disp` in
`Function.thunk_target`.

On the checked-in mingw32 sample that put all 34 of them outside the image: the
`msvcrt!wcslen` thunk at `0x004071e0` resolved to `0x008133e2` where its operand
names `0x0040c1fc`. This test reads the import table out of the file itself and
requires every recorded import-thunk target to be a real slot in it.
"""

from __future__ import annotations

import struct
from pathlib import Path

import glaurung as g
import pytest

PE32_SAMPLE = Path(
    "samples/binaries/platforms/windows/i386/export/windows/i686/O2/"
    "hello-c-mingw32-O2.exe"
)


def _import_slot_vas(data: bytes) -> tuple[int, dict[int, str]]:
    """Every `FirstThunk` slot VA in the image, mapped to `dll!symbol`.

    Parsed straight from the on-disk headers so the expectation is the file's own
    import table and not another of our own parsers.
    """
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew : e_lfanew + 4] == b"PE\0\0"
    coff = e_lfanew + 4
    section_count = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    magic = struct.unpack_from("<H", data, optional)[0]
    assert magic == 0x10B, f"expected a PE32 optional header, got {magic:#x}"
    image_base = struct.unpack_from("<I", data, optional + 28)[0]
    import_rva = struct.unpack_from("<I", data, optional + 96 + 8)[0]

    sections = []
    section_start = optional + optional_size
    for index in range(section_count):
        base = section_start + 40 * index
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, base + 8
        )
        sections.append((virtual_address, max(virtual_size, raw_size), raw_pointer))

    def offset_of(rva: int) -> int:
        for virtual_address, size, raw_pointer in sections:
            if virtual_address <= rva < virtual_address + size:
                return raw_pointer + (rva - virtual_address)
        raise AssertionError(f"rva {rva:#x} is in no section")

    slots: dict[int, str] = {}
    descriptor = offset_of(import_rva)
    while True:
        fields = struct.unpack_from("<IIIII", data, descriptor)
        if fields == (0, 0, 0, 0, 0):
            break
        _olt, _stamp, _chain, name_rva, first_thunk = fields
        dll = data[offset_of(name_rva) :].split(b"\0")[0].decode("latin1")
        rva = first_thunk
        while True:
            entry = struct.unpack_from("<I", data, offset_of(rva))[0]
            if entry == 0:
                break
            if entry & 0x8000_0000:
                symbol = f"ord#{entry & 0xFFFF}"
            else:
                symbol = data[offset_of(entry) + 2 :].split(b"\0")[0].decode("latin1")
            slots[image_base + rva] = f"{dll}!{symbol}"
            rva += 4
        descriptor += 20
    return image_base, slots


@pytest.mark.skipif(not PE32_SAMPLE.exists(), reason="PE32 sample missing")
def test_pe32_import_thunk_targets_land_on_real_iat_slots() -> None:
    data = PE32_SAMPLE.read_bytes()
    image_base, slots = _import_slot_vas(data)
    assert len(slots) > 20, (
        f"sample has too few imports to be a real test: {len(slots)}"
    )

    functions, _ = g.analysis.analyze_functions_path(
        str(PE32_SAMPLE), max_functions=2000
    )
    thunks = [
        function
        for function in functions
        if str(function.kind).lower().endswith("thunk")
        and function.thunk_target is not None
    ]
    assert thunks, "the sample's import thunks were not classified at all"

    import_thunks = []
    for function in thunks:
        entry = int(function.entry_point.value)
        # `FF 25 imm32` -- the shape this regression is about. A `jmp rel32` tail
        # thunk is mode-independent and is not what is under test here.
        offset = _file_offset(data, entry - image_base)
        if offset is None or data[offset : offset + 2] != b"\xff\x25":
            continue
        import_thunks.append((function, struct.unpack_from("<I", data, offset + 2)[0]))

    assert len(import_thunks) >= 20, (
        f"expected the mingw32 sample's IAT thunk table, found {len(import_thunks)}"
    )
    wrong = [
        (int(function.entry_point.value), int(function.thunk_target.value), operand)
        for function, operand in import_thunks
        if int(function.thunk_target.value) != operand
    ]
    assert not wrong, (
        "a 32-bit `jmp [imm32]` thunk target is the absolute operand, not "
        f"`entry + 6 + operand`: {[(hex(a), hex(b), hex(c)) for a, b, c in wrong[:4]]}"
    )
    # Every target must at least be a VA inside the image. This is the property
    # the RIP-relative reading broke outright: `0x004071e0 + 6 + 0x0040c1fc` is
    # `0x008133e2`, well past the end of a 0x400000-based image.
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    size_of_image = struct.unpack_from("<I", data, e_lfanew + 4 + 20 + 56)[0]
    outside = [
        hex(int(function.thunk_target.value))
        for function, _ in import_thunks
        if not image_base
        <= int(function.thunk_target.value)
        < image_base + size_of_image
    ]
    assert not outside, f"thunk targets outside the image: {outside[:4]}"

    # And the great majority must be import slots by name. One `FF 25` wrapper in
    # this sample jumps through `0x00408058`, a `.data` pointer that is not in the
    # import table at all, so this is a floor and not an equality.
    named = [
        function
        for function, _ in import_thunks
        if int(function.thunk_target.value) in slots
    ]
    assert len(named) >= 30, (
        f"only {len(named)} of {len(import_thunks)} thunk targets name an import"
    )


def _file_offset(data: bytes, rva: int) -> int | None:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    section_count = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    section_start = coff + 20 + optional_size
    for index in range(section_count):
        base = section_start + 40 * index
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, base + 8
        )
        size = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + size:
            return raw_pointer + (rva - virtual_address)
    return None
