"""Curated Windows kernel struct definitions for the rewrite_function_idiomatic
annotated mode.

These are PE/WDM/WDF struct shapes the LLM commonly encounters when
annotating Windows kernel drivers but cannot recover from the raw
decompile alone. Passing them in as `args.structs` lets Tool #14
resolve raw offsets like `*(u64 *)&[arg1 + 0x18]` to symbolic
`irp->AssociatedIrp.SystemBuffer`.

Offsets reflect x64 WDK 10. Where a struct has variants across
SKUs we use the modern release-build layout (these are the only
ones our v7 + patchtuesday-site corpora ship).
"""

from __future__ import annotations

from typing import List

from glaurung.llm.tools.rewrite_function_idiomatic import StructDef


# Indexed by role-classifier label. Each entry is the list of struct
# defs to inject. Keep these MINIMAL -- only the structs the LLM
# routinely guesses wrong on raw offsets. A bigger pack costs tokens
# without buying clarity.
_PACKS: dict[str, List[StructDef]] = {
    "network_io": [
        # IRP -- the central kernel-mode I/O request packet. Offsets
        # per ntddk.h (10.0.26100 SDK).
        StructDef(
            name="IRP",
            c_definition=(
                "typedef struct _IRP {\n"
                "    /* 0x000 */ CSHORT Type;\n"
                "    /* 0x002 */ USHORT Size;\n"
                "    /* 0x008 */ PMDL MdlAddress;\n"
                "    /* 0x010 */ ULONG Flags;\n"
                "    /* 0x018 */ union {\n"
                "                    struct _IRP *MasterIrp;\n"
                "                    LONG IrpCount;\n"
                "                    PVOID SystemBuffer;\n"
                "                } AssociatedIrp;\n"
                "    /* 0x020 */ LIST_ENTRY ThreadListEntry;\n"
                "    /* 0x030 */ IO_STATUS_BLOCK IoStatus;\n"
                "    /* 0x040 */ KPROCESSOR_MODE RequestorMode;\n"
                "    /* 0x041 */ BOOLEAN PendingReturned;\n"
                "    /* 0x042 */ CHAR StackCount;\n"
                "    /* 0x043 */ CHAR CurrentLocation;\n"
                "    /* 0x044 */ BOOLEAN Cancel;\n"
                "    /* 0x045 */ KIRQL CancelIrql;\n"
                "    /* 0x046 */ CCHAR ApcEnvironment;\n"
                "    /* 0x047 */ UCHAR AllocationFlags;\n"
                "    /* 0x048 */ PIO_STATUS_BLOCK UserIosb;\n"
                "    /* 0x050 */ PKEVENT UserEvent;\n"
                "    /* 0x058 */ /* Overlay union */\n"
                "    /* 0x078 */ PDRIVER_CANCEL CancelRoutine;\n"
                "    /* 0x080 */ PVOID UserBuffer;\n"
                "    /* 0x088 */ /* Tail union -- CurrentStackLocation lives in Tail.Overlay */\n"
                "    /* 0x0B8 */ PIO_STACK_LOCATION CurrentStackLocation;  /* Tail.Overlay.CurrentStackLocation */\n"
                "} IRP, *PIRP;"
            ),
        ),
        StructDef(
            name="IO_STACK_LOCATION",
            c_definition=(
                "typedef struct _IO_STACK_LOCATION {\n"
                "    /* 0x000 */ UCHAR MajorFunction;\n"
                "    /* 0x001 */ UCHAR MinorFunction;\n"
                "    /* 0x002 */ UCHAR Flags;\n"
                "    /* 0x003 */ UCHAR Control;\n"
                "    /* 0x008 */ union {\n"
                "                  /* For IRP_MJ_DEVICE_CONTROL: */\n"
                "                  struct {\n"
                "    /* 0x008 */     ULONG OutputBufferLength;\n"
                "    /* 0x010 */     ULONG InputBufferLength;\n"
                "    /* 0x018 */     ULONG IoControlCode;\n"
                "    /* 0x020 */     PVOID Type3InputBuffer;\n"
                "                  } DeviceIoControl;\n"
                "                  /* For IRP_MJ_READ / IRP_MJ_WRITE: */\n"
                "                  struct {\n"
                "    /* 0x008 */     ULONG Length;\n"
                "    /* 0x010 */     ULONG Key;\n"
                "    /* 0x018 */     LARGE_INTEGER ByteOffset;\n"
                "                  } Read;\n"
                "                } Parameters;\n"
                "    /* 0x028 */ PDEVICE_OBJECT DeviceObject;\n"
                "    /* 0x030 */ PFILE_OBJECT FileObject;\n"
                "    /* 0x038 */ PIO_COMPLETION_ROUTINE CompletionRoutine;\n"
                "    /* 0x040 */ PVOID Context;\n"
                "} IO_STACK_LOCATION, *PIO_STACK_LOCATION;"
            ),
        ),
        StructDef(
            name="IO_STATUS_BLOCK",
            c_definition=(
                "typedef struct _IO_STATUS_BLOCK {\n"
                "    /* 0x000 */ union {\n"
                "                    NTSTATUS Status;\n"
                "                    PVOID    Pointer;\n"
                "                };\n"
                "    /* 0x008 */ ULONG_PTR Information;\n"
                "} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;"
            ),
        ),
        StructDef(
            name="DEVICE_OBJECT",
            c_definition=(
                "typedef struct _DEVICE_OBJECT {\n"
                "    /* partial -- only the fields driver code commonly touches */\n"
                "    /* 0x000 */ CSHORT Type;\n"
                "    /* 0x002 */ USHORT Size;\n"
                "    /* 0x004 */ LONG ReferenceCount;\n"
                "    /* 0x008 */ struct _DRIVER_OBJECT *DriverObject;\n"
                "    /* 0x010 */ struct _DEVICE_OBJECT *NextDevice;\n"
                "    /* 0x028 */ ULONG Flags;\n"
                "    /* 0x02C */ ULONG Characteristics;\n"
                "    /* 0x040 */ PVOID DeviceExtension;\n"
                "} DEVICE_OBJECT, *PDEVICE_OBJECT;"
            ),
        ),
        StructDef(
            name="FILE_OBJECT",
            c_definition=(
                "typedef struct _FILE_OBJECT {\n"
                "    /* 0x000 */ CSHORT Type;\n"
                "    /* 0x002 */ CSHORT Size;\n"
                "    /* 0x008 */ PDEVICE_OBJECT DeviceObject;\n"
                "    /* 0x028 */ PVOID FsContext;\n"
                "    /* 0x030 */ PVOID FsContext2;\n"
                "} FILE_OBJECT, *PFILE_OBJECT;"
            ),
        ),
    ],
}


def kernel_struct_pack_for_role(role: str | None) -> List[StructDef]:
    """Return the kernel struct pack to inject for a given role.

    Empty list when the role is not a kernel role or unrecognized -- we
    do NOT inject these structs blindly because they bloat the prompt
    and confuse Tool #14 on userland binaries.
    """
    if not role:
        return []
    # Anything whose role looks kernel-shaped: 'network_io',
    # 'irp_dispatch', 'wdf_handler', 'minifilter', etc. Accept fuzzy
    # matches because the role labels are LLM-emitted strings.
    role_lower = role.lower()
    kernel_markers = (
        "irp", "wdm", "wdf", "minifilter", "kernel", "driver",
        "network_io", "fs_op", "ioctl",
    )
    if any(m in role_lower for m in kernel_markers):
        return list(_PACKS["network_io"])
    return []
