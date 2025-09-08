# Windows System Calls

This document provides an overview of the Windows system call (syscall) interface. It differs significantly from its Linux counterpart in its philosophy and usage.

## Key Characteristics: An Unstable, Undocumented Interface

The most critical concept to understand is that the direct syscall interface in Windows is **not a stable, documented, or public API**.

- **No Guaranteed Stability**: Microsoft does not guarantee that syscall numbers (known as System Service Numbers or SSNs) will remain the same between different Windows versions, service packs, or even minor security updates. This is an intentional design choice.
- **The Public API is WinAPI**: The stable, documented way to interact with the Windows kernel is through the high-level Windows API (`kernel32.dll`, `user32.dll`, etc.). These libraries provide the official, supported programming interface for applications.
- **`ntdll.dll` as the Gateway**: The WinAPI functions often call functions within `ntdll.dll`. This library, often called the "Native API," contains functions (e.g., `NtCreateFile`, `NtQuerySystemInformation`) that are the final user-mode layer before transitioning to the kernel. While more low-level, the Native API is still largely undocumented and can change. The `ntdll.dll` functions are responsible for placing the correct syscall number into the `eax` register and executing the `syscall` or `sysenter` instruction.

This design allows Microsoft to add, remove, or change the underlying kernel functions without breaking existing applications, as long as those applications use the stable, high-level WinAPI.

## Why and How Syscalls are Used Directly

Despite the instability, direct syscalls are frequently used in specific domains, primarily for **security and anti-security purposes**.

- **Evasion of Security Products**: Endpoint Detection and Response (EDR) and antivirus software often monitor for malicious activity by "hooking" functions in `kernel32.dll` and `ntdll.dll`. By bypassing these libraries and invoking a syscall directly, malware can evade detection.
- **Research and Debugging**: Security researchers and reverse engineers use syscalls to understand the inner workings of the Windows kernel and to analyze software behavior at the lowest level.

### Dynamic Syscall Resolution

Because syscall numbers are not stable, any program that uses them directly **must resolve the number at runtime**. Hardcoding a syscall number will cause the application to fail on different Windows versions.

The standard process for dynamic resolution is:
1.  Get the base address of the loaded `ntdll.dll` module in memory.
2.  Parse the module's Export Address Table (EAT) to find the memory address of the target Native API function (e.g., `NtCreateFile`).
3.  Read the first few bytes of the function's machine code. This code "stub" contains the instruction that moves the syscall number (SSN) into the `eax` register.
4.  Extract the SSN from that instruction.
5.  Use the extracted SSN to perform the direct syscall, typically with a small assembly block.

Advanced techniques like "Hell's Gate" and "Halo's Gate" refine this process to be even more evasive, avoiding the use of potentially hooked API calls to perform the resolution itself.

## Finding Syscall Information

Since there is no official documentation, this information is curated by the security and reverse engineering community.

- **[j00ru's Syscall Tables](https://j00ru.vexillium.org/syscalls/nt/64/)**: This is the most comprehensive and widely-respected public database of syscalls for nearly every version of Windows, covering both x86 and x64 architectures.
- **[HFIREF0X's Syscall Tables on GitHub](https://github.com/HFIREF0X/SyscallTables)**: Another excellent, community-maintained collection of syscall tables for various Windows builds.
- **Process Hacker / System Informer Source Code**: The source code for this popular system analysis tool is a valuable reference for the undocumented structures and function prototypes used by the Native API.
- **Windows Driver Kit (WDK)**: While not a syscall reference, the WDK documentation is the most official source for some of the kernel-level data structures that are passed as arguments to syscalls.
