# Linux System Calls

This document provides an overview of the Linux system call (syscall) interface, how it works, and where to find relevant information.

## Key Characteristics

The Linux syscall interface is designed to be **stable and reliable**. Unlike other operating systems, the syscall numbers and their corresponding functions are a public Application Binary Interface (ABI) that is rarely changed. This stability is a core design principle, ensuring that compiled applications continue to work across different kernel versions.

- **Direct Invocation:** While possible, syscalls are not typically invoked directly by application developers. Instead, they are wrapped by functions in standard libraries like `glibc`. For example, when a programmer calls the `open()` function, the C library handles the low-level details of placing the syscall number and arguments into the correct registers and triggering the kernel trap.
- **Architecture Specific:** Syscall numbers, calling conventions, and the exact mechanism for entering the kernel (`syscall`, `sysenter`, `int 0x80`) are specific to the hardware architecture (e.g., x86_64, aarch64).

## Finding Syscall Information

The "database" of syscalls is distributed across kernel source code and documentation.

### 1. Manual Pages (man pages)

This is the most direct and authoritative source of documentation for a developer.

- **`man syscalls`**: Provides a comprehensive list of all system calls available in the kernel.
- **`man 2 <syscall_name>`**: Provides the detailed manual page for a specific syscall (e.g., `man 2 open`). This includes:
    - The C function prototype.
    - A detailed description of its purpose.
    - An explanation of each argument.
    - Information on the return value and possible error codes (`errno`).

### 2. Online Reference Tables

For a quick, searchable overview, several community-maintained websites provide excellent syscall tables. These are often the most convenient way to look up a syscall number or find its arguments.

- **[Filippo Valsorda's Linux Syscall Table (x86_64)](https://filippo.io/linux-syscall-table/)**: An interactive and searchable table for the x86_64 architecture. It includes the syscall number, name, register mapping for arguments, and links to the kernel source code.

### 3. The Kernel Source Code (The Ultimate Ground Truth)

The kernel source code is the definitive reference for how syscalls are implemented.

- **Syscall Table Files**: These files map syscall numbers to their function names. For the x86_64 architecture, the primary file is located at:
  - `arch/x86/entry/syscalls/syscall_64.tbl`

- **Syscall Definitions**: The actual implementation of a syscall is defined in the kernel code using a family of macros. This makes it easy to find them.
  - `SYSCALL_DEFINE1(name, ...)`
  - `SYSCALL_DEFINE2(name, ...)`
  - `...`
  - `SYSCALL_DEFINE6(name, ...)`

  The number corresponds to the number of arguments the syscall takes. For example, you can find the implementation of the `read` syscall by searching for `SYSCALL_DEFINE3(read, ...)` in the kernel source, primarily within the `fs/` and `kernel/` directories.

- **Data Structures**: The definitions for structures and types used as arguments in syscalls are found in the kernel header files, primarily under `include/linux/` and `include/uapi/linux/`.
