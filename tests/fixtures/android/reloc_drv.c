/* Minimal AArch64 ET_REL fixture for executable-text relocation admission.
   The result adjustment prevents the compiler from turning the helper call
   into a tail branch, so the object retains R_AARCH64_CALL26 in the handler. */
typedef unsigned long ulong;
struct file;

extern long external_copy_from_user(ulong user_address);
extern unsigned char external_byte;
extern unsigned int external_u32;
extern ulong external_u64;
extern char external_buffer[];

__attribute__((noinline)) static long local_adjust(ulong value) {
    return (long)(value ^ 0x5aU);
}

long reloc_ioctl(struct file *file, unsigned int cmd, ulong arg) {
    (void)file;
    if (cmd != 0x4004b702U)
        return -22;
    return external_copy_from_user(arg + (ulong)(external_buffer + 37))
        + external_byte + external_u32 + external_u64 + local_adjust(arg);
}
