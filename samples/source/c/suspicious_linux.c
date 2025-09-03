// Suspicious Linux sample: references ptrace, mprotect, and execve
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {
    // Call ptrace to trigger import
    long res = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    (void)res;

    // Change memory protection (likely maps to mprotect import)
    void *addr = (void *)((unsigned long)main & ~0xFFFUL);
    mprotect(addr, 4096, PROT_READ | PROT_EXEC);

    // Reference execve to ensure symbol import
    char *args[] = { "/bin/true", NULL };
    execve("/bin/true", args, NULL);

    // Fallback
    puts("suspicious_linux executed");
    return 0;
}

