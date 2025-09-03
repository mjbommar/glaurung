// Suspicious Windows sample: references VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
#ifdef _WIN32
#include <windows.h>
#include <stdio.h>

int main(void) {
    HANDLE self = GetCurrentProcess();
    LPVOID mem = VirtualAllocEx(self, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SIZE_T written = 0;
    char data[] = "test";
    WriteProcessMemory(self, mem, data, sizeof(data), &written);
    HANDLE th = CreateRemoteThread(self, NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (th) CloseHandle(th);
    printf("suspicious_win executed\n");
    return 0;
}
#else
int main(void) { return 0; }
#endif

