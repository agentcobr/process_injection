#pragma once
#include <windows.h>
#include <string>
#include <vector>

class EDR_EVASION {
public:
    HANDLE NtOpenProcess(DWORD pid) {
        return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }

    LPVOID NtAllocateVirtualMemory(HANDLE hProcess, SIZE_T size) {
        return VirtualAllocEx(hProcess, NULL, size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
    }

    HANDLE NtCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE start_addr,
        LPVOID param) {
        return CreateRemoteThread(hProcess, NULL, 0, start_addr, param, 0, NULL);
    }

    BOOL NtFreeVirtualMemory(HANDLE hProcess, LPVOID address) {
        return VirtualFreeEx(hProcess, address, 0, MEM_RELEASE);
    }
};