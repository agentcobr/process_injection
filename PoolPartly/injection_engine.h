#pragma once
#include <windows.h>
#include <string>
#include <iostream>
#include <vector>

class InjectionEngine {
public:
    bool InjectDLL(DWORD pid, const std::string& dll_path) {
        std::cout << "[Injection] Starting DLL injection for PID: " << pid << std::endl;

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cerr << "[Injection] Failed to open process. Error: " << error << std::endl;
            return false;
        }
        std::cout << "[Injection] Process opened successfully" << std::endl;

        LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, dll_path.size() + 1,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pRemoteMemory) {
            DWORD error = GetLastError();
            std::cerr << "[Injection] Failed to allocate memory. Error: " << error << std::endl;
            CloseHandle(hProcess);
            return false;
        }
        std::cout << "[Injection] Memory allocated at: " << pRemoteMemory << std::endl;

        SIZE_T bytes_written;
        BOOL success = WriteProcessMemory(hProcess, pRemoteMemory, dll_path.c_str(),
            dll_path.size() + 1, &bytes_written);
        if (!success) {
            DWORD error = GetLastError();
            std::cerr << "[Injection] Failed to write memory. Error: " << error << std::endl;
            VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        std::cout << "[Injection] DLL path written to target process" << std::endl;

        // Отримуємо адресу LoadLibraryA
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) {
            std::cerr << "[Injection] Failed to get kernel32 handle" << std::endl;
            VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
        if (!pLoadLibrary) {
            std::cerr << "[Injection] Failed to get LoadLibraryA address" << std::endl;
            VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        std::cout << "[Injection] LoadLibraryA address: " << pLoadLibrary << std::endl;

        // Створюємо віддалений потік
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)pLoadLibrary,
            pRemoteMemory, 0, NULL);
        if (!hThread) {
            DWORD error = GetLastError();
            std::cerr << "[Injection] Failed to create remote thread. Error: " << error << std::endl;
            VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        std::cout << "[Injection] Remote thread created successfully" << std::endl;

        // Чекаємо завершення потоку
        WaitForSingleObject(hThread, 5000); // 5 секунд timeout

        // Перевіряємо результат
        DWORD exit_code = 0;
        if (GetExitCodeThread(hThread, &exit_code)) {
            if (exit_code == STILL_ACTIVE) {
                std::cout << "[Injection] Thread still active after 5 seconds" << std::endl;
            }
            else {
                std::cout << "[Injection] Thread completed with exit code: " << exit_code << std::endl;
            }
        }

        // Очищуємо ресурси
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);

        std::cout << "[Injection] Injection completed" << std::endl;
        return true;
    }

    bool InjectShellcode(DWORD pid, const std::vector<BYTE>& shellcode) {
        std::cout << "[Injection] Starting shellcode injection for PID: " << pid << std::endl;

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            return false;
        }

        LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, shellcode.size(),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pRemoteMemory) {
            CloseHandle(hProcess);
            return false;
        }

        SIZE_T bytes_written;
        BOOL success = WriteProcessMemory(hProcess, pRemoteMemory, shellcode.data(),
            shellcode.size(), &bytes_written);
        if (!success || bytes_written != shellcode.size()) {
            VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)pRemoteMemory,
            NULL, 0, NULL);
        if (!hThread) {
            VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        CloseHandle(hThread);
        CloseHandle(hProcess);

        std::cout << "[Injection] Shellcode injection completed" << std::endl;
        return true;
    }
};