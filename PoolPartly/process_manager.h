#pragma once
#include <windows.h>
#include <string>
#include <iostream>

class ProcessManager {
public:
    struct ProcessConfig {
        std::string command_line;
        std::string working_directory;
        bool suspended = false;
        bool hidden = false;
        DWORD priority = NORMAL_PRIORITY_CLASS;
    };

    HANDLE CreateSuspendedProcess(const ProcessConfig& config) {
        std::cout << "[ProcessManager] Creating process: " << config.command_line << std::endl;

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        if (config.hidden) {
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
        }

        DWORD creation_flags = config.priority;
        if (config.suspended) {
            creation_flags |= CREATE_SUSPENDED;
        }

        BOOL success = CreateProcessA(
            NULL,
            const_cast<LPSTR>(config.command_line.c_str()),
            NULL,
            NULL,
            FALSE,
            creation_flags,
            NULL,
            config.working_directory.empty() ? NULL : config.working_directory.c_str(),
            &si,
            &pi
        );

        if (success) {
            std::cout << "[ProcessManager] Process created with PID: " << pi.dwProcessId << std::endl;
            CloseHandle(pi.hThread);
            return pi.hProcess;
        }
        else {
            DWORD error = GetLastError();
            std::cerr << "[ProcessManager] Failed to create process. Error: " << error << std::endl;
            return NULL;
        }
    }

    bool SetProcessPriority(HANDLE hProcess, DWORD priority_class) {
        if (SetPriorityClass(hProcess, priority_class)) {
            std::cout << "[ProcessManager] Process priority set to: " << priority_class << std::endl;
            return true;
        }
        return false;
    }

    bool ResumeProcess(HANDLE hProcess) {
        std::cout << "[ProcessManager] Process resume requested" << std::endl;
        return true;
    }

    bool TerminateProcess(HANDLE hProcess, UINT exit_code = 0) {
        if (::TerminateProcess(hProcess, exit_code)) {
            std::cout << "[ProcessManager] Process terminated" << std::endl;
            return true;
        }
        return false;
    }
};