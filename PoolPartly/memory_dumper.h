#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <iostream>
#include <vector>
#include <sstream>

#pragma comment(lib, "dbghelp.lib")

class MemoryDumper {
public:
    bool CreateMiniDump(DWORD pid, const std::string& output_path) {
        std::cout << "Attempting to create dump for PID " << pid << " -> " << output_path << std::endl;

        // Відкриваємо процес
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cout << "? Failed to open process. Error: " << error << std::endl;
            return false;
        }

        // Створюємо файл
        HANDLE hFile = CreateFileA(output_path.c_str(), GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            std::cout << "? Failed to create file. Error: " << error << std::endl;
            CloseHandle(hProcess);
            return false;
        }

        // Налаштовуємо параметри дампу
        MINIDUMP_EXCEPTION_INFORMATION exceptionInfo;
        exceptionInfo.ThreadId = GetCurrentThreadId();
        exceptionInfo.ExceptionPointers = nullptr;
        exceptionInfo.ClientPointers = FALSE;

        // Створюємо дамп
        std::cout << "Creating mini dump..." << std::endl;
        BOOL success = MiniDumpWriteDump(
            hProcess,
            pid,
            hFile,
            static_cast<MINIDUMP_TYPE>(MiniDumpWithFullMemory |
                MiniDumpWithHandleData |
                MiniDumpWithThreadInfo |
                MiniDumpWithProcessThreadData),
            &exceptionInfo,
            nullptr,
            nullptr
        );

        if (success) {
            std::cout << "? Mini dump created successfully" << std::endl;

            // Отримуємо розмір файлу
            DWORD fileSize = GetFileSize(hFile, NULL);
            std::cout << "? Dump file size: " << (fileSize / 1024) << " KB" << std::endl;

            // Додаємо інформацію про процес у дамп (через додатковий файл)
            AddProcessInfoToDump(hProcess, output_path + ".txt");
        }
        else {
            DWORD error = GetLastError();
            std::cout << "? Failed to create mini dump. Error: " << error << std::endl;
        }

        CloseHandle(hFile);
        CloseHandle(hProcess);

        return success;
    }

private:
    void AddProcessInfoToDump(HANDLE hProcess, const std::string& info_path) {
        std::ofstream info_file(info_path);
        if (info_file.is_open()) {
            info_file << "Process Dump Additional Information\n";
            info_file << "===================================\n";

            // Інформація про процес
            info_file << "Process ID: " << GetProcessId(hProcess) << "\n";

            // Час створення процесу
            FILETIME creationTime, exitTime, kernelTime, userTime;
            if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
                info_file << "Process Creation Time: " << FileTimeToString(creationTime) << "\n";
                info_file << "Kernel Time: " << FileTimeToString(kernelTime) << "\n";
                info_file << "User Time: " << FileTimeToString(userTime) << "\n";
            }

            // Інформація про пам'ять
            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                info_file << "\nMemory Information:\n";
                info_file << "  Working Set: " << (pmc.WorkingSetSize / 1024) << " KB\n";
                info_file << "  Peak Working Set: " << (pmc.PeakWorkingSetSize / 1024) << " KB\n";
                info_file << "  Page File Usage: " << (pmc.PagefileUsage / 1024) << " KB\n";
                info_file << "  Peak Page File Usage: " << (pmc.PeakPagefileUsage / 1024) << " KB\n";
            }

            info_file.close();
            std::cout << "? Process info saved to: " << info_path << std::endl;
        }
    }

    std::string FileTimeToString(const FILETIME& ft) {
        SYSTEMTIME st;
        FileTimeToSystemTime(&ft, &st);

        std::stringstream ss;
        ss << st.wYear << "-" << st.wMonth << "-" << st.wDay << " "
            << st.wHour << ":" << st.wMinute << ":" << st.wSecond;
        return ss.str();
    }
};