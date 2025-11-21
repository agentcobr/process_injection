#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <unordered_map>

struct ProcessInfo {
    DWORD pid = 0;
    std::string name;
    std::string state;
    double cpu_usage = 0.0;
    SIZE_T memory_usage = 0;
    DWORD thread_count = 0;
    DWORD parent_pid = 0;

    ProcessInfo() : pid(0), cpu_usage(0.0), memory_usage(0), thread_count(0), parent_pid(0) {}
};
class ProcessScanner {
private:
    std::unordered_map<DWORD, unsigned long long> last_process_times;
    std::unordered_map<DWORD, unsigned long long> last_system_times;
    std::unordered_map<DWORD, unsigned long long> last_update_times;
    bool first_scan = true;

public:
    std::vector<ProcessInfo> ScanProcesses() {
        std::vector<ProcessInfo> processes;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return processes;
        }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &pe)) {
            do {
                ProcessInfo info;
                info.pid = pe.th32ProcessID;
                info.name = WCharToString(pe.szExeFile);
                info.thread_count = pe.cntThreads;
                info.parent_pid = pe.th32ParentProcessID;

                CalculateMemoryUsage(info);

                CalculateCpuUsage(info);

                processes.push_back(info);

            } while (Process32NextW(snapshot, &pe));
        }

        CloseHandle(snapshot);
        first_scan = false;
        return processes;
    }

private:
    std::string WCharToString(const WCHAR* wstr) {
        if (wstr == nullptr) return "";

        int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        if (size == 0) return "";

        std::string result(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size, nullptr, nullptr);

        if (!result.empty() && result.back() == '\0') {
            result.pop_back();
        }

        return result;
    }

    void CalculateMemoryUsage(ProcessInfo& info) {
        info.memory_usage = 0;

        if (info.pid == 0 || info.pid == 4 || info.pid == 8) {
            return;
        }

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, info.pid);
        if (hProcess) {
            PROCESS_MEMORY_COUNTERS pmc;
            pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS); 

            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                info.memory_usage = pmc.WorkingSetSize;
            }
            CloseHandle(hProcess);
        }
    }

    void CalculateCpuUsage(ProcessInfo& info) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, info.pid);
        if (!hProcess) {
            info.cpu_usage = 0.0;
            return;
        }

        FILETIME ftCreate, ftExit, ftKernel, ftUser;
        FILETIME ftIdle, ftKernelTotal, ftUserTotal;
        GetSystemTimeAsFileTime(&ftIdle);

        if (GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
            unsigned long long current_system_time = ConvertFileTimeToULONG64(ftIdle);
            unsigned long long kernel_time = ConvertFileTimeToULONG64(ftKernel);
            unsigned long long user_time = ConvertFileTimeToULONG64(ftUser);
            unsigned long long total_process_time = kernel_time + user_time;

            if (!first_scan &&
                last_process_times.find(info.pid) != last_process_times.end() &&
                last_system_times.find(info.pid) != last_system_times.end()) {

                unsigned long long system_time_diff = current_system_time - last_system_times[info.pid];
                unsigned long long process_time_diff = total_process_time - last_process_times[info.pid];

                if (system_time_diff > 0) {
                    info.cpu_usage = (process_time_diff * 100.0) / system_time_diff;
                    if (info.cpu_usage > 100.0) info.cpu_usage = 100.0;
                    if (info.cpu_usage < 0.0) info.cpu_usage = 0.0;
                }
                else {
                    info.cpu_usage = 0.0;
                }
            }
            else {
                info.cpu_usage = 0.0;
            }

            last_process_times[info.pid] = total_process_time;
            last_system_times[info.pid] = current_system_time;

        }
        else {
            info.cpu_usage = 0.0;
        }

        CloseHandle(hProcess);
    }

    unsigned long long ConvertFileTimeToULONG64(const FILETIME& ft) {
        return (static_cast<unsigned long long>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    }
};