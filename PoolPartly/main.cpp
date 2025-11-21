#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <iomanip>
#include <conio.h>
#include <algorithm>
#include <sstream>
#include <fstream>

#include "process_scanner.h"
#include "memory_dumper.h"
#include "injection_engine.h"
#include "process_manager.h"
#include "secure_logger.h"

class PoolParty {
private:
    SecureLogger logger;
    std::atomic<bool> running;
    ProcessScanner scanner;
    MemoryDumper dumper;
    InjectionEngine injector;
    ProcessManager process_manager;

public:
    PoolParty() : logger("pool_party.log"), running(false) {}

    SecureLogger& GetLogger() { return logger; }


    void StartMonitoring() {
        running = true;
        std::thread monitorThread(&PoolParty::MonitorProcesses, this);
        monitorThread.detach();
        logger.LogInfo("Monitoring started");
    }

    void StopMonitoring() {
        running = false;
        logger.LogInfo("Monitoring stopped");
    }

    bool CreateMemoryDump(DWORD pid, const std::string& filename) {
        logger.LogInfo("Creating memory dump for PID: " + std::to_string(pid));
        bool result = dumper.CreateMiniDump(pid, filename);
        if (result) {
            logger.LogInfo("Memory dump created successfully: " + filename);
        }
        else {
            logger.LogError("Failed to create memory dump for PID: " + std::to_string(pid));
        }
        return result;
    }

    bool InjectIntoProcess(DWORD pid, const std::string& dll_path) {
        logger.LogInfo("Attempting injection into PID: " + std::to_string(pid));
        bool result = injector.InjectDLL(pid, dll_path);
        if (result) {
            logger.LogInfo("Injection successful for PID: " + std::to_string(pid));
        }
        else {
            logger.LogError("Injection failed for PID: " + std::to_string(pid));
        }
        return result;
    }

    bool StartNewProcess(const std::string& command_line, bool suspended = false) {
        logger.LogInfo("Starting new process: " + command_line);

        ProcessManager::ProcessConfig config;
        config.command_line = command_line;
        config.suspended = suspended;
        config.hidden = false;

        HANDLE hProcess = process_manager.CreateSuspendedProcess(config);
        if (hProcess) {
            logger.LogInfo("Process started successfully");
            CloseHandle(hProcess);
            return true;
        }
        else {
            logger.LogError("Failed to start process: " + command_line);
            return false;
        }
    }

    std::vector<ProcessInfo> GetProcessList() {
        return scanner.ScanProcesses();
    }

private:
    void MonitorProcesses() {
        while (running) {
            auto processes = scanner.ScanProcesses();
            for (const auto& proc : processes) {
                if (proc.cpu_usage > 50.0) {
                    std::string warning = "High CPU usage detected: " + proc.name + " (" + std::to_string(proc.cpu_usage) + "%)";
                    logger.LogWarning(warning);
                }

                if (proc.memory_usage > 500 * 1024 * 1024) { // 500 MB
                    std::string warning = "High memory usage: " + proc.name + " (" +
                        std::to_string(proc.memory_usage / (1024 * 1024)) + " MB)";
                    logger.LogWarning(warning);
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
};

void ShowMenu() {
    std::cout << "\n=== Pool Party - Main Menu ===" << std::endl;
    std::cout << "1. Live Process Monitoring" << std::endl;
    std::cout << "2. Single Process Scan" << std::endl;
    std::cout << "3. Create Memory Dump" << std::endl;
    std::cout << "4. Inject DLL into Process" << std::endl;
    std::cout << "5. Start New Process" << std::endl;
    std::cout << "6. View Log File" << std::endl;
    std::cout << "7. Exit" << std::endl;
    std::cout << "Choice: ";
}

void LiveMonitoring(PoolParty& pool_party) {
    pool_party.StartMonitoring();

    std::cout << "\n=== Live Monitoring Started ===" << std::endl;
    std::cout << "Monitoring processes in real-time..." << std::endl;
    std::cout << "Warnings will be logged to pool_party.log" << std::endl;
    std::cout << "Press 'Q' to stop monitoring\n" << std::endl;

    while (true) {
        if (_kbhit()) {
            char ch = _getch();
            if (ch == 'q' || ch == 'Q') {
                pool_party.StopMonitoring();
                std::cout << "Monitoring stopped." << std::endl;
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void SingleProcessScan(PoolParty& pool_party) {
    auto processes = pool_party.GetProcessList();

    std::cout << "\n=== Process List ===" << std::endl;
    std::cout << "PID\tCPU%\tMemory(MB)\tName\n";
    std::cout << "---\t----\t----------\t----\n";

    // Сортуємо за CPU usage
    std::sort(processes.begin(), processes.end(),
        [](const ProcessInfo& a, const ProcessInfo& b) {
            return a.cpu_usage > b.cpu_usage;
        });

    int displayed = 0;
    for (const auto& proc : processes) {
        if (proc.cpu_usage > 0.1 || proc.memory_usage > 50 * 1024 * 1024) {
            std::cout << proc.pid << "\t"
                << std::fixed << std::setprecision(1) << proc.cpu_usage << "%\t"
                << (proc.memory_usage / (1024 * 1024)) << " MB\t\t"
                << proc.name << std::endl;
            displayed++;

            if (displayed >= 20) break;
        }
    }

    std::cout << "\nTotal processes: " << processes.size() << std::endl;
    std::cout << "Displayed: " << displayed << " (filtered by activity)" << std::endl;
}

void CreateMemoryDump(PoolParty& pool_party) {
    std::cout << "\n=== Create Memory Dump ===" << std::endl;

    // Показати список процесів для вибору
    auto processes = pool_party.GetProcessList();
    std::cout << "Recent processes:" << std::endl;

    int count = 0;
    for (const auto& proc : processes) {
        if (count < 10) { // Показати тільки перші 10
            std::cout << "  " << proc.pid << " - " << proc.name << std::endl;
            count++;
        }
    }

    DWORD pid;
    std::cout << "\nEnter PID to dump (or 0 for current process): ";
    std::cin >> pid;

    if (pid == 0) {
        pid = GetCurrentProcessId();
    }

    std::string filename = "dump_pid_" + std::to_string(pid) + ".dmp";

    std::cout << "Creating dump for PID " << pid << " to " << filename << "..." << std::endl;

    if (pool_party.CreateMemoryDump(pid, filename)) {
        std::cout << "✓ Dump created successfully!" << std::endl;
    }
    else {
        std::cout << "✗ Failed to create dump" << std::endl;
    }
}

void InjectDLL(PoolParty& pool_party) {
    std::cout << "\n=== DLL Injection ===" << std::endl;
    std::cout << "WARNING: This is for educational purposes only!" << std::endl;

    DWORD pid;
    std::string dll_path;

    std::cout << "Enter target PID: ";
    std::cin >> pid;
    std::cin.ignore(); // Очистити буфер

    std::cout << "Enter DLL path: ";
    std::getline(std::cin, dll_path);

    // Перевірити чи файл існує
    DWORD file_attr = GetFileAttributesA(dll_path.c_str());
    if (file_attr == INVALID_FILE_ATTRIBUTES) {
        std::cout << "✗ DLL file not found: " << dll_path << std::endl;
        return;
    }

    std::cout << "Attempting injection into PID " << pid << "..." << std::endl;

    if (pool_party.InjectIntoProcess(pid, dll_path)) {
        std::cout << "✓ Injection successful!" << std::endl;
    }
    else {
        std::cout << "✗ Injection failed" << std::endl;
    }
}

void StartNewProcess(PoolParty& pool_party) {
    std::cout << "\n=== Start New Process ===" << std::endl;

    std::string command_line;
    std::cout << "Enter command line (e.g., notepad.exe): ";
    std::cin.ignore();
    std::getline(std::cin, command_line);

    char suspended;
    std::cout << "Start suspended? (y/n): ";
    std::cin >> suspended;

    if (pool_party.StartNewProcess(command_line, (suspended == 'y' || suspended == 'Y'))) {
        std::cout << "✓ Process started successfully!" << std::endl;
    }
    else {
        std::cout << "✗ Failed to start process" << std::endl;
    }
}

void ViewLogFile(SecureLogger& logger) {
    std::cout << "\n=== Log File Contents ===" << std::endl;

    std::ifstream file(logger.GetLogFile());
    if (!file.is_open()) {
        std::cout << "Log file not found or empty." << std::endl;
        return;
    }

    std::string line;
    int count = 0;

    while (std::getline(file, line) && count < 200) {
        std::cout << line << std::endl;
        count++;
    }
}


int main() {

    PoolParty pool_party;
    int choice;

    do {
        ShowMenu();
        std::cin >> choice;

        switch (choice) {
        case 1:
            LiveMonitoring(pool_party);
            break;
        case 2:
            SingleProcessScan(pool_party);
            break;
        case 3:
            CreateMemoryDump(pool_party);
            break;
        case 4:
            InjectDLL(pool_party);
            break;
        case 5:
            StartNewProcess(pool_party);
            break;
        case 6:
            //ViewLogFile();
            ViewLogFile(pool_party.GetLogger());
            break;
            break;
        case 7:
            std::cout << "Exiting Pool Party..." << std::endl;
            break;
        default:
            std::cout << "Invalid choice. Please try again." << std::endl;
        }

        if (choice != 7) {
            std::cout << "\nPress Enter to continue...";
            std::cin.ignore();
            std::cin.get();
            system("cls");
        }

    } while (choice != 7);

    return 0;
}