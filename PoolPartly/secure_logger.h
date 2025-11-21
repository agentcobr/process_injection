#pragma once
#include <windows.h>
#include <string>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

class SecureLogger {
private:
    std::string log_file;

public:
    SecureLogger(const std::string& filename) : log_file(filename) {}

    void LogInfo(const std::string& message) {
        WriteLog("[INFO] " + message);
    }

    void LogWarning(const std::string& message) {
        WriteLog("[WARN] " + message);
    }

    void LogError(const std::string& message) {
        WriteLog("[ERROR] " + message);
    }

    const std::string& GetLogFile() const {
        return log_file;
    }

private:
    void WriteLog(const std::string& message) {
        std::ofstream file(log_file, std::ios::app);
        if (!file.is_open()) return;

        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);

        std::tm tm;
        localtime_s(&tm, &t);

        file << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] "
            << message << std::endl;
    }
};
