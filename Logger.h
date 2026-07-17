#pragma once

#include <string>
#include <vector>

struct LogEntry {
    int id;
    int timestamp;
    std::string username;
    std::string event;
    std::string details;
};

class Logger {
public:
    explicit Logger(const std::string& dbFilePath);
    bool logEvent(const std::string& username, const std::string& event, const std::string& details);
    bool logSecurity(const std::string& username, const std::string& event, const std::string& details);
    std::vector<LogEntry> getLogs() const;
    std::vector<LogEntry> getRecentLogs(int count) const;
    std::vector<LogEntry> getSuspiciousLogs() const;
private:
    std::string dbFilePath;
};
