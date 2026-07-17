#include "Logger.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <ctime>

namespace {
std::string logFilePath(const std::string& dbFilePath) {
    return dbFilePath + ".log";
}

std::vector<std::string> readLines(const std::string& path) {
    std::ifstream input(path);
    std::vector<std::string> lines;
    if (!input.is_open()) {
        return lines;
    }
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    return lines;
}
}

Logger::Logger(const std::string& dbFilePath)
    : dbFilePath(dbFilePath) {}

bool Logger::logEvent(const std::string& username, const std::string& event, const std::string& details) {
    std::ofstream output(logFilePath(dbFilePath), std::ios::app);
    if (!output.is_open()) {
        return false;
    }
    output << static_cast<int>(std::time(nullptr)) << '|'
           << (username.empty() ? "SYSTEM" : username) << '|'
           << event << '|'
           << details << '\n';
    return true;
}

bool Logger::logSecurity(const std::string& username, const std::string& event, const std::string& details) {
    return logEvent(username, event, details);
}

std::vector<LogEntry> Logger::getLogs() const {
    std::vector<LogEntry> entries;
    auto lines = readLines(logFilePath(dbFilePath));
    int id = 1;
    for (const std::string& line : lines) {
        std::stringstream stream(line);
        std::string timestampText;
        std::string usernameText;
        std::string eventText;
        std::string detailsText;
        std::getline(stream, timestampText, '|');
        std::getline(stream, usernameText, '|');
        std::getline(stream, eventText, '|');
        std::getline(stream, detailsText);
        if (timestampText.empty()) {
            continue;
        }
        LogEntry entry;
        entry.id = id++;
        entry.timestamp = std::stoi(timestampText);
        entry.username = usernameText;
        entry.event = eventText;
        entry.details = detailsText;
        entries.push_back(entry);
    }
    std::reverse(entries.begin(), entries.end());
    return entries;
}

std::vector<LogEntry> Logger::getRecentLogs(int count) const {
    auto entries = getLogs();
    if (count <= 0) {
        return {};
    }
    if (static_cast<int>(entries.size()) > count) {
        entries.erase(entries.begin(), entries.begin() + static_cast<int>(entries.size()) - count);
    }
    return entries;
}

std::vector<LogEntry> Logger::getSuspiciousLogs() const {
    auto entries = getLogs();
    entries.erase(std::remove_if(entries.begin(), entries.end(), [](const LogEntry& entry) {
        const std::string lowerEvent = entry.event;
        return lowerEvent.find("ALERT") == std::string::npos && lowerEvent.find("LOCK") == std::string::npos;
    }), entries.end());
    return entries;
}
