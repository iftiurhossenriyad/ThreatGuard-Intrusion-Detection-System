#include "DatabaseManager.h"
#include <algorithm>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

namespace {
std::string userFilePath(const std::string& dbFilePath) {
    return dbFilePath + ".users";
}

std::string logFilePath(const std::string& dbFilePath) {
    return dbFilePath + ".log";
}

std::vector<std::string> readLines(const std::string& path) {
    std::vector<std::string> lines;
    std::ifstream input(path);
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

void writeLines(const std::string& path, const std::vector<std::string>& lines) {
    std::ofstream output(path, std::ios::trunc);
    for (const std::string& line : lines) {
        output << line << '\n';
    }
}

bool parseUserLine(const std::string& line, User& user) {
    std::stringstream stream(line);
    std::string field;
    std::vector<std::string> parts;
    while (std::getline(stream, field, '|')) {
        parts.push_back(field);
    }
    if (parts.size() != 8) {
        return false;
    }

    try {
        user = User(
            std::stoi(parts[0]),
            parts[1],
            parts[2],
            parts[3],
            parts[4],
            std::stoi(parts[5]),
            parts[6] == "1",
            std::stoi(parts[7])
        );
        return true;
    } catch (...) {
        return false;
    }
}

std::string serializeUser(const User& user) {
    std::ostringstream stream;
    stream << user.getId() << '|'
           << user.getUsername() << '|'
           << user.getPasswordHash() << '|'
           << user.getSalt() << '|'
           << user.getRole() << '|'
           << user.getFailedAttempts() << '|'
           << (user.isLocked() ? 1 : 0) << '|'
           << user.getLastLoginAt();
    return stream.str();
}
}

DatabaseManager::DatabaseManager()
    : db(nullptr), statement(nullptr), dbFilePath(""), lastError("") {}

DatabaseManager::~DatabaseManager() {
    close();
}

bool DatabaseManager::open(const std::string& filename) {
    dbFilePath = filename;
    std::ofstream users(userFilePath(dbFilePath), std::ios::app);
    std::ofstream logs(logFilePath(dbFilePath), std::ios::app);
    (void)users;
    (void)logs;
    lastError = "";
    return true;
}

void DatabaseManager::close() {
    db = nullptr;
    statement = nullptr;
}

bool DatabaseManager::execute(const std::string&) {
    return true;
}

bool DatabaseManager::prepareStatement(const std::string&, sqlite3_stmt** outStmt) {
    if (outStmt) {
        *outStmt = nullptr;
    }
    return true;
}

bool DatabaseManager::stepStatement(sqlite3_stmt*, int& code) {
    code = 101;
    return true;
}

bool DatabaseManager::bindInt(sqlite3_stmt*, int, int) {
    return true;
}

bool DatabaseManager::bindText(sqlite3_stmt*, int, const std::string&) {
    return true;
}

int DatabaseManager::columnInt(sqlite3_stmt*, int) {
    return 0;
}

const unsigned char* DatabaseManager::columnText(sqlite3_stmt*, int) {
    return nullptr;
}

void DatabaseManager::finalizeStatement(sqlite3_stmt*) {}

std::string DatabaseManager::getLastError() const {
    return lastError;
}

bool DatabaseManager::initializeSchema() {
    return open(dbFilePath.empty() ? "threatguard.db" : dbFilePath);
}

bool DatabaseManager::createUser(const User& user) {
    std::vector<std::string> lines = readLines(userFilePath(dbFilePath));
    int nextId = 1;
    for (const std::string& line : lines) {
        User existing;
        if (parseUserLine(line, existing)) {
            nextId = std::max(nextId, existing.getId() + 1);
        }
    }

    User newUser(nextId, user.getUsername(), user.getPasswordHash(), user.getSalt(), user.getRole(), user.getFailedAttempts(), user.isLocked(), user.getLastLoginAt());
    lines.push_back(serializeUser(newUser));
    writeLines(userFilePath(dbFilePath), lines);
    return true;
}

bool DatabaseManager::getUserByUsername(const std::string& username, User& user) {
    std::vector<std::string> lines = readLines(userFilePath(dbFilePath));
    for (const std::string& line : lines) {
        User candidate;
        if (parseUserLine(line, candidate) && candidate.getUsername() == username) {
            user = candidate;
            return true;
        }
    }
    return false;
}

bool DatabaseManager::updateUser(const User& user) {
    std::vector<std::string> lines = readLines(userFilePath(dbFilePath));
    std::vector<std::string> updated;
    bool found = false;
    for (const std::string& line : lines) {
        User current;
        if (parseUserLine(line, current) && current.getUsername() == user.getUsername()) {
            updated.push_back(serializeUser(user));
            found = true;
        } else {
            updated.push_back(line);
        }
    }
    if (!found) {
        return false;
    }
    writeLines(userFilePath(dbFilePath), updated);
    return true;
}

bool DatabaseManager::insertSecurityLog(const std::string& username, const std::string& event, const std::string& details) {
    std::ofstream output(logFilePath(dbFilePath), std::ios::app);
    if (!output.is_open()) {
        return false;
    }
    output << static_cast<int>(std::time(nullptr)) << '|'
           << username << '|'
           << event << '|'
           << details << '\n';
    return true;
}

bool DatabaseManager::insertLoginHistory(int userId, bool success, const std::string& details) {
    return insertSecurityLog(std::to_string(userId), success ? "LOGIN_SUCCESS" : "LOGIN_FAILURE", details);
}

bool DatabaseManager::userExists(const std::string& username) {
    User user;
    return getUserByUsername(username, user);
}

bool DatabaseManager::lockUser(const std::string& username) {
    std::vector<std::string> lines = readLines(userFilePath(dbFilePath));
    std::vector<std::string> updated;
    bool found = false;
    for (const std::string& line : lines) {
        User current;
        if (parseUserLine(line, current) && current.getUsername() == username) {
            current.setLocked(true);
            updated.push_back(serializeUser(current));
            found = true;
        } else {
            updated.push_back(line);
        }
    }
    if (!found) {
        return false;
    }
    writeLines(userFilePath(dbFilePath), updated);
    return true;
}

bool DatabaseManager::resetFailedAttempts(const std::string& username) {
    std::vector<std::string> lines = readLines(userFilePath(dbFilePath));
    std::vector<std::string> updated;
    bool found = false;
    for (const std::string& line : lines) {
        User current;
        if (parseUserLine(line, current) && current.getUsername() == username) {
            current.setFailedAttempts(0);
            updated.push_back(serializeUser(current));
            found = true;
        } else {
            updated.push_back(line);
        }
    }
    if (!found) {
        return false;
    }
    writeLines(userFilePath(dbFilePath), updated);
    return true;
}

bool DatabaseManager::incrementFailedAttempts(const std::string& username) {
    std::vector<std::string> lines = readLines(userFilePath(dbFilePath));
    std::vector<std::string> updated;
    bool found = false;
    for (const std::string& line : lines) {
        User current;
        if (parseUserLine(line, current) && current.getUsername() == username) {
            current.setFailedAttempts(current.getFailedAttempts() + 1);
            updated.push_back(serializeUser(current));
            found = true;
        } else {
            updated.push_back(line);
        }
    }
    if (!found) {
        return false;
    }
    writeLines(userFilePath(dbFilePath), updated);
    return true;
}

bool DatabaseManager::listUsers(std::vector<User>& users) {
    users.clear();
    std::vector<std::string> lines = readLines(userFilePath(dbFilePath));
    for (const std::string& line : lines) {
        User user;
        if (parseUserLine(line, user)) {
            users.push_back(user);
        }
    }
    return true;
}
