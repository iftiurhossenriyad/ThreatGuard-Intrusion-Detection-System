#pragma once

#include <string>
#include <vector>
#include "User.h"

struct sqlite3;
struct sqlite3_stmt;

class DatabaseManager {
public:
    DatabaseManager();
    ~DatabaseManager();

    bool open(const std::string& filePath);
    void close();
    bool initializeSchema();

    bool userExists(const std::string& username);
    bool createUser(const User& user);
    bool getUserByUsername(const std::string& username, User& outUser);
    bool updateUser(const User& user);
    bool listUsers(std::vector<User>& users);
    bool insertSecurityLog(const std::string& username, const std::string& event, const std::string& details);
    bool insertLoginHistory(int userId, bool success, const std::string& details);
    bool lockUser(const std::string& username);
    bool resetFailedAttempts(const std::string& username);
    bool incrementFailedAttempts(const std::string& username);
    std::string getLastError() const;

    bool execute(const std::string& sql);
    bool prepareStatement(const std::string& sql, sqlite3_stmt** outStmt);
    bool stepStatement(sqlite3_stmt* stmt, int& code);
    bool bindInt(sqlite3_stmt* stmt, int index, int value);
    bool bindText(sqlite3_stmt* stmt, int index, const std::string& value);
    int columnInt(sqlite3_stmt* stmt, int columnIndex);
    const unsigned char* columnText(sqlite3_stmt* stmt, int columnIndex);
    void finalizeStatement(sqlite3_stmt* stmt);

private:
    sqlite3* db;
    sqlite3_stmt* statement;
    std::string dbFilePath;
    std::string lastError;
};
