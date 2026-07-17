#pragma once

#include <string>
#include "DatabaseManager.h"
#include "Logger.h"
#include "User.h"
#include "PasswordModule.h"

class ThreatGuard {
public:
    ThreatGuard();
    void run();

private:
    DatabaseManager database;
    Logger logger;
    void showMainMenu();
    void showRegisterScreen();
    void showLoginScreen();
    void showAdminLoginScreen();
    void showUserDashboard(const User& user);
    void showAdminDashboard();
    void showProfile(const User& user);
    void showChangePassword(const User& user);
    void registerUser();
    void loginUser();
    void adminLogin();
    void unlockAccount();
    void displayLogs();
    void displayRecentLogs();
    void displaySuspiciousLogs();
    void displayUsers();
    void searchUser();
    void showStatistics();
    void createDefaultAccounts();
    bool authenticate(const std::string& username, const std::string& password, User& outUser);
    bool authenticateAdmin(const std::string& username, const std::string& password, User& outUser);
    std::string readLine(const std::string& prompt) const;
    int readInt(const std::string& prompt) const;
    void pause() const;
};
