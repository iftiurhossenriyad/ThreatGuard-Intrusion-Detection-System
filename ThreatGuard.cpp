#include "ThreatGuard.h"
#include "Utilities.h"
#include "PasswordHasher.h"
#include <iostream>
#include <limits>

static std::string uiMainBorder(const std::string& text) {
    return Utilities::blue(text);
}

static std::string uiMainHeader(const std::string& text) {
    return Utilities::brightWhite(text);
}

static std::string uiMainOption(const std::string& text) {
    return Utilities::cyan(text);
}

static std::string uiPrompt(const std::string& text) {
    return Utilities::magenta(text);
}

static std::string uiRegisterBorder(const std::string& text) {
    return Utilities::magenta(text);
}

static std::string uiRegisterHeader(const std::string& text) {
    return Utilities::brightWhite(text);
}

static std::string uiRegisterPrompt(const std::string& text) {
    return Utilities::yellow(text);
}

static std::string uiLoginBorder(const std::string& text) {
    return Utilities::cyan(text);
}

static std::string uiLoginHeader(const std::string& text) {
    return Utilities::brightWhite(text);
}

static std::string uiAdminBorder(const std::string& text) {
    return Utilities::green(text);
}

static std::string uiAdminHeader(const std::string& text) {
    return Utilities::brightWhite(text);
}

static std::string uiAdminOption(const std::string& text) {
    return Utilities::yellow(text);
}

static std::string uiUserBorder(const std::string& text) {
    return Utilities::brightCyan(text);
}

static std::string uiUserHeader(const std::string& text) {
    return Utilities::white(text);
}

static std::string uiUserOption(const std::string& text) {
    return Utilities::green(text);
}

static std::string uiLogTitle(const std::string& text) {
    return Utilities::brightCyan(text);
}

static std::string uiLogBorder(const std::string& text) {
    return Utilities::blue(text);
}

static std::string uiSearchPrompt(const std::string& text) {
    return Utilities::magenta(text);
}

static std::string uiBorder(const std::string& text) {
    return uiMainBorder(text);
}

static std::string uiHeader(const std::string& text) {
    return uiMainHeader(text);
}

static std::string uiAccent(const std::string& text) {
    return uiMainOption(text);
}

ThreatGuard::ThreatGuard()
    : database(), logger("threatguard.db") {
    if (!database.open("threatguard.db")) {
        return;
    }
    if (!database.initializeSchema()) {
        std::cout << Utilities::red("Unable to initialize schema.\n");
        return;
    }
    createDefaultAccounts();
}

void ThreatGuard::run() {
    showMainMenu();
}

void ThreatGuard::showMainMenu() {
    while (true) {
        std::cout << uiMainBorder("+--------------------------------------+\n");
        std::cout << uiMainHeader("|           THREAT GUARD SYSTEM        |\n");
        std::cout << uiMainBorder("+--------------------------------------+\n");
        std::cout << uiMainHeader("|                MAIN MENU             |\n");
        std::cout << uiMainBorder("+--------------------------------------+\n");
        std::cout << uiMainOption("|  1. Register                         |\n");
        std::cout << uiMainOption("|  2. Login                            |\n");
        std::cout << uiMainOption("|  3. Admin Login                      |\n");
        std::cout << uiMainOption("|  4. View System Logs                 |\n");
        std::cout << uiMainOption("|  5. Exit                             |\n");
        std::cout << uiMainBorder("+--------------------------------------+\n");
        int choice = readInt("Select an option: ");

        switch (choice) {
            case 1:
                showRegisterScreen();
                break;
            case 2:
                showLoginScreen();
                break;
            case 3:
                showAdminLoginScreen();
                break;
            case 4:
                displayLogs();
                break;
            case 5:
                std::cout << "\nExiting system.\n";
                return;
            default:
                std::cout << "\nInvalid selection.\n";
        }
        std::cout << "\n";
    }
}

void ThreatGuard::showRegisterScreen() {
    std::cout << uiBorder("\n+--------------------------------------+\n");
    std::cout << uiHeader("|          USER REGISTRATION           |\n");
    std::cout << uiBorder("+--------------------------------------+\n");
    registerUser();
    pause();
}

void ThreatGuard::showLoginScreen() {
    std::cout << uiBorder("\n+--------------------------------------+\n");
    std::cout << uiHeader("|             USER LOGIN               |\n");
    std::cout << uiBorder("+--------------------------------------+\n");
    loginUser();
}

void ThreatGuard::showAdminLoginScreen() {
    std::cout << uiBorder("\n+--------------------------------------+\n");
    std::cout << uiHeader("|             ADMIN LOGIN              |\n");
    std::cout << uiBorder("+--------------------------------------+\n");
    adminLogin();
}

void ThreatGuard::showUserDashboard(const User& user) {
    while (true) {
        std::cout << uiBorder("\n+--------------------------------------+\n");
        std::cout << uiHeader("|            USER DASHBOARD            |\n");
        std::cout << uiBorder("+--------------------------------------+\n");
        std::cout << uiAccent("| Logged in: ") << Utilities::white(user.getUsername());
        std::cout << std::string(28 - std::min(28, static_cast<int>(user.getUsername().size())), ' ');
        std::cout << uiAccent("|\n");
        std::cout << uiAccent("| 1. View Profile                     |\n");
        std::cout << uiAccent("| 2. Change Password                  |\n");
        std::cout << uiAccent("| 3. View Personal Logs               |\n");
        std::cout << uiAccent("| 4. Logout                            |\n");
        std::cout << uiBorder("+--------------------------------------+\n");
        int choice = readInt("Select an option > ");

        switch (choice) {
            case 1:
                showProfile(user);
                break;
            case 2:
                showChangePassword(user);
                break;
            case 3:
                std::cout << "\nPersonal log view is not available in this version.\n\n";
                pause();
                break;
            case 4:
                return;
            default:
                std::cout << "\nInvalid selection.\n\n";
        }
    }
}

void ThreatGuard::showAdminDashboard() {
    while (true) {
        std::cout << uiBorder("\n+--------------------------------------+\n");
        std::cout << uiHeader("|           ADMIN DASHBOARD           |\n");
        std::cout << uiBorder("+--------------------------------------+\n");
        std::cout << uiAccent("| 1. View All Users                   |\n");
        std::cout << uiAccent("| 2. View All Logs                   |\n");
        std::cout << uiAccent("| 3. View Recent Logs                |\n");
        std::cout << uiAccent("| 4. View Suspicious Activities      |\n");
        std::cout << uiAccent("| 5. Unlock Account                   |\n");
        std::cout << uiAccent("| 6. Search User                      |\n");
        std::cout << uiAccent("| 7. System Statistics                |\n");
        std::cout << uiAccent("| 8. Logout                           |\n");
        std::cout << uiBorder("+--------------------------------------+\n");
        int choice = readInt("Select an option > ");

        switch (choice) {
            case 1:
                displayUsers();
                break;
            case 2:
                displayLogs();
                break;
            case 3:
                displayRecentLogs();
                break;
            case 4:
                displaySuspiciousLogs();
                break;
            case 5:
                unlockAccount();
                break;
            case 6:
                searchUser();
                break;
            case 7:
                showStatistics();
                break;
            case 8:
                return;
            default:
                std::cout << "\nInvalid selection.\n\n";
        }
    }
}

void ThreatGuard::showProfile(const User& user) {
    std::cout << uiBorder("\n+--------------------------------------+\n");
    std::cout << uiHeader("|               PROFILE               |\n");
    std::cout << uiBorder("+--------------------------------------+\n");
    std::cout << uiAccent("Username: ") << Utilities::white(user.getUsername()) << "\n";
    std::cout << uiAccent("Role: ") << Utilities::white(user.getRole()) << "\n";
    std::cout << uiAccent("Failed Attempts: ") << Utilities::white(std::to_string(user.getFailedAttempts())) << "\n";
    std::cout << uiAccent("Locked: ") << Utilities::white(user.isLocked() ? "Yes" : "No") << "\n\n";
    pause();
}

void ThreatGuard::showChangePassword(const User& user) {
    std::cout << uiBorder("\n+--------------------------------------+\n");
    std::cout << uiHeader("|            CHANGE PASSWORD          |\n");
    std::cout << uiBorder("+--------------------------------------+\n");
    std::string oldPassword = readLine(uiAccent("Current Password: "));
    User verifiedUser;
    if (!authenticate(user.getUsername(), oldPassword, verifiedUser)) {
        std::cout << Utilities::red("\nAuthentication failed.\n\n");
        pause();
        return;
    }
    std::string newPassword = readLine(uiAccent("New Password: "));
    std::string confirmPassword = readLine(uiAccent("Confirm Password: "));
    if (newPassword != confirmPassword) {
        std::cout << Utilities::yellow("\nPasswords do not match.\n\n");
        pause();
        return;
    }
    std::string message;
    if (!PasswordModule::validatePassword(newPassword, message)) {
        std::cout << Utilities::yellow("\n" + message + "\n\n");
        pause();
        return;
    }
    verifiedUser.setSalt(PasswordHasher::createSalt());
    verifiedUser.setPasswordHash(PasswordModule::hashPassword(newPassword, verifiedUser.getSalt()));
    database.updateUser(verifiedUser);
    logger.logEvent(verifiedUser.getUsername(), "PASSWORD_CHANGE", "User password changed");
    std::cout << Utilities::green("\nPassword changed successfully.\n\n");
    pause();
}

void ThreatGuard::registerUser() {
    std::string username = readLine(uiAccent("Username: "));
    if (username.empty()) {
        std::cout << Utilities::yellow("\nUsername cannot be empty.\n\n");
        return;
    }
    if (database.userExists(username)) {
        std::cout << Utilities::yellow("\nUsername already exists.\n\n");
        return;
    }
    std::string password = readLine(uiAccent("Password         : "));
    std::string confirmPassword = readLine(uiAccent("Confirm Password : "));
    if (password != confirmPassword) {
        std::cout << Utilities::yellow("\nPasswords do not match.\n\n");
        return;
    }
    std::string validationMessage;
    if (!PasswordModule::validatePassword(password, validationMessage)) {
        std::cout << Utilities::yellow("\n" + validationMessage + "\n\n");
        return;
    }
    User newUser(0, username, "", "", "User", 0, false, 0);
    newUser.setSalt(PasswordHasher::createSalt());
    newUser.setPasswordHash(PasswordModule::hashPassword(password, newUser.getSalt()));
    if (database.createUser(newUser)) {
        logger.logEvent(username, "REGISTRATION", "New user registered");
        std::cout << Utilities::green("\nRegistration successful.\n\n");
    } else {
        std::cout << Utilities::red("\nFailed to register user.\n\n");
    }
}

void ThreatGuard::loginUser() {
    std::string username = readLine(uiAccent("Username: "));
    std::string password = readLine(uiAccent("Password: "));
    User user;
    if (!authenticate(username, password, user)) {
        pause();
        return;
    }
    logger.logEvent(username, "LOGIN_SUCCESS", "User logged in");
    std::cout << Utilities::green("\nAuthentication successful.\n\n");
    showUserDashboard(user);
}

void ThreatGuard::adminLogin() {
    std::string username = readLine(uiAccent("Admin Username: "));
    std::string password = readLine(uiAccent("Admin Password: "));
    User admin;
    if (!authenticateAdmin(username, password, admin)) {
        pause();
        return;
    }
    logger.logEvent(username, "ADMIN_LOGIN", "Admin logged in");
    std::cout << Utilities::green("\nAuthentication successful.\n\n");
    showAdminDashboard();
}

void ThreatGuard::unlockAccount() {
    std::cout << "\n";
    std::string username = readLine(uiAccent("Username to unlock: "));
    User user;
    if (!database.getUserByUsername(username, user)) {
        std::cout << Utilities::yellow("\nUser not found.\n\n");
        return;
    }
    if (!user.isLocked()) {
        std::cout << Utilities::yellow("\nAccount is not locked.\n\n");
        return;
    }
    user.setLocked(false);
    user.setFailedAttempts(0);
    database.updateUser(user);
    logger.logEvent(username, "ACCOUNT_UNLOCK", "Account unlocked by admin");
    std::cout << Utilities::green("\nAccount unlocked.\n\n");
}

void ThreatGuard::displayLogs() {
    auto logs = logger.getLogs();
    std::cout << uiAccent("\nSYSTEM LOGS\n");
    std::cout << uiBorder("===================\n");
    for (const auto& entry : logs) {
        std::cout << entry.id << " | " << entry.timestamp << " | " << entry.username << " | " << entry.event << " | " << entry.details << "\n";
    }
    std::cout << "\n";
    pause();
}

void ThreatGuard::displayRecentLogs() {
    auto logs = logger.getRecentLogs(10);
    std::cout << uiAccent("\nRECENT LOGS\n");
    std::cout << uiBorder("===================\n");
    for (const auto& entry : logs) {
        std::cout << entry.id << " | " << entry.timestamp << " | " << entry.username << " | " << entry.event << " | " << entry.details << "\n";
    }
    std::cout << "\n";
    pause();
}

void ThreatGuard::displaySuspiciousLogs() {
    auto logs = logger.getSuspiciousLogs();
    std::cout << uiAccent("\nSUSPICIOUS ACTIVITIES\n");
    std::cout << uiBorder("===================\n");
    for (const auto& entry : logs) {
        std::cout << entry.id << " | " << entry.timestamp << " | " << entry.username << " | " << entry.event << " | " << entry.details << "\n";
    }
    std::cout << "\n";
    pause();
}

void ThreatGuard::displayUsers() {
    std::vector<User> users;
    if (!database.listUsers(users)) {
        std::cout << Utilities::yellow("\nUnable to load users.\n\n");
        return;
    }
    std::cout << uiAccent("\nREGISTERED USERS\n");
    std::cout << uiBorder("===================\n");
    for (const auto& user : users) {
        std::cout << user.getId() << " | " << user.getUsername() << " | " << user.getRole()
                  << " | Failed=" << user.getFailedAttempts()
                  << " | Locked=" << (user.isLocked() ? "Yes" : "No") << "\n";
    }
    std::cout << "\n";
    pause();
}

void ThreatGuard::searchUser() {
    std::cout << "\n";
    std::string username = readLine(uiAccent("Search Username: "));
    User user;
    if (!database.getUserByUsername(username, user)) {
        std::cout << Utilities::yellow("\nUser not found.\n\n");
    } else {
        std::cout << uiAccent("\nUsername: ") << Utilities::white(user.getUsername()) << "\n";
        std::cout << uiAccent("Role: ") << Utilities::white(user.getRole()) << "\n";
        std::cout << uiAccent("Failed Attempts: ") << Utilities::white(std::to_string(user.getFailedAttempts())) << "\n";
        std::cout << uiAccent("Locked: ") << Utilities::white(user.isLocked() ? "Yes" : "No") << "\n\n";
    }
    pause();
}

void ThreatGuard::showStatistics() {
    std::vector<User> users;
    database.listUsers(users);
    int totalUsers = static_cast<int>(users.size());
    int lockedUsers = 0;
    for (const auto& user : users) {
        if (user.isLocked()) {
            lockedUsers++;
        }
    }
    std::cout << uiAccent("\nSYSTEM STATISTICS\n");
    std::cout << uiBorder("===================\n");
    std::cout << uiAccent("Total users: ") << Utilities::white(std::to_string(totalUsers)) << "\n";
    std::cout << uiAccent("Locked accounts: ") << Utilities::white(std::to_string(lockedUsers)) << "\n\n";
    pause();
}

void ThreatGuard::createDefaultAccounts() {
    if (!database.userExists("admin")) {
        User admin(0, "admin", "", "", "Admin", 0, false, 0);
        admin.setSalt(PasswordHasher::createSalt());
        admin.setPasswordHash(PasswordModule::hashPassword("Uftb@123", admin.getSalt()));
        database.createUser(admin);
        logger.logEvent("admin", "DEFAULT_ACCOUNT", "Admin account created");
    }
    if (!database.userExists("user")) {
        User user(0, "user", "", "", "User", 0, false, 0);
        user.setSalt(PasswordHasher::createSalt());
        user.setPasswordHash(PasswordModule::hashPassword("Uftb@123", user.getSalt()));
        database.createUser(user);
        logger.logEvent("user", "DEFAULT_ACCOUNT", "Demo account created");
    }
}

bool ThreatGuard::authenticate(const std::string& username, const std::string& password, User& outUser) {
    if (!database.getUserByUsername(username, outUser)) {
        std::cout << Utilities::red("\nInvalid credentials.\n\n");
        logger.logEvent(username, "LOGIN_FAILURE", "Username not found");
        return false;
    }
    if (outUser.isLocked()) {
        std::cout << Utilities::yellow("\nAccount locked.\n\n");
        logger.logEvent(username, "LOGIN_FAILURE", "Account locked");
        return false;
    }
    if (!PasswordModule::verifyPassword(password, outUser.getSalt(), outUser.getPasswordHash())) {
        int attempts = outUser.getFailedAttempts() + 1;
        outUser.setFailedAttempts(attempts);
        if (attempts >= 3) {
            outUser.setLocked(true);
            database.updateUser(outUser);
            logger.logSecurity(username, "BRUTE_FORCE_ALERT", "Account locked after failed login attempts");
            std::cout << Utilities::brightRed("\nAccount locked after 3 failed attempts.\n\n");
            return false;
        }
        database.updateUser(outUser);
        logger.logEvent(username, "LOGIN_FAILURE", "Incorrect password");
        std::cout << Utilities::yellow("\nInvalid credentials. Remaining attempts: " + std::to_string(3 - attempts) + "\n\n");
        return false;
    }
    outUser.setFailedAttempts(0);
    database.updateUser(outUser);
    return true;
}

bool ThreatGuard::authenticateAdmin(const std::string& username, const std::string& password, User& outUser) {
    if (!authenticate(username, password, outUser)) {
        return false;
    }
    if (outUser.getRole() != "Admin") {
        std::cout << Utilities::yellow("Admin access required.\n");
        return false;
    }
    return true;
}

std::string ThreatGuard::readLine(const std::string& prompt) const {
    std::cout << prompt;
    std::cout.flush();
    std::string value;
    if (!std::getline(std::cin, value)) {
        return "";
    }
    if (!value.empty() && value.back() == '\r') {
        value.pop_back();
    }
    return value;
}

int ThreatGuard::readInt(const std::string& prompt) const {
    while (true) {
        std::string input = readLine(prompt);
        if (input.empty()) {
            std::cout << Utilities::yellow("Invalid entry. Please enter a number.\n");
            continue;
        }
        try {
            int value = std::stoi(input);
            return value;
        } catch (...) {
            std::cout << Utilities::yellow("Invalid entry. Please enter a number.\n");
        }
    }
}

void ThreatGuard::pause() const {
    std::cout << Utilities::brightWhite("\nPress Enter to continue...");
    std::cout.flush();
    std::string dummy;
    std::getline(std::cin, dummy);
}
