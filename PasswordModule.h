#pragma once

#include <string>

class PasswordModule {
public:
    static bool validatePassword(const std::string& password, std::string& message);
    static std::string hashPassword(const std::string& password, const std::string& salt);
    static bool verifyPassword(const std::string& password, const std::string& salt, const std::string& hash);
};
