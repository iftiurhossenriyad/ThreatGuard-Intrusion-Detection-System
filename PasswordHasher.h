#pragma once

#include <string>

class PasswordHasher {
public:
    static std::string createSalt();
    static std::string sha256(const std::string& input);
    static std::string hashPassword(const std::string& password, const std::string& salt);
    static bool verifyPassword(const std::string& password, const std::string& salt, const std::string& hash);
};
