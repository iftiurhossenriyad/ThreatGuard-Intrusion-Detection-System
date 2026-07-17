#include "PasswordModule.h"
#include "PasswordHasher.h"
#include <cctype>

bool PasswordModule::validatePassword(const std::string& password, std::string& message) {
    if (password.size() < 8) {
        message = "Password must be at least 8 characters.";
        return false;
    }
    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSpecial = false;
    for (char c : password) {
        if (std::isupper(static_cast<unsigned char>(c))) hasUpper = true;
        else if (std::islower(static_cast<unsigned char>(c))) hasLower = true;
        else if (std::isdigit(static_cast<unsigned char>(c))) hasDigit = true;
        else hasSpecial = true;
    }
    if (!hasUpper) {
        message = "Password must include at least one uppercase letter.";
        return false;
    }
    if (!hasLower) {
        message = "Password must include at least one lowercase letter.";
        return false;
    }
    if (!hasDigit) {
        message = "Password must include at least one digit.";
        return false;
    }
    if (!hasSpecial) {
        message = "Password must include at least one special character.";
        return false;
    }
    message = "Password is valid.";
    return true;
}

std::string PasswordModule::hashPassword(const std::string& password, const std::string& salt) {
    return PasswordHasher::hashPassword(password, salt);
}

bool PasswordModule::verifyPassword(const std::string& password, const std::string& salt, const std::string& hash) {
    return PasswordHasher::verifyPassword(password, salt, hash);
}
