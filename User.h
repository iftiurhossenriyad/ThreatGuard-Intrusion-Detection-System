#pragma once

#include <string>

class User {
public:
    User();
    User(int id, const std::string& username, const std::string& passwordHash, const std::string& salt, const std::string& role, int failedAttempts, bool locked, int lastLoginAt);

    int getId() const;
    const std::string& getUsername() const;
    const std::string& getPasswordHash() const;
    const std::string& getSalt() const;
    const std::string& getRole() const;
    int getFailedAttempts() const;
    bool isLocked() const;
    int getLastLoginAt() const;

    void setPasswordHash(const std::string& hash);
    void setSalt(const std::string& salt);
    void setRole(const std::string& role);
    void setFailedAttempts(int attempts);
    void setLocked(bool locked);
    void setLastLoginAt(int timestamp);

private:
    int id;
    std::string username;
    std::string passwordHash;
    std::string salt;
    std::string role;
    int failedAttempts;
    bool locked;
    int lastLoginAt;
};
