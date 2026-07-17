#include "User.h"

User::User()
    : id(0), username(""), passwordHash(""), salt(""), role("User"), failedAttempts(0), locked(false), lastLoginAt(0) {}

User::User(int id, const std::string& username, const std::string& passwordHash, const std::string& salt, const std::string& role, int failedAttempts, bool locked, int lastLoginAt)
    : id(id), username(username), passwordHash(passwordHash), salt(salt), role(role), failedAttempts(failedAttempts), locked(locked), lastLoginAt(lastLoginAt) {}

int User::getId() const {
    return id;
}

const std::string& User::getUsername() const {
    return username;
}

const std::string& User::getPasswordHash() const {
    return passwordHash;
}

const std::string& User::getSalt() const {
    return salt;
}

const std::string& User::getRole() const {
    return role;
}

int User::getFailedAttempts() const {
    return failedAttempts;
}

bool User::isLocked() const {
    return locked;
}

int User::getLastLoginAt() const {
    return lastLoginAt;
}

void User::setPasswordHash(const std::string& hash) {
    passwordHash = hash;
}

void User::setSalt(const std::string& newSalt) {
    salt = newSalt;
}

void User::setRole(const std::string& newRole) {
    role = newRole;
}

void User::setFailedAttempts(int attempts) {
    failedAttempts = attempts;
}

void User::setLocked(bool lockedState) {
    locked = lockedState;
}

void User::setLastLoginAt(int timestamp) {
    lastLoginAt = timestamp;
}
