#include "Utilities.h"
#include <iostream>
#include <string>
#include <algorithm>
#include <sstream>
#include <cstdlib>
#include <limits>
#include <ctime>
#ifdef _WIN32
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#endif

static bool g_ansiEnabled = false;

static std::string applyColor(const std::string& text, const char* code) {
    if (!g_ansiEnabled) {
        return text;
    }
    return std::string(code) + text + "\x1b[0m";
}

bool Utilities::enableANSISupport() {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) {
        g_ansiEnabled = false;
        return false;
    }
    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) {
        g_ansiEnabled = false;
        return false;
    }
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (!SetConsoleMode(hOut, dwMode)) {
        g_ansiEnabled = false;
        return false;
    }
    g_ansiEnabled = true;
    return true;
#else
    g_ansiEnabled = true;
    return true;
#endif
}

std::string Utilities::brightCyan(const std::string& text) {
    return applyColor(text, "\x1b[96m");
}

std::string Utilities::cyan(const std::string& text) {
    return applyColor(text, "\x1b[36m");
}

std::string Utilities::brightGreen(const std::string& text) {
    return applyColor(text, "\x1b[92m");
}

std::string Utilities::white(const std::string& text) {
    return applyColor(text, "\x1b[37m");
}

std::string Utilities::yellow(const std::string& text) {
    return applyColor(text, "\x1b[33m");
}

std::string Utilities::brightWhite(const std::string& text) {
    return applyColor(text, "\x1b[97m");
}

std::string Utilities::green(const std::string& text) {
    return applyColor(text, "\x1b[32m");
}

std::string Utilities::red(const std::string& text) {
    return applyColor(text, "\x1b[31m");
}

std::string Utilities::brightRed(const std::string& text) {
    return applyColor(text, "\x1b[91m");
}

std::string Utilities::blue(const std::string& text) {
    return applyColor(text, "\x1b[34m");
}

std::string Utilities::magenta(const std::string& text) {
    return applyColor(text, "\x1b[35m");
}

std::string Utilities::gray(const std::string& text) {
    return applyColor(text, "\x1b[90m");
}

std::string Utilities::buildHeader(const std::string& title) {
    std::string border(title.size() + 8, '=');
    std::stringstream ss;
    ss << border << "\n";
    ss << "==  " << title << "  ==\n";
    ss << border;
    return ss.str();
}

std::string Utilities::buildLine(int width) {
    return std::string(width, '-');
}

std::string Utilities::formatRow(const std::string& label, const std::string& value, int width) {
    std::string row = label + " " + value;
    if (static_cast<int>(row.size()) < width) {
        row += std::string(width - row.size(), ' ');
    }
    return row;
}

void Utilities::clearScreen() {
#ifdef _WIN32
    std::system("cls");
#else
    std::system("clear");
#endif
}

int Utilities::promptInt(const std::string& prompt, int minValue, int maxValue) {
    int value = 0;
    while (true) {
        std::cout << prompt;
        std::cout.flush();
        if (std::cin >> value && value >= minValue && value <= maxValue) {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return value;
        }
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Invalid selection. Please enter a number between " << minValue << " and " << maxValue << ".\n";
    }
}

std::string Utilities::promptString(const std::string& prompt) {
    std::cout << prompt;
    std::string input;
    std::getline(std::cin, input);
    return input;
}

void Utilities::pause() {
    std::cout << "\nPress Enter to continue...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

std::string Utilities::timestampToString(int timestamp) {
    std::time_t timeVal = static_cast<std::time_t>(timestamp);
    std::tm* local = std::localtime(&timeVal);
    if (!local) {
        return "Unknown";
    }
    char buffer[64];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", local);
    return buffer;
}
