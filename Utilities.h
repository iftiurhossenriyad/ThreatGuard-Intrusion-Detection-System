#pragma once

#include <string>
#include <vector>

class Utilities {
public:
    static std::string buildHeader(const std::string& title);
    static std::string buildLine(int width);
    static std::string formatRow(const std::string& label, const std::string& value, int width);
    static bool enableANSISupport();
    static std::string brightCyan(const std::string& text);
    static std::string cyan(const std::string& text);
    static std::string brightGreen(const std::string& text);
    static std::string white(const std::string& text);
    static std::string yellow(const std::string& text);
    static std::string brightWhite(const std::string& text);
    static std::string green(const std::string& text);
    static std::string red(const std::string& text);
    static std::string brightRed(const std::string& text);
    static std::string blue(const std::string& text);
    static std::string magenta(const std::string& text);
    static std::string gray(const std::string& text);
    static void clearScreen();
    static int promptInt(const std::string& prompt, int minValue, int maxValue);
    static std::string promptString(const std::string& prompt);
    static void pause();
    static std::string timestampToString(int timestamp);
};
