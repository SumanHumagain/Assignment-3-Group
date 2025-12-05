#include "Utils.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

using namespace std;

namespace Utils {

    // File operations
    bool fileExists(const string& path) {
        ifstream file(path);
        return file.good();
    }

    string readFile(const string& path) {
        ifstream file(path);
        if (!file.is_open()) {
            logError("Failed to open file: " + path);
            return "";
        }

        stringstream buffer;
        buffer << file.rdbuf();
        file.close();
        return buffer.str();
    }

    // String utilities
    string trim(const string& str) {
        size_t start = str.find_first_not_of(" \t\n\r");
        size_t end = str.find_last_not_of(" \t\n\r");

        if (start == string::npos) {
            return "";
        }

        return str.substr(start, end - start + 1);
    }

    vector<string> split(const string& str, char delimiter) {
        vector<string> tokens;
        stringstream ss(str);
        string token;

        while (getline(ss, token, delimiter)) {
            tokens.push_back(token);
        }

        return tokens;
    }

    // Security: Input sanitization
    string sanitizeInput(const string& input) {
        string sanitized = input;

        // Remove null bytes
        sanitized.erase(remove(sanitized.begin(), sanitized.end(), '\0'), sanitized.end());

        // Remove control characters except newline and tab
        sanitized.erase(
            remove_if(sanitized.begin(), sanitized.end(),
                [](char c) {
                    return (c < 32 && c != '\n' && c != '\t') || c == 127;
                }
            ),
            sanitized.end()
        );

        return sanitized;
    }

    bool validateFilePath(const string& path) {
        // Check if empty
        if (path.empty()) {
            logWarning("Empty file path");
            return false;
        }

        // Check for path traversal attempts
        if (path.find("..") != string::npos) {
            logWarning("Path traversal detected in: " + path);
            return false;
        }

        // Check for suspicious characters
        const string dangerous_chars = "|&;$`\n<>";
        for (char c : dangerous_chars) {
            if (path.find(c) != string::npos) {
                logWarning("Suspicious character detected in path: " + path);
                return false;
            }
        }

        // Check path length (prevent buffer overflow)
        if (path.length() > 4096) {
            logWarning("Path too long: " + path);
            return false;
        }

        return true;
    }

    // Logging functions
    void logInfo(const string& message) {
        cout << "[INFO] " << message << endl;
    }

    void logError(const string& message) {
        cerr << "[ERROR] " << message << endl;
    }

    void logWarning(const string& message) {
        cerr << "[WARNING] " << message << endl;
    }

}
