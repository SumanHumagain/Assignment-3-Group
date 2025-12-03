#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>

using namespace std;

namespace Utils {
    // File operations
    bool fileExists(const string& path);
    string readFile(const string& path);

    // String utilities
    string trim(const string& str);
    vector<string> split(const string& str, char delimiter);

    // Security: Input sanitization
    string sanitizeInput(const string& input);
    bool validateFilePath(const string& path);

    // Logging
    void logInfo(const string& message);
    void logError(const string& message);
    void logWarning(const string& message);
}

#endif
