#ifndef LOGPARSER_H
#define LOGPARSER_H

#include <string>
#include <vector>
#include <map>

using namespace std;

// Structure to represent a log entry
struct LogEntry {
    string timestamp;
    string severity;
    string source;
    string message;
    string eventType;
};

// Enum for log format types
enum LogFormat {
    SYSLOG,
    JSON,
    CSV,
    UNKNOWN
};

class LogParser {
private:
    vector<LogEntry> entries;
    LogFormat format;

    // Helper methods
    LogEntry parseSyslogLine(const string& line);
    LogEntry parseJsonLine(const string& line);
    LogEntry parseCsvLine(const string& line);

public:
    LogParser();
    ~LogParser();

    // Load and parse log file
    bool loadFile(const string& filePath);

    // Get parsed entries
    vector<LogEntry> getEntries() const;

    // Detect format automatically
    static LogFormat detectFormat(const string& filePath);
};

#endif
