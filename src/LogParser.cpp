#include "LogParser.h"
#include "Utils.h"
#include <fstream>
#include <sstream>
#include <regex>

using namespace std;

LogParser::LogParser() : format(UNKNOWN) {}

LogParser::~LogParser() {}

bool LogParser::loadFile(const string& filePath) {
    // Validate file path
    if (!Utils::validateFilePath(filePath)) {
        Utils::logError("Invalid file path: " + filePath);
        return false;
    }

    if (!Utils::fileExists(filePath)) {
        Utils::logError("File not found: " + filePath);
        return false;
    }

    // Detect format
    format = detectFormat(filePath);
    if (format == UNKNOWN) {
        Utils::logWarning("Unknown log format, attempting syslog parsing");
        format = SYSLOG;
    }

    // Read file
    ifstream file(filePath);
    if (!file.is_open()) {
        Utils::logError("Failed to open file: " + filePath);
        return false;
    }

    string line;
    int lineCount = 0;

    while (getline(file, line)) {
        lineCount++;

        // Skip empty lines
        line = Utils::trim(line);
        if (line.empty()) {
            continue;
        }

        // Sanitize input
        line = Utils::sanitizeInput(line);

        // Parse based on format
        LogEntry entry;
        try {
            switch (format) {
                case SYSLOG:
                    entry = parseSyslogLine(line);
                    break;
                case JSON:
                    entry = parseJsonLine(line);
                    break;
                case CSV:
                    entry = parseCsvLine(line);
                    break;
                default:
                    entry = parseSyslogLine(line);
                    break;
            }

            if (!entry.message.empty()) {
                entries.push_back(entry);
            }
        } catch (const exception& e) {
            Utils::logWarning("Failed to parse line " + to_string(lineCount) + ": " + string(e.what()));
        }
    }

    file.close();
    Utils::logInfo("Loaded " + to_string(entries.size()) + " log entries from " + filePath);
    return !entries.empty();
}

vector<LogEntry> LogParser::getEntries() const {
    return entries;
}

LogFormat LogParser::detectFormat(const string& filePath) {
    ifstream file(filePath);
    if (!file.is_open()) {
        return UNKNOWN;
    }

    string firstLine;
    getline(file, firstLine);
    file.close();

    firstLine = Utils::trim(firstLine);

    // Check for JSON
    if (firstLine[0] == '{' || firstLine[0] == '[') {
        return JSON;
    }

    // Check for CSV (contains commas and possibly quoted fields)
    if (firstLine.find(',') != string::npos) {
        return CSV;
    }

    // Default to syslog
    return SYSLOG;
}

LogEntry LogParser::parseSyslogLine(const string& line) {
    LogEntry entry;

    // Simple syslog pattern: timestamp hostname process: message
    // Example: Dec  3 15:30:45 server sshd[1234]: Failed password for user

    regex syslogPattern(R"(^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+?):\s+(.+)$)");
    smatch matches;

    if (regex_search(line, matches, syslogPattern)) {
        entry.timestamp = matches[1];
        entry.source = matches[2];
        entry.eventType = matches[3];
        entry.message = matches[4];

        // Determine severity based on keywords
        string lowerMsg = entry.message;
        transform(lowerMsg.begin(), lowerMsg.end(), lowerMsg.begin(), ::tolower);

        if (lowerMsg.find("fail") != string::npos ||
            lowerMsg.find("error") != string::npos ||
            lowerMsg.find("denied") != string::npos) {
            entry.severity = "ERROR";
        } else if (lowerMsg.find("warn") != string::npos) {
            entry.severity = "WARNING";
        } else {
            entry.severity = "INFO";
        }
    } else {
        // Fallback: just store the line as message
        entry.timestamp = "N/A";
        entry.source = "unknown";
        entry.severity = "INFO";
        entry.eventType = "raw";
        entry.message = line;
    }

    return entry;
}

LogEntry LogParser::parseJsonLine(const string& line) {
    LogEntry entry;

    // Simple JSON parsing (basic implementation)
    // For production, use a JSON library like nlohmann/json or rapidjson

    entry.timestamp = "N/A";
    entry.source = "json";
    entry.severity = "INFO";
    entry.eventType = "json_event";
    entry.message = line;

    // Extract basic fields if present
    size_t pos;

    // Extract timestamp
    if ((pos = line.find("\"timestamp\"")) != string::npos) {
        size_t start = line.find(":", pos) + 1;
        size_t end = line.find(",", start);
        if (end == string::npos) end = line.find("}", start);
        string ts = line.substr(start, end - start);
        ts = Utils::trim(ts);
        ts.erase(remove(ts.begin(), ts.end(), '"'), ts.end());
        entry.timestamp = ts;
    }

    // Extract message
    if ((pos = line.find("\"message\"")) != string::npos) {
        size_t start = line.find(":", pos) + 1;
        size_t end = line.find(",", start);
        if (end == string::npos) end = line.find("}", start);
        string msg = line.substr(start, end - start);
        msg = Utils::trim(msg);
        msg.erase(remove(msg.begin(), msg.end(), '"'), msg.end());
        entry.message = msg;
    }

    return entry;
}

LogEntry LogParser::parseCsvLine(const string& line) {
    LogEntry entry;

    vector<string> fields = Utils::split(line, ',');

    if (fields.size() >= 4) {
        entry.timestamp = Utils::trim(fields[0]);
        entry.severity = Utils::trim(fields[1]);
        entry.source = Utils::trim(fields[2]);
        entry.message = Utils::trim(fields[3]);

        // Remove quotes if present
        for (string* field : {&entry.timestamp, &entry.severity, &entry.source, &entry.message}) {
            if (field->front() == '"') field->erase(0, 1);
            if (field->back() == '"') field->pop_back();
        }

        entry.eventType = "csv_event";
    } else {
        // Fallback
        entry.timestamp = "N/A";
        entry.source = "csv";
        entry.severity = "INFO";
        entry.eventType = "csv_event";
        entry.message = line;
    }

    return entry;
}
