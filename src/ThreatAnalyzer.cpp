#include "ThreatAnalyzer.h"
#include "Utils.h"
#include <sstream>
#include <fstream>
#include <map>
#include <algorithm>

using namespace std;

ThreatAnalyzer::ThreatAnalyzer(LogParser* p, OllamaClient* c)
    : parser(p), client(c) {}

ThreatAnalyzer::~ThreatAnalyzer() {}

bool ThreatAnalyzer::analyzeFile(const string& filePath) {
    Utils::logInfo("Starting threat analysis...");

    // Load and parse log file
    if (!parser->loadFile(filePath)) {
        Utils::logError("Failed to load log file");
        return false;
    }

    vector<LogEntry> logs = parser->getEntries();
    if (logs.empty()) {
        Utils::logWarning("No log entries found");
        return false;
    }

    Utils::logInfo("Analyzing " + to_string(logs.size()) + " log entries");

    // Pattern-based threat detection
    vector<ThreatIndicator> bruteForce = detectBruteForce(logs);
    vector<ThreatIndicator> privEsc = detectPrivilegeEscalation(logs);

    // Combine all detected threats
    threats.clear();
    threats.insert(threats.end(), bruteForce.begin(), bruteForce.end());
    threats.insert(threats.end(), privEsc.begin(), privEsc.end());

    Utils::logInfo("Pattern detection found " + to_string(threats.size()) + " potential threats");

    return true;
}

vector<ThreatIndicator> ThreatAnalyzer::getThreats() const {
    return threats;
}

string ThreatAnalyzer::generateReport() {
    if (threats.empty()) {
        return "No significant threats detected in the analyzed logs.";
    }

    // Build summary for LLM
    vector<LogEntry> logs = parser->getEntries();
    string logSummary = buildAnalysisPrompt(logs);

    Utils::logInfo("Sending to OLLAMA for AI-powered analysis...");

    // Get LLM analysis
    OllamaResponse aiResponse = client->analyzeSecurityLogs(logSummary);

    stringstream report;

    // Header
    report << "=== THREAT ANALYSIS REPORT ===\n\n";

    // Pattern-based findings
    report << "PATTERN DETECTION RESULTS:\n";
    report << "Total Threats Detected: " << threats.size() << "\n\n";

    // Group by severity
    map<ThreatLevel, int> severityCounts;
    for (const auto& threat : threats) {
        severityCounts[threat.severity]++;
    }

    report << "Severity Breakdown:\n";
    if (severityCounts[CRITICAL] > 0) report << "  CRITICAL: " << severityCounts[CRITICAL] << "\n";
    if (severityCounts[HIGH] > 0) report << "  HIGH: " << severityCounts[HIGH] << "\n";
    if (severityCounts[MEDIUM] > 0) report << "  MEDIUM: " << severityCounts[MEDIUM] << "\n";
    if (severityCounts[LOW] > 0) report << "  LOW: " << severityCounts[LOW] << "\n";

    report << "\nDetailed Findings:\n";
    for (size_t i = 0; i < threats.size(); i++) {
        const auto& threat = threats[i];
        report << "\n[" << (i + 1) << "] " << threat.type << " - ";

        switch (threat.severity) {
            case CRITICAL: report << "CRITICAL"; break;
            case HIGH: report << "HIGH"; break;
            case MEDIUM: report << "MEDIUM"; break;
            case LOW: report << "LOW"; break;
            case INFO: report << "INFO"; break;
        }

        report << "\n    Description: " << threat.description << "\n";
        if (!threat.relatedLogs.empty()) {
            report << "    Related Log Entries: " << threat.relatedLogs.size() << "\n";
        }
    }

    // AI-powered analysis
    report << "\n\n=== AI-POWERED ANALYSIS ===\n\n";

    if (aiResponse.success) {
        report << aiResponse.content << "\n";
    } else {
        report << "AI analysis unavailable: " << aiResponse.error << "\n";
        report << "Note: Ensure OLLAMA is running (http://localhost:11434)\n";
    }

    return report.str();
}

vector<ThreatIndicator> ThreatAnalyzer::detectBruteForce(const vector<LogEntry>& logs) {
    vector<ThreatIndicator> findings;
    map<string, int> failedLogins;

    // Count failed login attempts
    for (const auto& log : logs) {
        string lowerMsg = log.message;
        transform(lowerMsg.begin(), lowerMsg.end(), lowerMsg.begin(), ::tolower);

        if (lowerMsg.find("failed") != string::npos &&
            (lowerMsg.find("login") != string::npos ||
             lowerMsg.find("password") != string::npos ||
             lowerMsg.find("authentication") != string::npos)) {

            string key = log.source + ":" + log.eventType;
            failedLogins[key]++;
        }
    }

    // Threshold: 3+ failed attempts = potential brute force
    for (const auto& entry : failedLogins) {
        if (entry.second >= 3) {
            ThreatIndicator threat;
            threat.type = "Brute Force Attack";
            threat.severity = (entry.second >= 10) ? CRITICAL : HIGH;
            threat.description = "Detected " + to_string(entry.second) +
                                " failed login attempts from " + entry.first;
            threat.relatedLogs.push_back(entry.first);
            findings.push_back(threat);
        }
    }

    return findings;
}

vector<ThreatIndicator> ThreatAnalyzer::detectPrivilegeEscalation(const vector<LogEntry>& logs) {
    vector<ThreatIndicator> findings;

    for (const auto& log : logs) {
        string lowerMsg = log.message;
        transform(lowerMsg.begin(), lowerMsg.end(), lowerMsg.begin(), ::tolower);

        // Look for privilege-related keywords
        bool hasPrivKeyword = (lowerMsg.find("sudo") != string::npos ||
                              lowerMsg.find("root") != string::npos ||
                              lowerMsg.find("admin") != string::npos ||
                              lowerMsg.find("privilege") != string::npos ||
                              lowerMsg.find("elevated") != string::npos);

        bool hasActionKeyword = (lowerMsg.find("escalat") != string::npos ||
                                lowerMsg.find("gain") != string::npos ||
                                lowerMsg.find("unauthorized") != string::npos);

        if (hasPrivKeyword && hasActionKeyword) {
            ThreatIndicator threat;
            threat.type = "Privilege Escalation Attempt";
            threat.severity = CRITICAL;
            threat.description = "Detected potential privilege escalation: " + log.message.substr(0, 100);
            threat.relatedLogs.push_back(log.timestamp);
            findings.push_back(threat);
        }
    }

    return findings;
}

string ThreatAnalyzer::buildAnalysisPrompt(const vector<LogEntry>& logs) {
    stringstream prompt;

    // Include first 20 logs or all if fewer
    int count = min(20, (int)logs.size());

    for (int i = 0; i < count; i++) {
        const auto& log = logs[i];
        prompt << "[" << log.timestamp << "] "
               << log.severity << " - "
               << log.source << " - "
               << log.message << "\n";
    }

    if (logs.size() > 20) {
        prompt << "\n... and " << (logs.size() - 20) << " more entries\n";
    }

    return prompt.str();
}

bool ThreatAnalyzer::exportToFile(const string& outputPath) {
    if (!Utils::validateFilePath(outputPath)) {
        Utils::logError("Invalid output path");
        return false;
    }

    string report = generateReport();

    ofstream outFile(outputPath);
    if (!outFile.is_open()) {
        Utils::logError("Failed to open output file: " + outputPath);
        return false;
    }

    outFile << report;
    outFile.close();

    Utils::logInfo("Report exported to: " + outputPath);
    return true;
}
