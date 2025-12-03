#ifndef THREATANALYZER_H
#define THREATANALYZER_H

#include "LogParser.h"
#include "OllamaClient.h"
#include <string>
#include <vector>

using namespace std;

// Threat severity levels
enum ThreatLevel {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO
};

// Structure for detected threats
struct ThreatIndicator {
    string type;
    ThreatLevel severity;
    string description;
    vector<string> relatedLogs;
};

class ThreatAnalyzer {
private:
    LogParser* parser;
    OllamaClient* client;
    vector<ThreatIndicator> threats;

    // Pattern detection
    vector<ThreatIndicator> detectBruteForce(const vector<LogEntry>& logs);
    vector<ThreatIndicator> detectPrivilegeEscalation(const vector<LogEntry>& logs);

    // Build LLM prompt
    string buildAnalysisPrompt(const vector<LogEntry>& logs);

public:
    ThreatAnalyzer(LogParser* p, OllamaClient* c);
    ~ThreatAnalyzer();

    // Main analysis
    bool analyzeFile(const string& filePath);

    // Get results
    vector<ThreatIndicator> getThreats() const;

    // Generate report
    string generateReport();

    // Export to file
    bool exportToFile(const string& outputPath);
};

#endif
