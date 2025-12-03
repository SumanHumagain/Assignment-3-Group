#ifndef OLLAMACLIENT_H
#define OLLAMACLIENT_H

#include <string>

using namespace std;

// Configuration for OLLAMA
struct OllamaConfig {
    string baseUrl;
    string model;
    int timeout;

    OllamaConfig() {
        baseUrl = "http://localhost:11434";
        model = "llama3";
        timeout = 30;
    }
};

// API Response
struct OllamaResponse {
    bool success;
    string content;
    string error;
};

class OllamaClient {
private:
    OllamaConfig config;

    // HTTP request helper
    string makeHttpRequest(const string& endpoint, const string& payload);

public:
    OllamaClient();
    explicit OllamaClient(const OllamaConfig& cfg);
    ~OllamaClient();

    // Check if service is available
    bool isAvailable();

    // Generate completion from prompt
    OllamaResponse generateCompletion(const string& prompt);

    // Analyze security logs
    OllamaResponse analyzeSecurityLogs(const string& logSummary);
};

#endif
