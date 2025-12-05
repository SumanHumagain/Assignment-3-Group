#include "OllamaClient.h"
#include "Utils.h"
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <array>

using namespace std;

OllamaClient::OllamaClient() {}

OllamaClient::OllamaClient(const OllamaConfig& cfg) : config(cfg) {}

OllamaClient::~OllamaClient() {}

bool OllamaClient::isAvailable() {
    try {
        string response = makeHttpRequest("/api/tags", "");
        return !response.empty();
    } catch (...) {
        return false;
    }
}

OllamaResponse OllamaClient::generateCompletion(const string& prompt) {
    OllamaResponse response;

    // Build JSON payload
    stringstream payload;
    payload << "{"
            << "\"model\":\"" << config.model << "\","
            << "\"prompt\":\"" << escapeJson(prompt) << "\","
            << "\"stream\":false"
            << "}";

    try {
        string rawResponse = makeHttpRequest("/api/generate", payload.str());

        if (rawResponse.empty()) {
            response.success = false;
            response.error = "Empty response from OLLAMA";
            return response;
        }

        // Extract response content
        response.content = extractResponseContent(rawResponse);
        response.success = !response.content.empty();

        if (!response.success) {
            response.error = "Failed to extract response content";
        }

    } catch (const exception& e) {
        response.success = false;
        response.error = string("Exception: ") + e.what();
    }

    return response;
}

OllamaResponse OllamaClient::analyzeSecurityLogs(const string& logSummary) {
    stringstream prompt;
    prompt << "You are a cybersecurity analyst. Analyze the following security log entries and provide:\n"
           << "1. Summary of security events\n"
           << "2. Potential threats identified\n"
           << "3. Recommended actions\n"
           << "4. Severity assessment (CRITICAL/HIGH/MEDIUM/LOW)\n\n"
           << "Log entries:\n"
           << logSummary << "\n\n"
           << "Provide a concise security analysis:";

    return generateCompletion(prompt.str());
}

string OllamaClient::makeHttpRequest(const string& endpoint, const string& jsonPayload) {
    // Validate URL to prevent SSRF
    if (!validateUrl(config.baseUrl + endpoint)) {
        Utils::logError("Invalid URL for request");
        return "";
    }

    string url = config.baseUrl + endpoint;
    string response;

    // Use curl for HTTP requests (cross-platform solution)
    // curl is available on Windows 10+ and most Linux systems

    stringstream curlCmd;

    if (jsonPayload.empty()) {
        // GET request
        curlCmd << "curl -s -m " << config.timeout << " " << url;
    } else {
        // POST request with JSON
        // Write payload to temp file to avoid command injection
        string tempFile = "ollama_payload_tmp.json";

        // Sanitize payload before writing
        ofstream tmpOut(tempFile);
        if (!tmpOut.is_open()) {
            Utils::logError("Failed to create temp file for request");
            return "";
        }
        tmpOut << jsonPayload;
        tmpOut.close();

        curlCmd << "curl -s -m " << config.timeout
                << " -X POST " << url
                << " -H \"Content-Type: application/json\""
                << " -d @" << tempFile;
    }

    // Execute curl command and capture output
    array<char, 128> buffer;
    string result;

    FILE* pipe = popen(curlCmd.str().c_str(), "r");
    if (!pipe) {
        Utils::logError("Failed to execute HTTP request");
        if (!jsonPayload.empty()) {
            remove("ollama_payload_tmp.json");
        }
        return "";
    }

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }

    int returnCode = pclose(pipe);

    // Clean up temp file
    if (!jsonPayload.empty()) {
        remove("ollama_payload_tmp.json");
    }

    if (returnCode != 0) {
        Utils::logWarning("HTTP request returned non-zero exit code: " + to_string(returnCode));
    }

    return result;
}

string OllamaClient::escapeJson(const string& input) {
    stringstream escaped;

    for (char c : input) {
        switch (c) {
            case '"':  escaped << "\\\""; break;
            case '\\': escaped << "\\\\"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            default:
                // Skip control characters
                if (c >= 32 && c <= 126) {
                    escaped << c;
                }
                break;
        }
    }

    return escaped.str();
}

string OllamaClient::extractResponseContent(const string& rawResponse) {
    // Extract "response" field from JSON
    // Simple extraction (for production, use a JSON library)

    size_t pos = rawResponse.find("\"response\"");
    if (pos == string::npos) {
        return "";
    }

    // Find the opening quote of the value
    size_t start = rawResponse.find("\"", pos + 10);
    if (start == string::npos) {
        return "";
    }
    start++; // Move past the quote

    // Find the closing quote (accounting for escaped quotes)
    size_t end = start;
    bool escaped = false;

    while (end < rawResponse.length()) {
        if (rawResponse[end] == '\\' && !escaped) {
            escaped = true;
            end++;
            continue;
        }

        if (rawResponse[end] == '"' && !escaped) {
            break;
        }

        escaped = false;
        end++;
    }

    if (end >= rawResponse.length()) {
        return "";
    }

    string content = rawResponse.substr(start, end - start);

    // Unescape JSON characters
    string unescaped;
    for (size_t i = 0; i < content.length(); i++) {
        if (content[i] == '\\' && i + 1 < content.length()) {
            switch (content[i + 1]) {
                case 'n':  unescaped += '\n'; i++; break;
                case 'r':  unescaped += '\r'; i++; break;
                case 't':  unescaped += '\t'; i++; break;
                case '"':  unescaped += '"'; i++; break;
                case '\\': unescaped += '\\'; i++; break;
                default:   unescaped += content[i]; break;
            }
        } else {
            unescaped += content[i];
        }
    }

    return unescaped;
}

bool OllamaClient::validateUrl(const string& url) {
    // Basic URL validation to prevent SSRF attacks

    // Only allow localhost and 127.0.0.1
    if (url.find("http://localhost") != 0 &&
        url.find("http://127.0.0.1") != 0) {
        Utils::logWarning("Blocked non-localhost URL: " + url);
        return false;
    }

    // Check for suspicious characters
    const string dangerous = "|&;$`<>";
    for (char c : dangerous) {
        if (url.find(c) != string::npos) {
            Utils::logWarning("Suspicious character in URL");
            return false;
        }
    }

    return true;
}
