#include <iostream>
#include <string>
#include <memory>
#include "LogParser.h"
#include "OllamaClient.h"
#include "ThreatAnalyzer.h"
#include "Utils.h"

using namespace std;

// Function prototypes
void printBanner();
void printUsage(const char* programName);
bool processLogFile(const string& filePath, const string& modelName, const string& outputFile);

int main(int argc, char* argv[]) {
    printBanner();

    // Parse command line arguments
    string logFilePath;
    string modelName = "llama3";
    string outputFile;

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "-m" || arg == "--model") {
            if (i + 1 < argc) {
                modelName = argv[++i];
            }
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                outputFile = argv[++i];
            }
        } else if (arg[0] != '-') {
            logFilePath = arg;
        }
    }

    // Check if log file specified
    if (logFilePath.empty()) {
        cerr << "Error: No log file specified\n\n";
        printUsage(argv[0]);
        return 1;
    }

    // Validate and process
    if (!Utils::validateFilePath(logFilePath)) {
        cerr << "Error: Invalid file path\n";
        return 1;
    }

    if (!Utils::fileExists(logFilePath)) {
        cerr << "Error: File not found: " << logFilePath << "\n";
        return 1;
    }

    // Process the log file
    bool success = processLogFile(logFilePath, modelName, outputFile);

    if (success) {
        cout << "\n=== Analysis Complete ===\n";
        return 0;
    } else {
        cerr << "\nAnalysis failed!\n";
        return 1;
    }
}

void printBanner() {
    cout << "====================================\n";
    cout << "   CISA Log Analyzer v1.0\n";
    cout << "   Powered by OLLAMA\n";
    cout << "====================================\n\n";
}

void printUsage(const char* programName) {
    cout << "Usage: " << programName << " [options] <log_file>\n\n";
    cout << "Options:\n";
    cout << "  -h, --help              Show this help message\n";
    cout << "  -m, --model <name>      OLLAMA model to use (default: llama3)\n";
    cout << "  -o, --output <file>     Save report to file\n\n";
    cout << "Examples:\n";
    cout << "  " << programName << " samples/security.log\n";
    cout << "  " << programName << " -m mistral samples/security.log\n";
    cout << "  " << programName << " -o report.txt samples/security.log\n";
}

bool processLogFile(const string& filePath, const string& modelName, const string& outputFile) {
    try {
        // Initialize components
        Utils::logInfo("Initializing components...");

        unique_ptr<LogParser> parser = make_unique<LogParser>();

        OllamaConfig config;
        config.model = modelName;
        unique_ptr<OllamaClient> client = make_unique<OllamaClient>(config);

        // Check OLLAMA availability
        cout << "\nChecking OLLAMA service...\n";
        if (!client->isAvailable()) {
            Utils::logWarning("OLLAMA service not available at http://localhost:11434");
            Utils::logWarning("Pattern detection will still run, but AI analysis will be skipped");
            Utils::logWarning("To enable AI analysis: Install OLLAMA and run 'ollama pull " + modelName + "'");
        } else {
            Utils::logInfo("OLLAMA service is available with model: " + modelName);
        }

        // Create analyzer
        ThreatAnalyzer analyzer(parser.get(), client.get());

        // Analyze log file
        cout << "\nAnalyzing log file: " << filePath << "\n";
        cout << "-----------------------------------\n";

        if (!analyzer.analyzeFile(filePath)) {
            Utils::logError("Analysis failed");
            return false;
        }

        // Display threat summary
        auto threats = analyzer.getThreats();
        cout << "\nPattern Detection Results:\n";
        cout << "  Threats Detected: " << threats.size() << "\n";

        // Generate full report
        cout << "\nGenerating detailed report...\n";
        string report = analyzer.generateReport();

        // Output report
        if (outputFile.empty()) {
            cout << "\n" << report << "\n";
        } else {
            if (analyzer.exportToFile(outputFile)) {
                cout << "\nReport saved to: " << outputFile << "\n";
            } else {
                Utils::logError("Failed to save report");
                return false;
            }
        }

        return true;

    } catch (const exception& e) {
        Utils::logError(string("Exception: ") + e.what());
        return false;
    }
}
