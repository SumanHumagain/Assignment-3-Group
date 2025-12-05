# CISA Cybersecurity Log Analyzer

**CSC-7309-001 - Assignment #3 - Group Project**

## Team Members
- Suman Humagain

## Project Overview
A cybersecurity analyst utility that leverages local LLM models via OLLAMA to analyze security logs, detect threats, and generate AI-powered summaries.

## Prerequisites

### OLLAMA Installation
This project requires OLLAMA to be installed and running locally.

**Download OLLAMA:**
- **Windows/Mac/Linux:** https://ollama.com/download

**After Installation:**
```bash
# Pull a model (required):
ollama pull llama3        # Recommended (4.7GB)
# OR
ollama pull mistral       # Alternative (4.1GB)
# OR
ollama pull llama3.2      # Smaller option (2GB)

# Verify installation:
ollama --version
curl http://localhost:11434/api/tags
```

### Build Tools
- C++ compiler (GCC/MSVC/Clang) with C++17 support
- CMake 3.10 or higher

## Development Status
✅ **Complete** - All 10 Phases Finished

## Features
- ✅ Multi-format log parsing (Syslog, CSV, JSON)
- ✅ Pattern-based threat detection
- ✅ Brute force attack detection
- ✅ Privilege escalation detection
- ✅ AI-powered analysis via OLLAMA
- ✅ Secure input validation and sanitization
- ✅ Modular C++ design with headers
- ✅ Command-line interface
- ✅ Report export functionality

## Project Structure
```
Assignment 3 Group/
├── include/              # Header files
│   ├── Utils.h          # Utilities and security functions
│   ├── LogParser.h      # Multi-format log parser
│   ├── OllamaClient.h   # OLLAMA API integration
│   └── ThreatAnalyzer.h # Threat detection engine
├── src/                 # Implementation files
│   ├── main.cpp         # Main program
│   ├── Utils.cpp
│   ├── LogParser.cpp
│   ├── OllamaClient.cpp
│   └── ThreatAnalyzer.cpp
├── samples/             # Sample log files
│   ├── security.log     # Syslog format sample
│   ├── firewall.csv     # CSV format sample
│   └── test_simple.log  # Simple test file
├── CMakeLists.txt       # CMake build configuration
├── Makefile             # Make build configuration
└── build.bat            # Windows build script
```

## Quick Start

### Build the Project
```bash
# Compile (one command)
g++ -std=c++17 -Iinclude src/*.cpp -o log_analyzer.exe
```

**Note:** This creates `log_analyzer.exe` in the current directory.

### How to Run the Program

**IMPORTANT:** This is a command-line tool. Do NOT double-click the .exe file!

**Open a terminal** (Command Prompt, PowerShell, or Git Bash) and run:

```bash
# Show help and usage
./log_analyzer.exe -h

# Analyze a log file (output to screen)
./log_analyzer.exe samples/security.log

# Save report to file (recommended)
./log_analyzer.exe -o report.txt samples/security.log

# Use different OLLAMA model
./log_analyzer.exe -m mistral samples/firewall.csv

# Analyze CSV format logs
./log_analyzer.exe samples/firewall.csv
```

**Why does double-clicking not work?**
- The program requires a log file path as input
- Without arguments, it shows an error and exits immediately
- Always run from terminal with proper arguments

## Usage Examples

**Example 1: Basic Analysis**
```bash
./log_analyzer samples/security.log
```
Output: Displays threat analysis with pattern detection and AI insights

**Example 2: Export Report**
```bash
./log_analyzer -o threat_report.txt samples/security.log
```
Output: Saves full analysis report to threat_report.txt

**Example 3: Custom Model**
```bash
./log_analyzer -m llama3.2 samples/firewall.csv
```
Output: Uses smaller llama3.2 model for faster analysis

## Security Features Implemented

1. **Input Validation**
   - Path traversal prevention
   - Command injection protection
   - Buffer overflow protection
   - Special character filtering

2. **Secure Coding Practices**
   - Input sanitization on all user data
   - SSRF prevention in HTTP client
   - JSON injection protection
   - Resource management (RAII, smart pointers)
   - Exception handling throughout

3. **Threat Detection**
   - Brute force attack detection
   - Privilege escalation attempts
   - Failed login pattern analysis
   - Suspicious activity flagging

## Testing

Sample log files are provided in `samples/` directory:
- `security.log` - Contains brute force and privilege escalation attempts
- `firewall.csv` - CSV format with various security events
- `test_simple.log` - Basic test file

Expected output: The tool should detect multiple HIGH and CRITICAL threats in security.log

