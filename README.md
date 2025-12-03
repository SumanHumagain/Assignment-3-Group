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
🚧 **In Progress** - Phase 5/10 Complete

