cmake_minimum_required(VERSION 3.10)
project(CISALogAnalyzer VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/include)

# Source files
set(SOURCES
    src/main.cpp
    src/Utils.cpp
    src/LogParser.cpp
    src/OllamaClient.cpp
    src/ThreatAnalyzer.cpp
)

# Create executable
add_executable(log_analyzer ${SOURCES})

# Installation
install(TARGETS log_analyzer DESTINATION bin)
