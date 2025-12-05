@echo off
echo Building CISA Log Analyzer...
echo.

if not exist build mkdir build

echo Compiling Utils.cpp...
g++ -std=c++17 -Iinclude -c src/Utils.cpp -o build/Utils.o
if errorlevel 1 goto error

echo Compiling LogParser.cpp...
g++ -std=c++17 -Iinclude -c src/LogParser.cpp -o build/LogParser.o
if errorlevel 1 goto error

echo Compiling OllamaClient.cpp...
g++ -std=c++17 -Iinclude -c src/OllamaClient.cpp -o build/OllamaClient.o
if errorlevel 1 goto error

echo Compiling ThreatAnalyzer.cpp...
g++ -std=c++17 -Iinclude -c src/ThreatAnalyzer.cpp -o build/ThreatAnalyzer.o
if errorlevel 1 goto error

echo Compiling main.cpp...
g++ -std=c++17 -Iinclude -c src/main.cpp -o build/main.o
if errorlevel 1 goto error

echo Linking...
g++ -o build/log_analyzer.exe build/main.o build/Utils.o build/LogParser.o build/OllamaClient.o build/ThreatAnalyzer.o
if errorlevel 1 goto error

echo.
echo Build successful! Executable: build\log_analyzer.exe
goto end

:error
echo.
echo Build failed!
exit /b 1

:end
