CXX = g++
CXXFLAGS = -std=c++17 -Wall -Iinclude
TARGET = build/log_analyzer.exe
OBJDIR = build
SRCDIR = src

SOURCES = $(SRCDIR)/main.cpp $(SRCDIR)/Utils.cpp $(SRCDIR)/LogParser.cpp $(SRCDIR)/OllamaClient.cpp $(SRCDIR)/ThreatAnalyzer.cpp
OBJECTS = $(OBJDIR)/main.o $(OBJDIR)/Utils.o $(OBJDIR)/LogParser.o $(OBJDIR)/OllamaClient.o $(OBJDIR)/ThreatAnalyzer.o

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR)/*.o $(TARGET)

.PHONY: all clean
