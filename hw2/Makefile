CXX = g++
CFLAGS = -g -Wall
SHARED_GLAGS = -shared -fPIC -ldl
MAIN_NAME = hw2.cpp
EXE_NAME = logger
INJ_NAME = logger.so
SAMPLE = sample

all: $(EXE_NAME) $(INJ_NAME)

$(EXE_NAME): $(MAIN_NAME)
	$(CXX) $^ -o $(EXE_NAME) $(CFLAGS)

$(INJ_NAME): logger.cpp
	$(CXX) $^ -o $(INJ_NAME) $(CFLAGS) $(SHARED_GLAGS)

clean:
	rm -f $(EXE_NAME)
	rm -f $(INJ_NAME)
	rm -f $(SAMPLE)