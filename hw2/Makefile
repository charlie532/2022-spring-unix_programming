CXX = g++
CFLAGS = -g -Wall
SHARED_GLAGS = -shared -fPIC -ldl
EXE_NAME = logger
INJ_NAME = logger.so
SAMPLE = sample

all: $(EXE_NAME) $(INJ_NAME)

$(EXE_NAME): hw2.cpp
	$(CXX) $^ -o $(EXE_NAME) $(CFLAGS)

$(INJ_NAME): logger.c
	$(CXX) $^ -o $(INJ_NAME) $(CFLAGS) $(SHARED_GLAGS)

clean:
	rm -f $(EXE_NAME)
	rm -f $(INJ_NAME)
	rm -f $(SAMPLE)