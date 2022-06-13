CXX = g++
PROGS = sdb.o
CFLAGS = -g -Wall

hw4: $(PROGS)
	$(CXX) $^ -o $@ $(CFLAGS) -lcapstone

%.o: %.cpp
	$(CXX) $< -c -o $@ $(CFLAGS)

clean:
	rm -f *.o hw4