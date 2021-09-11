CC = cc
CCFLAGS = -Wall

example: build/example.o build/tinyhttp.o
	$(CC) $(CCFLAGS) build/example.o build/tinyhttp.o -o build/example

build/example.o: src/example.c src/tinyhttp.h
	$(CC) $(CCFLAGS) -c src/example.c -o build/example.o

build/tinyhttp.o: src/tinyhttp.c src/tinyhttp.h
	$(CC) $(CCFLAGS) -c src/tinyhttp.c -o build/tinyhttp.o

clean:
	rm -f build/*.o build/tinyhttp build/example
