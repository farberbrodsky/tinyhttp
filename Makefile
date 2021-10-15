CC = cc
CCFLAGS = -Wall -g

example: build/example.o build/tinyhttp.o build/tinyhttp_io.o
	$(CC) $(CCFLAGS) build/example.o build/tinyhttp.o build/tinyhttp_io.o -o build/example

build/example.o: src/example.c src/tinyhttp.h src/tinyhttp_io.h src/tinyhttp_client_struct.h
	$(CC) $(CCFLAGS) -c src/example.c -o build/example.o

build/tinyhttp.o: src/tinyhttp.c src/tinyhttp.h src/tinyhttp_io.h src/tinyhttp_client_struct.h
	$(CC) $(CCFLAGS) -c src/tinyhttp.c -o build/tinyhttp.o

build/tinyhttp_io.o: src/tinyhttp_io.c src/tinyhttp_io.h src/tinyhttp_client_struct.h
	$(CC) $(CCFLAGS) -c src/tinyhttp_io.c -o build/tinyhttp_io.o

clean:
	rm -f build/*.o build/tinyhttp build/example
