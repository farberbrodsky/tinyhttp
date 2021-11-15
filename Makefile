CC = cc
CCFLAGS = -Wall -g

default:
	@echo "Usage: make example, make lib, make clean"

lib: build/tinyhttp.so
build/tinyhttp.so: build/tinyhttp.o build/tinyhttp_io.o
	$(CC) $(CCFLAGS) -shared -o build/tinyhttp.so build/tinyhttp.o build/tinyhttp_io.o

build/tinyhttp.o: src/tinyhttp.c src/tinyhttp.h src/tinyhttp_io.h src/tinyhttp_client_struct.h
	$(CC) $(CCFLAGS) -fPIC -c src/tinyhttp.c -o build/tinyhttp.o

build/tinyhttp_io.o: src/tinyhttp_io.c src/tinyhttp_io.h src/tinyhttp_client_struct.h
	$(CC) $(CCFLAGS) -fPIC -c src/tinyhttp_io.c -o build/tinyhttp_io.o


example: build/example
build/example: build/example.o build/tinyhttp.so
	$(CC) $(CCFLAGS) build/example.o build/tinyhttp.so -o build/example

build/example.o: src/example.c src/tinyhttp.h src/tinyhttp_io.h src/tinyhttp_client_struct.h
	$(CC) $(CCFLAGS) -c src/example.c -o build/example.o

clean:
	rm -f build/*.o build/tinyhttp.so build/example
