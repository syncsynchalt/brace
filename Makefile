SOURCE=$(wildcard *.c)
OBJECTS=$(patsubst .c, .o, $(SOURCE))
CFLAGS=-Wall -ggdb

brace: $(OBJECTS)
	$(CC) -o $@ $^

clean:
	rm -f *.o brace
