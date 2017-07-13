SOURCE=$(wildcard *.c)
OBJECTS=$(subst .c,.o,$(SOURCE))
CFLAGS=-Wall -ggdb

brace: $(OBJECTS)
	$(CC) -o $@ $^

clean:
	rm -f *.o brace

test: brace
	./brace ls -al
