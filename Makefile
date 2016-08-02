CC = gcc
CFLAGS = -g -lm
OBJECTS = client.o

all: clean mod

clean:
	rm -rf *.o
	rm -rf *.out

mod:
	apxs -i -a -c `pkg-config --cflags --libs jansson openssl` -lm -lcurl mod_perimeterx.c cookie_decoder.c
