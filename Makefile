CC = apxs
CFLAGS = -g -lm

all: clean module

module:
	$(CC) -i -a -c `pkg-config --cflags --libs jansson` -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lm -lcurl src/mod_perimeterx.c src/cookie_decoder.c src/http_util.c src/json_util.c

clean:
	rm -rf *.o
	rm -rf *.out
