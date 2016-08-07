CC = /usr/local/apache2/bin/apxs
CFLAGS = -g -lm

all: clean module

module:
	$(CC) -i -a -c `pkg-config --cflags --libs jansson openssl libcurl` -lm src/mod_perimeterx.c src/perimeterx.c src/cookie_decoder.c src/http_util.c src/json_util.c 

clean:
	rm -rf *.o
	rm -rf *.out
