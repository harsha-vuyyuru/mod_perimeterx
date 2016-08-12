CC = apxs
CFLAGS = -g -lm

all: clean module

module:
	$(CC) -i -a -Wc,-std=gnu99 -c `pkg-config --cflags --libs jansson openssl libcurl` -lm src/mod_perimeterx.c src/perimeterx.c src/cookie_decoder.c src/http_util.c src/json_util.c 

clean:
	rm -rf src/*.o
	rm -rf src/*.out
	rm -rf src/*.lo
	rm -rf src/*.slo
	rm -rf src/*.la
