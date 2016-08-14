CC = apxs
CFLAGS = -g

all: clean module

module:
	$(CC) -i -a -Wc,-std=gnu99 -c `pkg-config --cflags --libs jansson openssl libcurl` -lm src/mod_perimeterx.c src/perimeterx.c src/cookie_decoder.c src/http_util.c src/json_util.c

mod: mod_perimeterx.c
	$(CC) -i -a -Wc,-std=gnu99 -c `pkg-config --cflags --libs jansson openssl libcurl` mod_perimeterx.c curl_pool.c

b: b.c
	gcc b.c -std=gnu99 -ljansson -ob

clean:
	rm -f src/*.{o,out,lo,slo,la} *.{lo,slo,la} b
