CC = apxs
CFLAGS = -g -lm

all: clean module

module:
	$(CC) -i -a -Wc,-std=gnu99 -c `pkg-config --cflags --libs jansson openssl libcurl` -lm src/mod_perimeterx.c src/perimeterx.c src/cookie_decoder.c src/http_util.c src/json_util.c

b: b.c
	gcc b.c -std=gnu99 -ljansson -lm -ob

clean:
	rm -f src/*.{o,out,lo,slo,la}
