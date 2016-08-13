#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>

#include <jansson.h>

#define DEFAULT_ITERATIONS 1000000

struct timespec timer;

void timer_begin(const char *test) {
  printf("[\x1b[32mBEGIN\x1b[00m] %s\n", test);
  clock_gettime(CLOCK_REALTIME, &timer);
}

void timer_end(void) {
  struct timespec endTimer;
  clock_gettime(CLOCK_REALTIME, &endTimer);
  double begin_time = timer.tv_sec + (timer.tv_nsec / 1000000000.0);
  double end_time = endTimer.tv_sec + (endTimer.tv_nsec / 1000000000.0);
  printf("[\x1b[31mEND\x1b[00m] took \x1b[34m%0.12f\x1b[00m seconds\n\n", end_time - begin_time);
}

#define BENCH(n, x) \
  do { \
    timer_begin(n); \
    for (int benchIter = 0; benchIter < DEFAULT_ITERATIONS; ++benchIter) { x; } \
    timer_end(); \
  } while (0);


static const char *raw_cookie = "{\"v\":\"1\",\"u\":\"2\",\"s\":{\"a\":10,\"b\":20},\"t\":3,\"h\":\"4\"}";

int parse_cookie() {
    json_error_t error;
    json_t *j_cookie = json_loads(raw_cookie, 0, &error);
    if (!j_cookie) {
        fprintf(stderr, "cookie data: parse failed with error. raw_cookie (%s), text (%s)\n", raw_cookie, error.text);
        return -1;
    }
    const char *vid = NULL;
    const char *uuid = NULL;
    int a_val = 0;
    int b_val = 0;
    int ts = 0;
    const char *hash = NULL;
    if (json_unpack(j_cookie, "{s:s,s:s,s:{s:i,s:i},s:i,s:s}", "v", &vid, "u", &uuid, "s", "a", &a_val, "b", &b_val, "t", &ts, "h", &hash)) {
        fprintf(stderr, "cookie data: unpack json failed.\n");
        json_decref(j_cookie);
        return -2;
    }
    json_decref(j_cookie);
    return 0;
}

int parse_cookie2() {
    json_error_t error;
    json_t *j_cookie = json_loads(raw_cookie, 0, &error);
    if (!j_cookie) {
        fprintf(stderr, "cookie data: parse failed with error. raw_cookie (%s), text (%s)\n", raw_cookie, error.text);
        return -1;
    }

    const char *vid = NULL;
    const char *uuid = NULL;
    int a_val = 0;
    int b_val = 0;
    long long ts = 0;
    const char *hash = NULL;

    bool valid = true;
    const char *key, *skey;
    json_t *value, *svalue;
    json_t *scores;
    json_object_foreach(j_cookie, key, value) {
        if (strcmp(key, "v") == 0) {
            if (!json_is_string(value)) {
                valid = false;
                break;
            }
            vid = json_string_value(value);
        } else if (strcmp(key, "u") == 0) {
            if (!json_is_string(value)) {
                valid = false;
                break;
            }
            uuid = json_string_value(value);
        } else if (strcmp(key, "s") == 0) {
            if (!json_is_object(value)) {
                valid = false;
                break;
            }
            scores = value;
            json_object_foreach(scores, skey, svalue) {
                if (strcmp(skey, "a") == 0) {
                   if (!json_is_integer(svalue)) {
                       valid = false;
                       break;
                   }
                   a_val = json_integer_value(svalue);
                } else if (strcmp(skey, "b") == 0) {
                    if (!json_is_integer(svalue)) {
                        valid = false;
                        break;
                    }
                    b_val = json_integer_value(svalue);
                }
            }
        } else if (strcmp(key, "t") == 0) {
            if (!json_is_integer(value)) {
                value = false;
                break;
            }
            ts = json_integer_value(value);
        } else if (strcmp(key, "h") == 0) {
            if (!json_is_string(value)) {
                value = false;
                break;
            }
            hash = json_string_value(value);
        }
    }
    if (!valid) {
        fprintf(stderr, "cookie data: invalid cookie format\n");
        json_decref(j_cookie);
        return -2;
    }
    json_decref(j_cookie);
    return 0;
}

int parse_cookie3() {
    json_error_t error;
    json_t *j_cookie = json_loads(raw_cookie, 0, &error);
    if (!j_cookie) {
        fprintf(stderr, "cookie data: parse failed with error. raw_cookie (%s), text (%s)\n", raw_cookie, error.text);
        return -1;
    }


    json_t *j_vid = json_object_get(j_cookie, "v");
    if (!json_is_string(j_vid)) {
        json_decref(j_cookie);
        return -2;
    }
    json_t *j_uuid = json_object_get(j_cookie, "u");
    if (!json_is_string(j_uuid)) {
        json_decref(j_cookie);
        return -2;
    }
    json_t *j_hash = json_object_get(j_cookie, "h");
    if (!json_is_string(j_hash)) {
        json_decref(j_cookie);
        return -2;
    }
    json_t *j_scores = json_object_get(j_cookie, "s");
    if (!json_is_object(j_scores)) {
        json_decref(j_cookie);
        return -2;
    }
    json_t *j_val_a = json_object_get(j_scores, "a");
    if (!json_is_integer(j_val_a)) {
        json_decref(j_cookie);
        return -2;
    }
    json_t *j_val_b = json_object_get(j_scores, "b");
    if (!json_is_integer(j_val_b)) {
        json_decref(j_cookie);
        return -2;
    }
    json_t *j_ts = json_object_get(j_cookie, "t");
    if (!json_is_integer(j_ts)) {
        json_decref(j_cookie);
        return -2;
    }

    const char *vid = json_string_value(j_vid);
    const char *uuid = json_string_value(j_uuid);
    int a_val = json_integer_value(j_val_a);
    int b_val = json_integer_value(j_val_b);
    long long ts = json_integer_value(j_ts);
    const char *hash = json_string_value(j_hash);

    json_decref(j_cookie);
    return 0;
}

int main() {
    BENCH("parse cookie v1", parse_cookie());
    BENCH("parse cookie v2", parse_cookie2());
    BENCH("parse cookie v3", parse_cookie3());
    return 0;
}
