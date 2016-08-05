#ifndef TYPES_H
#define TYPES_H

#include <stdbool.h>
#include <curl/curl.h>

#define REQ_FAILED 1
#define REQ_SUCCESS 0

typedef struct px_config_t {
    const char *app_id;
    const char *cookie_key;
    const char *auth_token;
    const char *ip_header_key;
    char *auth_header;
    bool module_enabled;
    bool captcha_enabled;
    int blocking_score;
    long api_timeout;
    bool debug_level;
    bool send_page_activities;
    CURL* curl;
    char *module_version;
} px_config;

typedef enum {
    VALID,
    NO_SIGNING,
    EXPIRED,
    INVALID,
    NULL_COOKIE
} validation_result_t;

typedef enum s2s_call_reason_t {
    NONE,
    NO_COOKIE,
    EXPIRED_COOKIE,
    INVALID_COOKIE
} s2s_call_reason_t;

typedef enum {
    NO_BLOCKING,
    COOKIE,
    SERVER
} block_reason_t;

typedef struct risk_cookie_t {
    char *timestamp;
    long ts;
    char *hash;
    char *uuid;
    char *vid;
    char *a;
    char *b;
    int a_val;
    int b_val;
    validation_result_t validation_result;
} risk_cookie;

typedef struct risk_response_t {
    const char* uuid;
    int status;
    int score;
} risk_response;

typedef struct captcha_response_t {
    int status;
    const char *uuid;
    const char *vid;
    const char *cid;
} captcha_response;

typedef struct request_context_t {
    const char *px_cookie;
    const char *px_captcha;
    const char *ip;
    char *vid;
    char * uuid;
    apr_table_t *headers;
    const char *hostname;
    char *uri;
    const char *useragent;
    const char *full_url;
    const char *http_method;
    const char *http_version;
    int   score;
    block_reason_t block_reason;
    s2s_call_reason_t call_reason;
    request_rec *r;
} request_context;

#endif
