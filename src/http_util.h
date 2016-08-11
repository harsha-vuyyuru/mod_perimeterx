#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "httpd.h"
#include "types.h"

struct response_t {
    char* data;
    size_t size;
};

bool send_activity(const char* activity, const char* auth_token, request_rec *r, CURL *curl);
char *risk_api_request(char *risk_payload, char *auth_header,  request_rec *r, CURL *curl);
char *captcha_validation_request(char *captcha_payload, char *auth_header,  request_rec *r, CURL *curl);

#endif
