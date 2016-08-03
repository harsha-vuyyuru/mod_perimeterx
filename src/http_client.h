#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "httpd.h"
#include "types.h"

const char *RISK_API_URL = "http://collector.perimeterx.net/api/v1/risk";
const char *CAPTHCA_API_URL = "http://collector.perimeterx.net/api/v1/risk/captcha";
const char *ACTIVITIES_URL = "http://collector.perimeterx.net/api/v1/collector/s2s";

// TODO: change name
struct response_t {
    char* data;
    size_t size;
};

int send_activity(char* activity, char* auth_token, request_rec *r, CURL *curl);
risk_response *parse_risk_response(char* risk_response_str, const request_context *ctx);
captcha_response *parse_captcha_response(char* captcha_response_str, const request_context *ctx);
char *risk_api_request(char *risk_payload, char *auth_header,  request_rec *r, CURL *curl);
char *captcha_validation_request(char *captcha_payload, char *auth_header,  request_rec *r, CURL *curl);
char *create_activity(char *activity_type, px_config *conf, request_context *ctx);
char *create_risk_payload(const request_context *ctx, const px_config *conf);
char *create_captcha_payload(const request_context *ctx, px_config *conf);

#endif
