#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "types.h"

const char *RISK_API_URL = "http://collector.perimeterx.net/api/v1/risk";
const char *CAPTHCA_API_URL = "http://collector.perimeterx.net/api/v1/risk/captcha";
const char *ACTIVITIES_URL = "http://collector.perimeterx.net/api/v1/collector/s2s";

// TODO: change name
struct response_t {
    char* data;
    size_t size;
};

int send_activity(const char* activity, const char* auth_token, request_rec *r, CURL *curl);
risk_response *parse_risk_response(const char* risk_response_str, const request_context *ctx);
captcha_response *parse_captcha_response(const char* captcha_response_str, const request_context *ctx);
char *risk_api_request(const char *risk_payload, const char *auth_header,  request_rec *r, CURL *curl);
char *captcha_validation_request(const char *captcha_payload, const char *auth_header,  request_rec *r, CURL *curl);
char *create_activity(const char *activity_type, const px_config *conf, request_context *ctx);
char *create_captcha_payload(const request_context *ctx, const px_config *conf);

#endif
