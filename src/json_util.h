#ifndef JSON_UTIL_H
#define JSON_UTIL_H

#include "types.h"

risk_response *parse_risk_response(char* risk_response_str, const request_context *ctx);
captcha_response *parse_captcha_response(char* captcha_response_str, const request_context *ctx);
char *create_activity(char *activity_type, px_config *conf, request_context *ctx);
char *create_risk_payload(const request_context *ctx, const px_config *conf);
char *create_captcha_payload(const request_context *ctx, px_config *conf);

#endif
