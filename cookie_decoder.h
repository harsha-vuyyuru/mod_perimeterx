#ifndef COOKIE_DECODER_H
#define COOKIE_DECODER_H

#include <openssl/hmac.h>

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "http_request.h"
#include "apr_strings.h"

#include "types.h"

validation_result_t validate_cookie(risk_cookie *cookie, request_context *ctx, const char *cookie_key);
risk_cookie *decode_cookie(const char *px_cookie, char *cookie_key, request_context *ctx); // check if request conetxt is needed
void free_cookie(risk_cookie *cookie);

#endif
