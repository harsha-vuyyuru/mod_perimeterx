#include <httpd.h>

#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
#include "util_cookies.h"
#endif

#include <curl/curl.h>
#include "apr_strings.h"
#include "httpd.h"
#include "http_protocol.h"

#include "perimeterx.h"
#include "cookie_decoder.h"
#include "http_util.h"
#include "json_util.h"

#define BUF_SIZE 2048
#define BLOCKED_ACTIVITY_TYPE "block"
#define PAGE_REQUESTED_ACTIVITY_TYPE "page_requested"
#define EXT_ARR_SIZE 36

#define INFO(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server_rec, "[mod_perimeterx]: " __VA_ARGS__)

#define ERROR(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server_rec, "[mod_perimeterx]:" __VA_ARGS__)

static bool px_verify_request(request_context *ctx, px_config *conf);
int get_captcha_blocking_page(request_context *ctx, char *buffer);
int get_blocking_page(request_context *ctx, char *buffer);

bool verify_captcha(request_context *ctx, px_config *conf) {
    bool captcha_verified = false;

    if (!ctx->px_captcha) {
        return captcha_verified;
    }

    char *payload = create_captcha_payload(ctx, conf);
    char *response_str = captcha_validation_request(payload, conf->auth_header, ctx->r, ctx->curl);
    if (!response_str) {
        INFO(ctx->r->server, "Failed to perform captcha_validation_request. url: (%s)", ctx->full_url);
        return true;
    }

    captcha_response *c = parse_captcha_response(response_str, ctx);

    if (response_str) {
        free(response_str);
    }

    if (c) {
        captcha_verified = c->status == 0;
        if (!captcha_verified) {
            ctx->vid = NULL;
        }
        INFO(ctx->r->server, "verify_captcha: cookie validation status (%d)", captcha_verified);
    }
    return captcha_verified;
}

request_context* create_context(request_rec *req, const px_config *conf) {
    request_context *ctx;
    const char *px_cookie = NULL;
    const char *px_captcha_cookie = NULL;
    char *captcha_cookie = NULL;
    const char *useragent;
    char *captcha, *vid;

    ctx = (request_context*) apr_pcalloc(req->pool, sizeof(request_context));
    ctx->curl = curl_easy_init();
    curl_easy_setopt(ctx->curl, CURLOPT_TCP_KEEPALIVE, 1l);
    curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT, conf->api_timeout);
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4
    apr_status_t status = ap_cookie_read(req, "_px", &px_cookie, 0);
    status = ap_cookie_read(req, "_pxCaptcha", &px_captcha_cookie, 0);
    if (status == APR_SUCCESS) {
        captcha_cookie = apr_pstrdup(req->pool, px_captcha_cookie);
    }

    // If specific header wes mentiond for ip extraction we will use it
    ctx->ip = conf->ip_header_key ? apr_table_get(req->headers_in, conf->ip_header_key) : req->useragent_ip;
# else
    // If specific header wes mentiond for ip extraction we will use it
    ctx->ip = conf->ip_header_key ? apr_table_get(req->headers_in, conf->ip_header_key) : req->connection->remote_ip;

    char *cookie;
    char *strtok_ctx;

    char *cookies = apr_pstrdup(req->pool, (char *) apr_table_get(req->headers_in, "Cookie"));
    cookie = apr_strtok(cookies, ";", &strtok_ctx);

    while (cookie) {
        char *val_ctx;
        //trim leading space
        if (*cookie == ' ') {
            cookie ++;
        }
        if (strncmp(cookie, "_pxCaptcha", 10) == 0) {
            apr_pstrdup(req->pool, apr_strtok(cookie, "=", &val_ctx));
            captcha_cookie = apr_pstrdup(req->pool, apr_strtok(NULL, "", &val_ctx));
        } else if (strncmp(cookie, "_px", 3) == 0) {
            apr_strtok(cookie, "=", &val_ctx);
            px_cookie = apr_pstrdup(req->pool, apr_strtok(NULL, "", &val_ctx));
        }
        cookie = apr_strtok(NULL, ";", &strtok_ctx);
    }
#endif

    useragent = apr_table_get(req->headers_in, "User-Agent");
    ctx->px_cookie = px_cookie;
    ctx->uri = req->uri;
    ctx->hostname = req->hostname;
    ctx->http_method = req->method;
    ctx->useragent = useragent;
    ctx->full_url = apr_pstrcat(req->pool, req->hostname, req->unparsed_uri, NULL);
    ctx->vid = NULL;

    if (captcha_cookie) {
        char *saveptr;
        ctx->px_captcha = apr_strtok(captcha_cookie, ":", &saveptr);
        ctx->vid = apr_strtok(NULL, "", &saveptr);
        INFO(req->server, "PXCaptcha cookie was found: %s", ctx->px_captcha);
    }

    char *version = NULL;
    char *saveptr;
    char *delim = "/";
    char *protocol_cpy = apr_pstrmemdup(req->pool, req->protocol, strlen(req->protocol));
    apr_strtok(protocol_cpy , delim, &saveptr);
    version =  apr_strtok(NULL, delim, &saveptr);

    ctx->http_version = version;
    ctx->headers = req->headers_in;
    ctx->block_reason = NO_BLOCKING;
    ctx->call_reason = NONE;
    ctx->r = req;

    INFO(req->server, "create_context: useragent: (%s), px_cookie: (%s), full_url: (%s), hostname: (%s) , http_method: (%s), http_version: (%s), uri: (%s), ip: (%s)", ctx->useragent, ctx->px_cookie, ctx->full_url, ctx->hostname, ctx->http_method, ctx->http_version, ctx->uri, ctx->ip);

    return ctx;
}

risk_response* risk_api_get(const request_context *ctx, const px_config *conf, bool expired) {
    char *risk_payload = create_risk_payload(ctx, conf, expired);
    char *risk_response_str = risk_api_request(risk_payload, conf->auth_header, ctx->r, ctx->curl);
    if (risk_response_str == NULL) {
        return NULL;
    }

    INFO(ctx->r->server, "risk_api_get: server response (%s)", risk_response_str);
    risk_response *risk_response = parse_risk_response(risk_response_str, ctx);
    free(risk_response_str);
    return risk_response;
}

void set_call_reason(request_context *ctx, validation_result_t vr) {
    switch(vr) {
        case NULL_COOKIE:
            ctx->call_reason = NO_COOKIE;
            break;
        case INVALID:
            ctx->call_reason = INVALID_COOKIE;
            break;
        case EXPIRED:
            ctx->call_reason = EXPIRED_COOKIE;
            break;
    }
}

static void post_verification(request_context *ctx, px_config *conf, bool request_valid) {
    char *activity = NULL;
    char *activity_type = request_valid ? PAGE_REQUESTED_ACTIVITY_TYPE : BLOCKED_ACTIVITY_TYPE;
    activity = create_activity(activity_type, conf, ctx);
    if (activity_type == BLOCKED_ACTIVITY_TYPE || conf->send_page_activities) {
        if (!send_activity(activity, conf->auth_header, ctx->r, ctx->curl)) {
            ERROR(ctx->r->server, "post_verification: (%s) send failed", activity_type);
        }
    }
}

static bool px_verify_request(request_context *ctx, px_config *conf) {
    bool expired = false;
    bool request_valid = true;
    risk_response *risk_response;

    if (conf->captcha_enabled && ctx->px_captcha) {
        if (verify_captcha(ctx, conf)) {
            post_verification(ctx, conf, true);
            return request_valid;
        }
    }

    validation_result_t vr = NULL_COOKIE;
    risk_cookie *c = decode_cookie(ctx->px_cookie, conf->cookie_key, ctx);
    if (c) {
        ctx->score = c->b_val;
        ctx->vid = c->vid;
        ctx->uuid = c->uuid;
        vr = validate_cookie(c, ctx, conf->cookie_key);
    }
    switch (vr) {
        case VALID:
            request_valid = ctx->score < conf->blocking_score;
            if (!request_valid) {
                ctx->block_reason = COOKIE;
            }
            break;
        case EXPIRED:
            expired = true;
        case NULL_COOKIE:
        case INVALID:
            set_call_reason(ctx, vr);
            risk_response = risk_api_get(ctx, conf, expired);
            if (risk_response) {
                ctx->score = risk_response->score;
                request_valid = ctx->score < conf->blocking_score;
                if (!request_valid) {
                    ctx->block_reason = SERVER;
                }
            } else {
                ERROR(ctx->r->server, "px_verify_request: could not complete risk_api request");
                return true;
            }
            break;
        default:
            ERROR(ctx->r->server, "px_verify_request: cookie decode failed returning valid result (%d)", vr);
            return true;
    }

    post_verification(ctx, conf, request_valid);
    return request_valid;
}

static bool px_should_verify_request(request_rec *r, px_config *conf) {
    static const char* file_ext_whitelist[] = { ".css", ".bmp", ".tif", ".ttf", ".docx", ".woff2", ".js", ".pict", ".tiff", ".eot", ".xlsx", ".jpg", ".csv",
        ".eps", ".woff", ".xls", ".jpeg", ".doc", ".ejs", ".otf", ".pptx", ".gif", ".pdf", ".swf", ".svg", ".ps", ".ico", ".pls", ".midi", ".svgz",
        ".class", ".png", ".ppt", ".mid", "webp", ".jar" };

    if (!conf->module_enabled) {
        return false;
    }

    const char ch = '.';
    const char *file_ending = strchr(r->uri, ch);
    if (!file_ending || strcmp(file_ending, ".html") == 0) {
        return true;
    }
    for (int i = 0; i < EXT_ARR_SIZE; i++ ) {
        if (strcmp(file_ending, file_ext_whitelist[i]) == 0) {
            return false;
        }
    }
    return true;
}

int px_handle_request(request_rec *r, px_config *conf) {
    bool request_valid = true;
    request_context *ctx;

    if (px_should_verify_request(r, conf)) {
        ctx = create_context(r, conf);
        request_valid = px_verify_request(ctx, conf);
        apr_table_set(r->subprocess_env, "SCORE", apr_itoa(r->pool, ctx->score));
        curl_easy_cleanup(ctx->curl);

        if (!request_valid) {
            char *block_page = apr_palloc(r->pool, BUF_SIZE);
            if (conf->captcha_enabled) {
                get_captcha_blocking_page(ctx, block_page);
            } else {
                get_blocking_page(ctx, block_page);
            }
            ap_rprintf(r, "%s", block_page);
# if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 2
            ap_set_content_type(r, "text/html");
# endif
            INFO(r->server, "px_handle_request: request blocked");
            return DONE;
        }
        INFO(r->server, "px_handle_request: request passed");
    }
    return OK;
}

int get_blocking_page(request_context *ctx, char *buffer) {
    return sprintf(buffer, "<html lang=\"en\">\n\
            <head>\n\
            <link type=\"text/css\" rel=\"stylesheet\" media=\"screen, print\" href=\"//fonts.googleapis.com/css?family=Open+Sans:300italic,400italic,600italic,700italic,800italic,400,300,600,700,800\">\n\
            <meta charset=\"UTF-8\">\n\
            <title>Access to This Page Has Been Blocked</title>\n\
            <style> p { width: 60%%; margin: 0 auto; font-size: 35px; } body { background-color: #a2a2a2; font-family: \"Open Sans\"; margin: 5%%; } img { width: 180px; } a { color: #2020B1; text-decoration: blink; } a:hover { color: #2b60c6; } </style>\n\
            </head>\n\
            <body cz-shortcut-listen=\"true\">\n\
            <div><img src=\"http://storage.googleapis.com/instapage-thumbnails/035ca0ab/e94de863/1460594818-1523851-467x110-perimeterx.png\"> </div>\n \
            <span style=\"color: white; font-size: 34px;\">Access to This Page Has Been Blocked</span> \n\
            <div style=\"font-size: 24px;color: #000042;\">\n\
            <br> Access to '%s' is blocked according to the site security policy.<br> Your browsing behaviour fingerprinting made us think you may be a bot. <br> <br> This may happen as a result of the following: \n\
            <ul>\n\
            <li>JavaScript is disabled or not running properly.</li>\n\
            <li>Your browsing behaviour fingerprinting are not likely to be a regular user.</li>\n\
            </ul>\n\
            To read more about the bot defender solution: <a href=\"https://www.perimeterx.com/bot-defender\">https://www.perimeterx.com/bot-defender</a><br> If you think the blocking was done by mistake, contact the site administrator. <br> \n\
            <br><span style=\"font-size: 20px;\">Block Reference: <span style=\"color: #525151;\">#'%s'</span></span> \n\
            </div>\n\
            </body>\n\
            </html>", ctx->full_url, ctx->uuid);
}

int get_captcha_blocking_page(request_context *ctx, char *buffer) {
    return sprintf(buffer, "<html lang=\"en\">\n \
            <head>\n \
            <link type=\"text/css\" rel=\"stylesheet\" media=\"screen, print\" href=\"//fonts.googleapis.com/css?family=Open+Sans:300italic,400italic,600italic,700italic,800italic,400,300,600,700,800\">\n\
            <meta charset=\"UTF-8\">\n \
            <title>Access to This Page Has Been Blocked</title>\n \
            <style> p { width: 60%%; margin: 0 auto; font-size: 35px; } body { background-color: #a2a2a2; font-family: \"Open Sans\"; margin: 5%%; } img { width: 180px; } a { color: #2020B1; text-decoration: blink; } a:hover { color: #2b60c6; } </style>\n \
            <script src=\"https://www.google.com/recaptcha/api.js\"></script> \
            <script> \
            window.px_vid = '%s';\n \
            function handleCaptcha(response) { \n \
            var name = '_pxCaptcha';\n \
            var expiryUtc = new Date(Date.now() + 1000 * 10).toUTCString();\n \
            var cookieParts = [name, '=', response + ':' + window.px_vid, '; expires=', expiryUtc, '; path=/'];\n \
            document.cookie = cookieParts.join('');\n \
            location.reload();\n \
            }\n \
            </script> \n \
            </head>\n \
            <body cz-shortcut-listen=\"true\">\n \
            <div><img src=\"http://storage.googleapis.com/instapage-thumbnails/035ca0ab/e94de863/1460594818-1523851-467x110-perimeterx.png\"> </div>\n \
            <span style=\"color: white; font-size: 34px;\">Access to This Page Has Been Blocked</span> \n \
            <div style=\"font-size: 24px;color: #000042;\">\n \
            <br> Access to '%s' is blocked according to the site security policy.<br> Your browsing behaviour fingerprinting made us think you may be a bot. <br> <br> This may happen as a result of the following: \n \
            <ul>\n \
            <li>JavaScript is disabled or not running properly.</li>\n \
            <li>Your browsing behaviour fingerprinting are not likely to be a regular user.</li>\n \
            </ul>\n \
            To read more about the bot defender solution: <a href=\"https://www.perimeterx.com/bot-defender\">https://www.perimeterx.com/bot-defender</a><br> If you think the blocking was done by mistake, contact the site administrator. <br> \n \
            <div class=\"g-recaptcha\" data-sitekey=\"6Lcj-R8TAAAAABs3FrRPuQhLMbp5QrHsHufzLf7b\" data-callback=\"handleCaptcha\" data-theme=\"dark\"></div>\n \
            <br><span style=\"font-size: 20px;\">Block Reference: <span style=\"color: #525151;\">#' %s '</span></span> \n \
            </div>\n \
            </body>\n \
            </html>", ctx->vid, ctx->full_url, ctx->uuid);
}
