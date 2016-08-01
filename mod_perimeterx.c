#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "http_request.h"

#include "types.h"

#ifndef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

#define BLOCKED_ACTIVITY_TYPE "block"
#define PAGE_REQUESTED_ACTIVITY_TYPE "page_requested"
#define EXT_ARR_SIZE 36
#define MODULE_ID "Apache Module v1.0"

#define INFO(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server_rec, \
            "[mod_perimeterx]: " __VA_ARGS__)

#define ERROR(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server_rec, \
            "[mod_perimeterx]:" __VA_ARGS__)

#include "cookie_decoder.h"
#include "http_client.c"

module AP_MODULE_DECLARE_DATA perimeterx_module;

static bool px_verify_request(request_context *ctx, px_config *conf);

static void *create_dir_config(apr_pool_t *pool, char *dirname);
static void *create_server_config(apr_pool_t *pool, server_rec *s);
static void *create_config(apr_pool_t *pool);

static void perimeterx_register_hooks(apr_pool_t *pool);
static int perimeterx_handler(request_rec *r);

static const char *set_px_enabled(cmd_parms *cmd, void *config, int arg);
static const char *set_captcha_enabled(cmd_parms *cmd, void *config, int arg);
static const char *set_app_id(cmd_parms *cmd, void *config, const char *app_id);
static const char *set_cookie_key(cmd_parms *cmd, void *config, const char *cookie_key);
static const char *set_auth_token(cmd_parms *cmd, void *config, const char *auth_token);
static const char *set_api_timeout(cmd_parms *cmd, void *config, const char *api_timeout);
static const char *set_pagerequest_enabled(cmd_parms *cmd, void *config, int arg);
static const char *set_blocking_score(cmd_parms *cmd, void *config, const char *blocking_score);
static const char *set_ip_header(cmd_parms *cmd, void *config, const char *ip_header);

static const px_config *get_config(cmd_parms *cmd, void *dir_config);

static const command_rec px_directives[] = {
    AP_INIT_FLAG(
            "PXEnabled",
            set_px_enabled,
            NULL,
            OR_ALL,
            "Turn on mod_px"),
    AP_INIT_FLAG(
            "CaptchaEnabled",
            set_captcha_enabled,
            NULL,
            OR_ALL,
            "Turn on mod_px"),
    AP_INIT_TAKE1("AppID",
            set_app_id,
            NULL,
            OR_ALL,
            "PX Application ID"),
    AP_INIT_TAKE1("CookieKey",
            set_cookie_key,
            NULL,
            OR_ALL,
            "PX Application ID"),
    AP_INIT_TAKE1("AuthToken",
            set_auth_token,
            NULL,
            OR_ALL,
            "PX Application ID"),
    AP_INIT_TAKE1("AuthToken",
            set_auth_token,
            NULL,
            OR_ALL,
            "PX Application ID"),
    AP_INIT_TAKE1("BlockingScore",
            set_blocking_score,
            NULL,
            OR_ALL,
            "Request with score equal or greater than this will be blocked"),
    AP_INIT_TAKE1("APITimeout",
            set_api_timeout,
            NULL,
            OR_ALL,
            "Set timeout for server to server request"),
    AP_INIT_FLAG( "ReportPageRequest",
            set_pagerequest_enabled,
            NULL,
            OR_ALL,
            "Enable page_request activities report"),
    AP_INIT_TAKE1( "IPHeader",
            set_ip_header,
            NULL,
            OR_ALL,
            "This header will be used to get the request real IP"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA perimeterx_module =  {
    STANDARD20_MODULE_STUFF,
    create_dir_config,
    NULL,
    create_server_config,
    NULL,
    px_directives,
    perimeterx_register_hooks
};

static void perimeterx_register_hooks(apr_pool_t *pool) {
    // TODO: working after x module
    ap_hook_post_read_request(perimeterx_handler, NULL, NULL, APR_HOOK_LAST);
}

static const char *set_px_enabled(cmd_parms *cmd, void *dir_config, int arg) {
    px_config *conf = (px_config*)get_config(cmd, dir_config);
    if (!conf) {
        return "ERROR in config load";
    }
    conf->module_enabled = arg;

    return NULL;
}

static const px_config *get_config(cmd_parms *cmd, void *dir_config) {
    return cmd->path ?
        dir_config :
        ap_get_module_config(cmd->server->module_config,
                &perimeterx_module);

}

static const char *set_app_id(cmd_parms *cmd, void *dir_config, const char *app_id) {
    px_config *conf = (px_config*)get_config(cmd, dir_config);
    if (!conf) {
        return "ERROR in config load";
    }
    conf->app_id = app_id;

    return NULL;
}

static const char *set_cookie_key(cmd_parms *cmd, void *dir_config, const char *cookie_key) {
    px_config *conf = (px_config*)get_config(cmd, dir_config);
    if (!conf) {
        return "ERROR in config load";
    }
    conf->cookie_key = cookie_key;

    return NULL;
}

static const char *set_auth_token(cmd_parms *cmd, void *dir_config, const char *auth_token) {
    px_config *conf = (px_config*)get_config(cmd, dir_config);
    if (!conf) {
        return "ERROR in config load";
    }
    char *auth_header = apr_pstrcat(cmd->pool, "Authorization: Bearer ", auth_token, NULL);
    conf->auth_header = auth_header;
    conf->auth_token = auth_token;

    return NULL;
}

static const char *set_captcha_enabled(cmd_parms *cmd, void *dir_config, int arg) {
    px_config *conf = (px_config*)get_config(cmd, dir_config);
    if (!conf) {
        return "ERROR in config load";
    }
    conf->captcha_enabled = arg;

    return NULL;
}

static const char *set_pagerequest_enabled(cmd_parms *cmd, void *dir_config, int arg) {
    px_config *conf = (px_config*)get_config(cmd, dir_config);
    if (!conf) {
        return "ERROR in config load";
    }
    conf->send_page_activities = arg;

    return NULL;
}

static const char *set_blocking_score(cmd_parms *cmd, void *dir_config, const char *blocking_score){
    px_config *conf = (px_config*)get_config(cmd, dir_config);
    if (!conf) {
        return "ERROR in config load";
    }
    conf->blocking_score = atoi(blocking_score);

    return NULL;
}

static const char *set_api_timeout(cmd_parms *cmd, void *dir_config, const char *api_timeout) {
    px_config *conf = (px_config*)get_config(cmd, dir_config);
    if (!conf) {
        return "ERROR in config load";
    }
    conf->api_timeout = atoi(api_timeout);
    curl_easy_setopt(conf->curl, CURLOPT_TIMEOUT, conf->api_timeout);

    return NULL;
}

static const char *set_ip_header(cmd_parms *cmd, void *dir_config, const char *ip_header) {
    px_config *conf = (px_config*)get_config(cmd, dir_config);
    if (!conf) {
        return "ERROR in config load";
    }
    conf->ip_header_key = ip_header;

    return NULL;
}

void init_captcha_cookie_and_vid(char *captcha_cookie, request_context *ctx) {

    char *saveptr;

    const char *captcha = apr_strtok(captcha_cookie, ":", &saveptr);
    const char *vid = apr_strtok(NULL, "", &saveptr);

    ctx->px_captcha = (char*) apr_palloc(ctx->r->pool, sizeof(char) * strlen(captcha));
    ctx->vid = (char*) apr_palloc(ctx->r->pool, sizeof(char) * strlen(vid));

    strcpy(ctx->px_captcha, captcha);
    strcpy(ctx->vid, vid);
}

request_context* create_context(request_rec *req, char *ip_header_key) {

    request_context *ctx;
    char *px_cookie;
    char *px_captcha_cookie;
    char *useragent;
    char *captcha, *vid;

    ctx = (request_context*) apr_palloc(req->pool, sizeof(request_context));
    memset(ctx, 0, sizeof(request_context));
    apr_status_t status = ap_cookie_read(req, "_px", &px_cookie, 0);
    INFO(req->server, "PX Cookie: %s", px_cookie);

    if (status != APR_SUCCESS) {
        px_cookie = NULL;
    }

    status = ap_cookie_read(req, "_pxCaptcha", &px_captcha_cookie, 0);
    if (status != APR_SUCCESS) {
        px_captcha_cookie = NULL;
    }

    useragent = apr_table_get(req->headers_in, "User-Agent");
    ctx->px_cookie = px_cookie;
    ctx->uri = req->uri;
    ctx->hostname = req->hostname;
    ctx->http_method = req->method;
    ctx->useragent = useragent;
    // If specific header wes mentiond for ip extraction we will use it
    ctx->ip = ip_header_key ? apr_table_get(req->headers_in, ip_header_key) : req->useragent_ip;

    ctx->full_url = apr_pstrcat(req->pool, req->hostname, req->unparsed_uri, NULL);
    if (px_captcha_cookie) {
        INFO(req->server, "PXCaptcha cookie was found");
        init_captcha_cookie_and_vid(px_captcha_cookie, ctx);
    }

    // TODO: change the way we are handling this, handle null case
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

    return ctx;
}

risk_response* risk_api_verify(const request_context *ctx, const px_config *conf) {
    char *risk_response_str;
    char *risk_payload;
    risk_response *risk_response;

    risk_payload = create_risk_payload(ctx, conf);

    INFO(ctx->r->server, "risk payload: %s", risk_payload);
    risk_response_str = risk_api_request(risk_payload, conf->auth_header, ctx->r->pool, conf->curl);
    if (risk_response_str == NULL) {
        ERROR(ctx->r->server, "risk_api request failed");
        return NULL;
    }

    risk_response = parse_risk_response(risk_response_str, ctx);

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

static bool px_verify_request(request_context *ctx, px_config *conf) {
    risk_response *risk_response;
    char *activity = NULL;

    bool request_valid = true;
    risk_cookie *c = decode_cookie(ctx->px_cookie, conf->cookie_key, ctx);
    validation_result_t vr = validate_cookie(c, ctx, conf->cookie_key);
    switch (vr) {
        case VALID:
            ctx->score = c->b_val;
            ctx->vid = c->vid;
            ctx->uuid = c->uuid;
            request_valid = ctx->score < conf->blocking_score;
            if (!request_valid) {
                ctx->block_reason = COOKIE;
            }
            break;
        case NULL_COOKIE:
        case INVALID:
        case EXPIRED:
            set_call_reason(ctx, vr);
            risk_response = risk_api_verify(ctx, conf);
            if (risk_response) {
                ctx->score = risk_response->score;
                request_valid = ctx->score < conf->blocking_score;
                if (!request_valid) {
                    ctx->block_reason = SERVER;
                }
            } else {
                ERROR(ctx->r->server, "Could not complete risk_api request");
            }
            break;
        default:
            ERROR(ctx->r->server, "Cookie decode failed returning valid result: %d", vr);
            break;
    }

    char *activity_type = request_valid ? PAGE_REQUESTED_ACTIVITY_TYPE : BLOCKED_ACTIVITY_TYPE;
    activity = create_activity(activity_type, conf, ctx);
    if (activity_type == BLOCKED_ACTIVITY_TYPE || conf->send_page_activities) {
        if (send_activity(activity, conf->auth_header, ctx->r, conf->curl) != REQ_SUCCESS) {
            ERROR(ctx->r->server, "Activity: %s send failed", activity_type);
        }
    }

    //apr_table_entry_t h;
    apr_table_entry_t* new_header = (apr_table_entry_t*)apr_array_push(ctx->r->headers_out);
    new_header->key = "X-PX-SCORE";
    new_header->val = apr_itoa(ctx->r->pool, ctx->score);
    return request_valid;
}

bool px_should_handle_request(request_rec *r, px_config *conf) {
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

static int perimeterx_handler(request_rec *r) {
    bool request_valid = true;
    px_config *conf = ap_get_module_config(r->server->module_config, &perimeterx_module);
    if (px_should_handle_request(r, conf)) {
        request_context *ctx = create_context(r, conf->ip_header_key);
        request_valid = px_verify_request(ctx, conf);
        apr_table_set(r->subprocess_env, "SCORE", apr_itoa(r->pool, ctx->score));
    }
    if (!request_valid) {
        apr_table_set(r->subprocess_env, "BLOCK", "true");
        // captcha will go here
    }
    INFO(r->server, "PerimeterX reauest validation result: %s", request_valid ? "VALID" : "INVALID");
    return OK;
}

static void *create_dir_config(apr_pool_t *pool, char *dir_name) {
    return create_config(pool);
}

static void *create_server_config(apr_pool_t *pool, server_rec *s) {
    return create_config(pool);
}

static void *create_config(apr_pool_t *pool) {
    px_config *conf = apr_palloc(pool, sizeof(px_config));
    curl_global_init(CURL_GLOBAL_ALL);
    conf->curl = curl_easy_init();
    curl_easy_setopt(conf->curl, CURLOPT_TCP_KEEPALIVE, 1L);
    conf->module_enabled = false;
    conf->debug_level = false;
    conf->api_timeout = 0L;
    conf->send_page_activities = false;
    conf->blocking_score = 70;
    conf->captcha_enabled = false;
    conf->ip_header_key = NULL;
    conf->module_version = MODULE_ID;
    return conf;
}
