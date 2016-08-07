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
#include "util_cookies.h"

#include "cookie_decoder.h"
#include "http_util.h"
#include "json_util.h"
#include "perimeterx.h"

#ifndef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

#define BLOCKED_ACTIVITY_TYPE "block"
#define PAGE_REQUESTED_ACTIVITY_TYPE "page_requested"
#define EXT_ARR_SIZE 36
#define MODULE_ID "Apache Module v1.0"
#define BUF_SIZE 2048

#define INFO(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server_rec, \
            "[mod_perimeterx]: " __VA_ARGS__)

#define ERROR(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server_rec, \
            "[mod_perimeterx]:" __VA_ARGS__)


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
            "Captcha",
            set_captcha_enabled,
            NULL,
            OR_ALL,
            "Include captcha in the blocking page"),
    AP_INIT_TAKE1("AppID",
            set_app_id,
            NULL,
            OR_ALL,
            "PX Application ID"),
    AP_INIT_TAKE1("CookieKey",
            set_cookie_key,
            NULL,
            OR_ALL,
            "Cookie decryption key"),
    AP_INIT_TAKE1("AuthToken",
            set_auth_token,
            NULL,
            OR_ALL,
            "Risk API auth token"),
    AP_INIT_TAKE1("BlockingScore",
            set_blocking_score,
            NULL,
            OR_ALL,
            "Request with score equal or greater than this will be blocked"),
    AP_INIT_TAKE1("APITimeout",
            set_api_timeout,
            NULL,
            OR_ALL,
            "Set timeout for risk API request"),
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

static int perimeterx_handler(request_rec *r) {
    px_config *conf = ap_get_module_config(r->server->module_config, &perimeterx_module);
    return px_handle_requset(r, conf);
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
