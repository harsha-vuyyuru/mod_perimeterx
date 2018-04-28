#ifndef PX_UTILS_H
#define PX_UTILS_H

#include <http_protocol.h>
#include <apr_pools.h>
#include <http_log.h>
#include "px_types.h"

struct response_t {
    char* data;
    size_t size;
    server_rec *server;
    request_rec *r;
    apr_array_header_t *headers;
    const char *app_id;
    apr_pool_t *pool;
};

const char *get_request_ip(const request_rec *r, const px_config *conf);
const char *pescape_urlencoded(apr_pool_t *p, const char *str);
int extract_payload_from_header(apr_pool_t *pool, apr_table_t *headers, const char **payload3, const char **payload1);
CURLcode post_request_helper(CURL* curl, const char *url, const char *payload, long timeout, px_config *conf, server_rec *server, char **response_data);
CURLcode redirect_helper(CURL* curl, const char *base_url, const char *uri, const char *vid, px_config *conf, request_rec *r, const char **response_data,  apr_array_header_t **response_headers, int *content_size);
size_t write_response_cb(void* contents, size_t size, size_t nmemb, void *stream);
size_t write_response_pool_cb(void* contents, size_t size, size_t nmemb, void *stream);

/* Logging */
#define LOGGER_ERROR_HDR "[PerimeterX - ERROR][%s] - %s: "
#define LOGGER_DEBUG_HDR "[PerimeterX - DEBUG][%s] - %s: "


// logging macros (not thread-safe !)
#define px_log(log_debug, level, fmt, ...) \
    do { \
        if (!conf->px_debug && log_debug) { \
            break; \
        } \
        ap_log_error(APLOG_MARK, conf->px_debug ? level : conf->log_level_err, 0, conf->server, \
            log_debug ? LOGGER_DEBUG_HDR # fmt : LOGGER_ERROR_HDR # fmt, conf->app_id, __FUNCTION__, __VA_ARGS__); \
    } while(0)
#define px_log_error(...) px_log(0, conf->log_level_err, "%s", __VA_ARGS__)
#define px_log_error_fmt(fmt, ...) px_log(0, conf->log_level_err, fmt, __VA_ARGS__)
#define px_log_debug(...) px_log(1, conf->log_level_debug, "%s", __VA_ARGS__)
#define px_log_debug_fmt(fmt, ...) px_log(1, conf->log_level_debug, fmt, __VA_ARGS__)

// logging macros (thread-safe)
#define px_log_thd(log_debug, level, fmt, ...) \
    do { \
        if (conf && conf->remote_config_lock) {  \
            apr_thread_rwlock_rdlock(conf->remote_config_lock); \
        } \
        px_log(log_debug, level, fmt, __VA_ARGS__); \
        if (conf && conf->remote_config_lock) {  \
            apr_thread_rwlock_unlock(conf->remote_config_lock); \
        } \
    } while(0)
#define px_log_error_thd(...) px_log_thd(0, conf->log_level_err, "%s", __VA_ARGS__)
#define px_log_error_thd_fmt(fmt, ...) px_log_thd(0, conf->log_level_err, fmt, __VA_ARGS__)
#define px_log_debug_thd(...) px_log_thd(1, conf->log_level_debug, "%s", __VA_ARGS__)
#define px_log_debug_thd_fmt(fmt, ...) px_log_thd(1, conf->log_level_debug, fmt, __VA_ARGS__)

#endif
