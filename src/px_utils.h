#ifndef PX_UTILS_H
#define PX_UTILS_H

#include <http_protocol.h>
#include <apr_pools.h>

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
CURLcode post_request_helper(CURL* curl, const char *url, const char *payload, long connect_timeout, long timeout, px_config *conf, server_rec *server, char **response_data);
CURLcode redirect_helper(CURL* curl, const char *base_url, const char *uri, const char *vid, px_config *conf, request_rec *r, const char **response_data,  apr_array_header_t **response_headers, int *content_size);
size_t write_response_cb(void* contents, size_t size, size_t nmemb, void *stream);
size_t write_response_pool_cb(void* contents, size_t size, size_t nmemb, void *stream);
#endif
