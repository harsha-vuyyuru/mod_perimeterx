#include <jansson.h>
#include <jansson_config.h>

#include "json_util.h"

json_t *header_to_json(const char *key, const char *value);
json_t *headers_to_json(const apr_array_header_t *arr);
void free_headers_json(json_t *j_headers);

static const char *s2s_call_reason_string(s2s_call_reason_t r) {
    static const char *call_reasons[] = { "none", "no_cookie", "expired_cookie", "invalid_cookie"};
    return call_reasons[r];
}

static const char *block_reason_string(block_reason_t r) {
    static const char *block_reason[] = { "none", "cookie_high_score", "s2s_high_score" };
    return block_reason[r];
}

char *create_captcha_payload(const request_context *ctx, px_config *conf) {
    json_t *j_vid = NULL, *j_pxcaptcha = NULL, *j_hostname = NULL;

    json_t *root = json_object();
    json_t *request = json_pack("{s:s, s:s , s:s}", "ip", ctx->ip, "uri", ctx->uri, "url", ctx->full_url);
    const apr_array_header_t *header_arr = apr_table_elts(ctx->headers);
    json_t *j_headers = headers_to_json(header_arr);
    json_object_set(request, "headers", j_headers);
    json_object_set(root, "request", request);

    if (ctx->vid) {
        j_vid = json_string(ctx->vid);
        json_object_set(root, "vid", j_vid);
    }
    if (ctx->px_captcha) {
        j_pxcaptcha = json_string(ctx->px_captcha);
        json_object_set(root, "pxCaptcha", j_pxcaptcha);
    }
    if (ctx->hostname) {
        j_hostname = json_string(ctx->hostname);
        json_object_set(root, "hostname", j_hostname);
    }

    char *payload = json_dumps(root, JSON_ENCODE_ANY);

    if (j_vid) {
        free(j_vid);
    }
    if (j_hostname) {
        free(j_hostname);
    }
    if (j_pxcaptcha) {
        free(j_pxcaptcha);
    }

    free(root);
    free_headers_json(j_headers);
    free(j_headers);
    free(request);

    return payload;
}

char *create_risk_payload(const request_context *ctx, const px_config *conf, bool cookie_expired) {
    json_t *j_headers, *j_data, *request, *j_header, *j_uuid = NULL, *j_vid = NULL, *j_additional, *j_px_cookie = NULL;

    j_data = json_pack("{s:s,s:s,s:s}" , "ip", ctx->ip, "uri", ctx->uri, "url", ctx->full_url);
    request = json_object();

    const apr_array_header_t *header_arr = apr_table_elts(ctx->headers);
    j_headers = headers_to_json(header_arr);
    json_object_set(request, "request", j_data);
    json_object_set(j_data, "headers", j_headers);

    if (cookie_expired && ctx->uuid) {
        j_uuid = json_string(j_uuid);
        json_object_set(request, "uuid", j_uuid);
    }

    j_additional = json_pack("{s:s, s:s, s:s, s:s}", "s2s_call_reason", s2s_call_reason_string(ctx->call_reason), "http_method", ctx->http_method, "http_version", ctx->http_version, "module_version", conf->module_version);
    json_object_set(request, "additional", j_additional);

    if (ctx->px_cookie) {
        j_px_cookie = json_string(ctx->px_cookie);
        json_object_set(j_additional, "px_cookie", j_px_cookie);
    }
    if (ctx->vid) {
        j_vid = json_string(ctx->vid);
        json_object_set(j_data, "vid", j_vid);
    }

    char *request_str = json_dumps(request, JSON_ENCODE_ANY);

    if (j_uuid) {
        free(j_uuid);
    }
    if (j_vid) {
        free(j_vid);
    }
    if (j_px_cookie) {
        free(j_px_cookie);
    }

    free_headers_json(j_headers);
    free(j_headers);
    free(j_data);
    free(j_additional);
    free(request);

    return request_str;
}

char *create_activity(const char *activity_type, px_config *conf, request_context *ctx) {
    apr_table_entry_t h;
    json_t *j_vid = NULL, *j_uuid = NULL, *j_headers;
    // TODO: headers could be generated only once and saved on the struct
    const apr_array_header_t *header_arr = apr_table_elts(ctx->headers);

    json_t *activity = json_pack("{s:s, s:s, s:s, s:s}", "type", activity_type, "socket_ip", ctx->ip, "url", ctx->full_url, "px_app_id", conf->app_id);

    if (ctx->vid) {
        j_vid = json_string(ctx->vid);
        json_object_set(activity, "vid", j_vid);
    }

    json_t *details = json_pack("{s:i, s:s, s:s, s:s, s:s}", "block_score", ctx->score, "block_reason", block_reason_string(ctx->block_reason), "http_method", ctx->http_method, "http_version", ctx->http_version, "module_version", conf->module_version);

    if (activity_type == "block" && ctx->uuid) {
        j_uuid = json_string(ctx->uuid);
        json_object_set(details, "block_uuid", j_uuid);
    }

    json_object_set(activity, "details", details);

    j_headers = json_object();
    void **ptrs = apr_palloc(ctx->r->pool, sizeof(void*) *header_arr->nelts);
    int i;
    // Extract all headers and jsonfy it
    for (i = 0; i < header_arr->nelts; i++) {
        h = APR_ARRAY_IDX(header_arr, i, apr_table_entry_t);
        json_t *j_header = json_string(h.val);
        json_object_set(j_headers, h.key, j_header);
        ptrs[i] = j_header;
    }

    header_arr = apr_table_elts(ctx->headers);
    json_object_set(activity, "headers", j_headers);
    char *request_str = json_dumps(activity, JSON_ENCODE_ANY);

    if (j_vid) {
        free(j_vid);
    }
    if (j_uuid) {
        free(j_uuid);
    }
    for (i = 0; i < header_arr->nelts; i++) {
        free(ptrs[i]);
    }
    free(j_headers);
    free(details);
    free(activity);
    return request_str;
}

captcha_response *parse_captcha_response(char* captcha_response_str, const request_context *ctx) {
    json_error_t j_error;

    json_t *j_response = json_loads(captcha_response_str, JSON_DECODE_ANY, &j_error);

    captcha_response *parsed_response = (captcha_response*)apr_palloc(ctx->r->pool, sizeof(captcha_response));

    json_t *j_uuid = json_object_get(j_response, "uuid");
    json_t *j_status = json_object_get(j_response, "status");
    json_t *j_vid = json_object_get(j_response, "vid");
    json_t *j_cid = json_object_get(j_response, "cid");

    parsed_response->uuid = json_string_value(j_uuid);
    parsed_response->status = json_integer_value(j_status);
    parsed_response->vid = json_string_value(j_vid);
    parsed_response->cid = json_string_value(j_cid);

    return parsed_response;
}

risk_response* parse_risk_response(char* risk_response_str, const request_context *ctx) {
    json_error_t j_error;

    // TODO : check error
    json_t *j_response = json_loads(risk_response_str, JSON_DECODE_ANY, &j_error);

    risk_response *parsed_response = (risk_response*)apr_palloc(ctx->r->pool, sizeof(risk_response));

    json_t *j_uuid = json_object_get(j_response, "uuid");
    json_t *j_status = json_object_get(j_response, "status");
    json_t *j_scores = json_object_get(j_response, "scores");
    json_t *j_non_human = json_object_get(j_scores, "non_human");

    parsed_response->uuid = json_string_value(j_uuid);
    parsed_response->status = json_integer_value(j_status);
    parsed_response->score = json_integer_value(j_non_human);

    free(j_response);
    free(j_non_human);
    free(j_scores);
    free(j_status);
    free(j_uuid);

    return parsed_response;
}

json_t *header_to_json(const char *key, const char *value) {
    json_t *h = json_object();
    json_t *j_key = json_string(key);
    json_t *j_value = json_string(value);
    json_object_set(h, "name", j_key);
    json_object_set(h, "value", j_value);
    return h;
}

json_t *headers_to_json(const apr_array_header_t *arr) {
    int i;
    json_t *j_headers;
    apr_table_entry_t h;
    json_t *j_header;

    j_headers = json_array();
    // Extract all headers and jsonfy it
    for (i = 0; i < arr->nelts; i++) {
        h = APR_ARRAY_IDX(arr, i, apr_table_entry_t);
        j_header = header_to_json(h.key, h.val);
        json_array_append(j_headers, j_header);
    }

    return j_headers;
}

void free_headers_json(json_t *j_headers) {
    size_t index;
    json_t *value;

    // Free all headers
    json_array_foreach(j_headers, index, value) {
        free(value);
    }
}

