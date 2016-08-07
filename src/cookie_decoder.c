#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "cookie_decoder.h"

#define ITERATIONS_UPPER_BOUND 10000
#define ITERATIONS_LOWER_BOUND 0

#define INFO(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, server_rec, \
            "[mod_perimeterx]: " __VA_ARGS__)

#define ERROR(server_rec, ...) \
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, server_rec, \
            "[mod_perimeterx]:" __VA_ARGS__)

int decode_base64(char *s, unsigned char **o, int *len, apr_pool_t *p) {
    int l = strlen(s);
    *o = (unsigned char*)apr_palloc(p, (l * 3 + 1));
    BIO *bio = BIO_new_mem_buf(s, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *len = BIO_read(bio, *o, l);
    BIO_free_all(b64);
    return 0;
}

void digest(risk_cookie *cookie, request_context *ctx, const char *cookie_key, const char **signing_fields, int sign_fields_size, char buffer[65]) {
    unsigned char hash[32];

    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);

    int len = 32;

    HMAC_Init_ex(&hmac, cookie_key, strlen(cookie_key), EVP_sha256(), NULL);

    if (cookie->timestamp) {
        HMAC_Update(&hmac, cookie->timestamp, strlen(cookie->timestamp));
    }
    if (cookie->a) {
        HMAC_Update(&hmac, cookie->a, strlen(cookie->a));
    }
    if (cookie->b) {
        HMAC_Update(&hmac, cookie->b, strlen(cookie->b));
    }
    if (cookie->uuid) {
        HMAC_Update(&hmac, cookie->uuid, strlen(cookie->uuid));
    }
    if (cookie->vid) {
        HMAC_Update(&hmac, cookie->vid, strlen(cookie->vid));
    }

    int i;
    for (i = 0; i < sign_fields_size; i++) {
        HMAC_Update(&hmac, signing_fields[i], strlen(signing_fields[i]));
    }

    HMAC_Final(&hmac, hash, &len);

    for(i = 0; i < 32; i++) {
        sprintf(buffer + (i * 2), "%02x", hash[i]);
    }
}

validation_result_t validate_cookie(risk_cookie *cookie, request_context *ctx, const char *cookie_key) {
    if (cookie == NULL) {
        INFO(ctx->r->server, "cookie validation: NO COOKIE");
        return NULL_COOKIE;
    }

    if (cookie->hash == NULL || strlen(cookie->hash) == 0) {
        INFO(ctx->r->server, "cookie validatoin: NO SIGNING");
        return NO_SIGNING;
    }

    struct timeval te;
    gettimeofday(&te, NULL);
    long long currenttime = te.tv_sec * 1000LL + te.tv_usec / 1000;
    if (currenttime > cookie->ts) {
        INFO(ctx->r->server, "cookie validation: COOKIE EXPIRED");
        return EXPIRED;
    }

    char signature[65];
    const char *signing_fields[1] = { ctx->useragent } ;
    digest(cookie, ctx, cookie_key, signing_fields, 1, signature);

    if (memcmp(signature, cookie->hash, 64) != 0) {
        INFO(ctx->r->server, "cookie validation: SIGNATURE INVALID");
        return INVALID;
    }

    INFO(ctx->r->server, "cookie validation: VALID");
    return VALID;
}


risk_cookie *parse_risk_cookie(const char *raw_cookie, request_context *ctx) {

    int a_val, b_val;
    char *hash, *uuid, *vid;
    json_error_t error;
    json_int_t ts;

    json_t *j_cookie = json_loads(raw_cookie, JSON_DECODE_ANY, &error);
    risk_cookie *cookie = (risk_cookie*)apr_palloc(ctx->r->pool, sizeof(risk_cookie));

    json_unpack(j_cookie, "{s:s ,s:s,s:s}", "h", &hash, "v", &vid, "u", &uuid);

    json_t *h = json_object_get(j_cookie, "h");
    json_t *v = json_object_get(j_cookie, "v");
    json_t *t = json_object_get(j_cookie, "t");
    ts = json_integer_value(t);
    json_t *u = json_object_get(j_cookie, "u");
    json_t *s = json_object_get(j_cookie, "s");

    cookie->hash = hash;
    cookie->vid = vid;
    cookie->uuid = uuid;
    cookie->ts = ts;
    int n_digits = floor(log10(cookie->ts)) + 1;
    cookie->timestamp = apr_palloc(ctx->r->pool, (n_digits + 1) * sizeof(char));

    json_unpack(s, "{s:i, s:i}", "a", &a_val, "b", &b_val);

    cookie->a_val = a_val;
    cookie->b_val = b_val;

    cookie->a = apr_psprintf(ctx->r->pool, "%d", a_val);
    cookie->b = apr_psprintf(ctx->r->pool, "%d", a_val);
    cookie->timestamp = apr_psprintf(ctx->r->pool, "%ld", ts);

    INFO(ctx->r->server,"cookie data: timestamp %s, vid %s, uuid %s hash %s scores: a %s b %s", cookie->timestamp, cookie->vid, cookie->uuid, cookie->hash, cookie->a, cookie->b);

    free(h);
    free(v);
    free(t);
    free(u);
    free(s);
    free(j_cookie);

    return cookie;
}

void handle_error(request_context *r_ctx, EVP_CIPHER_CTX *ctx, const char *phase) {
    ERROR(r_ctx->r->server, "Decryption failed in: %s", phase);
    ERR_free_strings();
    EVP_CIPHER_CTX_free(ctx);
}

risk_cookie *decode_cookie(const char *px_cookie, const char *cookie_key, request_context *r_ctx) {

    if (px_cookie == NULL) {
        return NULL;
    }

    ERR_load_crypto_strings();
    char *px_cookie_cpy = apr_pstrmemdup(r_ctx->r->pool, px_cookie, strlen(px_cookie));
    // parse cookie
    char* saveptr;
    const char* delimieter = ":";
    char* encoded_salt = strtok_r(px_cookie_cpy, delimieter, &saveptr);
    int iterations = atoi(strtok_r(NULL, delimieter, &saveptr));
    char* encoded_payload = strtok_r(NULL, delimieter, &saveptr);

    // make sure iteratins is valid and not too big
    if (iterations < ITERATIONS_LOWER_BOUND || iterations > ITERATIONS_UPPER_BOUND) {
        ERROR(r_ctx->r->server,"Stoping cookie decryption: Number of iterations is illegal - %d", iterations);
        return NULL;
    }

    // decode payload
    unsigned char *payload;
    int payload_len;
    decode_base64(encoded_payload, &payload, &payload_len, r_ctx->r->pool);

    // decode salt
    unsigned char *salt;
    int salt_len;
    decode_base64(encoded_salt, &salt, &salt_len, r_ctx->r->pool);

    // pbkdf2
    const int iv_len = 16;
    const int key_len = 32;
    unsigned char *pbdk2_out = (unsigned char*)apr_palloc(r_ctx->r->pool, iv_len + key_len);
    if (PKCS5_PBKDF2_HMAC(cookie_key, strlen(cookie_key), salt, salt_len, iterations, EVP_sha256(),  iv_len + key_len, pbdk2_out) == 0) {
        ERROR(r_ctx->r->server,"PKCS5_PBKDF2_HMAC_SHA256 failed");
        return NULL;
    }
    const unsigned char key[32];
    memcpy((void*)key, pbdk2_out, sizeof(key));

    const unsigned char iv[16];
    memcpy((void*)iv, pbdk2_out+sizeof(key), sizeof(iv));

    // decrypt aes-256-cbc
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_error(r_ctx, ctx, "Init");
        return NULL;
    }
    unsigned char *dpayload = apr_palloc(r_ctx->r->pool, payload_len);
    int len;
    int dpayload_len;
    if (EVP_DecryptUpdate(ctx, dpayload, &len, payload, payload_len) != 1) {
        handle_error(r_ctx, ctx, "Update");
        return NULL;
    }
    dpayload_len = len;
    if (EVP_DecryptFinal_ex(ctx, dpayload + len, &len) != 1) {
        handle_error(r_ctx, ctx, "Final");
        return NULL;
    }

    dpayload_len += len;
    dpayload[dpayload_len] = '\0';

    // parse cookie string to risk struct
    risk_cookie *c = parse_risk_cookie((const char*)dpayload, r_ctx);

    // clean memory
    //EVP_CIPHER_CTX_free(ctx);
    //EVP_cleanup();
    ERR_free_strings();

    return c;
}

