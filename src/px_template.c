#include "px_template.h"
#include <http_log.h>
#include <apr_strings.h>

#include "px_types.h"
#include "mustach.h"
#include "px_json.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(perimeterx);
#endif

static const char *block_page_template = "<!DOCTYPE html> <html lang=\"en\"> <head> <meta charset=\"utf-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> <title>Access to this page has been denied.</title> <link href=\"https://fonts.googleapis.com/css?family=Open+Sans:300\" rel=\"stylesheet\"> <style> html, body { margin: 0; padding: 0; font-family: 'Open Sans', sans-serif; color: #000; } a { color: #c5c5c5; text-decoration: none; } .container { align-items: center; display: flex; flex: 1; justify-content: space-between; flex-direction: column; height: 100%; } .container > div { width: 100%; display: flex; justify-content: center; } .container > div > div { display: flex; width: 80%; } .customer-logo-wrapper { padding-top: 2rem; flex-grow: 0; background-color: #fff; visibility: {{logoVisibility}}; } .customer-logo { border-bottom: 1px solid #000; } .customer-logo > img { padding-bottom: 1rem; max-height: 50px; max-width: 100%; } .page-title-wrapper { flex-grow: 2; } .page-title { flex-direction: column-reverse; } .content-wrapper { flex-grow: 5; } .content { flex-direction: column; } .page-footer-wrapper { align-items: center; flex-grow: 0.2; background-color: #000; color: #c5c5c5; font-size: 70%; } @media (min-width: 768px) { html, body { height: 100%; } } </style> <!-- Custom CSS --> {{#cssRef}} <link rel=\"stylesheet\" type=\"text/css\" href=\"{{cssRef}}\"/> {{/cssRef}} </head> <body> <section class=\"container\"> <div class=\"customer-logo-wrapper\"> <div class=\"customer-logo\"> <img src=\"{{customLogo}}\" alt=\"Logo\"/> </div> </div> <div class=\"page-title-wrapper\"> <div class=\"page-title\"> <h1>Please verify you are a human</h1> </div> </div> <div class=\"content-wrapper\"> <div class=\"content\"> <div id=\"px-captcha\"> </div> <p> Access to this page has been denied because we believe you are using automation tools to browse the website. </p> <p> This may happen as a result of the following: </p> <ul> <li> Javascript is disabled or blocked by an extension (ad blockers for example) </li> <li> Your browser does not support cookies </li> </ul> <p> Please make sure that Javascript and cookies are enabled on your browser and that you are not blocking them from loading. </p> <p> Reference ID: #{{refId}} </p> </div> </div> <div class=\"page-footer-wrapper\"> <div class=\"page-footer\"> <p> Powered by <a href=\"https://www.perimeterx.com/whywasiblocked\">PerimeterX</a> , Inc. </p> </div> </div> </section> <!-- Px --> <script> window._pxAppId = '{{appId}}'; window._pxJsClientSrc = '{{{jsClientSrc}}}'; window._pxFirstPartyEnabled = {{firstPartyEnabled}}; window._pxVid = '{{vid}}'; window._pxUuid = '{{uuid}}'; window._pxHostUrl = '{{{hostUrl}}}'; </script> <script src=\"{{{blockScript}}}\"></script> <!-- Custom Script --> {{#jsRef}} <script src=\"{{jsRef}}\"></script> {{/jsRef}} </body> </html>";

static const char *visible = "visible";
static const char *hidden = "hidden";
static const char *collector_url = "https://collector-%s.perimeterx.net";
static const char *LOGGER_DEBUG_FORMAT = "[PerimeterX - DEBUG][%s] - %s"; 

typedef struct px_props_t {
    int depth;
    const char *appId;
    const char *refId;
    const char *vid;
    const char *uuid;
    const char *customLogo;
    const char *cssRef;
    const char *jsRef;
    const char *logoVisibility;
    const char *hostUrl;
    const char *jsClientSrc;
    const char *firstPartyEnabled;
    const char *captchaType;
    const char *blockScript;
} px_props;

static const char *get_px_props_value(const px_props *props, const char *key) {
    if (!strcmp(key, "appId")) {
        return props->appId;
    }
    if (!strcmp(key, "refId")) {
        return props->refId;
    }
    if (!strcmp(key, "vid")) {
        return props->vid;
    }
    if (!strcmp(key, "uuid")) {
        return props->uuid;
    }
    if (!strcmp(key, "customLogo")) {
        return props->customLogo;
    }
    if (!strcmp(key, "cssRef")) {
        return props->cssRef;
    }
    if (!strcmp(key, "jsRef")) {
        return props->jsRef;
    }
    if (!strcmp(key, "logoVisibility")) {
        return props->logoVisibility;
    }
    if (!strcmp(key, "hostUrl")) {
        return props->hostUrl;
    }
    if (!strcmp(key, "jsClientSrc")) {
        return props->jsClientSrc;
    }
    if (!strcmp(key, "firstPartyEnabled")) {
        return props->firstPartyEnabled;
    }
    if (!strcmp(key, "captchaType")) {
        return props->captchaType;
    }
    if (!strcmp(key, "blockScript")) {
        return props->blockScript;
    }

    return NULL;
}

static int start(void *closure) {
    px_props *props = (px_props *)closure;
    props->depth = 0;
    return 0;
}

static void print(FILE *file, const char *string, int escape) {
    if (!escape)
        fprintf(file, "%s", string);
    else if (*string)
        do {
            switch(*string) {
            case '<': fputs("&lt;", file); break;
            case '>': fputs("&gt;", file); break;
            case '&': fputs("&amp;", file); break;
            default: putc(*string, file); break;
            }
        } while(*++string);
}

static int put(void *closure, const char *name, int escape, FILE *file) {
    const px_props *props = (const px_props *)closure;
    const char *v = get_px_props_value(props, name);
    if (v) {
        print(file, v, escape);
    }
    return 0;
}

static int enter(void *closure, const char *name) {
    px_props *props = (px_props *)closure;
    if (++props->depth >= 255) {
        return MUSTACH_ERROR_TOO_DEPTH;
    }
    if (props->depth == 1 && get_px_props_value(props, name)) {
        return 1;
    }
    props->depth--;
    return 0;
}

static int next(void *closure) {
    px_props *props = (px_props *)closure;
    return (props->depth > 0) ? 0 : 1;
}

static int leave(void *closure) {
    px_props *props = (px_props *)closure;
    if (props->depth <= 0) {
        return MUSTACH_ERROR_CLOSING;
    }
    props->depth--;
    return 0;
}

static struct mustach_itf itf = {
    .start = start,
    .put = put,
    .enter = enter,
    .next = next,
    .leave = leave
};

int render_template(char **html, request_context *ctx, const px_config *conf, size_t *size) {
    const char *template = select_template(conf, ctx);

    px_props props = {
        .appId = conf->app_id,
        .uuid = ctx->uuid,
        .vid = ctx->vid,
        .refId = ctx->uuid,
        .customLogo = conf->custom_logo,
        .cssRef = conf->css_ref,
        .jsRef = conf->js_ref,
        .jsClientSrc = conf->first_party_enabled ? conf->client_path_prefix : conf->client_exteral_path,
        .firstPartyEnabled = conf->first_party_enabled ? "true" : "false",
        .logoVisibility = conf->custom_logo ? visible : hidden,
        .captchaType = captcha_type_str(conf->captcha_type),
        .hostUrl = ctx->host_url,
        .blockScript = ctx->captcha_js_src
    };

    int res = mustach(template, &itf, &props, html, size);
    return res;
}

const char* select_template(const px_config *conf, request_context *ctx) {
    if (ctx->action == ACTION_CHALLENGE) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, ctx->r->server, LOGGER_DEBUG_FORMAT, ctx->app_id, "Enforcing action: challenge page is served");
        return ctx->action_data_body;
    }

    // default hosts
    const char *template_host = conf->captcha_exteral_path; // src according to first party mode
    const char *host_url = apr_psprintf(ctx->r->pool, collector_url, conf->app_id, NULL);

    // template selection
    const char *template_prefix = ctx->action == ACTION_BLOCK ? "block" : captcha_type_str(conf->captcha_type); // template name according to action
    const char *template_postfix = ctx->token_origin == TOKEN_ORIGIN_COOKIE ? "" : ".mobile"; // for mobile captcha 

    // modify hosts according to first party
    const char *jsClientSrc = conf->client_exteral_path;
    if (conf->first_party_enabled && ctx->token_origin == TOKEN_ORIGIN_COOKIE) {
        template_host = conf->captcha_path_prefix;
        host_url = conf->xhr_path_prefix;
    }
    
    ctx->host_url = host_url;
    ctx->captcha_js_src = apr_pstrcat(ctx->r->pool, template_host, "/", template_prefix, template_postfix, ".js", NULL);

    return block_page_template;
}
