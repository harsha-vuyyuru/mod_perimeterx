#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <unistd.h>
#include <apr_queue.h>
#include <apr_strings.h>
#include <apr_atomic.h>
#include <apr_portable.h>
#include <apr_signal.h>
#include <apr_base64.h>
#include <apr_time.h>
#include <curl/curl.h>
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include "px_utils.h"
#include "background_activity.h"

/*
 * data structure to work with cURL handles
 */
typedef struct curl_h curl_h;
typedef struct cqueue_t cqueue_t;

struct cqueue_t {
    size_t count;
    curl_h *head;
    curl_h *tail;
};

struct curl_h {
    CURL *curl;
    int id;
    curl_h *prev;
    curl_h *next;
    cqueue_t *owner;
    struct curl_slist *headers;
};

static apr_status_t cqueue_create(cqueue_t **q, apr_pool_t *a)
{
    cqueue_t *queue;
    queue = apr_palloc(a, sizeof(cqueue_t));
    *q = queue;

    queue->count = 0;
    queue->head = NULL;
    queue->tail = NULL;

    return APR_SUCCESS;
}

// put curl_h to the queue, always success
static void cqueue_push(cqueue_t *queue, curl_h *c)
{
    queue->count++;

    if (queue->tail) {
        queue->tail->next = c;
    }

    c->prev = queue->tail;
    c->next = NULL;
    c->owner = queue;

    queue->tail = c;
    if (!queue->head) {
        queue->head = c;
    }
}

// remove curl_h from the queue (curl_h must be owned by the queue), return APR_SUCCESS if success
static apr_status_t cqueue_remove(cqueue_t *queue, curl_h *c)
{
    if (!queue->count) {
        return APR_EOF;
    }

    if (c->owner != queue) {
        return APR_EOF;
    }

    queue->count--;

    // is head ?
    if (!c->prev) {
        queue->head = c->next;
    } else {
        c->prev->next = c->next;
    }

    // is tail ?
    if (!c->next) {
        queue->tail = c->prev;
    } else {
        c->next->prev = c->prev;
    }

    return APR_SUCCESS;
}

// get curl_h from the queue, return APR_SUCCESS if success
static apr_status_t cqueue_pop(cqueue_t *queue, curl_h **c)
{
    *c = queue->head;
    return cqueue_remove(queue, *c);
}

// pipe write / read
apr_status_t background_activity_wakeup(int wakeup_fds[2])
{
    if (write(wakeup_fds[1], "\0", 1) != 1) {
        return APR_EINVAL;
    }
    return APR_SUCCESS;
}

static apr_status_t wakeup_read(int wakeup_fds[2])
{
    char buf[0x100];
    if (read(wakeup_fds[0], buf, sizeof(buf)) < 1) {
        return APR_EINVAL;
    }

    return APR_SUCCESS;
}

static const char *JSON_CONTENT_TYPE = "Content-Type: application/json";
static const char *EXPECT = "Expect:";

// we are not interested in response data, return realize
static size_t dummy_cb(void* contents, size_t size, size_t nmemb, void *stream) {
    (void)contents;
    (void)stream;
    size_t realsize = size * nmemb;
    return realsize;
}

// curl_multi_wait() was added in libcurl 7.28.0.
// use alternative select() interface if this function isn't present
#if (LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR < 28)
    #undef HAS_CURL_MULTI
    #warning Using select() interface, please update cURL library
#elif (LIBCURL_VERSION_MAJOR < 7)
    #error Unsupported cURL library version, please update cURL library
#else
    #define HAS_CURL_MULTI 1
#endif

#define SELECT_TIMEOUT_MS 200
// background_activity thread func
void *APR_THREAD_FUNC background_activity(apr_thread_t *thd, void *ctx)
{
    background_activity_data *thd_data = (background_activity_data *)ctx;
    px_config *conf = thd_data->conf;
    cqueue_t *q_waiting;
    cqueue_t *q_busy;
    apr_pool_t *pool;
    apr_status_t rv;
    int running_handles;
    CURLM *multi_curl;
    CURLMsg *msg;
    int i;
    int n;
    bool running = TRUE;
    CURLMcode res;

    px_log_debug_thd("thread init");

    rv = apr_pool_create(&pool, NULL);
    if (rv != APR_SUCCESS) {
        px_log_error_thd("failed to call apr_pool_create()");
        return NULL;
    }

    rv = cqueue_create(&q_waiting, pool);
    if (rv != APR_SUCCESS) {
        px_log_error_thd("failed to call cqueue_create()");
        return NULL;
    }
    rv = cqueue_create(&q_busy, pool);
    if (rv != APR_SUCCESS) {
        px_log_error_thd("failed to call cqueue_create()");
        return NULL;
    }

    multi_curl = curl_multi_init();
    if (!multi_curl) {
        px_log_error_thd("failed to create multi cURL multi handle");
        return NULL;
    }

    // init curl_h array, put in the waiting queue
    curl_h **cha = apr_pcalloc(pool, sizeof(curl_h *) * conf->background_activity_workers);
    for (i = 0; i < conf->background_activity_workers; i++) {
        curl_h *ch = apr_pcalloc(pool, sizeof(curl_h));
        cha[i] = ch;
        ch->id = i;
        ch->curl = curl_easy_init();
        if (!ch->curl) {
            px_log_error_thd("failed to create multi cURL easy handle");
            return NULL;
        }
        ch->prev = NULL;
        ch->next = NULL;
        ch->owner = NULL;
        cqueue_push(q_waiting, ch);

        // persistent cURL settings
        curl_easy_setopt(ch->curl, CURLOPT_PRIVATE, ch);
        curl_easy_setopt(ch->curl, CURLOPT_WRITEFUNCTION, dummy_cb);
        curl_easy_setopt(ch->curl, CURLOPT_TIMEOUT_MS, conf->api_timeout_ms);

        ch->headers = NULL;
        // it's safe to use conf->auth_header here, as we are locked
        ch->headers = curl_slist_append(ch->headers, conf->auth_header);
        ch->headers = curl_slist_append(ch->headers, JSON_CONTENT_TYPE);
        ch->headers = curl_slist_append(ch->headers, EXPECT);
        curl_easy_setopt(ch->curl, CURLOPT_HTTPHEADER, ch->headers);

        if (conf->proxy_url) {
            curl_easy_setopt(ch->curl, CURLOPT_PROXY, conf->proxy_url);
        }
    }

#ifdef HAS_CURL_MULTI
    struct curl_waitfd waitfd[1];
    int numfds;
    // setup pipe socket
    waitfd[0].fd = conf->background_activity_wakeup_fds[0];
    waitfd[0].events = CURL_WAIT_POLLIN;
#else
    fd_set rfds, wfds, efds;
    int maxfd;

    FD_ZERO(&rfds);
#endif

    while (running) {
#ifndef HAS_CURL_MULTI
        if (FD_ISSET(conf->background_activity_wakeup_fds[0], &rfds)) {
            if (wakeup_read(conf->background_activity_wakeup_fds) != APR_SUCCESS) {
                // report an error, but could potentially spam the log file
                // we still continue, as we could get further notifies via cURL events
                px_log_debug_thd("failed to call wakeup_read()");
            }
        }
#endif
        // if we have room to run one more CURL request
        if (q_waiting->count > 0) {
            char *activity;

            // pop activity, blocking if the queue is already empty
            // TODO: add timer, so we could process un-finished cURL requests
            apr_status_t rv = apr_queue_trypop(conf->background_activity_queue, (void *)&activity);

            if (rv == APR_EINTR) {
                continue;
            }

            // QUEUE terminated
            if (rv == APR_EOF) {
                running = FALSE;
            }

            if (rv == APR_SUCCESS && activity) {
                curl_h *ch;
                const char *url;

                // get the next cURL handle from the queue, the queue should have at least 1 item
                if (cqueue_pop(q_waiting, &ch) != APR_SUCCESS) {
                    px_log_debug_thd("failed to extract item from the waiting queue");
                    free(activity);
                    continue;
                }
                cqueue_push(q_busy, ch);

                // assuming to be a zero terminated string
                curl_easy_setopt(ch->curl, CURLOPT_COPYPOSTFIELDS, activity);

                // Not a thread-safe! conf->activities_api_url can be modified by remote_config thread
                // assuming that users can't change app_id via remote config.
                url = apr_pstrdup(pool, conf->activities_api_url);
                curl_easy_setopt(ch->curl, CURLOPT_URL, url);

                // fire request
                res = curl_multi_add_handle(multi_curl, ch->curl);
                if (res != CURLM_OK) {
                    px_log_error_thd_fmt("curl_multi_add_handle() error: %d", res);
                }
#ifdef DEBUG
                // spamming
                px_log_debug_thd_fmt("new request id: %d", ch->id);
#endif
            }
        }

#ifndef HAS_CURL_MULTI
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&efds);

        // recommended by cURL docs
        res = curl_multi_perform(multi_curl, &n);
        if (res != CURLM_OK) {
            px_log_error_thd_fmt("curl_multi_perform() error: %d", res);
        }

        //  max is FD_SETSIZE
        res = curl_multi_fdset(multi_curl, &rfds, &wfds, &efds, &maxfd);
        if (res != CURLM_OK) {
            px_log_error_thd_fmt("curl_multi_fdset() error: %d", res);
        }

        FD_SET(conf->background_activity_wakeup_fds[0], &rfds);
        if (conf->background_activity_wakeup_fds[0] > maxfd)
            maxfd = conf->background_activity_wakeup_fds[0];

        // hard-coded SELECT timeout, refer SELECT(2) for additional information
        struct timeval wait = { 0, SELECT_TIMEOUT_MS * 1000 };

        // wait until one of fd is active or timeout
        if (select(maxfd+1, &rfds, &wfds, &efds, &wait) < 0) {

            // something bad
            // TODO: handle select error
            px_log_debug_thd_fmt("select() error: %s", strerror(errno));

            // reset
            FD_ZERO(&rfds);
            continue;
        }
#else
        // wait until one of fd is active or timeout
        res = curl_multi_wait(multi_curl, waitfd, 1, SELECT_TIMEOUT_MS, &numfds);
        if (res != CURLM_OK) {
            px_log_error_thd_fmt("curl_multi_wait() error: %d", res);
        }

        // pipe is readable
        if (numfds && waitfd[0].revents & CURL_WAIT_POLLIN) {
            if (wakeup_read(conf->background_activity_wakeup_fds) != APR_SUCCESS) {
                // report an error, but could potentially spam the log file
                // we still continue, as we could get further notifies via cURL events
                px_log_debug_thd("failed to call wakeup_read()");
            }
        }
#endif
        // let cURL process requests
        res = curl_multi_perform(multi_curl, &running_handles);
        if (res != CURLM_OK) {
            px_log_error_thd_fmt("curl_multi_perform() error: %d", res);
        }

        // check if there is any finished requests
        while ((msg = curl_multi_info_read(multi_curl, &n))) {

            // currently CURLMSG_DONE is the only case
            if (msg && msg->msg == CURLMSG_DONE) {
                curl_h *ch;
                curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, (void *)&ch);

                if (msg->data.result != CURLE_OK) {
                    update_and_notify_health_check(conf);
                    px_log_error_thd_fmt("request error: (%d)%s, id: %d", msg->data.result, curl_easy_strerror(msg->data.result), ch->id);
                } else {
#ifdef DEBUG
                    // spamming
                    px_log_debug_thd_fmt("request success id: %d", ch->id);
#endif
                }

                // here we can handle response data, currently we do not process activity response

                // set cURL handle ready for reuse
                curl_multi_remove_handle(multi_curl, msg->easy_handle);
                cqueue_remove(q_busy, ch);
                cqueue_push(q_waiting, ch);
            }
        }
    }

    for (i = 0; i < conf->background_activity_workers; i++) {
        curl_multi_remove_handle(multi_curl, cha[i]->curl);
        curl_easy_cleanup(cha[i]->curl);
        curl_slist_free_all(cha[i]->headers);
    }
    curl_multi_cleanup(multi_curl);

    px_log_debug_thd("thread exited");

    apr_thread_exit(thd, 0);

    return NULL;
}
