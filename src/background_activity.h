#ifndef BACKGROUND_ACTIVITY_H
#define BACKGROUND_ACTIVITY_H

#include <apr_queue.h>
#include "px_types.h"

typedef struct {
    server_rec *server;
    px_config *conf;
} background_activity_data;

void *APR_THREAD_FUNC background_activity(apr_thread_t *thd, void *ctx);
// return APR_SUCCESS if background activity thread successfully notified
apr_status_t background_activity_wakeup(int wakeup_fds[2]);

#endif
