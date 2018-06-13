#ifndef PX_TEMPLATE_H
#define PX_TEMPLATE_H

#include "px_types.h"

int render_template(char **html, request_context *ctx, const px_config *conf, size_t *size);
#endif
