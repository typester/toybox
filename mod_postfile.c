#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <time.h>
#include <assert.h>

#include "base.h"
#include "log.h"
#include "buffer.h"

#include "plugin.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

typedef struct {
    buffer *dir;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config **config_storage;
    plugin_config   conf;
} plugin_data;

typedef struct {
    char  fn[PATH_MAX];
    int   fd;
    size_t read;
} handler_ctx;

static handler_ctx * handler_ctx_init() {
    handler_ctx * hctx;

    hctx = calloc(1, sizeof(*hctx));
    hctx->fd = -1;
    hctx->read = 0;

    return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
    free(hctx);
}



/* init the plugin data */
INIT_FUNC(mod_postfile_init) {
    plugin_data *p;
    p = calloc(1, sizeof(*p));

    return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_postfile_free) {
    plugin_data *p = p_d;

    UNUSED(srv);

    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        size_t i;

        for (i = 0; i < srv->config_context->used; i++) {
            plugin_config *s = p->config_storage[i];

            if (!s) continue;

            buffer_free(s->dir);

            free(s);
        }
        free(p->config_storage);
    }

    free(p);

    return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_postfile_set_defaults) {
    plugin_data *p = p_d;
    size_t i = 0;

    config_values_t cv[] = {
        { "postfile.dir", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION },       /* 0 */
        { NULL,           NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    if (!p) return HANDLER_ERROR;

    p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

    for (i = 0; i < srv->config_context->used; i++) {
        plugin_config *s;

        s = calloc(1, sizeof(plugin_config));

        s->dir = buffer_init();

        cv[0].destination = s->dir;

        p->config_storage[i] = s;

        if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
            return HANDLER_ERROR;
        }
    }

    return HANDLER_GO_ON;
}

#define PATCH(x) \
    p->conf.x = s->x;
static int mod_postfile_patch_connection(server *srv, connection *con, plugin_data *p) {
    size_t i, j;
    plugin_config *s = p->config_storage[0];

    PATCH(dir);

    /* skip the first, the global context */
    for (i = 1; i < srv->config_context->used; i++) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        for (j = 0; j < dc->value->used; j++) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("postfile.dir"))) {
                PATCH(dir);
            }
        }
    }

    return 0;
}
#undef PATCH

handler_t mod_postfile_uri_clean(server *srv, connection *con, void *p_d) {
    plugin_data *p = p_d;

    mod_postfile_patch_connection(srv, con, p);

    if (p->conf.dir->used == 0) return HANDLER_GO_ON;

    return HANDLER_GO_ON;
}

handler_t mod_postfile_read_post(server *srv, connection *con, void *p_d, char *buffer, int length) {
    plugin_data *p = p_d;
    handler_ctx *hctx;

    mod_postfile_patch_connection(srv, con, p);

    if (p->conf.dir->used == 0) return HANDLER_GO_ON;

    if (con->plugin_ctx[p->id]) {
        hctx = con->plugin_ctx[p->id];
    }
    else {
        // init
        hctx = handler_ctx_init();

        time_t t = time(NULL);

        char fn[NAME_MAX];
        snprintf(fn, NAME_MAX, "postfile-%d-%ld-%ld", inet_ntop_cache_get_ip(srv, &(con->dst_addr)), t, random());
        snprintf(hctx->fn, PATH_MAX, "%s/%s", p->conf.dir->ptr, fn);

        hctx->fd = open(hctx->fn, O_CREAT|O_TRUNC|O_WRONLY);
        chmod(hctx->fn, 0666);

        assert(hctx->fd > 0);

        con->plugin_ctx[p->id] = hctx;
    }

    char *sp = buffer;
    char *ep = sp + length;
    while (sp < ep) {
        int bytes = write(hctx->fd, sp, ep - sp);
        sp += bytes;
    }

    hctx->read += length;

    if (hctx->read == con->request.content_length) {
        close(hctx->fd);
        data_string *ds = data_string_init();
        buffer_copy_string_len(ds->key, CONST_STR_LEN("X-Sendfile"));
        buffer_copy_string_len(ds->value, hctx->fn, strlen(hctx->fn));
        array_insert_unique(con->request.headers, (data_unset *)ds);
    }

    return HANDLER_GO_ON;
}

handler_t mod_postfile_subrequest_start(server *srv, connection *con, void *p_d) {
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];

    if (!hctx) return HANDLER_GO_ON;
    if (!con->request.content_length) return HANDLER_GO_ON;

    mod_postfile_patch_connection(srv, con, p);

    if (p->conf.dir->used == 0) return HANDLER_GO_ON;

    if (con->request.content_length == hctx->read) {
        con->request.content_length = 0;
    }

    return HANDLER_GO_ON;
}

handler_t mod_postfile_connection_reset(server *srv, connection *con, void *p_d) {
    plugin_data *p = p_d;

    if (con->plugin_ctx[p->id]) {
        handler_ctx *hctx = con->plugin_ctx[p->id];
        if (hctx->fd > 0) close(hctx->fd);

        handler_ctx_free(hctx);
        con->plugin_ctx[p->id] = NULL;
    }

    return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_postfile_plugin_init(plugin *p) {
    p->version = LIGHTTPD_VERSION_ID;
    p->name    = buffer_init_string("postfile");

    p->init         = mod_postfile_init;
    p->set_defaults = mod_postfile_set_defaults;
    p->cleanup      = mod_postfile_free;

    p->handle_read_post        = mod_postfile_read_post;
    p->handle_subrequest_start = mod_postfile_subrequest_start;
    p->connection_reset        = mod_postfile_connection_reset;

    p->data = NULL;

    return 0;
}
