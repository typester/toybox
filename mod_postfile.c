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

handler_t mod_postfile_subrequest_start(server *srv, connection *con, void *p_d) {
    plugin_data *p = p_d;

    mod_postfile_patch_connection(srv, con, p);

    if (p->conf.dir->used == 0) return HANDLER_GO_ON;

    log_error_write(srv, __FILE__, __LINE__, "sb", "p->conf.dir: ", p->conf.dir);

    if (con->request.content_length > 0) {
        log_error_write(srv, __FILE__, __LINE__, "sd", "start save postfile: length:", con->request.content_length);

        chunkqueue *req_cq = con->request_content_queue;
        chunk *req_c;
        off_t offset;

        time_t t = time(NULL);

        char fn[NAME_MAX];
        snprintf(fn, NAME_MAX, "postfile-%d-%ld-%ld", inet_ntop_cache_get_ip(srv, &(con->dst_addr)), t, random());

        char path[PATH_MAX];
        snprintf(path, PATH_MAX, "%s/%s", p->conf.dir->ptr, fn);

        log_error_write(srv, __FILE__, __LINE__, "ss", "write to:", path);

        int fd = open(path, O_CREAT|O_TRUNC|O_WRONLY);
        assert(fd > 0);

        data_string *ds = data_string_init();
        buffer_copy_string_len(ds->key, CONST_STR_LEN("X-Sendfile"));
        buffer_copy_string_len(ds->value, path, strlen(path));
        array_insert_unique(con->request.headers, (data_unset *)ds);

        for (offset = 0, req_c = req_cq->first; offset != req_cq->bytes_in; ) {
            off_t weWant  = req_cq->bytes_in - offset;
            off_t weHave  = 0;
            off_t written = 0;

            for (written = 0; written != weWant; ) {
                log_error_write(srv, __FILE__, __LINE__, "soso", "written:", written, "weWant:", weWant);

                switch (req_c->type) {
                    case FILE_CHUNK:
                        log_error_write(srv, __FILE__, __LINE__, "s", "FILE_CHUNK");

                        weHave = req_c->file.length - req_c->offset;

                        int in_fd = open(req_c->file.name->ptr, O_RDONLY);
                        assert(in_fd > 0);

                        int n = 0;
                        char *buf = calloc(1, weHave);
                        while ( (n = read(in_fd, buf, weHave)) > 0) {
                            char *p  = buf;
                            char *ep = p + n;
                            while (p < ep) {
                                int bytes = write(fd, p, ep - p);
                                p += bytes;
                            }
                        }

                        close(in_fd);
                        free(buf);

                        req_c->offset += weHave;
                        req_cq->bytes_out += weHave;
                        written += weHave;

                        if (req_c->offset == req_c->file.length) {
                            req_c->file.is_temp = 0;
                            chunkqueue_remove_finished_chunks(req_cq);
                            req_c = req_cq->first;
                        }

                        break;
                    case MEM_CHUNK:
                        log_error_write(srv, __FILE__, __LINE__, "s", "MEM_CHUNK");

                        weHave = req_c->mem->used - 1 - req_c->offset;

                        log_error_write(srv, __FILE__, __LINE__, "so", "weHave", weHave);

                        char *p  = req_c->mem->ptr;
                        char *ep = p + weHave;
                        while (p < ep) {
                            int bytes = write(fd, p, ep - p);
                            p += bytes;
                        }

                        req_c->offset += weHave;
                        req_cq->bytes_out += weHave;
                        written += weHave;

                        log_error_write(srv, __FILE__, __LINE__, "so", "written", written);

                        if (req_c->offset == (off_t)req_c->mem->used - 1) {
                            chunkqueue_remove_finished_chunks(req_cq);
                            req_c = req_cq->first;
                        }

                        break;
                    default:
                        close(fd);
                        return HANDLER_GO_ON;
                }
            }
            offset += weWant;
        }

        close(fd);
        con->request.content_length = 0;
    }

    log_error_write(srv, __FILE__, __LINE__, "s", "end our process");

    return HANDLER_GO_ON;
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_postfile_plugin_init(plugin *p) {
    p->version = LIGHTTPD_VERSION_ID;
    p->name    = buffer_init_string("postfile");

    p->init         = mod_postfile_init;
    p->set_defaults = mod_postfile_set_defaults;
    p->cleanup      = mod_postfile_free;

    p->handle_subrequest_start = mod_postfile_subrequest_start;

    p->data = NULL;

    return 0;
}
