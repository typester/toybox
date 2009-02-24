#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#include "buffer.h"
#include "server.h"
#include "keyvalue.h"
#include "log.h"

#include "http_chunk.h"
#include "fdevent.h"
#include "connections.h"
#include "response.h"
#include "joblist.h"

#include "plugin.h"

#include "inet_ntop_cache.h"

#include <stdio.h>

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#include "sys-socket.h"

/* plugin config for all request/connections */
typedef struct {
    buffer *host;
    buffer *path;
} plugin_config;

typedef struct {
    PLUGIN_DATA;

    buffer *parse_response;

    plugin_config **config_storage;
    plugin_config conf;
} plugin_data;

typedef enum {
    PROXY_STATE_INIT,
    PROXY_STATE_CONNECT,
    PROXY_STATE_PREPARE_WRITE,
    PROXY_STATE_WRITE,
    PROXY_STATE_READ,
    PROXY_STATE_ERROR
} proxy_connection_state_t;

typedef struct {
    proxy_connection_state_t state;
    time_t state_timestamp;

    buffer *response;
    buffer *response_header;
    chunkqueue *wb;

    int fd;                     /* fd to the proxy process */
    int fde_ndx;                /* index into the fd-event buffer */

    connection  *remote_conn;
    plugin_data *plugin_data;
} handler_ctx;

static handler_ctx * handler_ctx_init() {
    handler_ctx *hctx;
    hctx = calloc(1, sizeof(*hctx));

    hctx->state           = PROXY_STATE_INIT;
    hctx->response        = buffer_init();
    hctx->response_header = buffer_init();
    hctx->wb              = chunkqueue_init();
    hctx->fd              = -1;
    hctx->fde_ndx         = -1;

    return hctx;
}

static void handler_ctx_free(handler_ctx *hctx) {
    buffer_free(hctx->response);
    buffer_free(hctx->response_header);
    chunkqueue_free(hctx->wb);
    free(hctx);
}

/* init the plugin data */
INIT_FUNC(mod_myproxy_init) {
    plugin_data *p;

    p = calloc(1, sizeof(*p));
    p->parse_response = buffer_init();

    return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_myproxy_free) {
    plugin_data *p = p_d;
    UNUSED(srv);

    if (!p) return HANDLER_GO_ON;

    if (p->config_storage) {
        size_t i;

        for (i = 0; i < srv->config_context->used; i++) {
            plugin_config *s = p->config_storage[i];

            if (!s) continue;

            buffer_free(s->host);
            buffer_free(s->path);

            free(s);
        }
        free(p->config_storage);
    }

    buffer_free(p->parse_response);
    free(p);

    return HANDLER_GO_ON;
}

/* prototype */
SUBREQUEST_FUNC(mod_myproxy_handle_subrequest);

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_myproxy_set_defaults) {
    plugin_data *p = p_d;
    size_t i = 0;

    config_values_t cv[] = {
        { "myproxy.host", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 0 */
        { "myproxy.path", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_CONNECTION }, /* 1 */
        { NULL,             NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
    };

    if (!p) return HANDLER_ERROR;

    p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

    for (i = 0; i < srv->config_context->used; i++) {
        plugin_config *s;

        s = calloc(1, sizeof(plugin_config));
        s->host = buffer_init();
        s->path = buffer_init();

        cv[0].destination = s->host;
        cv[1].destination = s->path;

        p->config_storage[i] = s;

        if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
            return HANDLER_ERROR;
        }
    }

    return HANDLER_GO_ON;
}

#define PATCH(x) \
    p->conf.x = s->x;
static int mod_myproxy_patch_connection(server *srv, connection *con, plugin_data *p) {
    size_t i, j;
    plugin_config *s = p->config_storage[0];

    PATCH(host);
    PATCH(path);

    /* skip the first, the global context */
    for (i = 1; i < srv->config_context->used; i++) {
        data_config *dc = (data_config *)srv->config_context->data[i];
        s = p->config_storage[i];

        /* condition didn't match */
        if (!config_check_cond(srv, con, dc)) continue;

        /* merge config */
        for (j = 0; j < dc->value->used; j++) {
            data_unset *du = dc->value->data[j];

            if (buffer_is_equal_string(du->key, CONST_STR_LEN("myproxy.target"))) {
                PATCH(host);
                PATCH(path);
            }
        }
    }

    return 0;
}
#undef PATCH

URIHANDLER_FUNC(mod_myproxy_uri_handler) {
    plugin_data *p = p_d;
    int s_len;
    size_t k, i;

    UNUSED(srv);

    if (con->mode != DIRECT) return HANDLER_GO_ON;
    if (con->uri.path->used == 0) return HANDLER_GO_ON;

    mod_myproxy_patch_connection(srv, con, p);

    if ( (p->conf.host->used == 0) || (p->conf.path->used ==0) ) return HANDLER_GO_ON;

    log_error_write(
        srv, __FILE__, __LINE__,
        "sbb", "myproxy-target: ",  p->conf.host, p->conf.path);

    /* init handler-context */
    handler_ctx *hctx;
    hctx = handler_ctx_init();
    hctx->remote_conn = con;
    hctx->plugin_data = p;

    con->mode = p->id;
    con->plugin_ctx[p->id] = hctx;

    return HANDLER_GO_ON;
}

static int proxy_response_parse(server *srv, connection *con,
                                plugin_data *p, buffer *in) {
    char *s, *ns;
    int   http_response_status = -1;

    UNUSED(srv);

    /* \r\n -> \0\0 */

    buffer_copy_string_buffer(p->parse_response, in);

    for (s = p->parse_response->ptr; NULL != (ns = strstr(s, "\r\n")); s = ns + 2) {
        char        *key, *value;
        int          key_len;
        data_string *ds;
        int          copy_header;

        ns[0] = '\0';
        ns[1] = '\0';

        if (-1 == http_response_status) {
            for (key = s; *key && *key != ' '; key++);

            if (*key) {
                http_response_status = (int)strtol(key, NULL, 10);
                if (http_response_status <= 0) http_response_status = 502;
            }
            else {
                http_response_status = 502;
            }

            con->http_status = http_response_status;
            con->parsed_response |= HTTP_STATUS;
            continue;
        }

        if (NULL == (value = strchr(s, ":"))) {
            /* now we expect: "<key>: <value>\n" */
            continue;
        }

        key = s;
        key_len = value - key;

        value++;
        /* strip WS */
        while (*value == ' ' || *value == '\t') value++;

        copy_header = 1;

        switch (key_len) {
            case 4:
                if (0 == strncasecmp(key, "Date", key_len)) {
                    con->parsed_response |= HTTP_DATE;
                }
                break;
            case 8:
                if (0 == strncasecmp(key, "Location", key_len)) {
                    con->parsed_response |= HTTP_LOCATION;
                }
                break;
            case 10:
                if (0 == strncasecmp(key, "Connection", key_len)) {
                    copy_header = 0;
                }
                break;
            case 14:
                if (0 == strncasecmp(key, "Content-Length", key_len)) {
                    con->response.content_length = strtol(value, NULL, 10);
                    con->parsed_response |= HTTP_CONTENT_LENGTH;
                }
                break;
            default:
                break;
        }

        if (copy_header) {
            ds = (data_string *)array_get_unused_element(
                con->response.headers, TYPE_STRING);
            if (NULL == ds) {
                ds = data_response_init();
            }
            buffer_copy_string_len(ds->key, key, key_len);
            buffer_copy_string_buffer(ds->value, value);

            array_insert_unique(con->response.headers, (data_unset *)ds);
        }
    }

    return 0;
}

static int proxy_demux_response(server *srv, handler_ctx *hctx) {
    int     fin = 0;
    int     b;
    ssize_t r;

    plugin_data *p        = hctx->plugin_data;
    connection  *con      = hctx->remote_conn;
    int          proxy_fd = hctx->fd;

    /* check how much we have to read */
    if (ioctl(hctx->fd, FIONREAD, &b)) {
        log_error_write(srv, __FILE__, __LINE__, "sd",
            "ioctl failed:", proxy_fd);
        return -1;
    }

    if (b > 0) {
        if (hctx->response->used == 0) {
            buffer_prepare_append(hctx->response, b + 1);
            hctx->response->used = 1;
        }
        else {
            buffer_prepare_append(hctx->response, b);
        }

        r = read(hctx->fd, hctx->response->ptr + hctx->response->used - 1, b);
        if (-1 == r) {
            if (errno == EAGAIN) return 0;
            log_error_write(srv, __FILE__, __LINE__, "sds",
                "unexpected end-of-file (perhaps the proxy process died):",
                proxy_fd, strerror(errno));
            return -1;
        }

        assert(r);

        hctx->response->used += r;
        hctx->response->ptr[hctx->response->used - 1] = '\0';

        if (0 == con->got_response) {
            con->got_response = 1;
            //            buffer_prepare_copy(hctx->response_header, 128);
        }

        if (0 == con->file_started) {
            char *c;

            /* search for the \r\n\r\n in the string */
            c = buffer_search_string_len(hctx->response, "\r\n\r\n", 4);
            if (NULL != c) {
                size_t hlen = c - hctx->response->ptr + 4;
                size_t blen = hctx->response->used - hlen - 1;
                /* found */

                buffer_append_string_len(
                    hctx->response_header, hctx->response->ptr,
                    c - hctx->response->ptr + 4);

                /* parse the response header */
                proxy_response_parse(srv, con, p, hctx->response_header);

                /* enable chunked-transfer-encoding */
                if (con->request.http_version == HTTP_VERSION_1_1 &&
                    !(con->parsed_response & HTTP_CONTENT_LENGTH)) {
                    con->response.transfer_encoding = HTTP_TRANSFER_ENCODING_CHUNKED;
                }

                con->file_started = 1;
                if (blen) {
                    http_chunk_append_mem(srv, con, c + 4, blen + 1);
                    joblist_append(srv, con);
                }
                hctx->response->used = 0;
            }
        }
        else {
            http_chunk_append_mem(srv, con, hctx->response->ptr, hctx->response->used);
            joblist_append(srv, con);
            hctx->response->used = 0;
        }
    }
    else {
        /* reading from upstream done */
        con->file_finished = 1;

        http_chunk_append_mem(srv, con, NULL, 0);
        joblist_append(srv, con);

        fin = 1;
    }

    return fin;
}

void proxy_connection_close(server *srv, handler_ctx *hctx) {
    plugin_data *p;
    connection  *con;

    if (NULL == hctx) return;

    p   = hctx->plugin_data;
    con = hctx->remote_conn;

    if (hctx->fd != -1) {
        fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
        fdevent_unregister(srv->ev, hctx->fd);

        close(hctx->fd);
        srv->cur_fds--;
    }

    handler_ctx_free(hctx);
    con->plugin_ctx[p->id] = NULL;
}

static handler_t proxy_handle_fdevent(void *s, void *ctx, int revents) {
    server      *srv  = (server *)s;
    handler_ctx *hctx = ctx;
    connection  *con  = hctx->remote_conn;
    plugin_data *p    = hctx->plugin_data;

    if (revents & FDEVENT_OUT) {
        if (hctx->state == PROXY_STATE_CONNECT || hctx->state == PROXY_STATE_WRITE) {
            return mod_myproxy_handle_subrequest(srv, con, p);
        }
    }

    if (revents & FDEVENT_IN) {
        if (hctx->state == PROXY_STATE_READ) {
            switch (proxy_demux_response(srv, hctx)) {
                case 0:
                    break;

                case 1:
                    /* we are done */
                    proxy_connection_close(srv, hctx);
                    joblist_append(srv, con);
                    return HANDLER_FINISHED;

                case -1:
                    if (con->file_started == 0) {
                        /* nothing has been sent out yet, send a 500 */
                        connection_set_state(srv, con, CON_STATE_HANDLE_REQUEST);
                        con->http_status = 500;
                        con->mode = DIRECT;
                    }
                    else {
                        /* response might have been already started, kill the con */
                        connection_set_state(srv, con, CON_STATE_ERROR);
                    }

                    joblist_append(srv, con);
                    return HANDLER_FINISHED;
            }
        }
    }

    if (revents &  FDEVENT_HUP) {
        if (hctx->state == PROXY_STATE_CONNECT) {
            proxy_connection_close(srv, hctx);
            joblist_append(srv, con);

            con->http_status = 503;
            con->mode = DIRECT;

            return HANDLER_FINISHED;
        }

        con->file_finished = 1;
        proxy_connection_close(srv, con);
        joblist_append(srv, con);
    }
    else if (revents & FDEVENT_ERR) {
        joblist_append(srv, con);
        proxy_connection_close(srv, hctx);
    }

    return HANDLER_FINISHED;
}

static int proxy_set_state(server *srv, handler_ctx *hctx,
                           proxy_connection_state_t state) {
    hctx->state = state;
    hctx->state_timestamp = srv->cur_ts;

    return 0;
}

static int proxy_establish_connection(server *srv, handler_ctx *hctx) {
    struct sockaddr    *proxy_addr;
    struct sockaddr_in  proxy_addr_in;
    socklen_t           servlen;

    plugin_data *p        = hctx->plugin_data;
    int          proxy_fd = hctx->fd;
    buffer      *host     = p->conf.host;

    memset(&proxy_addr, 0, sizeof(proxy_addr));

    proxy_addr_in.sin_family      = AF_INET;
    proxy_addr_in.sin_addr.s_addr = inet_addr(host->ptr);
    proxy_addr_in.sin_port        = htons(80);
    servlen = sizeof(proxy_addr_in);

    if (INADDR_NONE == proxy_addr_in.sin_addr.s_addr) {
        struct hostent *h;
        h = gethostbyname(host->ptr);
        if (NULL == host) {
            log_error_write(srv, __FILE__, __LINE__, "sd",
                "gethostbyname failed: ", proxy_fd);
            return -1;
        }
        proxy_addr_in.sin_addr.s_addr = *(unsigned int *)h->h_addr_list[0];
    }

    proxy_addr = (struct sockaddr *)&proxy_addr_in;

    if (-1 == connect(proxy_fd, proxy_addr, servlen)) {
        if (errno == EINPROGRESS || errno == EALREADY) {
            log_error_write(srv, __FILE__, __LINE__, "sd",
                "connect delayed:", proxy_fd);
            return 1;
        }
        else {
            log_error_write(srv, __FILE__, __LINE__, "sdsd",
                "connect failed:", proxy_fd, strerror(errno), errno);
            return -1;
        }
    }

    log_error_write(srv, __FILE__, __LINE__, "sd",
        "connect succeeded:", proxy_fd);

    return 0;
}

void proxy_set_header(connection *con, const char *key, const char *value) {
    data_string *ds_dst;

    ds_dst = (data_string *)array_get_unused_element(con->request.headers, TYPE_STRING);
    if (NULL == ds_dst) {
        ds_dst = data_string_init();
    }

    buffer_copy_string(ds_dst->key, key);
    buffer_append_string(ds_dst->value, value);
    array_insert_unique(con->request.headers, (data_unset *)ds_dst);

}

static int proxy_create_env(server *srv, handler_ctx *hctx) {
    size_t       i;
    connection  *con = hctx->remote_conn;
    buffer      *b;
    plugin_data *p   = hctx->plugin_data;

    b = chunkqueue_get_append_buffer(hctx->wb);

    /* request line */
    buffer_copy_string(b, get_http_method_name(con->request.http_method));
    buffer_append_string_len(b, CONST_STR_LEN(" "));
    buffer_append_string_buffer(b, p->conf.path);
    buffer_append_string_len(b, CONST_STR_LEN(" HTTP/1.0\r\n"));

    proxy_set_header(
        con, "X-Forwarded-For",
        (char *)inet_ntop_cache_get_ip(srv, &(con->dst_addr))
    );

    if (con->request.http_host && !buffer_is_empty(con->request.http_host)) {
        proxy_set_header(con, "X-Host", con->request.http_host->ptr);
    }
    proxy_set_header(con, "X-Forwarded-Proto", con->conf.is_ssl ? "https" : "http");

    /* request header */
    for (i = 0; i < con->request.headers->used; i++) {
        data_string *ds;
        ds = (data_string *)con->request.headers->data[i];

        if (ds->value->used && ds->key->used) {
            if (buffer_is_equal_string(ds->key, CONST_STR_LEN("Connection"))) continue;
            if (buffer_is_equal_string(ds->key, CONST_STR_LEN("Proxy-Connection"))) continue;

            if (buffer_is_equal_string(ds->key, CONST_STR_LEN("Host"))) {
                buffer_append_string_len(b, CONST_STR_LEN("Host: "));
                buffer_append_string_buffer(b, p->conf.host);
            }
            else {
                buffer_append_string_buffer(b, ds->key);
                buffer_append_string_len(b, CONST_STR_LEN(": "));
                buffer_append_string_buffer(b, ds->value);
            }
            buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
        }
    }

    buffer_append_string_len(b, CONST_STR_LEN("\r\n"));
    hctx->wb->bytes_in += b->used - 1;

    log_error_write(srv, __FILE__, __LINE__, "sb",
        "request: ", b);

    /* ignore body */
    return 0;
}

static handler_t proxy_write_request(server *srv, handler_ctx *hctx) {
    plugin_data *p   = hctx->plugin_data;
    connection  *con = hctx->remote_conn;

    int ret;

    switch (hctx->state) {
        case PROXY_STATE_INIT:
            if (-1 == (hctx->fd = socket(AF_INET, SOCK_STREAM, 0))) {
                log_error_write(
                    srv, __FILE__, __LINE__,
                    "ss", "socket failed: ", strerror(errno));
                return HANDLER_ERROR;
            }
            hctx->fde_ndx = -1;
            srv->cur_fds++;

            fdevent_register(srv->ev, hctx->fd, proxy_handle_fdevent, hctx);

            if (-1 == fdevent_fcntl_set(srv->ev, hctx->fd)) {
                log_error_write(
                    srv, __FILE__, __LINE__,
                    "ss", "fcntl failed: ", strerror(errno));
                return HANDLER_ERROR;
            }

        case PROXY_STATE_CONNECT:
            /* try to finish the connect() */
            if (hctx->state == PROXY_STATE_INIT) {
                switch (proxy_establish_connection(srv, hctx)) {
                    case 1:
                        proxy_set_state(srv, hctx, PROXY_STATE_CONNECT);
                        fdevent_event_add(
                            srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT
                        );

                        return HANDLER_WAIT_FOR_EVENT;

                    case -1:
                        log_error_write(srv, __FILE__, __LINE__, "s", "connection error");
                        hctx->fde_ndx = -1;
                        return HANDLER_ERROR;

                    default:
                        break;
                }
            }
            else {
                int       socket_error;
                socklen_t socket_error_len = sizeof(socket_error);

                fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);

                /* try to finish the connect() */
                if (0 != getsockopt(hctx->fd, SOL_SOCKET,
                        SO_ERROR, &socket_error, &socket_error_len)) {
                    log_error_write(srv, __FILE__, __LINE__, "ss",
                        "getsockopt failed:", strerror(errno));
                    return HANDLER_ERROR;
                }
                if (socket_error != 0) {
                    log_error_write(srv, __FILE__, __LINE__, "ss",
                        "establishing connection failed", strerror(socket_error));
                    return HANDLER_ERROR;
                }

                log_error_write(srv, __FILE__, __LINE__, "s",
                    "connection delayerd success");
            }
            proxy_set_state(srv, hctx, PROXY_STATE_PREPARE_WRITE);

        case PROXY_STATE_PREPARE_WRITE:
            proxy_create_env(srv, hctx);
            proxy_set_state(srv, hctx, PROXY_STATE_WRITE);

        case PROXY_STATE_WRITE:
            ret = srv->network_backend_write(srv, con, hctx->fd, hctx->wb);
            chunkqueue_remove_finished_chunks(hctx->wb);

            if (-1 == ret) {
                if (errno != EAGAIN && errno != EINTR) {
                    log_error_write(srv, __FILE__, __LINE__, "ssd",
                        "write failed:", strerror(errno), errno);
                    return HANDLER_ERROR;
                }
                else {
                    fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
                    return HANDLER_WAIT_FOR_EVENT;
                }
            }

            if (hctx->wb->bytes_out == hctx->wb->bytes_in) {
                proxy_set_state(srv, hctx, PROXY_STATE_READ);

                fdevent_event_del(srv->ev, &(hctx->fde_ndx), hctx->fd);
                fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_IN);
            }
            else {
                fdevent_event_add(srv->ev, &(hctx->fde_ndx), hctx->fd, FDEVENT_OUT);
            }

            return HANDLER_WAIT_FOR_EVENT;

        case PROXY_STATE_READ:
            /* waiting for a response */
            return HANDLER_WAIT_FOR_EVENT;

        default:
            log_error_write(srv, __FILE__, __LINE__, "s", "unknown state");
            return HANDLER_ERROR;
    }

    return HANDLER_GO_ON;
}

SUBREQUEST_FUNC(mod_myproxy_handle_subrequest) {
    plugin_data *p = p_d;
    handler_ctx *hctx = con->plugin_ctx[p->id];

    if (NULL == hctx) return HANDLER_GO_ON;

    /* not my job */
    if (con->mode != p->id) return HANDLER_GO_ON;

    mod_myproxy_patch_connection(srv, con, p);

    switch (proxy_write_request(srv, hctx)) {
        case HANDLER_ERROR:
            log_error_write(srv, __FILE__, __LINE__, "sbdd",
                "TODO: proxy-server disabled");

            proxy_connection_close(srv, hctx);
            return HANDLER_ERROR;
        case HANDLER_WAIT_FOR_EVENT:
            return HANDLER_WAIT_FOR_EVENT;
        case HANDLER_WAIT_FOR_FD:
            return HANDLER_WAIT_FOR_FD;
        default:
            break;
    }

    if (con->file_started == 1) {
        return HANDLER_FINISHED;
    }
    else {
        return HANDLER_WAIT_FOR_EVENT;
    }
}

static handler_t mod_myproxy_connection_close_callback(server *srv, connection *con,
    void *p_d) {
    plugin_data *p = p_d;

    proxy_connection_close(srv, con->plugin_ctx[p->id]);

    return HANDLER_GO_ON;
}


/* this function is called at dlopen() time and inits the callbacks */

int mod_myproxy_plugin_init(plugin *p) {
    p->version = LIGHTTPD_VERSION_ID;
    p->name    = buffer_init_string("myproxy");

    p->init                    = mod_myproxy_init;
    p->handle_uri_clean        = mod_myproxy_uri_handler;
    p->handle_subrequest       = mod_myproxy_handle_subrequest;
    p->set_defaults            = mod_myproxy_set_defaults;
    p->connection_reset        = mod_myproxy_connection_close_callback;
    p->handle_connection_close = mod_myproxy_connection_close_callback;
    p->cleanup                 = mod_myproxy_free;

    p->data = NULL;

    return 0;
}
