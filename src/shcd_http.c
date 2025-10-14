#define _GNU_SOURCE
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <bsd_queue.h>
#include <queue.h>
#include <fbuf.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include "mongoose.h"

#include "shcd_http.h"

#define HTTP_HEADERS_BASE "HTTP/1.0 200 OK\r\n" \
                          "Content-Type: %s\r\n" \
                          "Server: shardcached\r\n" \
                          "Connection: Close\r\n"

#define HTTP_HEADERS HTTP_HEADERS_BASE "Content-Length: %d\r\n\r\n"

#define HTTP_HEADERS_WITH_TIME HTTP_HEADERS_BASE "Last-Modified: %s\r\n\r\n"

#define ATOMIC_INCREMENT(_v) (void)__sync_add_and_fetch(&(_v), 1)
#define ATOMIC_DECREMENT(_v) (void)__sync_sub_and_fetch(&(_v), 1)

#define ATOMIC_READ(_v) __sync_fetch_and_add(&(_v), 0)

#define HTTP_CONFIGURE_COMMAND "__configure__"
#define HTTP_STATS_COMMAND "__stats__"
#define HTTP_INDEX_COMMAND "__index__"
#define HTTP_HEALTH_COMMAND "__health__"
#define HTTP_UPLOAD_COMMAND "__upload__"

#define HTTP_MAX_KEYLEN 2048
#define MAX_PATH_SIZE 8192

#define MAX_INMEMORY_OBJECT_SIZE 1<<20 * 100

typedef struct {
    fbuf_t fbuf;
    fbuf_t boundary;
    int fd;
    size_t data_len;
    char name[HTTP_MAX_KEYLEN];
    char filename[MAX_PATH_SIZE];
    int done;
} recv_buffer_t;

static void recv_buffer_destroy(recv_buffer_t *buf)
{
    fbuf_destroy(&buf->fbuf);
    fbuf_destroy(&buf->boundary);
    close(buf->fd);
    unlink(buf->filename);
}

static inline int
is_admin_command(char *key, char **extra)
{
    static __thread char buf[HTTP_MAX_KEYLEN];

    int i = 0;
    while (key[i] && key[i] != '/') {
        buf[i] = key[i];
        i++;
    }
    buf[i] = 0;

    if (strcmp(buf, HTTP_STATS_COMMAND) == 0 ||
        strcmp(buf, HTTP_INDEX_COMMAND) == 0 ||
        strcmp(buf, HTTP_HEALTH_COMMAND) == 0 ||
        strcmp(buf, HTTP_CONFIGURE_COMMAND) == 0 ||
        strcmp(buf, HTTP_UPLOAD_COMMAND) == 0)
    {
        key[i++] = 0;
        if (extra)
            *extra = key + i;

        return 1;
    }
    return 0;
}

typedef struct _http_worker_s {
    TAILQ_ENTRY(_http_worker_s) next;
    pthread_t th;
    struct mg_server *server;
    const char *me;
    const char *basepath;
    const char *adminpath;
    shardcache_t *cache;
    shcd_acl_t *acl;
    hashtable_t *mime_types;
    int leave;
} http_worker_t;

struct _shcd_http_s {
    int num_workers;
    TAILQ_HEAD(, _http_worker_s) workers;
};

typedef struct _http_job_s {

} http_job_t;

static int shcd_active_requests = 0;

// Function to URL-encode a string
static char *
url_encode(const char* str) {
    if (str == NULL) {
        return NULL;
    }

    size_t len = strlen(str);
    // Allocate memory for the encoded string. In the worst case, every character
    // might be encoded as %XX, so we need up to 3 times the original length + 1 for null terminator.
    char* encoded_str = (char*)malloc(len * 3 + 1);
    if (encoded_str == NULL) {
        perror("Failed to allocate memory for encoded string");
        return NULL;
    }

    char* p_encoded = encoded_str;
    for (size_t i = 0; i < len; ++i) {
        char c = str[i];
        // Characters that do not need encoding (alphanumeric and -._~)
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') {
            *p_encoded++ = c;
        } else {
            // Encode other characters as %XX
            sprintf(p_encoded, "%%%02X", (unsigned char)c);
            p_encoded += 3;
        }
    }
    *p_encoded = '\0'; // Null-terminate the encoded string

    return encoded_str;
}

static void
shardcached_build_index_response(fbuf_t *buf, int do_html, shardcache_t *cache, const char *basepath)
{
    int i;

    shardcache_storage_index_t *index = shardcache_get_index(cache);

    if (do_html) {
        fbuf_printf(buf,
                    "<html><body>"
                    "<table bgcolor='#000000' "
                    "cellspacing='1' "
                    "cellpadding='4'>"
                    "<tr bgcolor='#ffffff'>"
                    "<td><b>Key</b></td>"
                    "<td><b>Value size</b></td>"
                    "</tr>");
    }
    for (i = 0; i < index->size; i++) {
        size_t klen = index->items[i].klen;
        char keystr[klen+1];
        keystr[klen] = 0;
        memcpy(keystr, index->items[i].key, klen);
/*
        char keystr[klen * 5 + 1];
        char *t = keystr;
        char c;
        int p;
        for (p = 0 ; p < klen ; ++p) {
            c = ((char*)index->items[i].key)[p];
            if (c == '<')
                t = stpcpy(t, "&lt;");
            else if (c == '>')
                t = stpcpy(t, "&gt;");
            else if (c == '&')
                t = stpcpy(t, "&amp;");
            else if (c < ' ') {
                sprintf(t, "\\x%2x", (int)c);
                t += 4;
            }
            else
                *t++ = c;
        }
        *t = 0;
*/
        if (do_html) {
            char *encodedName = url_encode(keystr);
            fbuf_printf(buf,
                        "<tr bgcolor='#ffffff'><td><a href='/%s/%s'>%s</a></td>"
                        "<td>(%d)</td></tr>",
                        basepath, encodedName, keystr,
                        index->items[i].vlen);
            free(encodedName);
        } else {
            fbuf_printf(buf,
                        "%s;%d\r\n",
                        keystr,
                        index->items[i].vlen);
        }
    }

    if (do_html)
        fbuf_printf(buf, "</table></body></html>");

    shardcache_free_index(index);
}

static void
shardcached_build_stats_response(fbuf_t *buf, int do_html, http_worker_t *wrk)
{
    int i;
    int num_nodes = 0;
    shardcache_node_t **nodes = shardcache_get_nodes(wrk->cache, &num_nodes);
    if (do_html) {
        fbuf_printf(buf,
                    "<html><body>"
                    "<h1>%s</h1>"
                    "<table bgcolor='#000000' "
                    "cellspacing='1' "
                    "cellpadding='4'>"
                    "<tr bgcolor='#ffffff'>"
                    "<td><b>Counter</b></td>"
                    "<td><b>Value</b></td>"
                    "</tr>"
                    "<tr bgcolor='#ffffff'>"
                    "<td>active_http_requests</td>"
                    "<td>%d</td>"
                    "</tr>"
                    "<tr bgcolor='#ffffff'>"
                    "<td>num_nodes</td>"
                    "<td>%d</td>"
                    "</tr>",
                    wrk->me,
                    ATOMIC_READ(shcd_active_requests),
                    num_nodes);

        for (i = 0; i < num_nodes; i++) {
            fbuf_printf(buf,
                        "<tr bgcolor='#ffffff'>"
                        "<td>node::%s</td><td>%s</td>"
                        "</td></tr>",
                        shardcache_node_get_label(nodes[i]), shardcache_node_get_address_at_index(nodes[i], 0));
        }
    } else {
        fbuf_printf(buf,
                    "active_http_requests;%d\r\nnum_nodes;%d\r\n",
                    ATOMIC_READ(shcd_active_requests),
                    num_nodes);
        for (i = 0; i < num_nodes; i++) {
            fbuf_printf(buf, "node::%s;%s\r\n", shardcache_node_get_label(nodes[i]), shardcache_node_get_address(nodes[i]));
        }
    }

    if (nodes)
        shardcache_free_nodes(nodes, num_nodes);

    shardcache_counter_t *counters;
    int ncounters = shardcache_get_counters(wrk->cache, &counters);

    for (i = 0; i < ncounters; i++) {
        if (do_html)
            fbuf_printf(buf,
                        "<tr bgcolor='#ffffff'><td>%s</td><td>%u</td></tr>",
                        counters[i].name,
                        counters[i].value);
        else
            fbuf_printf(buf,
                        "%s;%llu\r\n",
                        counters[i].name,
                        counters[i].value);
    }
    if (do_html)
        fbuf_printf(buf, "</table></body></html>");
    free(counters);
}

/*
static int
shardcached_parse_querystring(
*/

static void
shardcached_handle_admin_request(http_worker_t *wrk,
                                 struct mg_connection *conn,
                                 char *key,
                                 char *extra,
                                 int is_head)
{
    if (wrk->acl) {
        shcd_acl_method_t method = SHCD_ACL_METHOD_GET;
        struct in_addr remote_addr;
        inet_aton(conn->remote_ip, &remote_addr);
        if (shcd_acl_eval(wrk->acl, method, key, remote_addr.s_addr) != SHCD_ACL_ACTION_ALLOW) {
            conn->status_code = 403;
            mg_printf(conn, "HTTP/1.0 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden");
            return;
        }
    }

    int do_html = (!conn->query_string ||
                   !strstr(conn->query_string, "nohtml=1"));
    if (strcmp(key, HTTP_CONFIGURE_COMMAND) == 0) {

        char *resp = do_html ? "<html><body>OK</body></html>" : "OK";

        mg_printf(conn, HTTP_HEADERS,
                        do_html ? "text/html" : "text/plain",
                        (int)strlen(resp));

        if (!is_head)
            mg_printf(conn, "%s", resp);

    } else if (strcmp(key, HTTP_STATS_COMMAND) == 0) {
        fbuf_t buf = FBUF_STATIC_INITIALIZER;
        shardcached_build_stats_response(&buf, do_html, wrk);

        conn->status_code = 200;
        mg_printf(conn, HTTP_HEADERS,
                        do_html ? "text/html" : "text/plain",
                        fbuf_used(&buf));

        if (!is_head)
            mg_printf(conn, "%s", fbuf_data(&buf));

        fbuf_destroy(&buf);

    } else if (strcmp(key, HTTP_INDEX_COMMAND) == 0) {
        fbuf_t buf = FBUF_STATIC_INITIALIZER;
        shardcached_build_index_response(&buf, do_html, wrk->cache, wrk->basepath);

        conn->status_code = 200;
        mg_printf(conn, HTTP_HEADERS,
                        do_html ? "text/html" : "text/plain",
                        fbuf_used(&buf));

        if (!is_head)
            mg_printf(conn, "%s", fbuf_data(&buf));

        fbuf_destroy(&buf);
    } else if (strcmp(key, HTTP_HEALTH_COMMAND) == 0) {
        conn->status_code = 200;
        char *resp = do_html ? "<html><body>OK</body></html>" : "OK";
        mg_printf(conn, HTTP_HEADERS,
                        do_html ? "text/html" : "text/plain",
                        (int)strlen(resp));

        if (!is_head)
            mg_printf(conn, "%s", resp);
    } else if (strcmp(key, "__upload__") == 0) {
        fbuf_t htmlBuf = FBUF_STATIC_INITIALIZER;

        fbuf_printf(&htmlBuf,
            "<form action=\"__post__\" method=\"POST\" enctype=\"multipart/form-data\"> \
               <label for=\"file-upload\">Select a file:</label> \
               <input type=\"file\" id=\"file-upload\" name=\"userFile\"> \
               <button type=\"submit\">Upload File</button> \
             </form>", wrk->adminpath);

        char *resp = do_html ? fbuf_data(&htmlBuf) : "Not Supported in no-html mode";
        conn->status_code = 200;

        mg_printf(conn, HTTP_HEADERS,
                        do_html ? "text/html" : "text/plain",
                        (int)strlen(resp));

        if (!is_head)
            mg_printf(conn, "%s", resp);

        fbuf_destroy(&htmlBuf);
    } else {
        conn->status_code = 404;
        mg_printf(conn, "HTTP/1.0 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found");
    }
}

#define MG_REQUEST_PROCESSED 1

typedef struct {
    http_worker_t *wrk;
    struct mg_connection *conn;
    char *mtype;
    int req_status;
    int found;
    int eof;
    pthread_mutex_t slock;
    fbuf_t *sbuf;
} connection_status_t;

static void connection_status_destroy(connection_status_t *connection_status) {
    pthread_mutex_destroy(&connection_status->slock);
    fbuf_free(connection_status->sbuf);
}

typedef enum {
    PARAM_TYPE_CONNECTION_STATUS = 0,
    PARAM_TYPE_RECEIVE_BUFFER = 1
} connection_param_type_t;

typedef struct {
    connection_param_type_t type;
    union {
        connection_status_t connection_status;
        recv_buffer_t receive_buffer;
    } param;
} connection_param_t;

static int
shardcache_get_async_callback(void *key,
                              size_t klen,
                              void *data,
                              size_t dlen,
                              size_t total_size,
                              struct timeval *timestamp,
                              void *priv)
{
    connection_status_t *st = (connection_status_t *)priv;

    pthread_mutex_lock(&st->slock);

    if (st->eof) { // the connection has been closed prematurely
        pthread_mutex_unlock(&st->slock);
        fbuf_free(st->sbuf);
        pthread_mutex_destroy(&st->slock);
        free(st);
        return -1;
    }

    if (!dlen && !total_size) {
        fbuf_printf(st->sbuf, "HTTP/1.0 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found");
        st->conn->status_code = 404;
        st->req_status = MG_REQUEST_PROCESSED;
        pthread_mutex_unlock(&st->slock);
        return 0;
    }

    if (!st->found) {
        fbuf_printf(st->sbuf, HTTP_HEADERS, st->mtype, total_size);
        st->found = 1;
    }

    if (dlen)
        fbuf_add_binary(st->sbuf, data, dlen);

    if (total_size && timestamp)
        st->req_status = MG_REQUEST_PROCESSED;

    pthread_mutex_unlock(&st->slock);
    return 0;
}

static int
shardcached_handle_get_request(http_worker_t *wrk, struct mg_connection *conn, char *key, int is_head)
{
    if (wrk->acl) {
        shcd_acl_method_t method = SHCD_ACL_METHOD_GET;
        struct in_addr remote_addr;
        inet_aton(conn->remote_ip, &remote_addr);
        if (shcd_acl_eval(wrk->acl, method, key, remote_addr.s_addr) != SHCD_ACL_ACTION_ALLOW) {
            mg_printf(conn, "HTTP/1.0 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden");
            conn->status_code = 403;
            return MG_TRUE;
        }
    }

    char *mtype = NULL;
    if (wrk->mime_types) {
        char *p = key;
        while (*p && *p != '.')
            p++;
        if (*p && *(p+1)) {
            p++;
            mtype = (char *)ht_get(wrk->mime_types, p, strlen(p), NULL);
            if (!mtype)
                mtype = (char *)mg_get_mime_type(key, "application/octet-stream");
        }
    } else {
        mtype = (char *)mg_get_mime_type(key, "application/octet-stream");
    }


    size_t vlen = 0;
    struct timeval ts = { 0, 0 };
    void *value = NULL;
    if (is_head) {
        vlen = shardcache_head(wrk->cache, key, strlen(key), NULL, 0, &ts);
        if (vlen) {
            int i;
            for (i = 0; i < conn->num_headers; i++) {
                struct tm tm;
                const char *hdr_name = conn->http_headers[i].name;
                const char *hdr_value = conn->http_headers[i].value;
                if (strcasecmp(hdr_name, "If-Modified-Since") == 0) {
                    if (strptime(hdr_value, "%a, %d %b %Y %T %z", &tm) != NULL) {
                        time_t time = mktime(&tm);
                        if (ts.tv_sec < time) {
                            mg_printf(conn, "HTTP/1.0 304 Not Modified\r\nContent-Length: 12\r\n\r\nNot Modified");
                            if (value)
                                free(value);
                            conn->status_code = 304;
                            return MG_TRUE;
                        }
                    }
                } else if (strcasecmp(hdr_name, "If-Unmodified-Since") == 0) {
                    if (strptime(hdr_value, "%a, %d %b %Y %T %z", &tm) != NULL) {
                        time_t time = mktime(&tm);
                        if (ts.tv_sec > time) {
                            mg_printf(conn, "HTTP/1.0 412 Precondition Failed\r\nContent-Length: 19\r\n\r\nPrecondition Failed");
                            if (value)
                                free(value);
                            conn->status_code = 412;
                            return MG_TRUE;
                        }

                    }
                }
            }

            char timestamp[256];
            struct tm gmts;
            strftime(timestamp, sizeof(timestamp), "%a, %d %b %Y %T %z", gmtime_r(&ts.tv_sec, &gmts));
            mg_printf(conn, HTTP_HEADERS_WITH_TIME, mtype, (int)vlen, timestamp);

            if (!is_head && value)
                mg_write(conn, value, vlen);

            if (value)
                free(value);
        } else {
            mg_printf(conn, "HTTP/1.0 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found");
            conn->status_code = 404;
        }
    } else {
        connection_param_t *cp = calloc(1, sizeof(connection_param_t));
        cp->type = PARAM_TYPE_CONNECTION_STATUS;
        cp->param.connection_status.wrk = wrk;
        cp->param.connection_status.conn = conn;
        cp->param.connection_status.mtype = mtype;
        pthread_mutex_init(&cp->param.connection_status.slock, NULL);
        cp->param.connection_status.sbuf = fbuf_create(0);

        int rc = shardcache_get(wrk->cache, key, strlen(key), shardcache_get_async_callback, &cp->param.connection_status);
        if (rc != 0) {
            mg_printf(conn, "HTTP/1.0 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found");
            conn->status_code = 404;
            connection_status_destroy(&cp->param.connection_status);
            free(cp);
            return MG_TRUE;
        }

        conn->connection_param = cp;

        return MG_MORE;
    }

    return MG_TRUE;
}

static void
shardcached_handle_delete_request(http_worker_t *wrk, struct mg_connection *conn, char *key)
{
    if (wrk->acl) {
        shcd_acl_method_t method = SHCD_ACL_METHOD_DEL;
        struct in_addr remote_addr;
        inet_aton(conn->remote_ip, &remote_addr);
        if (shcd_acl_eval(wrk->acl, method, key, remote_addr.s_addr) != SHCD_ACL_ACTION_ALLOW) {
            conn->status_code = 403;
            mg_printf(conn, "HTTP/1.0 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden");
            return;
        }
    }

    int rc = shardcache_del(wrk->cache, key, strlen(key), 0 , NULL);
    mg_printf(conn, "HTTP/1.0 %s\r\n"
                    "Content-Length: 0\r\n\r\n",
                     rc == 0 ? "200 OK" : "500 ERR");

}

static void
shardcached_handle_post_request(http_worker_t *wrk, struct mg_connection *conn, char *key)
{
    if (wrk->acl) {
        shcd_acl_method_t method = SHCD_ACL_METHOD_POST;
        struct in_addr remote_addr;
        inet_aton(conn->remote_ip, &remote_addr);
        if (shcd_acl_eval(wrk->acl, method, key, remote_addr.s_addr) != SHCD_ACL_ACTION_ALLOW) {
            conn->status_code = 403;
            mg_printf(conn, "HTTP/1.0 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden");
            return;
        }
    }


    fbuf_t output_data = FBUF_STATIC_INITIALIZER;
    fbuf_printf(&output_data, "<html><body>Data stored successfully. Go to the <a href=\"/%s/__index__\">Index</a>", wrk->basepath);

    connection_param_t *cp = (connection_param_t *)conn->connection_param;
    if (cp != NULL) {
        recv_buffer_t *recvb = &cp->param.receive_buffer;

        if (conn->content_len) {
            char *b = strstr(conn->content, fbuf_data(&recvb->boundary));
            if (b != NULL) {
                fbuf_add_binary(&recvb->fbuf, conn->content, b - conn->content);
            } else {
                fbuf_add_binary(&recvb->fbuf, conn->content, conn->content_len);
            }
        }

        while (fbuf_used(&recvb->fbuf)) {
            int wb = fbuf_write(&recvb->fbuf, recvb->fd, 0);
            if (wb == -1) {
                SHC_ERROR("Can't completely flush the receive buffer. Key %s is probably truncated. (%s)",
                          recvb->name, strerror(errno));
                break;
            }
        }
        shardcache_set_local(wrk->cache, recvb->name, strlen(recvb->name), recvb->filename, recvb->data_len, 0);
        recv_buffer_destroy(recvb);
        conn->connection_param = NULL;

        conn->status_code = 200;

        int do_html = (!conn->query_string ||
                       !strstr(conn->query_string, "nohtml=1"));

        mg_printf(conn, HTTP_HEADERS,
                        do_html ? "text/html" : "text/plain",
                        do_html ? fbuf_used(&output_data) : 2);
        mg_printf(conn, "%s", do_html ? fbuf_data(&output_data) : "Ok");
    } else {
            const char *data = NULL;
            int data_len = 0;
            char var_name[HTTP_MAX_KEYLEN];
            char file_name[HTTP_MAX_KEYLEN];
            mg_parse_multipart(conn->content, conn->content_len, var_name, sizeof(var_name), file_name, sizeof(file_name), &data, &data_len);
            if (data != NULL && data_len > 0) {
                shardcache_set(wrk->cache, file_name, strlen(file_name), (char *)data, data_len, 0, 0, 0, (void *)NULL, (void *)NULL);

            conn->status_code = 200;
            int do_html = (!conn->query_string ||
                           !strstr(conn->query_string, "nohtml=1"));

            mg_printf(conn, HTTP_HEADERS,
                            do_html ? "text/html" : "text/plain",
                            do_html ? fbuf_used(&output_data) : 2);
            mg_printf(conn, "%s", do_html ? fbuf_data(&output_data) : "Ok");
        } else {
            mg_printf(conn, "HTTP/1.0 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
            conn->status_code = 500;
        }
    }
}

static void
shardcached_handle_put_request(http_worker_t *wrk, struct mg_connection *conn, char *key)
{
    if (wrk->acl) {
        shcd_acl_method_t method = SHCD_ACL_METHOD_PUT;
        struct in_addr remote_addr;
        inet_aton(conn->remote_ip, &remote_addr);
        if (shcd_acl_eval(wrk->acl, method, key, remote_addr.s_addr) != SHCD_ACL_ACTION_ALLOW) {
            mg_printf(conn, "HTTP/1.0 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden");
            return;
        }
    }

    int clen = 0;
    const char *clen_hdr = mg_get_header(conn, "Content-Length");
    if (clen_hdr) {
        clen = strtol(clen_hdr, NULL, 10);
    }

    if (!clen) {
        mg_printf(conn, "HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        return;
    }

    shardcache_set(wrk->cache, key, strlen(key), conn->content, conn->content_len, 0, 0, 0, (void *)NULL, (void *)NULL);

    mg_printf(conn, "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
}

static int
shardcached_http_close_handler(struct mg_connection *conn)
{
    connection_param_t *cp = conn->connection_param;
    if (cp) {
        switch(cp->type) {
            case PARAM_TYPE_RECEIVE_BUFFER:
                recv_buffer_t *recvb = &cp->param.receive_buffer;
                recv_buffer_destroy(recvb);
                break;
            case PARAM_TYPE_CONNECTION_STATUS:
                connection_status_t *st = &cp->param.connection_status;
                pthread_mutex_lock(&st->slock);
                if (st->req_status == MG_REQUEST_PROCESSED) {
                    connection_status_destroy(st);
                } else {
                    st->eof = 1;
                    pthread_mutex_unlock(&st->slock);
                }
                break;
            default:
                SHC_ERROR("Unknown connection params found!");
        }
        free(cp);
        conn->connection_param = NULL;
    }
    return 0;
}

static inline int
shardcached_parse_request(const char *uri,
                          const char *basepath,
                          const char *adminpath,
                          char **key,
                          char **extra,
                          int *is_admin)
{
    char *k = (char *)uri;

    int basepath_len = strlen(basepath);
    int baseadminpath_len = strlen(adminpath);
    int basepaths_differ = (basepath_len != baseadminpath_len || strcmp(basepath, adminpath) != 0);

    while (*k == '/' && *k)
        k++;

    if (basepath_len || baseadminpath_len) {
        if (basepath_len && strncmp(k, basepath, basepath_len) == 0 &&
            strlen(k) > basepath_len && k[basepath_len] == '/')
        {
            k += basepath_len + 1;
            while (*k == '/' && *k)
                k++;
        }
        else if (basepaths_differ && baseadminpath_len &&
                 strncmp(k, adminpath, baseadminpath_len) == 0 &&
                 strlen(k) > baseadminpath_len && k[baseadminpath_len] == '/')
        {
            k += baseadminpath_len + 1;
            while (*k == '/' && *k)
                k++;
        }
        else
        {
            SHC_DEBUG("Out-of-scope uri : %s", uri);
            return 0;
        }
    }

    if (*k)
    {
        if (key)
            *key = k;

        char *e = NULL;
        int is_admin_url = ((!baseadminpath_len || !basepaths_differ) && is_admin_command(k, &e));
        if (is_admin)
            *is_admin = is_admin_url;

        if (extra)
            *extra = e;

        return 1;
    }

    return 0;
}

static int
shardcached_request_handler(struct mg_connection *conn, enum mg_event event)
{
    connection_param_t *cp = conn->connection_param;
    switch(event)
    {
        case MG_CLOSE:
            if (cp)
                return shardcached_http_close_handler(conn);
            break;
        case MG_RECV:
            // ignore MG_RECV events
            // NOTE : mongoose API expects the number of consumed bytes
            //        as return value from MG_RECV events

            if (strncasecmp(conn->request_method, "POST", 4) == 0 ||
                strncasecmp(conn->request_method, "PUT", 3) == 0)
            {
                int ofx = 0;
                connection_param_t *cp = (connection_param_t *)conn->connection_param;
                if (cp == NULL && conn->content_len > 1e9) {
                    cp = calloc(1, sizeof(connection_param_t));
                    cp->type = PARAM_TYPE_RECEIVE_BUFFER;
                    recv_buffer_t *recvb = &cp->param.receive_buffer;
                    FBUF_STATIC_INITIALIZER_POINTER(&recvb->fbuf, FBUF_MAXLEN_NONE, FBUF_MINLEN, FBUF_FASTGROWSIZE, FBUF_SLOWGROWSIZE);
                    FBUF_STATIC_INITIALIZER_POINTER(&recvb->boundary, FBUF_MAXLEN_NONE, FBUF_MINLEN, FBUF_FASTGROWSIZE, FBUF_SLOWGROWSIZE);

                    strcpy(recvb->filename, "/tmp/shcd_http_XXXXXX");
                    recvb->fd = mkstemp(recvb->filename);
                    conn->connection_param = cp;

                    if (strncasecmp(conn->request_method, "POST", 4) == 0) {
                        char *el = strstr(conn->content, "\r\n");
                        ofx = el - conn->content;

                        fbuf_add_binary(&recvb->boundary, conn->content, ofx);
                        ofx += 2;
                    }
                    mg_parse_header(conn->content+ofx, "filename", recvb->name, sizeof(recvb->name));
                    char *el = strstr(conn->content+ofx, "\r\n\r\n");
                    ofx = el - conn->content+4;
                }
                if (cp != NULL) {
                    recv_buffer_t *recvb = &cp->param.receive_buffer;
                    char *p = conn->content + ofx;
                    int len = conn->content_len - ofx;
                    char *b = strstr(p, fbuf_data(&recvb->boundary));
                    if (b != NULL) {
                        fbuf_add_binary(&recvb->fbuf, p, b - p);
                    } else {
                        fbuf_add_binary(&recvb->fbuf, p, len);
                    }
                    int wr = fbuf_write(&recvb->fbuf, recvb->fd, 0);
                    if (wr == -1) {
                        SHC_ERROR("Can't flush the receive buffer: %s",
                                  recvb->name, strerror(errno));
                    }
                    recvb->data_len += wr;
                    return conn->content_len;
                }
            }
            return 0;
        case MG_POLL:
        {
            if (cp && cp->type == PARAM_TYPE_CONNECTION_STATUS) {
                connection_status_t *st = (connection_status_t *)&cp->param.connection_status;
                if (st) {
                    int status = st->req_status;
                    int len = fbuf_used(st->sbuf);
                    if (len) {
                        mg_write(conn, fbuf_data(st->sbuf), len);
                        fbuf_remove(st->sbuf, len);
                    }
                    if (status == MG_REQUEST_PROCESSED) {
                        connection_status_destroy(st);
                        free(cp);
                        conn->connection_param = NULL;
                        return MG_TRUE;
                    }
                }
            }
            return MG_MORE;
        }
        case MG_REQUEST:
        {
            http_worker_t *wrk = conn->server_param;

            char *key = NULL;
            int is_admin = 0;
            char *extra = NULL;

            ATOMIC_INCREMENT(shcd_active_requests);

            if (!shardcached_parse_request(conn->uri, wrk->basepath, wrk->adminpath, &key, &extra, &is_admin))
            {
                mg_printf(conn, "HTTP/1.0 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found");
                ATOMIC_DECREMENT(shcd_active_requests);
                conn->status_code = 404;
                break;
            }

            if (*key == 0) {
                mg_printf(conn, "HTTP/1.0 404 Not Found\r\nContent-Length 9\r\n\r\nNot Found");
                ATOMIC_DECREMENT(shcd_active_requests);
                conn->status_code = 404;
                return MG_TRUE;
            }

            // if baseadminpath is not defined or it's the same as basepath,
            // we need to check for the "special" admin keys and handle them differently
            // (in such cases the labels __stats__, __index__ and __health__ become reserved
            // and can't be used as keys from the http interface)
            if (is_admin) {
                if (strncasecmp(conn->request_method, "GET", 3) == 0) {
                    shardcached_handle_admin_request(wrk, conn, key, extra, 0);
                //    rc = MG_MORE;
                } else {
                    conn->status_code = 403;
                    mg_printf(conn, "HTTP/1.0 403 Forbidden\r\nContent-Length 9\r\n\r\nForbidden");
                }
                ATOMIC_DECREMENT(shcd_active_requests);
                break;
            }

            // handle the actual GET/PUT/DELETE request
            conn->status_code = 200;
            if (strncasecmp(conn->request_method, "GET", 3) == 0)
                return shardcached_handle_get_request(wrk, conn, key, 0);
            else if (strncasecmp(conn->request_method, "HEAD", 4) == 0)
                return shardcached_handle_get_request(wrk, conn, key, 1);
            else if (strncasecmp(conn->request_method, "DELETE", 6) == 0)
                shardcached_handle_delete_request(wrk, conn, key);
            else if (strncasecmp(conn->request_method, "PUT", 3) == 0)
                shardcached_handle_put_request(wrk, conn, key);
            else if (strncasecmp(conn->request_method, "POST", 4) == 0)
                shardcached_handle_post_request(wrk, conn, key);
            else {
                mg_printf(conn, "HTTP/1.0 405 Method Not Allowed\r\nContent-Length: 11\r\n\r\nNot Allowed");
                conn->status_code = 405;
            }


            ATOMIC_DECREMENT(shcd_active_requests);
        }
        default:
            break;
    }
    return MG_TRUE;
}


void *
shcd_http_run(void *priv)
{
    http_worker_t *wrk = (http_worker_t *)priv;
    shardcache_thread_init(wrk->cache);
    while (!ATOMIC_READ(wrk->leave)) {
        mg_poll_server(wrk->server, 1000);
    }
    shardcache_thread_end(wrk->cache);
    return NULL;
}

shcd_http_t *
shcd_http_create(shardcache_t *cache,
                 const char *me,
                 const char *basepath,
                 const char *adminpath,
                 shcd_acl_t *acl,
                 hashtable_t *mime_types,
                 const char **options,
                 int num_workers)
{
    int i, n;
    if (num_workers < 0)
        return NULL;

    shcd_http_t *http = calloc(1, sizeof(shcd_http_t));

    http->num_workers = num_workers;

    TAILQ_INIT(&http->workers);
    for (i = 0; i < num_workers; i++) {

        http_worker_t *wrk = calloc(1, sizeof(http_worker_t));

        wrk->server = mg_create_server(wrk, shardcached_request_handler);
        if (!wrk->server) {
            SHC_ERROR("Can't start mongoose server");
            shcd_http_destroy(http);
            return NULL;
        }

        wrk->cache = cache;
        wrk->me = me;
        wrk->basepath = basepath;
        wrk->adminpath = adminpath;
        wrk->acl = acl;
        wrk->mime_types = mime_types;

        for (n = 0; options[n]; n += 2) {
            const char *option = options[n];
            const char *value = options[n+1];
            if (!option || !value) {
                SHC_ERROR("Bad mongoose options");
                shcd_http_destroy(http);
                return NULL;

            }
            if (strcmp(option, "listening_port") == 0 && i > 0) {
                mg_copy_listeners(TAILQ_FIRST(&http->workers)->server, wrk->server);
            } else {
                const char *msg = mg_set_option(wrk->server, option, value);
                if (msg != NULL) {
                    SHC_ERROR("Failed to set mongoose option [%s=%s]: %s",
                               option, value, msg);
                    shcd_http_destroy(http);
                    return NULL;
                }
            }
        }

        TAILQ_INSERT_TAIL(&http->workers, wrk, next);
        if (pthread_create(&wrk->th, NULL, shcd_http_run, wrk) != 0) {
            SHC_ERROR("Failed to start an http worker thread: %s",
                       strerror(errno));
            shcd_http_destroy(http);
            return NULL;
        }
    }
    return http;
};

void
shcd_http_destroy(shcd_http_t *http)
{
    http_worker_t *worker, *tmp;
    TAILQ_FOREACH_SAFE(worker, &http->workers, next, tmp) {
        TAILQ_REMOVE(&http->workers, worker, next);
        ATOMIC_INCREMENT(worker->leave);
        //pthread_cancel(worker->th);
        pthread_join(worker->th, NULL);
        mg_destroy_server(&worker->server);
        free(worker);
    }
    free(http);
}
