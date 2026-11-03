/*---[ fs-dash-http.h ]---------------------------------------------------
 * The dashboard's small HTTP/1.1 server (fs-dash-http.c).
 *
 * It owns the listening socket, the checks made when a connection is
 * accepted (peer address and peer uid), the connection slots, the
 * deadlines, request parsing and the checks every request crosses
 * before a handler sees it (Host, Upgrade, Transfer-Encoding,
 * Content-Length).  fs-dashboard.c supplies one handler that routes
 * the request and answers it exactly once.  Linux only.
 *--------------------------------------------------------------------*/
#ifndef FS_DASH_HTTP_H
#define FS_DASH_HTTP_H

#include <gio/gio.h>
#include <sys/types.h>

/* The request head must arrive within this many seconds of the
 * accept, the body (if any) within as many after the head, and the
 * answer must be written within as many again (T2). */
#define FS_DASH_DEADLINE_S   5
#define FS_DASH_MAX_HEAD     16384
#define FS_DASH_MAX_BODY     65536
/* Connections from one uid still sending their request.  A new one
 * past the limit closes the oldest of them (T2). */
#define FS_DASH_SLOTS_OPEN   16
/* All connections at once, whatever they are doing. */
#define FS_DASH_MAX_ALL      64

typedef struct _FsDashHttp FsDashHttp;
typedef struct _FsDashConn FsDashConn;

/* Called once per request that passed the server's checks.  It must
 * answer with one fs_dash_respond* call before it returns. */
typedef void (*FsDashHandler) (FsDashConn *conn, gpointer data);

/* Binds 127.0.0.1:want_port (0: the kernel picks).  Only connections
 * from 127.0.0.1 whose socket belongs to peer_uid are served. */
FsDashHttp  *fs_dash_http_new        (guint16 want_port, uid_t peer_uid,
                                      GError **error);
guint16      fs_dash_http_port       (const FsDashHttp *http);
/* The CSP nonce sent with every answer. */
void         fs_dash_http_set_nonce  (FsDashHttp *http, const gchar *nonce);
/* Adds an accepted Host value.  "127.0.0.1:<port>" is always there. */
void         fs_dash_http_allow_host (FsDashHttp *http, const gchar *host);
/* WSL with --allow-windows (2B): a peer at 127.0.0.1 whose socket has
 * no owner in /proc/net/tcp (Windows' localhost relay) is served too,
 * and fs_dash_conn_ownerless() says so.  Off, it is closed at accept,
 * and `refused' (when set) is called for it. */
void         fs_dash_http_allow_ownerless (FsDashHttp *http, gboolean allow);
void         fs_dash_http_on_ownerless_refused (FsDashHttp *http,
                                                GFunc refused,
                                                gpointer data);
void         fs_dash_http_start      (FsDashHttp *http,
                                      FsDashHandler handler, gpointer data);
void         fs_dash_http_free       (FsDashHttp *http);

const gchar *fs_dash_conn_method     (const FsDashConn *conn);
const gchar *fs_dash_conn_path       (const FsDashConn *conn);
/* The query parameters, or NULL without a query. */
GHashTable  *fs_dash_conn_params     (const FsDashConn *conn);
gboolean     fs_dash_conn_head_only  (const FsDashConn *conn);
/* A request header, case-insensitively; NULL if absent.  Free it. */
gchar       *fs_dash_conn_header     (const FsDashConn *conn,
                                      const gchar *name);
/* How many times a header appears. */
guint        fs_dash_conn_header_count (const FsDashConn *conn,
                                        const gchar *name);
/* The body Content-Length announced (it is all read); NULL with none. */
const gchar *fs_dash_conn_body       (const FsDashConn *conn, gsize *len);
/* TRUE when Content-Length was given (even as 0). */
gboolean     fs_dash_conn_has_length (const FsDashConn *conn);
/* TRUE for a peer let in by fs_dash_http_allow_ownerless. */
gboolean     fs_dash_conn_ownerless  (const FsDashConn *conn);

void         fs_dash_respond         (FsDashConn *conn, guint status,
                                      const gchar *type, const guint8 *body,
                                      gsize body_len);
/* Takes json. */
void         fs_dash_respond_json    (FsDashConn *conn, guint status,
                                      gchar *json);
void         fs_dash_respond_error   (FsDashConn *conn, guint status,
                                      const gchar *message);

/* [ fs_dash_peer_uid ]
 * The uid that owns the other end of a loopback TCP connection, from
 * the uid column of /proc/net/tcp (or tcp6) for the socket whose local
 * address is `peer' and whose remote address is `local'.  FALSE when no
 * such socket is listed or it has no owner (inode 0). */
gboolean     fs_dash_peer_uid        (GInetSocketAddress *peer,
                                      GInetSocketAddress *local,
                                      uid_t *uid);

#endif /* FS_DASH_HTTP_H */
