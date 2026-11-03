/*---[ fs-dash-http.c ]---------------------------------------------------
 * The dashboard's HTTP server, split out of fs-dashboard.c (PR 2, 2A).
 *
 * What it guarantees before a handler sees a request:
 *
 *   - At accept, before a byte is read: the peer is 127.0.0.1, and the
 *     peer's socket belongs to the one uid this dashboard serves (its
 *     own, or SUDO_UID under sudo; never uid 0).  The owner comes from
 *     the uid column of /proc/net/tcp, since SO_PEERCRED does not work
 *     on TCP.  Any other connection is closed at once, unread.
 *   - Slots: at most FS_DASH_SLOTS_OPEN connections per uid may be
 *     sending a request.  One more closes the oldest of them, so slow
 *     senders can no longer lock the user out (T2: with 32 of them
 *     held, the old server answered nothing).
 *   - Deadlines: the request head must arrive within 5 s of the
 *     accept and a body within 5 s after the head, however slowly the
 *     bytes trickle in; the answer must be written within 5 s.
 *   - The request: a three-part request line with HTTP/1.x, a head of
 *     at most 16 KB however it is split (431), exactly one Host header
 *     that is exactly 127.0.0.1:<port> (403: `localhost' is not
 *     accepted, G4), no Upgrade header (400: no WebSocket, T7), no
 *     Transfer-Encoding (400), and a Content-Length of at most 64 KB
 *     (413), whose body is read before the handler runs.
 *   - Every answer is written in one piece with Connection: close and
 *     the dashboard's security headers (2B added Trusted Types,
 *     Permissions-Policy and Cross-Origin-Embedder-Policy).
 *   - WSL with --allow-windows (2B): a peer with no socket owner is
 *     served as its own class; otherwise it is closed like any other.
 *--------------------------------------------------------------------*/
#include "cli/fs-dash-http.h"
#include "core/fs-json.h"

#include <stdio.h>
#include <string.h>

typedef struct
{
	GQueue open;           /* FsDashConn*, oldest first */
} SlotGroup;

struct _FsDashHttp
{
	GSocketService *service;
	guint16         port;
	uid_t           peer_uid;
	gchar          *nonce;
	GPtrArray      *hosts;  /* accepted Host values */
	GHashTable     *groups; /* uid -> SlotGroup* */
	guint           all;    /* every live connection */
	FsDashHandler   handler;
	gpointer        handler_data;
	gboolean        allow_ownerless;
	GFunc           ownerless_refused;
	gpointer        ownerless_data;
};

struct _FsDashConn
{
	FsDashHttp        *http;
	GSocketConnection *connection;
	GCancellable      *cancel;
	SlotGroup         *group;   /* while it holds an open slot */
	GList             *node;
	guint              deadline_id;
	gboolean           aborted;

	GString           *in;       /* every byte read so far */
	gsize              head_len; /* up to the blank line, once seen */
	gsize              body_len;
	guint8             buffer[4096];

	gchar            **lines;
	gchar             *method;
	gchar             *path;
	GHashTable        *params;
	gboolean           head_only;
	gboolean           answered;
	gboolean           has_length;
	gboolean           ownerless;
};

/* ------------------------------------------------------- the peer's uid */

/* [ hex_word ] -- 8 hex digits as the kernel printed a 32-bit word. */
static gboolean
hex_word (const gchar *s, guint32 *out)
{
	gchar buf[9];
	gchar *end = NULL;

	memcpy (buf, s, 8);
	buf[8] = '\0';
	*out = (guint32) g_ascii_strtoull (buf, &end, 16);
	return end == buf + 8;
}

/* [ addr_matches ]
 * One "ADDR:PORT" column of /proc/net/tcp{,6} against an address in
 * network byte order.  The kernel prints each 32-bit word of the
 * address with %08X as it sits in memory, and the port in host order.
 * In tcp6 an IPv4 address appears in its mapped form ::ffff:a.b.c.d. */
static gboolean
addr_matches (const gchar *col, gboolean v6, const guint8 *bytes4,
              guint16 port)
{
	guint8 want[16];
	guint words = v6 ? 4 : 1;
	const gchar *colon = strchr (col, ':');
	gchar *end = NULL;
	guint64 p;

	if (colon == NULL || (gsize) (colon - col) != words * 8)
		return FALSE;
	p = g_ascii_strtoull (colon + 1, &end, 16);
	if (end == colon + 1 || *end != '\0' || p != port)
		return FALSE;

	if (v6) {
		memset (want, 0, 10);
		want[10] = 0xff;
		want[11] = 0xff;
		memcpy (want + 12, bytes4, 4);
	} else {
		memcpy (want, bytes4, 4);
	}

	for (guint i = 0; i < words; i++) {
		guint32 word, mine;

		if (!hex_word (col + i * 8, &word))
			return FALSE;
		memcpy (&mine, want + i * 4, 4);
		if (word != mine)
			return FALSE;
	}
	return TRUE;
}

static gboolean
owner_in (const gchar *file, gboolean v6, const guint8 *peer4,
          guint16 peer_port, const guint8 *local4, guint16 local_port,
          uid_t *uid)
{
	gchar *text = NULL;
	gchar **lines;
	gboolean found = FALSE;

	if (!g_file_get_contents (file, &text, NULL, NULL))
		return FALSE;

	lines = g_strsplit (text, "\n", -1);
	/* Line 0 is the column header. */
	for (guint i = 1; lines[i] != NULL && !found; i++) {
		gchar **f = g_strsplit_set (g_strstrip (lines[i]), " \t", -1);
		const gchar *col[10];
		guint n = 0;

		for (guint k = 0; f[k] != NULL && n < G_N_ELEMENTS (col); k++)
			if (*f[k] != '\0')
				col[n++] = f[k];

		/* sl local rem st tx:rx tr:when retrnsmt uid timeout inode */
		if (n == G_N_ELEMENTS (col) &&
		    addr_matches (col[1], v6, peer4, peer_port) &&
		    addr_matches (col[2], v6, local4, local_port)) {
			gchar *end = NULL;
			guint64 u = g_ascii_strtoull (col[7], &end, 10);
			gchar *iend = NULL;
			guint64 inode = g_ascii_strtoull (col[9], &iend, 10);

			/* Inode 0: no socket owner (an orphan, or a
			 * connection the kernel is finishing). */
			if (end != col[7] && *end == '\0' && u < G_MAXUINT32 &&
			    iend != col[9] && *iend == '\0' && inode != 0) {
				*uid = (uid_t) u;
				found = TRUE;
			}
		}
		g_strfreev (f);
	}
	g_strfreev (lines);
	g_free (text);
	return found;
}

gboolean
fs_dash_peer_uid (GInetSocketAddress *peer, GInetSocketAddress *local,
                  uid_t *uid)
{
	GInetAddress *pa = g_inet_socket_address_get_address (peer);
	GInetAddress *la = g_inet_socket_address_get_address (local);
	guint8 p4[4], l4[4];
	guint16 pp = g_inet_socket_address_get_port (peer);
	guint16 lp = g_inet_socket_address_get_port (local);

	if (g_inet_address_get_family (pa) != G_SOCKET_FAMILY_IPV4 ||
	    g_inet_address_get_family (la) != G_SOCKET_FAMILY_IPV4)
		return FALSE;
	memcpy (p4, g_inet_address_to_bytes (pa), 4);
	memcpy (l4, g_inet_address_to_bytes (la), 4);

	/* An IPv4 client lists its socket in tcp; a dual-stack IPv6
	 * client connecting to 127.0.0.1 lists it in tcp6, mapped. */
	return owner_in ("/proc/net/tcp", FALSE, p4, pp, l4, lp, uid) ||
	       owner_in ("/proc/net/tcp6", TRUE, p4, pp, l4, lp, uid);
}

/* The slot group of peers without a socket owner (WSL, 2B). */
#define OWNERLESS_UID ((uid_t) -1)

/* [ peer_allowed ] -- the accept-time checks, before any byte is read. */
static gboolean
peer_allowed (FsDashHttp *http, GSocketConnection *connection, uid_t *uid,
              gboolean *ownerless)
{
	GSocketAddress *peer, *local;
	gboolean ok = FALSE;

	peer  = g_socket_connection_get_remote_address (connection, NULL);
	local = g_socket_connection_get_local_address (connection, NULL);

	if (G_IS_INET_SOCKET_ADDRESS (peer) && G_IS_INET_SOCKET_ADDRESS (local)) {
		GInetAddress *pa = g_inet_socket_address_get_address (
			G_INET_SOCKET_ADDRESS (peer));
		gchar *text = g_inet_address_to_string (pa);

		/* 127.0.0.1 exactly: not another address of 127/8. */
		if (g_strcmp0 (text, "127.0.0.1") == 0) {
			gboolean listed = fs_dash_peer_uid (
				G_INET_SOCKET_ADDRESS (peer),
				G_INET_SOCKET_ADDRESS (local), uid);
#ifdef FS_DASH_TESTING
			/* The test build only: sockets of this uid count as
			 * having no owner, as Windows' relay is expected to. */
			const gchar *t = g_getenv ("STOCKFW_TEST_OWNERLESS_UID");

			if (listed && t != NULL && *t != '\0' &&
			    g_ascii_strtoull (t, NULL, 10) == (guint64) *uid)
				listed = FALSE;
#endif
			if (listed && *uid == http->peer_uid && *uid != 0) {
				ok = TRUE;
			} else if (!listed && http->allow_ownerless) {
				/* WSL with --allow-windows: no socket of
				 * this machine's accounts, so the relay. */
				*uid = OWNERLESS_UID;
				*ownerless = TRUE;
				ok = TRUE;
			} else if (!listed && http->ownerless_refused != NULL) {
				http->ownerless_refused (NULL, http->ownerless_data);
			}
		}
		g_free (text);
	}

	g_clear_object (&peer);
	g_clear_object (&local);
	return ok;
}

/* ---------------------------------------------------------- the slots */

static void
slot_release (FsDashConn *conn)
{
	if (conn->group == NULL)
		return;
	g_queue_delete_link (&conn->group->open, conn->node);
	conn->group = NULL;
	conn->node = NULL;
}

static void
deadline_clear (FsDashConn *conn)
{
	if (conn->deadline_id != 0) {
		g_source_remove (conn->deadline_id);
		conn->deadline_id = 0;
	}
}

/* [ conn_free ] -- from the callback of the one async call in flight. */
static void
conn_free (FsDashConn *conn)
{
	slot_release (conn);
	deadline_clear (conn);
	g_io_stream_close (G_IO_STREAM (conn->connection), NULL, NULL);
	conn->http->all--;
	g_object_unref (conn->connection);
	g_object_unref (conn->cancel);
	g_string_free (conn->in, TRUE);
	g_strfreev (conn->lines);
	g_free (conn->method);
	g_free (conn->path);
	if (conn->params != NULL)
		g_hash_table_unref (conn->params);
	g_free (conn);
}

/* [ conn_abort ]
 * Ends a connection from outside its I/O: an expired deadline or an
 * eviction.  The read or write in flight then fails as cancelled, and
 * its callback frees the connection. */
static void
conn_abort (FsDashConn *conn)
{
	if (conn->aborted)
		return;
	conn->aborted = TRUE;
	slot_release (conn);
	deadline_clear (conn);
	g_cancellable_cancel (conn->cancel);
}

static gboolean
on_deadline (gpointer data)
{
	FsDashConn *conn = data;

	conn->deadline_id = 0;
	conn_abort (conn);
	return G_SOURCE_REMOVE;
}

static void
deadline_start (FsDashConn *conn)
{
	deadline_clear (conn);
	conn->deadline_id = g_timeout_add_seconds (FS_DASH_DEADLINE_S,
	                                           on_deadline, conn);
}

/* ------------------------------------------------------------ answers */

static const gchar *
status_text (guint status)
{
	switch (status) {
	case 200: return "OK";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 410: return "Gone";
	case 411: return "Length Required";
	case 413: return "Content Too Large";
	case 415: return "Unsupported Media Type";
	case 431: return "Request Header Fields Too Large";
	case 503: return "Service Unavailable";
	default:  return "Error";
	}
}

static void
on_written (GObject *source, GAsyncResult *result, gpointer data)
{
	FsDashConn *conn = data;

	g_output_stream_write_all_finish (G_OUTPUT_STREAM (source), result,
	                                  NULL, NULL);
	conn_free (conn);
}

void
fs_dash_respond (FsDashConn *conn, guint status, const gchar *type,
                 const guint8 *body, gsize body_len)
{
	FsDashHttp *http = conn->http;
	GString *out;
	GOutputStream *stream;
	GBytes *bytes;
	gsize size;
	gpointer data;

	g_return_if_fail (!conn->answered);
	conn->answered = TRUE;

	out = g_string_new (NULL);
	g_string_append_printf (out,
		"HTTP/1.1 %u %s\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %" G_GSIZE_FORMAT "\r\n"
		"Cache-Control: no-store\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"X-Frame-Options: DENY\r\n"
		"Referrer-Policy: no-referrer\r\n"
		"Cross-Origin-Opener-Policy: same-origin\r\n"
		"Cross-Origin-Resource-Policy: same-origin\r\n"
		"Content-Security-Policy: default-src 'none'; "
		"script-src 'nonce-%s'; style-src 'nonce-%s'; "
		"connect-src 'self'; img-src 'self'; base-uri 'none'; "
		"form-action 'none'; frame-ancestors 'none'; "
		"require-trusted-types-for 'script'; trusted-types 'none'\r\n"
		"Permissions-Policy: camera=(), microphone=(), geolocation=(), "
		"clipboard-read=()\r\n"
		"Cross-Origin-Embedder-Policy: require-corp\r\n"
		"Connection: close\r\n\r\n",
		status, status_text (status), type, body_len,
		http->nonce, http->nonce);

	if (!conn->head_only && body != NULL)
		g_string_append_len (out, (const gchar *) body, (gssize) body_len);

	size  = out->len;
	data  = g_string_free (out, FALSE);
	bytes = g_bytes_new_take (data, size);

	/* Answering: the request is in, so the slot for senders is free
	 * again; the write has a deadline of its own. */
	slot_release (conn);
	deadline_start (conn);

	stream = g_io_stream_get_output_stream (G_IO_STREAM (conn->connection));

	/* write_all_async does not copy: the GBytes stays alive in the
	 * connection until the write has finished. */
	g_object_set_data_full (G_OBJECT (conn->connection), "fs-response",
	                        bytes, (GDestroyNotify) g_bytes_unref);
	g_output_stream_write_all_async (stream, g_bytes_get_data (bytes, NULL),
	                                 size, G_PRIORITY_DEFAULT, conn->cancel,
	                                 on_written, conn);
}

void
fs_dash_respond_json (FsDashConn *conn, guint status, gchar *json)
{
	fs_dash_respond (conn, status, "application/json; charset=utf-8",
	                 (const guint8 *) json, strlen (json));
	g_free (json);
}

void
fs_dash_respond_error (FsDashConn *conn, guint status, const gchar *message)
{
	GString *out = g_string_new ("{");

	fs_json_kv_str (out, "error", message);
	g_string_append_c (out, '}');
	fs_dash_respond_json (conn, status, g_string_free (out, FALSE));
}

/* ----------------------------------------------------------- requests */

const gchar *
fs_dash_conn_method (const FsDashConn *conn)
{
	return conn->method;
}

const gchar *
fs_dash_conn_path (const FsDashConn *conn)
{
	return conn->path;
}

GHashTable *
fs_dash_conn_params (const FsDashConn *conn)
{
	return conn->params;
}

gboolean
fs_dash_conn_head_only (const FsDashConn *conn)
{
	return conn->head_only;
}

/* [ header_count ] -- how often a header appears; its first value. */
static guint
header_count (gchar **lines, const gchar *name, const gchar **first)
{
	gsize n = strlen (name);
	guint count = 0;

	if (first != NULL)
		*first = NULL;
	for (guint i = 1; lines[i] != NULL; i++) {
		if (g_ascii_strncasecmp (lines[i], name, n) == 0 &&
		    lines[i][n] == ':') {
			if (count == 0 && first != NULL)
				*first = lines[i] + n + 1;
			count++;
		}
	}
	return count;
}

guint
fs_dash_conn_header_count (const FsDashConn *conn, const gchar *name)
{
	return header_count (conn->lines, name, NULL);
}

const gchar *
fs_dash_conn_body (const FsDashConn *conn, gsize *len)
{
	*len = conn->body_len;
	if (!conn->has_length)
		return NULL;
	return conn->in->str + conn->head_len + 4;
}

gboolean
fs_dash_conn_has_length (const FsDashConn *conn)
{
	return conn->has_length;
}

gboolean
fs_dash_conn_ownerless (const FsDashConn *conn)
{
	return conn->ownerless;
}

gchar *
fs_dash_conn_header (const FsDashConn *conn, const gchar *name)
{
	const gchar *value;

	if (header_count (conn->lines, name, &value) == 0)
		return NULL;
	return g_strstrip (g_strdup (value));
}

static gboolean
host_allowed (FsDashHttp *http, const gchar *host)
{
	for (guint i = 0; i < http->hosts->len; i++)
		if (strcmp (host, g_ptr_array_index (http->hosts, i)) == 0)
			return TRUE;
	return FALSE;
}

/* [ parse_head ]
 * The request line and the server-wide checks.  FALSE when it has
 * already answered.  On TRUE, *body_len is what Content-Length asks
 * for. */
static gboolean
parse_head (FsDashConn *conn, gsize *body_len)
{
	FsDashHttp *http = conn->http;
	gchar *head = g_strndup (conn->in->str, conn->head_len);
	gchar **parts;
	const gchar *v;
	gchar *host;
	gchar *query;
	guint n;

	conn->lines = g_strsplit (head, "\r\n", -1);
	g_free (head);
	*body_len = 0;

	parts = g_strsplit (conn->lines[0], " ", 3);
	if (g_strv_length (parts) != 3 ||
	    !g_str_has_prefix (parts[2], "HTTP/1.")) {
		g_strfreev (parts);
		fs_dash_respond_error (conn, 400, "Malformed request line.");
		return FALSE;
	}
	conn->method = g_strdup (parts[0]);
	conn->path   = g_strdup (parts[1]);
	conn->head_only = strcmp (conn->method, "HEAD") == 0;
	g_strfreev (parts);

	/* DNS rebinding: one Host header, and only our own address.
	 * `localhost' is not ourselves for sure: another account may
	 * listen on [::1] at this port, and a browser may go there
	 * first (G4). */
	n = header_count (conn->lines, "Host", NULL);
	host = fs_dash_conn_header (conn, "Host");
	if (n != 1 || !host_allowed (http, host)) {
		g_free (host);
		fs_dash_respond_error (conn, 403, "Unexpected Host header.");
		return FALSE;
	}
	g_free (host);

	/* No WebSocket or any other protocol switch (T7). */
	if (header_count (conn->lines, "Upgrade", NULL) != 0) {
		fs_dash_respond_error (conn, 400, "Upgrade is not supported.");
		return FALSE;
	}

	/* Bodies are sized by Content-Length only: no chunked bodies, so
	 * no disagreement about where a request ends (T3, T4). */
	if (header_count (conn->lines, "Transfer-Encoding", NULL) != 0) {
		fs_dash_respond_error (conn, 400,
		                       "Transfer-Encoding is not accepted.");
		return FALSE;
	}
	n = header_count (conn->lines, "Content-Length", &v);
	if (n > 1) {
		fs_dash_respond_error (conn, 400, "More than one Content-Length.");
		return FALSE;
	}
	if (n == 1) {
		gchar *len = g_strstrip (g_strdup (v));
		gchar *end = NULL;
		guint64 want = g_ascii_strtoull (len, &end, 10);
		gboolean digits = g_ascii_isdigit (*len) && *end == '\0' &&
		                  strlen (len) <= 9;

		g_free (len);
		if (!digits) {
			fs_dash_respond_error (conn, 400, "Bad Content-Length.");
			return FALSE;
		}
		if (want > FS_DASH_MAX_BODY) {
			fs_dash_respond_error (conn, 413, "Request body too large.");
			return FALSE;
		}
		*body_len = (gsize) want;
		conn->has_length = TRUE;
	}

	query = strchr (conn->path, '?');
	if (query != NULL) {
		*query++ = '\0';
		conn->params = g_uri_parse_params (query, -1, "&",
		                                   G_URI_PARAMS_WWW_FORM, NULL);
	}
	return TRUE;
}

static void on_read (GObject *source, GAsyncResult *result, gpointer data);

static void
read_more (FsDashConn *conn)
{
	GInputStream *in = g_io_stream_get_input_stream (
		G_IO_STREAM (conn->connection));

	g_input_stream_read_async (in, conn->buffer, sizeof (conn->buffer),
	                           G_PRIORITY_DEFAULT, conn->cancel, on_read,
	                           conn);
}

static void
dispatch (FsDashConn *conn)
{
	conn->http->handler (conn, conn->http->handler_data);
	if (!conn->answered)
		fs_dash_respond_error (conn, 404, "Not found.");
}

static void
on_read (GObject *source, GAsyncResult *result, gpointer data)
{
	FsDashConn *conn = data;
	gssize got = g_input_stream_read_finish (G_INPUT_STREAM (source),
	                                         result, NULL);

	if (got <= 0 || conn->aborted) {
		conn_free (conn);
		return;
	}

	g_string_append_len (conn->in, (const gchar *) conn->buffer, got);

	if (conn->head_len == 0) {
		gchar *end = strstr (conn->in->str, "\r\n\r\n");

		/* The cap holds however the bytes were split across reads:
		 * a head that ends inside the read that crossed the limit
		 * is still too large. */
		if ((end != NULL ? (gsize) (end - conn->in->str) : conn->in->len)
		    > FS_DASH_MAX_HEAD) {
			fs_dash_respond_error (conn, 431, "Request head too large.");
			return;
		}
		if (end == NULL) {
			read_more (conn);
			return;
		}
		conn->head_len = (gsize) (end - conn->in->str);
		if (!parse_head (conn, &conn->body_len))
			return;
		/* The body has its own deadline, from the end of the head. */
		if (conn->in->len < conn->head_len + 4 + conn->body_len)
			deadline_start (conn);
	}

	if (conn->in->len < conn->head_len + 4 + conn->body_len) {
		read_more (conn);
		return;
	}

	/* The body is read (fs_dash_conn_body); bytes past it are
	 * ignored, since every answer closes. */
	dispatch (conn);
}

/* ------------------------------------------------------------- accept */

static gboolean
on_incoming (GSocketService *service, GSocketConnection *connection,
             GObject *source, gpointer data)
{
	FsDashHttp *http = data;
	FsDashConn *conn;
	SlotGroup *group;
	uid_t uid = (uid_t) -1;
	gboolean ownerless = FALSE;

	/* Not one byte is read from a connection that fails these. */
	if (http->all >= FS_DASH_MAX_ALL ||
	    !peer_allowed (http, connection, &uid, &ownerless)) {
		g_io_stream_close (G_IO_STREAM (connection), NULL, NULL);
		return TRUE;
	}

	group = g_hash_table_lookup (http->groups, GUINT_TO_POINTER (uid));
	if (group == NULL) {
		group = g_new0 (SlotGroup, 1);
		g_queue_init (&group->open);
		g_hash_table_insert (http->groups, GUINT_TO_POINTER (uid), group);
	}
	/* Full: the oldest connection still sending its request makes
	 * room.  A slow sender can delay the user's request by at most
	 * the deadline, never shut it out. */
	if (group->open.length >= FS_DASH_SLOTS_OPEN)
		conn_abort (g_queue_peek_head (&group->open));

	conn = g_new0 (FsDashConn, 1);
	conn->http = http;
	conn->connection = g_object_ref (connection);
	conn->cancel = g_cancellable_new ();
	conn->in = g_string_sized_new (1024);
	conn->ownerless = ownerless;
	g_queue_push_tail (&group->open, conn);
	conn->group = group;
	conn->node = g_queue_peek_tail_link (&group->open);
	http->all++;

	deadline_start (conn);
	read_more (conn);
	return TRUE;
}

/* ------------------------------------------------------------ the server */

FsDashHttp *
fs_dash_http_new (guint16 want_port, uid_t peer_uid, GError **error)
{
	FsDashHttp *http = g_new0 (FsDashHttp, 1);
	GInetAddress *loopback;
	GSocketAddress *address, *bound = NULL;

	http->service = g_socket_service_new ();
	loopback = g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV4);
	address = g_inet_socket_address_new (loopback, want_port);
	g_object_unref (loopback);

	if (!g_socket_listener_add_address (G_SOCKET_LISTENER (http->service),
	                                    address, G_SOCKET_TYPE_STREAM,
	                                    G_SOCKET_PROTOCOL_TCP, NULL,
	                                    &bound, error)) {
		g_object_unref (address);
		g_object_unref (http->service);
		g_free (http);
		return NULL;
	}
	g_object_unref (address);

	http->port = g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (bound));
	g_object_unref (bound);

	http->peer_uid = peer_uid;
	http->nonce = g_strdup ("");
	http->hosts = g_ptr_array_new_with_free_func (g_free);
	g_ptr_array_add (http->hosts, g_strdup_printf ("127.0.0.1:%u", http->port));
	http->groups = g_hash_table_new_full (NULL, NULL, NULL, g_free);
	return http;
}

guint16
fs_dash_http_port (const FsDashHttp *http)
{
	return http->port;
}

void
fs_dash_http_set_nonce (FsDashHttp *http, const gchar *nonce)
{
	g_free (http->nonce);
	http->nonce = g_strdup (nonce);
}

void
fs_dash_http_allow_host (FsDashHttp *http, const gchar *host)
{
	g_ptr_array_add (http->hosts, g_strdup (host));
}

void
fs_dash_http_allow_ownerless (FsDashHttp *http, gboolean allow)
{
	http->allow_ownerless = allow;
}

void
fs_dash_http_on_ownerless_refused (FsDashHttp *http, GFunc refused,
                                   gpointer data)
{
	http->ownerless_refused = refused;
	http->ownerless_data = data;
}

void
fs_dash_http_start (FsDashHttp *http, FsDashHandler handler, gpointer data)
{
	http->handler = handler;
	http->handler_data = data;
	g_signal_connect (http->service, "incoming", G_CALLBACK (on_incoming),
	                  http);
	g_socket_service_start (http->service);
}

/* [ fs_dash_http_free ]
 * At the end of the run, after the main loop stopped: connections still
 * open are left to the process exit, as before the split. */
void
fs_dash_http_free (FsDashHttp *http)
{
	if (http == NULL)
		return;
	g_socket_service_stop (http->service);
	g_socket_listener_close (G_SOCKET_LISTENER (http->service));
	g_object_unref (http->service);
	g_ptr_array_unref (http->hosts);
	/* Connections still open hold pointers into the groups. */
	if (http->all == 0) {
		g_hash_table_unref (http->groups);
		g_free (http->nonce);
		g_free (http);
	}
}
