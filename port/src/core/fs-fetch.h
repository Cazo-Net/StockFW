/*---[ fs-fetch.h ]------------------------------------------------------
 * One HTTPS download into memory, through curl, hardened against what a
 * root process inherits (1.0.7 threat intel; design section 5).
 *
 *   - argv only, absolute curl path, `-q' first (no curlrc);
 *   - an explicit environment (PATH and LC_ALL=C, nothing else), so no
 *     CURL_CA_BUNDLE, SSL_CERT_*, SSLKEYLOGFILE, *_proxy or HOME;
 *   - https only, also for redirects; a proxy only when the caller
 *     passes one, `--noproxy *' otherwise;
 *   - one URL is one transfer: `--globoff', or curl would expand [..]
 *     and {..} in the URL into many requests, even to other hosts;
 *   - as root, curl runs as `nobody' (resolved before the fork) with no
 *     supplementary groups; no such account => no download;
 *   - the body comes over a pipe, never a file, and is counted here:
 *     one byte over the cap and curl is killed; a whole-transfer
 *     timeout kills it too.
 *
 * fs_fetch() blocks; call it from a worker thread in the UI.  It runs
 * its own GMainContext, so it is safe from any thread.
 *
 * Test builds only (FS_FETCH_TESTING defined) also read
 * STOCKFW_TEST_CURL (curl path) and STOCKFW_TEST_CACERT (adds --cacert);
 * release builds have no such hook.
 *--------------------------------------------------------------------*/
#ifndef FS_FETCH_H
#define FS_FETCH_H

#include <glib.h>

G_BEGIN_DECLS

GQuark fs_fetch_error_quark (void);
#define FS_FETCH_ERROR (fs_fetch_error_quark ())

enum
{
	FS_FETCH_ERR_NO_CURL = 1,   /* curl is not installed                */
	FS_FETCH_ERR_URL,           /* the URL was refused before spawning  */
	FS_FETCH_ERR_PRIVILEGE,     /* root, but no `nobody' to run as      */
	FS_FETCH_ERR_TOO_LARGE,     /* the body passed max_bytes            */
	FS_FETCH_ERR_TIMEOUT,       /* the whole transfer took too long     */
	FS_FETCH_ERR_TLS,           /* certificate or TLS handshake failure */
	FS_FETCH_ERR_HTTP,          /* the server answered with an error    */
	FS_FETCH_ERR_NETWORK,       /* name lookup, connect, reset ...      */
	FS_FETCH_ERR_FAILED         /* anything else (curl's exit status)   */
};

typedef struct
{
	const gchar *url;          /* checked with fs_feed_url_is_acceptable */
	gsize        max_bytes;    /* > 0                                    */
	guint        timeout_s;    /* whole transfer, > 0                    */
	const gchar *proxy;        /* http:// or https:// URL, or NULL       */
	const gchar *user_agent;   /* "StockFW/1.0.7"; NULL => that default  */
} FsFetchRequest;

/* The body, or NULL with FS_FETCH_ERROR set.  The message is one line,
 * fit for the UI: it names the cause and, for curl failures, curl's
 * first stderr line ("Could not download: SSL certificate problem:
 * unable to get local issuer certificate"). */
GBytes *fs_fetch (const FsFetchRequest *request, GError **error);

/* ---- the pieces, pure, for the tests ------------------------------ */

/* /usr/bin/curl, else /bin/curl (Windows: <system dir>\curl.exe);
 * NULL when neither exists.  Static string; do not free. */
const gchar *fs_fetch_curl_path (void);

/* The argv fs_fetch() runs for `request' with `curl' as argv[0]:
 * curl -q --proto =https --proto-redir =https --proto-default https
 *      --tlsv1.2 --fail --silent --show-error --location
 *      --max-redirs 3 --globoff
 *      --max-filesize <max_bytes> --max-time <timeout_s>
 *      --connect-timeout 20 --user-agent <ua> --output -
 *      (--noproxy * | --proxy <proxy>) --url <url>
 * NULL when the request is invalid (bad URL or proxy, zero limits).
 * Caller frees with g_strfreev. */
gchar **fs_fetch_argv (const FsFetchRequest *request, const gchar *curl);

/* The environment curl gets: exactly "PATH=/usr/sbin:/usr/bin:/sbin:
 * /bin" and "LC_ALL=C" (Windows: SystemRoot and
 * NoDefaultCurrentDirectoryInExePath=1).  Caller frees. */
gchar **fs_fetch_envp (void);

/* A proxy URL StockFW accepts: http:// or https://, <= 2048 bytes,
 * printable ASCII, no spaces, not starting with '-'. */
gboolean fs_fetch_proxy_is_acceptable (const gchar *proxy);

/* curl's exit status to FS_FETCH_ERR_*.  Pure.
 *   5 6 7 16 18 52 55 56                    NETWORK
 *   28                                       TIMEOUT
 *   35 51 53 54 58 59 60 77 80 82 83 90 91   TLS
 *   22 (--fail: HTTP status >= 400)          HTTP
 *   63 (--max-filesize)                      TOO_LARGE
 *   1 (a redirect to a scheme --proto-redir
 *      refuses) and 47 (too many redirects)  URL
 *   anything else                            FAILED */
gint fs_fetch_classify_exit (gint curl_exit_status);

G_END_DECLS

#endif /* FS_FETCH_H */
