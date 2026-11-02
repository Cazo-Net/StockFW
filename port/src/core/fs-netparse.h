/*---[ fs-netparse.h ]---------------------------------------------------
 * Text parsers for the Linux backend: netfilter kernel-log lines and
 * the /proc/net tables.
 *
 * They live in core rather than in fs-backend-linux.c for one reason:
 * a parser is pure text in, data out, so the core suite can pin every
 * field against fixtures on any platform -- including the bugs it
 * exists to prevent (the source port shown as the port, the
 * destination port written over the OUT interface, a REJECT-mode drop
 * never reaching the Events page).  The backend keeps the parts that
 * touch the OS: tailing the log, reading the files, walking /proc.
 *--------------------------------------------------------------------*/
#ifndef FS_NETPARSE_H
#define FS_NETPARSE_H

#include <glib.h>
#include "core/fs-types.h"

G_BEGIN_DECLS

/* What both backends append to the service field of a dropped event.
 * Everything that paints a row red, counts an event as "serious",
 * feeds Sentinel's blocked fan-out or charts it as blocked keys on
 * this one suffix, so the Linux backend must write it exactly as the
 * Windows backend does. */
#define FS_HIT_BLOCKED_MARKER " [BLOCKED]"

/* TRUE when the service field carries FS_HIT_BLOCKED_MARKER. */
gboolean fs_hit_is_blocked (const FsHit *hit);

/* Parse one kernel-log line written by the generated script's LOG
 * target ("STOCKFW-DROP " or "STOCKFW-REJECT ").  Returns FALSE, and
 * leaves *hit untouched, for any other line.
 *
 * On TRUE the fields are newly allocated (caller clears them):
 *   time        ISO-8601 UTC "YYYY-MM-DDTHH:MM:SSZ" -- from an RFC 3339
 *               stamp, a classic "Mmm dd HH:MM:SS" syslog stamp (local
 *               time, year taken from `now'), or `now' itself when the
 *               line carries neither
 *   direction   "in" when the packet arrived on an interface (IN=),
 *               "out" when it was leaving one (OUT= only)
 *   in / out    the IN= / OUT= interface names ("" when absent)
 *   port        the DESTINATION port (DPT=) -- the service being
 *               reached; the source port is ephemeral and not kept
 *   source, destination, protocol, length (LEN=), tos (TOS=)
 * service is left NULL: the backend names it and appends the marker.
 *
 * `now' may be NULL for the real clock; tests pass a fixed one. */
gboolean fs_netparse_log_line (const gchar *line, FsHit *hit,
                               GDateTime *now);

/* Parse /proc/net/dev.  Returns a list of FsIfaceStat* with device,
 * received and sent filled in (kind, ip and up are the backend's to
 * add from sysfs); the loopback device is left out, as on Windows.
 * Free with g_list_free_full (..., fs_iface_stat_free). */
GList *fs_netparse_proc_dev (const gchar *text);

/* One row of /proc/net/tcp or /proc/net/tcp6. */
typedef struct
{
	gchar   *local_addr;    /* dotted quad or IPv6 text; an IPv4-mapped
	                         * IPv6 address is rendered as IPv4       */
	guint    local_port;
	gchar   *remote_addr;
	guint    remote_port;
	guint    state;         /* the kernel's TCP state number          */
	guint64  inode;         /* 0 for sockets with no owner (TIME_WAIT) */
} FsNetSocket;

void fs_net_socket_free (FsNetSocket *s);

/* Parse /proc/net/tcp (ipv6 = FALSE) or /proc/net/tcp6 (ipv6 = TRUE).
 * Malformed rows are skipped.  Free with
 * g_list_free_full (..., fs_net_socket_free). */
GList *fs_netparse_proc_tcp (const gchar *text, gboolean ipv6);

/* The Status page's "Active connections" rows from parsed sockets:
 * connected sockets only (not LISTEN, TIME_WAIT or CLOSE, and never a
 * 0.0.0.0:0 peer), the remote port's service name, the direction
 * guessed from the ports the way the Windows backend guesses it, and
 * the owning program from `programs' (inode as guint64* -> name), or
 * "?" when the socket's owner could not be read.  Returns a list of
 * FsConnection*, caller frees with fs_connection_free. */
GList *fs_netparse_connections (const GList *sockets,
                                GHashTable *programs);

/* "Inbound" or "Outbound" from the two ports of a TCP connection: a
 * well-known local port means someone reached a service here, a
 * well-known remote port means this machine reached one. */
const gchar *fs_netparse_guess_direction (guint local_port,
                                          guint remote_port);

G_END_DECLS

#endif /* FS_NETPARSE_H */
