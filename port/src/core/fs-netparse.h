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

/* The service name without the marker ("SSH [BLOCKED]" -> "SSH"), for
 * a reader that shows the verdict in its own column.  "" for a hit
 * with no service.  Caller frees. */
gchar *fs_hit_service_name (const FsHit *hit);

/* What a StockFW kernel-log line says happened to the packet. */
typedef enum
{
	FS_LOG_VERDICT_NONE = 0,   /* not one of our lines                  */
	FS_LOG_VERDICT_ALLOW,      /* "STOCKFW-ALLOW ": a new connection the
	                            * policy accepted (1.0.7, sampled)      */
	FS_LOG_VERDICT_DROP,       /* "STOCKFW-DROP "                       */
	FS_LOG_VERDICT_REJECT      /* "STOCKFW-REJECT "                     */
} FsLogVerdict;

/* Which of our markers the line carries (only the packet fields after
 * the syslog header are looked at, as in fs_netparse_log_line). */
FsLogVerdict fs_netparse_log_verdict (const gchar *line);

/* Parse one kernel-log line written by the generated script's LOG
 * target ("STOCKFW-DROP ", "STOCKFW-REJECT " or, since 1.0.7,
 * "STOCKFW-ALLOW ").  Returns FALSE, and
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

/* A line logged by the threat-intel table (design 7):
 * "STOCKFW-TI <id> IN=... SRC=...", parsed into the same fields as
 * fs_netparse_log_line().  *id (nullable) receives the list's id, which
 * passed fs_intel_id_is_valid(); caller frees.  FALSE, with *hit
 * untouched, for any other line -- the policy's lines included, and a
 * marker followed by something that is not an id.  The caller still
 * checks the id against the rule set it applied (fs_intel_applied_has)
 * before showing the event [S17.3]; fs_netparse_log_line() never
 * accepts these lines. */
gboolean fs_netparse_intel_line (const gchar *line, FsHit *hit,
                                 GDateTime *now, gchar **id);

/* The time stamp of any kernel-log line, ours or not, as the same
 * ISO-8601 UTC text fs_netparse_log_line produces; NULL when the line
 * has no stamp.  A reader backfilling from the log uses the first
 * line's stamp as the point from which its record is complete. */
gchar *fs_netparse_line_time (const gchar *line, GDateTime *now);

/* Name a parsed log hit the way the Events page shows it: the
 * destination port's service ("HTTPS"), "ICMP" for ICMP, otherwise
 * "Unknown" -- followed by FS_HIT_BLOCKED_MARKER, because every line
 * the generated script logs is a packet it is about to drop or reject.
 * Replaces hit->service. */
void fs_netparse_name_blocked (FsHit *hit);

/* The same naming without the marker: an accepted connection. */
void fs_netparse_name_allowed (FsHit *hit);

/* Name a parsed hit by the verdict its line carries: allowed for
 * FS_LOG_VERDICT_ALLOW, blocked otherwise. */
void fs_netparse_name_by_verdict (FsHit *hit, FsLogVerdict verdict);

/* One /dev/kmsg record ("<prio>,<seq>,<usec>,<flags>;<message>\n" with
 * optional " KEY=value" continuation lines) as a log line the parser
 * above reads: "<RFC 3339 UTC stamp> <message>".  The stamp is the
 * record's own time, from its microseconds-since-boot and the two
 * clocks the caller passes (g_get_real_time(), g_get_monotonic_time()).
 *
 * Only kernel-facility records are returned: anything userspace wrote
 * into the ring (journald forwards, `echo > /dev/kmsg') has a non-zero
 * facility and yields NULL, so a local process cannot forge a firewall
 * event by writing one.  NULL too for a malformed record.  `len' is the
 * record length as read() returned it.  Caller frees. */
gchar *fs_netparse_kmsg_line (const gchar *record, gsize len,
                              gint64 now_real_us, gint64 now_mono_us);

/* Free the fields of a stack FsHit filled by fs_netparse_log_line and
 * zero it (fs_hit_free would also free the struct itself). */
void fs_netparse_clear_hit (FsHit *hit);

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
 * 0.0.0.0:0 peer); inbound when the local port is one a LISTEN row in
 * the same list holds, otherwise the direction guessed from the ports
 * the way the Windows backend guesses it; the port and service named
 * from our end for an inbound connection and the peer's end for an
 * outbound one; and the owning program from `programs' (inode as
 * guint64* -> name), or "?" when the socket's owner could not be read.
 * Returns a list of FsConnection*, caller frees with
 * fs_connection_free. */
GList *fs_netparse_connections (const GList *sockets,
                                GHashTable *programs);

/* "Inbound" or "Outbound" from the two ports of a TCP connection: a
 * well-known local port means someone reached a service here, a
 * well-known remote port means this machine reached one. */
const gchar *fs_netparse_guess_direction (guint local_port,
                                          guint remote_port);

G_END_DECLS

#endif /* FS_NETPARSE_H */
