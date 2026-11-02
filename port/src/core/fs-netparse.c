/*---[ fs-netparse.c ]---------------------------------------------------
 * Parsers described in fs-netparse.h.  Pure text in, data out: no OS
 * headers, so the same file compiles into fs-core on every platform
 * and the core suite exercises it headless.
 *--------------------------------------------------------------------*/
#include "core/fs-netparse.h"
#include "core/fs-service.h"

#include <gio/gio.h>
#include <stdlib.h>
#include <string.h>

/* The kernel's TCP state numbers (include/net/tcp_states.h). */
#define TCP_STATE_TIME_WAIT 0x06
#define TCP_STATE_CLOSE     0x07
#define TCP_STATE_LISTEN    0x0A

gboolean
fs_hit_is_blocked (const FsHit *hit)
{
	return hit != NULL && hit->service != NULL &&
	       strstr (hit->service, FS_HIT_BLOCKED_MARKER) != NULL;
}

gchar *
fs_hit_service_name (const FsHit *hit)
{
	const gchar *mark;

	if (hit == NULL || hit->service == NULL)
		return g_strdup ("");

	mark = strstr (hit->service, FS_HIT_BLOCKED_MARKER);
	return mark != NULL ? g_strndup (hit->service, (gsize) (mark - hit->service))
	                    : g_strdup (hit->service);
}

/* ------------------------------------------------------------ log lines */

/* [ set_field ]
 * Assign a parsed value, replacing (and freeing) any earlier one: a
 * key that appears twice must not leak the first copy. */
static void
set_field (gchar **field, const gchar *value)
{
	g_free (*field);
	*field = g_strdup (value);
}

/* [ utc_stamp ]
 * The one time format the Events page knows how to localise. */
static gchar *
utc_stamp (GDateTime *when)
{
	GDateTime *utc = g_date_time_to_utc (when);
	gchar *text = g_date_time_format (utc, "%Y-%m-%dT%H:%M:%SZ");

	g_date_time_unref (utc);
	return text;
}

/* [ parse_rfc3339_stamp ]
 * "2026-10-11T14:30:00.123456+02:00 host kernel: ..." -- rsyslog's
 * default on current Debian and Kali.  The offset is honoured: taking
 * the first nineteen characters as UTC would shift every event by the
 * local offset. */
static gchar *
parse_rfc3339_stamp (const gchar *line)
{
	gchar *token;
	const gchar *space = strchr (line, ' ');
	GDateTime *when;
	gchar *text = NULL;

	if (space == NULL || space - line < 19 || line[10] != 'T')
		return NULL;

	token = g_strndup (line, (gsize) (space - line));
	when = g_date_time_new_from_iso8601 (token, NULL);

	if (when != NULL) {
		text = utc_stamp (when);
		g_date_time_unref (when);
	}

	g_free (token);
	return text;
}

/* [ parse_syslog_stamp ]
 * "Oct 11 14:30:00 host kernel: ..." -- the classic BSD stamp, which
 * journalctl -o short also writes.  It is local time and carries no
 * year: take the year from `now', and step back one when that would
 * put the event more than a day in the future (a December line read
 * in January). */
static gchar *
parse_syslog_stamp (const gchar *line, GDateTime *now)
{
	static const gchar *months[12] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	gint month = -1, day, hour, minute, second, year;
	GDateTime *when;
	gchar *text;

	if (strlen (line) < 15 || line[3] != ' ' || line[6] != ' ' ||
	    line[9] != ':' || line[12] != ':')
		return NULL;

	for (gint i = 0; i < 12; i++) {
		if (strncmp (line, months[i], 3) == 0) {
			month = i + 1;
			break;
		}
	}

	if (month < 0)
		return NULL;

	/* The day is space-padded: "Oct  1". */
	if (!(line[4] == ' ' || g_ascii_isdigit (line[4])) ||
	    !g_ascii_isdigit (line[5]))
		return NULL;

	for (gint i = 7; i <= 14; i++) {
		if (i == 9 || i == 12)
			continue;
		if (!g_ascii_isdigit (line[i]))
			return NULL;
	}

	day    = (line[4] == ' ' ? 0 : (line[4] - '0') * 10) + (line[5] - '0');
	hour   = (line[7] - '0') * 10 + (line[8] - '0');
	minute = (line[10] - '0') * 10 + (line[11] - '0');
	second = (line[13] - '0') * 10 + (line[14] - '0');
	year   = g_date_time_get_year (now);

	when = g_date_time_new (g_date_time_get_timezone (now), year, month,
	                        day, hour, minute, (gdouble) second);
	if (when == NULL)
		return NULL;

	if (g_date_time_difference (when, now) > G_TIME_SPAN_DAY) {
		GDateTime *earlier = g_date_time_add_years (when, -1);

		g_date_time_unref (when);
		when = earlier;
		if (when == NULL)
			return NULL;
	}

	text = utc_stamp (when);
	g_date_time_unref (when);

	return text;
}

/* [ token_is_marker ]
 * The LOG target's prefix appears as its own word, or glued to the
 * kernel's "[ 1234.5678]" uptime when the kernel prints no space. */
static gboolean
token_is_marker (const gchar *token)
{
	return g_str_has_suffix (token, "STOCKFW-DROP") ||
	       g_str_has_suffix (token, "STOCKFW-REJECT");
}

gboolean
fs_netparse_log_line (const gchar *line, FsHit *hit, GDateTime *now)
{
	FsHit parsed = { 0 };
	gchar **tokens;
	gboolean is_ours = FALSE;
	GDateTime *clock;

	if (line == NULL || hit == NULL)
		return FALSE;

	tokens = g_strsplit (line, " ", -1);

	for (gint i = 0; tokens[i] != NULL; i++) {
		const gchar *token = tokens[i];
		const gchar *eq;
		gchar *key;

		if (*token == '\0')
			continue;

		if (token_is_marker (token)) {
			is_ours = TRUE;
			continue;
		}

		/* Fields before the marker are the syslog header; a
		 * hostname that happens to contain '=' must not become a
		 * packet field. */
		if (!is_ours)
			continue;

		eq = strchr (token, '=');
		if (eq == NULL)
			continue;

		key = g_strndup (token, (gsize) (eq - token));
		eq++;

		if (strcmp (key, "SRC") == 0)
			set_field (&parsed.source, eq);
		else if (strcmp (key, "DST") == 0)
			set_field (&parsed.destination, eq);
		else if (strcmp (key, "PROTO") == 0)
			set_field (&parsed.protocol, eq);
		else if (strcmp (key, "DPT") == 0)
			set_field (&parsed.port, eq);
		else if (strcmp (key, "IN") == 0)
			set_field (&parsed.in, eq);
		else if (strcmp (key, "OUT") == 0)
			set_field (&parsed.out, eq);
		else if (strcmp (key, "LEN") == 0 && parsed.length == NULL)
			/* The IP header's LEN comes first; a UDP header
			 * repeats LEN= further on with its own length. */
			set_field (&parsed.length, eq);
		else if (strcmp (key, "TOS") == 0)
			set_field (&parsed.tos, eq);

		g_free (key);
	}

	g_strfreev (tokens);

	if (!is_ours) {
		g_free (parsed.source);
		g_free (parsed.destination);
		g_free (parsed.protocol);
		g_free (parsed.port);
		g_free (parsed.in);
		g_free (parsed.out);
		g_free (parsed.length);
		g_free (parsed.tos);
		return FALSE;
	}

	if (parsed.in == NULL)
		parsed.in = g_strdup ("");
	if (parsed.out == NULL)
		parsed.out = g_strdup ("");

	/* A packet with an input interface arrived here; one with only an
	 * output interface was leaving. */
	if (*parsed.in == '\0' && *parsed.out != '\0')
		parsed.direction = g_strdup ("out");
	else
		parsed.direction = g_strdup ("in");

	clock = now != NULL ? g_date_time_ref (now)
	                    : g_date_time_new_now_local ();

	parsed.time = parse_rfc3339_stamp (line);
	if (parsed.time == NULL)
		parsed.time = parse_syslog_stamp (line, clock);
	if (parsed.time == NULL)
		/* No stamp at all: the arrival time is the honest
		 * stand-in.  The raw line used to go into the Time column
		 * whole. */
		parsed.time = utc_stamp (clock);

	g_date_time_unref (clock);

	*hit = parsed;
	return TRUE;
}

gchar *
fs_netparse_line_time (const gchar *line, GDateTime *now)
{
	GDateTime *clock;
	gchar *stamp;

	if (line == NULL)
		return NULL;

	stamp = parse_rfc3339_stamp (line);
	if (stamp != NULL)
		return stamp;

	clock = now != NULL ? g_date_time_ref (now)
	                    : g_date_time_new_now_local ();
	stamp = parse_syslog_stamp (line, clock);
	g_date_time_unref (clock);

	return stamp;
}

void
fs_netparse_name_blocked (FsHit *hit)
{
	gchar *name = NULL;

	if (hit == NULL)
		return;

	if (hit->port != NULL)
		name = fs_service_lookup_port (atoi (hit->port));
	if (name == NULL && hit->protocol != NULL &&
	    g_ascii_strcasecmp (hit->protocol, "ICMP") == 0)
		name = g_strdup ("ICMP");
	if (name == NULL)
		name = g_strdup ("Unknown");

	g_free (hit->service);
	hit->service = g_strconcat (name, FS_HIT_BLOCKED_MARKER, NULL);
	g_free (name);
}

void
fs_netparse_clear_hit (FsHit *hit)
{
	if (hit == NULL)
		return;

	g_free (hit->time);
	g_free (hit->direction);
	g_free (hit->in);
	g_free (hit->out);
	g_free (hit->port);
	g_free (hit->source);
	g_free (hit->destination);
	g_free (hit->length);
	g_free (hit->tos);
	g_free (hit->protocol);
	g_free (hit->service);
	memset (hit, 0, sizeof (*hit));
}

/* ------------------------------------------------------------ /proc/net */

GList *
fs_netparse_proc_dev (const gchar *text)
{
	gchar **lines;
	GList *list = NULL;

	if (text == NULL)
		return NULL;

	lines = g_strsplit (text, "\n", -1);

	for (gint i = 0; lines[i] != NULL; i++) {
		gchar *colon = strchr (lines[i], ':');
		gchar *name;
		gchar **fields;
		guint n = 0;
		guint64 values[16];
		gboolean ok = TRUE;

		/* The two header lines use '|' and carry no ':'. */
		if (colon == NULL)
			continue;

		*colon = '\0';
		name = g_strstrip (lines[i]);

		if (*name == '\0' || strcmp (name, "lo") == 0)
			continue;

		fields = g_strsplit_set (colon + 1, " \t", -1);

		for (gint f = 0; fields[f] != NULL && n < 16; f++) {
			gchar *end = NULL;

			if (*fields[f] == '\0')
				continue;

			values[n++] = g_ascii_strtoull (fields[f], &end, 10);
			if (end == NULL || *end != '\0')
				ok = FALSE;
		}

		g_strfreev (fields);

		/* rx bytes is the first column, tx bytes the ninth. */
		if (ok && n >= 9) {
			FsIfaceStat *stat = g_new0 (FsIfaceStat, 1);

			stat->device   = g_strdup (name);
			stat->received = values[0];
			stat->sent     = values[8];
			stat->up       = TRUE;
			list = g_list_prepend (list, stat);
		}
	}

	g_strfreev (lines);

	return g_list_reverse (list);
}

void
fs_net_socket_free (FsNetSocket *s)
{
	if (s == NULL)
		return;

	g_free (s->local_addr);
	g_free (s->remote_addr);
	g_free (s);
}

/* [ decode_address ]
 * "0100007F:0016" -> "127.0.0.1", 22.  The kernel prints each 32-bit
 * word of the network-order address as a native integer (%08X), so
 * the word goes back into memory natively to recover the original
 * bytes -- correct on whichever byte order wrote the file, because it
 * is the same machine reading it. */
static gboolean
decode_address (const gchar *field, gboolean ipv6, gchar **addr,
                guint *port)
{
	const gchar *colon = strchr (field, ':');
	gsize hex_len = ipv6 ? 32 : 8;
	guint8 bytes[16];
	gchar *end = NULL;
	guint64 p;

	if (colon == NULL || (gsize) (colon - field) != hex_len)
		return FALSE;

	for (gsize w = 0; w < hex_len / 8; w++) {
		gchar word[9];
		guint32 value;

		memcpy (word, field + w * 8, 8);
		word[8] = '\0';

		for (gint c = 0; c < 8; c++)
			if (!g_ascii_isxdigit (word[c]))
				return FALSE;

		value = (guint32) g_ascii_strtoull (word, NULL, 16);
		memcpy (bytes + w * 4, &value, 4);
	}

	p = g_ascii_strtoull (colon + 1, &end, 16);
	if (end == NULL || *end != '\0' || end == colon + 1 || p > 65535)
		return FALSE;

	*port = (guint) p;

	if (ipv6) {
		static const guint8 mapped[12] = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
		};

		if (memcmp (bytes, mapped, 12) == 0) {
			*addr = g_strdup_printf ("%u.%u.%u.%u", bytes[12],
			                         bytes[13], bytes[14], bytes[15]);
		} else {
			GInetAddress *inet = g_inet_address_new_from_bytes (
				bytes, G_SOCKET_FAMILY_IPV6);

			*addr = g_inet_address_to_string (inet);
			g_object_unref (inet);
		}
	} else {
		*addr = g_strdup_printf ("%u.%u.%u.%u", bytes[0], bytes[1],
		                         bytes[2], bytes[3]);
	}

	return TRUE;
}

GList *
fs_netparse_proc_tcp (const gchar *text, gboolean ipv6)
{
	gchar **lines;
	GList *list = NULL;

	if (text == NULL)
		return NULL;

	lines = g_strsplit (text, "\n", -1);

	for (gint i = 0; lines[i] != NULL; i++) {
		gchar **raw = g_strsplit_set (lines[i], " \t", -1);
		const gchar *f[10];
		guint n = 0;
		FsNetSocket *s;
		gchar *end = NULL;

		for (gint k = 0; raw[k] != NULL && n < 10; k++)
			if (*raw[k] != '\0')
				f[n++] = raw[k];

		/* "sl:" then local, remote, st, tx:rx, tr:when, retrnsmt,
		 * uid, timeout, inode.  The header row fails the "N:" test. */
		if (n < 10 || !g_ascii_isdigit (f[0][0]) ||
		    !g_str_has_suffix (f[0], ":")) {
			g_strfreev (raw);
			continue;
		}

		s = g_new0 (FsNetSocket, 1);

		if (!decode_address (f[1], ipv6, &s->local_addr,
		                     &s->local_port) ||
		    !decode_address (f[2], ipv6, &s->remote_addr,
		                     &s->remote_port)) {
			fs_net_socket_free (s);
			g_strfreev (raw);
			continue;
		}

		s->state = (guint) g_ascii_strtoull (f[3], &end, 16);
		if (end == NULL || *end != '\0') {
			fs_net_socket_free (s);
			g_strfreev (raw);
			continue;
		}

		s->inode = g_ascii_strtoull (f[9], &end, 10);
		if (end == NULL || *end != '\0')
			s->inode = 0;

		list = g_list_prepend (list, s);
		g_strfreev (raw);
	}

	g_strfreev (lines);

	return g_list_reverse (list);
}

const gchar *
fs_netparse_guess_direction (guint local_port, guint remote_port)
{
	if (remote_port < 1024 && local_port >= 1024)
		return "Outbound";
	if (local_port < 1024)
		return "Inbound";
	if (local_port >= 49152)
		return "Outbound";
	if (remote_port >= 49152)
		return "Inbound";

	return "Outbound";
}

/* [ address_is_unspecified ] -- 0.0.0.0 or :: */
static gboolean
address_is_unspecified (const gchar *addr)
{
	return addr == NULL || strcmp (addr, "0.0.0.0") == 0 ||
	       strcmp (addr, "::") == 0;
}

GList *
fs_netparse_connections (const GList *sockets, GHashTable *programs)
{
	GList *list = NULL;
	GHashTable *listening = g_hash_table_new (g_direct_hash, g_direct_equal);

	/* The ports something here listens on.  A connection whose local
	 * end is one of them was accepted, so it is inbound whatever its
	 * port numbers look like (a dashboard on 8765, a database on
	 * 5432); only the rest fall back to the port-number guess. */
	for (const GList *l = sockets; l != NULL; l = l->next) {
		const FsNetSocket *s = l->data;

		if (s->state == TCP_STATE_LISTEN)
			g_hash_table_add (listening,
			                  GUINT_TO_POINTER (s->local_port));
	}

	for (const GList *l = sockets; l != NULL; l = l->next) {
		const FsNetSocket *s = l->data;
		FsConnection *conn;
		const gchar *program = NULL;
		gchar *service;
		gboolean inbound;
		guint port;

		if (s->state == TCP_STATE_LISTEN ||
		    s->state == TCP_STATE_TIME_WAIT ||
		    s->state == TCP_STATE_CLOSE)
			continue;

		if (address_is_unspecified (s->remote_addr) ||
		    s->remote_port == 0)
			continue;

		if (programs != NULL && s->inode != 0)
			program = g_hash_table_lookup (programs, &s->inode);

		if (g_hash_table_contains (listening,
		                           GUINT_TO_POINTER (s->local_port)))
			inbound = TRUE;
		else
			inbound = g_strcmp0 (fs_netparse_guess_direction (
			                         s->local_port, s->remote_port),
			                     "Inbound") == 0;

		/* The port that names the service: ours for an inbound
		 * connection (someone reached our SSH), theirs for an
		 * outbound one (we reached their HTTPS). */
		port = inbound ? s->local_port : s->remote_port;

		conn = g_new0 (FsConnection, 1);
		conn->source      = g_strdup (s->local_addr);
		conn->destination = g_strdup (s->remote_addr);
		conn->port        = g_strdup_printf ("%u", port);
		conn->protocol    = g_strdup ("TCP");
		conn->direction   = g_strdup (inbound ? "Inbound" : "Outbound");
		conn->program     = g_strdup (program != NULL ? program : "?");

		service = fs_service_lookup_port ((gint) port);
		conn->service = service != NULL ? service : g_strdup ("Unknown");

		list = g_list_prepend (list, conn);
	}

	g_hash_table_unref (listening);

	return g_list_reverse (list);
}
