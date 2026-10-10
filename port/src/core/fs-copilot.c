/*---[ fs-copilot.c ]---------------------------------------------------
 * Smart Firewall Copilot - Implementation.
 *
 * Learns application network behavior, detects anomalies, suggests
 * rules with natural-language explanations, and simulates "what-if"
 * scenarios before applying.
 *--------------------------------------------------------------------*/

#include "core/fs-copilot.h"
#include "core/fs-util.h"
#include "core/fs-service.h"
#include "core/fs-i18n.h"
#include "core/fs-fwrule.h"
#include "core/fs-rules.h"

#include <gio/gio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

struct _FsCopilot
{
	/* Learned application profiles. */
	GHashTable *profiles;           /* app_name -> FsAppProfile* */

	/* Current insights. */
	GList *insights;

	/* Policy for simulation (set via fs_copilot_set_policy). */
	FsPolicy *policy;

	/* Configuration. */
	gboolean learning_enabled;
	gdouble anomaly_threshold;      /* Standard deviations for anomaly */
	guint min_samples_for_baseline; /* Min connections before analyzing */

	/* Sentinel (1.0.4): covert-channel and fan-out state.  Arrival
	 * times are bucketed to whole seconds, so a polled batch of
	 * records counts as one moment instead of a fake burst. */
	GHashTable *beacon_stamps;      /* "host:port" -> GArray<gint64> */
	GHashTable *beacon_reported;    /* "host:port" -> TRUE           */
	GHashTable *fanout_seen;        /* host -> last bucketed second  */
	GHashTable *fanout_blocked;     /* blocked host -> bucketed sec  */
	gboolean    fanout_reported;    /* current window already told   */
};

/* Forward declarations. */
static FsAppProfile *app_profile_new (const gchar *name, const gchar *path,
                                      gint64 now_unix);
static void app_profile_free (FsAppProfile *profile);
static void app_profile_record_connection (FsAppProfile *profile,
                                           const gchar *remote_ip,
                                           guint port,
                                           const gchar *protocol,
                                           gboolean inbound,
                                           guint64 bytes,
                                           gint64 now_unix);
static gboolean is_novel_port (FsAppProfile *profile, guint port);
static gboolean is_novel_destination (FsAppProfile *profile,
                                      const gchar *remote_ip);
static gboolean is_novel_hour (FsAppProfile *profile, gint64 now_unix);
static gboolean rate_spike_take (FsAppProfile *profile, gint64 now_unix);
static void behavior_analyze (FsCopilot *copilot, FsAppProfile *profile,
                              const gchar *app_name,
                              const gchar *remote_ip, guint port,
                              gint64 now_unix);
static void emit_insight (FsCopilot *copilot, FsInsight *insight);
static gboolean sentinel_hit_is_inbound (const FsHit *hit);
static FsInsight *create_insight (FsInsightType type,
                                  FsCopilotSeverity severity,
                                  const gchar *title,
                                  gchar *description,
                                  const gchar *app_name,
                                  const gchar *destination);

/* ---- Sentinel thresholds (exercised by tests/test-core.sh) --------- */
#define FS_SENTINEL_BEACON_MIN_SAMPLES 6    /* contacts before judging   */
#define FS_SENTINEL_BEACON_MAX_CV      0.30 /* interval regularity       */
#define FS_SENTINEL_BEACON_MIN_MEAN_S  10   /* seconds between contacts  */
#define FS_SENTINEL_BEACON_MAX_MEAN_S  600
#define FS_SENTINEL_BEACON_MAX_STAMPS  32
#define FS_SENTINEL_FANOUT_WINDOW_S    60   /* rolling window, seconds   */
#define FS_SENTINEL_FANOUT_LIMIT       60   /* distinct hosts, any       */
#define FS_SENTINEL_FANOUT_BLOCKED     10   /* distinct hosts, blocked   */

static FsInsight *sentinel_beacon_check (FsCopilot *copilot,
                                         const FsHit *hit,
                                         gint64 now_us);
static FsInsight *sentinel_fanout_check (FsCopilot *copilot,
                                         const FsHit *hit,
                                         gint64 now_us);
/* Note: simulate_against_rules() was declared here once but never
 * written or called.  fs_copilot_simulate() says in its own comment
 * that it still uses heuristics rather than the rule engine, which is
 * what the declaration used to imply and was not true. */

/* ---- Behavior analysis bounds (P2) -------------------------------
 * Every structure here is bounded (Chapter 9):256 applications,
 * 256 ports and 1024 destinations per application, 200 insights in
 * the list, one rate report per 10-minute bucket. */
#define FS_BEHAVIOR_MAX_APPS          256
#define FS_BEHAVIOR_MAX_PORTS         256
#define FS_BEHAVIOR_MAX_DESTS         1024
#define FS_COPILOT_MAX_INSIGHTS       200
#define FS_BEHAVIOR_WINDOW_S          600    /* rate window: 10 minutes */
#define FS_BEHAVIOR_RATE_MIN_BUCKETS  8      /* buckets before judging rate */
#define FS_BEHAVIOR_RATE_MIN_EVENTS   10     /* floor: events per bucket    */
#define FS_BEHAVIOR_HOURS_MIN_DISTINCT 4     /* hours before judging hours  */

/* [ fs_copilot_new ] */
FsCopilot *
fs_copilot_new (void)
{
	FsCopilot *copilot = g_new0 (FsCopilot, 1);

	copilot->profiles = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                           g_free, (GDestroyNotify) app_profile_free);
	copilot->insights = NULL;
	copilot->policy = NULL;
	copilot->learning_enabled = TRUE;
	copilot->anomaly_threshold = 2.0;       /* 2 standard deviations */
	copilot->min_samples_for_baseline = 10; /* Need 10 connections baseline */

	copilot->beacon_stamps = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free,
		(GDestroyNotify) g_array_unref);
	copilot->beacon_reported = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free, NULL);
	copilot->fanout_seen = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free, NULL);
	copilot->fanout_blocked = g_hash_table_new_full (
		g_str_hash, g_str_equal, g_free, NULL);
	copilot->fanout_reported = FALSE;

	return copilot;
}

/* [ fs_copilot_set_policy ]
 * Attach a policy to the copilot for what-if simulation.  The copilot
 * does not take ownership -- the caller remains responsible for the
 * policy's lifetime.  Passing NULL clears the reference. */
void
fs_copilot_set_policy (FsCopilot *copilot, FsPolicy *policy)
{
	if (copilot == NULL)
		return;
	copilot->policy = policy;
}

/* [ fs_copilot_get_policy ]
 * Get the currently attached policy (may be NULL). */
FsPolicy *
fs_copilot_get_policy (FsCopilot *copilot)
{
	return (copilot != NULL) ? copilot->policy : NULL;
}

/* [ fs_copilot_free ] */
void
fs_copilot_free (FsCopilot *copilot)
{
	if (copilot == NULL)
		return;

	g_hash_table_unref (copilot->profiles);
	g_hash_table_unref (copilot->beacon_stamps);
	g_hash_table_unref (copilot->beacon_reported);
	g_hash_table_unref (copilot->fanout_seen);
	g_hash_table_unref (copilot->fanout_blocked);
	g_list_free_full (copilot->insights, (GDestroyNotify) fs_insight_free);
	g_free (copilot);
}

/* [ fs_copilot_feed_event ] */
void
fs_copilot_feed_event (FsCopilot *copilot, const FsHit *hit)
{
	fs_copilot_feed_event_full (copilot, hit, g_get_monotonic_time (),
	                            time (NULL));
}

/* [ fs_copilot_feed_event_at ] */
void
fs_copilot_feed_event_at (FsCopilot *copilot, const FsHit *hit,
                          gint64 now_us)
{
	fs_copilot_feed_event_full (copilot, hit, now_us, time (NULL));
}

/* [ evict_lru_profile ]
 * Room for a newcomer when the profile table is full: the least
 * recently seen application goes.  Its insights are plain strings and
 * stay valid; only its learned history resets. */
static void
evict_lru_profile (FsCopilot *copilot)
{
	GHashTableIter iter;
	gpointer key, value;
	gpointer oldest_key = NULL;
	FsAppProfile *oldest = NULL;

	g_hash_table_iter_init (&iter, copilot->profiles);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		FsAppProfile *p = value;

		if (oldest == NULL || p->last_seen < oldest->last_seen) {
			oldest = p;
			oldest_key = key;
		}
	}

	if (oldest_key != NULL)
		g_hash_table_remove (copilot->profiles, oldest_key);
}

/* [ fs_copilot_feed_event_full ]
 * One event, three jobs: teach the profile, run Sentinel, then judge
 * the event against the baseline it just joined -- correlating every
 * signal (port, destination, hour, rate) into a single finding
 * instead of the else-if chain that reported one signal and silently
 * dropped the others. */
void
fs_copilot_feed_event_full (FsCopilot *copilot, const FsHit *hit,
                            gint64 now_us, gint64 now_unix)
{
	gchar app_buf[256];
	const gchar *app_name;
	const gchar *remote_ip;
	const gchar *protocol;
	guint port;
	gboolean inbound;
	FsAppProfile *profile;

	if (copilot == NULL || hit == NULL || !copilot->learning_enabled)
		return;

	/* The per-application key.  The Windows backend appends
	 * " [BLOCKED]" to the service field of dropped events; without
	 * stripping it here, every blocked connection would start a
	 * SECOND profile for the same program and split the history the
	 * baseline is supposed to compare against.  Events without an
	 * Application Name carry the port's service name instead -- that
	 * is what the log held, and the profile's key says so. */
	g_strlcpy (app_buf, hit->service != NULL ? hit->service : "",
	           sizeof app_buf);
	if (g_str_has_suffix (app_buf, " [BLOCKED]"))
		app_buf[strlen (app_buf) - strlen (" [BLOCKED]")] = '\0';
	if (*app_buf == '\0')
		g_strlcpy (app_buf, "Unknown", sizeof app_buf);
	app_name = app_buf;

	/* Which end is the remote host depends on the direction: an
	 * outbound packet carries OUR address as the source.  Taking
	 * `source' unconditionally taught every outbound event that our
	 * own IP was a destination -- the baseline learned the wrong half
	 * of the conversation.  The direction test is case-insensitive
	 * because the Windows backend writes "in"/"out". */
	inbound = sentinel_hit_is_inbound (hit);
	if (inbound)
		remote_ip = (hit->source != NULL && *hit->source != '\0')
		            ? hit->source : hit->destination;
	else
		remote_ip = (hit->destination != NULL &&
		             *hit->destination != '\0')
		            ? hit->destination : hit->source;

	port = 0;
	if (hit->port != NULL && *hit->port != '\0') {
		glong parsed = strtol (hit->port, NULL, 10);

		if (parsed > 0 && parsed <= 65535)
			port = (guint) parsed;
	}

	protocol = hit->protocol != NULL ? hit->protocol : "TCP";

	/* Get or create profile.
	 *
	 * The insert belongs inside the "not found" branch and nowhere
	 * else.  g_hash_table_insert() on a key that already exists frees
	 * the OLD value through the table's destroy notify -- and when the
	 * profile came from the lookup, old value and new value are the
	 * same object.  So the unconditional insert used to free the very
	 * profile it then stored: the table kept a dangling pointer, the
	 * next event wrote into freed memory, and the one after that freed
	 * it again.  That was the crash behind monitoring the log --
	 * g_hash_table_lookup() inside the anomaly checks on the freed
	 * profile->common_ports (integer divide-by-zero or access violation
	 * in libglib), plus the heap fail-fasts from the double free. */
	profile = g_hash_table_lookup (copilot->profiles, app_name);
	if (profile == NULL)
	{
		if (g_hash_table_size (copilot->profiles) >=
		    FS_BEHAVIOR_MAX_APPS)
			evict_lru_profile (copilot);

		profile = app_profile_new (app_name, NULL, now_unix);
		g_hash_table_insert (copilot->profiles, g_strdup (app_name),
		                     profile);
	}

	app_profile_record_connection (profile, remote_ip, port, protocol,
	                               inbound, 0, now_unix);

	/* Sentinel runs on every event, baseline or not: a control
	 * channel has to be caught in its first minutes, not after the
	 * learning baseline has had its 10 samples. */
	{
		FsInsight *beacon = sentinel_beacon_check (copilot, hit, now_us);
		FsInsight *fanout = sentinel_fanout_check (copilot, hit, now_us);

		if (beacon != NULL) {
			beacon->timestamp = now_unix;
			emit_insight (copilot, beacon);
		}
		if (fanout != NULL) {
			fanout->timestamp = now_unix;
			emit_insight (copilot, fanout);
		}
	}

	/* Judge the event against the baseline once it has one. */
	if (profile->total_connections >= copilot->min_samples_for_baseline)
		behavior_analyze (copilot, profile, app_name, remote_ip,
		                  port, now_unix);
}

/* [ fs_copilot_get_insights ] */
GList *
fs_copilot_get_insights (FsCopilot *copilot)
{
	if (copilot == NULL)
		return NULL;

	return g_list_copy (copilot->insights);
}

/* [ fs_copilot_clear_insights ] */
void
fs_copilot_clear_insights (FsCopilot *copilot)
{
	if (copilot == NULL)
		return;

	g_list_free_full (copilot->insights, (GDestroyNotify) fs_insight_free);
	copilot->insights = NULL;
}

/* ---- What-If scenario grammar --------------------------------------
 * The simulator takes one line of plain text, e.g.
 *   allow SSH from 192.168.1.50 on port 22
 *   block DNS to 8.8.8.8 on port 53 udp
 *   ssh is open at 22 port          (the number may precede "port")
 *   allow anything to :22           (a port on this machine, no host)
 * The grammar is closed on purpose: direction keywords (inbound,
 * outbound, ingress, egress, from, to), a numeric host or CIDR block,
 * a "port N" / "N port" clause, a bare ":N" or "local:N" port, or a
 * known service name (ssh=22, http=80, https=443, dns=53, rdp=3389,
 * ftp=21, smtp=25, ...), and a protocol keyword.  Everything the
 * parser reads out lands in FsScenario, so the verdict is never based
 * on a reading the user cannot see. */

/* [ find_word_ci ]
 * Case-insensitive whole-word occurrence of needle (already lowercase)
 * in hay.  Word boundaries keep "port" out of "important" and "to"
 * out of "tomorrow". */
static const gchar *
find_word_ci (const gchar *hay, const gchar *needle)
{
	gsize nlen;

	if (hay == NULL || needle == NULL || *needle == '\0')
		return NULL;

	nlen = strlen (needle);

	for (const gchar *p = hay; *p != '\0'; p++) {
		gsize i = 0;

		while (i < nlen && p[i] != '\0' &&
		       g_ascii_tolower (p[i]) == needle[i])
			i++;

		if (i != nlen)
			continue;

		if ((p == hay || !g_ascii_isalnum (p[-1])) &&
		    (p[nlen] == '\0' || !g_ascii_isalnum (p[nlen])))
			return p;
	}

	return NULL;
}

/* [ looks_ipv4 ]
 * A strict dotted quad: four octets of digits, each 0-255.  Hostnames
 * deliberately do not pass -- "open.code.exe" must never be read as
 * the host of a scenario. */
static gboolean
looks_ipv4 (const gchar *s)
{
	gchar **parts;
	gboolean ok = TRUE;

	if (s == NULL || *s == '\0')
		return FALSE;

	parts = g_strsplit (s, ".", -1);

	if (g_strv_length (parts) != 4) {
		g_strfreev (parts);
		return FALSE;
	}

	for (guint i = 0; parts[i] != NULL; i++) {
		const gchar *octet = parts[i];

		if (*octet == '\0' || strlen (octet) > 3) {
			ok = FALSE;
			break;
		}

		for (const gchar *p = octet; *p != '\0'; p++) {
			if (!g_ascii_isdigit (*p)) {
				ok = FALSE;
				break;
			}
		}

		if (!ok)
			break;

		if (g_ascii_strtoll (octet, NULL, 10) > 255) {
			ok = FALSE;
			break;
		}
	}

	g_strfreev (parts);

	return ok;
}

/* [ looks_like_address ]
 * Numeric shapes only: an address with a prefix length, a dotted quad,
 * or an IPv6 address (strict, via the validator's inet_pton path). */
static gboolean
looks_like_address (const gchar *s)
{
	if (s == NULL || *s == '\0')
		return FALSE;

	if (strchr (s, '/') != NULL)
		return fs_util_is_valid_host (s);

	if (strchr (s, '.') != NULL)
		return looks_ipv4 (s);

	if (strchr (s, ':') != NULL)
		return fs_util_is_valid_host (s);

	return FALSE;
}

/* [ first_port_of ]
 * The first port of a service's "ports" string ("80", "67-68",
 * "137-139 445"), or 0 for none. */
static guint
first_port_of (const gchar *ports)
{
	if (ports == NULL || *ports == '\0')
		return 0;

	return (guint) g_ascii_strtoll (ports, NULL, 10);
}

/* [ addr_covers ]
 * TRUE when a compiled rule address covers the probed address.  NULL
 * is the compiled form of "Anyone" and covers everything; a CIDR rule
 * covers hosts inside its block; anything else needs an equal name. */
static gboolean
addr_covers (const gchar *rule_addr, const gchar *probe)
{
	if (rule_addr == NULL)
		return TRUE;

	if (probe == NULL || *probe == '\0')
		return TRUE;

	if (g_ascii_strcasecmp (rule_addr, probe) == 0)
		return TRUE;

	return fs_util_addr_in_cidr (rule_addr, probe);
}

/* [ scenario_line ]
 * The one place a scenario sentence is built, so the result log, the
 * dialog text and the tests all read the same words. */
static gchar *
scenario_line (gboolean inbound, const gchar *protocol,
               const gchar *remote_ip, guint port, const gchar *app)
{
	gchar *src;
	gchar *dst;
	gchar *port_txt;
	gchar *line;
	gboolean known = (remote_ip != NULL && *remote_ip != '\0');

	if (inbound) {
		src = g_strdup (known ? remote_ip : _("anywhere"));
		dst = g_strdup (_("local"));
	} else {
		src = g_strdup (_("local"));
		dst = g_strdup (known ? remote_ip : _("anywhere"));
	}

	port_txt = (port > 0) ? g_strdup_printf ("%u", port)
	                      : g_strdup (_("any port"));

	line = g_strdup_printf (_("%s %s connection from %s to %s port %s (%s)"),
	                        inbound ? _("Inbound") : _("Outbound"),
	                        (protocol != NULL && *protocol != '\0')
	                        ? protocol : "TCP",
	                        src, dst, port_txt,
	                        (app != NULL && *app != '\0') ? app
	                                                      : _("unnamed application"));

	g_free (src);
	g_free (dst);
	g_free (port_txt);

	return line;
}

/* [ fs_copilot_parse_scenario ] */
FsScenario *
fs_copilot_parse_scenario (const gchar *text)
{
	FsScenario *sc;
	gchar *lower;
	const gchar *hit;

	if (text == NULL || *text == '\0')
		return NULL;

	sc = g_new0 (FsScenario, 1);
	sc->protocol = g_strdup ("TCP");
	lower = g_ascii_strdown (text, -1);

	/* Direction: explicit keywords win, then from/to, then the
	 * documented default -- outbound, the common rule to test.
	 * g_ascii_strdown never changes the byte length of ASCII, so
	 * offsets into `lower` stay valid for slicing `text`. */
	if (find_word_ci (lower, "inbound") != NULL ||
	    find_word_ci (lower, "ingress") != NULL)
		sc->inbound = TRUE;
	else if (find_word_ci (lower, "outbound") != NULL ||
	         find_word_ci (lower, "outgoing") != NULL ||
	         find_word_ci (lower, "egress") != NULL)
		sc->inbound = FALSE;
	else if (find_word_ci (lower, "from") != NULL)
		sc->inbound = TRUE;
	else if (find_word_ci (lower, "to") != NULL)
		sc->inbound = FALSE;

	/* Protocol keyword.  TCP is already the default, so only the
	 * overrides need branches. */
	if (find_word_ci (lower, "udp") != NULL) {
		g_free (sc->protocol);
		sc->protocol = g_strdup ("UDP");
	} else if (find_word_ci (lower, "icmp") != NULL ||
	           find_word_ci (lower, "ping") != NULL) {
		g_free (sc->protocol);
		sc->protocol = g_strdup ("ICMP");
	}

	/* "port N" -- the explicit clause wins over a service name.  The
	 * number may follow the word ("port 22") or precede it ("ssh is
	 * open at 22 port", "scan at 8080 port"): both shapes were typed
	 * by real users and one of them used to read as no port at all. */
	hit = find_word_ci (lower, "port");
	if (hit != NULL) {
		const gchar *d = hit + 4;

		while (*d == ' ' || *d == '\t')
			d++;

		if (g_ascii_isdigit (*d)) {
			glong v = g_ascii_strtoll (d, NULL, 10);

			if (v >= 0 && v <= 65535) {
				sc->port = (guint) v;
				sc->had_port = TRUE;
			}
		} else {
			/* "22 port": the digits directly before the word. */
			const gchar *last = hit;
			const gchar *first;

			while (last > lower && (last[-1] == ' ' ||
			                       last[-1] == '\t'))
				last--;

			first = last;

			while (first > lower && g_ascii_isdigit (first[-1]))
				first--;

			if (first < last && g_ascii_isdigit (*first)) {
				glong v = g_ascii_strtoll (first, NULL, 10);

				if (v >= 1 && v <= 65535) {
					sc->port = (guint) v;
					sc->had_port = TRUE;
				}
			}
		}
	}

	/* The application/service: the token after "allow" or "allowing",
	 * minus the articles. */
	{
		const gchar *a = find_word_ci (lower, "allowing");
		gsize alen = 8;

		if (a == NULL) {
			a = find_word_ci (lower, "allow");
			alen = 5;
		}

		if (a != NULL) {
			static const gchar *articles[] = {
				"the", "a", "an", "my", "me", "any", "all", "new", NULL
			};
			const gchar *p = a + alen;
			gboolean skipped = TRUE;

			while (skipped) {
				while (*p == ' ' || *p == '\t')
					p++;

				skipped = FALSE;

				for (guint i = 0; articles[i] != NULL; i++) {
					gsize len = strlen (articles[i]);

					if (g_ascii_strncasecmp (p, articles[i], len) == 0 &&
					    (p[len] == '\0' || !g_ascii_isalnum (p[len]))) {
						p += len;
						skipped = TRUE;
						break;
					}
				}
			}

			{
				const gchar *start = p;

				while (*p != '\0' && !g_ascii_isspace (*p) &&
				       *p != ',' && *p != '"' && *p != '\'' &&
				       *p != '(' && *p != ')' && *p != ';')
					p++;

				if (p > start)
					sc->app = g_strndup (text + (start - lower),
					                      (gsize) (p - start));
			}
		}
	}

	/* The small well-known map, asked before the big service table
	 * below: these answer exactly as documented.  FTP means the
	 * control port 21 (the table's first port is 20, the data
	 * channel) and RDP lives here because the table predates it. */
	{
		static const struct {
			const gchar *name;
			guint        port;
		} known[] = {
			{ "ssh",    22   },
			{ "http",   80   },
			{ "https",  443  },
			{ "dns",    53   },
			{ "rdp",    3389 },
			{ "ftp",    21   },
			{ "smtp",   25   },
			{ "telnet", 23   }
		};

		for (guint i = 0; i < G_N_ELEMENTS (known); i++) {
			const gchar *m = find_word_ci (lower, known[i].name);

			if (m == NULL)
				continue;

			if (!sc->had_port) {
				sc->port = known[i].port;
				sc->had_port = TRUE;
			}

			if (sc->app == NULL)
				sc->app = g_strndup (text + (m - lower),
				                      strlen (known[i].name));
			break;
		}
	}

	/* A known service name supplies the port when the line has no
	 * "port N" clause ("allow SSH to 10.0.0.1") and the app name when
	 * the line had no "allow" token ("block DNS to 8.8.8.8"). */
	{
		guint n_user = 0;
		guint n_misc = 0;
		const FsService *lists[2];
		guint counts[2];

		lists[0] = fs_service_user_list (&n_user);
		counts[0] = n_user;
		lists[1] = fs_service_misc_list (&n_misc);
		counts[1] = n_misc;

		for (guint pass = 0; pass < 2; pass++) {
			for (guint i = 0; i < counts[pass]; i++) {
				gchar *needle = g_ascii_strdown (lists[pass][i].name, -1);
				const gchar *m = find_word_ci (lower, needle);

				if (m != NULL && !sc->had_port) {
					guint port = first_port_of (lists[pass][i].ports);

					if (port >= 1 && port <= 65535) {
						sc->port = port;
						sc->had_port = TRUE;
					}
				}

				if (m != NULL && sc->app == NULL)
					sc->app = g_strndup (text + (m - lower),
					                      strlen (lists[pass][i].name));

				g_free (needle);
			}
		}
	}

	/* The host: the first token that is a numeric address or block.
	 * The "10.0.0.1:22" shorthand supplies the port as well. */
	{
		const gchar *t = text;

		while (*t != '\0' && sc->remote_ip == NULL) {
			const gchar *start;
			const gchar *end;
			gchar *tok;

			while (*t != '\0' && (g_ascii_isspace (*t) || *t == ',' ||
			                      *t == '(' || *t == ')' || *t == '"' ||
			                      *t == '\'' || *t == ';'))
				t++;

			start = t;

			while (*t != '\0' && !g_ascii_isspace (*t) && *t != ',' &&
			       *t != '(' && *t != ')' && *t != '"' && *t != '\'' &&
			       *t != ';')
				t++;

			end = t;

			/* Sentence punctuation is not part of the address. */
			while (end > start && (end[-1] == '.' || end[-1] == ',' ||
			                       end[-1] == ';'))
				end--;

			if (end <= start)
				continue;

			tok = g_strndup (start, (gsize) (end - start));

			if (looks_like_address (tok)) {
				sc->remote_ip = tok;
				sc->had_addr = TRUE;
			} else {
				const gchar *colon = strchr (tok, ':');

				if (colon != NULL && colon == strrchr (tok, ':')) {
					gchar *head = g_strndup (tok,
					                          (gsize) (colon - tok));

					if (colon > tok && looks_ipv4 (head)) {
						if (!sc->had_port &&
						    g_ascii_isdigit (colon[1])) {
							glong v = g_ascii_strtoll (
								colon + 1, NULL, 10);

							if (v >= 1 && v <= 65535) {
								sc->port = (guint) v;
								sc->had_port = TRUE;
							}
						}

						sc->remote_ip = head;
						sc->had_addr = TRUE;
						head = NULL;
					} else if (!sc->had_port &&
					           g_ascii_isdigit (colon[1])) {
						/* ":22" or "local:22": a port on this
						 * machine, not a host.  Only the empty
						 * head and the names for "us" count --
						 * "example.com:22" is a hostname-shaped
						 * token and stays rejected. */
						static const gchar *local_heads[] = {
							"", "local", "localhost", "me",
							"myself", "self", "this", NULL
						};
						const gchar *e = colon + 1;
						gboolean all_digits = TRUE;

						while (*e != '\0') {
							if (!g_ascii_isdigit (*e)) {
								all_digits = FALSE;
								break;
							}
							e++;
						}

						if (all_digits &&
						    e - (colon + 1) <= 5) {
							gboolean ours = FALSE;

							for (guint i = 0;
							     local_heads[i] != NULL;
							     i++) {
								if (g_ascii_strcasecmp (
								    head,
								    local_heads[i]) == 0) {
									ours = TRUE;
									break;
								}
							}

							if (ours) {
								glong v = g_ascii_strtoll (
								colon + 1, NULL, 10);

								if (v >= 1 && v <= 65535) {
									sc->port = (guint) v;
									sc->had_port = TRUE;
								}
							}
						}
					}

					g_free (head);
				}

				g_free (tok);
			}
		}
	}

	g_free (lower);

	return sc;
}

/* [ fs_scenario_free ] */
void
fs_scenario_free (FsScenario *scenario)
{
	if (scenario == NULL)
		return;

	g_free (scenario->protocol);
	g_free (scenario->remote_ip);
	g_free (scenario->app);
	g_free (scenario);
}

/* [ fs_copilot_simulate_text ] */
FsSimulationResult *
fs_copilot_simulate_text (FsCopilot *copilot, const gchar *text,
                          FsScenario **parsed_out)
{
	FsScenario *sc = fs_copilot_parse_scenario (text);
	FsSimulationResult *result;

	if (sc == NULL)
		return NULL;

	result = fs_copilot_simulate (copilot, sc->app, sc->remote_ip,
	                              sc->port, sc->protocol, sc->inbound);

	if (parsed_out != NULL)
		*parsed_out = sc;
	else
		fs_scenario_free (sc);

	return result;
}

/* [ rule_port_covers ]
 * Port matching mirrors address matching: a port either side left
 * unnamed constrains nothing.  A rule with no port governs every
 * probe, and a line that named no port still meets the rule that
 * opens a specific one -- the same "every port" reading the panel's
 * no-port note promises and the no-host note gets from
 * addr_covers().  ICMP has no ports at all, so a ported rule cannot
 * govern ICMP traffic however the line phrased it. */
static gboolean
rule_port_covers (guint probe_port, gboolean icmp, gint rule_port)
{
	if (rule_port == 0)
		return TRUE;

	if (icmp)
		return FALSE;

	if (probe_port == 0)
		return TRUE;

	return rule_port == (gint) probe_port;
}

/* [ port_score ]
 * How precisely a rule's port answers the probe: the exact port
 * asked is the sharpest answer, a rule naming no port covers every
 * port, and a rule on some port a portless line never named is the
 * weakest cover of all. */
static gint
port_score (guint probe_port, gint rule_port)
{
	if (rule_port == 0)
		return 1;

	if (probe_port == (guint) rule_port)
		return 2;

	return 0;
}

/* [ match_score ]
 * The rule the verdict names should be the rule that actually
 * decided this traffic, not merely the first one that fits.  Every
 * matching rule on each side is scored -- port precision first,
 * then address precision -- and the higher score wins; ties keep
 * the policy's own order.  A line that named no port or no host is
 * scored the same way: the widest answer (any-port, anyone) beats a
 * rule covering only a slice of what the line left open. */
static gint
match_score (guint probe_port, const gchar *probe_addr,
             const FsFwRule *rule)
{
	gint port = MAX (port_score (probe_port, rule->local_port),
	                 port_score (probe_port, rule->remote_port));
	gint addr;

	if (probe_addr == NULL || *probe_addr == '\0')
		addr = (rule->remote_address == NULL) ? 3 : 1;
	else if (rule->remote_address == NULL)
		addr = 2;
	else if (g_ascii_strcasecmp (rule->remote_address, probe_addr) == 0)
		addr = 3;
	else
		addr = 2;   /* CIDR containment: the subnet covers it. */

	return (port * 10) + addr;
}

/* [ match_where ]
 * The " on port N (forwarded to X)" tail a verdict appends when the
 * rule that decided it pinned a port or redirects the traffic.  The
 * panel's no-port/no-host notes point the reader at exactly this:
 * without it, a verdict reached through a specific port would read
 * like a verdict for every port. */
static gchar *
match_where (const FsFwRule *rule)
{
	GString *s = g_string_new (NULL);
	gint port = (rule->local_port != 0) ? rule->local_port
	                                    : rule->remote_port;

	if (port != 0)
		g_string_append_printf (s, _(" on port %d"), port);

	if (rule->forward && rule->forward_address != NULL &&
	    *rule->forward_address != '\0')
		g_string_append_printf (s, _(" (forwarded to %s)"),
		                        rule->forward_address);

	return g_string_free (s, FALSE);
}

/* [ fs_copilot_simulate ]
 * Runs a what-if simulation against the attached policy: the first
 * allow and the first block that cover the probe are collected, and a
 * block wins -- the same precedence Windows Firewall applies.  If no
 * policy is attached, falls back to heuristic defaults (deny inbound,
 * allow outbound) and says so in the explanation. */
FsSimulationResult *
fs_copilot_simulate (FsCopilot *copilot,
                     const gchar *app_name,
                     const gchar *remote_ip,
                     guint port,
                     const gchar *protocol,
                     gboolean inbound)
{
	FsSimulationResult *result = g_new0 (FsSimulationResult, 1);
	gchar *reason = NULL;

	result->scenario = scenario_line (inbound, protocol, remote_ip, port,
	                                  app_name);

	/* If no policy is attached, fall back to heuristic defaults. */
	if (copilot == NULL || copilot->policy == NULL)
	{
		result->would_block = inbound;
		result->matching_rule = g_strdup (inbound
		                                  ? _("Default deny (no policy loaded)")
		                                  : _("Default allow (no policy loaded)"));
		reason = g_strdup (_("No firewall policy is loaded in the copilot, "
		                     "so the platform defaults were used: deny "
		                     "inbound, allow outbound.  Load a policy in "
		                     "the Policy tab for an answer against your "
		                     "real rules."));
	}
	else
	{
		/* Expand the policy into concrete rules. */
		GList *rules = fs_fwrule_from_policy (copilot->policy);

		if (rules == NULL)
		{
			/* No rules in policy -- use defaults. */
			result->would_block = inbound;
			result->matching_rule = g_strdup (inbound
			                                  ? _("Default deny (empty policy)")
			                                  : _("Default allow (empty policy)"));
			reason = g_strdup (_("The loaded policy contains no rules, so "
			                     "the platform defaults were used: deny "
			                     "inbound, allow outbound."));
		}
		else
		{
			/* Collect the best allow and the best block that fit the
			 * probe.  A block wins over an allow matching the same
			 * traffic -- Windows Firewall gives block rules precedence
			 * whatever order they were written in -- so reporting the
			 * allow as if it applied would be the quiet lie this port
			 * exists to remove.  Within each side every candidate is
			 * scored (match_score) so the rule the verdict names is
			 * the one that actually decided this traffic: the exact
			 * port and host beat an any-port or anyone rule, and the
			 * policy's own order breaks ties. */
			FsRuleProtocol proto = FS_PROTO_ANY;
			const gchar *remote_addr = (remote_ip && *remote_ip)
			                           ? remote_ip : NULL;
			FsFwRule *allow_match = NULL;
			FsFwRule *block_match = NULL;
			gint allow_score = -1;
			gint block_score = -1;
			gboolean icmp = (protocol != NULL &&
			                 g_ascii_strcasecmp (protocol, "ICMP") == 0);

			if (protocol != NULL)
			{
				if (g_strcmp0 (protocol, "TCP") == 0)
					proto = FS_PROTO_TCP;
				else if (g_strcmp0 (protocol, "UDP") == 0)
					proto = FS_PROTO_UDP;
			}

			for (GList *l = rules; l != NULL; l = l->next)
			{
				FsFwRule *rule = l->data;
				gboolean is_block = (rule->action == FS_ACTION_BLOCK);
				gint score;

				/* Direction must match. */
				if (rule->direction != (inbound ? FS_DIR_INBOUND
				                                 : FS_DIR_OUTBOUND))
					continue;

				/* Protocol must match (ANY matches TCP/UDP/ICMP). */
				if (rule->protocol != FS_PROTO_ANY && rule->protocol != proto)
					continue;

				/* Ports: a port either side left unnamed constrains
				 * nothing; ICMP meets only portless rules. */
				if (!rule_port_covers (port, icmp, rule->local_port))
					continue;
				if (!rule_port_covers (port, icmp, rule->remote_port))
					continue;

				/* Address: the compiled rule must cover the probe, as an
				 * equal name or as a block containing it.  The probe
				 * carries no local address, so a rule's local-address
				 * condition cannot exclude it. */
				if (!addr_covers (rule->remote_address, remote_addr))
					continue;

				score = match_score (port, remote_addr, rule);

				if (is_block) {
					if (score > block_score) {
						block_match = rule;
						block_score = score;
					}
				} else {
					if (score > allow_score) {
						allow_match = rule;
						allow_score = score;
					}
				}
			}

			if (block_match != NULL)
			{
				gchar *where = match_where (block_match);

				result->would_block = TRUE;
				result->matching_rule = g_strdup (block_match->name);

				if (allow_match != NULL)
					reason = g_strdup_printf (
						_("Rule '%s'%s blocks it. The allow rule '%s' "
						  "also matches, but block rules take "
						  "precedence, so that allow is shadowed."),
						block_match->name, where, allow_match->name);
				else
					reason = g_strdup_printf (
						_("Matched rule '%s'%s, which %s %s traffic."),
						block_match->name, where, _("blocks"),
						inbound ? _("inbound") : _("outbound"));
				g_free (where);
			}
			else if (allow_match != NULL)
			{
				gchar *where = match_where (allow_match);

				result->would_block = FALSE;
				result->matching_rule = g_strdup (allow_match->name);
				reason = g_strdup_printf (
					_("Matched rule '%s'%s, which %s %s traffic."),
					allow_match->name, where, _("allows"),
					inbound ? _("inbound") : _("outbound"));
				g_free (where);
			}
			else
			{
				/* No rule matched -- apply default policy. */
				result->would_block = inbound;
				result->matching_rule = g_strdup (
					inbound ? _("Default deny (no matching rule)")
					        : _("Default allow (no matching rule)"));
				reason = g_strdup_printf (
					_("No rule in the loaded policy matches this "
					  "connection.  Default policy: %s."),
					inbound ? _("deny inbound") : _("allow outbound"));
			}

			fs_fwrule_list_free (rules);
		}
	}

	result->affected_connections = 1;
	result->reason = g_strdup (reason);
	result->explanation = g_strdup_printf (_("Simulation: %s would be %s. "
	                                         "Reason: %s"),
	                                       result->scenario,
	                                       result->would_block ? _("BLOCKED")
	                                                          : _("ALLOWED"),
	                                       reason);
	g_free (reason);

	return result;
}

/* [ fs_copilot_allow_suggestion ]
 * The "how to allow this" sentence a blocked verdict shows.  Built in
 * core so the panel, the visualizer and the tests read the same
 * words. */
gchar *
fs_copilot_allow_suggestion (const FsScenario *scenario)
{
	GString *s;
	gboolean icmp;

	if (scenario == NULL)
		return NULL;

	icmp = (g_strcmp0 (scenario->protocol, "ICMP") == 0);

	s = g_string_new ("Allow ");
	g_string_append (s, scenario->inbound ? _("inbound") : _("outbound"));
	g_string_append_c (s, ' ');
	g_string_append (s, (scenario->protocol != NULL &&
	                     *scenario->protocol != '\0')
	                  ? scenario->protocol : "TCP");

	/* ICMP has no ports; saying "port 0" or "any port" for it would
	 * be a question the line never asked. */
	if (scenario->had_port)
		g_string_append_printf (s, " %s %u", _("port"), scenario->port);
	else if (!icmp)
		g_string_append (s, _(" traffic"));

	if (scenario->remote_ip != NULL && *scenario->remote_ip != '\0')
		g_string_append_printf (s, " %s %s",
		                        scenario->inbound ? _("from") : _("to"),
		                        scenario->remote_ip);

	g_string_append_c (s, '.');

	return g_string_free (s, FALSE);
}

/* [ fs_copilot_allow_rule_for ]
 * The rule that would let the scenario through: the service-allow kind
 * of its direction, its port, its host.  The service column carries
 * the well-known name when the port has one ("SSH" for 22) and the
 * protocol word when it does not ("TCP" for 8443), so the Policy page
 * shows something a person can recognize either way. */
FsRule *
fs_copilot_allow_rule_for (const FsScenario *scenario)
{
	FsRule *rule;
	gchar *service = NULL;

	if (scenario == NULL)
		return NULL;

	rule = fs_rule_new (scenario->inbound
	                    ? FS_RULE_INBOUND_ALLOW_SERVICE
	                    : FS_RULE_OUTBOUND_ALLOW_SERVICE);

	if (scenario->port > 0)
		service = fs_service_lookup_port ((gint) scenario->port);

	if (service == NULL)
		service = g_strdup ((scenario->protocol != NULL &&
		                     *scenario->protocol != '\0')
		                    ? scenario->protocol : "TCP");

	rule->service = service;
	rule->port = (scenario->port > 0)
	             ? g_strdup_printf ("%u", scenario->port)
	             : g_strdup ("");
	rule->target = (scenario->remote_ip != NULL &&
	                *scenario->remote_ip != '\0')
	               ? g_strdup (scenario->remote_ip)
	               : g_strdup (FS_TARGET_ANY);
	rule->comment = g_strdup ("What-If Simulator suggestion");

	return rule;
}

/* [ fs_copilot_get_profile ] */
const FsAppProfile *
fs_copilot_get_profile (FsCopilot *copilot, const gchar *app_name)
{
	if (copilot == NULL || app_name == NULL)
		return NULL;

	return g_hash_table_lookup (copilot->profiles, app_name);
}

/* [ fs_copilot_get_all_profiles ] */
GList *
fs_copilot_get_all_profiles (FsCopilot *copilot)
{
	if (copilot == NULL)
		return NULL;

	GList *list = NULL;
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, copilot->profiles);
	while (g_hash_table_iter_next (&iter, &key, &value))
		list = g_list_prepend (list, value);

	return list;
}

/* [ fs_copilot_export_json ] */
gchar *
fs_copilot_export_json (FsCopilot *copilot)
{
	if (copilot == NULL)
		return NULL;

	/* Simplified JSON export - in production would use JSON-GLib. */
	GString *json = g_string_new ("{ \"profiles\": {");
	gboolean first = TRUE;

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init (&iter, copilot->profiles);
	while (g_hash_table_iter_next (&iter, &key, &value))
	{
		FsAppProfile *p = value;
		if (!first) g_string_append (json, ", ");
		first = FALSE;

		g_string_append_printf (json, "\"%s\": { \"connections\": %" G_GUINT64_FORMAT
		                        ", \"bytes_sent\": %" G_GUINT64_FORMAT
		                        ", \"bytes_recv\": %" G_GUINT64_FORMAT
		                        ", \"first_seen\": %" G_GUINT64_FORMAT
		                        ", \"last_seen\": %" G_GUINT64_FORMAT " }",
		                        (const gchar *) key,
		                        p->total_connections,
		                        p->total_bytes_sent,
		                        p->total_bytes_recv,
		                        p->first_seen,
		                        p->last_seen);
	}

	g_string_append (json, "} }");
	return g_string_free (json, FALSE);
}

/* [ fs_copilot_import_json ] */
gboolean
fs_copilot_import_json (FsCopilot *copilot, const gchar *json)
{
	/* Would parse JSON and rebuild profiles. Simplified for now. */
	(void) copilot; (void) json;
	return FALSE;
}

/* ---- Historical behavior baseline (P2) ----------------------------
 * One CSV row per learned fact, in the trust store's dialect (the
 * shared writer/parser in fs-util): a "meta" row carries totals and
 * first/last seen, a "rate" row the frequency state, and
 * port/dest/hour rows the learned sets.  The file is what makes the
 * baseline HISTORICAL -- a restart resumes yesterday's knowledge
 * instead of relearning it and calling every old port new. */

/* [ parse_u64 ] -- strict: digits only, the whole field. */
static gboolean
parse_u64 (const gchar *text, guint64 *out)
{
	gchar *end = NULL;
	guint64 value;

	if (text == NULL || *text == '\0' || !g_ascii_isdigit (*text))
		return FALSE;

	value = g_ascii_strtoull (text, &end, 10);
	if (end == text || *end != '\0')
		return FALSE;

	*out = value;
	return TRUE;
}

/* [ fs_copilot_baseline_path ] -- follows the trust store's
 * convention; STOCKFW_BEHAVIOR_FILE overrides it for the tests. */
gchar *
fs_copilot_baseline_path (void)
{
	const gchar *env = g_getenv ("STOCKFW_BEHAVIOR_FILE");

	if (env != NULL && *env != '\0')
		return g_strdup (env);

#ifdef G_OS_WIN32
	/* Same home as stockfw.conf and trust.csv: the roaming AppData
	 * folder, not the local one g_get_user_config_dir() would give. */
	{
		const gchar *appdata = g_getenv ("APPDATA");

		if (appdata != NULL && *appdata != '\0')
			return g_build_filename (appdata, "stockfw",
			                         "behavior.csv", NULL);

		return g_build_filename (g_get_home_dir (), "AppData",
		                         "Roaming", "stockfw",
		                         "behavior.csv", NULL);
	}
#else
	return g_build_filename (g_get_user_config_dir (), "stockfw",
	                         "behavior.csv", NULL);
#endif
}

/* [ cmp_app_name ] -- g_strcmp0 as a GCompareFunc, without the cast
 * GCC's -Wcast-function-type would complain about. */
static gint
cmp_app_name (gconstpointer a, gconstpointer b)
{
	return g_strcmp0 ((const gchar *) a, (const gchar *) b);
}

/* [ fs_copilot_baseline_save ]
 * Deterministic output: application names sorted, one group per
 * application (meta, rate, partial flag, ports, destinations, hours),
 * so two saves of the same state are the same file. */
gboolean
fs_copilot_baseline_save (FsCopilot *copilot, const gchar *path,
                          GError **error)
{
	GString *out;
	GList *names = NULL;
	GList *l;
	GHashTableIter iter;
	gpointer key, value;
	gboolean ok;

	if (copilot == NULL || path == NULL || *path == '\0') {
		if (error != NULL)
			g_set_error_literal (error, G_IO_ERROR,
			                     G_IO_ERROR_INVALID_ARGUMENT,
			                     "behavior baseline has no file to write");
		return FALSE;
	}

	if (!fs_util_ensure_parent_dir (path)) {
		if (error != NULL)
			g_set_error_literal (error, G_IO_ERROR,
			                     G_IO_ERROR_FAILED,
			                     "the baseline directory could not be created");
		return FALSE;
	}

	g_hash_table_iter_init (&iter, copilot->profiles);
	while (g_hash_table_iter_next (&iter, &key, &value))
		names = g_list_prepend (names, (gchar *) key);
	names = g_list_sort (names, cmp_app_name);

	out = g_string_new ("# StockFW behavior baseline v1\n");

	for (l = names; l != NULL; l = l->next) {
		const gchar *app = l->data;
		FsAppProfile *p = g_hash_table_lookup (copilot->profiles, app);
		gchar num[3][32];

		if (p == NULL)
			continue;

		/* meta: total connections, first seen, last seen.  Every
		 * row's first field is written with first=TRUE -- the flag
		 * skips the separator, and each row starts a new line. */
		g_snprintf (num[0], sizeof num[0],
		            "%" G_GUINT64_FORMAT, p->total_connections);
		g_snprintf (num[1], sizeof num[1],
		            "%" G_GUINT64_FORMAT, p->first_seen);
		g_snprintf (num[2], sizeof num[2],
		            "%" G_GUINT64_FORMAT, p->last_seen);
		fs_util_csv_append_field (out, app, TRUE);
		fs_util_csv_append_field (out, "meta", FALSE);
		fs_util_csv_append_field (out, num[0], FALSE);
		fs_util_csv_append_field (out, num[1], FALSE);
		fs_util_csv_append_field (out, num[2], FALSE);
		g_string_append_c (out, '\n');

		/* rate: EWMA x1000, buckets closed, bucket reported */
		g_snprintf (num[0], sizeof num[0], "%u", p->rate_ema_milli);
		g_snprintf (num[1], sizeof num[1], "%u", p->rate_buckets);
		g_snprintf (num[2], sizeof num[2],
		            "%" G_GUINT64_FORMAT, p->rate_reported);
		fs_util_csv_append_field (out, app, TRUE);
		fs_util_csv_append_field (out, "rate", FALSE);
		fs_util_csv_append_field (out, num[0], FALSE);
		fs_util_csv_append_field (out, num[1], FALSE);
		fs_util_csv_append_field (out, num[2], FALSE);
		g_string_append_c (out, '\n');

		/* partial: this profile's sets were capped somewhere */
		if (p->baseline_partial) {
			fs_util_csv_append_field (out, app, TRUE);
			fs_util_csv_append_field (out, "partial", FALSE);
			g_string_append_c (out, '\n');
		}

		/* ports */
		{
			GHashTableIter set_iter;
			gpointer pkey, pvalue;

			g_hash_table_iter_init (&set_iter, p->common_ports);
			while (g_hash_table_iter_next (&set_iter, &pkey,
			                               &pvalue)) {
				g_snprintf (num[0], sizeof num[0], "%u",
				            GPOINTER_TO_UINT (pkey));
				g_snprintf (num[1], sizeof num[1], "%u",
				            *(guint *) pvalue);
				fs_util_csv_append_field (out, app, TRUE);
				fs_util_csv_append_field (out, "port", FALSE);
				fs_util_csv_append_field (out, num[0], FALSE);
				fs_util_csv_append_field (out, num[1], FALSE);
				g_string_append_c (out, '\n');
			}
		}

		/* destinations */
		{
			GHashTableIter set_iter;
			gpointer pkey, pvalue;

			g_hash_table_iter_init (&set_iter,
			                        p->common_destinations);
			while (g_hash_table_iter_next (&set_iter, &pkey,
			                               &pvalue)) {
				g_snprintf (num[1], sizeof num[1], "%u",
				            *(guint *) pvalue);
				fs_util_csv_append_field (out, app, TRUE);
				fs_util_csv_append_field (out, "dest", FALSE);
				fs_util_csv_append_field (out, (const gchar *)
				                          pkey, FALSE);
				fs_util_csv_append_field (out, num[1], FALSE);
				g_string_append_c (out, '\n');
			}
		}

		/* hours */
		{
			GHashTableIter set_iter;
			gpointer pkey, pvalue;

			g_hash_table_iter_init (&set_iter, p->hourly_activity);
			while (g_hash_table_iter_next (&set_iter, &pkey,
			                               &pvalue)) {
				g_snprintf (num[0], sizeof num[0], "%u",
				            GPOINTER_TO_UINT (pkey));
				g_snprintf (num[1], sizeof num[1],
				            "%" G_GUINT64_FORMAT,
				            *(guint64 *) pvalue);
				fs_util_csv_append_field (out, app, TRUE);
				fs_util_csv_append_field (out, "hour", FALSE);
				fs_util_csv_append_field (out, num[0], FALSE);
				fs_util_csv_append_field (out, num[1], FALSE);
				g_string_append_c (out, '\n');
			}
		}
	}

	g_list_free (names);

	ok = g_file_set_contents (path, out->str, out->len, error);
	g_string_free (out, TRUE);
	return ok;
}

/* [ fs_copilot_baseline_load ]
 * Merges the file into whatever the copilot already knows: meta rows
 * replace totals, fact rows accumulate (a port row adds its count).
 * Unknown rows are skipped -- a newer format still loads what it
 * understands.  Rows refused by a cap mark that profile partial, so
 * a truncated baseline never claims to know everything. */
gboolean
fs_copilot_baseline_load (FsCopilot *copilot, const gchar *path,
                          GError **error)
{
	gchar *contents = NULL;
	gchar **lines;
	guint i;

	if (copilot == NULL || path == NULL) {
		if (error != NULL)
			g_set_error_literal (error, G_IO_ERROR,
			                     G_IO_ERROR_INVALID_ARGUMENT,
			                     "behavior baseline load needs a file");
		return FALSE;
	}

	if (!g_file_get_contents (path, &contents, NULL, error)) {
		/* A file that is not there is a fresh start, not a failure. */
		if (error != NULL && *error != NULL &&
		    g_error_matches (*error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			g_clear_error (error);
		return FALSE;
	}

	lines = g_strsplit (contents, "\n", -1);
	g_free (contents);

	for (i = 0; lines[i] != NULL; i++) {
		GPtrArray *fields;
		const gchar *app, *kind;
		FsAppProfile *p;
		guint64 a, b, c;

		g_strstrip (lines[i]);
		if (*lines[i] == '\0' || *lines[i] == '#')
			continue;

		fields = fs_util_csv_split_line (lines[i]);
		if (fields->len < 2) {
			g_ptr_array_unref (fields);
			continue;
		}

		app = g_ptr_array_index (fields, 0);
		kind = g_ptr_array_index (fields, 1);
		if (*app == '\0') {
			g_ptr_array_unref (fields);
			continue;
		}

		/* An unknown kind is skipped whole -- and creates no
		 * profile: nothing understands the row, so nothing should
		 * pretend this application was learned from it. */
		if (g_strcmp0 (kind, "meta") != 0 &&
		    g_strcmp0 (kind, "rate") != 0 &&
		    g_strcmp0 (kind, "partial") != 0 &&
		    g_strcmp0 (kind, "port") != 0 &&
		    g_strcmp0 (kind, "dest") != 0 &&
		    g_strcmp0 (kind, "hour") != 0) {
			g_ptr_array_unref (fields);
			continue;
		}

		p = g_hash_table_lookup (copilot->profiles, app);
		if (p == NULL) {
			if (g_hash_table_size (copilot->profiles) >=
			    FS_BEHAVIOR_MAX_APPS) {
				g_ptr_array_unref (fields);
				continue;   /* whole app past the cap: ignored */
			}
			p = app_profile_new (app, NULL, time (NULL));
			g_hash_table_insert (copilot->profiles,
			                     g_strdup (app), p);
		}

		if (g_strcmp0 (kind, "meta") == 0) {
			if (fields->len >= 5 &&
			    parse_u64 (g_ptr_array_index (fields, 2), &a) &&
			    parse_u64 (g_ptr_array_index (fields, 3), &b) &&
			    parse_u64 (g_ptr_array_index (fields, 4), &c)) {
				p->total_connections = a;
				p->first_seen = b;
				p->last_seen = c;
			}
		} else if (g_strcmp0 (kind, "rate") == 0) {
			if (fields->len >= 5 &&
			    parse_u64 (g_ptr_array_index (fields, 2), &a) &&
			    parse_u64 (g_ptr_array_index (fields, 3), &b) &&
			    parse_u64 (g_ptr_array_index (fields, 4), &c)) {
				p->rate_ema_milli = (guint) MIN (a,
				                                  G_MAXUINT);
				p->rate_buckets = (guint) MIN (b, G_MAXUINT);
				p->rate_reported = c;
			}
		} else if (g_strcmp0 (kind, "partial") == 0) {
			p->baseline_partial = TRUE;
		} else if (g_strcmp0 (kind, "port") == 0) {
			if (fields->len >= 4 &&
			    parse_u64 (g_ptr_array_index (fields, 2), &a) &&
			    parse_u64 (g_ptr_array_index (fields, 3), &b) &&
			    a > 0 && a <= 65535) {
				guint *existing = g_hash_table_lookup (
					p->common_ports,
					GUINT_TO_POINTER ((guint) a));
				if (existing != NULL)
					*existing += (guint) MIN (b, G_MAXUINT);
				else if (g_hash_table_size (p->common_ports) >=
				         FS_BEHAVIOR_MAX_PORTS)
					p->baseline_partial = TRUE;
				else {
					guint *slot = g_new (guint, 1);
					*slot = (guint) MIN (b, G_MAXUINT);
					g_hash_table_insert (p->common_ports,
					                     GUINT_TO_POINTER (
					                             (guint) a),
					                     slot);
				}
			}
		} else if (g_strcmp0 (kind, "dest") == 0) {
			const gchar *addr = g_ptr_array_index (fields, 2);

			if (fields->len >= 4 && *addr != '\0' &&
			    parse_u64 (g_ptr_array_index (fields, 3), &b)) {
				guint *existing = g_hash_table_lookup (
					p->common_destinations, addr);
				if (existing != NULL)
					*existing += (guint) MIN (b, G_MAXUINT);
				else if (g_hash_table_size (
				         p->common_destinations) >=
				         FS_BEHAVIOR_MAX_DESTS)
					p->baseline_partial = TRUE;
				else {
					guint *slot = g_new (guint, 1);
					*slot = (guint) MIN (b, G_MAXUINT);
					g_hash_table_insert (
						p->common_destinations,
						g_strdup (addr), slot);
				}
			}
		} else if (g_strcmp0 (kind, "hour") == 0) {
			if (fields->len >= 4 &&
			    parse_u64 (g_ptr_array_index (fields, 2), &a) &&
			    parse_u64 (g_ptr_array_index (fields, 3), &b) &&
			    a < 24) {
				guint64 *existing = g_hash_table_lookup (
					p->hourly_activity,
					GUINT_TO_POINTER ((guint) a));
				if (existing != NULL)
					*existing += b;
				else {
					guint64 *slot = g_new (guint64, 1);
					*slot = b;
					g_hash_table_insert (p->hourly_activity,
					                     GUINT_TO_POINTER (
					                             (guint) a),
					                     slot);
				}
			}
		}
		/* Unknown kinds were skipped above: a newer format still
		 * loads what this reader understands. */

		g_ptr_array_unref (fields);
	}

	g_strfreev (lines);
	return TRUE;
}

/* [ fs_insight_free ] */
void
fs_insight_free (FsInsight *insight)
{
	if (insight == NULL)
		return;

	g_free (insight->title);
	g_free (insight->description);
	g_free (insight->application);
	g_free (insight->destination);
	g_free (insight->suggested_rule);
	g_free (insight->rule_csv);
	g_free (insight);
}

/* [ fs_simulation_result_free ] */
void
fs_simulation_result_free (FsSimulationResult *result)
{
	if (result == NULL)
		return;

	g_free (result->scenario);
	g_free (result->matching_rule);
	g_free (result->explanation);
	g_free (result->reason);
	g_free (result);
}

/* [ fs_insight_to_rule ] */
FsRule *
fs_insight_to_rule (const FsInsight *insight)
{
	if (insight == NULL || insight->rule_csv == NULL ||
	    *insight->rule_csv == '\0')
		return NULL;

	return fs_rule_from_csv (insight->rule_kind, insight->rule_csv);
}

/* [ fs_insight_apply ]
 * Stage an insight's rule: add a copy to the policy and persist.  The
 * persist helper rolls the store back when the write fails, so FALSE
 * here always means "the disk and the store do not carry this rule". */
gboolean
fs_insight_apply (const FsInsight *insight, FsPolicy *policy)
{
	FsRule *rule = fs_insight_to_rule (insight);
	gboolean ok;

	if (rule == NULL)
		return FALSE;

	if (policy == NULL) {
		fs_rule_free (rule);
		return FALSE;
	}

	ok = fs_policy_add_persist (policy, rule);
	fs_rule_free (rule);
	return ok;
}

/* [ fs_insight_is_auto_safe ]
 * The auto-block invariant, in one place: an insight may be staged
 * WITHOUT a human only when its rule can only TIGHTEN the policy --
 * an outbound deny.  Suggestions that open things (service allows,
 * which legacy insights carry for the user's confirmed Apply button)
 * are never safe to stage automatically, whatever their flag says. */
gboolean
fs_insight_is_auto_safe (const FsInsight *insight)
{
	if (insight == NULL || insight->rule_csv == NULL ||
	    *insight->rule_csv == '\0')
		return FALSE;

	return insight->rule_kind == FS_RULE_OUTBOUND_DENY_TO ||
	       insight->rule_kind == FS_RULE_OUTBOUND_DENY_SERVICE;
}

/* [ app_profile_new ] */
static FsAppProfile *
app_profile_new (const gchar *name, const gchar *path, gint64 now_unix)
{
	FsAppProfile *profile = g_new0 (FsAppProfile, 1);
	profile->app_name = g_strdup (name);
	profile->app_path = path ? g_strdup (path) : NULL;
	profile->common_ports = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                               NULL, NULL);
	profile->common_destinations = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                                      g_free, NULL);
	profile->hourly_activity = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                                      NULL, NULL);
	profile->first_seen = (guint64) now_unix;
	return profile;
}

/* [ app_profile_free ] */
static void
app_profile_free (FsAppProfile *profile)
{
	if (profile == NULL)
		return;

	g_free (profile->app_name);
	g_free (profile->app_path);
	g_hash_table_unref (profile->common_ports);
	g_hash_table_unref (profile->common_destinations);
	g_hash_table_unref (profile->hourly_activity);
	g_free (profile);
}

/* [ app_profile_record_connection ]
 * The single write path of a profile: totals, port, destination,
 * hour of day, and the open rate window.  The clock arrives from the
 * caller (feed_event_full), so the tests drive wall time and every
 * timing finding is deterministic.  Port 0 (ICMP, unparsed) is not a
 * port and is never stored.  The set tables are bounded; hitting a
 * cap marks the profile partial so no later signal can claim a
 * truncated baseline knows everything. */
static void
app_profile_record_connection (FsAppProfile *profile,
                               const gchar *remote_ip,
                               guint port,
                               const gchar *protocol,
                               gboolean inbound,
                               guint64 bytes,
                               gint64 now_unix)
{
	guint64 bucket;
	GDateTime *dt;
	gint hour;

	(void) protocol;
	(void) inbound;

	profile->total_connections++;
	profile->last_seen = (guint64) now_unix;

	if (bytes > 0)
	{
		if (bytes > 0) /* Direction inferred from context */
			profile->total_bytes_recv += bytes;
		else
			profile->total_bytes_sent += bytes;
	}

	/* Record port usage. */
	if (port != 0)
	{
		guint *port_count = g_hash_table_lookup (profile->common_ports,
		                                         GUINT_TO_POINTER (port));
		if (port_count == NULL)
		{
			if (g_hash_table_size (profile->common_ports) >=
			    FS_BEHAVIOR_MAX_PORTS)
				profile->baseline_partial = TRUE;
			else {
				guint *new_count = g_new (guint, 1);
				*new_count = 1;
				g_hash_table_insert (profile->common_ports,
				                     GUINT_TO_POINTER (port),
				                     new_count);
			}
		}
		else
		{
			(*port_count)++;
		}
	}

	/* Record destination. */
	if (remote_ip && *remote_ip)
	{
		guint *dest_count = g_hash_table_lookup (profile->common_destinations,
		                                         remote_ip);
		if (dest_count == NULL)
		{
			if (g_hash_table_size (profile->common_destinations) >=
			    FS_BEHAVIOR_MAX_DESTS)
				profile->baseline_partial = TRUE;
			else {
				guint *new_count = g_new (guint, 1);
				*new_count = 1;
				g_hash_table_insert (profile->common_destinations,
				                     g_strdup (remote_ip),
				                     new_count);
			}
		}
		else
		{
			(*dest_count)++;
		}
	}

	/* Record hourly activity from the caller's wall clock. */
	dt = g_date_time_new_from_unix_local (now_unix);
	hour = dt != NULL ? g_date_time_get_hour (dt) : 0;
	if (dt != NULL)
		g_date_time_unref (dt);

	{
		guint64 *hour_count = g_hash_table_lookup (profile->hourly_activity,
		                                           GUINT_TO_POINTER (hour));
		if (hour_count == NULL)
		{
			guint64 *new_count = g_new (guint64, 1);
			*new_count = 1;
			g_hash_table_insert (profile->hourly_activity,
			                     GUINT_TO_POINTER (hour), new_count);
		}
		else
		{
			(*hour_count)++;
		}
	}

	/* Record the rate window: close the open one when the clock has
	 * moved to another 10-minute bucket, then count this event in the
	 * current bucket.  The established rate is an integer EWMA
	 * (x1000, alpha 0.25) seeded with the first closed bucket. */
	bucket = (guint64) ((now_unix / FS_BEHAVIOR_WINDOW_S) *
	                    FS_BEHAVIOR_WINDOW_S);
	if (bucket == 0)
		bucket = FS_BEHAVIOR_WINDOW_S;   /* guard: 0 means "no window" */

	if (profile->rate_window_start != 0 &&
	    profile->rate_window_start != bucket)
	{
		if (profile->rate_buckets == 0)
			profile->rate_ema_milli =
				profile->rate_window_count * 1000;
		else
			profile->rate_ema_milli = (guint) (
				(gint64) profile->rate_ema_milli +
				((250 * ((gint64) profile->rate_window_count * 1000 -
				         (gint64) profile->rate_ema_milli)) / 1000));
		profile->rate_buckets++;
		profile->rate_window_count = 0;
	}

	profile->rate_window_start = bucket;
	profile->rate_window_count++;
}

/* [ is_novel_port ]
 * Recording happens BEFORE analysis, so a port first used by THIS
 * event has a count of exactly 1 -- that is the whole honest test.
 * (The old check fired while the count was < 3, so the same port was
 * reported two or three times while its message claimed the app had
 * "never used it before".) */
static gboolean
is_novel_port (FsAppProfile *profile, guint port)
{
	guint *count;

	if (port == 0)
		return FALSE;

	count = g_hash_table_lookup (profile->common_ports,
	                             GUINT_TO_POINTER (port));
	return count != NULL && *count == 1;
}

/* [ is_novel_destination ] -- same discipline: count == 1 means this
 * event made first contact. */
static gboolean
is_novel_destination (FsAppProfile *profile, const gchar *remote_ip)
{
	guint *count;

	if (remote_ip == NULL || *remote_ip == '\0')
		return FALSE;

	count = g_hash_table_lookup (profile->common_destinations, remote_ip);
	return count != NULL && *count == 1;
}

/* [ is_novel_hour ]
 * The first time an application is active in an hour -- but only once
 * it has ESTABLISHED hours to be outside of: with fewer than four
 * hour buckets the profile has no "usual hours" yet, and calling any
 * new hour unusual would be theater. */
static gboolean
is_novel_hour (FsAppProfile *profile, gint64 now_unix)
{
	GDateTime *dt;
	guint64 *count;
	gboolean novel;

	dt = g_date_time_new_from_unix_local (now_unix);
	if (dt == NULL)
		return FALSE;

	count = g_hash_table_lookup (profile->hourly_activity,
	                             GUINT_TO_POINTER (g_date_time_get_hour (dt)));
	g_date_time_unref (dt);

	if (count == NULL || *count != 1)
		return FALSE;

	novel = g_hash_table_size (profile->hourly_activity) >=
	        FS_BEHAVIOR_HOURS_MIN_DISTINCT;
	return novel;
}

/* [ rate_spike_take ]
 * Connection frequency: this event's 10-minute bucket holds far more
 * than the rate the application has established over the previous
 * buckets.  TRUE at most once per bucket (rate_reported is consumed
 * here -- the count keeps growing while the bucket is open, and one
 * report per burst is the honest number).  Integer arithmetic only:
 * same inputs, same verdict, every run. */
static gboolean
rate_spike_take (FsAppProfile *profile, gint64 now_unix)
{
	guint64 window;
	guint threshold;

	if (profile->rate_buckets < FS_BEHAVIOR_RATE_MIN_BUCKETS)
		return FALSE;                   /* rate not established yet */

	window = (guint64) ((now_unix / FS_BEHAVIOR_WINDOW_S) *
	                    FS_BEHAVIOR_WINDOW_S);
	if (window == 0)
		window = FS_BEHAVIOR_WINDOW_S;

	if (profile->rate_window_start != window)
		return FALSE;                   /* only the open bucket counts */
	if (profile->rate_reported == window)
		return FALSE;                   /* already reported this burst */
	if (profile->rate_window_count < FS_BEHAVIOR_RATE_MIN_EVENTS)
		return FALSE;                   /* floor, whatever the rate */

	threshold = (profile->rate_ema_milli / 1000) * 3 + 5;
	if (profile->rate_window_count <= threshold)
		return FALSE;

	profile->rate_reported = window;
	return TRUE;
}

/* [ brief_ports ] / [ brief_hours ]
 * The numbers a signal line shows: up to six sorted ports, up to
 * eight sorted hours, "... past the cut, "none" when empty.  Bounded
 * on purpose -- a finding is a sentence, not a dump. */
static gint
cmp_port_key (gconstpointer a, gconstpointer b)
{
	return (gint) GPOINTER_TO_UINT (a) - (gint) GPOINTER_TO_UINT (b);
}

static gchar *
brief_ports (FsAppProfile *profile)
{
	GList *keys = g_hash_table_get_keys (profile->common_ports);
	GString *out = g_string_new (NULL);
	GList *l;
	guint n = 0;

	keys = g_list_sort (keys, cmp_port_key);
	for (l = keys; l != NULL; l = l->next) {
		if (n == 6) {
			g_string_append (out, ", ...");
			break;
		}
		if (n > 0)
			g_string_append (out, ", ");
		g_string_append_printf (out, "%u",
		                        GPOINTER_TO_UINT (l->data));
		n++;
	}
	g_list_free (keys);

	if (out->len == 0)
		g_string_append (out, "none");

	return g_string_free (out, FALSE);
}

static gchar *
brief_hours (FsAppProfile *profile)
{
	GList *keys = g_hash_table_get_keys (profile->hourly_activity);
	GString *out = g_string_new (NULL);
	GList *l;
	guint n = 0;

	keys = g_list_sort (keys, cmp_port_key);
	for (l = keys; l != NULL; l = l->next) {
		if (n == 8) {
			g_string_append (out, ", ...");
			break;
		}
		if (n > 0)
			g_string_append (out, ", ");
		g_string_append_printf (out, "%02u",
		                        GPOINTER_TO_UINT (l->data));
		n++;
	}
	g_list_free (keys);

	if (out->len == 0)
		g_string_append (out, "none");

	return g_string_free (out, FALSE);
}

/* [ behavior_analyze ]
 * P2's whole point: correlate, don't chain.  Every signal this event
 * raises -- new port, new destination, first activity in an hour,
 * rate far above the app's own -- goes into ONE finding whose
 * description lists each signal with its numbers, so the reader sees
 * what fired and why together.  Two or more signals on one event
 * escalate to CRITICAL: that is what correlation buys.  A correlated
 * finding carries no suggested rule; a single port/destination one
 * keeps the legacy allow suggestion (an outbound service allow,
 * never auto-safe, so the Sentinel path cannot stage it). */
static void
behavior_analyze (FsCopilot *copilot, FsAppProfile *profile,
                  const gchar *app_name, const gchar *remote_ip,
                  guint port, gint64 now_unix)
{
	gboolean sig_port, sig_dest, sig_hour, sig_rate;
	GPtrArray *lines;
	GString *desc;
	FsInsightType type;
	FsCopilotSeverity severity;
	FsInsight *insight;
	const gchar *title;
	gchar *owned_title = NULL;
	gchar *dest_owned = NULL;
	guint n, i;

	sig_port = !profile->baseline_partial &&
	           is_novel_port (profile, port);
	sig_dest = !profile->baseline_partial &&
	           is_novel_destination (profile, remote_ip);
	sig_hour = is_novel_hour (profile, now_unix);
	sig_rate = rate_spike_take (profile, now_unix);

	if (!sig_port && !sig_dest && !sig_hour && !sig_rate)
		return;

	lines = g_ptr_array_new_with_free_func (g_free);

	if (sig_port) {
		gchar *known = brief_ports (profile);

		g_ptr_array_add (lines, g_strdup_printf (
			_("first use of port %u -- before this, the baseline "
			  "knew %s"),
			port, known));
		g_free (known);
	}
	if (sig_dest) {
		g_ptr_array_add (lines, g_strdup_printf (
			_("first contact with %s -- the baseline knew %u "
			  "destinations"),
			remote_ip,
			g_hash_table_size (profile->common_destinations) - 1));
	}
	if (sig_hour) {
		GDateTime *dt = g_date_time_new_from_unix_local (now_unix);
		gchar *hours = brief_hours (profile);
		gint hour = dt != NULL ? g_date_time_get_hour (dt) : 0;

		g_ptr_array_add (lines, g_strdup_printf (
			_("first activity at %02d:00 -- established hours: %s"),
			hour, hours));
		g_free (hours);
		if (dt != NULL)
			g_date_time_unref (dt);
	}
	if (sig_rate) {
		g_ptr_array_add (lines, g_strdup_printf (
			_("%u connections in the last 10 minutes -- the usual "
			  "rate is about %u per 10 minutes"),
			profile->rate_window_count,
			profile->rate_ema_milli / 1000));
	}

	n = lines->len;

	type = sig_port ? FS_INSIGHT_UNUSUAL_PORT
	     : sig_dest ? FS_INSIGHT_UNUSUAL_DESTINATION
	     : sig_rate ? FS_INSIGHT_UNUSUAL_VOLUME
	     :            FS_INSIGHT_UNUSUAL_TIME;
	severity = n > 1 ? FS_COPILOT_CRITICAL
	         : (type == FS_INSIGHT_UNUSUAL_TIME ? FS_COPILOT_INFO
	                                             : FS_COPILOT_WARNING);

	if (n > 1) {
		title = owned_title = g_strdup_printf (
			_("Multiple signals for %s"), app_name);
	} else if (sig_port) {
		title = _("Unusual port for application");
	} else if (sig_dest) {
		title = _("Unusual destination");
	} else if (sig_rate) {
		title = _("Unusual connection rate");
	} else {
		title = _("Activity at unusual time");
	}

	desc = g_string_new (NULL);
	g_string_append_printf (desc,
	                        _("%s deviates from its established "
	                          "baseline:"),
	                        app_name);
	for (i = 0; i < n; i++)
		g_string_append_printf (desc, "\n- %s",
		                        (const gchar *)
		                        g_ptr_array_index (lines, i));

	if (sig_dest && remote_ip != NULL && *remote_ip != '\0')
		dest_owned = g_strdup (remote_ip);
	else if (sig_port && remote_ip != NULL && *remote_ip != '\0')
		dest_owned = g_strdup_printf ("%s:%u", remote_ip, port);

	insight = create_insight (type, severity, title,
	                          g_string_free (desc, FALSE), app_name,
	                          dest_owned);

	if (n == 1 && port != 0 && remote_ip != NULL &&
	    *remote_ip != '\0' && (sig_port || sig_dest)) {
		if (sig_port)
			insight->suggested_rule = g_strdup_printf (
				_("Allow %s on port %u for %s"),
				app_name, port, remote_ip);
		else
			insight->suggested_rule = g_strdup_printf (
				_("Allow %s to connect to %s"),
				app_name, remote_ip);
		insight->rule_csv = g_strdup_printf ("%s, %u, %s, %s",
		                                     app_name, port,
		                                     remote_ip,
		                                     _("Auto-generated by Copilot"));
		insight->auto_applicable = TRUE;
	}

	insight->timestamp = now_unix;
	emit_insight (copilot, insight);

	g_ptr_array_unref (lines);
	g_free (owned_title);
	g_free (dest_owned);
}

/* [ emit_insight ]
 * Every insight enters through here: the list is bounded (Chapter
 * 9).  The oldest falls off at the cap, so a scanning flood cannot
 * grow the list without end. */
static void
emit_insight (FsCopilot *copilot, FsInsight *insight)
{
	copilot->insights = g_list_prepend (copilot->insights, insight);

	while (g_list_length (copilot->insights) > FS_COPILOT_MAX_INSIGHTS) {
		GList *oldest = g_list_last (copilot->insights);

		fs_insight_free (oldest->data);
		copilot->insights = g_list_delete_link (copilot->insights,
		                                        oldest);
	}
}

/* ---- Sentinel: covert-channel and fan-out detection ---------------- */

/* [ sentinel_hit_is_inbound ]
 * The rogue-agent problem is egress: what leaves the host.  Sentinel
 * watches outbound events only. */
static gboolean
sentinel_hit_is_inbound (const FsHit *hit)
{
	if (hit->direction == NULL)
		return FALSE;

	return g_ascii_strcasecmp (hit->direction, "In") == 0 ||
	       g_ascii_strcasecmp (hit->direction, "Inbound") == 0;
}

/* [ sentinel_hit_is_blocked ]
 * The Windows backend appends " [BLOCKED]" to the service field of
 * dropped events; blocked fan-out is the strongest scan signal. */
static gboolean
sentinel_hit_is_blocked (const FsHit *hit)
{
	return hit->service != NULL &&
	       strstr (hit->service, " [BLOCKED]") != NULL;
}

/* [ sentinel_beacon_check ]
 * Regularity, not content: a host contacted every N seconds with
 * metronomic intervals is running a check-in loop, because humans,
 * page loads and even scheduled jobs jitter.  Arrival times are
 * bucketed to whole seconds (a polled batch is one moment), the
 * interval series is capped, and each host:port is reported once. */
static FsInsight *
sentinel_beacon_check (FsCopilot *copilot, const FsHit *hit, gint64 now_us)
{
	const gchar *dst, *port;
	gchar *key;
	gboolean key_owned = FALSE;
	GArray *stamps;
	gint64 sec, last, sum = 0;
	gdouble mean, var = 0.0;
	guint i, n_diff;

	if (sentinel_hit_is_inbound (hit))
		return NULL;

	dst  = hit->destination;
	port = hit->port;
	if (dst == NULL || *dst == '\0' || port == NULL || *port == '\0')
		return NULL;

	sec = now_us / G_USEC_PER_SEC;
	key = g_strdup_printf ("%s:%s", dst, port);

	stamps = g_hash_table_lookup (copilot->beacon_stamps, key);
	if (stamps == NULL) {
		stamps = g_array_new (FALSE, TRUE, sizeof (gint64));
		g_hash_table_insert (copilot->beacon_stamps, key, stamps);
		key_owned = TRUE;
	}

	if (stamps->len == 0) {
		g_array_append_val (stamps, sec);
	} else {
		last = g_array_index (stamps, gint64, stamps->len - 1);

		if (last < sec) {
			g_array_append_val (stamps, sec);
			if (stamps->len > FS_SENTINEL_BEACON_MAX_STAMPS)
				g_array_remove_index (stamps, 0);
		}
		/* last == sec: same-second batch, no new information. */
	}

	if (stamps->len < FS_SENTINEL_BEACON_MIN_SAMPLES)
		goto out;

	n_diff = stamps->len - 1;
	for (i = 0; i < n_diff; i++)
		sum += g_array_index (stamps, gint64, i + 1) -
		       g_array_index (stamps, gint64, i);

	mean = (gdouble) sum / n_diff;
	for (i = 0; i < n_diff; i++) {
		gdouble d = (gdouble) (g_array_index (stamps, gint64, i + 1) -
		                       g_array_index (stamps, gint64, i));

		var += (d - mean) * (d - mean);
	}

	/* Regularity as cv^2 against the threshold -- no sqrt(), so no
	 * libm dependency in the test build. */
	if (mean < FS_SENTINEL_BEACON_MIN_MEAN_S ||
	    mean > FS_SENTINEL_BEACON_MAX_MEAN_S ||
	    var / n_diff > (FS_SENTINEL_BEACON_MAX_CV *
	                    FS_SENTINEL_BEACON_MAX_CV) * mean * mean)
		goto out;

	if (g_hash_table_contains (copilot->beacon_reported, key))
		goto out;

	g_hash_table_insert (copilot->beacon_reported, g_strdup (key),
	                     GINT_TO_POINTER (1));

	{
		FsInsight *insight = create_insight (
			FS_INSIGHT_BEACON, FS_COPILOT_CRITICAL,
			_("Periodic beacon traffic detected"),
			g_strdup_printf (
				_("Connection to %s:%s repeated %u times at "
				  "near-identical intervals of about %d "
				  "seconds. Traffic this metronomic is the "
				  "signature of a control channel checking "
				  "in. StockFW suggests blocking further "
				  "outbound traffic to this destination."),
				dst, port, stamps->len, (gint) (mean + 0.5)),
			hit->service, dst);

		insight->suggested_rule = g_strdup_printf (
			_("Block outbound traffic to %s"), dst);
		insight->rule_csv = g_strdup_printf (
			"%s, %s", dst, "Sentinel: periodic beacon");
		insight->rule_kind = FS_RULE_OUTBOUND_DENY_TO;
		insight->auto_applicable = TRUE;

		if (!key_owned)
			g_free (key);
		return insight;
	}

out:
	if (!key_owned)
		g_free (key);
	return NULL;
}

/* [ sentinel_fanout_check ]
 * One program reaching many distinct hosts inside a short window is a
 * scan, a worm or data leaving by many doors.  Blocked hosts count on
 * their own, lower, threshold: legitimate bulk traffic is mostly
 * allowed, scanning is mostly refused.  One report per window; the
 * episode ends when the window empties. */
static FsInsight *
sentinel_fanout_check (FsCopilot *copilot, const FsHit *hit, gint64 now_us)
{
	const gchar *dst;
	gint64 sec, window_start;
	guint n_any, n_blocked;
	GHashTableIter iter;
	gpointer k, v;
	FsInsight *insight;

	if (sentinel_hit_is_inbound (hit))
		return NULL;

	dst = hit->destination;
	if (dst == NULL || *dst == '\0')
		return NULL;

	sec         = now_us / G_USEC_PER_SEC;
	window_start = sec - FS_SENTINEL_FANOUT_WINDOW_S;

	g_hash_table_iter_init (&iter, copilot->fanout_seen);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		if (GPOINTER_TO_INT (v) < window_start)
			g_hash_table_iter_remove (&iter);
	}

	g_hash_table_iter_init (&iter, copilot->fanout_blocked);
	while (g_hash_table_iter_next (&iter, &k, &v)) {
		if (GPOINTER_TO_INT (v) < window_start)
			g_hash_table_iter_remove (&iter);
	}

	/* An emptied window starts a fresh episode. */
	if (g_hash_table_size (copilot->fanout_seen) == 0)
		copilot->fanout_reported = FALSE;

	g_hash_table_insert (copilot->fanout_seen, g_strdup (dst),
	                     GINT_TO_POINTER ((gint) sec));

	if (sentinel_hit_is_blocked (hit))
		g_hash_table_insert (copilot->fanout_blocked, g_strdup (dst),
		                     GINT_TO_POINTER ((gint) sec));

	n_any     = g_hash_table_size (copilot->fanout_seen);
	n_blocked = g_hash_table_size (copilot->fanout_blocked);

	if (n_blocked < FS_SENTINEL_FANOUT_BLOCKED &&
	    n_any < FS_SENTINEL_FANOUT_LIMIT)
		return NULL;

	if (copilot->fanout_reported)
		return NULL;

	copilot->fanout_reported = TRUE;

	insight = create_insight (
		FS_INSIGHT_FANOUT, FS_COPILOT_CRITICAL,
		_("Burst of distinct destinations"),
		g_strdup_printf (
			_("In the last %d seconds this host contacted %u "
			  "distinct remote hosts, %u of them while being "
			  "blocked. One program fanning out like this is a "
			  "scan, a worm or data leaving by many doors. "
			  "Right-click a row in Events to block a host."),
			FS_SENTINEL_FANOUT_WINDOW_S, n_any, n_blocked),
		hit->service, NULL);

	/* No single guilty host exists, so this detection carries no
	 * rule: auto-block must never guess. */
	insight->suggested_rule = g_strdup (
		_("Review the events and block the hosts that should not "
		  "be reached"));
	insight->rule_csv = NULL;
	insight->auto_applicable = FALSE;

	return insight;
}

/* [ create_insight ] */
static FsInsight *
create_insight (FsInsightType type,
                FsCopilotSeverity severity,
                const gchar *title,
                gchar *description,
                const gchar *app_name,
                const gchar *destination)
{
	FsInsight *insight = g_new0 (FsInsight, 1);
	insight->type = type;
	insight->severity = severity;
	insight->title = g_strdup (title);
	/* Every caller passes a freshly formatted string here (and a
	 * literal for the title), so the description is taken over as it
	 * stands -- the g_strdup this used to do leaked one string per
	 * insight. */
	insight->description = description;
	/* Legacy suggestions are CSV rows shaped as outbound service
	 * allows; Sentinel block suggestions override this with the deny
	 * kind they were built for. */
	insight->rule_kind = FS_RULE_OUTBOUND_ALLOW_SERVICE;
	insight->application = g_strdup (app_name);
	insight->destination = destination ? g_strdup (destination) : NULL;
	return insight;
}