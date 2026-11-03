/*---[ fs-feed.c ]-------------------------------------------------------
 * Threat-intel feeds: the catalog, the three formats, the parse guards,
 * the URL rule and the update judge.  See fs-feed.h; the design is
 * docs/design/1.0.7-threat-intel-design.md, section 4.
 *
 * A feed body is bytes from the internet, so every line takes the same
 * path: split, classified by its format, parsed strictly (fs_range_parse,
 * which never resolves a name), cut by the protected ranges, measured
 * and counted.  Memory is bounded by the entry cap, work by the size
 * cap, and nothing here reads a clock, a file or the network.
 *--------------------------------------------------------------------*/

#include "core/fs-feed.h"
#include "core/fs-i18n.h"

#include <string.h>

GQuark
fs_feed_error_quark (void)
{
	return g_quark_from_static_string ("stockfw-feed-error");
}

/* ============================================================== catalog */

/* Every entry was checked against its publisher on 2026-11-02: its page
 * and terms were read and, where the web tools could fetch it, a real
 * copy of the list for its format and its content-date line (the two
 * exceptions say so).  `license' is set only where the publisher's own
 * page or file names a licence; the source of each fact is in the
 * comment above the entry. */
static const FsFeedInfo CATALOG[] = {
	/* Sample: one {"cidr":"1.10.16.0/20","sblid":"SBL256894",
	 * "rir":"apnic"} per line, then {"type":"metadata","timestamp":
	 * 1793468642,"size":...,"records":...,"copyright":...,"terms":...}.
	 * Terms (www.spamhaus.org/drop/terms/): free of charge, no licence
	 * named, commercial use not restricted; credit Spamhaus in a
	 * product.  The DROP page asks that the data "should not be
	 * downloaded from our website more than once per day", so the
	 * interval is 24 h rather than the 12 h of the design table. */
	{
		.id             = "spamhaus-drop",
		.name           = N_("Spamhaus DROP (IPv4)"),
		.category       = N_("Hijacked networks"),
		.description    = N_("Networks hijacked or run by spammers and "
		                     "cyber-criminals; Spamhaus advises dropping "
		                     "all traffic to and from them."),
		.url            = "https://www.spamhaus.org/drop/drop_v4.json",
		.host           = "www.spamhaus.org",
		.info_url       = "https://www.spamhaus.org/blocklists/"
		                  "do-not-route-or-peer/",
		.terms_url      = "https://www.spamhaus.org/drop/terms/",
		.license        = NULL,
		.noncommercial  = FALSE,
		.format         = FS_FEED_FMT_SPAMHAUS_JSON,
		.default_dir    = FS_INTEL_DIR_BOTH,
		.interval_hours = 24,
		.recommended    = TRUE,
		.includes       = NULL,
		.has_v6         = FALSE,
		.credit         = "The Spamhaus Project, spamhaus.org (DROP)",
	},
	/* Sample: 89 {"cidr":"2001:678:254::/48",...} lines and the same
	 * metadata line ("records":89).  Terms and interval as above. */
	{
		.id             = "spamhaus-dropv6",
		.name           = N_("Spamhaus DROP (IPv6)"),
		.category       = N_("Hijacked networks"),
		.description    = N_("The IPv6 networks of Spamhaus DROP: "
		                     "hijacked or criminal ranges that carry no "
		                     "legitimate traffic."),
		.url            = "https://www.spamhaus.org/drop/drop_v6.json",
		.host           = "www.spamhaus.org",
		.info_url       = "https://www.spamhaus.org/blocklists/"
		                  "do-not-route-or-peer/",
		.terms_url      = "https://www.spamhaus.org/drop/terms/",
		.license        = NULL,
		.noncommercial  = FALSE,
		.format         = FS_FEED_FMT_SPAMHAUS_JSON,
		.default_dir    = FS_INTEL_DIR_BOTH,
		.interval_hours = 24,
		.recommended    = TRUE,
		.includes       = NULL,
		.has_v6         = TRUE,
		.credit         = "The Spamhaus Project, spamhaus.org (DROPv6)",
	},
	/* Sample: a '#' box with "# Last updated: 2026-03-04 14:28:39 UTC",
	 * "# DstIP", one IPv4 address per line, "# END 1 entries".
	 * Licence: abuse.ch terms of use (abuse.ch/terms-of-use/, s3.4):
	 * Feodo Tracker data is "free to use without limitations according
	 * to Creative Commons principles (CC0)" for commercial and
	 * non-commercial use. */
	{
		.id             = "feodo",
		.name           = N_("abuse.ch Feodo Tracker"),
		.category       = N_("Botnet C2"),
		.description    = N_("Botnet command-and-control servers that "
		                     "Feodo Tracker has seen active in the past "
		                     "hours."),
		.url            = "https://feodotracker.abuse.ch/downloads/"
		                  "ipblocklist_recommended.txt",
		.host           = "feodotracker.abuse.ch",
		.info_url       = "https://feodotracker.abuse.ch/blocklist/",
		.terms_url      = "https://abuse.ch/terms-of-use/",
		.license        = "CC0",
		.noncommercial  = FALSE,
		.format         = FS_FEED_FMT_PLAIN,
		.default_dir    = FS_INTEL_DIR_BOTH,
		.interval_hours = 6,
		.recommended    = TRUE,
		.includes       = NULL,
		.has_v6         = FALSE,
		.credit         = "abuse.ch Feodo Tracker, feodotracker.abuse.ch",
	},
	/* Sample: '#' header with "#    updated: 2026-11-02T12:45:39.735756"
	 * and "some rights reserved. Details http://creativecommons.org/
	 * licenses/by-nc-sa/2.5/", then start<TAB>end<TAB>24<TAB>count<TAB>
	 * name<TAB>country<TAB>email rows (20 /24s).  The file itself names
	 * the licence: CC BY-NC-SA 2.5, non-commercial [P9]. */
	{
		.id             = "dshield",
		.name           = N_("DShield top attackers"),
		.category       = N_("Attackers"),
		.description    = N_("The twenty /24 networks that attacked "
		                     "DShield sensors the most over the last "
		                     "three days."),
		.url            = "https://feeds.dshield.org/block.txt",
		.host           = "feeds.dshield.org",
		.info_url       = "https://www.dshield.org/",
		.terms_url      = "https://creativecommons.org/licenses/"
		                  "by-nc-sa/2.5/",
		.license        = "CC BY-NC-SA 2.5",
		.noncommercial  = TRUE,
		.format         = FS_FEED_FMT_DSHIELD,
		.default_dir    = FS_INTEL_DIR_IN,
		.interval_hours = 24,
		.recommended    = FALSE,
		.includes       = NULL,
		.has_v6         = FALSE,
		.credit         = "DShield.org, SANS Internet Storm Center",
	},
	/* Sample: "# ipv4 hash:net ipset", "(includes: dshield feodo
	 * fullbogons spamhaus_drop)", "# This File Date  : Sat Oct 24
	 * 04:49:13 UTC 2026", then one CIDR per line (0.0.0.0/8, ...,
	 * 224.0.0.0/3).  The publisher's page for the list
	 * (iplists.firehol.org/firehol_level1.html) links this GitHub copy
	 * as its download, not iplists.firehol.org/files/; the list "is
	 * updated automatically every time any of its IP lists is updated"
	 * (no fixed schedule; the design's 24 h).  IPv4 only, so it includes
	 * Spamhaus DROP (IPv4) but not DROP (IPv6).  No licence: the
	 * repository says some lists carry their own and to check each
	 * source; it carries DShield's list, whose CC BY-NC-SA terms forbid
	 * commercial use, hence non-commercial. */
	{
		.id             = "firehol-level1",
		.name           = N_("FireHOL level 1"),
		.category       = N_("Aggregate"),
		.description    = N_("FireHOL's composite of Spamhaus DROP, "
		                     "DShield, Feodo Tracker and unroutable "
		                     "addresses, for basic protection with few "
		                     "false positives."),
		.url            = "https://raw.githubusercontent.com/firehol/"
		                  "blocklist-ipsets/master/firehol_level1.netset",
		.host           = "raw.githubusercontent.com",
		.info_url       = "https://iplists.firehol.org/"
		                  "?ipset=firehol_level1",
		.terms_url      = "https://github.com/firehol/blocklist-ipsets",
		.license        = NULL,
		.noncommercial  = TRUE,
		.format         = FS_FEED_FMT_PLAIN,
		.default_dir    = FS_INTEL_DIR_IN,
		.interval_hours = 24,
		.recommended    = FALSE,
		.includes       = "spamhaus-drop feodo dshield",
		.has_v6         = FALSE,
		.credit         = "FireHOL IP lists, iplists.firehol.org",
	},
	/* Sample: one address per line, no comments, no date.  Export page:
	 * "All IP addresses that have attacked one of our customers/servers
	 * in the last 48 hours", generated every 30 minutes.  Terms
	 * (blocklist.de/en/terms.html): no licence, nothing on commercial
	 * use.  IPv6: the list carries IPv6 addresses (pfSense issue 16766,
	 * confirmed by its maintainer). */
	{
		.id             = "blocklist-de",
		.name           = N_("blocklist.de"),
		.category       = N_("Attackers"),
		.description    = N_("Addresses that attacked servers reporting "
		                     "to blocklist.de (fail2ban and similar) in "
		                     "the last 48 hours."),
		.url            = "https://lists.blocklist.de/lists/all.txt",
		.host           = "lists.blocklist.de",
		.info_url       = "https://www.blocklist.de/en/export.html",
		.terms_url      = "https://www.blocklist.de/en/terms.html",
		.license        = NULL,
		.noncommercial  = FALSE,
		.format         = FS_FEED_FMT_PLAIN,
		.default_dir    = FS_INTEL_DIR_IN,
		.interval_hours = 24,
		.recommended    = FALSE,
		.includes       = NULL,
		.has_v6         = TRUE,
		.credit         = "blocklist.de",
	},
	/* The file could not be read with the web tools (the site refuses
	 * robots); FireHOL's copy of it (et_compromised.ipset, source this
	 * URL) is IPv4 addresses, one per line.  The list's old
	 * documentation page redirects to the community site.  No licence
	 * is published with the list; the community thread on its licence
	 * is the terms link. */
	{
		.id             = "et-compromised",
		.name           = N_("Emerging Threats compromised hosts"),
		.category       = N_("Compromised hosts"),
		.description    = N_("Hosts that Emerging Threats has seen "
		                     "compromised and attacking others."),
		.url            = "https://rules.emergingthreats.net/blockrules/"
		                  "compromised-ips.txt",
		.host           = "rules.emergingthreats.net",
		.info_url       = "https://community.emergingthreats.net/",
		.terms_url      = "https://community.emergingthreats.net/t/"
		                  "licensing-is-the-compromised-ips-list-also-"
		                  "open/676",
		.license        = NULL,
		.noncommercial  = FALSE,
		.format         = FS_FEED_FMT_PLAIN,
		.default_dir    = FS_INTEL_DIR_IN,
		.interval_hours = 24,
		.recommended    = FALSE,
		.includes       = NULL,
		.has_v6         = FALSE,
		.credit         = "Emerging Threats, emergingthreats.net",
	},
	/* Sample: one IPv4 address per line, no comments, no date.  The
	 * home page: capped at 15,000 addresses, "a simple text file, with
	 * which you can parse and use in any way you see fit"; no licence
	 * named. */
	{
		.id             = "cins-army",
		.name           = N_("CINS Army"),
		.category       = N_("Attackers"),
		.description    = N_("Up to 15,000 addresses with the poorest "
		                     "reputation in the CINS threat intelligence "
		                     "network."),
		.url            = "https://cinsscore.com/list/ci-badguys.txt",
		.host           = "cinsscore.com",
		.info_url       = "https://cinsscore.com/",
		.terms_url      = "https://cinsscore.com/",
		.license        = NULL,
		.noncommercial  = FALSE,
		.format         = FS_FEED_FMT_PLAIN,
		.default_dir    = FS_INTEL_DIR_IN,
		.interval_hours = 24,
		.recommended    = FALSE,
		.includes       = NULL,
		.has_v6         = FALSE,
		.credit         = "CINS Army list, cinsscore.com",
	},
	/* The Tor Project's "Latest bulk exit list" (its exit-ops notes);
	 * the bulk exporter page names no licence or terms.  The exit
	 * scanner behind it does not support IPv6.  The file arrives as
	 * binary to the web tools, so its lines were not seen; it is read
	 * as plain, which takes bare addresses and skips comments. */
	{
		.id             = "tor-exits",
		.name           = N_("Tor exit relays"),
		.category       = N_("Anonymity network"),
		.description    = N_("The relays that Tor traffic leaves from; "
		                     "blocking them is a policy choice about Tor "
		                     "users, not protection from a threat."),
		.url            = "https://check.torproject.org/torbulkexitlist",
		.host           = "check.torproject.org",
		.info_url       = "https://check.torproject.org/api/bulk",
		.terms_url      = "https://check.torproject.org/api/bulk",
		.license        = NULL,
		.noncommercial  = FALSE,
		.format         = FS_FEED_FMT_PLAIN,
		.default_dir    = FS_INTEL_DIR_IN,
		.interval_hours = 6,
		.recommended    = FALSE,
		.includes       = NULL,
		.has_v6         = FALSE,
		.credit         = "The Tor Project, check.torproject.org",
	},
};

const FsFeedInfo *
fs_feed_catalog (guint *n)
{
	if (n != NULL)
		*n = G_N_ELEMENTS (CATALOG);
	return CATALOG;
}

const FsFeedInfo *
fs_feed_catalog_find (const gchar *id)
{
	for (guint i = 0; id != NULL && i < G_N_ELEMENTS (CATALOG); i++)
		if (strcmp (CATALOG[i].id, id) == 0)
			return &CATALOG[i];
	return NULL;
}

/* ============================================================= formats */

const gchar *
fs_feed_format_to_string (FsFeedFormat fmt)
{
	switch (fmt) {
	case FS_FEED_FMT_PLAIN:
		return "plain";
	case FS_FEED_FMT_SPAMHAUS_JSON:
		return "spamhaus-json";
	case FS_FEED_FMT_DSHIELD:
		return "dshield";
	}
	return NULL;
}

gboolean
fs_feed_format_from_string (const gchar *text, FsFeedFormat *fmt)
{
	static const FsFeedFormat all[] = {
		FS_FEED_FMT_PLAIN, FS_FEED_FMT_SPAMHAUS_JSON, FS_FEED_FMT_DSHIELD
	};

	for (guint i = 0; text != NULL && i < G_N_ELEMENTS (all); i++) {
		if (strcmp (text, fs_feed_format_to_string (all[i])) == 0) {
			if (fmt != NULL)
				*fmt = all[i];
			return TRUE;
		}
	}
	return FALSE;
}

/* ================================================================ u128 */

static gint
u128_cmp (FsU128 a, FsU128 b)
{
	if (a.hi != b.hi)
		return a.hi < b.hi ? -1 : 1;
	if (a.lo != b.lo)
		return a.lo < b.lo ? -1 : 1;
	return 0;
}

/* a + 1; the caller makes sure a is not the maximum. */
static FsU128
u128_inc (FsU128 a)
{
	a.lo++;
	if (a.lo == 0)
		a.hi++;
	return a;
}

/* a - 1; the caller makes sure a is not zero. */
static FsU128
u128_dec (FsU128 a)
{
	if (a.lo == 0)
		a.hi--;
	a.lo--;
	return a;
}

static FsU128
u128_sub (FsU128 a, FsU128 b)
{
	FsU128 r;

	r.lo = a.lo - b.lo;
	r.hi = a.hi - b.hi - (a.lo < b.lo ? 1 : 0);
	return r;
}

/* ============================================================= helpers */

/* 1614 -> "1,614", for counts in sentences people read.  Caller frees. */
static gchar *
grouped (guint64 v)
{
	gchar digits[24];
	GString *out = g_string_new (NULL);
	gsize n = (gsize) g_snprintf (digits, sizeof digits,
	                              "%" G_GUINT64_FORMAT, v);

	for (gsize i = 0; i < n; i++) {
		if (i > 0 && (n - i) % 3 == 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, digits[i]);
	}
	return g_string_free (out, FALSE);
}

static gboolean
has_ascii_letter (const gchar *s)
{
	for (; *s != '\0'; s++)
		if (g_ascii_isalpha (*s))
			return TRUE;
	return FALSE;
}

/* The n characters at s (the caller knows they are there) as a number;
 * -1 when one of them is not an ASCII digit. */
static gint
digits_at (const gchar *s, gsize n)
{
	gint v = 0;

	for (gsize i = 0; i < n; i++) {
		if (!g_ascii_isdigit (s[i]))
			return -1;
		v = v * 10 + (s[i] - '0');
	}
	return v;
}

/* ================================================================ dates */

/* Content dates outside 2000-2099 are a broken header (a timestamp in
 * milliseconds, a zeroed field), not a date: they would make every
 * later copy look like a rollback, or none. */
#define DATE_MIN G_GINT64_CONSTANT (946684800)    /* 2000-01-01 UTC */
#define DATE_MAX G_GINT64_CONSTANT (4102444800)   /* 2100-01-01 UTC */

/* Unix seconds of a UTC calendar time; 0 when it is not a real time. */
static gint64
utc_seconds (gint y, gint mo, gint d, gint h, gint mi, gint s)
{
	GDateTime *dt;
	gint64 t;

	if (y < 2000 || y > 2099)
		return 0;
	dt = g_date_time_new_utc (y, mo, d, h, mi, s);
	if (dt == NULL)
		return 0;
	t = g_date_time_to_unix (dt);
	g_date_time_unref (dt);
	return t;
}

/* "14:28:39" -> unix seconds of `y-mo-d' at that time, or 0. */
static gint64
at_time (gint y, gint mo, gint d, const gchar *time)
{
	gint h, mi, s;

	if (strlen (time) != 8 || time[2] != ':' || time[5] != ':')
		return 0;
	h = digits_at (time, 2);
	mi = digits_at (time + 3, 2);
	s = digits_at (time + 6, 2);
	if (y < 0 || mo < 0 || d < 0 || h < 0 || mi < 0 || s < 0)
		return 0;
	return utc_seconds (y, mo, d, h, mi, s);
}

/* "2026-03-04" and "14:28:39" -> unix seconds, or 0. */
static gint64
ymd_hms (const gchar *date, const gchar *time)
{
	if (strlen (date) != 10 || date[4] != '-' || date[7] != '-')
		return 0;
	return at_time (digits_at (date, 4), digits_at (date + 5, 2),
	                digits_at (date + 8, 2), time);
}

/* Splits s in place at ASCII whitespace.  Up to `max' words go to w;
 * returns how many words there were in all. */
static guint
split_words (gchar *s, gchar **w, guint max)
{
	guint n = 0;

	while (*s != '\0') {
		while (g_ascii_isspace (*s))
			s++;
		if (*s == '\0')
			break;
		if (n < max)
			w[n] = s;
		n++;
		while (*s != '\0' && !g_ascii_isspace (*s))
			s++;
		if (*s != '\0')
			*s++ = '\0';
	}
	return n;
}

/* FireHOL: "Sat Oct 24 04:49:13 UTC 2026" (date(1) output, in UTC). */
static gint64
date_firehol (gchar *value)
{
	static const gchar *const months[] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
	};
	gchar *w[6];
	gint mo = -1;
	gsize dlen;

	if (split_words (value, w, G_N_ELEMENTS (w)) != 6 ||
	    strcmp (w[4], "UTC") != 0 || strlen (w[5]) != 4)
		return 0;
	for (guint i = 0; i < G_N_ELEMENTS (months); i++)
		if (strcmp (w[1], months[i]) == 0)
			mo = (gint) i + 1;
	/* date(1) pads a one-digit day with a space, which split_words
	 * already took, so the day is one or two digits. */
	dlen = strlen (w[2]);
	if (dlen != 1 && dlen != 2)
		return 0;
	return at_time (digits_at (w[5], 4), mo, digits_at (w[2], dlen),
	                w[3]);
}

/* abuse.ch: "2026-03-04 14:28:39 UTC", where the line may go on to the
 * '#' that closes the header's box. */
static gint64
date_abusech (gchar *value)
{
	gchar *w[4];
	guint n = split_words (value, w, G_N_ELEMENTS (w));

	if (n == 4 && strcmp (w[3], "#") == 0)
		n = 3;
	if (n != 3 || strcmp (w[2], "UTC") != 0)
		return 0;
	return ymd_hms (w[0], w[1]);
}

/* DShield: "2026-11-02T12:45:39.735756".  The header gives no zone; it
 * is read as UTC, and the fraction of a second is dropped. */
static gint64
date_dshield (gchar *value)
{
	gchar *w[2];
	gchar *v, *p;

	if (split_words (value, w, G_N_ELEMENTS (w)) != 1)
		return 0;
	v = w[0];
	if (strlen (v) < 19 || v[10] != 'T')
		return 0;
	p = v + 19;
	if (*p == '.') {
		gsize k = strspn (p + 1, "0123456789");

		if (k == 0 || k > 9)
			return 0;
		p += 1 + k;
	}
	if (*p == 'Z')
		p++;
	if (*p != '\0')
		return 0;
	v[10] = '\0';
	v[19] = '\0';
	return ymd_hms (v, v + 11);
}

/* The value after "<key> :" in a '#' comment line ("# This File Date  :
 * Sat Oct 24 ..."), or NULL.  The key matches without regard to case. */
static gchar *
comment_value (gchar *comment, const gchar *key)
{
	gchar *s = comment;
	gsize k = strlen (key);

	while (*s == '#' || g_ascii_isspace (*s))
		s++;
	if (g_ascii_strncasecmp (s, key, k) != 0)
		return NULL;
	s += k;
	while (*s == ' ' || *s == '\t')
		s++;
	if (*s != ':')
		return NULL;
	s++;
	while (g_ascii_isspace (*s))
		s++;
	return s;
}

static gint64
clamp_date (gint64 t)
{
	return t >= DATE_MIN && t < DATE_MAX ? t : 0;
}

/* ============================================================== parser */

/* What one line of a feed turned out to be. */
typedef enum
{
	LINE_COMMENT,   /* blank, comment, header or metadata */
	LINE_INVALID,
	LINE_ENTRY
} LineKind;

typedef struct
{
	FsAddrFamily fam;
	FsRange4     r4;
	FsRange6     r6;
	gboolean     host_bits;
} Entry;

typedef struct
{
	FsFeedParseStats *st;
	FsRangeSet       *set;
	const FsRangeSet *prot;
	GArray           *pieces4;   /* scratch: one entry minus protected */
	GArray           *pieces6;
	gboolean          seen_data; /* CSV: a data line was read          */
} Parser;

/* One line, NUL-terminated and without its line end, in a buffer the
 * classifier may cut up. */
typedef LineKind (*Classify) (Parser *ps, gchar *line, Entry *e);

static LineKind
parse_entry (const gchar *text, Entry *e)
{
	e->fam = fs_range_parse (text, &e->r4, &e->r6, NULL, &e->host_bits);
	return e->fam == FS_AF_NONE ? LINE_INVALID : LINE_ENTRY;
}

/* The pieces of r that lie outside the protected ranges (sorted and
 * disjoint, so one pass); *hit says whether any part was protected. */
static void
pieces4 (const FsRange4 *r, const FsRangeSet *prot, GArray *out,
         gboolean *hit)
{
	guint32 cur = r->start;
	gboolean done = FALSE;   /* the rest of r is protected */

	*hit = FALSE;
	g_array_set_size (out, 0);
	for (guint k = 0; k < prot->v4->len; k++) {
		const FsRange4 *p = &g_array_index (prot->v4, FsRange4, k);

		if (p->end < cur)
			continue;
		if (p->start > r->end)
			break;
		*hit = TRUE;
		if (p->start > cur) {
			FsRange4 piece = { cur, p->start - 1 };

			g_array_append_val (out, piece);
		}
		if (p->end >= r->end) {
			done = TRUE;
			break;
		}
		cur = p->end + 1;   /* p->end < r->end: cannot wrap */
	}
	if (!done) {
		FsRange4 piece = { cur, r->end };

		g_array_append_val (out, piece);
	}
}

static void
pieces6 (const FsRange6 *r, const FsRangeSet *prot, GArray *out,
         gboolean *hit)
{
	FsU128 cur = r->start;
	gboolean done = FALSE;

	*hit = FALSE;
	g_array_set_size (out, 0);
	for (guint k = 0; k < prot->v6->len; k++) {
		const FsRange6 *p = &g_array_index (prot->v6, FsRange6, k);

		if (u128_cmp (p->end, cur) < 0)
			continue;
		if (u128_cmp (p->start, r->end) > 0)
			break;
		*hit = TRUE;
		if (u128_cmp (p->start, cur) > 0) {
			FsRange6 piece = { cur, u128_dec (p->start) };

			g_array_append_val (out, piece);
		}
		if (u128_cmp (p->end, r->end) >= 0) {
			done = TRUE;
			break;
		}
		cur = u128_inc (p->end);
	}
	if (!done) {
		FsRange6 piece = { cur, r->end };

		g_array_append_val (out, piece);
	}
}

/* The span floor [S1.1, S4]: every piece left of an entry is measured by
 * its size, never by a prefix length, so a mapped CIDR, an a-b range
 * and a plain CIDR of the same width are judged alike.  A /10 (2^22
 * addresses) is the widest IPv4 piece allowed. */
static gboolean
too_broad4 (const GArray *pieces)
{
	for (guint i = 0; i < pieces->len; i++)
		if (fs_range4_size (&g_array_index (pieces, FsRange4, i)) >
		    FS_FEED_MAX_SPAN4)
			return TRUE;
	return FALSE;
}

/* IPv6: a piece of size d + 1 is wider than 2^99 exactly when d is at
 * least 2^99, that is when the high half of d is 2^35 or more. */
static gboolean
too_broad6 (const GArray *pieces)
{
	for (guint i = 0; i < pieces->len; i++) {
		const FsRange6 *r = &g_array_index (pieces, FsRange6, i);
		FsU128 d = u128_sub (r->end, r->start);

		if ((d.hi >> (FS_FEED_MAX_SPAN6_LOG2 - 64)) != 0)
			return TRUE;
	}
	return FALSE;
}

/* One parsed entry through the guards.  FALSE (error set) when it is
 * one entry more than the list may have. */
static gboolean
take_entry (Parser *ps, const Entry *e, GError **error)
{
	FsFeedParseStats *st = ps->st;
	gboolean hit = FALSE, broad;

	/* The protected ranges come out first, and the floor is measured on
	 * what is left: FireHOL's 224.0.0.0/3 is all multicast and reserved
	 * space, so it loses nothing real and is not "too broad" [P7]. */
	if (e->fam == FS_AF_V4) {
		pieces4 (&e->r4, ps->prot, ps->pieces4, &hit);
		broad = too_broad4 (ps->pieces4);
	} else {
		pieces6 (&e->r6, ps->prot, ps->pieces6, &hit);
		broad = too_broad6 (ps->pieces6);
	}
	if (broad) {
		st->too_broad++;
		return TRUE;
	}

	if (st->entries >= FS_FEED_MAX_ENTRIES) {
		gchar *max = grouped (FS_FEED_MAX_ENTRIES);

		g_set_error (error, FS_FEED_ERROR, FS_FEED_ERR_TOO_MANY,
		             _("The list has more than %s entries; a list that "
		               "long is refused."), max);
		g_free (max);
		return FALSE;
	}
	st->entries++;
	if (hit)
		st->protected_hits++;
	if (e->host_bits)
		st->host_bits++;

	if (e->fam == FS_AF_V4)
		g_array_append_vals (ps->set->v4, ps->pieces4->data,
		                     ps->pieces4->len);
	else
		g_array_append_vals (ps->set->v6, ps->pieces6->data,
		                     ps->pieces6->len);
	return TRUE;
}

/* IPv6 coverage in /64 networks: an interval of d + 1 addresses counts
 * as ceil ((d + 1) / 2^64) = d.hi + 1 of them; saturating. */
guint64
fs_feed_cover6_64 (const FsRangeSet *set)
{
	guint64 total = 0;

	for (guint i = 0; i < set->v6->len; i++) {
		const FsRange6 *r = &g_array_index (set->v6, FsRange6, i);
		FsU128 d = u128_sub (r->end, r->start);
		guint64 n = d.hi == G_MAXUINT64 ? G_MAXUINT64 : d.hi + 1;

		if (total > G_MAXUINT64 - n)
			return G_MAXUINT64;
		total += n;
	}
	return total;
}

static void
note_invalid (FsFeedParseStats *st)
{
	st->invalid++;
	if (st->first_invalid == 0)
		st->first_invalid = st->lines;
}

/* The checks on the whole list, once every line is in.  The set is
 * normalized and the stats are complete, so a refusal can say why. */
static gboolean
judge_list (const FsFeedParseStats *st, GError **error)
{
	/* Mostly not addresses: an HTML error page, the wrong file.  This
	 * also covers "nothing parsed while lines were invalid". */
	if (st->invalid > st->entries) {
		g_set_error (error, FS_FEED_ERROR, FS_FEED_ERR_NOT_A_LIST,
		             _("This does not look like a blocklist: %u of %u "
		               "data lines are not addresses (the first is "
		               "line %u)."), st->invalid,
		             st->invalid + st->entries + st->too_broad,
		             st->first_invalid);
		return FALSE;
	}
	/* A poisoned list: as many entries too broad to block as entries
	 * kept.  The floor already dropped each of them, but a list that is
	 * mostly /8s is broken or hostile, not a blocklist with a few
	 * mistakes, and its other entries are not to be trusted either. */
	if (st->too_broad > 0 && st->too_broad >= st->entries) {
		g_set_error (error, FS_FEED_ERROR, FS_FEED_ERR_NOT_A_LIST,
		             _("%u entries are too broad to block (wider than "
		               "an IPv4 /10 or an IPv6 /29) and only %u could "
		               "be kept; the list looks broken or poisoned."),
		             st->too_broad, st->entries);
		return FALSE;
	}
	/* Coverage caps on the whole list [S1.2]: many entries just under
	 * the floor must not add up to a slice of the internet. */
	if (st->cover4 > FS_FEED_MAX_COVER4) {
		gchar *n = grouped (st->cover4);
		gchar *max = grouped (FS_FEED_MAX_COVER4);

		g_set_error (error, FS_FEED_ERROR, FS_FEED_ERR_COVERAGE,
		             _("The list covers %s IPv4 addresses; a list may "
		               "cover at most %s."), n, max);
		g_free (n);
		g_free (max);
		return FALSE;
	}
	if (st->cover6_64 > FS_FEED_MAX_COVER6_64) {
		gchar *n = grouped (st->cover6_64);
		gchar *max = grouped (FS_FEED_MAX_COVER6_64);

		g_set_error (error, FS_FEED_ERROR, FS_FEED_ERR_COVERAGE,
		             _("The list covers %s IPv6 /64 networks; a list "
		               "may cover at most %s."), n, max);
		g_free (n);
		g_free (max);
		return FALSE;
	}
	return TRUE;
}

static FsRangeSet *
parse_body (const gchar *data, gsize len, Classify classify,
            FsFeedParseStats *stats, GError **error)
{
	FsFeedParseStats local;
	gchar line[FS_FEED_MAX_LINE + 1];
	const gchar *p, *end;
	Parser ps;
	gboolean ok = TRUE;

	if (stats == NULL)
		stats = &local;
	memset (stats, 0, sizeof *stats);
	if (data == NULL) {
		data = "";
		len = 0;
	}

	/* Size first: a runaway body is refused before a byte of it is
	 * looked at. */
	if (len > FS_FEED_MAX_BYTES) {
		gchar *n = grouped (len);

		g_set_error (error, FS_FEED_ERROR, FS_FEED_ERR_TOO_LARGE,
		             _("The list is %s bytes; a list may be at most "
		               "32 MiB."), n);
		g_free (n);
		return NULL;
	}
	/* A NUL byte means binary data (or a caller that counted the C
	 * terminator): not a text list.  Without one, every line below is
	 * safely a C string. */
	{
		const gchar *nul = memchr (data, '\0', len);

		if (nul != NULL) {
			g_set_error (error, FS_FEED_ERROR, FS_FEED_ERR_TOO_LARGE,
			             _("The list holds a NUL byte (at offset "
			               "%" G_GSIZE_FORMAT "); it is not a text "
			               "list."), (gsize) (nul - data));
			return NULL;
		}
	}

	memset (&ps, 0, sizeof ps);
	ps.st = stats;
	ps.set = fs_range_set_new ();
	ps.prot = fs_range_protected ();
	ps.pieces4 = g_array_new (FALSE, FALSE, sizeof (FsRange4));
	ps.pieces6 = g_array_new (FALSE, FALSE, sizeof (FsRange6));

	p = data;
	end = data + len;
	if (len >= 3 && memcmp (p, "\xEF\xBB\xBF", 3) == 0)
		p += 3;   /* a UTF-8 byte order mark */

	while (ok && p < end) {
		const gchar *nl = memchr (p, '\n', (gsize) (end - p));
		gsize n = nl != NULL ? (gsize) (nl - p) : (gsize) (end - p);
		Entry e;

		stats->lines++;
		if (n > 0 && p[n - 1] == '\r')
			n--;   /* CRLF */

		if (n > FS_FEED_MAX_LINE) {
			note_invalid (stats);
		} else {
			memcpy (line, p, n);
			line[n] = '\0';
			switch (classify (&ps, line, &e)) {
			case LINE_COMMENT:
				stats->comments++;
				break;
			case LINE_INVALID:
				note_invalid (stats);
				break;
			case LINE_ENTRY:
				ok = take_entry (&ps, &e, error);
				break;
			}
		}
		p = nl != NULL ? nl + 1 : end;
	}

	g_array_unref (ps.pieces4);
	g_array_unref (ps.pieces6);

	if (ok) {
		/* The pieces are already outside the protected ranges, and
		 * merging cannot bring any of that space back. */
		fs_range_set_normalize (ps.set);
		stats->v4 = fs_range_set_count4 (ps.set);
		stats->v6 = fs_range_set_count6 (ps.set);
		stats->cover4 = fs_range_set_addresses4 (ps.set);
		stats->cover6_64 = fs_feed_cover6_64 (ps.set);
		ok = judge_list (stats, error);
	}
	if (!ok) {
		fs_range_set_free (ps.set);
		return NULL;
	}
	return ps.set;
}

/* ---- plain -------------------------------------------------------- */

static LineKind
classify_plain (Parser *ps, gchar *line, Entry *e)
{
	gchar *s = line;

	while (g_ascii_isspace (*s))
		s++;
	if (*s == '\0')
		return LINE_COMMENT;
	if (*s == '#' || *s == ';') {
		gchar *v;
		gint64 t = 0;

		if (*s == '#' && ps->st->content_date == 0) {
			if ((v = comment_value (s, "This File Date")) != NULL)
				t = date_firehol (v);         /* FireHOL  */
			else if ((v = comment_value (s, "Last updated")) != NULL)
				t = date_abusech (v);         /* abuse.ch */
			ps->st->content_date = clamp_date (t);
		}
		return LINE_COMMENT;
	}
	/* The entry is the first word; a comment may follow it. */
	s[strcspn (s, " \t\v\f;,#")] = '\0';
	return parse_entry (s, e);
}

/* ---- dshield ------------------------------------------------------ */

static LineKind
classify_dshield (Parser *ps, gchar *line, Entry *e)
{
	gchar *s = line, *tab, *first, *second;
	guint32 s4 = 0, e4 = 0;
	FsU128 s6 = { 0, 0 }, e6 = { 0, 0 };
	FsAddrFamily fam_s, fam_e;

	while (g_ascii_isspace (*s))
		s++;
	if (*s == '\0')
		return LINE_COMMENT;
	if (*s == '#') {
		gchar *v;

		if (ps->st->content_date == 0 &&
		    (v = comment_value (s, "updated")) != NULL)
			ps->st->content_date = clamp_date (date_dshield (v));
		return LINE_COMMENT;
	}

	/* start<TAB>end<TAB>prefix<TAB>... */
	tab = strchr (s, '\t');
	if (tab != NULL)
		*tab = '\0';
	first = g_strstrip (s);
	if (g_ascii_strcasecmp (first, "Start") == 0)
		return LINE_COMMENT;   /* the column header row */
	if (tab == NULL)
		return LINE_INVALID;
	second = tab + 1;
	tab = strchr (second, '\t');
	if (tab != NULL)
		*tab = '\0';
	second = g_strstrip (second);

	fam_s = fs_addr_parse (first, &s4, &s6);
	fam_e = fs_addr_parse (second, &e4, &e6);
	if (fam_s == FS_AF_NONE || fam_s != fam_e)
		return LINE_INVALID;
	e->fam = fam_s;
	e->host_bits = FALSE;
	if (fam_s == FS_AF_V4) {
		if (s4 > e4)
			return LINE_INVALID;
		e->r4.start = s4;
		e->r4.end = e4;
	} else {
		if (u128_cmp (s6, e6) > 0)
			return LINE_INVALID;
		e->r6.start = s6;
		e->r6.end = e6;
	}
	return LINE_ENTRY;
}

/* ---- spamhaus-json ------------------------------------------------ *
 * A small, strict reader for one NDJSON line: exactly one object, any
 * valid JSON inside it, and four top-level keys picked out.  There is
 * no JSON parser in GLib, and the format needs no more than this. */

#define JSON_MAX_DEPTH 16

typedef struct
{
	const gchar *p;
	const gchar *end;
} Json;

typedef struct
{
	gchar    cidr[128];
	gboolean has_cidr;      /* "cidr" with a string value that fit    */
	gboolean bad_cidr;      /* "cidr" with any other value            */
	gboolean metadata;      /* "type":"metadata"                      */
	gboolean has_ts, has_records;
	guint64  ts, records;
	gboolean dup;           /* one of the four keys twice             */
	guint    seen;          /* bit per key, for dup                   */
} JsonLine;

static void
json_ws (Json *j)
{
	while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' ||
	                         *j->p == '\r' || *j->p == '\n'))
		j->p++;
}

static gboolean
json_hex4 (Json *j, guint *out)
{
	guint v = 0;

	if (j->end - j->p < 4)
		return FALSE;
	for (guint i = 0; i < 4; i++) {
		gint x = g_ascii_xdigit_value (j->p[i]);

		if (x < 0)
			return FALSE;
		v = (v << 4) | (guint) x;
	}
	j->p += 4;
	*out = v;
	return TRUE;
}

/* A string; its decoded bytes go to out (up to cap - 1, then NUL) when
 * out is not NULL, and *fits says whether all of them did.  \u0000 is
 * refused: a value with a NUL inside would read as a shorter one. */
static gboolean
json_string (Json *j, gchar *out, gsize cap, gboolean *fits)
{
	gsize n = 0;

	if (fits != NULL)
		*fits = TRUE;
	if (j->p >= j->end || *j->p != '"')
		return FALSE;
	j->p++;
	while (j->p < j->end) {
		guchar c = (guchar) *j->p++;
		gchar enc[6];
		gint m = 1;

		if (c == '"') {
			if (out != NULL)
				out[n] = '\0';
			return TRUE;
		}
		if (c < 0x20)
			return FALSE;   /* raw control characters are not JSON */
		enc[0] = (gchar) c;
		if (c == '\\') {
			guint cp;

			if (j->p >= j->end)
				return FALSE;
			c = (guchar) *j->p++;
			switch (c) {
			case '"': case '\\': case '/':
				enc[0] = (gchar) c;
				break;
			case 'b': enc[0] = '\b'; break;
			case 'f': enc[0] = '\f'; break;
			case 'n': enc[0] = '\n'; break;
			case 'r': enc[0] = '\r'; break;
			case 't': enc[0] = '\t'; break;
			case 'u':
				if (!json_hex4 (j, &cp) || cp == 0)
					return FALSE;
				if (cp >= 0xd800 && cp <= 0xdbff) {
					guint lo;

					if (j->end - j->p < 2 || j->p[0] != '\\' ||
					    j->p[1] != 'u')
						return FALSE;
					j->p += 2;
					if (!json_hex4 (j, &lo) ||
					    lo < 0xdc00 || lo > 0xdfff)
						return FALSE;
					cp = 0x10000 + ((cp - 0xd800) << 10) +
					     (lo - 0xdc00);
				} else if (cp >= 0xdc00 && cp <= 0xdfff) {
					return FALSE;   /* a lone low surrogate */
				}
				m = g_unichar_to_utf8 (cp, enc);
				break;
			default:
				return FALSE;
			}
		}
		if (out != NULL) {
			if (n + (gsize) m < cap) {
				memcpy (out + n, enc, (gsize) m);
				n += (gsize) m;
			} else if (fits != NULL) {
				*fits = FALSE;
			}
		}
	}
	return FALSE;   /* no closing quote */
}

/* A number.  *integer gets its value when it is a plain non-negative
 * integer that fits a guint64 (no sign, fraction or exponent). */
static gboolean
json_number (Json *j, guint64 *integer, gboolean *is_integer)
{
	gboolean plain = TRUE, overflow = FALSE;
	guint64 v = 0;

	if (j->p < j->end && *j->p == '-') {
		plain = FALSE;
		j->p++;
	}
	if (j->p >= j->end || !g_ascii_isdigit (*j->p))
		return FALSE;
	if (*j->p == '0') {
		j->p++;   /* no leading zeros: "01" fails at the caller */
	} else {
		while (j->p < j->end && g_ascii_isdigit (*j->p)) {
			guint d = (guint) (*j->p++ - '0');

			if (v > (G_MAXUINT64 - d) / 10)
				overflow = TRUE;
			else
				v = v * 10 + d;
		}
	}
	if (j->p < j->end && *j->p == '.') {
		plain = FALSE;
		j->p++;
		if (j->p >= j->end || !g_ascii_isdigit (*j->p))
			return FALSE;
		while (j->p < j->end && g_ascii_isdigit (*j->p))
			j->p++;
	}
	if (j->p < j->end && (*j->p == 'e' || *j->p == 'E')) {
		plain = FALSE;
		j->p++;
		if (j->p < j->end && (*j->p == '+' || *j->p == '-'))
			j->p++;
		if (j->p >= j->end || !g_ascii_isdigit (*j->p))
			return FALSE;
		while (j->p < j->end && g_ascii_isdigit (*j->p))
			j->p++;
	}
	*is_integer = plain && !overflow;
	*integer = v;
	return TRUE;
}

static gboolean
json_literal (Json *j, const gchar *word)
{
	gsize n = strlen (word);

	if ((gsize) (j->end - j->p) < n || memcmp (j->p, word, n) != 0)
		return FALSE;
	j->p += n;
	return TRUE;
}

static gboolean json_value (Json *j, guint depth);

/* An object or an array whose contents are only checked. */
static gboolean
json_container (Json *j, guint depth)
{
	gboolean object = *j->p == '{';
	gchar close = object ? '}' : ']';

	if (depth >= JSON_MAX_DEPTH)
		return FALSE;
	j->p++;
	json_ws (j);
	if (j->p < j->end && *j->p == close) {
		j->p++;
		return TRUE;
	}
	for (;;) {
		if (object) {
			if (!json_string (j, NULL, 0, NULL))
				return FALSE;
			json_ws (j);
			if (j->p >= j->end || *j->p != ':')
				return FALSE;
			j->p++;
			json_ws (j);
		}
		if (!json_value (j, depth + 1))
			return FALSE;
		json_ws (j);
		if (j->p >= j->end)
			return FALSE;
		if (*j->p == close) {
			j->p++;
			return TRUE;
		}
		if (*j->p != ',')
			return FALSE;
		j->p++;
		json_ws (j);
	}
}

static gboolean
json_value (Json *j, guint depth)
{
	guint64 v;
	gboolean is_int;

	if (j->p >= j->end)
		return FALSE;
	switch (*j->p) {
	case '"':
		return json_string (j, NULL, 0, NULL);
	case '{':
	case '[':
		return json_container (j, depth);
	case 't':
		return json_literal (j, "true");
	case 'f':
		return json_literal (j, "false");
	case 'n':
		return json_literal (j, "null");
	default:
		return json_number (j, &v, &is_int);
	}
}

/* Marks key number `bit' as seen; a second sighting is a duplicate,
 * which different JSON readers resolve differently, so it is refused. */
static void
json_seen (JsonLine *out, guint bit)
{
	if (out->seen & (1u << bit))
		out->dup = TRUE;
	out->seen |= 1u << bit;
}

/* The top-level object of one line, with "cidr", "type", "timestamp"
 * and "records" picked out.  FALSE when the line is not exactly one
 * JSON object. */
static gboolean
json_line (const gchar *text, JsonLine *out)
{
	Json j = { text, text + strlen (text) };

	memset (out, 0, sizeof *out);
	json_ws (&j);
	if (j.p >= j.end || *j.p != '{')
		return FALSE;
	j.p++;
	json_ws (&j);
	if (j.p < j.end && *j.p == '}') {
		j.p++;
	} else {
		for (;;) {
			gchar key[16];
			gboolean key_fits, fits, is_int;
			guint64 num;

			if (!json_string (&j, key, sizeof key, &key_fits))
				return FALSE;
			json_ws (&j);
			if (j.p >= j.end || *j.p != ':')
				return FALSE;
			j.p++;
			json_ws (&j);
			if (j.p >= j.end)
				return FALSE;

			if (key_fits && strcmp (key, "cidr") == 0) {
				json_seen (out, 0);
				if (*j.p == '"') {
					if (!json_string (&j, out->cidr,
					                  sizeof out->cidr, &fits))
						return FALSE;
					out->has_cidr = fits;
					out->bad_cidr = !fits;
				} else {
					if (!json_value (&j, 1))
						return FALSE;
					out->bad_cidr = TRUE;
				}
			} else if (key_fits && strcmp (key, "type") == 0) {
				gchar type[16];

				json_seen (out, 1);
				if (*j.p == '"') {
					if (!json_string (&j, type, sizeof type,
					                  &fits))
						return FALSE;
					out->metadata = fits &&
					                strcmp (type, "metadata") == 0;
				} else if (!json_value (&j, 1)) {
					return FALSE;
				}
			} else if (key_fits &&
			           (strcmp (key, "timestamp") == 0 ||
			            strcmp (key, "records") == 0)) {
				gboolean ts = key[0] == 't';

				json_seen (out, ts ? 2 : 3);
				if (*j.p == '-' || g_ascii_isdigit (*j.p)) {
					if (!json_number (&j, &num, &is_int))
						return FALSE;
					if (is_int && ts) {
						out->has_ts = TRUE;
						out->ts = num;
					} else if (is_int) {
						out->has_records = TRUE;
						out->records = num;
					}
				} else if (!json_value (&j, 1)) {
					return FALSE;
				}
			} else if (!json_value (&j, 1)) {
				return FALSE;
			}

			json_ws (&j);
			if (j.p >= j.end)
				return FALSE;
			if (*j.p == '}') {
				j.p++;
				break;
			}
			if (*j.p != ',')
				return FALSE;
			j.p++;
			json_ws (&j);
		}
	}
	json_ws (&j);
	return j.p == j.end;   /* nothing after the object */
}

static LineKind
classify_json (Parser *ps, gchar *line, Entry *e)
{
	JsonLine jl;
	const gchar *s = line;

	while (g_ascii_isspace (*s))
		s++;
	if (*s == '\0')
		return LINE_COMMENT;
	if (!json_line (s, &jl) || jl.dup)
		return LINE_INVALID;

	if (jl.has_cidr || jl.bad_cidr)
		return jl.has_cidr ? parse_entry (jl.cidr, e) : LINE_INVALID;

	if (jl.metadata) {
		/* The first metadata object gives the content date and the
		 * advertised count; the count is recorded, not enforced. */
		if (ps->st->content_date == 0 && jl.has_ts &&
		    jl.ts <= (guint64) G_MAXINT64)
			ps->st->content_date = clamp_date ((gint64) jl.ts);
		if (ps->st->meta_records == 0 && jl.has_records &&
		    jl.records <= G_MAXUINT)
			ps->st->meta_records = (guint) jl.records;
		return LINE_COMMENT;
	}
	/* An object that is neither an entry nor the metadata: an error
	 * document ({"error": ...}) must not read as an empty list. */
	return LINE_INVALID;
}

/* ---- CSV (a file the user imports) -------------------------------- *
 * The rules of fs_blocklist_parse_csv(): blank lines and lines starting
 * with '#' or ';' are comments; the first field is the address, quoted
 * or up to the first ',', ';', tab or space; a first data line that
 * does not parse and holds a letter is a header. */

static LineKind
classify_csv (Parser *ps, gchar *line, Entry *e)
{
	gchar *s = g_strstrip (line);
	gchar *field;
	LineKind kind;

	if (*s == '\0' || *s == '#' || *s == ';')
		return LINE_COMMENT;
	if (*s == '"') {
		gchar *close = strchr (s + 1, '"');

		field = s + 1;
		if (close != NULL)
			*close = '\0';
	} else {
		field = s;
		field[strcspn (field, ",; \t")] = '\0';
	}
	g_strstrip (field);

	kind = *field != '\0' ? parse_entry (field, e) : LINE_INVALID;
	if (kind == LINE_INVALID && !ps->seen_data && has_ascii_letter (field))
		kind = LINE_COMMENT;   /* "ip,comment", "address" */
	ps->seen_data = TRUE;
	return kind;
}

/* ---- entry points ------------------------------------------------- */

FsRangeSet *
fs_feed_parse (const gchar *data, gsize len, FsFeedFormat fmt,
               FsFeedParseStats *stats, GError **error)
{
	switch (fmt) {
	case FS_FEED_FMT_PLAIN:
		return parse_body (data, len, classify_plain, stats, error);
	case FS_FEED_FMT_SPAMHAUS_JSON:
		return parse_body (data, len, classify_json, stats, error);
	case FS_FEED_FMT_DSHIELD:
		return parse_body (data, len, classify_dshield, stats, error);
	}
	if (stats != NULL)
		memset (stats, 0, sizeof *stats);
	g_set_error (error, FS_FEED_ERROR, FS_FEED_ERR_NOT_A_LIST,
	             _("Unknown list format."));
	return NULL;
}

FsRangeSet *
fs_feed_parse_csv (const gchar *data, gsize len, FsFeedParseStats *stats,
                   GError **error)
{
	return parse_body (data, len, classify_csv, stats, error);
}

/* ============================================================ URL rule */

#define URL_MAX 2048u

static gboolean
url_refuse (GError **error, const gchar *why)
{
	g_set_error_literal (error, FS_FEED_ERROR, FS_FEED_ERR_URL, why);
	return FALSE;
}

/* host[:port] as the URL rule wants it: a DNS name (letters, digits,
 * '-', '.', '_') or a bracketed IPv6 literal, then an optional port of
 * 1-65535.  Anything else may be read differently by curl than by us. */
static gboolean
authority_ok (const gchar *a, gsize n, GError **error)
{
	gsize i = 0;

	if (n == 0)
		return url_refuse (error, _("The URL has no host."));
	if (a[0] == '[') {
		for (i = 1; i < n && a[i] != ']'; i++)
			if (!g_ascii_isxdigit (a[i]) && a[i] != ':' &&
			    a[i] != '.')
				return url_refuse (error, _("The URL's host is "
				                   "not a valid address."));
		if (i >= n || i == 1)
			return url_refuse (error, _("The URL's host is not a "
			                   "valid address."));
		i++;   /* past ']' */
	} else {
		for (; i < n && a[i] != ':'; i++)
			if (!g_ascii_isalnum (a[i]) && a[i] != '-' &&
			    a[i] != '.' && a[i] != '_')
				return url_refuse (error, _("The URL's host may "
				                   "hold only letters, digits, '-', "
				                   "'.' and '_'."));
		if (i == 0)
			return url_refuse (error, _("The URL has no host."));
	}
	if (i < n) {
		guint port = 0;
		gsize digits = n - i - 1;

		if (a[i] != ':' || digits == 0 || digits > 5)
			return url_refuse (error, _("The URL's port is not a "
			                   "number from 1 to 65535."));
		for (gsize k = i + 1; k < n; k++) {
			if (!g_ascii_isdigit (a[k]))
				return url_refuse (error, _("The URL's port is "
				                   "not a number from 1 to 65535."));
			port = port * 10 + (guint) (a[k] - '0');
		}
		if (port == 0 || port > 65535)
			return url_refuse (error, _("The URL's port is not a "
			                   "number from 1 to 65535."));
	}
	return TRUE;
}

gboolean
fs_feed_url_is_acceptable (const gchar *url, GError **error)
{
	const gchar *auth;
	gsize n, auth_len;

	if (url == NULL || *url == '\0')
		return url_refuse (error, _("The URL is empty."));
	/* It ends up as an argument to curl; never let it look like an
	 * option, even behind --url. */
	if (url[0] == '-')
		return url_refuse (error, _("A URL may not start with '-'."));
	n = strlen (url);
	if (n > URL_MAX)
		return url_refuse (error, _("The URL is longer than 2,048 "
		                   "bytes."));
	for (gsize i = 0; i < n; i++)
		if ((guchar) url[i] <= 0x20 || (guchar) url[i] >= 0x7f)
			return url_refuse (error, _("A URL may hold only "
			                   "printable ASCII characters, without "
			                   "spaces."));
	if (g_ascii_strncasecmp (url, "https://", 8) != 0)
		return url_refuse (error, _("Only https:// URLs are accepted."));

	auth = url + 8;
	auth_len = strcspn (auth, "/?#");
	/* user:password@host: a secret in the one string every surface
	 * shows, and the classic way to disguise the real host. */
	if (memchr (auth, '@', auth_len) != NULL)
		return url_refuse (error, _("A URL may not carry a user name "
		                   "or password (user@host)."));
	return authority_ok (auth, auth_len, error);
}

gchar *
fs_feed_url_redacted (const gchar *url)
{
	const gchar *auth, *sep, *rest, *at = NULL;
	gsize auth_len;
	GString *out;

	if (url == NULL)
		return NULL;

	sep = strstr (url, "://");
	auth = sep != NULL ? sep + 3 : url;
	auth_len = strcspn (auth, "/?#");
	for (gsize i = 0; i < auth_len; i++)
		if (auth[i] == '@')
			at = auth + i;   /* the last one ends the user part */

	out = g_string_new (NULL);
	g_string_append_len (out, url, auth - url);
	if (at != NULL) {
		/* Refused by the URL rule, but a refusal message may still
		 * show the URL: keep the password out of it. */
		g_string_append (out, "\xE2\x80\xA6@");
		g_string_append_len (out, at + 1, auth + auth_len - (at + 1));
	} else {
		g_string_append_len (out, auth, auth_len);
	}

	/* The query string starts at the first '?' before any '#'; a key
	 * for a paid feed lives there [S18].  The fragment after it stays:
	 * it is never sent to the server, so it cannot carry a key. */
	rest = auth + auth_len;
	sep = rest + strcspn (rest, "?#");
	if (*sep == '?') {
		g_string_append_len (out, rest, sep - rest);
		g_string_append (out, "?\xE2\x80\xA6");
		g_string_append (out, sep + strcspn (sep, "#"));
	} else {
		g_string_append (out, rest);
	}
	return g_string_free (out, FALSE);
}

/* =============================================================== judge */

/* Below these, a list is too small for "a quarter of it" to mean
 * anything: 8 entries, 2^16 IPv4 addresses (design 4.5). */
#define SHRINK_MIN_ENTRIES 8u
#define SHRINK_MIN_COVER4  (G_GUINT64_CONSTANT (1) << 16)
/* Growth needs both: more than double, and more than a /10 more. */
#define GROW_MIN_ADDED     (G_GUINT64_CONSTANT (1) << 22)

static gchar *
date_text (gint64 t)
{
	GDateTime *dt = g_date_time_new_from_unix_utc (t);
	gchar *s;

	if (dt == NULL)
		return g_strdup ("?");
	/* To the second: two copies of a list can be minutes apart. */
	s = g_date_time_format (dt, "%Y-%m-%d %H:%M:%S UTC");
	g_date_time_unref (dt);
	return s;
}

static const gchar *
entries_word (guint64 n)
{
	return n == 1 ? _("entry") : _("entries");
}

/* now < max / 4 exactly, with no multiplication to overflow on a
 * history read back from a damaged state file. */
static gboolean
below_quarter (guint64 now, guint64 max)
{
	return now < max / 4 || (now == max / 4 && max % 4 != 0);
}

/* The shrink rule for one copy against the largest before it. */
static gboolean
shrank (guint64 entries, guint64 cover4, guint64 max_entries,
        guint64 max_cover4)
{
	return (max_entries >= SHRINK_MIN_ENTRIES &&
	        below_quarter (entries, max_entries)) ||
	       (max_cover4 >= SHRINK_MIN_COVER4 &&
	        below_quarter (cover4, max_cover4));
}
FsFeedVerdict
fs_feed_judge (const FsFeedParseStats *now, const FsFeedHistory *history,
               guint flags, gchar **why)
{
	gboolean shrink_ok = (flags & FS_FEED_ACCEPT_SHRINK) != 0;
	gboolean cover_ok = (flags & FS_FEED_ACCEPT_COVERAGE) != 0;
	guint n, base_entries = 0;
	guint64 max_cover4 = 0, base_cover4 = 0;
	gchar *a, *b;

	if (why != NULL)
		*why = NULL;
	/* Refusing is the safe answer to a caller with nothing to judge. */
	g_return_val_if_fail (now != NULL, FS_FEED_VERDICT_EMPTY);

	n = history != NULL ? MIN (history->n, FS_FEED_HISTORY) : 0;
	if (n == 0)
		return FS_FEED_VERDICT_OK;
	for (guint i = 0; i < n; i++)
		max_cover4 = MAX (max_cover4, history->cover4[i]);

	/* The shrink baseline, oldest copy first.  A copy that was itself
	 * below a quarter of the baseline before it can only have been let
	 * in by an accepted shrink: the user said that size is right, so
	 * the baseline starts again from it.  Without this, one accepted
	 * shrink would be refused again on each of the next six updates.
	 * A walk down a quarter at a time never resets it [S15.1]. */
	for (guint j = n; j-- > 0;) {
		if (shrank (history->entries[j], history->cover4[j],
		            base_entries, base_cover4)) {
			base_entries = history->entries[j];
			base_cover4 = history->cover4[j];
		} else {
			base_entries = MAX (base_entries, history->entries[j]);
			base_cover4 = MAX (base_cover4, history->cover4[j]);
		}
	}

	/* A list that blocks nothing replaces one that blocked something
	 * only on request: a broken export must not turn into "block
	 * nothing" [S15.3].  The copy in use blocked something when it
	 * covered IPv4 addresses or had more entries than this one; an
	 * unchanged list of protected space only (it blocked nothing
	 * either) is not refused on every update. */
	if (!shrink_ok && now->v4 == 0 && now->v6 == 0 &&
	    history->entries[0] > 0 &&
	    (now->entries < history->entries[0] || history->cover4[0] > 0)) {
		if (why != NULL) {
			a = grouped (history->entries[0]);
			*why = g_strdup_printf (_("The new copy blocks no address; "
			                          "the copy in use has %s %s."), a,
			                        entries_word (history->entries[0]));
			g_free (a);
		}
		return FS_FEED_VERDICT_EMPTY;
	}

	/* Content older than the copy we have: a replayed list [S12.4].
	 * Without a date on both sides there is nothing to compare. */
	if (!shrink_ok && now->content_date != 0 &&
	    history->content_date != 0 &&
	    now->content_date < history->content_date) {
		if (why != NULL) {
			a = date_text (now->content_date);
			b = date_text (history->content_date);
			*why = g_strdup_printf (_("The new copy is dated %s, older "
			                          "than the copy in use (%s)."),
			                        a, b);
			g_free (a);
			g_free (b);
		}
		return FS_FEED_VERDICT_ROLLBACK;
	}

	/* Against the largest of the recent copies (since the last accepted
	 * shrink), so the list cannot be walked down a quarter at a time
	 * [S15.1]. */
	if (!shrink_ok && base_entries >= SHRINK_MIN_ENTRIES &&
	    below_quarter (now->entries, base_entries)) {
		if (why != NULL) {
			a = grouped (now->entries);
			b = grouped (base_entries);
			*why = g_strdup_printf (_("The new copy has %s %s; recent "
			                          "copies had up to %s."), a,
			                        entries_word (now->entries), b);
			g_free (a);
			g_free (b);
		}
		return FS_FEED_VERDICT_SHRANK;
	}
	if (!shrink_ok && base_cover4 >= SHRINK_MIN_COVER4 &&
	    below_quarter (now->cover4, base_cover4)) {
		if (why != NULL) {
			a = grouped (now->cover4);
			b = grouped (base_cover4);
			*why = g_strdup_printf (_("The new copy covers %s IPv4 "
			                          "addresses; recent copies "
			                          "covered up to %s."), a, b);
			g_free (a);
			g_free (b);
		}
		return FS_FEED_VERDICT_SHRANK;
	}

	/* Sudden growth: a list that suddenly blocks far more than it ever
	 * did [S1.3].  Both conditions, so a small list may still double
	 * and a large one may still grow by a few networks. */
	if (!cover_ok && now->cover4 > max_cover4 &&
	    now->cover4 - max_cover4 > max_cover4 &&
	    now->cover4 - max_cover4 > GROW_MIN_ADDED) {
		if (why != NULL) {
			a = grouped (now->cover4);
			b = grouped (max_cover4);
			*why = g_strdup_printf (_("The new copy covers %s IPv4 "
			                          "addresses, more than twice the "
			                          "%s of recent copies."), a, b);
			g_free (a);
			g_free (b);
		}
		return FS_FEED_VERDICT_GREW;
	}
	return FS_FEED_VERDICT_OK;
}

void
fs_feed_history_push (FsFeedHistory *history,
                      const FsFeedParseStats *accepted)
{
	guint keep;

	g_return_if_fail (history != NULL && accepted != NULL);

	keep = MIN (history->n, FS_FEED_HISTORY - 1);
	memmove (&history->entries[1], &history->entries[0],
	         keep * sizeof history->entries[0]);
	memmove (&history->cover4[1], &history->cover4[0],
	         keep * sizeof history->cover4[0]);
	history->entries[0] = accepted->entries;
	history->cover4[0] = accepted->cover4;
	/* The newest copy's date, even 0: after an accepted override the
	 * next copy is compared with what is now in use. */
	history->content_date = accepted->content_date;
	history->n = keep + 1;
}
