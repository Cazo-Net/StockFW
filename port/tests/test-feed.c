/*---[ test-feed.c ]-----------------------------------------------------
 * Threat-intel feeds (fs-feed): the catalog, the three formats with
 * fixtures modelled on the publishers' real files (headers verbatim,
 * entries mostly moved to documentation ranges), every parse guard of
 * design 4.3 against hostile input, CSV import, the URL rule and its
 * redaction, and every verdict of the update judge.  Pure: GLib only;
 * no root, no network.  IPv6 is checked as parsed values only.
 * The bugs these checks are proven to catch: tests/README.md.
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <string.h>

#include "core/fs-feed.h"
#include "core/fs-iprange.h"
#include "core/fs-nftset.h"   /* fs_blocklist_parse_csv, for CSV parity */

static guint failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (cond) {                                             \
		g_print ("ok:   " __VA_ARGS__);                 \
	} else {                                                \
		g_print ("FAIL: " __VA_ARGS__);                 \
		failures++;                                     \
	}                                                       \
	g_print ("\n");                                         \
} while (0)

#define POW2(n) (G_GUINT64_CONSTANT (1) << (n))

/* ============================================================ helpers */

static FsRangeSet *
parse_len (const gchar *text, gsize len, FsFeedFormat fmt,
           FsFeedParseStats *st, GError **err)
{
	return fs_feed_parse (text, len, fmt, st, err);
}

static FsRangeSet *
parse (const gchar *text, FsFeedFormat fmt, FsFeedParseStats *st,
       GError **err)
{
	return fs_feed_parse (text, strlen (text), fmt, st, err);
}

/* The text is refused with FS_FEED_ERROR / code; stats go to st. */
static gboolean
refused_as (const gchar *text, gsize len, FsFeedFormat fmt, gint code,
            FsFeedParseStats *st)
{
	GError *err = NULL;
	FsRangeSet *set = parse_len (text, len, fmt, st, &err);
	gboolean ok = set == NULL && g_error_matches (err, FS_FEED_ERROR, code);

	fs_range_set_free (set);
	g_clear_error (&err);
	return ok;
}

static gboolean
csv_refused_as (const gchar *text, gsize len, gint code,
                FsFeedParseStats *st)
{
	GError *err = NULL;
	FsRangeSet *set = fs_feed_parse_csv (text, len, st, &err);
	gboolean ok = set == NULL && g_error_matches (err, FS_FEED_ERROR, code);

	fs_range_set_free (set);
	g_clear_error (&err);
	return ok;
}

/* One sentence: not empty, ends in '.', one line. */
static gboolean
one_sentence (const gchar *s)
{
	gsize n = s != NULL ? strlen (s) : 0;

	return n > 1 && s[n - 1] == '.' && strchr (s, '\n') == NULL;
}

/* ============================================================ catalog */

/* ^[a-z0-9][a-z0-9-]{0,39}$ (design 6.2, fs_intel_id_is_valid), and the
 * catalog's own <= 32; restated so this test stands alone. */
static gboolean
id_ok (const gchar *id)
{
	gsize n = id != NULL ? strlen (id) : 0;

	if (n == 0 || n > 32)
		return FALSE;
	if (!g_ascii_islower (id[0]) && !g_ascii_isdigit (id[0]))
		return FALSE;
	for (gsize i = 1; i < n; i++)
		if (!g_ascii_islower (id[i]) && !g_ascii_isdigit (id[i]) &&
		    id[i] != '-')
			return FALSE;
	return TRUE;
}

/* The host of an https:// URL, as written. */
static gchar *
host_of (const gchar *url)
{
	const gchar *h = url + strlen ("https://");

	return g_strndup (h, strcspn (h, "/?#:"));
}

static void
test_catalog (void)
{
	static const struct {
		const gchar *id;
		FsFeedFormat fmt;
		FsIntelDir   dir;
		gboolean     recommended;
	} table[] = {
		/* design 4.1, in display order */
		{ "spamhaus-drop",   FS_FEED_FMT_SPAMHAUS_JSON, FS_INTEL_DIR_BOTH, TRUE  },
		{ "spamhaus-dropv6", FS_FEED_FMT_SPAMHAUS_JSON, FS_INTEL_DIR_BOTH, TRUE  },
		{ "feodo",           FS_FEED_FMT_PLAIN,         FS_INTEL_DIR_BOTH, TRUE  },
		{ "dshield",         FS_FEED_FMT_DSHIELD,       FS_INTEL_DIR_IN,   FALSE },
		{ "firehol-level1",  FS_FEED_FMT_PLAIN,         FS_INTEL_DIR_IN,   FALSE },
		{ "blocklist-de",    FS_FEED_FMT_PLAIN,         FS_INTEL_DIR_IN,   FALSE },
		{ "et-compromised",  FS_FEED_FMT_PLAIN,         FS_INTEL_DIR_IN,   FALSE },
		{ "cins-army",       FS_FEED_FMT_PLAIN,         FS_INTEL_DIR_IN,   FALSE },
		{ "tor-exits",       FS_FEED_FMT_PLAIN,         FS_INTEL_DIR_IN,   FALSE },
	};
	guint n = 0, recommended = 0;
	const FsFeedInfo *cat = fs_feed_catalog (&n);
	gboolean ids = TRUE, unique = TRUE, urls = TRUE, hosts = TRUE;
	gboolean pages = TRUE, words = TRUE, finds = TRUE, includes = TRUE;
	gboolean intervals = TRUE, licences = TRUE;
	const FsFeedInfo *dshield;

	CHECK (n == G_N_ELEMENTS (table), "the catalog has the design's %u "
	       "feeds (got %u)", (guint) G_N_ELEMENTS (table), n);
	if (n != G_N_ELEMENTS (table))
		return;

	for (guint i = 0; i < n; i++) {
		const FsFeedInfo *f = &cat[i];
		GError *err = NULL;
		gchar *host;

		CHECK (g_strcmp0 (f->id, table[i].id) == 0 &&
		       f->format == table[i].fmt &&
		       f->default_dir == table[i].dir &&
		       f->recommended == table[i].recommended,
		       "%s: in order, format %s, default direction and "
		       "recommended as in the design table", table[i].id,
		       fs_feed_format_to_string (table[i].fmt));

		ids = ids && id_ok (f->id);
		for (guint k = 0; k < i; k++)
			if (g_strcmp0 (cat[k].id, f->id) == 0 ||
			    g_strcmp0 (cat[k].url, f->url) == 0)
				unique = FALSE;
		if (!fs_feed_url_is_acceptable (f->url, &err)) {
			g_print ("      %s: %s\n", f->id,
			         err != NULL ? err->message : "no error set");
			urls = FALSE;
		}
		g_clear_error (&err);
		host = host_of (f->url);
		if (g_strcmp0 (host, f->host) != 0) {
			g_print ("      %s: host %s, URL host %s\n", f->id,
			         f->host, host);
			hosts = FALSE;
		}
		g_free (host);
		pages = pages && f->terms_url != NULL && f->info_url != NULL &&
		        fs_feed_url_is_acceptable (f->info_url, NULL) &&
		        fs_feed_url_is_acceptable (f->terms_url, NULL);
		words = words && f->name != NULL && *f->name != '\0' &&
		        f->category != NULL && *f->category != '\0' &&
		        f->description != NULL && *f->description != '\0';
		finds = finds && fs_feed_catalog_find (f->id) == f;
		intervals = intervals && f->interval_hours >= 1 &&
		            f->interval_hours <= 24 * 7;
		if (f->recommended)
			recommended++;

		if (f->includes != NULL) {
			gchar **ids_in = g_strsplit (f->includes, " ", -1);

			for (guint k = 0; ids_in[k] != NULL; k++)
				if (fs_feed_catalog_find (ids_in[k]) == NULL ||
				    strcmp (ids_in[k], f->id) == 0)
					includes = FALSE;
			g_strfreev (ids_in);
		}
		/* Verified on the publishers' own pages and files: abuse.ch
		 * terms of use s3.4 (CC0), DShield's block.txt header
		 * (CC BY-NC-SA 2.5).  Nobody else names a licence. */
		if (strcmp (f->id, "feodo") == 0)
			licences = licences && g_strcmp0 (f->license, "CC0") == 0;
		else if (strcmp (f->id, "dshield") == 0)
			licences = licences &&
			           g_strcmp0 (f->license, "CC BY-NC-SA 2.5") == 0;
		else
			licences = licences && f->license == NULL;
	}
	CHECK (ids, "every id is ^[a-z0-9][a-z0-9-]{0,39}$ and at most 32 "
	       "characters");
	CHECK (unique, "ids and URLs are unique");
	CHECK (urls, "every feed URL passes the URL rule");
	CHECK (hosts, "every host is the host of its URL");
	CHECK (pages, "every feed has an info page and a terms page, both "
	       "https");
	CHECK (words, "every feed has a name, a category and a description");
	CHECK (finds, "fs_feed_catalog_find finds every id");
	CHECK (fs_feed_catalog_find ("nope") == NULL &&
	       fs_feed_catalog_find (NULL) == NULL,
	       "an unknown id or NULL finds nothing");
	CHECK (includes, "includes names only other ids that exist");
	CHECK (g_strcmp0 (fs_feed_catalog_find ("firehol-level1")->includes,
	                  "spamhaus-drop feodo dshield") == 0,
	       "FireHOL level 1 includes Spamhaus DROP (IPv4), Feodo and "
	       "DShield, as its header says (IPv4 only: not DROPv6)");
	CHECK (intervals, "every interval is between 1 hour and a week");
	CHECK (recommended == 3, "exactly three feeds are recommended");
	CHECK (licences, "a licence only where the publisher states one "
	       "(Feodo CC0, DShield CC BY-NC-SA 2.5)");

	dshield = fs_feed_catalog_find ("dshield");
	CHECK (dshield != NULL && dshield->noncommercial && !dshield->recommended,
	       "DShield is flagged non-commercial and not recommended [P9]");
	CHECK (fs_feed_catalog_find ("spamhaus-drop")->interval_hours >= 24 &&
	       fs_feed_catalog_find ("spamhaus-dropv6")->interval_hours >= 24,
	       "Spamhaus DROP is fetched at most once a day, as its page asks");
	CHECK (fs_feed_catalog_find ("spamhaus-dropv6")->has_v6 &&
	       !fs_feed_catalog_find ("spamhaus-drop")->has_v6,
	       "DROPv6 publishes IPv6, DROP (IPv4) does not");
}

static void
test_format_names (void)
{
	FsFeedFormat f = 0;

	CHECK (g_strcmp0 (fs_feed_format_to_string (FS_FEED_FMT_PLAIN),
	                  "plain") == 0 &&
	       g_strcmp0 (fs_feed_format_to_string (FS_FEED_FMT_SPAMHAUS_JSON),
	                  "spamhaus-json") == 0 &&
	       g_strcmp0 (fs_feed_format_to_string (FS_FEED_FMT_DSHIELD),
	                  "dshield") == 0,
	       "format names: plain, spamhaus-json, dshield");
	CHECK (fs_feed_format_from_string ("plain", &f) &&
	       f == FS_FEED_FMT_PLAIN &&
	       fs_feed_format_from_string ("spamhaus-json", &f) &&
	       f == FS_FEED_FMT_SPAMHAUS_JSON &&
	       fs_feed_format_from_string ("dshield", &f) &&
	       f == FS_FEED_FMT_DSHIELD &&
	       fs_feed_format_from_string ("plain", NULL),
	       "format names parse back");
	CHECK (!fs_feed_format_from_string ("Plain", &f) &&
	       !fs_feed_format_from_string ("auto", &f) &&
	       !fs_feed_format_from_string ("plain ", &f) &&
	       !fs_feed_format_from_string ("", &f) &&
	       !fs_feed_format_from_string (NULL, &f),
	       "format names are exact: no case folding, no auto, no NULL");
	CHECK (fs_feed_format_to_string (0) == NULL &&
	       fs_feed_format_to_string (99) == NULL,
	       "an unknown format value has no name");
	CHECK (FS_FEED_ERROR != 0 &&
	       g_strcmp0 (g_quark_to_string (FS_FEED_ERROR),
	                  "stockfw-feed-error") == 0,
	       "the error domain is registered");
}

/* ============================================================ formats */

/* FireHOL's header, verbatim from firehol_level1.netset (2026-10-24);
 * the entries are its first lines, its protected aggregates and the
 * documentation ranges it really lists. */
static const gchar FIREHOL[] =
	"#\n"
	"# firehol_level1\n"
	"#\n"
	"# ipv4 hash:net ipset\n"
	"#\n"
	"# A firewall blacklist composed from IP lists, providing \n"
	"# maximum protection with minimum false positives. Suitable \n"
	"# for basic protection on all internet facing servers, \n"
	"# routers and firewalls. (includes: dshield feodo fullbogons \n"
	"# spamhaus_drop)\n"
	"#\n"
	"# Maintainer      : FireHOL\n"
	"# Maintainer URL  : http://iplists.firehol.org/\n"
	"# List source URL : \n"
	"# Source File Date: Sat Oct 24 04:29:57 UTC 2026\n"
	"#\n"
	"# Category        : attacks\n"
	"# Version         : 33045\n"
	"#\n"
	"# This File Date  : Sat Oct 24 04:49:13 UTC 2026\n"
	"# Update Frequency: 1 min \n"
	"# Aggregation     : none\n"
	"# Entries         : 3921 subnets, 611035265 unique IPs\n"
	"#\n"
	"# Full list analysis, including geolocation map, history,\n"
	"# retention policy, overlaps with other lists, etc.\n"
	"# available at:\n"
	"#\n"
	"#  http://iplists.firehol.org/?ipset=firehol_level1\n"
	"#\n"
	"# Generated by FireHOL's update-ipsets.sh\n"
	"# Processed with FireHOL's iprange\n"
	"#\n"
	"0.0.0.0/8\n"
	"1.10.16.0/20\n"
	"1.19.0.0/16\n"
	"1.32.128.0/18\n"
	"2.26.75.0/24\n"
	"10.0.0.0/8\n"
	"100.64.0.0/10\n"
	"127.0.0.0/8\n"
	"169.254.0.0/16\n"
	"172.16.0.0/12\n"
	"192.0.0.0/24\n"
	"192.0.2.0/24\n"
	"192.168.0.0/16\n"
	"198.18.0.0/15\n"
	"198.51.100.0/24\n"
	"203.0.113.0/24\n"
	"224.0.0.0/3\n";

/* Feodo Tracker's file, verbatim (2026-03-04) but for the address. */
static const gchar FEODO[] =
	"################################################################\n"
	"# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (recommended)  #\n"
	"# Last updated: 2026-03-04 14:28:39 UTC                        #\n"
	"#                                                              #\n"
	"# Terms Of Use: https://feodotracker.abuse.ch/blocklist/       #\n"
	"# For questions please contact feodotracker [at] abuse.ch      #\n"
	"################################################################\n"
	"#\n"
	"# DstIP\n"
	"198.51.100.211\n"
	"# END 1 entries\n";

static void
test_plain (void)
{
	FsFeedParseStats st;
	GError *err = NULL;
	FsRangeSet *set;

	set = parse (FIREHOL, FS_FEED_FMT_PLAIN, &st, &err);
	CHECK (set != NULL, "FireHOL level 1 parses (%s)",
	       err ? err->message : "no error");
	g_clear_error (&err);
	CHECK (st.content_date == 1792817353,
	       "FireHOL: the content date is \"This File Date\", Sat Oct 24 "
	       "04:49:13 UTC 2026, not the source date (got %" G_GINT64_FORMAT
	       ")", st.content_date);
	CHECK (st.entries == 17 && st.invalid == 0 && st.too_broad == 0 &&
	       st.comments == 33 && st.lines == 50,
	       "FireHOL: 17 entries, 33 comment lines, none invalid, none "
	       "too broad (entries %u comments %u invalid %u broad %u lines "
	       "%u)", st.entries, st.comments, st.invalid, st.too_broad,
	       st.lines);
	CHECK (st.protected_hits == 10,
	       "FireHOL: its 10 bogon and special-purpose entries are "
	       "protected space (got %u)", st.protected_hits);
	CHECK (st.cover4 == 87040 && st.v4 == 7 && st.v6 == 0,
	       "FireHOL: only the 7 real networks are left, 87,040 addresses "
	       "(got %u, %" G_GUINT64_FORMAT ")", st.v4, st.cover4);
	CHECK (set != NULL &&
	       fs_range_set_contains_text (set, "1.10.16.1") &&
	       fs_range_set_contains_text (set, "192.0.2.77") &&
	       !fs_range_set_contains_text (set, "10.1.2.3") &&
	       !fs_range_set_contains_text (set, "198.18.0.1") &&
	       !fs_range_set_contains_text (set, "192.0.0.9") &&
	       !fs_range_set_contains_text (set, "224.0.0.251") &&
	       !fs_range_set_contains_text (set, "255.255.255.255"),
	       "FireHOL: listed networks are in, protected space is out");
	fs_range_set_free (set);

	set = parse (FEODO, FS_FEED_FMT_PLAIN, &st, &err);
	CHECK (set != NULL && st.entries == 1 && st.comments == 10 &&
	       st.lines == 11 && st.invalid == 0 &&
	       fs_range_set_contains_text (set, "198.51.100.211"),
	       "Feodo Tracker: one address, ten comment lines");
	CHECK (st.content_date == 1772634519,
	       "Feodo Tracker: the content date is \"Last updated\", "
	       "2026-03-04 14:28:39 UTC, inside the '#' box (got %"
	       G_GINT64_FORMAT ")", st.content_date);
	fs_range_set_free (set);
	g_clear_error (&err);

	/* blocklist.de, CINS Army, ET, Tor: bare addresses, no header.
	 * blocklist.de carries IPv6 too. */
	set = parse ("198.51.100.7\n198.51.100.8\n203.0.113.9\n2001:db8::7\n"
	             "2001:db8:0:1::8\n", FS_FEED_FMT_PLAIN, &st, &err);
	CHECK (set != NULL && st.entries == 5 && st.v4 == 2 && st.v6 == 2 &&
	       st.content_date == 0 && st.cover6_64 == 2 &&
	       fs_range_set_contains_text (set, "2001:db8:0:1::8"),
	       "bare address lists, IPv4 and IPv6, parse without a date");
	fs_range_set_free (set);
	g_clear_error (&err);

	/* Anything after the first space, ';' or ',' is a comment; a '#'
	 * starts one too; a CIDR with host bits is kept, masked. */
	set = parse ("192.0.2.0/24 ; SBL123\n198.51.100.1,scanner\n"
	             "203.0.113.5 # note\n203.0.113.6#note\n"
	             "\t 203.0.113.7\t\n198.51.100.77/30\n; comment\n",
	             FS_FEED_FMT_PLAIN, &st, &err);
	CHECK (set != NULL && st.entries == 6 && st.invalid == 0 &&
	       st.comments == 1 && st.host_bits == 1 &&
	       fs_range_set_contains_text (set, "198.51.100.76") &&
	       !fs_range_set_contains_text (set, "198.51.100.80"),
	       "plain: trailing comments are ignored, host bits masked and "
	       "counted (entries %u invalid %u host bits %u)", st.entries,
	       st.invalid, st.host_bits);
	fs_range_set_free (set);
	g_clear_error (&err);

	/* A well-formed list with nothing in it is an empty set, not an
	 * error: the judge decides about it. */
	set = parse ("# END 0 entries\n", FS_FEED_FMT_PLAIN, &st, &err);
	CHECK (set != NULL && fs_range_set_is_empty (set) && err == NULL,
	       "a list of comments only is an empty set, not an error");
	fs_range_set_free (set);
	set = parse_len (NULL, 0, FS_FEED_FMT_PLAIN, NULL, &err);
	CHECK (set != NULL && fs_range_set_is_empty (set) && err == NULL,
	       "an empty body is an empty set (stats may be NULL)");
	fs_range_set_free (set);

	/* Dates that are not dates are ignored, never guessed. */
	set = parse ("# This File Date  : Sat Oct 24 04:49:13 CEST 2026\n"
	             "# Last updated: 1970-01-01 00:00:00 UTC\n192.0.2.1\n",
	             FS_FEED_FMT_PLAIN, &st, NULL);
	CHECK (set != NULL && st.content_date == 0,
	       "a date in another zone or before 2000 is no content date");
	fs_range_set_free (set);
	set = parse ("# This File Date  : Sat Oct  4 04:49:13 UTC 2026\n"
	             "192.0.2.1\n", FS_FEED_FMT_PLAIN, &st, NULL);
	CHECK (set != NULL && st.content_date == 1791089353,
	       "FireHOL: a one-digit day padded with a space reads "
	       "(got %" G_GINT64_FORMAT ")", st.content_date);
	fs_range_set_free (set);

	set = parse ("192.0.2.1\n", 0, &st, &err);
	CHECK (set == NULL && g_error_matches (err, FS_FEED_ERROR,
	                                       FS_FEED_ERR_NOT_A_LIST),
	       "an unknown format is an error, not a guess");
	g_clear_error (&err);
}

/* Spamhaus DROP, as drop_v4.json / drop_v6.json are on 2026-11-02:
 * entry objects, then the metadata object (verbatim). */
static const gchar DROP4[] =
	"{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL256894\",\"rir\":\"apnic\"}\n"
	"{\"cidr\":\"1.19.0.0/16\",\"sblid\":\"SBL434604\",\"rir\":\"apnic\"}\n"
	"{\"cidr\":\"192.0.2.0/24\",\"sblid\":\"SBL000001\",\"rir\":\"ripencc\"}\n"
	"{\"type\":\"metadata\",\"timestamp\":1793468642,\"size\":5617,"
	"\"records\":3,\"copyright\":\"(c) 2026 The Spamhaus Project SLU\","
	"\"terms\":\"https://www.spamhaus.org/drop/terms/\"}\n";

static const gchar DROP6[] =
	"{\"cidr\":\"2001:678:254::/48\",\"sblid\":\"SBL697648\",\"rir\":\"ripencc\"}\n"
	"{\"cidr\":\"2001:db8:1::/48\",\"sblid\":\"SBL000002\",\"rir\":\"ripencc\"}\n"
	"{\"type\":\"metadata\",\"timestamp\":1793468642,\"size\":5617,"
	"\"records\":89,\"copyright\":\"(c) 2026 The Spamhaus Project SLU\","
	"\"terms\":\"https://www.spamhaus.org/drop/terms/\"}\n";

/* body = good entries + one hostile line: it must count invalid and
 * leave the rest alone. */
static void
expect_json_line_invalid (const gchar *line, const gchar *what)
{
	FsFeedParseStats st;
	gchar *body = g_strconcat (
		"{\"cidr\":\"192.0.2.0/24\"}\n{\"cidr\":\"198.51.100.0/24\"}\n",
		line, "\n", NULL);
	FsRangeSet *set = parse (body, FS_FEED_FMT_SPAMHAUS_JSON, &st, NULL);

	CHECK (set != NULL && st.entries == 2 && st.invalid == 1 &&
	       st.first_invalid == 3 && st.cover4 == 512,
	       "spamhaus-json: %s is an invalid line", what);
	fs_range_set_free (set);
	g_free (body);
}

static void
test_spamhaus (void)
{
	FsFeedParseStats st;
	GError *err = NULL;
	FsRangeSet *set;

	set = parse (DROP4, FS_FEED_FMT_SPAMHAUS_JSON, &st, &err);
	CHECK (set != NULL && st.entries == 3 && st.invalid == 0 &&
	       st.comments == 1 && st.cover4 == 4096 + 65536 + 256,
	       "Spamhaus DROP (IPv4): the cidr of each object, the metadata "
	       "is not an entry (%s)", err ? err->message : "no error");
	CHECK (st.content_date == 1793468642 && st.meta_records == 3,
	       "Spamhaus: the metadata gives the content date and the "
	       "advertised record count");
	fs_range_set_free (set);
	g_clear_error (&err);

	set = parse (DROP6, FS_FEED_FMT_SPAMHAUS_JSON, &st, &err);
	CHECK (set != NULL && st.v6 == 2 && st.v4 == 0 && st.entries == 2 &&
	       st.meta_records == 89 && st.cover6_64 == 2 * POW2 (16) &&
	       fs_range_set_contains_text (set, "2001:678:254:ffff::1"),
	       "Spamhaus DROPv6: IPv6 /48s, 2 x 65,536 /64s; \"records\" is "
	       "recorded, not enforced (89 against 2 here)");
	fs_range_set_free (set);
	g_clear_error (&err);

	/* Strict JSON, but all of JSON: escapes, nesting, spacing, CRLF. */
	set = parse (" { \"cidr\" : \"19\\u0032.0.2.0/24\" , \"x\" : "
	             "{\"a\":[1,-2.5e3,{\"b\":null}],\"c\":true} }\r\n"
	             "{\"sblid\":\"SBL1\",\"cidr\":\"198.51.100.0\\/24\"}\r\n",
	             FS_FEED_FMT_SPAMHAUS_JSON, &st, &err);
	CHECK (set != NULL && st.entries == 2 && st.invalid == 0 &&
	       fs_range_set_contains_text (set, "192.0.2.9"),
	       "spamhaus-json: escapes, nested values, spaces and CRLF read "
	       "as JSON");
	fs_range_set_free (set);
	g_clear_error (&err);

	expect_json_line_invalid ("{\"cidr\":\"203.0.113.0/24\"} x",
	                          "text after the object");
	expect_json_line_invalid ("{\"cidr\":\"203.0.113.0/24\","
	                          "\"cidr\":\"0.0.0.0/0\"}", "a duplicate key");
	expect_json_line_invalid ("{\"cidr\":203}", "a cidr that is a number");
	expect_json_line_invalid ("{\"cidr\":\"203.0.113.0/24\\u0000x\"}",
	                          "a cidr with \\u0000 inside");
	expect_json_line_invalid ("{\"cidr\":\" 203.0.113.0/24\"}",
	                          "a cidr with a space");
	expect_json_line_invalid ("{\"cidr\":\"203.0.113.0/24}",
	                          "an unterminated string");
	expect_json_line_invalid ("[{\"cidr\":\"203.0.113.0/24\"}]",
	                          "an array");
	expect_json_line_invalid ("{\"error\":\"rate limited\"}",
	                          "an object with neither cidr nor metadata");
	expect_json_line_invalid ("# comment", "a '#' comment");
	expect_json_line_invalid ("{\"cidr\":\"203.0.113.0/24\",}",
	                          "a trailing comma");
	expect_json_line_invalid ("{\"cidr\":\"203.0.113.0/24\","
	                          "\"n\":\"\\udc00\"}", "a lone low surrogate");
	expect_json_line_invalid ("{\"cidr\":\"203.0.113.0/24\","
	                          "\"n\":\"\\ud800x\"}",
	                          "a high surrogate with no low one");
	expect_json_line_invalid ("{\"cidr\":\"203.0.113.0/24\","
	                          "\"n\":\"a\tb\"}",
	                          "a raw tab inside a string");
	expect_json_line_invalid ("{\"cidr\":\"203.0.113.0/24\",\"n\":01}",
	                          "a number with a leading zero");
	expect_json_line_invalid ("{\"cidr\":\"203.0.113.0/24\",\"n\":"
	                          "[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]}",
	                          "nesting 16 deep below the line's object");

	/* 15 deep is still JSON this reader takes; a pair of surrogates is
	 * one character. */
	set = parse ("{\"cidr\":\"192.0.2.0/24\",\"n\":"
	             "[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]],"
	             "\"s\":\"\\ud83d\\ude00\"}\n",
	             FS_FEED_FMT_SPAMHAUS_JSON, &st, NULL);
	CHECK (set != NULL && st.entries == 1 && st.invalid == 0,
	       "spamhaus-json: nesting 15 deep and a surrogate pair are read");
	fs_range_set_free (set);

	CHECK (refused_as ("{\"error\":\"Too many requests\"}\n",
	                   strlen ("{\"error\":\"Too many requests\"}\n"),
	                   FS_FEED_FMT_SPAMHAUS_JSON, FS_FEED_ERR_NOT_A_LIST,
	                   &st),
	       "spamhaus-json: an error document is not an empty list");

	set = parse ("{\"cidr\":\"192.0.2.0/24\"}\n{\"type\":\"metadata\","
	             "\"timestamp\":1793468642000,\"records\":1}\n",
	             FS_FEED_FMT_SPAMHAUS_JSON, &st, NULL);
	CHECK (set != NULL && st.content_date == 0 && st.meta_records == 1,
	       "spamhaus-json: a timestamp in milliseconds is no date");
	fs_range_set_free (set);
}

/* DShield's block.txt, header verbatim (2026-11-02, tabs and all), with
 * the old "Start" column row and documentation networks. */
static const gchar DSHIELD[] =
	"#\n"
	"#   DShield.org Recommended Block List \n"
	"#    (c) $year DShield.org\n"
	"#   some rights reserved. Details http://creativecommons.org/licenses/by-nc-sa/2.5/\n"
	"#   use on your own risk. No warranties implied.\n"
	"#   primary URL: https://feeds.dshield.org/block.txt\n"
	"#     PGP Sign.: https://feeds.dshield.org/block.txt.asc\n"
	"#\n"
	"#   comments: systems@isc.sans.edu\n"
	"#    updated: 2026-11-02T12:45:39.735756\n"
	"#   \n"
	"#    This list summarizes the top 20 attacking class C (/24) subnets\n"
	"#   over the last three days. The number of 'attacks' indicates the \n"
	"#   number of targets reporting scans from this subnet.\n"
	"#\n"
	"#\n"
	"#    Columns (tab delimited):\n"
	"#\n"
	"#    (1) start of netblock  \n"
	"#    (2) end of netblock\n"
	"#    (3) subnet (/24 for class C)\n"
	"#    (4) number of targets scanned\n"
	"#    (5) name of Network \n"
	"#    (6) Country\n"
	"#    (7) contact email address\n"
	"#\n"
	"#    If a range is assigned to multiple users, the first one is listed. \n"
	"#     \n"
	"Start\tEnd\tNetblock\tAttacks\tName\tCountry\temail\n"
	"192.0.2.0\t192.0.2.255\t24\t341\tHURRICANE\tUS\tabuse@he.net\n"
	"198.51.100.0\t198.51.100.255\t24\t337\tGOOGLE-CLOUD-PLATFORM\tUS\tNone\n"
	"203.0.113.0\t203.0.113.255\t24\t315\t-\t-\t-\n";

static void
test_dshield (void)
{
	FsFeedParseStats st;
	GError *err = NULL;
	FsRangeSet *set;
	gchar *crlf;

	set = parse (DSHIELD, FS_FEED_FMT_DSHIELD, &st, &err);
	CHECK (set != NULL && st.entries == 3 && st.invalid == 0 &&
	       st.comments == 29 && st.cover4 == 768 && st.v4 == 3,
	       "DShield: three start-end rows, the Start row is a header "
	       "(entries %u comments %u invalid %u) %s", st.entries,
	       st.comments, st.invalid, err ? err->message : "");
	CHECK (st.content_date == 1793623539,
	       "DShield: the content date is \"updated:\", "
	       "2026-11-02T12:45:39 read as UTC (got %" G_GINT64_FORMAT ")",
	       st.content_date);
	fs_range_set_free (set);
	g_clear_error (&err);

	/* Today's file has no Start row, and CRLF must not matter. */
	crlf = g_strjoinv ("\r\n", (gchar *[]) {
		"#    updated: 2026-11-02T12:45:39.735756",
		"192.0.2.0\t192.0.2.255\t24\t341\tHURRICANE\tUS\tabuse@he.net",
		"2001:db8::\t2001:db8::ffff\t112\t3\tX\tZZ\t-",
		"", NULL });
	set = parse (crlf, FS_FEED_FMT_DSHIELD, &st, &err);
	CHECK (set != NULL && st.entries == 2 && st.v6 == 1 &&
	       st.content_date == 1793623539,
	       "DShield: without the Start row, with CRLF, IPv6 rows too");
	fs_range_set_free (set);
	g_free (crlf);
	g_clear_error (&err);

	set = parse ("192.0.2.0\t192.0.2.255\t24\n"
	             "198.51.100.0\t198.51.100.255\t24\n"
	             "203.0.113.0\t203.0.113.255\t24\n"
	             "198.51.100.0\t198.51.100.127\t25\n"
	             "203.0.113.128\t203.0.113.255\t25\n"
	             "192.0.2.0\n"
	             "192.0.2.255\t192.0.2.0\t24\n"
	             "192.0.2.0\t2001:db8::1\t24\n"
	             "192.0.2.0/24\t192.0.2.255\t24\n",
	             FS_FEED_FMT_DSHIELD, &st, &err);
	CHECK (set != NULL && st.entries == 5 && st.invalid == 4 &&
	       st.first_invalid == 6 && st.cover4 == 768,
	       "DShield: a lone field, start > end, mixed families and a CIDR "
	       "for an address are invalid rows (invalid %u)", st.invalid);
	fs_range_set_free (set);
	g_clear_error (&err);
}

/* ===================================================== hostile input */

static void
test_size_nul_bom_crlf (void)
{
	FsFeedParseStats st;
	GError *err = NULL;
	FsRangeSet *set;
	gsize max = FS_FEED_MAX_BYTES;
	gchar *big = g_malloc (max + 1);
	gchar *line;

	/* 8192 comment lines of exactly 4096 bytes: 32 MiB on the dot. */
	for (gsize off = 0; off < max; off += 4096) {
		memset (big + off, ' ', 4096);
		big[off] = '#';
		big[off + 4095] = '\n';
	}
	big[max] = '\n';
	set = parse_len (big, max, FS_FEED_FMT_PLAIN, &st, &err);
	CHECK (set != NULL && st.lines == 8192 && st.comments == 8192,
	       "a body of exactly 32 MiB is read (%s)",
	       err ? err->message : "no error");
	fs_range_set_free (set);
	g_clear_error (&err);
	CHECK (refused_as (big, max + 1, FS_FEED_FMT_PLAIN,
	                   FS_FEED_ERR_TOO_LARGE, &st) && st.lines == 0,
	       "a body of 32 MiB + 1 is refused before it is read");
	CHECK (csv_refused_as (big, max + 1, FS_FEED_ERR_TOO_LARGE, &st),
	       "CSV: a file over 32 MiB is refused");
	g_free (big);

	CHECK (refused_as ("192.0.2.1\n\0\n198.51.100.1\n", 25,
	                   FS_FEED_FMT_PLAIN, FS_FEED_ERR_TOO_LARGE, &st),
	       "a NUL byte refuses the body");
	CHECK (refused_as ("192.0.2.1\n", sizeof "192.0.2.1\n",
	                   FS_FEED_FMT_PLAIN, FS_FEED_ERR_TOO_LARGE, &st),
	       "a NUL at the very end (the C terminator counted) refuses it");
	CHECK (refused_as (DROP4, sizeof DROP4, FS_FEED_FMT_SPAMHAUS_JSON,
	                   FS_FEED_ERR_TOO_LARGE, &st) &&
	       refused_as (DSHIELD, sizeof DSHIELD, FS_FEED_FMT_DSHIELD,
	                   FS_FEED_ERR_TOO_LARGE, &st) &&
	       csv_refused_as ("1.2.3.4\n\0", 9, FS_FEED_ERR_TOO_LARGE, &st),
	       "a NUL byte refuses every format and CSV");

	set = parse ("\xEF\xBB\xBF" "192.0.2.1\r\n198.51.100.0/24\r\n"
	             "# c\r\n\r\n203.0.113.1", FS_FEED_FMT_PLAIN, &st, &err);
	CHECK (set != NULL && st.entries == 3 && st.invalid == 0 &&
	       st.comments == 2 && st.lines == 5,
	       "a UTF-8 BOM, CRLF and a last line without a newline are read "
	       "(entries %u invalid %u comments %u lines %u)", st.entries,
	       st.invalid, st.comments, st.lines);
	fs_range_set_free (set);
	g_clear_error (&err);

	/* Line length: 4096 bytes is a line, 4097 is invalid; the CR of a
	 * CRLF is not part of it. */
	line = g_malloc0 (4200);
	memset (line, ' ', 4097);
	memcpy (line, "192.0.2.1", 9);
	memcpy (line + 4096, "\n", 1);
	set = parse (line, FS_FEED_FMT_PLAIN, &st, NULL);
	CHECK (set != NULL && st.entries == 1 && st.invalid == 0,
	       "a line of exactly 4096 bytes is read");
	fs_range_set_free (set);
	memcpy (line + 4096, "\r\n", 3);
	set = parse (line, FS_FEED_FMT_PLAIN, &st, NULL);
	CHECK (set != NULL && st.entries == 1 && st.invalid == 0,
	       "4096 bytes and a CRLF is still a line of 4096");
	fs_range_set_free (set);
	memcpy (line + 4096, " \n198.51.100.1\n198.51.100.2\n", 28);
	set = parse (line, FS_FEED_FMT_PLAIN, &st, NULL);
	CHECK (set != NULL && st.entries == 2 && st.invalid == 1 &&
	       st.first_invalid == 1 &&
	       !fs_range_set_contains_text (set, "192.0.2.1"),
	       "a line of 4097 bytes is invalid, not truncated");
	fs_range_set_free (set);
	g_free (line);
}

static gchar *
many_addresses (guint n)
{
	GString *s = g_string_sized_new (n * 12);

	/* 1.0.0.0 + i: never protected space. */
	for (guint i = 0; i < n; i++) {
		guint32 a = 0x01000000u + i;

		g_string_append_printf (s, "%u.%u.%u.%u\n", a >> 24,
		                        (a >> 16) & 0xff, (a >> 8) & 0xff,
		                        a & 0xff);
	}
	return g_string_free (s, FALSE);
}

static void
test_entry_cap (void)
{
	FsFeedParseStats st;
	gchar *text = many_addresses (FS_FEED_MAX_ENTRIES);
	gchar *more = many_addresses (FS_FEED_MAX_ENTRIES + 1);
	FsRangeSet *set;

	set = parse (text, FS_FEED_FMT_PLAIN, &st, NULL);
	CHECK (set != NULL && st.entries == 200000,
	       "200,000 entries are accepted");
	fs_range_set_free (set);
	CHECK (refused_as (more, strlen (more), FS_FEED_FMT_PLAIN,
	                   FS_FEED_ERR_TOO_MANY, &st),
	       "200,001 entries are refused (TOO_MANY)");
	CHECK (csv_refused_as (more, strlen (more), FS_FEED_ERR_TOO_MANY, &st),
	       "CSV: 200,001 entries are refused");
	g_free (text);
	g_free (more);
}

/* Each form, alone among good entries, is dropped as too broad and the
 * list is kept; alone, it is a poisoned list. */
static void
test_too_broad (void)
{
	static const gchar *const forms[] = {
		"0.0.0.0/0",
		"::/0",
		"2.0.0.0/7",
		"::ffff:0.0.0.0/96",
		"::ffff:0.0.0.0/97",
		"::ffff:1.0.0.0/104",
		"0.0.0.0-255.255.255.255",
		"1.0.0.0-1.255.255.255",
		"2000::-3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"2001::/16",
		"::ffff:1.0.0.0-::ffff:1.255.255.255",
	};

	for (guint i = 0; i < G_N_ELEMENTS (forms); i++) {
		FsFeedParseStats st;
		GError *err = NULL;
		gchar *body = g_strdup_printf ("192.0.2.1\n%s\n198.51.100.1\n",
		                               forms[i]);
		gchar *csv = g_strdup_printf ("ip,why\n192.0.2.1,a\n\"%s\",b\n"
		                              "198.51.100.1,c\n", forms[i]);
		FsRangeSet *set = parse (body, FS_FEED_FMT_PLAIN, &st, &err);

		CHECK (set != NULL && st.too_broad == 1 && st.entries == 2 &&
		       st.cover4 == 2 && st.v6 == 0,
		       "too broad: %s is dropped, the list kept (broad %u, "
		       "entries %u, cover %" G_GUINT64_FORMAT ") %s", forms[i],
		       st.too_broad, st.entries, st.cover4,
		       err ? err->message : "");
		fs_range_set_free (set);
		g_clear_error (&err);

		set = fs_feed_parse_csv (csv, strlen (csv), &st, &err);
		CHECK (set != NULL && st.too_broad == 1 && st.entries == 2 &&
		       st.cover4 == 2,
		       "CSV, too broad: %s is dropped", forms[i]);
		fs_range_set_free (set);
		g_clear_error (&err);

		CHECK (refused_as (forms[i], strlen (forms[i]),
		                   FS_FEED_FMT_PLAIN, FS_FEED_ERR_NOT_A_LIST,
		                   &st) && st.too_broad == 1,
		       "too broad: %s alone is a poisoned list", forms[i]);
		g_free (body);
		g_free (csv);
	}
}

/* The floor is a size: a /10 of any spelling passes, one address more
 * does not. */
static void
test_floor_boundary (void)
{
	static const struct {
		const gchar *text;
		gboolean     broad;
	} cases[] = {
		{ "44.0.0.0/10",                      FALSE },
		{ "44.0.0.0-44.63.255.255",           FALSE },
		{ "::ffff:44.0.0.0/106",              FALSE },
		{ "44.0.0.0-44.64.0.0",               TRUE  },
		{ "44.0.0.0/9",                       TRUE  },
		{ "2001:db8::/29",                    FALSE },
		{ "2001:db8::-2001:dbf:ffff:ffff:ffff:ffff:ffff:ffff", FALSE },
		{ "2001:db8::-2001:dc0::",            TRUE  },
		{ "2001:db0::/28",                    TRUE  },
	};

	for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
		FsFeedParseStats st;
		gchar *body = g_strdup_printf ("%s\n192.0.2.1\n198.51.100.1\n",
		                               cases[i].text);
		FsRangeSet *set = parse (body, FS_FEED_FMT_PLAIN, &st, NULL);

		CHECK (set != NULL && st.too_broad == (cases[i].broad ? 1u : 0u),
		       "floor: %s is %s", cases[i].text,
		       cases[i].broad ? "too broad" : "allowed");
		fs_range_set_free (set);
		g_free (body);
	}

	{
		FsFeedParseStats st;
		FsRangeSet *set = parse ("44.0.0.0/10\n", FS_FEED_FMT_PLAIN,
		                         &st, NULL);

		CHECK (set != NULL && st.cover4 == POW2 (22) && st.entries == 1,
		       "a /10 exactly is allowed: 4,194,304 addresses kept");
		fs_range_set_free (set);
		set = parse ("2001:db8::/29\n", FS_FEED_FMT_PLAIN, &st, NULL);
		CHECK (set != NULL && st.cover6_64 == POW2 (35),
		       "an IPv6 /29 exactly is allowed: 2^35 /64s");
		fs_range_set_free (set);
	}
}

static void
test_protected (void)
{
	FsFeedParseStats st;
	GError *err = NULL;
	FsRangeSet *set;

	/* FireHOL lists 224.0.0.0/3: all multicast and reserved space. */
	set = parse ("224.0.0.0/3\n198.51.100.1\n", FS_FEED_FMT_PLAIN, &st,
	             &err);
	CHECK (set != NULL && st.too_broad == 0 && st.entries == 2 &&
	       st.protected_hits == 1 && st.cover4 == 1 &&
	       !fs_range_set_contains_text (set, "224.0.0.1") &&
	       !fs_range_set_contains_text (set, "240.0.0.1"),
	       "FireHOL's 224.0.0.0/3 counts nothing: not too broad, nothing "
	       "kept, one protected hit [P7] %s", err ? err->message : "");
	fs_range_set_free (set);
	g_clear_error (&err);

	set = parse ("10.1.2.0/24\n100.64.0.0/10\n198.18.0.0/15\n"
	             "192.0.0.0/24\n192.88.99.0/24\n64:ff9b::/96\n"
	             "64:ff9b:1::/48\n9.255.255.0-10.0.0.255\nfe80::1\n"
	             "192.0.2.1\n", FS_FEED_FMT_PLAIN, &st, &err);
	CHECK (set != NULL && st.entries == 10 && st.protected_hits == 9 &&
	       st.too_broad == 0 && st.cover4 == 257 && st.v6 == 0,
	       "protected_hits counts every entry that touched protected "
	       "space (got %u of 10, cover %" G_GUINT64_FORMAT ")",
	       st.protected_hits, st.cover4);
	CHECK (set != NULL &&
	       fs_range_set_contains_text (set, "9.255.255.1") &&
	       !fs_range_set_contains_text (set, "10.0.0.1") &&
	       !fs_range_set_contains_text (set, "198.18.7.7") &&
	       !fs_range_set_contains_text (set, "192.88.99.1") &&
	       !fs_range_set_contains_text (set, "64:ff9b::808:808") &&
	       fs_range_set_contains_text (set, "192.0.2.1"),
	       "the unprotected part of a straddling range is kept, the "
	       "rest (RFC 1918, special-purpose, NAT64) taken out");
	fs_range_set_free (set);
	g_clear_error (&err);
}

static gchar *
slash8s (guint extra_hosts)
{
	GString *s = g_string_new (NULL);
	guint n = 0;

	/* 221 /8s: every /8 below 224 but 0, 10 and 127. */
	for (guint a = 1; a < 224; a++) {
		if (a == 10 || a == 127)
			continue;
		g_string_append_printf (s, "%u.0.0.0/8\n", a);
		n++;
	}
	g_assert (n == 221);
	for (guint i = 0; i < extra_hosts; i++)
		g_string_append_printf (s, "198.51.100.%u\n", i % 256);
	return g_string_free (s, FALSE);
}

static void
test_poisoned (void)
{
	FsFeedParseStats st;
	GString *s;
	gchar *text;
	FsRangeSet *set;

	text = slash8s (0);
	CHECK (refused_as (text, strlen (text), FS_FEED_FMT_PLAIN,
	                   FS_FEED_ERR_NOT_A_LIST, &st) &&
	       st.too_broad == 221 && st.entries == 0,
	       "poisoned: 221 /8s are refused (broad %u)", st.too_broad);
	g_free (text);

	/* As many good entries as broad ones is still poisoned; one more
	 * good entry and the list is kept without the /8s. */
	text = slash8s (221);
	CHECK (refused_as (text, strlen (text), FS_FEED_FMT_PLAIN,
	                   FS_FEED_ERR_NOT_A_LIST, &st),
	       "poisoned: 221 /8s and 221 good entries are refused");
	g_free (text);
	text = slash8s (222);
	set = parse (text, FS_FEED_FMT_PLAIN, &st, NULL);
	CHECK (set != NULL && st.too_broad == 221 && st.entries == 222 &&
	       st.cover4 == 222,
	       "221 /8s and 222 good entries: kept, the /8s dropped");
	fs_range_set_free (set);
	g_free (text);

	/* 1,000 /9s, from /8s with no protected space in them. */
	s = g_string_new (NULL);
	for (guint i = 0; i < 1000; i++) {
		guint a = 11 + (i / 2) % 80;   /* 11 .. 90 */

		g_string_append_printf (s, "%u.%u.0.0/9\n", a, i % 2 ? 128 : 0);
	}
	CHECK (refused_as (s->str, s->len, FS_FEED_FMT_PLAIN,
	                   FS_FEED_ERR_NOT_A_LIST, &st) &&
	       st.too_broad == 1000,
	       "poisoned: 1,000 /9s are refused");
	g_string_free (s, TRUE);

	/* 82 IPv6 /16s: the RIR blocks of 2000::/3 in a few lines. */
	s = g_string_new (NULL);
	for (guint i = 0; i < 82; i++)
		g_string_append_printf (s, "%x::/16\n", 0x2000 + i);
	CHECK (refused_as (s->str, s->len, FS_FEED_FMT_PLAIN,
	                   FS_FEED_ERR_NOT_A_LIST, &st) &&
	       st.too_broad == 82,
	       "poisoned: 82 IPv6 /16s are refused");
	g_string_free (s, TRUE);

	CHECK (csv_refused_as ("0.0.0.0/0\n::/0\n192.0.2.1\n", 25,
	                       FS_FEED_ERR_NOT_A_LIST, &st),
	       "CSV: a poisoned file is refused too");
}

static void
test_coverage (void)
{
	FsFeedParseStats st;
	GString *s = g_string_new (NULL);
	GError *err = NULL;
	FsRangeSet *set;

	/* Eight /10s are 2^25 addresses: at the cap.  A ninth is over. */
	for (guint i = 0; i < 8; i++)
		g_string_append_printf (s, "%u.%u.0.0/10\n", 1 + i / 4,
		                        (i % 4) * 64);
	set = parse (s->str, FS_FEED_FMT_PLAIN, &st, &err);
	CHECK (set != NULL && st.cover4 == POW2 (25) && st.too_broad == 0,
	       "eight /10s (2^25 addresses, at the cap) are accepted %s",
	       err ? err->message : "");
	fs_range_set_free (set);
	g_clear_error (&err);
	g_string_append (s, "3.0.0.0/10\n");
	CHECK (refused_as (s->str, s->len, FS_FEED_FMT_PLAIN,
	                   FS_FEED_ERR_COVERAGE, &st) &&
	       st.cover4 == 9 * POW2 (22),
	       "nine /10s are over the IPv4 coverage cap");
	CHECK (csv_refused_as (s->str, s->len, FS_FEED_ERR_COVERAGE, &st),
	       "CSV: nine /10s are over the cap too");
	g_string_free (s, TRUE);

	/* IPv6: 128 /29s are 2^42 /64s, at the cap; 129 are over. */
	s = g_string_new (NULL);
	for (guint k = 0; k < 128; k++)
		g_string_append_printf (s, "2001:%x::/29\n", k * 8);
	set = parse (s->str, FS_FEED_FMT_PLAIN, &st, &err);
	CHECK (set != NULL && st.cover6_64 == POW2 (42),
	       "128 IPv6 /29s (2^42 /64s, at the cap) are accepted");
	fs_range_set_free (set);
	g_clear_error (&err);
	g_string_append (s, "2001:400::/29\n");
	CHECK (refused_as (s->str, s->len, FS_FEED_FMT_PLAIN,
	                   FS_FEED_ERR_COVERAGE, &st),
	       "129 IPv6 /29s are over the IPv6 coverage cap");
	g_string_free (s, TRUE);
}

static void
test_not_a_list (void)
{
	static const gchar html[] =
		"<!DOCTYPE html>\n"
		"<html>\n"
		"<head><title>503 Service Unavailable</title></head>\n"
		"<body>\n"
		"<h1>503 Service Unavailable</h1>\n"
		"192.0.2.44\n"
		"</body>\n"
		"</html>\n";
	FsFeedParseStats st;
	GError *err = NULL;
	FsRangeSet *set;

	CHECK (refused_as (html, strlen (html), FS_FEED_FMT_PLAIN,
	                   FS_FEED_ERR_NOT_A_LIST, &st) &&
	       st.invalid == 7 && st.entries == 1 && st.first_invalid == 1,
	       "an HTML error page is not a list (invalid %u, entries %u)",
	       st.invalid, st.entries);
	CHECK (refused_as (html, strlen (html), FS_FEED_FMT_DSHIELD,
	                   FS_FEED_ERR_NOT_A_LIST, &st) &&
	       refused_as (html, strlen (html), FS_FEED_FMT_SPAMHAUS_JSON,
	                   FS_FEED_ERR_NOT_A_LIST, &st) &&
	       csv_refused_as (html, strlen (html), FS_FEED_ERR_NOT_A_LIST,
	                       &st),
	       "an HTML page is not a list in any format, nor as CSV");

	set = parse_len (html, strlen (html), FS_FEED_FMT_PLAIN, NULL, &err);
	CHECK (set == NULL && err != NULL && one_sentence (err->message),
	       "the refusal says why in one sentence: %s",
	       err ? err->message : "(none)");
	g_clear_error (&err);

	CHECK (refused_as ("garbage\n", 8, FS_FEED_FMT_PLAIN,
	                   FS_FEED_ERR_NOT_A_LIST, &st),
	       "nothing parsed while a line was invalid is not a list");

	/* A few bad lines in a real list are counted, not fatal. */
	set = parse ("192.0.2.1\nnot-an-address\n198.51.100.1\n203.0.113.1\n"
	             "example.com\n", FS_FEED_FMT_PLAIN, &st, &err);
	CHECK (set != NULL && st.entries == 3 && st.invalid == 2 &&
	       st.first_invalid == 2,
	       "invalid lines in a mostly good list are counted, the first "
	       "named (line %u)", st.first_invalid);
	fs_range_set_free (set);
	g_clear_error (&err);
}

/* ================================================================ CSV */

static void
test_csv (void)
{
	static const gchar csv[] =
		"ip,comment\n"
		"192.0.2.1,scanner\n"
		"\"198.51.100.0/24\",\"a, quoted, field\"\n"
		"203.0.113.10-203.0.113.20;range\n"
		"# a comment\n"
		"; another\n"
		"  2001:db8::/48\t\n"
		"\"203.0.113.99\n"
		"0.0.0.0/0,everything\n"
		"not-an-address,x\n"
		"10.9.8.7,lan\n";
	static const gchar clean[] =
		"\xEF\xBB\xBF" "address\r\n"
		"192.0.2.0/24 ; SBL000001\r\n"
		"\"198.51.100.7\",scanner\r\n"
		"203.0.113.10-203.0.113.20,range\r\n"
		"2001:db8:bad::/48\r\n"
		"10.0.0.0/8\r\n"
		"192.168.1.5\r\n"
		"junk\r\n";
	FsFeedParseStats st;
	FsBlocklistStats bst;
	GError *err = NULL;
	FsRangeSet *set, *ref;
	gchar *a, *b;

	set = fs_feed_parse_csv (csv, strlen (csv), &st, &err);
	CHECK (set != NULL && st.entries == 6 && st.comments == 3 &&
	       st.too_broad == 1 && st.invalid == 1 && st.first_invalid == 10 &&
	       st.protected_hits == 1 && st.content_date == 0,
	       "CSV: header, quoted fields, an unclosed quote, comments; the "
	       "/0 dropped, the LAN address taken out (entries %u comments "
	       "%u broad %u invalid %u) %s", st.entries, st.comments,
	       st.too_broad, st.invalid, err ? err->message : "");
	CHECK (set != NULL &&
	       fs_range_set_contains_text (set, "198.51.100.200") &&
	       fs_range_set_contains_text (set, "203.0.113.15") &&
	       fs_range_set_contains_text (set, "203.0.113.99") &&
	       fs_range_set_contains_text (set, "2001:db8::1") &&
	       !fs_range_set_contains_text (set, "10.9.8.7"),
	       "CSV: every kept field is in the set");
	fs_range_set_free (set);
	g_clear_error (&err);

	/* The same rules as fs_blocklist_parse_csv, plus the guards: on a
	 * file with nothing too broad, the two agree once the protected
	 * ranges are out. */
	set = fs_feed_parse_csv (clean, strlen (clean), &st, &err);
	ref = fs_blocklist_parse_csv (clean, strlen (clean), &bst);
	fs_range_set_subtract (ref, fs_range_protected ());
	a = set != NULL ? fs_range_set_to_text (set) : g_strdup ("(refused)");
	b = fs_range_set_to_text (ref);
	CHECK (g_strcmp0 (a, b) == 0 && st.entries == bst.entries &&
	       st.invalid == bst.skipped && bst.header && st.comments == 1,
	       "CSV reads like fs_blocklist_parse_csv (BOM, CRLF, header, "
	       "quotes): same set, same counts");
	g_free (a);
	g_free (b);
	fs_range_set_free (set);
	fs_range_set_free (ref);
	g_clear_error (&err);

	/* Only the first data line can be a header. */
	a = g_strdup ("192.0.2.1\nfoo,bar\n198.51.100.1\n");
	set = fs_feed_parse_csv (a, strlen (a), &st, &err);
	CHECK (set != NULL && st.entries == 2 && st.invalid == 1 &&
	       st.comments == 0,
	       "CSV: a lettered line after the data is invalid, not a header");
	fs_range_set_free (set);
	g_clear_error (&err);
	g_free (a);

	a = g_strdup ("# This File Date  : Sat Oct 24 04:49:13 UTC 2026\n"
	              "192.0.2.1\n");
	set = fs_feed_parse_csv (a, strlen (a), &st, &err);
	CHECK (set != NULL && st.content_date == 0,
	       "CSV: an imported file has no content date");
	fs_range_set_free (set);
	g_clear_error (&err);
	g_free (a);
}

/* ============================================================== judge */

static FsFeedParseStats
copy_of (guint entries, guint64 cover4, gint64 date)
{
	FsFeedParseStats s;

	memset (&s, 0, sizeof s);
	s.entries = entries;
	s.v4 = entries > 0 ? 1 : 0;
	s.cover4 = cover4;
	s.content_date = date;
	return s;
}

static FsFeedHistory
history_of (guint entries, guint64 cover4, gint64 date)
{
	FsFeedHistory h;
	FsFeedParseStats s = copy_of (entries, cover4, date);

	memset (&h, 0, sizeof h);
	fs_feed_history_push (&h, &s);
	return h;
}

/* Judge; the verdict must be `want', with one sentence of why when it
 * is not OK and NULL when it is. */
static void
expect_verdict (const FsFeedParseStats *now, const FsFeedHistory *h,
                guint flags, FsFeedVerdict want, const gchar *what)
{
	static gchar unset[] = "(why not set)";
	gchar *why = unset;
	FsFeedVerdict got = fs_feed_judge (now, h, flags, &why);
	gboolean sentence = why != unset &&
	                    (want == FS_FEED_VERDICT_OK ? why == NULL
	                                                : one_sentence (why));

	CHECK (got == want && sentence, "judge: %s (verdict %d, want %d%s%s)",
	       what, got, want, why != NULL ? ": " : "",
	       why != NULL ? why : "");
	if (why != unset)
		g_free (why);
}

static void
test_judge (void)
{
	const gint64 D = 1793468642;   /* Spamhaus, 2026-10-31 17:44 UTC */
	FsFeedHistory h, none;
	FsFeedParseStats now, empty;
	gchar *why = NULL;

	memset (&none, 0, sizeof none);
	empty = copy_of (0, 0, 0);

	now = copy_of (5, POW2 (30), 0);
	expect_verdict (&now, &none, 0, FS_FEED_VERDICT_OK,
	                "an empty history accepts anything that parsed");
	expect_verdict (&empty, NULL, 0, FS_FEED_VERDICT_OK,
	                "no history at all accepts an empty list");

	/* EMPTY */
	h = history_of (1614, 14917120, 0);
	expect_verdict (&empty, &h, 0, FS_FEED_VERDICT_EMPTY,
	                "EMPTY: nothing now, 1,614 entries in use");
	expect_verdict (&empty, &h, FS_FEED_ACCEPT_SHRINK, FS_FEED_VERDICT_OK,
	                "EMPTY is overridden by accept-shrink");
	expect_verdict (&empty, &h, FS_FEED_ACCEPT_COVERAGE,
	                FS_FEED_VERDICT_EMPTY,
	                "EMPTY is not overridden by accept-coverage");
	now = copy_of (3, 0, 0);
	now.v4 = 0;   /* three entries, all protected space */
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_EMPTY,
	                "EMPTY: entries that block nothing are nothing");
	h = history_of (0, 0, 0);
	expect_verdict (&empty, &h, 0, FS_FEED_VERDICT_OK,
	                "EMPTY needs a copy in use that had something");
	h = history_of (1, 1, 0);
	expect_verdict (&empty, &h, 0, FS_FEED_VERDICT_EMPTY,
	                "EMPTY guards a list too small for SHRANK: 1 -> 0 "
	                "[S15.3]");
	h = history_of (89, 0, D);
	now = copy_of (89, 0, D);
	now.v4 = 0;
	now.v6 = 89;
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_OK,
	                "an IPv6-only list (no IPv4 coverage) is not EMPTY");

	/* SHRANK by entries, against the largest recent copy */
	h = history_of (1614, 0, 0);
	now = copy_of (403, 0, 0);
	(void) fs_feed_judge (&now, &h, 0, &why);
	CHECK (g_strcmp0 (why, "The new copy has 403 entries; recent copies "
	                       "had up to 1,614.") == 0,
	       "the sentence for the UI and the audit line (%s)",
       why != NULL ? why : "none");
	g_free (why);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_SHRANK,
	                "SHRANK: 403 is under a quarter of 1,614");
	now = copy_of (404, 0, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_OK,
	                "404 is a quarter of 1,614 or more");
	fs_feed_history_push (&h, &now);
	now = copy_of (101, 0, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_SHRANK,
	                "SHRANK: the walk 1,614 -> 404 -> 101 is caught at 101 "
	                "[S15]");
	expect_verdict (&now, &h, FS_FEED_ACCEPT_SHRINK, FS_FEED_VERDICT_OK,
	                "SHRANK is overridden by accept-shrink");
	expect_verdict (&now, &h, FS_FEED_ACCEPT_COVERAGE,
	                FS_FEED_VERDICT_SHRANK,
	                "SHRANK is not overridden by accept-coverage");

	/* the threshold: 8 entries */
	h = history_of (8, 0, 0);
	now = copy_of (1, 0, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_SHRANK,
	                "SHRANK applies from 8 entries: 8 -> 1");
	now = copy_of (2, 0, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_OK,
	                "8 -> 2 is a quarter, accepted");
	h = history_of (7, 0, 0);
	now = copy_of (1, 0, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_OK,
	                "below 8 entries there is no shrink rule: 7 -> 1");

	/* SHRANK by IPv4 coverage: from 2^16 addresses */
	h = history_of (10, POW2 (16), 0);
	now = copy_of (10, POW2 (14) - 1, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_SHRANK,
	                "SHRANK by coverage: 16,383 of 65,536 addresses");
	now = copy_of (10, POW2 (14), 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_OK,
	                "16,384 of 65,536 addresses is a quarter");
	h = history_of (10, POW2 (16) - 1, 0);
	now = copy_of (10, 1, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_OK,
	                "below 2^16 addresses there is no coverage shrink rule");

	/* only the last seven copies count */
	h = history_of (1614, 0, 0);
	for (guint i = 0; i < 6; i++) {
		FsFeedParseStats s = copy_of (500, 0, 0);

		fs_feed_history_push (&h, &s);
	}
	now = copy_of (130, 0, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_SHRANK,
	                "the 1,614 copy still counts six copies later");
	{
		FsFeedParseStats s = copy_of (500, 0, 0);

		fs_feed_history_push (&h, &s);
	}
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_OK,
	                "and is forgotten after seven");

	/* GREW: more than doubled AND more than 2^22 more */
	h = history_of (100, 10000000, 0);
	now = copy_of (100, 20000001, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_GREW,
	                "GREW: 10,000,000 -> 20,000,001 addresses");
	now = copy_of (100, 20000000, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_OK,
	                "exactly doubled is not more than doubled");
	h = history_of (100, 1000000, 0);
	now = copy_of (100, 1000000 + POW2 (22) + 1, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_GREW,
	                "GREW: 1,000,000 -> 5,194,305 addresses");
	now = copy_of (100, 1000000 + POW2 (22), 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_OK,
	                "growing by exactly 2^22 is allowed");
	now = copy_of (100, 1000000 + POW2 (22) + 1, 0);
	expect_verdict (&now, &h, FS_FEED_ACCEPT_COVERAGE, FS_FEED_VERDICT_OK,
	                "GREW is overridden by accept-coverage");
	expect_verdict (&now, &h, FS_FEED_ACCEPT_SHRINK, FS_FEED_VERDICT_GREW,
	                "GREW is not overridden by accept-shrink");
	h = history_of (89, 0, 0);
	now = copy_of (89, POW2 (22) + 1, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_GREW,
	                "GREW from no IPv4 at all to more than a /10's worth");

	/* ROLLBACK */
	h = history_of (100, 1000, D);
	now = copy_of (100, 1000, D - 1);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_ROLLBACK,
	                "ROLLBACK: content one second older than ours");
	(void) fs_feed_judge (&now, &h, 0, &why);
	CHECK (why != NULL &&
	       strstr (why, "dated 2026-10-31 17:44:01 UTC") != NULL &&
	       strstr (why, "(2026-10-31 17:44:02 UTC)") != NULL,
	       "the rollback sentence names both dates (%s)",
       why != NULL ? why : "none");
	g_free (why);
	expect_verdict (&now, &h, FS_FEED_ACCEPT_SHRINK, FS_FEED_VERDICT_OK,
	                "ROLLBACK is overridden by accept-shrink");
	expect_verdict (&now, &h, FS_FEED_ACCEPT_COVERAGE,
	                FS_FEED_VERDICT_ROLLBACK,
	                "ROLLBACK is not overridden by accept-coverage");
	now = copy_of (100, 1000, D);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_OK,
	                "the same content date is not a rollback");
	now = copy_of (100, 1000, 0);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_OK,
	                "an undated copy cannot be judged a rollback");
	h = history_of (100, 1000, 0);
	now = copy_of (100, 1000, D - 1);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_OK,
	                "nor a dated copy after an undated one");

	/* several at once: each needs its own override */
	h = history_of (1000, 1000, 0);
	now = copy_of (10, POW2 (24), 0);   /* a few /10s for many /32s */
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_SHRANK,
	                "fewer entries but far more addresses: SHRANK first");
	expect_verdict (&now, &h, FS_FEED_ACCEPT_SHRINK, FS_FEED_VERDICT_GREW,
	                "accept-shrink alone still meets GREW");
	expect_verdict (&now, &h, FS_FEED_ACCEPT_SHRINK |
	                FS_FEED_ACCEPT_COVERAGE, FS_FEED_VERDICT_OK,
	                "both overrides accept it");
	h = history_of (100, 1000, D);
	now = copy_of (0, 0, D - 1);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_EMPTY,
	                "an empty copy that is also older: EMPTY comes first");
	now = copy_of (10, 1000, D - 1);
	expect_verdict (&now, &h, 0, FS_FEED_VERDICT_ROLLBACK,
	                "a shrunk copy that is also older: ROLLBACK comes "
	                "before SHRANK");
}

static void
test_history (void)
{
	FsFeedHistory h;
	gboolean order = TRUE;

	memset (&h, 0, sizeof h);
	for (guint i = 1; i <= 9; i++) {
		FsFeedParseStats s = copy_of (i, 10 * i, 1000 + i);

		fs_feed_history_push (&h, &s);
	}
	for (guint k = 0; k < FS_FEED_HISTORY; k++)
		order = order && h.entries[k] == 9 - k &&
		        h.cover4[k] == 10 * (9 - k);
	CHECK (h.n == FS_FEED_HISTORY && order && h.content_date == 1009,
	       "history: newest first, the last 7 kept, the newest date");

	{
		FsFeedParseStats s = copy_of (5, 50, 0);

		fs_feed_history_push (&h, &s);
		CHECK (h.content_date == 0 && h.entries[0] == 5 &&
		       h.entries[1] == 9 && h.n == FS_FEED_HISTORY,
		       "history: an undated copy leaves no date behind");
		h.n = 50;   /* a damaged state file */
		fs_feed_history_push (&h, &s);
		CHECK (h.n == FS_FEED_HISTORY,
		       "history: a damaged count is clamped to 7");
	}
}

/* ================================================================ URL */

static void
test_url (void)
{
	static const gchar *const good[] = {
		"https://example.com/list.txt",
		"https://example.com:8443/feed?key=abc&fmt=plain",
		"https://sub.example-feeds.net/a/b/c.netset",
		"https://[2001:db8::1]/list",
		"https://[2001:db8::1]:443/list",
		"https://203.0.113.5/list#latest",
		"HTTPS://EXAMPLE.COM/x",
	};
	static const gchar *const bad[] = {
		"",
		"http://example.com/list.txt",
		"ftp://example.com/list.txt",
		"file:///etc/passwd",
		"example.com/list.txt",
		"https://user@example.com/list.txt",
		"https://user:secret@example.com/list.txt",
		"https://exa mple.com/list.txt",
		"https://example.com/a b",
		"https://example.com/list.txt\n",
		"https://example.com/\tx",
		"https://example.com/\x7f",
		"https://ex\xc3\xa4mple.com/",
		"-https://example.com/",
		"--config=/etc/passwd",
		"https://",
		"https:///list.txt",
		"https://:443/list.txt",
		"https://?key=1",
		"https://#frag",
		"https://example.com:0/x",
		"https://example.com:65536/x",
		"https://example.com:/x",
		"https://example.com:44a/x",
		"https://exa%6dple.com/x",
		"https://evil.example\\@good.example/x",
		"https://good.example\\evil.example/x",
		"https://[]/x",
		"https://[2001:db8::1/x",
		"https://[2001:db8::1]x/",
	};
	GString *s = g_string_new ("https://example.com/");
	GError *err = NULL;
	gboolean ok = TRUE;

	for (guint i = 0; i < G_N_ELEMENTS (good); i++) {
		if (!fs_feed_url_is_acceptable (good[i], &err)) {
			g_print ("      refused %s: %s\n", good[i],
			         err != NULL ? err->message : "no error set");
			ok = FALSE;
		}
		g_clear_error (&err);
	}
	CHECK (ok, "URL rule: https URLs with ports, queries, IPv6 literals "
	       "and fragments are accepted");

	for (guint i = 0; i < G_N_ELEMENTS (bad); i++) {
		gchar *shown = g_strescape (bad[i], NULL);
		gboolean refused = !fs_feed_url_is_acceptable (bad[i], &err);

		CHECK (refused && g_error_matches (err, FS_FEED_ERROR,
		                                   FS_FEED_ERR_URL) &&
		       one_sentence (err->message),
		       "URL rule refuses \"%s\" (%s)", shown,
		       err ? err->message : "accepted");
		g_clear_error (&err);
		g_free (shown);
	}
	CHECK (!fs_feed_url_is_acceptable (NULL, NULL),
	       "URL rule refuses NULL (error may be NULL)");

	while (s->len < 2048)
		g_string_append_c (s, 'a');
	CHECK (fs_feed_url_is_acceptable (s->str, NULL),
	       "URL rule: 2048 bytes are accepted");
	g_string_append_c (s, 'a');
	CHECK (!fs_feed_url_is_acceptable (s->str, NULL),
	       "URL rule: 2049 bytes are refused");
	g_string_free (s, TRUE);
}

/* For the log only: U+2026 as "<...>", since g_print turns it into '?'
 * in the C locale. */
static gchar *
shown (const gchar *s)
{
	gchar **parts = g_strsplit (s != NULL ? s : "(null)", "\xE2\x80\xA6",
	                            -1);
	gchar *out = g_strjoinv ("<...>", parts);

	g_strfreev (parts);
	return out;
}

static void
expect_redacted (const gchar *url, const gchar *want)
{
	gchar *got = fs_feed_url_redacted (url);
	gchar *w = shown (want), *g = shown (got);

	CHECK (g_strcmp0 (got, want) == 0, "redacted: %s -> %s (got %s)",
	       url, w, g);
	g_free (got);
	g_free (w);
	g_free (g);
}

static void
test_redaction (void)
{
	expect_redacted ("https://example.com/list?key=SECRET",
	                 "https://example.com/list?\xE2\x80\xA6");
	expect_redacted ("https://example.com/list?key=SECRET#part",
	                 "https://example.com/list?\xE2\x80\xA6#part");
	expect_redacted ("https://example.com/list?a=1?b=SECRET#x?y",
	                 "https://example.com/list?\xE2\x80\xA6#x?y");
	expect_redacted ("https://example.com?key=SECRET",
	                 "https://example.com?\xE2\x80\xA6");
	expect_redacted ("https://example.com/list.txt",
	                 "https://example.com/list.txt");
	expect_redacted ("https://example.com/p#frag?notaquery",
	                 "https://example.com/p#frag?notaquery");
	expect_redacted ("https://user:SECRET@example.com/x?k=SECRET",
	                 "https://\xE2\x80\xA6@example.com/x?\xE2\x80\xA6");
	expect_redacted ("https://a@SECRET@example.com/x",
	                 "https://\xE2\x80\xA6@example.com/x");
	expect_redacted ("https://example.com/users/@me",
	                 "https://example.com/users/@me");
	CHECK (fs_feed_url_redacted (NULL) == NULL, "redacted: NULL is NULL");
}

int
main (void)
{
	test_catalog ();
	test_format_names ();
	test_plain ();
	test_spamhaus ();
	test_dshield ();
	test_size_nul_bom_crlf ();
	test_entry_cap ();
	test_too_broad ();
	test_floor_boundary ();
	test_protected ();
	test_poisoned ();
	test_coverage ();
	test_not_a_list ();
	test_csv ();
	test_judge ();
	test_history ();
	test_url ();
	test_redaction ();

	g_print ("\n%s: %u failure(s)\n", failures ? "FAILED" : "PASSED",
	         failures);
	return failures ? 1 : 0;
}
