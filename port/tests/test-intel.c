/*---[ test-intel.c ]----------------------------------------------------
 * Threat intel: address ranges (fs-iprange), the blocklist-to-nftables
 * path (fs-nftset) up to the script it renders, and the engine
 * (fs-intel: store, intel.conf, local lists, updates, the build, the
 * gate, the honest state, lookups) driven through a fake backend and a
 * fake downloader.  GLib only; no network, no nft.  Root is not needed;
 * a few store checks (a directory owned by another user) run only as
 * root.  The live half, the script applied by a real nft in a network
 * namespace, is test-nftset.sh / test-intelset.sh.
 *--------------------------------------------------------------------*/
#include <gio/gio.h>   /* G_IO_ERROR, as the Linux backend reports */
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "core/fs-iprange.h"
#include "core/fs-nftset.h"
#include "core/fs-intel.h"
#include "core/fs-intelset.h"
#include "core/fs-feed.h"
#include "core/fs-hostnet.h"
#include "core/fs-intelwin.h"

#ifdef G_OS_UNIX
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

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

static gchar *
parsed (const gchar *text)
{
	FsRange4 r4;
	FsRange6 r6;

	switch (fs_range_parse (text, &r4, &r6, NULL, NULL)) {
	case FS_AF_V4:
		return fs_range4_to_string (&r4);
	case FS_AF_V6:
		return fs_range6_to_string (&r6);
	default:
		return g_strdup ("(none)");
	}
}

static void
expect_parse (const gchar *in, const gchar *want)
{
	gchar *got = parsed (in);

	CHECK (g_strcmp0 (got, want) == 0, "parse \"%s\" -> %s (got %s)",
	       in, want, got);
	g_free (got);
}

static void
test_parse (void)
{
	guint plen = 99;
	gboolean hb = FALSE;
	FsRange4 r4;

	expect_parse ("192.0.2.7", "192.0.2.7");
	expect_parse ("192.0.2.0/24", "192.0.2.0/24");
	expect_parse ("192.0.2.0-192.0.2.255", "192.0.2.0/24");
	expect_parse ("192.0.2.10-192.0.2.20", "192.0.2.10-192.0.2.20");
	expect_parse ("2001:db8::/32", "2001:db8::/32");
	expect_parse ("2001:DB8:0:0::1", "2001:db8::1");
	expect_parse ("::ffff:198.51.100.9", "198.51.100.9");
	expect_parse ("::ffff:198.51.100.0/120", "198.51.100.0/24");
	expect_parse ("0.0.0.0/0", "0.0.0.0/0");
	expect_parse ("::/0", "::/0");

	/* Refusals */
	expect_parse ("", "(none)");
	expect_parse ("example.com", "(none)");
	expect_parse ("192.0.2.0/33", "(none)");
	expect_parse ("2001:db8::/129", "(none)");
	expect_parse ("192.0.2.0/", "(none)");
	expect_parse ("192.0.2.0/+8", "(none)");
	expect_parse ("192.0.2.0/1234", "(none)");
	expect_parse (" 192.0.2.1", "(none)");
	expect_parse ("192.0.2.9-192.0.2.1", "(none)");
	expect_parse ("192.0.2.1-2001:db8::1", "(none)");
	expect_parse ("192.0.2.1/24-192.0.2.9", "(none)");
	expect_parse ("256.0.0.1", "(none)");

	CHECK (fs_range_parse ("10.1.2.3/8", &r4, NULL, &plen, &hb) ==
	       FS_AF_V4 && plen == 8 && hb && r4.start == 0x0a000000u &&
	       r4.end == 0x0affffffu,
	       "host bits below the prefix are flagged and masked off");
	CHECK (fs_range_parse ("10.0.0.0/8", &r4, NULL, &plen, &hb) ==
	       FS_AF_V4 && !hb, "an aligned CIDR has no host bits");
}

static void
test_sets (void)
{
	FsRangeSet *s = fs_range_set_new ();
	FsRangeSet *rm = fs_range_set_new ();
	gchar *text;

	/* overlap, adjacency, duplicates, out-of-order input */
	fs_range_set_add_text (s, "192.0.2.128/25");
	fs_range_set_add_text (s, "192.0.2.0/25");        /* touches it */
	fs_range_set_add_text (s, "198.51.100.5");
	fs_range_set_add_text (s, "198.51.100.5");        /* duplicate  */
	fs_range_set_add_text (s, "198.51.100.1-198.51.100.6");
	fs_range_set_add_text (s, "2001:db8::/48");
	fs_range_set_add_text (s, "2001:db8:1::/48");     /* adjacent   */
	fs_range_set_normalize (s);

	text = fs_range_set_to_text (s);
	CHECK (g_strcmp0 (text, "192.0.2.0/24\n198.51.100.1-198.51.100.6\n"
	                        "2001:db8::/47\n") == 0,
	       "normalize merges overlap, adjacency and duplicates (got %s)",
	       text);
	g_free (text);

	CHECK (fs_range_set_contains_text (s, "192.0.2.200") &&
	       fs_range_set_contains_text (s, "198.51.100.6") &&
	       !fs_range_set_contains_text (s, "198.51.100.7") &&
	       fs_range_set_contains_text (s, "2001:db8:1:ffff::1") &&
	       !fs_range_set_contains_text (s, "2001:db8:2::1") &&
	       fs_range_set_contains_text (s, "::ffff:192.0.2.1"),
	       "membership, including a v4-mapped address");

	/* subtract: a hole in the middle splits, an edge trims */
	fs_range_set_add_text (rm, "192.0.2.10-192.0.2.19");
	fs_range_set_add_text (rm, "198.51.100.6");
	fs_range_set_add_text (rm, "2001:db8::/48");
	fs_range_set_normalize (rm);
	fs_range_set_subtract (s, rm);
	text = fs_range_set_to_text (s);
	CHECK (g_strcmp0 (text, "192.0.2.0-192.0.2.9\n"
	                        "192.0.2.20-192.0.2.255\n"
	                        "198.51.100.1-198.51.100.5\n"
	                        "2001:db8:1::/48\n") == 0,
	       "subtract splits and trims (got %s)", text);
	g_free (text);

	fs_range_set_free (s);
	fs_range_set_free (rm);

	/* the protected ranges */
	CHECK (fs_range_set_contains_text (fs_range_protected (), "10.20.30.40") &&
	       fs_range_set_contains_text (fs_range_protected (), "127.0.0.1") &&
	       fs_range_set_contains_text (fs_range_protected (), "fe80::1") &&
	       fs_range_set_contains_text (fs_range_protected (), "ff02::1") &&
	       !fs_range_set_contains_text (fs_range_protected (), "192.0.2.1") &&
	       !fs_range_set_contains_text (fs_range_protected (), "8.8.8.8") &&
	       !fs_range_set_contains_text (fs_range_protected (), "2001:db8::1"),
	       "protected: LAN, loopback, link-local, multicast; not TEST-NETs");

	{
		FsRangeSet *dns = fs_range_set_from_resolv_conf (
			"# resolver\nnameserver 192.0.2.53\n"
			"nameserver   fe80::1%eth0\nsearch example\n"
			"nameserverx 1.1.1.1\n");

		CHECK (fs_range_set_count4 (dns) == 1 &&
		       fs_range_set_count6 (dns) == 1 &&
		       fs_range_set_contains_text (dns, "192.0.2.53") &&
		       fs_range_set_contains_text (dns, "fe80::1"),
		       "resolv.conf: nameservers only, zone suffix dropped");
		fs_range_set_free (dns);
	}
}

static void
test_csv (void)
{
	const gchar *csv =
		"\xEF\xBB\xBF" "ip,comment\n"
		"# Spamhaus-style and CSV mixed\n"
		"192.0.2.0/24 ; SBL000001\n"
		"\"198.51.100.7\",scanner\n"
		"203.0.113.10-203.0.113.20,range\n"
		"2001:db8:bad::/48\n"
		"; semicolon comment\n"
		"\n"
		"not-an-address,junk\n"
		"10.1.2.3\n";
	FsBlocklistStats st;
	FsRangeSet *s = fs_blocklist_parse_csv (csv, strlen (csv), &st);

	CHECK (st.entries == 5, "five addresses read (got %u)", st.entries);
	CHECK (st.header, "the \"ip,comment\" first line is a header");
	CHECK (st.skipped == 1 && st.first_bad_line == 9,
	       "one bad line, reported as line 9 (got %u at %u)",
	       st.skipped, st.first_bad_line);
	CHECK (fs_range_set_contains_text (s, "198.51.100.7") &&
	       fs_range_set_contains_text (s, "203.0.113.15") &&
	       fs_range_set_contains_text (s, "2001:db8:bad::1"),
	       "quoted, ranged and IPv6 fields all land in the set");
	fs_range_set_free (s);

	/* Not NUL-terminated input: only `len' bytes are read. */
	s = fs_blocklist_parse_csv ("192.0.2.1\n192.0.2.2XXXX", 19, &st);
	CHECK (st.entries == 2 && fs_range_set_count4 (s) == 1,
	       "parse stops at len (got %u entries)", st.entries);
	fs_range_set_free (s);
}

static void
test_script (void)
{
	FsRangeSet *s = fs_range_set_new ();
	gchar *script;
	guint adds = 0;

	CHECK (fs_nft_name_is_valid ("blocklist") &&
	       fs_nft_name_is_valid ("s_1_4") &&
	       !fs_nft_name_is_valid ("1abc") &&
	       !fs_nft_name_is_valid ("bad name") &&
	       !fs_nft_name_is_valid ("x;flush ruleset") &&
	       !fs_nft_name_is_valid ("") &&
	       !fs_nft_name_is_valid ("a234567890123456789012345678901b"),
	       "names: a letter, then letters, digits, _; 31 at most");

	CHECK (fs_nftset_script ("t", "x } ; flush ruleset ; {", s) == NULL,
	       "a hostile set name renders no script at all");

	fs_range_set_add_text (s, "192.0.2.0/24");
	fs_range_set_add_text (s, "2001:db8::1");
	fs_range_set_normalize (s);
	script = fs_nftset_script ("stockfw_intel", "blocklist", s);
	CHECK (strstr (script, "table inet stockfw_intel {\n"
	                       "\tset blocklist {\n\t\ttype ipv4_addr\n") != NULL &&
	       strstr (script, "\tset blocklist6 {\n\t\ttype ipv6_addr\n") != NULL,
	       "declares blocklist (v4) and blocklist6 (v6)");
	CHECK (strstr (script, "flush set inet stockfw_intel blocklist\n") != NULL &&
	       strstr (script, "flush set inet stockfw_intel blocklist6\n") != NULL,
	       "flushes both sets before adding: replace, not merge");
	CHECK (strstr (script, "add element inet stockfw_intel blocklist "
	                       "{ 192.0.2.0/24 }\n") != NULL &&
	       strstr (script, "add element inet stockfw_intel blocklist6 "
	                       "{ 2001:db8::1 }\n") != NULL,
	       "adds each family to its own set");
	CHECK (strstr (script, "flush set inet stockfw_intel blocklist\n") <
	       strstr (script, "add element"),
	       "the flush comes before the adds");
	g_free (script);
	fs_range_set_free (s);

	/* 2500 single addresses: three statements, 1000 + 1000 + 500. */
	s = fs_range_set_new ();
	for (guint32 i = 0; i < 2500; i++)
		fs_range_set_add4 (s, 0xc6120000u + 2 * i, 0xc6120000u + 2 * i);
	fs_range_set_normalize (s);
	script = fs_nftset_script ("stockfw_intel", "blocklist", s);
	for (const gchar *p = script; (p = strstr (p, "add element")) != NULL; p++)
		adds++;
	CHECK (adds == 3, "2500 elements go in 3 statements (got %u)", adds);
	g_free (script);
	fs_range_set_free (s);
}

/* ================================================== the engine (fs-intel)
 *
 * Everything below drives src/core/fs-intel.c through a fake backend
 * (it records what intel_apply received and plays the kernel: success,
 * failure, a timeout after nft committed, an unreadable listing) and a
 * fake downloader (fs_intel_set_fetcher), with an injected clock where
 * the engine takes one.  The store is a fresh directory per test under
 * a base whose every parent passes the store's ownership check.
 */

#ifdef G_OS_UNIX

/* A fixed "now": 2026-10-26 18:13:20 UTC. */
#define NOW0 G_GINT64_CONSTANT (1793038400)
#define HOUR 3600

static gchar *eng_base;      /* a safe directory for stores          */
static gchar *eng_audit;     /* the audit file every check reads     */
static guint  eng_seq;

/* ---- files ---------------------------------------------------------- */

static void
rm_rf (const gchar *path)
{
	GDir *d = g_dir_open (path, 0, NULL);
	struct stat st;

	if (lstat (path, &st) != 0)
		return;
	if (d != NULL && !S_ISLNK (st.st_mode)) {
		const gchar *n;

		while ((n = g_dir_read_name (d)) != NULL) {
			gchar *c = g_build_filename (path, n, NULL);

			rm_rf (c);
			g_free (c);
		}
		g_dir_close (d);
		g_rmdir (path);
	} else {
		if (d != NULL)
			g_dir_close (d);
		g_unlink (path);
	}
}

static gchar *
store_path (const gchar *name)
{
	return g_build_filename (g_getenv ("STOCKFW_INTEL_DIR"), name, NULL);
}

static void
put_file_len (const gchar *name, const gchar *text, gssize len)
{
	gchar *p = store_path (name);

	g_file_set_contents (p, text, len, NULL);
	g_chmod (p, 0600);
	g_free (p);
}

static void
put_file (const gchar *name, const gchar *text)
{
	gchar *p = store_path (name);

	g_file_set_contents (p, text, -1, NULL);
	g_chmod (p, 0600);
	g_free (p);
}

static gchar *
get_file (const gchar *name)
{
	gchar *p = store_path (name);
	gchar *text = NULL;

	g_file_get_contents (p, &text, NULL, NULL);
	g_free (p);
	return text;
}

static gboolean
has_file (const gchar *name)
{
	gchar *p = store_path (name);
	gboolean has = g_file_test (p, G_FILE_TEST_EXISTS);

	g_free (p);
	return has;
}

/* A fresh, empty store for the next test. */
static void
fresh_store (void)
{
	gchar *name = g_strdup_printf ("store-%u", ++eng_seq);
	gchar *path = g_build_filename (eng_base, name, NULL);

	g_setenv ("STOCKFW_INTEL_DIR", path, TRUE);
	g_free (name);
	g_free (path);
}

static gchar *
audit_text (void)
{
	gchar *text = NULL;

	g_file_get_contents (eng_audit, &text, NULL, NULL);
	return text != NULL ? text : g_strdup ("");
}

static guint
count_substr (const gchar *hay, const gchar *needle)
{
	guint n = 0;

	for (const gchar *p = hay; (p = strstr (p, needle)) != NULL; p++)
		n++;
	return n;
}

static void
audit_reset (void)
{
	g_unlink (eng_audit);
}

/* A base for stores: a new directory whose chain passes the check. */
static gboolean
find_safe_base (const gchar *argv0)
{
	const gchar *cands[4];
	gchar *exe_dir = g_path_get_dirname (argv0);
	gchar *cwd = g_get_current_dir ();
	gchar *abs_exe = g_path_is_absolute (exe_dir)
	                 ? g_strdup (exe_dir)
	                 : g_build_filename (cwd, exe_dir, NULL);
	guint n = 0;

	cands[n++] = g_getenv ("STOCKFW_TEST_SAFE_DIR");
	cands[n++] = g_get_home_dir ();
	cands[n++] = abs_exe;
	cands[n++] = NULL;
	for (guint i = 0; i < n && eng_base == NULL; i++) {
		gchar *tmpl, *dir;
		GError *e = NULL;

		if (cands[i] == NULL)
			continue;
		tmpl = g_build_filename (cands[i], "sfw-intel-test-XXXXXX", NULL);
		dir = g_mkdtemp_full (tmpl, 0700);
		if (dir == NULL) {
			g_free (tmpl);
			continue;
		}
		{
			gchar *probe = g_build_filename (dir, "probe", NULL);
			gchar *got;

			g_setenv ("STOCKFW_INTEL_DIR", probe, TRUE);
			got = fs_intel_dir (&e);
			if (got != NULL)
				eng_base = g_strdup (dir);
			else
				rm_rf (dir);
			g_free (got);
			g_free (probe);
			g_clear_error (&e);
		}
		g_free (tmpl);
	}
	g_free (exe_dir);
	g_free (abs_exe);
	g_free (cwd);
	if (eng_base != NULL) {
		eng_audit = g_build_filename (eng_base, "audit.log", NULL);
		g_setenv ("STOCKFW_AUDIT_FILE", eng_audit, TRUE);
	}
	return eng_base != NULL;
}

/* ---- the fake downloader ---------------------------------------------- */

typedef struct
{
	GHashTable *bodies;     /* url -> body text ("" allowed)        */
	GHashTable *errors;     /* url -> error message                 */
	guint       calls;
	gchar      *last_url;
	gchar      *last_proxy;
} FakeNet;

static FakeNet net;

/* Runs while a download is in progress (an apply or a Stop meanwhile). */
static void (*during_fetch) (void);

static GBytes *
fake_fetch (const gchar *url, const gchar *proxy, gpointer user_data,
            GError **error)
{
	FakeNet *fn = user_data;
	const gchar *body, *err;

	fn->calls++;
	if (during_fetch != NULL)
		during_fetch ();
	g_free (fn->last_url);
	g_free (fn->last_proxy);
	fn->last_url = g_strdup (url);
	fn->last_proxy = g_strdup (proxy);
	err = g_hash_table_lookup (fn->errors, url);
	if (err != NULL) {
		g_set_error_literal (error, g_quark_from_static_string ("fake"),
		                     1, err);
		return NULL;
	}
	body = g_hash_table_lookup (fn->bodies, url);
	if (body == NULL) {
		g_set_error (error, g_quark_from_static_string ("fake"), 2,
		             "HTTP 404 for %s", url);
		return NULL;
	}
	return g_bytes_new (body, strlen (body));
}

static void
net_reset (void)
{
	if (net.bodies == NULL) {
		net.bodies = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                    g_free, g_free);
		net.errors = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                    g_free, g_free);
	}
	g_hash_table_remove_all (net.bodies);
	g_hash_table_remove_all (net.errors);
	net.calls = 0;
	g_clear_pointer (&net.last_url, g_free);
	g_clear_pointer (&net.last_proxy, g_free);
	fs_intel_set_fetcher (fake_fetch, &net);
}

static void
serve (const gchar *id, const gchar *body)
{
	const FsFeedInfo *fi = fs_feed_catalog_find (id);
	const gchar *url = fi != NULL ? fi->url : id;

	g_hash_table_remove (net.errors, url);
	g_hash_table_replace (net.bodies, g_strdup (url), g_strdup (body));
}

static void
serve_error (const gchar *id, const gchar *message)
{
	const FsFeedInfo *fi = fs_feed_catalog_find (id);

	g_hash_table_replace (net.errors, g_strdup (fi ? fi->url : id),
	                      g_strdup (message));
}

/* A plain list of n addresses from `base' on, every other one (so no
 * two merge). */
static gchar *
plain_list (guint n, guint32 base)
{
	GString *out = g_string_new ("# test list\n");

	for (guint i = 0; i < n; i++) {
		guint32 a = base + 2 * i;

		g_string_append_printf (out, "%u.%u.%u.%u\n", a >> 24,
		                        (a >> 16) & 255, (a >> 8) & 255, a & 255);
	}
	return g_string_free (out, FALSE);
}

/* A Spamhaus DROP body with a content date. */
static gchar *
drop_body (const gchar *cidrs, gint64 stamp)
{
	GString *out = g_string_new (NULL);
	gchar **v = g_strsplit (cidrs, " ", -1);
	guint n = 0;

	for (guint i = 0; v[i] != NULL; i++, n++)
		g_string_append_printf (out, "{\"cidr\":\"%s\",\"sblid\":"
		                        "\"SBL%u\",\"rir\":\"arin\"}\n", v[i], i);
	g_string_append_printf (out, "{\"type\":\"metadata\",\"timestamp\":%"
	                        G_GINT64_FORMAT ",\"size\":1,\"records\":%u}\n",
	                        stamp, n);
	g_strfreev (v);
	return g_string_free (out, FALSE);
}

/* ---- the fake backend ----------------------------------------------- */

typedef enum
{
	APPLY_OK,          /* commits, returns TRUE                         */
	APPLY_FAIL,        /* nothing changes, returns FALSE                */
	APPLY_COMMITTED,   /* commits, then "times out": returns FALSE      */
	APPLY_LIE          /* returns TRUE, changes nothing                 */
} ApplyMode;

typedef struct
{
	ApplyMode   mode;
	gboolean    clear_ok;
	gboolean    live_unknown;   /* intel_live reads UNKNOWN          */
	gboolean    no_tool;        /* Linux without nft: every slot
	                             * fails G_IO_ERROR_NOT_FOUND, live
	                             * UNKNOWN, counters NULL            */
	gboolean    counters_unreadable; /* the chains cannot be listed  */
	gboolean    apply_inactive; /* an apply leaves rules that are not
	                             * enforced (Windows: firewall off for
	                             * the profile in use)               */
	gchar      *not_in_force;   /* intel_not_in_force's sentence     */
	FsIntelLive live;           /* what the kernel holds             */
	gchar      *live_digest;
	GHashTable *counters;       /* of the live table: id -> counter  */
	guint       apply_calls;
	guint       clear_calls;
	guint       counter_calls;
	gchar      *got_digest;     /* of the last ruleset received      */
	gchar      *got_text;       /* "id dir\n<ranges>" per set        */
	guint       got_sets;
	void      (*during_apply) (void);  /* runs inside intel_apply     */
	void      (*during_clear) (void);  /* runs inside intel_clear     */
	const gchar *live_error;    /* intel_live_error's answer         */
} FakeKernel;

static FakeKernel kern;

static GHashTable *
counters_new (void)
{
	return g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

static void
counter_set (GHashTable *t, const gchar *id, guint64 p, guint64 b)
{
	FsIntelCounter *c = g_new0 (FsIntelCounter, 1);

	c->packets = p;
	c->bytes = b;
	g_hash_table_replace (t, g_strdup (id), c);
}

static gchar *
ruleset_text (const FsIntelRuleset *rs)
{
	GString *out = g_string_new (NULL);

	for (guint i = 0; i < rs->sets->len; i++) {
		const FsIntelSet *s = g_ptr_array_index (rs->sets, i);
		gchar *t = fs_range_set_to_text (s->ranges);

		g_string_append_printf (out, "[%s %s]\n%s", s->id,
		                        fs_intel_dir_to_string (s->dir), t);
		g_free (t);
	}
	return g_string_free (out, FALSE);
}

static gboolean
fake_apply (const FsIntelRuleset *rs, GError **error)
{
	gchar *digest = fs_intel_ruleset_digest (rs);

	kern.apply_calls++;
	if (kern.during_apply != NULL)
		kern.during_apply ();
	if (kern.no_tool) {
		g_free (digest);
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
		                     "nft was not found on PATH.");
		return FALSE;
	}
	g_free (kern.got_digest);
	g_free (kern.got_text);
	kern.got_digest = g_strdup (digest);
	kern.got_text = ruleset_text (rs);
	kern.got_sets = rs->sets->len;
	if (kern.mode == APPLY_OK || kern.mode == APPLY_COMMITTED) {
		/* The empty rule set renders no table. */
		kern.live = rs->sets->len == 0 ? FS_INTEL_LIVE_ABSENT
		            : kern.apply_inactive ? FS_INTEL_LIVE_INACTIVE
		            : FS_INTEL_LIVE_PRESENT;
		g_free (kern.live_digest);
		kern.live_digest = rs->sets->len ? g_strdup (digest) : NULL;
		/* A new table: every set with addresses has its counter
		 * rules, at zero, as `nft list chain' shows them; a set
		 * with none has no rule (fs_intelset_nft_script). */
		g_hash_table_remove_all (kern.counters);
		for (guint i = 0; i < rs->sets->len; i++) {
			const FsIntelSet *s = g_ptr_array_index (rs->sets, i);

			if (!fs_range_set_is_empty (s->ranges))
				counter_set (kern.counters, s->id, 0, 0);
		}
	}
	g_free (digest);
	if (kern.mode == APPLY_FAIL) {
		g_set_error (error, g_quark_from_static_string ("fake"), 3,
		             "nft: Error: syntax error|line 7\nsecond line");
		return FALSE;
	}
	if (kern.mode == APPLY_COMMITTED) {
		g_set_error (error, g_quark_from_static_string ("fake"), 4,
		             "nft timed out after 60 s");
		return FALSE;
	}
	return TRUE;
}

static gboolean
fake_clear (GError **error)
{
	kern.clear_calls++;
	if (kern.during_clear != NULL)
		kern.during_clear ();
	if (kern.no_tool) {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
		                     "nft was not found on PATH.");
		return FALSE;
	}
	if (!kern.clear_ok) {
		g_set_error (error, g_quark_from_static_string ("fake"), 5,
		             "nft: cannot clear");
		return FALSE;
	}
	kern.live = FS_INTEL_LIVE_ABSENT;
	g_clear_pointer (&kern.live_digest, g_free);
	g_hash_table_remove_all (kern.counters);
	return TRUE;
}

static GHashTable *
fake_counters (void)
{
	GHashTable *t;
	GHashTableIter it;
	gpointer k, v;

	kern.counter_calls++;
	if (kern.no_tool || kern.counters_unreadable ||
	    kern.live != FS_INTEL_LIVE_PRESENT)
		return NULL;
	t = counters_new ();
	g_hash_table_iter_init (&it, kern.counters);
	while (g_hash_table_iter_next (&it, &k, &v)) {
		const FsIntelCounter *c = v;

		counter_set (t, k, c->packets, c->bytes);
	}
	return t;
}

static FsIntelLive
fake_live (gchar **digest)
{
	if (digest != NULL)
		*digest = NULL;
	if (kern.live_unknown || kern.no_tool)
		return FS_INTEL_LIVE_UNKNOWN;
	if (digest != NULL && (kern.live == FS_INTEL_LIVE_PRESENT ||
	                       kern.live == FS_INTEL_LIVE_INACTIVE))
		*digest = g_strdup (kern.live_digest);
	return kern.live;
}

static gchar *
fake_live_error (void)
{
	return g_strdup (kern.live_error);
}

static gchar *
fake_not_in_force (void)
{
	return g_strdup (kern.not_in_force);
}

static FsBackend fake_backend;
static FsBackend bare_backend;   /* no intel slots (another platform) */

static void
kern_reset (void)
{
	if (kern.counters == NULL)
		kern.counters = counters_new ();
	g_hash_table_remove_all (kern.counters);
	kern.mode = APPLY_OK;
	kern.clear_ok = TRUE;
	kern.live_unknown = FALSE;
	kern.no_tool = FALSE;
	kern.counters_unreadable = FALSE;
	kern.apply_inactive = FALSE;
	g_clear_pointer (&kern.not_in_force, g_free);
	kern.live = FS_INTEL_LIVE_ABSENT;
	g_clear_pointer (&kern.live_digest, g_free);
	g_clear_pointer (&kern.got_digest, g_free);
	g_clear_pointer (&kern.got_text, g_free);
	kern.apply_calls = kern.clear_calls = kern.counter_calls = 0;
	kern.got_sets = 0;
	kern.during_apply = kern.during_clear = NULL;
	kern.live_error = NULL;
	fake_backend.intel_live_error = fake_live_error;
	fake_backend.name = "fake";
	fake_backend.intel_apply = fake_apply;
	fake_backend.intel_clear = fake_clear;
	fake_backend.intel_counters = fake_counters;
	fake_backend.intel_live = fake_live;
	fake_backend.intel_not_in_force = NULL;
	bare_backend.name = "bare";
}

/* ---- small builders -------------------------------------------------- */

static FsIntelConfig *
conf_with (const gchar *ids)
{
	FsIntelConfig *c = fs_intel_config_new ();
	gchar **v = g_strsplit (ids, " ", -1);

	for (guint i = 0; v[i] != NULL; i++)
		if (*v[i] && !fs_intel_config_enable_feed (c, v[i], 0, TRUE, NULL))
			g_print ("(setup: cannot enable %s)\n", v[i]);
	g_strfreev (v);
	return c;
}

static FsIntelUpdateResult *
result_for (GPtrArray *rs, const gchar *id)
{
	for (guint i = 0; i < rs->len; i++) {
		FsIntelUpdateResult *r = g_ptr_array_index (rs, i);

		if (strcmp (r->id, id) == 0)
			return r;
	}
	return NULL;
}

static FsIntelUpdateOutcome
update1 (const FsIntelConfig *c, const gchar *id, guint flags, gint64 now,
         gchar **message)
{
	GPtrArray *rs = fs_intel_update (c, id, flags, now);
	FsIntelUpdateResult *r = result_for (rs, id);
	FsIntelUpdateOutcome o = r ? r->outcome : (FsIntelUpdateOutcome) 99;

	if (message != NULL)
		*message = g_strdup (r ? r->message : "(no result)");
	g_ptr_array_unref (rs);
	return o;
}

static gchar *
import_text (FsIntelConfig *c, const gchar *name, const gchar *text,
             FsIntelDir dir, GError **error)
{
	gchar *path = g_build_filename (eng_base, "import.csv", NULL);
	gchar *id = NULL;

	g_file_set_contents (path, text, -1, NULL);
	fs_intel_import_list (c, path, name, dir, NULL, &id, error);
	g_unlink (path);
	g_free (path);
	return id;
}

static FsHostNet *
host_fixture (void)
{
	FsHostNet *h = fs_hostnet_new ();

	fs_range_set_add_text (h->own, "203.0.113.5");
	fs_range_set_add_text (h->own, "2001:db8:5::5");
	fs_range_set_add_text (h->onlink, "203.0.113.0/29");
	fs_range_set_add_text (h->gateways, "203.0.113.1");
	fs_range_set_add_text (h->resolvers, "198.51.100.53");
	fs_range_set_add_text (h->sessions, "192.0.2.22");
	fs_range_set_add_text (h->update_hosts, "198.51.100.80");
	fs_range_set_normalize (h->own);
	fs_range_set_normalize (h->onlink);
	fs_range_set_normalize (h->gateways);
	fs_range_set_normalize (h->resolvers);
	fs_range_set_normalize (h->sessions);
	fs_range_set_normalize (h->update_hosts);
	return h;
}

static gboolean
notes_have (GPtrArray *notes, const gchar *needle)
{
	for (guint i = 0; notes != NULL && i < notes->len; i++)
		if (strstr (g_ptr_array_index (notes, i), needle) != NULL)
			return TRUE;
	return FALSE;
}

/* ---- store directory -------------------------------------------------- */

static void
expect_dir_refused (const gchar *path, gint code, const gchar *what)
{
	GError *e = NULL;
	gchar *got;

	g_setenv ("STOCKFW_INTEL_DIR", path, TRUE);
	got = fs_intel_dir (&e);
	CHECK (got == NULL && g_error_matches (e, FS_INTEL_ERROR, code),
	       "store: %s is refused (got %s: %s)", what, got ? got : "NULL",
	       e ? e->message : "no error");
	g_free (got);
	g_clear_error (&e);
}

static void
test_store_dir (void)
{
	gchar *ok_path = g_build_filename (eng_base, "safe", NULL);
	gchar *wide = g_build_filename (eng_base, "wide", NULL);
	gchar *link = g_build_filename (eng_base, "link", NULL);
	gchar *via = g_build_filename (eng_base, "via", NULL);
	gchar *via_store = g_build_filename (via, "store", NULL);
	gchar *got, *expect;
	GError *e = NULL;
	struct stat st;

	g_setenv ("STOCKFW_INTEL_DIR", ok_path, TRUE);
	got = fs_intel_dir (&e);
	CHECK (got != NULL && stat (ok_path, &st) == 0 &&
	       (st.st_mode & 0777) == 0700,
	       "store: a safe override is created 0700 (%s)",
	       e ? e->message : "ok");
	g_free (got);
	g_clear_error (&e);

	expect_dir_refused ("relative/intel", FS_INTEL_ERR_UNSAFE_DIR,
	                    "a relative path");
	/* /tmp is writable by everyone (sticky or not).  A directory left
	 * by an earlier run (with a broken check) is removed first. */
	g_rmdir ("/tmp/stockfw-intel-test-never");
	expect_dir_refused ("/tmp/stockfw-intel-test-never",
	                    FS_INTEL_ERR_UNSAFE_DIR,
	                    "a directory under world-writable /tmp");
	{
		struct stat tst;

		CHECK (lstat ("/tmp/stockfw-intel-test-never", &tst) != 0,
		       "store: ... and nothing was created there");
		g_rmdir ("/tmp/stockfw-intel-test-never");
	}

	g_mkdir (wide, 0700);
	g_chmod (wide, 0777);
	expect_dir_refused (wide, FS_INTEL_ERR_UNSAFE_DIR,
	                    "a directory writable by others (0777)");
	g_chmod (wide, 0720);
	expect_dir_refused (wide, FS_INTEL_ERR_UNSAFE_DIR,
	                    "a directory writable by its group (0720)");

	if (symlink (ok_path, link) == 0)
		expect_dir_refused (link, FS_INTEL_ERR_UNSAFE_DIR,
		                    "a symbolic link as the store itself");

	/* A store inside a directory others can write is refused even when
	 * the store itself is 0700. */
	{
		gchar *inner = g_build_filename (wide, "inner", NULL);

		g_chmod (wide, 0700);
		g_mkdir (inner, 0700);
		g_chmod (wide, 0777);
		expect_dir_refused (inner, FS_INTEL_ERR_UNSAFE_DIR,
		                    "a 0700 store inside a 0777 parent");
		g_chmod (wide, 0700);
		g_free (inner);
	}

	/* A symlink in a parent is followed to its target, and the target
	 * chain is what is checked. */
	if (symlink (eng_base, via) == 0) {
		g_setenv ("STOCKFW_INTEL_DIR", via_store, TRUE);
		got = fs_intel_dir (&e);
		expect = g_build_filename (eng_base, "store", NULL);
		CHECK (g_strcmp0 (got, expect) == 0,
		       "store: a symlinked parent resolves to its target (%s)",
		       got ? got : (e ? e->message : "NULL"));
		g_free (expect);
		g_free (got);
		g_clear_error (&e);
	}

	/* An existing store others can read (or enter) lists the feeds and
	 * local lists in use, though its files are 0600: it is tightened
	 * to 0700 (design 6.1), never used as it is. */
	{
		static const guint modes[] = { 0755, 0750, 0711, 0705 };
		gchar *open_dir = g_build_filename (eng_base, "readable", NULL);

		for (guint i = 0; i < G_N_ELEMENTS (modes); i++) {
			g_rmdir (open_dir);
			g_mkdir (open_dir, 0700);
			g_chmod (open_dir, modes[i]);
			g_setenv ("STOCKFW_INTEL_DIR", open_dir, TRUE);
			got = fs_intel_dir (&e);
			CHECK (got != NULL && stat (open_dir, &st) == 0 &&
			       (st.st_mode & 0777) == 0700,
			       "store: an existing %04o store is set to 0700 "
			       "(mode now %04o; %s)", modes[i],
			       (guint) (st.st_mode & 0777),
			       e ? e->message : "ok");
			g_free (got);
			g_clear_error (&e);
		}
		/* And through every store operation, not only fs_intel_dir. */
		g_chmod (open_dir, 0755);
		{
			FsIntelConfig *c = fs_intel_config_new ();

			fs_intel_config_save (c, NULL);
			fs_intel_config_free (c);
		}
		CHECK (stat (open_dir, &st) == 0 && (st.st_mode & 0777) == 0700,
		       "store: saving the configuration into a 0755 store "
		       "leaves it 0700");
		g_free (open_dir);
	}

	if (geteuid () == 0) {
		gchar *other = g_build_filename (eng_base, "other", NULL);
		gchar *inner = g_build_filename (other, "inner", NULL);

		/* `sudo -E' with STOCKFW_INTEL_DIR in a user's directory. */
		g_mkdir (other, 0700);
		if (chown (other, 65534, 65534) == 0) {
			expect_dir_refused (other, FS_INTEL_ERR_UNSAFE_DIR,
			                    "as root, a directory owned by another "
			                    "user");
			g_mkdir (inner, 0700);
			expect_dir_refused (inner, FS_INTEL_ERR_UNSAFE_DIR,
			                    "as root, a root-owned store inside a "
			                    "user's directory");
		}
		g_free (inner);
		g_free (other);
	} else {
		g_unsetenv ("STOCKFW_INTEL_DIR");
		got = fs_intel_dir (&e);
		CHECK (got == NULL && g_error_matches (e, FS_INTEL_ERROR,
		                                       FS_INTEL_ERR_NEEDS_ROOT),
		       "store: not root and no override -> needs root");
		g_free (got);
		g_clear_error (&e);
		g_print ("SKIP: owned-by-another-user checks need root\n");
	}

	g_free (ok_path);
	g_free (wide);
	g_free (link);
	g_free (via);
	g_free (via_store);
}

/* ---- intel.conf ------------------------------------------------------- */

static void
expect_conf_error (const gchar *text, const gchar *needle, const gchar *what)
{
	GError *e = NULL;
	FsIntelConfig *c;

	fresh_store ();
	g_free (fs_intel_dir (NULL));
	put_file ("intel.conf", text);
	c = fs_intel_config_load (&e);
	CHECK (c == NULL && g_error_matches (e, FS_INTEL_ERROR,
	                                     FS_INTEL_ERR_CONFIG) &&
	       strstr (e->message, needle) != NULL,
	       "intel.conf: %s fails, naming %s (got %s)", what, needle,
	       e ? e->message : "a config");
	fs_intel_config_free (c);
	g_clear_error (&e);
}

static void
test_config (void)
{
	FsIntelConfig *c, *d;
	GError *e = NULL;
	gchar *id = NULL, *text;
	guint ncat = 0;
	const FsFeedInfo *cat = fs_feed_catalog (&ncat);
	gboolean defaults = TRUE;

	fresh_store ();
	c = fs_intel_config_load (&e);
	CHECK (c != NULL && c->enabled && c->proxy == NULL &&
	       c->feeds->len == ncat && c->lists->len == 0 &&
	       fs_range_set_is_empty (c->exceptions),
	       "intel.conf: a missing file is the defaults");
	for (guint i = 0; c != NULL && i < ncat; i++) {
		FsIntelFeedConf *f = g_ptr_array_index (c->feeds, i);

		if (strcmp (f->id, cat[i].id) != 0 || f->enabled ||
		    f->dir != cat[i].default_dir || f->accepted_at != 0)
			defaults = FALSE;
	}
	CHECK (defaults, "defaults: every catalog feed, in catalog order, off, "
	                 "in its default direction, terms not accepted");
	fs_intel_config_free (c);
	g_clear_error (&e);

	/* Consent */
	c = fs_intel_config_new ();
	CHECK (!fs_intel_config_enable_feed (c, "feodo", 0, FALSE, &e) &&
	       g_error_matches (e, FS_INTEL_ERROR, FS_INTEL_ERR_CONSENT) &&
	       !fs_intel_config_feed (c, "feodo")->enabled,
	       "enable without accepting the terms: CONSENT, nothing changes");
	g_clear_error (&e);
	CHECK (!fs_intel_config_set_enabled (c, "feodo", TRUE, &e) &&
	       g_error_matches (e, FS_INTEL_ERROR, FS_INTEL_ERR_CONSENT),
	       "set_enabled is no way around the consent");
	g_clear_error (&e);
	CHECK (fs_intel_config_enable_feed (c, "feodo", FS_INTEL_DIR_IN, TRUE,
	                                    NULL) &&
	       fs_intel_config_feed (c, "feodo")->accepted_at > 0 &&
	       fs_intel_config_feed (c, "feodo")->dir == FS_INTEL_DIR_IN,
	       "enable with the terms accepted records when");
	CHECK (fs_intel_config_disable_feed (c, "feodo", NULL) &&
	       fs_intel_config_set_enabled (c, "feodo", TRUE, NULL),
	       "once accepted, a feed is turned off and on freely");
	CHECK (!fs_intel_config_enable_feed (c, "no-such-feed", 0, TRUE, &e) &&
	       g_error_matches (e, FS_INTEL_ERROR, FS_INTEL_ERR_UNKNOWN),
	       "an unknown feed is UNKNOWN");
	g_clear_error (&e);

	/* Custom feeds */
	CHECK (!fs_intel_config_add_custom (c, "Mine", "http://example.com/x",
	                                    FS_FEED_FMT_PLAIN, FS_INTEL_DIR_IN,
	                                    NULL, &e) &&
	       g_error_matches (e, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID),
	       "custom feed: http:// is refused");
	g_clear_error (&e);
	CHECK (!fs_intel_config_add_custom (c, "Mine",
	                                    "https://user:pw@example.com/x",
	                                    FS_FEED_FMT_PLAIN, FS_INTEL_DIR_IN,
	                                    NULL, &e),
	       "custom feed: a user@ part is refused");
	g_clear_error (&e);
	CHECK (fs_intel_config_add_custom (c, "My Own List!", "https://lists."
	                                   "example.com/bad.txt?key=s3cret",
	                                   FS_FEED_FMT_PLAIN, FS_INTEL_DIR_BOTH,
	                                   &id, &e) &&
	       g_strcmp0 (id, "custom-my-own-list") == 0 &&
	       fs_intel_config_feed (c, id)->enabled &&
	       fs_intel_config_feed (c, id)->accepted_at > 0,
	       "custom feed: id custom-<slug>, on, typed URL = consent (%s)",
	       id ? id : (e ? e->message : "?"));
	g_clear_error (&e);
	CHECK (!fs_intel_config_add_custom (c, "my own list",
	                                    "https://example.com/y",
	                                    FS_FEED_FMT_PLAIN, FS_INTEL_DIR_IN,
	                                    NULL, &e),
	       "custom feed: the same slug twice is refused");
	g_clear_error (&e);
	CHECK (!fs_intel_config_remove (c, "feodo", &e) &&
	       g_error_matches (e, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID),
	       "a catalog feed cannot be removed");
	g_clear_error (&e);
	CHECK (g_strcmp0 (fs_intel_config_label (c, id), "My Own List!") == 0 &&
	       g_strcmp0 (fs_intel_config_label (c, "feodo"),
	                  "abuse.ch Feodo Tracker") == 0 &&
	       fs_intel_config_label (c, "nope") == NULL,
	       "labels: custom name, catalog name, NULL when unknown");

	/* Round trip */
	fs_range_set_add_text (c->exceptions, "198.51.100.7");
	fs_range_set_add_text (c->exceptions, "2001:db8::/64");
	fs_range_set_normalize (c->exceptions);
	c->proxy = g_strdup ("http://proxy.example:3128");
	{
		FsIntelListConf *l = g_new0 (FsIntelListConf, 1);

		l->id = g_strdup ("local-office");
		l->name = g_strdup ("Office; \"blocks\" = [x]");
		l->enabled = TRUE;
		l->dir = FS_INTEL_DIR_OUT;
		l->imported_at = 1700000000;
		g_ptr_array_add (c->lists, l);
	}
	CHECK (fs_intel_config_save (c, &e), "intel.conf saved (%s)",
	       e ? e->message : "ok");
	g_clear_error (&e);
	d = fs_intel_config_load (&e);
	text = get_file ("intel.conf");
	CHECK (d != NULL && g_strcmp0 (d->proxy, c->proxy) == 0 &&
	       fs_intel_config_feed (d, "feodo")->enabled &&
	       fs_intel_config_feed (d, "feodo")->accepted_at ==
	       fs_intel_config_feed (c, "feodo")->accepted_at &&
	       fs_intel_config_feed (d, id) != NULL &&
	       fs_intel_config_feed (d, id)->custom &&
	       g_strcmp0 (fs_intel_config_feed (d, id)->url,
	                  fs_intel_config_feed (c, id)->url) == 0 &&
	       fs_intel_config_feed (d, id)->dir == FS_INTEL_DIR_BOTH &&
	       fs_intel_config_list (d, "local-office") != NULL &&
	       g_strcmp0 (fs_intel_config_list (d, "local-office")->name,
	                  "Office; \"blocks\" = [x]") == 0 &&
	       fs_intel_config_list (d, "local-office")->dir == FS_INTEL_DIR_OUT &&
	       fs_range_set_contains_text (d->exceptions, "198.51.100.7") &&
	       fs_range_set_contains_text (d->exceptions, "2001:db8::ffff") &&
	       !fs_range_set_contains_text (d->exceptions, "198.51.100.8"),
	       "intel.conf: save and load round-trip everything");
	CHECK (text != NULL &&
	       strstr (text, "[feed feodo]\nenabled=true\ndirection=in\n") &&
	       strstr (text, "[feed custom-my-own-list]\n") &&
	       strstr (text, "format=plain\n") &&
	       strstr (text, "[list local-office]\n") &&
	       strstr (text, "[exceptions]\nranges=198.51.100.7;2001:db8::/64;\n"),
	       "intel.conf: the golden layout ([feed <id>], [list <id>], "
	       "[exceptions])");
	{
		struct stat st;
		gchar *p = store_path ("intel.conf");

		CHECK (stat (p, &st) == 0 && (st.st_mode & 0777) == 0600,
		       "intel.conf is 0600");
		g_free (p);
	}
	g_free (text);
	fs_intel_config_free (d);
	fs_intel_config_free (c);
	g_free (id);
	g_clear_error (&e);

	/* Unknown keys and groups are ignored. */
	fresh_store ();
	g_free (fs_intel_dir (NULL));
	put_file ("intel.conf", "[intel]\nenabled=true\ncolour=blue\n"
	          "[weird group]\nx=y\n[feed retired-feed]\nenabled=true\n"
	          "[feed feodo]\nenabled=true\naccepted-at=5\nfuture-key=1\n");
	c = fs_intel_config_load (&e);
	CHECK (c != NULL && fs_intel_config_feed (c, "feodo")->enabled &&
	       fs_intel_config_feed (c, "retired-feed") == NULL,
	       "intel.conf: unknown keys, groups and feeds are ignored (%s)",
	       e ? e->message : "ok");
	fs_intel_config_free (c);
	g_clear_error (&e);

	expect_conf_error ("[feed feodo]\ndirection=sideways\n",
	                   "[feed feodo] direction", "a bad direction");
	expect_conf_error ("[feed feodo]\nenabled=yes\n",
	                   "[feed feodo] enabled", "enabled=yes");
	expect_conf_error ("[feed feodo]\naccepted-at=-5\n",
	                   "[feed feodo] accepted-at", "a negative time");
	expect_conf_error ("[feed feodo]\naccepted-at=12abc\n",
	                   "[feed feodo] accepted-at", "a time with junk");
	expect_conf_error ("[feed custom-x]\nname=X\nurl=http://e.com/\n"
	                   "format=plain\n", "[feed custom-x] url",
	                   "a custom feed over http://");
	expect_conf_error ("[feed custom-x]\nname=X\nurl=https://e.com/\n"
	                   "format=csv\n", "[feed custom-x] format",
	                   "an unknown format");
	expect_conf_error ("[feed custom-x]\nurl=https://e.com/\n"
	                   "format=plain\n", "[feed custom-x] name",
	                   "a custom feed without a name");
	expect_conf_error ("[feed Bad;Id]\nenabled=true\n", "[feed Bad;Id] id",
	                   "an id nft must never see");
	expect_conf_error ("[list local-x]\nname=a\\nb\n", "[list local-x] name",
	                   "a list name with a line break");
	expect_conf_error ("[list other-x]\nname=a\n", "[list other-x] id",
	                   "a list id without local-");
	expect_conf_error ("[intel]\nproxy=http://user:secret@proxy:3128\n",
	                   "[intel] proxy",
	                   "a proxy with a password (it would sit in curl's "
	                   "argv)");
	expect_conf_error ("[intel]\nproxy=socks5://proxy:1080\n",
	                   "[intel] proxy", "a socks proxy");
	expect_conf_error ("[exceptions]\nranges=192.0.2.1;example.com\n",
	                   "[exceptions] ranges", "an exception that is a name");
	expect_conf_error ("[intel\nenabled=true\n", "not a valid",
	                   "a broken group line");
	expect_conf_error ("\xff\xfe[intel]\n", "not a valid",
	                   "bytes that are not UTF-8");
	/* A value GKeyFile cannot decode (a bad escape) is invalid, never
	 * "absent": the proxy would be dropped (downloads going direct)
	 * and every exception with it (the excepted addresses blocked). */
	expect_conf_error ("[intel]\nproxy=http://proxy.example:3128/\\q\n",
	                   "[intel] proxy",
	                   "a proxy with an invalid escape (\\q)");
	expect_conf_error ("[exceptions]\nranges=45.0.0.1;45.0.0.2\\q;\n",
	                   "[exceptions] ranges",
	                   "exceptions with one invalid escape");
	expect_conf_error ("[feed custom-x]\nname=X\\q\nurl=https://e.com/\n"
	                   "format=plain\n", "[feed custom-x] name",
	                   "a custom feed name with an invalid escape");
	expect_conf_error ("[list local-x]\nname=a\\q\n", "[list local-x] name",
	                   "a list name with an invalid escape");
	{
		/* The same file without the bad escape loads both. */
		GError *e = NULL;
		FsIntelConfig *ok;

		fresh_store ();
		g_free (fs_intel_dir (NULL));
		put_file ("intel.conf", "[intel]\nproxy=http://proxy.example:3128/\n"
		          "[exceptions]\nranges=45.0.0.1;45.0.0.2;\n");
		ok = fs_intel_config_load (&e);
		CHECK (ok != NULL &&
		       g_strcmp0 (ok->proxy, "http://proxy.example:3128/") == 0 &&
		       fs_range_set_contains_text (ok->exceptions, "45.0.0.1") &&
		       fs_range_set_contains_text (ok->exceptions, "45.0.0.2"),
		       "intel.conf: ... and without it, the proxy and both "
		       "exceptions load (%s)", e ? e->message : "ok");
		fs_intel_config_free (ok);
		g_clear_error (&e);
	}

	/* Hostile files */
	fresh_store ();
	g_free (fs_intel_dir (NULL));
	{
		gchar *big = g_malloc (1024 * 1024 + 2);
		gchar *p = store_path ("intel.conf");

		memset (big, '#', 1024 * 1024 + 1);
		big[1024 * 1024 + 1] = '\0';
		put_file ("intel.conf", big);
		c = fs_intel_config_load (&e);
		CHECK (c == NULL && g_error_matches (e, FS_INTEL_ERROR,
		                                     FS_INTEL_ERR_STORE),
		       "intel.conf over 1 MiB is a STORE error, not read");
		g_clear_error (&e);
		g_unlink (p);
		CHECK (symlink ("/etc/passwd", p) == 0 &&
		       (c = fs_intel_config_load (&e)) == NULL &&
		       g_error_matches (e, FS_INTEL_ERROR, FS_INTEL_ERR_STORE),
		       "intel.conf as a symlink is refused (%s)",
		       e ? e->message : "read");
		g_clear_error (&e);
		g_unlink (p);
		CHECK (mkfifo (p, 0600) == 0 &&
		       (c = fs_intel_config_load (&e)) == NULL,
		       "intel.conf as a FIFO is refused without waiting");
		g_clear_error (&e);
		g_unlink (p);
		/* A crash during a save leaves a stray temporary: ignored. */
		put_file (".intel.conf.deadbeef.tmp", "[intel]\nenabled=false\n");
		c = fs_intel_config_load (&e);
		CHECK (c != NULL && c->enabled,
		       "a stray temporary from a crashed save is never read");
		CHECK (c != NULL && fs_intel_config_save (c, NULL) &&
		       has_file (".intel.conf.deadbeef.tmp"),
		       "and a save next to it still works");
		fs_intel_config_free (c);
		g_free (big);
		g_free (p);
	}

	/* Consent text */
	c = fs_intel_config_new ();
	text = fs_intel_consent_text (c, "feodo");
	CHECK (text && strstr (text, "feodotracker.abuse.ch") &&
	       strstr (text, "every 6 hours") && strstr (text, "StockFW/") &&
	       strstr (text, "public IP address") && strstr (text, "CC0") &&
	       strstr (text, "https://abuse.ch/terms-of-use/") &&
	       strstr (text, "exception") && !strstr (text, "commercial use"),
	       "consent (Feodo): host, how often, what it learns, licence, "
	       "terms, exceptions");
	g_free (text);
	text = fs_intel_consent_text (c, "spamhaus-drop");
	CHECK (text && strstr (text, "www.spamhaus.org") &&
	       strstr (text, "once a day") &&
	       strstr (text, "See the provider's terms of use: "
	                     "https://www.spamhaus.org/drop/terms/"),
	       "consent (Spamhaus): once a day, \"see the provider's terms\"");
	g_free (text);
	text = fs_intel_consent_text (c, "firehol-level1");
	CHECK (text && strstr (text, "raw.githubusercontent.com") &&
	       strstr (text, "do not allow commercial use"),
	       "consent (FireHOL level 1): its host and the non-commercial "
	       "warning");
	g_free (text);
	CHECK (fs_intel_consent_text (c, "nope") == NULL,
	       "consent: NULL for an unknown id");
	fs_intel_config_free (c);
}

/* ---- updates ---------------------------------------------------------- */

static void
test_update_consent_and_network (void)
{
	FsIntelConfig *c;
	GPtrArray *rs;
	guint n = 0;

	fresh_store ();
	net_reset ();
	c = fs_intel_config_new ();
	rs = fs_intel_update (c, NULL, FS_INTEL_UPDATE_NOW, NOW0);
	CHECK (rs->len == 0 && net.calls == 0,
	       "the default configuration makes no request at all [S14]");
	g_ptr_array_unref (rs);

	/* Every feed on but none accepted (a hand-edited intel.conf). */
	fs_feed_catalog (&n);
	for (guint i = 0; i < c->feeds->len; i++)
		((FsIntelFeedConf *) g_ptr_array_index (c->feeds, i))->enabled = TRUE;
	rs = fs_intel_update (c, NULL, FS_INTEL_UPDATE_NOW, NOW0);
	{
		gboolean all = rs->len == n;

		for (guint i = 0; i < rs->len; i++)
			if (((FsIntelUpdateResult *) g_ptr_array_index (rs, i))->outcome
			    != FS_INTEL_NEEDS_CONSENT)
				all = FALSE;
		CHECK (all && net.calls == 0,
		       "enabled without accepted terms: NEEDS_CONSENT, no "
		       "request (%u calls)", net.calls);
	}
	g_ptr_array_unref (rs);

	/* The master switch off: nothing is fetched. */
	fs_intel_config_free (c);
	c = conf_with ("feodo");
	c->enabled = FALSE;
	serve ("feodo", "192.0.2.1\n");
	CHECK (update1 (c, "feodo", FS_INTEL_UPDATE_NOW, NOW0, NULL) ==
	       FS_INTEL_NOT_DUE && net.calls == 0,
	       "master switch off: not fetched");
	fs_intel_config_free (c);

	/* The URL rule is checked before any download. */
	c = fs_intel_config_new ();
	{
		gchar *id = NULL;
		FsIntelFeedConf *f;
		gchar *msg = NULL;

		fs_intel_config_add_custom (c, "Keyed", "https://e.example/l.txt",
		                            FS_FEED_FMT_PLAIN, FS_INTEL_DIR_IN,
		                            &id, NULL);
		f = fs_intel_config_feed (c, id);
		g_free (f->url);
		f->url = g_strdup ("https://user@e.example/l.txt");
		serve (f->url, "192.0.2.1\n");
		CHECK (update1 (c, id, FS_INTEL_UPDATE_NOW, NOW0, &msg) ==
		       FS_INTEL_FAILED && net.calls == 0,
		       "a URL the design's rule refuses is never fetched (%s)",
		       msg);
		g_free (msg);
		/* A hand-filled struct with an id that is a path: nothing
		 * outside the store is written, read or removed. */
		{
			gchar *outside = g_build_filename (eng_base,
			                                   "victim.list", NULL);
			gchar *saved = f->id;

			g_file_set_contents (outside, "keep me\n", -1, NULL);
			f->id = g_strdup ("../victim");
			g_free (f->url);
			f->url = g_strdup ("https://e.example/l.txt");
			serve (f->url, "192.0.2.1\n");
			CHECK (update1 (c, f->id, FS_INTEL_UPDATE_NOW, NOW0, NULL) ==
			       FS_INTEL_FAILED,
			       "an id that is a path: the update fails");
			CHECK (!fs_intel_config_remove (c, f->id, NULL) &&
			       g_file_test (outside, G_FILE_TEST_EXISTS),
			       "an id that is a path: remove deletes nothing "
			       "outside the store");
			g_free (f->id);
			f->id = saved;
			g_unlink (outside);
			g_free (outside);
			net.calls = 0;
		}
		g_free (f->url);
		f->url = g_strdup ("https://e.example/l.txt");
		c->proxy = g_strdup ("http://proxy.example:3128");
		serve (f->url, "192.0.2.1\n");
		CHECK (update1 (c, id, FS_INTEL_UPDATE_NOW, NOW0, NULL) ==
		       FS_INTEL_UPDATED && net.calls == 1 &&
		       g_strcmp0 (net.last_proxy, "http://proxy.example:3128") == 0,
		       "a custom feed is fetched through the configured proxy");
		g_free (id);
	}
	fs_intel_config_free (c);

	/* only_id */
	c = conf_with ("feodo");
	{
		FsIntelListConf *l = g_new0 (FsIntelListConf, 1);
		gchar *msg = NULL;

		l->id = g_strdup ("local-x");
		l->name = g_strdup ("X");
		l->enabled = TRUE;
		l->dir = FS_INTEL_DIR_IN;
		g_ptr_array_add (c->lists, l);
		net.calls = 0;
		CHECK (update1 (c, "local-x", 0, NOW0, &msg) == FS_INTEL_FAILED &&
		       strstr (msg, "imported") && net.calls == 0,
		       "update of a local list: refused, never fetched");
		g_free (msg);
		CHECK (update1 (c, "dshield", FS_INTEL_UPDATE_NOW, NOW0, NULL) ==
		       FS_INTEL_FAILED && net.calls == 0,
		       "update of a feed that is off: refused, never fetched");
		CHECK (update1 (c, "nope", 0, NOW0, NULL) == FS_INTEL_FAILED,
		       "update of an unknown id: FAILED");
	}
	fs_intel_config_free (c);
}

static void
test_update_guards (void)
{
	FsIntelConfig *c = conf_with ("feodo");
	FsIntelSourceState *s;
	gchar *body10 = plain_list (10, 0x2d000000u);   /* 45.0.0.0 ... */
	gchar *body1 = plain_list (1, 0x2d000000u);
	gchar *msg = NULL, *list_before, *text, *a;
	FsRangeSet *set;
	GError *e = NULL;

	fresh_store ();
	net_reset ();
	audit_reset ();
	serve ("feodo", body10);
	CHECK (update1 (c, "feodo", 0, NOW0, &msg) == FS_INTEL_UPDATED &&
	       strstr (msg, "10 entries"),
	       "first download: UPDATED (%s)", msg);
	g_free (msg);
	s = fs_intel_source_state ("feodo");
	CHECK (s != NULL && s->fetched_at == NOW0 && s->attempted_at == NOW0 &&
	       s->entries == 10 && s->count4 == 10 && s->history.n == 1 &&
	       s->sha256 != NULL && strlen (s->sha256) == 64 &&
	       s->last_error == NULL && s->refused == NULL,
	       "the state records the copy");
	fs_intel_source_state_free (s);
	set = fs_intel_source_load ("feodo", &e);
	CHECK (set != NULL && fs_range_set_count4 (set) == 10 &&
	       fs_range_set_contains_text (set, "45.0.0.18"),
	       "the stored list loads back");
	fs_range_set_free (set);
	g_clear_error (&e);
	{
		struct stat st;
		gchar *p = store_path ("feodo.list");

		CHECK (stat (p, &st) == 0 && (st.st_mode & 0777) == 0600,
		       "feodo.list is 0600");
		g_free (p);
	}
	list_before = get_file ("feodo.list");

	/* Schedule (Feodo: every 6 h) with an injected clock. */
	CHECK (update1 (c, "feodo", 0, NOW0 + 5 * HOUR, NULL) == FS_INTEL_NOT_DUE &&
	       net.calls == 1, "5 h later: not due, not fetched");
	CHECK (!fs_intel_source_is_due (c, "feodo", NOW0 + 6 * HOUR - 1) &&
	       fs_intel_source_is_due (c, "feodo", NOW0 + 6 * HOUR),
	       "due exactly one interval after the last attempt");
	CHECK (fs_intel_source_is_due (c, "feodo", NOW0 - 2 * HOUR),
	       "the clock went back: due again, not after the clock catches up");
	CHECK (update1 (c, "feodo", 0, NOW0 + 6 * HOUR, &msg) ==
	       FS_INTEL_UNCHANGED && net.calls == 2,
	       "6 h later: fetched, same bytes: UNCHANGED (%s)", msg);
	g_free (msg);
	CHECK (update1 (c, "feodo", FS_INTEL_UPDATE_NOW, NOW0 + 6 * HOUR + 1,
	                NULL) == FS_INTEL_UNCHANGED && net.calls == 3,
	       "--now ignores the schedule");
	CHECK (!fs_intel_source_is_stale (c, "feodo", NOW0 + 6 * HOUR + 42 * HOUR + 1) &&
	       fs_intel_source_is_stale (c, "feodo", NOW0 + 6 * HOUR + 42 * HOUR + 2),
	       "stale after 7 intervals (no content date: from the download)");

	/* Shrink, empty, HTML, failure: refused, the copy stays. */
	serve ("feodo", body1);
	CHECK (update1 (c, "feodo", FS_INTEL_UPDATE_NOW, NOW0 + 7 * HOUR, &msg) ==
	       FS_INTEL_REFUSED, "10 -> 1 entries: REFUSED (%s)", msg);
	g_free (msg);
	text = get_file ("feodo.list");
	s = fs_intel_source_state ("feodo");
	CHECK (g_strcmp0 (text, list_before) == 0 && s && s->refused != NULL &&
	       s->entries == 10,
	       "a refused copy keeps the previous list and records why");
	CHECK (s && s->refused_override == FS_INTEL_UPDATE_ACCEPT_SHRINK,
	       "a shrink refusal records that --accept-shrink lets it in "
	       "(the page's \"Accept smaller list\"; got %u)",
	       s ? s->refused_override : 99);
	fs_intel_source_state_free (s);
	g_free (text);
	serve ("feodo", "# nothing listed today\n");
	CHECK (update1 (c, "feodo", FS_INTEL_UPDATE_NOW, NOW0 + 7 * HOUR, &msg) ==
	       FS_INTEL_REFUSED, "an empty list after 10 entries: REFUSED (%s)",
	       msg);
	g_free (msg);
	serve ("feodo", "<html><body>Service unavailable</body></html>\n"
	       "<p>try later</p>\n");
	CHECK (update1 (c, "feodo", FS_INTEL_UPDATE_NOW, NOW0 + 7 * HOUR, &msg) ==
	       FS_INTEL_REFUSED, "an HTML error page: REFUSED (%s)", msg);
	g_free (msg);
	s = fs_intel_source_state ("feodo");
	CHECK (s && s->refused != NULL && s->refused_override == 0,
	       "a body that is not a list: nothing overrides it (got %u)",
	       s ? s->refused_override : 99);
	fs_intel_source_state_free (s);
	serve_error ("feodo", "Could not download: SSL certificate problem|x\n"
	             "INJECTED 2026-01-01T00:00:00Z | forged | line");
	CHECK (update1 (c, "feodo", FS_INTEL_UPDATE_NOW, NOW0 + 7 * HOUR, &msg) ==
	       FS_INTEL_FAILED && strstr (msg, "SSL certificate") &&
	       !strstr (msg, "INJECTED"),
	       "a failed download: FAILED, the tool's first line only (%s)", msg);
	g_free (msg);
	text = get_file ("feodo.list");
	s = fs_intel_source_state ("feodo");
	CHECK (g_strcmp0 (text, list_before) == 0 && s && s->last_error &&
	       strstr (s->last_error, "SSL") && s->entries == 10,
	       "after all of them the 10-entry list is still the one stored");
	fs_intel_source_state_free (s);
	g_free (text);
	serve ("feodo", body1);
	CHECK (update1 (c, "feodo", FS_INTEL_UPDATE_NOW |
	                FS_INTEL_UPDATE_ACCEPT_SHRINK, NOW0 + 8 * HOUR, &msg) ==
	       FS_INTEL_UPDATED, "--accept-shrink lets the shrink in (%s)", msg);
	g_free (msg);
	s = fs_intel_source_state ("feodo");
	text = get_file ("feodo.state");
	CHECK (s && s->refused == NULL && s->refused_override == 0 &&
	       text && !strstr (text, "refused-override"),
	       "an accepted copy clears the refusal and its override");
	fs_intel_source_state_free (s);
	g_free (text);

	/* The audit: one line per attempted feed, escaped. */
	a = audit_text ();
	CHECK (count_substr (a, "| intel-update |") == 8,
	       "one audit line per attempted download (got %u)",
	       count_substr (a, "| intel-update |"));
	CHECK (strstr (a, "certificate problem\\|x") != NULL &&
	       strstr (a, "INJECTED") == NULL &&
	       count_substr (a, "\n") == count_substr (a, "Z | intel-"),
	       "audit: '|' escaped, the forged second line never written");
	g_free (a);

	g_free (body10);
	g_free (body1);
	g_free (list_before);
	fs_intel_config_free (c);
}

/* A list that suddenly covers far more is refused with the override
 * that lets it in (the page's "Accept larger list"), and that flag, not
 * the shrink one, does. */
static void
test_update_grew (void)
{
	FsIntelConfig *c = conf_with ("cins-army");
	FsIntelSourceState *s;
	gchar *msg = NULL;

	fresh_store ();
	net_reset ();
	serve ("cins-army", "45.0.0.0/16\n");
	CHECK (update1 (c, "cins-army", 0, NOW0, NULL) == FS_INTEL_UPDATED,
	       "grew: a /16 is stored");
	serve ("cins-army", "45.0.0.0/10\n46.0.0.0/10\n");
	CHECK (update1 (c, "cins-army", FS_INTEL_UPDATE_NOW |
	                FS_INTEL_UPDATE_ACCEPT_SHRINK, NOW0 + HOUR, &msg) ==
	       FS_INTEL_REFUSED, "grew: two /10s after a /16: REFUSED, also "
	       "with --accept-shrink (%s)", msg);
	g_free (msg);
	s = fs_intel_source_state ("cins-army");
	CHECK (s && s->refused != NULL &&
	       s->refused_override == FS_INTEL_UPDATE_ACCEPT_COVERAGE,
	       "grew: the refusal records --accept-coverage as its override "
	       "(got %u)", s ? s->refused_override : 99);
	fs_intel_source_state_free (s);
	CHECK (update1 (c, "cins-army", FS_INTEL_UPDATE_NOW |
	                FS_INTEL_UPDATE_ACCEPT_COVERAGE, NOW0 + 2 * HOUR,
	                &msg) == FS_INTEL_UPDATED,
	       "grew: --accept-coverage lets it in (%s)", msg);
	g_free (msg);
	fs_intel_config_free (c);
}

static void
test_update_dates (void)
{
	FsIntelConfig *c = conf_with ("spamhaus-drop");
	gchar *b, *msg = NULL, *st_text;
	FsIntelSourceState *s;
	const gint64 day = 24 * HOUR;

	fresh_store ();
	net_reset ();
	b = drop_body ("45.1.0.0/24 45.2.0.0/24", NOW0 - day);
	serve ("spamhaus-drop", b);
	g_free (b);
	CHECK (update1 (c, "spamhaus-drop", 0, NOW0, NULL) == FS_INTEL_UPDATED,
	       "Spamhaus: a copy dated yesterday is stored");
	s = fs_intel_source_state ("spamhaus-drop");
	CHECK (s && s->content_date == NOW0 - day, "its content date is kept");
	fs_intel_source_state_free (s);
	CHECK (!fs_intel_source_is_stale (c, "spamhaus-drop", NOW0 + 6 * day) &&
	       fs_intel_source_is_stale (c, "spamhaus-drop", NOW0 + 6 * day + 1),
	       "stale 7 intervals after the content date, not the download");

	/* A copy dated in the future is refused, also with --accept-shrink
	 * (it would make every honest copy after it a rollback). */
	b = drop_body ("45.1.0.0/24 45.2.0.0/24 45.3.0.0/24", NOW0 + 400 * day);
	serve ("spamhaus-drop", b);
	g_free (b);
	CHECK (update1 (c, "spamhaus-drop", FS_INTEL_UPDATE_NOW |
	                FS_INTEL_UPDATE_ACCEPT_SHRINK, NOW0 + day, &msg) ==
	       FS_INTEL_REFUSED && strstr (msg, "future"),
	       "a content date a year ahead: REFUSED (%s)", msg);
	g_free (msg);
	b = drop_body ("45.1.0.0/24 45.2.0.0/24 45.3.0.0/24", NOW0 + day + 3600);
	serve ("spamhaus-drop", b);
	g_free (b);
	CHECK (update1 (c, "spamhaus-drop", FS_INTEL_UPDATE_NOW, NOW0 + day,
	                &msg) == FS_INTEL_UPDATED,
	       "an hour of clock skew is not \"the future\" (%s)", msg);
	g_free (msg);

	/* Rollback */
	b = drop_body ("45.1.0.0/24 45.2.0.0/24 45.3.0.0/24 45.4.0.0/24",
	               NOW0 - 2 * day);
	serve ("spamhaus-drop", b);
	g_free (b);
	CHECK (update1 (c, "spamhaus-drop", FS_INTEL_UPDATE_NOW, NOW0 + 2 * day,
	                &msg) == FS_INTEL_REFUSED,
	       "an older content date than ours: REFUSED (%s)", msg);
	g_free (msg);

	/* A stored date that is in the future (the clock was put back, or
	 * an older build stored it) is forgotten, not a permanent block. */
	st_text = get_file ("spamhaus-drop.state");
	{
		GKeyFile *kf = g_key_file_new ();
		gchar *data;

		g_key_file_load_from_data (kf, st_text, -1, G_KEY_FILE_KEEP_COMMENTS,
		                           NULL);
		g_key_file_set_value (kf, "state", "history-content-date",
		                      "2000000000");
		data = g_key_file_to_data (kf, NULL, NULL);
		put_file ("spamhaus-drop.state", data);
		g_free (data);
		g_key_file_free (kf);
	}
	b = drop_body ("45.1.0.0/24 45.2.0.0/24 45.3.0.0/24 45.5.0.0/24",
	               NOW0 + 2 * day);
	serve ("spamhaus-drop", b);
	g_free (b);
	CHECK (update1 (c, "spamhaus-drop", FS_INTEL_UPDATE_NOW, NOW0 + 3 * day,
	                &msg) == FS_INTEL_UPDATED,
	       "a stored content date in 2033 does not refuse an honest copy "
	       "forever (%s)", msg);
	g_free (msg);
	g_free (st_text);
	fs_intel_config_free (c);
}

static void
test_update_isolation_and_crash (void)
{
	FsIntelConfig *c = conf_with ("feodo dshield blocklist-de");
	gchar *b1 = plain_list (12, 0x2e000000u);
	gchar *b2 = plain_list (14, 0x2e000000u);
	gchar *old_state, *old_list, *list_now, *msg = NULL;
	GPtrArray *rs;

	fresh_store ();
	net_reset ();
	serve ("feodo", b1);
	serve ("dshield", "Start\tEnd\tNetblock\n45.9.0.0\t45.9.0.255\t24\n");
	serve ("blocklist-de", b1);
	rs = fs_intel_update (c, NULL, 0, NOW0);
	CHECK (rs->len == 3 &&
	       result_for (rs, "feodo")->outcome == FS_INTEL_UPDATED &&
	       result_for (rs, "dshield")->outcome == FS_INTEL_UPDATED &&
	       result_for (rs, "blocklist-de")->outcome == FS_INTEL_UPDATED &&
	       strcmp (((FsIntelUpdateResult *) rs->pdata[0])->id, "feodo") == 0 &&
	       strcmp (((FsIntelUpdateResult *) rs->pdata[1])->id, "dshield") == 0,
	       "three feeds: three results, in config order");
	g_ptr_array_unref (rs);

	/* One fails, one is garbage, one is fine: each stands alone. */
	serve_error ("feodo", "Could not resolve host");
	serve ("dshield", "\x01\x02 not a list at all\nreally not\n");
	serve ("blocklist-de", b2);
	rs = fs_intel_update (c, NULL, FS_INTEL_UPDATE_NOW, NOW0 + HOUR);
	CHECK (result_for (rs, "feodo")->outcome == FS_INTEL_FAILED &&
	       result_for (rs, "dshield")->outcome == FS_INTEL_REFUSED &&
	       result_for (rs, "blocklist-de")->outcome == FS_INTEL_UPDATED &&
	       result_for (rs, "blocklist-de")->entries == 14 &&
	       result_for (rs, "feodo")->entries == 12,
	       "per-feed isolation: FAILED, REFUSED and UPDATED side by side");
	g_ptr_array_unref (rs);
	CHECK (has_file ("feodo.list") && has_file ("dshield.list"),
	       "the failed and the refused feed keep their lists");

	/* A crash between writing the new list and its state: the state
	 * still describes the old copy.  Fetching the old bytes again must
	 * store them again, not say "unchanged" over a list that is not
	 * theirs. */
	serve ("blocklist-de", b1);
	CHECK (update1 (c, "blocklist-de", FS_INTEL_UPDATE_NOW, NOW0 + 2 * HOUR,
	                NULL) == FS_INTEL_UPDATED, "back to the 12-entry copy");
	old_state = get_file ("blocklist-de.state");
	old_list = get_file ("blocklist-de.list");
	serve ("blocklist-de", b2);
	CHECK (update1 (c, "blocklist-de", FS_INTEL_UPDATE_NOW, NOW0 + 3 * HOUR,
	                NULL) == FS_INTEL_UPDATED, "the 14-entry copy stored");
	put_file ("blocklist-de.state", old_state);   /* the crash */
	serve ("blocklist-de", b1);
	CHECK (update1 (c, "blocklist-de", FS_INTEL_UPDATE_NOW, NOW0 + 4 * HOUR,
	                &msg) == FS_INTEL_UPDATED,
	       "crash between list and state: the old bytes are stored again, "
	       "not \"unchanged\" (%s)", msg);
	g_free (msg);
	list_now = get_file ("blocklist-de.list");
	CHECK (g_strcmp0 (list_now, old_list) == 0,
	       "and the list on disk is the copy the state describes");
	g_free (list_now);

	/* A damaged state file: the update still works and rebuilds it. */
	put_file ("feodo.state", "[state]\nfetched-at=yesterday\n\x01\n");
	serve ("feodo", b2);
	CHECK (update1 (c, "feodo", FS_INTEL_UPDATE_NOW, NOW0 + 5 * HOUR, &msg) ==
	       FS_INTEL_UPDATED,
	       "a damaged state file is rebuilt by the next update (%s)", msg);
	g_free (msg);
	{
		FsIntelSourceState *s = fs_intel_source_state ("feodo");

		CHECK (s && s->entries == 14 && s->history.n == 1,
		       "... with a fresh history");
		fs_intel_source_state_free (s);
	}
	put_file ("feodo.state", "[state]\nentries=99999999999999999999\n");
	CHECK (fs_intel_source_state ("feodo") == NULL,
	       "a state with an out-of-range number is not trusted");
	/* A stray temporary from a crashed write never matters. */
	put_file (".feodo.list.0badf00d.tmp", "0.0.0.0/0\n");
	{
		FsRangeSet *set = fs_intel_source_load ("feodo", NULL);

		CHECK (set && !fs_range_set_contains_text (set, "8.8.8.8"),
		       "a stray temporary list is never loaded");
		fs_range_set_free (set);
	}

	g_free (old_state);
	g_free (old_list);
	g_free (b1);
	g_free (b2);
	fs_intel_config_free (c);
}

/* ---- stored lists ----------------------------------------------------- */

static void
expect_tampered (const gchar *text, const gchar *what)
{
	GError *e = NULL;
	FsRangeSet *set;

	put_file ("local-t.list", text);
	set = fs_intel_source_load ("local-t", &e);
	CHECK (set == NULL && g_error_matches (e, FS_INTEL_ERROR,
	                                       FS_INTEL_ERR_TAMPERED),
	       "tampered list: %s -> TAMPERED (%s)", what,
	       e ? e->message : "loaded");
	fs_range_set_free (set);
	g_clear_error (&e);
}

static void
test_stored_lists (void)
{
	FsIntelConfig *c = fs_intel_config_new ();
	GError *e = NULL;
	FsRangeSet *set;
	gchar *id, *p;
	GString *many;

	fresh_store ();
	g_free (fs_intel_dir (NULL));

	set = fs_intel_source_load ("local-none", &e);
	CHECK (set == NULL && g_error_matches (e, FS_INTEL_ERROR,
	                                       FS_INTEL_ERR_STORE),
	       "a missing list is a STORE error");
	g_clear_error (&e);
	CHECK (fs_intel_source_load ("../etc/passwd", &e) == NULL &&
	       g_error_matches (e, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID),
	       "an id that is a path is refused");
	g_clear_error (&e);

	expect_tampered ("45.0.0.1\nnot an address\n", "a line that is not one");
	expect_tampered ("45.0.0.1 # trailing words\n", "junk after an entry");
	expect_tampered ("0.0.0.0/0\n", "the whole IPv4 internet");
	expect_tampered ("::/0\n", "the whole IPv6 internet");
	expect_tampered ("2000::/3\n", "all of global unicast IPv6");
	expect_tampered ("4.0.0.0/6\n", "a /6 (2^26 addresses)");
	put_file_len ("local-t.list", "45.0.0.1\n45.0.0.2\0\n", 19);
	set = fs_intel_source_load ("local-t", &e);
	CHECK (set == NULL && g_error_matches (e, FS_INTEL_ERROR,
	                                       FS_INTEL_ERR_TAMPERED),
	       "tampered list: a NUL byte -> TAMPERED");
	fs_range_set_free (set);
	g_clear_error (&e);
	many = g_string_new (NULL);
	for (guint i = 0; i < 200300; i++)
		g_string_append_printf (many, "%u.%u.%u.1\n", 50 + i / 65536,
		                        (i / 256) % 256, i % 256);
	expect_tampered (many->str, "200,300 intervals");
	g_string_free (many, TRUE);

	/* What the parser let in must load again: eight adjacent /10s
	 * (each at the span floor) are stored as one /7, at the coverage
	 * cap exactly. */
	put_file ("local-t.list", "4.0.0.0/7\n2001:db8::/32\n");
	set = fs_intel_source_load ("local-t", &e);
	CHECK (set != NULL, "merged neighbours at the coverage cap load (%s)",
	       e ? e->message : "ok");
	fs_range_set_free (set);
	g_clear_error (&e);
	put_file ("local-t.list", "10.0.0.0/8\n45.0.0.1\n");
	set = fs_intel_source_load ("local-t", &e);
	CHECK (set != NULL && fs_range_set_count4 (set) == 1 &&
	       !fs_range_set_contains_text (set, "10.1.1.1"),
	       "protected space in a stored list is taken out, never blocked");
	fs_range_set_free (set);
	g_clear_error (&e);
	p = store_path ("local-t.list");
	g_unlink (p);
	set = symlink ("/etc/hosts", p) == 0
	      ? fs_intel_source_load ("local-t", &e) : NULL;
	CHECK (set == NULL && g_error_matches (e, FS_INTEL_ERROR,
	                                       FS_INTEL_ERR_STORE),
	       "a list that is a symlink is refused");
	g_clear_error (&e);
	g_unlink (p);
	g_free (p);

	/* Import */
	id = import_text (c, "Office blocks", "ip,comment\n"
	                  "\"45.6.0.1\",scanner\n45.6.1.0/24,range\n"
	                  "2001:db8:bad::/48\n10.0.0.1\n", FS_INTEL_DIR_OUT, &e);
	CHECK (g_strcmp0 (id, "local-office-blocks") == 0 &&
	       fs_intel_config_list (c, id) != NULL &&
	       fs_intel_config_list (c, id)->enabled &&
	       fs_intel_config_list (c, id)->dir == FS_INTEL_DIR_OUT,
	       "import: a CSV becomes local-<slug>, enabled, its direction (%s)",
	       e ? e->message : "ok");
	g_clear_error (&e);
	set = fs_intel_source_load (id, NULL);
	CHECK (set && fs_range_set_contains_text (set, "45.6.1.200") &&
	       fs_range_set_contains_text (set, "2001:db8:bad::1") &&
	       !fs_range_set_contains_text (set, "10.0.0.1"),
	       "import: entries stored, protected space left out");
	fs_range_set_free (set);
	g_free (id);
	id = import_text (c, "office  BLOCKS", "45.7.0.1\n", FS_INTEL_DIR_IN, &e);
	set = fs_intel_source_load (id, NULL);
	CHECK (g_strcmp0 (id, "local-office-blocks") == 0 && c->lists->len == 1 &&
	       set && fs_range_set_count4 (set) == 1 &&
	       !fs_range_set_contains_text (set, "45.6.0.1") &&
	       fs_intel_config_list (c, id)->dir == FS_INTEL_DIR_IN,
	       "import: the same name again replaces the list");
	fs_range_set_free (set);
	g_free (id);
	/* A different name with the same slug never overwrites the list. */
	{
		static const gchar *const others[] = {
			"office-blocks", "Office: blocks!", "OFFICE_BLOCKS"
		};

		for (guint i = 0; i < G_N_ELEMENTS (others); i++) {
			id = import_text (c, others[i], "46.0.0.1\n",
			                  FS_INTEL_DIR_BOTH, &e);
			set = fs_intel_source_load ("local-office-blocks", NULL);
			CHECK (id == NULL &&
			       g_error_matches (e, FS_INTEL_ERROR,
			                        FS_INTEL_ERR_INVALID) &&
			       strstr (e->message, "office  BLOCKS") != NULL &&
			       c->lists->len == 1 && set != NULL &&
			       fs_range_set_contains_text (set, "45.7.0.1") &&
			       !fs_range_set_contains_text (set, "46.0.0.1") &&
			       g_strcmp0 (fs_intel_config_list (c,
			                  "local-office-blocks")->name,
			                  "office  BLOCKS") == 0 &&
			       fs_intel_config_list (c, "local-office-blocks")->dir ==
			       FS_INTEL_DIR_IN,
			       "import: \"%s\" (the same slug, another name) is "
			       "refused and the list is untouched (%s)", others[i],
			       e ? e->message : "imported");
			fs_range_set_free (set);
			g_clear_error (&e);
			g_free (id);
		}
	}
	{
		/* Two long names that differ only after the slug's 34
		 * characters. */
		FsIntelConfig *c2 = fs_intel_config_new ();
		gchar *id2;

		id = import_text (c2, "Customer blocklist from the SOC team 2025",
		                  "45.0.0.1\n", FS_INTEL_DIR_IN, NULL);
		id2 = import_text (c2, "Customer blocklist from the SOC team 2026",
		                   "46.0.0.1\n", FS_INTEL_DIR_IN, &e);
		set = id ? fs_intel_source_load (id, NULL) : NULL;
		CHECK (id != NULL && id2 == NULL && e != NULL &&
		       c2->lists->len == 1 && set != NULL &&
		       fs_range_set_contains_text (set, "45.0.0.1") &&
		       !fs_range_set_contains_text (set, "46.0.0.1") &&
		       g_strcmp0 (fs_intel_config_list (c2, id)->name,
		                  "Customer blocklist from the SOC team 2025") == 0,
		       "import: two long names cut to the same id: the second is "
		       "refused, the first list keeps its name and addresses "
		       "(%s)", id ? id : "?");
		g_clear_error (&e);
		fs_range_set_free (set);
		if (id != NULL)
			fs_intel_config_remove (c2, id, NULL);
		g_free (id);
		g_free (id2);
		fs_intel_config_free (c2);
	}
	/* The same name in another case or spacing still replaces it. */
	id = import_text (c, "  Office Blocks ", "45.7.0.2\n", FS_INTEL_DIR_IN,
	                  &e);
	set = fs_intel_source_load ("local-office-blocks", NULL);
	CHECK (g_strcmp0 (id, "local-office-blocks") == 0 && e == NULL &&
	       set != NULL && fs_range_set_contains_text (set, "45.7.0.2") &&
	       c->lists->len == 1,
	       "import: the same name in another case and spacing replaces it "
	       "(%s)", e ? e->message : "ok");
	g_clear_error (&e);
	fs_range_set_free (set);
	g_free (id);
	id = import_text (c, "Empty", "ip\n# nothing\n", FS_INTEL_DIR_IN, &e);
	CHECK (id == NULL && e != NULL && c->lists->len == 1,
	       "import: a file with no address is refused");
	g_clear_error (&e);
	id = import_text (c, "Wide", "0.0.0.0/1\n1.0.0.0/2\n", FS_INTEL_DIR_IN,
	                  &e);
	CHECK (id == NULL && e != NULL, "import: the parse guards apply (%s)",
	       e ? e->message : "imported");
	g_clear_error (&e);
	{
		gchar *fifo = g_build_filename (eng_base, "fifo", NULL);

		mkfifo (fifo, 0600);
		CHECK (!fs_intel_import_list (c, fifo, "F", FS_INTEL_DIR_IN, NULL,
		                              NULL, &e) && e != NULL,
		       "import: a FIFO is refused without waiting");
		g_clear_error (&e);
		CHECK (!fs_intel_import_list (c, eng_base, "D", FS_INTEL_DIR_IN,
		                              NULL, NULL, &e) && e != NULL,
		       "import: a directory is refused");
		g_clear_error (&e);
		g_unlink (fifo);
		g_free (fifo);
	}
	/* Removing a list deletes its files. */
	CHECK (has_file ("local-office-blocks.list") &&
	       fs_intel_config_remove (c, "local-office-blocks", NULL) &&
	       !has_file ("local-office-blocks.list") &&
	       !has_file ("local-office-blocks.state") && c->lists->len == 0,
	       "remove: the list and its state are deleted");
	fs_intel_config_free (c);
}

/* "h:l" as eight groups of an IPv6 address. */
static void
append_v6 (GString *s, guint64 hi, guint64 lo)
{
	g_string_append_printf (s, "%x:%x:%x:%x:%x:%x:%x:%x",
	                        (guint) (hi >> 48) & 0xffff,
	                        (guint) (hi >> 32) & 0xffff,
	                        (guint) (hi >> 16) & 0xffff, (guint) hi & 0xffff,
	                        (guint) (lo >> 48) & 0xffff,
	                        (guint) (lo >> 32) & 0xffff,
	                        (guint) (lo >> 16) & 0xffff, (guint) lo & 0xffff);
}

/* What the parser accepts at a coverage cap must load again: the
 * engine re-checks a stored list with the parser's own count.  128
 * IPv6 ranges, none aligned on a /64, each 2^35 /64s as the parser
 * counts them -- 2^42 in all, the cap exactly.  A count of the
 * engine's own (end.hi - start.hi + 1) made each one 2^35 + 1, so the
 * stored copy read as "tampered" and every build failed, healthy lists
 * included, while every update reported "Updated". */
static void
test_cover6_at_cap (void)
{
	FsIntelConfig *c = fs_intel_config_new ();
	const gchar *url = "https://feed.example/wide-v6.txt";
	FsFeedParseStats st = { 0 };
	FsIntelRuleset *rs;
	FsRangeSet *set;
	GString *body = g_string_new ("# 128 unaligned IPv6 ranges\n");
	GError *e = NULL;
	gchar *id = NULL, *msg = NULL;

	fresh_store ();
	net_reset ();
	for (guint i = 0; i < 128; i++) {
		guint64 h = G_GUINT64_CONSTANT (0x2400000000000000) +
		            ((guint64) i << 36);

		append_v6 (body, h, G_GUINT64_CONSTANT (0x8000000000000000));
		g_string_append_c (body, '-');
		append_v6 (body, h + (G_GUINT64_CONSTANT (1) << 35),
		           G_GUINT64_CONSTANT (0x7fffffffffffffff));
		g_string_append_c (body, '\n');
	}
	set = fs_feed_parse (body->str, body->len, FS_FEED_FMT_PLAIN, &st, &e);
	CHECK (set != NULL && st.cover6_64 == FS_FEED_MAX_COVER6_64 &&
	       fs_feed_cover6_64 (set) == FS_FEED_MAX_COVER6_64,
	       "cover6 cap: the parser accepts 128 unaligned ranges at the "
	       "cap exactly (%" G_GUINT64_FORMAT ")", st.cover6_64);
	fs_range_set_free (set);
	g_clear_error (&e);

	fs_intel_config_add_custom (c, "Wide v6", url, FS_FEED_FMT_PLAIN,
	                            FS_INTEL_DIR_IN, &id, NULL);
	g_hash_table_replace (net.bodies, g_strdup (url), g_strdup (body->str));
	CHECK (update1 (c, id, 0, NOW0, &msg) == FS_INTEL_UPDATED,
	       "cover6 cap: the update stores it (%s)", msg);
	g_free (msg);
	set = fs_intel_source_load (id, &e);
	CHECK (set != NULL && fs_range_set_count6 (set) == 128,
	       "cover6 cap: the stored copy loads again, not TAMPERED (%s)",
	       e ? e->message : "ok");
	fs_range_set_free (set);
	g_clear_error (&e);
	g_free (import_text (c, "Healthy", "45.0.0.1\n", FS_INTEL_DIR_IN, NULL));
	rs = fs_intel_build (c, NULL, NULL, &e);
	CHECK (rs != NULL && rs->sets->len == 2 &&
	       fs_intel_ruleset_count6 (rs) == 128,
	       "cover6 cap: the build holds it and the healthy list (%s)",
	       e ? e->message : "ok");
	fs_intel_ruleset_free (rs);
	g_clear_error (&e);
	/* One /64 more is over the cap, in the parser and on load alike. */
	g_string_append (body, "2600::/64\n");
	set = fs_feed_parse (body->str, body->len, FS_FEED_FMT_PLAIN, &st, &e);
	CHECK (set == NULL && e != NULL,
	       "cover6 cap: one /64 more is refused by the parser");
	g_clear_error (&e);
	{
		gchar *name = g_strconcat (id, ".list", NULL);
		gchar *text = get_file (name);
		gchar *more = g_strconcat (text, "2600::/64\n", NULL);

		put_file (name, more);
		set = fs_intel_source_load (id, &e);
		CHECK (set == NULL && g_error_matches (e, FS_INTEL_ERROR,
		                                       FS_INTEL_ERR_TAMPERED),
		       "cover6 cap: ... and a stored copy one /64 over it is "
		       "TAMPERED");
		fs_range_set_free (set);
		g_clear_error (&e);
		g_free (more);
		g_free (text);
		g_free (name);
	}
	g_string_free (body, TRUE);
	g_free (id);
	fs_intel_config_free (c);
}

/* ---- the build -------------------------------------------------------- */

static void
test_build (void)
{
	FsIntelConfig *c = conf_with ("feodo dshield");
	FsHostNet *h = host_fixture ();
	FsIntelRuleset *rs;
	GPtrArray *notes = NULL;
	GError *e = NULL;
	gchar *id, *text;

	fresh_store ();
	net_reset ();
	fs_intel_config_set_dir (c, "feodo", FS_INTEL_DIR_BOTH, NULL);
	fs_intel_config_set_dir (c, "dshield", FS_INTEL_DIR_IN, NULL);
	serve ("feodo", "203.0.113.5\n203.0.113.9\n198.51.100.53\n"
	       "192.0.2.22\n198.51.100.80\n45.0.0.1\n45.0.0.7\n"
	       "2001:db8:5::5\n2001:db8:6::/48\n");
	g_ptr_array_unref (fs_intel_update (c, NULL, 0, NOW0));
	id = import_text (c, "Mine", "203.0.113.1\n45.8.0.0/30\n"
	                  "198.51.100.7\n", FS_INTEL_DIR_OUT, NULL);
	fs_range_set_add_text (c->exceptions, "45.0.0.7");
	fs_range_set_add_text (c->exceptions, "64:ff9b::2d08:2");
	fs_range_set_normalize (c->exceptions);

	rs = fs_intel_build (c, h, &notes, &e);
	text = rs ? ruleset_text (rs) : g_strdup (e ? e->message : "?");
	CHECK (rs != NULL && g_strcmp0 (text,
		"[feodo both]\n"
		"45.0.0.1\n"
		"203.0.113.9\n"
		"64:ff9b::2d00:1\n"
		"64:ff9b::cb00:7109\n"
		"2001:db8:6::/48\n"
		"[local-mine out]\n"
		"45.8.0.0/30\n"
		"198.51.100.7\n"
		"64:ff9b::2d08:0/127\n"
		"64:ff9b::2d08:3\n"
		"64:ff9b::c633:6407\n") == 0,
	       "build (golden): own/on-link/gateway/resolver/session/update "
	       "host and exceptions subtracted; v4 of out/both sets mapped "
	       "into 64:ff9b::/96; a list not downloaded has no set; got\n%s",
	       text);
	CHECK (notes_have (notes, "dshield") || notes_have (notes, "DShield"),
	       "notes: a list never downloaded is named");
	CHECK (notes_have (notes, "Kept reachable: 203.0.113.5, 2001:db8:5::5 "
	                          "(this computer's own address)") &&
	       notes_have (notes, "(a DNS server in use)") &&
	       notes_have (notes, "192.0.2.22 (an SSH session to this computer)") &&
	       notes_have (notes, "(a feed's download server or proxy)") &&
	       notes_have (notes, "203.0.113.1 (a default gateway), although "
	                          "Mine lists it") &&
	       notes_have (notes, "Not blocked, by exception: 45.0.0.7"),
	       "notes: every kind of address kept, and the list that named it");
	if (notes != NULL)
		for (guint i = 0; i < notes->len; i++)
			g_print ("      note: %s\n", (gchar *) notes->pdata[i]);
	if (rs != NULL) {
		/* Windows Firewall has no "allow wins": a block rule beats any
		 * allow rule, so an exception only holds because the build
		 * subtracted it before any rule was written.  The rules the
		 * Windows backend would write never name a subtracted address. */
		FsIntelWinPlan *plan = fs_intelwin_plan (rs, "g00000001",
		                                         FS_INTELWIN_MAX_TOKENS,
		                                         FS_INTELWIN_MAX_CHARS);
		FsRangeSet *all = fs_range_set_new ();
		gboolean parsed = plan != NULL && plan->rules->len > 1;

		for (guint i = 0; plan != NULL && i < plan->rules->len; i++) {
			const FsIntelWinRule *r = plan->rules->pdata[i];

			if (r->family != FS_AF_NONE &&
			    !fs_intelwin_parse_remote (r->remote, all))
				parsed = FALSE;
		}
		fs_range_set_normalize (all);
		CHECK (parsed &&
		       fs_range_set_contains_text (all, "45.0.0.1") &&
		       !fs_range_set_contains_text (all, "45.0.0.7") &&
		       !fs_range_set_contains_text (all, "64:ff9b::2d08:2") &&
		       !fs_range_set_contains_text (all, "64:ff9b::2d00:7") &&
		       !fs_range_set_contains_text (all, "203.0.113.5") &&
		       !fs_range_set_contains_text (all, "192.0.2.22") &&
		       !fs_range_set_contains_text (all, "203.0.113.1"),
		       "build -> Windows rules: exceptions and kept addresses are "
		       "subtracted before any rule is written, so no Windows "
		       "block rule names them");
		fs_range_set_free (all);
		fs_intelwin_plan_free (plan);
	}
	g_free (text);
	g_clear_pointer (&notes, g_ptr_array_unref);
	fs_intel_ruleset_free (rs);
	g_clear_error (&e);

	/* No host at all: nothing but exceptions is taken out. */
	rs = fs_intel_build (c, NULL, NULL, &e);
	CHECK (rs && fs_range_set_contains_text (
	           fs_intel_ruleset_find (rs, "feodo")->ranges, "203.0.113.5"),
	       "build with host NULL: only exceptions are subtracted");
	fs_intel_ruleset_free (rs);

	/* Master switch off, or nothing on: the empty rule set. */
	c->enabled = FALSE;
	rs = fs_intel_build (c, h, NULL, &e);
	CHECK (rs && rs->sets->len == 0, "master switch off: empty rule set");
	fs_intel_ruleset_free (rs);
	c->enabled = TRUE;

	/* Includes: FireHOL level 1 with Feodo on. */
	fs_intel_config_enable_feed (c, "firehol-level1", 0, TRUE, NULL);
	rs = fs_intel_build (c, h, &notes, NULL);
	CHECK (notes_have (notes, "FireHOL level 1 already contains abuse.ch "
	                          "Feodo Tracker"),
	       "notes: a feed that already contains another one on");
	g_clear_pointer (&notes, g_ptr_array_unref);
	fs_intel_ruleset_free (rs);
	fs_intel_config_disable_feed (c, "firehol-level1", NULL);

	/* A tampered list fails the whole build. */
	put_file ("feodo.list", "0.0.0.0/0\n");
	rs = fs_intel_build (c, h, NULL, &e);
	CHECK (rs == NULL && g_error_matches (e, FS_INTEL_ERROR,
	                                      FS_INTEL_ERR_TAMPERED),
	       "a tampered stored list: the build fails (TAMPERED)");
	g_clear_error (&e);
	g_free (id);
	fs_hostnet_free (h);
	fs_intel_config_free (c);
}

static void
test_build_limits (void)
{
	FsIntelConfig *c = fs_intel_config_new ();
	FsIntelRuleset *rs;
	GError *e = NULL;
	gchar *a, *b, *x;

	fresh_store ();
	/* 2 x 160,000 intervals: over the 300,000 a rule set may hold. */
	a = plain_list (160000, 0x2d000000u);
	b = plain_list (160000, 0x2f000000u);
	g_free (import_text (c, "Big A", a, FS_INTEL_DIR_IN, NULL));
	g_free (import_text (c, "Big B", b, FS_INTEL_DIR_IN, NULL));
	rs = fs_intel_build (c, NULL, NULL, &e);
	CHECK (rs == NULL && g_error_matches (e, FS_INTEL_ERROR,
	                                      FS_INTEL_ERR_TOO_BIG) &&
	       strstr (e->message, "Big A (160,000)") &&
	       strstr (e->message, "Big B (160,000)"),
	       "320,000 intervals: TOO_BIG naming the largest sets (%s)",
	       e ? e->message : "built");
	g_clear_error (&e);
	fs_intel_ruleset_free (rs);
	/* One alone is fine; an out list doubles its intervals (NAT64). */
	fs_intel_config_set_enabled (c, "local-big-b", FALSE, NULL);
	fs_intel_config_set_dir (c, "local-big-a", FS_INTEL_DIR_OUT, NULL);
	rs = fs_intel_build (c, NULL, NULL, &e);
	CHECK (rs == NULL && g_error_matches (e, FS_INTEL_ERROR,
	                                      FS_INTEL_ERR_TOO_BIG),
	       "160,000 outbound intervals + their NAT64 copies: TOO_BIG");
	g_clear_error (&e);
	fs_intel_ruleset_free (rs);
	fs_intel_config_set_dir (c, "local-big-a", FS_INTEL_DIR_IN, NULL);
	rs = fs_intel_build (c, NULL, NULL, &e);
	CHECK (rs != NULL && fs_intel_ruleset_count4 (rs) == 160000,
	       "160,000 inbound intervals alone: built");
	fs_intel_ruleset_free (rs);
	g_clear_error (&e);
	g_free (a);
	g_free (b);
	fs_intel_config_remove (c, "local-big-a", NULL);
	fs_intel_config_remove (c, "local-big-b", NULL);

	/* 3 x 2^25 IPv4 addresses (each at its own cap): over 2^26. */
	g_free (import_text (c, "Wide A", "4.0.0.0/10\n4.64.0.0/10\n"
	                     "4.128.0.0/10\n4.192.0.0/10\n5.0.0.0/10\n"
	                     "5.64.0.0/10\n5.128.0.0/10\n5.192.0.0/10\n",
	                     FS_INTEL_DIR_IN, &e));
	g_clear_error (&e);
	g_free (import_text (c, "Wide B", "8.0.0.0/10\n8.64.0.0/10\n"
	                     "8.128.0.0/10\n8.192.0.0/10\n9.0.0.0/10\n"
	                     "9.64.0.0/10\n9.128.0.0/10\n9.192.0.0/10\n",
	                     FS_INTEL_DIR_IN, NULL));
	rs = fs_intel_build (c, NULL, NULL, &e);
	CHECK (rs != NULL, "2 x 2^25 = 2^26 addresses: at the limit, built");
	fs_intel_ruleset_free (rs);
	g_clear_error (&e);
	g_free (import_text (c, "Wide C", "12.0.0.0/10\n", FS_INTEL_DIR_IN,
	                     NULL));
	rs = fs_intel_build (c, NULL, NULL, &e);
	x = e ? e->message : "built";
	CHECK (rs == NULL && g_error_matches (e, FS_INTEL_ERROR,
	                                      FS_INTEL_ERR_TOO_BIG) &&
	       strstr (x, "Wide A (33,554,432)") != NULL,
	       "one /10 more: over 2^26 IPv4 addresses, TOO_BIG (%s)", x);
	g_clear_error (&e);
	fs_intel_ruleset_free (rs);
	fs_intel_config_free (c);
}

/* ---- the gate, the lifecycle and the state ---------------------------- */

static FsIntelState
state_of (const FsIntelConfig *c, gchar **detail)
{
	return fs_intel_state (&fake_backend, c, detail);
}

static void
test_gate (void)
{
	FsIntelConfig *c = fs_intel_config_new ();
	FsHostNet *h = host_fixture ();
	FsIntelOutcome *o;
	FsIntelRuleset *rs;
	GError *e = NULL;
	gchar *detail = NULL, *a, *digest1, *applied1;
	FsIntelSourceState *s;
	GHashTable *t;

	fresh_store ();
	net_reset ();
	kern_reset ();
	audit_reset ();
	g_free (import_text (c, "Gate", "45.0.0.1\n45.0.0.3\n2001:db8:6::/48\n",
	                     FS_INTEL_DIR_BOTH, NULL));
	CHECK (state_of (c, &detail) == FS_INTEL_STATE_NOT_LOADED,
	       "state: on, never applied, no table: not-loaded (%s)", detail);
	g_free (detail);
	rs = fs_intel_build (c, h, NULL, NULL);
	digest1 = fs_intel_ruleset_digest (rs);
	fs_intel_ruleset_free (rs);
	fs_intel_config_save (c, NULL);

	/* Hold */
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", "policy locked",
	                         &e);
	CHECK (o && o->result == FS_APPLY_DRY_RUN && o->held &&
	       g_strcmp0 (o->hold_reason, "policy locked") == 0 &&
	       kern.apply_calls == 0 && kern.counter_calls == 0 &&
	       !has_file ("applied.state"),
	       "hold: DRY_RUN, nothing reaches the backend, nothing recorded");
	fs_intel_outcome_free (o);

	/* No intel slots */
	o = fs_intel_apply_safe (&bare_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_FAILED &&
	       g_error_matches (e, FS_INTEL_ERROR, FS_INTEL_ERR_UNSUPPORTED),
	       "a backend without intel slots: FAILED, \"not available\"");
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	CHECK (fs_intel_state (&bare_backend, c, NULL) ==
	       FS_INTEL_STATE_UNSUPPORTED,
	       "state with no intel slots: unsupported");

	/* Success */
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_OK && kern.apply_calls == 1 &&
	       g_strcmp0 (kern.got_digest, digest1) == 0 &&
	       g_strcmp0 (o->digest, digest1) == 0 && o->sets == 1 &&
	       o->count4 == 2 && o->count6 == 3,
	       "apply: the backend gets exactly the built rule set (%s)",
	       e ? e->message : "ok");
	g_clear_error (&e);
	fs_intel_outcome_free (o);
	CHECK (state_of (c, &detail) == FS_INTEL_STATE_ENFORCED &&
	       strstr (detail, "1 list is enforced: Gate"),
	       "state: enforced (%s)", detail);
	g_free (detail);
	CHECK (fs_intel_applied_has ("local-gate") && !fs_intel_applied_has ("feodo")
	       && !fs_intel_applied_has ("bad id"),
	       "applied_has: only the sets in the applied rule set");
	applied1 = get_file ("applied.state");
	CHECK (applied1 && strstr (applied1, digest1) &&
	       strstr (applied1, "suspended=false") &&
	       strstr (applied1, "sets=local-gate;"),
	       "applied.state records digest, sets, not suspended (%s)",
	       applied1);

	/* Counters move; a failed apply must not carry them (the old table
	 * keeps counting), a successful one must. */
	counter_set (kern.counters, "local-gate", 5, 500);
	t = fs_intel_counters (&fake_backend);
	CHECK (((FsIntelCounter *) g_hash_table_lookup (t, "local-gate"))->packets == 5,
	       "counters: live 5");
	g_hash_table_unref (t);
	kern.mode = APPLY_FAIL;
	fs_range_set_add_text (c->exceptions, "45.0.0.3");
	fs_range_set_normalize (c->exceptions);
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	s = fs_intel_source_state ("local-gate");
	a = get_file ("applied.state");
	CHECK (o && o->result == FS_APPLY_FAILED && e != NULL &&
	       g_strcmp0 (a, applied1) == 0 && s && s->carried_packets == 0 &&
	       g_strcmp0 (kern.live_digest, digest1) == 0,
	       "a failed apply: FAILED, applied.state unchanged, counters not "
	       "carried (the old table still counts them)");
	CHECK (state_of (c, NULL) == FS_INTEL_STATE_ENFORCED,
	       "... and the old table is still enforced");
	g_free (a);
	fs_intel_source_state_free (s);
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	t = fs_intel_counters (&fake_backend);
	CHECK (((FsIntelCounter *) g_hash_table_lookup (t, "local-gate"))->packets == 5,
	       "counters after the failed apply: still 5, not 10");
	g_hash_table_unref (t);

	/* nft timed out after committing: the kernel decides. */
	kern.mode = APPLY_COMMITTED;
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	s = fs_intel_source_state ("local-gate");
	CHECK (o && o->result == FS_APPLY_OK && e == NULL &&
	       notes_have (o->notes, "timed out") &&
	       g_strcmp0 (kern.live_digest, o->digest) == 0 &&
	       s && s->carried_packets == 5 && s->carried_bytes == 500 &&
	       s->counted_since > 0,
	       "a timeout after nft committed: OK (the live digest is the new "
	       "one), counters carried once");
	CHECK (state_of (c, NULL) == FS_INTEL_STATE_ENFORCED,
	       "... and the state is enforced");
	fs_intel_source_state_free (s);
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	counter_set (kern.counters, "local-gate", 2, 20);
	t = fs_intel_counters (&fake_backend);
	CHECK (((FsIntelCounter *) g_hash_table_lookup (t, "local-gate"))->packets == 7 &&
	       ((FsIntelCounter *) g_hash_table_lookup (t, "local-gate"))->bytes == 520,
	       "counters: carried 5 + live 2 = 7 (blocked since the first "
	       "apply)");
	g_hash_table_unref (t);

	/* The backend says yes, the kernel says otherwise. */
	kern.mode = APPLY_LIE;
	fs_range_set_add_text (c->exceptions, "45.0.0.1");
	fs_range_set_normalize (c->exceptions);
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_FAILED,
	       "the backend reports success but the kernel holds the old "
	       "table: FAILED");
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	s = fs_intel_source_state ("local-gate");
	CHECK (s && s->carried_packets == 5,
	       "... and nothing is carried (got %" G_GUINT64_FORMAT ")",
	       s ? s->carried_packets : 0);
	fs_intel_source_state_free (s);

	/* The kernel cannot be read after the apply. */
	kern.mode = APPLY_FAIL;
	kern.live_unknown = TRUE;
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_FAILED,
	       "an error and an unreadable kernel: FAILED, never assumed");
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	kern.mode = APPLY_OK;
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_OK,
	       "success and an unreadable kernel: the backend's verdict stands");
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	CHECK (state_of (c, &detail) == FS_INTEL_STATE_UNKNOWN ||
	       (geteuid () != 0 && state_of (c, NULL) ==
	        FS_INTEL_STATE_NEEDS_ROOT),
	       "state: an unreadable listing is unknown, never not-loaded "
	       "(%s)", detail);
	g_free (detail);
	kern.live_unknown = FALSE;

	/* Someone flushed the ruleset. */
	kern.live = FS_INTEL_LIVE_ABSENT;
	CHECK (state_of (c, NULL) == FS_INTEL_STATE_NOT_LOADED,
	       "state: the table is gone (reboot, flush ruleset): not-loaded");
	kern.live = FS_INTEL_LIVE_PRESENT;
	g_free (kern.live_digest);
	kern.live_digest = g_strdup ("0123456789abcdef0123456789abcdef");
	CHECK (state_of (c, NULL) == FS_INTEL_STATE_DIFFERS,
	       "state: a table with another digest: differs");
	g_free (kern.live_digest);
	kern.live_digest = NULL;
	CHECK (state_of (c, NULL) == FS_INTEL_STATE_DIFFERS,
	       "state: a table with no digest: differs");

	/* Re-apply heals it; then the user stops the firewall. */
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	fs_intel_outcome_free (o);
	counter_set (kern.counters, "local-gate", 3, 30);
	CHECK (fs_intel_suspend (&fake_backend, "test", &e) &&
	       kern.live == FS_INTEL_LIVE_ABSENT && kern.clear_calls == 1,
	       "suspend: the table is removed");
	g_clear_error (&e);
	s = fs_intel_source_state ("local-gate");
	/* 5 carried by the committed apply, 2 by the apply the kernel
	 * could not confirm (it did replace the table), 3 now. */
	CHECK (s && s->carried_packets == 10,
	       "suspend carries the counters (10, got %" G_GUINT64_FORMAT ")",
	       s ? s->carried_packets : 0);
	fs_intel_source_state_free (s);
	CHECK (state_of (c, &detail) == FS_INTEL_STATE_SUSPENDED,
	       "state: suspended (%s)", detail);
	g_free (detail);
	CHECK (!fs_intel_applied_has ("local-gate"),
	       "applied_has: nothing while suspended");
	kern.live = FS_INTEL_LIVE_PRESENT;
	g_free (kern.live_digest);
	kern.live_digest = g_strdup (digest1);
	CHECK (state_of (c, NULL) == FS_INTEL_STATE_DIFFERS,
	       "state: suspended, but a table is back: differs");
	kern.live = FS_INTEL_LIVE_ABSENT;

	/* Start: resume re-applies through the gate (hold respected).  The
	 * user did start the firewall, so a held Start is not "suspended"
	 * (the firewall stopped): the lists are not loaded, and the held
	 * outcome says why. */
	kern.apply_calls = 0;
	o = fs_intel_resume (&fake_backend, "test", "audit-only testing mode",
	                     &e);
	CHECK (o && o->result == FS_APPLY_DRY_RUN && o->held &&
	       kern.apply_calls == 0 &&
	       state_of (c, &detail) == FS_INTEL_STATE_NOT_LOADED,
	       "resume under a hold: nothing applied, not-loaded, never "
	       "suspended (%s)", detail);
	g_free (detail);
	fs_intel_outcome_free (o);
	o = fs_intel_resume (&fake_backend, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_OK &&
	       state_of (c, NULL) == FS_INTEL_STATE_ENFORCED &&
	       fs_intel_applied_has ("local-gate"),
	       "resume: applied again, enforced (%s)", e ? e->message : "ok");
	fs_intel_outcome_free (o);
	g_clear_error (&e);

	/* Suspend when the tool fails: the kernel decides again. */
	kern.clear_ok = FALSE;
	CHECK (!fs_intel_suspend (&fake_backend, "test", &e) && e != NULL &&
	       state_of (c, NULL) == FS_INTEL_STATE_ENFORCED,
	       "suspend fails and the table is still there: FALSE, enforced");
	g_clear_error (&e);
	kern.live = FS_INTEL_LIVE_ABSENT;
	CHECK (fs_intel_suspend (&fake_backend, "test", &e) &&
	       state_of (c, NULL) == FS_INTEL_STATE_SUSPENDED,
	       "the tool complains but the table is gone: suspended");
	g_clear_error (&e);
	kern.clear_ok = TRUE;
	CHECK (fs_intel_suspend (&bare_backend, "test", &e),
	       "suspend without intel slots: a no-op");

	/* Turning everything off: the empty rule set has no table. */
	fs_intel_config_set_enabled (c, "local-gate", FALSE, NULL);
	kern.live = FS_INTEL_LIVE_PRESENT;
	g_free (kern.live_digest);
	kern.live_digest = g_strdup (digest1);
	CHECK (state_of (c, &detail) == FS_INTEL_STATE_DIFFERS,
	       "state: lists off but the table still loaded: differs, not off "
	       "(%s)", detail);
	g_free (detail);
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_OK && kern.got_sets == 0 &&
	       kern.live == FS_INTEL_LIVE_ABSENT,
	       "apply with nothing on: the empty rule set, expected ABSENT, OK "
	       "(%s)", e ? e->message : "ok");
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	CHECK (state_of (c, &detail) == FS_INTEL_STATE_OFF,
	       "state: off (%s)", detail);
	g_free (detail);
	kern.mode = APPLY_COMMITTED;
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_OK,
	       "empty rule set, a timeout, the table absent: OK");
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	kern.mode = APPLY_OK;

	/* The audit: one line per attempt. */
	a = audit_text ();
	CHECK (count_substr (a, "| intel-apply |") == 13 &&
	       count_substr (a, "result=held hold=policy locked") == 1 &&
	       count_substr (a, "| intel-suspend |") == 3 &&
	       strstr (a, "syntax error\\|line 7") != NULL &&
	       strstr (a, "second line") == NULL,
	       "audit: one intel-apply line per attempt (%u), held and failed "
	       "ones too, tool output escaped",
	       count_substr (a, "| intel-apply |"));
	g_free (a);

	g_free (applied1);
	g_free (digest1);
	fs_hostnet_free (h);
	fs_intel_config_free (c);
}

static void
test_gate_hostile (void)
{
	FsIntelConfig *c = conf_with ("feodo");
	FsHostNet *h = host_fixture ();
	FsIntelOutcome *o;
	GError *e = NULL;
	gchar *detail = NULL;

	fresh_store ();
	net_reset ();
	kern_reset ();
	serve ("feodo", "45.0.0.1\n");
	g_ptr_array_unref (fs_intel_update (c, NULL, 0, NOW0));
	fs_intel_config_save (c, NULL);
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, NULL);
	fs_intel_outcome_free (o);

	/* A tampered list: the build fails, the kernel keeps its table. */
	put_file ("feodo.list", "0.0.0.0/1\n");
	kern.apply_calls = 0;
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o == NULL && g_error_matches (e, FS_INTEL_ERROR,
	                                     FS_INTEL_ERR_TAMPERED) &&
	       kern.apply_calls == 0 && state_of (c, NULL) ==
	       FS_INTEL_STATE_ENFORCED,
	       "tampered list: NULL + TAMPERED, the backend is never called, "
	       "the old table stays enforced");
	g_clear_error (&e);
	g_ptr_array_unref (fs_intel_update (c, NULL, FS_INTEL_UPDATE_NOW,
	                                    NOW0 + HOUR));

	/* A corrupt intel.conf: no state claim, no apply on Start. */
	put_file ("intel.conf", "[feed feodo]\nenabled=maybe\n");
	CHECK (fs_intel_state (&fake_backend, NULL, &detail) ==
	       FS_INTEL_STATE_UNKNOWN && strstr (detail, "[feed feodo] enabled"),
	       "corrupt intel.conf: state unknown, naming the key (%s)", detail);
	g_free (detail);
	o = fs_intel_resume (&fake_backend, "test", NULL, &e);
	CHECK (o == NULL && g_error_matches (e, FS_INTEL_ERROR,
	                                     FS_INTEL_ERR_CONFIG) &&
	       kern.apply_calls == 0,
	       "corrupt intel.conf: resume applies nothing, says why");
	g_clear_error (&e);
	fs_intel_config_save (c, NULL);

	/* A damaged applied.state: never "enforced" on its word. */
	put_file ("applied.state", "[applied]\ndigest=../../etc\n");
	CHECK (state_of (c, NULL) == FS_INTEL_STATE_DIFFERS,
	       "damaged applied.state with a table loaded: differs");
	CHECK (!fs_intel_applied_has ("feodo"),
	       "damaged applied.state: no log line is attributed");
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_OK &&
	       state_of (c, NULL) == FS_INTEL_STATE_ENFORCED &&
	       fs_intel_applied_has ("feodo"),
	       "a re-apply heals it");
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	put_file ("applied.state", "");
	CHECK (state_of (c, NULL) == FS_INTEL_STATE_DIFFERS,
	       "an empty (truncated) applied.state: differs");

	/* A missing store directory is created; an unsafe one refuses. */
	{
		gchar *wide = g_build_filename (eng_base, "wide2", NULL);

		g_mkdir (wide, 0777);
		g_chmod (wide, 0777);
		g_setenv ("STOCKFW_INTEL_DIR", wide, TRUE);
		kern.apply_calls = 0;
		o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
		CHECK (o == NULL && g_error_matches (e, FS_INTEL_ERROR,
		                                     FS_INTEL_ERR_UNSAFE_DIR) &&
		       kern.apply_calls == 0,
		       "an unsafe store: nothing is applied");
		g_clear_error (&e);
		CHECK (fs_intel_state (&fake_backend, c, NULL) ==
		       FS_INTEL_STATE_UNKNOWN,
		       "an unsafe store: state unknown");
		g_free (wide);
	}
	fs_hostnet_free (h);
	fs_intel_config_free (c);
}

/* ---- update hosts, same-digest re-applies, Stop/Start, rules gone ----- */

static gchar *
hosts_text (const FsIntelConfig *c)
{
	gchar **v = fs_intel_update_hosts (c);
	gchar *s = g_strjoinv (" ", v);

	g_strfreev (v);
	return s;
}

/* Every address the fake kernel received, all sets together. */
static FsRangeSet *
got_ranges (void)
{
	GString *t = g_string_new (NULL);
	gchar **lines = g_strsplit (kern.got_text ? kern.got_text : "", "\n",
	                            -1);
	FsRangeSet *set;

	for (guint i = 0; lines[i] != NULL; i++)
		if (lines[i][0] != '[')
			g_string_append_printf (t, "%s\n", lines[i]);
	set = fs_range_set_from_text (t->str, NULL);
	g_strfreev (lines);
	g_string_free (t, TRUE);
	return set != NULL ? set : fs_range_set_new ();
}

static void
test_update_hosts (void)
{
	FsIntelConfig *c = fs_intel_config_new ();
	FsIntelOutcome *o;
	FsRangeSet *got;
	GError *e = NULL;
	gchar *s, *id = NULL;

	fresh_store ();
	net_reset ();
	kern_reset ();

	c->proxy = g_strdup ("http://198.51.100.200:3128");
	s = hosts_text (c);
	CHECK (g_strcmp0 (s, "") == 0,
	       "update hosts: no feed on: none, not even the proxy (\"%s\")", s);
	g_free (s);

	fs_intel_config_enable_feed (c, "feodo", 0, TRUE, NULL);
	CHECK (fs_intel_config_add_custom (c, "Shouting",
	                                   "HTTPS://198.51.100.201:8443/l.txt",
	                                   FS_FEED_FMT_PLAIN, FS_INTEL_DIR_IN,
	                                   &id, &e),
	       "update hosts: an upper-case HTTPS:// custom feed is accepted "
	       "(%s)", e ? e->message : "ok");
	g_clear_error (&e);
	s = hosts_text (c);
	CHECK (g_strcmp0 (s, "feodotracker.abuse.ch 198.51.100.201 "
	                     "198.51.100.200") == 0,
	       "update hosts: each enabled feed's host (an upper-case scheme "
	       "too), then the proxy's (\"%s\")", s);
	g_free (s);
	g_free (c->proxy);
	c->proxy = g_strdup ("HTTPS://[2001:db8::3]:8443/");
	s = hosts_text (c);
	CHECK (g_strcmp0 (s, "feodotracker.abuse.ch 198.51.100.201 "
	                     "2001:db8::3") == 0,
	       "update hosts: an IPv6 proxy, brackets and port dropped "
	       "(\"%s\")", s);
	g_free (s);
	g_free (c->proxy);
	c->proxy = g_strdup ("http://FeodoTracker.abuse.ch:3128");
	s = hosts_text (c);
	CHECK (g_strcmp0 (s, "feodotracker.abuse.ch 198.51.100.201") == 0,
	       "update hosts: a host named twice is listed once, whatever "
	       "its case (\"%s\")", s);
	g_free (s);

	/* The apply reads this computer's addresses itself (host NULL).
	 * Catalog feeds off: no name to resolve here. */
	fs_intel_config_disable_feed (c, "feodo", NULL);
	g_free (c->proxy);
	c->proxy = g_strdup ("http://198.51.100.200:3128");
	g_free (import_text (c, "Outbound", "198.51.100.200\n198.51.100.201\n"
	                     "203.0.113.9\n", FS_INTEL_DIR_OUT, NULL));
	fs_intel_config_save (c, NULL);
	o = fs_intel_apply_safe (&fake_backend, c, NULL, "test", NULL, &e);
	got = got_ranges ();
	CHECK (o && o->result == FS_APPLY_OK &&
	       fs_range_set_contains_text (got, "203.0.113.9") &&
	       fs_range_set_contains_text (got, "64:ff9b::cb00:7109") &&
	       !fs_range_set_contains_text (got, "198.51.100.200") &&
	       !fs_range_set_contains_text (got, "64:ff9b::c633:64c8") &&
	       !fs_range_set_contains_text (got, "198.51.100.201") &&
	       !fs_range_set_contains_text (got, "64:ff9b::c633:64c9"),
	       "apply: a list naming the proxy and a feed's server keeps both "
	       "reachable, their NAT64 forms too (%s)",
	       e ? e->message : "ok");
	CHECK (o && notes_have (o->notes, "198.51.100.200") &&
	       notes_have (o->notes, "(a feed's download server or proxy), "
	                             "although Outbound lists it"),
	       "... and a note says so");
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	fs_range_set_free (got);

	/* No feed on: nothing is downloaded, so nothing needs the proxy. */
	fs_intel_config_set_enabled (c, id, FALSE, NULL);
	o = fs_intel_apply_safe (&fake_backend, c, NULL, "test", NULL, &e);
	got = got_ranges ();
	CHECK (o && o->result == FS_APPLY_OK &&
	       fs_range_set_contains_text (got, "198.51.100.200"),
	       "apply with no feed on: the proxy is not kept (%s)",
	       e ? e->message : "ok");
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	fs_range_set_free (got);
	g_free (id);
	fs_intel_config_free (c);
}

static guint64
total_packets (const gchar *id)
{
	GHashTable *t = fs_intel_counters (&fake_backend);
	const FsIntelCounter *k = t ? g_hash_table_lookup (t, id) : NULL;
	guint64 p = k ? k->packets : G_MAXUINT64;

	if (t != NULL)
		g_hash_table_unref (t);
	return p;
}

static guint64
carried_packets (const gchar *id)
{
	FsIntelSourceState *s = fs_intel_source_state (id);
	guint64 p = s ? s->carried_packets : G_MAXUINT64;

	fs_intel_source_state_free (s);
	return p;
}

static void
test_gate_same_digest (void)
{
	FsIntelConfig *c = fs_intel_config_new ();
	FsHostNet *h = host_fixture ();
	FsIntelOutcome *o;
	GError *e = NULL;
	gchar *a, *digest;

	fresh_store ();
	net_reset ();
	kern_reset ();
	audit_reset ();
	g_free (import_text (c, "Same", "45.0.1.1\n", FS_INTEL_DIR_BOTH, NULL));
	fs_intel_config_save (c, NULL);
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, NULL);
	digest = g_strdup (o ? o->digest : "");
	fs_intel_outcome_free (o);
	counter_set (kern.counters, "local-same", 5, 500);

	/* nft refuses the transaction of an unchanged rule set (the hourly
	 * re-apply): the old table, identical, is still in force and still
	 * counting. */
	kern.mode = APPLY_FAIL;
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_FAILED && e != NULL &&
	       strstr (e->message, "syntax error") != NULL &&
	       notes_have (o->notes, "The same rules were already in force") &&
	       g_strcmp0 (kern.live_digest, digest) == 0,
	       "same digest, nft refuses: FAILED with nft's error, and a note "
	       "that the same rules are still in force (%s)",
	       e ? e->message : "no error");
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	CHECK (carried_packets ("local-same") == 0 &&
	       total_packets ("local-same") == 5,
	       "... nothing carried: the counters read 5, not 10 (%"
	       G_GUINT64_FORMAT ")", total_packets ("local-same"));
	CHECK (state_of (c, NULL) == FS_INTEL_STATE_ENFORCED,
	       "... and the lists are still enforced");
	a = audit_text ();
	CHECK (a && count_substr (a, "result=failed digest=") == 1 &&
	       strstr (a, "syntax error") != NULL,
	       "... and the audit records the failure");
	g_free (a);

	/* nft commits the same table, then times out: the counters went
	 * down, so the table is new and they are carried, once. */
	kern.mode = APPLY_COMMITTED;
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_OK && e == NULL &&
	       notes_have (o->notes, "timed out") &&
	       carried_packets ("local-same") == 5 &&
	       total_packets ("local-same") == 5,
	       "same digest, committed then timed out: OK, counters carried "
	       "once (%" G_GUINT64_FORMAT ")", total_packets ("local-same"));
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	counter_set (kern.counters, "local-same", 1, 100);

	/* The backend says yes and changes nothing: the right rules are in
	 * force, but the old table still counts -- nothing is carried. */
	kern.mode = APPLY_LIE;
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_OK &&
	       carried_packets ("local-same") == 5 &&
	       total_packets ("local-same") == 6,
	       "same digest, the table untouched: OK, nothing carried (6, "
	       "not 7: %" G_GUINT64_FORMAT ")", total_packets ("local-same"));
	fs_intel_outcome_free (o);
	g_clear_error (&e);

	kern.mode = APPLY_OK;
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_OK &&
	       carried_packets ("local-same") == 6 &&
	       total_packets ("local-same") == 6,
	       "same digest, replaced: carried once (6: %" G_GUINT64_FORMAT
	       ")", total_packets ("local-same"));
	fs_intel_outcome_free (o);
	g_clear_error (&e);

	/* Nothing counted yet: nothing tells a refused transaction from a
	 * committed one, so a refusal is never reported as applied. */
	kern.mode = APPLY_FAIL;
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_FAILED &&
	       carried_packets ("local-same") == 6,
	       "same digest, nothing counted, nft refuses: FAILED");
	fs_intel_outcome_free (o);
	g_clear_error (&e);

	/* Another rule set refused: FAILED, the old one in force, which is
	 * not "the same rules". */
	fs_intel_config_set_dir (c, "local-same", FS_INTEL_DIR_IN, NULL);
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_FAILED &&
	       !notes_have (o->notes, "The same rules") &&
	       g_strcmp0 (kern.live_digest, digest) == 0,
	       "another rule set refused: FAILED, no same-rules note");
	fs_intel_outcome_free (o);
	g_clear_error (&e);

	g_free (digest);
	fs_hostnet_free (h);
	fs_intel_config_free (c);
}

static void
test_gate_start_stop (void)
{
	FsIntelConfig *c = fs_intel_config_new ();
	FsHostNet *h = host_fixture ();
	FsIntelOutcome *o;
	FsIntelState st;
	GError *e = NULL;
	gchar *detail = NULL;

	fresh_store ();
	net_reset ();
	kern_reset ();
	g_free (import_text (c, "Start", "45.0.5.1\n", FS_INTEL_DIR_BOTH, NULL));
	fs_intel_config_save (c, NULL);
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, NULL);
	fs_intel_outcome_free (o);

	/* Stop, then a Start whose apply fails: the firewall runs again,
	 * so not "suspended" but not-loaded, which says to apply. */
	CHECK (fs_intel_suspend (&fake_backend, "test", &e) &&
	       kern.clear_calls == 1 &&
	       state_of (c, NULL) == FS_INTEL_STATE_SUSPENDED,
	       "stop: the table removed, suspended (%s)",
	       e ? e->message : "ok");
	g_clear_error (&e);
	kern.mode = APPLY_FAIL;
	o = fs_intel_resume (&fake_backend, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_FAILED && e != NULL &&
	       kern.live == FS_INTEL_LIVE_ABSENT &&
	       state_of (c, &detail) == FS_INTEL_STATE_NOT_LOADED,
	       "start, the apply fails: FAILED, then not-loaded, never "
	       "suspended (%s)", detail);
	g_free (detail);
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	kern.mode = APPLY_OK;

	/* Stop with no table: nothing to clear.  Then a Start whose build
	 * is refused. */
	CHECK (fs_intel_suspend (&fake_backend, "test", &e) &&
	       kern.clear_calls == 1 &&
	       state_of (c, NULL) == FS_INTEL_STATE_SUSPENDED,
	       "stop with no table loaded: nothing cleared, suspended");
	g_clear_error (&e);
	put_file ("local-start.list", "0.0.0.0/1\n");
	o = fs_intel_resume (&fake_backend, "test", NULL, &e);
	CHECK (o == NULL && g_error_matches (e, FS_INTEL_ERROR,
	                                     FS_INTEL_ERR_TAMPERED) &&
	       state_of (c, NULL) == FS_INTEL_STATE_NOT_LOADED,
	       "start, the build refused: TAMPERED, then not-loaded");
	g_clear_error (&e);
	g_free (import_text (c, "Start", "45.0.5.1\n", FS_INTEL_DIR_BOTH,
	                     NULL));
	o = fs_intel_resume (&fake_backend, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_OK &&
	       state_of (c, NULL) == FS_INTEL_STATE_ENFORCED,
	       "start: applied, enforced (%s)", e ? e->message : "ok");
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	o = fs_intel_resume (&bare_backend, "test", NULL, &e);
	CHECK (o == NULL && e == NULL,
	       "start without intel slots: a no-op, no error");
	fs_intel_outcome_free (o);
	g_clear_error (&e);

	/* Linux without nft, no list ever applied. */
	fresh_store ();
	kern_reset ();
	{
		FsIntelConfig *none = fs_intel_config_new ();

		fs_intel_config_save (none, NULL);
		kern.no_tool = TRUE;
		CHECK (fs_intel_suspend (&fake_backend, "test", &e) && e == NULL,
		       "no nft, nothing ever applied: stop is not an error (%s)",
		       e ? e->message : "ok");
		g_clear_error (&e);
		CHECK (fs_intel_state (&fake_backend, none, &detail) ==
		       FS_INTEL_STATE_OFF,
		       "no nft, nothing on: off, not unknown (%s)", detail);
		g_free (detail);
		fs_intel_config_free (none);
	}

	/* Linux without nft, after StockFW left a table (nft removed
	 * since): the table may still block, so never off. */
	fresh_store ();
	kern_reset ();
	g_free (import_text (c, "Start", "45.0.5.1\n", FS_INTEL_DIR_BOTH, NULL));
	fs_intel_config_save (c, NULL);
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, NULL);
	fs_intel_outcome_free (o);
	kern.no_tool = TRUE;
	CHECK (!fs_intel_suspend (&fake_backend, "test", &e) &&
	       g_error_matches (e, G_IO_ERROR, G_IO_ERROR_NOT_FOUND),
	       "no nft, a table left: stop fails, saying why");
	g_clear_error (&e);
	st = state_of (c, NULL);
	CHECK (st == FS_INTEL_STATE_UNKNOWN || st == FS_INTEL_STATE_NEEDS_ROOT,
	       "... the state is not off (%s)", fs_intel_state_to_string (st));
	fs_intel_config_set_enabled (c, "local-start", FALSE, NULL);
	st = state_of (c, NULL);
	CHECK (st == FS_INTEL_STATE_UNKNOWN || st == FS_INTEL_STATE_NEEDS_ROOT,
	       "... nor once the list is turned off, while the record says a "
	       "table was left (%s)", fs_intel_state_to_string (st));
	kern.no_tool = FALSE;

	/* No store at all (no list ever turned on): Stop and Start create
	 * nothing; a table left behind is still removed. */
	{
		gchar *never = g_build_filename (eng_base, "never-used", NULL);

		kern_reset ();
		g_setenv ("STOCKFW_INTEL_DIR", never, TRUE);
		o = fs_intel_resume (&fake_backend, "test", NULL, &e);
		CHECK (fs_intel_suspend (&fake_backend, "test", NULL) &&
		       kern.clear_calls == 0 && o == NULL && e == NULL &&
		       kern.apply_calls == 0 &&
		       !g_file_test (never, G_FILE_TEST_EXISTS),
		       "no store: stop and start do nothing, create nothing");
		fs_intel_outcome_free (o);
		g_clear_error (&e);
		/* The log reader asks this for any "STOCKFW-TI" line. */
		CHECK (!fs_intel_applied_has ("local-start") &&
		       !g_file_test (never, G_FILE_TEST_EXISTS),
		       "no store: a list's log line is not attributed, and "
		       "asking creates nothing");
		kern.live = FS_INTEL_LIVE_PRESENT;
		kern.live_digest = g_strdup ("0123456789abcdef0123456789abcdef");
		CHECK (fs_intel_suspend (&fake_backend, "test", &e) &&
		       kern.clear_calls == 1 &&
		       kern.live == FS_INTEL_LIVE_ABSENT &&
		       !g_file_test (never, G_FILE_TEST_EXISTS),
		       "no store, a table left behind: stop removes it, creates "
		       "nothing");
		g_clear_error (&e);
		g_free (never);
		fresh_store ();
	}

	fs_hostnet_free (h);
	fs_intel_config_free (c);
}

static gchar *
without_line (const gchar *text, const gchar *prefix)
{
	gchar **lines = g_strsplit (text != NULL ? text : "", "\n", -1);
	GString *out = g_string_new (NULL);

	for (guint i = 0; lines[i] != NULL; i++)
		if (!g_str_has_prefix (lines[i], prefix))
			g_string_append_printf (out, "%s\n", lines[i]);
	g_strfreev (lines);
	return g_string_free (out, FALSE);
}

static void
test_state_rules (void)
{
	FsIntelConfig *c = fs_intel_config_new ();
	FsHostNet *h = host_fixture ();
	FsIntelOutcome *o;
	GKeyFile *kf = g_key_file_new ();
	gchar *detail = NULL, *rec, *old, **ruled = NULL;
	gsize n = 0;

	fresh_store ();
	net_reset ();
	kern_reset ();
	g_free (import_text (c, "Kept", "45.0.7.1\n", FS_INTEL_DIR_BOTH, NULL));
	g_free (import_text (c, "Flush", "45.0.8.1\n", FS_INTEL_DIR_IN, NULL));
	g_free (import_text (c, "Excepted", "45.0.9.1\n", FS_INTEL_DIR_IN,
	                     NULL));
	fs_range_set_add_text (c->exceptions, "45.0.9.1");
	fs_range_set_normalize (c->exceptions);
	fs_intel_config_save (c, NULL);
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, NULL);
	fs_intel_outcome_free (o);
	rec = get_file ("applied.state");
	if (rec != NULL && g_key_file_load_from_data (kf, rec, -1, 0, NULL))
		ruled = g_key_file_get_string_list (kf, "applied", "ruled", &n,
		                                    NULL);
	CHECK (n == 2 && ruled != NULL &&
	       g_strv_contains ((const gchar *const *) ruled, "local-kept") &&
	       g_strv_contains ((const gchar *const *) ruled, "local-flush"),
	       "applied.state: \"ruled\" names the lists whose sets have "
	       "addresses, not an emptied one (%s)", rec);
	g_strfreev (ruled);
	g_key_file_free (kf);

	CHECK (state_of (c, &detail) == FS_INTEL_STATE_ENFORCED,
	       "rules: every list's counter rules are there: enforced (%s)",
	       detail);
	g_free (detail);
	g_hash_table_remove (kern.counters, "local-flush");
	CHECK (state_of (c, &detail) == FS_INTEL_STATE_DIFFERS &&
	       strstr (detail, "Flush") != NULL &&
	       strstr (detail, "Kept") == NULL,
	       "rules: one list's rules gone: differs, naming it (%s)", detail);
	g_free (detail);
	/* nft flush table: the table and its comment stay, the chains are
	 * empty. */
	g_hash_table_remove_all (kern.counters);
	CHECK (state_of (c, &detail) == FS_INTEL_STATE_DIFFERS &&
	       strstr (detail, "Flush") != NULL &&
	       strstr (detail, "Kept") != NULL,
	       "rules: the chains flushed: differs, never enforced (%s)",
	       detail);
	g_free (detail);
	kern.counters_unreadable = TRUE;
	CHECK (state_of (c, NULL) == FS_INTEL_STATE_ENFORCED,
	       "rules: the chains cannot be listed: the digest decides");
	kern.counters_unreadable = FALSE;
	old = without_line (rec, "ruled=");
	put_file ("applied.state", old);
	CHECK (state_of (c, NULL) == FS_INTEL_STATE_ENFORCED,
	       "rules: a record from before \"ruled\": the digest decides");
	g_free (old);
	put_file ("applied.state", rec);
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, NULL);
	CHECK (o && o->result == FS_APPLY_OK &&
	       state_of (c, NULL) == FS_INTEL_STATE_ENFORCED,
	       "rules: an apply restores them: enforced");
	fs_intel_outcome_free (o);

	g_free (rec);
	fs_hostnet_free (h);
	fs_intel_config_free (c);
}

/* ---- lookup ----------------------------------------------------------- */

typedef struct
{
	const gchar *addr;
	gboolean     ok;
	gboolean     blocked;
	FsIntelDir   dir;
	const gchar *sources;   /* space separated, "" none */
	gboolean     prot, exc, host;
} LookupCase;


/* ---- Windows: rules that are not whole, or not in force (Round 3) --- */

static void
test_state_windows (void)
{
	FsIntelConfig *c = fs_intel_config_new ();
	FsHostNet *h = host_fixture ();
	FsBackend win = { 0 };
	FsIntelOutcome *o;
	GError *e = NULL;
	gchar *detail = NULL, *digest;
	FsIntelState st;

	fresh_store ();
	net_reset ();
	kern_reset ();
	audit_reset ();
	fake_backend.intel_not_in_force = fake_not_in_force;
	g_free (import_text (c, "Win", "45.0.0.1\n45.0.0.3\n",
	                     FS_INTEL_DIR_BOTH, NULL));
	fs_intel_config_save (c, NULL);

	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_OK &&
	       state_of (c, NULL) == FS_INTEL_STATE_ENFORCED,
	       "windows states: applied and read back whole is enforced");
	digest = o ? g_strdup (o->digest) : NULL;
	fs_intel_outcome_free (o);
	g_clear_error (&e);

	/* PARTIAL: some of our rules there, not as written. */
	kern.live = FS_INTEL_LIVE_PARTIAL;
	st = state_of (c, &detail);
	CHECK (st == FS_INTEL_STATE_DIFFERS && detail &&
	       strstr (detail, "missing or were changed"),
	       "windows states: rules missing or edited outside StockFW read "
	       "\"differs\", never enforced (%s)", detail);
	g_clear_pointer (&detail, g_free);

	/* Apply over PARTIAL replaces them. */
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	CHECK (o && o->result == FS_APPLY_OK && kern.apply_calls == 2 &&
	       kern.live == FS_INTEL_LIVE_PRESENT,
	       "windows states: an apply over partial rules writes them "
	       "again, even with the same digest");
	fs_intel_outcome_free (o);
	g_clear_error (&e);

	/* INACTIVE: the rules are whole, the firewall does not enforce
	 * them. */
	kern.live = FS_INTEL_LIVE_INACTIVE;
	kern.not_in_force = g_strdup ("Windows Firewall is off for the "
	                              "Public profile.");
	st = state_of (c, &detail);
	CHECK (st == FS_INTEL_STATE_NOT_IN_FORCE &&
	       g_strcmp0 (detail, kern.not_in_force) == 0,
	       "windows states: whole rules the firewall does not enforce read "
	       "\"not in force\" with the backend's reason (%s)", detail);
	g_clear_pointer (&detail, g_free);
	CHECK (g_strcmp0 (fs_intel_state_to_string (st), "not-in-force") == 0,
	       "windows states: the state's name is \"not-in-force\"");

	g_free (kern.live_digest);
	kern.live_digest = g_strdup ("0123456789abcdef0123456789abcdef");
	st = state_of (c, &detail);
	CHECK (st == FS_INTEL_STATE_NOT_IN_FORCE && detail &&
	       strstr (detail, "Public profile") &&
	       strstr (detail, "not the ones StockFW last applied"),
	       "windows states: not in force with other rules says both (%s)",
	       detail);
	g_clear_pointer (&detail, g_free);
	g_free (kern.live_digest);
	kern.live_digest = g_strdup (digest);

	g_clear_pointer (&kern.not_in_force, g_free);
	st = state_of (c, &detail);
	CHECK (st == FS_INTEL_STATE_NOT_IN_FORCE && detail && *detail,
	       "windows states: not in force without a reason still says so "
	       "(%s)", detail);
	g_clear_pointer (&detail, g_free);

	/* UNKNOWN, and the platform knows nothing is enforced. */
	kern.live_unknown = TRUE;
	kern.not_in_force = g_strdup ("The Windows Firewall service (MpsSvc) "
	                              "is not running.");
	st = state_of (c, &detail);
	CHECK (st == FS_INTEL_STATE_NOT_IN_FORCE &&
	       detail && strstr (detail, "MpsSvc"),
	       "windows states: rules that cannot be read with the service "
	       "stopped read \"not in force\" (%s)", detail);
	g_clear_pointer (&detail, g_free);
	g_clear_pointer (&kern.not_in_force, g_free);
	st = state_of (c, NULL);
	CHECK (st == FS_INTEL_STATE_UNKNOWN || st == FS_INTEL_STATE_NEEDS_ROOT,
	       "windows states: unreadable with nothing known is never "
	       "\"not in force\" or \"enforced\" (%s)",
	       fs_intel_state_to_string (st));
	kern.live_unknown = FALSE;

	/* An apply that leaves the rules not in force: OK, with a note
	 * that says they block nothing yet. */
	kern.apply_inactive = TRUE;
	kern.not_in_force = g_strdup ("Windows Firewall is off for the "
	                              "Public profile.");
	kern.live = FS_INTEL_LIVE_ABSENT;
	g_clear_pointer (&kern.live_digest, g_free);
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, &e);
	{
		gboolean noted = FALSE;

		for (guint i = 0; o != NULL && i < o->notes->len; i++)
			if (strstr (o->notes->pdata[i], "not in force") &&
			    strstr (o->notes->pdata[i], "Public profile"))
				noted = TRUE;
		CHECK (o && o->result == FS_APPLY_OK && noted,
		       "windows states: an apply whose rules are not enforced "
		       "is OK and says, in its notes, that they are not in "
		       "force");
	}
	fs_intel_outcome_free (o);
	g_clear_error (&e);
	kern.apply_inactive = FALSE;

	/* Stop removes rules that are there, whole or not. */
	kern.live = FS_INTEL_LIVE_PARTIAL;
	kern.clear_calls = 0;
	CHECK (fs_intel_suspend (&fake_backend, "test", &e) &&
	       kern.clear_calls == 1 && kern.live == FS_INTEL_LIVE_ABSENT,
	       "windows states: Stop removes partial rules too");
	g_clear_error (&e);
	kern.live = FS_INTEL_LIVE_INACTIVE;
	kern.live_digest = g_strdup (digest);
	kern.clear_calls = 0;
	CHECK (fs_intel_suspend (&fake_backend, "test", &e) &&
	       kern.clear_calls == 1 && kern.live == FS_INTEL_LIVE_ABSENT,
	       "windows states: Stop removes rules that are not in force");
	g_clear_error (&e);

	/* Counts: a backend that applies but cannot count says so, never
	 * "0 blocked". */
	win.name = "windows-like";
	win.intel_apply = fake_apply;
	win.intel_clear = fake_clear;
	win.intel_live = fake_live;
	{
		GHashTable *t = fs_intel_counters (&win);

		CHECK (fs_intel_counts_unavailable (&win) != NULL &&
		       strstr (fs_intel_counts_unavailable (&win),
		               "cannot show") &&
		       t != NULL && g_hash_table_size (t) == 0,
		       "windows states: no counters slot -> counts are not "
		       "available (\"%s\"), and no list gets a count of 0",
		       fs_intel_counts_unavailable (&win));
		g_hash_table_unref (t);
	}
	CHECK (fs_intel_counts_unavailable (&fake_backend) == NULL &&
	       fs_intel_counts_unavailable (&bare_backend) == NULL,
	       "windows states: a backend that counts, or has no blocklists "
	       "at all, gets no such sentence");

	fake_backend.intel_not_in_force = NULL;
	g_free (digest);
	fs_hostnet_free (h);
	fs_intel_config_free (c);
}

static void
test_lookup (void)
{
	FsIntelConfig *c = conf_with ("feodo");
	FsHostNet *h = host_fixture ();
	FsIntelRuleset *rs;
	gchar *sentence;
	FsIntelLookup r;
	static const LookupCase cases[] = {
		{ "45.0.0.1",          TRUE, TRUE,  FS_INTEL_DIR_BOTH, "feodo local-mine", 0, 0, 0 },
		{ "45.0.0.2",          TRUE, FALSE, 0, "", 0, 0, 0 },
		{ "::ffff:45.0.0.1",   TRUE, TRUE,  FS_INTEL_DIR_BOTH, "feodo local-mine", 0, 0, 0 },
		{ "198.51.100.0",      TRUE, TRUE,  FS_INTEL_DIR_IN, "feodo", 0, 0, 0 },
		{ "198.51.100.255",    TRUE, TRUE,  FS_INTEL_DIR_IN, "feodo", 0, 0, 0 },
		{ "198.51.99.255",     TRUE, FALSE, 0, "", 0, 0, 0 },
		{ "198.51.101.0",      TRUE, FALSE, 0, "", 0, 0, 0 },
		{ "198.51.100.53",     TRUE, FALSE, FS_INTEL_DIR_IN, "feodo", 0, 0, 1 },
		{ "198.51.100.7",      TRUE, FALSE, FS_INTEL_DIR_IN, "feodo", 0, 1, 0 },
		{ "2001:db8:bad::",    TRUE, TRUE,  FS_INTEL_DIR_IN, "feodo", 0, 0, 0 },
		{ "2001:db8:bad:ffff:ffff:ffff:ffff:ffff", TRUE, TRUE, FS_INTEL_DIR_IN, "feodo", 0, 0, 0 },
		{ "2001:db8:bae::",    TRUE, FALSE, 0, "", 0, 0, 0 },
		{ "2001:DB8:BAD::1",   TRUE, TRUE,  FS_INTEL_DIR_IN, "feodo", 0, 0, 0 },
		/* NAT64: only the out list maps its IPv4 entries. */
		{ "64:ff9b::2d00:1",   TRUE, TRUE,  FS_INTEL_DIR_OUT, "local-mine", 0, 0, 0 },
		{ "64:ff9b::c633:6401", TRUE, FALSE, 0, "", 0, 0, 0 },
		{ "64:ff9b::a00:1",    TRUE, FALSE, 0, "", 1, 0, 0 },
		{ "10.0.0.1",          TRUE, FALSE, 0, "", 1, 0, 0 },
		{ "fe80::1",           TRUE, FALSE, 0, "", 1, 0, 0 },
		{ "203.0.113.5",       TRUE, FALSE, FS_INTEL_DIR_OUT, "local-mine", 0, 0, 1 },
		/* not single addresses */
		{ "45.0.0.0/24",       FALSE, FALSE, 0, "", 0, 0, 0 },
		{ "45.0.0.1-45.0.0.2", FALSE, FALSE, 0, "", 0, 0, 0 },
		{ "fe80::1%eth0",      FALSE, FALSE, 0, "", 0, 0, 0 },
		{ " 45.0.0.1",         FALSE, FALSE, 0, "", 0, 0, 0 },
		{ "example.com",       FALSE, FALSE, 0, "", 0, 0, 0 },
		{ "",                  FALSE, FALSE, 0, "", 0, 0, 0 },
		{ "2001:db8::1/128",   FALSE, FALSE, 0, "", 0, 0, 0 },
	};

	fresh_store ();
	net_reset ();
	fs_intel_config_set_dir (c, "feodo", FS_INTEL_DIR_IN, NULL);
	serve ("feodo", "45.0.0.1\n198.51.100.0/24\n2001:db8:bad::/48\n"
	       "10.0.0.0/8\n");
	g_ptr_array_unref (fs_intel_update (c, NULL, 0, NOW0));
	g_free (import_text (c, "Mine", "45.0.0.1\n203.0.113.5\n",
	                     FS_INTEL_DIR_OUT, NULL));
	fs_range_set_add_text (c->exceptions, "198.51.100.7");
	fs_range_set_normalize (c->exceptions);
	rs = fs_intel_build (c, h, NULL, NULL);

	for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
		const LookupCase *k = &cases[i];
		gboolean ok = fs_intel_lookup (c, h, k->addr, &r);
		GString *got = g_string_new (NULL);
		gboolean kernel = FALSE;

		for (guint j = 0; j < r.sources->len; j++)
			g_string_append_printf (got, "%s%s", j ? " " : "",
			                        (gchar *) r.sources->pdata[j]);
		CHECK (ok == k->ok && (!ok || (r.blocked == k->blocked &&
		       r.dir == k->dir && strcmp (got->str, k->sources) == 0 &&
		       r.is_protected == k->prot && r.is_exception == k->exc &&
		       r.is_host == k->host)),
		       "lookup %s: %s blocked=%d dir=%d [%s] prot=%d exc=%d "
		       "host=%d", k->addr, ok ? "ok" : "refused", r.blocked,
		       r.dir, got->str, r.is_protected, r.is_exception,
		       r.is_host);
		/* The lookup says what the built rule set does. */
		if (ok) {
			guint32 v4;
			FsU128 v6;
			FsAddrFamily fam = fs_addr_parse (k->addr, &v4, &v6);

			for (guint j = 0; rs && j < rs->sets->len; j++) {
				const FsIntelSet *s = g_ptr_array_index (rs->sets, j);

				if (fam == FS_AF_V4 ? fs_range_set_contains4 (s->ranges, v4)
				                    : fs_range_set_contains6 (s->ranges, v6))
					kernel = TRUE;
			}
			CHECK (kernel == r.blocked,
			       "lookup %s agrees with the built rule set (%d)",
			       k->addr, kernel);
		}
		g_string_free (got, TRUE);
		fs_intel_lookup_clear (&r);
	}

	fs_intel_lookup (c, h, "45.0.0.1", &r);
	sentence = fs_intel_lookup_sentence (c, &r);
	CHECK (g_strcmp0 (sentence, "Blocked by threat intel: abuse.ch Feodo "
	                            "Tracker, Mine") == 0,
	       "sentence: \"%s\"", sentence);
	g_free (sentence);
	fs_intel_lookup_clear (&r);
	fs_intel_lookup (c, h, "198.51.100.7", &r);
	CHECK (fs_intel_lookup_sentence (c, &r) == NULL,
	       "sentence: NULL for an address an exception keeps");
	fs_intel_lookup_clear (&r);
	fs_intel_lookup (c, NULL, "203.0.113.5", &r);
	CHECK (r.blocked, "lookup with host NULL: own address is blocked when "
	                  "listed (nothing kept)");
	fs_intel_lookup_clear (&r);
	c->enabled = FALSE;
	fs_intel_lookup (c, h, "45.0.0.1", &r);
	CHECK (!r.blocked && r.sources->len == 0,
	       "master switch off: nothing is listed");
	fs_intel_lookup_clear (&r);

	fs_intel_ruleset_free (rs);
	fs_hostnet_free (h);
	fs_intel_config_free (c);
}

/* ---- lookups answer from the kernel (design 6.6) -------------------- */

typedef struct
{
	gboolean ok, blocked, in_force, pending, uncertain;
	FsIntelState state;
	gchar *kernel;     /* kernel_sources, space-separated */
} Live;

static Live
live_lookup (const FsIntelConfig *c, const FsHostNet *h, const gchar *addr)
{
	FsIntelLookup r;
	Live l = { 0 };
	GString *k = g_string_new (NULL);

	l.ok = fs_intel_lookup (c, h, addr, &r);
	fs_intel_lookup_live (&fake_backend, c, addr, &r);
	l.blocked = r.blocked;
	l.in_force = r.in_force;
	l.pending = r.pending;
	l.uncertain = r.uncertain;
	l.state = r.state;
	for (guint i = 0; r.kernel_sources && i < r.kernel_sources->len; i++)
		g_string_append_printf (k, "%s%s", i ? " " : "",
		                        (gchar *) r.kernel_sources->pdata[i]);
	l.kernel = g_string_free (k, FALSE);
	fs_intel_lookup_clear (&r);
	return l;
}

#define LIVE_CHECK(l, b, f, p, st, what) \
	CHECK ((l).ok && (l).blocked == (b) && (l).in_force == (f) && \
	       (l).pending == (p) && (l).state == (st), \
	       "lookup_live: %s (blocked=%d in_force=%d pending=%d state=%s " \
	       "kernel=[%s])", what, (l).blocked, (l).in_force, (l).pending, \
	       fs_intel_state_to_string ((l).state), (l).kernel)

static void
apply_ok (const FsIntelConfig *c, const FsHostNet *h)
{
	FsIntelOutcome *o = fs_intel_apply_safe (&fake_backend, c, h, "test",
	                                         NULL, NULL);

	if (o == NULL || o->result != FS_APPLY_OK)
		g_print ("(setup: an apply failed)\n");
	fs_intel_outcome_free (o);
}

/* fs_intel_lookup_live on the Windows live values (merge of Round 3
 * and the Windows enforcement): "in force" only when the rules are
 * PRESENT with the digest last applied.  Rules the firewall does not
 * enforce (INACTIVE), rules not whole (PARTIAL) and someone else's
 * rules never are, and the state detail is the backend's sentence. */
static void
test_lookup_live_windows (void)
{
	FsIntelConfig *c = conf_with ("feodo");
	FsHostNet *h = host_fixture ();
	FsIntelLookup r = { 0 };
	FsIntelState st;
	gchar *detail = NULL, *good;
	Live l;

	fresh_store ();
	net_reset ();
	kern_reset ();
	/* Like the Windows backend: no counters slot, a not-in-force one. */
	fake_backend.intel_counters = NULL;
	fake_backend.intel_not_in_force = fake_not_in_force;
	serve ("feodo", "45.0.0.1\n46.0.0.0/24\n");
	g_ptr_array_unref (fs_intel_update (c, NULL, 0, NOW0));
	fs_intel_config_save (c, NULL);
	apply_ok (c, h);
	good = g_strdup (kern.live_digest);

	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, TRUE, FALSE, FS_INTEL_STATE_ENFORCED,
	            "windows: PRESENT with the digest is in force (no counters "
	            "slot needed)");
	g_free (l.kernel);

	kern.live = FS_INTEL_LIVE_INACTIVE;
	kern.not_in_force = g_strdup ("Windows Firewall is off for the Public "
	                              "profile, which the network in use has.");
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, FALSE, FALSE, FS_INTEL_STATE_NOT_IN_FORCE,
	            "windows: INACTIVE with the same digest is never in force");
	g_free (l.kernel);
	fs_intel_lookup (c, h, "45.0.0.1", &r);
	fs_intel_lookup_live (&fake_backend, c, "45.0.0.1", &r);
	CHECK (!r.in_force && r.kernel_sources->len == 0 &&
	       g_strcmp0 (r.state_detail, kern.not_in_force) == 0,
	       "windows: ... no list named in force, and the detail is the "
	       "backend's sentence (%s)", r.state_detail);
	fs_intel_lookup_clear (&r);

	kern.live = FS_INTEL_LIVE_PARTIAL;
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, FALSE, FALSE, FS_INTEL_STATE_DIFFERS,
	            "windows: PARTIAL rules are never in force");
	g_free (l.kernel);

	kern.live = FS_INTEL_LIVE_PRESENT;
	g_free (kern.live_digest);
	kern.live_digest = g_strdup ("0123456789abcdef0123456789abcdef");
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, FALSE, FALSE, FS_INTEL_STATE_DIFFERS,
	            "windows: PRESENT with another digest is not in force");
	g_free (l.kernel);

	g_free (kern.live_digest);
	kern.live_digest = good;
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, TRUE, FALSE, FS_INTEL_STATE_ENFORCED,
	            "windows: back to PRESENT with the digest: in force again");
	g_free (l.kernel);

	/* No store at all (nothing ever turned on here), and rules of ours
	 * on the firewall anyway: never "off". */
	fresh_store ();
	{
		FsIntelConfig *none = fs_intel_config_new ();

		kern.live = FS_INTEL_LIVE_PARTIAL;
		st = fs_intel_state (&fake_backend, NULL, &detail);
		CHECK (st == FS_INTEL_STATE_DIFFERS,
		       "windows: no store, PARTIAL rules there: differs (%s)",
		       detail);
		g_clear_pointer (&detail, g_free);
		kern.live = FS_INTEL_LIVE_INACTIVE;
		st = fs_intel_state (&fake_backend, none, &detail);
		CHECK (st == FS_INTEL_STATE_DIFFERS,
		       "windows: no store, INACTIVE rules there: differs (%s)",
		       detail);
		g_clear_pointer (&detail, g_free);
		CHECK (!fs_intel_store_exists (),
		       "windows: ... and asking created no store");
		fs_intel_config_free (none);
	}

	CHECK (fs_intel_counts_unavailable (&fake_backend) != NULL,
	       "windows: a backend without counters says counts are "
	       "unavailable");
	kern_reset ();
	CHECK (fs_intel_counts_unavailable (&fake_backend) == NULL,
	       "windows: ... and one with counters does not");
	fs_hostnet_free (h);
	fs_intel_config_free (c);
}

static void
test_lookup_live (void)
{
	FsIntelConfig *c = conf_with ("feodo");
	FsHostNet *h = host_fixture ();
	Live l;
	FsIntelOutcome *o;

	fresh_store ();
	net_reset ();
	kern_reset ();
	serve ("feodo", "45.0.0.1\n46.0.0.0/24\n");
	g_ptr_array_unref (fs_intel_update (c, NULL, 0, NOW0));
	fs_intel_config_save (c, NULL);

	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, FALSE, FALSE, FS_INTEL_STATE_NOT_LOADED,
	            "listed, nothing applied: not in force");
	g_free (l.kernel);

	apply_ok (c, h);
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, TRUE, FALSE, FS_INTEL_STATE_ENFORCED,
	            "applied: in force, by feodo");
	CHECK (strcmp (l.kernel, "feodo") == 0, "  ... kernel_sources [%s]",
	       l.kernel);
	g_free (l.kernel);
	l = live_lookup (c, h, "8.8.8.8");
	LIVE_CHECK (l, FALSE, FALSE, FALSE, FS_INTEL_STATE_ENFORCED,
	            "an address on no list");
	g_free (l.kernel);

	/* An exception saved but not applied: the kernel still blocks it. */
	fs_range_set_add_text (c->exceptions, "45.0.0.1");
	fs_range_set_normalize (c->exceptions);
	fs_intel_config_save (c, NULL);
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, FALSE, TRUE, TRUE, FS_INTEL_STATE_ENFORCED,
	            "exception not applied: not blocked by the config, still "
	            "in force in the kernel, pending");
	g_free (l.kernel);
	apply_ok (c, h);
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, FALSE, FALSE, FALSE, FS_INTEL_STATE_ENFORCED,
	            "exception applied: let through, nothing pending");
	g_free (l.kernel);

	/* The exception taken out, not applied: the kernel lets it in. */
	fs_range_set_free (c->exceptions);
	c->exceptions = fs_range_set_new ();
	fs_intel_config_save (c, NULL);
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, FALSE, TRUE, FS_INTEL_STATE_ENFORCED,
	            "exception removed, not applied: would be blocked, is not");
	g_free (l.kernel);
	apply_ok (c, h);

	/* A direction change not applied is pending; the kernel answer
	 * stays the applied direction's. */
	fs_intel_config_set_dir (c, "feodo", FS_INTEL_DIR_IN, NULL);
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, TRUE, TRUE, FS_INTEL_STATE_ENFORCED,
	            "direction changed, not applied: in force, pending");
	g_free (l.kernel);
	fs_intel_config_set_dir (c, "feodo", FS_INTEL_DIR_BOTH, NULL);

	/* Stop: nothing in the kernel. */
	CHECK (fs_intel_suspend (&fake_backend, "test", NULL), "(suspend)");
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, FALSE, FALSE, FS_INTEL_STATE_SUSPENDED,
	            "firewall stopped: listed, not in force");
	g_free (l.kernel);
	o = fs_intel_resume (&fake_backend, "test", NULL, NULL);
	fs_intel_outcome_free (o);
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, TRUE, FALSE, FS_INTEL_STATE_ENFORCED,
	            "started again: in force");
	g_free (l.kernel);

	/* clear: not loaded. */
	CHECK (fs_intel_clear (&fake_backend, "test", NULL), "(clear)");
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, FALSE, FALSE, FS_INTEL_STATE_NOT_LOADED,
	            "cleared: listed, not in force");
	g_free (l.kernel);
	apply_ok (c, h);

	/* A new copy stored, not applied: what the kernel's set holds can
	 * no longer be read, so the answer is uncertain, never "blocked". */
	serve ("feodo", "45.0.0.1\n47.0.0.1\n");
	g_ptr_array_unref (fs_intel_update (c, NULL, FS_INTEL_UPDATE_NOW,
	                                    NOW0 + 10));
	l = live_lookup (c, h, "47.0.0.1");
	CHECK (l.blocked && !l.in_force && l.pending && l.uncertain,
	       "lookup_live: a new copy not applied: listed, uncertain, "
	       "pending (in_force=%d uncertain=%d)", l.in_force, l.uncertain);
	g_free (l.kernel);

	/* A table someone else loaded (differs): not in force. */
	apply_ok (c, h);
	g_free (kern.live_digest);
	kern.live_digest = g_strdup ("0123456789abcdef0123456789abcdef");
	l = live_lookup (c, h, "45.0.0.1");
	LIVE_CHECK (l, TRUE, FALSE, FALSE, FS_INTEL_STATE_DIFFERS,
	            "another table in the kernel: not in force");
	g_free (l.kernel);

	fs_hostnet_free (h);
	fs_intel_config_free (c);
}

/* ---- one engine operation at a time (design 6.5) --------------------- */

static GThread *racer;
static gint     racer_done;
static gboolean racer_ok;
static FsIntelOutcome *racer_outcome;
static FsIntelConfig  *racer_config;
static FsHostNet      *racer_host;

static gpointer
stop_thread (gpointer data)
{
	(void) data;
	racer_ok = fs_intel_suspend (&fake_backend, "racer", NULL);
	g_atomic_int_set (&racer_done, 1);
	return NULL;
}

static gpointer
apply_thread (gpointer data)
{
	(void) data;
	racer_outcome = fs_intel_apply_safe (&fake_backend, racer_config,
	                                     racer_host, "racer", NULL, NULL);
	g_atomic_int_set (&racer_done, 1);
	return NULL;
}

/* Inside the apply: a Stop arrives from another thread (the Status
 * page's worker, or `stockfw stop' in another process). */
static void
race_stop_during_apply (void)
{
	kern.during_apply = NULL;
	g_atomic_int_set (&racer_done, 0);
	racer = g_thread_new ("stop", stop_thread, NULL);
	g_usleep (300 * 1000);
}

static void
race_apply_during_stop (void)
{
	kern.during_clear = NULL;
	g_atomic_int_set (&racer_done, 0);
	racer = g_thread_new ("apply", apply_thread, NULL);
	g_usleep (300 * 1000);
}

static void
test_engine_lock (void)
{
	FsIntelConfig *c = fs_intel_config_new ();
	FsHostNet *h = host_fixture ();
	FsIntelOutcome *o;
	gboolean waited;
	gchar *audit, *pa, *ps;

	fresh_store ();
	net_reset ();
	kern_reset ();
	audit_reset ();
	g_free (import_text (c, "Race", "45.0.6.1\n", FS_INTEL_DIR_BOTH, NULL));
	fs_intel_config_save (c, NULL);
	apply_ok (c, h);

	/* A Stop during an apply waits for it, then takes the lists down:
	 * the apply never writes "enforced" over the Stop's "suspended". */
	kern.during_apply = race_stop_during_apply;
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, NULL);
	waited = !g_atomic_int_get (&racer_done);
	g_thread_join (racer);
	audit = audit_text ();
	pa = strstr (audit, "| intel-apply | source=test result=ok");
	ps = strstr (audit, "| intel-suspend | source=racer result=ok");
	CHECK (o != NULL && o->result == FS_APPLY_OK && waited && racer_ok &&
	       kern.live == FS_INTEL_LIVE_ABSENT &&
	       state_of (c, NULL) == FS_INTEL_STATE_SUSPENDED &&
	       pa != NULL && ps != NULL && ps > pa,
	       "a Stop during an apply waits for it (waited=%d), then the "
	       "lists are down and suspended (state %s)", waited,
	       fs_intel_state_to_string (state_of (c, NULL)));
	g_free (audit);
	fs_intel_outcome_free (o);

	/* An apply that waited for a Stop does not load the lists behind
	 * its back: it is held, the kernel left empty. */
	o = fs_intel_resume (&fake_backend, "test", NULL, NULL);
	fs_intel_outcome_free (o);
	racer_config = c;
	racer_host = h;
	kern.during_clear = race_apply_during_stop;
	CHECK (fs_intel_suspend (&fake_backend, "test", NULL), "(suspend)");
	waited = !g_atomic_int_get (&racer_done);
	g_thread_join (racer);
	CHECK (racer_outcome != NULL && racer_outcome->held &&
	       racer_outcome->result == FS_APPLY_DRY_RUN && waited &&
	       strstr (racer_outcome->hold_reason, "stopped while this apply "
	               "waited") != NULL &&
	       kern.live == FS_INTEL_LIVE_ABSENT &&
	       state_of (c, NULL) == FS_INTEL_STATE_SUSPENDED,
	       "an apply that waited for a Stop is held (waited=%d, %s), the "
	       "lists stay down", waited, racer_outcome && racer_outcome->hold_reason
	       ? racer_outcome->hold_reason : "not held");
	fs_intel_outcome_free (racer_outcome);
	racer_outcome = NULL;

	/* An apply asked for while stopped, with no race, still goes in
	 * (as before: `intel apply' with the firewall stopped). */
	o = fs_intel_apply_safe (&fake_backend, c, h, "test", NULL, NULL);
	CHECK (o != NULL && o->result == FS_APPLY_OK &&
	       kern.live == FS_INTEL_LIVE_PRESENT,
	       "an apply that did not wait is not held by an old Stop");
	fs_intel_outcome_free (o);

	fs_hostnet_free (h);
	fs_intel_config_free (c);
}

/* An update downloads for minutes; a Stop in that time carries the
 * counters into the source's state.  The update's own state write must
 * keep them. */
static void
stop_during_fetch (void)
{
	during_fetch = NULL;
	fs_intel_suspend (&fake_backend, "test", NULL);
}

static void
test_update_keeps_carried (void)
{
	FsIntelConfig *c = conf_with ("feodo");
	FsHostNet *h = host_fixture ();
	FsIntelSourceState *s;

	fresh_store ();
	net_reset ();
	kern_reset ();
	serve ("feodo", "45.0.8.1\n");
	g_ptr_array_unref (fs_intel_update (c, NULL, 0, NOW0));
	fs_intel_config_save (c, NULL);
	apply_ok (c, h);
	counter_set (kern.counters, "feodo", 42, 4200);
	serve ("feodo", "45.0.8.1\n45.0.8.2\n");
	during_fetch = stop_during_fetch;
	g_ptr_array_unref (fs_intel_update (c, NULL, FS_INTEL_UPDATE_NOW,
	                                    NOW0 + 60));
	during_fetch = NULL;
	s = fs_intel_source_state ("feodo");
	CHECK (s != NULL && s->carried_packets == 42 && s->entries == 2,
	       "an update during which a Stop carried the counters keeps them "
	       "(carried %" G_GUINT64_FORMAT ", entries %u)",
	       s ? s->carried_packets : 0, s ? s->entries : 0);
	fs_intel_source_state_free (s);
	fs_hostnet_free (h);
	fs_intel_config_free (c);
}

/* ---- smaller engine fixes --------------------------------------------- */

static void
test_engine_misc (void)
{
	FsIntelConfig *c = fs_intel_config_new ();
	FsIntelListConf *l;
	GError *e = NULL;
	gchar *id, *text, *detail = NULL;

	fresh_store ();
	net_reset ();
	kern_reset ();

	/* Re-importing a list keeps its direction (dir 0), whatever the
	 * case or spacing of its name; a new list blocks both ways. */
	id = import_text (c, "office bad", "45.0.7.1\n", FS_INTEL_DIR_IN, NULL);
	g_free (id);
	id = import_text (c, "Office  Bad", "45.0.7.2\n", 0, &e);
	l = id != NULL ? fs_intel_config_list (c, id) : NULL;
	CHECK (l != NULL && l->dir == FS_INTEL_DIR_IN && c->lists->len == 1,
	       "re-import with dir 0 keeps the list's direction (in) (%s)",
	       e ? e->message : l ? fs_intel_dir_to_string (l->dir) : "none");
	g_clear_error (&e);
	g_free (id);
	id = import_text (c, "Fresh", "45.0.7.3\n", 0, NULL);
	l = id != NULL ? fs_intel_config_list (c, id) : NULL;
	CHECK (l != NULL && l->dir == FS_INTEL_DIR_BOTH,
	       "a new list imported with dir 0 blocks both ways");
	g_free (id);
	CHECK (import_text (c, "Bad dir", "45.0.7.4\n", (FsIntelDir) 7, &e) == NULL &&
	       e != NULL, "an invalid direction is still refused");
	g_clear_error (&e);

	/* The proxy setter. */
	CHECK (!fs_intel_config_set_proxy (c, "http://user:pw@proxy.example:3128",
	                                   &e) && e != NULL && c->proxy == NULL,
	       "proxy with a password: refused, nothing set");
	g_clear_error (&e);
	CHECK (!fs_intel_config_set_proxy (c, "socks5://proxy.example:1080", &e) &&
	       c->proxy == NULL, "a socks proxy: refused");
	g_clear_error (&e);
	CHECK (fs_intel_config_set_proxy (c, "http://proxy.example:3128", NULL) &&
	       g_strcmp0 (c->proxy, "http://proxy.example:3128") == 0,
	       "an http proxy: set");
	fs_intel_config_save (c, NULL);
	{
		FsIntelConfig *back = fs_intel_config_load (NULL);

		CHECK (back != NULL &&
		       g_strcmp0 (back->proxy, "http://proxy.example:3128") == 0,
		       "  ... saved as [intel] proxy= and read back");
		fs_intel_config_free (back);
	}
	CHECK (fs_intel_config_set_proxy (c, "", NULL) && c->proxy == NULL,
	       "an empty proxy: none");

	/* The rule an event carries, the same for every reader. */
	text = fs_intel_rule_text ("spamhaus-drop");
	CHECK (g_strcmp0 (text, "Threat intel: Spamhaus DROP (IPv4)") == 0,
	       "rule text of a catalog feed: \"%s\"", text);
	g_free (text);
	text = fs_intel_rule_text ("local-fresh");
	CHECK (g_strcmp0 (text, "Threat intel: Fresh") == 0,
	       "rule text of a local list, from the saved config: \"%s\"", text);
	g_free (text);

	/* Unknown with a reason: the backend says why the kernel could
	 * not be read (no nft), and the state's sentence carries it. */
	kern.live_unknown = TRUE;
	kern.live_error = "nft was not found on PATH. Install the nftables "
	                  "package to use blocklists.";
	(void) state_of (c, &detail);
	CHECK (detail != NULL && strstr (detail, "nftables package") != NULL,
	       "unknown: the reason is in the sentence (\"%s\")", detail);
	g_free (detail);
	kern.live_unknown = FALSE;
	kern.live_error = NULL;

	fs_intel_config_free (c);
}

static void
test_engine (const gchar *argv0)
{
	if (!find_safe_base (argv0)) {
		g_print ("SKIP: no directory whose parents pass the store check "
		         "(set STOCKFW_TEST_SAFE_DIR); engine tests not run\n");
		return;
	}
	kern_reset ();
	net_reset ();
	test_store_dir ();
	test_config ();
	test_update_consent_and_network ();
	test_update_guards ();
	test_update_dates ();
	test_update_grew ();
	test_update_isolation_and_crash ();
	test_stored_lists ();
	test_cover6_at_cap ();
	test_build ();
	test_build_limits ();
	test_gate ();
	test_gate_hostile ();
	test_update_hosts ();
	test_gate_same_digest ();
	test_gate_start_stop ();
	test_state_rules ();
	test_state_windows ();
	test_lookup ();
	test_lookup_live ();
	test_lookup_live_windows ();
	test_engine_lock ();
	test_update_keeps_carried ();
	test_engine_misc ();

	fs_intel_set_fetcher (NULL, NULL);
	rm_rf (eng_base);
	g_free (eng_base);
	g_free (eng_audit);
	g_hash_table_unref (net.bodies);
	g_hash_table_unref (net.errors);
	g_free (net.last_url);
	g_free (net.last_proxy);
	g_hash_table_unref (kern.counters);
	g_free (kern.live_digest);
	g_free (kern.got_digest);
	g_free (kern.got_text);
}

#else  /* !G_OS_UNIX */

static void
test_engine (const gchar *argv0)
{
	g_print ("SKIP: the threat-intel store is Linux-only in Round 1\n");
}

#endif

int
main (int argc, char **argv)
{
	test_parse ();
	test_sets ();
	test_csv ();
	test_script ();
	test_engine (argv[0]);

	g_print ("\n%s: %u failure(s)\n", failures ? "FAILED" : "PASSED",
	         failures);
	return failures ? 1 : 0;
}
