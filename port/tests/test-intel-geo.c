/*---[ test-intel-geo.c ]-------------------------------------------------
 * Threat intel round 2, part 2: country and network-owner (AS) rules in
 * the engine (src/core/fs-intel.c), design section 12.  The location
 * databases are written by the test (tests/geodb-writer.h) and signed
 * with a key made at run time; the reader is a test build
 * (FS_GEODB_TESTING) told that key.  The backend and both downloaders
 * are fakes, so nothing here touches the network or the kernel; the
 * live half is tests/test-intel-e2e.sh.
 *
 * Built by tests/test-core.sh (by hand, like test-geodb) and by
 * `ninja fs-intel-geo-test'.  Linux only: the store is Linux-only until
 * Round 3; elsewhere it checks the wording and SKIPs the rest.
 *--------------------------------------------------------------------*/
#include <gio/gio.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-geodb.h"
#include "core/fs-intel.h"
#include "core/fs-intelset.h"
#include "core/fs-iprange.h"
#include "geodb-writer.h"

#ifdef G_OS_UNIX
#include <sys/stat.h>
#include <unistd.h>
#endif

static guint failures = 0;
static guint checks = 0;

#define CHECK(cond, ...) do {                                   \
	checks++;                                               \
	if (cond) {                                             \
		g_print ("ok:   " __VA_ARGS__);                 \
	} else {                                                \
		g_print ("FAIL: " __VA_ARGS__);                 \
		failures++;                                     \
	}                                                       \
	g_print ("\n");                                         \
} while (0)

#define DAY (24 * 3600)

/* ======================================================= the wording */

static void
test_wording (void)
{
	gchar *a = fs_intel_geo_attribution ();
	FsIntelConfig *c = fs_intel_config_new ();
	gchar *t = fs_intel_geo_consent_text (c);

	CHECK (strstr (a, "IPFire") != NULL && strstr (a, "CC BY-SA 4.0") &&
	       strstr (a, "not confirmed") != NULL &&
	       strstr (a, "commercial") != NULL,
	       "the attribution names IPFire and the licence, and says it is "
	       "not confirmed (%s)", a);
	CHECK (strstr (t, "location.ipfire.org") != NULL &&
	       strstr (t, "once a day") != NULL &&
	       strstr (t, "public IP address") != NULL &&
	       strstr (t, "StockFW/") != NULL &&
	       strstr (t, "not confirmed") != NULL &&
	       strstr (t, "registered") != NULL &&
	       strstr (t, "anycast") != NULL &&
	       strstr (t, "exception") != NULL,
	       "the consent text names the host, how often, what it learns, "
	       "the licence status, \"registered\", anycast and exceptions");
	CHECK (!c->geo_enabled && c->geo_accepted_at == 0 &&
	       c->locations != NULL && c->locations->len == 0,
	       "the defaults: the location database is off, never consented, "
	       "no rules");
	CHECK (fs_intel_source_kind ("country-asia") == FS_INTEL_KIND_COUNTRY &&
	       fs_intel_source_kind ("asn-cloud") == FS_INTEL_KIND_ASN &&
	       fs_intel_source_kind ("local-x") == FS_INTEL_KIND_LIST &&
	       fs_intel_source_kind ("custom-x") == FS_INTEL_KIND_CUSTOM &&
	       fs_intel_source_kind ("spamhaus-drop") == FS_INTEL_KIND_FEED &&
	       fs_intel_source_kind ("nonsense") == FS_INTEL_KIND_UNKNOWN &&
	       fs_intel_source_kind ("Country-x") == FS_INTEL_KIND_UNKNOWN,
	       "source kinds by id: feed, custom, local, country, asn");
	{
		gchar *n4 = fs_intelset_nft_set_name ("country-asia", FS_AF_V4);
		gchar *n6 = fs_intelset_nft_set_name ("asn-cloud", FS_AF_V6);
		gchar *l4 = fs_intelset_nft_set_name ("local-asia", FS_AF_V4);

		CHECK (g_strcmp0 (n4, "s_country_asia_4") == 0 &&
		       g_strcmp0 (n6, "s_asn_cloud_6") == 0 &&
		       g_strcmp0 (l4, "s_local_asia_4") == 0,
		       "set names show the kind: %s, %s beside %s", n4, n6, l4);
		g_free (n4);
		g_free (n6);
		g_free (l4);
	}
#ifdef G_OS_WIN32
	{
		GError *e = NULL;

		CHECK (!fs_intel_geo_supported () &&
		       !fs_intel_config_enable_geo (c, TRUE, &e) &&
		       e != NULL && strstr (e->message, "not available on "
		                            "Windows yet") != NULL,
		       "Windows: location blocking is not available yet");
		g_clear_error (&e);
	}
#else
	CHECK (fs_intel_geo_supported (), "Linux: location blocking is supported");
#endif
	g_free (a);
	g_free (t);
	fs_intel_config_free (c);
}

#ifdef __linux__

/* ======================================================= fixtures */

static gchar *base;          /* scratch, with a chain that passes   */
static guint store_n;
static EVP_PKEY *key;        /* the "IPFire" key of this run        */
static EVP_PKEY *other_key;  /* a key nobody trusts                 */
static gint64 now_s;

static void
rm_rf (const gchar *path)
{
	GDir *d = g_dir_open (path, 0, NULL);
	const gchar *n;

	if (d != NULL) {
		while ((n = g_dir_read_name (d)) != NULL) {
			gchar *p = g_build_filename (path, n, NULL);

			if (g_file_test (p, G_FILE_TEST_IS_DIR) &&
			    !g_file_test (p, G_FILE_TEST_IS_SYMLINK))
				rm_rf (p);
			else
				g_unlink (p);
			g_free (p);
		}
		g_dir_close (d);
	}
	g_rmdir (path);
}

/* A new, empty store for the next test. */
static gchar *
fresh_store (void)
{
	gchar *dir = g_strdup_printf ("%s/store%u", base, ++store_n);

	g_setenv ("STOCKFW_INTEL_DIR", dir, TRUE);
	g_free (fs_intel_dir (NULL));   /* creates it */
	return dir;
}

static gboolean
find_base (const gchar *argv0)
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
	for (guint i = 0; i < n && base == NULL; i++) {
		gchar *tmpl, *dir, *probe, *got;
		GError *e = NULL;

		if (cands[i] == NULL)
			continue;
		tmpl = g_build_filename (cands[i], "sfw-intel-geo-XXXXXX", NULL);
		dir = g_mkdtemp_full (tmpl, 0700);   /* fills in tmpl itself */
		if (dir == NULL) {
			g_free (tmpl);
			continue;
		}
		probe = g_build_filename (dir, "probe", NULL);
		g_setenv ("STOCKFW_INTEL_DIR", probe, TRUE);
		got = fs_intel_dir (&e);
		if (got != NULL) {
			base = g_strdup (dir);
		} else {
			g_print ("note: %s: %s\n", dir, e->message);
			rm_rf (dir);
		}
		g_clear_error (&e);
		g_free (tmpl);
		g_free (got);
		g_free (probe);
	}
	g_free (exe_dir);
	g_free (abs_exe);
	g_free (cwd);
	if (base != NULL) {
		gchar *audit = g_build_filename (base, "audit.log", NULL);

		g_setenv ("STOCKFW_AUDIT_FILE", audit, TRUE);
		g_free (audit);
	}
	return base != NULL;
}

/* The standard database (design 12.6's cases), made at `created':
 *   198.51.100.0/24      XA  AS64500
 *   198.51.100.128/25    XB  AS64501   (more specific: XB wins)
 *   203.0.113.0/24       XA  AS64502   anycast
 *   192.0.2.0/24         XC  AS64503   (XD in the "moved" version)
 *   10.0.0.0/8           XA  AS64500   (protected space: never blocked)
 *   2001:db8:a::/48      XA  AS64500
 *   2001:db8:b::/48      XB  AS64501
 * with the countries XA, XB, XC (and XD) and three named ASes. */
static guint8 *
std_db (gint64 created, gboolean moved, EVP_PKEY *k, gsize *len)
{
	GeoWriter *w = geow_new (created);
	guint8 *d;

	geow_net (w, "198.51.100.0/24", "XA", 64500, 0);
	geow_net (w, "198.51.100.128/25", "XB", 64501, 0);
	geow_net (w, "203.0.113.0/24", "XA", 64502, 4 /* anycast */);
	geow_net (w, "192.0.2.0/24", moved ? "XD" : "XC", 64503, 0);
	geow_net (w, "10.0.0.0/8", "XA", 64500, 0);
	geow_net (w, "2001:db8:a::/48", "XA", 64500, 0);
	geow_net (w, "2001:db8:b::/48", "XB", 64501, 0);
	geow_as (w, 64500, "Alpha Networks");
	geow_as (w, 64501, "Beta Hosting");
	geow_as (w, 64502, "Anycast CDN");
	geow_country (w, "XA", "EU", "Atlantis");
	geow_country (w, "XB", "AS", "Brigadoon");
	geow_country (w, "XC", "AF", "Cockaigne");
	geow_country (w, "XD", "OC", "Dinotopia");
	d = geow_build (w, k, len);
	geow_free (w);
	return d;
}

static GBytes *
std_xz (gint64 created, gboolean moved, EVP_PKEY *k)
{
	gsize len = 0;
	guint8 *d = std_db (created, moved, k, &len);
	GBytes *xz = geow_xz (d, len);

	g_free (d);
	return xz;
}

/* ---- the fake downloaders: every request is counted ----------------- */

static guint geo_calls, feed_calls;
static GBytes *geo_body;        /* what location.ipfire.org answers   */
static gchar *geo_fail;         /* or this error                       */
static gchar *geo_last_proxy;

static GBytes *
fake_geo_fetch (const gchar *url, const gchar *proxy, gpointer data,
                GError **error)
{
	(void) data;
	geo_calls++;
	g_free (geo_last_proxy);
	geo_last_proxy = g_strdup (proxy);
	if (g_strcmp0 (url, FS_GEODB_URL) != 0) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "unexpected URL %s", url);
		return NULL;
	}
	if (geo_fail != NULL || geo_body == NULL) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "%s",
		             geo_fail ? geo_fail : "HTTP 404");
		return NULL;
	}
	return g_bytes_ref (geo_body);
}

static GBytes *
fake_feed_fetch (const gchar *url, const gchar *proxy, gpointer data,
                 GError **error)
{
	(void) url;
	(void) proxy;
	(void) data;
	feed_calls++;
	g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "no feeds here");
	return NULL;
}

static void
serve_geo (GBytes *xz)
{
	if (geo_body != NULL)
		g_bytes_unref (geo_body);
	geo_body = xz;
	g_clear_pointer (&geo_fail, g_free);
}

/* ---- the fake backend ------------------------------------------------ */

typedef struct
{
	FsIntelLive live;
	gchar      *live_digest;
	GHashTable *counters;
	guint       apply_calls;
	gchar      *got_text;      /* "[id dir]\n<ranges>" per set */
	gchar      *got_digest;
} Kern;

static Kern kern;
static FsBackend fake_backend;
static FsBackend bare_backend;

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

static void
counter_set (GHashTable *t, const gchar *id, guint64 p, guint64 b)
{
	FsIntelCounter *c = g_new0 (FsIntelCounter, 1);

	c->packets = p;
	c->bytes = b;
	g_hash_table_replace (t, g_strdup (id), c);
}

static gboolean
fake_apply (const FsIntelRuleset *rs, GError **error)
{
	(void) error;
	kern.apply_calls++;
	g_free (kern.got_text);
	g_free (kern.got_digest);
	kern.got_text = ruleset_text (rs);
	kern.got_digest = fs_intel_ruleset_digest (rs);
	kern.live = rs->sets->len ? FS_INTEL_LIVE_PRESENT : FS_INTEL_LIVE_ABSENT;
	g_free (kern.live_digest);
	kern.live_digest = rs->sets->len ? g_strdup (kern.got_digest) : NULL;
	g_hash_table_remove_all (kern.counters);
	for (guint i = 0; i < rs->sets->len; i++) {
		const FsIntelSet *s = g_ptr_array_index (rs->sets, i);

		if (!fs_range_set_is_empty (s->ranges))
			counter_set (kern.counters, s->id, 0, 0);
	}
	return TRUE;
}

static gboolean
fake_clear (GError **error)
{
	(void) error;
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

	if (kern.live != FS_INTEL_LIVE_PRESENT)
		return NULL;
	t = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_iter_init (&it, kern.counters);
	while (g_hash_table_iter_next (&it, &k, &v))
		counter_set (t, k, ((FsIntelCounter *) v)->packets,
		             ((FsIntelCounter *) v)->bytes);
	return t;
}

static FsIntelLive
fake_live (gchar **digest)
{
	if (digest != NULL)
		*digest = kern.live == FS_INTEL_LIVE_PRESENT
		          ? g_strdup (kern.live_digest) : NULL;
	return kern.live;
}

static void
kern_reset (void)
{
	if (kern.counters == NULL)
		kern.counters = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                       g_free, g_free);
	g_hash_table_remove_all (kern.counters);
	kern.live = FS_INTEL_LIVE_ABSENT;
	g_clear_pointer (&kern.live_digest, g_free);
	g_clear_pointer (&kern.got_text, g_free);
	g_clear_pointer (&kern.got_digest, g_free);
	kern.apply_calls = 0;
	fake_backend.name = "fake";
	fake_backend.intel_apply = fake_apply;
	fake_backend.intel_clear = fake_clear;
	fake_backend.intel_counters = fake_counters;
	fake_backend.intel_live = fake_live;
	bare_backend.name = "bare";
}

/* ---- small helpers ----------------------------------------------------- */

static FsIntelUpdateResult *
geo_result (GPtrArray *rs)
{
	for (guint i = 0; i < rs->len; i++) {
		FsIntelUpdateResult *r = g_ptr_array_index (rs, i);

		if (strcmp (r->id, FS_INTEL_GEO_ID) == 0)
			return r;
	}
	return NULL;
}

/* fs_intel_update of the database alone: its outcome (99: none) and
 * message. */
static FsIntelUpdateOutcome
geo_update (const FsIntelConfig *c, guint flags, gint64 now, gchar **msg)
{
	GPtrArray *rs = fs_intel_update (c, NULL, flags, now);
	FsIntelUpdateResult *r = geo_result (rs);
	FsIntelUpdateOutcome o = r ? r->outcome : (FsIntelUpdateOutcome) 99;

	if (msg != NULL)
		*msg = g_strdup (r ? r->message : "(no result)");
	g_ptr_array_unref (rs);
	return o;
}

/* A config with the database on (consented) and the given rules:
 * "country:NAME:CODES:DIR" or "asn:NAME:NUMBERS:DIR", values comma
 * separated. */
static FsIntelConfig *
geo_conf (const gchar *const *rules)
{
	FsIntelConfig *c = fs_intel_config_new ();
	GError *e = NULL;

	if (!fs_intel_config_enable_geo (c, TRUE, &e))
		g_print ("(setup: %s)\n", e ? e->message : "?");
	g_clear_error (&e);
	for (guint i = 0; rules != NULL && rules[i] != NULL; i++) {
		gchar **p = g_strsplit (rules[i], ":", 4);
		gchar **v = g_strsplit (p[2], ",", -1);
		FsIntelDir dir = 0;

		fs_intel_dir_from_string (p[3], &dir);
		if (!fs_intel_config_add_location (c, p[1],
		        strcmp (p[0], "country") == 0 ? FS_INTEL_LOCATION_COUNTRY
		                                      : FS_INTEL_LOCATION_ASN,
		        (const gchar *const *) v, dir, NULL, &e))
			g_print ("(setup: %s: %s)\n", rules[i],
			         e ? e->message : "?");
		g_clear_error (&e);
		g_strfreev (v);
		g_strfreev (p);
	}
	return c;
}

/* Install the standard database into the current store through the
 * engine's update, as a real download would. */
static gboolean
install_std (const FsIntelConfig *c, gint64 created, gboolean moved)
{
	serve_geo (std_xz (created, moved, key));
	return geo_update (c, FS_INTEL_UPDATE_NOW, now_s, NULL) ==
	       FS_INTEL_UPDATED;
}

static const FsIntelSet *
set_of (const FsIntelRuleset *rs, const gchar *id)
{
	return rs != NULL ? fs_intel_ruleset_find (rs, id) : NULL;
}

static gchar *
set_text (const FsIntelRuleset *rs, const gchar *id)
{
	const FsIntelSet *s = set_of (rs, id);

	return s != NULL ? fs_range_set_to_text (s->ranges) : g_strdup ("(none)");
}

static gboolean
notes_have (GPtrArray *notes, const gchar *needle)
{
	for (guint i = 0; notes != NULL && i < notes->len; i++)
		if (strstr (g_ptr_array_index (notes, i), needle) != NULL)
			return TRUE;
	return FALSE;
}

static gchar *
notes_joined (GPtrArray *notes)
{
	GString *out = g_string_new (NULL);

	for (guint i = 0; notes != NULL && i < notes->len; i++)
		g_string_append_printf (out, "%s%s", i ? " | " : "",
		                        (gchar *) g_ptr_array_index (notes, i));
	return g_string_free (out, FALSE);
}

static gchar *
read_file (const gchar *dir, const gchar *name, gsize *len)
{
	gchar *p = g_build_filename (dir, name, NULL);
	gchar *t = NULL;

	if (!g_file_get_contents (p, &t, len, NULL))
		t = NULL;
	g_free (p);
	return t;
}

/* ======================================================= intel.conf */

static FsIntelConfig *
conf_from (const gchar *text, GError **error)
{
	gchar *dir = fresh_store ();
	gchar *p = g_build_filename (dir, "intel.conf", NULL);
	FsIntelConfig *c;

	g_file_set_contents (p, text, -1, NULL);
	g_chmod (p, 0600);
	c = fs_intel_config_load (error);
	g_free (p);
	g_free (dir);
	return c;
}

static void
expect_conf_error (const gchar *text, const gchar *needle, const gchar *what)
{
	GError *e = NULL;
	FsIntelConfig *c = conf_from (text, &e);

	CHECK (c == NULL && e != NULL && e->code == FS_INTEL_ERR_CONFIG &&
	       strstr (e->message, needle) != NULL,
	       "intel.conf refused: %s (%s)", what, e ? e->message : "loaded");
	fs_intel_config_free (c);
	g_clear_error (&e);
}

static void
test_config (void)
{
	GError *e = NULL;
	FsIntelConfig *c, *c2;
	FsIntelLocationConf *l;
	gchar *dir;

	c = conf_from ("[geo]\nenabled=true\naccepted-at=1700000000\n"
	               "[location country-high-risk]\nname=High risk\n"
	               "countries=xb;XA;xa;\ndirection=both\nenabled=true\n"
	               "unknown-key=whatever\n"
	               "[location asn-hosters]\nname=Hosters\n"
	               "asns=AS64501;64500;as64500\nenabled=false\n", &e);
	l = fs_intel_config_location (c, "country-high-risk");
	CHECK (c != NULL && c->geo_enabled && c->geo_accepted_at == 1700000000 &&
	       l != NULL && l->kind == FS_INTEL_LOCATION_COUNTRY &&
	       g_strv_length (l->countries) == 2 &&
	       strcmp (l->countries[0], "XA") == 0 &&
	       strcmp (l->countries[1], "XB") == 0 &&
	       l->dir == FS_INTEL_DIR_BOTH && l->enabled && l->asns == NULL,
	       "a country rule: codes upper case, sorted, duplicates dropped, "
	       "unknown keys ignored (%s)", e ? e->message : "loaded");
	g_clear_error (&e);
	l = fs_intel_config_location (c, "asn-hosters");
	CHECK (l != NULL && l->kind == FS_INTEL_LOCATION_ASN &&
	       l->asns->len == 2 && g_array_index (l->asns, guint32, 0) == 64500 &&
	       g_array_index (l->asns, guint32, 1) == 64501 && !l->enabled &&
	       l->dir == FS_INTEL_DIR_IN && l->countries == NULL,
	       "an AS rule: \"AS64501\", \"64500\" and \"as64500\" read as two "
	       "numbers; the default direction is in");
	CHECK (g_strcmp0 (fs_intel_config_label (c, "country-high-risk"),
	                  "High risk") == 0 &&
	       g_strcmp0 (fs_intel_config_label (c, FS_INTEL_GEO_ID),
	                  "Location database") == 0,
	       "labels: a rule's name, and the database's");
	CHECK (fs_intel_config_save (c, &e), "the config saves (%s)",
	       e ? e->message : "ok");
	g_clear_error (&e);
	c2 = fs_intel_config_load (&e);
	l = c2 ? fs_intel_config_location (c2, "asn-hosters") : NULL;
	CHECK (c2 != NULL && c2->geo_enabled && c2->geo_accepted_at == 1700000000 &&
	       c2->locations->len == 2 && l != NULL && l->asns->len == 2 &&
	       !l->enabled &&
	       fs_intel_config_location (c2, "country-high-risk")->dir ==
	       FS_INTEL_DIR_BOTH,
	       "and loads back the same");
	g_clear_error (&e);
	fs_intel_config_free (c2);
	fs_intel_config_free (c);

	expect_conf_error ("[location local-x]\nname=X\ncountries=XA\n",
	                   "[location local-x] id", "an id that is not "
	                   "country- or asn-");
	expect_conf_error ("[location country-x]\nname=X\ncountries=XA\n"
	                   "asns=64500\n", "[location country-x] asns",
	                   "a country rule with AS numbers");
	expect_conf_error ("[location asn-x]\nname=X\nasns=64500\n"
	                   "countries=XA\n", "[location asn-x] countries",
	                   "an AS rule with countries");
	expect_conf_error ("[location country-x]\nname=X\ncountries=XA;C1\n",
	                   "\"C1\" is not a country code",
	                   "a code that is not two letters");
	expect_conf_error ("[location country-x]\nname=X\ncountries=CHN\n",
	                   "\"CHN\" is not a country code", "a three-letter code");
	expect_conf_error ("[location country-x]\nname=X\ncountries=;\n",
	                   "1 to 1000 values", "an empty rule");
	expect_conf_error ("[location country-x]\nname=X\n",
	                   "[location country-x] countries: missing",
	                   "a rule with no countries key");
	expect_conf_error ("[location asn-x]\nname=X\nasns=0\n",
	                   "\"0\" is not an AS number", "AS 0");
	expect_conf_error ("[location asn-x]\nname=X\nasns=4294967296\n",
	                   "is not an AS number", "an AS number past 32 bits");
	expect_conf_error ("[location asn-x]\nname=X\nasns=AS-5\n",
	                   "is not an AS number", "\"AS-5\"");
	expect_conf_error ("[location asn-x]\nname=X\nasns=64500\n"
	                   "direction=sideways\n", "direction",
	                   "a bad direction");
	expect_conf_error ("[location asn-x]\nasns=64500\n", "name",
	                   "a rule without a name");
	expect_conf_error ("[geo]\nenabled=yes\n", "[geo] enabled",
	                   "[geo] enabled not true or false");
	expect_conf_error ("[geo]\naccepted-at=soon\n", "[geo] accepted-at",
	                   "[geo] accepted-at not a time");
	{
		GString *many = g_string_new ("[location asn-x]\nname=X\nasns=");

		for (guint i = 1; i <= FS_INTEL_LOCATION_MAX_VALUES + 1; i++)
			g_string_append_printf (many, "%u;", i);
		g_string_append (many, "\n");
		expect_conf_error (many->str, "1 to 1000 values",
		                   "1,001 values in one rule");
		g_string_free (many, TRUE);
	}

	/* Removing a rule removes its counters' state too. */
	dir = fresh_store ();
	c = geo_conf ((const gchar *const[]) { "country:Gone:XA:in", NULL });
	{
		gchar *p = g_build_filename (dir, "country-gone.state", NULL);

		g_file_set_contents (p, "[state]\n", -1, NULL);
		CHECK (fs_intel_config_remove (c, "country-gone", &e) &&
		       fs_intel_config_location (c, "country-gone") == NULL &&
		       !g_file_test (p, G_FILE_TEST_EXISTS),
		       "removing a location rule removes it and its state file");
		g_clear_error (&e);
		g_free (p);
	}
	fs_intel_config_free (c);
	g_free (dir);
}

/* ======================================================= consent */

static void
test_consent (void)
{
	FsIntelConfig *c = fs_intel_config_new ();
	GError *e = NULL;
	const gchar *codes[] = { "XA", NULL };
	gchar *id = NULL;
	gint64 before = g_get_real_time () / G_USEC_PER_SEC;

	CHECK (!fs_intel_config_add_location (c, "Early", FS_INTEL_LOCATION_COUNTRY,
	                                      codes, FS_INTEL_DIR_IN, &id, &e) &&
	       e != NULL && e->code == FS_INTEL_ERR_CONSENT &&
	       c->locations->len == 0 && id == NULL,
	       "a location rule before the database's terms were accepted: "
	       "CONSENT, nothing added (%s)", e ? e->message : "added");
	g_clear_error (&e);
	CHECK (!fs_intel_config_enable_geo (c, FALSE, &e) && e != NULL &&
	       e->code == FS_INTEL_ERR_CONSENT && !c->geo_enabled &&
	       c->geo_accepted_at == 0,
	       "turning the database on without accepting: CONSENT, still off");
	g_clear_error (&e);
	CHECK (fs_intel_config_enable_geo (c, TRUE, &e) && c->geo_enabled &&
	       c->geo_accepted_at >= before,
	       "accepting turns it on and records when");
	g_clear_error (&e);
	fs_intel_config_disable_geo (c);
	CHECK (!c->geo_enabled && c->geo_accepted_at > 0 &&
	       fs_intel_config_enable_geo (c, FALSE, &e) && c->geo_enabled,
	       "off and on again: the consent is remembered");
	g_clear_error (&e);
	CHECK (fs_intel_config_add_location (c, "Early bird",
	                                     FS_INTEL_LOCATION_COUNTRY, codes,
	                                     FS_INTEL_DIR_IN, &id, &e) &&
	       g_strcmp0 (id, "country-early-bird") == 0,
	       "after consent a rule is added: %s", id ? id : "(none)");
	g_clear_error (&e);
	g_free (id);
	id = NULL;
	CHECK (!fs_intel_config_add_location (c, "EARLY  bird",
	                                      FS_INTEL_LOCATION_COUNTRY, codes,
	                                      FS_INTEL_DIR_IN, &id, &e) &&
	       e != NULL && e->code == FS_INTEL_ERR_INVALID &&
	       c->locations->len == 1,
	       "a name whose id is already a rule is refused");
	g_clear_error (&e);
	{
		const gchar *bad[] = { "XA", "X1", NULL };
		const gchar *none[] = { NULL };
		const gchar *asns[] = { "AS13335", "13335", " 64500 ", NULL };

		CHECK (!fs_intel_config_add_location (c, "Bad",
		                                      FS_INTEL_LOCATION_COUNTRY,
		                                      bad, FS_INTEL_DIR_IN, NULL,
		                                      &e) && e != NULL &&
		       e->code == FS_INTEL_ERR_INVALID &&
		       strstr (e->message, "X1") != NULL,
		       "a bad code is refused naming it (%s)",
		       e ? e->message : "added");
		g_clear_error (&e);
		CHECK (!fs_intel_config_add_location (c, "None",
		                                      FS_INTEL_LOCATION_ASN, none,
		                                      FS_INTEL_DIR_IN, NULL, &e),
		       "a rule with no values is refused");
		g_clear_error (&e);
		CHECK (fs_intel_config_add_location (c, "Cloud",
		                                     FS_INTEL_LOCATION_ASN, asns,
		                                     FS_INTEL_DIR_OUT, &id, &e) &&
		       g_strcmp0 (id, "asn-cloud") == 0 &&
		       fs_intel_config_location (c, id)->asns->len == 2,
		       "an AS rule: \"AS13335\" and \"13335\" are one value");
		g_clear_error (&e);
		CHECK (fs_intel_config_set_location_values (c, "asn-cloud",
		                                            (const gchar *[])
		                                            { "64501", NULL }, &e) &&
		       fs_intel_config_location (c, "asn-cloud")->asns->len == 1,
		       "a rule's values can be replaced");
		g_clear_error (&e);
	}
	g_free (id);

	/* A config written by hand: rules on, the terms never accepted. */
	c->geo_accepted_at = 0;
	CHECK (!fs_intel_config_set_enabled (c, "asn-cloud", TRUE, &e) &&
	       e != NULL && e->code == FS_INTEL_ERR_CONSENT,
	       "turning a rule on without the database's consent: CONSENT");
	g_clear_error (&e);
	CHECK (fs_intel_config_set_dir (c, "asn-cloud", FS_INTEL_DIR_BOTH, &e) &&
	       fs_intel_config_location (c, "asn-cloud")->dir == FS_INTEL_DIR_BOTH,
	       "set_dir works on a location rule");
	g_clear_error (&e);
	fs_intel_config_free (c);
}

/* ======================================================= no network */

static void
test_no_network (void)
{
	gchar *dir = fresh_store ();
	FsIntelConfig *c = fs_intel_config_new ();
	GPtrArray *rs;
	gchar *msg = NULL;

	geo_calls = feed_calls = 0;
	serve_geo (std_xz (now_s - DAY, FALSE, key));
	rs = fs_intel_update (c, NULL, FS_INTEL_UPDATE_NOW, now_s);
	CHECK (rs->len == 0 && geo_calls == 0 && feed_calls == 0,
	       "the default configuration: no result, no request at all");
	g_ptr_array_unref (rs);
	rs = fs_intel_update (c, FS_INTEL_GEO_ID, FS_INTEL_UPDATE_NOW, now_s);
	CHECK (rs->len == 1 && ((FsIntelUpdateResult *) rs->pdata[0])->outcome ==
	       FS_INTEL_FAILED && geo_calls == 0,
	       "asking for the database while it is off: failed, no request (%s)",
	       rs->len ? ((FsIntelUpdateResult *) rs->pdata[0])->message : "");
	g_ptr_array_unref (rs);

	/* intel.conf edited by hand: on, never consented. */
	c->geo_enabled = TRUE;
	CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s, &msg) ==
	       FS_INTEL_NEEDS_CONSENT && geo_calls == 0,
	       "on without consent: needs consent, no request (%s)", msg);
	g_free (msg);

	c->geo_accepted_at = now_s - 10;
	c->enabled = FALSE;
	CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s, &msg) ==
	       FS_INTEL_NOT_DUE && geo_calls == 0,
	       "the master switch off: no request (%s)", msg);
	g_free (msg);
	c->enabled = TRUE;
	c->geo_enabled = FALSE;
	rs = fs_intel_update (c, NULL, FS_INTEL_UPDATE_NOW, now_s);
	CHECK (rs->len == 0 && geo_calls == 0,
	       "consented but turned off: no result, no request");
	g_ptr_array_unref (rs);
	{
		gchar **hosts = fs_intel_update_hosts (c);

		CHECK (hosts[0] == NULL, "and no download host to keep reachable");
		g_strfreev (hosts);
	}

	c->geo_enabled = TRUE;
	c->proxy = g_strdup ("http://proxy.example:3128");
	CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s, &msg) ==
	       FS_INTEL_UPDATED && geo_calls == 1 && feed_calls == 0 &&
	       g_strcmp0 (geo_last_proxy, "http://proxy.example:3128") == 0,
	       "on and consented: one request, through the configured proxy "
	       "(%s)", msg);
	g_free (msg);
	{
		gchar **hosts = fs_intel_update_hosts (c);
		gchar *joined = g_strjoinv (" ", hosts);

		CHECK (g_strcmp0 (joined, "location.ipfire.org proxy.example") == 0,
		       "the database's host and the proxy are kept reachable "
		       "while it is on (%s)", joined);
		g_free (joined);
		g_strfreev (hosts);
	}
	fs_intel_config_free (c);
	g_free (dir);
}

/* ======================================================= updates */

static void
test_updates (void)
{
	gchar *dir = fresh_store ();
	FsIntelConfig *c = geo_conf ((const gchar *const[])
	                             { "country:Atlantis:XA:in", NULL });
	FsIntelGeoStatus st;
	FsIntelRuleset *rs;
	gchar *msg = NULL, *db1, *db2, *before;
	gsize n1 = 0, n2 = 0;
	GError *e = NULL;

	geo_calls = 0;
	serve_geo (std_xz (now_s - 2 * DAY, FALSE, key));
	CHECK (geo_update (c, 0, now_s, &msg) == FS_INTEL_UPDATED &&
	       geo_calls == 1, "first copy: updated (%s)", msg);
	g_free (msg);
	db1 = read_file (dir, "location.db", &n1);
	CHECK (db1 != NULL && fs_intel_geo_status (&st, now_s, NULL) &&
	       st.present && st.created_at == now_s - 2 * DAY && !st.stale &&
	       st.fetched_at == now_s && st.attempted_at == now_s &&
	       g_strcmp0 (st.license, "CC BY-SA 4.0") == 0 &&
	       st.networks == 7 && st.countries == 4 && st.ases == 3,
	       "the status: present, created, fetched, the licence the file "
	       "declares, its counts");
	fs_intel_geo_status_clear (&st);
	CHECK (geo_update (c, 0, now_s + 3600, &msg) == FS_INTEL_NOT_DUE &&
	       geo_calls == 1, "an hour later: not due, no request (%s)", msg);
	g_free (msg);
	CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s + 3600, &msg) ==
	       FS_INTEL_UNCHANGED && geo_calls == 2,
	       "now, the same copy: unchanged (%s)", msg);
	g_free (msg);

	/* A rollback: an older copy, validly signed. */
	rs = fs_intel_build (c, NULL, NULL, NULL);
	before = set_text (rs, "country-atlantis");
	fs_intel_ruleset_free (rs);
	serve_geo (std_xz (now_s - 3 * DAY, TRUE, key));
	CHECK (geo_update (c, FS_INTEL_UPDATE_NOW | FS_INTEL_UPDATE_ACCEPT_SHRINK,
	                   now_s + DAY, &msg) == FS_INTEL_REFUSED &&
	       strstr (msg, "older") != NULL,
	       "an older copy is refused, even with accept-shrink (%s)", msg);
	g_free (msg);
	db2 = read_file (dir, "location.db", &n2);
	CHECK (db2 != NULL && n1 == n2 && memcmp (db1, db2, n1) == 0,
	       "the copy in use is byte for byte the last good one");
	g_free (db2);
	rs = fs_intel_build (c, NULL, NULL, NULL);
	{
		gchar *after = set_text (rs, "country-atlantis");

		CHECK (g_strcmp0 (before, after) == 0,
		       "and the build is unchanged");
		g_free (after);
	}
	fs_intel_ruleset_free (rs);
	CHECK (fs_intel_geo_status (&st, now_s + DAY, NULL) && st.present &&
	       st.created_at == now_s - 2 * DAY && st.refused != NULL &&
	       strstr (st.refused, "older") != NULL,
	       "the status says why the last download was refused (%s)",
	       st.refused ? st.refused : "-");
	fs_intel_geo_status_clear (&st);

	serve_geo (std_xz (now_s - DAY, FALSE, other_key));
	CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s + DAY, &msg) ==
	       FS_INTEL_REFUSED && strstr (msg, "signature") != NULL,
	       "a copy signed by another key: refused (%s)", msg);
	g_free (msg);
	serve_geo (g_bytes_new_static ("not xz at all", 13));
	CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s + DAY, &msg) ==
	       FS_INTEL_REFUSED, "a body that is not xz: refused (%s)", msg);
	g_free (msg);
	serve_geo (std_xz (now_s + 30 * DAY, FALSE, key));
	CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s + DAY, &msg) ==
	       FS_INTEL_REFUSED, "a copy from the future: refused (%s)", msg);
	g_free (msg);
	serve_geo (NULL);
	geo_fail = g_strdup ("Could not resolve host\nsecond line");
	CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s + DAY, &msg) ==
	       FS_INTEL_FAILED && strstr (msg, "Could not resolve") != NULL &&
	       strstr (msg, "second line") == NULL,
	       "a failed download: failed, first line only (%s)", msg);
	g_free (msg);
	db2 = read_file (dir, "location.db", &n2);
	CHECK (db2 != NULL && n1 == n2 && memcmp (db1, db2, n1) == 0,
	       "after every refusal and failure, the same copy is in use");
	g_free (db2);
	CHECK (fs_intel_geo_status (&st, now_s + DAY, NULL) &&
	       st.last_error != NULL && st.fetched_at == now_s + 3600,
	       "the status keeps the last error and the last success");
	fs_intel_geo_status_clear (&st);

	serve_geo (std_xz (now_s - 12 * 3600, TRUE, key));
	CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s + DAY, &msg) ==
	       FS_INTEL_UPDATED, "a newer copy: updated (%s)", msg);
	g_free (msg);
	{
		GPtrArray *one = fs_intel_update (c, FS_INTEL_GEO_ID, 0,
		                                  now_s + DAY + 60);

		CHECK (one->len == 1 && ((FsIntelUpdateResult *)
		       one->pdata[0])->outcome == FS_INTEL_NOT_DUE,
		       "only_id \"location\" updates just the database");
		g_ptr_array_unref (one);
	}

	/* Review GEO-ROLLBACK-1 / GEO-2: the floor is the newest copy ever
	 * accepted (geodb.state), not whatever location.db is now.  A copy
	 * in use that is damaged or gone is repaired only by a copy at
	 * least that new; an older signed copy is still a rollback. */
	{
		const gint64 floor_t = now_s - 12 * 3600;
		gchar *p = g_build_filename (dir, "location.db", NULL);
		gchar *d = NULL, *state, *want;
		gsize n = 0;

		g_file_get_contents (p, &d, &n, NULL);
		d[n - 1] ^= 0x01;
		g_file_set_contents (p, d, (gssize) n, NULL);
		g_chmod (p, 0600);
		serve_geo (std_xz (now_s - 400 * DAY, FALSE, key));
		CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s + DAY, &msg) ==
		       FS_INTEL_REFUSED && strstr (msg, "older") != NULL,
		       "rollback floor: one byte of the copy in use damaged, a "
		       "signed copy 400 days old is still refused (%s)", msg);
		g_free (msg);
		db2 = read_file (dir, "location.db", &n2);
		CHECK (db2 != NULL && n2 == n && memcmp (db2, d, n) == 0,
		       "rollback floor: the damaged copy is left as it was (the "
		       "build keeps failing closed)");
		g_free (db2);
		g_unlink (p);
		CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s + DAY, &msg) ==
		       FS_INTEL_REFUSED && strstr (msg, "older") != NULL &&
		       !g_file_test (p, G_FILE_TEST_EXISTS),
		       "rollback floor: the copy in use deleted, the old copy is "
		       "still refused and nothing is installed (%s)", msg);
		g_free (msg);
		state = read_file (dir, "geodb.state", NULL);
		want = g_strdup_printf ("created-at=%" G_GINT64_FORMAT "\n",
		                        floor_t);
		CHECK (state != NULL && strstr (state, want) != NULL,
		       "rollback floor: geodb.state still records the newest copy "
		       "accepted (%s)", want);
		g_free (state);
		g_free (want);
		serve_geo (std_xz (now_s - DAY - 1, TRUE, key));
		CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s + DAY, &msg) ==
		       FS_INTEL_REFUSED,
		       "rollback floor: a copy one day and a second older than "
		       "the floor is refused too (%s)", msg);
		g_free (msg);
		serve_geo (std_xz (floor_t, TRUE, key));
		CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s + DAY, &msg) ==
		       FS_INTEL_UPDATED &&
		       fs_intel_geo_status (&st, now_s + DAY, NULL) && st.present &&
		       st.created_at == floor_t,
		       "rollback floor: the copy last accepted (the same second) "
		       "repairs it (%s)", msg);
		fs_intel_geo_status_clear (&st);
		g_free (msg);
		g_free (d);
		g_free (p);
	}
	{
		gchar *audit = read_file (base, "audit.log", NULL);

		CHECK (audit != NULL && strstr (audit, "location: refused: ") &&
		       strstr (audit, "location: updated: "),
		       "every attempt is an audit line");
		g_free (audit);
	}
	(void) e;
	g_free (before);
	g_free (db1);
	fs_intel_config_free (c);
	g_free (dir);
}

/* ======================================================= the build */

static FsHostNet *
host_fixture (void)
{
	FsHostNet *h = fs_hostnet_new ();

	fs_range_set_add_text (h->own, "198.51.100.200");
	fs_range_set_add_text (h->gateways, "198.51.100.1");
	fs_range_set_add_text (h->resolvers, "2001:db8:a::53");
	fs_range_set_normalize (h->own);
	fs_range_set_normalize (h->gateways);
	fs_range_set_normalize (h->resolvers);
	return h;
}

/* What the enumeration gives minus `minus' (normalized). */
static gchar *
expected (const gchar *const *codes, guint32 asn, const gchar *minus)
{
	gsize len = 0;
	guint8 *d = std_db (now_s - DAY, FALSE, key, &len);
	gchar *path = g_build_filename (base, "expect.db", NULL);
	FsGeodb *db;
	FsGeodbFilter f = { codes, asn ? &asn : NULL, asn ? 1 : 0, 0 };
	FsRangeSet *set, *rm = fs_range_set_new ();
	gchar **v = g_strsplit (minus, " ", -1), *out;

	g_file_set_contents (path, (const gchar *) d, (gssize) len, NULL);
	db = fs_geodb_open (path, NULL);
	set = db ? fs_geodb_enumerate (db, &f, NULL) : fs_range_set_new ();
	for (guint i = 0; v[i] != NULL; i++)
		if (*v[i])
			fs_range_set_add_text (rm, v[i]);
	fs_range_set_normalize (rm);
	fs_range_set_subtract (set, fs_range_protected ());
	fs_range_set_subtract (set, rm);
	out = fs_range_set_to_text (set);
	fs_range_set_free (set);
	fs_range_set_free (rm);
	fs_geodb_close (db);
	g_unlink (path);
	g_free (path);
	g_free (d);
	g_strfreev (v);
	return out;
}

static void
test_build (void)
{
	gchar *dir = fresh_store ();
	FsIntelConfig *c = geo_conf ((const gchar *const[]) {
		"country:Atlantis:XA:in", "asn:Beta:64501:out",
		"country:Nowhere:XZ:in", "asn:Empty:64999:both", NULL });
	FsHostNet *host = host_fixture ();
	GPtrArray *notes = NULL;
	GError *e = NULL;
	FsIntelRuleset *rs;
	gchar *got, *want, *all;

	/* No copy yet: notes, no sets, no failure. */
	rs = fs_intel_build (c, host, &notes, &e);
	all = notes_joined (notes);
	CHECK (rs != NULL && rs->sets->len == 0 &&
	       notes_have (notes, "Atlantis is not enforced: the location "
	                   "database has not been downloaded yet") &&
	       notes_have (notes, "Beta is not enforced"),
	       "no copy yet: every rule says it is not enforced (%s)", all);
	g_free (all);
	g_clear_pointer (&notes, g_ptr_array_unref);
	fs_intel_ruleset_free (rs);
	g_clear_error (&e);

	install_std (c, now_s - DAY, FALSE);
	fs_range_set_add_text (c->exceptions, "198.51.100.7");
	fs_range_set_add_text (c->exceptions, "2001:db8:a::1");
	fs_range_set_add_text (c->exceptions, "203.0.113.5");
	fs_range_set_normalize (c->exceptions);
	rs = fs_intel_build (c, host, &notes, &e);
	all = notes_joined (notes);
	CHECK (rs != NULL, "the build succeeds (%s)", e ? e->message : "ok");
	g_clear_error (&e);

	got = set_text (rs, "country-atlantis");
	want = expected ((const gchar *const[]) { "XA", NULL }, 0,
	                 "198.51.100.7 2001:db8:a::1 203.0.113.5 198.51.100.200 "
	                 "198.51.100.1 2001:db8:a::53");
	CHECK (g_strcmp0 (got, want) == 0 && strstr (got, "10.") == NULL &&
	       strstr (got, "198.51.100.128") == NULL,
	       "the country set is the enumeration minus the protected ranges, "
	       "the exceptions and this computer's addresses; the nested XB "
	       "network and 10/8 are out:\n%s", got);
	g_free (want);
	g_free (got);
	CHECK (set_of (rs, "country-atlantis")->dir == FS_INTEL_DIR_IN &&
	       g_strcmp0 (set_of (rs, "country-atlantis")->label, "Atlantis") == 0,
	       "its direction and label are the rule's");
	CHECK (notes_have (notes, "Not blocked, by exception: 198.51.100.7, "
	                   "203.0.113.5, 2001:db8:a::1 (listed by Atlantis)") &&
	       notes_have (notes, "Kept reachable: 198.51.100.200 (this "
	                   "computer's own address), although Beta lists it") &&
	       notes_have (notes, "Kept reachable: 198.51.100.1 (a default "
	                   "gateway), although Atlantis lists it"),
	       "exceptions win, and the notes say so (%s)", all);
	CHECK (notes_have (notes, "Atlantis includes 8 anycast prefixes (255 "
	                   "IPv4 addresses)") &&
	       !notes_have (notes, "Beta includes"),
	       "anycast is kept and counted after the exception (203.0.113.0/24 "
	       "less .5 is 8 prefixes): the note says so (%s)", all);
	got = set_text (rs, "asn-beta");
	CHECK (g_strcmp0 (got, "198.51.100.128-198.51.100.199\n"
	                       "198.51.100.201-198.51.100.255\n"
	                       "64:ff9b::c633:6480-64:ff9b::c633:64c7\n"
	                       "64:ff9b::c633:64c9-64:ff9b::c633:64ff\n"
	                       "2001:db8:b::/48\n") == 0,
	       "an outbound AS rule: its networks less this computer's own "
	       "address, also in 64:ff9b::/96 (%s)",
	       got);
	g_free (got);
	CHECK (notes_have (notes, "Nowhere: the location database names no "
	                   "country XZ") &&
	       notes_have (notes, "Nowhere matches no address") &&
	       notes_have (notes, "Empty matches no address") &&
	       set_of (rs, "asn-empty") != NULL &&
	       fs_range_set_is_empty (set_of (rs, "asn-empty")->ranges),
	       "rules that match nothing are enforced empty, with notes");
	g_free (all);
	g_clear_pointer (&notes, g_ptr_array_unref);
	fs_intel_ruleset_free (rs);

	/* Merged with a local list in one rule set; lists first. */
	{
		gchar *csv = g_build_filename (base, "list.csv", NULL);
		gchar *id = NULL;

		g_file_set_contents (csv, "192.0.2.10\n198.51.100.20\n", -1, NULL);
		CHECK (fs_intel_import_list (c, csv, "Lab", FS_INTEL_DIR_IN, NULL,
		                             &id, &e),
		       "a local list is imported beside the rules");
		g_clear_error (&e);
		g_unlink (csv);
		g_free (csv);
		g_free (id);
	}
	rs = fs_intel_build (c, host, NULL, &e);
	CHECK (rs != NULL && rs->sets->len == 5 &&
	       strcmp (((FsIntelSet *) rs->sets->pdata[0])->id, "local-lab") == 0 &&
	       strcmp (((FsIntelSet *) rs->sets->pdata[1])->id,
	               "country-atlantis") == 0,
	       "lists and location rules in one rule set, lists first");
	{
		gchar *script = rs ? fs_intelset_nft_script (rs) : NULL;

		CHECK (script != NULL &&
		       strstr (script, "set s_local_lab_4 ") != NULL &&
		       strstr (script, "set s_country_atlantis_4 ") != NULL &&
		       strstr (script, "set s_country_atlantis_6 ") != NULL &&
		       strstr (script, "set s_asn_beta_6 ") != NULL &&
		       strstr (script, "log prefix \"STOCKFW-TI country-atlantis \"") &&
		       strstr (script, "counter drop comment \"country-atlantis\""),
		       "the nft script has separate sets per kind, with their own "
		       "log prefix and counter comment");
		g_free (script);
	}
	fs_intel_ruleset_free (rs);
	g_clear_error (&e);

	/* The database off: the rules stay, nothing is enforced. */
	fs_intel_config_disable_geo (c);
	rs = fs_intel_build (c, host, NULL, &e);
	CHECK (rs != NULL && rs->sets->len == 1 &&
	       set_of (rs, "country-atlantis") == NULL,
	       "the database turned off: only the list is built");
	fs_intel_ruleset_free (rs);
	c->geo_enabled = TRUE;

	/* A copy that no longer verifies: the build fails, closed. */
	{
		gchar *p = g_build_filename (dir, "location.db", NULL);
		gchar *d = NULL;
		gsize n = 0;

		g_file_get_contents (p, &d, &n, NULL);
		d[n - 20] ^= 0x01;
		g_file_set_contents (p, d, (gssize) n, NULL);
		g_chmod (p, 0600);
		rs = fs_intel_build (c, host, NULL, &e);
		CHECK (rs == NULL && e != NULL && e->code == FS_INTEL_ERR_TAMPERED &&
		       strstr (e->message, "location database") != NULL,
		       "a copy in use that no longer verifies fails the build "
		       "(%s)", e ? e->message : "built");
		g_clear_error (&e);
		fs_intel_ruleset_free (rs);
		/* and an update repairs it */
		serve_geo (std_xz (now_s - DAY + 60, FALSE, key));
		CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s, NULL) ==
		       FS_INTEL_UPDATED &&
		       (rs = fs_intel_build (c, host, NULL, NULL)) != NULL,
		       "the next update replaces the damaged copy");
		fs_intel_ruleset_free (rs);
		g_free (d);
		g_free (p);
	}

	/* A stale copy is enforced, with a note. */
	{
		FsIntelConfig *s = geo_conf ((const gchar *const[])
		                             { "country:Old:XA:in", NULL });
		gchar *sdir = fresh_store ();

		install_std (s, now_s - 40 * DAY, FALSE);
		rs = fs_intel_build (s, NULL, &notes, NULL);
		CHECK (rs != NULL && set_of (rs, "country-old") != NULL &&
		       !fs_range_set_is_empty (set_of (rs, "country-old")->ranges) &&
		       notes_have (notes, "more than 30 days ago"),
		       "a copy 40 days old is still enforced, with a note");
		g_clear_pointer (&notes, g_ptr_array_unref);
		fs_intel_ruleset_free (rs);
		fs_intel_config_free (s);
		g_free (sdir);
	}
	fs_hostnet_free (host);
	fs_intel_config_free (c);
	g_free (dir);
}

/* ======================================================= the limits */

static void
test_limits (void)
{
	gchar *dir = fresh_store ();
	GeoWriter *w = geow_new (now_s - DAY);
	FsIntelConfig *c;
	FsIntelRuleset *rs;
	GError *e = NULL;
	guint8 *d;
	gsize len = 0;
	const guint n = 300001;

	/* 300,001 networks of XL, none touching: more intervals than the
	 * lists may have, fewer than the location limit. */
	for (guint i = 0; i < n; i++) {
		guint32 a = 0x2d000000u + 4u * i;   /* from 45.0.0.0 */
		gchar *cidr = g_strdup_printf ("%u.%u.%u.%u/31", a >> 24,
		                               (a >> 16) & 255, (a >> 8) & 255,
		                               a & 255);

		geow_net (w, cidr, "XL", 64600, 0);
		g_free (cidr);
	}
	/* and one country of 2^27 addresses, past the lists' 2^26 union */
	geow_net (w, "64.0.0.0/5", "XW", 64601, 0);
	geow_country (w, "XL", "EU", "Largeland");
	geow_country (w, "XW", "EU", "Wideland");
	d = geow_build (w, key, &len);
	geow_free (w);
	c = geo_conf ((const gchar *const[]) { "country:Large:XL:in",
	                                       "country:Wide:XW:in", NULL });
	serve_geo (geow_xz (d, len));
	g_free (d);
	CHECK (geo_update (c, FS_INTEL_UPDATE_NOW, now_s, NULL) == FS_INTEL_UPDATED,
	       "a database with 300,001 networks of one country installs");
	rs = fs_intel_build (c, NULL, NULL, &e);
	CHECK (rs != NULL &&
	       fs_range_set_count4 (set_of (rs, "country-large")->ranges) == n &&
	       fs_range_set_addresses4 (set_of (rs, "country-wide")->ranges) ==
	       (G_GUINT64_CONSTANT (1) << 27),
	       "the lists' caps do not apply to location rules: 300,001 "
	       "intervals and 2^27 addresses build (%s)",
	       e ? e->message : "ok");
	g_clear_error (&e);
	fs_intel_ruleset_free (rs);
	fs_intel_config_set_dir (c, "country-large", FS_INTEL_DIR_OUT, NULL);
	rs = fs_intel_build (c, NULL, NULL, &e);
	CHECK (rs == NULL && e != NULL && e->code == FS_INTEL_ERR_TOO_BIG &&
	       strstr (e->message, "500,000") != NULL &&
	       strstr (e->message, "Large (600,002)") != NULL,
	       "outbound, with its NAT64 copy, it passes 500,000: refused, "
	       "naming the rule (%s)", e ? e->message : "built");
	g_clear_error (&e);
	fs_intel_ruleset_free (rs);
	fs_intel_config_free (c);
	g_free (dir);
}

/* ======================================================= lookups */

static void
expect_lookup (const FsIntelConfig *c, const FsHostNet *host,
               const gchar *addr, const gchar *want, const gchar *what)
{
	FsIntelLookup r;
	GString *got = g_string_new (NULL);
	gchar *sentence;

	fs_intel_lookup (c, host, addr, &r);
	g_string_append_printf (got, "cc=%s(%s) asn=%u(%s) net=%s flags=%u "
	                        "%slocations=", r.country,
	                        r.country_name ? r.country_name : "-", r.asn,
	                        r.as_name ? r.as_name : "-",
	                        r.network ? r.network : "-", r.geo_flags,
	                        r.geo_via_nat64 ? "via=nat64 " : "");
	for (guint i = 0; i < r.locations->len; i++)
		g_string_append_printf (got, "%s%s", i ? "," : "",
		                        (gchar *) r.locations->pdata[i]);
	g_string_append_printf (got, " lists=%u dir=%s blocked=%d exception=%d",
	                        r.sources->len,
	                        r.dir ? fs_intel_dir_to_string (r.dir) : "-",
	                        r.blocked, r.is_exception);
	sentence = fs_intel_lookup_sentence (c, &r);
	if (sentence != NULL)
		g_string_append_printf (got, " | %s", sentence);
	CHECK (strcmp (got->str, want) == 0, "lookup %s: %s\n      got:  %s",
	       addr, what, got->str);
	g_free (sentence);
	g_string_free (got, TRUE);
	fs_intel_lookup_clear (&r);
}

static void
test_lookup (void)
{
	gchar *dir = fresh_store ();
	FsIntelConfig *c = geo_conf ((const gchar *const[]) {
		"country:Atlantis:XA:in", "asn:Beta:64501:out", NULL });
	FsGeodbMatch m;
	GError *e = NULL;

	install_std (c, now_s - DAY, FALSE);
	fs_range_set_add_text (c->exceptions, "198.51.100.7");
	fs_range_set_normalize (c->exceptions);

	expect_lookup (c, NULL, "198.51.100.9",
	               "cc=XA(Atlantis) asn=64500(Alpha Networks) "
	               "net=198.51.100.0/24 flags=0 locations=country-atlantis "
	               "lists=0 dir=in blocked=1 exception=0 | Blocked by threat "
	               "intel: Atlantis", "registered in XA, blocked inbound");
	expect_lookup (c, NULL, "198.51.100.130",
	               "cc=XB(Brigadoon) asn=64501(Beta Hosting) "
	               "net=198.51.100.128/25 flags=0 locations=asn-beta lists=0 "
	               "dir=out blocked=1 exception=0 | Blocked by threat intel: "
	               "Beta", "the nested network: XB, the AS rule (outbound)");
	/* Review GEO-3: a NAT64 address is shown with the country, AS and
	 * network of the IPv4 address it carries (via=nat64). */
	expect_lookup (c, NULL, "64:ff9b::c633:6482",
	               "cc=XB(Brigadoon) asn=64501(Beta Hosting) "
	               "net=198.51.100.128/25 flags=0 via=nat64 "
	               "locations=asn-beta lists=0 dir=out blocked=1 exception=0 "
	               "| Blocked by threat intel: Beta",
	               "its NAT64 form: the outbound rule holds it, and it is "
	               "located by its IPv4 address");
	expect_lookup (c, NULL, "64:ff9b::c633:6409",
	               "cc=XA(Atlantis) asn=64500(Alpha Networks) "
	               "net=198.51.100.0/24 flags=0 via=nat64 locations= lists=0 "
	               "dir=- blocked=0 exception=0",
	               "a NAT64 address in XA: located by its IPv4 address, yet "
	               "no inbound rule holds it");
	expect_lookup (c, NULL, "64:ff9b::6440:1",
	               "cc=(-) asn=0(-) net=- flags=0 locations= lists=0 dir=- "
	               "blocked=0 exception=0",
	               "a NAT64 address whose IPv4 address is in no network");
	expect_lookup (c, NULL, "198.51.100.7",
	               "cc=XA(Atlantis) asn=64500(Alpha Networks) "
	               "net=198.51.100.0/24 flags=0 locations=country-atlantis "
	               "lists=0 dir=in blocked=0 exception=1",
	               "an exception: located, not blocked");
	expect_lookup (c, NULL, "203.0.113.77",
	               "cc=XA(Atlantis) asn=64502(Anycast CDN) net=203.0.113.0/24 "
	               "flags=4 locations=country-atlantis lists=0 dir=in "
	               "blocked=1 exception=0 | Blocked by threat intel: Atlantis",
	               "an anycast network: flagged");
	expect_lookup (c, NULL, "2001:db8:b::5",
	               "cc=XB(Brigadoon) asn=64501(Beta Hosting) "
	               "net=2001:db8:b::/48 flags=0 locations=asn-beta lists=0 "
	               "dir=out blocked=1 exception=0 | Blocked by threat intel: "
	               "Beta", "IPv6");
	expect_lookup (c, NULL, "192.0.2.1",
	               "cc=XC(Cockaigne) asn=64503(-) net=192.0.2.0/24 flags=0 "
	               "locations= lists=0 dir=- blocked=0 exception=0",
	               "enrichment without a rule: country and AS only");
	expect_lookup (c, NULL, "10.1.2.3",
	               "cc=XA(Atlantis) asn=64500(Alpha Networks) net=10.0.0.0/8 "
	               "flags=0 locations=country-atlantis lists=0 dir=in "
	               "blocked=0 exception=0",
	               "protected space is located but never blocked");
	expect_lookup (c, NULL, "100.64.0.1",
	               "cc=(-) asn=0(-) net=- flags=0 locations= lists=0 dir=- "
	               "blocked=0 exception=0", "no network");

	CHECK (fs_intel_geo_lookup (c, "198.51.100.9", &m, &e) && m.found &&
	       strcmp (m.country, "XA") == 0 && m.asn == 64500,
	       "geo_lookup: the cheap answer for events");
	fs_geodb_match_clear (&m);
	g_clear_error (&e);
	CHECK (!fs_intel_geo_lookup (c, "not an address", &m, &e) && e != NULL,
	       "geo_lookup of a non-address: an error");
	g_clear_error (&e);

	/* The cache follows the file: a newer copy moves 192.0.2.0/24. */
	serve_geo (std_xz (now_s - 3600, TRUE, key));
	geo_update (c, FS_INTEL_UPDATE_NOW, now_s, NULL);
	CHECK (fs_intel_geo_lookup (c, "192.0.2.1", &m, NULL) &&
	       strcmp (m.country, "XD") == 0,
	       "after an update the lookup answers from the new copy (%s)",
	       m.country);
	fs_geodb_match_clear (&m);

	fs_intel_config_disable_geo (c);
	CHECK (!fs_intel_geo_lookup (c, "198.51.100.9", &m, &e) && e != NULL,
	       "the database off: geo_lookup answers nothing");
	g_clear_error (&e);
	expect_lookup (c, NULL, "198.51.100.9",
	               "cc=(-) asn=0(-) net=- flags=0 locations= lists=0 dir=- "
	               "blocked=0 exception=0",
	               "the database off: no location, no rule");
	c->geo_enabled = TRUE;

	{
		FsIntelLocationStats st;
		const gchar *xa[] = { "xa", NULL };
		const gchar *bad[] = { "1", NULL };

		CHECK (fs_intel_location_stats (c, FS_INTEL_LOCATION_COUNTRY, xa,
		                                &st, &e) &&
		       st.prefixes4 == 8 && st.prefixes6 == 1 &&
		       st.addresses4 == 128 + 256 - 1 &&
		       st.anycast_prefixes == 1 && st.anycast_addresses4 == 256,
		       "the picker's preview for XA: 8 IPv4 prefixes (.0/25 less "
		       "the exception, and the anycast /24), 1 IPv6, 1 anycast "
		       "prefix (%u %u %" G_GUINT64_FORMAT " %u)", st.prefixes4,
		       st.prefixes6, st.addresses4, st.anycast_prefixes);
		g_clear_error (&e);
		CHECK (!fs_intel_location_stats (c, FS_INTEL_LOCATION_COUNTRY, bad,
		                                 &st, &e) && e != NULL,
		       "the preview refuses a bad code");
		g_clear_error (&e);
	}
	{
		GPtrArray *cs = fs_intel_geo_countries (&e);
		GPtrArray *as = fs_intel_geo_search_as ("beta", 10, NULL);

		CHECK (cs != NULL && cs->len == 4 &&
		       strcmp (((FsGeodbCountry *) cs->pdata[0])->code, "XA") == 0 &&
		       as != NULL && as->len == 1 &&
		       ((FsGeodbAs *) as->pdata[0])->asn == 64501,
		       "the picker: countries and an AS search from the copy in use");
		if (cs)
			g_ptr_array_unref (cs);
		if (as)
			g_ptr_array_unref (as);
		g_clear_error (&e);
	}
	fs_intel_config_free (c);
	g_free (dir);
}

/* ======================================================= the gate */

static void
test_gate (void)
{
	gchar *dir = fresh_store ();
	FsIntelConfig *c = geo_conf ((const gchar *const[]) {
		"country:Atlantis:XA:both", NULL });
	FsIntelOutcome *o;
	FsHostNet *host = fs_hostnet_new ();
	GError *e = NULL;
	gchar *detail = NULL, *d1;
	GHashTable *cnt;

	kern_reset ();
	install_std (c, now_s - DAY, FALSE);
	{
		gchar *csv = g_build_filename (base, "list.csv", NULL);

		g_file_set_contents (csv, "192.0.2.10\n", -1, NULL);
		fs_intel_import_list (c, csv, "Lab", FS_INTEL_DIR_IN, NULL, NULL,
		                      NULL);
		g_unlink (csv);
		g_free (csv);
	}
	fs_intel_config_save (c, NULL);

	o = fs_intel_apply_safe (&fake_backend, c, host, "test", "Audit-only",
	                         &e);
	CHECK (o != NULL && o->result == FS_APPLY_DRY_RUN && kern.apply_calls == 0,
	       "a hold keeps the location sets out of the kernel too");
	fs_intel_outcome_free (o);
	o = fs_intel_apply_safe (&fake_backend, c, host, "test", NULL, &e);
	CHECK (o != NULL && o->result == FS_APPLY_OK && o->sets == 2 &&
	       kern.got_text != NULL &&
	       strstr (kern.got_text, "[country-atlantis both]") != NULL &&
	       strstr (kern.got_text, "[local-lab in]") != NULL,
	       "an apply gives the kernel the list and the country set");
	d1 = o ? g_strdup (o->digest) : NULL;
	fs_intel_outcome_free (o);
	CHECK (fs_intel_state (&fake_backend, c, &detail) ==
	       FS_INTEL_STATE_ENFORCED &&
	       g_strcmp0 (detail, "1 list and 1 location rule are enforced: "
	                          "Lab, Atlantis.") == 0,
	       "state: enforced, naming the list and the rule (%s)", detail);
	g_free (detail);
	CHECK (fs_intel_applied_has ("country-atlantis"),
	       "the log parser accepts STOCKFW-TI country-atlantis");

	/* counters carry across a replace */
	counter_set (kern.counters, "country-atlantis", 7, 700);
	fs_intel_config_set_dir (c, "country-atlantis", FS_INTEL_DIR_IN, NULL);
	o = fs_intel_apply_safe (&fake_backend, c, host, "test", NULL, &e);
	cnt = fs_intel_counters (&fake_backend);
	{
		FsIntelCounter *k = g_hash_table_lookup (cnt, "country-atlantis");

		CHECK (o != NULL && o->result == FS_APPLY_OK &&
		       g_strcmp0 (o->digest, d1) != 0 && k != NULL &&
		       k->packets == 7 && k->bytes == 700,
		       "a location rule's counters carry across a replace");
	}
	g_hash_table_unref (cnt);
	fs_intel_outcome_free (o);

	/* Stop and Start */
	CHECK (fs_intel_suspend (&fake_backend, "test", &e) &&
	       kern.live == FS_INTEL_LIVE_ABSENT &&
	       fs_intel_state (&fake_backend, NULL, NULL) ==
	       FS_INTEL_STATE_SUSPENDED,
	       "Stop removes the table with the location set: suspended");
	g_clear_error (&e);
	fs_intel_config_save (c, NULL);
	o = fs_intel_resume (&fake_backend, "test", NULL, &e);
	CHECK (o != NULL && o->result == FS_APPLY_OK &&
	       kern.live == FS_INTEL_LIVE_PRESENT &&
	       strstr (kern.got_text, "[country-atlantis in]") != NULL,
	       "Start brings it back through the gate");
	fs_intel_outcome_free (o);
	g_clear_error (&e);

	/* Review GEO-1: the copy in use stops verifying (or goes) after an
	 * apply.  The kernel keeps the country set (the build fails
	 * closed), so the lookup must not say "not blocked". */
	{
		gchar *p = g_build_filename (dir, "location.db", NULL);
		gchar *d = NULL, *s;
		gsize n = 0;
		FsIntelLookup r;

		g_file_get_contents (p, &d, &n, NULL);
		d[n - 20] ^= 0x01;
		g_file_set_contents (p, d, (gssize) n, NULL);
		g_chmod (p, 0600);
		fs_range_set_add_text (c->exceptions, "198.51.100.7");
		fs_range_set_normalize (c->exceptions);
		o = fs_intel_apply_safe (&fake_backend, c, host, "test", NULL, &e);
		CHECK ((o == NULL || o->result != FS_APPLY_OK) && e != NULL &&
		       e->code == FS_INTEL_ERR_TAMPERED &&
		       strstr (kern.got_text, "[country-atlantis in]") != NULL,
		       "a damaged copy: the apply is refused and the kernel keeps "
		       "the country set (%s)", e ? e->message : "applied");
		fs_intel_outcome_free (o);
		g_clear_error (&e);
		for (guint pass = 0; pass < 2; pass++) {
			const gchar *how = pass == 0 ? "damaged" : "deleted";

			fs_intel_lookup (c, host, "198.51.100.9", &r);
			s = fs_intel_lookup_sentence (c, &r);
			CHECK (s != NULL && strstr (s, "Atlantis") != NULL &&
			       strstr (s, "cannot be read") != NULL &&
			       r.locations_unknown != NULL &&
			       r.locations_unknown->len == 1 &&
			       strcmp (r.locations_unknown->pdata[0],
			               "country-atlantis") == 0 &&
			       r.geo_unknown && !r.blocked,
			       "lookup with the copy in use %s while Atlantis is in "
			       "the kernel: never \"not blocked\" (%s)", how,
			       s ? s : "no sentence");
			g_free (s);
			fs_intel_lookup_clear (&r);
			/* an exception and protected space still win, as in
			 * the kernel */
			for (guint k = 0; k < 2; k++) {
				const gchar *a = k ? "10.1.2.3" : "198.51.100.7";

				fs_intel_lookup (c, host, a, &r);
				s = fs_intel_lookup_sentence (c, &r);
				CHECK (s == NULL && !r.blocked,
				       "lookup of %s with the copy %s: no sentence "
				       "(%s)", a, how, s ? s : "none");
				g_free (s);
				fs_intel_lookup_clear (&r);
			}
			g_unlink (p);
		}
		/* suspended: nothing is in the kernel, nothing is claimed */
		CHECK (fs_intel_suspend (&fake_backend, "test", &e), "Stop");
		g_clear_error (&e);
		fs_intel_lookup (c, host, "198.51.100.9", &r);
		s = fs_intel_lookup_sentence (c, &r);
		CHECK (s == NULL && r.locations_unknown->len == 0,
		       "after Stop, a missing copy claims nothing (%s)",
		       s ? s : "no sentence");
		g_free (s);
		fs_intel_lookup_clear (&r);
		install_std (c, now_s - DAY, FALSE);
		fs_intel_config_save (c, NULL);
		o = fs_intel_resume (&fake_backend, "test", NULL, &e);
		CHECK (o != NULL && o->result == FS_APPLY_OK,
		       "the copy last accepted repairs it, and Start applies again");
		fs_intel_outcome_free (o);
		g_clear_error (&e);
		fs_intel_lookup (c, host, "198.51.100.9", &r);
		CHECK (r.blocked && !r.geo_unknown && r.locations_unknown->len == 0,
		       "and the lookup is certain again");
		fs_intel_lookup_clear (&r);
		g_free (d);
		g_free (p);
	}

	/* Only rules, the database off: off, and says why. */
	{
		FsIntelConfig *r = geo_conf ((const gchar *const[]) {
			"country:Only:XA:in", NULL });

		fs_intel_config_disable_geo (r);
		kern_reset ();
		CHECK (fs_intel_state (&fake_backend, r, &detail) ==
		       FS_INTEL_STATE_OFF && detail != NULL &&
		       strstr (detail, "location database is off") != NULL,
		       "rules on, the database off: state off, and why (%s)",
		       detail);
		g_free (detail);
		fs_intel_config_free (r);
	}

	/* A platform without the slots says so, for both kinds. */
	o = fs_intel_apply_safe (&bare_backend, c, host, "test", NULL, &e);
	CHECK (o != NULL && o->result == FS_APPLY_FAILED && e != NULL &&
	       strcmp (e->message, "Blocklists and country or network-owner "
	                           "blocking are not available on this "
	                           "platform yet.") == 0,
	       "no slots: blocklists and location blocking are not available "
	       "(%s)", e ? e->message : "-");
	g_clear_error (&e);
	fs_intel_outcome_free (o);
	CHECK (fs_intel_state (&bare_backend, c, &detail) ==
	       FS_INTEL_STATE_UNSUPPORTED && detail != NULL &&
	       strstr (detail, "country or network-owner") != NULL,
	       "and the state says the same");
	g_free (detail);
	g_free (d1);
	fs_hostnet_free (host);
	fs_intel_config_free (c);
	g_free (dir);
}

static void
test_engine (const gchar *argv0)
{
	gchar *pem;

	if (!find_base (argv0)) {
		g_print ("SKIP: no directory whose parents pass the store check "
		         "(set STOCKFW_TEST_SAFE_DIR); engine tests not run\n");
		return;
	}
	now_s = g_get_real_time () / G_USEC_PER_SEC;
	key = geow_key_new ();
	other_key = geow_key_new ();
	pem = geow_key_pub_pem (key);
	fs_geodb_testing_set_key (pem);
	g_free (pem);
	fs_geodb_set_fetcher (fake_geo_fetch, NULL);
	fs_intel_set_fetcher (fake_feed_fetch, NULL);
	kern_reset ();

	test_config ();
	test_consent ();
	test_no_network ();
	test_updates ();
	test_build ();
	test_limits ();
	test_lookup ();
	test_gate ();

	fs_geodb_set_fetcher (NULL, NULL);
	fs_intel_set_fetcher (NULL, NULL);
	fs_geodb_testing_set_key (NULL);
	serve_geo (NULL);
	g_free (geo_last_proxy);
	EVP_PKEY_free (key);
	EVP_PKEY_free (other_key);
	g_hash_table_unref (kern.counters);
	g_free (kern.live_digest);
	g_free (kern.got_text);
	g_free (kern.got_digest);
	rm_rf (base);
	g_free (base);
}

#else

static void
test_engine (const gchar *argv0)
{
	(void) argv0;
	g_print ("SKIP: the threat-intel store is Linux-only until Round 3\n");
}

#endif

int
main (int argc, char **argv)
{
	(void) argc;
	test_wording ();
	test_engine (argv[0]);
	g_print ("\n%u checks, %s: %u failure(s)\n", checks,
	         failures ? "FAILED" : "PASSED", failures);
	return failures ? 1 : 0;
}
