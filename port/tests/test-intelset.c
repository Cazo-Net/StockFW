/*---[ test-intelset.c ]-------------------------------------------------
 * The threat-intel rule set and its nftables rendering (fs-intelset),
 * the pure half: every byte of the script nft is given, which ids may
 * reach it, the digest, and the parsers for what nft prints back.
 * GLib only: no root, no network, no nft.  The live half -- the same
 * scripts in a real kernel, with packets -- is test-intelset.sh.
 *
 * The golden digests below were computed outside GLib (SHA-256 of the
 * canonical text by another tool), so they pin the canonical form
 * itself, not just this code's agreement with itself.
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <stdarg.h>
#include <string.h>

#include "core/fs-intelset.h"

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

/* A normalized range set from texts; NULL ends the list. */
static FsRangeSet *
ranges (const gchar *first, ...)
{
	FsRangeSet *set = fs_range_set_new ();
	va_list ap;

	va_start (ap, first);
	for (const gchar *t = first; t != NULL; t = va_arg (ap, const gchar *))
		if (!fs_range_set_add_text (set, t))
			g_error ("bad fixture range: %s", t);
	va_end (ap);
	fs_range_set_normalize (set);
	return set;
}

/* Byte-for-byte; on a mismatch, the first line that differs. */
static void
expect_text (const gchar *what, const gchar *got, const gchar *want)
{
	gchar **g, **w;
	guint i;

	if (g_strcmp0 (got, want) == 0) {
		CHECK (TRUE, "%s", what);
		return;
	}
	CHECK (FALSE, "%s", what);
	if (got == NULL || want == NULL) {
		g_print ("      got %s, want %s\n", got ? "text" : "NULL",
		         want ? "text" : "NULL");
		return;
	}
	g = g_strsplit (got, "\n", -1);
	w = g_strsplit (want, "\n", -1);
	for (i = 0; g[i] != NULL && w[i] != NULL; i++)
		if (strcmp (g[i], w[i]) != 0)
			break;
	g_print ("      line %u\n      got:  %s\n      want: %s\n", i + 1,
	         g[i] != NULL ? g[i] : "(end)", w[i] != NULL ? w[i] : "(end)");
	g_strfreev (g);
	g_strfreev (w);
}

/* ============================================================ goldens */

#define EMPTY_SCRIPT \
	"table inet stockfw_intel {}\n" \
	"delete table inet stockfw_intel\n"

static const gchar GOLDEN_IN4[] =
	"table inet stockfw_intel {}\n"
	"delete table inet stockfw_intel\n"
	"table inet stockfw_intel {\n"
	"\tcomment \"sfw:7322e67f7b093a917d49cd417dd976d7\"\n"
	"\tset s_feed_in_4 { type ipv4_addr; flags interval; }\n"
	"\tchain input {\n"
	"\t\tcomment \"sfw:7322e67f7b093a917d49cd417dd976d7\"\n"
	"\t\ttype filter hook input priority filter - 10; policy accept;\n"
	"\t\tiif \"lo\" accept\n"
	"\t\tip saddr @s_feed_in_4 ct direction original limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-in \" level info\n"
	"\t\tip saddr @s_feed_in_4 ct direction original counter drop comment \"feed-in\"\n"
	"\t}\n"
	"\tchain output {\n"
	"\t\tcomment \"sfw:7322e67f7b093a917d49cd417dd976d7\"\n"
	"\t\ttype filter hook output priority filter - 10; policy accept;\n"
	"\t\toif \"lo\" accept\n"
	"\t}\n"
	"\tchain forward {\n"
	"\t\tcomment \"sfw:7322e67f7b093a917d49cd417dd976d7\"\n"
	"\t\ttype filter hook forward priority filter - 10; policy accept;\n"
	"\t\tip saddr @s_feed_in_4 ct direction original limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-in \" level info\n"
	"\t\tip saddr @s_feed_in_4 ct direction original counter drop comment \"feed-in\"\n"
	"\t}\n"
	"}\n"
	"add element inet stockfw_intel s_feed_in_4 { 192.0.2.0/24, 198.51.100.7 }\n";

static const gchar GOLDEN_OUT6[] =
	"table inet stockfw_intel {}\n"
	"delete table inet stockfw_intel\n"
	"table inet stockfw_intel {\n"
	"\tcomment \"sfw:3606c7af9889afedfedb2e3c37deb3b7\"\n"
	"\tset s_feed_out_6 { type ipv6_addr; flags interval; }\n"
	"\tchain input {\n"
	"\t\tcomment \"sfw:3606c7af9889afedfedb2e3c37deb3b7\"\n"
	"\t\ttype filter hook input priority filter - 10; policy accept;\n"
	"\t\tiif \"lo\" accept\n"
	"\t}\n"
	"\tchain output {\n"
	"\t\tcomment \"sfw:3606c7af9889afedfedb2e3c37deb3b7\"\n"
	"\t\ttype filter hook output priority filter - 10; policy accept;\n"
	"\t\toif \"lo\" accept\n"
	"\t\tip6 daddr @s_feed_out_6 ct direction original limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-out \" level info\n"
	"\t\tip6 daddr @s_feed_out_6 ct direction original counter reject with icmpx type admin-prohibited comment \"feed-out\"\n"
	"\t}\n"
	"\tchain forward {\n"
	"\t\tcomment \"sfw:3606c7af9889afedfedb2e3c37deb3b7\"\n"
	"\t\ttype filter hook forward priority filter - 10; policy accept;\n"
	"\t\tip6 daddr @s_feed_out_6 ct direction original limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-out \" level info\n"
	"\t\tip6 daddr @s_feed_out_6 ct direction original counter reject with icmpx type admin-prohibited comment \"feed-out\"\n"
	"\t}\n"
	"}\n"
	"add element inet stockfw_intel s_feed_out_6 { 2001:db8:bad::/48, 2001:db8:beef::1-2001:db8:beef::9 }\n";

static const gchar GOLDEN_BOTH[] =
	"table inet stockfw_intel {}\n"
	"delete table inet stockfw_intel\n"
	"table inet stockfw_intel {\n"
	"\tcomment \"sfw:68ca2f1469cc978f02dd154b67c0c887\"\n"
	"\tset s_feed_both_4 { type ipv4_addr; flags interval; }\n"
	"\tset s_feed_both_6 { type ipv6_addr; flags interval; }\n"
	"\tchain input {\n"
	"\t\tcomment \"sfw:68ca2f1469cc978f02dd154b67c0c887\"\n"
	"\t\ttype filter hook input priority filter - 10; policy accept;\n"
	"\t\tiif \"lo\" accept\n"
	"\t\tip saddr @s_feed_both_4 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip saddr @s_feed_both_4 counter drop comment \"feed-both\"\n"
	"\t\tip6 saddr @s_feed_both_6 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip6 saddr @s_feed_both_6 counter drop comment \"feed-both\"\n"
	"\t}\n"
	"\tchain output {\n"
	"\t\tcomment \"sfw:68ca2f1469cc978f02dd154b67c0c887\"\n"
	"\t\ttype filter hook output priority filter - 10; policy accept;\n"
	"\t\toif \"lo\" accept\n"
	"\t\tip daddr @s_feed_both_4 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip daddr @s_feed_both_4 counter reject with icmpx type admin-prohibited comment \"feed-both\"\n"
	"\t\tip6 daddr @s_feed_both_6 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip6 daddr @s_feed_both_6 counter reject with icmpx type admin-prohibited comment \"feed-both\"\n"
	"\t}\n"
	"\tchain forward {\n"
	"\t\tcomment \"sfw:68ca2f1469cc978f02dd154b67c0c887\"\n"
	"\t\ttype filter hook forward priority filter - 10; policy accept;\n"
	"\t\tip saddr @s_feed_both_4 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip saddr @s_feed_both_4 counter drop comment \"feed-both\"\n"
	"\t\tip daddr @s_feed_both_4 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip daddr @s_feed_both_4 counter reject with icmpx type admin-prohibited comment \"feed-both\"\n"
	"\t\tip6 saddr @s_feed_both_6 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip6 saddr @s_feed_both_6 counter drop comment \"feed-both\"\n"
	"\t\tip6 daddr @s_feed_both_6 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip6 daddr @s_feed_both_6 counter reject with icmpx type admin-prohibited comment \"feed-both\"\n"
	"\t}\n"
	"}\n"
	"add element inet stockfw_intel s_feed_both_4 { 203.0.113.0/25 }\n"
	"add element inet stockfw_intel s_feed_both_6 { 2001:db8:c0de::/64 }\n";

/* The three above in one rule set, in that order. */
static const gchar GOLDEN_SEVERAL[] =
	"table inet stockfw_intel {}\n"
	"delete table inet stockfw_intel\n"
	"table inet stockfw_intel {\n"
	"\tcomment \"sfw:a06d0e574758073c0514fb6047039306\"\n"
	"\tset s_feed_in_4 { type ipv4_addr; flags interval; }\n"
	"\tset s_feed_out_6 { type ipv6_addr; flags interval; }\n"
	"\tset s_feed_both_4 { type ipv4_addr; flags interval; }\n"
	"\tset s_feed_both_6 { type ipv6_addr; flags interval; }\n"
	"\tchain input {\n"
	"\t\tcomment \"sfw:a06d0e574758073c0514fb6047039306\"\n"
	"\t\ttype filter hook input priority filter - 10; policy accept;\n"
	"\t\tiif \"lo\" accept\n"
	"\t\tip saddr @s_feed_in_4 ct direction original limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-in \" level info\n"
	"\t\tip saddr @s_feed_in_4 ct direction original counter drop comment \"feed-in\"\n"
	"\t\tip saddr @s_feed_both_4 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip saddr @s_feed_both_4 counter drop comment \"feed-both\"\n"
	"\t\tip6 saddr @s_feed_both_6 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip6 saddr @s_feed_both_6 counter drop comment \"feed-both\"\n"
	"\t}\n"
	"\tchain output {\n"
	"\t\tcomment \"sfw:a06d0e574758073c0514fb6047039306\"\n"
	"\t\ttype filter hook output priority filter - 10; policy accept;\n"
	"\t\toif \"lo\" accept\n"
	"\t\tip6 daddr @s_feed_out_6 ct direction original limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-out \" level info\n"
	"\t\tip6 daddr @s_feed_out_6 ct direction original counter reject with icmpx type admin-prohibited comment \"feed-out\"\n"
	"\t\tip daddr @s_feed_both_4 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip daddr @s_feed_both_4 counter reject with icmpx type admin-prohibited comment \"feed-both\"\n"
	"\t\tip6 daddr @s_feed_both_6 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip6 daddr @s_feed_both_6 counter reject with icmpx type admin-prohibited comment \"feed-both\"\n"
	"\t}\n"
	"\tchain forward {\n"
	"\t\tcomment \"sfw:a06d0e574758073c0514fb6047039306\"\n"
	"\t\ttype filter hook forward priority filter - 10; policy accept;\n"
	"\t\tip saddr @s_feed_in_4 ct direction original limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-in \" level info\n"
	"\t\tip saddr @s_feed_in_4 ct direction original counter drop comment \"feed-in\"\n"
	"\t\tip6 daddr @s_feed_out_6 ct direction original limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-out \" level info\n"
	"\t\tip6 daddr @s_feed_out_6 ct direction original counter reject with icmpx type admin-prohibited comment \"feed-out\"\n"
	"\t\tip saddr @s_feed_both_4 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip saddr @s_feed_both_4 counter drop comment \"feed-both\"\n"
	"\t\tip daddr @s_feed_both_4 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip daddr @s_feed_both_4 counter reject with icmpx type admin-prohibited comment \"feed-both\"\n"
	"\t\tip6 saddr @s_feed_both_6 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip6 saddr @s_feed_both_6 counter drop comment \"feed-both\"\n"
	"\t\tip6 daddr @s_feed_both_6 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI feed-both \" level info\n"
	"\t\tip6 daddr @s_feed_both_6 counter reject with icmpx type admin-prohibited comment \"feed-both\"\n"
	"\t}\n"
	"}\n"
	"add element inet stockfw_intel s_feed_in_4 { 192.0.2.0/24, 198.51.100.7 }\n"
	"add element inet stockfw_intel s_feed_out_6 { 2001:db8:bad::/48, 2001:db8:beef::1-2001:db8:beef::9 }\n"
	"add element inet stockfw_intel s_feed_both_4 { 203.0.113.0/25 }\n"
	"add element inet stockfw_intel s_feed_both_6 { 2001:db8:c0de::/64 }\n";

static void
add_in4 (FsIntelRuleset *rs)
{
	fs_intel_ruleset_add (rs, "feed-in", "Inbound feed", FS_INTEL_DIR_IN,
	                      ranges ("198.51.100.7", "192.0.2.0/24", NULL));
}

static void
add_out6 (FsIntelRuleset *rs)
{
	fs_intel_ruleset_add (rs, "feed-out", "Outbound feed", FS_INTEL_DIR_OUT,
	                      ranges ("2001:db8:bad::/48",
	                              "2001:db8:beef::1-2001:db8:beef::9", NULL));
}

static void
add_both (FsIntelRuleset *rs)
{
	fs_intel_ruleset_add (rs, "feed-both", "Both ways", FS_INTEL_DIR_BOTH,
	                      ranges ("2001:db8:c0de::/64", "203.0.113.0/25",
	                              NULL));
}

/* Every line inside a chain -- the chain's type line and every rule --
 * ends at its newline: none of them carries a brace [N7]. */
static gboolean
rules_end_with_newline (const gchar *script)
{
	gchar **lines = g_strsplit (script, "\n", -1);
	gboolean ok = g_str_has_suffix (script, "\n");

	for (guint i = 0; lines[i] != NULL; i++)
		if (g_str_has_prefix (lines[i], "\t\t") &&
		    strpbrk (lines[i], "{}") != NULL)
			ok = FALSE;
	g_strfreev (lines);
	return ok;
}

static void
test_scripts (void)
{
	FsIntelRuleset *rs;
	gchar *script, *clear;

	rs = fs_intel_ruleset_new ();
	add_in4 (rs);
	script = fs_intelset_nft_script (rs);
	expect_text ("golden: an IN set, IPv4 only", script, GOLDEN_IN4);
	CHECK (script != NULL && strstr (script, "s_feed_in_6") == NULL &&
	       strstr (script, "ip6") == NULL,
	       "an empty family has no set and no rules (no s_feed_in_6, "
	       "no ip6)");
	g_free (script);
	fs_intel_ruleset_free (rs);

	rs = fs_intel_ruleset_new ();
	add_out6 (rs);
	script = fs_intelset_nft_script (rs);
	expect_text ("golden: an OUT set, IPv6 only", script, GOLDEN_OUT6);
	g_free (script);
	fs_intel_ruleset_free (rs);

	rs = fs_intel_ruleset_new ();
	add_both (rs);
	script = fs_intelset_nft_script (rs);
	expect_text ("golden: a BOTH set with both families", script,
	             GOLDEN_BOTH);
	g_free (script);
	fs_intel_ruleset_free (rs);

	rs = fs_intel_ruleset_new ();
	add_in4 (rs);
	add_out6 (rs);
	add_both (rs);
	script = fs_intelset_nft_script (rs);
	expect_text ("golden: several sets, in their order", script,
	             GOLDEN_SEVERAL);
	CHECK (script != NULL && rules_end_with_newline (script),
	       "every statement and rule ends with a newline; no rule shares "
	       "a line with a brace");
	g_free (script);
	fs_intel_ruleset_free (rs);

	rs = fs_intel_ruleset_new ();
	script = fs_intelset_nft_script (rs);
	clear = fs_intelset_nft_clear_script ();
	expect_text ("the empty rule set is exactly the create and delete lines",
	             script, EMPTY_SCRIPT);
	expect_text ("the clear script is the same two lines", clear,
	             EMPTY_SCRIPT);
	g_free (clear);
	g_free (script);
	fs_intel_ruleset_free (rs);

	/* A set that has no addresses at all (a feed never fetched): no
	 * nft set, no rules -- but it is part of the digest. */
	rs = fs_intel_ruleset_new ();
	fs_intel_ruleset_add (rs, "not-fetched", NULL, FS_INTEL_DIR_BOTH,
	                      fs_range_set_new ());
	add_in4 (rs);
	script = fs_intelset_nft_script (rs);
	CHECK (script != NULL && strstr (script, "not_fetched") == NULL &&
	       strstr (script, "not-fetched") == NULL &&
	       strstr (script, "s_feed_in_4") != NULL,
	       "a set without addresses renders nothing; the others render");
	{
		FsIntelRuleset *alone = fs_intel_ruleset_new ();
		gchar *a, *b;

		add_in4 (alone);
		a = fs_intel_ruleset_digest (rs);
		b = fs_intel_ruleset_digest (alone);
		CHECK (g_strcmp0 (a, b) != 0,
		       "... but it is in the digest (%s vs %s)", a, b);
		g_free (a);
		g_free (b);
		fs_intel_ruleset_free (alone);
	}
	g_free (script);
	fs_intel_ruleset_free (rs);

	/* 2500 separate addresses: 1000 + 1000 + 500. */
	{
		FsRangeSet *many = fs_range_set_new ();
		gchar **lines;
		guint adds = 0, sizes[4] = { 0 };

		for (guint32 i = 0; i < 2500; i++)
			fs_range_set_add4 (many, 0xc6120000u + 2 * i,
			                   0xc6120000u + 2 * i);
		fs_range_set_normalize (many);
		rs = fs_intel_ruleset_new ();
		fs_intel_ruleset_add (rs, "many", NULL, FS_INTEL_DIR_IN, many);
		script = fs_intelset_nft_script (rs);
		lines = g_strsplit (script, "\n", -1);
		for (guint i = 0; lines[i] != NULL; i++) {
			if (!g_str_has_prefix (lines[i], "add element "))
				continue;
			if (adds < G_N_ELEMENTS (sizes)) {
				const gchar *p = lines[i];

				sizes[adds] = 1;
				while ((p = strstr (p, ", ")) != NULL) {
					sizes[adds]++;
					p += 2;
				}
			}
			adds++;
		}
		CHECK (adds == 3 && sizes[0] == 1000 && sizes[1] == 1000 &&
		       sizes[2] == 500,
		       "2500 elements go in 3 add-element statements of "
		       "1000, 1000, 500 (got %u: %u, %u, %u)",
		       adds, sizes[0], sizes[1], sizes[2]);
		g_strfreev (lines);
		g_free (script);
		fs_intel_ruleset_free (rs);
	}
}

/* The sizes of the add-element statements the script of one IN set of
 * `n' separate IPv4 addresses has, as "1000+1"; an empty statement
 * ("{  }") counts as 0.  Caller frees. */
static gchar *
element_statements (guint n)
{
	FsRangeSet *many = fs_range_set_new ();
	FsIntelRuleset *rs = fs_intel_ruleset_new ();
	GString *sizes = g_string_new (NULL);
	gchar *script, **lines;

	for (guint32 i = 0; i < n; i++)
		fs_range_set_add4 (many, 0xc6120000u + 2 * i, 0xc6120000u + 2 * i);
	fs_range_set_normalize (many);
	fs_intel_ruleset_add (rs, "chunk", NULL, FS_INTEL_DIR_IN, many);
	script = fs_intelset_nft_script (rs);
	lines = g_strsplit (script != NULL ? script : "", "\n", -1);
	for (guint i = 0; lines[i] != NULL; i++) {
		const gchar *open = strchr (lines[i], '{'), *p;
		guint size = 0;

		if (!g_str_has_prefix (lines[i], "add element ") || open == NULL)
			continue;
		for (p = open + 1; *p == ' '; p++)
			;
		if (*p != '}') {
			size = 1;
			while ((p = strchr (p, ',')) != NULL) {
				size++;
				p++;
			}
		}
		g_string_append_printf (sizes, "%s%u", sizes->len ? "+" : "", size);
	}
	g_strfreev (lines);
	g_free (script);
	fs_intel_ruleset_free (rs);
	return g_string_free (sizes, FALSE);
}

/* Chunks of FS_INTEL_NFT_CHUNK at their edges: an off-by-one in the
 * loop would add an empty statement after an exact multiple, which nft
 * refuses as a syntax error, failing the whole apply [N7]. */
static void
test_chunks (void)
{
	static const struct
	{
		guint        n;
		const gchar *want;
	} cases[] = {
		{ 1,    "1"         },
		{ 999,  "999"       },
		{ 1000, "1000"      },
		{ 1001, "1000+1"    },
		{ 2000, "1000+1000" },
	};

	for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
		gchar *got = element_statements (cases[i].n);

		CHECK (g_strcmp0 (got, cases[i].want) == 0,
		       "%u elements go in statements of %s, none empty (got %s)",
		       cases[i].n, cases[i].want, got);
		g_free (got);
	}
}

/* A label is display text.  It never reaches nft, so a hostile one
 * cannot inject a statement, and renaming a list changes no byte of
 * the script. */
static void
test_labels (void)
{
	static const gchar hostile[] =
		"Evil\" counter accept comment \"x\"\n}\nflush ruleset\n#";
	FsIntelRuleset *a = fs_intel_ruleset_new ();
	FsIntelRuleset *b = fs_intel_ruleset_new ();
	gchar *sa, *sb;

	fs_intel_ruleset_add (a, "feed-in", hostile, FS_INTEL_DIR_BOTH,
	                      ranges ("192.0.2.0/24", "2001:db8::/48", NULL));
	fs_intel_ruleset_add (b, "feed-in", NULL, FS_INTEL_DIR_BOTH,
	                      ranges ("192.0.2.0/24", "2001:db8::/48", NULL));
	sa = fs_intelset_nft_script (a);
	sb = fs_intelset_nft_script (b);
	CHECK (sa != NULL && g_strcmp0 (sa, sb) == 0 &&
	       strstr (sa, "flush") == NULL && strstr (sa, "Evil") == NULL &&
	       strstr (sa, "accept comment") == NULL,
	       "a hostile label never reaches the script: byte for byte the "
	       "script of the same set without a label");
	g_free (sa);
	g_free (sb);
	fs_intel_ruleset_free (a);
	fs_intel_ruleset_free (b);
}

/* ================================================================ ids */

static void
test_ids (void)
{
	static const gchar *const good[] = {
		"a", "0", "a-", "a1-b2", "spamhaus-drop", "local-my-list",
		"a123456789-123456789-123456789-123456789",   /* 40 */
	};
	static const gchar *const refused[] = {
		"", "Feed", "spamhaus-DROP", "a_b", "-a", "a b", "a.b", "a/b",
		"\xc3\xa9t\xc3\xa9", "a\"", "a\n",
		"a123456789-123456789-123456789-1234567890",  /* 41 */
		"a\";flush ruleset;#",
	};
	FsIntelRuleset *rs = fs_intel_ruleset_new ();
	gchar *name;

	for (guint i = 0; i < G_N_ELEMENTS (good); i++)
		CHECK (fs_intel_id_is_valid (good[i]), "id accepted: \"%s\"",
		       good[i]);
	for (guint i = 0; i < G_N_ELEMENTS (refused); i++) {
		gchar *shown = g_strescape (refused[i], NULL);

		CHECK (!fs_intel_id_is_valid (refused[i]) &&
		       !fs_intel_ruleset_add (rs, refused[i], NULL,
		                              FS_INTEL_DIR_IN,
		                              ranges ("192.0.2.1", NULL)) &&
		       fs_intelset_nft_set_name (refused[i], FS_AF_V4) == NULL,
		       "id refused, by the check, the rule set and the set "
		       "name: \"%s\"", shown);
		g_free (shown);
	}
	CHECK (!fs_intel_id_is_valid (NULL) &&
	       fs_intelset_nft_set_name (NULL, FS_AF_V4) == NULL,
	       "a NULL id is refused");
	CHECK (rs->sets->len == 0, "nothing refused reached the rule set");
	fs_intel_ruleset_free (rs);

	name = fs_intelset_nft_set_name ("spamhaus-drop", FS_AF_V4);
	CHECK (g_strcmp0 (name, "s_spamhaus_drop_4") == 0,
	       "set name: spamhaus-drop, IPv4 -> s_spamhaus_drop_4 (got %s)",
	       name);
	g_free (name);
	name = fs_intelset_nft_set_name ("local-a-b", FS_AF_V6);
	CHECK (g_strcmp0 (name, "s_local_a_b_6") == 0,
	       "set name: every '-' becomes '_', IPv6 -> _6 (got %s)", name);
	g_free (name);
	name = fs_intelset_nft_set_name ("0", FS_AF_V6);
	CHECK (g_strcmp0 (name, "s_0_6") == 0, "set name: s_0_6 (got %s)", name);
	g_free (name);
	CHECK (fs_intelset_nft_set_name ("feed", FS_AF_NONE) == NULL,
	       "set name: no family, no name");
}

/* ============================================================ rule set */

static void
test_ruleset (void)
{
	FsIntelRuleset *rs = fs_intel_ruleset_new ();
	const FsIntelSet *set;
	FsIntelDir dir = 0;
	gboolean ok;

	CHECK (g_strcmp0 (fs_intel_dir_to_string (FS_INTEL_DIR_IN), "in") == 0 &&
	       g_strcmp0 (fs_intel_dir_to_string (FS_INTEL_DIR_OUT), "out") == 0 &&
	       g_strcmp0 (fs_intel_dir_to_string (FS_INTEL_DIR_BOTH), "both") == 0 &&
	       fs_intel_dir_to_string (0) == NULL &&
	       fs_intel_dir_to_string (4) == NULL,
	       "direction names: in, out, both; nothing for other values");
	CHECK (fs_intel_dir_from_string ("out", &dir) && dir == FS_INTEL_DIR_OUT &&
	       fs_intel_dir_from_string ("both", &dir) && dir == FS_INTEL_DIR_BOTH &&
	       fs_intel_dir_from_string ("in", &dir) && dir == FS_INTEL_DIR_IN &&
	       !fs_intel_dir_from_string ("IN", &dir) &&
	       !fs_intel_dir_from_string ("In", &dir) &&
	       !fs_intel_dir_from_string (" in", &dir) &&
	       !fs_intel_dir_from_string ("inbound", &dir) &&
	       !fs_intel_dir_from_string ("", &dir) &&
	       !fs_intel_dir_from_string (NULL, &dir) && dir == FS_INTEL_DIR_IN,
	       "direction from text: exact and lower case only; a refusal "
	       "leaves the value alone");

	CHECK (!fs_intel_ruleset_add (rs, "bad-dir", NULL, 0,
	                              ranges ("192.0.2.1", NULL)) &&
	       !fs_intel_ruleset_add (rs, "bad-dir", NULL, 4,
	                              ranges ("192.0.2.1", NULL)),
	       "a direction that is not one of the three is refused");

	ok = fs_intel_ruleset_add (rs, "dup", "First", FS_INTEL_DIR_IN,
	                           ranges ("192.0.2.1", "2001:db8::1", NULL));
	/* The second copy's ranges must be freed by the refusal: under
	 * AddressSanitizer a leak here fails the run. */
	CHECK (ok && !fs_intel_ruleset_add (rs, "dup", "Second",
	                                    FS_INTEL_DIR_OUT,
	                                    ranges ("198.51.100.0/24", NULL)),
	       "a duplicate id is refused (and its ranges freed)");
	set = fs_intel_ruleset_find (rs, "dup");
	CHECK (rs->sets->len == 1 && set != NULL &&
	       g_strcmp0 (set->label, "First") == 0 &&
	       set->dir == FS_INTEL_DIR_IN &&
	       fs_range_set_contains_text (set->ranges, "192.0.2.1") &&
	       !fs_range_set_contains_text (set->ranges, "198.51.100.1"),
	       "the first set of that id is untouched");

	CHECK (fs_intel_ruleset_add (rs, "no-ranges", NULL, FS_INTEL_DIR_BOTH,
	                             NULL) &&
	       fs_range_set_is_empty (fs_intel_ruleset_find (rs, "no-ranges")->ranges) &&
	       g_strcmp0 (fs_intel_ruleset_find (rs, "no-ranges")->label,
	                  "no-ranges") == 0,
	       "NULL ranges are an empty set; a NULL label is the id");

	/* Ranges handed over unnormalized are normalized: nft refuses
	 * overlapping intervals. */
	{
		FsRangeSet *raw = fs_range_set_new ();

		fs_range_set_add_text (raw, "203.0.113.128/25");
		fs_range_set_add_text (raw, "203.0.113.0/25");
		fs_range_set_add_text (raw, "203.0.113.10");
		fs_intel_ruleset_add (rs, "raw", NULL, FS_INTEL_DIR_IN, raw);
		set = fs_intel_ruleset_find (rs, "raw");
		CHECK (set != NULL && fs_range_set_count4 (set->ranges) == 1,
		       "overlapping input becomes one interval (203.0.113.0/24)");
	}

	CHECK (fs_intel_ruleset_count4 (rs) == 2 &&
	       fs_intel_ruleset_count6 (rs) == 1,
	       "interval totals over every set: 2 IPv4, 1 IPv6 (got %u, %u)",
	       fs_intel_ruleset_count4 (rs), fs_intel_ruleset_count6 (rs));
	CHECK (fs_intel_ruleset_find (rs, "nope") == NULL &&
	       fs_intel_ruleset_find (rs, NULL) == NULL &&
	       fs_intel_ruleset_find (NULL, "dup") == NULL,
	       "find: unknown ids are not found");
	fs_intel_ruleset_free (rs);

	/* The struct is public; one filled in by hand is checked again
	 * before anything is rendered. */
	{
		FsIntelSet *bad;

		rs = fs_intel_ruleset_new ();
		add_in4 (rs);
		bad = g_new0 (FsIntelSet, 1);
		bad->id = g_strdup ("x\";flush ruleset;#");
		bad->dir = FS_INTEL_DIR_IN;
		bad->ranges = ranges ("192.0.2.1", NULL);
		g_ptr_array_add (rs->sets, bad);
		CHECK (fs_intelset_nft_script (rs) == NULL,
		       "a hand-made set with a hostile id renders no script");
		g_free (bad->id);
		bad->id = g_strdup ("feed-in");
		CHECK (fs_intelset_nft_script (rs) == NULL,
		       "a hand-made set repeating an id renders no script");
		g_free (bad->id);
		bad->id = g_strdup ("other");
		bad->dir = 7;
		CHECK (fs_intelset_nft_script (rs) == NULL,
		       "a hand-made set with no valid direction renders no script");

		/* No ranges at all is what fs_intel_ruleset_add() makes of
		 * NULL: an empty set, rendered as nothing. */
		bad->dir = FS_INTEL_DIR_BOTH;
		fs_range_set_free (bad->ranges);
		bad->ranges = NULL;
		{
			FsIntelRuleset *same = fs_intel_ruleset_new ();
			gchar *script = fs_intelset_nft_script (rs);
			gchar *da = fs_intel_ruleset_digest (rs), *db;

			add_in4 (same);
			fs_intel_ruleset_add (same, "other", NULL,
			                      FS_INTEL_DIR_BOTH, NULL);
			db = fs_intel_ruleset_digest (same);
			CHECK (script != NULL && strstr (script, "s_other") == NULL &&
			       strstr (script, "s_feed_in_4") != NULL &&
			       g_strcmp0 (da, db) == 0,
			       "a hand-made set with NULL ranges renders and hashes "
			       "as an empty set");
			g_free (script);
			g_free (da);
			g_free (db);
			fs_intel_ruleset_free (same);
		}
		fs_intel_ruleset_free (rs);
	}
}

/* ============================================================== digest */

static gboolean
is_hex32 (const gchar *s)
{
	if (s == NULL || strlen (s) != 32)
		return FALSE;
	for (const gchar *p = s; *p != '\0'; p++)
		if (!g_ascii_isdigit (*p) && !(*p >= 'a' && *p <= 'f'))
			return FALSE;
	return TRUE;
}

static void
test_digest (void)
{
	FsIntelRuleset *a = fs_intel_ruleset_new ();
	FsIntelRuleset *b = fs_intel_ruleset_new ();
	gchar *da, *db;

	da = fs_intel_ruleset_digest (a);
	CHECK (g_strcmp0 (da, "e3b0c44298fc1c149afbf4c8996fb924") == 0,
	       "the empty rule set has a digest: SHA-256 of nothing (got %s)",
	       da);
	g_free (da);

	/* "feed-in\tin\n192.0.2.0/24\n198.51.100.7\n" */
	add_in4 (a);
	da = fs_intel_ruleset_digest (a);
	CHECK (g_strcmp0 (da, "7322e67f7b093a917d49cd417dd976d7") == 0 &&
	       is_hex32 (da),
	       "golden digest: \"<id>\\t<dir>\\n\" then the stored text "
	       "form (got %s)", da);

	/* Equal input, built separately and handed over in another order
	 * and unnormalized: the same digest. */
	{
		FsRangeSet *r = fs_range_set_new ();

		fs_range_set_add_text (r, "198.51.100.7");
		fs_range_set_add_text (r, "192.0.2.128/25");
		fs_range_set_add_text (r, "192.0.2.0/25");
		fs_intel_ruleset_add (b, "feed-in", "Inbound feed",
		                      FS_INTEL_DIR_IN, r);
	}
	db = fs_intel_ruleset_digest (b);
	CHECK (g_strcmp0 (da, db) == 0, "equal rule sets, equal digests");
	g_free (db);
	fs_intel_ruleset_free (b);

	/* Only the label differs. */
	b = fs_intel_ruleset_new ();
	fs_intel_ruleset_add (b, "feed-in", "A different name entirely",
	                      FS_INTEL_DIR_IN,
	                      ranges ("192.0.2.0/24", "198.51.100.7", NULL));
	db = fs_intel_ruleset_digest (b);
	CHECK (g_strcmp0 (da, db) == 0,
	       "a label change leaves the digest alone (labels never reach "
	       "the kernel)");
	g_free (db);
	fs_intel_ruleset_free (b);

	/* Only the direction differs. */
	b = fs_intel_ruleset_new ();
	fs_intel_ruleset_add (b, "feed-in", "Inbound feed", FS_INTEL_DIR_OUT,
	                      ranges ("192.0.2.0/24", "198.51.100.7", NULL));
	db = fs_intel_ruleset_digest (b);
	CHECK (g_strcmp0 (db, "a5a3df30925b8236d73e5b04bc299ee8") == 0,
	       "a direction change changes the digest (got %s)", db);
	g_free (db);
	fs_intel_ruleset_free (b);

	/* One more address. */
	b = fs_intel_ruleset_new ();
	fs_intel_ruleset_add (b, "feed-in", "Inbound feed", FS_INTEL_DIR_IN,
	                      ranges ("192.0.2.0/24", "198.51.100.7",
	                              "198.51.100.9", NULL));
	db = fs_intel_ruleset_digest (b);
	CHECK (g_strcmp0 (da, db) != 0, "a range change changes the digest");
	g_free (db);
	fs_intel_ruleset_free (b);
	g_free (da);
	fs_intel_ruleset_free (a);

	/* The same sets in another order. */
	a = fs_intel_ruleset_new ();
	add_in4 (a);
	add_out6 (a);
	add_both (a);
	b = fs_intel_ruleset_new ();
	add_both (b);
	add_in4 (b);
	add_out6 (b);
	da = fs_intel_ruleset_digest (a);
	db = fs_intel_ruleset_digest (b);
	CHECK (g_strcmp0 (da, "a06d0e574758073c0514fb6047039306") == 0 &&
	       g_strcmp0 (da, db) != 0,
	       "golden digest of several sets; their order changes it "
	       "(%s vs %s)", da, db);
	g_free (da);
	g_free (db);
	fs_intel_ruleset_free (a);
	fs_intel_ruleset_free (b);
}

/* ============================================================ counters */

/* `nft list chain inet stockfw_intel input', `... output' and
 * `... forward', concatenated, as nft 1.0.9 printed them after real
 * traffic.  Three rules were added by hand to the input chain: a
 * counter with no comment just before beta's rule, a counter whose
 * comment is not an id, and an id as the comment of a rule with no
 * counter. */
static const gchar LISTING[] =
	"table inet stockfw_intel {\n"
	"\tchain input {\n"
	"\t\tcomment \"sfw:a06d0e574758073c0514fb6047039306\"\n"
	"\t\ttype filter hook input priority filter - 10; policy accept;\n"
	"\t\tiif \"lo\" accept\n"
	"\t\tip saddr @s_alpha_4 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI alpha \" level info\n"
	"\t\tip saddr @s_alpha_4 counter packets 2 bytes 120 drop comment \"alpha\"\n"
	"\t\tip6 saddr @s_alpha_6 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI alpha \" level info\n"
	"\t\tip6 saddr @s_alpha_6 counter packets 0 bytes 0 drop comment \"alpha\"\n"
	"\t\tip saddr @s_beta_4 ct direction original limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI beta \" level info\n"
	"\t\tip saddr 192.0.2.5 counter packets 4 bytes 216\n"
	"\t\tip saddr @s_beta_4 ct direction original counter packets 2 bytes 120 drop comment \"beta\"\n"
	"\t\tip saddr 192.0.2.4 counter packets 4 bytes 216 accept comment \"Not_An_Id\"\n"
	"\t\tip saddr 192.0.2.6 accept comment \"alpha\"\n"
	"\t}\n"
	"}\n"
	"table inet stockfw_intel {\n"
	"\tchain output {\n"
	"\t\tcomment \"sfw:a06d0e574758073c0514fb6047039306\"\n"
	"\t\ttype filter hook output priority filter - 10; policy accept;\n"
	"\t\toif \"lo\" accept\n"
	"\t\tip daddr @s_alpha_4 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI alpha \" level info\n"
	"\t\tip daddr @s_alpha_4 counter packets 2 bytes 120 reject with icmpx admin-prohibited comment \"alpha\"\n"
	"\t\tip6 daddr @s_alpha_6 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI alpha \" level info\n"
	"\t\tip6 daddr @s_alpha_6 counter packets 0 bytes 0 reject with icmpx admin-prohibited comment \"alpha\"\n"
	"\t}\n"
	"}\n"
	"table inet stockfw_intel {\n"
	"\tchain forward {\n"
	"\t\tcomment \"sfw:a06d0e574758073c0514fb6047039306\"\n"
	"\t\ttype filter hook forward priority filter - 10; policy accept;\n"
	"\t\tip saddr @s_alpha_4 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI alpha \" level info\n"
	"\t\tip saddr @s_alpha_4 counter packets 0 bytes 0 drop comment \"alpha\"\n"
	"\t\tip daddr @s_alpha_4 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI alpha \" level info\n"
	"\t\tip daddr @s_alpha_4 counter packets 0 bytes 0 reject with icmpx admin-prohibited comment \"alpha\"\n"
	"\t\tip6 saddr @s_alpha_6 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI alpha \" level info\n"
	"\t\tip6 saddr @s_alpha_6 counter packets 0 bytes 0 drop comment \"alpha\"\n"
	"\t\tip6 daddr @s_alpha_6 limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI alpha \" level info\n"
	"\t\tip6 daddr @s_alpha_6 counter packets 0 bytes 0 reject with icmpx admin-prohibited comment \"alpha\"\n"
	"\t\tip saddr @s_beta_4 ct direction original limit rate 10/second burst 20 packets log prefix \"STOCKFW-TI beta \" level info\n"
	"\t\tip saddr @s_beta_4 ct direction original counter packets 0 bytes 0 drop comment \"beta\"\n"
	"\t}\n"
	"}\n";

static gboolean
counter_is (GHashTable *t, const gchar *id, guint64 packets, guint64 bytes)
{
	const FsIntelCounter *c = g_hash_table_lookup (t, id);

	return c != NULL && c->packets == packets && c->bytes == bytes;
}

static void
test_counters (void)
{
	GHashTable *t = fs_intelset_nft_parse_counters (LISTING);
	const FsIntelCounter *c;

	c = g_hash_table_lookup (t, "alpha");
	CHECK (counter_is (t, "alpha", 4, 240),
	       "alpha: its eight counted rules over three chains are summed "
	       "(2 + 2 packets; got %" G_GUINT64_FORMAT ")",
	       c != NULL ? c->packets : 0);
	c = g_hash_table_lookup (t, "beta");
	CHECK (counter_is (t, "beta", 2, 120),
	       "beta: 2 packets, 120 bytes -- the comment-less counter on the "
	       "line before is not added (got %" G_GUINT64_FORMAT ")",
	       c != NULL ? c->packets : 0);
	CHECK (g_hash_table_size (t) == 2 &&
	       g_hash_table_lookup (t, "Not_An_Id") == NULL,
	       "a comment that is not an id is ignored, and nothing else is "
	       "counted (got %u ids)", g_hash_table_size (t));
	g_hash_table_unref (t);

	t = fs_intelset_nft_parse_counters (
		"\t\tip saddr @s_x_4 counter packets 7 bytes 420 drop\n"
		"\t\tip saddr @s_x_4 drop comment \"x\"\n"
		"\t\tcounter packets bytes 3 drop comment \"x\"\n"
		"\t\tcounter packets 5 bytes drop comment \"x\"\n"
		"\t\tcounter packets 99999999999999999999 bytes 1 drop comment \"x\"\n"
		"\t\tcounter packets 1x bytes 1 drop comment \"x\"\n"
		"\t\tcounter packets 9 bytes 90 drop comment \"y\"");
	CHECK (g_hash_table_size (t) == 1 && counter_is (t, "y", 9, 90),
	       "lines without both a counter and a comment, or with a broken "
	       "number, are ignored; the last line needs no newline");
	g_hash_table_unref (t);

	t = fs_intelset_nft_parse_counters (
		"counter packets 18446744073709551615 bytes 1 drop comment \"z\"\n"
		"counter packets 5 bytes 1 drop comment \"z\"\n");
	CHECK (counter_is (t, "z", G_MAXUINT64, 2),
	       "sums saturate instead of wrapping");
	g_hash_table_unref (t);

	/* What `nft -a list chain' adds after the comment, the longest
	 * id, leading zeros and CRLF line ends all still read. */
	t = fs_intelset_nft_parse_counters (
		"\t\tip saddr @s_l_4 counter packets 3 bytes 180 drop comment "
		"\"a123456789-123456789-123456789-123456789\" # handle 7\r\n"
		"\t\tip daddr @s_b_4 counter packets 007 bytes 0420 reject with "
		"icmpx admin-prohibited comment \"b\" # handle 12\r\n");
	CHECK (g_hash_table_size (t) == 2 &&
	       counter_is (t, "a123456789-123456789-123456789-123456789", 3, 180) &&
	       counter_is (t, "b", 7, 420),
	       "handles after the comment, a 40-character id, leading zeros "
	       "and CRLF still count");
	g_hash_table_unref (t);

	t = fs_intelset_nft_parse_counters (NULL);
	CHECK (t != NULL && g_hash_table_size (t) == 0,
	       "no listing: an empty table, never NULL");
	g_hash_table_unref (t);
}

/* ================================================================ live */

/* `nft -j list tables' as nft 1.0.9 printed it: ours with its digest,
 * then two that must not be mistaken for it. */
static const gchar JSON_PRESENT[] =
	"{\"nftables\": [{\"metainfo\": {\"version\": \"1.0.9\", \"release_name\": "
	"\"Old Doc Yak #3\", \"json_schema_version\": 1}}, {\"table\": {\"family\": "
	"\"inet\", \"name\": \"stockfw_intel\", \"handle\": 2, \"comment\": "
	"\"sfw:43254231e49deba9152e6f56f6251661\"}}, {\"table\": {\"family\": "
	"\"inet\", \"name\": \"stockfw_intel2\", \"handle\": 3}}, {\"table\": "
	"{\"family\": \"ip\", \"name\": \"stockfw_intel\", \"handle\": 4, "
	"\"comment\": \"sfw:ffffffffffffffffffffffffffffffff\"}}]}\n";

/* Ours without a comment (made by hand), listed after the decoys. */
static const gchar JSON_NO_COMMENT[] =
	"{\"nftables\": [{\"metainfo\": {\"version\": \"1.0.9\", \"release_name\": "
	"\"Old Doc Yak #3\", \"json_schema_version\": 1}}, {\"table\": {\"family\": "
	"\"inet\", \"name\": \"stockfw_intel2\", \"handle\": 3}}, {\"table\": "
	"{\"family\": \"ip\", \"name\": \"stockfw_intel\", \"handle\": 4, "
	"\"comment\": \"sfw:ffffffffffffffffffffffffffffffff\"}}, {\"table\": "
	"{\"family\": \"inet\", \"name\": \"stockfw_intel\", \"handle\": 5}}]}\n";

/* Only the decoys. */
static const gchar JSON_DECOYS[] =
	"{\"nftables\": [{\"metainfo\": {\"version\": \"1.0.9\", \"release_name\": "
	"\"Old Doc Yak #3\", \"json_schema_version\": 1}}, {\"table\": {\"family\": "
	"\"inet\", \"name\": \"stockfw_intel2\", \"handle\": 3}}, {\"table\": "
	"{\"family\": \"ip\", \"name\": \"stockfw_intel\", \"handle\": 4, "
	"\"comment\": \"sfw:ffffffffffffffffffffffffffffffff\"}}]}\n";

static const gchar JSON_EMPTY[] =
	"{\"nftables\": [{\"metainfo\": {\"version\": \"1.0.9\", \"release_name\": "
	"\"Old Doc Yak #3\", \"json_schema_version\": 1}}]}\n";

/* Short names for the three answers, in the table below. */
#define PRESENT FS_INTEL_LIVE_PRESENT
#define ABSENT  FS_INTEL_LIVE_ABSENT
#define UNKNOWN FS_INTEL_LIVE_UNKNOWN

static const gchar *
live_name (FsIntelLive live)
{
	switch (live) {
	case FS_INTEL_LIVE_PRESENT:
		return "present";
	case FS_INTEL_LIVE_ABSENT:
		return "absent";
	default:
		return "unknown";
	}
}

/* Both readers: parse_live_state() keeps the three answers apart, and
 * parse_live() is TRUE exactly when that answer is "present". */
static void
expect_live (const gchar *what, const gchar *json, FsIntelLive want,
             const gchar *want_digest)
{
	/* The parser must set *digest to NULL first: a stale value left
	 * there would read as a digest. */
	static gchar untouched[] = "untouched";
	gchar *digest = untouched, *digest2 = untouched;
	FsIntelLive got = fs_intelset_nft_parse_live_state (json, &digest);
	gboolean present = fs_intelset_nft_parse_live (json, &digest2);

	CHECK (got == want && g_strcmp0 (digest, want_digest) == 0 &&
	       present == (want == FS_INTEL_LIVE_PRESENT) &&
	       g_strcmp0 (digest2, want_digest) == 0,
	       "live: %s -> %s, digest %s (got %s, %s)", what,
	       live_name (want), want_digest != NULL ? want_digest : "none",
	       live_name (got), digest != NULL ? digest : "none");
	if (digest != untouched)
		g_free (digest);
	if (digest2 != untouched)
		g_free (digest2);
}

static void
test_live (void)
{
	expect_live ("captured, ours with a digest", JSON_PRESENT, PRESENT,
	             "43254231e49deba9152e6f56f6251661");
	expect_live ("captured, ours without a comment", JSON_NO_COMMENT, PRESENT,
	             NULL);
	expect_live ("captured, only stockfw_intel2 and family ip", JSON_DECOYS,
	             ABSENT, NULL);
	expect_live ("captured, no tables at all", JSON_EMPTY, ABSENT, NULL);
	expect_live ("only \"stockfw_intel2\"",
	             "{\"nftables\": [{\"table\": {\"family\": \"inet\", \"name\": "
	             "\"stockfw_intel2\", \"comment\": \"sfw:0123456789abcdef"
	             "0123456789abcdef\"}}]}", ABSENT, NULL);
	expect_live ("only family \"ip\"",
	             "{\"nftables\": [{\"table\": {\"family\": \"ip\", \"name\": "
	             "\"stockfw_intel\", \"comment\": \"sfw:0123456789abcdef"
	             "0123456789abcdef\"}}]}", ABSENT, NULL);
	expect_live ("a prefix of the name (\"stockfw_inte\")",
	             "{\"nftables\": [{\"table\": {\"family\": \"inet\", \"name\": "
	             "\"stockfw_inte\"}}]}", ABSENT, NULL);

	/* Other spacing and key order. */
	expect_live ("pretty-printed, keys in another order",
	             "{\n  \"nftables\" : [\n    { \"metainfo\" : { \"json_schema_version\" : 1 } },\n"
	             "    {\n      \"table\" : {\n        \"comment\" : \"sfw:0123456789abcdef0123456789abcdef\",\n"
	             "        \"handle\" : 9,\n        \"name\" : \"stockfw_intel\",\n"
	             "        \"family\" : \"inet\",\n        \"flags\" : [ \"dormant\" ]\n      }\n    }\n  ]\n}\n",
	             PRESENT, "0123456789abcdef0123456789abcdef");
	expect_live ("no blanks at all",
	             "{\"nftables\":[{\"table\":{\"name\":\"stockfw_intel\","
	             "\"family\":\"inet\",\"handle\":1,\"comment\":"
	             "\"sfw:00000000000000000000000000000000\"}}]}",
	             PRESENT, "00000000000000000000000000000000");

	/* Same family and name, but not a table object. */
	expect_live ("a set or chain object with the same family and name",
	             "{\"nftables\": [{\"set\": {\"family\": \"inet\", \"name\": "
	             "\"stockfw_intel\", \"table\": \"stockfw_intel\"}}, "
	             "{\"chain\": {\"family\": \"inet\", \"table\": "
	             "\"stockfw_intel\", \"name\": \"stockfw_intel\"}}]}",
	             ABSENT, NULL);
	expect_live ("a table object nested anywhere but the top-level list",
	             "{\"other\": {\"table\": {\"family\": \"inet\", \"name\": "
	             "\"stockfw_intel\"}}, \"nftables\": []}", ABSENT, NULL);

	/* Comments that are not a digest StockFW wrote. */
	expect_live ("a comment without the sfw: tag",
	             "{\"nftables\": [{\"table\": {\"family\": \"inet\", \"name\": "
	             "\"stockfw_intel\", \"comment\": \"made by hand\"}}]}",
	             PRESENT, NULL);
	expect_live ("sfw: and something that is not 32 hex digits",
	             "{\"nftables\": [{\"table\": {\"family\": \"inet\", \"name\": "
	             "\"stockfw_intel\", \"comment\": \"sfw:0123456789ABCDEF"
	             "0123456789abcdef\"}}]}", PRESENT, NULL);
	expect_live ("sfw: and 31 hex digits",
	             "{\"nftables\": [{\"table\": {\"family\": \"inet\", \"name\": "
	             "\"stockfw_intel\", \"comment\": \"sfw:0123456789abcdef"
	             "0123456789abcde\"}}]}", PRESENT, NULL);
	expect_live ("sfw: and 33 hex digits",
	             "{\"nftables\": [{\"table\": {\"family\": \"inet\", \"name\": "
	             "\"stockfw_intel\", \"comment\": \"sfw:0123456789abcdef"
	             "0123456789abcdef0\"}}]}", PRESENT, NULL);
	expect_live ("a comment that is not a string",
	             "{\"nftables\": [{\"table\": {\"family\": \"inet\", \"name\": "
	             "\"stockfw_intel\", \"comment\": 42}}]}", PRESENT, NULL);
	expect_live ("a name written with an escape is not ours",
	             "{\"nftables\": [{\"table\": {\"family\": \"inet\", \"name\": "
	             "\"stockfw\\u005fintel\"}}]}", ABSENT, NULL);
	expect_live ("escapes elsewhere are read past",
	             "{\"nftables\": [{\"metainfo\": {\"release_name\": "
	             "\"a \\\"quoted\\\" \\\\ name \\u00e9\"}}, {\"table\": {\"family\": "
	             "\"inet\", \"name\": \"stockfw_intel\", \"comment\": "
	             "\"sfw:0123456789abcdef0123456789abcdef\"}}]}",
	             PRESENT, "0123456789abcdef0123456789abcdef");

	/* Not JSON, or not whole. */
	expect_live ("truncated", "{\"nftables\": [{\"table\": {\"family\": "
	             "\"inet\", \"name\": \"stockfw_intel\"}}", UNKNOWN, NULL);
	expect_live ("trailing garbage", "{\"nftables\": [{\"table\": "
	             "{\"family\": \"inet\", \"name\": \"stockfw_intel\"}}]} x",
	             UNKNOWN, NULL);
	expect_live ("a bare string", "\"stockfw_intel\"", UNKNOWN, NULL);
	expect_live ("empty text", "", UNKNOWN, NULL);
	expect_live ("NULL", NULL, UNKNOWN, NULL);
	expect_live ("whole JSON without the nftables list", "{}", UNKNOWN, NULL);
	expect_live ("an nftables member that is not a list",
	             "{\"nftables\": {\"table\": {\"family\": \"inet\", "
	             "\"name\": \"stockfw_intel\"}}}", UNKNOWN, NULL);
	expect_live ("a line of text before the listing",
	             "Warning: something\n{\"nftables\": []}\n", UNKNOWN, NULL);
	{
		GString *deep = g_string_new ("{\"nftables\": ");

		for (guint i = 0; i < 100; i++)
			g_string_append_c (deep, '[');
		for (guint i = 0; i < 100; i++)
			g_string_append_c (deep, ']');
		g_string_append_c (deep, '}');
		expect_live ("nesting 100 deep is refused, not recursed into",
		             deep->str, UNKNOWN, NULL);
		g_string_free (deep, TRUE);
	}

	CHECK (fs_intelset_nft_parse_live (JSON_PRESENT, NULL),
	       "live: the digest pointer may be NULL");
}

/* `nft -j list chains inet' as nft 1.0.9 printed it for a table this
 * StockFW wrote (every chain carries the digest), with a decoy chain of
 * another table that carries a different one. */
#define CHAIN_JSON(table, name, comment) \
	"{\"chain\": {\"family\": \"inet\", \"table\": \"" table "\", " \
	"\"name\": \"" name "\", \"handle\": 1, " comment "\"type\": " \
	"\"filter\", \"hook\": \"" name "\", \"prio\": -10, " \
	"\"policy\": \"accept\"}}"
#define META "{\"metainfo\": {\"version\": \"1.0.9\", " \
	"\"release_name\": \"Old Doc Yak #3\", \"json_schema_version\": 1}}"
#define D1 "\"comment\": \"sfw:43254231e49deba9152e6f56f6251661\", "
#define D2 "\"comment\": \"sfw:ffffffffffffffffffffffffffffffff\", "

static void
expect_chains (const gchar *what, const gchar *json, FsIntelLive want,
               const gchar *want_digest)
{
	static gchar untouched[] = "untouched";
	gchar *digest = untouched;
	FsIntelLive got = fs_intelset_nft_parse_live_chains (json, &digest);

	CHECK (got == want && g_strcmp0 (digest, want_digest) == 0,
	       "chains: %s -> %s, digest %s (got %s, %s)", what,
	       live_name (want), want_digest != NULL ? want_digest : "none",
	       live_name (got), digest != NULL && digest != untouched
	       ? digest : "none");
	if (digest != untouched)
		g_free (digest);
}

static void
test_live_chains (void)
{
	expect_chains ("ours, every chain with the digest, a decoy table's chain",
	               "{\"nftables\": [" META ", "
	               CHAIN_JSON ("stockfw_intel2", "input", D2) ", "
	               CHAIN_JSON ("stockfw_intel", "input", D1) ", "
	               CHAIN_JSON ("stockfw_intel", "output", D1) ", "
	               CHAIN_JSON ("stockfw_intel", "forward", D1) "]}\n",
	               PRESENT, "43254231e49deba9152e6f56f6251661");
	expect_chains ("an older table: chains without comments (read the table)",
	               "{\"nftables\": [" META ", "
	               CHAIN_JSON ("stockfw_intel", "input", "") ", "
	               CHAIN_JSON ("stockfw_intel", "output", "") "]}",
	               PRESENT, NULL);
	expect_chains ("one chain replaced by hand, without the digest",
	               "{\"nftables\": [" META ", "
	               CHAIN_JSON ("stockfw_intel", "input", D1) ", "
	               CHAIN_JSON ("stockfw_intel", "output", "") "]}",
	               PRESENT, NULL);
	expect_chains ("two different digests",
	               "{\"nftables\": [" META ", "
	               CHAIN_JSON ("stockfw_intel", "input", D1) ", "
	               CHAIN_JSON ("stockfw_intel", "output", D2) "]}",
	               PRESENT, NULL);
	expect_chains ("only another table's chains",
	               "{\"nftables\": [" META ", "
	               CHAIN_JSON ("stockfw_intel2", "input", D1) "]}",
	               ABSENT, NULL);
	expect_chains ("no chains at all", "{\"nftables\": [" META "]}",
	               ABSENT, NULL);
	expect_chains ("a family ip chain of the same table name",
	               "{\"nftables\": [{\"chain\": {\"family\": \"ip\", "
	               "\"table\": \"stockfw_intel\", \"name\": \"input\", "
	               D1 "\"handle\": 1}}]}", ABSENT, NULL);
	expect_chains ("cut short", "{\"nftables\": [" META ", "
	               CHAIN_JSON ("stockfw_intel", "input", D1), UNKNOWN, NULL);
	expect_chains ("not a listing", "{}", UNKNOWN, NULL);
	expect_chains ("NULL", NULL, UNKNOWN, NULL);
	expect_chains ("an error line first",
	               "Error: x\n{\"nftables\": []}", UNKNOWN, NULL);
}

int
main (void)
{
	test_scripts ();
	test_chunks ();
	test_labels ();
	test_ids ();
	test_ruleset ();
	test_digest ();
	test_counters ();
	test_live ();
	test_live_chains ();

	g_print ("\n%s: %u failure(s)\n", failures ? "FAILED" : "PASSED",
	         failures);
	return failures ? 1 : 0;
}
