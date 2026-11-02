/*---[ test-intel.c ]----------------------------------------------------
 * Threat intel, the pure parts: address ranges (fs-iprange) and the
 * blocklist-to-nftables path (fs-nftset) up to the script it renders.
 * GLib only; no root, no network, no nft.  The live half, the script
 * applied by a real nft in a network namespace, is test-nftset.sh.
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <string.h>

#include "core/fs-iprange.h"
#include "core/fs-nftset.h"

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

int
main (void)
{
	test_parse ();
	test_sets ();
	test_csv ();
	test_script ();

	g_print ("\n%s: %u failure(s)\n", failures ? "FAILED" : "PASSED",
	         failures);
	return failures ? 1 : 0;
}
