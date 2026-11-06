/*---[ fuzz-geodb.c ]----------------------------------------------------
 * A libFuzzer harness for the location database reader
 * (src/core/fs-geodb.c).  Each input is a whole database file; it goes
 * through every structural check (the signature step is skipped, so the
 * fuzzer reaches the parser), and whatever opens is used: lookups of
 * addresses taken from the input, enumeration by the first country, AS
 * and every flag, the country list and an AS search.  Built and run by
 * tests/test-geodb.sh with clang:
 *
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined -DFS_GEODB_TESTING \
 *         tests/fuzz-geodb.c src/core/*.c ...
 *   ./fuzz-geodb -max_total_time=180 corpus/ tests/geodb/
 *
 * Any crash, sanitizer report, leak or abort() below is a finding.
 *--------------------------------------------------------------------*/

#include <glib.h>
#include <gio/gio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/fs-geodb.h"
#include "core/fs-iprange.h"

static void
sane_or_die (gboolean cond)
{
	if (!cond)
		abort ();
}

static void
use (FsGeodb *db, const uint8_t *data, size_t size)
{
	const FsGeodbInfo *info = fs_geodb_info (db);
	GPtrArray *cs, *as;
	const gchar *codes[2] = { NULL, NULL };
	guint32 asn = 0;
	FsGeodbFilter f = { 0 };
	FsRangeSet *set;

	sane_or_die (info != NULL &&
	             g_utf8_validate (info->vendor, -1, NULL) &&
	             g_utf8_validate (info->description, -1, NULL) &&
	             g_utf8_validate (info->license, -1, NULL));

	/* addresses from the input's last bytes, and a few fixed ones */
	for (guint i = 0; i < 8; i++) {
		guint8 b[16] = { 0 };
		GInetAddress *a;
		FsGeodbMatch m;

		for (guint k = 0; k < 16; k++)
			b[k] = size > 0 ? data[(size - 1 - (i * 16 + k) % size)] : 0;
		if (i == 6)
			memset (b, 0, sizeof b);
		if (i == 7)
			memset (b, 0xff, sizeof b);
		a = g_inet_address_new_from_bytes (b, i % 2 ? G_SOCKET_FAMILY_IPV6
		                                            : G_SOCKET_FAMILY_IPV4);
		sane_or_die (fs_geodb_lookup_inet (db, a, &m, NULL));
		if (m.found) {
			sane_or_die (m.network != NULL &&
			             m.prefix_len <= (m.family == FS_AF_V4 ? 32u : 128u));
			if (m.country[0] != '\0' && codes[0] == NULL)
				codes[0] = g_intern_string (m.country);
			if (m.asn != 0 && asn == 0)
				asn = m.asn;
		}
		fs_geodb_match_clear (&m);
		g_object_unref (a);
	}

	cs = fs_geodb_countries (db);
	for (guint i = 0; i < cs->len; i++) {
		FsGeodbCountry *c = g_ptr_array_index (cs, i);

		sane_or_die (g_utf8_validate (c->name, -1, NULL));
		if (codes[0] == NULL)
			codes[0] = g_intern_string (c->code);
	}
	g_ptr_array_unref (cs);
	as = fs_geodb_search_as (db, "a", 16);
	g_ptr_array_unref (as);
	g_free (fs_geodb_as_name (db, asn));

	f.countries = codes[0] != NULL ? codes : NULL;
	f.asns = &asn;
	f.n_asns = asn != 0 ? 1 : 0;
	f.flags = FS_GEODB_FLAGS_KNOWN;
	set = fs_geodb_enumerate (db, &f, NULL);
	sane_or_die (set != NULL);
	g_ptr_array_unref (fs_geodb_set_prefixes (set));
	fs_range_set_free (set);
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	GError *e = NULL;
	FsGeodb *db = fs_geodb_testing_open_unverified (data, size, &e);

	if (db != NULL) {
		use (db, data, size);
		fs_geodb_close (db);
	} else {
		/* a refusal always says why, and it is always FORMAT */
		sane_or_die (e != NULL && e->domain == FS_GEODB_ERROR &&
		             e->code == FS_GEODB_ERR_FORMAT);
	}
	g_clear_error (&e);
	return 0;
}
