/*---[ test-geodb.c ]----------------------------------------------------
 * The location database reader (src/core/fs-geodb.c), 1.0.7 threat
 * intel round 2.  Design: docs/1.0.7-threat-intel-design.md, section
 * 11; how to run: tests/README.md.
 *
 *   fs-geodb-test [fixture dir]          the suite (default tests/geodb)
 *   fs-geodb-test golden DIR NAME PUB         golden checks of DIR/NAME.*
 *   fs-geodb-test lookup-tsv DB PUB FILE      one TSV line per address
 *   fs-geodb-test enum DB PUB SPEC            prefixes for a filter
 *   fs-geodb-test resign IN OUT KEY [SLOT]    sign with a private key
 *   fs-geodb-test info DB [PUB]               open and print metadata
 *   fs-geodb-test update STORE PUB            fs_geodb_update, default
 *                                             downloader (STOCKFW_TEST_CURL)
 *   fs-geodb-test mutate SEED N DIR           the mutation loop alone
 *
 * Built with FS_GEODB_TESTING (verify with a test key; check a buffer
 * without its signature).  The fixtures in tests/geodb were written by
 * libloc's own writer (tests/geodb-fixtures.py), with the answers
 * libloc's reader gives; the malformed files are made here, from those,
 * and signed here with a key made at run time, so that every structural
 * check is reached past a valid signature.
 *--------------------------------------------------------------------*/

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <lzma.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#ifdef G_OS_WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "core/fs-geodb.h"
#include "core/fs-iprange.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do {                                   \
	checks++;                                                \
	if (!(cond)) {                                           \
		printf ("FAIL: ");                               \
		printf (__VA_ARGS__);                            \
		printf ("\n");                                   \
		failures++;                                      \
	} else {                                                 \
		printf ("ok:   ");                               \
		printf (__VA_ARGS__);                            \
		printf ("\n");                                   \
	}                                                        \
} while (0)

/* ---- the format, as the test knows it (file offsets) ------------------ */

#define F_CREATED      8
#define F_VENDOR       16
#define F_DESC         20
#define F_LICENSE      24
#define F_SEC_OFF(i)   (28 + 8 * (i))
#define F_SEC_LEN(i)   (32 + 8 * (i))
#define F_SIG1_LEN     68
#define F_SIG2_LEN     70
#define F_SIG1         72
#define F_SIG2         (72 + 2048)
#define F_RESERVED     (72 + 4096)
#define F_HEADER_END   4200
#define SEC_AS         0
#define SEC_NETS       1
#define SEC_TREE       2
#define SEC_COUNTRIES  3
#define SEC_POOL       4

static const gchar *fixdir = "tests/geodb";
static gchar *tmpdir;

static gchar *
fx (const gchar *name)
{
	return g_build_filename (fixdir, name, NULL);
}

static guint32
get32 (const guint8 *p)
{
	return ((guint32) p[0] << 24) | ((guint32) p[1] << 16) |
	       ((guint32) p[2] << 8) | p[3];
}

static void
put16 (guint8 *p, guint16 v)
{
	p[0] = (guint8) (v >> 8);
	p[1] = (guint8) v;
}

static void
put32 (guint8 *p, guint32 v)
{
	p[0] = (guint8) (v >> 24);
	p[1] = (guint8) (v >> 16);
	p[2] = (guint8) (v >> 8);
	p[3] = (guint8) v;
}

static void
put64 (guint8 *p, guint64 v)
{
	put32 (p, (guint32) (v >> 32));
	put32 (p + 4, (guint32) v);
}

static guint8 *
slurp (const gchar *path, gsize *len)
{
	gchar *data = NULL;

	if (!g_file_get_contents (path, &data, len, NULL)) {
		*len = 0;
		return NULL;
	}
	return (guint8 *) data;
}

static guint8 *
slurp_fx (const gchar *name, gsize *len)
{
	gchar *p = fx (name);
	guint8 *d = slurp (p, len);

	if (d == NULL) {
		printf ("FAIL: fixture %s is missing\n", p);
		failures++;
	}
	g_free (p);
	return d;
}

static gboolean
spit (const gchar *path, const guint8 *data, gsize len)
{
	return g_file_set_contents (path, (const gchar *) data, (gssize) len,
	                            NULL);
}

static void
use_key_file (const gchar *name)
{
	gchar *p = fx (name), *pem = NULL;

	if (!g_file_get_contents (p, &pem, NULL, NULL)) {
		printf ("FAIL: key %s is missing\n", p);
		failures++;
	}
	fs_geodb_testing_set_key (pem);
	g_free (pem);
	g_free (p);
}

/* Open a buffer through the real path: written to a file, then
 * fs_geodb_open (map, verify, check). */
static FsGeodb *
open_buf (const guint8 *data, gsize len, GError **error)
{
	gchar *path = g_build_filename (tmpdir, "case.db", NULL);
	FsGeodb *db = NULL;

	g_unlink (path);
	if (spit (path, data, len))
		db = fs_geodb_open (path, error);
	else
		g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_FAILED, "write");
	g_unlink (path);
	g_free (path);
	return db;
}

/* NULL and the expected code: TRUE.  Anything else: FALSE, and says
 * what happened in `got' (static). */
static const gchar *
outcome_text (FsGeodb *db, GError *e)
{
	static gchar buf[512];

	if (db != NULL)
		return "opened";
	if (e == NULL)
		return "NULL without an error";
	g_snprintf (buf, sizeof buf, "code %d: %s", e->code, e->message);
	return buf;
}

static gboolean
refused_with (FsGeodb *db, GError *e, gint code, const gchar **got)
{
	*got = outcome_text (db, e);
	return db == NULL && e != NULL && e->domain == FS_GEODB_ERROR &&
	       e->code == code;
}

/* ---- a P-521 key made at run time, and a signer ------------------------ */

static EVP_PKEY *
key_new (const gchar *curve)
{
	EVP_PKEY *k = EVP_PKEY_Q_keygen (NULL, NULL, "EC", curve);

	if (k == NULL) {
		printf ("FAIL: could not make a %s key\n", curve);
		failures++;
	}
	return k;
}

static gchar *
key_pub_pem (EVP_PKEY *key)
{
	BIO *bio = BIO_new (BIO_s_mem ());
	BUF_MEM *mem = NULL;
	gchar *out;

	PEM_write_bio_PUBKEY (bio, key);
	BIO_get_mem_ptr (bio, &mem);
	out = g_strndup (mem->data, mem->length);
	BIO_free (bio);
	return out;
}

/* The test's own signer, from the format's rule: SHA-256, ECDSA (DER)
 * over the whole file with both lengths and both 2048-byte slots read
 * as zeros.  tests/test-geodb.sh checks that `location verify' accepts
 * what it signs.  Writes slot `slot' (1 or 2) and its length; the other
 * slot is left as it is. */
static gboolean
sign_slot (guint8 *data, gsize len, EVP_PKEY *key, guint slot)
{
	guint8 *msg;
	EVP_MD_CTX *ctx;
	guint8 sig[512];
	size_t sig_len = sizeof sig;
	gboolean ok;

	if (len < F_HEADER_END)
		return FALSE;
	msg = g_memdup2 (data, len);
	memset (msg + F_SIG1_LEN, 0, 4);
	memset (msg + F_SIG1, 0, 4096);
	ctx = EVP_MD_CTX_new ();
	ok = EVP_DigestSignInit (ctx, NULL, EVP_sha256 (), NULL, key) == 1 &&
	     EVP_DigestSign (ctx, sig, &sig_len, msg, len) == 1;
	EVP_MD_CTX_free (ctx);
	g_free (msg);
	if (!ok)
		return FALSE;
	memset (data + (slot == 1 ? F_SIG1 : F_SIG2), 0, 2048);
	memcpy (data + (slot == 1 ? F_SIG1 : F_SIG2), sig, sig_len);
	put16 (data + (slot == 1 ? F_SIG1_LEN : F_SIG2_LEN), (guint16) sig_len);
	return TRUE;
}

static void
clear_slot (guint8 *data, guint slot)
{
	memset (data + (slot == 1 ? F_SIG1 : F_SIG2), 0, 2048);
	put16 (data + (slot == 1 ? F_SIG1_LEN : F_SIG2_LEN), 0);
}

/* Both slots cleared, then signed in slot 1. */
static gboolean
resign (guint8 *data, gsize len, EVP_PKEY *key)
{
	if (len < F_HEADER_END)
		return FALSE;
	clear_slot (data, 1);
	clear_slot (data, 2);
	return sign_slot (data, len, key, 1);
}

/* ---- an xz encoder, for the unpack tests ------------------------------- */

static GBytes *
xz_encode (const guint8 *data, gsize len, guint32 preset)
{
	gsize cap = lzma_stream_buffer_bound (len), out_len = 0;
	guint8 *out = g_malloc (cap);

	if (lzma_easy_buffer_encode (preset, LZMA_CHECK_CRC64, NULL, data, len,
	                             out, &out_len, cap) != LZMA_OK) {
		g_free (out);
		return NULL;
	}
	return g_bytes_new_take (out, out_len);
}

/* `total' zero bytes, streamed through the encoder (a bomb). */
static GBytes *
xz_zeros (guint64 total)
{
	lzma_stream s = LZMA_STREAM_INIT;
	GByteArray *out = g_byte_array_new ();
	static guint8 zeros[1 << 16];
	guint8 buf[1 << 16];
	guint64 fed = 0;
	lzma_ret ret;

	if (lzma_easy_encoder (&s, 0, LZMA_CHECK_CRC64) != LZMA_OK)
		return NULL;
	for (;;) {
		lzma_action act = LZMA_RUN;

		if (s.avail_in == 0 && fed < total) {
			gsize n = (gsize) MIN ((guint64) sizeof zeros, total - fed);

			s.next_in = zeros;
			s.avail_in = n;
			fed += n;
		}
		if (s.avail_in == 0 && fed >= total)
			act = LZMA_FINISH;
		s.next_out = buf;
		s.avail_out = sizeof buf;
		ret = lzma_code (&s, act);
		g_byte_array_append (out, buf, (guint) (sizeof buf - s.avail_out));
		if (ret == LZMA_STREAM_END)
			break;
		if (ret != LZMA_OK) {
			lzma_end (&s);
			g_byte_array_unref (out);
			return NULL;
		}
	}
	lzma_end (&s);
	return g_byte_array_free_to_bytes (out);
}

/* The LZMA2 dictionary-size property of the first block, set to `prop'
 * (its 6-bit code), with the block header's CRC32 made right again. */
static GBytes *
xz_with_dict (GBytes *xz, guint8 prop)
{
	gsize len = 0;
	const guint8 *src = g_bytes_get_data (xz, &len);
	guint8 *d = g_memdup2 (src, len);
	gsize hdr = 12, size = ((gsize) d[hdr] + 1) * 4, at = hdr + 2;
	guint8 flags = d[hdr + 1];

	for (guint i = 0; i < 2; i++)                /* the optional sizes */
		if (flags & (i == 0 ? 0x40 : 0x80))
			while (d[at++] & 0x80)
				;
	/* filter id 0x21 (LZMA2), one property byte */
	if (d[at] != 0x21 || d[at + 1] != 1) {
		g_free (d);
		return NULL;
	}
	d[at + 2] = prop;
	{
		guint32 crc = lzma_crc32 (d + hdr, size - 4, 0);

		d[hdr + size - 4] = (guint8) crc;
		d[hdr + size - 3] = (guint8) (crc >> 8);
		d[hdr + size - 2] = (guint8) (crc >> 16);
		d[hdr + size - 1] = (guint8) (crc >> 24);
	}
	return g_bytes_new_take (d, len);
}

static int
null_fd (void)
{
#ifdef G_OS_WIN32
	return g_open ("NUL", O_WRONLY | O_BINARY, 0);
#else
	return g_open ("/dev/null", O_WRONLY, 0);
#endif
}

/* ---- expected answers ------------------------------------------------ */

static gchar *
unesc (const gchar *s)
{
	GString *o = g_string_new (NULL);

	for (; *s != '\0'; s++) {
		if (*s == '\\' && s[1] != '\0') {
			s++;
			g_string_append_c (o, *s == 'n' ? '\n' :
			                      *s == 't' ? '\t' : *s);
		} else {
			g_string_append_c (o, *s);
		}
	}
	return g_string_free (o, FALSE);
}

typedef struct
{
	gchar  *addr;
	gchar  *status;      /* found / none / ref-error */
	gchar  *network;
	gchar  *cc;
	guint32 asn;
	guint   flags;
	gchar  *as_name;
} Expect;

static void
expect_free (gpointer p)
{
	Expect *e = p;

	g_free (e->addr);
	g_free (e->status);
	g_free (e->network);
	g_free (e->cc);
	g_free (e->as_name);
	g_free (e);
}

static GPtrArray *
load_lookups (const gchar *name)
{
	gchar *file = g_strdup_printf ("%s.lookup.tsv", name);
	gchar *path = fx (file), *text = NULL;
	gchar **lines;
	GPtrArray *out = g_ptr_array_new_with_free_func (expect_free);

	if (!g_file_get_contents (path, &text, NULL, NULL)) {
		printf ("FAIL: %s is missing\n", path);
		failures++;
	}
	lines = g_strsplit (text ? text : "", "\n", -1);
	for (gchar **l = lines; *l != NULL; l++) {
		gchar **f;
		Expect *e;

		if (**l == '\0')
			continue;
		f = g_strsplit (*l, "\t", 7);
		if (g_strv_length (f) != 7) {
			g_strfreev (f);
			continue;
		}
		e = g_new0 (Expect, 1);
		e->addr = g_strdup (f[0]);
		e->status = g_strdup (f[1]);
		e->network = g_strdup (f[2]);
		e->cc = g_strdup (f[3]);
		e->asn = (guint32) g_ascii_strtoull (f[4], NULL, 10);
		e->flags = (guint) g_ascii_strtoull (f[5], NULL, 10);
		e->as_name = unesc (f[6]);
		g_ptr_array_add (out, e);
		g_strfreev (f);
	}
	g_strfreev (lines);
	g_free (text);
	g_free (path);
	g_free (file);
	return out;
}

/* "cc=DE,US asn=1,2 flags=8" (a "-" for none) into a filter. */
typedef struct
{
	gchar       **countries;
	GArray       *asns;
	FsGeodbFilter f;
} SpecFilter;

static void
spec_parse (const gchar *spec, SpecFilter *sf)
{
	gchar **parts = g_strsplit (spec, " ", -1);

	memset (sf, 0, sizeof *sf);
	sf->asns = g_array_new (FALSE, FALSE, sizeof (guint32));
	for (gchar **p = parts; *p != NULL; p++) {
		if (g_str_has_prefix (*p, "cc=") && strcmp (*p + 3, "-") != 0)
			sf->countries = g_strsplit (*p + 3, ",", -1);
		else if (g_str_has_prefix (*p, "asn=") &&
		         strcmp (*p + 4, "-") != 0) {
			gchar **a = g_strsplit (*p + 4, ",", -1);

			for (gchar **x = a; *x != NULL; x++) {
				guint32 v = (guint32) g_ascii_strtoull (*x, NULL, 10);

				g_array_append_val (sf->asns, v);
			}
			g_strfreev (a);
		} else if (g_str_has_prefix (*p, "flags=")) {
			sf->f.flags = (guint) g_ascii_strtoull (*p + 6, NULL, 10);
		}
	}
	g_strfreev (parts);
	sf->f.countries = (const gchar *const *) sf->countries;
	sf->f.asns = (const guint32 *) sf->asns->data;
	sf->f.n_asns = sf->asns->len;
}

static void
spec_clear (SpecFilter *sf)
{
	g_strfreev (sf->countries);
	g_array_unref (sf->asns);
}

static gchar *
prefixes_joined (const FsRangeSet *set)
{
	GPtrArray *p = fs_geodb_set_prefixes (set);
	GString *s = g_string_new (NULL);

	for (guint i = 0; i < p->len; i++) {
		g_string_append (s, g_ptr_array_index (p, i));
		g_string_append_c (s, '\n');
	}
	g_ptr_array_unref (p);
	return g_string_free (s, FALSE);
}

/* ===================================================== the pinned key */

/* SHA-256 of the DER SubjectPublicKeyInfo of IPFire's key; the key in
 * fs-geodb.c cannot change without this changing too. */
#define PINNED_SPKI_SHA256 \
	"f2af409aeb339c55d686644f661b96d329f80c5f1ab34ef027cb36d2620b53aa"

static gchar *
spki_sha256 (const gchar *pem)
{
	BIO *bio = BIO_new_mem_buf (pem, -1);
	EVP_PKEY *k = PEM_read_bio_PUBKEY (bio, NULL, NULL, NULL);
	guint8 *der = NULL;
	int n;
	gchar *hex = NULL;

	BIO_free (bio);
	if (k == NULL)
		return NULL;
	n = i2d_PUBKEY (k, &der);
	if (n > 0)
		hex = g_compute_checksum_for_data (G_CHECKSUM_SHA256, der,
		                                   (gsize) n);
	OPENSSL_free (der);
	EVP_PKEY_free (k);
	return hex;
}

static void
test_pinned_key (void)
{
	const gchar *pem = fs_geodb_pinned_key_pem ();
	BIO *bio = BIO_new_mem_buf (pem, -1);
	EVP_PKEY *k = PEM_read_bio_PUBKEY (bio, NULL, NULL, NULL);
	gchar group[64] = "";
	size_t glen = 0;
	gchar *fp = spki_sha256 (pem), *distro = NULL;

	BIO_free (bio);
	CHECK (k != NULL && EVP_PKEY_get_base_id (k) == EVP_PKEY_EC &&
	       EVP_PKEY_get_group_name (k, group, sizeof group, &glen) == 1 &&
	       strcmp (group, "secp521r1") == 0,
	       "the pinned key is an ECDSA P-521 public key (%s)", group);
	EVP_PKEY_free (k);
	printf ("      pinned key SPKI SHA-256: %s\n", fp ? fp : "?");
	CHECK (fp != NULL && strcmp (fp, PINNED_SPKI_SHA256) == 0,
	       "the pinned key is IPFire's (SPKI SHA-256 pinned in the test)");
	if (g_file_get_contents ("/var/lib/location/signing-key.pem", &distro,
	                         NULL, NULL)) {
		gchar *dfp = spki_sha256 (distro);

		CHECK (dfp != NULL && fp != NULL && strcmp (dfp, fp) == 0,
		       "the pinned key is the one the distribution's `location' "
		       "package ships (/var/lib/location/signing-key.pem)");
		g_free (dfp);
		g_free (distro);
	} else {
		printf ("SKIP: /var/lib/location/signing-key.pem is not here "
		        "(apt install location)\n");
	}
	g_free (fp);
}

/* ==================================================== the real thing */

/* Ubuntu's libloc-database package: a database IPFire built and signed
 * on 2022-10-29.  Checked with the pinned key, never a test key. */
#define REAL_DB          "/usr/share/libloc-location/location.db"
#define REAL_CREATED_AT  G_GINT64_CONSTANT (1667023194)

static void
test_real_database (void)
{
	const gchar *path = g_getenv ("STOCKFW_GEODB_REAL");
	GError *e = NULL;
	FsGeodb *db;
	FsGeodbMatch m;
	const FsGeodbInfo *info;
	gint64 t0;

	if (path == NULL || *path == '\0')
		path = REAL_DB;
	if (!g_file_test (path, G_FILE_TEST_IS_REGULAR)) {
		printf ("SKIP: no IPFire-signed database at %s "
		        "(apt install libloc-database)\n", path);
		return;
	}
	fs_geodb_testing_set_key (NULL);          /* the pinned key */
	t0 = g_get_monotonic_time ();
	db = fs_geodb_open (path, &e);
	CHECK (db != NULL, "IPFire's own database verifies with the pinned "
	       "key and passes every check (%s)", outcome_text (db, e));
	g_clear_error (&e);
	if (db == NULL)
		return;
	info = fs_geodb_info (db);
	printf ("      %s: %" G_GUINT64_FORMAT " bytes, %u networks, %u nodes, "
	        "%u ASes, %u countries, slot %u, opened in %" G_GINT64_FORMAT
	        " ms\n", path, info->size, info->networks, info->nodes,
	        info->ases, info->countries, info->signed_slot,
	        (g_get_monotonic_time () - t0) / 1000);
	CHECK (strcmp (info->vendor, "IPFire Project") == 0 &&
	       strcmp (info->license, "CC BY-SA 4.0") == 0,
	       "its vendor is \"%s\" and its licence \"%s\"", info->vendor,
	       info->license);
	if (info->created_at == REAL_CREATED_AT) {
		gboolean ok;

		CHECK (info->signed_slot == 2,
		       "the 2022-10-29 copy is signed in slot 2 only, and that is "
		       "enough");
		ok = fs_geodb_lookup (db, "8.8.8.8", &m, NULL) && m.found &&
		     strcmp (m.network, "8.8.8.0/24") == 0 &&
		     strcmp (m.country, "US") == 0 && m.asn == 15169 &&
		     m.as_name != NULL && strcmp (m.as_name, "GOOGLE") == 0 &&
		     m.flags == FS_GEODB_FLAG_ANYCAST;
		CHECK (ok, "8.8.8.8 is in 8.8.8.0/24, registered in US, AS15169 "
		       "GOOGLE, anycast (as `location lookup' says)");
		fs_geodb_match_clear (&m);
		ok = fs_geodb_lookup (db, "2a00:1450::1", &m, NULL) && m.found &&
		     strcmp (m.network, "2a00:1450::/32") == 0 &&
		     strcmp (m.country, "IE") == 0 && m.asn == 15169;
		CHECK (ok, "2a00:1450::1 is in 2a00:1450::/32, registered in IE, "
		       "AS15169");
		fs_geodb_match_clear (&m);
	} else {
		printf ("      (not the 2022-10-29 copy: its lookups are compared "
		        "by tests/test-geodb.sh)\n");
	}
	fs_geodb_close (db);
}

/* ============================================= golden: lookups */

static gboolean
match_equals (const Expect *e, const FsGeodbMatch *m, gchar **why)
{
	gboolean want = strcmp (e->status, "found") == 0;

	if (want != m->found) {
		*why = g_strdup_printf ("%s: libloc %s, fs-geodb %s", e->addr,
		                        e->status, m->found ? m->network : "none");
		return FALSE;
	}
	if (!want)
		return TRUE;
	if (strcmp (e->network, m->network) != 0 ||
	    strcmp (e->cc, m->country) != 0 || e->asn != m->asn ||
	    e->flags != m->flags ||
	    strcmp (e->as_name, m->as_name ? m->as_name : "") != 0) {
		*why = g_strdup_printf ("%s: libloc %s %s AS%u %u \"%s\", "
		                        "fs-geodb %s %s AS%u %u \"%s\"", e->addr,
		                        e->network, e->cc, e->asn, e->flags,
		                        e->as_name, m->network, m->country, m->asn,
		                        m->flags, m->as_name ? m->as_name : "");
		return FALSE;
	}
	return TRUE;
}

static FsGeodb *
open_fixture (const gchar *name)
{
	gchar *file = g_strdup_printf ("%s.db", name);
	gchar *path = fx (file);
	GError *e = NULL;
	FsGeodb *db = fs_geodb_open (path, &e);

	if (db == NULL) {
		printf ("FAIL: %s does not open: %s\n", path,
		        e ? e->message : "?");
		failures++;
	}
	g_clear_error (&e);
	g_free (path);
	g_free (file);
	return db;
}

static void
golden_lookups (const gchar *name)
{
	FsGeodb *db = open_fixture (name);
	GPtrArray *ex = load_lookups (name);
	guint bad = 0, found = 0, none = 0, referr = 0;

	if (db == NULL) {
		g_ptr_array_unref (ex);
		return;
	}
	for (guint i = 0; i < ex->len; i++) {
		const Expect *e = g_ptr_array_index (ex, i);
		FsGeodbMatch m;
		gchar *why = NULL;

		if (!fs_geodb_lookup (db, e->addr, &m, NULL))
			why = g_strdup_printf ("%s: refused as an address", e->addr);
		else
			match_equals (e, &m, &why);
		if (why != NULL) {
			if (bad++ < 5)
				printf ("      differs: %s\n", why);
			g_free (why);
		}
		found += m.found ? 1 : 0;
		none += strcmp (e->status, "none") == 0;
		referr += strcmp (e->status, "ref-error") == 0;
		fs_geodb_match_clear (&m);
	}
	CHECK (ex->len > 0 && bad == 0,
	       "%s.db: all %u lookups agree with libloc's (%u found, %u none, "
	       "%u where libloc fails and fs-geodb finds no network)", name,
	       ex->len, found, none, referr);
	g_ptr_array_unref (ex);
	fs_geodb_close (db);
}

/* The cases the small database was written for, by name. */
static void
small_lookups (void)
{
	static const struct {
		const gchar *addr, *net, *cc;
		guint32 asn;
		guint flags;
		const gchar *as_name;
		const gchar *what;
	} cases[] = {
		{ "10.9.9.9", "10.0.0.0/8", "DE", 64500, 0, "Example One",
		  "the outer of three nested networks" },
		{ "10.1.9.9", "10.1.0.0/16", "US", 64501, FS_GEODB_FLAG_ANYCAST,
		  "Example Two GmbH", "the middle one, anycast" },
		{ "10.1.2.3", "10.1.2.0/24", "FR", 64502,
		  FS_GEODB_FLAG_ANONYMOUS_PROXY | FS_GEODB_FLAG_DROP,
		  "T\xc3\xa9st \xc3\x9cn\xc3\xaf" "code",
		  "the inner one: two flags, a UTF-8 AS name" },
		{ "10.1.2.200", "10.1.2.128/25", "", 64503, 0, NULL,
		  "no country, an AS the table does not name" },
		{ "192.0.2.77", "192.0.2.0/24", "NL", 64504,
		  FS_GEODB_FLAG_SATELLITE_PROVIDER, "Sat?Net",
		  "satellite; a BEL in the AS name is shown as ?" },
		{ "198.51.100.7", "198.51.100.7/32", "GB", 64505, 0,
		  "?Evil Corp", "a /32; a bidi override in the name is shown as ?" },
		{ "::ffff:198.51.100.7", "198.51.100.7/32", "GB", 64505, 0,
		  "?Evil Corp", "the same address IPv4-mapped" },
		{ "255.255.255.255", "255.255.255.255/32", "JP", 2147483647, 0,
		  "Largest the binding takes", "the last IPv4 address" },
		{ "2001:db8:1:2::1", "2001:db8:1:2::1/128", "GB", 64505, 0,
		  "?Evil Corp", "a /128 inside three nested IPv6 networks" },
		{ "2001:db8:1:2::2", "2001:db8:1:2::/64", "FR", 64502, 0,
		  "T\xc3\xa9st \xc3\x9cn\xc3\xaf" "code", "its /64" },
		{ "2001:db8:1:3::", "2001:db8:1::/48", "DE", 64500,
		  FS_GEODB_FLAG_DROP, "Example One", "its /48, drop" },
		{ "2001:db8:2::", "2001:db8::/32", "US", 64501, 0,
		  "Example Two GmbH", "its /32" },
		{ "2c0f:f000::1", "2c0f:f000::/20", "NL", 0, FS_GEODB_FLAG_ANYCAST,
		  NULL, "no AS at all" },
		{ "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		  "ffff:ffff:ffff:ffff::/64", "IT", 64506, 0, "Adjacent Halves",
		  "the last IPv6 address" },
	};
	FsGeodb *db = open_fixture ("small");
	FsGeodbMatch m;

	if (db == NULL)
		return;
	for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
		gboolean ok = fs_geodb_lookup (db, cases[i].addr, &m, NULL) &&
		              m.found && strcmp (m.network, cases[i].net) == 0 &&
		              strcmp (m.country, cases[i].cc) == 0 &&
		              m.asn == cases[i].asn && m.flags == cases[i].flags &&
		              g_strcmp0 (m.as_name, cases[i].as_name) == 0;

		CHECK (ok, "small: %s -> %s %s AS%u (%s)", cases[i].addr,
		       cases[i].net, cases[i].cc, cases[i].asn, cases[i].what);
		fs_geodb_match_clear (&m);
	}
	CHECK (fs_geodb_lookup (db, "9.255.255.255", &m, NULL) && !m.found &&
	       m.network == NULL,
	       "small: 9.255.255.255, just below 10.0.0.0/8, is in no network");
	fs_geodb_match_clear (&m);
	CHECK (fs_geodb_lookup (db, "::1", &m, NULL) && !m.found,
	       "small: ::1 is in no network");
	fs_geodb_match_clear (&m);
	fs_geodb_close (db);
}

/* Hand-checked semantics libloc cannot give an answer for. */
static void
edge_lookups (void)
{
	FsGeodb *db = open_fixture ("edge");
	FsGeodb *db6 = open_fixture ("edge6");
	FsGeodbMatch m;

	if (db != NULL) {
		CHECK (fs_geodb_lookup (db, "::1", &m, NULL) && m.found &&
		       strcmp (m.network, "::/8") == 0 &&
		       strcmp (m.country, "US") == 0,
		       "edge: ::1 is in the IPv6 network ::/8");
		fs_geodb_match_clear (&m);
		CHECK (fs_geodb_lookup (db, "8.8.8.8", &m, NULL) && m.found &&
		       strcmp (m.network, "0.0.0.0/0") == 0 &&
		       m.family == FS_AF_V4 && m.prefix_len == 0,
		       "edge: 8.8.8.8 is in 0.0.0.0/0 (IPv4, prefix 0), not in "
		       "::/8, which covers ::ffff:0:0/96 in the tree");
		fs_geodb_match_clear (&m);
	}
	if (db6 != NULL) {
		CHECK (fs_geodb_lookup (db6, "8.8.8.8", &m, NULL) && !m.found,
		       "edge6: ::/0 is an IPv6 network and never answers for an "
		       "IPv4 address (libloc fails on this lookup)");
		fs_geodb_match_clear (&m);
		CHECK (fs_geodb_lookup (db6, "1.2.3.4", &m, NULL) && m.found &&
		       strcmp (m.network, "1.0.0.0/8") == 0 &&
		       m.country[0] == '\0' && m.asn == 5,
		       "edge6: 1.2.3.4 is in 1.0.0.0/8 (no country, AS5)");
		fs_geodb_match_clear (&m);
		CHECK (fs_geodb_lookup (db6, "2001:db8::1", &m, NULL) && m.found &&
		       strcmp (m.network, "::/0") == 0,
		       "edge6: any IPv6 address is in ::/0");
		fs_geodb_match_clear (&m);
	}
	fs_geodb_close (db);
	fs_geodb_close (db6);
}

/* ========================================== golden: enumerate */

static void
golden_enumerate (const gchar *name)
{
	gchar *file = g_strdup_printf ("%s.enum.txt", name);
	gchar *path = fx (file), *text = NULL;
	gchar **lines;
	FsGeodb *db = open_fixture (name);
	guint sections = 0, skipped = 0, bad = 0, prefixes = 0;
	GString *want = NULL;
	gchar *spec = NULL;

	if (db == NULL || !g_file_get_contents (path, &text, NULL, NULL)) {
		CHECK (FALSE, "%s: fixture readable", path);
		goto out;
	}
	lines = g_strsplit (text, "\n", -1);
	for (gchar **l = lines;; l++) {
		gboolean header = *l != NULL && g_str_has_prefix (*l, "filter ");

		if ((*l == NULL || header) && spec != NULL) {
			SpecFilter sf;
			GError *e = NULL;
			FsRangeSet *set;
			gchar *got;

			spec_parse (spec, &sf);
			set = fs_geodb_enumerate (db, &sf.f, &e);
			got = set ? prefixes_joined (set) : g_strdup ("(error)\n");
			if (strcmp (got, want->str) != 0 && bad++ < 3)
				printf ("      differs for %s:\n--- libloc\n%s"
				        "--- fs-geodb\n%s", spec, want->str, got);
			sections++;
			g_free (got);
			g_clear_error (&e);
			fs_range_set_free (set);
			spec_clear (&sf);
			g_free (spec);
			spec = NULL;
			g_string_free (want, TRUE);
			want = NULL;
		}
		if (*l == NULL)
			break;
		if (header) {
			if (g_str_has_suffix (*l, " ref-error")) {
				skipped++;
				continue;
			}
			spec = g_strdup (*l + 7);
			want = g_string_new (NULL);
		} else if (**l != '\0' && want != NULL) {
			g_string_append (want, *l);
			g_string_append_c (want, '\n');
			prefixes++;
		}
	}
	g_strfreev (lines);
	CHECK (sections > 0 && bad == 0,
	       "%s.db: %u enumerations (%u prefixes) are exactly libloc's "
	       "flattened search, merged (and %u libloc cannot do)", name,
	       sections, prefixes, skipped);
out:
	g_free (text);
	g_free (path);
	g_free (file);
	fs_geodb_close (db);
}

/* Enumerate agrees with lookup, address by address, whatever libloc
 * says: an address is in the set for country C exactly when its lookup
 * says C (and the same for each AS and each flag). */
static void
enumerate_matches_lookup (const gchar *name)
{
	FsGeodb *db = open_fixture (name);
	GPtrArray *ex = load_lookups (name);
	GHashTable *ccs = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                         g_free, NULL);
	GHashTable *asns = g_hash_table_new (g_direct_hash, g_direct_equal);
	GPtrArray *sets = g_ptr_array_new ();
	GPtrArray *keys = g_ptr_array_new_with_free_func (g_free);
	guint bad = 0, tested = 0;
	GHashTableIter it;
	gpointer k;

	if (db == NULL)
		goto out;
	for (guint i = 0; i < ex->len; i++) {
		const Expect *e = g_ptr_array_index (ex, i);

		if (e->cc[0] != '\0')
			g_hash_table_add (ccs, g_strdup (e->cc));
		if (e->asn != 0)
			g_hash_table_add (asns, GUINT_TO_POINTER (e->asn));
	}
	g_hash_table_iter_init (&it, ccs);
	while (g_hash_table_iter_next (&it, &k, NULL))
		g_ptr_array_add (keys, g_strdup_printf ("cc=%s", (gchar *) k));
	g_hash_table_iter_init (&it, asns);
	while (g_hash_table_iter_next (&it, &k, NULL))
		g_ptr_array_add (keys, g_strdup_printf ("asn=%u",
		                                        GPOINTER_TO_UINT (k)));
	for (guint f = 1; f <= 8; f <<= 1)
		g_ptr_array_add (keys, g_strdup_printf ("flags=%u", f));
	for (guint i = 0; i < keys->len; i++) {
		SpecFilter sf;

		spec_parse (g_ptr_array_index (keys, i), &sf);
		g_ptr_array_add (sets, fs_geodb_enumerate (db, &sf.f, NULL));
		spec_clear (&sf);
	}
	for (guint i = 0; i < ex->len; i++) {
		const Expect *e = g_ptr_array_index (ex, i);
		FsGeodbMatch m;

		if (!fs_geodb_lookup (db, e->addr, &m, NULL))
			continue;
		for (guint j = 0; j < keys->len; j++) {
			const gchar *key = g_ptr_array_index (keys, j);
			const FsRangeSet *set = g_ptr_array_index (sets, j);
			gboolean want, in;

			if (g_str_has_prefix (key, "cc="))
				want = m.found && strcmp (m.country, key + 3) == 0;
			else if (g_str_has_prefix (key, "asn="))
				want = m.found &&
				       m.asn == (guint32) g_ascii_strtoull (key + 4,
				                                            NULL, 10);
			else
				want = m.found &&
				       (m.flags & (guint) g_ascii_strtoull (key + 6,
				                                            NULL, 10));
			in = set != NULL && fs_range_set_contains_text (set, e->addr);
			tested++;
			if (in != want && bad++ < 5)
				printf ("      %s: lookup %s, enumerate(%s) %s\n",
				        e->addr, m.found ? m.network : "none", key,
				        in ? "has it" : "does not");
		}
		fs_geodb_match_clear (&m);
	}
	CHECK (tested > 0 && bad == 0,
	       "%s.db: enumerate agrees with lookup for every address and "
	       "every country, AS and flag (%u pairs)", name, tested);
out:
	for (guint i = 0; i < sets->len; i++)
		fs_range_set_free (g_ptr_array_index (sets, i));
	g_ptr_array_unref (sets);
	g_ptr_array_unref (keys);
	g_hash_table_unref (ccs);
	g_hash_table_unref (asns);
	g_ptr_array_unref (ex);
	fs_geodb_close (db);
}

static void
enumerate_details (void)
{
	FsGeodb *db = open_fixture ("small"), *edge = open_fixture ("edge");
	FsGeodb *edge6 = open_fixture ("edge6");
	SpecFilter sf;
	FsRangeSet *a, *b;
	gchar *ta, *tb;
	GError *e = NULL;
	GPtrArray *p;

	if (db == NULL || edge == NULL || edge6 == NULL)
		goto out;

	spec_parse ("cc=IT", &sf);
	a = fs_geodb_enumerate (db, &sf.f, NULL);
	p = fs_geodb_set_prefixes (a);
	CHECK (p->len == 2 &&
	       strcmp (g_ptr_array_index (p, 0), "203.0.113.0/24") == 0 &&
	       strcmp (g_ptr_array_index (p, 1), "ffff:ffff:ffff:ffff::/64") == 0,
	       "small: IT is 203.0.113.0/24 (two adjacent /25s merged) and "
	       "ffff:ffff:ffff:ffff::/64, IPv4 first");
	g_ptr_array_unref (p);
	fs_range_set_free (a);
	spec_clear (&sf);

	spec_parse ("cc=DE", &sf);
	a = fs_geodb_enumerate (db, &sf.f, NULL);
	CHECK (a != NULL && fs_range_set_contains_text (a, "10.200.1.1") &&
	       fs_range_set_contains_text (a, "10.0.0.1") &&
	       !fs_range_set_contains_text (a, "10.1.0.1"),
	       "small: DE holds 10.0.0.0/8 and its nested DE /14, but not the "
	       "US /16 inside it");
	fs_range_set_free (a);
	spec_clear (&sf);

	spec_parse ("cc=DE,US asn=64505 flags=12", &sf);
	a = fs_geodb_enumerate (db, &sf.f, NULL);
	b = fs_geodb_enumerate (db, &sf.f, NULL);
	ta = prefixes_joined (a);
	tb = prefixes_joined (b);
	CHECK (strcmp (ta, tb) == 0 && strlen (ta) > 0,
	       "the same filter twice gives the same text");
	g_free (ta);
	g_free (tb);
	fs_range_set_free (a);
	fs_range_set_free (b);
	spec_clear (&sf);

	spec_parse ("cc=de", &sf);
	a = fs_geodb_enumerate (db, &sf.f, NULL);
	spec_clear (&sf);
	spec_parse ("cc=DE", &sf);
	b = fs_geodb_enumerate (db, &sf.f, NULL);
	ta = prefixes_joined (a);
	tb = prefixes_joined (b);
	CHECK (strcmp (ta, tb) == 0, "a country code in lower case is the "
	       "same filter");
	g_free (ta);
	g_free (tb);
	fs_range_set_free (a);
	fs_range_set_free (b);
	spec_clear (&sf);

	{
		const gchar *bad_cc[][2] = { { "D", NULL }, { "DEU", NULL },
		                             { "D1", NULL }, { "", NULL },
		                             { "D\xc3", NULL } };

		for (guint i = 0; i < G_N_ELEMENTS (bad_cc); i++) {
			FsGeodbFilter f = { 0 };

			f.countries = bad_cc[i];
			a = fs_geodb_enumerate (db, &f, &e);
			CHECK (a == NULL && e != NULL &&
			       e->code == FS_GEODB_ERR_INVALID,
			       "the country code \"%s\" is refused", bad_cc[i][0]);
			g_clear_error (&e);
			fs_range_set_free (a);
		}
	}
	{
		guint32 zero = 0;
		FsGeodbFilter f = { 0 };

		f.asns = &zero;
		f.n_asns = 1;
		a = fs_geodb_enumerate (db, &f, &e);
		CHECK (a == NULL && e != NULL && e->code == FS_GEODB_ERR_INVALID,
		       "AS 0 is refused (it would match every network without "
		       "an AS)");
		g_clear_error (&e);
		fs_range_set_free (a);
	}
	{
		FsGeodbFilter f = { 0 };

		a = fs_geodb_enumerate (db, &f, NULL);
		CHECK (a != NULL && fs_range_set_is_empty (a),
		       "an empty filter gives an empty set");
		fs_range_set_free (a);
	}

	/* edge: ::/8 owns ::ffff:0:0/96 in the tree, but IPv4 is IPv4's */
	spec_parse ("cc=US", &sf);
	a = fs_geodb_enumerate (edge, &sf.f, NULL);
	b = fs_range_set_new ();
	fs_range_set_add_text (b, "::-::fffe:ffff:ffff");
	fs_range_set_add_text (b, "::1:0:0:0-ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
	fs_range_set_normalize (b);
	ta = a ? fs_range_set_to_text (a) : g_strdup ("(null)");
	tb = fs_range_set_to_text (b);
	CHECK (strcmp (ta, tb) == 0,
	       "edge: US (::/8) is ::/8 without ::ffff:0:0/96, and no IPv4");
	p = a ? fs_geodb_set_prefixes (a) : g_ptr_array_new ();
	CHECK (p->len == 88 &&
	       strcmp (g_ptr_array_index (p, 0), "::/81") == 0 &&
	       strcmp (g_ptr_array_index (p, 87), "80::/9") == 0,
	       "edge: as prefixes, the 88 Python's ipaddress gives, ::/81 "
	       "first and 80::/9 last");
	g_ptr_array_unref (p);
	g_free (ta);
	g_free (tb);
	fs_range_set_free (a);
	fs_range_set_free (b);
	a = fs_geodb_enumerate (edge6, &sf.f, NULL);
	CHECK (a != NULL && fs_range_set_count4 (a) == 0 &&
	       fs_range_set_count6 (a) == 2,
	       "edge6: US (::/0) is all of IPv6 but ::ffff:0:0/96, and no IPv4");
	fs_range_set_free (a);
	spec_clear (&sf);

	/* set_prefixes on hand-made sets: whole spaces, odd edges */
	{
		static const struct { const gchar *in; const gchar *out; } c[] = {
			{ "0.0.0.0-255.255.255.255", "0.0.0.0/0\n" },
			{ "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::/0\n" },
			{ "255.255.255.255", "255.255.255.255/32\n" },
			{ "10.0.0.1-10.0.0.6",
			  "10.0.0.1/32\n10.0.0.2/31\n10.0.0.4/31\n10.0.0.6/32\n" },
			{ "2001:db8::1-2001:db8::2",
			  "2001:db8::1/128\n2001:db8::2/128\n" },
			{ "0.0.0.0-127.255.255.254", NULL },
		};

		for (guint i = 0; i < G_N_ELEMENTS (c); i++) {
			FsRangeSet *s = fs_range_set_new ();
			gchar *got;
			gboolean ok;

			fs_range_set_add_text (s, c[i].in);
			fs_range_set_normalize (s);
			got = prefixes_joined (s);
			if (c[i].out != NULL) {
				ok = strcmp (got, c[i].out) == 0;
			} else {
				/* a /2, then /3 ... /31 and a /32: 31 blocks */
				p = fs_geodb_set_prefixes (s);
				ok = p->len == 31 &&
				     strcmp (g_ptr_array_index (p, 0), "0.0.0.0/2") == 0 &&
				     strcmp (g_ptr_array_index (p, 30),
				             "127.255.255.254/32") == 0;
				g_ptr_array_unref (p);
			}
			CHECK (ok, "the fewest prefixes for %s", c[i].in);
			g_free (got);
			fs_range_set_free (s);
		}
	}
out:
	fs_geodb_close (db);
	fs_geodb_close (edge);
	fs_geodb_close (edge6);
}

/* ===================================================== metadata */

static void
test_metadata (void)
{
	FsGeodb *db = open_fixture ("small");
	gchar *path = fx ("small.meta.txt"), *text = NULL;
	gchar **lines;
	const FsGeodbInfo *info;
	GPtrArray *countries, *found;
	guint ci = 0, bad_c = 0, n_as = 0, bad_as = 0;
	FsGeodbCountry *c;
	gchar *s;

	if (db == NULL || !g_file_get_contents (path, &text, NULL, NULL)) {
		CHECK (FALSE, "small: metadata fixture");
		goto out;
	}
	info = fs_geodb_info (db);
	countries = fs_geodb_countries (db);
	lines = g_strsplit (text, "\n", -1);
	for (gchar **l = lines; *l != NULL; l++) {
		gchar **f = g_strsplit (*l, "\t", 4);
		guint n = g_strv_length (f);
		gchar *want = n >= 2 ? unesc (f[n - 1]) : NULL;

		if (n == 2 && strcmp (f[0], "created_at") == 0)
			CHECK (info->created_at == g_ascii_strtoll (f[1], NULL, 10),
			       "small: created at %s, as libloc reads it", f[1]);
		else if (n == 2 && strcmp (f[0], "vendor") == 0)
			CHECK (strcmp (info->vendor, want) == 0, "small: vendor \"%s\"",
			       want);
		else if (n == 2 && strcmp (f[0], "description") == 0)
			CHECK (strcmp (info->description, want) == 0,
			       "small: the description, newline kept");
		else if (n == 2 && strcmp (f[0], "license") == 0)
			CHECK (strcmp (info->license, want) == 0,
			       "small: licence \"%s\"", want);
		else if (n == 4 && strcmp (f[0], "country") == 0) {
			FsGeodbCountry *got = ci < countries->len
				? g_ptr_array_index (countries, ci) : NULL;

			ci++;
			if (got == NULL || strcmp (got->code, f[1]) != 0 ||
			    strcmp (got->continent, f[2]) != 0 ||
			    strcmp (got->name, want) != 0)
				bad_c++;
		} else if (n == 3 && strcmp (f[0], "as") == 0) {
			gchar *name = fs_geodb_as_name (db, (guint32)
			                                g_ascii_strtoull (f[1], NULL,
			                                                  10));

			n_as++;
			if (g_strcmp0 (name, want) != 0)
				bad_as++;
			g_free (name);
		}
		g_free (want);
		g_strfreev (f);
	}
	g_strfreev (lines);
	CHECK (ci == 7 && ci == countries->len && bad_c == 0,
	       "small: the %u countries (code, continent, name), in libloc's "
	       "order", countries->len);
	CHECK (n_as == 7 && bad_as == 0, "small: the %u AS names, as libloc "
	       "reads them (control and format characters as ?)", n_as);
	g_ptr_array_unref (countries);

	CHECK (info->networks > 0 && info->nodes > 0 && info->ases == 7 &&
	       info->countries == 7 && info->signed_slot == 1,
	       "small: %u networks, %u nodes, 7 ASes, 7 countries, signed in "
	       "slot 1", info->networks, info->nodes);

	c = fs_geodb_country (db, "jp");
	CHECK (c != NULL && strcmp (c->code, "JP") == 0 &&
	       strcmp (c->continent, "AS") == 0 &&
	       strcmp (c->name, "Japan") == 0,
	       "small: country \"jp\" is JP, Japan, AS (a country with no "
	       "networks is still listed)");
	fs_geodb_country_free (c);
	c = fs_geodb_country (db, "XX");
	CHECK (c == NULL, "small: no country XX");
	fs_geodb_country_free (c);
	c = fs_geodb_country (db, "D");
	CHECK (c == NULL, "small: \"D\" is no code");
	fs_geodb_country_free (c);
	s = fs_geodb_as_name (db, 64503);
	CHECK (s == NULL, "small: AS64503 has no name (it is not in the table)");
	g_free (s);

	found = fs_geodb_search_as (db, "example", 0);
	CHECK (found->len == 2 &&
	       ((FsGeodbAs *) g_ptr_array_index (found, 0))->asn == 64500 &&
	       ((FsGeodbAs *) g_ptr_array_index (found, 1))->asn == 64501,
	       "search \"example\": AS64500 and AS64501, ascending");
	g_ptr_array_unref (found);
	found = fs_geodb_search_as (db, "  AS64504 ", 0);
	CHECK (found->len == 1 &&
	       strcmp (((FsGeodbAs *) g_ptr_array_index (found, 0))->name,
	               "Sat?Net") == 0,
	       "search \"AS64504\": by number, name shown safely");
	g_ptr_array_unref (found);
	found = fs_geodb_search_as (db, "64506", 0);
	CHECK (found->len == 1, "search \"64506\": by number without AS");
	g_ptr_array_unref (found);
	found = fs_geodb_search_as (db, "e", 2);
	CHECK (found->len == 2, "search with a limit of 2 stops at 2");
	g_ptr_array_unref (found);
	found = fs_geodb_search_as (db, "", 0);
	CHECK (found->len == 0, "an empty search finds nothing");
	g_ptr_array_unref (found);
	found = fs_geodb_search_as (db, "\xc3\x9cn\xc3\xaf", 0);
	CHECK (found->len == 1, "a UTF-8 search finds the UTF-8 name");
	g_ptr_array_unref (found);
	found = fs_geodb_search_as (db, "AS99999999999", 0);
	CHECK (found->len == 0, "a number past 32 bits finds nothing");
	g_ptr_array_unref (found);
out:
	g_free (text);
	g_free (path);
	fs_geodb_close (db);
}

/* =================================================== lookup API */

static void
test_lookup_api (void)
{
	static const gchar *const bad[] = {
		"", "example.com", "10.1.2.3/24", " 10.1.2.3", "10.1.2.3 ",
		"fe80::1%eth0", "10.1.2", "::ffff:10.1.2.3/96", "10.1.2.256",
		"1.2.3.4.5", "2001:db8:::1", "0x0a010203", "10.1.2.3\n",
		"\xe2\x80\xae" "10.1.2.3",
	};
	FsGeodb *db = open_fixture ("small");
	FsGeodbMatch m, m2;
	GError *e = NULL;

	if (db == NULL)
		return;
	for (guint i = 0; i < G_N_ELEMENTS (bad); i++) {
		gchar *shown = g_strescape (bad[i], NULL);

		CHECK (!fs_geodb_lookup (db, bad[i], &m, &e) && e != NULL &&
		       e->code == FS_GEODB_ERR_INVALID && !m.found &&
		       g_utf8_validate (e->message, -1, NULL),
		       "\"%s\" is not an address (INVALID)", shown);
		g_clear_error (&e);
		g_free (shown);
	}
	CHECK (!fs_geodb_lookup (db, NULL, &m, &e) && e != NULL,
	       "a NULL address is refused");
	g_clear_error (&e);
	{
		static const gchar *const same[][2] = {
			{ "10.1.2.3", "::ffff:10.1.2.3" },
			{ "2001:db8:1:2::1", "2001:0db8:0001:0002:0000:0000:0000:0001" },
			{ "198.51.100.7", "::FFFF:198.51.100.7" },
		};

		for (guint i = 0; i < G_N_ELEMENTS (same); i++) {
			GInetAddress *ia = g_inet_address_new_from_string (same[i][1]);

			CHECK (fs_geodb_lookup (db, same[i][0], &m, NULL) &&
			       fs_geodb_lookup (db, same[i][1], &m2, NULL) &&
			       m.found && m2.found &&
			       strcmp (m.network, m2.network) == 0 &&
			       m.family == m2.family,
			       "%s and %s give the same answer", same[i][0],
			       same[i][1]);
			fs_geodb_match_clear (&m2);
			CHECK (ia != NULL && fs_geodb_lookup_inet (db, ia, &m2, NULL) &&
			       m2.found && strcmp (m.network, m2.network) == 0,
			       "as a GInetAddress too (%s)", same[i][1]);
			fs_geodb_match_clear (&m);
			fs_geodb_match_clear (&m2);
			g_clear_object (&ia);
		}
	}
	{
		GInetAddress *ia = g_inet_address_new_from_string ("10.1.2.3");

		CHECK (fs_geodb_lookup_inet (db, ia, &m, NULL) && m.found &&
		       m.family == FS_AF_V4 && m.prefix_len == 24 &&
		       strcmp (m.network, "10.1.2.0/24") == 0,
		       "a GInetAddress (IPv4) gives family 4, prefix 24");
		fs_geodb_match_clear (&m);
		g_object_unref (ia);
		CHECK (!fs_geodb_lookup_inet (db, NULL, &m, &e) && e != NULL,
		       "a NULL GInetAddress is refused");
		g_clear_error (&e);
	}
	fs_geodb_close (db);
}

/* ================================================== signatures */

static void
test_signature (EVP_PKEY *runtime)
{
	gsize len = 0, len2 = 0, lnew = 0;
	guint8 *small = slurp_fx ("small.db", &len);
	guint8 *two = slurp_fx ("small-two.db", &len2);
	guint8 *newer = slurp_fx ("small-newer.db", &lnew);
	gchar *runtime_pem = key_pub_pem (runtime);
	guint8 *d;
	FsGeodb *db;
	GError *e = NULL;
	const gchar *got;
	guint32 sig1_len;

	if (small == NULL || two == NULL || newer == NULL)
		goto out;
	sig1_len = (guint32) ((small[F_SIG1_LEN] << 8) | small[F_SIG1_LEN + 1]);

	use_key_file ("k1.pub");
	db = open_buf (small, len, &e);
	CHECK (db != NULL && fs_geodb_info (db)->signed_slot == 1,
	       "small.db (libloc's writer, key 1) verifies with key 1, slot 1 "
	       "(%s)", outcome_text (db, e));
	fs_geodb_close (db);
	g_clear_error (&e);

	use_key_file ("k2.pub");
	db = open_buf (small, len, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got),
	       "small.db with key 2: SIGNATURE (%s)", got);
	fs_geodb_close (db);
	g_clear_error (&e);
	fs_geodb_testing_set_key (runtime_pem);
	db = open_buf (small, len, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got),
	       "small.db with a key made now: SIGNATURE (%s)", got);
	fs_geodb_close (db);
	g_clear_error (&e);
	fs_geodb_testing_set_key (NULL);
	db = open_buf (small, len, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got),
	       "small.db with the pinned key (IPFire's): SIGNATURE (%s)", got);
	fs_geodb_close (db);
	g_clear_error (&e);

	/* either slot */
	use_key_file ("k1.pub");
	db = open_buf (two, len2, &e);
	CHECK (db != NULL && fs_geodb_info (db)->signed_slot == 1,
	       "small-two.db (keys 1 and 2) verifies with key 1 in slot 1");
	fs_geodb_close (db);
	g_clear_error (&e);
	use_key_file ("k2.pub");
	db = open_buf (two, len2, &e);
	CHECK (db != NULL && fs_geodb_info (db)->signed_slot == 2,
	       "small-two.db verifies with key 2 in slot 2 (%s)",
	       outcome_text (db, e));
	fs_geodb_close (db);
	g_clear_error (&e);

	/* slot 1 emptied: slot 2 alone still verifies, because the signed
	 * message reads both slots and lengths as zeros */
	d = g_memdup2 (two, len2);
	clear_slot (d, 1);
	db = open_buf (d, len2, &e);
	CHECK (db != NULL && fs_geodb_info (db)->signed_slot == 2,
	       "zeroing: slot 1 removed, slot 2 alone verifies (%s)",
	       outcome_text (db, e));
	fs_geodb_close (db);
	g_clear_error (&e);
	use_key_file ("k1.pub");
	db = open_buf (d, len2, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got),
	       "and key 1 no longer verifies it (%s)", got);
	fs_geodb_close (db);
	g_clear_error (&e);
	g_free (d);

	/* slot 1's signature moved to slot 2: the same message */
	d = g_memdup2 (small, len);
	memcpy (d + F_SIG2, small + F_SIG1, 2048);
	put16 (d + F_SIG2_LEN, (guint16) sig1_len);
	clear_slot (d, 1);
	db = open_buf (d, len, &e);
	CHECK (db != NULL && fs_geodb_info (db)->signed_slot == 2,
	       "zeroing: key 1's signature moved to slot 2 verifies there (%s)",
	       outcome_text (db, e));
	fs_geodb_close (db);
	g_clear_error (&e);
	g_free (d);

	/* the whole slot is zeroed, not only the signature's length */
	d = g_memdup2 (small, len);
	memset (d + F_SIG1 + sig1_len, 0xA5, 2048 - sig1_len);
	db = open_buf (d, len, &e);
	CHECK (db != NULL, "zeroing: bytes after the signature inside its "
	       "slot are not signed (%s)", outcome_text (db, e));
	fs_geodb_close (db);
	g_clear_error (&e);
	g_free (d);

	/* the unused slot and its length are not signed either */
	d = g_memdup2 (small, len);
	memset (d + F_SIG2, 0x5A, 2048);
	put16 (d + F_SIG2_LEN, 137);
	db = open_buf (d, len, &e);
	CHECK (db != NULL && fs_geodb_info (db)->signed_slot == 1,
	       "zeroing: garbage in slot 2 with a length of 137 does not stop "
	       "slot 1 (%s)", outcome_text (db, e));
	fs_geodb_close (db);
	g_clear_error (&e);
	put16 (d + F_SIG2_LEN, 4096);
	db = open_buf (d, len, &e);
	CHECK (db != NULL, "nor a slot-2 length past the slot (%s)",
	       outcome_text (db, e));
	fs_geodb_close (db);
	g_clear_error (&e);
	g_free (d);

	/* but the 32 reserved bytes are signed */
	for (guint at = F_RESERVED; at < F_HEADER_END; at += 31) {
		d = g_memdup2 (small, len);
		d[at] ^= 0x01;
		db = open_buf (d, len, &e);
		CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got),
		       "zeroing: a bit flipped in reserved byte %u: SIGNATURE",
		       at - F_RESERVED);
		fs_geodb_close (db);
		g_clear_error (&e);
		g_free (d);
	}

	/* flipped bytes, region by region */
	{
		struct { gsize at; const gchar *what; gint code; } flips[] = {
			{ 0, "magic", FS_GEODB_ERR_FORMAT },
			{ 6, "magic, last byte", FS_GEODB_ERR_FORMAT },
			{ 7, "version", FS_GEODB_ERR_FORMAT },
			{ F_CREATED + 7, "created_at", FS_GEODB_ERR_SIGNATURE },
			{ F_VENDOR + 3, "vendor offset", FS_GEODB_ERR_SIGNATURE },
			{ F_LICENSE + 3, "licence offset", FS_GEODB_ERR_SIGNATURE },
			{ F_SEC_OFF (SEC_AS) + 2, "AS offset", FS_GEODB_ERR_SIGNATURE },
			{ F_SEC_LEN (SEC_TREE) + 3, "tree length",
			  FS_GEODB_ERR_SIGNATURE },
			{ F_SEC_LEN (SEC_POOL) + 3, "pool length",
			  FS_GEODB_ERR_SIGNATURE },
			{ F_SIG1_LEN + 1, "signature 1 length", FS_GEODB_ERR_SIGNATURE },
			{ F_SIG1 + 10, "signature 1, inside the DER",
			  FS_GEODB_ERR_SIGNATURE },
			{ F_SIG1 + 2, "signature 1, its first integer's length",
			  FS_GEODB_ERR_SIGNATURE },
			{ F_HEADER_END, "the first byte after the header",
			  FS_GEODB_ERR_SIGNATURE },
			{ 8000, "the gap before the first section",
			  FS_GEODB_ERR_SIGNATURE },
		};
		for (guint i = 0; i < G_N_ELEMENTS (flips); i++) {
			d = g_memdup2 (small, len);
			d[flips[i].at] ^= 0x10;
			db = open_buf (d, len, &e);
			CHECK (refused_with (db, e, flips[i].code, &got),
			       "a byte flipped in the %s: %s (%s)", flips[i].what,
			       flips[i].code == FS_GEODB_ERR_FORMAT ? "FORMAT"
			                                            : "SIGNATURE", got);
			fs_geodb_close (db);
			g_clear_error (&e);
			g_free (d);
		}
		/* the first and last byte of every section */
		for (guint s = 0; s < 5; s++) {
			guint32 off = get32 (small + F_SEC_OFF (s));
			guint32 slen = get32 (small + F_SEC_LEN (s));

			for (guint w = 0; w < 2 && slen > 0; w++) {
				d = g_memdup2 (small, len);
				d[off + (w ? slen - 1 : 0)] ^= 0x01;
				db = open_buf (d, len, &e);
				CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got),
				       "a bit flipped in the %s byte of section %u: "
				       "SIGNATURE", w ? "last" : "first", s);
				fs_geodb_close (db);
				g_clear_error (&e);
				g_free (d);
			}
		}
	}
	d = g_malloc (len + 1);
	memcpy (d, small, len);
	d[len] = 0;
	db = open_buf (d, len + 1, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got),
	       "one byte appended: SIGNATURE (%s)", got);
	fs_geodb_close (db);
	g_clear_error (&e);
	db = open_buf (small, len - 1, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got),
	       "the last byte cut: SIGNATURE (%s)", got);
	fs_geodb_close (db);
	g_clear_error (&e);
	g_free (d);

	/* no signature at all */
	d = g_memdup2 (small, len);
	clear_slot (d, 1);
	clear_slot (d, 2);
	db = open_buf (d, len, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got) &&
	       strstr (e->message, "not signed") != NULL,
	       "both slots empty: SIGNATURE, \"not signed\" (%s)", got);
	fs_geodb_close (db);
	g_clear_error (&e);
	put16 (d + F_SIG1_LEN, 2049);
	put16 (d + F_SIG2_LEN, 65535);
	memcpy (d + F_SIG1, small + F_SIG1, sig1_len);
	db = open_buf (d, len, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got),
	       "both lengths past the slot: SIGNATURE (%s)", got);
	fs_geodb_close (db);
	g_clear_error (&e);
	g_free (d);

	/* a real signature of another file */
	d = g_memdup2 (newer, lnew);
	memcpy (d + F_SIG1_LEN, small + F_SIG1_LEN, 4);
	memcpy (d + F_SIG1, small + F_SIG1, 4096);
	db = open_buf (d, lnew, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got),
	       "small.db's signature on small-newer.db: SIGNATURE (%s)", got);
	fs_geodb_close (db);
	g_clear_error (&e);
	g_free (d);

	/* the test signer agrees with libloc's writer: re-signed with key 1
	 * the file is byte for byte valid in both places */
	{
		EVP_PKEY *other = key_new ("P-521");
		gchar *other_pem = other ? key_pub_pem (other) : NULL;

		d = g_memdup2 (small, len);
		resign (d, len, runtime);
		fs_geodb_testing_set_key (runtime_pem);
		db = open_buf (d, len, &e);
		CHECK (db != NULL, "small.db re-signed here with a key made now "
		       "verifies with that key (%s)", outcome_text (db, e));
		fs_geodb_close (db);
		g_clear_error (&e);
		fs_geodb_testing_set_key (other_pem);
		db = open_buf (d, len, &e);
		CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got),
		       "and not with another key made now (%s)", got);
		fs_geodb_close (db);
		g_clear_error (&e);
		g_free (d);
		g_free (other_pem);
		EVP_PKEY_free (other);
	}

	/* keys that are not P-521 */
	{
		EVP_PKEY *p256 = key_new ("P-256");
		gchar *p256_pem = p256 ? key_pub_pem (p256) : NULL;

		d = g_memdup2 (small, len);
		resign (d, len, p256);
		fs_geodb_testing_set_key (p256_pem);
		db = open_buf (d, len, &e);
		CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got) &&
		       strstr (e->message, "P-521") != NULL,
		       "a file signed with a P-256 key, checked with that key: "
		       "SIGNATURE, the key is not P-521 (%s)", got);
		fs_geodb_close (db);
		g_clear_error (&e);
		fs_geodb_testing_set_key ("-----BEGIN PUBLIC KEY-----\nAAAA\n"
		                          "-----END PUBLIC KEY-----\n");
		db = open_buf (small, len, &e);
		CHECK (refused_with (db, e, FS_GEODB_ERR_SIGNATURE, &got),
		       "a key that does not parse: SIGNATURE (%s)", got);
		fs_geodb_close (db);
		g_clear_error (&e);
		g_free (d);
		g_free (p256_pem);
		EVP_PKEY_free (p256);
	}
out:
	fs_geodb_testing_set_key (NULL);
	g_free (runtime_pem);
	g_free (small);
	g_free (two);
	g_free (newer);
}

/* What reaches fs_geodb_open from the file system. */
static void
test_open_files (void)
{
	gchar *path = g_build_filename (tmpdir, "big.db", NULL);
	gchar *src = fx ("small.db");
	GError *e = NULL;
	FsGeodb *db;
	const gchar *got;
	int fd;

	use_key_file ("k1.pub");
	db = fs_geodb_open ("/nonexistent/location.db", &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_IO, &got),
	       "a missing file: IO (%s)", got);
	g_clear_error (&e);
	db = fs_geodb_open (tmpdir, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_IO, &got),
	       "a directory: IO (%s)", got);
	g_clear_error (&e);
	fd = g_open (path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600);
	CHECK (fd >= 0 && write (fd, "LOCDBXX\x01", 8) == 8,
	       "a short file can be written");
	if (fd >= 0)
		close (fd);
	db = fs_geodb_open (path, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_FORMAT, &got),
	       "eight bytes of preamble only: FORMAT (%s)", got);
	g_clear_error (&e);
	db = fs_geodb_open ("", &e);
	CHECK (db == NULL && e != NULL, "an empty path is refused");
	g_clear_error (&e);
#ifndef G_OS_WIN32
	{
		gchar *link = g_build_filename (tmpdir, "link.db", NULL);
		gchar *abs = g_canonicalize_filename (src, NULL);

		g_unlink (link);
		CHECK (symlink (abs, link) == 0, "a symbolic link can be made");
		db = fs_geodb_open (link, &e);
		CHECK (refused_with (db, e, FS_GEODB_ERR_IO, &got) &&
		       strstr (e->message, "symbolic link") != NULL,
		       "a symbolic link to a good database: IO, not followed (%s)",
		       got);
		g_clear_error (&e);
		g_unlink (link);
		g_free (link);
		g_free (abs);
	}
	/* sparse files: the size cap, then one byte under it */
	fd = g_open (path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	CHECK (fd >= 0 && ftruncate (fd, (off_t) FS_GEODB_MAX_DB_BYTES + 1) == 0,
	       "a sparse file of 256 MiB + 1 byte");
	if (fd >= 0)
		close (fd);
	db = fs_geodb_open (path, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_TOO_LARGE, &got),
	       "256 MiB + 1 byte: TOO_LARGE, before anything is read (%s)", got);
	g_clear_error (&e);
	fd = g_open (path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	CHECK (fd >= 0 && ftruncate (fd, (off_t) FS_GEODB_MAX_DB_BYTES) == 0,
	       "a sparse file of exactly 256 MiB");
	if (fd >= 0)
		close (fd);
	db = fs_geodb_open (path, &e);
	CHECK (refused_with (db, e, FS_GEODB_ERR_FORMAT, &got),
	       "exactly 256 MiB is read (and is no database: FORMAT) (%s)", got);
	g_clear_error (&e);
#endif
	g_unlink (path);
	g_free (path);
	g_free (src);
}

/* ================================================ malformed files */

/* A database made from parts, laid out by the test (no page alignment,
 * sections in the order AS, tree, networks, countries, pool), unsigned
 * until resign().  For the shapes libloc's writer never makes. */
typedef struct
{
	GByteArray *sec[5];
	guint64     created;
	guint32     vendor, desc, lic;
} Synth;

static void
synth_init (Synth *s)
{
	memset (s, 0, sizeof *s);
	for (guint i = 0; i < 5; i++)
		s->sec[i] = g_byte_array_new ();
	s->created = 1700000000;
	g_byte_array_append (s->sec[SEC_POOL], (const guint8 *) "", 1);
}

static void
synth_clear (Synth *s)
{
	for (guint i = 0; i < 5; i++)
		g_byte_array_unref (s->sec[i]);
}

static guint32
synth_str (Synth *s, const gchar *str, gsize len)
{
	guint32 at = s->sec[SEC_POOL]->len;

	g_byte_array_append (s->sec[SEC_POOL], (const guint8 *) str, (guint) len);
	g_byte_array_append (s->sec[SEC_POOL], (const guint8 *) "", 1);
	return at;
}

static void
synth_u32s (GByteArray *a, guint32 x, guint32 y, guint32 z, guint n)
{
	guint8 b[12];

	put32 (b, x);
	put32 (b + 4, y);
	put32 (b + 8, z);
	g_byte_array_append (a, b, n);
}

static void
synth_node (Synth *s, guint32 zero, guint32 one, guint32 net)
{
	synth_u32s (s->sec[SEC_TREE], zero, one, net, 12);
}

static void
synth_net (Synth *s, const gchar *cc, guint32 asn, guint16 flags)
{
	guint8 b[12] = { 0 };

	if (cc != NULL && cc[0] != '\0') {
		b[0] = (guint8) cc[0];
		b[1] = (guint8) cc[1];
	}
	put32 (b + 4, asn);
	put16 (b + 8, flags);
	g_byte_array_append (s->sec[SEC_NETS], b, 12);
}

static void
synth_as (Synth *s, guint32 number, const gchar *name)
{
	guint32 at = synth_str (s, name, strlen (name));

	synth_u32s (s->sec[SEC_AS], number, at, 0, 8);
}

static void
synth_country (Synth *s, const gchar *code, const gchar *cont,
               const gchar *name)
{
	guint8 b[8];

	b[0] = (guint8) code[0];
	b[1] = (guint8) code[1];
	b[2] = (guint8) cont[0];
	b[3] = (guint8) cont[1];
	put32 (b + 4, synth_str (s, name, strlen (name)));
	g_byte_array_append (s->sec[SEC_COUNTRIES], b, 8);
}

static guint8 *
synth_build (Synth *s, gsize *len)
{
	static const guint order[5] = { SEC_AS, SEC_TREE, SEC_NETS,
	                                SEC_COUNTRIES, SEC_POOL };
	GByteArray *out = g_byte_array_new ();
	guint8 head[F_HEADER_END] = { 0 };
	guint32 at = F_HEADER_END;

	memcpy (head, "LOCDBXX\x01", 8);
	put64 (head + F_CREATED, s->created);
	put32 (head + F_VENDOR, s->vendor);
	put32 (head + F_DESC, s->desc);
	put32 (head + F_LICENSE, s->lic);
	for (guint i = 0; i < 5; i++) {
		guint k = order[i];

		put32 (head + F_SEC_OFF (k), s->sec[k]->len ? at : 0);
		put32 (head + F_SEC_LEN (k), s->sec[k]->len);
		at += s->sec[k]->len;
	}
	g_byte_array_append (out, head, sizeof head);
	for (guint i = 0; i < 5; i++)
		g_byte_array_append (out, s->sec[order[i]]->data,
		                     s->sec[order[i]]->len);
	*len = out->len;
	return g_byte_array_free (out, FALSE);
}

/* A chain of `depth' zero-branch nodes from the root, the last one
 * naming network 0: the address :: is in ::/<depth>. */
static guint8 *
synth_chain (guint depth, gsize *len)
{
	Synth s;
	guint8 *d;

	synth_init (&s);
	for (guint i = 0; i < depth; i++)
		synth_node (&s, i + 1, 0, 0xffffffffu);
	synth_node (&s, 0, 0, 0);
	synth_net (&s, "DE", 64500, 0);
	d = synth_build (&s, len);
	synth_clear (&s);
	return d;
}

/* Re-sign with the run-time key, open through the file, expect FORMAT;
 * also through the unverified path (the same checks). */
static void
expect_malformed (guint8 *d, gsize len, EVP_PKEY *key, const gchar *what)
{
	GError *e = NULL, *e2 = NULL;
	FsGeodb *db, *db2;
	const gchar *got;
	gboolean ok;

	resign (d, len, key);
	db = open_buf (d, len, &e);
	ok = refused_with (db, e, FS_GEODB_ERR_FORMAT, &got);
	db2 = fs_geodb_testing_open_unverified (d, len, &e2);
	CHECK (ok && db2 == NULL && e2 != NULL && e2->code == FS_GEODB_ERR_FORMAT,
	       "%s: FORMAT (%s)", what, got);
	fs_geodb_close (db);
	fs_geodb_close (db2);
	g_clear_error (&e);
	g_clear_error (&e2);
}

static void
expect_valid (guint8 *d, gsize len, EVP_PKEY *key, const gchar *what)
{
	GError *e = NULL;
	FsGeodb *db;

	resign (d, len, key);
	db = open_buf (d, len, &e);
	CHECK (db != NULL, "%s: opens (%s)", what, outcome_text (db, e));
	fs_geodb_close (db);
	g_clear_error (&e);
}

static void
test_malformed (EVP_PKEY *key)
{
	gsize len = 0;
	guint8 *small = slurp_fx ("small.db", &len);
	gchar *pem = key_pub_pem (key);
	guint32 off[5], slen[5], n_nodes, n_nets;
	guint8 *d;
	gchar *what;
	guint truncs = 0, trunc_ok = 0;

	if (small == NULL)
		goto out;
	fs_geodb_testing_set_key (pem);
	for (guint i = 0; i < 5; i++) {
		off[i] = get32 (small + F_SEC_OFF (i));
		slen[i] = get32 (small + F_SEC_LEN (i));
	}
	n_nodes = slen[SEC_TREE] / 12;
	n_nets = slen[SEC_NETS] / 12;

	d = g_memdup2 (small, len);
	expect_valid (d, len, key, "small.db re-signed unchanged (the control)");
	g_free (d);

	/* truncated everywhere: every 61st byte past the header, the last
	 * 64 bytes one by one, and every section edge */
	for (gsize cut = F_HEADER_END; cut < len; cut++) {
		gboolean edge = len - cut <= 64;
		GError *e = NULL;
		FsGeodb *db;

		for (guint i = 0; i < 5; i++)
			if (cut + 1 >= off[i] && cut <= off[i] + 1)
				edge = TRUE;
		if (!edge && (cut - F_HEADER_END) % 61 != 0)
			continue;
		d = g_memdup2 (small, cut);
		resign (d, cut, key);
		db = open_buf (d, cut, &e);
		truncs++;
		if (db == NULL && e != NULL && e->code == FS_GEODB_ERR_FORMAT)
			trunc_ok++;
		else if (truncs - trunc_ok <= 3)
			printf ("      cut at %" G_GSIZE_FORMAT ": %s\n", cut,
			        outcome_text (db, e));
		fs_geodb_close (db);
		g_clear_error (&e);
		g_free (d);
	}
	CHECK (truncs > 100 && trunc_ok == truncs,
	       "truncated and re-signed at %u places past the header: FORMAT "
	       "every time", truncs);
	for (gsize cut = 0; cut < F_HEADER_END; cut += 397) {
		GError *e = NULL;
		FsGeodb *db = open_buf (small, cut, &e);
		const gchar *got;

		CHECK (refused_with (db, e, FS_GEODB_ERR_FORMAT, &got),
		       "cut inside the header at %" G_GSIZE_FORMAT ": FORMAT (%s)",
		       cut, got);
		fs_geodb_close (db);
		g_clear_error (&e);
	}

	/* every offset and length pointing outside */
	for (guint s = 0; s < 5; s++) {
		static const gchar *names[5] = { "AS", "network", "tree",
		                                 "country", "pool" };
		struct { guint32 o, l; const gchar *how; } bad[] = {
			{ (guint32) len, slen[s], "starts at the end of the file" },
			{ (guint32) len - slen[s] + 1, slen[s], "ends one byte past it" },
			{ off[s], 0xffffffffu, "length 0xffffffff" },
			{ 0xfffffff0u, 0x20, "offset + length wraps 32 bits" },
			{ 0xffffffffu, slen[s], "offset 0xffffffff" },
			{ 0, slen[s], "starts at 0 (the magic)" },
			{ 8, slen[s], "starts in the header" },
			{ F_HEADER_END - 1, slen[s], "starts on the header's last byte" },
		};

		for (guint b = 0; b < G_N_ELEMENTS (bad); b++) {
			d = g_memdup2 (small, len);
			put32 (d + F_SEC_OFF (s), bad[b].o);
			put32 (d + F_SEC_LEN (s), bad[b].l);
			what = g_strdup_printf ("the %s section %s", names[s],
			                        bad[b].how);
			expect_malformed (d, len, key, what);
			g_free (what);
			g_free (d);
		}
		if (s != SEC_POOL) {
			d = g_memdup2 (small, len);
			put32 (d + F_SEC_LEN (s), slen[s] + 1);
			what = g_strdup_printf ("the %s section one byte longer "
			                        "(not whole records)", names[s]);
			expect_malformed (d, len, key, what);
			g_free (what);
			g_free (d);
		}
	}

	/* overlapping sections */
	{
		struct { guint a, b; gint shift; const gchar *what; } ov[] = {
			{ SEC_AS, SEC_TREE, 0, "the AS table on the tree" },
			{ SEC_COUNTRIES, SEC_POOL, 0, "the countries on the pool" },
			{ SEC_TREE, SEC_NETS, -4, "the tree ending inside the networks" },
			{ SEC_POOL, SEC_COUNTRIES, 4, "the pool starting inside the "
			                              "countries" },
		};

		for (guint i = 0; i < G_N_ELEMENTS (ov); i++) {
			d = g_memdup2 (small, len);
			put32 (d + F_SEC_OFF (ov[i].a),
			       off[ov[i].b] + (guint32) ov[i].shift);
			if (ov[i].a == SEC_TREE)
				put32 (d + F_SEC_OFF (ov[i].a),
				       off[ov[i].b] - slen[ov[i].a] + 12);
			expect_malformed (d, len, key, ov[i].what);
			g_free (d);
		}
	}

	/* the tree */
	{
		const guint8 *tree = small + off[SEC_TREE];
		guint32 parent = 0, child = 0;

		/* a node with a zero child, and that child */
		for (guint32 i = 1; i < n_nodes && child == 0; i++)
			if (get32 (tree + 12 * i) != 0) {
				parent = i;
				child = get32 (tree + 12 * i);
			}
		CHECK (child != 0, "small.db has a node below the root with a "
		       "child (%u -> %u)", parent, child);

		d = g_memdup2 (small, len);
		put32 (d + off[SEC_TREE] + 12 * parent, parent);
		expect_malformed (d, len, key, "a node whose child is itself");
		g_free (d);
		d = g_memdup2 (small, len);
		put32 (d + off[SEC_TREE] + 12 * child, parent);
		put32 (d + off[SEC_TREE] + 12 * child + 4, 0);
		expect_malformed (d, len, key, "a node whose child is its parent "
		                  "(a loop)");
		g_free (d);
		d = g_memdup2 (small, len);
		put32 (d + off[SEC_TREE] + 12 * parent + 4, child);
		expect_malformed (d, len, key, "a node whose two children are the "
		                  "same node (a shared branch)");
		g_free (d);
		d = g_memdup2 (small, len);
		put32 (d + off[SEC_TREE] + 12 * child + 4, 1);
		expect_malformed (d, len, key, "a deep node pointing back at node 1");
		g_free (d);
		d = g_memdup2 (small, len);
		put32 (d + off[SEC_TREE] + 12 * parent, n_nodes);
		expect_malformed (d, len, key, "a child index one past the tree");
		g_free (d);
		d = g_memdup2 (small, len);
		put32 (d + off[SEC_TREE] + 12 * parent, 0xfffffffeu);
		expect_malformed (d, len, key, "a child index 0xfffffffe");
		g_free (d);
		d = g_memdup2 (small, len);
		put32 (d + off[SEC_TREE] + 12 * parent + 8, n_nets);
		expect_malformed (d, len, key, "a network index one past the table");
		g_free (d);
		d = g_memdup2 (small, len);
		put32 (d + off[SEC_TREE] + 12 * parent + 8, 0xfffffffeu);
		expect_malformed (d, len, key, "a network index 0xfffffffe");
		g_free (d);
	}

	/* strings */
	{
		struct { gsize at; guint32 v; const gchar *what; } st[] = {
			{ F_VENDOR, slen[SEC_POOL], "the vendor at the pool's end" },
			{ F_DESC, 0xffffffffu, "the description at 0xffffffff" },
			{ F_LICENSE, slen[SEC_POOL] + 100, "the licence past the pool" },
			{ (gsize) off[SEC_AS] + 4, slen[SEC_POOL], "an AS name past the "
			                                           "pool" },
			{ (gsize) off[SEC_COUNTRIES] + 4, 0x7fffffffu, "a country name "
			                                               "far out" },
		};

		for (guint i = 0; i < G_N_ELEMENTS (st); i++) {
			d = g_memdup2 (small, len);
			put32 (d + st[i].at, st[i].v);
			expect_malformed (d, len, key, st[i].what);
			g_free (d);
		}
		/* the pool's last string loses its NUL: whoever names it now
		 * runs off the end of the pool */
		d = g_memdup2 (small, len);
		d[off[SEC_POOL] + slen[SEC_POOL] - 1] = 'x';
		expect_malformed (d, len, key, "the pool's last string without "
		                  "its NUL (it runs to the end of the file)");
		g_free (d);
	}

	/* tables */
	{
		guint8 tmp[8];

		d = g_memdup2 (small, len);
		memcpy (tmp, d + off[SEC_AS], 8);
		memcpy (d + off[SEC_AS], d + off[SEC_AS] + 8, 8);
		memcpy (d + off[SEC_AS] + 8, tmp, 8);
		expect_malformed (d, len, key, "two ASes swapped (not ascending)");
		g_free (d);
		d = g_memdup2 (small, len);
		memcpy (d + off[SEC_AS] + 8, d + off[SEC_AS], 4);
		expect_malformed (d, len, key, "an AS number twice");
		g_free (d);
		d = g_memdup2 (small, len);
		memcpy (tmp, d + off[SEC_COUNTRIES], 8);
		memcpy (d + off[SEC_COUNTRIES], d + off[SEC_COUNTRIES] + 8, 8);
		memcpy (d + off[SEC_COUNTRIES] + 8, tmp, 8);
		expect_malformed (d, len, key, "two countries swapped");
		g_free (d);
		d = g_memdup2 (small, len);
		d[off[SEC_COUNTRIES]] = 'd';
		expect_malformed (d, len, key, "a country code in lower case");
		g_free (d);
		d = g_memdup2 (small, len);
		d[off[SEC_COUNTRIES] + 2] = '1';
		expect_malformed (d, len, key, "a continent code with a digit");
		g_free (d);
		d = g_memdup2 (small, len);
		d[off[SEC_NETS]] = 'D';
		d[off[SEC_NETS] + 1] = 0;
		expect_malformed (d, len, key, "a network country of one letter");
		g_free (d);
		d = g_memdup2 (small, len);
		d[off[SEC_NETS]] = 0xc3;
		d[off[SEC_NETS] + 1] = 0x9c;
		expect_malformed (d, len, key, "a network country in UTF-8");
		g_free (d);
		d = g_memdup2 (small, len);
		put64 (d + F_CREATED, 0);
		expect_malformed (d, len, key, "created_at 0");
		g_free (d);
		d = g_memdup2 (small, len);
		put64 (d + F_CREATED, G_GUINT64_CONSTANT (0x8000000000000000));
		expect_malformed (d, len, key, "created_at 2^63");
		g_free (d);
	}

	/* shapes libloc's writer never makes */
	{
		gsize sl;
		Synth s;

		d = synth_chain (128, &sl);
		resign (d, sl, key);
		{
			GError *e = NULL;
			FsGeodb *db = open_buf (d, sl, &e);
			FsGeodbMatch m;

			CHECK (db != NULL && fs_geodb_lookup (db, "::", &m, NULL) &&
			       m.found && strcmp (m.network, "::/128") == 0,
			       "a chain 128 nodes deep is a tree: :: is in ::/128 (%s)",
			       outcome_text (db, e));
			if (db != NULL)
				fs_geodb_match_clear (&m);
			fs_geodb_close (db);
			g_clear_error (&e);
		}
		g_free (d);
		d = synth_chain (129, &sl);
		expect_malformed (d, sl, key, "a chain 129 nodes deep");
		g_free (d);
		d = synth_chain (4000, &sl);
		expect_malformed (d, sl, key, "a chain 4,000 nodes deep");
		g_free (d);

		/* a string of the longest length, and one byte more */
		for (guint extra = 0; extra < 2; extra++) {
			gchar *big = g_malloc (FS_GEODB_MAX_STRING + 1);

			memset (big, 'a', FS_GEODB_MAX_STRING + 1);
			synth_init (&s);
			synth_node (&s, 0, 0, 0xffffffffu);
			s.vendor = synth_str (&s, big, FS_GEODB_MAX_STRING + extra);
			d = synth_build (&s, &sl);
			if (extra)
				expect_malformed (d, sl, key, "a vendor of 4,097 bytes");
			else
				expect_valid (d, sl, key, "a vendor of 4,096 bytes");
			g_free (d);
			g_free (big);
			synth_clear (&s);
		}

		/* the largest AS number, a tree with no networks at all */
		synth_init (&s);
		synth_node (&s, 0, 1, 0xffffffffu);   /* root: 1 -> node 1 */
		synth_node (&s, 0, 0, 0);             /* 8000::/1 */
		synth_net (&s, "", 0xffffffffu, 0xfff0 | FS_GEODB_FLAG_DROP);
		synth_as (&s, 0xffffffffu, "Last");
		d = synth_build (&s, &sl);
		resign (d, sl, key);
		{
			GError *e = NULL;
			FsGeodb *db = open_buf (d, sl, &e);
			FsGeodbMatch m;
			FsGeodbFilter f = { 0 };
			guint32 last = 0xffffffffu;
			FsRangeSet *set;

			CHECK (db != NULL && fs_geodb_lookup (db, "8000::1", &m, NULL) &&
			       m.found && m.asn == 0xffffffffu &&
			       g_strcmp0 (m.as_name, "Last") == 0 &&
			       m.flags == FS_GEODB_FLAG_DROP,
			       "AS 4294967295 and unknown flag bits: the AS is named, "
			       "the unknown bits are dropped (%s)", outcome_text (db, e));
			if (db != NULL) {
				fs_geodb_match_clear (&m);
				f.asns = &last;
				f.n_asns = 1;
				set = fs_geodb_enumerate (db, &f, NULL);
				CHECK (set != NULL && fs_range_set_count6 (set) == 1 &&
				       fs_range_set_contains_text (set, "ffff::1") &&
				       !fs_range_set_contains_text (set, "7fff::1"),
				       "and enumerating that AS gives 8000::/1");
				fs_range_set_free (set);
			}
			fs_geodb_close (db);
			g_clear_error (&e);
		}
		g_free (d);
		synth_clear (&s);

		/* no tree: nothing is found, nothing enumerated */
		synth_init (&s);
		synth_net (&s, "DE", 1, 0);
		d = synth_build (&s, &sl);
		resign (d, sl, key);
		{
			GError *e = NULL;
			FsGeodb *db = open_buf (d, sl, &e);
			FsGeodbMatch m;
			const gchar *de[] = { "DE", NULL };
			FsGeodbFilter f = { 0 };
			FsRangeSet *set;

			f.countries = de;
			CHECK (db != NULL && fs_geodb_lookup (db, "1.2.3.4", &m, NULL) &&
			       !m.found,
			       "a database with networks but no tree finds nothing "
			       "(%s)", outcome_text (db, e));
			set = db ? fs_geodb_enumerate (db, &f, NULL) : NULL;
			CHECK (set != NULL && fs_range_set_is_empty (set),
			       "and enumerates nothing");
			fs_range_set_free (set);
			fs_geodb_close (db);
			g_clear_error (&e);
		}
		g_free (d);
		synth_clear (&s);

		/* countries: a missing continent is fine, a repeated code is
		 * not (the table must be strictly ascending) */
		synth_init (&s);
		synth_country (&s, "AA", "\0\0", "No continent");
		synth_country (&s, "AB", "EU", "Ab");
		d = synth_build (&s, &sl);
		{
			GError *e = NULL;
			FsGeodb *db;
			FsGeodbCountry *c;

			resign (d, sl, key);
			db = open_buf (d, sl, &e);
			c = db ? fs_geodb_country (db, "aa") : NULL;
			CHECK (c != NULL && c->continent[0] == '\0' &&
			       strcmp (c->name, "No continent") == 0,
			       "a country without a continent opens and reads "
			       "back with none (%s)", outcome_text (db, e));
			fs_geodb_country_free (c);
			fs_geodb_close (db);
			g_clear_error (&e);
		}
		g_free (d);
		synth_clear (&s);
		synth_init (&s);
		synth_country (&s, "AA", "EU", "One");
		synth_country (&s, "AA", "EU", "Two");
		d = synth_build (&s, &sl);
		expect_malformed (d, sl, key, "a country code twice");
		g_free (d);
		synth_clear (&s);
	}
out:
	fs_geodb_testing_set_key (NULL);
	g_free (pem);
	g_free (small);
}

/* ============================================= the mutation loop */

/* A deterministic fuzzer that runs in every suite run (the libFuzzer
 * harness, tests/fuzz-geodb.c, runs for longer in tests/test-geodb.sh).
 * Each case is a fixture with a few mutations: bit flips, bytes, 32-bit
 * fields set to edge values (header fields and records alike), tree
 * records copied over each other or pointed anywhere (loops, shared
 * subtrees, out of range), truncation and growth.  Every case must be
 * refused with FORMAT or open; whatever opens is used (lookups,
 * enumeration, the tables) and must give sane answers.  Every 16th case
 * is re-signed and opened through the file as well: the signed path must
 * agree with the unsigned one. */

static const guint32 interesting32[] = {
	0, 1, 2, 3, 4, 7, 8, 11, 12, 13, 127, 128, 129, 255, 256, 4095, 4096,
	4199, 4200, 4201, 8192, 0x7fff, 0x8000, 0xffff, 0x10000, 0x7fffffffu,
	0x80000000u, 0xfffffff0u, 0xfffffff4u, 0xfffffff8u, 0xfffffffeu,
	0xffffffffu
};

static guint8 *
mutate (GRand *r, const guint8 *base, gsize len, gsize *out_len)
{
	gsize n = len;
	guint8 *d = g_malloc (len + 4096);
	guint rounds = (guint) g_rand_int_range (r, 1, 6);

	memcpy (d, base, len);
	for (guint i = 0; i < rounds; i++) {
		guint kind = (guint) g_rand_int_range (r, 0, 9);
		guint32 tree_off = n >= F_HEADER_END ? get32 (d + F_SEC_OFF (SEC_TREE)) : 0;
		guint32 tree_len = n >= F_HEADER_END ? get32 (d + F_SEC_LEN (SEC_TREE)) : 0;
		gboolean tree_ok = tree_len >= 24 && (guint64) tree_off + tree_len <= n;
		guint32 nodes = tree_ok ? tree_len / 12 : 0;

		if (n == 0)
			break;
		switch (kind) {
		case 0:                         /* one bit */
			d[g_rand_int_range (r, 0, (gint32) n)] ^=
				(guint8) (1u << g_rand_int_range (r, 0, 8));
			break;
		case 1:                         /* one byte */
			d[g_rand_int_range (r, 0, (gint32) n)] =
				(guint8) g_rand_int_range (r, 0, 256);
			break;
		case 2:                         /* a header field */
			if (n >= 68) {
				guint field = (guint) g_rand_int_range (r, 2, 17);

				put32 (d + 4 * field, interesting32[g_rand_int_range (
					r, 0, G_N_ELEMENTS (interesting32))]);
			}
			break;
		case 3:                         /* a field anywhere */
			if (n >= F_HEADER_END + 4) {
				gsize at = (gsize) g_rand_int_range (r, F_HEADER_END,
				                                     (gint32) n - 3);

				put32 (d + (at & ~(gsize) 3),
				       g_rand_boolean (r)
				       ? interesting32[g_rand_int_range (
				               r, 0, G_N_ELEMENTS (interesting32))]
				       : (guint32) g_rand_int_range (r, 0, 64));
			}
			break;
		case 4:                         /* one tree record over another */
			if (tree_ok) {
				guint32 a = (guint32) g_rand_int_range (r, 0, (gint32) nodes);
				guint32 b = (guint32) g_rand_int_range (r, 0, (gint32) nodes);

				memmove (d + tree_off + 12 * a, d + tree_off + 12 * b, 12);
			}
			break;
		case 5:                         /* a child pointed anywhere */
			if (tree_ok) {
				guint32 a = (guint32) g_rand_int_range (r, 0, (gint32) nodes);
				guint which = (guint) g_rand_int_range (r, 0, 3);

				put32 (d + tree_off + 12 * a + 4 * which,
				       (guint32) g_rand_int_range (r, 0, (gint32) nodes + 2));
			}
			break;
		case 6:                         /* truncate */
			n = (gsize) g_rand_int_range (r, 0, (gint32) n);
			break;
		case 7:                         /* grow */
			if (n + 64 <= len + 4096) {
				for (guint k = 0; k < 64; k++)
					d[n + k] = (guint8) g_rand_int_range (r, 0, 256);
				n += (gsize) g_rand_int_range (r, 1, 65);
			}
			break;
		default:                        /* a string byte (pool) */
			if (n >= F_HEADER_END) {
				guint32 po = get32 (d + F_SEC_OFF (SEC_POOL));
				guint32 pl = get32 (d + F_SEC_LEN (SEC_POOL));

				if (pl > 0 && (guint64) po + pl <= n)
					d[po + (guint32) g_rand_int_range (r, 0, (gint32) pl)] =
						g_rand_boolean (r) ? 0 : (guint8) g_rand_int_range (r, 1, 256);
			}
			break;
		}
	}
	*out_len = n;
	return d;
}

static gboolean
cc_sane (const gchar *cc)
{
	return cc[0] == '\0' ||
	       (g_ascii_isupper (cc[0]) && g_ascii_isupper (cc[1]) && cc[2] == '\0');
}

/* Use an open database; count the answers that are not sane. */
static guint
exercise (FsGeodb *db, GRand *r)
{
	guint bad = 0;
	GPtrArray *cs, *as;
	const FsGeodbInfo *info = fs_geodb_info (db);
	FsGeodbFilter f = { 0 };
	const gchar *codes[2] = { NULL, NULL };
	guint32 asn = 0;
	FsRangeSet *set;

	if (info == NULL || !g_utf8_validate (info->vendor, -1, NULL) ||
	    !g_utf8_validate (info->description, -1, NULL) ||
	    !g_utf8_validate (info->license, -1, NULL))
		bad++;
	for (guint i = 0; i < 24; i++) {
		guint8 bytes[16];
		GInetAddress *a;
		FsGeodbMatch m;
		gboolean v4 = i % 2 == 0;

		for (guint k = 0; k < 16; k++)
			bytes[k] = (guint8) g_rand_int_range (r, 0, 256);
		if (i % 6 == 1)                 /* near the fixtures' networks */
			bytes[0] = (guint8) g_rand_int_range (r, 0, 16);
		if (i % 6 == 3)
			memcpy (bytes, "\x20\x01\x0d\xb8", 4);
		a = g_inet_address_new_from_bytes (bytes, v4 ? G_SOCKET_FAMILY_IPV4
		                                              : G_SOCKET_FAMILY_IPV6);
		if (!fs_geodb_lookup_inet (db, a, &m, NULL)) {
			bad++;
		} else if (m.found) {
			if (m.network == NULL || !cc_sane (m.country) ||
			    m.prefix_len > (m.family == FS_AF_V4 ? 32u : 128u) ||
			    (m.as_name != NULL && !g_utf8_validate (m.as_name, -1, NULL)))
				bad++;
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

		if (!cc_sane (c->code) || c->code[0] == '\0' ||
		    !g_utf8_validate (c->name, -1, NULL))
			bad++;
		if (codes[0] == NULL)
			codes[0] = g_intern_string (c->code);
	}
	g_ptr_array_unref (cs);
	as = fs_geodb_search_as (db, "e", 50);
	for (guint i = 0; i < as->len; i++) {
		FsGeodbAs *x = g_ptr_array_index (as, i);

		if (x->name == NULL || !g_utf8_validate (x->name, -1, NULL))
			bad++;
	}
	g_ptr_array_unref (as);

	f.countries = codes[0] != NULL ? codes : NULL;
	f.asns = &asn;
	f.n_asns = asn != 0 ? 1 : 0;
	f.flags = FS_GEODB_FLAGS_KNOWN;
	set = fs_geodb_enumerate (db, &f, NULL);
	if (set == NULL) {
		bad++;
	} else {
		GPtrArray *p = fs_geodb_set_prefixes (set);

		g_ptr_array_unref (p);
		fs_range_set_free (set);
	}
	return bad;
}

static void
mutation_loop (EVP_PKEY *key, guint32 seed, guint n, gboolean quiet)
{
	static const gchar *bases[] = { "small", "random", "edge", "edge6", "empty" };
	GBytes *base[G_N_ELEMENTS (bases)];
	GRand *r = g_rand_new_with_seed (seed);
	guint opened = 0, refused = 0, odd = 0, insane = 0, resigned = 0,
	      disagree = 0;
	gchar *pem = key_pub_pem (key);

	for (guint i = 0; i < G_N_ELEMENTS (bases); i++) {
		gchar *file = g_strdup_printf ("%s.db", bases[i]);
		gsize len = 0;
		guint8 *d = slurp_fx (file, &len);

		base[i] = g_bytes_new_take (d, len);
		g_free (file);
	}
	fs_geodb_testing_set_key (pem);
	for (guint i = 0; i < n; i++) {
		gsize blen, mlen;
		const guint8 *b = g_bytes_get_data (base[i % G_N_ELEMENTS (bases)],
		                                    &blen);
		guint8 *m;
		GError *e = NULL;
		FsGeodb *db;
		gboolean ok;

		if (blen == 0)
			continue;
		m = mutate (r, b, blen, &mlen);
		if (i % 16 == 15 && mlen >= F_HEADER_END)
			resign (m, mlen, key);
		db = fs_geodb_testing_open_unverified (m, mlen, &e);
		ok = db != NULL;
		if (db != NULL) {
			opened++;
			insane += exercise (db, r);
			fs_geodb_close (db);
		} else if (e != NULL && e->domain == FS_GEODB_ERROR &&
		           e->code == FS_GEODB_ERR_FORMAT) {
			refused++;
		} else {
			if (odd++ < 3)
				printf ("      case %u: %s\n", i, outcome_text (db, e));
		}
		g_clear_error (&e);
		if (i % 16 == 15 && mlen >= F_HEADER_END) {
			resigned++;
			db = open_buf (m, mlen, &e);
			if ((db != NULL) != ok ||
			    (db == NULL && (e == NULL || e->code != FS_GEODB_ERR_FORMAT))) {
				if (disagree++ < 3)
					printf ("      case %u: unsigned path %s, signed "
					        "path %s\n", i, ok ? "opened" : "refused",
					        outcome_text (db, e));
			}
			fs_geodb_close (db);
			g_clear_error (&e);
		}
		g_free (m);
	}
	CHECK (odd == 0 && insane == 0 && disagree == 0 && opened > 0 &&
	       refused > 0,
	       "mutation loop (seed %u, %u cases): %u refused with FORMAT, "
	       "%u opened and gave sane answers, %u re-signed and opened "
	       "through the file agree (%u other outcomes, %u odd answers, "
	       "%u disagreements)", seed, n, refused, opened, resigned, odd,
	       insane, disagree);
	(void) quiet;
	for (guint i = 0; i < G_N_ELEMENTS (bases); i++)
		g_bytes_unref (base[i]);
	g_rand_free (r);
	g_free (pem);
}

/* ======================================================== xz unpack */

static GBytes *bomb_over;      /* FS_GEODB_MAX_DB_BYTES + 1 zero bytes, xz */

static GBytes *
bomb (void)
{
	if (bomb_over == NULL)
		bomb_over = xz_zeros ((guint64) FS_GEODB_MAX_DB_BYTES + 1);
	return bomb_over;
}

/* Unpack into a fresh file; returns the error code (0 when it worked),
 * the bytes written and the file's size afterwards. */
static gint
unpack_to_file (GBytes *xz, guint64 cap, guint64 *written, guint64 *size,
                gchar **contents, gsize *contents_len)
{
	gchar *path = g_build_filename (tmpdir, "unpack.out", NULL);
	int fd;
	GError *e = NULL;
	gint code = 0;
	GStatBuf st;

	g_unlink (path);
	fd = g_open (path, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
	if (!fs_geodb_unpack_xz (xz, fd, cap, written, &e))
		code = e != NULL && e->domain == FS_GEODB_ERROR ? e->code : -1;
	g_clear_error (&e);
	close (fd);
	*size = g_stat (path, &st) == 0 ? (guint64) st.st_size : G_MAXUINT64;
	if (contents != NULL)
		g_file_get_contents (path, contents, contents_len, NULL);
	g_unlink (path);
	g_free (path);
	return code;
}

static gint
unpack_null (GBytes *xz, guint64 cap, guint64 *written)
{
	int fd = null_fd ();
	GError *e = NULL;
	gint code = 0;

	if (!fs_geodb_unpack_xz (xz, fd, cap, written, &e))
		code = e != NULL && e->domain == FS_GEODB_ERROR ? e->code : -1;
	g_clear_error (&e);
	close (fd);
	return code;
}

static GBytes *
bytes_edit (GBytes *b, gssize cut, const gchar *append, gsize append_len,
            gssize flip_at)
{
	gsize len;
	const guint8 *d = g_bytes_get_data (b, &len);
	GByteArray *a = g_byte_array_new ();

	g_byte_array_append (a, d, (guint) (cut >= 0 ? (gsize) cut : len));
	if (append != NULL)
		g_byte_array_append (a, (const guint8 *) append, (guint) append_len);
	if (flip_at >= 0 && (gsize) flip_at < a->len)
		a->data[flip_at] ^= 0x55;
	return g_byte_array_free_to_bytes (a);
}

static void
test_xz (void)
{
	gsize len = 0, got_len = 0;
	guint8 *small = slurp_fx ("small.db", &len);
	GBytes *xz, *xz9, *x, *two;
	guint64 written = 0, size = 0;
	gchar *got = NULL;
	gint code;
	const guint64 mib = 1024 * 1024;

	if (small == NULL)
		return;
	xz = xz_encode (small, len, 6);
	code = unpack_to_file (xz, 0, &written, &size, &got, &got_len);
	CHECK (code == 0 && written == len && got_len == len &&
	       memcmp (got, small, len) == 0,
	       "xz: small.db round trips byte for byte (%" G_GUINT64_FORMAT
	       " bytes, code %d)", written, code);
	g_free (got);

	/* the decoder's memory limit: -9e (64 MiB dictionary) fits, a stream
	 * that asks for a 128 MiB dictionary does not */
	xz9 = xz_encode (small, len, 9 | LZMA_PRESET_EXTREME);
	CHECK (unpack_null (xz9, 0, NULL) == 0,
	       "xz: a stream made with xz -9e (64 MiB dictionary) unpacks");
	x = xz_with_dict (xz, 28);
	CHECK (x != NULL && unpack_null (x, 0, NULL) == 0,
	       "xz: a 64 MiB dictionary, set in the block header, unpacks");
	g_clear_pointer (&x, g_bytes_unref);
	x = xz_with_dict (xz, 30);
	code = x ? unpack_null (x, 0, NULL) : -1;
	CHECK (code == FS_GEODB_ERR_XZ,
	       "xz: a 128 MiB dictionary is over the decoder's memory limit "
	       "(%u MiB): XZ (code %d)", FS_GEODB_XZ_MEMLIMIT / (1024 * 1024),
	       code);
	g_clear_pointer (&x, g_bytes_unref);
	x = xz_with_dict (xz, 40);
	code = x ? unpack_null (x, 0, NULL) : -1;
	CHECK (code == FS_GEODB_ERR_XZ,
	       "xz: a dictionary size code past the format's range: XZ "
	       "(code %d)", code);
	g_clear_pointer (&x, g_bytes_unref);

	/* bombs: the cap is checked before each write */
	written = 0;
	code = unpack_null (bomb (), 0, &written);
	CHECK (code == FS_GEODB_ERR_TOO_LARGE &&
	       written <= FS_GEODB_MAX_DB_BYTES,
	       "xz: %" G_GSIZE_FORMAT " bytes that unpack to 256 MiB + 1: "
	       "TOO_LARGE, %" G_GUINT64_FORMAT " bytes written, never more than "
	       "the cap (code %d)", g_bytes_get_size (bomb ()), written, code);
	x = xz_zeros (FS_GEODB_MAX_DB_BYTES);
	written = 0;
	code = unpack_null (x, 0, &written);
	CHECK (code == 0 && written == FS_GEODB_MAX_DB_BYTES,
	       "xz: exactly 256 MiB unpacks (the cap is inclusive; code %d)",
	       code);
	g_bytes_unref (x);
	x = xz_zeros (mib + 1);
	code = unpack_to_file (x, mib, &written, &size, NULL, NULL);
	CHECK (code == FS_GEODB_ERR_TOO_LARGE && size <= mib && written == size,
	       "xz: a 1 MiB cap and 1 MiB + 1 of data: TOO_LARGE, the file "
	       "holds %" G_GUINT64_FORMAT " bytes (code %d)", size, code);
	g_bytes_unref (x);
	x = xz_zeros (mib);
	code = unpack_to_file (x, mib, &written, &size, NULL, NULL);
	CHECK (code == 0 && size == mib,
	       "xz: a 1 MiB cap and exactly 1 MiB of data unpacks (code %d)",
	       code);
	g_bytes_unref (x);

	/* broken streams */
	x = bytes_edit (xz, -1, NULL, 0, (gssize) g_bytes_get_size (xz) / 2);
	code = unpack_null (x, 0, NULL);
	CHECK (code == FS_GEODB_ERR_XZ, "xz: a corrupt byte: XZ (code %d)", code);
	g_bytes_unref (x);
	x = bytes_edit (xz, (gssize) g_bytes_get_size (xz) - 1, NULL, 0, -1);
	code = unpack_null (x, 0, NULL);
	CHECK (code == FS_GEODB_ERR_XZ,
	       "xz: one byte short: XZ (code %d)", code);
	g_bytes_unref (x);
	x = bytes_edit (xz, (gssize) g_bytes_get_size (xz) / 2, NULL, 0, -1);
	code = unpack_null (x, 0, NULL);
	CHECK (code == FS_GEODB_ERR_XZ, "xz: half a stream: XZ (code %d)", code);
	g_bytes_unref (x);
	x = bytes_edit (xz, -1, "junk", 4, -1);
	code = unpack_null (x, 0, NULL);
	CHECK (code == FS_GEODB_ERR_XZ,
	       "xz: data after the stream: XZ (code %d)", code);
	g_bytes_unref (x);
	x = bytes_edit (xz, -1, "\0\0\0\0", 4, -1);
	code = unpack_null (x, 0, NULL);
	CHECK (code == FS_GEODB_ERR_XZ,
	       "xz: stream padding after the stream: XZ (code %d)", code);
	g_bytes_unref (x);
	{
		gsize xl;
		const gchar *xd = g_bytes_get_data (xz, &xl);

		two = bytes_edit (xz, -1, xd, xl, -1);
		code = unpack_null (two, 0, NULL);
		CHECK (code == FS_GEODB_ERR_XZ,
		       "xz: two streams back to back: XZ, one stream only "
		       "(code %d)", code);
		g_bytes_unref (two);
	}
	x = g_bytes_new_static ("", 0);
	code = unpack_null (x, 0, NULL);
	CHECK (code == FS_GEODB_ERR_XZ, "xz: nothing: XZ (code %d)", code);
	g_bytes_unref (x);
	x = g_bytes_new_static (small, len);
	code = unpack_null (x, 0, NULL);
	CHECK (code == FS_GEODB_ERR_XZ,
	       "xz: an unpacked database is not xz: XZ (code %d)", code);
	g_bytes_unref (x);
	{
		GError *e = NULL;
		int fd = null_fd ();

		CHECK (!fs_geodb_unpack_xz (NULL, fd, 0, NULL, &e) && e != NULL &&
		       e->code == FS_GEODB_ERR_INVALID,
		       "xz: no data: INVALID");
		g_clear_error (&e);
		CHECK (!fs_geodb_unpack_xz (xz, -1, 0, NULL, &e) && e != NULL &&
		       e->code == FS_GEODB_ERR_INVALID,
		       "xz: no file: INVALID");
		g_clear_error (&e);
		close (fd);
	}
	g_bytes_unref (xz9);
	g_bytes_unref (xz);
	g_free (small);
}

/* ============================================ freshness, rollback */

static void
test_judge (void)
{
	const gint64 T0 = 1700000000, now = T0 + 100,
	             skew = FS_GEODB_FUTURE_SKEW_S;
	static const gchar *names[] = { "NEWER", "SAME", "OLDER", "FROM_FUTURE" };
	struct { gint64 offered, current; FsGeodbVerdict want; const gchar *what; }
	cases[] = {
		{ T0,            0,      FS_GEODB_NEWER, "a first copy" },
		{ T0,            T0 - 1, FS_GEODB_NEWER, "one second newer" },
		{ T0,            T0,     FS_GEODB_SAME,  "the same second" },
		{ T0 - 1,        T0,     FS_GEODB_OLDER, "one second older" },
		{ 1,             T0,     FS_GEODB_OLDER, "from 1970" },
		{ 0,             0,      FS_GEODB_OLDER, "no creation time" },
		{ -5,            0,      FS_GEODB_OLDER, "a negative time" },
		{ now + skew,    T0,     FS_GEODB_NEWER, "exactly a day ahead" },
		{ now + skew + 1, T0,    FS_GEODB_FROM_FUTURE,
		  "a day and a second ahead (newer, but the future check is first)" },
		{ now + skew + 1, 0,     FS_GEODB_FROM_FUTURE,
		  "a day and a second ahead, first copy" },
		{ G_MAXINT64,    T0,     FS_GEODB_FROM_FUTURE, "the end of time" },
	};

	for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
		gchar *reason = NULL;
		FsGeodbVerdict v = fs_geodb_judge (cases[i].offered, cases[i].current,
		                                   now, &reason);

		CHECK (v == cases[i].want &&
		       (v == FS_GEODB_NEWER) == (reason == NULL),
		       "judge: %s: %s%s%s", cases[i].what, names[v],
		       reason ? ": " : "", reason ? reason : "");
		g_free (reason);
	}
	CHECK (fs_geodb_judge (T0, 0, now, NULL) == FS_GEODB_NEWER,
	       "judge: works without a reason");
	CHECK (!fs_geodb_is_stale (T0, T0 + FS_GEODB_STALE_S) &&
	       fs_geodb_is_stale (T0, T0 + FS_GEODB_STALE_S + 1) &&
	       fs_geodb_is_stale (0, now) && !fs_geodb_is_stale (now + 10, now),
	       "stale: after 30 days, not on the day; no time is stale; a copy "
	       "from the near future is not");
}

/* ===================================================== install, update */

#ifdef __linux__

static gboolean
store_has_only (const gchar *store, const gchar *only)
{
	GDir *dir = g_dir_open (store, 0, NULL);
	const gchar *n;
	gboolean ok = dir != NULL;

	while (dir != NULL && (n = g_dir_read_name (dir)) != NULL)
		if (only == NULL || strcmp (n, only) != 0) {
			printf ("      left in the store: %s\n", n);
			ok = FALSE;
		}
	if (dir != NULL)
		g_dir_close (dir);
	return ok;
}

static gboolean
store_is (const gchar *store, const guint8 *want, gsize want_len)
{
	gchar *p = g_build_filename (store, FS_GEODB_FILE, NULL);
	gsize len = 0;
	guint8 *d = slurp (p, &len);
	gboolean same = d != NULL && len == want_len &&
	                memcmp (d, want, len) == 0;

	g_free (d);
	g_free (p);
	return same;
}

static GBytes *
xz_of_fixture (const gchar *name, guint8 **raw, gsize *raw_len)
{
	gsize len = 0;
	guint8 *d = slurp_fx (name, &len);
	GBytes *b = d ? xz_encode (d, len, 6) : NULL;

	if (raw != NULL) {
		*raw = d;
		*raw_len = len;
	} else {
		g_free (d);
	}
	return b;
}

typedef struct
{
	GBytes *body;
	gchar  *url;
	gchar  *proxy;
	guint   calls;
} FakeFetch;

static GBytes *
fake_fetcher (const gchar *url, const gchar *proxy, gpointer user_data,
              GError **error)
{
	FakeFetch *f = user_data;

	f->calls++;
	g_free (f->url);
	g_free (f->proxy);
	f->url = g_strdup (url);
	f->proxy = g_strdup (proxy);
	if (f->body == NULL) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_HOST_UNREACHABLE,
		             "the test's network is down");
		return NULL;
	}
	return g_bytes_ref (f->body);
}

static void
install_case (const gchar *store, GBytes *xz, gint64 now,
              FsGeodbOutcome want, gint want_code, gint64 want_created,
              const guint8 *want_file, gsize want_len, const gchar *what)
{
	static const gchar *names[] = { "UPDATED", "UNCHANGED", "REFUSED",
	                                "FAILED" };
	GError *e = NULL;
	gint64 created = -1;
	FsGeodbOutcome o = fs_geodb_install_xz (store, xz, now, &created, &e);
	gboolean code_ok = want_code == 0
		? e == NULL
		: e != NULL && e->domain == FS_GEODB_ERROR && e->code == want_code;

	CHECK (o == want && code_ok && created == want_created &&
	       (want_file == NULL || store_is (store, want_file, want_len)) &&
	       store_has_only (store, want_file != NULL ? FS_GEODB_FILE : NULL),
	       "install: %s: %s%s%s; created_at %" G_GINT64_FORMAT
	       "; the copy in use is %s, nothing else is left in the store",
	       what, names[o], e ? ", " : "", e ? e->message : "", created,
	       want_file != NULL ? "as expected" : "absent");
	g_clear_error (&e);
}

static void
test_install (void)
{
	const gint64 T0 = 1700000000, now = T0 + 100;
	gchar *store = g_build_filename (tmpdir, "store", NULL);
	gchar *dbpath = g_build_filename (store, FS_GEODB_FILE, NULL);
	guint8 *small, *older, *newer;
	gsize small_len, older_len, newer_len;
	GBytes *x_small, *x_older, *x_newer, *x;
	FsGeodb *db;
	GError *e = NULL;

	use_key_file ("k1.pub");
	g_mkdir (store, 0700);
	x_small = xz_of_fixture ("small.db", &small, &small_len);
	x_older = xz_of_fixture ("small-older.db", &older, &older_len);
	x_newer = xz_of_fixture ("small-newer.db", &newer, &newer_len);
	if (x_small == NULL || x_older == NULL || x_newer == NULL)
		goto out;

	install_case (store, x_small, now, FS_GEODB_UPDATED, 0, T0,
	              small, small_len, "a first copy");
	db = fs_geodb_open_store (store, &e);
	CHECK (db != NULL && fs_geodb_info (db)->created_at == T0,
	       "install: the store opens (%s)", outcome_text (db, e));
	fs_geodb_close (db);
	g_clear_error (&e);
	{
		GStatBuf st;

		CHECK (g_stat (dbpath, &st) == 0 && (st.st_mode & 0777) == 0600,
		       "install: the copy in use is mode 0600 (%o)",
		       (guint) (st.st_mode & 0777));
	}
	install_case (store, x_small, now, FS_GEODB_UNCHANGED, 0, T0,
	              small, small_len, "the same copy again");
	install_case (store, x_older, now, FS_GEODB_REFUSED,
	              FS_GEODB_ERR_ROLLBACK, T0, small, small_len,
	              "a copy one second older (rollback)");
	install_case (store, x_newer, T0 - 1, FS_GEODB_REFUSED,
	              FS_GEODB_ERR_FUTURE, T0, small, small_len,
	              "a newer copy more than a day ahead of the clock");
	install_case (store, x_newer, now, FS_GEODB_UPDATED, 0, T0 + 86400,
	              newer, newer_len, "a newer copy");
	install_case (store, x_small, now, FS_GEODB_REFUSED,
	              FS_GEODB_ERR_ROLLBACK, T0 + 86400, newer, newer_len,
	              "the first copy again, now older than the one in use");

	/* a newer creation time, but the signature no longer matches */
	{
		guint8 *d = g_memdup2 (newer, newer_len);

		put64 (d + F_CREATED, (guint64) (T0 + 86400 + 1));
		x = xz_encode (d, newer_len, 6);
		install_case (store, x, now + 86400, FS_GEODB_REFUSED,
		              FS_GEODB_ERR_SIGNATURE, T0 + 86400, newer, newer_len,
		              "a newer creation time written into a signed copy");
		g_bytes_unref (x);
		g_free (d);
	}
	x = xz_encode ((const guint8 *) "not a database", 14, 6);
	install_case (store, x, now, FS_GEODB_REFUSED, FS_GEODB_ERR_FORMAT,
	              T0 + 86400, newer, newer_len, "an xz file of something else");
	g_bytes_unref (x);
	x = bytes_edit (x_small, -1, NULL, 0, (gssize) g_bytes_get_size (x_small) / 2);
	install_case (store, x, now, FS_GEODB_REFUSED, FS_GEODB_ERR_XZ,
	              T0 + 86400, newer, newer_len, "a corrupt download");
	g_bytes_unref (x);
	install_case (store, bomb (), now, FS_GEODB_REFUSED,
	              FS_GEODB_ERR_TOO_LARGE, T0 + 86400, newer, newer_len,
	              "an xz bomb (256 MiB + 1 unpacked)");
	{
		guint8 *big = g_malloc0 (FS_GEODB_MAX_XZ_BYTES + 1);

		x = g_bytes_new_take (big, FS_GEODB_MAX_XZ_BYTES + 1);
		install_case (store, x, now, FS_GEODB_REFUSED,
		              FS_GEODB_ERR_TOO_LARGE, T0 + 86400, newer, newer_len,
		              "a download over 64 MB");
		g_bytes_unref (x);
	}
	install_case (store, NULL, now, FS_GEODB_FAILED,
	              FS_GEODB_ERR_INVALID, T0 + 86400, newer, newer_len,
	              "nothing to install");

	/* the store itself */
	{
		gint64 c = -1;
		FsGeodbOutcome o;
		gchar *link = g_build_filename (tmpdir, "store-link", NULL);

		o = fs_geodb_install_xz ("relative/store", x_small, now, &c, &e);
		CHECK (o == FS_GEODB_FAILED && e != NULL &&
		       e->code == FS_GEODB_ERR_INVALID,
		       "install: a relative store path: FAILED, INVALID");
		g_clear_error (&e);
		CHECK (symlink (store, link) == 0, "a symbolic link to the store");
		o = fs_geodb_install_xz (link, x_newer, now, &c, &e);
		CHECK (o == FS_GEODB_FAILED && e != NULL &&
		       e->code == FS_GEODB_ERR_IO,
		       "install: a store that is a symbolic link: FAILED (%s)",
		       e ? e->message : "no error");
		g_clear_error (&e);
		db = fs_geodb_open_store (link, &e);
		CHECK (db == NULL, "open_store: a store that is a symbolic link "
		       "is not opened");
		fs_geodb_close (db);
		g_clear_error (&e);
		g_unlink (link);
		g_free (link);
	}

	/* a copy in use that is a symbolic link is not followed: it does
	 * not count, and the new copy replaces the link, not its target */
	{
		gchar *target = g_build_filename (tmpdir, "elsewhere.db", NULL);
		gsize tl = 0;
		guint8 *td;

		spit (target, newer, newer_len);
		g_unlink (dbpath);
		CHECK (symlink (target, dbpath) == 0,
		       "a symbolic link as the copy in use");
		db = fs_geodb_open_store (store, &e);
		CHECK (db == NULL && e != NULL,
		       "open_store: a copy in use that is a symbolic link is not "
		       "opened (%s)", e ? e->message : "opened");
		fs_geodb_close (db);
		g_clear_error (&e);
		install_case (store, x_small, now, FS_GEODB_UPDATED, 0, T0,
		              small, small_len,
		              "over a symbolic link (counts as no copy)");
		td = slurp (target, &tl);
		CHECK (td != NULL && tl == newer_len &&
		       memcmp (td, newer, tl) == 0 &&
		       !g_file_test (dbpath, G_FILE_TEST_IS_SYMLINK),
		       "install: the link was replaced; its target is untouched");
		g_free (td);
		g_unlink (target);
		g_free (target);
	}

	/* a damaged copy in use does not count (the new copy is still
	 * verified and checked) */
	{
		guint8 *d = g_memdup2 (small, small_len);

		d[small_len - 1] ^= 1;
		spit (dbpath, d, small_len);
		install_case (store, x_older, now, FS_GEODB_UPDATED, 0, T0 - 1,
		              older, older_len,
		              "a damaged copy in use is replaced, even by an older "
		              "good one");
		g_free (d);
	}

	/* a store we cannot write */
	if (geteuid () != 0) {
		g_chmod (store, 0500);
		install_case (store, x_newer, now, FS_GEODB_FAILED,
		              FS_GEODB_ERR_IO, T0 - 1, older, older_len,
		              "a store that cannot be written: FAILED");
		g_chmod (store, 0700);
	} else {
		printf ("SKIP: running as root, a read-only store is writable\n");
	}

	/* fs_geodb_update: the downloader is asked for FS_GEODB_URL through
	 * the proxy; a failed download changes nothing */
	{
		FakeFetch f = { 0 };
		gint64 c = -1;
		FsGeodbOutcome o;

		f.body = NULL;
		fs_geodb_set_fetcher (fake_fetcher, &f);
		o = fs_geodb_update (store, "http://proxy.test:3128", now, &c, &e);
		CHECK (o == FS_GEODB_FAILED && e != NULL && c == T0 - 1 &&
		       store_is (store, older, older_len) &&
		       store_has_only (store, FS_GEODB_FILE),
		       "update: the download fails: FAILED (%s), the copy in use "
		       "is kept and reported", e ? e->message : "no error");
		g_clear_error (&e);
		f.body = x_newer;
		o = fs_geodb_update (store, "http://proxy.test:3128", now, &c, &e);
		CHECK (o == FS_GEODB_UPDATED && c == T0 + 86400 &&
		       store_is (store, newer, newer_len) && f.calls == 2 &&
		       g_strcmp0 (f.url, FS_GEODB_URL) == 0 &&
		       g_strcmp0 (f.proxy, "http://proxy.test:3128") == 0,
		       "update: one download of %s through the given proxy, "
		       "installed (%s)", f.url ? f.url : "?",
		       e ? e->message : "no error");
		g_clear_error (&e);
		f.body = x_older;
		o = fs_geodb_update (store, NULL, now, &c, &e);
		CHECK (o == FS_GEODB_REFUSED && e != NULL &&
		       e->code == FS_GEODB_ERR_ROLLBACK && c == T0 + 86400 &&
		       f.proxy == NULL && store_is (store, newer, newer_len),
		       "update: an older download is refused (%s)",
		       e ? e->message : "no error");
		g_clear_error (&e);
		fs_geodb_set_fetcher (NULL, NULL);
		g_free (f.url);
		g_free (f.proxy);
	}
out:
	g_unlink (dbpath);
	g_rmdir (store);
	g_clear_pointer (&x_small, g_bytes_unref);
	g_clear_pointer (&x_older, g_bytes_unref);
	g_clear_pointer (&x_newer, g_bytes_unref);
	g_free (small);
	g_free (older);
	g_free (newer);
	g_free (dbpath);
	g_free (store);
}

#else

static void
test_install (void)
{
	GError *e = NULL;
	gint64 c = -1;
	GBytes *x = g_bytes_new_static ("", 0);

	CHECK (fs_geodb_install_xz ("C:\\store", x, 0, &c, &e) == FS_GEODB_FAILED &&
	       e != NULL && e->code == FS_GEODB_ERR_UNSUPPORTED && c == 0,
	       "install: not on this platform yet: FAILED, UNSUPPORTED");
	g_clear_error (&e);
	g_bytes_unref (x);
}

#endif

/* ============================================================ drivers */

/* PUB is a PEM public key file, or "pinned" for IPFire's. */
static gboolean
driver_key (const gchar *pub)
{
	gchar *pem = NULL;

	if (strcmp (pub, "pinned") == 0) {
		fs_geodb_testing_set_key (NULL);
		return TRUE;
	}
	if (!g_file_get_contents (pub, &pem, NULL, NULL)) {
		fprintf (stderr, "cannot read %s\n", pub);
		return FALSE;
	}
	fs_geodb_testing_set_key (pem);
	g_free (pem);
	return TRUE;
}

static FsGeodb *
driver_open (const gchar *path, const gchar *pub)
{
	GError *e = NULL;
	FsGeodb *db;

	if (!driver_key (pub))
		return NULL;
	db = fs_geodb_open (path, &e);
	if (db == NULL)
		fprintf (stderr, "%s: %s (code %d)\n", path,
		         e ? e->message : "?", e ? e->code : 0);
	g_clear_error (&e);
	return db;
}

static gchar *
esc (const gchar *s)
{
	GString *o = g_string_new (NULL);

	for (; s != NULL && *s != '\0'; s++) {
		if (*s == '\\')
			g_string_append (o, "\\\\");
		else if (*s == '\n')
			g_string_append (o, "\\n");
		else if (*s == '\t')
			g_string_append (o, "\\t");
		else
			g_string_append_c (o, *s);
	}
	return g_string_free (o, FALSE);
}

/* lookup-tsv DB PUB FILE: the .lookup.tsv format, for each address. */
static int
drive_lookup_tsv (const gchar *path, const gchar *pub, const gchar *file)
{
	FsGeodb *db = driver_open (path, pub);
	gchar *text = NULL;
	gchar **lines;

	if (db == NULL || !g_file_get_contents (file, &text, NULL, NULL))
		return 2;
	lines = g_strsplit (text, "\n", -1);
	for (gchar **l = lines; *l != NULL; l++) {
		FsGeodbMatch m;
		gchar *a = g_strstrip (g_strdup (*l)), *name;

		if (*a == '\0') {
			g_free (a);
			continue;
		}
		if (!fs_geodb_lookup (db, a, &m, NULL)) {
			printf ("%s\tinvalid\t\t\t0\t0\t\n", a);
		} else if (!m.found) {
			printf ("%s\tnone\t\t\t0\t0\t\n", a);
		} else {
			name = esc (m.as_name ? m.as_name : "");
			printf ("%s\tfound\t%s\t%s\t%u\t%u\t%s\n", a, m.network,
			        m.country, m.asn, m.flags, name);
			g_free (name);
		}
		fs_geodb_match_clear (&m);
		g_free (a);
	}
	g_strfreev (lines);
	g_free (text);
	fs_geodb_close (db);
	return 0;
}

/* enum DB PUB SPEC: the prefixes for one filter ("cc=DE asn=- flags=0"). */
static int
drive_enum (const gchar *path, const gchar *pub, const gchar *spec)
{
	FsGeodb *db = driver_open (path, pub);
	SpecFilter sf;
	FsRangeSet *set;
	GError *e = NULL;
	gchar *out;

	if (db == NULL)
		return 2;
	spec_parse (spec, &sf);
	set = fs_geodb_enumerate (db, &sf.f, &e);
	if (set == NULL) {
		fprintf (stderr, "%s\n", e ? e->message : "?");
		return 2;
	}
	out = prefixes_joined (set);
	fputs (out, stdout);
	g_free (out);
	fs_range_set_free (set);
	spec_clear (&sf);
	fs_geodb_close (db);
	return 0;
}

/* resign IN OUT KEY [SLOT]: both slots cleared, then signed in SLOT
 * (default 1) with the private key in KEY (PEM). */
static int
drive_resign (const gchar *in, const gchar *out, const gchar *keyfile,
              guint slot)
{
	gsize len = 0;
	guint8 *d = slurp (in, &len);
	BIO *bio = BIO_new_file (keyfile, "r");
	EVP_PKEY *k = bio ? PEM_read_bio_PrivateKey (bio, NULL, NULL, NULL) : NULL;
	int rc = 2;

	if (bio != NULL)
		BIO_free (bio);
	if (d != NULL && k != NULL && len >= F_HEADER_END) {
		clear_slot (d, 1);
		clear_slot (d, 2);
		if (sign_slot (d, len, k, slot == 2 ? 2 : 1) && spit (out, d, len))
			rc = 0;
	}
	if (rc != 0)
		fprintf (stderr, "resign failed\n");
	EVP_PKEY_free (k);
	g_free (d);
	return rc;
}

/* info DB [PUB]: open (pinned key unless PUB) and print the metadata. */
static int
drive_info (const gchar *path, const gchar *pub)
{
	FsGeodb *db = driver_open (path, pub != NULL ? pub : "pinned");
	const FsGeodbInfo *i;
	gchar *d;

	if (db == NULL)
		return 1;
	i = fs_geodb_info (db);
	d = esc (i->description);
	printf ("created_at\t%" G_GINT64_FORMAT "\nvendor\t%s\ndescription\t%s\n"
	        "license\t%s\nsigned_slot\t%u\nsize\t%" G_GUINT64_FORMAT "\n"
	        "networks\t%u\nnodes\t%u\nases\t%u\ncountries\t%u\n",
	        i->created_at, i->vendor, d, i->license, i->signed_slot, i->size,
	        i->networks, i->nodes, i->ases, i->countries);
	g_free (d);
	fs_geodb_close (db);
	return 0;
}

/* update STORE PUB [PROXY]: fs_geodb_update with the default downloader
 * (fs_fetch; tests/test-geodb.sh stands curl in with STOCKFW_TEST_CURL). */
static int
drive_update (const gchar *store, const gchar *pub, const gchar *proxy)
{
	static const gchar *names[] = { "UPDATED", "UNCHANGED", "REFUSED",
	                                "FAILED" };
	GError *e = NULL;
	gint64 c = 0;
	FsGeodbOutcome o;

	if (!driver_key (pub))
		return 2;
	o = fs_geodb_update (store, proxy, g_get_real_time () / G_USEC_PER_SEC,
	                     &c, &e);
	printf ("%s\t%" G_GINT64_FORMAT "\t%d\t%s\n", names[o], c,
	        e ? e->code : 0, e ? e->message : "");
	g_clear_error (&e);
	return o == FS_GEODB_UPDATED || o == FS_GEODB_UNCHANGED ? 0 : 1;
}

/* golden DIR NAME PUB: the golden lookups and enumerations of DIR/NAME.*
 * (tests/test-geodb.sh runs this on freshly made fixtures and on the
 * real database). */
static int
drive_golden (const gchar *dir, const gchar *name, const gchar *pub)
{
	fixdir = dir;
	if (!driver_key (pub))
		return 2;
	golden_lookups (name);
	golden_enumerate (name);
	enumerate_matches_lookup (name);
	printf ("%d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}

static void
remove_tree (const gchar *path)
{
	GDir *dir;
	const gchar *n;

	if (g_file_test (path, G_FILE_TEST_IS_SYMLINK) ||
	    !g_file_test (path, G_FILE_TEST_IS_DIR)) {
		g_unlink (path);
		return;
	}
	dir = g_dir_open (path, 0, NULL);
	while (dir != NULL && (n = g_dir_read_name (dir)) != NULL) {
		gchar *c = g_build_filename (path, n, NULL);

		remove_tree (c);
		g_free (c);
	}
	if (dir != NULL)
		g_dir_close (dir);
	g_rmdir (path);
}

int
main (int argc, char **argv)
{
	EVP_PKEY *runtime;
	static const gchar *fixtures[] = { "small", "random", "edge", "edge6",
	                                   "empty" };
	const gchar *mode = argc > 1 ? argv[1] : "";
	guint mutations = 4000;

	setvbuf (stdout, NULL, _IOLBF, 0);
	if (strcmp (mode, "lookup-tsv") == 0 && argc == 5)
		return drive_lookup_tsv (argv[2], argv[3], argv[4]);
	if (strcmp (mode, "enum") == 0 && argc == 5)
		return drive_enum (argv[2], argv[3], argv[4]);
	if (strcmp (mode, "resign") == 0 && (argc == 5 || argc == 6))
		return drive_resign (argv[2], argv[3], argv[4],
		                     argc == 6 ? (guint) atoi (argv[5]) : 1);
	if (strcmp (mode, "info") == 0 && (argc == 3 || argc == 4))
		return drive_info (argv[2], argc == 4 ? argv[3] : NULL);
	if (strcmp (mode, "update") == 0 && (argc == 4 || argc == 5))
		return drive_update (argv[2], argv[3], argc == 5 ? argv[4] : NULL);
	if (strcmp (mode, "golden") == 0 && argc == 5)
		return drive_golden (argv[2], argv[3], argv[4]);
	if (strcmp (mode, "mutate") == 0 && argc == 5) {
		fixdir = argv[4];
		tmpdir = g_dir_make_tmp ("fs-geodb-XXXXXX", NULL);
		runtime = key_new ("P-521");
		mutation_loop (runtime, (guint32) g_ascii_strtoull (argv[2], NULL, 10),
		               (guint) g_ascii_strtoull (argv[3], NULL, 10), FALSE);
		EVP_PKEY_free (runtime);
		remove_tree (tmpdir);
		printf ("%d checks, %d failures\n", checks, failures);
		return failures == 0 ? 0 : 1;
	}
	if (argc > 2 || (argc == 2 && g_str_has_suffix (mode, ".db"))) {
		fprintf (stderr, "usage: see the head of tests/test-geodb.c\n");
		return 2;
	}
	if (argc == 2)
		fixdir = argv[1];
	if (g_getenv ("STOCKFW_GEODB_MUTATIONS") != NULL)
		mutations = (guint) g_ascii_strtoull (
			g_getenv ("STOCKFW_GEODB_MUTATIONS"), NULL, 10);

	tmpdir = g_dir_make_tmp ("fs-geodb-XXXXXX", NULL);
	runtime = key_new ("P-521");
	if (tmpdir == NULL || runtime == NULL) {
		printf ("FAIL: no temporary directory or key\n");
		return 1;
	}

	test_pinned_key ();
	test_real_database ();

	use_key_file ("k1.pub");
	for (guint i = 0; i < G_N_ELEMENTS (fixtures); i++)
		golden_lookups (fixtures[i]);
	small_lookups ();
	edge_lookups ();
	for (guint i = 0; i < G_N_ELEMENTS (fixtures); i++) {
		golden_enumerate (fixtures[i]);
		enumerate_matches_lookup (fixtures[i]);
	}
	enumerate_details ();
	use_key_file ("k1.pub");
	test_metadata ();
	use_key_file ("k1.pub");
	test_lookup_api ();
	test_signature (runtime);
	test_open_files ();
	test_malformed (runtime);
	mutation_loop (runtime, 1077, mutations, FALSE);
	test_xz ();
	test_judge ();
	test_install ();

	fs_geodb_testing_set_key (NULL);
	g_clear_pointer (&bomb_over, g_bytes_unref);
	EVP_PKEY_free (runtime);
	remove_tree (tmpdir);
	g_free (tmpdir);
	printf ("\n%d checks, %d failures\n", checks, failures);
	printf (failures == 0 ? "test-geodb: PASSED\n" : "test-geodb: FAILED\n");
	return failures == 0 ? 0 : 1;
}
