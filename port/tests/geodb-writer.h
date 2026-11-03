/*---[ geodb-writer.h ]--------------------------------------------------
 * Tests only: write a location database (libloc format version 1, the
 * layout fs-geodb.c reads) from a list of networks, and sign it with a
 * key made at run time, so the engine's tests and the end-to-end driver
 * can build exactly the database they need.  The reader must be a test
 * build (FS_GEODB_TESTING) told the key with fs_geodb_testing_set_key().
 *
 *   GeoWriter *w = geow_new (created_at);
 *   geow_net (w, "198.51.100.0/24", "XA", 64500, 0);
 *   geow_as (w, 64500, "Example AS");
 *   geow_country (w, "XA", "EU", "Testland");
 *   EVP_PKEY *key = geow_key_new ();
 *   guint8 *db = geow_build (w, key, &len);      signed, slot 1
 *   GBytes *xz = geow_xz (db, len);              what IPFire serves
 *
 * The file: the magic and version, the 4,192-byte header (creation
 * time, vendor, description and licence strings, five sections as
 * offset and length, two signature lengths and slots), then the AS
 * table, the network tree, the network table, the country table and
 * the string pool.  The tree is a binary trie over 128-bit addresses,
 * IPv4 under ::ffff:0:0/96.  Header-only: every function is static.
 *--------------------------------------------------------------------*/
#ifndef STOCKFW_TESTS_GEODB_WRITER_H
#define STOCKFW_TESTS_GEODB_WRITER_H

#include <glib.h>
#include <string.h>
#include <lzma.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "core/fs-iprange.h"

#define GEOW_F_CREATED     8
#define GEOW_F_VENDOR      16
#define GEOW_F_DESC        20
#define GEOW_F_LICENSE     24
#define GEOW_F_SEC_OFF(i)  (28 + 8 * (i))
#define GEOW_F_SEC_LEN(i)  (32 + 8 * (i))
#define GEOW_F_SIG1_LEN    68
#define GEOW_F_SIG1        72
#define GEOW_HEADER_END    4200
#define GEOW_SEC_AS        0
#define GEOW_SEC_NETS      1
#define GEOW_SEC_TREE      2
#define GEOW_SEC_COUNTRIES 3
#define GEOW_SEC_POOL      4
#define GEOW_NO_NET        0xffffffffu

typedef struct
{
	guint32 zero, one, net;
} GeowNode;

typedef struct
{
	gchar   cc[3];
	guint32 asn;
	guint16 flags;
} GeowNet;

typedef struct
{
	gint64      created;
	GArray     *nodes;      /* GeowNode; node 0 is the root          */
	GArray     *nets;       /* GeowNet                               */
	GArray     *ases;       /* guint32 number, then name, pairs      */
	GPtrArray  *as_names;
	GPtrArray  *countries;  /* "XA\tEU\tName"                         */
	gchar      *license;
} GeoWriter;

static void
geow_put16 (guint8 *p, guint16 v)
{
	p[0] = (guint8) (v >> 8);
	p[1] = (guint8) v;
}

static void
geow_put32 (guint8 *p, guint32 v)
{
	p[0] = (guint8) (v >> 24);
	p[1] = (guint8) (v >> 16);
	p[2] = (guint8) (v >> 8);
	p[3] = (guint8) v;
}

static void
geow_put64 (guint8 *p, guint64 v)
{
	geow_put32 (p, (guint32) (v >> 32));
	geow_put32 (p + 4, (guint32) v);
}

static GeoWriter *
geow_new (gint64 created)
{
	GeoWriter *w = g_new0 (GeoWriter, 1);
	GeowNode root = { 0, 0, GEOW_NO_NET };

	w->created = created;
	w->nodes = g_array_new (FALSE, FALSE, sizeof (GeowNode));
	g_array_append_val (w->nodes, root);
	w->nets = g_array_new (FALSE, FALSE, sizeof (GeowNet));
	w->ases = g_array_new (FALSE, FALSE, sizeof (guint32));
	w->as_names = g_ptr_array_new_with_free_func (g_free);
	w->countries = g_ptr_array_new_with_free_func (g_free);
	w->license = g_strdup ("CC BY-SA 4.0");
	return w;
}

static void
geow_free (GeoWriter *w)
{
	g_array_unref (w->nodes);
	g_array_unref (w->nets);
	g_array_unref (w->ases);
	g_ptr_array_unref (w->as_names);
	g_ptr_array_unref (w->countries);
	g_free (w->license);
	g_free (w);
}

/* Bit `i' (0 = most significant) of a 128-bit value. */
static guint
geow_bit (FsU128 a, guint i)
{
	return i < 64 ? (guint) ((a.hi >> (63 - i)) & 1)
	              : (guint) ((a.lo >> (127 - i)) & 1);
}

/* A network "a.b.c.d/n" or "x::/n" with its country ("" none), AS
 * (0 none) and flags.  The same prefix twice keeps the last.  FALSE
 * when the text is not a CIDR. */
static gboolean
geow_net (GeoWriter *w, const gchar *cidr, const gchar *cc, guint32 asn,
          guint16 flags)
{
	FsRange4 r4;
	FsRange6 r6;
	guint plen = 0, depth;
	FsU128 addr;
	FsAddrFamily fam = fs_range_parse (cidr, &r4, &r6, &plen, NULL);
	GeowNet net = { { 0 }, asn, flags };
	guint32 index = 0;

	if (fam == FS_AF_NONE || strchr (cidr, '-') != NULL)
		return FALSE;
	if (fam == FS_AF_V4) {
		addr.hi = 0;
		addr.lo = G_GUINT64_CONSTANT (0x0000ffff00000000) | r4.start;
		depth = 96 + plen;
	} else {
		addr = r6.start;
		depth = plen;
	}
	if (cc != NULL && cc[0] != '\0') {
		net.cc[0] = cc[0];
		net.cc[1] = cc[1];
	}
	for (guint i = 0; i < depth; i++) {
		GeowNode *n = &g_array_index (w->nodes, GeowNode, index);
		guint32 child = geow_bit (addr, i) ? n->one : n->zero;

		if (child == 0) {
			GeowNode fresh = { 0, 0, GEOW_NO_NET };

			child = w->nodes->len;
			g_array_append_val (w->nodes, fresh);
			n = &g_array_index (w->nodes, GeowNode, index);
			if (geow_bit (addr, i))
				n->one = child;
			else
				n->zero = child;
		}
		index = child;
	}
	g_array_append_val (w->nets, net);
	g_array_index (w->nodes, GeowNode, index).net = w->nets->len - 1;
	return TRUE;
}

static void
geow_as (GeoWriter *w, guint32 number, const gchar *name)
{
	g_array_append_val (w->ases, number);
	g_ptr_array_add (w->as_names, g_strdup (name));
}

static void
geow_country (GeoWriter *w, const gchar *code, const gchar *continent,
              const gchar *name)
{
	g_ptr_array_add (w->countries, g_strdup_printf ("%c%c\t%c%c\t%s",
		code[0], code[1], continent[0], continent[1], name));
}

static guint32
geow_str (GByteArray *pool, const gchar *s)
{
	guint32 at = pool->len;

	g_byte_array_append (pool, (const guint8 *) s, (guint) strlen (s) + 1);
	return at;
}

static gint
geow_cmp_str (gconstpointer a, gconstpointer b)
{
	return strcmp (*(const gchar *const *) a, *(const gchar *const *) b);
}

/* The test's signer, from the format's rule: SHA-256 and ECDSA (DER)
 * over the whole file with both signature lengths and both 2,048-byte
 * slots read as zeros; written into slot 1. */
static gboolean
geow_sign (guint8 *data, gsize len, EVP_PKEY *key)
{
	guint8 *msg = g_memdup2 (data, len);
	EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
	guint8 sig[512];
	size_t sig_len = sizeof sig;
	gboolean ok;

	memset (msg + GEOW_F_SIG1_LEN, 0, 4);
	memset (msg + GEOW_F_SIG1, 0, 4096);
	ok = EVP_DigestSignInit (ctx, NULL, EVP_sha256 (), NULL, key) == 1 &&
	     EVP_DigestSign (ctx, sig, &sig_len, msg, len) == 1;
	EVP_MD_CTX_free (ctx);
	g_free (msg);
	if (!ok)
		return FALSE;
	memset (data + GEOW_F_SIG1_LEN, 0, 4);
	memset (data + GEOW_F_SIG1, 0, 4096);
	memcpy (data + GEOW_F_SIG1, sig, sig_len);
	geow_put16 (data + GEOW_F_SIG1_LEN, (guint16) sig_len);
	return TRUE;
}

/* The whole file, signed with `key'.  Caller frees. */
static guint8 *
geow_build (GeoWriter *w, EVP_PKEY *key, gsize *len)
{
	static const guint order[5] = { GEOW_SEC_AS, GEOW_SEC_TREE,
	                                GEOW_SEC_NETS, GEOW_SEC_COUNTRIES,
	                                GEOW_SEC_POOL };
	GByteArray *sec[5], *out = g_byte_array_new ();
	guint8 head[GEOW_HEADER_END] = { 0 };
	guint32 at = GEOW_HEADER_END, vendor, desc, lic;
	GPtrArray *as_order = g_ptr_array_new ();
	guint8 *data;

	for (guint i = 0; i < 5; i++)
		sec[i] = g_byte_array_new ();
	g_byte_array_append (sec[GEOW_SEC_POOL], (const guint8 *) "", 1);
	vendor = geow_str (sec[GEOW_SEC_POOL], "StockFW tests");
	desc = geow_str (sec[GEOW_SEC_POOL], "A database written by the tests");
	lic = geow_str (sec[GEOW_SEC_POOL], w->license);

	/* ASes ascending by number (the reader binary-searches them). */
	for (guint i = 0; i < w->ases->len; i++)
		g_ptr_array_add (as_order, GUINT_TO_POINTER (i));
	for (guint i = 0; i < as_order->len; i++)
		for (guint j = i + 1; j < as_order->len; j++) {
			guint a = GPOINTER_TO_UINT (as_order->pdata[i]);
			guint b = GPOINTER_TO_UINT (as_order->pdata[j]);

			if (g_array_index (w->ases, guint32, b) <
			    g_array_index (w->ases, guint32, a)) {
				as_order->pdata[i] = GUINT_TO_POINTER (b);
				as_order->pdata[j] = GUINT_TO_POINTER (a);
			}
		}
	for (guint i = 0; i < as_order->len; i++) {
		guint k = GPOINTER_TO_UINT (as_order->pdata[i]);
		guint8 b[8];

		geow_put32 (b, g_array_index (w->ases, guint32, k));
		geow_put32 (b + 4, geow_str (sec[GEOW_SEC_POOL],
		                             g_ptr_array_index (w->as_names, k)));
		g_byte_array_append (sec[GEOW_SEC_AS], b, 8);
	}
	g_ptr_array_free (as_order, TRUE);

	for (guint i = 0; i < w->nodes->len; i++) {
		const GeowNode *n = &g_array_index (w->nodes, GeowNode, i);
		guint8 b[12];

		geow_put32 (b, n->zero);
		geow_put32 (b + 4, n->one);
		geow_put32 (b + 8, n->net);
		g_byte_array_append (sec[GEOW_SEC_TREE], b, 12);
	}
	for (guint i = 0; i < w->nets->len; i++) {
		const GeowNet *n = &g_array_index (w->nets, GeowNet, i);
		guint8 b[12] = { 0 };

		b[0] = (guint8) n->cc[0];
		b[1] = (guint8) n->cc[1];
		geow_put32 (b + 4, n->asn);
		geow_put16 (b + 8, n->flags);
		g_byte_array_append (sec[GEOW_SEC_NETS], b, 12);
	}
	g_ptr_array_sort (w->countries, geow_cmp_str);
	for (guint i = 0; i < w->countries->len; i++) {
		const gchar *c = g_ptr_array_index (w->countries, i);
		guint8 b[8];

		b[0] = (guint8) c[0];
		b[1] = (guint8) c[1];
		b[2] = (guint8) c[3];
		b[3] = (guint8) c[4];
		geow_put32 (b + 4, geow_str (sec[GEOW_SEC_POOL], c + 6));
		g_byte_array_append (sec[GEOW_SEC_COUNTRIES], b, 8);
	}

	memcpy (head, "LOCDBXX\x01", 8);
	geow_put64 (head + GEOW_F_CREATED, (guint64) w->created);
	geow_put32 (head + GEOW_F_VENDOR, vendor);
	geow_put32 (head + GEOW_F_DESC, desc);
	geow_put32 (head + GEOW_F_LICENSE, lic);
	for (guint i = 0; i < 5; i++) {
		guint k = order[i];

		geow_put32 (head + GEOW_F_SEC_OFF (k), sec[k]->len ? at : 0);
		geow_put32 (head + GEOW_F_SEC_LEN (k), sec[k]->len);
		at += sec[k]->len;
	}
	g_byte_array_append (out, head, sizeof head);
	for (guint i = 0; i < 5; i++)
		g_byte_array_append (out, sec[order[i]]->data,
		                     sec[order[i]]->len);
	for (guint i = 0; i < 5; i++)
		g_byte_array_unref (sec[i]);
	*len = out->len;
	data = g_byte_array_free (out, FALSE);
	if (key != NULL && !geow_sign (data, *len, key)) {
		g_free (data);
		return NULL;
	}
	return data;
}

/* xz, as IPFire serves the file. */
static GBytes *
geow_xz (const guint8 *data, gsize len)
{
	gsize cap = lzma_stream_buffer_bound (len), out_len = 0;
	guint8 *out = g_malloc (cap);

	if (lzma_easy_buffer_encode (1, LZMA_CHECK_CRC64, NULL, data, len, out,
	                             &out_len, cap) != LZMA_OK) {
		g_free (out);
		return NULL;
	}
	return g_bytes_new_take (out, out_len);
}

/* An EC key on P-521, the curve IPFire signs with. */
static EVP_PKEY *
geow_key_new (void)
{
	return EVP_PKEY_Q_keygen (NULL, NULL, "EC", "P-521");
}

/* Its public half, PEM.  Caller frees. */
static gchar *
geow_key_pub_pem (EVP_PKEY *key)
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

#endif /* STOCKFW_TESTS_GEODB_WRITER_H */
