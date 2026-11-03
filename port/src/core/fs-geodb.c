/*---[ fs-geodb.c ]------------------------------------------------------
 * The IPFire location database reader.  See fs-geodb.h and
 * docs/1.0.7-threat-intel-design.md, section 12.
 *
 * Original code, written from the published layout of libloc's format
 * version 1; no libloc code or structure definition is used.  The facts
 * it relies on (all integers big-endian):
 *
 *   file      magic "LOCDBXX", one version byte (1), the header, then
 *             five sections anywhere after the header
 *   header    4192 bytes:
 *               0  u64 created_at (unix seconds)
 *               8  u32 vendor, description, licence (string offsets)
 *              20  u32 offset, u32 length of: the AS table, the network
 *                  table, the network tree, the country table and the
 *                  string pool, in that order (offsets from the start
 *                  of the file)
 *              60  u16 length of signature 1, u16 length of signature 2
 *              64  signature 1 (2048 bytes), then signature 2 (2048)
 *            4160  32 bytes reserved
 *   AS        8 bytes: u32 number, u32 name; ascending by number
 *   network   12 bytes: 2 country letters (two NULs: none), 2 unused,
 *             u32 ASN, u16 flags, 2 unused
 *   node      12 bytes: u32 child for bit 0, u32 child for bit 1 (0: no
 *             child; node 0 is the root), u32 network (0xffffffff: none)
 *   country   8 bytes: 2 code letters, 2 continent letters, u32 name;
 *             ascending by code
 *   pool      NUL-terminated strings; an offset is from the pool start
 *
 * The tree is one binary trie over 128-bit addresses, most significant
 * bit first; IPv4 lives under ::ffff:0:0/96.  A node at depth d that
 * names a network says the prefix spelled by the path to it, of length
 * d, belongs to that network; the most specific one wins.
 *
 * The signature: ECDSA (DER) over SHA-256 of the magic and version, the
 * header with both signature lengths and both 2048-byte signature
 * fields set to zero (the reserved bytes are not zeroed), and every
 * byte from the end of the header to the end of the file.
 *
 * Layout of this file: helpers, the pinned key, verify, check (the
 * structural checks of step 3), open, lookup, enumerate, countries and
 * ASes, judge, unpack, install and update.
 *--------------------------------------------------------------------*/

#ifdef __linux__
#define _GNU_SOURCE
#endif

#include "core/fs-geodb.h"
#include "core/fs-fetch.h"
#include "core/fs-i18n.h"

#include <glib/gstdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

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
#ifdef __linux__
#include <dirent.h>
#include <sys/file.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif

/* ---- the format ------------------------------------------------------ */

#define MAGIC            "LOCDBXX"
#define MAGIC_LEN        7u
#define PREAMBLE_LEN     8u              /* magic + version byte       */
#define FORMAT_VERSION   1u
#define HEADER_LEN       4192u
#define HEADER_END       (PREAMBLE_LEN + HEADER_LEN)   /* 4200          */

#define H_CREATED_AT     0u
#define H_VENDOR         8u
#define H_DESCRIPTION    12u
#define H_LICENSE        16u
#define H_SECTIONS       20u             /* 5 x (u32 offset, u32 length) */
#define H_SIG1_LEN       60u
#define H_SIG2_LEN       62u
#define H_SIG1           64u
#define SIG_SLOT         2048u
#define H_SIG2           (H_SIG1 + SIG_SLOT)
#define H_RESERVED       (H_SIG2 + SIG_SLOT)            /* 4160          */

#define AS_REC           8u
#define NET_REC          12u
#define NODE_REC         12u
#define COUNTRY_REC      8u

#define NO_NET           0xffffffffu
#define NO_NODE          0xffffffffu

/* The DFS stack: on each level at most one sibling waits, plus the two
 * children of the deepest node. */
#define STACK_MAX        (2u * (FS_GEODB_MAX_DEPTH + 2u))

/* Bytes hashed per update call, and decoded per write. */
#define HASH_CHUNK       (1024u * 1024u)
#define XZ_OUT_CHUNK     (256u * 1024u)

/* The key IPFire signs the database with: secp521r1, "Created: Dec 10,
 * 2019 by Michael Tremer".  Copied from /var/lib/location/signing-key.pem
 * of Ubuntu 24.04's `location' package (libloc 0.9.16-3.1build2), which
 * is the upstream key libloc ships; that key verifies the IPFire-signed
 * database in Ubuntu's libloc-database package (0~20221029-1), and the
 * test suite checks both. */
static const gchar pinned_key_pem[] =
	"-----BEGIN PUBLIC KEY-----\n"
	"MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB1PzZdV9DE59LVCdXy/9cRgvTy9lx\n"
	"L5tV10awZDilwQ9GR8x/irJE8ctGSnZ5HgbOk+gilurmC5JlJmTjZrW7tt8Awiu8\n"
	"ir3y2n7XXyiVGIzTHrA6Tw7SG+H9LzuIl0wCg6s6svnXVDyho7b0tSZPUGKMI28q\n"
	"CUXef0jvZ9+ncTiJh1w=\n"
	"-----END PUBLIC KEY-----\n";

G_DEFINE_QUARK (fs-geodb-error-quark, fs_geodb_error)

typedef struct
{
	gsize off;
	gsize len;
	gsize count;     /* len / record size */
} Section;

struct _FsGeodb
{
	GMappedFile  *map;           /* NULL for a test buffer             */
	const guint8 *data;
	gsize         size;
	Section       as, nets, tree, countries, pool;
	guint32       v4_root;       /* the node at ::ffff:0:0/96          */
	FsGeodbInfo   info;
	gchar        *vendor;
	gchar        *description;
	gchar        *license;
};

typedef struct
{
	guint32 zero;
	guint32 one;
	guint32 net;
} Node;

typedef struct
{
	gchar   cc[3];
	guint32 asn;
	guint   flags;
} Net;

/* ============================================================ helpers */

static inline guint16
be16 (const guint8 *p)
{
	return (guint16) (((guint) p[0] << 8) | p[1]);
}

static inline guint32
be32 (const guint8 *p)
{
	return ((guint32) p[0] << 24) | ((guint32) p[1] << 16) |
	       ((guint32) p[2] << 8) | (guint32) p[3];
}

static inline guint64
be64 (const guint8 *p)
{
	return ((guint64) be32 (p) << 32) | be32 (p + 4);
}

static inline gboolean
is_upper (guint8 c)
{
	return c >= 'A' && c <= 'Z';
}

static gboolean
malformed (GError **error, const gchar *why)
{
	g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_FORMAT,
	             _("The location database is malformed: %s."), why);
	return FALSE;
}

/* 128-bit values (FsU128: hi holds bits 0-63, most significant first). */

static inline guint
u128_bit (FsU128 a, guint depth)
{
	return depth < 64 ? (guint) ((a.hi >> (63 - depth)) & 1u)
	                  : (guint) ((a.lo >> (127 - depth)) & 1u);
}

static inline void
u128_set_bit (FsU128 *a, guint depth)
{
	if (depth < 64)
		a->hi |= (guint64) 1 << (63 - depth);
	else
		a->lo |= (guint64) 1 << (127 - depth);
}

/* The low `bits' bits set (bits <= 128). */
static inline FsU128
u128_low_mask (guint bits)
{
	FsU128 m = { 0, 0 };

	if (bits >= 128) {
		m.hi = G_MAXUINT64;
		m.lo = G_MAXUINT64;
	} else if (bits >= 64) {
		m.hi = bits == 64 ? 0 : (((guint64) 1 << (bits - 64)) - 1);
		m.lo = G_MAXUINT64;
	} else {
		m.lo = bits == 0 ? 0 : (((guint64) 1 << bits) - 1);
	}
	return m;
}

static inline FsU128
u128_or (FsU128 a, FsU128 b)
{
	FsU128 r = { a.hi | b.hi, a.lo | b.lo };
	return r;
}

static inline FsU128
u128_and_not (FsU128 a, FsU128 b)
{
	FsU128 r = { a.hi & ~b.hi, a.lo & ~b.lo };
	return r;
}

static inline gboolean
u128_eq (FsU128 a, FsU128 b)
{
	return a.hi == b.hi && a.lo == b.lo;
}

static inline gboolean
u128_is_max (FsU128 a)
{
	return a.hi == G_MAXUINT64 && a.lo == G_MAXUINT64;
}

static inline FsU128
u128_inc (FsU128 a)
{
	FsU128 r = a;

	r.lo++;
	if (r.lo == 0)
		r.hi++;
	return r;
}

static inline FsU128
u128_sub (FsU128 a, FsU128 b)
{
	FsU128 r;

	r.lo = a.lo - b.lo;
	r.hi = a.hi - b.hi - (a.lo < b.lo ? 1 : 0);
	return r;
}

/* Trailing zero bits (128 for zero). */
static guint
u128_ctz (FsU128 a)
{
	guint n = 0;

	if (a.lo == 0) {
		if (a.hi == 0)
			return 128;
		n = 64;
		while (((a.hi >> (n - 64)) & 1u) == 0)
			n++;
		return n;
	}
	while (((a.lo >> n) & 1u) == 0)
		n++;
	return n;
}

/* floor(log2(a)), a != 0. */
static guint
u128_log2 (FsU128 a)
{
	guint n = 63;

	if (a.hi != 0) {
		while (((a.hi >> n) & 1u) == 0)
			n--;
		return n + 64;
	}
	while (((a.lo >> n) & 1u) == 0)
		n--;
	return n;
}

/* ::ffff:0:0/96, where IPv4 lives in the tree. */
static const FsU128 mapped_prefix = { 0, G_GUINT64_CONSTANT (0x0000ffff00000000) };

static inline gboolean
u128_is_mapped (FsU128 a)
{
	return a.hi == 0 && (a.lo >> 32) == 0xffffu;
}

/* ---- text ----------------------------------------------------------- */

static gchar *
format_v4 (guint32 a)
{
	return g_strdup_printf ("%u.%u.%u.%u", a >> 24, (a >> 16) & 0xffu,
	                        (a >> 8) & 0xffu, a & 0xffu);
}

/* RFC 5952: lower case, no leading zeros, the longest run of two or
 * more zero groups (the first of equal runs) as "::", never the dotted
 * IPv4 tail.  Our own so the text is the same on every platform. */
static gchar *
format_v6 (FsU128 a)
{
	guint16 g[8];
	gint best = -1, best_len = 0;
	GString *s = g_string_sized_new (40);

	for (guint i = 0; i < 4; i++) {
		g[i] = (guint16) (a.hi >> (48 - 16 * i));
		g[i + 4] = (guint16) (a.lo >> (48 - 16 * i));
	}
	for (gint i = 0; i < 8; ) {
		gint j = i;

		while (j < 8 && g[j] == 0)
			j++;
		if (j - i > best_len && j - i >= 2) {
			best = i;
			best_len = j - i;
		}
		i = j > i ? j : i + 1;
	}
	for (gint i = 0; i < 8; i++) {
		if (i == best) {
			g_string_append (s, "::");
			i += best_len - 1;
			continue;
		}
		if (s->len > 0 && s->str[s->len - 1] != ':')
			g_string_append_c (s, ':');
		g_string_append_printf (s, "%x", g[i]);
	}
	return g_string_free (s, FALSE);
}

static gchar *
format_prefix (FsAddrFamily family, FsU128 start, guint prefix_len)
{
	gchar *addr = family == FS_AF_V4 ? format_v4 ((guint32) start.lo)
	                                 : format_v6 (start);
	gchar *out = g_strdup_printf ("%s/%u", addr, prefix_len);

	g_free (addr);
	return out;
}

/* A string from the file made safe to show: valid UTF-8, and control
 * and format characters (bidi overrides among them) become '?'; a
 * newline is kept where `newlines' says so. */
static gchar *
display_copy (const gchar *raw, gsize len, gboolean newlines)
{
	gchar *valid = g_utf8_make_valid (raw, (gssize) len);
	GString *out = g_string_sized_new (len + 1);

	for (const gchar *p = valid; *p != '\0'; p = g_utf8_next_char (p)) {
		gunichar c = g_utf8_get_char (p);

		if (c == '\n' && newlines)
			g_string_append_c (out, '\n');
		else if (g_unichar_iscntrl (c) ||
		         g_unichar_type (c) == G_UNICODE_FORMAT)
			g_string_append_c (out, '?');
		else
			g_string_append_unichar (out, c);
	}
	g_free (valid);
	return g_string_free (out, FALSE);
}

/* ---- range-checked access -------------------------------------------- */

static const guint8 *
record (const FsGeodb *db, const Section *s, gsize size, guint32 index)
{
	/* off + count * size <= file size was checked at open */
	if ((gsize) index >= s->count)
		return NULL;
	return db->data + s->off + (gsize) index * size;
}

static gboolean
node_get (const FsGeodb *db, guint32 index, Node *n)
{
	const guint8 *p = record (db, &db->tree, NODE_REC, index);

	if (p == NULL)
		return FALSE;
	n->zero = be32 (p);
	n->one = be32 (p + 4);
	n->net = be32 (p + 8);
	return TRUE;
}

static gboolean
net_get (const FsGeodb *db, guint32 index, Net *n)
{
	const guint8 *p;

	if (index == NO_NET || (p = record (db, &db->nets, NET_REC, index)) == NULL)
		return FALSE;
	if (is_upper (p[0]) && is_upper (p[1])) {
		n->cc[0] = (gchar) p[0];
		n->cc[1] = (gchar) p[1];
	} else {
		n->cc[0] = n->cc[1] = '\0';
	}
	n->cc[2] = '\0';
	n->asn = be32 (p + 4);
	n->flags = be16 (p + 8) & FS_GEODB_FLAGS_KNOWN;
	return TRUE;
}

/* A string in the pool: in range, terminated inside the pool, at most
 * FS_GEODB_MAX_STRING bytes.  NULL otherwise. */
static const gchar *
pool_string (const FsGeodb *db, guint32 offset, gsize *len)
{
	const guint8 *p, *nul;
	gsize avail;

	if ((gsize) offset >= db->pool.len)
		return NULL;
	p = db->data + db->pool.off + offset;
	avail = db->pool.len - offset;
	nul = memchr (p, '\0', MIN (avail, (gsize) FS_GEODB_MAX_STRING + 1));
	if (nul == NULL)
		return NULL;
	*len = (gsize) (nul - p);
	return (const gchar *) p;
}

static gchar *
pool_display (const FsGeodb *db, guint32 offset, gboolean newlines)
{
	gsize len = 0;
	const gchar *s = pool_string (db, offset, &len);

	return s != NULL ? display_copy (s, len, newlines) : NULL;
}

/* ============================================================ the key */

const gchar *
fs_geodb_pinned_key_pem (void)
{
	return pinned_key_pem;
}

#ifdef FS_GEODB_TESTING
static GMutex testing_lock;
static gchar *testing_key;

void
fs_geodb_testing_set_key (const gchar *pem)
{
	g_mutex_lock (&testing_lock);
	g_free (testing_key);
	testing_key = g_strdup (pem);
	g_mutex_unlock (&testing_lock);
}
#endif

static EVP_PKEY *
load_key (GError **error)
{
	gchar *pem;
	BIO *bio;
	EVP_PKEY *key;
	gchar group[64] = "";
	size_t group_len = 0;

#ifdef FS_GEODB_TESTING
	g_mutex_lock (&testing_lock);
	pem = g_strdup (testing_key != NULL ? testing_key : pinned_key_pem);
	g_mutex_unlock (&testing_lock);
#else
	pem = g_strdup (pinned_key_pem);
#endif
	bio = BIO_new_mem_buf (pem, -1);
	key = bio != NULL ? PEM_read_bio_PUBKEY (bio, NULL, NULL, NULL) : NULL;
	BIO_free (bio);
	g_free (pem);
	if (key != NULL &&
	    (EVP_PKEY_get_base_id (key) != EVP_PKEY_EC ||
	     EVP_PKEY_get_group_name (key, group, sizeof group, &group_len) != 1 ||
	     strcmp (group, "secp521r1") != 0)) {
		EVP_PKEY_free (key);
		key = NULL;
	}
	ERR_clear_error ();
	if (key == NULL)
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_SIGNATURE,
		             _("The location database's signing key is not "
		               "an ECDSA P-521 public key."));
	return key;
}

/* ========================================================= verify (2) */

/* The preamble and header must be there to verify at all. */
static gboolean
check_preamble (const guint8 *data, gsize size, GError **error)
{
	if (size < PREAMBLE_LEN || memcmp (data, MAGIC, MAGIC_LEN) != 0) {
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_FORMAT,
		             _("This is not a location database."));
		return FALSE;
	}
	if (data[MAGIC_LEN] != FORMAT_VERSION) {
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_FORMAT,
		             _("Location database format %u is not supported "
		               "(only format 1 is)."), data[MAGIC_LEN]);
		return FALSE;
	}
	if (size < HEADER_END)
		return malformed (error, _("it is shorter than its header"));
	return TRUE;
}

/* Verify the file against the key.  `hdr' receives a copy of the
 * header, with the signature fields zeroed: everything after this
 * reads the header from that copy, the bytes that were verified.
 * *slot gets 1 or 2. */
static gboolean
verify (const guint8 *data, gsize size, guint8 hdr[HEADER_LEN],
        guint *slot, GError **error)
{
	EVP_PKEY *key;
	EVP_MD_CTX *ctx[2] = { NULL, NULL };
	guint8 sig[2][SIG_SLOT];
	gsize sig_len[2];
	gboolean ok = FALSE, usable = FALSE;

	if (!check_preamble (data, size, error))
		return FALSE;
	memcpy (hdr, data + PREAMBLE_LEN, HEADER_LEN);
	sig_len[0] = be16 (hdr + H_SIG1_LEN);
	sig_len[1] = be16 (hdr + H_SIG2_LEN);
	memcpy (sig[0], hdr + H_SIG1, SIG_SLOT);
	memcpy (sig[1], hdr + H_SIG2, SIG_SLOT);
	/* What was signed: both lengths and both whole slots as zeros. */
	memset (hdr + H_SIG1_LEN, 0, 4);
	memset (hdr + H_SIG1, 0, 2 * SIG_SLOT);

	if ((key = load_key (error)) == NULL)
		return FALSE;
	for (guint i = 0; i < 2; i++) {
		if (sig_len[i] == 0 || sig_len[i] > SIG_SLOT)
			continue;
		ctx[i] = EVP_MD_CTX_new ();
		if (ctx[i] == NULL ||
		    EVP_DigestVerifyInit (ctx[i], NULL, EVP_sha256 (), NULL,
		                          key) != 1) {
			EVP_MD_CTX_free (ctx[i]);
			ctx[i] = NULL;
			continue;
		}
		usable = TRUE;
	}
	if (!usable) {
		EVP_PKEY_free (key);
		ERR_clear_error ();
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_SIGNATURE,
		             _("The location database is not signed."));
		return FALSE;
	}
	for (guint i = 0; i < 2; i++) {
		gsize at = HEADER_END;

		if (ctx[i] == NULL)
			continue;
		if (EVP_DigestVerifyUpdate (ctx[i], data, PREAMBLE_LEN) != 1 ||
		    EVP_DigestVerifyUpdate (ctx[i], hdr, HEADER_LEN) != 1)
			goto next;
		while (at < size) {
			gsize n = MIN ((gsize) HASH_CHUNK, size - at);

			if (EVP_DigestVerifyUpdate (ctx[i], data + at, n) != 1)
				goto next;
			at += n;
		}
		if (EVP_DigestVerifyFinal (ctx[i], sig[i], sig_len[i]) == 1) {
			ok = TRUE;
			*slot = i + 1;
		}
	next:
		EVP_MD_CTX_free (ctx[i]);
		ctx[i] = NULL;
		if (ok)
			break;
	}
	for (guint i = 0; i < 2; i++)
		EVP_MD_CTX_free (ctx[i]);
	EVP_PKEY_free (key);
	ERR_clear_error ();
	if (!ok)
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_SIGNATURE,
		             _("The location database's signature does not "
		               "verify with IPFire's key."));
	return ok;
}

/* ========================================================== check (3) */

static gboolean
section_read (FsGeodb *db, const guint8 *hdr, guint index, gsize rec_size,
              const gchar *name, Section *s, GError **error)
{
	guint64 off = be32 (hdr + H_SECTIONS + 8 * index);
	guint64 len = be32 (hdr + H_SECTIONS + 8 * index + 4);
	guint64 end;
	gchar *why;

	s->off = s->len = s->count = 0;
	if (len == 0)
		return TRUE;            /* an empty section has no place */
	if (!g_uint64_checked_add (&end, off, len) || end > db->size) {
		why = g_strdup_printf (_("the %s lies outside the file"), name);
		goto bad;
	}
	if (off < HEADER_END) {
		why = g_strdup_printf (_("the %s overlaps the header"), name);
		goto bad;
	}
	if (rec_size > 1 && len % rec_size != 0) {
		why = g_strdup_printf (_("the %s is not a whole number of "
		                         "records"), name);
		goto bad;
	}
	s->off = (gsize) off;
	s->len = (gsize) len;
	s->count = (gsize) (len / rec_size);
	if (s->count > G_MAXUINT32 - 1) {
		why = g_strdup_printf (_("the %s has too many records"), name);
		goto bad;
	}
	return TRUE;

bad:
	malformed (error, why);
	g_free (why);
	return FALSE;
}

static gboolean
sections_apart (const Section *a, const Section *b)
{
	if (a->len == 0 || b->len == 0)
		return TRUE;
	return a->off + a->len <= b->off || b->off + b->len <= a->off;
}

static gboolean
check_sections (FsGeodb *db, const guint8 *hdr, GError **error)
{
	static const gchar *const names[5] = {
		N_("AS table"), N_("network table"), N_("network tree"),
		N_("country table"), N_("string pool")
	};
	static const gsize sizes[5] = {
		AS_REC, NET_REC, NODE_REC, COUNTRY_REC, 1
	};
	Section *s[5] = { &db->as, &db->nets, &db->tree, &db->countries,
	                  &db->pool };

	for (guint i = 0; i < 5; i++)
		if (!section_read (db, hdr, i, sizes[i], _(names[i]), s[i], error))
			return FALSE;
	for (guint i = 0; i < 5; i++)
		for (guint j = i + 1; j < 5; j++)
			if (!sections_apart (s[i], s[j])) {
				gchar *why = g_strdup_printf (_("the %s and the %s "
				                                "overlap"),
				                              _(names[i]),
				                              _(names[j]));
				malformed (error, why);
				g_free (why);
				return FALSE;
			}
	return TRUE;
}

/* The tree, walked once: a tree (no node reached twice, so no loop and
 * no shared branch), at most FS_GEODB_MAX_DEPTH deep, every index in
 * range.  Every later walk is bounded by what this proved. */
static gboolean
check_tree (FsGeodb *db, GError **error)
{
	struct { guint32 node; guint depth; } stack[STACK_MAX];
	gsize top = 0;
	guint8 *seen;
	const gchar *why = NULL;

	db->v4_root = NO_NODE;
	if (db->tree.count == 0)
		return TRUE;
	seen = g_malloc0 (db->tree.count / 8 + 1);
	seen[0] = 1;
	stack[top].node = 0;
	stack[top++].depth = 0;
	while (top > 0 && why == NULL) {
		guint32 index = stack[--top].node;
		guint depth = stack[top].depth;
		Node n;

		if (!node_get (db, index, &n)) {
			why = _("a tree node lies outside the tree");
			break;
		}
		if (n.net != NO_NET && (gsize) n.net >= db->nets.count) {
			why = _("a tree node names a network that does not exist");
			break;
		}
		for (guint b = 0; b < 2 && why == NULL; b++) {
			guint32 child = b ? n.one : n.zero;

			if (child == 0)
				continue;
			if ((gsize) child >= db->tree.count)
				why = _("a tree node points outside the tree");
			else if (depth >= FS_GEODB_MAX_DEPTH)
				why = _("the tree is deeper than 128 levels");
			else if (seen[child / 8] & (1u << (child % 8)))
				why = _("a tree node is reached twice (a loop or "
				        "a shared branch)");
			else if (top >= STACK_MAX)
				why = _("the tree is too deep");
			else {
				seen[child / 8] |= (guint8) (1u << (child % 8));
				stack[top].node = child;
				stack[top++].depth = depth + 1;
			}
		}
	}
	g_free (seen);
	if (why != NULL)
		return malformed (error, why);

	/* Where IPv4 starts: 80 zero bits, then 16 one bits. */
	{
		guint32 index = 0;
		Node n;

		for (guint depth = 0; depth < 96; depth++) {
			guint32 child;

			if (!node_get (db, index, &n))
				return TRUE;
			child = u128_bit (mapped_prefix, depth) ? n.one : n.zero;
			if (child == 0)
				return TRUE;
			index = child;
		}
		db->v4_root = index;
	}
	return TRUE;
}

static gboolean
check_tables (FsGeodb *db, GError **error)
{
	gsize len;

	for (guint32 i = 0; i < db->nets.count; i++) {
		const guint8 *p = record (db, &db->nets, NET_REC, i);

		if (!((p[0] == 0 && p[1] == 0) ||
		      (is_upper (p[0]) && is_upper (p[1]))))
			return malformed (error, _("a network has an invalid "
			                           "country code"));
	}
	for (guint32 i = 0; i < db->as.count; i++) {
		const guint8 *p = record (db, &db->as, AS_REC, i);

		if (i > 0 && be32 (p) <= be32 (p - AS_REC))
			return malformed (error, _("the AS table is not in "
			                           "ascending order"));
		if (pool_string (db, be32 (p + 4), &len) == NULL)
			return malformed (error, _("an AS name lies outside the "
			                           "string pool"));
	}
	for (guint32 i = 0; i < db->countries.count; i++) {
		const guint8 *p = record (db, &db->countries, COUNTRY_REC, i);

		if (!is_upper (p[0]) || !is_upper (p[1]))
			return malformed (error, _("a country has an invalid "
			                           "code"));
		if (!((p[2] == 0 && p[3] == 0) ||
		      (is_upper (p[2]) && is_upper (p[3]))))
			return malformed (error, _("a country has an invalid "
			                           "continent code"));
		if (i > 0 && memcmp (p, p - COUNTRY_REC, 2) <= 0)
			return malformed (error, _("the country table is not in "
			                           "ascending order"));
		if (pool_string (db, be32 (p + 4), &len) == NULL)
			return malformed (error, _("a country name lies outside "
			                           "the string pool"));
	}
	return TRUE;
}

/* Everything after the signature: the header (from the verified copy),
 * the sections, the tables, the tree. */
static gboolean
db_check (FsGeodb *db, const guint8 *hdr, GError **error)
{
	guint64 created = be64 (hdr + H_CREATED_AT);

	if (created == 0 || created > (guint64) G_MAXINT64)
		return malformed (error, _("it has no valid creation time"));
	if (!check_sections (db, hdr, error))
		return FALSE;
	db->vendor = pool_display (db, be32 (hdr + H_VENDOR), FALSE);
	db->description = pool_display (db, be32 (hdr + H_DESCRIPTION), TRUE);
	db->license = pool_display (db, be32 (hdr + H_LICENSE), FALSE);
	if (db->vendor == NULL || db->description == NULL ||
	    db->license == NULL)
		return malformed (error, _("its vendor, description or licence "
		                           "lies outside the string pool"));
	if (!check_tables (db, error) || !check_tree (db, error))
		return FALSE;

	db->info.created_at = (gint64) created;
	db->info.vendor = db->vendor;
	db->info.description = db->description;
	db->info.license = db->license;
	db->info.size = db->size;
	db->info.networks = (guint) db->nets.count;
	db->info.nodes = (guint) db->tree.count;
	db->info.ases = (guint) db->as.count;
	db->info.countries = (guint) db->countries.count;
	return TRUE;
}

/* =============================================================== open */

void
fs_geodb_close (FsGeodb *db)
{
	if (db == NULL)
		return;
	if (db->map != NULL)
		g_mapped_file_unref (db->map);
	g_free (db->vendor);
	g_free (db->description);
	g_free (db->license);
	g_free (db);
}

static gboolean
io_error (GError **error, const gchar *what, int err)
{
	g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_IO,
	             _("Could not read the location database %s: %s."),
	             what, g_strerror (err));
	return FALSE;
}

/* Map an open descriptor (consumed) and verify and check it. */
static FsGeodb *
open_fd (int fd, const gchar *label, GError **error)
{
	struct stat st;
	GMappedFile *map;
	GError *local = NULL;
	FsGeodb *db;
	guint8 *hdr;
	guint slot = 0;

	if (fstat (fd, &st) != 0) {
		io_error (error, label, errno);
		close (fd);
		return NULL;
	}
	if (!S_ISREG (st.st_mode)) {
		close (fd);
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_IO,
		             _("Could not read the location database %s: it is "
		               "not a regular file."), label);
		return NULL;
	}
	if (st.st_size < 0 || (guint64) st.st_size > FS_GEODB_MAX_DB_BYTES) {
		close (fd);
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_TOO_LARGE,
		             _("The location database is larger than %u MB."),
		             FS_GEODB_MAX_DB_BYTES / (1024u * 1024u));
		return NULL;
	}
	if ((guint64) st.st_size < HEADER_END) {
		guint8 head[PREAMBLE_LEN] = { 0 };
		gssize got = read (fd, head, sizeof head);

		close (fd);
		check_preamble (head, got > 0 ? (gsize) got : 0, error);
		if (error != NULL && *error == NULL)
			malformed (error, _("it is shorter than its header"));
		return NULL;
	}
	map = g_mapped_file_new_from_fd (fd, FALSE, &local);
	close (fd);
	if (map == NULL) {
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_IO,
		             _("Could not read the location database %s: %s."),
		             label, local->message);
		g_error_free (local);
		return NULL;
	}
	db = g_new0 (FsGeodb, 1);
	db->map = map;
	db->data = (const guint8 *) g_mapped_file_get_contents (map);
	db->size = g_mapped_file_get_length (map);
	if (db->data == NULL || db->size > FS_GEODB_MAX_DB_BYTES) {
		fs_geodb_close (db);
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_FORMAT,
		             _("The location database changed while it was "
		               "read."));
		return NULL;
	}
	hdr = g_malloc (HEADER_LEN);
	if (!verify (db->data, db->size, hdr, &slot, error) ||
	    !db_check (db, hdr, error)) {
		g_free (hdr);
		fs_geodb_close (db);
		return NULL;
	}
	g_free (hdr);
	db->info.signed_slot = slot;
	return db;
}

FsGeodb *
fs_geodb_open (const gchar *path, GError **error)
{
	int fd;

	g_return_val_if_fail (path != NULL, NULL);
	fd = g_open (path, O_RDONLY | O_BINARY | O_CLOEXEC | O_NOFOLLOW
#ifdef __linux__
	                   | O_NONBLOCK | O_NOCTTY
#endif
	             , 0);
	if (fd < 0) {
		int err = errno;

#ifdef __linux__
		if (err == ELOOP) {
			g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_IO,
			             _("Could not read the location database %s: "
			               "it is a symbolic link."), path);
			return NULL;
		}
#endif
		io_error (error, path, err);
		return NULL;
	}
	return open_fd (fd, path, error);
}

#ifdef FS_GEODB_TESTING
FsGeodb *
fs_geodb_testing_open_unverified (const guint8 *data, gsize size,
                                  GError **error)
{
	FsGeodb *db;
	guint8 hdr[HEADER_LEN];

	if (!check_preamble (data, size, error))
		return NULL;
	if (size > FS_GEODB_MAX_DB_BYTES) {
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_TOO_LARGE,
		             "too large");
		return NULL;
	}
	memcpy (hdr, data + PREAMBLE_LEN, HEADER_LEN);
	db = g_new0 (FsGeodb, 1);
	db->data = data;
	db->size = size;
	if (!db_check (db, hdr, error)) {
		fs_geodb_close (db);
		return NULL;
	}
	db->info.signed_slot = 0;
	return db;
}
#endif

const FsGeodbInfo *
fs_geodb_info (const FsGeodb *db)
{
	g_return_val_if_fail (db != NULL, NULL);
	return &db->info;
}

/* ============================================================= lookup */

void
fs_geodb_match_clear (FsGeodbMatch *match)
{
	if (match == NULL)
		return;
	g_free (match->as_name);
	g_free (match->network);
	memset (match, 0, sizeof *match);
}

/* The deepest network on the path of `addr', starting at `start' (at
 * depth `depth').  Every step is range-checked and the walk ends at
 * depth 128 whatever the file says. */
static guint32
walk (const FsGeodb *db, FsU128 addr, guint32 start, guint depth,
      guint *best_depth)
{
	guint32 index = start, best = NO_NET;
	Node n;

	while (node_get (db, index, &n)) {
		guint32 child;

		if (n.net != NO_NET && (gsize) n.net < db->nets.count) {
			best = n.net;
			*best_depth = depth;
		}
		if (depth >= FS_GEODB_MAX_DEPTH)
			break;
		child = u128_bit (addr, depth) ? n.one : n.zero;
		if (child == 0)
			break;
		index = child;
		depth++;
	}
	return best;
}

static gchar *
as_name_of (const FsGeodb *db, guint32 asn)
{
	gsize lo = 0, hi = db->as.count;

	while (lo < hi) {
		gsize mid = lo + (hi - lo) / 2;
		const guint8 *p = record (db, &db->as, AS_REC, (guint32) mid);
		guint32 number;

		if (p == NULL)
			return NULL;
		number = be32 (p);
		if (number == asn)
			return pool_display (db, be32 (p + 4), FALSE);
		if (number < asn)
			lo = mid + 1;
		else
			hi = mid;
	}
	return NULL;
}

static gboolean
lookup_value (const FsGeodb *db, FsAddrFamily family, guint32 v4, FsU128 v6,
              FsGeodbMatch *match)
{
	FsU128 addr = v6;
	guint32 net;
	guint depth = 0;
	Net n;

	memset (match, 0, sizeof *match);
	if (family == FS_AF_V4) {
		addr = mapped_prefix;
		addr.lo |= v4;
		/* IPv4 is the subtree at ::ffff:0:0/96 and only that */
		if (db->v4_root == NO_NODE)
			return TRUE;
		net = walk (db, addr, db->v4_root, 96, &depth);
	} else {
		net = walk (db, addr, 0, 0, &depth);
	}
	if (net == NO_NET || !net_get (db, net, &n))
		return TRUE;
	match->found = TRUE;
	memcpy (match->country, n.cc, sizeof match->country);
	match->asn = n.asn;
	match->as_name = n.asn != 0 ? as_name_of (db, n.asn) : NULL;
	match->flags = n.flags;
	{
		FsU128 start = u128_and_not (addr, u128_low_mask (128 - depth));

		if (family == FS_AF_V4) {
			match->family = FS_AF_V4;
			match->prefix_len = depth - 96;
		} else {
			match->family = FS_AF_V6;
			match->prefix_len = depth;
		}
		match->network = format_prefix (match->family, start,
		                                match->prefix_len);
	}
	return TRUE;
}

static gboolean
invalid_address (GError **error, const gchar *address)
{
	gchar *shown = display_copy (address, strlen (address), FALSE);

	g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_INVALID,
	             _("\"%s\" is not an IPv4 or IPv6 address."), shown);
	g_free (shown);
	return FALSE;
}

gboolean
fs_geodb_lookup (const FsGeodb *db, const gchar *address,
                 FsGeodbMatch *match, GError **error)
{
	guint32 v4 = 0;
	FsU128 v6 = { 0, 0 };
	FsAddrFamily family;

	g_return_val_if_fail (db != NULL && match != NULL, FALSE);
	memset (match, 0, sizeof *match);
	if (address == NULL)
		return invalid_address (error, "");
	family = fs_addr_parse (address, &v4, &v6);
	if (family == FS_AF_NONE)
		return invalid_address (error, address);
	return lookup_value (db, family, v4, v6, match);
}

gboolean
fs_geodb_lookup_inet (const FsGeodb *db, GInetAddress *address,
                      FsGeodbMatch *match, GError **error)
{
	const guint8 *b;
	FsU128 v6 = { 0, 0 };

	g_return_val_if_fail (db != NULL && match != NULL, FALSE);
	memset (match, 0, sizeof *match);
	if (address == NULL || !G_IS_INET_ADDRESS (address))
		return invalid_address (error, "");
	b = g_inet_address_to_bytes (address);
	if (g_inet_address_get_family (address) == G_SOCKET_FAMILY_IPV4)
		return lookup_value (db, FS_AF_V4, be32 (b), v6, match);
	if (g_inet_address_get_family (address) != G_SOCKET_FAMILY_IPV6)
		return invalid_address (error, "");
	v6.hi = be64 (b);
	v6.lo = be64 (b + 8);
	if (u128_is_mapped (v6))
		return lookup_value (db, FS_AF_V4, (guint32) v6.lo, v6, match);
	return lookup_value (db, FS_AF_V6, 0, v6, match);
}

/* ========================================================== enumerate */

typedef struct
{
	guint8   cc[26 * 26 / 8 + 1];
	GArray  *asns;               /* guint32, sorted, unique */
	guint    flags;
} Filter;

static gint
cmp_u32 (gconstpointer a, gconstpointer b)
{
	guint32 x = *(const guint32 *) a, y = *(const guint32 *) b;

	return x < y ? -1 : x > y;
}

static gboolean
filter_build (const FsGeodbFilter *in, Filter *f, GError **error)
{
	memset (f, 0, sizeof *f);
	f->asns = g_array_new (FALSE, FALSE, sizeof (guint32));
	if (in == NULL)
		return TRUE;
	for (const gchar *const *c = in->countries; c != NULL && *c != NULL;
	     c++) {
		gchar a, b;
		guint bit;

		if (strlen (*c) != 2 || !g_ascii_isalpha ((*c)[0]) ||
		    !g_ascii_isalpha ((*c)[1])) {
			gchar *shown = display_copy (*c, strlen (*c), FALSE);

			g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_INVALID,
			             _("\"%s\" is not a two-letter country "
			               "code."), shown);
			g_free (shown);
			return FALSE;
		}
		a = g_ascii_toupper ((*c)[0]);
		b = g_ascii_toupper ((*c)[1]);
		bit = (guint) (a - 'A') * 26u + (guint) (b - 'A');
		f->cc[bit / 8] |= (guint8) (1u << (bit % 8));
	}
	for (gsize i = 0; in->asns != NULL && i < in->n_asns; i++) {
		if (in->asns[i] == 0) {
			g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_INVALID,
			             _("AS 0 is not a network owner."));
			return FALSE;
		}
		g_array_append_val (f->asns, in->asns[i]);
	}
	g_array_sort (f->asns, cmp_u32);
	for (guint i = 1; i < f->asns->len; ) {
		if (g_array_index (f->asns, guint32, i) ==
		    g_array_index (f->asns, guint32, i - 1))
			g_array_remove_index (f->asns, i);
		else
			i++;
	}
	f->flags = in->flags & FS_GEODB_FLAGS_KNOWN;
	return TRUE;
}

static gboolean
filter_matches (const FsGeodb *db, const Filter *f, guint32 index)
{
	Net n;

	if (!net_get (db, index, &n))
		return FALSE;
	if (n.cc[0] != '\0') {
		guint bit = (guint) (n.cc[0] - 'A') * 26u + (guint) (n.cc[1] - 'A');

		if (f->cc[bit / 8] & (1u << (bit % 8)))
			return TRUE;
	}
	if (n.asn != 0 && f->asns->len > 0 &&
	    bsearch (&n.asn, f->asns->data, f->asns->len, sizeof (guint32),
	             (int (*) (const void *, const void *)) cmp_u32) != NULL)
		return TRUE;
	return (n.flags & f->flags) != 0;
}

/* Intervals arrive in ascending order; adjacent ones are joined here so
 * a whole country is a few thousand intervals, not a million. */
typedef struct
{
	FsRangeSet *set;
	gboolean    have4, have6;
	FsRange4    cur4;
	FsRange6    cur6;
} Collect;

static void
collect (Collect *c, gboolean v4, FsU128 start, guint depth)
{
	FsU128 end = u128_or (start, u128_low_mask (128 - depth));

	if (v4) {
		guint32 s = (guint32) start.lo, e = (guint32) end.lo;

		if (c->have4 && c->cur4.end != G_MAXUINT32 && c->cur4.end + 1 == s) {
			c->cur4.end = e;
			return;
		}
		if (c->have4)
			fs_range_set_add4 (c->set, c->cur4.start, c->cur4.end);
		c->cur4.start = s;
		c->cur4.end = e;
		c->have4 = TRUE;
		return;
	}
	if (c->have6 && !u128_is_max (c->cur6.end) &&
	    u128_eq (u128_inc (c->cur6.end), start)) {
		c->cur6.end = end;
		return;
	}
	if (c->have6)
		fs_range_set_add6 (c->set, c->cur6.start, c->cur6.end);
	c->cur6.start = start;
	c->cur6.end = end;
	c->have6 = TRUE;
}

typedef struct
{
	guint32 node;      /* NO_NODE: a region with no node, only an owner */
	guint   depth;
	FsU128  prefix;
	guint32 owner;     /* the deepest network above (NO_NET: none)      */
} Frame;

/* Depth-first, zero branch first, so regions come out in address
 * order.  Each region that no deeper node splits is owned by the
 * deepest network above it.  `skip' (a node) is neither descended into
 * nor emitted.  At most one visit per node: the tree check proved it,
 * the count enforces it. */
static gboolean
walk_regions (const FsGeodb *db, guint32 start, guint depth, FsU128 prefix,
              guint32 skip, gboolean v4, const Filter *f, Collect *c,
              GError **error)
{
	Frame stack[STACK_MAX];
	gsize top = 0;
	guint64 visits = 0;

	stack[top].node = start;
	stack[top].depth = depth;
	stack[top].prefix = prefix;
	stack[top++].owner = NO_NET;
	while (top > 0) {
		Frame fr = stack[--top];
		guint32 owner;
		Node n;

		if (fr.node == NO_NODE) {
			collect (c, v4, fr.prefix, fr.depth);
			continue;
		}
		if (fr.node == skip)
			continue;
		if (!node_get (db, fr.node, &n) || ++visits > db->tree.count)
			return malformed (error, _("the tree changed while it "
			                           "was read"));
		owner = (n.net != NO_NET && (gsize) n.net < db->nets.count)
		        ? n.net : fr.owner;
		if (n.zero == 0 && n.one == 0) {
			if (filter_matches (db, f, owner))
				collect (c, v4, fr.prefix, fr.depth);
			continue;
		}
		if (fr.depth >= FS_GEODB_MAX_DEPTH)
			return malformed (error, _("the tree is deeper than 128 "
			                           "levels"));
		for (gint b = 1; b >= 0; b--) {
			guint32 child = b ? n.one : n.zero;
			Frame next;

			next.depth = fr.depth + 1;
			next.prefix = fr.prefix;
			next.owner = owner;
			if (b)
				u128_set_bit (&next.prefix, fr.depth);
			if (child == 0 || (gsize) child >= db->tree.count) {
				if (!filter_matches (db, f, owner))
					continue;
				next.node = NO_NODE;
			} else {
				next.node = child;
			}
			if (top >= STACK_MAX)
				return malformed (error, _("the tree is too deep"));
			stack[top++] = next;
		}
	}
	return TRUE;
}

FsRangeSet *
fs_geodb_enumerate (const FsGeodb *db, const FsGeodbFilter *filter,
                    GError **error)
{
	Filter f;
	Collect c = { 0 };
	FsRangeSet *mapped;
	FsU128 zero = { 0, 0 };

	g_return_val_if_fail (db != NULL, NULL);
	if (!filter_build (filter, &f, error)) {
		g_array_unref (f.asns);
		return NULL;
	}
	c.set = fs_range_set_new ();
	if (db->tree.count > 0 &&
	    ((db->v4_root != NO_NODE &&
	      !walk_regions (db, db->v4_root, 96, mapped_prefix, NO_NODE, TRUE,
	                     &f, &c, error)) ||
	     !walk_regions (db, 0, 0, zero, db->v4_root, FALSE, &f, &c,
	                    error))) {
		g_array_unref (f.asns);
		fs_range_set_free (c.set);
		return NULL;
	}
	g_array_unref (f.asns);
	if (c.have4)
		fs_range_set_add4 (c.set, c.cur4.start, c.cur4.end);
	if (c.have6)
		fs_range_set_add6 (c.set, c.cur6.start, c.cur6.end);
	fs_range_set_normalize (c.set);
	/* IPv4-mapped space is IPv4's: never in the IPv6 set */
	mapped = fs_range_set_new ();
	fs_range_set_add6 (mapped, mapped_prefix,
	                   u128_or (mapped_prefix, u128_low_mask (32)));
	fs_range_set_subtract (c.set, mapped);
	fs_range_set_free (mapped);
	return c.set;
}

/* The fewest CIDR blocks covering [start, end] exactly. */
static void
prefixes_of (GPtrArray *out, FsAddrFamily family, FsU128 start, FsU128 end)
{
	guint width = family == FS_AF_V4 ? 32 : 128;

	for (;;) {
		FsU128 span = u128_sub (end, start);   /* size - 1 */
		guint fit = u128_is_max (span) ? 128 : u128_log2 (u128_inc (span));
		guint bits = MIN (u128_ctz (start), fit);

		bits = MIN (bits, width);
		g_ptr_array_add (out, format_prefix (family, start, width - bits));
		if (bits >= 128)
			return;
		{
			FsU128 step = u128_low_mask (bits);
			FsU128 last = u128_or (start, step);

			if (u128_eq (last, end))
				return;
			start = u128_inc (last);
		}
	}
}

GPtrArray *
fs_geodb_set_prefixes (const FsRangeSet *set)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (g_free);

	if (set == NULL)
		return out;
	for (guint i = 0; set->v4 != NULL && i < set->v4->len; i++) {
		const FsRange4 *r = &g_array_index (set->v4, FsRange4, i);
		FsU128 s = { 0, r->start }, e = { 0, r->end };

		prefixes_of (out, FS_AF_V4, s, e);
	}
	for (guint i = 0; set->v6 != NULL && i < set->v6->len; i++) {
		const FsRange6 *r = &g_array_index (set->v6, FsRange6, i);

		prefixes_of (out, FS_AF_V6, r->start, r->end);
	}
	return out;
}

/* ============================================== countries and ASes */

void
fs_geodb_country_free (FsGeodbCountry *country)
{
	if (country == NULL)
		return;
	g_free (country->name);
	g_free (country);
}

void
fs_geodb_as_free (FsGeodbAs *as)
{
	if (as == NULL)
		return;
	g_free (as->name);
	g_free (as);
}

static FsGeodbCountry *
country_at (const FsGeodb *db, guint32 index)
{
	const guint8 *p = record (db, &db->countries, COUNTRY_REC, index);
	FsGeodbCountry *c;
	gchar *name;

	if (p == NULL || (name = pool_display (db, be32 (p + 4), FALSE)) == NULL)
		return NULL;
	c = g_new0 (FsGeodbCountry, 1);
	c->code[0] = (gchar) p[0];
	c->code[1] = (gchar) p[1];
	if (is_upper (p[2]) && is_upper (p[3])) {
		c->continent[0] = (gchar) p[2];
		c->continent[1] = (gchar) p[3];
	}
	c->name = name;
	return c;
}

GPtrArray *
fs_geodb_countries (const FsGeodb *db)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_geodb_country_free);

	g_return_val_if_fail (db != NULL, out);
	for (guint32 i = 0; i < db->countries.count; i++) {
		FsGeodbCountry *c = country_at (db, i);

		if (c != NULL)
			g_ptr_array_add (out, c);
	}
	return out;
}

FsGeodbCountry *
fs_geodb_country (const FsGeodb *db, const gchar *code)
{
	gchar key[2];
	gsize lo = 0, hi;

	g_return_val_if_fail (db != NULL, NULL);
	if (code == NULL || strlen (code) != 2 || !g_ascii_isalpha (code[0]) ||
	    !g_ascii_isalpha (code[1]))
		return NULL;
	key[0] = g_ascii_toupper (code[0]);
	key[1] = g_ascii_toupper (code[1]);
	hi = db->countries.count;
	while (lo < hi) {
		gsize mid = lo + (hi - lo) / 2;
		const guint8 *p = record (db, &db->countries, COUNTRY_REC,
		                          (guint32) mid);
		gint cmp;

		if (p == NULL)
			return NULL;
		cmp = memcmp (p, key, 2);
		if (cmp == 0)
			return country_at (db, (guint32) mid);
		if (cmp < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return NULL;
}

gchar *
fs_geodb_as_name (const FsGeodb *db, guint32 asn)
{
	g_return_val_if_fail (db != NULL, NULL);
	return asn != 0 ? as_name_of (db, asn) : NULL;
}

static gboolean
ascii_icontains (const gchar *hay, gsize hay_len, const gchar *needle,
                 gsize needle_len)
{
	if (needle_len == 0 || needle_len > hay_len)
		return FALSE;
	for (gsize i = 0; i + needle_len <= hay_len; i++)
		if (g_ascii_strncasecmp (hay + i, needle, needle_len) == 0)
			return TRUE;
	return FALSE;
}

GPtrArray *
fs_geodb_search_as (const FsGeodb *db, const gchar *query, guint max)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_geodb_as_free);
	gchar *q;
	const gchar *digits;
	guint64 number = 0;
	gboolean numeric = FALSE;
	gsize q_len;

	g_return_val_if_fail (db != NULL, out);
	if (query == NULL)
		return out;
	q = g_strstrip (g_strdup (query));
	q_len = strlen (q);
	if (q_len == 0 || q_len > FS_GEODB_MAX_STRING) {
		g_free (q);
		return out;
	}
	digits = g_ascii_strncasecmp (q, "AS", 2) == 0 ? q + 2 : q;
	if (*digits != '\0' && strspn (digits, "0123456789") == strlen (digits) &&
	    strlen (digits) <= 10) {
		number = g_ascii_strtoull (digits, NULL, 10);
		numeric = number > 0 && number <= G_MAXUINT32;
	}
	for (guint32 i = 0; i < db->as.count; i++) {
		const guint8 *p = record (db, &db->as, AS_REC, i);
		const gchar *name;
		gsize len = 0;

		if (p == NULL)
			break;
		name = pool_string (db, be32 (p + 4), &len);
		if ((numeric && be32 (p) == number) ||
		    (name != NULL && ascii_icontains (name, len, q, q_len))) {
			FsGeodbAs *as = g_new0 (FsGeodbAs, 1);

			as->asn = be32 (p);
			as->name = name != NULL ? display_copy (name, len, FALSE)
			                        : g_strdup ("");
			g_ptr_array_add (out, as);
			if (max > 0 && out->len >= max)
				break;
		}
	}
	g_free (q);
	return out;
}

/* ============================================================== judge */

static gchar *
format_time (gint64 t)
{
	GDateTime *dt = g_date_time_new_from_unix_utc (t);
	gchar *s;

	if (dt == NULL)
		return g_strdup_printf ("%" G_GINT64_FORMAT, t);
	s = g_date_time_format (dt, "%Y-%m-%d %H:%M UTC");
	g_date_time_unref (dt);
	return s;
}

FsGeodbVerdict
fs_geodb_judge (gint64 offered, gint64 current, gint64 now, gchar **reason)
{
	FsGeodbVerdict v = FS_GEODB_NEWER;
	gchar *a, *b;

	if (reason != NULL)
		*reason = NULL;
	if (offered > 0 && now < G_MAXINT64 - FS_GEODB_FUTURE_SKEW_S &&
	    offered > now + FS_GEODB_FUTURE_SKEW_S)
		v = FS_GEODB_FROM_FUTURE;
	else if (offered <= 0 || (current > 0 && offered < current))
		v = FS_GEODB_OLDER;
	else if (current > 0 && offered == current)
		v = FS_GEODB_SAME;
	if (reason == NULL || v == FS_GEODB_NEWER)
		return v;
	a = format_time (offered);
	b = format_time (current);
	switch (v) {
	case FS_GEODB_FROM_FUTURE:
		*reason = g_strdup_printf (_("The location database says it was "
		                             "created on %s, more than a day "
		                             "ahead of this computer's clock; "
		                             "check the clock."), a);
		break;
	case FS_GEODB_SAME:
		*reason = g_strdup_printf (_("The location database is the copy "
		                             "already in use (created on %s)."),
		                           a);
		break;
	default:
		*reason = current > 0
			? g_strdup_printf (_("The location database was created "
			                     "on %s, before the newest copy "
			                     "already accepted (%s): an older copy "
			                     "never replaces a newer one."), a, b)
			: g_strdup (_("The location database has no creation "
			              "time."));
		break;
	}
	g_free (a);
	g_free (b);
	return v;
}

gboolean
fs_geodb_is_stale (gint64 created_at, gint64 now)
{
	return created_at <= 0 || (now > created_at &&
	                           now - created_at > FS_GEODB_STALE_S);
}

/* ============================================================= unpack */

static gboolean
write_all (int fd, const guint8 *buf, gsize len)
{
	while (len > 0) {
		gssize put = write (fd, buf, (guint) MIN (len, (gsize) G_MAXINT));

		if (put < 0 && errno == EINTR)
			continue;
		if (put <= 0)
			return FALSE;
		buf += put;
		len -= (gsize) put;
	}
	return TRUE;
}

static gboolean
xz_error (GError **error, lzma_ret ret)
{
	const gchar *why;

	switch (ret) {
	case LZMA_MEMLIMIT_ERROR:
		why = _("it needs more memory to decode than allowed");
		break;
	case LZMA_FORMAT_ERROR:
		why = _("it is not an xz file");
		break;
	case LZMA_OPTIONS_ERROR:
		why = _("it uses options this decoder does not support");
		break;
	case LZMA_UNSUPPORTED_CHECK:
		why = _("it uses an integrity check this decoder cannot verify");
		break;
	case LZMA_MEM_ERROR:
		why = _("out of memory");
		break;
	case LZMA_BUF_ERROR:
		why = _("it is truncated");
		break;
	default:
		why = _("it is corrupt");
		break;
	}
	g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_XZ,
	             _("Could not unpack the location database: %s."), why);
	return FALSE;
}

gboolean
fs_geodb_unpack_xz (GBytes *xz, int out_fd, guint64 max_out,
                    guint64 *written, GError **error)
{
	lzma_stream strm = LZMA_STREAM_INIT;
	lzma_ret ret;
	guint8 *out;
	guint64 total = 0;
	gsize in_len = 0;
	const guint8 *in;
	gboolean ok = FALSE;

	if (written != NULL)
		*written = 0;
	if (max_out == 0)
		max_out = FS_GEODB_MAX_DB_BYTES;
	if (xz == NULL || out_fd < 0) {
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_INVALID,
		             _("Nothing to unpack."));
		return FALSE;
	}
	in = g_bytes_get_data (xz, &in_len);
	ret = lzma_stream_decoder (&strm, FS_GEODB_XZ_MEMLIMIT,
	                           LZMA_TELL_UNSUPPORTED_CHECK);
	if (ret != LZMA_OK)
		return xz_error (error, ret);
	strm.next_in = in;
	strm.avail_in = in_len;
	out = g_malloc (XZ_OUT_CHUNK);
	for (;;) {
		gsize produced;

		strm.next_out = out;
		strm.avail_out = XZ_OUT_CHUNK;
		ret = lzma_code (&strm, LZMA_FINISH);
		produced = XZ_OUT_CHUNK - strm.avail_out;
		if (produced > 0) {
			if ((guint64) produced > max_out - total) {
				g_set_error (error, FS_GEODB_ERROR,
				             FS_GEODB_ERR_TOO_LARGE,
				             _("The location database unpacks to "
				               "more than %" G_GUINT64_FORMAT
				               " bytes."), max_out);
				goto done;
			}
			if (!write_all (out_fd, out, produced)) {
				g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_IO,
				             _("Could not write the unpacked "
				               "location database: %s."),
				             g_strerror (errno ? errno : EIO));
				goto done;
			}
			total += produced;
			if (written != NULL)
				*written = total;
		}
		if (ret == LZMA_STREAM_END)
			break;
		if (ret != LZMA_OK) {
			xz_error (error, ret);
			goto done;
		}
	}
	if (strm.avail_in != 0) {
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_XZ,
		             _("Could not unpack the location database: there is "
		               "data after the end of the xz stream."));
		goto done;
	}
	ok = TRUE;
done:
	lzma_end (&strm);
	g_free (out);
	return ok;
}

/* ============================================== install and update */

static GMutex fetcher_lock;
static FsGeodbFetcher fetcher_fn;
static gpointer fetcher_data;

void
fs_geodb_set_fetcher (FsGeodbFetcher fetcher, gpointer user_data)
{
	g_mutex_lock (&fetcher_lock);
	fetcher_fn = fetcher;
	fetcher_data = user_data;
	g_mutex_unlock (&fetcher_lock);
}

static GBytes *
default_fetcher (const gchar *url, const gchar *proxy, gpointer user_data,
                 GError **error)
{
	FsFetchRequest req = { 0 };

	req.url = url;
	req.max_bytes = FS_GEODB_MAX_XZ_BYTES;
	req.timeout_s = FS_GEODB_FETCH_TIMEOUT_S;
	req.proxy = proxy;
	req.user_agent = NULL;          /* fs_fetch: "StockFW/<version>" */
	return fs_fetch (&req, error);
}

#ifdef __linux__
static int
store_dir_open (const gchar *store_dir, GError **error)
{
	int fd;

	if (store_dir == NULL || !g_path_is_absolute (store_dir)) {
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_INVALID,
		             _("The location database store must be an "
		               "absolute path."));
		return -1;
	}
	fd = open (store_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_IO,
		             _("Could not open the location database store %s: "
		               "%s."), store_dir, g_strerror (errno));
	return fd;
}

static FsGeodb *
open_at (int dir, const gchar *name, GError **error)
{
	int fd = openat (dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
	                            O_NONBLOCK | O_NOCTTY);

	if (fd < 0) {
		if (errno == ELOOP)
			g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_IO,
			             _("Could not read the location database %s: "
			               "it is a symbolic link."), name);
		else
			io_error (error, name, errno);
		return NULL;
	}
	return open_fd (fd, name, error);
}

/* Review GEO-TMP-LEAK-2: an install that was killed (SIGKILL, the OOM
 * killer, power loss) leaves its ".location.db.<random>.tmp" behind,
 * up to FS_GEODB_MAX_DB_BYTES each, and the next one picks a new name.
 * Called with the store locked, so no other install is writing one:
 * every regular file of that pattern is removed, never anything else
 * (a symbolic link, a directory) and never through a link. */
static void
sweep_stale_tmp (int dir)
{
	static const gchar prefix[] = "." FS_GEODB_FILE ".";
	int fd = dup (dir);
	DIR *d;
	struct dirent *ent;

	if (fd < 0)
		return;
	if ((d = fdopendir (fd)) == NULL) {
		close (fd);
		return;
	}
	while ((ent = readdir (d)) != NULL) {
		struct stat st;

		if (!g_str_has_prefix (ent->d_name, prefix) ||
		    !g_str_has_suffix (ent->d_name, ".tmp") ||
		    strlen (ent->d_name) <= sizeof prefix - 1 + 4)
			continue;
		if (fstatat (dir, ent->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
		    S_ISREG (st.st_mode))
			unlinkat (dir, ent->d_name, 0);
	}
	closedir (d);   /* closes fd, not dir */
}
#endif

FsGeodb *
fs_geodb_open_store (const gchar *store_dir, GError **error)
{
#ifdef __linux__
	int dir = store_dir_open (store_dir, error);
	FsGeodb *db;

	if (dir < 0)
		return NULL;
	db = open_at (dir, FS_GEODB_FILE, error);
	close (dir);
	return db;
#else
	g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_UNSUPPORTED,
	             _("Country and network-owner blocking is not available "
	               "on this platform yet."));
	return NULL;
#endif
}

FsGeodbOutcome
fs_geodb_install_xz (const gchar *store_dir, GBytes *xz, gint64 now,
                     gint64 min_created, gint64 *created_at, GError **error)
{
#ifdef __linux__
	int dir, fd = -1;
	gchar *tmp = NULL, *reason = NULL;
	gint64 current = 0, floor_at, offered;
	FsGeodb *db;
	FsGeodbOutcome outcome = FS_GEODB_FAILED;
	GError *local = NULL;

	if (created_at != NULL)
		*created_at = 0;
	if ((dir = store_dir_open (store_dir, error)) < 0)
		return FS_GEODB_FAILED;
	/* One install at a time (the lock goes with the descriptor), so
	 * the sweep below never takes another install's file. */
	while (flock (dir, LOCK_EX) != 0) {
		if (errno != EINTR) {
			g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_IO,
			             _("Could not lock the location database "
			               "store: %s."), g_strerror (errno));
			close (dir);
			return FS_GEODB_FAILED;
		}
	}
	sweep_stale_tmp (dir);

	/* The copy in use, if there is a good one. */
	if ((db = open_at (dir, FS_GEODB_FILE, NULL)) != NULL) {
		current = db->info.created_at;
		fs_geodb_close (db);
	}
	if (created_at != NULL)
		*created_at = current;
	/* The floor: never below the newest copy ever accepted, whether or
	 * not the copy in use still verifies (GEO-ROLLBACK-1). */
	floor_at = MAX (current, MAX (min_created, 0));

	if (xz == NULL) {
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_INVALID,
		             _("Nothing to install."));
		close (dir);
		return FS_GEODB_FAILED;
	}
	if (g_bytes_get_size (xz) > FS_GEODB_MAX_XZ_BYTES) {
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_TOO_LARGE,
		             _("The location database download is larger than "
		               "%u MB."), FS_GEODB_MAX_XZ_BYTES / (1024u * 1024u));
		close (dir);
		return FS_GEODB_REFUSED;
	}

	for (guint tries = 0; tries < 16 && fd < 0; tries++) {
		g_free (tmp);
		tmp = g_strdup_printf (".%s.%08x.tmp", FS_GEODB_FILE,
		                       g_random_int ());
		fd = openat (dir, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
		                       O_CLOEXEC, 0600);
		if (fd < 0 && errno != EEXIST)
			break;
	}
	if (fd < 0) {
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_IO,
		             _("Could not write the location database store: "
		               "%s."), g_strerror (errno));
		g_free (tmp);
		close (dir);
		return FS_GEODB_FAILED;
	}

	/* 1. unpack, next to the copy in use */
	if (!fs_geodb_unpack_xz (xz, fd, FS_GEODB_MAX_DB_BYTES, NULL, &local)) {
		outcome = local->code == FS_GEODB_ERR_IO ? FS_GEODB_FAILED
		                                         : FS_GEODB_REFUSED;
		g_propagate_error (error, local);
		goto fail;
	}
	if (fsync (fd) != 0 || close (fd) != 0) {
		fd = -1;
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_IO,
		             _("Could not write the location database store: "
		               "%s."), g_strerror (errno));
		goto fail;
	}
	fd = -1;

	/* 2. and 3. verify and check, from the file as it is on disk */
	if ((db = open_at (dir, tmp, &local)) == NULL) {
		outcome = local->code == FS_GEODB_ERR_IO ? FS_GEODB_FAILED
		                                         : FS_GEODB_REFUSED;
		g_propagate_error (error, local);
		goto fail;
	}
	offered = db->info.created_at;
	fs_geodb_close (db);

	/* 4. judge, against the floor */
	switch (fs_geodb_judge (offered, floor_at, now, &reason)) {
	case FS_GEODB_NEWER:
		break;
	case FS_GEODB_SAME:
		if (offered != current) {
			/* the copy last accepted, again: it repairs a copy in
			 * use that is damaged or gone */
			g_free (reason);
			reason = NULL;
			break;
		}
		outcome = FS_GEODB_UNCHANGED;
		g_free (reason);
		reason = NULL;
		unlinkat (dir, tmp, 0);
		g_free (tmp);
		close (dir);
		return outcome;
	case FS_GEODB_FROM_FUTURE:
		g_set_error_literal (error, FS_GEODB_ERROR, FS_GEODB_ERR_FUTURE,
		                     reason);
		outcome = FS_GEODB_REFUSED;
		goto fail;
	case FS_GEODB_OLDER:
	default:
		g_set_error_literal (error, FS_GEODB_ERROR, FS_GEODB_ERR_ROLLBACK,
		                     reason);
		outcome = FS_GEODB_REFUSED;
		goto fail;
	}

	if (renameat (dir, tmp, dir, FS_GEODB_FILE) != 0) {
		g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_IO,
		             _("Could not write the location database store: "
		               "%s."), g_strerror (errno));
		goto fail;
	}
	fsync (dir);
	close (dir);
	g_free (tmp);
	if (created_at != NULL)
		*created_at = offered;
	return FS_GEODB_UPDATED;

fail:
	g_free (reason);
	if (fd >= 0)
		close (fd);
	unlinkat (dir, tmp, 0);
	g_free (tmp);
	close (dir);
	return outcome;
#else
	if (created_at != NULL)
		*created_at = 0;
	g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_UNSUPPORTED,
	             _("Country and network-owner blocking is not available "
	               "on this platform yet."));
	return FS_GEODB_FAILED;
#endif
}

FsGeodbOutcome
fs_geodb_update (const gchar *store_dir, const gchar *proxy, gint64 now,
                 gint64 min_created, gint64 *created_at, GError **error)
{
	FsGeodbFetcher fn;
	gpointer data;
	GBytes *body;
	FsGeodbOutcome outcome;

	if (created_at != NULL)
		*created_at = 0;
	g_mutex_lock (&fetcher_lock);
	fn = fetcher_fn != NULL ? fetcher_fn : default_fetcher;
	data = fetcher_data;
	g_mutex_unlock (&fetcher_lock);

	body = fn (FS_GEODB_URL, proxy, data, error);
	if (body == NULL) {
		if (error != NULL && *error == NULL)
			g_set_error (error, FS_GEODB_ERROR, FS_GEODB_ERR_IO,
			             _("Could not download the location "
			               "database."));
		/* report the copy still in use */
		if (created_at != NULL) {
			FsGeodb *db = fs_geodb_open_store (store_dir, NULL);

			if (db != NULL) {
				*created_at = db->info.created_at;
				fs_geodb_close (db);
			}
		}
		return FS_GEODB_FAILED;
	}
	outcome = fs_geodb_install_xz (store_dir, body, now, min_created,
	                               created_at, error);
	g_bytes_unref (body);
	return outcome;
}
