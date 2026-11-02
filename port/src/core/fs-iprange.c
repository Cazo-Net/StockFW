/*---[ fs-iprange.c ]----------------------------------------------------
 * Address ranges for the threat-intel engine.  See fs-iprange.h.
 *
 * Everything here is plain arithmetic on host-order integers: IPv4 as a
 * guint32, IPv6 as two guint64 halves.  Text goes in through inet_pton
 * and out through inet_ntop, so nothing here ever resolves a name.
 *--------------------------------------------------------------------*/

#include "core/fs-iprange.h"

#include <gio/gio.h>
#include <string.h>

#ifdef G_OS_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/* ================================================================ u128 */

static const FsU128 U128_ZERO = { 0, 0 };
static const FsU128 U128_MAX  = { G_MAXUINT64, G_MAXUINT64 };

static gint
u128_cmp (FsU128 a, FsU128 b)
{
	if (a.hi != b.hi)
		return a.hi < b.hi ? -1 : 1;
	if (a.lo != b.lo)
		return a.lo < b.lo ? -1 : 1;
	return 0;
}

static gboolean
u128_eq (FsU128 a, FsU128 b)
{
	return a.hi == b.hi && a.lo == b.lo;
}

/* a + 1; the caller makes sure a is not the maximum. */
static FsU128
u128_inc (FsU128 a)
{
	FsU128 r = a;

	r.lo++;
	if (r.lo == 0)
		r.hi++;
	return r;
}

/* a - 1; the caller makes sure a is not zero. */
static FsU128
u128_dec (FsU128 a)
{
	FsU128 r = a;

	if (r.lo == 0)
		r.hi--;
	r.lo--;
	return r;
}

static FsU128
u128_sub (FsU128 a, FsU128 b)
{
	FsU128 r;

	r.lo = a.lo - b.lo;
	r.hi = a.hi - b.hi - (a.lo < b.lo ? 1 : 0);
	return r;
}

static FsU128
u128_and (FsU128 a, FsU128 b)
{
	FsU128 r = { a.hi & b.hi, a.lo & b.lo };
	return r;
}

static FsU128
u128_or (FsU128 a, FsU128 b)
{
	FsU128 r = { a.hi | b.hi, a.lo | b.lo };
	return r;
}

static FsU128
u128_not (FsU128 a)
{
	FsU128 r = { ~a.hi, ~a.lo };
	return r;
}

/* The mask with the low `bits' bits set (0 <= bits <= 128). */
static FsU128
u128_low_mask (guint bits)
{
	FsU128 r = U128_ZERO;

	if (bits >= 128)
		return U128_MAX;
	if (bits >= 64) {
		r.lo = G_MAXUINT64;
		r.hi = bits == 64 ? 0 : (G_MAXUINT64 >> (128 - bits));
	} else if (bits > 0) {
		r.lo = G_MAXUINT64 >> (64 - bits);
	}
	return r;
}

static FsU128
u128_from_bytes (const guint8 b[16])
{
	FsU128 r = U128_ZERO;

	for (guint i = 0; i < 8; i++)
		r.hi = (r.hi << 8) | b[i];
	for (guint i = 8; i < 16; i++)
		r.lo = (r.lo << 8) | b[i];
	return r;
}

static void
u128_to_bytes (FsU128 v, guint8 b[16])
{
	for (gint i = 7; i >= 0; i--) {
		b[i] = (guint8) (v.hi & 0xff);
		v.hi >>= 8;
	}
	for (gint i = 15; i >= 8; i--) {
		b[i] = (guint8) (v.lo & 0xff);
		v.lo >>= 8;
	}
}

/* ::ffff:a.b.c.d -- the IPv4-mapped block, ::ffff:0:0/96. */
static gboolean
u128_is_v4_mapped (FsU128 v)
{
	return v.hi == 0 && (v.lo >> 32) == 0xffffu;
}

/* ======================================================== single values */

static guint32
v4_from_bytes (const guint8 b[4])
{
	return ((guint32) b[0] << 24) | ((guint32) b[1] << 16) |
	       ((guint32) b[2] << 8) | (guint32) b[3];
}

FsAddrFamily
fs_addr_parse (const gchar *text, guint32 *v4, FsU128 *v6)
{
	guint8 buf[16];

	if (text == NULL || *text == '\0')
		return FS_AF_NONE;

	if (inet_pton (AF_INET, text, buf) == 1) {
		if (v4 != NULL)
			*v4 = v4_from_bytes (buf);
		return FS_AF_V4;
	}

	if (inet_pton (AF_INET6, text, buf) == 1) {
		FsU128 v = u128_from_bytes (buf);

		if (u128_is_v4_mapped (v)) {
			if (v4 != NULL)
				*v4 = (guint32) (v.lo & 0xffffffffu);
			return FS_AF_V4;
		}
		if (v6 != NULL)
			*v6 = v;
		return FS_AF_V6;
	}

	return FS_AF_NONE;
}

/* A prefix length: 1 to 3 ASCII digits, nothing else. */
static gboolean
parse_prefix (const gchar *text, guint *out)
{
	guint value = 0;
	gsize n = strlen (text);

	if (n == 0 || n > 3)
		return FALSE;
	for (gsize i = 0; i < n; i++) {
		if (text[i] < '0' || text[i] > '9')
			return FALSE;
		value = value * 10 + (guint) (text[i] - '0');
	}
	*out = value;
	return TRUE;
}

FsAddrFamily
fs_range_parse (const gchar *text, FsRange4 *r4, FsRange6 *r6,
                guint *prefix_len, gboolean *host_bits)
{
	const gchar *dash, *slash;
	FsAddrFamily fam = FS_AF_NONE;
	gboolean hb = FALSE;
	guint plen = 0;
	FsRange4 a4 = { 0, 0 };
	FsRange6 a6 = { { 0, 0 }, { 0, 0 } };

	if (text == NULL || *text == '\0')
		return FS_AF_NONE;

	dash = strchr (text, '-');
	slash = strchr (text, '/');

	if (dash != NULL && slash != NULL)
		return FS_AF_NONE;

	if (dash != NULL) {
		/* a-b: both ends the same family, start <= end.  IPv6 text
		 * never contains '-', so the first one is the separator. */
		gchar *left = g_strndup (text, (gsize) (dash - text));
		const gchar *right = dash + 1;
		guint32 s4 = 0, e4 = 0;
		FsU128 s6 = U128_ZERO, e6 = U128_ZERO;
		FsAddrFamily fl = fs_addr_parse (left, &s4, &s6);
		FsAddrFamily fr = fs_addr_parse (right, &e4, &e6);

		g_free (left);
		if (fl == FS_AF_NONE || fl != fr)
			return FS_AF_NONE;
		if (fl == FS_AF_V4) {
			if (s4 > e4)
				return FS_AF_NONE;
			a4.start = s4;
			a4.end = e4;
		} else {
			if (u128_cmp (s6, e6) > 0)
				return FS_AF_NONE;
			a6.start = s6;
			a6.end = e6;
		}
		fam = fl;
		plen = 0;
	} else if (slash != NULL) {
		gchar *addr = g_strndup (text, (gsize) (slash - text));
		guint8 buf[16];

		if (!parse_prefix (slash + 1, &plen)) {
			g_free (addr);
			return FS_AF_NONE;
		}

		if (inet_pton (AF_INET, addr, buf) == 1) {
			guint32 v = v4_from_bytes (buf);
			guint32 host = plen >= 32 ? 0 :
			               (plen == 0 ? 0xffffffffu :
			                (0xffffffffu >> plen));

			g_free (addr);
			if (plen > 32)
				return FS_AF_NONE;
			hb = (v & host) != 0;
			a4.start = v & ~host;
			a4.end = a4.start | host;
			fam = FS_AF_V4;
		} else if (inet_pton (AF_INET6, addr, buf) == 1) {
			FsU128 v = u128_from_bytes (buf);
			FsU128 host;

			g_free (addr);
			if (plen > 128)
				return FS_AF_NONE;
			host = u128_low_mask (128 - plen);
			hb = !u128_eq (u128_and (v, host), U128_ZERO);

			if (u128_is_v4_mapped (v) && plen >= 96) {
				/* ::ffff:a.b.c.d/n is IPv4 /n-96. */
				guint32 v4v = (guint32) (v.lo & 0xffffffffu);
				guint p4 = plen - 96;
				guint32 h4 = p4 >= 32 ? 0 :
				             (p4 == 0 ? 0xffffffffu :
				              (0xffffffffu >> p4));

				a4.start = v4v & ~h4;
				a4.end = a4.start | h4;
				plen = p4;
				fam = FS_AF_V4;
			} else {
				a6.start = u128_and (v, u128_not (host));
				a6.end = u128_or (a6.start, host);
				fam = FS_AF_V6;
			}
		} else {
			g_free (addr);
			return FS_AF_NONE;
		}
	} else {
		guint32 v4 = 0;
		FsU128 v6 = U128_ZERO;

		fam = fs_addr_parse (text, &v4, &v6);
		if (fam == FS_AF_V4) {
			a4.start = a4.end = v4;
			plen = 32;
		} else if (fam == FS_AF_V6) {
			a6.start = a6.end = v6;
			plen = 128;
		} else {
			return FS_AF_NONE;
		}
	}

	if (fam == FS_AF_V4 && r4 != NULL)
		*r4 = a4;
	if (fam == FS_AF_V6 && r6 != NULL)
		*r6 = a6;
	if (prefix_len != NULL)
		*prefix_len = plen;
	if (host_bits != NULL)
		*host_bits = hb;
	return fam;
}

static void
format_v4 (guint32 v, gchar out[INET_ADDRSTRLEN])
{
	guint8 b[4] = { (guint8) (v >> 24), (guint8) (v >> 16),
	                (guint8) (v >> 8), (guint8) v };

	inet_ntop (AF_INET, b, out, INET_ADDRSTRLEN);
}

static void
format_v6 (FsU128 v, gchar out[INET6_ADDRSTRLEN])
{
	guint8 b[16];

	u128_to_bytes (v, b);
	inet_ntop (AF_INET6, b, out, INET6_ADDRSTRLEN);
}

gchar *
fs_range4_to_string (const FsRange4 *r)
{
	gchar s[INET_ADDRSTRLEN], e[INET_ADDRSTRLEN];
	guint64 size;

	format_v4 (r->start, s);
	if (r->start == r->end)
		return g_strdup (s);

	size = (guint64) r->end - r->start + 1;
	if ((size & (size - 1)) == 0 && (r->start & (guint32) (size - 1)) == 0) {
		guint bits = 0;

		while ((G_GUINT64_CONSTANT (1) << bits) < size)
			bits++;
		return g_strdup_printf ("%s/%u", s, 32 - bits);
	}

	format_v4 (r->end, e);
	return g_strdup_printf ("%s-%s", s, e);
}

gchar *
fs_range6_to_string (const FsRange6 *r)
{
	gchar s[INET6_ADDRSTRLEN], e[INET6_ADDRSTRLEN];

	format_v6 (r->start, s);
	if (u128_eq (r->start, r->end))
		return g_strdup (s);

	/* The interval is exactly one block when, for some host width,
	 * start has none of those bits set and end has all of them. */
	for (guint host = 1; host <= 128; host++) {
		FsU128 m = u128_low_mask (host);

		if (!u128_eq (u128_and (r->start, m), U128_ZERO))
			break;
		if (u128_eq (u128_or (r->start, m), r->end))
			return g_strdup_printf ("%s/%u", s, 128 - host);
	}

	format_v6 (r->end, e);
	return g_strdup_printf ("%s-%s", s, e);
}

guint64
fs_range4_size (const FsRange4 *r)
{
	return (guint64) r->end - r->start + 1;
}

guint64
fs_range6_size (const FsRange6 *r)
{
	FsU128 d = u128_sub (r->end, r->start);

	if (d.hi != 0 || d.lo == G_MAXUINT64)
		return G_MAXUINT64;
	return d.lo + 1;
}

/* ================================================================== sets */

FsRangeSet *
fs_range_set_new (void)
{
	FsRangeSet *set = g_new0 (FsRangeSet, 1);

	set->v4 = g_array_new (FALSE, FALSE, sizeof (FsRange4));
	set->v6 = g_array_new (FALSE, FALSE, sizeof (FsRange6));
	return set;
}

FsRangeSet *
fs_range_set_copy (const FsRangeSet *set)
{
	FsRangeSet *copy = fs_range_set_new ();

	if (set != NULL) {
		g_array_append_vals (copy->v4, set->v4->data, set->v4->len);
		g_array_append_vals (copy->v6, set->v6->data, set->v6->len);
	}
	return copy;
}

void
fs_range_set_free (FsRangeSet *set)
{
	if (set == NULL)
		return;
	g_array_unref (set->v4);
	g_array_unref (set->v6);
	g_free (set);
}

gboolean
fs_range_set_is_empty (const FsRangeSet *set)
{
	return set == NULL || (set->v4->len == 0 && set->v6->len == 0);
}

void
fs_range_set_add4 (FsRangeSet *set, guint32 start, guint32 end)
{
	FsRange4 r = { MIN (start, end), MAX (start, end) };

	g_array_append_val (set->v4, r);
}

void
fs_range_set_add6 (FsRangeSet *set, FsU128 start, FsU128 end)
{
	FsRange6 r;

	if (u128_cmp (start, end) <= 0) {
		r.start = start;
		r.end = end;
	} else {
		r.start = end;
		r.end = start;
	}
	g_array_append_val (set->v6, r);
}

gboolean
fs_range_set_add_text (FsRangeSet *set, const gchar *text)
{
	FsRange4 r4;
	FsRange6 r6;

	switch (fs_range_parse (text, &r4, &r6, NULL, NULL)) {
	case FS_AF_V4:
		g_array_append_val (set->v4, r4);
		return TRUE;
	case FS_AF_V6:
		g_array_append_val (set->v6, r6);
		return TRUE;
	default:
		return FALSE;
	}
}

static gint
cmp4 (gconstpointer a, gconstpointer b)
{
	const FsRange4 *x = a, *y = b;

	if (x->start != y->start)
		return x->start < y->start ? -1 : 1;
	if (x->end != y->end)
		return x->end < y->end ? -1 : 1;
	return 0;
}

static gint
cmp6 (gconstpointer a, gconstpointer b)
{
	const FsRange6 *x = a, *y = b;
	gint c = u128_cmp (x->start, y->start);

	return c != 0 ? c : u128_cmp (x->end, y->end);
}

void
fs_range_set_normalize (FsRangeSet *set)
{
	GArray *out;

	if (set == NULL)
		return;

	/* IPv4: sort, then fold each interval into the previous one when
	 * it overlaps or touches it (prev.end + 1 >= next.start). */
	g_array_sort (set->v4, cmp4);
	out = g_array_sized_new (FALSE, FALSE, sizeof (FsRange4), set->v4->len);
	for (guint i = 0; i < set->v4->len; i++) {
		FsRange4 r = g_array_index (set->v4, FsRange4, i);
		FsRange4 *last = out->len > 0 ?
			&g_array_index (out, FsRange4, out->len - 1) : NULL;

		if (last != NULL &&
		    (last->end == G_MAXUINT32 || r.start <= last->end + 1)) {
			if (r.end > last->end)
				last->end = r.end;
		} else {
			g_array_append_val (out, r);
		}
	}
	g_array_unref (set->v4);
	set->v4 = out;

	g_array_sort (set->v6, cmp6);
	out = g_array_sized_new (FALSE, FALSE, sizeof (FsRange6), set->v6->len);
	for (guint i = 0; i < set->v6->len; i++) {
		FsRange6 r = g_array_index (set->v6, FsRange6, i);
		FsRange6 *last = out->len > 0 ?
			&g_array_index (out, FsRange6, out->len - 1) : NULL;

		if (last != NULL &&
		    (u128_eq (last->end, U128_MAX) ||
		     u128_cmp (r.start, u128_inc (last->end)) <= 0)) {
			if (u128_cmp (r.end, last->end) > 0)
				last->end = r.end;
		} else {
			g_array_append_val (out, r);
		}
	}
	g_array_unref (set->v6);
	set->v6 = out;
}

void
fs_range_set_union (FsRangeSet *into, const FsRangeSet *other)
{
	if (other != NULL) {
		g_array_append_vals (into->v4, other->v4->data, other->v4->len);
		g_array_append_vals (into->v6, other->v6->data, other->v6->len);
	}
	fs_range_set_normalize (into);
}

void
fs_range_set_subtract (FsRangeSet *set, const FsRangeSet *remove)
{
	GArray *out;
	guint j;

	if (set == NULL || remove == NULL)
		return;

	/* Both lists are sorted and disjoint, so one pass with a cursor
	 * into `remove' suffices.  The cursor only skips removals that end
	 * before the current interval starts: a removal can still overlap
	 * the next interval, so it is not consumed. */
	out = g_array_new (FALSE, FALSE, sizeof (FsRange4));
	j = 0;
	for (guint i = 0; i < set->v4->len; i++) {
		FsRange4 a = g_array_index (set->v4, FsRange4, i);
		gboolean alive = TRUE;

		while (j < remove->v4->len &&
		       g_array_index (remove->v4, FsRange4, j).end < a.start)
			j++;

		for (guint k = j; alive && k < remove->v4->len; k++) {
			FsRange4 r = g_array_index (remove->v4, FsRange4, k);

			if (r.start > a.end)
				break;
			if (r.start > a.start) {
				FsRange4 piece = { a.start, r.start - 1 };
				g_array_append_val (out, piece);
			}
			if (r.end >= a.end)
				alive = FALSE;
			else
				a.start = r.end + 1;
		}
		if (alive)
			g_array_append_val (out, a);
	}
	g_array_unref (set->v4);
	set->v4 = out;

	out = g_array_new (FALSE, FALSE, sizeof (FsRange6));
	j = 0;
	for (guint i = 0; i < set->v6->len; i++) {
		FsRange6 a = g_array_index (set->v6, FsRange6, i);
		gboolean alive = TRUE;

		while (j < remove->v6->len &&
		       u128_cmp (g_array_index (remove->v6, FsRange6, j).end,
		                 a.start) < 0)
			j++;

		for (guint k = j; alive && k < remove->v6->len; k++) {
			FsRange6 r = g_array_index (remove->v6, FsRange6, k);

			if (u128_cmp (r.start, a.end) > 0)
				break;
			if (u128_cmp (r.start, a.start) > 0) {
				FsRange6 piece = { a.start, u128_dec (r.start) };
				g_array_append_val (out, piece);
			}
			if (u128_cmp (r.end, a.end) >= 0)
				alive = FALSE;
			else
				a.start = u128_inc (r.end);
		}
		if (alive)
			g_array_append_val (out, a);
	}
	g_array_unref (set->v6);
	set->v6 = out;
}

gboolean
fs_range_set_contains4 (const FsRangeSet *set, guint32 addr)
{
	guint lo = 0, hi;

	if (set == NULL)
		return FALSE;

	/* The last interval whose start is <= addr. */
	hi = set->v4->len;
	while (lo < hi) {
		guint mid = lo + (hi - lo) / 2;

		if (g_array_index (set->v4, FsRange4, mid).start <= addr)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo > 0 && addr <= g_array_index (set->v4, FsRange4, lo - 1).end;
}

gboolean
fs_range_set_contains6 (const FsRangeSet *set, FsU128 addr)
{
	guint lo = 0, hi;

	if (set == NULL)
		return FALSE;

	hi = set->v6->len;
	while (lo < hi) {
		guint mid = lo + (hi - lo) / 2;

		if (u128_cmp (g_array_index (set->v6, FsRange6, mid).start,
		              addr) <= 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo > 0 &&
	       u128_cmp (addr, g_array_index (set->v6, FsRange6, lo - 1).end) <= 0;
}

gboolean
fs_range_set_contains_text (const FsRangeSet *set, const gchar *addr)
{
	guint32 v4;
	FsU128 v6;

	switch (fs_addr_parse (addr, &v4, &v6)) {
	case FS_AF_V4:
		return fs_range_set_contains4 (set, v4);
	case FS_AF_V6:
		return fs_range_set_contains6 (set, v6);
	default:
		return FALSE;
	}
}

guint
fs_range_set_count4 (const FsRangeSet *set)
{
	return set != NULL ? set->v4->len : 0;
}

guint
fs_range_set_count6 (const FsRangeSet *set)
{
	return set != NULL ? set->v6->len : 0;
}

guint64
fs_range_set_addresses4 (const FsRangeSet *set)
{
	guint64 total = 0;

	for (guint i = 0; set != NULL && i < set->v4->len; i++)
		total += fs_range4_size (&g_array_index (set->v4, FsRange4, i));
	return total;
}

guint64
fs_range_set_addresses6 (const FsRangeSet *set)
{
	guint64 total = 0;

	for (guint i = 0; set != NULL && i < set->v6->len; i++) {
		guint64 n = fs_range6_size (&g_array_index (set->v6, FsRange6, i));

		if (total > G_MAXUINT64 - n)
			return G_MAXUINT64;
		total += n;
	}
	return total;
}

/* ============================================================ text form */

gchar *
fs_range_set_to_text (const FsRangeSet *set)
{
	FsRangeSet *norm = fs_range_set_copy (set);
	GString *out = g_string_new (NULL);

	fs_range_set_normalize (norm);
	for (guint i = 0; i < norm->v4->len; i++) {
		gchar *s = fs_range4_to_string (&g_array_index (norm->v4,
		                                                FsRange4, i));
		g_string_append (out, s);
		g_string_append_c (out, '\n');
		g_free (s);
	}
	for (guint i = 0; i < norm->v6->len; i++) {
		gchar *s = fs_range6_to_string (&g_array_index (norm->v6,
		                                                FsRange6, i));
		g_string_append (out, s);
		g_string_append_c (out, '\n');
		g_free (s);
	}
	fs_range_set_free (norm);
	return g_string_free (out, FALSE);
}

FsRangeSet *
fs_range_set_from_text (const gchar *text, GError **error)
{
	FsRangeSet *set = fs_range_set_new ();
	gchar **lines = g_strsplit (text != NULL ? text : "", "\n", -1);

	for (guint i = 0; lines[i] != NULL; i++) {
		gchar *line = g_strstrip (lines[i]);

		if (*line == '\0' || *line == '#')
			continue;
		if (!fs_range_set_add_text (set, line)) {
			g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
			             "line %u: not an address, CIDR or range: %.60s",
			             i + 1, line);
			g_strfreev (lines);
			fs_range_set_free (set);
			return NULL;
		}
	}
	g_strfreev (lines);
	fs_range_set_normalize (set);
	return set;
}

/* ===================================================== protected ranges */

static const gchar *const PROTECTED[] = {
	/* IPv4 */
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
	"224.0.0.0/4", "240.0.0.0/4",
	/* IPv6 (::ffff:0:0/96 is the mapped block: stated as a range so
	 * it stays IPv6 instead of folding into IPv4) */
	"::/128", "::1/128", "::ffff:0.0.0.0-::ffff:255.255.255.255",
	"fe80::/10", "fc00::/7", "ff00::/8",
	NULL
};

const FsRangeSet *
fs_range_protected (void)
{
	static gsize once = 0;
	static FsRangeSet *set = NULL;

	if (g_once_init_enter (&once)) {
		FsRangeSet *s = fs_range_set_new ();

		for (guint i = 0; PROTECTED[i] != NULL; i++) {
			if (g_str_has_prefix (PROTECTED[i], "::ffff:")) {
				/* fs_addr_parse folds mapped addresses into
				 * IPv4, so build this one by hand. */
				FsU128 a = { 0, G_GUINT64_CONSTANT (0xffff00000000) };
				FsU128 b = { 0, G_GUINT64_CONSTANT (0xffffffffffff) };

				fs_range_set_add6 (s, a, b);
				continue;
			}
			if (!fs_range_set_add_text (s, PROTECTED[i]))
				g_warn_if_reached ();
		}
		fs_range_set_normalize (s);
		set = s;
		g_once_init_leave (&once, 1);
	}
	return set;
}

FsRangeSet *
fs_range_set_from_resolv_conf (const gchar *text)
{
	FsRangeSet *set = fs_range_set_new ();
	gchar **lines = g_strsplit (text != NULL ? text : "", "\n", -1);

	for (guint i = 0; lines[i] != NULL; i++) {
		gchar *line = g_strstrip (lines[i]);
		gchar **words;
		guint32 v4;
		FsU128 v6;

		if (!g_str_has_prefix (line, "nameserver"))
			continue;
		words = g_strsplit_set (line, " \t", -1);
		if (g_strcmp0 (words[0], "nameserver") == 0) {
			/* The address is the next non-empty word. */
			for (guint w = 1; words[w] != NULL; w++) {
				gchar *pct;

				if (*words[w] == '\0')
					continue;
				pct = strchr (words[w], '%');
				if (pct != NULL)
					*pct = '\0';
				switch (fs_addr_parse (words[w], &v4, &v6)) {
				case FS_AF_V4:
					fs_range_set_add4 (set, v4, v4);
					break;
				case FS_AF_V6:
					fs_range_set_add6 (set, v6, v6);
					break;
				default:
					break;
				}
				break;
			}
		}
		g_strfreev (words);
	}
	g_strfreev (lines);
	fs_range_set_normalize (set);
	return set;
}
