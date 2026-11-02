/*---[ fs-eventstore.c ]-------------------------------------------------
 * The in-memory event store.  See fs-eventstore.h for the design.
 *--------------------------------------------------------------------*/

#include "core/fs-eventstore.h"
#include "core/fs-iprange.h"

#include <glib/gstdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#ifdef G_OS_WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

/* The time slot of a record: one of these two, or the id of the
 * interned text when the stamp is in no format the store can rebuild. */
#define TIME_FRAC7 0xFFFFFFFFu
#define TIME_SECS  0xFFFFFFFEu

#define DEDUP_KEEP 64

/* Flags of a distinct string, worked out once when it is interned. */
#define ATOM_BLOCKED  (1u << 0)   /* a service carrying "[BLOCKED]" */
#define ATOM_IN       (1u << 1)   /* a direction meaning inbound    */
#define ATOM_OUT      (1u << 2)   /* a direction meaning outbound   */

typedef struct
{
	gint64  ticks;                   /* 100 ns since 1970, UTC        */
	guint32 id[FS_EV_N_FIELDS];      /* [FS_EV_TIME]: see TIME_*      */
} Rec;

typedef struct
{
	gchar   *str;      /* NULL while the id is free                   */
	guint32  refs;     /* records using it (id 0 is never freed)       */
	guint32  serial;   /* new on each reuse of the id: query caches    */
	guint32  flags;    /* ATOM_*                                       */
} Atom;

struct _FsEventStore
{
	Rec        *ring;
	guint       capacity;
	guint       length;
	guint       first_slot;   /* slot of the oldest event              */
	guint64     first_seq;    /* its seq; the next one is first+length */

	GArray     *atoms;        /* Atom, indexed by id                   */
	GHashTable *atom_index;   /* str (owned by the Atom) -> id         */
	GArray     *free_ids;     /* guint32                               */
	guint32     next_serial;
	guint       n_strings;
	gsize       string_bytes;

	/* The id each field interned last: consecutive events share most
	 * of their fields, and a strcmp is cheaper than a hash lookup. */
	guint32     last_id[FS_EV_N_FIELDS];

	guint64     dedup[DEDUP_KEEP];
	guint       dedup_n;
	guint       dedup_pos;

	FsEventEvictFunc evict_func;
	gpointer         evict_data;
};

/* ------------------------------------------------------------ helpers */

static inline guint
slot_of (const FsEventStore *s, guint64 seq)
{
	guint64 off = seq - s->first_seq;

	return (guint) ((s->first_slot + off) % s->capacity);
}

static inline const Rec *
rec_of (const FsEventStore *s, guint64 seq)
{
	if (s == NULL || seq < s->first_seq ||
	    seq >= s->first_seq + s->length)
		return NULL;

	return &s->ring[slot_of (s, seq)];
}

static inline Atom *
atom_at (const FsEventStore *s, guint32 id)
{
	return &g_array_index (s->atoms, Atom, id);
}

static guint32
atom_flags_for (const gchar *str, FsEventField field)
{
	guint32 flags = 0;

	if (field == FS_EV_SERVICE && strstr (str, "[BLOCKED]") != NULL)
		flags |= ATOM_BLOCKED;

	if (field == FS_EV_DIRECTION) {
		if (g_ascii_strcasecmp (str, "in") == 0 ||
		    g_ascii_strcasecmp (str, "inbound") == 0)
			flags |= ATOM_IN;
		else if (g_ascii_strcasecmp (str, "out") == 0 ||
		         g_ascii_strcasecmp (str, "outbound") == 0)
			flags |= ATOM_OUT;
	}

	return flags;
}

/* [ intern ]
 * The id for str, one more reference taken.  The flags are per field
 * kind, but a string is interned once whatever field it came in: the
 * flags a field needs are ORed in when that field first meets it. */
static guint32
intern (FsEventStore *s, const gchar *str, FsEventField field)
{
	gpointer value;
	guint32 id;
	Atom *a;

	if (str == NULL || *str == '\0')
		return 0;

	/* The same text as this field's last event: no hash. */
	id = s->last_id[field];
	if (id != 0 && id < s->atoms->len) {
		a = atom_at (s, id);
		if (a->str != NULL && strcmp (a->str, str) == 0) {
			a->refs++;
			a->flags |= atom_flags_for (str, field);
			return id;
		}
	}

	if (g_hash_table_lookup_extended (s->atom_index, str, NULL, &value)) {
		id = GPOINTER_TO_UINT (value);
		a = atom_at (s, id);
		a->refs++;
		a->flags |= atom_flags_for (str, field);
		s->last_id[field] = id;
		return id;
	}

	if (s->free_ids->len > 0) {
		id = g_array_index (s->free_ids, guint32, s->free_ids->len - 1);
		g_array_set_size (s->free_ids, s->free_ids->len - 1);
	} else {
		Atom blank = { NULL, 0, 0, 0 };

		id = s->atoms->len;
		g_array_append_val (s->atoms, blank);
	}

	a = atom_at (s, id);
	a->str = g_strdup (str);
	a->refs = 1;
	a->serial = ++s->next_serial;
	a->flags = atom_flags_for (str, field);
	g_hash_table_insert (s->atom_index, a->str, GUINT_TO_POINTER (id));
	s->n_strings++;
	s->string_bytes += strlen (str) + 1;
	s->last_id[field] = id;

	return id;
}

static void
release (FsEventStore *s, guint32 id)
{
	Atom *a;

	if (id == 0 || id >= s->atoms->len)
		return;

	a = atom_at (s, id);
	if (a->str == NULL || a->refs == 0)
		return;

	if (--a->refs > 0)
		return;

	g_hash_table_remove (s->atom_index, a->str);
	s->string_bytes -= strlen (a->str) + 1;
	g_free (a->str);
	a->str = NULL;
	a->flags = 0;
	s->n_strings--;
	g_array_append_val (s->free_ids, id);

	for (guint f = 0; f < FS_EV_N_FIELDS; f++)
		if (s->last_id[f] == id)
			s->last_id[f] = 0;
}

static void
release_rec (FsEventStore *s, const Rec *r)
{
	for (guint f = 0; f < FS_EV_N_FIELDS; f++) {
		if (f == FS_EV_TIME &&
		    (r->id[f] == TIME_FRAC7 || r->id[f] == TIME_SECS))
			continue;
		release (s, r->id[f]);
	}
}

/* [ rec_key ]
 * What makes two records the same event, as a 64-bit hash: every
 * field, and the time -- as ticks when the stamp was read, as the
 * text otherwise (the time an unreadable stamp was received is not
 * part of the event). */
static guint64
rec_key (const Rec *r)
{
	guint64 h = 1469598103934665603ull;   /* FNV-1a 64 */
	gboolean parsed = r->id[FS_EV_TIME] == TIME_FRAC7 ||
	                  r->id[FS_EV_TIME] == TIME_SECS;
	guint64 words[FS_EV_N_FIELDS + 1];

	words[0] = parsed ? (guint64) r->ticks : 0;
	for (guint f = 0; f < FS_EV_N_FIELDS; f++)
		words[f + 1] = r->id[f];

	for (guint i = 0; i < G_N_ELEMENTS (words); i++) {
		guint64 w = words[i];

		for (guint b = 0; b < 8; b++) {
			h ^= (w >> (b * 8)) & 0xffu;
			h *= 1099511628211ull;
		}
	}

	return h;
}

/* ------------------------------------------------------------- times */

/* Days since 1970-01-01 of a civil date, and back (H. Hinnant's
 * algorithms; proleptic Gregorian, valid far beyond any log). */
static gint64
days_from_civil (gint64 y, guint m, guint d)
{
	gint64 era;
	guint yoe, doy, doe;

	y -= m <= 2;
	era = (y >= 0 ? y : y - 399) / 400;
	yoe = (guint) (y - era * 400);
	doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
	doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return era * 146097 + (gint64) doe - 719468;
}

static void
civil_from_days (gint64 z, gint64 *y, guint *m, guint *d)
{
	gint64 era;
	guint doe, yoe, doy, mp;

	z += 719468;
	era = (z >= 0 ? z : z - 146096) / 146097;
	doe = (guint) (z - era * 146097);
	yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	*y = (gint64) yoe + era * 400;
	doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	mp = (5 * doy + 2) / 153;
	*d = doy - (153 * mp + 2) / 5 + 1;
	*m = mp < 10 ? mp + 3 : mp - 9;
	*y += *m <= 2;
}

static gboolean
digits (const gchar *p, guint n, guint *out)
{
	guint v = 0;

	for (guint i = 0; i < n; i++) {
		if (p[i] < '0' || p[i] > '9')
			return FALSE;
		v = v * 10 + (guint) (p[i] - '0');
	}
	*out = v;
	return TRUE;
}

FsEventTimeFormat
fs_event_time_parse (const gchar *t, gint64 *ticks)
{
	guint y, mo, d, h, mi, s, frac = 0;
	gsize len;
	FsEventTimeFormat fmt;

	if (t == NULL)
		return FS_EVENT_TIME_OTHER;

	len = strlen (t);
	if (len == 20 && t[19] == 'Z')
		fmt = FS_EVENT_TIME_SECS;
	else if (len == 28 && t[19] == '.' && t[27] == 'Z' &&
	         digits (t + 20, 7, &frac))
		fmt = FS_EVENT_TIME_FRAC7;
	else
		return FS_EVENT_TIME_OTHER;

	if (!digits (t, 4, &y) || t[4] != '-' ||
	    !digits (t + 5, 2, &mo) || t[7] != '-' ||
	    !digits (t + 8, 2, &d) || t[10] != 'T' ||
	    !digits (t + 11, 2, &h) || t[13] != ':' ||
	    !digits (t + 14, 2, &mi) || t[16] != ':' ||
	    !digits (t + 17, 2, &s))
		return FS_EVENT_TIME_OTHER;

	if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 ||
	    s > 59 || y < 1970)
		return FS_EVENT_TIME_OTHER;

	/* A day past the month's end would not come back as the same
	 * text; such a stamp is kept as text. */
	{
		static const guint mdays[] = { 31, 29, 31, 30, 31, 30,
		                               31, 31, 30, 31, 30, 31 };
		gboolean leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;

		if (d > mdays[mo - 1] || (mo == 2 && d == 29 && !leap))
			return FS_EVENT_TIME_OTHER;
	}

	if (ticks != NULL) {
		gint64 days = days_from_civil (y, mo, d);

		*ticks = ((days * 86400 + h * 3600 + mi * 60 + s) *
		          (gint64) 10000000) + frac;
	}

	return fmt;
}

static void
split_ticks (gint64 ticks, gint64 *y, guint *mo, guint *d, guint *h,
             guint *mi, guint *s, guint *frac)
{
	gint64 secs = ticks / 10000000;
	gint64 rem = ticks % 10000000;
	gint64 days, sod;

	if (rem < 0) {
		rem += 10000000;
		secs--;
	}
	days = secs / 86400;
	sod = secs % 86400;
	if (sod < 0) {
		sod += 86400;
		days--;
	}

	civil_from_days (days, y, mo, d);
	*h = (guint) (sod / 3600);
	*mi = (guint) ((sod / 60) % 60);
	*s = (guint) (sod % 60);
	*frac = (guint) rem;
}

void
fs_event_time_format (gint64 ticks, FsEventTimeFormat format,
                      gchar buf[FS_EVENT_TIME_BUF])
{
	gint64 y;
	guint mo, d, h, mi, s, frac;

	split_ticks (ticks, &y, &mo, &d, &h, &mi, &s, &frac);

	if (format == FS_EVENT_TIME_FRAC7)
		g_snprintf (buf, FS_EVENT_TIME_BUF,
		            "%04d-%02u-%02uT%02u:%02u:%02u.%07uZ",
		            (gint) y, mo, d, h, mi, s, frac);
	else
		g_snprintf (buf, FS_EVENT_TIME_BUF,
		            "%04d-%02u-%02uT%02u:%02u:%02uZ",
		            (gint) y, mo, d, h, mi, s);
}

void
fs_event_time_day (gint64 ticks, gchar buf[16])
{
	gint64 y;
	guint mo, d, h, mi, s, frac;

	split_ticks (ticks, &y, &mo, &d, &h, &mi, &s, &frac);
	g_snprintf (buf, 16, "%04d-%02u-%02u", (gint) y, mo, d);
}

/* ------------------------------------------------------------- store */

FsEventStore *
fs_eventstore_new (guint capacity)
{
	FsEventStore *s = g_new0 (FsEventStore, 1);
	Atom empty = { g_strdup (""), 1, 0, 0 };

	s->capacity = CLAMP (capacity, FS_EVENTSTORE_MIN_CAPACITY,
	                     FS_EVENTSTORE_MAX_CAPACITY);
	s->ring = g_new (Rec, s->capacity);
	s->first_seq = 1;

	s->atoms = g_array_new (FALSE, FALSE, sizeof (Atom));
	g_array_append_val (s->atoms, empty);        /* id 0: "" */
	s->atom_index = g_hash_table_new (g_str_hash, g_str_equal);
	s->free_ids = g_array_new (FALSE, FALSE, sizeof (guint32));

	return s;
}

void
fs_eventstore_free (FsEventStore *s)
{
	if (s == NULL)
		return;

	for (guint i = 0; i < s->atoms->len; i++)
		g_free (atom_at (s, i)->str);

	g_array_unref (s->atoms);
	g_hash_table_destroy (s->atom_index);
	g_array_unref (s->free_ids);
	g_free (s->ring);
	g_free (s);
}

void
fs_eventstore_set_evict_func (FsEventStore *s, FsEventEvictFunc func,
                              gpointer user_data)
{
	g_return_if_fail (s != NULL);

	s->evict_func = func;
	s->evict_data = user_data;
}

guint
fs_eventstore_capacity (const FsEventStore *s)
{
	return s != NULL ? s->capacity : 0;
}

/* [ drop_oldest ] -- the evict func first, while the event reads. */
static void
drop_oldest (FsEventStore *s)
{
	Rec *r = &s->ring[s->first_slot];

	if (s->evict_func != NULL)
		s->evict_func (s, s->first_seq, s->evict_data);

	release_rec (s, r);
	s->first_slot = (s->first_slot + 1) % s->capacity;
	s->first_seq++;
	s->length--;
}

guint
fs_eventstore_set_capacity (FsEventStore *s, guint capacity)
{
	Rec *ring;

	g_return_val_if_fail (s != NULL, 0);

	capacity = CLAMP (capacity, FS_EVENTSTORE_MIN_CAPACITY,
	                  FS_EVENTSTORE_MAX_CAPACITY);
	if (capacity == s->capacity)
		return capacity;

	while (s->length > capacity)
		drop_oldest (s);

	/* Lay the events out from slot 0 in the new ring. */
	ring = g_new (Rec, capacity);
	for (guint i = 0; i < s->length; i++)
		ring[i] = s->ring[(s->first_slot + i) % s->capacity];

	g_free (s->ring);
	s->ring = ring;
	s->capacity = capacity;
	s->first_slot = 0;

	return capacity;
}

guint64
fs_eventstore_append (FsEventStore *s, const FsHit *hit, gint64 received_us)
{
	const gchar *fields[FS_EV_N_FIELDS];
	FsEventTimeFormat fmt;
	Rec rec;
	guint64 key;
	guint64 seq;

	if (s == NULL || hit == NULL)
		return 0;

	fields[FS_EV_TIME]        = hit->time;
	fields[FS_EV_DIRECTION]   = hit->direction;
	fields[FS_EV_IN]          = hit->in;
	fields[FS_EV_OUT]         = hit->out;
	fields[FS_EV_PORT]        = hit->port;
	fields[FS_EV_SOURCE]      = hit->source;
	fields[FS_EV_DESTINATION] = hit->destination;
	fields[FS_EV_LENGTH]      = hit->length;
	fields[FS_EV_TOS]         = hit->tos;
	fields[FS_EV_PROTOCOL]    = hit->protocol;
	fields[FS_EV_SERVICE]     = hit->service;
	fields[FS_EV_RULE]        = hit->rule;

	fmt = fs_event_time_parse (hit->time, &rec.ticks);
	if (fmt == FS_EVENT_TIME_FRAC7)
		rec.id[FS_EV_TIME] = TIME_FRAC7;
	else if (fmt == FS_EVENT_TIME_SECS)
		rec.id[FS_EV_TIME] = TIME_SECS;
	else {
		rec.ticks = received_us * 10;
		rec.id[FS_EV_TIME] = intern (s, hit->time, FS_EV_TIME);
	}

	for (guint f = FS_EV_DIRECTION; f < FS_EV_N_FIELDS; f++)
		rec.id[f] = intern (s, fields[f], (FsEventField) f);

	/* The same event as one of the last few accepted: refused, and
	 * its references handed back. */
	key = rec_key (&rec);
	for (guint i = 0; i < s->dedup_n; i++) {
		if (s->dedup[i] == key) {
			release_rec (s, &rec);
			return 0;
		}
	}

	s->dedup[s->dedup_pos] = key;
	s->dedup_pos = (s->dedup_pos + 1) % DEDUP_KEEP;
	if (s->dedup_n < DEDUP_KEEP)
		s->dedup_n++;

	if (s->length == s->capacity)
		drop_oldest (s);

	seq = s->first_seq + s->length;
	s->ring[(s->first_slot + s->length) % s->capacity] = rec;
	s->length++;

	return seq;
}

void
fs_eventstore_clear (FsEventStore *s)
{
	if (s == NULL)
		return;

	while (s->length > 0) {
		release_rec (s, &s->ring[s->first_slot]);
		s->first_slot = (s->first_slot + 1) % s->capacity;
		s->first_seq++;
		s->length--;
	}

	s->first_slot = 0;
	s->dedup_n = 0;
	s->dedup_pos = 0;
}

guint
fs_eventstore_length (const FsEventStore *s)
{
	return s != NULL ? s->length : 0;
}

guint64
fs_eventstore_first_seq (const FsEventStore *s)
{
	return (s != NULL && s->length > 0) ? s->first_seq : 0;
}

guint64
fs_eventstore_last_seq (const FsEventStore *s)
{
	return (s != NULL && s->length > 0)
	       ? s->first_seq + s->length - 1 : 0;
}

gboolean
fs_eventstore_has (const FsEventStore *s, guint64 seq)
{
	return rec_of (s, seq) != NULL;
}

gint64
fs_eventstore_ticks (const FsEventStore *s, guint64 seq)
{
	const Rec *r = rec_of (s, seq);

	return r != NULL ? r->ticks : 0;
}

gint64
fs_eventstore_time_us (const FsEventStore *s, guint64 seq)
{
	return fs_eventstore_ticks (s, seq) / 10;
}

const gchar *
fs_eventstore_field (const FsEventStore *s, guint64 seq, FsEventField field)
{
	const Rec *r = rec_of (s, seq);
	guint32 id;

	if (r == NULL || field >= FS_EV_N_FIELDS)
		return "";

	id = r->id[field];
	if (field == FS_EV_TIME && (id == TIME_FRAC7 || id == TIME_SECS))
		return "";

	return atom_at (s, id)->str;
}

const gchar *
fs_eventstore_time_text (const FsEventStore *s, guint64 seq,
                         gchar buf[FS_EVENT_TIME_BUF])
{
	const Rec *r = rec_of (s, seq);

	buf[0] = '\0';
	if (r == NULL)
		return buf;

	if (r->id[FS_EV_TIME] == TIME_FRAC7) {
		fs_event_time_format (r->ticks, FS_EVENT_TIME_FRAC7, buf);
		return buf;
	}
	if (r->id[FS_EV_TIME] == TIME_SECS) {
		fs_event_time_format (r->ticks, FS_EVENT_TIME_SECS, buf);
		return buf;
	}

	return atom_at (s, r->id[FS_EV_TIME])->str;
}

static guint32
rec_flags (const FsEventStore *s, const Rec *r, FsEventField f)
{
	return atom_at (s, r->id[f])->flags;
}

gboolean
fs_eventstore_is_blocked (const FsEventStore *s, guint64 seq)
{
	const Rec *r = rec_of (s, seq);

	return r != NULL && (rec_flags (s, r, FS_EV_SERVICE) & ATOM_BLOCKED);
}

gboolean
fs_eventstore_is_inbound (const FsEventStore *s, guint64 seq)
{
	const Rec *r = rec_of (s, seq);

	return r != NULL && (rec_flags (s, r, FS_EV_DIRECTION) & ATOM_IN);
}

gboolean
fs_eventstore_is_outbound (const FsEventStore *s, guint64 seq)
{
	const Rec *r = rec_of (s, seq);

	return r != NULL && (rec_flags (s, r, FS_EV_DIRECTION) & ATOM_OUT);
}

static gchar *
dup_or_null (const gchar *s)
{
	return (s != NULL && *s != '\0') ? g_strdup (s) : NULL;
}

FsHit *
fs_eventstore_get_hit (const FsEventStore *s, guint64 seq)
{
	gchar buf[FS_EVENT_TIME_BUF];
	FsHit *hit;

	if (!fs_eventstore_has (s, seq))
		return NULL;

	hit = fs_hit_new ();
	hit->time        = g_strdup (fs_eventstore_time_text (s, seq, buf));
	hit->direction   = g_strdup (fs_eventstore_field (s, seq, FS_EV_DIRECTION));
	hit->in          = g_strdup (fs_eventstore_field (s, seq, FS_EV_IN));
	hit->out         = g_strdup (fs_eventstore_field (s, seq, FS_EV_OUT));
	hit->port        = g_strdup (fs_eventstore_field (s, seq, FS_EV_PORT));
	hit->source      = g_strdup (fs_eventstore_field (s, seq, FS_EV_SOURCE));
	hit->destination = g_strdup (fs_eventstore_field (s, seq, FS_EV_DESTINATION));
	hit->length      = g_strdup (fs_eventstore_field (s, seq, FS_EV_LENGTH));
	hit->tos         = g_strdup (fs_eventstore_field (s, seq, FS_EV_TOS));
	hit->protocol    = g_strdup (fs_eventstore_field (s, seq, FS_EV_PROTOCOL));
	hit->service     = g_strdup (fs_eventstore_field (s, seq, FS_EV_SERVICE));
	hit->rule        = dup_or_null (fs_eventstore_field (s, seq, FS_EV_RULE));

	return hit;
}

guint32
fs_eventstore_field_id (const FsEventStore *s, guint64 seq, FsEventField field)
{
	const Rec *r = rec_of (s, seq);

	if (r == NULL || field >= FS_EV_N_FIELDS)
		return 0;
	if (field == FS_EV_TIME &&
	    (r->id[field] == TIME_FRAC7 || r->id[field] == TIME_SECS))
		return 0;

	return r->id[field];
}

const gchar *
fs_eventstore_atom (const FsEventStore *s, guint32 id)
{
	if (s == NULL || id >= s->atoms->len)
		return NULL;

	return atom_at (s, id)->str;
}

guint
fs_eventstore_n_atoms (const FsEventStore *s)
{
	return s != NULL ? s->atoms->len : 0;
}

guint
fs_eventstore_n_strings (const FsEventStore *s)
{
	return s != NULL ? s->n_strings : 0;
}

gsize
fs_eventstore_memory (const FsEventStore *s)
{
	gsize bytes;

	if (s == NULL)
		return 0;

	bytes = sizeof (*s) + (gsize) s->capacity * sizeof (Rec);
	bytes += (gsize) s->atoms->len * sizeof (Atom);
	bytes += (gsize) s->free_ids->len * sizeof (guint32);
	/* The hash table: a key, a value and a hash per entry, about. */
	bytes += (gsize) s->n_strings * (sizeof (gpointer) * 2 + sizeof (guint));
	/* Each string with a rough malloc header. */
	bytes += s->string_bytes + (gsize) s->n_strings * 16;

	return bytes;
}

/* ----------------------------------------------------------- queries */

G_DEFINE_QUARK (fs-eventquery-error-quark, fs_eventquery_error)

#define BIT_TEXT  (1u << 0)
#define BIT_PROTO (1u << 1)
#define BIT_PORT  (1u << 2)
#define BIT_ADDR  (1u << 3)

typedef struct
{
	guint32 serial;    /* the atom's serial these bits are for */
	guint32 bits;      /* BIT_* the string passes                */
} CacheEnt;

struct _FsEventQuery
{
	gchar               *text;       /* NULL: no text test          */
	gboolean             text_timeish; /* could be in a time stamp  */
	gint64               time_sec;   /* the second in time_text      */
	gchar                time_text[FS_EVENT_TIME_BUF]; /* "...:SSZ"  */
	FsEventDirFilter     direction;
	gchar               *protocol;
	gboolean             has_port;
	guint                port_lo, port_hi;
	FsRangeSet          *addresses;  /* NULL: no address test       */
	FsEventActionFilter  action;
	gint64               since_ticks; /* 0: open                     */
	gint64               until_ticks;

	const FsEventStore  *cache_store;
	GArray              *cache;      /* CacheEnt by atom id         */
};

static gboolean
ascii_case_contains (const gchar *haystack, const gchar *needle)
{
	gsize nlen = strlen (needle);

	if (nlen == 0)
		return TRUE;

	for (const gchar *p = haystack; *p != '\0'; p++) {
		gsize i;

		for (i = 0; i < nlen; i++) {
			if (p[i] == '\0' ||
			    g_ascii_tolower (p[i]) != g_ascii_tolower (needle[i]))
				break;
		}
		if (i == nlen)
			return TRUE;
	}

	return FALSE;
}

/* "443", "1000-2000", "1000:2000". */
static gboolean
parse_port_spec (const gchar *text, guint *lo, guint *hi)
{
	gchar **parts;
	gboolean ok = TRUE;
	guint64 a, b;
	gchar *end;

	if (strchr (text, '-') != NULL)
		parts = g_strsplit (text, "-", 2);
	else
		parts = g_strsplit (text, ":", 2);

	for (guint i = 0; parts[i] != NULL; i++) {
		g_strstrip (parts[i]);
		if (*parts[i] == '\0' || !g_ascii_isdigit (*parts[i]))
			ok = FALSE;
	}

	if (ok) {
		a = g_ascii_strtoull (parts[0], &end, 10);
		ok = *end == '\0' && a <= 65535;
		b = a;
		if (ok && parts[1] != NULL) {
			b = g_ascii_strtoull (parts[1], &end, 10);
			ok = *end == '\0' && b <= 65535 && a <= b;
		}
		*lo = (guint) a;
		*hi = (guint) b;
	}

	g_strfreev (parts);
	return ok;
}

/* Only text that could be part of "2026-11-02T10:00:00.0000000Z" can
 * be in a stamp: its characters, at most one '.', two '-', two ':'.
 * Other searches (an address has three dots) never format a time. */
static gboolean
could_be_in_stamp (const gchar *t)
{
	guint dots = 0, dashes = 0, colons = 0;

	if (t[strspn (t, "0123456789-:.TtZz")] != '\0')
		return FALSE;
	for (; *t != '\0'; t++) {
		dots += *t == '.';
		dashes += *t == '-';
		colons += *t == ':';
	}
	return dots <= 1 && dashes <= 2 && colons <= 2;
}

/* The time as the list shows it.  The text up to the second is made
 * once per second (the rows come in time order, mostly), the fraction
 * by hand: a search over a million stamps stays a few tens of ms. */
static const gchar *
query_time_text (FsEventQuery *q, const Rec *r, gchar buf[FS_EVENT_TIME_BUF])
{
	gint64 sec;
	gsize len;

	if (r->ticks < 0) {
		fs_event_time_format (r->ticks, r->id[FS_EV_TIME] == TIME_FRAC7
		                      ? FS_EVENT_TIME_FRAC7 : FS_EVENT_TIME_SECS,
		                      buf);
		return buf;
	}

	sec = r->ticks / 10000000;
	if (sec != q->time_sec) {
		fs_event_time_format (sec * 10000000, FS_EVENT_TIME_SECS,
		                      q->time_text);
		q->time_sec = sec;
	}
	if (r->id[FS_EV_TIME] != TIME_FRAC7)
		return q->time_text;

	len = strlen (q->time_text) - 1;          /* without the Z */
	memcpy (buf, q->time_text, len);
	buf[len] = '.';
	for (gint i = 7, frac = (gint) (r->ticks % 10000000); i >= 1; i--) {
		buf[len + (gsize) i] = (gchar) ('0' + frac % 10);
		frac /= 10;
	}
	buf[len + 8] = 'Z';
	buf[len + 9] = '\0';
	return buf;
}

FsEventQuery *
fs_eventquery_new (const FsEventFilter *f, GError **error)
{
	FsEventQuery *q = g_new0 (FsEventQuery, 1);

	if (f == NULL)
		return q;

	if (f->text != NULL) {
		gchar *t = g_strstrip (g_strdup (f->text));

		if (*t != '\0') {
			q->text = t;
			q->text_timeish = could_be_in_stamp (t);
			q->time_sec = G_MININT64;
		} else {
			g_free (t);
		}
	}

	if (f->protocol != NULL) {
		gchar *p = g_strstrip (g_strdup (f->protocol));

		if (*p != '\0')
			q->protocol = p;
		else
			g_free (p);
	}

	if (f->port != NULL) {
		gchar *p = g_strstrip (g_strdup (f->port));

		if (*p != '\0') {
			if (!parse_port_spec (p, &q->port_lo, &q->port_hi)) {
				g_set_error (error, FS_EVENTQUERY_ERROR,
				             FS_EVENTQUERY_ERROR_PORT,
				             "\"%s\" is not a port (0-65535) or a "
				             "range such as 1000-2000", p);
				g_free (p);
				fs_eventquery_free (q);
				return NULL;
			}
			q->has_port = TRUE;
		}
		g_free (p);
	}

	if (f->address != NULL) {
		gchar *a = g_strstrip (g_strdup (f->address));

		if (*a != '\0') {
			q->addresses = fs_range_set_new ();
			if (!fs_range_set_add_text (q->addresses, a)) {
				g_set_error (error, FS_EVENTQUERY_ERROR,
				             FS_EVENTQUERY_ERROR_ADDRESS,
				             "\"%s\" is not an address, a CIDR block "
				             "(10.0.0.0/8) or a range (a-b)", a);
				g_free (a);
				fs_eventquery_free (q);
				return NULL;
			}
			fs_range_set_normalize (q->addresses);
		}
		g_free (a);
	}

	q->direction = f->direction;
	q->action = f->action;
	q->since_ticks = f->since_us > 0 ? f->since_us * 10 : 0;
	q->until_ticks = f->until_us > 0 ? f->until_us * 10 : 0;

	if (q->since_ticks != 0 && q->until_ticks != 0 &&
	    q->since_ticks >= q->until_ticks) {
		g_set_error_literal (error, FS_EVENTQUERY_ERROR,
		                     FS_EVENTQUERY_ERROR_TIME,
		                     "the start of the time range is not "
		                     "before its end");
		fs_eventquery_free (q);
		return NULL;
	}

	return q;
}

void
fs_eventquery_free (FsEventQuery *q)
{
	if (q == NULL)
		return;

	g_free (q->text);
	g_free (q->protocol);
	fs_range_set_free (q->addresses);
	if (q->cache != NULL)
		g_array_unref (q->cache);
	g_free (q);
}

gboolean
fs_eventquery_is_empty (const FsEventQuery *q)
{
	return q == NULL ||
	       (q->text == NULL && q->direction == FS_EVQ_DIR_ANY &&
	        q->protocol == NULL && !q->has_port && q->addresses == NULL &&
	        q->action == FS_EVQ_ACTION_ANY && q->since_ticks == 0 &&
	        q->until_ticks == 0);
}

static gboolean
port_in (const FsEventQuery *q, const gchar *s)
{
	gchar *end;
	guint64 v;

	if (s == NULL || !g_ascii_isdigit (*s))
		return FALSE;

	v = g_ascii_strtoull (s, &end, 10);
	return *end == '\0' && v >= q->port_lo && v <= q->port_hi;
}

static gboolean
address_in (const FsEventQuery *q, const gchar *s)
{
	if (s == NULL || *s == '\0')
		return FALSE;

	return fs_range_set_contains_text (q->addresses, s);
}

/* [ string_bits ] -- every per-string test, done once for one string. */
static guint32
string_bits (const FsEventQuery *q, const gchar *s)
{
	guint32 bits = 0;

	if (s == NULL)
		return 0;

	if (q->text != NULL && ascii_case_contains (s, q->text))
		bits |= BIT_TEXT;
	if (q->protocol != NULL && g_ascii_strcasecmp (s, q->protocol) == 0)
		bits |= BIT_PROTO;
	if (q->has_port && port_in (q, s))
		bits |= BIT_PORT;
	if (q->addresses != NULL && address_in (q, s))
		bits |= BIT_ADDR;

	return bits;
}

static guint32
cached_bits (FsEventQuery *q, const FsEventStore *s, guint32 id)
{
	const Atom *a;
	CacheEnt *e;

	if (id == TIME_FRAC7 || id == TIME_SECS || id >= s->atoms->len)
		return 0;

	if (q->cache_store != s || q->cache == NULL) {
		if (q->cache != NULL)
			g_array_unref (q->cache);
		q->cache = g_array_new (FALSE, TRUE, sizeof (CacheEnt));
		q->cache_store = s;
	}

	if (id >= q->cache->len)
		g_array_set_size (q->cache, s->atoms->len);   /* zeroed */

	a = atom_at (s, id);
	e = &g_array_index (q->cache, CacheEnt, id);

	/* serial 0 is id 0 (""), which passes nothing but stays valid. */
	if (e->serial != a->serial || (e->bits & 0x80000000u) == 0) {
		e->serial = a->serial;
		e->bits = string_bits (q, a->str) | 0x80000000u;
	}

	return e->bits;
}

gboolean
fs_eventquery_match (FsEventQuery *q, const FsEventStore *s, guint64 seq)
{
	const Rec *r = rec_of (s, seq);

	if (r == NULL)
		return FALSE;
	if (q == NULL)
		return TRUE;

	if (q->since_ticks != 0 && r->ticks < q->since_ticks)
		return FALSE;
	if (q->until_ticks != 0 && r->ticks >= q->until_ticks)
		return FALSE;

	if (q->direction == FS_EVQ_DIR_IN &&
	    !(rec_flags (s, r, FS_EV_DIRECTION) & ATOM_IN))
		return FALSE;
	if (q->direction == FS_EVQ_DIR_OUT &&
	    !(rec_flags (s, r, FS_EV_DIRECTION) & ATOM_OUT))
		return FALSE;

	if (q->action != FS_EVQ_ACTION_ANY) {
		gboolean blocked = (rec_flags (s, r, FS_EV_SERVICE) &
		                    ATOM_BLOCKED) != 0;

		if (blocked != (q->action == FS_EVQ_ACTION_BLOCKED))
			return FALSE;
	}

	if (q->protocol != NULL &&
	    !(cached_bits (q, s, r->id[FS_EV_PROTOCOL]) & BIT_PROTO))
		return FALSE;

	if (q->has_port &&
	    !(cached_bits (q, s, r->id[FS_EV_PORT]) & BIT_PORT))
		return FALSE;

	if (q->addresses != NULL &&
	    !(cached_bits (q, s, r->id[FS_EV_SOURCE]) & BIT_ADDR) &&
	    !(cached_bits (q, s, r->id[FS_EV_DESTINATION]) & BIT_ADDR))
		return FALSE;

	/* The columns the list shows, as it shows them: the time, then
	 * direction to service.  Not the rule, which no column shows: a
	 * row it matched had no cell with the text in it. */
	if (q->text != NULL) {
		gboolean any = FALSE;

		for (guint f = FS_EV_DIRECTION; f <= FS_EV_SERVICE && !any; f++)
			any = (cached_bits (q, s, r->id[f]) & BIT_TEXT) != 0;

		if (!any && (r->id[FS_EV_TIME] == TIME_FRAC7 ||
		             r->id[FS_EV_TIME] == TIME_SECS)) {
			if (q->text_timeish) {
				gchar buf[FS_EVENT_TIME_BUF];

				any = ascii_case_contains (
					query_time_text (q, r, buf), q->text);
			}
		} else if (!any) {
			any = (cached_bits (q, s, r->id[FS_EV_TIME]) &
			       BIT_TEXT) != 0;
		}
		if (!any)
			return FALSE;
	}

	return TRUE;
}

static gboolean
hit_inbound (const FsHit *h)
{
	return h->direction != NULL &&
	       (g_ascii_strcasecmp (h->direction, "in") == 0 ||
	        g_ascii_strcasecmp (h->direction, "inbound") == 0);
}

static gboolean
hit_outbound (const FsHit *h)
{
	return h->direction != NULL &&
	       (g_ascii_strcasecmp (h->direction, "out") == 0 ||
	        g_ascii_strcasecmp (h->direction, "outbound") == 0);
}

gboolean
fs_eventquery_match_hit (const FsEventQuery *q, const FsHit *h,
                         gint64 time_us)
{
	if (h == NULL)
		return FALSE;
	if (q == NULL)
		return TRUE;

	if (q->since_ticks != 0 && time_us * 10 < q->since_ticks)
		return FALSE;
	if (q->until_ticks != 0 && time_us * 10 >= q->until_ticks)
		return FALSE;

	if (q->direction == FS_EVQ_DIR_IN && !hit_inbound (h))
		return FALSE;
	if (q->direction == FS_EVQ_DIR_OUT && !hit_outbound (h))
		return FALSE;

	if (q->action != FS_EVQ_ACTION_ANY) {
		gboolean blocked = h->service != NULL &&
		                   strstr (h->service, "[BLOCKED]") != NULL;

		if (blocked != (q->action == FS_EVQ_ACTION_BLOCKED))
			return FALSE;
	}

	if (q->protocol != NULL &&
	    !(string_bits (q, h->protocol) & BIT_PROTO))
		return FALSE;
	if (q->has_port && !(string_bits (q, h->port) & BIT_PORT))
		return FALSE;
	if (q->addresses != NULL &&
	    !(string_bits (q, h->source) & BIT_ADDR) &&
	    !(string_bits (q, h->destination) & BIT_ADDR))
		return FALSE;

	if (q->text != NULL) {
		/* What fs_eventquery_match reads: the shown columns. */
		const gchar *fields[] = {
			h->time, h->direction, h->in, h->out, h->port,
			h->source, h->destination, h->length, h->tos,
			h->protocol, h->service
		};
		gboolean any = FALSE;

		for (guint i = 0; i < G_N_ELEMENTS (fields) && !any; i++)
			any = fields[i] != NULL &&
			      ascii_case_contains (fields[i], q->text);
		if (!any)
			return FALSE;
	}

	return TRUE;
}

guint
fs_eventstore_select (const FsEventStore *s, FsEventQuery *q, GArray *seqs)
{
	guint n = 0;

	if (s == NULL || seqs == NULL)
		return 0;

	for (guint i = 0; i < s->length; i++) {
		guint64 seq = s->first_seq + i;

		if (q == NULL || fs_eventquery_match (q, s, seq)) {
			g_array_append_val (seqs, seq);
			n++;
		}
	}

	return n;
}

/* ------------------------------------------------------- time specs */

gboolean
fs_event_parse_time_spec (const gchar *text, gint64 now_us, gboolean end,
                          gint64 *out_us, GError **error)
{
	gchar *t;
	gboolean ok = FALSE;
	gsize len;

	*out_us = 0;
	if (text == NULL)
		return TRUE;

	t = g_strstrip (g_strdup (text));
	len = strlen (t);

	if (len == 0) {
		ok = TRUE;
		goto out;
	}

	if (g_ascii_strcasecmp (t, "now") == 0) {
		*out_us = now_us;
		ok = TRUE;
		goto out;
	}

	/* "15m", "2h", ... */
	if (len >= 2 && g_ascii_isdigit (t[0]) &&
	    strchr ("smhdw", g_ascii_tolower (t[len - 1])) != NULL) {
		gchar *endp;
		guint64 n = g_ascii_strtoull (t, &endp, 10);

		if (endp == t + len - 1 && n <= 100000) {
			gint64 unit;

			switch (g_ascii_tolower (t[len - 1])) {
			case 's': unit = G_USEC_PER_SEC; break;
			case 'm': unit = 60 * (gint64) G_USEC_PER_SEC; break;
			case 'h': unit = 3600 * (gint64) G_USEC_PER_SEC; break;
			case 'd': unit = 86400 * (gint64) G_USEC_PER_SEC; break;
			default:  unit = 7 * 86400 * (gint64) G_USEC_PER_SEC; break;
			}
			*out_us = now_us - (gint64) n * unit;
			ok = TRUE;
			goto out;
		}
	}

	/* "YYYY-MM-DD", local. */
	if (len == 10 && t[4] == '-' && t[7] == '-') {
		guint y, mo, d;

		if (digits (t, 4, &y) && digits (t + 5, 2, &mo) &&
		    digits (t + 8, 2, &d)) {
			GTimeZone *tz = g_time_zone_new_local ();
			GDateTime *dt = g_date_time_new (tz, (gint) y, (gint) mo,
			                                 (gint) d, 0, 0, 0);

			if (dt != NULL) {
				if (end) {
					GDateTime *next = g_date_time_add_days (dt, 1);

					g_date_time_unref (dt);
					dt = next;
				}
				*out_us = g_date_time_to_unix (dt) * G_USEC_PER_SEC;
				g_date_time_unref (dt);
				ok = TRUE;
			}
			g_time_zone_unref (tz);
			goto out;
		}
	}

	/* "YYYY-MM-DD HH:MM[:SS]" or with T, local unless it says. */
	if (len >= 16 && t[4] == '-' && t[7] == '-' &&
	    (t[10] == ' ' || t[10] == 'T' || t[10] == 't')) {
		GTimeZone *tz = g_time_zone_new_local ();
		gchar *iso = g_strdup (t);
		GDateTime *dt;

		iso[10] = 'T';
		if (len == 16) {
			gchar *longer = g_strconcat (iso, ":00", NULL);

			g_free (iso);
			iso = longer;
		}

		dt = g_date_time_new_from_iso8601 (iso, tz);
		if (dt != NULL) {
			*out_us = g_date_time_to_unix (dt) * G_USEC_PER_SEC +
			          g_date_time_get_microsecond (dt);
			g_date_time_unref (dt);
			ok = TRUE;
		}
		g_free (iso);
		g_time_zone_unref (tz);
	}

out:
	if (!ok)
		g_set_error (error, FS_EVENTQUERY_ERROR, FS_EVENTQUERY_ERROR_TIME,
		             "\"%s\" is not a time: use 15m, 2h, 3d, 2026-11-01 "
		             "or 2026-11-01 14:30", t);
	g_free (t);
	return ok;
}

/* ------------------------------------------------------------ export */

/* "-5", "-1.25": a plain negative number, which a spreadsheet reads as
 * a number and nothing more. */
static gboolean
plain_number (const gchar *s)
{
	if (*s == '-')
		s++;
	if (!g_ascii_isdigit (*s))
		return FALSE;
	while (g_ascii_isdigit (*s))
		s++;
	if (*s == '.') {
		s++;
		if (!g_ascii_isdigit (*s))
			return FALSE;
		while (g_ascii_isdigit (*s))
			s++;
	}
	return *s == '\0';
}

/* [ csv_field ]
 * A field a spreadsheet would run as a formula (= + - @ TAB CR first)
 * is written as text: quoted, with an apostrophe in front.  A leading
 * '-' is left alone only for a whole plain number (or alone): "-1+1" and the DDE
 * payload "-2+3+cmd|' /C calc'!A0" start with a minus and a digit too,
 * and both run, and the IN=, OUT=, SRC= and PROTO= text comes from the
 * kernel or a syslog line as it is. */
static void
csv_field (GString *out, const gchar *value)
{
	gboolean quote;
	gboolean formula;

	if (value == NULL)
		value = "";

	formula = value[0] == '=' || value[0] == '+' || value[0] == '@' ||
	          value[0] == '\t' || value[0] == '\r' ||
	          (value[0] == '-' && value[1] != '\0' &&
	           !plain_number (value));
	quote = formula || strpbrk (value, ",\"\r\n") != NULL;

	if (!quote) {
		g_string_append (out, value);
		return;
	}

	g_string_append_c (out, '"');
	if (formula)
		g_string_append_c (out, '\'');
	for (const gchar *p = value; *p != '\0'; p++) {
		if (*p == '"')
			g_string_append_c (out, '"');
		g_string_append_c (out, *p);
	}
	g_string_append_c (out, '"');
}

void
fs_event_csv_row (GString *out, const FsHit *h, gboolean blocked)
{
	const gchar *fields[] = {
		h->time, h->direction, h->in, h->out, h->port, h->source,
		h->destination, h->length, h->tos, h->protocol, h->service,
		blocked ? "blocked" : "allowed", h->rule
	};

	for (guint i = 0; i < G_N_ELEMENTS (fields); i++) {
		if (i > 0)
			g_string_append_c (out, ',');
		csv_field (out, fields[i]);
	}
}

gboolean
fs_eventstore_write_csv (const FsEventStore *s, const guint64 *seqs,
                         guint n_seqs, const gchar *path, guint *written,
                         GError **error)
{
	GString *out = g_string_sized_new (128 + (gsize) n_seqs * 128);
	guint rows = 0;
	gboolean ok;

	g_string_append (out, "time,direction,in,out,port,source,destination,"
	                      "length,tos,protocol,service,action,rule\r\n");

	for (guint i = 0; i < n_seqs; i++) {
		FsHit *h = fs_eventstore_get_hit (s, seqs[i]);

		if (h == NULL)
			continue;
		fs_event_csv_row (out, h, fs_eventstore_is_blocked (s, seqs[i]));
		g_string_append (out, "\r\n");
		fs_hit_free (h);
		rows++;
	}

	ok = g_file_set_contents_full (path, out->str, (gssize) out->len,
	                               G_FILE_SET_CONTENTS_CONSISTENT, 0600,
	                               error);
	g_string_free (out, TRUE);

	if (written != NULL)
		*written = ok ? rows : 0;
	return ok;
}
