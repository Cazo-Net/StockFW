/*---[ fs-eventmodel.c ]-------------------------------------------------
 * A GtkTreeModel over the event store.  See fs-eventmodel.h.
 *
 * The rows are a list of seqs in chunks ("the row list" below), kept
 * in ascending order of the sort key.  A descending sort only reads it
 * backwards, so the default view -- newest first -- appends at the
 * list's end and drops at its start, and any other sort moves at most
 * one chunk per event.
 *--------------------------------------------------------------------*/

#include "ui/fs-eventmodel.h"

#include <stdlib.h>
#include <string.h>

#define N_COLUMNS FS_NUM_HITCOLUMNS

struct _FsEventModel
{
	GObject       parent;

	FsEventStore *store;
	FsEventQuery *query;

	struct _Chunk **chunks;   /* see "the row list" */
	guint          n_chunks;
	guint          chunks_alloc;
	guint         *starts;
	guint          len;
	guint          hint;

	gint          sort_col;
	GtkSortType   order;

	gint          stamp;
	guint64       value_reads;
};

static void tree_model_init (GtkTreeModelIface *iface);
static void sortable_init   (GtkTreeSortableIface *iface);

G_DEFINE_TYPE_WITH_CODE (FsEventModel, fs_event_model, G_TYPE_OBJECT,
	G_IMPLEMENT_INTERFACE (GTK_TYPE_TREE_MODEL, tree_model_init)
	G_IMPLEMENT_INTERFACE (GTK_TYPE_TREE_SORTABLE, sortable_init))

/* ----------------------------------------------------------- the key */

static gboolean
all_digits (const gchar *s)
{
	if (*s == '\0')
		return FALSE;
	for (; *s != '\0'; s++)
		if (!g_ascii_isdigit (*s))
			return FALSE;
	return TRUE;
}

/* [ cmp_text ]
 * Numbers as numbers (ports, lengths) and before any text, the text
 * without regard to case; strcmp last, so two different strings never
 * tie.  It has to be a total order: comparing "22" < "123" as numbers
 * but "123" < "1a" < "22" as text made a cycle, and the sort put the
 * 22s after the 123s. */
static gint
cmp_text (const gchar *a, const gchar *b)
{
	gboolean na, nb;
	gint r;

	if (a == b)
		return 0;

	na = all_digits (a);
	nb = all_digits (b);
	if (na != nb)
		return na ? -1 : 1;

	/* As numbers, of any length: without the leading zeros, the
	 * longer is the larger, and same lengths compare digit by digit. */
	if (na) {
		const gchar *x = a, *y = b;
		gsize lx, ly;

		while (*x == '0' && x[1] != '\0')
			x++;
		while (*y == '0' && y[1] != '\0')
			y++;
		lx = strlen (x);
		ly = strlen (y);
		if (lx != ly)
			return lx < ly ? -1 : 1;
		r = strcmp (x, y);
		if (r != 0)
			return r < 0 ? -1 : 1;
	}

	r = g_ascii_strcasecmp (a, b);
	return r != 0 ? r : strcmp (a, b);
}

static gint
cmp_seq (FsEventModel *m, guint64 a, guint64 b)
{
	gint64 ta, tb;

	if (a == b)
		return 0;

	if (m->sort_col == FS_HITCOL_COLOR) {
		gboolean ba = fs_eventstore_is_blocked (m->store, a);
		gboolean bb = fs_eventstore_is_blocked (m->store, b);

		if (ba != bb)
			return ba ? 1 : -1;
	} else if (m->sort_col != FS_HITCOL_TIME) {
		gint r = cmp_text (fs_eventstore_field (m->store, a, m->sort_col),
		                   fs_eventstore_field (m->store, b, m->sort_col));

		if (r != 0)
			return r;
	}

	ta = fs_eventstore_ticks (m->store, a);
	tb = fs_eventstore_ticks (m->store, b);
	if (ta != tb)
		return ta < tb ? -1 : 1;

	return a < b ? -1 : 1;
}

/* ------------------------------------------------------- the rows */

/* [ the row list ]
 * The rows in ascending key order, as a list of chunks of at most
 * CHUNK_MAX seqs.  starts[k] is the position of chunk k's first row and
 * starts[n_chunks] the length, so a position is a binary search over
 * the chunks away.  Adding or removing a row moves at most one chunk's
 * seqs (16 KB) and adds one to the starts after it.
 *
 * It replaced one flat array, which moved up to the whole list for
 * each event under any sort but time: two memmoves of up to 8 MB per
 * event at 1,000,000 rows, about 200 us, so a burst of 5,000 events a
 * second took the whole main thread.  Each chunk keeps room at both
 * ends, so the time sort's drop at the front and add at the back still
 * move nothing. */
#define CHUNK_MAX   2048u
#define CHUNK_FILL  1536u     /* what a rebuild puts in each chunk   */
#define CHUNK_SMALL  256u     /* below this a chunk joins a neighbour */

typedef struct _Chunk
{
	guint   off;              /* the first slot in use */
	guint   n;                /* slots in use          */
	guint64 v[CHUNK_MAX];
} Chunk;

static Chunk *
chunk_new (void)
{
	Chunk *c = g_new (Chunk, 1);

	c->off = CHUNK_MAX / 2;
	c->n = 0;
	return c;
}

/* starts[from ..] from the chunk sizes. */
static void
fix_starts (FsEventModel *m, guint from)
{
	guint pos = from > 0 ? m->starts[from - 1] + m->chunks[from - 1]->n
	                     : 0;

	for (guint k = from; k < m->n_chunks; k++) {
		m->starts[k] = pos;
		pos += m->chunks[k]->n;
	}
	m->starts[m->n_chunks] = pos;
	m->len = pos;
}

static void
shift_starts (FsEventModel *m, guint k, gint delta)
{
	for (guint j = k + 1; j <= m->n_chunks; j++)
		m->starts[j] = (guint) ((gint) m->starts[j] + delta);
	m->len = m->starts[m->n_chunks];
}

/* The chunk holding position pos (< len), and pos within it.  No chunk
 * is ever empty, so the starts rise strictly. */
static guint
chunk_of (FsEventModel *m, guint pos, guint *local)
{
	guint lo = 0, hi = m->n_chunks;

	/* Cells are read row after row: try the last chunk first. */
	if (m->hint < m->n_chunks && m->starts[m->hint] <= pos &&
	    pos < m->starts[m->hint + 1]) {
		*local = pos - m->starts[m->hint];
		return m->hint;
	}

	while (hi - lo > 1) {
		guint mid = lo + (hi - lo) / 2;

		if (m->starts[mid] <= pos)
			lo = mid;
		else
			hi = mid;
	}
	m->hint = lo;
	*local = pos - m->starts[lo];
	return lo;
}

static inline guint64
at (FsEventModel *m, guint pos)
{
	guint local;
	Chunk *c = m->chunks[chunk_of (m, pos, &local)];

	return c->v[c->off + local];
}

static void
insert_chunk (FsEventModel *m, guint k, Chunk *c)
{
	if (m->n_chunks + 1 > m->chunks_alloc) {
		m->chunks_alloc = MAX (16u, m->chunks_alloc * 2);
		m->chunks = g_renew (Chunk *, m->chunks, m->chunks_alloc);
		m->starts = g_renew (guint, m->starts, m->chunks_alloc + 1);
	}
	memmove (m->chunks + k + 1, m->chunks + k,
	         (m->n_chunks - k) * sizeof (Chunk *));
	m->chunks[k] = c;
	m->n_chunks++;
	fix_starts (m, k);
}

static void
drop_chunk (FsEventModel *m, guint k)
{
	g_free (m->chunks[k]);
	memmove (m->chunks + k, m->chunks + k + 1,
	         (m->n_chunks - k - 1) * sizeof (Chunk *));
	m->n_chunks--;
	fix_starts (m, k);
}

static void
free_rows (FsEventModel *m)
{
	for (guint k = 0; k < m->n_chunks; k++)
		g_free (m->chunks[k]);
	m->n_chunks = 0;
	m->len = 0;
	m->hint = 0;
	if (m->starts != NULL)
		m->starts[0] = 0;
}

/* The rows from a flat array, in that order. */
static void
load_rows (FsEventModel *m, const guint64 *seqs, guint n)
{
	free_rows (m);

	for (guint i = 0; i < n; i += CHUNK_FILL) {
		Chunk *c = g_new (Chunk, 1);

		c->n = MIN (CHUNK_FILL, n - i);
		c->off = (CHUNK_MAX - c->n) / 2;
		memcpy (c->v + c->off, seqs + i, c->n * sizeof (guint64));

		if (m->n_chunks + 1 > m->chunks_alloc) {
			m->chunks_alloc = MAX (16u, m->chunks_alloc * 2);
			m->chunks = g_renew (Chunk *, m->chunks,
			                     m->chunks_alloc);
			m->starts = g_renew (guint, m->starts,
			                     m->chunks_alloc + 1);
		}
		m->chunks[m->n_chunks++] = c;
	}
	if (m->starts == NULL)
		m->starts = g_new0 (guint, 1);
	fix_starts (m, 0);
}

/* Every row, flat, in ascending order.  Caller frees. */
static guint64 *
flat_rows (FsEventModel *m)
{
	guint64 *out = g_new (guint64, MAX (m->len, 1u));
	guint pos = 0;

	for (guint k = 0; k < m->n_chunks; k++) {
		Chunk *c = m->chunks[k];

		memcpy (out + pos, c->v + c->off, c->n * sizeof (guint64));
		pos += c->n;
	}
	return out;
}

static void
insert_at (FsEventModel *m, guint pos, guint64 seq)
{
	Chunk *c;
	guint k, local;
	gboolean front;

	if (m->n_chunks == 0) {
		if (m->starts == NULL)
			m->starts = g_new0 (guint, 1);
		insert_chunk (m, 0, chunk_new ());
	}

	if (pos >= m->len) {
		k = m->n_chunks - 1;
		local = m->chunks[k]->n;
	} else {
		k = chunk_of (m, pos, &local);
	}
	c = m->chunks[k];

	/* A full chunk: its upper half becomes a new one after it. */
	if (c->n == CHUNK_MAX) {
		Chunk *d = g_new (Chunk, 1);
		guint half = CHUNK_MAX / 2;

		d->n = c->n - half;
		d->off = (CHUNK_MAX - d->n) / 2;
		memcpy (d->v + d->off, c->v + c->off + half,
		        d->n * sizeof (guint64));
		c->n = half;
		insert_chunk (m, k + 1, d);
		if (local > half) {
			k++;
			local -= half;
			c = d;
		}
	}

	/* Move the shorter side; with no room on that side, centre the
	 * chunk once (the room it makes lasts many inserts). */
	front = local < c->n / 2;
	if (front ? c->off == 0 : c->off + c->n == CHUNK_MAX) {
		guint off = (CHUNK_MAX - c->n) / 2;

		memmove (c->v + off, c->v + c->off, c->n * sizeof (guint64));
		c->off = off;
		if (front && c->off == 0)
			front = FALSE;
	}

	if (front) {
		memmove (c->v + c->off - 1, c->v + c->off,
		         local * sizeof (guint64));
		c->off--;
	} else {
		memmove (c->v + c->off + local + 1, c->v + c->off + local,
		         (c->n - local) * sizeof (guint64));
	}
	c->v[c->off + local] = seq;
	c->n++;
	shift_starts (m, k, 1);
}

/* A small chunk joins the smaller neighbour, when the two fit in one,
 * so random removals cannot leave a long list of near-empty chunks. */
static void
maybe_join (FsEventModel *m, guint k)
{
	Chunk *a, *b;
	guint lo, n, off;

	if (m->chunks[k]->n >= CHUNK_SMALL || m->n_chunks < 2)
		return;

	if (k == 0)
		lo = 0;
	else if (k + 1 == m->n_chunks)
		lo = k - 1;
	else
		lo = m->chunks[k - 1]->n < m->chunks[k + 1]->n ? k - 1 : k;

	a = m->chunks[lo];
	b = m->chunks[lo + 1];
	n = a->n + b->n;
	if (n > CHUNK_FILL)
		return;

	off = (CHUNK_MAX - n) / 2;
	memmove (a->v + off, a->v + a->off, a->n * sizeof (guint64));
	memcpy (a->v + off + a->n, b->v + b->off, b->n * sizeof (guint64));
	a->off = off;
	a->n = n;
	drop_chunk (m, lo + 1);
}

static void
remove_at (FsEventModel *m, guint pos)
{
	guint local;
	guint k = chunk_of (m, pos, &local);
	Chunk *c = m->chunks[k];

	if (local < c->n / 2) {
		memmove (c->v + c->off + 1, c->v + c->off,
		         local * sizeof (guint64));
		c->off++;
	} else {
		memmove (c->v + c->off + local, c->v + c->off + local + 1,
		         (c->n - local - 1) * sizeof (guint64));
	}
	c->n--;

	if (c->n == 0) {
		drop_chunk (m, k);
		return;
	}
	shift_starts (m, k, -1);
	maybe_join (m, k);
}

static inline guint
row_to_pos (FsEventModel *m, guint row)
{
	return m->order == GTK_SORT_DESCENDING ? m->len - 1 - row : row;
}

static inline guint
pos_to_row (FsEventModel *m, guint pos)
{
	return row_to_pos (m, pos);   /* the mapping is its own inverse */
}

/* First position whose key is above seq's. */
static guint
upper_bound (FsEventModel *m, guint64 seq)
{
	guint lo = 0, hi = m->len;

	/* The usual case under the default sort: newer than everything. */
	if (m->len > 0 && cmp_seq (m, at (m, m->len - 1), seq) < 0)
		return m->len;

	while (lo < hi) {
		guint mid = lo + (hi - lo) / 2;

		if (cmp_seq (m, at (m, mid), seq) <= 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

/* The position of seq, or -1. */
static gint
find (FsEventModel *m, guint64 seq)
{
	guint lo = 0, hi = m->len;

	/* The usual drop: the oldest, first in the array. */
	if (m->len > 0 && at (m, 0) == seq)
		return 0;

	while (lo < hi) {
		guint mid = lo + (hi - lo) / 2;
		gint r = cmp_seq (m, at (m, mid), seq);

		if (r == 0)
			return (gint) mid;
		if (r < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return -1;
}

/* ------------------------------------------------------- full sort */

typedef struct
{
	guint32 rank;
	gint64  ticks;
	guint64 seq;
	guint32 old_row;
} SortEnt;

/* (time, seq): the order within one rank. */
static gint
time_ent_cmp (gconstpointer pa, gconstpointer pb)
{
	const SortEnt *a = pa, *b = pb;

	if (a->ticks != b->ticks)
		return a->ticks < b->ticks ? -1 : 1;
	if (a->seq != b->seq)
		return a->seq < b->seq ? -1 : 1;
	return 0;
}

static gint
atom_cmp (gconstpointer pa, gconstpointer pb, gpointer data)
{
	FsEventStore *store = data;

	return cmp_text (fs_eventstore_atom (store, *(const guint32 *) pa),
	                 fs_eventstore_atom (store, *(const guint32 *) pb));
}

/* [ sort_rows ]
 * Every distinct string of the column is ranked once, then the rows
 * are put in (rank, time, seq) order with plain integers: in time
 * order first, then a counting sort by rank, which keeps that order
 * within each rank.
 * Sorts rows[0 .. n) in place.  Fills old_pos[new position] with the
 * position each entry had before, when old_pos is not NULL. */
static void
sort_rows (FsEventModel *m, guint64 *rows, guint n, guint *old_pos)
{
	guint32 *rank = NULL;
	SortEnt *ents;

	if (n == 0)
		return;

	/* Only the strings this column uses are ranked: sorting by port
	 * ranks a few thousand ports, not every address in the store. */
	if (m->sort_col != FS_HITCOL_TIME && m->sort_col != FS_HITCOL_COLOR) {
		guint na = fs_eventstore_n_atoms (m->store);
		GArray *ids = g_array_new (FALSE, FALSE, sizeof (guint32));
		guint8 *used = g_new0 (guint8, MAX (na, 1u));

		for (guint i = 0; i < n; i++) {
			guint32 id = fs_eventstore_field_id (m->store, rows[i],
			                                     m->sort_col);

			if (id < na && !used[id]) {
				used[id] = 1;
				g_array_append_val (ids, id);
			}
		}
		g_free (used);
		g_array_sort_with_data (ids, atom_cmp, m->store);

		rank = g_new0 (guint32, MAX (na, 1u));
		for (guint i = 0; i < ids->len; i++)
			rank[g_array_index (ids, guint32, i)] = i;
		g_array_unref (ids);
	}

	ents = g_new (SortEnt, n);
	for (guint i = 0; i < n; i++) {
		guint64 seq = rows[i];

		ents[i].seq = seq;
		ents[i].ticks = fs_eventstore_ticks (m->store, seq);
		ents[i].old_row = i;
		if (rank != NULL)
			ents[i].rank = rank[fs_eventstore_field_id (m->store, seq,
			                                            m->sort_col)];
		else if (m->sort_col == FS_HITCOL_COLOR)
			ents[i].rank = fs_eventstore_is_blocked (m->store, seq);
		else
			ents[i].rank = 0;
	}

	/* Time order first: usually there already (the store's order, or
	 * the time sort being left), so this is one pass, not a sort. */
	for (guint i = 1; i < n; i++) {
		if (time_ent_cmp (&ents[i - 1], &ents[i]) > 0) {
			qsort (ents, n, sizeof (SortEnt), time_ent_cmp);
			break;
		}
	}

	/* Then by rank, keeping time order within a rank: a counting
	 * sort, one pass over the rows, where qsort of a million random
	 * ranks took a third of a second. */
	if (rank != NULL || m->sort_col == FS_HITCOL_COLOR) {
		guint n_ranks = 0;
		guint *count;
		SortEnt *out = g_new (SortEnt, n);

		for (guint i = 0; i < n; i++)
			n_ranks = MAX (n_ranks, ents[i].rank + 1);
		count = g_new0 (guint, n_ranks + 1);
		for (guint i = 0; i < n; i++)
			count[ents[i].rank + 1]++;
		for (guint r = 1; r <= n_ranks; r++)
			count[r] += count[r - 1];
		for (guint i = 0; i < n; i++)
			out[count[ents[i].rank]++] = ents[i];
		g_free (count);
		g_free (ents);
		ents = out;
	}

	for (guint i = 0; i < n; i++) {
		rows[i] = ents[i].seq;
		if (old_pos != NULL)
			old_pos[i] = ents[i].old_row;
	}

	g_free (ents);
	g_free (rank);
}

/* ------------------------------------------------------------ public */

static void
on_evict (FsEventStore *store, guint64 seq, gpointer data)
{
	FsEventModel *m = data;
	GtkTreePath *path;
	gint pos;
	guint row;

	(void) store;

	pos = find (m, seq);
	if (pos < 0)
		return;

	row = pos_to_row (m, (guint) pos);
	remove_at (m, (guint) pos);
	m->stamp++;

	path = gtk_tree_path_new_from_indices ((gint) row, -1);
	gtk_tree_model_row_deleted (GTK_TREE_MODEL (m), path);
	gtk_tree_path_free (path);
}

FsEventModel *
fs_event_model_new (FsEventStore *store)
{
	FsEventModel *m = g_object_new (FS_TYPE_EVENT_MODEL, NULL);

	m->store = store;
	fs_eventstore_set_evict_func (store, on_evict, m);
	fs_event_model_rebuild (m);

	return m;
}

void
fs_event_model_rebuild (FsEventModel *m)
{
	guint n = fs_eventstore_length (m->store);
	guint64 first = fs_eventstore_first_seq (m->store);
	guint64 *rows = g_new (guint64, MAX (n, 1u));
	guint len = 0;

	for (guint i = 0; i < n; i++) {
		guint64 seq = first + i;

		if (m->query == NULL ||
		    fs_eventquery_match (m->query, m->store, seq))
			rows[len++] = seq;
	}

	/* Arrival order is not time order (a batch comes newest first),
	 * and other columns need their sort. */
	sort_rows (m, rows, len, NULL);
	load_rows (m, rows, len);
	g_free (rows);
	m->stamp++;
}

void
fs_event_model_set_query (FsEventModel *m, FsEventQuery *query)
{
	if (m->query != NULL && m->query != query)
		fs_eventquery_free (m->query);
	m->query = query;
	fs_event_model_rebuild (m);
}

FsEventQuery *
fs_event_model_get_query (FsEventModel *m)
{
	return m->query;
}

gboolean
fs_event_model_note_append (FsEventModel *m, guint64 seq)
{
	GtkTreePath *path;
	GtkTreeIter iter;
	guint pos, row;

	if (!fs_eventstore_has (m->store, seq))
		return FALSE;
	if (m->query != NULL && !fs_eventquery_match (m->query, m->store, seq))
		return FALSE;

	pos = upper_bound (m, seq);
	insert_at (m, pos, seq);
	m->stamp++;

	row = pos_to_row (m, pos);
	iter.stamp = m->stamp;
	iter.user_data = GUINT_TO_POINTER (row);
	path = gtk_tree_path_new_from_indices ((gint) row, -1);
	gtk_tree_model_row_inserted (GTK_TREE_MODEL (m), path, &iter);
	gtk_tree_path_free (path);

	return TRUE;
}

guint
fs_event_model_n_rows (FsEventModel *m)
{
	return m->len;
}

guint64
fs_event_model_seq_at (FsEventModel *m, guint row)
{
	if (row >= m->len)
		return 0;
	return at (m, row_to_pos (m, row));
}

guint64
fs_event_model_iter_seq (FsEventModel *m, GtkTreeIter *iter)
{
	if (iter == NULL || iter->stamp != m->stamp)
		return 0;
	return fs_event_model_seq_at (m, GPOINTER_TO_UINT (iter->user_data));
}

GArray *
fs_event_model_rows (FsEventModel *m)
{
	GArray *out = g_array_sized_new (FALSE, FALSE, sizeof (guint64), m->len);
	guint64 *flat = flat_rows (m);

	for (guint row = 0; row < m->len; row++)
		g_array_append_val (out, flat[row_to_pos (m, row)]);
	g_free (flat);
	return out;
}

guint64
fs_event_model_value_reads (FsEventModel *m)
{
	return m->value_reads;
}

/* ------------------------------------------------------ GObject */

static void
fs_event_model_finalize (GObject *object)
{
	FsEventModel *m = FS_EVENT_MODEL (object);

	if (m->store != NULL)
		fs_eventstore_set_evict_func (m->store, NULL, NULL);
	fs_eventquery_free (m->query);
	free_rows (m);
	g_free (m->chunks);
	g_free (m->starts);

	G_OBJECT_CLASS (fs_event_model_parent_class)->finalize (object);
}

static void
fs_event_model_class_init (FsEventModelClass *klass)
{
	G_OBJECT_CLASS (klass)->finalize = fs_event_model_finalize;
}

static void
fs_event_model_init (FsEventModel *m)
{
	m->sort_col = FS_HITCOL_TIME;
	m->order = GTK_SORT_DESCENDING;
	m->stamp = g_random_int ();
}

/* --------------------------------------------------- GtkTreeModel */

static GtkTreeModelFlags
tm_get_flags (GtkTreeModel *model)
{
	return GTK_TREE_MODEL_LIST_ONLY;
}

static gint
tm_get_n_columns (GtkTreeModel *model)
{
	return N_COLUMNS;
}

static GType
tm_get_column_type (GtkTreeModel *model, gint index)
{
	return G_TYPE_STRING;
}

static gboolean
set_iter (FsEventModel *m, GtkTreeIter *iter, guint row)
{
	if (row >= m->len) {
		iter->stamp = 0;
		return FALSE;
	}
	iter->stamp = m->stamp;
	iter->user_data = GUINT_TO_POINTER (row);
	return TRUE;
}

static gboolean
tm_get_iter (GtkTreeModel *model, GtkTreeIter *iter, GtkTreePath *path)
{
	FsEventModel *m = FS_EVENT_MODEL (model);
	gint depth = 0;
	gint *idx = gtk_tree_path_get_indices_with_depth (path, &depth);

	if (depth != 1 || idx[0] < 0)
		return set_iter (m, iter, G_MAXUINT);
	return set_iter (m, iter, (guint) idx[0]);
}

static GtkTreePath *
tm_get_path (GtkTreeModel *model, GtkTreeIter *iter)
{
	FsEventModel *m = FS_EVENT_MODEL (model);

	g_return_val_if_fail (iter->stamp == m->stamp, NULL);
	return gtk_tree_path_new_from_indices (
		(gint) GPOINTER_TO_UINT (iter->user_data), -1);
}

static void
tm_get_value (GtkTreeModel *model, GtkTreeIter *iter, gint column,
              GValue *value)
{
	FsEventModel *m = FS_EVENT_MODEL (model);
	guint64 seq;

	g_value_init (value, G_TYPE_STRING);
	g_return_if_fail (iter->stamp == m->stamp);
	g_return_if_fail (column >= 0 && column < N_COLUMNS);

	m->value_reads++;
	seq = fs_event_model_seq_at (m, GPOINTER_TO_UINT (iter->user_data));
	if (seq == 0)
		return;

	if (column == FS_HITCOL_TIME) {
		gchar buf[FS_EVENT_TIME_BUF];

		g_value_set_string (value,
		                    fs_eventstore_time_text (m->store, seq, buf));
	} else if (column == FS_HITCOL_COLOR) {
		/* "" allowed, "#cc0000" blocked, or, for a block whose
		 * event names the rule that blocked it ("Threat intel:
		 * Spamhaus DROP (IPv4)"), that rule: the Events page
		 * paints any non-empty value red and shows a rule after
		 * the service. */
		const gchar *rule = fs_eventstore_field (m->store, seq,
		                                         FS_EV_RULE);

		if (!fs_eventstore_is_blocked (m->store, seq))
			g_value_set_static_string (value, "");
		else if (rule != NULL && *rule != '\0')
			g_value_set_static_string (value, rule);
		else
			g_value_set_static_string (value, "#cc0000");
	} else {
		/* Interned: lives as long as the event, which outlives
		 * this value (nothing drops an event while a cell is
		 * being drawn). */
		g_value_set_static_string (
			value, fs_eventstore_field (m->store, seq, column));
	}
}

static gboolean
tm_iter_next (GtkTreeModel *model, GtkTreeIter *iter)
{
	FsEventModel *m = FS_EVENT_MODEL (model);

	g_return_val_if_fail (iter->stamp == m->stamp, FALSE);
	return set_iter (m, iter, GPOINTER_TO_UINT (iter->user_data) + 1);
}

static gboolean
tm_iter_previous (GtkTreeModel *model, GtkTreeIter *iter)
{
	FsEventModel *m = FS_EVENT_MODEL (model);
	guint row;

	g_return_val_if_fail (iter->stamp == m->stamp, FALSE);
	row = GPOINTER_TO_UINT (iter->user_data);
	return row > 0 ? set_iter (m, iter, row - 1)
	               : set_iter (m, iter, G_MAXUINT);
}

static gboolean
tm_iter_children (GtkTreeModel *model, GtkTreeIter *iter,
                  GtkTreeIter *parent)
{
	FsEventModel *m = FS_EVENT_MODEL (model);

	if (parent != NULL)
		return set_iter (m, iter, G_MAXUINT);
	return set_iter (m, iter, 0);
}

static gboolean
tm_iter_has_child (GtkTreeModel *model, GtkTreeIter *iter)
{
	return FALSE;
}

static gint
tm_iter_n_children (GtkTreeModel *model, GtkTreeIter *iter)
{
	FsEventModel *m = FS_EVENT_MODEL (model);

	return iter == NULL ? (gint) m->len : 0;
}

static gboolean
tm_iter_nth_child (GtkTreeModel *model, GtkTreeIter *iter,
                   GtkTreeIter *parent, gint n)
{
	FsEventModel *m = FS_EVENT_MODEL (model);

	if (parent != NULL || n < 0)
		return set_iter (m, iter, G_MAXUINT);
	return set_iter (m, iter, (guint) n);
}

static gboolean
tm_iter_parent (GtkTreeModel *model, GtkTreeIter *iter, GtkTreeIter *child)
{
	iter->stamp = 0;
	return FALSE;
}

static void
tree_model_init (GtkTreeModelIface *iface)
{
	iface->get_flags       = tm_get_flags;
	iface->get_n_columns   = tm_get_n_columns;
	iface->get_column_type = tm_get_column_type;
	iface->get_iter        = tm_get_iter;
	iface->get_path        = tm_get_path;
	iface->get_value       = tm_get_value;
	iface->iter_next       = tm_iter_next;
	iface->iter_previous   = tm_iter_previous;
	iface->iter_children   = tm_iter_children;
	iface->iter_has_child  = tm_iter_has_child;
	iface->iter_n_children = tm_iter_n_children;
	iface->iter_nth_child  = tm_iter_nth_child;
	iface->iter_parent     = tm_iter_parent;
}

/* ------------------------------------------------- GtkTreeSortable */

static gboolean
ts_get_sort_column_id (GtkTreeSortable *sortable, gint *column,
                       GtkSortType *order)
{
	FsEventModel *m = FS_EVENT_MODEL (sortable);

	if (column != NULL)
		*column = m->sort_col;
	if (order != NULL)
		*order = m->order;
	return TRUE;
}

static void
ts_set_sort_column_id (GtkTreeSortable *sortable, gint column,
                       GtkSortType order)
{
	FsEventModel *m = FS_EVENT_MODEL (sortable);
	gint *new_order;
	guint *old_pos;
	GtkSortType old_order = m->order;
	GtkTreePath *root;

	/* The default and "unsorted" both mean newest first. */
	if (column < 0 || column >= N_COLUMNS) {
		column = FS_HITCOL_TIME;
		order = GTK_SORT_DESCENDING;
	}

	if (column == m->sort_col && order == m->order)
		return;

	old_pos = g_new (guint, MAX (m->len, 1u));
	new_order = g_new (gint, MAX (m->len, 1u));

	if (column == m->sort_col) {
		for (guint i = 0; i < m->len; i++)
			old_pos[i] = i;
	} else {
		guint64 *rows = flat_rows (m);

		m->sort_col = column;
		sort_rows (m, rows, m->len, old_pos);
		load_rows (m, rows, m->len);
		g_free (rows);
	}
	m->order = order;
	m->stamp++;

	/* new_order[new row] = the row it was on. */
	for (guint pos = 0; pos < m->len; pos++) {
		guint new_row = pos_to_row (m, pos);
		guint was = old_order == GTK_SORT_DESCENDING
		            ? m->len - 1 - old_pos[pos] : old_pos[pos];

		new_order[new_row] = (gint) was;
	}

	if (m->len > 0) {
		root = gtk_tree_path_new ();
		gtk_tree_model_rows_reordered_with_length (GTK_TREE_MODEL (m),
		                                           root, NULL, new_order,
		                                           (gint) m->len);
		gtk_tree_path_free (root);
	}

	g_free (new_order);
	g_free (old_pos);

	gtk_tree_sortable_sort_column_changed (sortable);
}

static void
ts_set_sort_func (GtkTreeSortable *sortable, gint column,
                  GtkTreeIterCompareFunc func, gpointer data,
                  GDestroyNotify destroy)
{
	/* The model's own orders only. */
	if (destroy != NULL)
		destroy (data);
}

static void
ts_set_default_sort_func (GtkTreeSortable *sortable,
                          GtkTreeIterCompareFunc func, gpointer data,
                          GDestroyNotify destroy)
{
	if (destroy != NULL)
		destroy (data);
}

static gboolean
ts_has_default_sort_func (GtkTreeSortable *sortable)
{
	return TRUE;
}

static void
sortable_init (GtkTreeSortableIface *iface)
{
	iface->get_sort_column_id    = ts_get_sort_column_id;
	iface->set_sort_column_id    = ts_set_sort_column_id;
	iface->set_sort_func         = ts_set_sort_func;
	iface->set_default_sort_func = ts_set_default_sort_func;
	iface->has_default_sort_func = ts_has_default_sort_func;
}
