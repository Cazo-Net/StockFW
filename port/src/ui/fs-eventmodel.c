/*---[ fs-eventmodel.c ]-------------------------------------------------
 * A GtkTreeModel over the event store.  See fs-eventmodel.h.
 *
 * The rows are a gap-at-both-ends array of seqs (start, len, alloc),
 * kept in ascending order of the sort key.  A descending sort only
 * reads it backwards, so the default view -- newest first -- appends
 * at the array's end and drops at its start: both O(1).
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

	guint64      *rows;
	guint         start;
	guint         len;
	guint         alloc;

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

	if (na) {
		guint64 x = g_ascii_strtoull (a, NULL, 10);
		guint64 y = g_ascii_strtoull (b, NULL, 10);

		if (x != y)
			return x < y ? -1 : 1;
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

/* ------------------------------------------------------- the array */

static inline guint64
at (FsEventModel *m, guint pos)
{
	return m->rows[m->start + pos];
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

static void
reserve_tail (FsEventModel *m)
{
	if (m->start + m->len < m->alloc)
		return;

	/* Slack at the front from drops: slide down instead of growing. */
	if (m->start > m->len / 2 && m->start > 0) {
		memmove (m->rows, m->rows + m->start, m->len * sizeof (guint64));
		m->start = 0;
		return;
	}

	m->alloc = MAX (1024u, m->alloc * 2);
	m->rows = g_renew (guint64, m->rows, m->alloc);
}

static void
insert_at (FsEventModel *m, guint pos, guint64 seq)
{
	if (pos < m->len / 2 && m->start > 0) {
		m->start--;
		memmove (m->rows + m->start, m->rows + m->start + 1,
		         pos * sizeof (guint64));
	} else {
		reserve_tail (m);
		memmove (m->rows + m->start + pos + 1, m->rows + m->start + pos,
		         (m->len - pos) * sizeof (guint64));
	}
	m->rows[m->start + pos] = seq;
	m->len++;
}

static void
remove_at (FsEventModel *m, guint pos)
{
	if (pos < m->len / 2) {
		memmove (m->rows + m->start + 1, m->rows + m->start,
		         pos * sizeof (guint64));
		m->start++;
	} else {
		memmove (m->rows + m->start + pos, m->rows + m->start + pos + 1,
		         (m->len - pos - 1) * sizeof (guint64));
	}
	m->len--;
	if (m->len == 0)
		m->start = 0;
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

static gint
sort_ent_cmp (gconstpointer pa, gconstpointer pb)
{
	const SortEnt *a = pa, *b = pb;

	if (a->rank != b->rank)
		return a->rank < b->rank ? -1 : 1;
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
 * are sorted by (rank, time, seq) as plain integers: 100,000 rows
 * cost 100,000 integer comparisons per level, not string compares.
 * Fills old_rows[new position] with the row each entry had before
 * (under the order before), when old_rows is not NULL. */
static void
sort_rows (FsEventModel *m, guint *old_pos)
{
	guint32 *rank = NULL;
	SortEnt *ents;

	if (m->len == 0)
		return;

	if (m->sort_col != FS_HITCOL_TIME && m->sort_col != FS_HITCOL_COLOR) {
		guint n = fs_eventstore_n_atoms (m->store);
		GArray *ids = g_array_sized_new (FALSE, FALSE, sizeof (guint32), n);

		for (guint32 id = 0; id < n; id++)
			if (fs_eventstore_atom (m->store, id) != NULL)
				g_array_append_val (ids, id);
		g_array_sort_with_data (ids, atom_cmp, m->store);

		rank = g_new0 (guint32, n);
		for (guint i = 0; i < ids->len; i++)
			rank[g_array_index (ids, guint32, i)] = i;
		g_array_unref (ids);
	}

	ents = g_new (SortEnt, m->len);
	for (guint i = 0; i < m->len; i++) {
		guint64 seq = at (m, i);

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

	qsort (ents, m->len, sizeof (SortEnt), sort_ent_cmp);

	for (guint i = 0; i < m->len; i++) {
		m->rows[m->start + i] = ents[i].seq;
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

	if (m->alloc < n) {
		g_free (m->rows);
		m->alloc = MAX (1024u, n + n / 4);
		m->rows = g_new (guint64, m->alloc);
	}
	m->start = 0;
	m->len = 0;

	for (guint i = 0; i < n; i++) {
		guint64 seq = first + i;

		if (m->query == NULL ||
		    fs_eventquery_match (m->query, m->store, seq))
			m->rows[m->len++] = seq;
	}

	/* Arrival order is not time order (a batch comes newest first),
	 * and other columns need their sort. */
	sort_rows (m, NULL);
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

	for (guint row = 0; row < m->len; row++) {
		guint64 seq = at (m, row_to_pos (m, row));

		g_array_append_val (out, seq);
	}
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
	g_free (m->rows);

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
		g_value_set_static_string (
			value, fs_eventstore_is_blocked (m->store, seq)
			       ? "#cc0000" : "");
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
		m->sort_col = column;
		sort_rows (m, old_pos);
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
