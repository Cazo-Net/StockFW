/*---[ fs-eventmodel.h ]-------------------------------------------------
 * The Events list's model (1.0.7): a GtkTreeModel over the event store
 * that copies nothing.
 *
 * It holds one array of seqs -- the events the current filter lets
 * through, in the current sort order -- and answers every cell from
 * the store when the view asks for it, which is only for the rows on
 * screen.  So 100,000 events cost the view 800 KB of seqs instead of
 * 1.2 million strings, and an append is a binary search and one
 * row-inserted signal instead of a walk down the list.
 *
 * Columns: the twelve string columns of the old GtkListStore, in the
 * same order (FsHitColumn), so cell functions and tests that read
 * COL_TIME .. COL_COLOR keep working.  COL_TIME is the stamp as the
 * backend gave it, COL_COLOR "#cc0000" for a blocked event.
 *
 * Sorting (GtkTreeSortable): any column, either way; by default the
 * newest event first.  Ties go by time, then by arrival.
 *--------------------------------------------------------------------*/
#ifndef FS_EVENTMODEL_H
#define FS_EVENTMODEL_H

#include <gtk/gtk.h>
#include "core/fs-eventstore.h"

G_BEGIN_DECLS

#define FS_TYPE_EVENT_MODEL (fs_event_model_get_type ())
G_DECLARE_FINAL_TYPE (FsEventModel, fs_event_model, FS, EVENT_MODEL, GObject)

/* The model registers itself as the store's evict func, so a dropped
 * event leaves the list with a row-deleted. */
FsEventModel *fs_event_model_new        (FsEventStore *store);

/* Takes the query (NULL: everything) and rebuilds the rows.  Rebuilding
 * emits no per-row signals: detach the model from its view around the
 * call (gtk_tree_view_set_model NULL, then back), which is far cheaper
 * than 100,000 row-deleted signals. */
void          fs_event_model_set_query  (FsEventModel *model,
                                         FsEventQuery *query);
FsEventQuery *fs_event_model_get_query  (FsEventModel *model);
/* Rebuild under the same query (after the store was reloaded or
 * cleared).  Same rule: detached. */
void          fs_event_model_rebuild    (FsEventModel *model);

/* After fs_eventstore_append: lists seq where it sorts, if the query
 * lets it through.  Returns TRUE when a row was inserted. */
gboolean      fs_event_model_note_append (FsEventModel *model, guint64 seq);

guint         fs_event_model_n_rows     (FsEventModel *model);
/* The seq on row n (0 when out of range), and under an iter. */
guint64       fs_event_model_seq_at     (FsEventModel *model, guint row);
guint64       fs_event_model_iter_seq   (FsEventModel *model,
                                         GtkTreeIter *iter);
/* Every listed seq, in the order shown (a GArray of guint64). */
GArray       *fs_event_model_rows       (FsEventModel *model);

/* How many cell values the view has read: the smoke test's evidence
 * that the model is asked for what is on screen, not every row. */
guint64       fs_event_model_value_reads (FsEventModel *model);

G_END_DECLS

#endif /* FS_EVENTMODEL_H */
