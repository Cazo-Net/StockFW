/*---[ fs-intelview.h ]--------------------------------------------------
 * The Threat Intel page (1.0.7, design section 8): whether the
 * blocklists are really in the kernel, each feed with what it blocks,
 * its licence and credit, its entries, its last and next update, its
 * status (a refused update offers the override that lets it in), its
 * blocked count and its switch; Update now; the allow list
 * (exceptions) and your own blocklist; imported lists; and a lookup.
 *
 * Everything that touches the store, the network or the kernel runs in
 * a worker thread (GTask), one job at a time, with progress on the
 * page; the main thread only ever shows a finished snapshot.
 *--------------------------------------------------------------------*/
#ifndef FS_INTELVIEW_H
#define FS_INTELVIEW_H

#include <gtk/gtk.h>
#include "core/fs-backend.h"

G_BEGIN_DECLS

/* The page, header included (fs-app.c adds it with no frame). */
GtkWidget *fs_intelview_page (void);

/* Re-read the state, the store and the counters (in the worker). */
void fs_intelview_refresh (void);

/* What else holds an apply besides audit-only mode (the Overview's
 * Lock): a sentence, or NULL when nothing does.  Called on the main
 * thread when a job starts. */
typedef const gchar *(*FsIntelHoldFunc) (void);
void fs_intelview_set_hold_func (FsIntelHoldFunc func);

/* What holds a blocklist apply right now: fs_apply_hold_reason()
 * (audit-only mode), else the hold function's sentence (the Lock), else
 * NULL.  Every apply the app makes -- the page's, and the Status page's
 * Start -- is held by this one answer (design 6.5).  Main thread. */
const gchar *fs_intelview_hold_reason (void);

/* The Events page: whether an event's rule text ("Threat intel:
 * Spamhaus DROP (IPv4)", FsHit.rule) names a blocklist. */
gboolean fs_intelview_rule_is_intel (const gchar *rule);

/* The Events page's "Add exception": ask, then put `addr' on the allow
 * list and re-apply (in the worker); the outcome is shown in a dialog
 * over `parent' and on the page. */
void fs_intelview_add_exception (GtkWindow *parent, const gchar *addr,
                                 const gchar *rule);

/* ---- for the smoke test ------------------------------------------- */

/* The backend the page drives; NULL means fs_backend(). */
void fs_intelview_set_backend (const FsBackend *backend);

/* Stands in for the user at every dialog the page runs (consent,
 * confirmations, results, the file chooser): returns the response.
 * NULL restores gtk_dialog_run(). */
typedef gint (*FsIntelResponder) (GtkDialog *dialog, gpointer data);
void fs_intelview_set_responder (FsIntelResponder responder,
                                 gpointer data);

/* TRUE while a job is queued or running. */
gboolean fs_intelview_busy (void);

/* The import file chooser is skipped when this is set (tests). */
void fs_intelview_set_import_path (const gchar *path);

G_END_DECLS

#endif /* FS_INTELVIEW_H */
