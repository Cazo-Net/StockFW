/*---[ fs-activityview.h ]-----------------------------------------------
 * The Activity page (1.0.6): two graphs over the last 15 minutes to 24
 * hours.
 *
 *   Policy activity  events per minute, allowed and blocked (blocked
 *                    only on Linux, whose kernel log carries drops and
 *                    rejects but not accepts)
 *   Network I/O      bytes per second received and sent, all adapters
 *                    or one
 *
 * The page counts what the Events page lists (the same filters run
 * first, and a row listed twice is one event), and samples the
 * adapters' byte counters every two seconds.  Both series start when
 * the app starts; the stretch before that is drawn as "no data", never
 * as a quiet zero.  Each graph has a table view with the same numbers.
 *--------------------------------------------------------------------*/
#ifndef FS_ACTIVITYVIEW_H
#define FS_ACTIVITYVIEW_H

#include <gtk/gtk.h>
#include "core/fs-activity.h"
#include "core/fs-types.h"

G_BEGIN_DECLS

GtkWidget *fs_activityview_page (void);

/* Count one listed event: blocked when it carries the marker, allowed
 * otherwise, at the event's own time when it has a readable one.
 * Called by the Events page after a row is accepted. */
void fs_activityview_note_hit (const FsHit *hit);

/* Read the adapters' counters now (the page also does this on its own
 * two-second timer). */
void fs_activityview_sample (void);

/* The range shown, in seconds (900, 3600, 21600 or 86400). */
void  fs_activityview_set_range (guint seconds);
guint fs_activityview_get_range (void);

/* Switch both cards between graph and table. */
void     fs_activityview_set_table (gboolean table);

/* For the smoke test: the series behind the page, the rows the
 * events table would show, and whether the allowed series is drawn. */
FsActivity *fs_activityview_events (void);
FsActivity *fs_activityview_network (void);
guint       fs_activityview_table_rows (void);
gboolean    fs_activityview_shows_allowed (void);

G_END_DECLS

#endif /* FS_ACTIVITYVIEW_H */
