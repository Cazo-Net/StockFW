/*---[ fs-feed-sync.h ]--------------------------------------------------
 * 24-hour background threat intel KEV auto-refresh worker thread and toast notification.
 *--------------------------------------------------------------------*/
#ifndef FS_FEED_SYNC_H
#define FS_FEED_SYNC_H

#include <glib.h>
#include "core/fs-kev.h"

G_BEGIN_DECLS

/* Toast notification callback type */
typedef void (*FsFeedSyncToastCallback) (const gchar *title, const gchar *message, gpointer user_data);

/* Initialize feed sync subsystem */
void fs_feed_sync_init (void);

/* Start the 24-hour background auto-refresh worker thread */
void fs_feed_sync_start (void);

/* Stop the background worker thread */
void fs_feed_sync_stop (void);

/* Check if the worker thread is running */
gboolean fs_feed_sync_is_running (void);

/* Set toast notification callback */
void fs_feed_sync_set_toast_callback (FsFeedSyncToastCallback callback, gpointer user_data);

/* Trigger an immediate refresh/sync (fetches CISA KEV feed, parses, checks updates, notifies) */
gboolean fs_feed_sync_refresh_now (GError **error);

/* Get/set sync interval in hours (default 24) */
void fs_feed_sync_set_interval_hours (guint hours);
guint fs_feed_sync_get_interval_hours (void);

/* Get last sync timestamp */
gint64 fs_feed_sync_get_last_sync_time (void);

G_END_DECLS

#endif /* FS_FEED_SYNC_H */
