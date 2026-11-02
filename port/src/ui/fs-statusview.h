#ifndef FS_STATUSVIEW_H
#define FS_STATUSVIEW_H

#include <gtk/gtk.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

/* The Overview page (1.0.7; the Status page before it): the verdict,
 * the firewall's switch, totals, open connections, adapters and the
 * most recent blocks. */
GtkWidget     *fs_statusview_page (void);

/* Resample the adapters and open connections immediately. */
void           fs_statusview_refresh (void);

/* Re-read whether IPv6 is filtered (FsBackend.ipv6_state) and update
 * the verdict.  Called on every state change and after each apply. */
void           fs_statusview_refresh_ipv6 (void);

/* TRUE while the Lock toggle is on; the Policy page refuses to apply
 * while this is set. */
gboolean       fs_statusview_policy_locked (void);

void           fs_statusview_set_state (FsFirewallState state);
FsFirewallState fs_statusview_get_state (void);

/* After the firewall started (start TRUE) or stopped: the threat-intel
 * blocklists follow (fs_intel_resume under fs_intelview_hold_reason(), or
 * fs_intel_suspend), in a worker, one job at a time, in order; an
 * error dialog if they could not.  `source' names the caller in the
 * audit log. */
void           fs_statusview_intel_follow (gboolean start,
                                           const gchar *source);

/* The policy whose rules the Overview counts.  Not owned. */
void           fs_statusview_set_policy (FsPolicy *policy);

/* How the Overview judges the machine right now, for anything that
 * shows the same verdict elsewhere (the sidebar).  One judgement, so
 * the two can never disagree. */
typedef enum
{
	FS_VERDICT_UNKNOWN = 0,   /* the state could not be read          */
	FS_VERDICT_OK,            /* running, every family filtered       */
	FS_VERDICT_WARN,          /* running, but IPv6 passes unfiltered  */
	FS_VERDICT_BAD            /* stopped: nothing is filtered         */
} FsVerdict;

/* The verdict in a few words ("Protected"), and its level in *level
 * when level is not NULL.  The string is owned by the page. */
const gchar   *fs_statusview_verdict (FsVerdict *level);

/* Called after every change of the verdict.  One listener. */
typedef void (*FsStatusChanged) (gpointer user);
void           fs_statusview_set_changed_cb (FsStatusChanged cb,
                                             gpointer user);

/* Called by the Events page for every event; drives the counters. */
void fs_statusview_event_in      (gboolean serious);
void fs_statusview_event_out     (gboolean serious);
void fs_statusview_events_reset  (void);

/* A blocked event, for the Overview's "Recent blocks" card.  The hit
 * is copied; the newest few are kept. */
void fs_statusview_note_block    (const FsHit *hit);

/* The Recent blocks card's rows, newest first, as "title\ndetail".
 * For tests.  Free with g_strfreev. */
gchar **fs_statusview_recent_blocks (void);

G_END_DECLS

#endif /* FS_STATUSVIEW_H */
