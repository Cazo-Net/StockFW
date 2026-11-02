/*---[ fs-blocktally.h ]-------------------------------------------------
 * "Blocked today: N" and the last few blocks, for the tray menu and its
 * tooltip.
 *
 * Fed with every blocked event the Events page lists (fs-hitview.c, the
 * same filter the Overview's counters use).  Counted by the local day
 * the event ARRIVED, not by the log line's own time stamp: the event
 * feed delivers new events only, never history, and log time stamps
 * come in two formats, one without a year.  The count starts again at
 * local midnight, and from zero when StockFW starts (it counts what
 * this copy saw, and the tray says so).
 *--------------------------------------------------------------------*/
#ifndef FS_BLOCKTALLY_H
#define FS_BLOCKTALLY_H

#include <glib.h>
#include "core/fs-types.h"

G_BEGIN_DECLS

/* How many recent blocks are kept. */
#define FS_BLOCK_TALLY_RECENT 5

/* Count one blocked event that arrived at `now' (local time). */
void fs_block_tally_note (const FsHit *hit, GDateTime *now);

/* Blocks counted on the local day of `now'.  0 after midnight. */
guint fs_block_tally_today (GDateTime *now);

/* The last few blocks, newest first, each one line:
 * "TCP 445 from 203.0.113.5 (10:42)", "UDP 53 to 192.0.2.53 (10:41)".
 * Free with g_strfreev; never NULL. */
gchar **fs_block_tally_recent (void);

/* Forget everything (tests). */
void fs_block_tally_reset (void);

/* The one-line form of `hit' as fs_block_tally_recent() shows it,
 * with `hhmm' as the time.  Exposed for tests. */
gchar *fs_block_tally_describe (const FsHit *hit, const gchar *hhmm);

G_END_DECLS

#endif /* FS_BLOCKTALLY_H */
