/*---[ fs-activity.h ]---------------------------------------------------
 * Activity time series: the data behind the 1.0.6 graphs.
 *
 * A small set of named counters ("events.allowed", "events.blocked",
 * "net.rx", "net.tx", per-adapter "net.<device>.rx" ...) bucketed into
 * ten-second slots and kept for twenty-four hours in fixed rings, so a
 * StockFW that runs in the tray for a week uses the same memory on the
 * last day as on the first.  The desktop app's Activity page, the CLI
 * and the local dashboard all read the same structure.
 *
 * Honesty rules the readers rely on:
 *   - a point before the series could have seen anything is "no data"
 *     (covered == 0), never a zero that reads as an idle firewall;
 *   - the newest point is the current, partial interval, and covered
 *     says how much of it has elapsed, so a rate is never diluted by
 *     seconds that have not happened yet.
 *
 * The clock is injectable: the core suite drives a day of traffic in
 * microseconds of test time.
 *--------------------------------------------------------------------*/
#ifndef FS_ACTIVITY_H
#define FS_ACTIVITY_H

#include <glib.h>

G_BEGIN_DECLS

/* Base resolution and depth: 10 s slots, 8640 of them = 24 hours. */
#define FS_ACTIVITY_SLOT_S     10
#define FS_ACTIVITY_SLOTS      8640
#define FS_ACTIVITY_SPAN_S     (FS_ACTIVITY_SLOT_S * FS_ACTIVITY_SLOTS)

/* At most this many series.  Past it, fs_activity_add refuses a new
 * name (existing series keep counting), so a host with hundreds of
 * virtual adapters cannot grow the structure without bound.  At
 * 8 bytes a slot that is ~1.6 MB at the cap. */
#define FS_ACTIVITY_MAX_SERIES 24

/* Well-known series names. */
#define FS_ACTIVITY_ALLOWED "events.allowed"
#define FS_ACTIVITY_BLOCKED "events.blocked"
#define FS_ACTIVITY_NET_RX  "net.rx"
#define FS_ACTIVITY_NET_TX  "net.tx"

typedef struct _FsActivity FsActivity;

/* Seconds since the Unix epoch.  NULL means the real clock. */
typedef gint64 (*FsActivityClock) (gpointer user_data);

FsActivity *fs_activity_new  (FsActivityClock clock, gpointer user_data);
void        fs_activity_free (FsActivity *activity);

/* The structure's notion of now, and the first second it covers. */
gint64 fs_activity_now     (FsActivity *activity);
gint64 fs_activity_started (FsActivity *activity);

/* Count `amount' into a series at now / at `when'.  A new name past
 * FS_ACTIVITY_MAX_SERIES is refused (FALSE); a time older than the
 * ring or before the start is dropped (FALSE); a time in the future
 * is clamped to now.  TRUE when the amount was counted. */
gboolean fs_activity_add    (FsActivity *activity, const gchar *series,
                             guint64 amount);
gboolean fs_activity_add_at (FsActivity *activity, const gchar *series,
                             gint64 when, guint64 amount);

/* Read n_points points of step_s seconds each, oldest first, ending
 * with the point that contains now.  Points are aligned to multiples
 * of step_s so a redraw does not slide the buckets under the reader.
 * step_s is rounded up to a multiple of FS_ACTIVITY_SLOT_S.
 *
 *   values[i]   the sum counted inside point i
 *   covered[i]  how many seconds of point i lie inside
 *               [started, now] -- 0 means no data at all
 *   start_out   (optional) the first second of point 0
 *
 * An unknown series reads as zeros with real coverage: it simply has
 * not counted anything yet.  Returns the step actually used. */
guint fs_activity_window (FsActivity *activity, const gchar *series,
                          guint step_s, guint n_points,
                          guint64 *values, guint *covered,
                          gint64 *start_out);

/* Sum of a series over the last `seconds' (clamped to the ring). */
guint64 fs_activity_total (FsActivity *activity, const gchar *series,
                           guint seconds);

/* Names of every series, sorted.  The strings are owned by the
 * structure; free the list itself with g_list_free. */
GList *fs_activity_series_names (FsActivity *activity);

/* The step a reader should use to show `range_s' seconds in about
 * `max_points' points: the smallest of 10 s, 30 s, 1, 5, 15 and 30 min
 * that fits, so axis ticks land on round times. */
guint fs_activity_step_for (guint range_s, guint max_points);

/* ------------------------------------------------- interface sampling */

/* Turns successive cumulative interface counters (FsIfaceStat lists)
 * into byte deltas counted into "net.rx"/"net.tx" and the per-device
 * series.  The first sample of a device only sets its baseline; a
 * counter that went backwards (adapter reset, driver reload) counts as
 * a fresh baseline, never as negative traffic. */
typedef struct _FsActivitySampler FsActivitySampler;

FsActivitySampler *fs_activity_sampler_new  (FsActivity *activity);
void               fs_activity_sampler_free (FsActivitySampler *sampler);

/* stats: GList of FsIfaceStat* (borrowed).  Returns the number of
 * devices that contributed a delta this time. */
guint fs_activity_sampler_feed (FsActivitySampler *sampler,
                                const GList *stats);

/* "net.<device>.rx" / ".tx" for one device.  Caller frees. */
gchar *fs_activity_device_series (const gchar *device, gboolean sent);

G_END_DECLS

#endif /* FS_ACTIVITY_H */
