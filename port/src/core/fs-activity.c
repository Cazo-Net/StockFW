/*---[ fs-activity.c ]---------------------------------------------------
 * The time series described in fs-activity.h.
 *--------------------------------------------------------------------*/
#include "core/fs-activity.h"
#include "core/fs-types.h"

#include <string.h>

typedef struct
{
	guint64 slots[FS_ACTIVITY_SLOTS];
	gint64  head;        /* absolute slot index of the newest slot */
} Series;

struct _FsActivity
{
	FsActivityClock clock;
	gpointer        clock_data;
	gint64          started;     /* unix seconds */
	GHashTable     *series;      /* name -> Series* */
};

/* [ floor_div ] -- division that rounds towards minus infinity. */
static gint64
floor_div (gint64 a, gint64 b)
{
	gint64 q = a / b;

	if ((a % b != 0) && ((a < 0) != (b < 0)))
		q--;

	return q;
}

static gint64
real_clock (gpointer user_data)
{
	(void) user_data;
	return g_get_real_time () / G_USEC_PER_SEC;
}

FsActivity *
fs_activity_new (FsActivityClock clock, gpointer user_data)
{
	FsActivity *activity = g_new0 (FsActivity, 1);

	activity->clock      = clock != NULL ? clock : real_clock;
	activity->clock_data = user_data;
	activity->started    = activity->clock (activity->clock_data);
	activity->series     = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                              g_free, g_free);

	return activity;
}

void
fs_activity_free (FsActivity *activity)
{
	if (activity == NULL)
		return;

	g_hash_table_unref (activity->series);
	g_free (activity);
}

gint64
fs_activity_now (FsActivity *activity)
{
	return activity->clock (activity->clock_data);
}

gint64
fs_activity_started (FsActivity *activity)
{
	return activity->started;
}

/* [ series_advance ]
 * Move a ring's head forward to `slot', zeroing every slot it passes
 * over: those intervals happened and counted nothing. */
static void
series_advance (Series *s, gint64 slot)
{
	gint64 n;

	if (slot <= s->head)
		return;

	n = slot - s->head;

	if (n >= FS_ACTIVITY_SLOTS) {
		memset (s->slots, 0, sizeof (s->slots));
	} else {
		for (gint64 b = s->head + 1; b <= slot; b++)
			s->slots[b % FS_ACTIVITY_SLOTS] = 0;
	}

	s->head = slot;
}

/* [ series_read ] -- one slot, or 0 when it is outside the ring. */
static guint64
series_read (const Series *s, gint64 slot)
{
	if (s == NULL || slot > s->head || slot <= s->head - FS_ACTIVITY_SLOTS)
		return 0;

	return s->slots[slot % FS_ACTIVITY_SLOTS];
}

gboolean
fs_activity_add_at (FsActivity *activity, const gchar *series,
                    gint64 when, guint64 amount)
{
	Series *s;
	gint64 now, slot;

	g_return_val_if_fail (activity != NULL && series != NULL, FALSE);

	now = fs_activity_now (activity);
	if (when > now)
		when = now;
	if (when < activity->started)
		return FALSE;

	slot = floor_div (when, FS_ACTIVITY_SLOT_S);

	s = g_hash_table_lookup (activity->series, series);
	if (s == NULL) {
		if (g_hash_table_size (activity->series) >= FS_ACTIVITY_MAX_SERIES)
			return FALSE;

		s = g_new0 (Series, 1);
		s->head = floor_div (now, FS_ACTIVITY_SLOT_S);
		g_hash_table_insert (activity->series, g_strdup (series), s);
	}

	if (slot <= s->head - FS_ACTIVITY_SLOTS)
		return FALSE;

	series_advance (s, slot);
	s->slots[slot % FS_ACTIVITY_SLOTS] += amount;

	return TRUE;
}

gboolean
fs_activity_add (FsActivity *activity, const gchar *series, guint64 amount)
{
	g_return_val_if_fail (activity != NULL, FALSE);

	return fs_activity_add_at (activity, series,
	                           fs_activity_now (activity), amount);
}

guint
fs_activity_window (FsActivity *activity, const gchar *series,
                    guint step_s, guint n_points,
                    guint64 *values, guint *covered, gint64 *start_out)
{
	const Series *s;
	gint64 now, cur_slot, ring_floor, data_floor, last_start, start0;

	g_return_val_if_fail (activity != NULL, 0);

	if (step_s < FS_ACTIVITY_SLOT_S)
		step_s = FS_ACTIVITY_SLOT_S;
	if (step_s % FS_ACTIVITY_SLOT_S != 0)
		step_s += FS_ACTIVITY_SLOT_S - step_s % FS_ACTIVITY_SLOT_S;

	s   = series != NULL ? g_hash_table_lookup (activity->series, series)
	                     : NULL;
	now = fs_activity_now (activity);

	/* Data can exist only from the start, and only as far back as
	 * the ring reaches from now. */
	cur_slot   = floor_div (now, FS_ACTIVITY_SLOT_S);
	ring_floor = (cur_slot - FS_ACTIVITY_SLOTS + 1) * FS_ACTIVITY_SLOT_S;
	data_floor = MAX (activity->started, ring_floor);

	last_start = floor_div (now, step_s) * step_s;
	start0     = last_start - (gint64) (n_points > 0 ? n_points - 1 : 0)
	                          * step_s;

	if (start_out != NULL)
		*start_out = start0;

	for (guint i = 0; i < n_points; i++) {
		gint64 ps = start0 + (gint64) i * step_s;
		gint64 pe = ps + step_s;              /* exclusive */
		gint64 lo = MAX (ps, data_floor);
		gint64 hi = MIN (pe, now + 1);
		guint64 sum = 0;

		if (covered != NULL)
			covered[i] = hi > lo ? (guint) (hi - lo) : 0;

		if (values != NULL) {
			if (s != NULL && hi > lo) {
				for (gint64 b = floor_div (ps, FS_ACTIVITY_SLOT_S);
				     b < floor_div (pe, FS_ACTIVITY_SLOT_S); b++)
					sum += series_read (s, b);
			}
			values[i] = sum;
		}
	}

	return step_s;
}

guint64
fs_activity_total (FsActivity *activity, const gchar *series, guint seconds)
{
	const Series *s;
	gint64 now, first, last;
	guint64 sum = 0;

	g_return_val_if_fail (activity != NULL, 0);

	s = series != NULL ? g_hash_table_lookup (activity->series, series)
	                   : NULL;
	if (s == NULL || seconds == 0)
		return 0;

	if (seconds > FS_ACTIVITY_SPAN_S)
		seconds = FS_ACTIVITY_SPAN_S;

	now   = fs_activity_now (activity);
	last  = floor_div (now, FS_ACTIVITY_SLOT_S);
	first = floor_div (now - (gint64) seconds + 1, FS_ACTIVITY_SLOT_S);

	for (gint64 b = first; b <= last; b++)
		sum += series_read (s, b);

	return sum;
}

GList *
fs_activity_series_names (FsActivity *activity)
{
	GList *names;

	g_return_val_if_fail (activity != NULL, NULL);

	names = g_hash_table_get_keys (activity->series);
	return g_list_sort (names, (GCompareFunc) g_strcmp0);
}

guint
fs_activity_step_for (guint range_s, guint max_points)
{
	static const guint steps[] = { 10, 30, 60, 300, 900, 1800, 3600 };

	if (max_points == 0)
		max_points = 1;

	for (guint i = 0; i < G_N_ELEMENTS (steps); i++)
		if ((range_s + steps[i] - 1) / steps[i] <= max_points)
			return steps[i];

	return steps[G_N_ELEMENTS (steps) - 1];
}

/* ------------------------------------------------- interface sampling */

typedef struct
{
	guint64 received;
	guint64 sent;
} Baseline;

struct _FsActivitySampler
{
	FsActivity *activity;
	GHashTable *baselines;    /* device -> Baseline* */
};

FsActivitySampler *
fs_activity_sampler_new (FsActivity *activity)
{
	FsActivitySampler *sampler = g_new0 (FsActivitySampler, 1);

	sampler->activity  = activity;
	sampler->baselines = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                            g_free, g_free);
	return sampler;
}

void
fs_activity_sampler_free (FsActivitySampler *sampler)
{
	if (sampler == NULL)
		return;

	g_hash_table_unref (sampler->baselines);
	g_free (sampler);
}

gchar *
fs_activity_device_series (const gchar *device, gboolean sent)
{
	return g_strdup_printf ("net.%s.%s", device, sent ? "tx" : "rx");
}

guint
fs_activity_sampler_feed (FsActivitySampler *sampler, const GList *stats)
{
	GHashTable *seen;
	GHashTableIter iter;
	gpointer key;
	guint contributed = 0;
	guint64 rx_total = 0, tx_total = 0;

	g_return_val_if_fail (sampler != NULL, 0);

	seen = g_hash_table_new (g_str_hash, g_str_equal);

	for (const GList *l = stats; l != NULL; l = l->next) {
		const FsIfaceStat *stat = l->data;
		Baseline *prev;

		if (stat == NULL || stat->device == NULL)
			continue;

		g_hash_table_add (seen, stat->device);
		prev = g_hash_table_lookup (sampler->baselines, stat->device);

		if (prev != NULL &&
		    stat->received >= prev->received &&
		    stat->sent >= prev->sent) {
			guint64 dr = stat->received - prev->received;
			guint64 ds = stat->sent - prev->sent;
			gchar *rx = fs_activity_device_series (stat->device, FALSE);
			gchar *tx = fs_activity_device_series (stat->device, TRUE);

			rx_total += dr;
			tx_total += ds;

			/* The per-device series may be refused at the cap;
			 * the totals above still count the device. */
			fs_activity_add (sampler->activity, rx, dr);
			fs_activity_add (sampler->activity, tx, ds);
			g_free (rx);
			g_free (tx);
			contributed++;
		}

		if (prev == NULL) {
			prev = g_new0 (Baseline, 1);
			g_hash_table_insert (sampler->baselines,
			                     g_strdup (stat->device), prev);
		}

		prev->received = stat->received;
		prev->sent     = stat->sent;
	}

	/* The totals exist from the first delta on, even at zero: an
	 * idle link is a measured zero, not a missing line. */
	if (contributed > 0) {
		fs_activity_add (sampler->activity, FS_ACTIVITY_NET_RX, rx_total);
		fs_activity_add (sampler->activity, FS_ACTIVITY_NET_TX, tx_total);
	}

	/* A device that vanished loses its baseline, so if it comes back
	 * its first sample is a baseline again rather than a jump. */
	g_hash_table_iter_init (&iter, sampler->baselines);
	while (g_hash_table_iter_next (&iter, &key, NULL))
		if (!g_hash_table_contains (seen, key))
			g_hash_table_iter_remove (&iter);

	g_hash_table_unref (seen);

	return contributed;
}
