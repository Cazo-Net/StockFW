/*---[ fs-feed-sync.c ]-------------------------------------------------------
 * 24-hour background threat intel KEV auto-refresh worker thread and toast notification.
 *--------------------------------------------------------------------*/

#include "core/fs-feed-sync.h"
#include "core/fs-fetch.h"
#include "core/fs-kev.h"
#include "core/fs-i18n.h"

#include <string.h>
#include <time.h>

#define CISA_KEV_URL "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

static GThread                *worker_thread = NULL;
static gboolean                running = FALSE;
static gboolean                stop_requested = FALSE;
static GMutex                  sync_mutex;
static GCond                   sync_cond;
static guint                   interval_hours = 24;
static gint64                  last_sync_time = 0;
static FsFeedSyncToastCallback toast_cb = NULL;
static gpointer                toast_user_data = NULL;
static guint                   last_kev_total_count = 0;
static gchar                  *last_latest_cve = NULL;

void
fs_feed_sync_init (void)
{
	g_mutex_init (&sync_mutex);
	g_cond_init (&sync_cond);
}

void
fs_feed_sync_set_toast_callback (FsFeedSyncToastCallback callback, gpointer user_data)
{
	g_mutex_lock (&sync_mutex);
	toast_cb = callback;
	toast_user_data = user_data;
	g_mutex_unlock (&sync_mutex);
}

void
fs_feed_sync_set_interval_hours (guint hours)
{
	g_mutex_lock (&sync_mutex);
	interval_hours = hours > 0 ? hours : 24;
	g_mutex_unlock (&sync_mutex);
}

guint
fs_feed_sync_get_interval_hours (void)
{
	guint hours;
	g_mutex_lock (&sync_mutex);
	hours = interval_hours;
	g_mutex_unlock (&sync_mutex);
	return hours;
}

gint64
fs_feed_sync_get_last_sync_time (void)
{
	gint64 t;
	g_mutex_lock (&sync_mutex);
	t = last_sync_time;
	g_mutex_unlock (&sync_mutex);
	return t;
}

gboolean
fs_feed_sync_refresh_now (GError **error)
{
	FsFetchRequest req;
	GBytes *bytes;
	GError *local_error = NULL;
	FsKevCatalog *catalog;
	gboolean success = FALSE;

	memset (&req, 0, sizeof req);
	req.url = CISA_KEV_URL;
	req.max_bytes = 32u * 1024u * 1024u;
	req.timeout_s = 60;
	req.user_agent = "StockFW/1.0.9";

	bytes = fs_fetch (&req, &local_error);
	if (!bytes) {
		if (error)
			*error = local_error;
		else
			g_error_free (local_error);
		return FALSE;
	}

	{
		gsize len = 0;
		const gchar *data = (const gchar *) g_bytes_get_data (bytes, &len);

		catalog = fs_kev_parse (data, len, &local_error);
		g_bytes_unref (bytes);
	}

	if (!catalog) {
		if (error)
			*error = local_error;
		else
			g_error_free (local_error);
		return FALSE;
	}

	g_mutex_lock (&sync_mutex);
	{
		guint new_total = catalog->total_count;
		gchar *new_latest = NULL;

		if (catalog->entries && catalog->entries->len > 0) {
			FsKevEntry *first_entry = g_ptr_array_index (catalog->entries, 0);
			if (first_entry && first_entry->cve_id)
				new_latest = g_strdup (first_entry->cve_id);
		}

		if (last_kev_total_count == 0 && last_latest_cve == NULL) {
			/* Initial sync baseline */
			last_kev_total_count = new_total;
			g_free (last_latest_cve);
			last_latest_cve = new_latest;
			success = TRUE;
		} else {
			if (new_total > last_kev_total_count ||
			    (new_latest && last_latest_cve && strcmp (new_latest, last_latest_cve) != 0)) {
				guint diff = new_total >= last_kev_total_count ? new_total - last_kev_total_count : 0;
				gchar *msg = g_strdup_printf (
				    _("CISA KEV feed updated: %u new vulnerabilities added (Total: %u). Latest CVE: %s"),
				    diff, new_total, new_latest ? new_latest : "N/A");

				if (toast_cb) {
					toast_cb (_("Threat Intel KEV Update"), msg, toast_user_data);
				}
				g_free (msg);

				last_kev_total_count = new_total;
				g_free (last_latest_cve);
				last_latest_cve = new_latest;
			} else {
				g_free (new_latest);
			}
			success = TRUE;
		}
		last_sync_time = (gint64) time (NULL);
	}
	g_mutex_unlock (&sync_mutex);

	fs_kev_catalog_free (catalog);
	return success;
}

static gpointer
feed_sync_worker_thread (gpointer data)
{
	g_mutex_lock (&sync_mutex);
	while (!stop_requested) {
		guint current_interval = interval_hours;
		gint64 wait_until = g_get_monotonic_time () + (gint64)current_interval * G_TIME_SPAN_HOUR;

		g_mutex_unlock (&sync_mutex);

		/* Perform initial/periodic refresh */
		{
			GError *refresh_err = NULL;
			if (!fs_feed_sync_refresh_now (&refresh_err)) {
				if (refresh_err) {
					g_warning ("CISA KEV background refresh failed: %s", refresh_err->message);
					g_error_free (refresh_err);
				}
			}
		}

		g_mutex_lock (&sync_mutex);
		while (!stop_requested) {
			if (g_cond_wait_until (&sync_cond, &sync_mutex, wait_until)) {
				/* Woke up by signal (e.g. manual refresh or stop) */
				break;
			}
			/* Timeout reached (interval elapsed) */
			break;
		}
	}
	running = FALSE;
	g_mutex_unlock (&sync_mutex);
	return NULL;
}

void
fs_feed_sync_start (void)
{
	g_mutex_lock (&sync_mutex);
	if (running) {
		g_mutex_unlock (&sync_mutex);
		return;
	}
	stop_requested = FALSE;
	running = TRUE;
	worker_thread = g_thread_new ("fs-feed-sync", feed_sync_worker_thread, NULL);
	g_mutex_unlock (&sync_mutex);
}

void
fs_feed_sync_stop (void)
{
	g_mutex_lock (&sync_mutex);
	if (!running) {
		g_mutex_unlock (&sync_mutex);
		return;
	}
	stop_requested = TRUE;
	g_cond_signal (&sync_cond);
	g_mutex_unlock (&sync_mutex);

	if (worker_thread) {
		g_thread_join (worker_thread);
		worker_thread = NULL;
	}

	g_mutex_lock (&sync_mutex);
	running = FALSE;
	g_free (last_latest_cve);
	last_latest_cve = NULL;
	g_mutex_unlock (&sync_mutex);
}

gboolean
fs_feed_sync_is_running (void)
{
	gboolean r;
	g_mutex_lock (&sync_mutex);
	r = running;
	g_mutex_unlock (&sync_mutex);
	return r;
}
