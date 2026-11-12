/*---[ test-feed-sync.c ]------------------------------------------------
 * Unit test for fs-feed-sync (24-hour threat intel KEV auto-refresh worker and toast).
 *--------------------------------------------------------------------*/

#include "core/fs-feed-sync.h"
#include <glib.h>
#include <assert.h>
#include <stdio.h>

static gboolean toast_called = FALSE;
static gchar *toast_title_received = NULL;
static gchar *toast_msg_received = NULL;

static void
test_toast_cb (const gchar *title, const gchar *message, gpointer user_data)
{
	toast_called = TRUE;
	g_free (toast_title_received);
	g_free (toast_msg_received);
	toast_title_received = g_strdup (title);
	toast_msg_received = g_strdup (message);
}

static void
test_feed_sync_basics (void)
{
	fs_feed_sync_init ();

	assert (fs_feed_sync_get_interval_hours () == 24);
	fs_feed_sync_set_interval_hours (12);
	assert (fs_feed_sync_get_interval_hours () == 12);
	fs_feed_sync_set_interval_hours (24);

	fs_feed_sync_set_toast_callback (test_toast_cb, NULL);

	assert (!fs_feed_sync_is_running ());
	fs_feed_sync_start ();
	assert (fs_feed_sync_is_running ());

	/* Let thread run briefly */
	g_usleep (100000); /* 0.1s */

	fs_feed_sync_stop ();
	assert (!fs_feed_sync_is_running ());

	g_print ("test-feed-sync passed successfully.\n");
}

int
main (int argc, char **argv)
{
	test_feed_sync_basics ();
	g_free (toast_title_received);
	g_free (toast_msg_received);
	return 0;
}
