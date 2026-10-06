/*---[ fs-statusview.c ]------------------------------------------------
 * The Status page.
 *
 * Laid out the way the original Firestarter laid it out: a status line
 * with its emblem on the left and the Events counters (Total / Serious,
 * across Inbound / Outbound) on the right, then the profile switches,
 * then the two live tables -- "Network" and "Active connections".
 *
 * Both tables are polled.  Interface octet counters come from the
 * backend's list_interface_stats() and open sockets from
 * list_connections(); a backend that has neither leaves the panels
 * hidden rather than showing invented numbers.
 *--------------------------------------------------------------------*/

#include "ui/fs-statusview.h"
#include "ui/fs-dialogs.h"
#include "core/fs-backend.h"
#include "core/fs-i18n.h"
#include "stockfw-logo-96.h"

#include <gdk-pixbuf/gdk-pixbuf.h>

/* How often the live panels are resampled.  Interface counters are
 * cheap; enumerating sockets is dearer, so it runs less often. */
#define NET_REFRESH_MS    2000
#define CONN_REFRESH_MS   3000

static FsFirewallState current_state = FS_FW_NONE;

/* Set by the toolbar's Lock button.  While TRUE the Policy page
 * refuses to write rules -- the lock is a real gate, not a label. */
static gboolean policy_locked = FALSE;

static GtkWidget *state_label;
static GtkWidget *state_icon;
static GtkWidget *backend_label;
static GtkWidget *logo_image;

/* Toolbar buttons, kept so the state change can enable/disable them. */
static GtkWidget *tool_start;
static GtkWidget *tool_stop;
static GtkWidget *tool_lock;

/* The in-page pair mirrors the toolbar so the controls still work when
 * the toolbar is collapsed on a narrow window. */
static GtkWidget *button_start;
static GtkWidget *button_stop;

/* Per-profile switches, used only when the backend supports them. */
static GtkWidget *profile_switches[FS_PROFILE_COUNT];
static GtkWidget *profiles_frame;

/* Events counters: [direction][total=0 serious=1]. */
static guint    events[2][2];
static GtkWidget *counter[2][2];

/* The two live panels. */
enum
{
	NET_COL_DEVICE,
	NET_COL_TYPE,
	NET_COL_RECV,
	NET_COL_SENT,
	NET_COL_ACTIVITY,
	NET_N_COLS
};

enum
{
	CONN_COL_SOURCE,
	CONN_COL_DEST,
	CONN_COL_PORT,
	CONN_COL_SERVICE,
	CONN_COL_PROGRAM,
	CONN_COL_DIRECTION,
	CONN_N_COLS
};

static GtkListStore *net_store;
static GtkListStore *conn_store;
static GtkWidget     *network_frame;
static GtkWidget     *connections_frame;

/* Previous interface sample, so consecutive polls yield a rate. */
typedef struct
{
	guint64 received;
	guint64 sent;
	gint64  stamp;   /* monotonic microseconds */
} NetSample;

static GHashTable *net_samples = NULL;

/* Load the embedded StockFW logo. */
static GdkPixbuf *
load_status_logo (void)
{
	GError *error = NULL;
	GdkPixbufLoader *loader;
	GdkPixbuf *pixbuf = NULL;

	loader = gdk_pixbuf_loader_new ();
	if (gdk_pixbuf_loader_write (loader, stockfw_logo_96_png,
	                             stockfw_logo_96_png_len, &error)) {
		gdk_pixbuf_loader_close (loader, NULL);
		pixbuf = gdk_pixbuf_loader_get_pixbuf (loader);
		if (pixbuf)
			g_object_ref (pixbuf);
	} else {
		g_clear_error (&error);
	}
	g_object_unref (loader);

	return pixbuf;
}

/* [ state_to_text ] */
static const gchar *
state_to_text (FsFirewallState state)
{
	switch (state) {
	case FS_FW_STOPPED: return _("The firewall is stopped");
	case FS_FW_RUNNING: return _("The firewall is running");
	case FS_FW_LOCKED:  return _("The firewall is locked");
	case FS_FW_HIT:     return _("The firewall has been hit");
	case FS_FW_NONE:
	default:            return _("Firewall state is unknown");
	}
}

/* [ state_to_icon ] -- themed emblem beside the status line. */
static const gchar *
state_to_icon (FsFirewallState state)
{
	switch (state) {
	case FS_FW_STOPPED: return "media-playback-stop";
	case FS_FW_RUNNING: return "media-playback-start";
	case FS_FW_LOCKED:  return "changes-prevent";
	case FS_FW_HIT:     return "dialog-warning";
	case FS_FW_NONE:
	default:            return "dialog-question";
	}
}

/* [ state_to_class ] -- CSS class giving the status line its colour. */
static const gchar *
state_to_class (FsFirewallState state)
{
	switch (state) {
	case FS_FW_STOPPED: return "fs-state-stopped";
	case FS_FW_LOCKED:  return "fs-state-locked";
	case FS_FW_RUNNING:
	case FS_FW_HIT:     return "fs-state-active";
	case FS_FW_NONE:
	default:            return "";
	}
}

/* [ install_css ]
 * Status colours live here rather than in gtk_widget_override_color,
 * which is deprecated and had no bold-face equivalent anyway. */
static void
install_css (GtkWidget *for_widget)
{
	static const gchar *css =
		".fs-state-active  { font-weight: bold; color: #2e7d32; }\n"
		".fs-state-stopped { font-weight: bold; color: #c62828; }\n"
		".fs-state-locked  { font-weight: bold; color: #b26a00; }\n"
		".fs-counter       { font-weight: bold; }\n"
		".fs-counter-head  { font-weight: bold; }\n";
	GError *error = NULL;
	GtkCssProvider *provider;

	provider = gtk_css_provider_new ();

	if (!gtk_css_provider_load_from_data (provider, css, -1, &error)) {
		g_clear_error (&error);
		g_object_unref (provider);
		return;
	}

	gtk_style_context_add_provider_for_screen (
		gtk_widget_get_screen (for_widget),
		GTK_STYLE_PROVIDER (provider),
		GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

	g_object_unref (provider);
}

/* [ on_profile_toggled ]
 * Fired when the user flips a profile switch.  We read which profile
 * from the widget's user-data property rather than threading state
 * through the signal payload. */
static void
on_profile_toggled (GtkSwitch *sw, GParamSpec *pspec, gpointer data)
{
	gboolean active = gtk_switch_get_active (sw);
	gpointer ud = g_object_get_data (G_OBJECT (sw), "user-data");
	gint profile = GPOINTER_TO_INT (ud);
	GError *error = NULL;

	(void) pspec;
	(void) data;

	if (!fs_backend ()->set_profile_enabled (profile, active, &error)) {
		fs_dialogs_error (NULL, _("Could not change the firewall profile"),
		                  error ? error->message : NULL);
		g_clear_error (&error);

		/* Revert the switch: the change did not happen. */
		g_signal_handlers_block_by_func (sw, on_profile_toggled, NULL);
		gtk_switch_set_active (sw, !active);
		g_signal_handlers_unblock_by_func (sw, on_profile_toggled, NULL);
	}
}

static void
refresh_controls (void)
{
	const FsBackend *backend = fs_backend ();
	gboolean running = (current_state == FS_FW_RUNNING ||
	                    current_state == FS_FW_LOCKED  ||
	                    current_state == FS_FW_HIT);
	gboolean usable = backend->available ();

	/* The toolbar is built after the page, so on the very first call
	 * its buttons do not exist yet. */
	if (tool_start != NULL)
		gtk_widget_set_sensitive (tool_start, usable && !running);
	if (tool_stop != NULL)
		gtk_widget_set_sensitive (tool_stop, usable && running);
	if (button_start != NULL)
		gtk_widget_set_sensitive (button_start, usable && !running);
	if (button_stop != NULL)
		gtk_widget_set_sensitive (button_stop, usable && running);

	/* Reflect the real profile states whenever the main state
	 * changes.  Done with the signal blocked so the refresh
	 * itself does not read as a user toggle. */
	for (gint i = 0; i < FS_PROFILE_COUNT; i++) {
		gboolean enabled = FALSE;

		if (profile_switches[i] != NULL &&
		    backend->get_profile_enabled (i, &enabled)) {
			g_signal_handlers_block_by_func (profile_switches[i],
			                                 on_profile_toggled, NULL);
			gtk_switch_set_active (GTK_SWITCH (profile_switches[i]),
			                       enabled);
			g_signal_handlers_unblock_by_func (profile_switches[i],
			                                   on_profile_toggled, NULL);
		}
	}
}

/* ------------------------------------------------------------------ events
 *
 * Four numbers: Inbound/Outbound, each split into Total and Serious
 * (blocked), matching the original's counter table.
 */

static void
update_counters (void)
{
	for (gint dir = 0; dir < 2; dir++) {
		for (gint kind = 0; kind < 2; kind++) {
			gchar *text;

			if (counter[dir][kind] == NULL)
				continue;

			text = g_strdup_printf ("%u", events[dir][kind]);
			gtk_label_set_text (GTK_LABEL (counter[dir][kind]), text);
			g_free (text);
		}
	}
}

void
fs_statusview_event_in (gboolean serious)
{
	events[0][0]++;
	if (serious)
		events[0][1]++;

	update_counters ();
}

void
fs_statusview_event_out (gboolean serious)
{
	events[1][0]++;
	if (serious)
		events[1][1]++;

	update_counters ();
}

void
fs_statusview_events_reset (void)
{
	events[0][0] = events[0][1] = 0;
	events[1][0] = events[1][1] = 0;

	update_counters ();
}

/* ------------------------------------------------------------ formatting */

/* [ format_bytes ]
 * Binary units, one decimal above kilobytes: the original printed
 * "1.4 GB", not "1503238553". */
static gchar *
format_bytes (guint64 bytes)
{
	const guint64 kib = 1024;
	const guint64 mib = kib * 1024;
	const guint64 gib = mib * 1024;

	if (bytes >= gib)
		return g_strdup_printf ("%.1f GiB", (gdouble) bytes / (gdouble) gib);
	if (bytes >= mib)
		return g_strdup_printf ("%.1f MiB", (gdouble) bytes / (gdouble) mib);
	if (bytes >= kib)
		return g_strdup_printf ("%.1f KiB", (gdouble) bytes / (gdouble) kib);

	return g_strdup_printf ("%u B", (guint) bytes);
}

static gchar *
format_rate (guint64 bytes_per_second)
{
	gchar *amount;
	gchar *text;

	if (bytes_per_second == 0)
		return g_strdup (_("Idle"));

	amount = format_bytes (bytes_per_second);
	text = g_strdup_printf ("%s/s", amount);
	g_free (amount);

	return text;
}

/* [ store_set_nth ]
 * Sets row N, appending it when the store has not reached N yet.  Going
 * row by row like this keeps the scroll position and selection stable
 * across refreshes, which clear-and-refill would throw away every
 * couple of seconds. */
static void
store_set_nth (GtkListStore *store, gint n, const gchar *const *values,
               gint n_cols)
{
	GtkTreeIter iter;
	gboolean have = gtk_tree_model_iter_nth_child (GTK_TREE_MODEL (store),
	                                               &iter, NULL, n);

	/* Rows are written in order, so a miss means the store is one
	 * short and this row is the append. */
	if (!have)
		gtk_list_store_append (store, &iter);

	for (gint i = 0; i < n_cols; i++)
		gtk_list_store_set (store, &iter, i, values[i], -1);
}

/* [ store_trim ]
 * Drop rows past the ones just written. */
static void
store_trim (GtkListStore *store, gint keep)
{
	while (gtk_tree_model_iter_n_children (GTK_TREE_MODEL (store), NULL) > keep) {
		GtkTreeIter iter;

		if (!gtk_tree_model_iter_nth_child (GTK_TREE_MODEL (store), &iter,
		                                    NULL, keep))
			break;

		gtk_list_store_remove (store, &iter);
	}
}

/* ------------------------------------------------------------- network */

/* [ refresh_network ]
 * Sample the interface counters and turn two consecutive samples into
 * the Activity column. */
static void
refresh_network (void)
{
	const FsBackend *backend = fs_backend ();
	GList *stats, *l;
	gint64 now;
	gint row = 0;

	if (net_store == NULL || network_frame == NULL)
		return;

	if (backend->list_interface_stats == NULL)
		return;

	stats = backend->list_interface_stats ();

	if (stats == NULL) {
		/* Nothing to show.  Hide the panel rather than present an
		 * empty table as if it were live. */
		gtk_widget_hide (network_frame);
		g_hash_table_remove_all (net_samples);
		return;
	}

	gtk_widget_show (network_frame);

	now = g_get_monotonic_time ();

	for (l = stats; l != NULL; l = l->next) {
		FsIfaceStat *stat = l->data;
		NetSample *prev;
		guint64 rate = 0;
		gchar *recv, *sent, *activity;
		const gchar *values[NET_N_COLS];

		prev = g_hash_table_lookup (net_samples, stat->device);

		if (prev != NULL && now > prev->stamp) {
			gdouble elapsed = (gdouble) (now - prev->stamp) / 1000000.0;
			/* A counter that went backwards means the adapter
			 * was reset, not that traffic was un-sent. */
			guint64 dr = stat->received >= prev->received
			           ? stat->received - prev->received : 0;
			guint64 ds = stat->sent >= prev->sent
			           ? stat->sent - prev->sent : 0;

			rate = (guint64) ((gdouble) (dr + ds) / elapsed);
		}

		prev = g_new0 (NetSample, 1);
		prev->received = stat->received;
		prev->sent     = stat->sent;
		prev->stamp    = now;

		/* Replacing by device name means an adapter that vanishes
		 * takes its old sample with it. */
		g_hash_table_insert (net_samples, g_strdup (stat->device), prev);

		recv     = format_bytes (stat->received);
		sent     = format_bytes (stat->sent);
		activity = format_rate (rate);

		values[NET_COL_DEVICE]  = stat->device;
		values[NET_COL_TYPE]    = stat->kind != NULL ? stat->kind : "";
		values[NET_COL_RECV]    = recv;
		values[NET_COL_SENT]    = sent;
		values[NET_COL_ACTIVITY] = activity;

		store_set_nth (net_store, row, values, NET_N_COLS);

		g_free (recv);
		g_free (sent);
		g_free (activity);

		row++;
	}

	store_trim (net_store, row);
}

/* --------------------------------------------------------- connections */

static void
refresh_connections (void)
{
	const FsBackend *backend = fs_backend ();
	GList *conns, *l;
	gint row = 0;

	if (conn_store == NULL || connections_frame == NULL)
		return;

	if (backend->list_connections == NULL)
		return;

	conns = backend->list_connections ();

	if (conns == NULL) {
		/* An empty list is a legitimate answer (nothing open), so
		 * this empties the table rather than hiding the panel. */
		store_trim (conn_store, 0);
		return;
	}

	gtk_widget_show (connections_frame);

	for (l = conns; l != NULL; l = l->next) {
		FsConnection *c = l->data;
		const gchar *values[CONN_N_COLS];

		values[CONN_COL_SOURCE]    = c->source      ? c->source      : "";
		values[CONN_COL_DEST]      = c->destination ? c->destination : "";
		values[CONN_COL_PORT]      = c->port        ? c->port        : "";
		values[CONN_COL_SERVICE]   = c->service     ? c->service     : "";
		values[CONN_COL_PROGRAM]   = c->program     ? c->program     : "";
		values[CONN_COL_DIRECTION] = c->direction   ? c->direction   : "";

		store_set_nth (conn_store, row, values, CONN_N_COLS);
		row++;
	}

	store_trim (conn_store, row);
}

void
fs_statusview_refresh (void)
{
	refresh_network ();
	refresh_connections ();
}

/* [ on_net_timeout ] [ on_conn_timeout ]
 * g_timeout_add wants a gboolean back; these return TRUE to keep the
 * timer running. */
static gboolean
on_net_timeout (gpointer data)
{
	(void) data;
	refresh_network ();
	return TRUE;
}

static gboolean
on_conn_timeout (gpointer data)
{
	(void) data;
	refresh_connections ();
	return TRUE;
}

/* --------------------------------------------------------------- actions */

static void
on_start_clicked (GtkButton *button, gpointer data)
{
	GError *error = NULL;

	(void) button;
	(void) data;

	if (!fs_backend ()->start (&error)) {
		fs_dialogs_error (NULL, _("Failed to start the firewall"),
		                  error ? error->message : NULL);
		g_clear_error (&error);
		return;
	}

	fs_statusview_set_state (fs_backend ()->get_state ());
}

static void
on_stop_clicked (GtkButton *button, gpointer data)
{
	GError *error = NULL;

	(void) button;
	(void) data;

	if (!fs_backend ()->stop (&error)) {
		fs_dialogs_error (NULL, _("Failed to stop the firewall"),
		                  error ? error->message : NULL);
		g_clear_error (&error);
		return;
	}

	fs_statusview_set_state (fs_backend ()->get_state ());
}

/* [ on_preferences_clicked ]
 * The dialog saves the keys itself and then calls
 * fs_app_reload_settings(), so the new settings reach the rules
 * before the dialog is even gone. */
static void
on_preferences_clicked (GtkToolButton *button, gpointer data)
{
	(void) data;

	fs_dialogs_preferences (gtk_widget_get_toplevel (GTK_WIDGET (button)));
}

/* [ on_lock_toggled ]
 * A real gate: while locked the Policy page refuses to apply.  Nothing
 * at the OS level is touched, so this is undoable and never leaves the
 * machine with a rule set the user cannot see. */
static void
on_lock_toggled (GtkToolButton *button, gpointer data)
{
	(void) button;
	(void) data;

	policy_locked = !policy_locked;

	if (policy_locked && current_state == FS_FW_RUNNING)
		current_state = FS_FW_LOCKED;
	else if (!policy_locked && current_state == FS_FW_LOCKED)
		current_state = FS_FW_RUNNING;

	fs_statusview_set_state (current_state);
}

gboolean
fs_statusview_policy_locked (void)
{
	return policy_locked;
}

void
fs_statusview_set_state (FsFirewallState state)
{
	GtkStyleContext *ctx;
	const gchar *klass;

	current_state = state;

	if (state_label != NULL)
		gtk_label_set_text (GTK_LABEL (state_label), state_to_text (state));

	if (state_icon != NULL)
		gtk_image_set_from_icon_name (GTK_IMAGE (state_icon),
		                              state_to_icon (state),
		                              GTK_ICON_SIZE_DIALOG);

	/* Swap the colour class rather than stacking them. */
	klass = state_to_class (state);

	ctx = gtk_widget_get_style_context (state_label);
	gtk_style_context_remove_class (ctx, "fs-state-active");
	gtk_style_context_remove_class (ctx, "fs-state-stopped");
	gtk_style_context_remove_class (ctx, "fs-state-locked");

	if (*klass != '\0')
		gtk_style_context_add_class (ctx, klass);

	if (tool_lock != NULL)
		gtk_toggle_tool_button_set_active (GTK_TOGGLE_TOOL_BUTTON (tool_lock),
		                                   policy_locked);

	refresh_controls ();
}

FsFirewallState
fs_statusview_get_state (void)
{
	return current_state;
}

/* ------------------------------------------------------------------ page */

/* [ make_table ]
 * A scrolled tree view inside a labelled frame, both sized so the page
 * scrolls as a whole instead of each table claiming the window. */
static GtkWidget *
make_table (const gchar *title, GtkListStore **store_out,
            const gchar *const *labels, gint n_cols)
{
	GtkWidget *frame, *scroll, *view;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;

	*store_out = gtk_list_store_new (n_cols, G_TYPE_STRING, G_TYPE_STRING,
	                                 G_TYPE_STRING, G_TYPE_STRING,
	                                 G_TYPE_STRING, G_TYPE_STRING,
	                                 G_TYPE_STRING, G_TYPE_STRING);

	view = gtk_tree_view_new_with_model (GTK_TREE_MODEL (*store_out));
	gtk_tree_view_set_headers_visible (GTK_TREE_VIEW (view), TRUE);

	for (gint i = 0; i < n_cols; i++) {
		renderer = gtk_cell_renderer_text_new ();
		column = gtk_tree_view_column_new_with_attributes (
			_(labels[i]), renderer, "text", i, NULL);
		gtk_tree_view_column_set_resizable (column, TRUE);
		gtk_tree_view_append_column (GTK_TREE_VIEW (view), column);
	}

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	gtk_widget_set_size_request (scroll, -1, 140);
	gtk_container_add (GTK_CONTAINER (scroll), view);

	frame = gtk_frame_new (_(title));
	gtk_container_add (GTK_CONTAINER (frame), scroll);

	return frame;
}

/* [ build_events_box ] -- the Total / Serious counter table. */
static GtkWidget *
build_events_box (void)
{
	GtkWidget *frame, *grid;
	const gchar *heads[] = { "", N_("Total"), N_("Serious") };
	const gchar *dirs[]  = { N_("Inbound"), N_("Outbound") };

	grid = gtk_grid_new ();
	gtk_grid_set_row_spacing (GTK_GRID (grid), 4);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 14);
	gtk_container_set_border_width (GTK_CONTAINER (grid), 6);

	for (gint col = 0; col < 3; col++) {
		GtkWidget *label = gtk_label_new (heads[col][0] != '\0'
		                                  ? _(heads[col]) : "");
		gtk_widget_set_halign (label, col == 0 ? GTK_ALIGN_START
		                                       : GTK_ALIGN_END);
		gtk_style_context_add_class (gtk_widget_get_style_context (label),
		                             "fs-counter-head");
		gtk_grid_attach (GTK_GRID (grid), label, col, 0, 1, 1);
	}

	for (gint dir = 0; dir < 2; dir++) {
		GtkWidget *label = gtk_label_new (_(dirs[dir]));

		gtk_label_set_xalign (GTK_LABEL (label), 0.0);
		gtk_grid_attach (GTK_GRID (grid), label, 0, dir + 1, 1, 1);

		for (gint kind = 0; kind < 2; kind++) {
			GtkWidget *value = gtk_label_new ("0");

			gtk_widget_set_halign (value, GTK_ALIGN_END);
			gtk_style_context_add_class (
				gtk_widget_get_style_context (value), "fs-counter");

			gtk_grid_attach (GTK_GRID (grid), value, kind + 1,
			                 dir + 1, 1, 1);

			counter[dir][kind] = value;
		}
	}

	frame = gtk_frame_new (_("Events"));
	gtk_container_add (GTK_CONTAINER (frame), grid);

	return frame;
}

/* [ fs_statusview_toolbar ]
 * The Status page's icon row: Preferences, Lock, Start, Stop.
 *
 * The items are handed to the toolbar and not unreffed afterwards:
 * gtk_toolbar_insert() takes over the floating reference they were
 * created with, so unreffing would free them while the toolbar still
 * held them, and every later use of tool_start/tool_stop/tool_lock
 * would be a use-after-free. */
GtkWidget *
fs_statusview_toolbar (void)
{
	GtkWidget *toolbar;
	GtkToolItem *item;

	toolbar = gtk_toolbar_new ();
	gtk_toolbar_set_style (GTK_TOOLBAR (toolbar), GTK_TOOLBAR_BOTH_HORIZ);

	item = gtk_tool_button_new (NULL, _("Preferences"));
	gtk_tool_button_set_icon_name (GTK_TOOL_BUTTON (item),
	                               "preferences-system");
	gtk_tool_item_set_tooltip_text (item, _("Open the preferences dialog"));
	g_signal_connect (item, "clicked",
	                  G_CALLBACK (on_preferences_clicked), NULL);
	gtk_toolbar_insert (GTK_TOOLBAR (toolbar), item, -1);

	item = gtk_separator_tool_item_new ();
	gtk_toolbar_insert (GTK_TOOLBAR (toolbar), item, -1);

	item = gtk_toggle_tool_button_new ();
	gtk_tool_button_set_label (GTK_TOOL_BUTTON (item), _("Lock Firewall"));
	gtk_tool_button_set_icon_name (GTK_TOOL_BUTTON (item), "changes-prevent");
	gtk_tool_item_set_tooltip_text (item,
		_("Lock policy editing until unlocked again"));
	g_signal_connect (item, "toggled", G_CALLBACK (on_lock_toggled), NULL);
	gtk_toolbar_insert (GTK_TOOLBAR (toolbar), item, -1);
	tool_lock = GTK_WIDGET (item);

	item = gtk_tool_button_new (NULL, _("Start"));
	gtk_tool_button_set_icon_name (GTK_TOOL_BUTTON (item),
	                               "media-playback-start");
	gtk_tool_item_set_tooltip_text (item, _("Start the firewall"));
	g_signal_connect (item, "clicked", G_CALLBACK (on_start_clicked), NULL);
	gtk_toolbar_insert (GTK_TOOLBAR (toolbar), item, -1);
	tool_start = GTK_WIDGET (item);

	item = gtk_tool_button_new (NULL, _("Stop"));
	gtk_tool_button_set_icon_name (GTK_TOOL_BUTTON (item),
	                               "media-playback-stop");
	gtk_tool_item_set_tooltip_text (item, _("Stop the firewall"));
	g_signal_connect (item, "clicked", G_CALLBACK (on_stop_clicked), NULL);
	gtk_toolbar_insert (GTK_TOOLBAR (toolbar), item, -1);
	tool_stop = GTK_WIDGET (item);

	return toolbar;
}

/* [ fs_statusview_page ] */
GtkWidget *
fs_statusview_page (void)
{
	GtkWidget *page, *header, *top, *left, *button_box;
	static const gchar *net_labels[NET_N_COLS] = {
		"Device", "Type", "Received", "Sent", "Activity"
	};
	static const gchar *conn_labels[CONN_N_COLS] = {
		"Source", "Destination", "Port", "Service", "Program", "Direction"
	};
	const FsBackend *backend = fs_backend ();

	page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 10);
	gtk_container_set_border_width (GTK_CONTAINER (page), 10);

	/* ---- logo banner ---- */
	header = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	{
		GdkPixbuf *logo = load_status_logo ();

		if (logo != NULL) {
			logo_image = gtk_image_new_from_pixbuf (logo);
			g_object_unref (logo);
			gtk_box_pack_start (GTK_BOX (header), logo_image,
			                    FALSE, FALSE, 0);
		}

		{
			GtkWidget *title_box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
			GtkWidget *title = gtk_label_new ("StockFW");
			GtkWidget *subtitle = gtk_label_new (
				_("Smart Firewall Configuration Tool"));

			gtk_label_set_xalign (GTK_LABEL (title), 0.0);
			gtk_label_set_xalign (GTK_LABEL (subtitle), 0.0);
			gtk_style_context_add_class (
				gtk_widget_get_style_context (title), "title");
			gtk_style_context_add_class (
				gtk_widget_get_style_context (subtitle), "dim-label");

			gtk_box_pack_start (GTK_BOX (title_box), title, FALSE, FALSE, 0);
			gtk_box_pack_start (GTK_BOX (title_box), subtitle, FALSE, FALSE, 0);
			gtk_box_pack_start (GTK_BOX (header), title_box, TRUE, TRUE, 0);
		}
	}
	gtk_box_pack_start (GTK_BOX (page), header, FALSE, FALSE, 0);

	/* ---- status line + events counters ---- */
	top = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);

	left = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	gtk_widget_set_valign (left, GTK_ALIGN_START);

	state_icon = gtk_image_new_from_icon_name (state_to_icon (FS_FW_NONE),
	                                           GTK_ICON_SIZE_DIALOG);
	gtk_box_pack_start (GTK_BOX (left), state_icon, FALSE, FALSE, 0);

	{
		GtkWidget *col = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);

		state_label = gtk_label_new (state_to_text (FS_FW_NONE));
		gtk_label_set_xalign (GTK_LABEL (state_label), 0.0);
		install_css (state_label);
		gtk_style_context_add_class (gtk_widget_get_style_context (state_label),
		                             state_to_class (FS_FW_NONE));

		backend_label = gtk_label_new (backend->display_name);
		gtk_label_set_xalign (GTK_LABEL (backend_label), 0.0);
		gtk_style_context_add_class (
			gtk_widget_get_style_context (backend_label), "dim-label");

		gtk_box_pack_start (GTK_BOX (col), state_label, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (col), backend_label, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (left), col, TRUE, TRUE, 0);
	}

	gtk_box_pack_start (GTK_BOX (top), left, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (top), build_events_box (), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), top, FALSE, FALSE, 0);

	/* ---- start/stop, for when the toolbar is collapsed ---- */
	button_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_widget_set_halign (button_box, GTK_ALIGN_START);

	button_start = gtk_button_new_with_label (_("Start firewall"));
	button_stop  = gtk_button_new_with_label (_("Stop firewall"));

	g_signal_connect (button_start, "clicked",
	                  G_CALLBACK (on_start_clicked), NULL);
	g_signal_connect (button_stop, "clicked",
	                  G_CALLBACK (on_stop_clicked), NULL);

	gtk_box_pack_start (GTK_BOX (button_box), button_start, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (button_box), button_stop,  FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (page), button_box, FALSE, FALSE, 0);

	/* ---- profile switches ---- */
	profiles_frame = gtk_frame_new (_("Firewall profiles"));
	{
		GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
		const gchar *names[] = { _("Domain"), _("Private"), _("Public") };

		gtk_container_set_border_width (GTK_CONTAINER (inner), 6);
		gtk_container_add (GTK_CONTAINER (profiles_frame), inner);

		for (gint i = 0; i < FS_PROFILE_COUNT; i++) {
			GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
			GtkWidget *label = gtk_label_new (names[i]);
			GtkWidget *toggle = gtk_switch_new ();
			gboolean enabled = FALSE;

			gtk_label_set_xalign (GTK_LABEL (label), 0.0);
			gtk_widget_set_hexpand (label, TRUE);
			g_object_set_data (G_OBJECT (toggle), "user-data",
			                   GINT_TO_POINTER (i));

			if (fs_backend ()->get_profile_enabled (i, &enabled))
				gtk_switch_set_active (GTK_SWITCH (toggle), enabled);

			g_signal_connect (toggle, "notify::active",
			                  G_CALLBACK (on_profile_toggled), NULL);

			gtk_box_pack_start (GTK_BOX (row), label, TRUE, TRUE, 0);
			gtk_box_pack_start (GTK_BOX (row), toggle, FALSE, FALSE, 0);
			gtk_box_pack_start (GTK_BOX (inner), row, FALSE, FALSE, 0);

			profile_switches[i] = toggle;
		}
	}

	/* The backend decides whether to show this: Windows has three
	 * profiles, Linux has one global state and hides the box. */
	{
		gboolean any = FALSE;

		for (gint i = 0; i < FS_PROFILE_COUNT; i++) {
			if (fs_backend ()->get_profile_enabled (i, NULL))
				any = TRUE;
		}

		if (any)
			gtk_widget_show_all (profiles_frame);
		else
			gtk_widget_hide (profiles_frame);
	}

	gtk_box_pack_start (GTK_BOX (page), profiles_frame, FALSE, FALSE, 0);

	/* ---- the two live tables ---- */
	net_samples = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                     g_free, g_free);

	network_frame = make_table (_("Network"), &net_store,
	                            net_labels, NET_N_COLS);
	gtk_box_pack_start (GTK_BOX (page), network_frame, FALSE, FALSE, 0);

	connections_frame = make_table (_("Active connections"), &conn_store,
	                                conn_labels, CONN_N_COLS);
	gtk_box_pack_start (GTK_BOX (page), connections_frame, FALSE, FALSE, 0);

	/* Hidden until the first sample proves there is data. */
	gtk_widget_hide (network_frame);

	refresh_controls ();
	fs_statusview_set_state (FS_FW_NONE);

	g_timeout_add (NET_REFRESH_MS,  on_net_timeout,  NULL);
	g_timeout_add (CONN_REFRESH_MS, on_conn_timeout, NULL);

	/* First sample immediately so the panels are not empty for two
	 * seconds after startup. */
	fs_statusview_refresh ();

	return page;
}
