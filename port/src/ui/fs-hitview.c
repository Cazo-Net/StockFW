/*---[ fs-hitview.c ]--------------------------------------------------
 * The Events page.
 *
 * A bounded list of firewall hits, fed by the platform backend.  The
 * original kept every hit in a GList and appended straight to the
 * model; on a busy machine that grows without limit, so rows are capped
 * and the oldest dropped.
 *--------------------------------------------------------------------*/

#include "ui/fs-hitview.h"
#include "ui/fs-dialogs.h"
#include "ui/fs-copilot.h"
#include "ui/fs-statusview.h"
#include "core/fs-backend.h"
#include "core/fs-service.h"
#include "core/fs-prefs.h"
#include "core/fs-copilot.h"
#include "core/fs-i18n.h"

#include <string.h>

/* How many rows to keep.  Beyond this the oldest is dropped, so a
 * long-running session cannot exhaust memory. */
#define FS_HITVIEW_MAX_ROWS 2000

static GtkWidget    *view;
static GtkListStore *store;
static GtkWidget    *count_label;
static GtkWidget    *monitor_warning;        /* strip; hidden unless needed */
static GtkWidget    *monitor_warning_label;

/* Column order matches FsHitColumn; the colour column is last. */
enum
{
	COL_TIME,
	COL_DIRECTION,
	COL_IN,
	COL_OUT,
	COL_PORT,
	COL_SOURCE,
	COL_DESTINATION,
	COL_LENGTH,
	COL_TOS,
	COL_PROTOCOL,
	COL_SERVICE,
	COL_COLOR,
	COL_COUNT
};

static const struct
{
	const gchar *label;
	gboolean     visible;
	const gchar *pref_key;
} column_defs[FS_NUM_HITCOLUMNS] = {
	{ N_("Time"),        TRUE,  "/apps/stockfw/client/ui/hitview_time_col" },
	{ N_("Direction"),   TRUE,  "/apps/stockfw/client/ui/hitview_direction_col" },
	{ N_("In"),          TRUE,  "/apps/stockfw/client/ui/hitview_in_col" },
	{ N_("Out"),         TRUE,  "/apps/stockfw/client/ui/hitview_out_col" },
	{ N_("Port"),        TRUE,  "/apps/stockfw/client/ui/hitview_port_col" },
	{ N_("Source"),      TRUE,  "/apps/stockfw/client/ui/hitview_source_col" },
	{ N_("Destination"), TRUE,  "/apps/stockfw/client/ui/hitview_destination_col" },
	{ N_("Length"),      FALSE, "/apps/stockfw/client/ui/hitview_length_col" },
	{ N_("ToS"),         FALSE, "/apps/stockfw/client/ui/hitview_tos_col" },
	{ N_("Protocol"),    TRUE,  "/apps/stockfw/client/ui/hitview_protocol_col" },
	{ N_("Service"),     TRUE,  "/apps/stockfw/client/ui/hitview_service_col" },
	{ N_(""),            FALSE, NULL },   /* colour, never shown */
};

static guint row_count = 0;

/* [ color_cell_data ]
 * Applies the colour column to a text cell.  Rows with no colour keep
 * the theme default. */
static void
color_cell_data (GtkTreeViewColumn *column, GtkCellRenderer *renderer,
                 GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	gchar *color = NULL;

	(void) column;
	(void) data;

	gtk_tree_model_get (model, iter, COL_COLOR, &color, -1);

	g_object_set (renderer, "foreground",
	              (color != NULL && *color != '\0') ? color : NULL,
	              NULL);
	g_free (color);
}

/* [ update_count_label ] */
static void
update_count_label (void)
{
	gchar *text;

	if (count_label == NULL)
		return;

	text = g_strdup_printf (row_count == 1 ? "%u event" : "%u events",
	                        row_count);
	gtk_label_set_text (GTK_LABEL (count_label), text);
	g_free (text);
}

/* [ hit_is_blocked ]
 * The Windows backend marks dropped events by appending " [BLOCKED]"
 * to the service field.  Everything the Status page counts as "serious"
 * and everything the Events page paints red comes from this. */
static gboolean
hit_is_blocked (const FsHit *hit)
{
	return hit != NULL && hit->service != NULL &&
	       strstr (hit->service, "[BLOCKED]") != NULL;
}

/* [ hit_is_inbound ]
 * Direction arrives as "In"/"Out" from the parser and as the
 * "Inbound"/"Outbound" wording from other paths, so both are accepted. */
static gboolean
hit_is_inbound (const FsHit *hit)
{
	if (hit == NULL || hit->direction == NULL)
		return FALSE;

	return g_ascii_strcasecmp (hit->direction, "In") == 0 ||
	       g_ascii_strcasecmp (hit->direction, "Inbound") == 0;
}

/* [ hit_is_outbound ] */
static gboolean
hit_is_outbound (const FsHit *hit)
{
	if (hit == NULL || hit->direction == NULL)
		return FALSE;

	return g_ascii_strcasecmp (hit->direction, "Out") == 0 ||
	       g_ascii_strcasecmp (hit->direction, "Outbound") == 0;
}

/* ---- the two Interface > Events filters -----------------------------
 *
 * Ported from the original hitview.c, which ran both inside
 * hitview_append_hit() before the status counters were touched.  So a
 * filtered event produces no row, no counter tick and no Copilot
 * input -- it is as if the firewall had not logged it. */

/* The row the list accepted most recently, kept as copies rather than
 * as a pointer into the model because rows are trimmed once the cap
 * is passed. */
static gchar *last_port = NULL;
static gchar *last_proto = NULL;
static gchar *last_src = NULL;
static gchar *last_dst = NULL;

/* [ hit_is_redundant ]
 * The original compared port, protocol, source and destination
 * against the previous hit and treated a match as one event repeated.
 * Checked most likely to differ first. */
static gboolean
hit_is_redundant (const FsHit *hit)
{
	if (hit == NULL || last_dst == NULL ||
	    hit->port == NULL || hit->protocol == NULL ||
	    hit->source == NULL || hit->destination == NULL)
		return FALSE;

	if (g_strcmp0 (hit->port, last_port) != 0)
		return FALSE;

	if (g_strcmp0 (hit->protocol, last_proto) != 0)
		return FALSE;

	if (g_strcmp0 (hit->source, last_src) != 0)
		return FALSE;

	return g_strcmp0 (hit->destination, last_dst) == 0;
}

static void
remember_hit (const FsHit *hit)
{
	if (hit == NULL)
		return;

	g_free (last_port);
	g_free (last_proto);
	g_free (last_src);
	g_free (last_dst);

	last_port  = g_strdup (hit->port);
	last_proto = g_strdup (hit->protocol);
	last_src   = g_strdup (hit->source);
	last_dst   = g_strdup (hit->destination);
}

/* Local addresses are refreshed on a timer rather than read per event:
 * the Windows implementation asks GetAdaptersAddresses, which is far
 * too heavy to call for every packet in a flood. */
static GList  *local_addresses = NULL;
static gint64  local_addresses_checked = 0;

static GList *
current_local_addresses (void)
{
	const gint64 now = g_get_monotonic_time ();

	if (local_addresses == NULL || now - local_addresses_checked > 10 * G_USEC_PER_SEC) {
		g_list_free_full (local_addresses,
		                  (GDestroyNotify) fs_interface_free);
		local_addresses = fs_backend ()->list_interfaces ();
		local_addresses_checked = now;
	}

	return local_addresses;
}

/* [ hit_is_for_me ]
 * TRUE when the destination is one of this machine's own addresses.
 *
 * The original compared against the single external interface's IP.
 * Asking every interface is both more accurate and something that can
 * work on Windows, which has no one "external device" to query.  The
 * useful effect is the same: broadcast and multicast destinations are
 * not us, so discovery noise stops flooding the list. */
static gboolean
hit_is_for_me (const FsHit *hit)
{
	GList *ifaces;
	gboolean found = FALSE;

	if (hit == NULL || hit->destination == NULL)
		return FALSE;

	ifaces = current_local_addresses ();

	for (GList *l = ifaces; l != NULL; l = l->next) {
		FsInterface *iface = l->data;

		if (iface->ip != NULL &&
		    g_ascii_strcasecmp (iface->ip, hit->destination) == 0) {
			found = TRUE;
			break;
		}
	}

	return found;
}

/* [ on_hit ]
 * Backend log callback.  Runs on the main loop because the backend
 * delivers through a GLib source. */
static void
on_hit (const FsHit *hit, gpointer user_data)
{
	gboolean blocked;

	/* Both filters run before anything is counted, as they did in the
	 * original. */
	if (fs_prefs_get_bool (FS_PREFS_SKIP_REDUNDANT, FALSE) &&
	    hit_is_redundant (hit))
		return;

	if (fs_prefs_get_bool (FS_PREFS_SKIP_NOT_FOR_FIREWALL, TRUE) &&
	    !hit_is_for_me (hit) && !hit_is_outbound (hit))
		return;

	if (!fs_hitview_append (hit))
		return;

	blocked = hit_is_blocked (hit);
	remember_hit (hit);

	/* Feed to copilot for learning and anomaly detection. */
	extern FsCopilot *copilot;
	if (copilot != NULL)
		fs_copilot_feed_event (copilot, hit);

	/* Update copilot stats counter. */
	fs_copilot_note_event ();

	/* Status page counters.  These were declared but never called,
	 * which is why the panel always read 0. */
	if (hit_is_inbound (hit))
		fs_statusview_event_in (blocked);
	else
		fs_statusview_event_out (blocked);
}

gboolean
fs_hitview_append (const FsHit *hit)
{
	GtkTreeIter iter;
	const gchar *fields[FS_NUM_HITCOLUMNS];

	if (store == NULL || hit == NULL)
		return FALSE;

	fields[COL_TIME]        = hit->time;
	fields[COL_DIRECTION]   = hit->direction;
	fields[COL_IN]          = hit->in;
	fields[COL_OUT]         = hit->out;
	fields[COL_PORT]        = hit->port;
	fields[COL_SOURCE]      = hit->source;
	fields[COL_DESTINATION] = hit->destination;
	fields[COL_LENGTH]      = hit->length;
	fields[COL_TOS]         = hit->tos;
	fields[COL_PROTOCOL]    = hit->protocol;
	fields[COL_SERVICE]     = hit->service;
	/* Paint blocked events red, as the original did.  The colour is a
	 * separate column because GtkCellRendererText has no per-row text
	 * colour; a cell-data-func below reads it back. */
	fields[COL_COLOR]       = hit_is_blocked (hit) ? "#cc0000" : "";

	gtk_list_store_append (store, &iter);

	for (gint i = 0; i < FS_NUM_HITCOLUMNS; i++)
		gtk_list_store_set (store, &iter, i, fields[i] ? fields[i] : "", -1);

	row_count++;

	/* Drop the oldest row once the cap is passed.  GtkListStore has no
	 * "remove first" helper, so walk to the first row and remove it. */
	while (row_count > FS_HITVIEW_MAX_ROWS) {
		GtkTreeIter first;

		if (!gtk_tree_model_get_iter_first (GTK_TREE_MODEL (store), &first))
			break;

		gtk_list_store_remove (store, &first);
		row_count--;
	}

	/* Follow the tail when the list is already scrolled to the end, so
	 * a user watching events sees new ones without scrolling. */
	{
		GtkWidget *parent = gtk_widget_get_parent (view);
		GtkAdjustment *adj = NULL;

		if (GTK_IS_SCROLLED_WINDOW (parent))
			adj = gtk_scrolled_window_get_vadjustment (
				GTK_SCROLLED_WINDOW (parent));

		if (adj != NULL &&
		    gtk_adjustment_get_value (adj) >=
		    gtk_adjustment_get_upper (adj) - 1.0)
			gtk_tree_view_scroll_to_cell (GTK_TREE_VIEW (view), NULL,
			                               NULL, FALSE, 0, 0);
	}

	update_count_label ();

	return TRUE;
}

guint
fs_hitview_count (void)
{
	return row_count;
}

void
fs_hitview_clear (void)
{
	if (store != NULL)
		gtk_list_store_clear (store);

	row_count = 0;
	update_count_label ();
}

/* [ set_monitor_warning ]
 * The reason monitoring cannot run, shown as a strip above the list.
 * It stays on the page rather than flashing past in a dialog, because
 * the user needs the cause to still be there when they look again and
 * an empty list with no explanation is indistinguishable from a
 * firewall with nothing to report.  NULL clears it. */
static void
set_monitor_warning (const gchar *reason)
{
	if (monitor_warning == NULL)
		return;

	if (reason == NULL) {
		gtk_widget_hide (monitor_warning);
		return;
	}

	gtk_label_set_text (GTK_LABEL (monitor_warning_label), reason);
	gtk_widget_show (monitor_warning);
}

void
fs_hitview_reload (void)
{
	GError *error = NULL;

	/* The list is a live tail, not a file to re-read: restarting the
	 * source is the equivalent of a reload. */
	fs_hitview_clear ();
	fs_hitview_stop  ();

	if (!fs_hitview_start (&error)) {
		set_monitor_warning (error != NULL
		                     ? error->message
		                     : _("Monitoring could not be restarted."));
		g_clear_error (&error);
	}
}

gboolean
fs_hitview_start (GError **error)
{
	const FsBackend *backend = fs_backend ();

	if (fs_hitview_active ())
		return TRUE;

	return backend->log_start (on_hit, NULL, error);
}

void
fs_hitview_stop (void)
{
	if (fs_hitview_active ())
		fs_backend ()->log_stop ();
}

gboolean
fs_hitview_active (void)
{
	return fs_backend ()->log_active ();
}

const FsHit *
fs_hitview_selected (void)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	static gchar *fields[FS_NUM_HITCOLUMNS];
	static FsHit hit;

	if (view == NULL)
		return NULL;

	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (view));

	if (!gtk_tree_selection_get_selected (selection, &model, &iter))
		return NULL;

	for (gint i = 0; i < FS_NUM_HITCOLUMNS - 1; i++) {
		g_clear_pointer (&fields[i], g_free);
		gtk_tree_model_get (model, &iter, i, &fields[i], -1);
	}

	hit.time        = fields[COL_TIME];
	hit.direction   = fields[COL_DIRECTION];
	hit.in          = fields[COL_IN];
	hit.out         = fields[COL_OUT];
	hit.port        = fields[COL_PORT];
	hit.source      = fields[COL_SOURCE];
	hit.destination = fields[COL_DESTINATION];
	hit.length      = fields[COL_LENGTH];
	hit.tos         = fields[COL_TOS];
	hit.protocol    = fields[COL_PROTOCOL];
	hit.service     = fields[COL_SERVICE];

	return &hit;
}

/* [ on_clear_clicked ] */
static void
on_clear_clicked (GtkButton *button, gpointer data)
{
	fs_hitview_clear ();
}

/* [ on_reload_clicked ] */
static void
on_reload_clicked (GtkButton *button, gpointer data)
{
	fs_hitview_reload ();
}

/* [ on_start_toggled ]
 * Starts or stops the event source. */
static void
on_start_toggled (GtkToggleButton *button, gpointer data)
{
	GError *error = NULL;

	if (gtk_toggle_button_get_active (button)) {
		if (!fs_hitview_start (&error)) {
			fs_dialogs_error (NULL,
			                  _("Could not monitor firewall events"),
			                  error ? error->message : NULL);
			set_monitor_warning (error != NULL
			                     ? error->message
			                     : _("Monitoring could not start."));
			g_clear_error (&error);

			/* Leave the switch off rather than pretending to monitor. */
			gtk_toggle_button_set_active (button, FALSE);
			return;
		}

		set_monitor_warning (NULL);
	} else {
		fs_hitview_stop ();
	}
}

GtkWidget *
fs_hitview_page (void)
{
	GtkWidget *page, *box, *scroll, *button_box, *button, *toggle;
	GtkWidget *header, *image;

	page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);

	/* Header: what is shown, and the controls. */
	header = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_container_set_border_width (GTK_CONTAINER (header), 6);

	count_label = gtk_label_new ("0 events");
	gtk_label_set_xalign (GTK_LABEL (count_label), 0.0);
	gtk_box_pack_start (GTK_BOX (header), count_label, TRUE, TRUE, 0);

	button_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);

	toggle = gtk_check_button_new_with_mnemonic (_("_Monitor"));
	g_signal_connect (toggle, "toggled", G_CALLBACK (on_start_toggled),
	                  NULL);
	gtk_box_pack_start (GTK_BOX (button_box), toggle, FALSE, FALSE, 0);

	button = gtk_button_new_with_mnemonic (_("_Clear"));
	g_signal_connect (button, "clicked", G_CALLBACK (on_clear_clicked),
	                  NULL);
	gtk_box_pack_start (GTK_BOX (button_box), button, FALSE, FALSE, 0);

	button = gtk_button_new_with_mnemonic (_("Re_fresh"));
	g_signal_connect (button, "clicked", G_CALLBACK (on_reload_clicked),
	                  NULL);
	gtk_box_pack_start (GTK_BOX (button_box), button, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (header), button_box, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), header, FALSE, FALSE, 0);

	/* Strip that carries the reason monitoring is not running.  Hidden
	 * by default, and marked no-show-all so gtk_widget_show_all() on
	 * the page does not reveal it before it has a reason to be seen. */
	monitor_warning = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	monitor_warning_label = gtk_label_new ("");
	gtk_label_set_xalign (GTK_LABEL (monitor_warning_label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (monitor_warning_label), TRUE);

	/* The contents are shown once here and then left alone: only the
	 * strip itself is ever toggled.  no_show_all on the strip is what
	 * keeps the page-wide gtk_widget_show_all() from revealing a bare
	 * one, but that same flag stops the walk from reaching these
	 * children -- so letting show_all do it would render a blank bar
	 * exactly when a reason had to be read. */
	image = gtk_image_new_from_icon_name ("dialog-warning",
	                                      GTK_ICON_SIZE_BUTTON);
	gtk_widget_show (image);
	gtk_widget_show (monitor_warning_label);

	gtk_box_pack_start (GTK_BOX (monitor_warning), image, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (monitor_warning), monitor_warning_label,
	                    TRUE, TRUE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (monitor_warning), 6);
	gtk_style_context_add_class (
		gtk_widget_get_style_context (monitor_warning), "warning");
	gtk_widget_set_no_show_all (monitor_warning, TRUE);
	gtk_box_pack_start (GTK_BOX (page), monitor_warning, FALSE, FALSE, 0);

	/* The list. */
	store = gtk_list_store_newv (FS_NUM_HITCOLUMNS, (GType[FS_NUM_HITCOLUMNS])
		{ G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
		  G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
		  G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING });

	view = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));

	for (gint i = 0; i < FS_NUM_HITCOLUMNS; i++) {
		GtkCellRenderer *renderer;
		GtkTreeViewColumn *column;

		/* The colour column carries no text. */
		if (column_defs[i].label[0] == '\0')
			continue;

		renderer = gtk_cell_renderer_text_new ();

		column = gtk_tree_view_column_new_with_attributes (
			_(column_defs[i].label), renderer, "text", i, NULL);
		gtk_tree_view_column_set_resizable (column, TRUE);

		/* Every visible text column reads the colour column so a
		 * blocked event is red right across the row. */
		gtk_tree_view_column_set_cell_data_func (column, renderer,
		                                         color_cell_data,
		                                         NULL, NULL);

		/* Column visibility is remembered, as in the original. */
		if (column_defs[i].pref_key != NULL)
			gtk_tree_view_column_set_visible (
				column,
				fs_prefs_get_bool (column_defs[i].pref_key,
				                   column_defs[i].visible));

		gtk_tree_view_append_column (GTK_TREE_VIEW (view), column);
	}

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll),
	                                     GTK_SHADOW_IN);
	gtk_widget_set_vexpand (scroll, TRUE);
	gtk_container_add (GTK_CONTAINER (scroll), view);
	gtk_box_pack_start (GTK_BOX (page), scroll, TRUE, TRUE, 0);

	/* Start monitoring straight away: the whole point of the page is
	 * watching events, and the original did this too.  A failure here
	 * used to be dropped on the floor, leaving an empty list that read
	 * as a working firewall with nothing to report; it now has to say
	 * why. */
	{
		GError *error = NULL;

		if (!fs_hitview_start (&error)) {
			set_monitor_warning (error != NULL
			                     ? error->message
			                     : _("Monitoring could not start."));
			g_clear_error (&error);
		}
	}

	(void) box;

	return page;
}