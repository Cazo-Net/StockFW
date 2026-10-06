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
	{ N_("Time"),        TRUE,  "/apps/firestarter/client/ui/hitview_time_col" },
	{ N_("Direction"),   TRUE,  "/apps/firestarter/client/ui/hitview_direction_col" },
	{ N_("In"),          TRUE,  "/apps/firestarter/client/ui/hitview_in_col" },
	{ N_("Out"),         TRUE,  "/apps/firestarter/client/ui/hitview_out_col" },
	{ N_("Port"),        TRUE,  "/apps/firestarter/client/ui/hitview_port_col" },
	{ N_("Source"),      TRUE,  "/apps/firestarter/client/ui/hitview_source_col" },
	{ N_("Destination"), TRUE,  "/apps/firestarter/client/ui/hitview_destination_col" },
	{ N_("Length"),      FALSE, "/apps/firestarter/client/ui/hitview_length_col" },
	{ N_("ToS"),         FALSE, "/apps/firestarter/client/ui/hitview_tos_col" },
	{ N_("Protocol"),    TRUE,  "/apps/firestarter/client/ui/hitview_protocol_col" },
	{ N_("Service"),     TRUE,  "/apps/firestarter/client/ui/hitview_service_col" },
	{ N_(""),            FALSE, NULL },   /* colour, never shown */
};

static guint row_count = 0;

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

/* [ on_hit ]
 * Backend log callback.  Runs on the main loop because the backend
 * delivers through a GLib source. */
static void
on_hit (const FsHit *hit, gpointer user_data)
{
	fs_hitview_append (hit);

	/* Feed to copilot for learning and anomaly detection. */
	extern FsCopilot *copilot;
	if (copilot != NULL)
		fs_copilot_feed_event (copilot, hit);

	/* Update copilot stats counter. */
	fs_copilot_note_event ();
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
	fields[COL_COLOR]       = "";

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

void
fs_hitview_reload (void)
{
	/* The list is a live tail, not a file to re-read: restarting the
	 * source is the equivalent of a reload. */
	fs_hitview_clear ();
	fs_hitview_stop  ();
	fs_hitview_start (NULL);
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
			g_clear_error (&error);

			/* Leave the switch off rather than pretending to monitor. */
			gtk_toggle_button_set_active (button, FALSE);
			return;
		}
	} else {
		fs_hitview_stop ();
	}
}

GtkWidget *
fs_hitview_page (void)
{
	GtkWidget *page, *box, *scroll, *button_box, *button, *toggle;
	GtkWidget *header;

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
	 * watching events, and the original did this too. */
	fs_hitview_start (NULL);

	(void) box;

	return page;
}