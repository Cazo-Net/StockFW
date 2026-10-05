/*---[ fs-statusview.c ]------------------------------------------------
 * The Status page: firewall state, start/stop controls and the live
 * event counters.
 *
 * Rebuilt on top of GtkBox/GtkGrid instead of the GnomeApp contents
 * machinery the original relied on.
 *--------------------------------------------------------------------*/

#include "ui/fs-statusview.h"
#include "ui/fs-dialogs.h"
#include "core/fs-backend.h"
#include "core/fs-i18n.h"

static FsFirewallState current_state = FS_FW_NONE;

static GtkWidget *state_label;
static GtkWidget *banner_icon;
static GtkWidget *backend_label;
static GtkWidget *button_start;
static GtkWidget *button_stop;
static GtkWidget *in_value;
static GtkWidget *out_value;

/* Per-profile switches, used only when the backend supports them. */
static GtkWidget *profile_switches[FS_PROFILE_COUNT];
static GtkWidget *profiles_frame;

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

/* [ state_to_style ]
 * Maps a state onto the image used next to the label. */
static const gchar *
state_to_icon (FsFirewallState state)
{
	switch (state) {
	case FS_FW_RUNNING:
	case FS_FW_LOCKED:  return "dialog-information";
	case FS_FW_STOPPED: return "dialog-warning";
	default:            return "dialog-question";
	}
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

	gtk_widget_set_sensitive (button_start, usable && !running);
	gtk_widget_set_sensitive (button_stop,  usable &&  running);

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

static guint events_in = 0;
static guint events_out = 0;

static void
update_counters (void)
{
	gchar *text;

	text = g_strdup_printf ("%u", events_in);
	gtk_label_set_text (GTK_LABEL (in_value), text);
	g_free (text);

	text = g_strdup_printf ("%u", events_out);
	gtk_label_set_text (GTK_LABEL (out_value), text);
	g_free (text);
}

static void
on_start_clicked (GtkButton *button, gpointer data)
{
	GError *error = NULL;

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

	if (!fs_backend ()->stop (&error)) {
		fs_dialogs_error (NULL, _("Failed to stop the firewall"),
		                  error ? error->message : NULL);
		g_clear_error (&error);
		return;
	}

	fs_statusview_set_state (fs_backend ()->get_state ());
}

void
fs_statusview_set_state (FsFirewallState state)
{
	current_state = state;

	if (state_label != NULL)
		gtk_label_set_text (GTK_LABEL (state_label), state_to_text (state));

	/* The banner is a box holding the icon and the text side by side,
	 * so the image needs its own widget rather than reaching into the
	 * label's internals the way the original code did. */
	if (banner_icon != NULL)
		gtk_image_set_from_icon_name (GTK_IMAGE (banner_icon),
		                              state_to_icon (state),
		                              GTK_ICON_SIZE_DIALOG);

	refresh_controls ();
}

FsFirewallState
fs_statusview_get_state (void)
{
	return current_state;
}

void
fs_statusview_event_in (gboolean serious)
{
	(void) serious;

	events_in++;
	update_counters ();
}

void
fs_statusview_event_out (gboolean serious)
{
	(void) serious;

	events_out++;
	update_counters ();
}

void
fs_statusview_events_reset (void)
{
	events_in = 0;
	events_out = 0;
	update_counters ();
}

/* [ fs_statusview_page ] */
GtkWidget *
fs_statusview_page (void)
{
	GtkWidget *page, *box, *grid, *button_box;
	const FsBackend *backend = fs_backend ();

	page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	gtk_container_set_border_width (GTK_CONTAINER (page), 12);

	/* State banner */
	box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	banner_icon = gtk_image_new_from_icon_name ("dialog-question",
	                                            GTK_ICON_SIZE_DIALOG);
	gtk_box_pack_start (GTK_BOX (box), banner_icon, FALSE, FALSE, 0);

	state_label = gtk_label_new (state_to_text (FS_FW_NONE));
	gtk_label_set_xalign (GTK_LABEL (state_label), 0.0);
	gtk_box_pack_start (GTK_BOX (box), state_label, TRUE, TRUE, 0);

	gtk_box_pack_start (GTK_BOX (page), box, FALSE, FALSE, 0);

	/* Backend description */
	backend_label = gtk_label_new (backend->display_name);
	gtk_label_set_xalign (GTK_LABEL (backend_label), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (backend_label),
	                             "dim-label");
	gtk_box_pack_start (GTK_BOX (page), backend_label, FALSE, FALSE, 0);

	/* Event counters */
	grid = gtk_grid_new ();
	gtk_grid_set_row_spacing (GTK_GRID (grid), 6);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 12);

	{
		GtkWidget *label = gtk_label_new (_("Incoming events"));
		gtk_label_set_xalign (GTK_LABEL (label), 0.0);
		gtk_grid_attach (GTK_GRID (grid), label, 0, 0, 1, 1);

		in_value = gtk_label_new ("0");
		gtk_label_set_xalign (GTK_LABEL (in_value), 0.0);
		gtk_grid_attach (GTK_GRID (grid), in_value, 1, 0, 1, 1);

		label = gtk_label_new (_("Outgoing events"));
		gtk_label_set_xalign (GTK_LABEL (label), 0.0);
		gtk_grid_attach (GTK_GRID (grid), label, 0, 1, 1, 1);

		out_value = gtk_label_new ("0");
		gtk_label_set_xalign (GTK_LABEL (out_value), 0.0);
		gtk_grid_attach (GTK_GRID (grid), out_value, 1, 1, 1, 1);
	}

	gtk_box_pack_start (GTK_BOX (page), grid, FALSE, FALSE, 0);

	/* Per-profile controls, visible only when the backend reports them. */
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

			gtk_label_set_xalign (GTK_LABEL (label), 0.0);
			gtk_widget_set_hexpand (label, TRUE);
			g_object_set_data (G_OBJECT (toggle), "user-data",
			                   GINT_TO_POINTER (i));

			/* Read the current state before wiring the signal, so
			 * the initial set_active does not count as a user
			 * toggle. */
			{
				gboolean enabled = FALSE;

				if (fs_backend ()->get_profile_enabled (i, &enabled))
					gtk_switch_set_active (GTK_SWITCH (toggle), enabled);
			}

			g_signal_connect (toggle, "notify::active",
			                  G_CALLBACK (on_profile_toggled),
			                  NULL);

			gtk_box_pack_start (GTK_BOX (row), label, TRUE, TRUE, 0);
			gtk_box_pack_start (GTK_BOX (row), toggle, FALSE, FALSE, 0);

			gtk_box_pack_start (GTK_BOX (inner), row, FALSE, FALSE, 0);

			profile_switches[i] = toggle;
		}
	}

	/* The backend decides whether to show this: Windows has three
	 * profiles, Linux has one global state and hides the box. */
	{
		gboolean *enabled = g_new0 (gboolean, 1);
		gboolean any = FALSE;

		for (gint i = 0; i < FS_PROFILE_COUNT; i++) {
			if (fs_backend ()->get_profile_enabled (i, enabled))
				any = TRUE;
		}

		g_free (enabled);

		if (any)
			gtk_widget_show_all (profiles_frame);
		else
			gtk_widget_hide (profiles_frame);
	}

	gtk_box_pack_start (GTK_BOX (page), profiles_frame, FALSE, FALSE, 0);

	/* Controls */
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

	refresh_controls ();

	return page;
}