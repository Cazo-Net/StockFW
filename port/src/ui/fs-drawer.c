/* The detail drawer.  See fs-drawer.h.
 *
 * One GtkRevealer that slides a fixed-width panel in from the right:
 * a head (title, subtitle, close), a body that scrolls, and a foot of
 * full-width action buttons.  The main window puts the revealer in an
 * overlay over its pages (fs-app.c); with no window at all, as in a
 * test that builds one page, the same calls work on a revealer nobody
 * shows.
 *
 * The revealer is hidden while it is closed, not merely collapsed: an
 * overlay child takes the mouse over whatever it is allocated, and the
 * list's scrollbar is under that edge. */

#include "ui/fs-drawer.h"
#include "ui/fs-icons.h"
#include "core/fs-i18n.h"

#define FS_DRAWER_WIDTH       380
#define FS_DRAWER_SLIDE_MS    180
/* The column of field names: one width in every grid of a body, so the
 * values line up from one section to the next. */
#define FS_DRAWER_NAME_WIDTH  88
/* Wrapping labels fill the width they are given; this is only the
 * width they ask for, kept short so that no text widens the panel. */
#define FS_DRAWER_WRAP_CHARS  24

static GtkWidget *revealer = NULL;
static GtkWidget *title_label = NULL;
static GtkWidget *subtitle_label = NULL;
static GtkWidget *close_button = NULL;
static GtkWidget *body_slot = NULL;
static GtkWidget *foot = NULL;
static gpointer   current_owner = NULL;
/* What had the keyboard when the drawer opened, for a close that would
 * otherwise leave it on a button that is going away.  A weak pointer:
 * the widget may be gone by then. */
static GtkWidget *prev_focus = NULL;

typedef struct
{
	FsDrawerRun run;
	gpointer    data;
} ActionData;

static gboolean
animations_enabled (void)
{
	GtkSettings *settings = gtk_settings_get_default ();
	gboolean on = TRUE;

	if (settings != NULL)
		g_object_get (settings, "gtk-enable-animations", &on, NULL);
	return on;
}

static void
forget_focus (void)
{
	if (prev_focus != NULL)
		g_object_remove_weak_pointer (G_OBJECT (prev_focus),
		                              (gpointer *) &prev_focus);
	prev_focus = NULL;
}

/* The window the drawer is in, or NULL when nothing hosts it. */
static GtkWidget *
host_window (void)
{
	GtkWidget *top = revealer != NULL ? gtk_widget_get_toplevel (revealer)
	                                  : NULL;

	return top != NULL && GTK_IS_WINDOW (top) ? top : NULL;
}

/* Is the keyboard on something inside the drawer? */
static gboolean
focus_inside (void)
{
	GtkWidget *top = host_window ();
	GtkWidget *focus = top != NULL
	                 ? gtk_window_get_focus (GTK_WINDOW (top)) : NULL;

	return focus != NULL && gtk_widget_is_ancestor (focus, revealer);
}

static void
on_revealer_destroy (GtkWidget *widget, gpointer data)
{
	(void) data;

	if (widget != revealer)
		return;
	forget_focus ();
	revealer = NULL;
	title_label = NULL;
	subtitle_label = NULL;
	close_button = NULL;
	body_slot = NULL;
	foot = NULL;
	current_owner = NULL;
	/* The reference ensure () took. */
	g_object_unref (widget);
}

/* The slide has ended.  Slid shut, the revealer leaves the overlay
 * altogether (see the top of the file); a drawer opened again before
 * the slide ended stays. */
static void
on_child_revealed (GObject *object, GParamSpec *pspec, gpointer data)
{
	GtkRevealer *r = GTK_REVEALER (object);

	(void) pspec;
	(void) data;

	if (!gtk_revealer_get_child_revealed (r) &&
	    !gtk_revealer_get_reveal_child (r))
		gtk_widget_hide (GTK_WIDGET (r));
}

static void
on_close_clicked (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;
	fs_drawer_close ();
}

static void
on_action_clicked (GtkButton *button, gpointer data)
{
	const ActionData *action = data;
	/* Copied first: the action may refill the drawer, which destroys
	 * this button and frees `action' with it. */
	FsDrawerRun run = action->run;
	gpointer run_data = action->data;

	(void) button;
	if (run != NULL)
		run (run_data);
}

static void
action_data_free (gpointer data, GClosure *closure)
{
	(void) closure;
	g_free (data);
}

static void
ensure (void)
{
	GtkWidget *panel, *head, *titles, *scroll;
	AtkObject *atk;

	if (revealer != NULL)
		return;

	revealer = gtk_revealer_new ();
	/* Held here as well as by the overlay it is added to, so the
	 * drawer also works in a test that builds one page and no window. */
	g_object_ref_sink (revealer);
	gtk_widget_set_name (revealer, "fs-drawer");
	gtk_revealer_set_transition_type (GTK_REVEALER (revealer),
	                                  GTK_REVEALER_TRANSITION_TYPE_SLIDE_LEFT);
	gtk_revealer_set_reveal_child (GTK_REVEALER (revealer), FALSE);
	/* Its own width at the right edge, never the whole page: the rest
	 * of the page keeps the mouse. */
	gtk_widget_set_halign (revealer, GTK_ALIGN_END);
	gtk_widget_set_valign (revealer, GTK_ALIGN_FILL);
	/* Shown by fs_drawer_open () only: the window's show_all at start
	 * must not put an empty drawer over the page. */
	gtk_widget_set_no_show_all (revealer, TRUE);
	g_signal_connect (revealer, "destroy",
	                  G_CALLBACK (on_revealer_destroy), NULL);
	g_signal_connect (revealer, "notify::child-revealed",
	                  G_CALLBACK (on_child_revealed), NULL);

	panel = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_style_context_add_class (gtk_widget_get_style_context (panel),
	                             "fs-drawer");
	gtk_widget_set_size_request (panel, FS_DRAWER_WIDTH, -1);
	atk = gtk_widget_get_accessible (panel);
	if (atk != NULL)
		atk_object_set_name (atk, _("Details"));
	gtk_container_add (GTK_CONTAINER (revealer), panel);

	head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	gtk_style_context_add_class (gtk_widget_get_style_context (head),
	                             "fs-drawer-head");
	gtk_box_pack_start (GTK_BOX (panel), head, FALSE, FALSE, 0);

	titles = gtk_box_new (GTK_ORIENTATION_VERTICAL, 3);
	gtk_widget_set_valign (titles, GTK_ALIGN_CENTER);
	gtk_box_pack_start (GTK_BOX (head), titles, TRUE, TRUE, 0);

	title_label = gtk_label_new (NULL);
	gtk_widget_set_name (title_label, "fs-drawer-title");
	gtk_style_context_add_class (gtk_widget_get_style_context (title_label),
	                             "fs-drawer-title");
	gtk_label_set_xalign (GTK_LABEL (title_label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (title_label), TRUE);
	gtk_label_set_line_wrap_mode (GTK_LABEL (title_label),
	                              PANGO_WRAP_WORD_CHAR);
	gtk_label_set_max_width_chars (GTK_LABEL (title_label),
	                               FS_DRAWER_WRAP_CHARS);
	gtk_box_pack_start (GTK_BOX (titles), title_label, FALSE, FALSE, 0);

	subtitle_label = gtk_label_new (NULL);
	gtk_widget_set_name (subtitle_label, "fs-drawer-subtitle");
	gtk_style_context_add_class (gtk_widget_get_style_context (subtitle_label),
	                             "fs-drawer-subtitle");
	gtk_label_set_xalign (GTK_LABEL (subtitle_label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (subtitle_label), TRUE);
	gtk_label_set_line_wrap_mode (GTK_LABEL (subtitle_label),
	                              PANGO_WRAP_WORD_CHAR);
	gtk_label_set_max_width_chars (GTK_LABEL (subtitle_label),
	                               FS_DRAWER_WRAP_CHARS);
	gtk_widget_set_no_show_all (subtitle_label, TRUE);
	gtk_box_pack_start (GTK_BOX (titles), subtitle_label, FALSE, FALSE, 0);

	/* A cross, not the word: the name and the tooltip say what it
	 * does. */
	close_button = gtk_button_new ();
	gtk_container_add (GTK_CONTAINER (close_button),
	                   fs_icon_new (FS_ICON_CLOSE, 14));
	gtk_widget_set_name (close_button, "fs-drawer-close");
	gtk_button_set_relief (GTK_BUTTON (close_button), GTK_RELIEF_NONE);
	gtk_style_context_add_class (
		gtk_widget_get_style_context (close_button), "fs-drawer-close");
	gtk_widget_set_valign (close_button, GTK_ALIGN_START);
	gtk_widget_set_tooltip_text (close_button, _("Close the details (Esc)"));
	atk = gtk_widget_get_accessible (close_button);
	if (atk != NULL)
		atk_object_set_name (atk, _("Close details"));
	g_signal_connect (close_button, "clicked",
	                  G_CALLBACK (on_close_clicked), NULL);
	gtk_box_pack_end (GTK_BOX (head), close_button, FALSE, FALSE, 0);

	/* A body wider than the panel scrolls sideways; it must not widen
	 * the panel (with GTK_POLICY_NEVER it would). */
	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	gtk_box_pack_start (GTK_BOX (panel), scroll, TRUE, TRUE, 0);

	body_slot = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	gtk_widget_set_name (body_slot, "fs-drawer-body");
	gtk_style_context_add_class (gtk_widget_get_style_context (body_slot),
	                             "fs-drawer-body");
	gtk_container_add (GTK_CONTAINER (scroll), body_slot);

	foot = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
	gtk_widget_set_name (foot, "fs-drawer-actions");
	gtk_style_context_add_class (gtk_widget_get_style_context (foot),
	                             "fs-drawer-foot");
	gtk_widget_set_no_show_all (foot, TRUE);
	gtk_box_pack_end (GTK_BOX (panel), foot, FALSE, FALSE, 0);

	gtk_widget_show_all (panel);
}

static void
empty_container (GtkWidget *container)
{
	GList *children = gtk_container_get_children (GTK_CONTAINER (container));
	GList *l;

	for (l = children; l != NULL; l = l->next)
		gtk_widget_destroy (GTK_WIDGET (l->data));
	g_list_free (children);
}

GtkWidget *
fs_drawer_widget (void)
{
	ensure ();
	return revealer;
}

void
fs_drawer_open (gpointer              owner,
                const gchar          *title,
                const gchar          *subtitle,
                GtkWidget            *body,
                const FsDrawerAction *actions,
                guint                 n_actions)
{
	GtkWidget *first_action = NULL;
	gboolean had_focus;
	guint i;

	ensure ();

	/* A refill from one of the drawer's own buttons destroys the
	 * button that has the keyboard; it is handed on below. */
	had_focus = fs_drawer_is_open () && focus_inside ();

	if (!fs_drawer_is_open ()) {
		GtkWidget *top = host_window ();

		forget_focus ();
		if (top != NULL)
			prev_focus = gtk_window_get_focus (GTK_WINDOW (top));
		if (prev_focus != NULL)
			g_object_add_weak_pointer (G_OBJECT (prev_focus),
			                           (gpointer *) &prev_focus);
	}

	gtk_label_set_text (GTK_LABEL (title_label), title != NULL ? title : "");
	if (subtitle != NULL && *subtitle != '\0') {
		gtk_label_set_text (GTK_LABEL (subtitle_label), subtitle);
		gtk_widget_show (subtitle_label);
	} else {
		gtk_widget_hide (subtitle_label);
	}

	empty_container (body_slot);
	if (body != NULL) {
		gtk_box_pack_start (GTK_BOX (body_slot), body, FALSE, FALSE, 0);
		gtk_widget_show_all (body);
	}

	empty_container (foot);
	for (i = 0; actions != NULL && i < n_actions; i++) {
		GtkWidget *button = gtk_button_new_with_label (actions[i].label);
		GtkWidget *label = gtk_bin_get_child (GTK_BIN (button));
		ActionData *action = g_new0 (ActionData, 1);

		/* A long label ("Block <an IPv6 address> ...") takes a
		 * second line; it does not widen the panel. */
		if (GTK_IS_LABEL (label)) {
			gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
			gtk_label_set_line_wrap_mode (GTK_LABEL (label),
			                              PANGO_WRAP_WORD_CHAR);
			gtk_label_set_max_width_chars (GTK_LABEL (label),
			                               FS_DRAWER_WRAP_CHARS);
			gtk_label_set_justify (GTK_LABEL (label),
			                       GTK_JUSTIFY_CENTER);
		}

		action->run = actions[i].run;
		action->data = actions[i].data;
		gtk_style_context_add_class (
			gtk_widget_get_style_context (button),
			actions[i].klass != NULL ? actions[i].klass : "btn-subtle");
		g_signal_connect_data (button, "clicked",
		                       G_CALLBACK (on_action_clicked), action,
		                       action_data_free, 0);
		gtk_box_pack_start (GTK_BOX (foot), button, FALSE, FALSE, 0);
		gtk_widget_show (button);
		if (first_action == NULL)
			first_action = button;
	}
	gtk_widget_set_visible (foot, first_action != NULL);

	current_owner = owner;
	gtk_revealer_set_transition_duration (GTK_REVEALER (revealer),
		animations_enabled () ? FS_DRAWER_SLIDE_MS : 0);
	gtk_widget_show (revealer);
	gtk_revealer_set_reveal_child (GTK_REVEALER (revealer), TRUE);

	if (had_focus && !focus_inside ())
		gtk_widget_grab_focus (first_action != NULL ? first_action
		                                            : close_button);
}

void
fs_drawer_close (void)
{
	GtkWidget *back = prev_focus;

	current_owner = NULL;
	if (revealer == NULL)
		return;

	/* The keyboard goes back to the list that opened the drawer if it
	 * was left on one of the drawer's buttons; otherwise it is already
	 * where the user put it. */
	if (focus_inside () && back != NULL && gtk_widget_get_mapped (back) &&
	    gtk_widget_get_toplevel (back) == host_window ()) {
		if (GTK_IS_ENTRY (back))
			gtk_entry_grab_focus_without_selecting (GTK_ENTRY (back));
		else
			gtk_widget_grab_focus (back);
	}
	forget_focus ();

	gtk_revealer_set_transition_duration (GTK_REVEALER (revealer),
		animations_enabled () ? FS_DRAWER_SLIDE_MS : 0);
	gtk_revealer_set_reveal_child (GTK_REVEALER (revealer), FALSE);
	/* on_child_revealed () hides it when the slide ends; with nothing
	 * on screen to slide there is nothing to wait for. */
	if (!gtk_widget_get_mapped (revealer))
		gtk_widget_hide (revealer);
}

gboolean
fs_drawer_is_open (void)
{
	return revealer != NULL
	       && gtk_revealer_get_reveal_child (GTK_REVEALER (revealer));
}

gpointer
fs_drawer_owner (void)
{
	return fs_drawer_is_open () ? current_owner : NULL;
}

GtkWidget *
fs_drawer_fields_new (void)
{
	GtkWidget *grid = gtk_grid_new ();

	gtk_grid_set_column_spacing (GTK_GRID (grid), 16);
	gtk_grid_set_row_spacing (GTK_GRID (grid), 8);
	gtk_style_context_add_class (gtk_widget_get_style_context (grid),
	                             "fs-drawer-fields");
	return grid;
}

void
fs_drawer_field (GtkWidget   *fields,
                 const gchar *name,
                 const gchar *value,
                 gboolean     mono)
{
	GtkWidget *name_label, *value_label;
	GtkStyleContext *ctx;
	gint row;

	g_return_if_fail (GTK_IS_GRID (fields));
	if (value == NULL || *value == '\0')
		return;

	row = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (fields),
	                                          "fs-drawer-rows"));

	name_label = gtk_label_new (name);
	gtk_label_set_xalign (GTK_LABEL (name_label), 0.0);
	gtk_widget_set_valign (name_label, GTK_ALIGN_BASELINE);
	gtk_widget_set_size_request (name_label, FS_DRAWER_NAME_WIDTH, -1);
	gtk_style_context_add_class (gtk_widget_get_style_context (name_label),
	                             "fs-drawer-name");
	gtk_grid_attach (GTK_GRID (fields), name_label, 0, row, 1, 1);

	value_label = gtk_label_new (value);
	gtk_label_set_xalign (GTK_LABEL (value_label), 0.0);
	gtk_widget_set_valign (value_label, GTK_ALIGN_BASELINE);
	gtk_label_set_line_wrap (GTK_LABEL (value_label), TRUE);
	gtk_label_set_line_wrap_mode (GTK_LABEL (value_label),
	                              PANGO_WRAP_WORD_CHAR);
	gtk_label_set_max_width_chars (GTK_LABEL (value_label),
	                               FS_DRAWER_WRAP_CHARS);
	/* Text to copy with the mouse, but not a stop for Tab. */
	gtk_label_set_selectable (GTK_LABEL (value_label), TRUE);
	gtk_widget_set_can_focus (value_label, FALSE);
	gtk_widget_set_hexpand (value_label, TRUE);
	ctx = gtk_widget_get_style_context (value_label);
	gtk_style_context_add_class (ctx, "fs-drawer-value");
	if (mono)
		gtk_style_context_add_class (ctx, "mono");
	gtk_grid_attach (GTK_GRID (fields), value_label, 1, row, 1, 1);

	gtk_grid_set_row_baseline_position (GTK_GRID (fields), row,
	                                    GTK_BASELINE_POSITION_TOP);

	g_object_set_data (G_OBJECT (fields), "fs-drawer-rows",
	                   GINT_TO_POINTER (row + 1));
}

GtkWidget *
fs_drawer_section (const gchar *heading)
{
	GtkWidget *label = gtk_label_new (heading);

	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             "fs-drawer-section");
	return label;
}
