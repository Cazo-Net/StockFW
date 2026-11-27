/* The detail drawer.  See fs-drawer.h. */

#include "ui/fs-drawer.h"
#include "core/fs-i18n.h"

#define FS_DRAWER_WIDTH       380
#define FS_DRAWER_SLIDE_MS    180

static GtkWidget *revealer = NULL;
static GtkWidget *title_label = NULL;
static GtkWidget *subtitle_label = NULL;
static GtkWidget *body_slot = NULL;
static GtkWidget *foot = NULL;
static gpointer   current_owner = NULL;

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
on_revealer_destroy (GtkWidget *widget, gpointer data)
{
	(void) data;

	if (widget != revealer)
		return;
	revealer = NULL;
	title_label = NULL;
	subtitle_label = NULL;
	body_slot = NULL;
	foot = NULL;
	current_owner = NULL;
	/* The reference ensure () took. */
	g_object_unref (widget);
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
	GtkWidget *panel, *head, *titles, *close, *scroll;
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
	gtk_widget_set_halign (revealer, GTK_ALIGN_END);
	gtk_widget_set_valign (revealer, GTK_ALIGN_FILL);
	g_signal_connect (revealer, "destroy",
	                  G_CALLBACK (on_revealer_destroy), NULL);

	panel = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_style_context_add_class (gtk_widget_get_style_context (panel),
	                             "fs-drawer");
	gtk_widget_set_size_request (panel, FS_DRAWER_WIDTH, -1);
	gtk_container_add (GTK_CONTAINER (revealer), panel);

	head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	gtk_style_context_add_class (gtk_widget_get_style_context (head),
	                             "fs-drawer-head");
	gtk_box_pack_start (GTK_BOX (panel), head, FALSE, FALSE, 0);

	titles = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	gtk_box_pack_start (GTK_BOX (head), titles, TRUE, TRUE, 0);

	title_label = gtk_label_new (NULL);
	gtk_widget_set_name (title_label, "fs-drawer-title");
	gtk_style_context_add_class (gtk_widget_get_style_context (title_label),
	                             "fs-drawer-title");
	gtk_label_set_xalign (GTK_LABEL (title_label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (title_label), TRUE);
	gtk_label_set_line_wrap_mode (GTK_LABEL (title_label),
	                              PANGO_WRAP_WORD_CHAR);
	gtk_label_set_max_width_chars (GTK_LABEL (title_label), 30);
	gtk_box_pack_start (GTK_BOX (titles), title_label, FALSE, FALSE, 0);

	subtitle_label = gtk_label_new (NULL);
	gtk_widget_set_name (subtitle_label, "fs-drawer-subtitle");
	gtk_style_context_add_class (gtk_widget_get_style_context (subtitle_label),
	                             "fs-drawer-subtitle");
	gtk_label_set_xalign (GTK_LABEL (subtitle_label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (subtitle_label), TRUE);
	gtk_label_set_line_wrap_mode (GTK_LABEL (subtitle_label),
	                              PANGO_WRAP_WORD_CHAR);
	gtk_label_set_max_width_chars (GTK_LABEL (subtitle_label), 34);
	gtk_widget_set_no_show_all (subtitle_label, TRUE);
	gtk_box_pack_start (GTK_BOX (titles), subtitle_label, FALSE, FALSE, 0);

	close = gtk_button_new_with_label (_("Close"));
	gtk_widget_set_name (close, "fs-drawer-close");
	gtk_style_context_add_class (gtk_widget_get_style_context (close),
	                             "btn-subtle");
	gtk_widget_set_valign (close, GTK_ALIGN_START);
	gtk_widget_set_tooltip_text (close, _("Close the details (Esc)"));
	atk = gtk_widget_get_accessible (close);
	if (atk != NULL)
		atk_object_set_name (atk, _("Close details"));
	g_signal_connect (close, "clicked", G_CALLBACK (on_close_clicked), NULL);
	gtk_box_pack_end (GTK_BOX (head), close, FALSE, FALSE, 0);

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_box_pack_start (GTK_BOX (panel), scroll, TRUE, TRUE, 0);

	body_slot = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	gtk_widget_set_name (body_slot, "fs-drawer-body");
	gtk_style_context_add_class (gtk_widget_get_style_context (body_slot),
	                             "fs-drawer-body");
	gtk_container_add (GTK_CONTAINER (scroll), body_slot);

	foot = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
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
	guint i;

	ensure ();

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
		ActionData *action = g_new0 (ActionData, 1);

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
	}
	gtk_widget_set_visible (foot, actions != NULL && n_actions > 0);

	current_owner = owner;
	gtk_revealer_set_transition_duration (GTK_REVEALER (revealer),
		animations_enabled () ? FS_DRAWER_SLIDE_MS : 0);
	gtk_widget_show (revealer);
	gtk_revealer_set_reveal_child (GTK_REVEALER (revealer), TRUE);
}

void
fs_drawer_close (void)
{
	current_owner = NULL;
	if (revealer == NULL)
		return;
	gtk_revealer_set_transition_duration (GTK_REVEALER (revealer),
		animations_enabled () ? FS_DRAWER_SLIDE_MS : 0);
	gtk_revealer_set_reveal_child (GTK_REVEALER (revealer), FALSE);
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

	gtk_grid_set_column_spacing (GTK_GRID (grid), 12);
	gtk_grid_set_row_spacing (GTK_GRID (grid), 6);
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
	gtk_label_set_yalign (GTK_LABEL (name_label), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (name_label),
	                             "fs-drawer-name");
	gtk_grid_attach (GTK_GRID (fields), name_label, 0, row, 1, 1);

	value_label = gtk_label_new (value);
	gtk_label_set_xalign (GTK_LABEL (value_label), 0.0);
	gtk_label_set_yalign (GTK_LABEL (value_label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (value_label), TRUE);
	gtk_label_set_line_wrap_mode (GTK_LABEL (value_label),
	                              PANGO_WRAP_WORD_CHAR);
	gtk_label_set_max_width_chars (GTK_LABEL (value_label), 30);
	/* Text to copy with the mouse, but not a stop for Tab. */
	gtk_label_set_selectable (GTK_LABEL (value_label), TRUE);
	gtk_widget_set_can_focus (value_label, FALSE);
	gtk_widget_set_hexpand (value_label, TRUE);
	ctx = gtk_widget_get_style_context (value_label);
	gtk_style_context_add_class (ctx, "fs-drawer-value");
	if (mono)
		gtk_style_context_add_class (ctx, "mono");
	gtk_grid_attach (GTK_GRID (fields), value_label, 1, row, 1, 1);

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
