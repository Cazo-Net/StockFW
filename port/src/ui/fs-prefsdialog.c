/*---[ fs-prefsdialog.c ]------------------------------------------------
 * The Preferences window (1.0.7).
 *
 * Built like the main window: a dark navigation column on the left,
 * one page per subject on the right, each page a title, a line on what
 * it is for, and white cards of settings.  Every setting is one row --
 * its name in bold, one line on what it does, and the switch or choice
 * on the right -- so the window explains itself.  The footer under
 * the pages has Help on the left (it and F1 open the Help topic for
 * the page shown; Help lives in its own window group, so it takes
 * input while this modal window is open), and Cancel and Save.
 *
 * Honesty rule: a setting is offered only where this platform acts on
 * it.  Whole pages follow the backend's FS_FWSEC_* bits, rows inside a
 * page its FS_FWHON_* bits; a row that cannot act *right now* (a Linux
 * block that needs an Internet device nobody chose) stays visible but
 * disabled, with the reason under it.
 *
 *   General     tray icon, close/minimize to tray, start on open
 *   Events      hide repeats, skip events for other machines
 *   Policy      apply immediately; audit-only shown, set on Policy
 *   Firewall    reject or drop, outbound mode, log allowed
 *               (rows only where the backend sets FS_FWHON_*:
 *               Linux has all three, Windows none, so no page)
 *   Network     Internet and local devices, connection sharing
 *               (FS_FWSEC_NETWORK: Linux)
 *   ICMP        the allow-list (FS_FWSEC_ICMP: both)
 *   Protection  broadcast and reserved-source blocks
 *               (FS_FWSEC_ADVANCED: both; scoped to the devices on
 *               Linux, to the network profiles on Windows)
 *
 * The window edits a copy (FsPrefsEdit, core/fs-prefs.h).  Save writes
 * only the values the user changed whose control it offers, then reloads
 * the settings; when a firewall setting changed and the firewall is
 * running it offers to apply them now, through the apply gate
 * (fs_settings_apply_safe), and reports what the gate did.
 *--------------------------------------------------------------------*/

#include "ui/fs-dialogs.h"
#include "ui/fs-app.h"
#include "ui/fs-helpwindow.h"
#include "ui/fs-icons.h"
#include "ui/fs-policyview.h"
#include "ui/fs-statusview.h"
#include "core/fs-backend.h"
#include "core/fs-apply.h"
#include "core/fs-i18n.h"
#include "core/fs-prefs.h"
#include "core/fs-script.h"
#include "core/fs-util.h"

#include <string.h>

#define PREFS_WIDTH   860
#define PREFS_HEIGHT  600
#define NAV_WIDTH     200

typedef enum
{
	PREFS_CANCEL = 0,
	PREFS_SAVE,
	PREFS_OPEN_POLICY     /* closed, nothing changed: show Policy */
} PrefsResponse;

typedef enum
{
	ROW_SWITCH,
	ROW_CHOICE,           /* two-way combo over a boolean        */
	ROW_DEVICE            /* network device combo over a string  */
} RowKind;

typedef struct _PrefsWin PrefsWin;
typedef struct _Row Row;

struct _Row
{
	PrefsWin    *win;
	const gchar *key;
	RowKind      kind;
	GtkWidget   *box;       /* the .pref-row                        */
	GtkWidget   *control;   /* GtkSwitch or GtkComboBoxText         */
	GtkWidget   *reason;    /* why it is disabled, shown when it is */
	const gchar *about;     /* the line on what it does, or NULL    */
	const gchar *true_id;   /* ROW_CHOICE: the id meaning TRUE      */
	Row         *master;    /* a switch this row needs on, or NULL  */
	gboolean     blocked;   /* cannot act now: disabled, reason
	                         * shown.  A change made before it was
	                         * blocked is still saved: the switch
	                         * shows it, so Save must not drop it. */
};

struct _PrefsWin
{
	GtkWidget   *window;
	GtkWidget   *stack;
	GPtrArray   *nav;           /* GtkToggleButton*, one per page   */
	GPtrArray   *rows;          /* Row*, owned                      */
	FsPrefsEdit *edit;
	GtkWidget   *status;        /* footer: unsaved changes          */
	GtkWidget   *policy_link;
	GtkWidget   *outbound_warning;
	GtkWidget   *absent_note;   /* a stored device is not present   */
	GMainLoop   *loop;
	PrefsResponse response;
	gboolean     syncing;
	guint32      sections;
	guint32      honors;
};

/* ------------------------------------------------------------ helpers */

static void
add_class (GtkWidget *widget, const gchar *klass)
{
	gtk_style_context_add_class (gtk_widget_get_style_context (widget),
	                             klass);
}

static GtkWidget *
label_new (const gchar *text, const gchar *klass, gboolean wrap)
{
	GtkWidget *label = gtk_label_new (text);

	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	if (wrap) {
		gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
		gtk_label_set_line_wrap_mode (GTK_LABEL (label),
		                              PANGO_WRAP_WORD_CHAR);
		/* Narrow natural width: the label grows with the window and
		 * wraps when it is narrow, instead of forcing it wide. */
		gtk_label_set_width_chars (GTK_LABEL (label), 20);
		gtk_label_set_max_width_chars (GTK_LABEL (label), 64);
	}
	if (klass != NULL)
		add_class (label, klass);
	return label;
}

static Row *
row_for_key (PrefsWin *win, const gchar *key)
{
	for (guint i = 0; i < win->rows->len; i++) {
		Row *row = g_ptr_array_index (win->rows, i);

		if (g_strcmp0 (row->key, key) == 0)
			return row;
	}
	return NULL;
}

static gboolean
edit_bool (PrefsWin *win, const gchar *key)
{
	return fs_prefs_edit_get_bool (win->edit, key);
}

static gboolean
edit_has_string (PrefsWin *win, const gchar *key)
{
	const gchar *value = fs_prefs_edit_get_string (win->edit, key);

	return value != NULL && *value != '\0';
}

/* ------------------------------------------------------------ refresh */

/* [ row_describe ]
 * What a screen reader says after the setting's name: the line on what
 * it does, and first, while it shows, the reason it cannot act -- a
 * disabled control is otherwise just "unavailable", with no why. */
static void
row_describe (Row *row)
{
	AtkObject *atk = gtk_widget_get_accessible (row->control);
	gboolean why = row->reason != NULL &&
	               gtk_widget_get_visible (row->reason);
	gchar *text;

	if (atk == NULL)
		return;

	text = g_strjoin (" ",
	                  why ? gtk_label_get_text (GTK_LABEL (row->reason))
	                      : "",
	                  row->about != NULL ? row->about : "", NULL);
	g_strstrip (text);
	atk_object_set_description (atk, text);
	g_free (text);
}

static void
set_blocked (Row *row, gboolean blocked)
{
	if (row == NULL)
		return;

	row->blocked = blocked;
	if (row->reason != NULL)
		gtk_widget_set_visible (row->reason, blocked);
}

/* [ refresh ]
 * After every change: what depends on what, the warnings that follow a
 * choice, and the footer's count.  Sensitivity is derived here and
 * nowhere else, so it cannot drift from the values. */
static void
refresh (PrefsWin *win)
{
	guint changed;

	/* Linux scopes the Protection blocks and connection sharing to the
	 * chosen devices; the generator leaves them out without one.  The
	 * conditions are the generator's own (fs-script.c, and
	 * fs_settings_sharing for router mode); the fake smoke checks the
	 * two against each other. */
	if (win->sections & FS_FWSEC_NETWORK) {
		gboolean ext = edit_has_string (win, FS_PREFS_FW_EXT_IF);
		gboolean intf = edit_has_string (win, FS_PREFS_FW_INT_IF);
		gboolean nat = edit_bool (win, FS_PREFS_FW_NAT);
		Row *nat_row = row_for_key (win, FS_PREFS_FW_NAT);

		set_blocked (row_for_key (win, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST),
		             !ext);
		set_blocked (row_for_key (win, FS_PREFS_FW_BLOCK_NON_ROUTABLES),
		             !ext);
		set_blocked (row_for_key (win, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST),
		             !(nat && ext && intf));

		/* Sharing needs both devices to be turned on.  A switch that
		 * is stored on stays movable whatever the devices are, so it
		 * can always be turned off -- and back on before saving. */
		if (nat_row != NULL) {
			set_blocked (nat_row, !(ext && intf) &&
			             !fs_prefs_edit_orig_bool (win->edit,
			                                       FS_PREFS_FW_NAT));
			if (nat_row->reason != NULL)
				gtk_widget_set_visible (nat_row->reason,
				                        !(ext && intf));
		}
	}

	for (guint i = 0; i < win->rows->len; i++) {
		Row *row = g_ptr_array_index (win->rows, i);
		gboolean on = !row->blocked;

		if (row->master != NULL)
			on = on && edit_bool (win, row->master->key);

		gtk_widget_set_sensitive (row->control, on);
		row_describe (row);
	}

	if (win->outbound_warning != NULL)
		gtk_widget_set_visible (win->outbound_warning,
		                        edit_bool (win,
		                                   FS_PREFS_FW_RESTRICTIVE_OUTBOUND));

	/* What Save will write, exactly: changed keys this window offers. */
	changed = fs_prefs_edit_n_pending (win->edit);
	if (changed == 0) {
		gtk_label_set_text (GTK_LABEL (win->status), _("No changes"));
	} else {
		gchar *text = changed == 1
			? g_strdup (_("1 unsaved change"))
			: g_strdup_printf (_("%u unsaved changes"), changed);

		gtk_label_set_text (GTK_LABEL (win->status), text);
		g_free (text);
	}

	if (win->policy_link != NULL) {
		gtk_widget_set_sensitive (win->policy_link, changed == 0);
		gtk_widget_set_tooltip_text (win->policy_link,
			changed == 0 ? _("Closes Preferences and opens the "
			                 "Policy page.")
			             : _("Save or cancel your changes first."));
	}
}

/* ------------------------------------------------------------ signals */

static void
on_switch_active (GObject *object, GParamSpec *pspec, gpointer data)
{
	Row *row = data;

	(void) pspec;
	if (row->win->syncing)
		return;

	fs_prefs_edit_set_bool (row->win->edit, row->key,
	                        gtk_switch_get_active (GTK_SWITCH (object)));
	refresh (row->win);
}

static void
on_combo_changed (GtkComboBox *combo, gpointer data)
{
	Row *row = data;
	const gchar *id = gtk_combo_box_get_active_id (combo);

	if (row->win->syncing || id == NULL)
		return;

	if (row->kind == ROW_CHOICE)
		fs_prefs_edit_set_bool (row->win->edit, row->key,
		                        g_strcmp0 (id, row->true_id) == 0);
	else
		fs_prefs_edit_set_string (row->win->edit, row->key, id);

	refresh (row->win);
}

/* --------------------------------------------------------------- rows */

/* [ row_new ]
 * One setting: the name and its one line on the left, the control on
 * the right (the Overview's profile rows, the same shape). */
static Row *
row_new (PrefsWin *win, GtkWidget *card, const gchar *key, RowKind kind,
         const gchar *title, const gchar *about, const gchar *reason,
         GtkWidget *control)
{
	Row *row = g_new0 (Row, 1);
	GtkWidget *text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 3);
	gchar *name;

	row->win = win;
	row->key = key;
	row->kind = kind;
	row->control = control;
	row->about = about;

	/* A setting is written only when this window offers its control:
	 * one the platform does not act on has no row, so it is never
	 * written, whatever the copy holds (D8). */
	fs_prefs_edit_set_writable (win->edit, key, TRUE);

	row->box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 16);
	add_class (row->box, "pref-row");
	name = g_strconcat ("row:", key, NULL);
	gtk_widget_set_name (row->box, name);
	g_free (name);

	gtk_box_pack_start (GTK_BOX (text), label_new (title, "pref-label", TRUE),
	                    FALSE, FALSE, 0);
	if (about != NULL)
		gtk_box_pack_start (GTK_BOX (text),
		                    label_new (about, "muted", TRUE),
		                    FALSE, FALSE, 0);
	if (reason != NULL) {
		row->reason = label_new (reason, "pref-reason", TRUE);
		name = g_strconcat ("reason:", key, NULL);
		gtk_widget_set_name (row->reason, name);
		g_free (name);
		/* refresh() decides; show_all must not. */
		gtk_widget_set_no_show_all (row->reason, TRUE);
		gtk_box_pack_start (GTK_BOX (text), row->reason,
		                    FALSE, FALSE, 0);
	}
	gtk_box_pack_start (GTK_BOX (row->box), text, TRUE, TRUE, 0);

	gtk_widget_set_name (control, key);
	gtk_widget_set_valign (control, GTK_ALIGN_CENTER);
	atk_object_set_name (gtk_widget_get_accessible (control), title);
	g_object_set_data (G_OBJECT (control), "fs-pref-row", row);
	gtk_box_pack_start (GTK_BOX (row->box), control, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (card), row->box, FALSE, FALSE, 0);
	g_ptr_array_add (win->rows, row);

	return row;
}

static Row *
add_switch (PrefsWin *win, GtkWidget *card, const gchar *key,
            const gchar *title, const gchar *about, const gchar *reason)
{
	GtkWidget *toggle = gtk_switch_new ();
	Row *row;

	gtk_switch_set_active (GTK_SWITCH (toggle), edit_bool (win, key));
	row = row_new (win, card, key, ROW_SWITCH, title, about, reason,
	               toggle);
	g_signal_connect (toggle, "notify::active",
	                  G_CALLBACK (on_switch_active), row);
	return row;
}

/* [ add_choice ] -- two named options over one boolean key. */
static Row *
add_choice (PrefsWin *win, GtkWidget *card, const gchar *key,
            const gchar *title, const gchar *about,
            const gchar *false_id, const gchar *false_label,
            const gchar *true_id, const gchar *true_label)
{
	GtkWidget *combo = gtk_combo_box_text_new ();
	Row *row;

	gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (combo), false_id,
	                           false_label);
	gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (combo), true_id,
	                           true_label);
	gtk_combo_box_set_active_id (GTK_COMBO_BOX (combo),
	                             edit_bool (win, key) ? true_id : false_id);

	row = row_new (win, card, key, ROW_CHOICE, title, about, NULL, combo);
	row->true_id = true_id;
	g_signal_connect (combo, "changed", G_CALLBACK (on_combo_changed), row);
	return row;
}

/* [ add_device ]
 * A network device chooser.  Rows are keyed by the device name
 * (gtk_combo_box_set_active_id), never by position: picking row 1 for
 * "whichever matched" once showed and then saved the wrong adapter.
 * A stored device that is not attached right now stays on the list as
 * "name (not present)" and stays selected, so opening and saving the
 * window can never quietly move the firewall to another device. */
static Row *
add_device (PrefsWin *win, GtkWidget *card, const gchar *key,
            const gchar *title, const gchar *about, GList *ifaces)
{
	GtkWidget *combo = gtk_combo_box_text_new ();
	const gchar *current = fs_prefs_edit_get_string (win->edit, key);
	GHashTable *seen = g_hash_table_new (g_str_hash, g_str_equal);
	Row *row;

	gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (combo), "",
	                           _("None chosen"));

	for (GList *l = ifaces; l != NULL; l = l->next) {
		FsInterface *iface = l->data;
		gchar *label;

		/* One row per device, however many addresses it has. */
		if (iface->name == NULL || *iface->name == '\0' ||
		    g_hash_table_contains (seen, iface->name))
			continue;
		g_hash_table_add (seen, iface->name);

		label = (iface->ip != NULL && *iface->ip != '\0')
		      ? g_strdup_printf ("%s (%s)", iface->name, iface->ip)
		      : g_strdup (iface->name);
		gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (combo),
		                           iface->name, label);
		g_free (label);
	}

	if (current != NULL && *current != '\0' &&
	    !g_hash_table_contains (seen, current)) {
		gchar *label = g_strdup_printf (_("%s (not present)"), current);

		gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (combo), current,
		                           label);
		g_free (label);
		if (win->absent_note != NULL)
			gtk_widget_show (win->absent_note);
	}
	g_hash_table_unref (seen);

	gtk_combo_box_set_active_id (GTK_COMBO_BOX (combo),
	                             current != NULL ? current : "");

	row = row_new (win, card, key, ROW_DEVICE, title, about, NULL, combo);
	g_signal_connect (combo, "changed", G_CALLBACK (on_combo_changed), row);
	return row;
}

/* A line of explanation inside a card, under its rows. */
static GtkWidget *
add_note (GtkWidget *card, const gchar *text)
{
	GtkWidget *note = label_new (text, "pref-note", TRUE);

	gtk_box_pack_start (GTK_BOX (card), note, FALSE, FALSE, 0);
	return note;
}

/* -------------------------------------------------------------- pages */

static void
on_nav_toggled (GtkToggleButton *button, gpointer data)
{
	PrefsWin *win = data;
	const gchar *page = g_object_get_data (G_OBJECT (button), "page");

	if (win->syncing)
		return;

	/* A press on the selected item would un-check it; pages are not
	 * optional, so it is put straight back. */
	if (!gtk_toggle_button_get_active (button)) {
		win->syncing = TRUE;
		gtk_toggle_button_set_active (button, TRUE);
		win->syncing = FALSE;
		return;
	}

	gtk_stack_set_visible_child_name (GTK_STACK (win->stack), page);
}

static void
on_page_shown (GObject *stack, GParamSpec *pspec, gpointer data)
{
	PrefsWin *win = data;
	const gchar *page = gtk_stack_get_visible_child_name (GTK_STACK (stack));

	(void) pspec;
	win->syncing = TRUE;
	for (guint i = 0; i < win->nav->len; i++) {
		GtkWidget *item = g_ptr_array_index (win->nav, i);
		gboolean on = g_strcmp0 (g_object_get_data (G_OBJECT (item),
		                                            "page"), page) == 0;

		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (item), on);
		if (on)
			add_class (item, "nav-active");
		else
			gtk_style_context_remove_class (
				gtk_widget_get_style_context (item), "nav-active");
	}
	win->syncing = FALSE;
}

/* [ page_new ]
 * A page and its navigation item.  Returns the box the cards go in.
 * The whole page scrolls, so a short or narrow window loses nothing. */
static GtkWidget *
page_new (PrefsWin *win, GtkWidget *nav_box, const gchar *id,
          FsIconKind icon, const gchar *title, const gchar *subtitle)
{
	GtkWidget *scroll = gtk_scrolled_window_new (NULL, NULL);
	GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *head = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *cards = gtk_box_new (GTK_ORIENTATION_VERTICAL, 16);
	GtkWidget *item = gtk_toggle_button_new ();
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	gchar *name;

	add_class (page, "page");
	add_class (head, "page-head");
	gtk_box_pack_start (GTK_BOX (head), label_new (title, "page-title", FALSE),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (head),
	                    label_new (subtitle, "page-subtitle", TRUE),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), head, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), cards, FALSE, FALSE, 0);

	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), page);
	gtk_stack_add_titled (GTK_STACK (win->stack), scroll, id, title);

	/* The navigation item, drawn like the main window's. */
	gtk_box_pack_start (GTK_BOX (row), fs_icon_new (icon, 18),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (row), label_new (title, NULL, FALSE),
	                    TRUE, TRUE, 0);
	gtk_container_add (GTK_CONTAINER (item), row);
	gtk_button_set_relief (GTK_BUTTON (item), GTK_RELIEF_NONE);
	add_class (item, "nav-item");
	name = g_strconcat ("nav:", id, NULL);
	gtk_widget_set_name (item, name);
	g_free (name);
	g_object_set_data_full (G_OBJECT (item), "page", g_strdup (id), g_free);
	g_signal_connect (item, "toggled", G_CALLBACK (on_nav_toggled), win);
	gtk_box_pack_start (GTK_BOX (nav_box), item, FALSE, FALSE, 0);
	g_ptr_array_add (win->nav, item);

	return cards;
}

/* [ card_new ] -- a white card with a heading; returns the card. */
static GtkWidget *
card_new (GtkWidget *cards, const gchar *heading)
{
	GtkWidget *card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *label = label_new (heading, "card-heading", FALSE);

	add_class (card, "card");
	add_class (card, "pref-card");
	add_class (label, "card-head");
	gtk_box_pack_start (GTK_BOX (card), label, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (cards), card, FALSE, FALSE, 0);
	return card;
}

/* [ add_background_rows ]
 * The place for settings that keep StockFW at work while nobody has it
 * open (starting it at sign-in).  It adds nothing yet and says so by
 * returning FALSE, which keeps the "Background" card hidden: a heading
 * over no settings would promise something that does not exist. */
static gboolean
add_background_rows (PrefsWin *win, GtkWidget *card)
{
	(void) win;
	(void) card;
	return FALSE;
}

static void
build_general (PrefsWin *win, GtkWidget *nav)
{
	GtkWidget *cards = page_new (win, nav, "general", FS_ICON_SETTINGS,
		_("General"),
		_("How the StockFW window behaves, and what happens when it "
		  "opens."));
	GtkWidget *card;
	Row *tray;

	card = card_new (cards, _("Window and tray"));
	tray = add_switch (win, card, FS_PREFS_ENABLE_TRAY_ICON,
		_("Show a tray icon"),
		_("Puts StockFW in the notification area, with a menu to open "
		  "the window or quit."), NULL);
	add_switch (win, card, FS_PREFS_MINIMIZE_TO_TRAY,
		_("Close and minimize to the tray"),
		_("Closing or minimizing hides the window in the tray instead "
		  "of quitting, so event monitoring and Sentinel keep running. "
		  "Needs the tray icon; where the desktop has no tray area, "
		  "closing quits."), NULL)->master = tray;

	card = card_new (cards, _("Firewall"));
	add_switch (win, card, FS_PREFS_START_ON_GUI,
		_("Start the firewall when StockFW opens"),
		_("Turns the firewall on each time StockFW starts. Off: the "
		  "firewall is left as it was."), NULL);

	card = card_new (cards, _("Background"));
	gtk_widget_set_name (card, "prefs-background");
	if (!add_background_rows (win, card))
		gtk_widget_set_no_show_all (card, TRUE);
}

static void
build_events (PrefsWin *win, GtkWidget *nav)
{
	GtkWidget *cards = page_new (win, nav, "events", FS_ICON_LIST,
		_("Events"), _("What the Events list shows."));
	GtkWidget *card = card_new (cards, _("Event list"));

	/* fs-hitview.c hit_is_redundant: the hit just before, nothing
	 * older, and the action is not compared. */
	add_switch (win, card, FS_PREFS_SKIP_REDUNDANT,
		_("Hide repeated events"),
		_("Leaves out a hit that repeats the one just before it (same "
		  "source, destination, port and protocol), so one program "
		  "retrying does not fill the list."),
		NULL);
	add_switch (win, card, FS_PREFS_SKIP_NOT_FOR_FIREWALL,
		_("Skip events not addressed to this computer"),
		_("Leaves out broadcasts and traffic meant for other machines. "
		  "Connections this computer starts are always listed."),
		NULL);
}

static void
on_open_policy (GtkButton *button, gpointer data)
{
	PrefsWin *win = data;

	(void) button;
	win->response = PREFS_OPEN_POLICY;
	g_main_loop_quit (win->loop);
}

static void
build_policy (PrefsWin *win, GtkWidget *nav)
{
	GtkWidget *cards = page_new (win, nav, "policy", FS_ICON_SLIDERS,
		_("Policy"), _("When changes to your rules reach the firewall."));
	GtkWidget *card, *row, *text, *pill;
	gboolean audit = fs_apply_audit_only ();

	card = card_new (cards, _("Applying changes"));
	add_switch (win, card, FS_PREFS_APPLY_POLICY_INSTANTLY,
		_("Apply policy changes immediately"),
		_("Each rule you add, edit or remove on the Policy page goes to "
		  "the firewall at once. Off: changes wait for Apply policy."),
		NULL);

	/* Audit-only is switched beside the Apply button it guards; here
	 * it is only reported, with the way there.  Two switches for one
	 * setting would fall out of step. */
	card = card_new (cards, _("Testing"));
	row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 16);
	add_class (row, "pref-row");
	gtk_widget_set_name (row, "row:audit-only");
	text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 3);
	gtk_box_pack_start (GTK_BOX (text),
	                    label_new (_("Audit-only testing mode"),
	                               "pref-label", TRUE),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (text),
		label_new (audit
		           ? _("On: policy changes are saved and written to the "
		               "audit log, but the firewall is left untouched "
		               "until you turn it off.")
		           : _("Off: applying the policy changes the firewall. "
		               "Turn it on to try changes without touching the "
		               "firewall."),
		           "muted", TRUE), FALSE, FALSE, 0);
	if (fs_statusview_policy_locked ())
		gtk_box_pack_start (GTK_BOX (text),
			label_new (_("The Lock on the Overview page is also "
			             "holding every change back right now."),
			           "pref-reason", TRUE), FALSE, FALSE, 0);
	win->policy_link = gtk_button_new_with_label (_("Change on the Policy page"));
	add_class (win->policy_link, "fs-link");
	gtk_widget_set_name (win->policy_link, "prefs-open-policy");
	gtk_widget_set_valign (win->policy_link, GTK_ALIGN_CENTER);
	g_signal_connect (win->policy_link, "clicked",
	                  G_CALLBACK (on_open_policy), win);
	gtk_box_pack_start (GTK_BOX (text), win->policy_link, FALSE, FALSE, 0);
	gtk_widget_set_halign (win->policy_link, GTK_ALIGN_START);
	gtk_box_pack_start (GTK_BOX (row), text, TRUE, TRUE, 0);

	pill = label_new (audit ? _("On") : _("Off"), "state-pill", FALSE);
	gtk_widget_set_name (pill, "audit-only-state");
	if (audit)
		add_class (pill, "on");
	gtk_widget_set_valign (pill, GTK_ALIGN_CENTER);
	gtk_box_pack_start (GTK_BOX (row), pill, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (card), row, FALSE, FALSE, 0);
}

static void
build_firewall (PrefsWin *win, GtkWidget *nav)
{
	const guint32 mine = FS_FWHON_REJECT_METHOD | FS_FWHON_OUTBOUND_MODE |
	                     FS_FWHON_LOG_ALLOWED;
	GtkWidget *cards, *card;

	/* Rows only where the backend acts on them, and no page at all
	 * when none does (Windows drops silently, leaves the outbound
	 * default to its profiles and logs through its audit policy). */
	if ((win->honors & mine) == 0)
		return;

	cards = page_new (win, nav, "firewall", FS_ICON_SHIELD,
		_("Firewall"),
		_("How blocked connections are answered, and what may leave "
		  "this computer."));

	if (win->honors & FS_FWHON_REJECT_METHOD) {
		card = card_new (cards, _("Blocked connections"));
		add_choice (win, card, FS_PREFS_FW_DENY_PACKETS,
			_("Answer to a blocked connection"),
			_("Drop: the sender hears nothing, as if this computer "
			  "were not there. Reject: the sender is told at once "
			  "that the connection was refused."),
			"reject", _("Reject with an error"),
			"drop", _("Drop silently"));
	}

	if (win->honors & FS_FWHON_OUTBOUND_MODE) {
		card = card_new (cards, _("Outgoing connections"));
		add_choice (win, card, FS_PREFS_FW_RESTRICTIVE_OUTBOUND,
			_("Connections from this computer"),
			_("Which connections programs on this computer may "
			  "start. Your outbound deny rules apply either way."),
			"allow", _("Allow all outgoing"),
			"block", _("Block outgoing unless allowed"));
		win->outbound_warning = label_new (
			_("Only connections that an outbound allow rule on the "
			  "Policy page names can leave this computer. Everything "
			  "else is blocked, including software updates, until "
			  "you allow it."), "pref-warning", TRUE);
		gtk_widget_set_name (win->outbound_warning,
		                     "prefs-outbound-warning");
		gtk_widget_set_no_show_all (win->outbound_warning, TRUE);
		gtk_box_pack_start (GTK_BOX (card), win->outbound_warning,
		                    FALSE, FALSE, 0);
	}

	if (win->honors & FS_FWHON_LOG_ALLOWED) {
		card = card_new (cards, _("Logging"));
		add_switch (win, card, FS_PREFS_FW_LOG_ALLOWED,
			_("Log allowed connections"),
			_("Records the first packet of each new connection your "
			  "policy allows, at most 10 a second, so Events and "
			  "Activity show allowed traffic as well as blocked."),
			NULL);
	}
}

static void
build_network (PrefsWin *win, GtkWidget *nav)
{
	GtkWidget *cards, *card;
	GList *ifaces;

	if ((win->sections & FS_FWSEC_NETWORK) == 0)
		return;

	cards = page_new (win, nav, "network", FS_ICON_ADAPTER,
		_("Network"),
		_("Which adapters face the Internet and your own network."));
	ifaces = fs_backend ()->list_interfaces != NULL
	       ? fs_backend ()->list_interfaces () : NULL;

	card = card_new (cards, _("Devices"));
	win->absent_note = label_new (
		_("A device marked \"not present\" is not connected right now. "
		  "It stays chosen, and its rules apply again when it is "
		  "back."), "pref-note", TRUE);
	gtk_widget_set_name (win->absent_note, "prefs-absent-note");
	gtk_widget_set_no_show_all (win->absent_note, TRUE);

	add_device (win, card, FS_PREFS_FW_EXT_IF, _("Internet device"),
		_("The adapter that connects this computer to the Internet. "
		  "Port forwards, connection sharing and the Protection "
		  "blocks apply to it."), ifaces);
	add_device (win, card, FS_PREFS_FW_INT_IF, _("Local network device"),
		_("The adapter that faces your own network. Only used for "
		  "connection sharing."), ifaces);
	gtk_box_pack_start (GTK_BOX (card), win->absent_note, FALSE, FALSE, 0);
	g_list_free_full (ifaces, (GDestroyNotify) fs_interface_free);

	card = card_new (cards, _("Connection sharing"));
	add_switch (win, card, FS_PREFS_FW_NAT,
		_("Share the Internet connection (NAT)"),
		_("Lets devices on your local network reach the Internet "
		  "through this computer, which then acts as their router."),
		_("Needs both devices: choose an Internet device and a local "
		  "network device above."));
}

static void
build_icmp (PrefsWin *win, GtkWidget *nav)
{
	/* What each switch adds.  On Linux (FS_FWHON_ICMP_EXACT) the
	 * accepts come before the connection-state accept in INBOUND
	 * (fs-script.c), so replies and errors that belong to this
	 * computer's own traffic get in whatever these say: the switches
	 * only decide about unsolicited ones, and `exact' says so.
	 * Elsewhere they are plain allow rules (fs-settings-plan.c), and
	 * `about' says no more than that. */
	static const struct
	{
		const gchar *key;
		const gchar *title;
		const gchar *about;
		const gchar *exact;   /* Linux wording, or NULL: as about */
	} types[] = {
		{ FS_PREFS_FW_ICMP_ECHO_REQUEST, N_("Echo request (ping)"),
		  N_("Lets other computers ping this one."), NULL },
		{ FS_PREFS_FW_ICMP_ECHO_REPLY, N_("Echo reply"),
		  N_("Lets in echo replies from anywhere, asked for or not."),
		  N_("Lets in echo replies this computer did not ask for. "
		     "Replies to your own pings get through either way.") },
		{ FS_PREFS_FW_ICMP_UNREACHABLE, N_("Host unreachable"),
		  N_("Lets in \"host unreachable\" reports from anywhere."),
		  N_("Lets in \"host unreachable\" reports that are not about "
		     "a connection this computer made. Reports about your own "
		     "connections get through either way.") },
		{ FS_PREFS_FW_ICMP_TRACEROUTE, N_("Traceroute"),
		  N_("Opens UDP port 33434, where Unix-style traceroute "
		     "probes arrive."), NULL },
		{ FS_PREFS_FW_ICMP_MSTRACEROUTE, N_("Windows traceroute"),
		  N_("Lets in every \"destination unreachable\" report (the "
		     "original's \"MS traceroute\" option). Traceroute and "
		     "tracert do not need it."), NULL },
		{ FS_PREFS_FW_ICMP_REDIRECTION, N_("Redirection"),
		  N_("Lets routers send traffic another way. Seldom needed, "
		     "and open to abuse."), NULL },
		{ FS_PREFS_FW_ICMP_TIMESTAMPING, N_("Timestamping (IPv4 only)"),
		  N_("Answers time queries. Rarely needed, and it gives away "
		     "the clock."), NULL },
		{ FS_PREFS_FW_ICMP_MASKING, N_("Address masking (IPv4 only)"),
		  N_("Answers netmask queries. Obsolete."), NULL },
		{ FS_PREFS_FW_ICMP_SOURCE_QUENCHES,
		  N_("Source quenching (IPv4 only)"),
		  N_("Obsolete congestion messages."), NULL },
	};
	gboolean exact = (win->honors & FS_FWHON_ICMP_EXACT) != 0;
	GtkWidget *cards, *card;
	Row *master;

	if ((win->sections & FS_FWSEC_ICMP) == 0)
		return;

	cards = page_new (win, nav, "icmp", FS_ICON_ACTIVITY, _("ICMP"),
		_("Which network control messages may reach this computer."));

	card = card_new (cards, _("ICMP filtering"));
	master = add_switch (win, card, FS_PREFS_FW_FILTER_ICMP,
		_("Filter ICMP messages"),
		_("On: only the message types switched on below are let in. "
		  "Off: every ICMP message is let in."), NULL);

	/* What the choices do not cover, said beside the switch that
	 * turns them on, before anyone scrolls through the types. */
	if ((win->honors & FS_FWHON_ICMP_EXACT) == 0)
		add_note (card,
			_("IPv4 only: these become allow rules beside Windows' "
			  "own, and Windows' own rules may still allow some "
			  "types you switch off here. ICMPv6 is left to "
			  "Windows."));
	if ((win->honors & FS_FWHON_RATE_LIMIT) == 0)
		add_note (card,
			_("Windows Firewall does not rate-limit these messages, so "
			  "a flood of an allowed type is not slowed down."));
	if ((win->honors & FS_FWHON_ICMP_EXACT) != 0 &&
	    fs_backend ()->ipv6_state != NULL)
		add_note (card,
			_("IPv6 uses the same choices. Neighbour discovery, router "
			  "advertisements, \"packet too big\" and DHCPv6 replies "
			  "are always allowed: IPv6 stops working without them."));

	card = card_new (cards, _("Allowed message types"));
	for (guint i = 0; i < G_N_ELEMENTS (types); i++)
		add_switch (win, card, types[i].key, _(types[i].title),
		            exact && types[i].exact != NULL
		            ? _(types[i].exact) : _(types[i].about),
		            NULL)->master = master;
}

static void
build_protection (PrefsWin *win, GtkWidget *nav)
{
	gboolean devices = (win->sections & FS_FWSEC_NETWORK) != 0;
	GtkWidget *cards, *card;

	if ((win->sections & FS_FWSEC_ADVANCED) == 0)
		return;

	cards = page_new (win, nav, "protection", FS_ICON_SHIELD_CHECK,
		_("Protection"),
		_("Extra blocks for traffic that should never arrive."));

	/* Linux scopes each block to a device, Windows to the network
	 * profiles: the same switch, said the way it actually works. */
	card = card_new (cards, _("Broadcasts"));
	add_switch (win, card, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST,
		_("Block broadcasts from the Internet side"),
		devices
		? _("Drops broadcast packets arriving on the Internet device.")
		: _("Drops broadcast packets on networks Windows treats as "
		    "public."),
		devices
		? _("Has no effect until you choose an Internet device on the "
		    "Network page.")
		: NULL);
	add_switch (win, card, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST,
		_("Block broadcasts from the local network"),
		devices
		? _("Drops broadcast packets arriving on the local network "
		    "device while the connection is shared.")
		: _("Drops broadcast packets on networks Windows treats as "
		    "private. Some printers and media players find each "
		    "other this way."),
		devices
		? _("Has no effect unless connection sharing is on and both "
		    "devices are chosen on the Network page.")
		: NULL);

	card = card_new (cards, _("Spoofed addresses"));
	add_switch (win, card, FS_PREFS_FW_BLOCK_NON_ROUTABLES,
		_("Block reserved source addresses"),
		devices
		? _("Drops packets on the Internet device that claim to come "
		    "from private or loopback ranges (10/8, 172.16/12, "
		    "192.168/16, 127/8); they cannot be genuine there.")
		: _("Drops packets from private and loopback ranges (10/8, "
		    "172.16/12, 192.168/16, 127/8) on networks Windows "
		    "treats as public."),
		devices
		? _("Has no effect until you choose an Internet device on the "
		    "Network page.")
		: NULL);
}

/* ------------------------------------------------------------- window */

static void
on_cancel (GtkButton *button, gpointer data)
{
	PrefsWin *win = data;

	(void) button;
	win->response = PREFS_CANCEL;
	g_main_loop_quit (win->loop);
}

static void
on_save (GtkButton *button, gpointer data)
{
	PrefsWin *win = data;

	(void) button;
	win->response = PREFS_SAVE;
	g_main_loop_quit (win->loop);
}

static gboolean
on_delete (GtkWidget *widget, GdkEvent *event, gpointer data)
{
	PrefsWin *win = data;

	(void) widget;
	(void) event;
	win->response = PREFS_CANCEL;
	if (g_main_loop_is_running (win->loop))
		g_main_loop_quit (win->loop);
	return TRUE;   /* destroyed by fs_dialogs_preferences */
}

/* Help, and F1: the Help topic for the page shown. */
static void
on_help (GtkButton *button, gpointer data)
{
	PrefsWin *win = data;
	const gchar *page =
		gtk_stack_get_visible_child_name (GTK_STACK (win->stack));

	(void) button;
	fs_help_show (win->window, fs_help_topic_for_prefs_page (page));
}

static gboolean
on_key (GtkWidget *widget, GdkEventKey *event, gpointer data)
{
	(void) widget;

	if (event->keyval == GDK_KEY_F1
	    && (event->state & gtk_accelerator_get_default_mod_mask ()) == 0) {
		on_help (NULL, data);
		return TRUE;
	}
	if (event->keyval == GDK_KEY_Escape) {
		on_cancel (NULL, data);
		return TRUE;
	}
	return FALSE;
}

/* [ clamp_size ] -- 860x600, or what the work area leaves of it. */
static void
clamp_size (GtkWindow *window, GtkWidget *parent)
{
	GdkDisplay *display = gdk_display_get_default ();
	GdkMonitor *monitor = NULL;
	gint width = PREFS_WIDTH, height = PREFS_HEIGHT;

	if (display != NULL) {
		GdkWindow *on = parent != NULL ? gtk_widget_get_window (parent)
		                               : NULL;

		monitor = on != NULL
		        ? gdk_display_get_monitor_at_window (display, on)
		        : gdk_display_get_primary_monitor (display);
		if (monitor == NULL && gdk_display_get_n_monitors (display) > 0)
			monitor = gdk_display_get_monitor (display, 0);
	}

	if (monitor != NULL) {
		GdkRectangle area;

		gdk_monitor_get_workarea (monitor, &area);
		if (area.width > 0)
			width = MIN (width, MAX (area.width - 40, 480));
		if (area.height > 0)
			height = MIN (height, MAX (area.height - 40, 360));
	}

	gtk_window_set_default_size (window, width, height);
}

static GtkWidget *
build_window (PrefsWin *win, GtkWidget *parent)
{
	GtkWidget *outer, *nav, *head, *right, *footer, *cancel, *save, *help;
	const FsBackend *backend = fs_backend ();

	win->window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title (GTK_WINDOW (win->window), _("Preferences"));
	gtk_widget_set_name (win->window, "fs-preferences");
	gtk_window_set_modal (GTK_WINDOW (win->window), TRUE);
	gtk_window_set_type_hint (GTK_WINDOW (win->window),
	                          GDK_WINDOW_TYPE_HINT_DIALOG);
	gtk_window_set_position (GTK_WINDOW (win->window),
	                         parent != NULL ? GTK_WIN_POS_CENTER_ON_PARENT
	                                        : GTK_WIN_POS_CENTER);
	if (parent != NULL) {
		gtk_window_set_transient_for (GTK_WINDOW (win->window),
		                              GTK_WINDOW (parent));
		gtk_window_set_destroy_with_parent (GTK_WINDOW (win->window),
		                                    TRUE);
	}
	clamp_size (GTK_WINDOW (win->window), parent);
	g_signal_connect (win->window, "delete-event",
	                  G_CALLBACK (on_delete), win);
	g_signal_connect (win->window, "key-press-event",
	                  G_CALLBACK (on_key), win);

	outer = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_container_add (GTK_CONTAINER (win->window), outer);

	/* Navigation: the main window's sidebar, smaller. */
	nav = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	gtk_widget_set_size_request (nav, NAV_WIDTH, -1);
	add_class (nav, "fs-sidebar");
	add_class (nav, "prefs-nav");
	head = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	add_class (head, "fs-brand");
	gtk_box_pack_start (GTK_BOX (head),
	                    label_new (_("Preferences"), "fs-brand-name", FALSE),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (head),
	                    label_new (backend->display_name != NULL
	                               ? backend->display_name : "",
	                               "fs-brand-version", TRUE),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (nav), head, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (outer), nav, FALSE, FALSE, 0);

	right = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_pack_start (GTK_BOX (outer), right, TRUE, TRUE, 0);

	win->stack = gtk_stack_new ();
	gtk_widget_set_name (win->stack, "prefs-pages");
	gtk_widget_set_hexpand (win->stack, TRUE);
	gtk_widget_set_vexpand (win->stack, TRUE);
	gtk_box_pack_start (GTK_BOX (right), win->stack, TRUE, TRUE, 0);

	/* Footer: Help and what is pending on the left, the two answers
	 * on the right. */
	footer = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	add_class (footer, "prefs-footer");
	help = gtk_button_new ();
	{
		GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);

		gtk_box_pack_start (GTK_BOX (row), fs_icon_new (FS_ICON_HELP, 16),
		                    FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (row),
		                    gtk_label_new_with_mnemonic (_("_Help")),
		                    FALSE, FALSE, 0);
		gtk_container_add (GTK_CONTAINER (help), row);
	}
	gtk_widget_set_name (help, "prefs-help");
	gtk_widget_set_tooltip_text (help, _("Help for this page (F1)"));
	add_class (help, "btn-subtle");
	g_signal_connect (help, "clicked", G_CALLBACK (on_help), win);
	gtk_box_pack_start (GTK_BOX (footer), help, FALSE, FALSE, 0);
	win->status = label_new ("", "muted", FALSE);
	gtk_widget_set_name (win->status, "prefs-status");
	gtk_label_set_ellipsize (GTK_LABEL (win->status), PANGO_ELLIPSIZE_END);
	gtk_box_pack_start (GTK_BOX (footer), win->status, TRUE, TRUE, 0);

	cancel = gtk_button_new_with_mnemonic (_("_Cancel"));
	gtk_widget_set_name (cancel, "prefs-cancel");
	add_class (cancel, "btn-subtle");
	g_signal_connect (cancel, "clicked", G_CALLBACK (on_cancel), win);
	gtk_box_pack_start (GTK_BOX (footer), cancel, FALSE, FALSE, 0);

	save = gtk_button_new_with_mnemonic (_("_Save"));
	gtk_widget_set_name (save, "prefs-save");
	add_class (save, "btn-primary");
	gtk_widget_set_can_default (save, TRUE);
	g_signal_connect (save, "clicked", G_CALLBACK (on_save), win);
	gtk_box_pack_start (GTK_BOX (footer), save, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (right), footer, FALSE, FALSE, 0);

	build_general (win, nav);
	build_events (win, nav);
	build_policy (win, nav);
	build_firewall (win, nav);
	build_network (win, nav);
	build_icmp (win, nav);
	build_protection (win, nav);

	g_signal_connect (win->stack, "notify::visible-child",
	                  G_CALLBACK (on_page_shown), win);

	gtk_window_set_default (GTK_WINDOW (win->window), save);

	return save;
}

/* --------------------------------------------------------- after save */

static void
report (GtkWidget *parent, gboolean error, const gchar *header,
        const gchar *body)
{
	if (error)
		fs_dialogs_error (parent, header, body);
	else
		fs_dialogs_info (parent, header, body);
}

/* [ offer_apply ]
 * A firewall setting changed: settings reach the firewall only with an
 * apply.  Ask, and apply through the gate -- the same holds, rollback
 * and audit line as Apply policy -- reporting exactly what it did.
 *
 * Asked when the firewall is running, and also when it is off on a
 * backend whose Start does not re-apply the rules (Windows: Start only
 * turns the profiles on, so the old settings would come back with
 * them).  On Linux with the firewall off nothing is asked: Start loads
 * the whole policy under the saved settings.
 *
 * The settings go out under the policy that is live -- the last one
 * applied, from the journal -- so Policy-page edits nobody has applied
 * yet (auto-apply is off by default) are not pushed past the Policy
 * page's own preview.  With no applied policy on record they can only
 * go out together with the loaded policy, and the question says so,
 * with what that apply changes. */
static void
offer_apply (GtkWidget *parent, const FsSettings *saved_before)
{
	const FsBackend *backend = fs_backend ();
	FsPolicy *loaded = fs_app_policy ();
	FsPolicy *live, *under;
	FsPolicyImpact *pending;
	FsSettings *previous;
	GHashTable *recorded;
	FsFirewallState state;
	GtkWidget *dialog;
	FsApplyOutcome *outcome;
	GError *error = NULL;
	GString *body;
	const gchar *hold;
	gboolean running, start_applies, journal, unapplied;
	gchar *desc;
	gint answer;

	if (backend->available == NULL || !backend->available () ||
	    backend->get_state == NULL)
		return;

	state = backend->get_state ();
	running = (state == FS_FW_RUNNING || state == FS_FW_HIT ||
	           state == FS_FW_LOCKED);
	start_applies = (backend->fw_honors & FS_FWHON_START_APPLIES) != 0;
	if (!running && (start_applies || state != FS_FW_STOPPED))
		return;   /* Start applies the whole policy, saved settings
		           * included; or the firewall cannot be reached */

	if (loaded == NULL) {
		report (parent, FALSE, _("Settings saved, not applied"),
			_("StockFW has no policy loaded to apply them with, so "
			  "the firewall was left as it was. They take effect the "
			  "next time the policy is applied."));
		return;
	}

	live = fs_policy_new ();
	journal = fs_apply_journal_load (live, NULL);
	under = journal ? live : loaded;
	pending = fs_policy_impact (journal ? live : NULL, loaded);
	unapplied = pending->added > 0 || pending->removed > 0;
	desc = fs_policy_impact_describe (pending);

	body = g_string_new (running
		? _("The firewall is running with the previous settings.")
		: _("The firewall is off. Turning it on does not apply "
		    "settings: it brings back the rules as they were last "
		    "applied."));
	g_string_append_c (body, ' ');
	if (journal) {
		g_string_append (body,
			_("Apply now puts the new settings in place under the "
			  "policy that is live, with the same checks as Apply "
			  "policy."));
		if (unapplied) {
			g_string_append (body, "\n\n");
			g_string_append_printf (body,
				_("Changes on the Policy page that are not applied "
				  "yet (%s) are left out and stay pending: apply "
				  "them on the Policy page."), desc);
		}
	} else {
		g_string_append_printf (body,
			_("No applied policy is on record, so the settings can "
			  "only reach the firewall together with your policy. "
			  "Apply now applies both, with the same checks as "
			  "Apply policy: %s."), desc);
	}
	g_string_append (body, "\n\n");
	g_string_append (body, start_applies
		? _("Later keeps the previous settings until the policy is "
		    "next applied or the firewall is started.")
		: _("Later keeps the previous settings until the policy is "
		    "next applied."));

	dialog = gtk_message_dialog_new (parent != NULL ? GTK_WINDOW (parent)
	                                                : NULL,
	                                 GTK_DIALOG_MODAL,
	                                 GTK_MESSAGE_QUESTION,
	                                 GTK_BUTTONS_NONE, "%s",
	                                 _("Apply the new firewall settings "
	                                   "now?"));
	gtk_widget_set_name (dialog, "prefs-apply-question");
	gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
	                                          "%s", body->str);
	gtk_dialog_add_buttons (GTK_DIALOG (dialog),
	                        _("_Later"), GTK_RESPONSE_CANCEL,
	                        _("_Apply now"), GTK_RESPONSE_OK, NULL);
	gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);
	answer = gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
	g_string_free (body, TRUE);

	if (answer != GTK_RESPONSE_OK) {
		fs_policy_impact_free (pending);
		fs_policy_free (live);
		g_free (desc);
		return;
	}

	/* What to roll back to: the settings the journal says went out
	 * with the live policy, or -- with no record -- the ones saved
	 * before this change. */
	recorded = journal ? fs_apply_journal_settings () : NULL;
	if (recorded != NULL) {
		previous = fs_settings_new ();
		fs_settings_load_values (previous, recorded);
	} else {
		previous = fs_settings_copy (saved_before);
	}

	hold = fs_policyview_hold_reason ();
	outcome = fs_app_apply_settings (under, previous, hold, &error);

	if (outcome == NULL) {
		report (parent, FALSE, _("Settings saved, not applied"),
			_("StockFW has no policy loaded to apply them with, so "
			  "the firewall was left as it was. They take effect the "
			  "next time the policy is applied."));
	} else if (outcome->held) {
		gchar *msg = g_strdup_printf (
			_("Reason: %s.\n\nThe settings are saved, but the "
			  "firewall was deliberately left untouched. Turn the hold "
			  "off (Audit-only on the Policy page, or the Lock on the "
			  "Overview) and apply the policy to make them live."),
			outcome->hold_reason);

		report (parent, FALSE, _("Settings saved, not applied"), msg);
		g_free (msg);
	} else if (outcome->result == FS_APPLY_OK) {
		/* Applying does not turn a stopped firewall on (Windows
		 * keeps the profiles as they are), so say where it stands. */
		GString *msg = g_string_new (running
			? _("The firewall now uses the new settings.")
			: _("The new settings are in place. The firewall is still "
			    "off: they take effect when it is turned on."));

		if (!journal) {
			g_string_append (msg, "\n\n");
			g_string_append_printf (msg,
				_("Your policy was applied with them: %s."),
				desc);
		} else if (unapplied) {
			g_string_append (msg, "\n\n");
			g_string_append (msg,
				_("Changes on the Policy page that are not "
				  "applied yet were left out: apply them on the "
				  "Policy page."));
		}
		if (outcome->notes != NULL) {
			g_string_append (msg, _("\n\nPlease note:\n"));
			g_string_append (msg, outcome->notes);
		}

		report (parent, FALSE, _("Firewall settings applied"),
		        msg->str);
		g_string_free (msg, TRUE);
	} else {
		const gchar *why = error != NULL
			? error->message
			: _(fs_util_apply_result_to_string ((int) outcome->result));
		const gchar *rollback;
		gchar *msg;

		if (outcome->rollback_attempted && outcome->rollback_verified)
			rollback = recorded != NULL
				? _("The firewall was put back to the last "
				    "applied policy and the settings it ran with, "
				    "and that restore was verified.")
				: _("The firewall was put back to the last "
				    "applied policy, under the settings saved "
				    "before this change, and that restore was "
				    "verified.");
		else if (outcome->rollback_attempted)
			rollback = _("Putting the previous rules back ALSO failed: "
			             "the firewall may be in an inconsistent state. "
			             "Check the Overview and apply again from a "
			             "session running as administrator.");
		else
			rollback = _("No previously applied policy is recorded, so "
			             "there was nothing to restore.");

		msg = g_strdup_printf (_("%s\n\n%s\n\nYour choices are saved; "
		                         "the next apply tries them again."),
		                       why, rollback);
		report (parent, TRUE, _("Could not apply the new settings"), msg);
		g_free (msg);
	}

	/* An apply can change what the Overview says about IPv6. */
	if (outcome != NULL && !outcome->held)
		fs_statusview_refresh_ipv6 ();

	fs_apply_outcome_free (outcome);
	g_clear_error (&error);
	if (recorded != NULL)
		g_hash_table_unref (recorded);
	fs_settings_free (previous);
	fs_policy_impact_free (pending);
	fs_policy_free (live);
	g_free (desc);
}

/* [ commit ]
 * Writes the changed values of the rows this window offers (row_new
 * marked them writable).  A row that is disabled right now still
 * counts: the ICMP types while filtering is off, a block whose device
 * was just cleared, the sharing switch turned off with a device
 * missing.  Its switch shows the change, and the footer counted it, so
 * dropping it on Save would be a quiet lie.  Returns TRUE when a
 * firewall setting was among them. */
static gboolean
commit (PrefsWin *win, guint *written)
{
	gboolean firewall = FALSE;

	*written = fs_prefs_edit_commit (win->edit, &firewall);
	return firewall;
}

/* [ fs_dialogs_preferences ]
 * Modal; nothing is written unless Save is pressed. */
void
fs_dialogs_preferences (GtkWidget *parent)
{
	PrefsWin win;
	GtkWidget *save;

	memset (&win, 0, sizeof (win));
	win.nav = g_ptr_array_new ();
	win.rows = g_ptr_array_new_with_free_func (g_free);
	win.edit = fs_prefs_edit_new ();
	win.sections = fs_backend ()->fw_sections;
	win.honors = fs_backend ()->fw_honors;
	win.loop = g_main_loop_new (NULL, FALSE);
	win.response = PREFS_CANCEL;

	save = build_window (&win, parent);
	refresh (&win);

	gtk_widget_show_all (win.window);
	gtk_stack_set_visible_child_name (GTK_STACK (win.stack), "general");
	on_page_shown (G_OBJECT (win.stack), NULL, &win);
	gtk_widget_grab_focus (save);

	g_main_loop_run (win.loop);

	if (win.response == PREFS_SAVE) {
		FsSettings *previous = fs_settings_new ();
		gboolean firewall;
		guint written = 0;

		/* What the firewall was told before this save, for the
		 * rollback should applying the new settings fail. */
		fs_settings_load_prefs (previous);
		firewall = commit (&win, &written);

		gtk_widget_destroy (win.window);
		win.window = NULL;

		if (written > 0) {
			fs_prefs_save ();
			fs_app_reload_settings ();
		}
		if (firewall)
			offer_apply (parent, previous);

		fs_settings_free (previous);
	} else {
		gtk_widget_destroy (win.window);
		win.window = NULL;
		if (win.response == PREFS_OPEN_POLICY)
			fs_app_show_page (FS_PAGE_POLICY);
	}

	g_main_loop_unref (win.loop);
	g_ptr_array_unref (win.rows);
	g_ptr_array_unref (win.nav);
	fs_prefs_edit_free (win.edit);
}
