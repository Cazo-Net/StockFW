/*---[ fs-app.c ]-------------------------------------------------------
 * Application object and main window.
 *
 * Replaces gnome_app_new()/gnome_app_set_contents()/gnome_app_set_menus()
 * and the gnome_program_init()/gnome_master_client() startup dance in
 * the original stockfw.c with a plain GtkApplication.
 *
 * Layout (1.0.7 redesign): a dark sidebar on the left -- the logo on a
 * light tile, one item per page, Preferences and About, and the
 * firewall's verdict at the bottom -- and the selected page on the
 * right.  The pages live in a GtkNotebook whose own tabs are hidden;
 * the sidebar items stand in for them.  There is no menubar: its three
 * entries (Preferences, About, Quit) are the sidebar's footer items and
 * the Ctrl+, / Ctrl+Q shortcuts.
 *--------------------------------------------------------------------*/

#include "ui/fs-app.h"
#include "ui/fs-dialogs.h"
#include "ui/fs-statusview.h"
#include "ui/fs-policyview.h"
#include "ui/fs-hitview.h"
#include "ui/fs-activityview.h"
#include "ui/fs-copilot.h"
#include "ui/fs-trustview.h"
#include "ui/fs-tray.h"
#include "ui/fs-icons.h"
#include "core/fs-apply.h"
#include "core/fs-backend.h"
#include "core/fs-prefs.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"
#include "core/fs-copilot.h"
#include "core/fs-trust.h"
#include "core/fs-i18n.h"
#include "stockfw-logo-32.h"
#include "stockfw-logo-64.h"
#include "stockfw-logo-128.h"
#include "fs-theme-css.h"        /* generated from src/ui/fs-theme.css */

#include <gdk-pixbuf/gdk-pixbuf.h>

static FsApp fsapp = { NULL, NULL, NULL };

/* [ logo_pixbuf ] -- one embedded logo size, or NULL. */
static GdkPixbuf *
logo_pixbuf (const guchar *data, gsize len)
{
	GdkPixbufLoader *loader = gdk_pixbuf_loader_new ();
	GdkPixbuf *pixbuf = NULL;

	if (gdk_pixbuf_loader_write (loader, data, len, NULL) &&
	    gdk_pixbuf_loader_close (loader, NULL)) {
		pixbuf = gdk_pixbuf_loader_get_pixbuf (loader);
		if (pixbuf != NULL)
			g_object_ref (pixbuf);
	} else {
		gdk_pixbuf_loader_close (loader, NULL);
	}
	g_object_unref (loader);

	return pixbuf;
}

/* [ logo_icon_list ]
 * The window icon in three sizes, so the title bar, the task bar and
 * the window switcher each pick a sharp one instead of scaling a
 * single 64 px image.  64 comes first: gtk_window_get_icon() returns
 * the first entry, and the tray icon reuses it.  Free with
 * g_list_free_full (list, g_object_unref). */
static GList *
logo_icon_list (void)
{
	GList *list = NULL;
	GdkPixbuf *p;

	if ((p = logo_pixbuf (stockfw_logo_128_png,
	                      stockfw_logo_128_png_len)) != NULL)
		list = g_list_prepend (list, p);
	if ((p = logo_pixbuf (stockfw_logo_32_png,
	                      stockfw_logo_32_png_len)) != NULL)
		list = g_list_prepend (list, p);
	if ((p = logo_pixbuf (stockfw_logo_64_png,
	                      stockfw_logo_64_png_len)) != NULL)
		list = g_list_prepend (list, p);

	return list;
}

/* The sidebar's page items, index-aligned with the notebook pages
 * (FsAppPage order). */
static GtkWidget *nav_items[FS_PAGE_COUNT];

/* Set while the sidebar is being re-synced to the notebook, so the
 * items' own handlers do not fire back into the notebook. */
static gboolean nav_syncing = FALSE;

/* The sidebar footer: verdict dot, verdict, and who enforces it. */
static GtkWidget *side_dot = NULL;
static GtkWidget *side_state = NULL;
static GtkWidget *side_backend = NULL;

/* The traffic policy, shared by the Policy page and Apply. */
static FsPolicy *policy = NULL;

/* Interface and NAT choices, handed to the rule generator. */
static FsSettings *settings = NULL;

/* Smart Firewall Copilot instance. */
FsCopilot *copilot = NULL;

static gboolean
on_delete_event (GtkWidget *widget, GdkEvent *event, gpointer data)
{
	/* GTK owns the event it passes to the handler; freeing it here
	 * made the main loop free the same block a second time when the
	 * window closed -- a double free on every exit. */
	(void) event;
	(void) data;

	/* Background mode: with the tray icon up and "Minimize to the
	 * tray" on, the window closes INTO the icon and the firewall
	 * keeps running behind it; the tray menu's Quit is the way out.
	 * The gate refuses unless an icon is really embedded with the
	 * shell, so this can never hide the window with nothing to bring
	 * it back from. */
	if (fs_tray_hide_on_close ()) {
		gtk_widget_hide (widget);
		return TRUE;
	}

	/* No tray (or the preference is off): quit.  TRUE on both paths --
	 * this handler decides the window's fate, so the default handler
	 * must not destroy it underneath the quit.  The old void return
	 * left this signal's boolean result as whatever the callee had in
	 * a register. */
	fs_app_quit ();
	return TRUE;
}

/* [ on_window_state_event ] -- "Minimize to the tray": the minimize
 * button hides the window behind the icon under the same gate as the
 * close button, for the same reason.  Hiding an already-hidden window
 * cannot happen here: the gate only sees ICONIFIED arriving, and an
 * unmap removes it from the new state. */
static gboolean
on_window_state_event (GtkWidget *widget, GdkEventWindowState *event,
                       gpointer data)
{
	(void) data;

	if ((event->changed_mask & GDK_WINDOW_STATE_ICONIFIED) != 0 &&
	    (event->new_window_state & GDK_WINDOW_STATE_ICONIFIED) != 0 &&
	    fs_tray_hide_on_close ()) {
		gtk_widget_hide (widget);
		return TRUE;
	}

	return FALSE;
}

/* [ on_action_quit ]
 * "app.quit" */
static void
on_action_quit (GSimpleAction *action, GVariant *parameter, gpointer data)
{
	fs_app_quit ();
}

/* [ on_action_about ]
 * "app.about" */
static void
on_action_about (GSimpleAction *action, GVariant *parameter, gpointer data)
{
	fs_dialogs_about (fsapp.window);
}

/* [ on_action_preferences ]
 * "app.preferences" */
static void
on_action_preferences (GSimpleAction *action, GVariant *parameter, gpointer data)
{
	fs_dialogs_preferences (fsapp.window);
}

/* [ register_actions ] */
static void
register_actions (void)
{
	GSimpleAction *quit, *about, *preferences;

	quit = g_simple_action_new ("quit", NULL);
	g_signal_connect (quit, "activate", G_CALLBACK (on_action_quit), NULL);
	g_action_map_add_action (G_ACTION_MAP (fsapp.app), G_ACTION (quit));
	g_object_unref (quit);

	about = g_simple_action_new ("about", NULL);
	g_signal_connect (about, "activate", G_CALLBACK (on_action_about), NULL);
	g_action_map_add_action (G_ACTION_MAP (fsapp.app), G_ACTION (about));
	g_object_unref (about);

	preferences = g_simple_action_new ("preferences", NULL);
	g_signal_connect (preferences, "activate", G_CALLBACK (on_action_preferences), NULL);
	g_action_map_add_action (G_ACTION_MAP (fsapp.app), G_ACTION (preferences));
	g_object_unref (preferences);

	/* The menubar these used to live in is gone; the shortcuts stay. */
	{
		const gchar *quit_keys[] = { "<Primary>q", NULL };
		const gchar *pref_keys[] = { "<Primary>comma", NULL };

		gtk_application_set_accels_for_action (fsapp.app, "app.quit",
		                                       quit_keys);
		gtk_application_set_accels_for_action (fsapp.app,
		                                       "app.preferences",
		                                       pref_keys);
	}
}

/* [ page_frame ]
 * The header every page but the Overview shares: the page's name and
 * one line on what it is for, above the page's own controls, on the
 * same margins as the Overview so the title does not jump when the
 * sidebar switches pages.  The Overview draws its own header because
 * its title row also carries the Lock toggle. */
static GtkWidget *
page_frame (const gchar *title, const gchar *subtitle, GtkWidget *content,
            gboolean scrolls)
{
	GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *head = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *label;

	gtk_style_context_add_class (gtk_widget_get_style_context (page),
	                             "page");
	gtk_style_context_add_class (gtk_widget_get_style_context (head),
	                             "page-head");

	label = gtk_label_new (title);
	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             "page-title");
	gtk_box_pack_start (GTK_BOX (head), label, FALSE, FALSE, 0);

	label = gtk_label_new (subtitle);
	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             "page-subtitle");
	gtk_box_pack_start (GTK_BOX (head), label, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (page), head, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), content, TRUE, TRUE, 0);

	/* A page with no list of its own to scroll (Activity's graphs,
	 * Copilot's stacked cards) scrolls as a whole, header included,
	 * as the Overview does.  Otherwise its minimum height becomes the
	 * window's, and the notebook is as tall as its tallest page. */
	if (scrolls) {
		GtkWidget *scroll = gtk_scrolled_window_new (NULL, NULL);

		gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
		                                GTK_POLICY_NEVER,
		                                GTK_POLICY_AUTOMATIC);
		gtk_container_add (GTK_CONTAINER (scroll), page);
		return scroll;
	}
	return page;
}

/* [ add_page ]
 * Appends a notebook page.  The sidebar item for it already exists:
 * the two are index-aligned by FsAppPage.  A NULL subtitle means the
 * page draws its own header (the Overview); `scrolls' as page_frame. */
static void
add_page (const gchar *title, const gchar *subtitle, GtkWidget *content,
          gboolean scrolls)
{
	if (subtitle != NULL)
		content = page_frame (title, subtitle, content, scrolls);

	gtk_widget_show_all (content);
	gtk_notebook_append_page (GTK_NOTEBOOK (fsapp.notebook), content,
	                          gtk_label_new (title));
}

/* [ sync_nav ]
 * Push the notebook's current page into the sidebar: the selected item
 * is checked and carries "nav-active", the rest lose both. */
static void
sync_nav (guint page_num)
{
	nav_syncing = TRUE;

	for (guint i = 0; i < FS_PAGE_COUNT; i++) {
		GtkStyleContext *ctx;

		if (nav_items[i] == NULL)
			continue;

		ctx = gtk_widget_get_style_context (nav_items[i]);
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (nav_items[i]),
		                              i == page_num);
		if (i == page_num)
			gtk_style_context_add_class (ctx, "nav-active");
		else
			gtk_style_context_remove_class (ctx, "nav-active");
	}

	nav_syncing = FALSE;
}

/* [ on_nav_toggled ]
 * A sidebar item was pressed.  A press on the selected item would
 * un-check it; pages are not optional, so put it straight back. */
static void
on_nav_toggled (GtkToggleButton *button, gpointer data)
{
	guint page = GPOINTER_TO_UINT (data);

	if (nav_syncing)
		return;

	if (!gtk_toggle_button_get_active (button)) {
		gtk_toggle_button_set_active (button, TRUE);
		return;
	}

	gtk_notebook_set_current_page (GTK_NOTEBOOK (fsapp.notebook),
	                               (gint) page);
}

void
fs_app_show_page (FsAppPage page)
{
	if (fsapp.notebook == NULL || page >= FS_PAGE_COUNT)
		return;

	gtk_notebook_set_current_page (GTK_NOTEBOOK (fsapp.notebook),
	                               (gint) page);
}

/* [ on_page_switched ] -- keep the sidebar in step with the notebook. */
static void
on_page_switched (GtkNotebook *notebook, GtkWidget *page, guint page_num,
                  gpointer data)
{
	(void) notebook;
	(void) page;
	(void) data;

	sync_nav (page_num);
}

/* [ nav_button ]
 * One sidebar item: a drawn icon and a label in a flat button.  The
 * icon is drawn in the button's CSS colour, so hover and selection
 * recolour it along with the text. */
static GtkWidget *
nav_button (GtkWidget *button, FsIconKind icon, const gchar *text)
{
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	GtkWidget *label = gtk_label_new (text);

	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_box_pack_start (GTK_BOX (row), fs_icon_new (icon, 18),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (row), label, TRUE, TRUE, 0);
	gtk_container_add (GTK_CONTAINER (button), row);

	gtk_button_set_relief (GTK_BUTTON (button), GTK_RELIEF_NONE);
	gtk_widget_set_can_focus (button, TRUE);
	gtk_style_context_add_class (gtk_widget_get_style_context (button),
	                             "nav-item");
	return button;
}

static void
on_nav_preferences (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;
	fs_dialogs_preferences (fsapp.window);
}

static void
on_nav_about (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;
	fs_dialogs_about (fsapp.window);
}

/* [ sync_sidebar_state ]
 * The footer's verdict follows the Overview page's, word for word, so
 * the two can never disagree. */
static void
sync_sidebar_state (gpointer data)
{
	static const gchar *const dot_classes[] = {
		"dot-unknown", "dot-ok", "dot-warn", "dot-bad"
	};
	FsVerdict level = FS_VERDICT_UNKNOWN;
	const gchar *text = fs_statusview_verdict (&level);
	const gchar *backend_name = fs_backend ()->display_name;
	GtkStyleContext *ctx;

	(void) data;

	if (side_state == NULL)
		return;

	gtk_label_set_text (GTK_LABEL (side_state), text);
	gtk_label_set_text (GTK_LABEL (side_backend),
	                    backend_name != NULL ? backend_name : "");

	ctx = gtk_widget_get_style_context (side_dot);
	for (guint i = 0; i < G_N_ELEMENTS (dot_classes); i++)
		gtk_style_context_remove_class (ctx, dot_classes[i]);
	if ((guint) level < G_N_ELEMENTS (dot_classes))
		gtk_style_context_add_class (ctx, dot_classes[level]);
}

/* [ build_sidebar ]
 * Logo on a light tile (the logo's dark lower half disappears on the
 * dark sidebar otherwise), the page items, then Preferences and About,
 * then the verdict. */
static GtkWidget *
build_sidebar (void)
{
	static const struct {
		FsIconKind icon;
		const gchar *label;
	} pages[FS_PAGE_COUNT] = {
		{ FS_ICON_SHIELD,       N_("Overview") },
		{ FS_ICON_LIST,         N_("Events") },
		{ FS_ICON_ACTIVITY,     N_("Activity") },
		{ FS_ICON_SLIDERS,      N_("Policy") },
		{ FS_ICON_CHAT,         N_("Copilot") },
		{ FS_ICON_CHECK_CIRCLE, N_("Trust") },
	};
	GtkWidget *bar, *brand, *tile, *names, *label, *spacer, *footer, *row;

	bar = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	gtk_widget_set_size_request (bar, 220, -1);
	gtk_style_context_add_class (gtk_widget_get_style_context (bar),
	                             "fs-sidebar");

	/* ---- brand ---- */
	brand = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
	gtk_style_context_add_class (gtk_widget_get_style_context (brand),
	                             "fs-brand");

	tile = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_widget_set_size_request (tile, 40, 40);
	gtk_widget_set_valign (tile, GTK_ALIGN_CENTER);
	gtk_style_context_add_class (gtk_widget_get_style_context (tile),
	                             "fs-brand-tile");
	{
		GdkPixbuf *logo = logo_pixbuf (stockfw_logo_32_png,
		                               stockfw_logo_32_png_len);

		if (logo != NULL) {
			GtkWidget *image = gtk_image_new_from_pixbuf (logo);

			gtk_widget_set_halign (image, GTK_ALIGN_CENTER);
			gtk_widget_set_valign (image, GTK_ALIGN_CENTER);
			gtk_box_pack_start (GTK_BOX (tile), image, TRUE, TRUE, 0);
			g_object_unref (logo);
		}
	}
	gtk_box_pack_start (GTK_BOX (brand), tile, FALSE, FALSE, 0);

	names = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_widget_set_valign (names, GTK_ALIGN_CENTER);
	label = gtk_label_new ("StockFW");
	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             "fs-brand-name");
	gtk_box_pack_start (GTK_BOX (names), label, FALSE, FALSE, 0);
#ifdef FS_VERSION
	label = gtk_label_new (FS_VERSION);
#else
	label = gtk_label_new ("");
#endif
	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             "fs-brand-version");
	gtk_box_pack_start (GTK_BOX (names), label, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (brand), names, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (bar), brand, FALSE, FALSE, 0);

	/* ---- pages ---- */
	for (guint i = 0; i < FS_PAGE_COUNT; i++) {
		GtkWidget *item = nav_button (gtk_toggle_button_new (),
		                              pages[i].icon, _(pages[i].label));

		g_signal_connect (item, "toggled", G_CALLBACK (on_nav_toggled),
		                  GUINT_TO_POINTER (i));
		gtk_box_pack_start (GTK_BOX (bar), item, FALSE, FALSE, 0);
		nav_items[i] = item;
	}

	spacer = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_pack_start (GTK_BOX (bar), spacer, TRUE, TRUE, 0);

	/* ---- Preferences, About ---- */
	{
		GtkWidget *item;

		item = nav_button (gtk_button_new (), FS_ICON_SETTINGS,
		                   _("Preferences"));
		gtk_widget_set_tooltip_text (item, _("Preferences (Ctrl+,)"));
		g_signal_connect (item, "clicked",
		                  G_CALLBACK (on_nav_preferences), NULL);
		gtk_box_pack_start (GTK_BOX (bar), item, FALSE, FALSE, 0);

		item = nav_button (gtk_button_new (), FS_ICON_INFO,
		                   _("About StockFW"));
		g_signal_connect (item, "clicked", G_CALLBACK (on_nav_about),
		                  NULL);
		gtk_box_pack_start (GTK_BOX (bar), item, FALSE, FALSE, 0);
	}

	/* ---- verdict ---- */
	footer = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
	gtk_style_context_add_class (gtk_widget_get_style_context (footer),
	                             "fs-sidebar-footer");

	row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	side_dot = fs_icon_new (FS_ICON_DOT, 8);
	gtk_style_context_add_class (gtk_widget_get_style_context (side_dot),
	                             "fs-side-dot");
	gtk_box_pack_start (GTK_BOX (row), side_dot, FALSE, FALSE, 0);
	side_state = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (side_state), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (side_state),
	                             "fs-side-state");
	gtk_box_pack_start (GTK_BOX (row), side_state, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (footer), row, FALSE, FALSE, 0);

	side_backend = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (side_backend), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (side_backend), TRUE);
	gtk_style_context_add_class (gtk_widget_get_style_context (side_backend),
	                             "fs-side-backend");
	gtk_box_pack_start (GTK_BOX (footer), side_backend, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (bar), footer, FALSE, FALSE, 0);

	return bar;
}

/* [ install_theme ]
 * One stylesheet for the whole application: the light palette from
 * src/ui/fs-theme.css, compiled into the binary (fs-theme-css.h is
 * generated at configure time), so the installed exe needs no data
 * files beside it. */
static void
install_theme (void)
{
	GtkCssProvider *provider = gtk_css_provider_new ();
	GError *error = NULL;

	if (!gtk_css_provider_load_from_data (provider, fs_theme_css,
	                                       -1, &error)) {
		/* A stylesheet that will not parse must not stop the
		 * window from opening; the app then runs in the system
		 * theme and says so on stderr. */
		g_warning ("StockFW theme failed to load: %s",
		           error ? error->message : "unknown error");
		g_clear_error (&error);
		g_object_unref (provider);
		return;
	}

	gtk_style_context_add_provider_for_screen (
		gdk_screen_get_default (),
		GTK_STYLE_PROVIDER (provider),
		GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

	g_object_unref (provider);
}

/* The trust engine asks the platform for Authenticode verdicts
 * through the backend vtable: core stays portable, the UI stays the
 * only place that knows both halves exist. */
static gboolean
app_trust_signature (const gchar *path, FsTrustSignature *sig,
                     gchar **publisher, gpointer user)
{
	const FsBackend *backend = fs_backend ();

	(void) user;
	if (backend->trust_signature == NULL)
		return FALSE;

	return backend->trust_signature (path, sig, publisher);
}

/* [ start_at_launch ]
 * "Start the firewall on program startup", once the policy is really
 * loaded and Sentinel's restore has taken its expired rows out.  The
 * start goes through the start gate, so audit-only mode and the Policy
 * Lock hold it exactly as they hold an apply, and it is audited.  A
 * failure is not fatal: the window still opens and the state line
 * reports what actually happened.
 *
 * `restore_dropped': Sentinel's boot restore took rows out of the
 * policy (blocks whose ten minutes ran out while StockFW was closed).
 * Those blocks are still on the firewall until something pushes; a
 * start that installed the restored policy already did, otherwise
 * they are pushed through the apply gate here -- but on Linux only
 * while the firewall runs, because there an apply IS a start, and a
 * firewall the user left stopped must not start behind their back. */
static void
start_at_launch (gboolean restore_dropped)
{
	const FsBackend *backend = fs_backend ();
	gboolean installed = FALSE;

	if (fs_prefs_get_bool (FS_PREFS_START_ON_GUI, FALSE) &&
	    backend->available ()) {
		GError *error = NULL;
		FsApplyOutcome *outcome;

		outcome = fs_firewall_start_safe (backend, policy,
		                                  "start on program startup",
		                                  fs_policyview_hold_reason (),
		                                  &error);
		installed = outcome->applied && !outcome->held;
		g_clear_error (&error);
		fs_apply_outcome_free (outcome);
	}

	if (restore_dropped && !installed &&
	    (!backend->start_applies_policy ||
	     (backend->get_state != NULL &&
	      backend->get_state () == FS_FW_RUNNING)))
		fs_copilot_autoblocks_push ();
}

void
fs_app_activate (GtkApplication *app)
{
	GtkWidget *box;
	gboolean restore_dropped;

	fsapp.app = GTK_APPLICATION (app);

	fs_trust_set_signature_provider (app_trust_signature, NULL);

	/* Window */
	fsapp.window = gtk_application_window_new (app);
	gtk_window_set_title (GTK_WINDOW (fsapp.window), "StockFW");
	/* Sidebar (220) plus an Overview that shows its connections and
	 * adapters side by side.  1180x780 still fits a 1366x768 laptop
	 * screen once the window manager has had its say. */
	gtk_window_set_default_size (GTK_WINDOW (fsapp.window), 1180, 780);

	/* Window icon from the embedded logo, in several sizes. */
	{
		GList *icons = logo_icon_list ();

		if (icons != NULL)
			gtk_window_set_icon_list (GTK_WINDOW (fsapp.window), icons);
		g_list_free_full (icons, g_object_unref);
	}

	g_signal_connect (fsapp.window, "delete-event",
	                   G_CALLBACK (on_delete_event), NULL);
	g_signal_connect (fsapp.window, "window-state-event",
	                   G_CALLBACK (on_window_state_event), NULL);

	/* Theme first: everything built below picks up the classes. */
	install_theme ();

	box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_container_add (GTK_CONTAINER (fsapp.window), box);

	register_actions ();

	/* The default icon for ALL windows (main, dialogs, about). */
	{
		GList *icons = logo_icon_list ();

		if (icons != NULL)
			gtk_window_set_default_icon_list (icons);
		g_list_free_full (icons, g_object_unref);
	}

	gtk_box_pack_start (GTK_BOX (box), build_sidebar (), FALSE, FALSE, 0);

	/* The pages, in sidebar order (FsAppPage). */
	fsapp.notebook = gtk_notebook_new ();
	gtk_notebook_set_show_tabs (GTK_NOTEBOOK (fsapp.notebook), FALSE);
	gtk_notebook_set_show_border (GTK_NOTEBOOK (fsapp.notebook), FALSE);
	gtk_widget_set_hexpand (fsapp.notebook, TRUE);
	gtk_widget_set_vexpand (fsapp.notebook, TRUE);
	gtk_box_pack_start (GTK_BOX (box), fsapp.notebook, TRUE, TRUE, 0);

	g_signal_connect (fsapp.notebook, "switch-page",
	                  G_CALLBACK (on_page_switched), NULL);

	add_page (_("Overview"), NULL, fs_statusview_page (), FALSE);
	add_page (_("Events"),
	          _("Connections your rules allowed or blocked, as they "
	            "happen."),
	          fs_hitview_page (), FALSE);

	/* Activity (1.0.6): the graphs, beside the list they count. */
	add_page (_("Activity"),
	          _("Allowed and blocked events, and adapter traffic, over "
	            "time."),
	          fs_activityview_page (), TRUE);

	policy = fs_policy_new ();

	/* The Events page was built above (before there was a policy to
	 * give it); its right-click Event -> Rule actions need the
	 * pointer now that it exists.  The Overview counts its rules. */
	fs_hitview_set_policy (policy);
	fs_statusview_set_policy (policy);

	settings = fs_settings_new ();
	fs_settings_load_prefs (settings);
	fs_backend_set_context (policy, settings);

	/* No start here: the policy above is still EMPTY.  The Policy page
	 * below loads it from disk, Sentinel's restore then reconciles its
	 * own rows, and only then does start_at_launch() run.  Starting
	 * here installed a zero-rule policy on Linux (1.0.7 fix). */
	add_page (_("Policy"),
	          _("The rules StockFW enforces, and which addresses each "
	            "one covers."),
	          fs_policyview_page (policy), FALSE);

	/* Smart Firewall Copilot tab */
	copilot = fs_copilot_new ();

	/* Resume the historical behavior baseline (P2): yesterday's
	 * learned ports, destinations, hours and rates are loaded before
	 * the first event arrives, so a restart does not call every old
	 * port new.  A missing file is a fresh start, not an error. */
	{
		gchar *baseline = fs_copilot_baseline_path ();
		GError *baseline_err = NULL;

		if (!fs_copilot_baseline_load (copilot, baseline,
		                               &baseline_err))
			g_clear_error (&baseline_err);
		g_free (baseline);
	}

	add_page (_("Copilot"),
	          _("Learns each program's usual traffic, flags what is "
	            "unusual, and tries rule changes before you make them."),
	          fs_copilot_page (copilot, policy), TRUE);

	/* P6 (false-outage hardening): the Sentinel staged-block list is
	 * persisted, so a restart must reconcile it -- rows whose ten
	 * minutes ran out while StockFW was not running come out of the
	 * policy BEFORE the start below can install them, the rest are
	 * re-armed with their original clock, and a Sentinel mode that is
	 * not "auto" lifts the lot.  The page above owns the shared policy
	 * and the mode cache this reads; start_at_launch() takes what came
	 * out to the firewall. */
	restore_dropped = fs_copilot_autoblocks_restore (policy);

	/* Trust tab: the application trust engine's surface. */
	add_page (_("Trust"),
	          _("Who published a program, whether it is signed, and "
	            "whether it has changed since you attested it."),
	          fs_trustview_page (), FALSE);

	/* Policy loaded, Sentinel reconciled: now the firewall may start. */
	start_at_launch (restore_dropped);

	gtk_widget_show_all (fsapp.window);
	sync_nav ((guint) gtk_notebook_get_current_page (
		GTK_NOTEBOOK (fsapp.notebook)));

	/* The sidebar's verdict follows the Overview's. */
	fs_statusview_set_changed_cb (sync_sidebar_state, NULL);

	/* Reflect the real firewall state, if the backend knows it. */
	fs_statusview_set_state (fs_backend ()->get_state ());

	/* Tray last: the icon reuses the window logo set above, and the
	 * state call just now already fed the tooltip text. */
	fs_tray_set_window (GTK_WINDOW (fsapp.window));
	fs_tray_sync ();
}

void
fs_app_reload_settings (void)
{
	if (settings == NULL)
		return;

	fs_settings_load_prefs (settings);
	fs_backend_set_context (policy, settings);

	/* The Preferences dialog may have toggled the tray switches. */
	fs_tray_sync ();
}

void
fs_app_quit (void)
{
	/* Icon down first: a tray icon that outlives the program is a
	 * dead icon that still looks clickable. */
	fs_tray_uninstall ();

	fs_prefs_save ();

	if (policy != NULL) {
		fs_policy_free (policy);
		policy = NULL;
	}

	if (settings != NULL) {
		fs_settings_free (settings);
		settings = NULL;
	}

	if (copilot != NULL) {
		/* Best effort: an unsaved baseline only costs relearning,
		 * never a wrong rule or a lost audit line. */
		gchar *baseline = fs_copilot_baseline_path ();

		fs_copilot_baseline_save (copilot, baseline, NULL);
		g_free (baseline);

		fs_copilot_free (copilot);
		copilot = NULL;
	}

	if (fsapp.app != NULL)
		g_application_quit (G_APPLICATION (fsapp.app));
}