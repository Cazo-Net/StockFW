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
#include "core/fs-util.h"
#include "core/fs-i18n.h"
#include "stockfw-logo-32.h"
#include "stockfw-logo-64.h"
#include "stockfw-logo-128.h"
#include "fs-theme-css.h"        /* generated from src/ui/fs-theme.css */

#include <gdk-pixbuf/gdk-pixbuf.h>

#ifdef G_OS_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>             /* MSG, WM_QUERYENDSESSION */
#endif

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

FsAppPage
fs_app_current_page (void)
{
	gint page;

	if (fsapp.notebook == NULL)
		return FS_PAGE_COUNT;
	page = gtk_notebook_get_current_page (GTK_NOTEBOOK (fsapp.notebook));
	return page >= 0 && page < FS_PAGE_COUNT ? (FsAppPage) page
	                                         : FS_PAGE_COUNT;
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

/* [ fs_app_can_change_firewall ] -- see fs-app.h. */
gboolean
fs_app_can_change_firewall (void)
{
	const FsBackend *backend = fs_backend ();

	if (backend->available == NULL || !backend->available ())
		return FALSE;
#ifdef G_OS_WIN32
	/* The Windows backend reads the firewall without elevation, so
	 * "available" is not "may change it": that takes an elevated
	 * token.  On Linux available() already means root. */
	return fs_util_privileged ();
#else
	return TRUE;
#endif
}

/* [ start_at_launch ]
 * "Start the firewall on program startup", once the policy is really
 * loaded and Sentinel's restore has taken its expired rows out.  The
 * start goes through the start gate, so audit-only mode and the Policy
 * Lock hold it exactly as they hold an apply, it is audited, and on
 * Linux it installs the last APPLIED policy (the journal), never
 * changes in the file that nobody applied.  A failure is not fatal:
 * the window still opens and the state line reports what actually
 * happened.
 *
 * `due': the Sentinel blocks whose ten minutes ran out while StockFW
 * was closed.  The firewall may still hold them.  A start leaves them
 * out of what it installs; otherwise only THEIR removal is pushed
 * (fs_firewall_lift_live: the journal less those rules) -- and only
 * by a copy that may change the firewall, and on Linux only while the
 * firewall runs, because there an apply IS a start, and a firewall the
 * user left stopped must not start behind their back.  The policy
 * file is never what gets pushed here: it may hold an allow nobody
 * applied. */
static void
start_at_launch (const FsPolicy *due)
{
	const FsBackend *backend = fs_backend ();
	gboolean installed = FALSE, any_due = FALSE;

	for (gint k = 0; due != NULL && k < FS_RULE_N_KINDS; k++)
		if (due->kinds[k]->len > 0)
			any_due = TRUE;

	if (fs_prefs_bool (FS_PREFS_START_ON_GUI) &&
	    fs_app_can_change_firewall ()) {
		GError *error = NULL;
		FsApplyOutcome *outcome;

		outcome = fs_firewall_start_lifting (backend, policy, due,
		                                     "start on program startup",
		                                     fs_policyview_hold_reason (),
		                                     &error);
		installed = outcome->applied;
		g_clear_error (&error);
		fs_apply_outcome_free (outcome);
	}

	if (any_due && !installed && fs_app_can_change_firewall () &&
	    (!backend->start_applies_policy ||
	     (backend->get_state != NULL &&
	      backend->get_state () == FS_FW_RUNNING))) {
		GError *error = NULL;
		FsApplyOutcome *outcome;

		outcome = fs_firewall_lift_live (backend, due,
		                                 "sentinel auto-block expired",
		                                 fs_policyview_hold_reason (),
		                                 &error);
		if (outcome != NULL)
			fs_apply_outcome_free (outcome);
		g_clear_error (&error);
	}
}

/* --------------------------------------------------------- hidden start
 *
 * --background: the window stays hidden behind the tray icon -- but
 * only once the shell has really embedded that icon.  Embedding is
 * asynchronous (X11 docks it when the tray answers; Windows when
 * Explorer's notification area is up), so the window waits up to
 * HIDDEN_START_WAIT_S for it and is shown if it never comes: a hidden
 * window with no icon would leave a running firewall front-end nobody
 * can reach. */

#define HIDDEN_START_WAIT_S 5

static gboolean start_hidden = FALSE;
static guint    hidden_timeout = 0;
static gulong   hidden_embed_handler = 0;

static void
hidden_start_end (void)
{
	GtkStatusIcon *icon = fs_tray_icon ();

	if (hidden_timeout != 0) {
		g_source_remove (hidden_timeout);
		hidden_timeout = 0;
	}
	if (hidden_embed_handler != 0) {
		if (icon != NULL)
			g_signal_handler_disconnect (icon,
			                             hidden_embed_handler);
		hidden_embed_handler = 0;
	}
}

/* [ hidden_start_give_up ] -- no icon in time: show the window. */
static gboolean
hidden_start_give_up (gpointer data)
{
	(void) data;

	hidden_timeout = 0;
	hidden_start_end ();

	if (!fs_tray_active ()) {
		g_message ("StockFW: no notification area took the icon "
		           "within %d s; showing the window instead of "
		           "staying hidden", HIDDEN_START_WAIT_S);
		gtk_widget_show (fsapp.window);
	}
	return G_SOURCE_REMOVE;
}

static void
on_hidden_icon_embedded (GObject *icon, GParamSpec *pspec, gpointer data)
{
	(void) icon;
	(void) pspec;
	(void) data;

	/* Docked: the window may stay hidden; nothing more to wait for. */
	if (fs_tray_active ())
		hidden_start_end ();
}

static void
hidden_start_begin (void)
{
	GtkStatusIcon *icon = fs_tray_icon ();

	if (icon == NULL) {
		/* "Show a tray icon" is off: nothing to hide behind. */
		gtk_widget_show (fsapp.window);
		return;
	}
	if (fs_tray_active ())
		return;

	hidden_embed_handler = g_signal_connect (
		icon, "notify::embedded",
		G_CALLBACK (on_hidden_icon_embedded), NULL);
	hidden_timeout = g_timeout_add_seconds (HIDDEN_START_WAIT_S,
	                                        hidden_start_give_up, NULL);
}

/*---[ session safety (1.0.7) ]-----------------------------------------
 * A copy that lives in the notification area for weeks is ended by a
 * sign-out, a shutdown or a kill far more often than by its Quit item,
 * and what the user set and what the Copilot learned must not depend
 * on that item.  So:
 *
 *   - every AUTOSAVE_S the settings and the Copilot baseline are
 *     written if they changed since the last write, and a Sentinel
 *     staged-list write that failed is retried (that list is otherwise
 *     written on every stage and retire);
 *   - the session manager's query-end (register-session, main.c) and
 *     Windows' WM_QUERYENDSESSION write everything at once.  Neither
 *     asks to delay the sign-out: there is nothing here worth holding
 *     a user's logout for, and the firewall runs without us;
 *   - SIGTERM, SIGINT and SIGHUP quit through fs_app_quit() (main.c).
 *
 * None of this touches the firewall: it stays as it is.
 * STOCKFW_AUTOSAVE_S shortens the period for the tests. */

#define AUTOSAVE_S 300

static guint    autosave_id = 0;
static gboolean baseline_dirty = FALSE;
static gboolean quit_started = FALSE;
#ifdef G_OS_WIN32
static gboolean session_ending = FALSE;
#endif

void
fs_app_note_learning (void)
{
	baseline_dirty = TRUE;
}

/* [ save_state ] -- `everything' writes the settings and the baseline
 * whether or not they changed (quit, end of session); otherwise only
 * what changed since the last write.  Best effort throughout: each
 * writer reports its own failure, and a baseline that could not be
 * written stays dirty for the next round. */
static void
save_state (gboolean everything)
{
	if (everything || fs_prefs_dirty ())
		fs_prefs_save ();

	if (copilot != NULL && (everything || baseline_dirty)) {
		gchar *path = fs_copilot_baseline_path ();

		if (fs_copilot_baseline_save (copilot, path, NULL))
			baseline_dirty = FALSE;
		g_free (path);
	}

	fs_copilot_autoblocks_flush ();
}

static guint
autosave_period (void)
{
	const gchar *env = g_getenv ("STOCKFW_AUTOSAVE_S");

	if (env != NULL && *env != '\0') {
		gchar *end = NULL;
		guint64 s = g_ascii_strtoull (env, &end, 10);

		if (end != NULL && *end == '\0' && s >= 1 && s <= 86400)
			return (guint) s;
	}
	return AUTOSAVE_S;
}

static gboolean
on_autosave (gpointer data)
{
	(void) data;

	save_state (FALSE);
	return G_SOURCE_CONTINUE;
}

/* [ on_query_end ] -- the session manager is about to end the session.
 * No gtk_application_inhibit(): see the block comment above. */
static void
on_query_end (GtkApplication *app, gpointer data)
{
	(void) app;
	(void) data;

	save_state (TRUE);
}

/* [ free_state ] -- the policy, the settings and the Copilot.  Only
 * once the run loop has ended (on_shutdown): the Overview's refresh,
 * Sentinel's expiry and the backend all hold the same pointers, and a
 * source that came due in the same loop pass as the quit is still
 * dispatched after it -- freeing in the quit handed those freed
 * memory. */
static void
free_state (void)
{
	if (policy != NULL) {
		fs_policy_free (policy);
		policy = NULL;
	}

	if (settings != NULL) {
		fs_settings_free (settings);
		settings = NULL;
	}

	if (copilot != NULL) {
		fs_copilot_free (copilot);
		copilot = NULL;
	}
}

/* [ on_shutdown ] -- the run loop has ended, by fs_app_quit() or by
 * the session manager's Stop, which quits the application directly
 * (then write what changed since query-end).  Nothing runs after
 * this: now the shared state may go. */
static void
on_shutdown (GApplication *app, gpointer data)
{
	(void) app;
	(void) data;

	if (!quit_started)
		save_state (FALSE);

	free_state ();
}

#ifdef G_OS_WIN32
/* [ on_win32_message ] -- every message to a StockFW window passes
 * here first.  Windows sends WM_QUERYENDSESSION to each top-level
 * window before a sign-out or shutdown and WM_ENDSESSION after, and
 * kills the process soon after that.  CONTINUE always: the default
 * answer lets the session end. */
static GdkFilterReturn
on_win32_message (GdkXEvent *xevent, GdkEvent *event, gpointer data)
{
	const MSG *msg = (const MSG *) xevent;

	(void) event;
	(void) data;

	if (msg->message == WM_QUERYENDSESSION) {
		/* Once per sign-out, not once per window. */
		if (!session_ending) {
			session_ending = TRUE;
			save_state (TRUE);
		}
	} else if (msg->message == WM_ENDSESSION) {
		if (msg->wParam)
			save_state (FALSE);
		else
			session_ending = FALSE;    /* someone cancelled it */
	}
	return GDK_FILTER_CONTINUE;
}
#endif

static void
session_safety_begin (GtkApplication *app)
{
	autosave_id = g_timeout_add_seconds (autosave_period (),
	                                     on_autosave, NULL);
	g_signal_connect (app, "query-end", G_CALLBACK (on_query_end), NULL);
	g_signal_connect (app, "shutdown", G_CALLBACK (on_shutdown), NULL);

#ifdef G_OS_WIN32
	/* WM_QUERYENDSESSION only reaches windows that exist; a hidden
	 * start never shows (so never creates) the main one.  Realized,
	 * it exists without being shown. */
	gtk_widget_realize (fsapp.window);
	gdk_window_add_filter (NULL, on_win32_message, NULL);
#endif
}

void
fs_app_activate (GtkApplication *app)
{
	GtkWidget *box;
	FsPolicy *due;

	/* Everything below builds static state once: a second activate
	 * would start a second monitor, a second Sentinel and a second
	 * tray icon.  It only means "show me". */
	if (fsapp.window != NULL) {
		fs_app_present ();
		return;
	}

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
	due = fs_policy_new ();
	fs_copilot_autoblocks_restore (policy, due);

	/* Trust tab: the application trust engine's surface. */
	add_page (_("Trust"),
	          _("Who published a program, whether it is signed, and "
	            "whether it has changed since you attested it."),
	          fs_trustview_page (), FALSE);

	/* Policy loaded, Sentinel reconciled: now the firewall may start. */
	start_at_launch (due);
	fs_policy_free (due);

	/* Everything inside the window is shown now; the window itself
	 * only below, once it is known whether it may stay hidden. */
	gtk_widget_show_all (box);
	sync_nav ((guint) gtk_notebook_get_current_page (
		GTK_NOTEBOOK (fsapp.notebook)));

	/* The sidebar's verdict follows the Overview's. */
	fs_statusview_set_changed_cb (sync_sidebar_state, NULL);

	/* Reflect the real firewall state, if the backend knows it. */
	fs_statusview_set_state (fs_backend ()->get_state ());

	/* The tray before the window: a hidden start needs the icon up
	 * first, to come back from.  It reuses the window logo set above,
	 * and the state call just now already fed the tooltip text. */
	fs_tray_set_window (GTK_WINDOW (fsapp.window));
	fs_tray_sync ();

	/* Everything that is saved now exists: save it as it changes. */
	session_safety_begin (app);

	if (start_hidden)
		hidden_start_begin ();
	else
		gtk_widget_show (fsapp.window);
}

void
fs_app_set_start_hidden (gboolean hidden)
{
	start_hidden = hidden;
}

void
fs_app_present (void)
{
	/* Asked for before the window exists: open it visible. */
	if (fsapp.window == NULL) {
		start_hidden = FALSE;
		return;
	}

	hidden_start_end ();
	fs_tray_show_window ();
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

/* [ settings_swap ]
 * The apply gate's hook for a settings rollback: the previous settings
 * into the backend's context for the restore, the saved ones back
 * afterwards. */
static void
settings_swap (gboolean previous, gpointer data)
{
	fs_backend_set_context (policy, previous ? (FsSettings *) data
	                                         : settings);
}

FsPolicy *
fs_app_policy (void)
{
	return policy;
}

FsApplyOutcome *
fs_app_apply_settings (FsPolicy *under, const FsSettings *previous,
                       const gchar *hold, GError **error)
{
	FsSettings *before;
	FsApplyOutcome *outcome;

	/* No window, no loaded policy: nothing to apply them with, and an
	 * empty policy is never pushed in its place. */
	if (under == NULL || policy == NULL || settings == NULL)
		return NULL;

	before = previous != NULL ? fs_settings_copy (previous)
	                          : fs_settings_new ();
	outcome = fs_settings_apply_safe (fs_backend (), under,
	                                  "preferences", hold,
	                                  settings_swap, before, error);
	fs_settings_free (before);

	return outcome;
}

#ifdef FS_PREFS_FAKE_BACKEND
void
fs_app_test_set_context (FsPolicy *test_policy, FsSettings *test_settings)
{
	policy = test_policy;
	settings = test_settings;
}
#endif

/* [ cancel_dialogs ] -- answer every open dialog as its close button
 * would (GTK_RESPONSE_DELETE_EVENT), which ends a gtk_dialog_run()
 * loop on its caller's "closed, change nothing" path.  The Preferences
 * window is no GtkDialog but runs a loop of its own: it is cancelled
 * the same way (nothing saved), or the quit would wait for it. */
static void
cancel_dialogs (void)
{
	GList *tops = gtk_window_list_toplevels ();
	GList *l;

	fs_dialogs_preferences_cancel ();

	/* A response handler may destroy other windows in the list. */
	for (l = tops; l != NULL; l = l->next)
		g_object_ref (l->data);
	for (l = tops; l != NULL; l = l->next) {
		if (GTK_IS_DIALOG (l->data) &&
		    gtk_widget_get_visible (GTK_WIDGET (l->data)))
			gtk_dialog_response (GTK_DIALOG (l->data),
			                     GTK_RESPONSE_DELETE_EVENT);
	}
	g_list_free_full (tops, g_object_unref);
}

static void quit_finish (void);

static gboolean
quit_when_unwound (gpointer data)
{
	(void) data;

	if (g_main_depth () > 1)
		return G_SOURCE_CONTINUE;

	quit_finish ();
	return G_SOURCE_REMOVE;
}

/* [ fs_app_quit ]
 * The tray's Quit, the window's close button without a tray, --quit
 * from another launch, and SIGTERM/SIGINT/SIGHUP all end here.  The
 * firewall is left as it is.
 *
 * A quit can arrive while a dialog runs its own loop: a signal or
 * --quit is dispatched by whatever loop is running.  In that case the
 * state is saved and the icon taken down at once, the dialogs are
 * closed, and the rest waits for the outer loop.  Nothing is freed
 * before the run loop has ended (on_shutdown): a dialog's caller, or
 * a timer due in the same loop pass, still finds everything in
 * place. */
void
fs_app_quit (void)
{
	if (quit_started)
		return;
	quit_started = TRUE;

	if (autosave_id != 0) {
		g_source_remove (autosave_id);
		autosave_id = 0;
	}

	/* Icon down first: a tray icon that outlives the program is a
	 * dead icon that still looks clickable. */
	fs_tray_uninstall ();

	/* Settings, the Copilot baseline (best effort: an unsaved
	 * baseline only costs relearning, never a wrong rule or a lost
	 * audit line) and a staged list still owed to its file. */
	save_state (TRUE);

	if (g_main_depth () > 1) {
		cancel_dialogs ();
		g_timeout_add (100, quit_when_unwound, NULL);
		return;
	}

	quit_finish ();
}

static void
quit_finish (void)
{
	GApplication *app = fsapp.app != NULL ? G_APPLICATION (fsapp.app)
	                                      : g_application_get_default ();

	/* Whatever changed while the dialogs closed. */
	save_state (FALSE);

	/* Nothing is freed here: sources already due in this loop pass
	 * still run after us.  on_shutdown() frees once the loop is over.
	 * Through the default application too: a signal can come before
	 * activate has recorded ours. */
	if (app != NULL)
		g_application_quit (app);
}