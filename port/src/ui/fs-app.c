/*---[ fs-app.c ]-------------------------------------------------------
 * Application object and main window.
 *
 * Replaces gnome_app_new()/gnome_app_set_contents()/gnome_app_set_menus()
 * and the gnome_program_init()/gnome_master_client() startup dance in
 * the original stockfw.c with a plain GtkApplication.
 *
 * Layout (1.0.7 redesign): a dark sidebar on the left -- the logo on a
 * light tile, one item per page, Preferences, Help and About, and the
 * firewall's verdict at the bottom -- and the selected page on the
 * right.  The pages live in a GtkNotebook whose own tabs are hidden;
 * the sidebar items stand in for them.  There is no menubar: its
 * entries (Preferences, Help, About, Quit) are the sidebar's footer
 * items and the Ctrl+, / F1 / Ctrl+Q shortcuts.  F1 opens the Help
 * topic for the page shown.
 *--------------------------------------------------------------------*/

#include "ui/fs-app.h"
#include "ui/fs-dialogs.h"
#include "ui/fs-helpwindow.h"
#include "ui/fs-statusview.h"
#include "ui/fs-policyview.h"
#include "ui/fs-hitview.h"
#include "ui/fs-activityview.h"
#include "ui/fs-topology.h"
#include "ui/fs-copilot.h"
#include "ui/fs-trustview.h"
#include "ui/fs-intelview.h"
#include "ui/fs-nexora.h"
#include "ui/fs-tray.h"
#include "ui/fs-icons.h"
#include "ui/fs-drawer.h"
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
#include "ui/fs-theme-light.h"   /* the light values of its colours */
#include "ui/fs-theme-accent.h"  /* the accents, the comfortable rows */

#include <gdk-pixbuf/gdk-pixbuf.h>
#include <gdk/gdkkeysyms.h>
#include <string.h>

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

/* The sidebar folds to a rail of icons (Ctrl+B) and remembers it.  The
 * key is not in the settings table: like the Events columns' keys it
 * is how the window was left, not a setting Preferences offers. */
#define FS_SIDEBAR_COLLAPSED_KEY "/apps/stockfw/client/ui/sidebar_collapsed"
#define FS_SIDEBAR_WIDTH 232
#define FS_SIDEBAR_RAIL_WIDTH 52

static gboolean   side_collapsed = FALSE;
static GtkWidget *side_bar = NULL;
static GtkWidget *side_brand = NULL;
static GtkWidget *side_toggle = NULL;
static GtkWidget *side_search = NULL;
static GtkWidget *side_search_row = NULL;
static GtkWidget *side_footer = NULL;
static GtkWidget *side_footer_row = NULL;
/* What the rail hides (names, shortcut hints, group headings), what
 * only the rail shows (the rules that stand in for the headings), and
 * the items, whose tooltips name them once their labels are gone.
 * None of the arrays owns its widgets; the sidebar does. */
static GPtrArray *side_texts = NULL;
static GPtrArray *side_rules = NULL;
static GPtrArray *side_items = NULL;

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

/* [ show_help ]
 * The Help window, at the topic for the page shown. */
static void
show_help (void)
{
	gint page = fsapp.notebook != NULL
	          ? gtk_notebook_get_current_page (GTK_NOTEBOOK (fsapp.notebook))
	          : -1;

	fs_help_show (fsapp.window, fs_help_topic_for_page (page));
}

/* [ on_action_help ]
 * "app.help" (F1) */
static void
on_action_help (GSimpleAction *action, GVariant *parameter, gpointer data)
{
	(void) action;
	(void) parameter;
	(void) data;
	show_help ();
}

static void palette_toggle (void);
static void sidebar_toggle (void);
static void on_action_page (GSimpleAction *action, GVariant *parameter,
                            gpointer data);

static void
on_action_palette (GSimpleAction *action, GVariant *parameter, gpointer data)
{
	(void) action;
	(void) parameter;
	(void) data;
	palette_toggle ();
}

/* [ on_action_sidebar ]
 * "app.sidebar" (Ctrl+B) */
static void
on_action_sidebar (GSimpleAction *action, GVariant *parameter, gpointer data)
{
	(void) action;
	(void) parameter;
	(void) data;
	sidebar_toggle ();
}

/* [ register_actions ] */
static void
register_actions (void)
{
	GSimpleAction *quit, *about, *preferences, *help, *palette, *sidebar;

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

	help = g_simple_action_new ("help", NULL);
	g_signal_connect (help, "activate", G_CALLBACK (on_action_help), NULL);
	g_action_map_add_action (G_ACTION_MAP (fsapp.app), G_ACTION (help));
	g_object_unref (help);

	palette = g_simple_action_new ("palette", NULL);
	g_signal_connect (palette, "activate", G_CALLBACK (on_action_palette), NULL);
	g_action_map_add_action (G_ACTION_MAP (fsapp.app), G_ACTION (palette));
	g_object_unref (palette);

	sidebar = g_simple_action_new ("sidebar", NULL);
	g_signal_connect (sidebar, "activate", G_CALLBACK (on_action_sidebar), NULL);
	g_action_map_add_action (G_ACTION_MAP (fsapp.app), G_ACTION (sidebar));
	g_object_unref (sidebar);

	/* Ctrl+1 .. Ctrl+9: the sidebar's items, top to bottom. */
	for (guint i = 0; i < FS_PAGE_COUNT && i < 9; i++) {
		gchar *name = g_strdup_printf ("page%u", i + 1);
		gchar *detailed = g_strdup_printf ("app.page%u", i + 1);
		gchar *accel = g_strdup_printf ("<Primary>%u", i + 1);
		const gchar *keys[] = { accel, NULL };
		GSimpleAction *go = g_simple_action_new (name, NULL);

		g_signal_connect (go, "activate", G_CALLBACK (on_action_page),
		                  GUINT_TO_POINTER (i));
		g_action_map_add_action (G_ACTION_MAP (fsapp.app), G_ACTION (go));
		gtk_application_set_accels_for_action (fsapp.app, detailed, keys);
		g_object_unref (go);
		g_free (accel);
		g_free (detailed);
		g_free (name);
	}

	/* The menubar these used to live in is gone; the shortcuts stay. */
	{
		const gchar *palette_keys[] = { "<Primary>k",
		                                "<Primary><Shift>p", NULL };
		const gchar *quit_keys[] = { "<Primary>q", NULL };
		const gchar *sidebar_keys[] = { "<Primary>b", NULL };

		gtk_application_set_accels_for_action (fsapp.app, "app.palette",
		                                       palette_keys);
		gtk_application_set_accels_for_action (fsapp.app, "app.sidebar",
		                                       sidebar_keys);
		const gchar *pref_keys[] = { "<Primary>comma", NULL };
		const gchar *help_keys[] = { "F1", NULL };

		gtk_application_set_accels_for_action (fsapp.app, "app.quit",
		                                       quit_keys);
		gtk_application_set_accels_for_action (fsapp.app,
		                                       "app.preferences",
		                                       pref_keys);
		gtk_application_set_accels_for_action (fsapp.app, "app.help",
		                                       help_keys);
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

/* [ on_page_switched ] -- keep the sidebar in step with the notebook.
 * The detail drawer shows something the page left behind had selected,
 * so it goes with that page. */
static void
on_page_switched (GtkNotebook *notebook, GtkWidget *page, guint page_num,
                  gpointer data)
{
	(void) notebook;
	(void) page;
	(void) data;

	sync_nav (page_num);
	fs_drawer_close ();
}

/* [ on_window_key_after ]
 * Escape closes the detail drawer.  Connected AFTER the window's own
 * handler, so this only sees an Escape that nothing used: the command
 * palette's entry, a search field, a cell being edited and the focused
 * Activity graph all keep theirs. */
static gboolean
on_window_key_after (GtkWidget *widget, GdkEventKey *event, gpointer data)
{
	(void) widget;
	(void) data;

	if (event->keyval != GDK_KEY_Escape ||
	    (event->state & gtk_accelerator_get_default_mod_mask ()) != 0 ||
	    !fs_drawer_is_open ())
		return FALSE;

	fs_drawer_close ();
	return TRUE;
}

/* [ on_window_focus_moved ]
 * The open drawer lies over the right-hand edge of the page, and what
 * is under it can still be reached with Tab.  When the keyboard goes
 * to a control of the page that is wholly under the drawer, the drawer
 * closes, so the control that has the keyboard can be seen.  (The
 * mouse cannot get there: the drawer takes it over its own rectangle.)
 *
 * Left alone: the drawer's own buttons; the sidebar; a list or a
 * diagram that only runs under the drawer with its right-hand part;
 * and anything while the drawer is still sliding in, when it is the
 * control that opened the drawer taking the keyboard.  A control
 * that already has the keyboard when the drawer opens over it is not
 * a move, and is left alone too.  Connected AFTER the window's own
 * handler, so the keyboard is already where it is going and the
 * close has nothing to give back. */
static void
on_window_focus_moved (GtkWindow *window, GtkWidget *focus, gpointer data)
{
	GtkWidget *drawer, *pages, *panel;
	gint x = 0, y = 0, width = 0;

	(void) data;

	if (focus == NULL || fsapp.notebook == NULL || !fs_drawer_is_open ())
		return;

	drawer = fs_drawer_widget ();
	pages = gtk_widget_get_parent (drawer);
	panel = gtk_bin_get_child (GTK_BIN (drawer));
	if (pages == NULL || panel == NULL ||
	    gtk_widget_get_toplevel (drawer) != GTK_WIDGET (window) ||
	    !gtk_widget_get_mapped (drawer) ||
	    !gtk_revealer_get_child_revealed (GTK_REVEALER (drawer)) ||
	    !gtk_widget_is_ancestor (focus, fsapp.notebook))
		return;

	/* The drawer is as tall as the pages and ends at their right edge,
	 * so a control that starts at or past the drawer's left edge is
	 * all under it.  Where that edge is comes from the width the
	 * drawer's panel asks for, not from where the drawer was last
	 * laid out: one shown a moment ago has not been laid out again. */
	gtk_widget_get_preferred_width (panel, &width, NULL);
	if (gtk_widget_translate_coordinates (focus, pages, 0, 0, &x, &y) &&
	    x >= gtk_widget_get_allocated_width (pages) - width)
		fs_drawer_close ();
}

/* [ side_text ] -- a label the rail hides. */
static GtkWidget *
side_text (GtkWidget *label)
{
	if (side_texts == NULL)
		side_texts = g_ptr_array_new ();
	g_ptr_array_add (side_texts, label);
	return label;
}

/* [ nav_button ]
 * One sidebar item: a drawn icon, a label and (optionally) its
 * shortcut in quiet monospace at the end of the row, in a flat button.
 * The icon is drawn in the button's CSS colour, so hover and selection
 * recolour it along with the text.
 *
 * In the rail only the icon is left, so the item also carries what the
 * rail needs to stay usable: its name for a screen reader, set here
 * instead of read off a label that may be hidden, and a tooltip with
 * the name and the shortcut ("fs-rail-tip"). */
static GtkWidget *
nav_button (GtkWidget *button, FsIconKind icon, const gchar *text,
            const gchar *keys)
{
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	GtkWidget *label = gtk_label_new (text);
	AtkObject *atk = gtk_widget_get_accessible (button);

	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
	gtk_box_pack_start (GTK_BOX (row), fs_icon_new (icon, 16),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (row), side_text (label), TRUE, TRUE, 0);
	if (keys != NULL) {
		GtkWidget *hint = gtk_label_new (keys);

		gtk_style_context_add_class (
			gtk_widget_get_style_context (hint), "fs-kbd");
		gtk_box_pack_end (GTK_BOX (row), side_text (hint),
		                  FALSE, FALSE, 0);
	}
	gtk_container_add (GTK_CONTAINER (button), row);

	gtk_button_set_relief (GTK_BUTTON (button), GTK_RELIEF_NONE);
	gtk_widget_set_can_focus (button, TRUE);
	gtk_style_context_add_class (gtk_widget_get_style_context (button),
	                             "nav-item");

	if (atk != NULL)
		atk_object_set_name (atk, text);
	g_object_set_data (G_OBJECT (button), "fs-nav-row", row);
	g_object_set_data_full (G_OBJECT (button), "fs-rail-tip",
	                        keys != NULL
	                        ? g_strdup_printf ("%s (%s)", text, keys)
	                        : g_strdup (text),
	                        g_free);
	if (side_items == NULL)
		side_items = g_ptr_array_new ();
	g_ptr_array_add (side_items, button);
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
on_nav_help (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;
	show_help ();
}

static void
on_nav_about (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;
	fs_dialogs_about (fsapp.window);
}

/* [ sync_footer_tip ]
 * In the rail the footer is the dot alone, so its tooltip says what the
 * two hidden lines say: the verdict, and who enforces it. */
static void
sync_footer_tip (void)
{
	const gchar *state, *backend_name;
	gchar *tip = NULL;

	if (side_footer == NULL || side_state == NULL)
		return;

	state = gtk_label_get_text (GTK_LABEL (side_state));
	backend_name = gtk_label_get_text (GTK_LABEL (side_backend));
	if (side_collapsed && *state != '\0')
		tip = *backend_name != '\0'
		    ? g_strdup_printf ("%s\n%s", state, backend_name)
		    : g_strdup (state);
	gtk_widget_set_tooltip_text (side_footer, tip);
	g_free (tip);
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

	sync_footer_tip ();
}

/* [ sidebar_apply ]
 * Lay the sidebar out as side_collapsed says: the full list, or a rail
 * of icons.  The rail is the same widgets with their text hidden, not
 * a second sidebar, so the selected page, the verdict dot and the
 * keyboard focus carry over; an item's geometry is the same in both
 * (tests/ui-theme-smoke.c measures it), only its row is centred. */
static void
sidebar_apply (void)
{
	GtkStyleContext *ctx;
	AtkObject *atk;

	if (side_bar == NULL)
		return;

	ctx = gtk_widget_get_style_context (side_bar);
	if (side_collapsed)
		gtk_style_context_add_class (ctx, "rail");
	else
		gtk_style_context_remove_class (ctx, "rail");
	gtk_widget_set_size_request (side_bar,
	                             side_collapsed ? FS_SIDEBAR_RAIL_WIDTH
	                                            : FS_SIDEBAR_WIDTH, -1);

	for (guint i = 0; side_texts != NULL && i < side_texts->len; i++)
		gtk_widget_set_visible (g_ptr_array_index (side_texts, i),
		                        !side_collapsed);
	for (guint i = 0; side_rules != NULL && i < side_rules->len; i++)
		gtk_widget_set_visible (g_ptr_array_index (side_rules, i),
		                        side_collapsed);

	for (guint i = 0; side_items != NULL && i < side_items->len; i++) {
		GtkWidget *item = g_ptr_array_index (side_items, i);
		GtkWidget *row = g_object_get_data (G_OBJECT (item),
		                                    "fs-nav-row");

		gtk_widget_set_halign (row, side_collapsed ? GTK_ALIGN_CENTER
		                                           : GTK_ALIGN_FILL);
		/* Expanded, an item keeps the tooltip it was built with
		 * (most have none: the label says it). */
		gtk_widget_set_tooltip_text (
			item, g_object_get_data (G_OBJECT (item),
			                         side_collapsed ? "fs-rail-tip"
			                                        : "fs-wide-tip"));
	}

	/* In the rail the brand row stands on end: the tile, then the
	 * fold button under it. */
	gtk_orientable_set_orientation (GTK_ORIENTABLE (side_brand),
	                                side_collapsed
	                                ? GTK_ORIENTATION_VERTICAL
	                                : GTK_ORIENTATION_HORIZONTAL);
	gtk_widget_set_halign (side_search_row,
	                       side_collapsed ? GTK_ALIGN_CENTER
	                                      : GTK_ALIGN_FILL);
	gtk_widget_set_halign (side_footer_row,
	                       side_collapsed ? GTK_ALIGN_CENTER
	                                      : GTK_ALIGN_FILL);

	gtk_widget_set_tooltip_text (side_toggle,
	                             side_collapsed
	                             ? _("Expand the sidebar (Ctrl+B)")
	                             : _("Collapse the sidebar (Ctrl+B)"));
	atk = gtk_widget_get_accessible (side_toggle);
	if (atk != NULL)
		atk_object_set_name (atk, side_collapsed
		                          ? _("Expand the sidebar")
		                          : _("Collapse the sidebar"));

	sync_footer_tip ();
}

/* [ sidebar_toggle ] -- the brand row's button, Ctrl+B and the command
 * palette.  Remembered for the next start. */
static void
sidebar_toggle (void)
{
	if (side_bar == NULL)
		return;

	side_collapsed = !side_collapsed;
	fs_prefs_set_bool (FS_SIDEBAR_COLLAPSED_KEY, side_collapsed);
	sidebar_apply ();
}

static void
on_side_toggle (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;
	sidebar_toggle ();
}

/* The sidebar's order, which is also the order of the page shortcuts
 * (Ctrl+1 is the first item, whatever its FsAppPage number) and of the
 * command palette's "Go to" entries. */
static const struct {
	FsAppPage    page;
	FsIconKind   icon;
	const gchar *label;
	const gchar *group;
} nav_order[FS_PAGE_COUNT] = {
	{ FS_PAGE_OVERVIEW, FS_ICON_SHIELD,       N_("Overview"),     N_("Monitor") },
	{ FS_PAGE_EVENTS,   FS_ICON_LIST,         N_("Events"),       N_("Monitor") },
	{ FS_PAGE_ACTIVITY, FS_ICON_ACTIVITY,     N_("Activity"),     N_("Monitor") },
	{ FS_PAGE_TOPOLOGY, FS_ICON_WIFI,         N_("Topology"),     N_("Monitor") },
	{ FS_PAGE_POLICY,   FS_ICON_SLIDERS,      N_("Policy"),       N_("Protect") },
	{ FS_PAGE_INTEL,    FS_ICON_SHIELD_X,     N_("Threat Intel"), N_("Protect") },
	{ FS_PAGE_TRUST,    FS_ICON_CHECK_CIRCLE, N_("Trust"),        N_("Protect") },
	{ FS_PAGE_COPILOT,  FS_ICON_CHAT,         N_("Copilot"),      N_("Assist") },
	{ FS_PAGE_NEXORA,   FS_ICON_SHIELD_ALERT, N_("Nexora"),       N_("Assist") },
};

static void
on_action_page (GSimpleAction *action, GVariant *parameter, gpointer data)
{
	guint at = GPOINTER_TO_UINT (data);

	(void) action;
	(void) parameter;

	if (at < FS_PAGE_COUNT)
		fs_app_show_page (nav_order[at].page);
}

/* =====================================================================
 * Command palette (Ctrl+K): every page and action, one search away.
 *
 * A card in the window's overlay, over a scrim: a search entry and the
 * commands it has not filtered out.  The entry keeps the keyboard the
 * whole time (Tab is swallowed, the rows take no focus: what is under
 * the scrim must not be reachable while it is up); Up/Down move the
 * selection in the list, Enter runs it, Escape (or a click on the
 * scrim) closes and hands the keyboard back to the widget that had it.
 * ===================================================================== */
typedef void (*PaletteRun) (gpointer data);

typedef struct {
	const gchar *group;
	const gchar *title;
	FsIconKind   icon;
	const gchar *keys;
	PaletteRun   run;
	gpointer     data;
} PaletteCommand;

static GtkWidget *palette_scrim = NULL;
static GtkWidget *palette_entry = NULL;
static GtkWidget *palette_list = NULL;
static GtkWidget *palette_scroll = NULL;
static GtkWidget *palette_empty = NULL;
/* What had the keyboard when the palette opened; a weak pointer, the
 * widget may be gone by the time the palette closes. */
static GtkWidget *palette_prev_focus = NULL;

static void apply_appearance (void);

static void
palette_forget_focus (void)
{
	if (palette_prev_focus != NULL)
		g_object_remove_weak_pointer (G_OBJECT (palette_prev_focus),
		                              (gpointer *) &palette_prev_focus);
	palette_prev_focus = NULL;
}

static void
palette_close (void)
{
	GtkWidget *back = palette_prev_focus;

	if (palette_scrim == NULL || !gtk_widget_get_visible (palette_scrim))
		return;

	/* Hiding the scrim takes the focus widget with it and leaves
	 * the window with none: typing and the arrow keys would go
	 * nowhere until the next click. */
	palette_forget_focus ();
	gtk_widget_hide (palette_scrim);

	if (back == NULL || !gtk_widget_get_mapped (back) ||
	    gtk_widget_get_toplevel (back) != fsapp.window)
		return;
	if (GTK_IS_ENTRY (back))
		gtk_entry_grab_focus_without_selecting (GTK_ENTRY (back));
	else
		gtk_widget_grab_focus (back);
}

/* The rows the filter left on show, in order.  Free with g_list_free. */
static GList *
palette_visible_rows (void)
{
	GList *rows = NULL;
	GtkListBoxRow *row;

	for (gint i = 0;
	     (row = gtk_list_box_get_row_at_index (GTK_LIST_BOX (palette_list),
	                                           i)) != NULL; i++)
		if (gtk_widget_get_child_visible (GTK_WIDGET (row)))
			rows = g_list_prepend (rows, row);
	return g_list_reverse (rows);
}

/* Select `row' and bring it into view without giving it the focus:
 * the entry keeps the keyboard. */
static void
palette_select (GtkListBoxRow *row)
{
	GtkAdjustment *adj;
	GtkAllocation alloc;

	gtk_list_box_select_row (GTK_LIST_BOX (palette_list), row);
	if (row == NULL)
		return;

	gtk_widget_get_allocation (GTK_WIDGET (row), &alloc);
	adj = gtk_scrolled_window_get_vadjustment (
		GTK_SCROLLED_WINDOW (palette_scroll));
	if (alloc.height > 1)
		gtk_adjustment_clamp_page (adj, alloc.y,
		                           alloc.y + alloc.height);
}

static void
palette_move (gint step)
{
	GList *rows = palette_visible_rows ();
	GtkListBoxRow *current =
		gtk_list_box_get_selected_row (GTK_LIST_BOX (palette_list));
	gint n = (gint) g_list_length (rows);
	gint at = g_list_index (rows, current);

	if (n > 0) {
		at = at < 0 ? (step > 0 ? 0 : n - 1) : (at + step + n) % n;
		palette_select (g_list_nth_data (rows, (guint) at));
	}
	g_list_free (rows);
}

/* Every word typed must appear somewhere in "group title". */
static gboolean
palette_filter (GtkListBoxRow *row, gpointer data)
{
	const gchar *hay = g_object_get_data (G_OBJECT (row), "fs-palette-hay");
	gchar *needle = g_utf8_casefold (
		gtk_entry_get_text (GTK_ENTRY (palette_entry)), -1);
	gchar **words = g_strsplit_set (needle, " \t", -1);
	gboolean match = TRUE;

	(void) data;

	for (guint i = 0; hay != NULL && words[i] != NULL; i++)
		if (words[i][0] != '\0' && strstr (hay, words[i]) == NULL)
			match = FALSE;

	g_strfreev (words);
	g_free (needle);
	return match;
}

static void
on_palette_changed (GtkEditable *editable, gpointer data)
{
	GList *rows;

	(void) editable;
	(void) data;

	gtk_list_box_invalidate_filter (GTK_LIST_BOX (palette_list));
	rows = palette_visible_rows ();
	palette_select (rows != NULL ? rows->data : NULL);
	gtk_widget_set_visible (palette_empty, rows == NULL);
	gtk_widget_set_visible (palette_scroll, rows != NULL);
	g_list_free (rows);
}

/* The command runs from idle, after the palette has gone: several of
 * them open a dialog, which must not come up under the scrim. */
static gboolean
palette_run_idle (gpointer data)
{
	const PaletteCommand *cmd = data;

	cmd->run (cmd->data);
	return G_SOURCE_REMOVE;
}

static void
palette_run_row (GtkListBoxRow *row)
{
	PaletteCommand *cmd = row != NULL ?
		g_object_get_data (G_OBJECT (row), "fs-palette-cmd") : NULL;

	palette_close ();
	if (cmd != NULL && cmd->run != NULL)
		g_idle_add (palette_run_idle, cmd);
}

static void
on_palette_row_activated (GtkListBox *box, GtkListBoxRow *row, gpointer data)
{
	(void) box;
	(void) data;

	palette_run_row (row);
}

static gboolean
on_palette_key (GtkWidget *widget, GdkEventKey *event, gpointer data)
{
	gboolean ctrl = (event->state & GDK_CONTROL_MASK) != 0;

	(void) widget;
	(void) data;

	switch (event->keyval) {
	case GDK_KEY_Escape:
		palette_close ();
		return TRUE;
	case GDK_KEY_Tab:
	case GDK_KEY_KP_Tab:
	case GDK_KEY_ISO_Left_Tab:
		/* Focus stays in the entry: past it are the rows, then
		 * the page and the sidebar under the scrim. */
		return TRUE;
	case GDK_KEY_Down:
	case GDK_KEY_KP_Down:
		palette_move (1);
		return TRUE;
	case GDK_KEY_Up:
	case GDK_KEY_KP_Up:
		palette_move (-1);
		return TRUE;
	case GDK_KEY_n:
	case GDK_KEY_p:
		if (!ctrl)
			return FALSE;
		palette_move (event->keyval == GDK_KEY_n ? 1 : -1);
		return TRUE;
	case GDK_KEY_Return:
	case GDK_KEY_KP_Enter:
	case GDK_KEY_ISO_Enter:
		palette_run_row (gtk_list_box_get_selected_row (
			GTK_LIST_BOX (palette_list)));
		return TRUE;
	default:
		return FALSE;
	}
}

/* A press on the scrim itself closes; a press inside the card (which
 * has a window of its own) is the card's business. */
static gboolean
on_palette_scrim_press (GtkWidget *widget, GdkEventButton *event,
                        gpointer data)
{
	(void) data;

	if (event->window == gtk_widget_get_window (widget)) {
		palette_close ();
		return TRUE;
	}
	return FALSE;
}

static void
palette_open (void)
{
	if (palette_scrim == NULL)
		return;

	if (!gtk_widget_get_visible (palette_scrim)) {
		palette_forget_focus ();
		palette_prev_focus = gtk_window_get_focus (
			GTK_WINDOW (fsapp.window));
		if (palette_prev_focus != NULL)
			g_object_add_weak_pointer (
				G_OBJECT (palette_prev_focus),
				(gpointer *) &palette_prev_focus);
	}

	gtk_entry_set_text (GTK_ENTRY (palette_entry), "");
	gtk_widget_show (palette_scrim);
	on_palette_changed (NULL, NULL);
	gtk_widget_grab_focus (palette_entry);
}

static void
palette_toggle (void)
{
	if (palette_scrim != NULL && gtk_widget_get_visible (palette_scrim))
		palette_close ();
	else
		palette_open ();
}

/* ---- what the commands do ---- */
static void
palette_go (gpointer data)
{
	fs_app_show_page ((FsAppPage) GPOINTER_TO_UINT (data));
}

static void
palette_firewall (gpointer data)
{
	if (GPOINTER_TO_INT (data))
		fs_statusview_firewall_start (fsapp.window, "palette");
	else
		fs_statusview_firewall_stop (fsapp.window, "palette");
}

static void
palette_preferences (gpointer data)
{
	(void) data;
	fs_dialogs_preferences (fsapp.window);
}

static void
palette_help (gpointer data)
{
	(void) data;
	show_help ();
}

static void
palette_about (gpointer data)
{
	(void) data;
	fs_dialogs_about (fsapp.window);
}

/* The Appearance settings of Preferences, one command away: stored
 * like a Save there would (the periodic save and the one at quit write
 * the file) and applied at once.  `data' is the accent's stored word. */
static void
palette_accent (gpointer data)
{
	fs_prefs_set_string (FS_PREFS_ACCENT, data);
	apply_appearance ();
}

static void
palette_density (gpointer data)
{
	gboolean comfortable = strcmp (fs_prefs_choice (FS_PREFS_DENSITY),
	                               "comfortable") == 0;

	(void) data;
	fs_prefs_set_string (FS_PREFS_DENSITY,
	                     comfortable ? "compact" : "comfortable");
	apply_appearance ();
}

static void
palette_theme (gpointer data)
{
	(void) data;
	fs_prefs_set_bool (FS_PREFS_DARK_MODE,
	                   !fs_prefs_bool (FS_PREFS_DARK_MODE));
	apply_appearance ();
}

static void
palette_sidebar (gpointer data)
{
	(void) data;
	sidebar_toggle ();
}

static void
palette_quit (gpointer data)
{
	(void) data;
	fs_app_quit ();
}

static void
palette_add (const gchar *group, const gchar *title, FsIconKind icon,
             const gchar *keys, PaletteRun run, gpointer data)
{
	PaletteCommand *cmd = g_new0 (PaletteCommand, 1);
	GtkWidget *row = gtk_list_box_row_new ();
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
	GtkWidget *label;
	gchar *both = g_strdup_printf ("%s %s", group, title);

	gtk_widget_set_can_focus (row, FALSE);

	cmd->group = group;
	cmd->title = title;
	cmd->icon = icon;
	cmd->keys = keys;
	cmd->run = run;
	cmd->data = data;

	gtk_box_pack_start (GTK_BOX (box), fs_icon_new (icon, 16),
	                    FALSE, FALSE, 0);
	label = gtk_label_new (title);
	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             "fs-palette-title");
	gtk_box_pack_start (GTK_BOX (box), label, FALSE, FALSE, 0);
	label = gtk_label_new (group);
	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             "fs-palette-group");
	gtk_box_pack_start (GTK_BOX (box), label, TRUE, TRUE, 0);
	if (keys != NULL) {
		label = gtk_label_new (keys);
		gtk_style_context_add_class (
			gtk_widget_get_style_context (label), "fs-kbd");
		gtk_box_pack_end (GTK_BOX (box), label, FALSE, FALSE, 0);
	}
	gtk_container_add (GTK_CONTAINER (row), box);

	g_object_set_data_full (G_OBJECT (row), "fs-palette-cmd", cmd, g_free);
	g_object_set_data_full (G_OBJECT (row), "fs-palette-hay",
	                        g_utf8_casefold (both, -1), g_free);
	g_free (both);

	gtk_container_add (GTK_CONTAINER (palette_list), row);
}

static GtkWidget *
palette_hint (const gchar *keys, const gchar *what)
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *label = gtk_label_new (keys);
	GtkStyleContext *ctx = gtk_widget_get_style_context (label);

	gtk_style_context_add_class (ctx, "fs-kbd");
	gtk_style_context_add_class (ctx, "boxed");
	gtk_box_pack_start (GTK_BOX (box), label, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), gtk_label_new (what),
	                    FALSE, FALSE, 0);
	return box;
}

/* [ build_palette ] -- the overlay child; hidden until asked for. */
static GtkWidget *
build_palette (void)
{
	static const gchar *const page_keys[FS_PAGE_COUNT] = {
		"Ctrl+1", "Ctrl+2", "Ctrl+3", "Ctrl+4", "Ctrl+5",
		"Ctrl+6", "Ctrl+7", "Ctrl+8", "Ctrl+9"
	};
	GtkWidget *card_window, *card, *foot;

	palette_scrim = gtk_event_box_new ();
	gtk_widget_set_name (palette_scrim, "fs-palette");
	gtk_style_context_add_class (
		gtk_widget_get_style_context (palette_scrim),
		"fs-palette-scrim");
	g_signal_connect (palette_scrim, "button-press-event",
	                  G_CALLBACK (on_palette_scrim_press), NULL);

	/* The card in a window of its own, so the scrim can tell a press
	 * on the card from a press beside it. */
	card_window = gtk_event_box_new ();
	gtk_widget_set_halign (card_window, GTK_ALIGN_CENTER);
	gtk_widget_set_valign (card_window, GTK_ALIGN_START);
	gtk_widget_set_margin_top (card_window, 96);
	gtk_widget_set_size_request (card_window, 560, -1);
	gtk_event_box_set_visible_window (GTK_EVENT_BOX (card_window), FALSE);
	gtk_event_box_set_above_child (GTK_EVENT_BOX (card_window), FALSE);
	gtk_container_add (GTK_CONTAINER (palette_scrim), card_window);

	card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_style_context_add_class (gtk_widget_get_style_context (card),
	                             "fs-palette");
	gtk_container_add (GTK_CONTAINER (card_window), card);

	palette_entry = gtk_entry_new ();
	gtk_widget_set_name (palette_entry, "fs-palette-entry");
	gtk_entry_set_placeholder_text (GTK_ENTRY (palette_entry),
	                                _("Search pages and commands"));
	gtk_style_context_add_class (
		gtk_widget_get_style_context (palette_entry),
		"fs-palette-entry");
	g_signal_connect (palette_entry, "changed",
	                  G_CALLBACK (on_palette_changed), NULL);
	g_signal_connect (palette_entry, "key-press-event",
	                  G_CALLBACK (on_palette_key), NULL);
	gtk_box_pack_start (GTK_BOX (card), palette_entry, FALSE, FALSE, 0);

	palette_scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (palette_scroll),
	                                GTK_POLICY_NEVER,
	                                GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_max_content_height (
		GTK_SCROLLED_WINDOW (palette_scroll), 340);
	gtk_scrolled_window_set_propagate_natural_height (
		GTK_SCROLLED_WINDOW (palette_scroll), TRUE);
	gtk_box_pack_start (GTK_BOX (card), palette_scroll, FALSE, FALSE, 0);

	palette_list = gtk_list_box_new ();
	gtk_widget_set_name (palette_list, "fs-palette-list");
	gtk_list_box_set_selection_mode (GTK_LIST_BOX (palette_list),
	                                 GTK_SELECTION_SINGLE);
	gtk_list_box_set_activate_on_single_click (
		GTK_LIST_BOX (palette_list), TRUE);
	gtk_list_box_set_filter_func (GTK_LIST_BOX (palette_list),
	                              palette_filter, NULL, NULL);
	gtk_widget_set_can_focus (palette_list, FALSE);
	gtk_style_context_add_class (
		gtk_widget_get_style_context (palette_list),
		"fs-palette-list");
	g_signal_connect (palette_list, "row-activated",
	                  G_CALLBACK (on_palette_row_activated), NULL);
	gtk_container_add (GTK_CONTAINER (palette_scroll), palette_list);

	for (guint i = 0; i < FS_PAGE_COUNT; i++)
		palette_add (_("Go to"), _(nav_order[i].label),
		             nav_order[i].icon, page_keys[i], palette_go,
		             GUINT_TO_POINTER (nav_order[i].page));
	palette_add (_("Firewall"), _("Start firewall"), FS_ICON_PLAY, NULL,
	             palette_firewall, GINT_TO_POINTER (TRUE));
	palette_add (_("Firewall"), _("Stop firewall\342\200\246"),
	             FS_ICON_STOP, NULL, palette_firewall,
	             GINT_TO_POINTER (FALSE));
	palette_add (_("App"), _("Preferences"), FS_ICON_SETTINGS, "Ctrl+,",
	             palette_preferences, NULL);
	palette_add (_("App"), _("Accent: blue"), FS_ICON_MONITOR, NULL,
	             palette_accent, "blue");
	palette_add (_("App"), _("Accent: green"), FS_ICON_MONITOR, NULL,
	             palette_accent, "green");
	palette_add (_("App"), _("Accent: amber"), FS_ICON_MONITOR, NULL,
	             palette_accent, "amber");
	palette_add (_("App"), _("Toggle row density"), FS_ICON_LIST, NULL,
	             palette_density, NULL);
	palette_add (_("App"), _("Toggle dark mode"), FS_ICON_MONITOR, NULL,
	             palette_theme, NULL);
	palette_add (_("App"), _("Toggle sidebar"), FS_ICON_SIDEBAR, "Ctrl+B",
	             palette_sidebar, NULL);
	palette_add (_("App"), _("Help"), FS_ICON_HELP, "F1",
	             palette_help, NULL);
	palette_add (_("App"), _("About StockFW"), FS_ICON_INFO, NULL,
	             palette_about, NULL);
	palette_add (_("App"), _("Quit StockFW"), FS_ICON_STOP, "Ctrl+Q",
	             palette_quit, NULL);

	palette_empty = gtk_label_new (_("No matching command"));
	gtk_label_set_xalign (GTK_LABEL (palette_empty), 0.0);
	gtk_style_context_add_class (
		gtk_widget_get_style_context (palette_empty),
		"fs-palette-empty");
	gtk_widget_set_no_show_all (palette_empty, TRUE);
	gtk_box_pack_start (GTK_BOX (card), palette_empty, FALSE, FALSE, 0);

	foot = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 14);
	gtk_style_context_add_class (gtk_widget_get_style_context (foot),
	                             "fs-palette-foot");
	gtk_box_pack_start (GTK_BOX (foot),
	                    palette_hint ("\342\206\221\342\206\223", _("Move")),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (foot), palette_hint ("Enter", _("Run")),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (foot), palette_hint ("Esc", _("Close")),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (card), foot, FALSE, FALSE, 0);

	/* Built shown inside, hidden as a whole: show_all on the window
	 * must not open the palette. */
	gtk_widget_show_all (card_window);
	gtk_widget_hide (palette_empty);
	gtk_widget_set_no_show_all (palette_scrim, TRUE);

	return palette_scrim;
}

static void
on_side_search (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;

	palette_open ();
}

/* [ build_sidebar ]
 * A dense list in the manner of OpenCode's session list: the name and
 * version on one line, the command palette's trigger where a search
 * field would be, the pages in three quiet groups with their
 * shortcuts, then Preferences, Help and About, then the verdict.
 *
 * The button at the end of the first line (and Ctrl+B) folds all of it
 * to a rail of icons; sidebar_apply () has the two layouts. */
static GtkWidget *
build_sidebar (void)
{
	static const gchar *const page_keys[FS_PAGE_COUNT] = {
		"Ctrl+1", "Ctrl+2", "Ctrl+3", "Ctrl+4", "Ctrl+5",
		"Ctrl+6", "Ctrl+7", "Ctrl+8", "Ctrl+9"
	};
	GtkWidget *bar, *brand, *tile, *label, *spacer, *footer, *row;
	const gchar *group = NULL;

	side_collapsed = fs_prefs_get_bool (FS_SIDEBAR_COLLAPSED_KEY, FALSE);

	bar = gtk_box_new (GTK_ORIENTATION_VERTICAL, 1);
	gtk_widget_set_name (bar, "fs-sidebar");
	gtk_widget_set_size_request (bar, FS_SIDEBAR_WIDTH, -1);
	gtk_style_context_add_class (gtk_widget_get_style_context (bar),
	                             "fs-sidebar");
	side_bar = bar;

	/* ---- brand ---- */
	brand = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	gtk_style_context_add_class (gtk_widget_get_style_context (brand),
	                             "fs-brand");
	side_brand = brand;

	tile = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_widget_set_size_request (tile, 24, 24);
	gtk_widget_set_halign (tile, GTK_ALIGN_CENTER);
	gtk_widget_set_valign (tile, GTK_ALIGN_CENTER);
	gtk_style_context_add_class (gtk_widget_get_style_context (tile),
	                             "fs-brand-tile");
	{
		GdkPixbuf *logo = logo_pixbuf (stockfw_logo_32_png,
		                               stockfw_logo_32_png_len);

		if (logo != NULL) {
			GdkPixbuf *small = gdk_pixbuf_scale_simple (
				logo, 18, 18, GDK_INTERP_BILINEAR);
			GtkWidget *image = gtk_image_new_from_pixbuf (
				small != NULL ? small : logo);

			gtk_widget_set_halign (image, GTK_ALIGN_CENTER);
			gtk_widget_set_valign (image, GTK_ALIGN_CENTER);
			gtk_box_pack_start (GTK_BOX (tile), image, TRUE, TRUE, 0);
			g_clear_object (&small);
			g_object_unref (logo);
		}
	}
	gtk_box_pack_start (GTK_BOX (brand), tile, FALSE, FALSE, 0);

	label = gtk_label_new ("StockFW");
	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             "fs-brand-name");
	gtk_box_pack_start (GTK_BOX (brand), side_text (label), TRUE, TRUE, 0);

	/* The fold button, at the end of the row; its tooltip and name
	 * say which way it goes (sidebar_apply). */
	side_toggle = gtk_button_new ();
	gtk_container_add (GTK_CONTAINER (side_toggle),
	                   fs_icon_new (FS_ICON_SIDEBAR, 16));
	gtk_widget_set_name (side_toggle, "nav-collapse");
	gtk_button_set_relief (GTK_BUTTON (side_toggle), GTK_RELIEF_NONE);
	gtk_widget_set_halign (side_toggle, GTK_ALIGN_CENTER);
	gtk_widget_set_valign (side_toggle, GTK_ALIGN_CENTER);
	gtk_style_context_add_class (
		gtk_widget_get_style_context (side_toggle), "fs-side-toggle");
	g_signal_connect (side_toggle, "clicked",
	                  G_CALLBACK (on_side_toggle), NULL);
	gtk_box_pack_end (GTK_BOX (brand), side_toggle, FALSE, FALSE, 0);

#ifdef FS_VERSION
	label = gtk_label_new (FS_VERSION);
#else
	label = gtk_label_new ("");
#endif
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             "fs-brand-version");
	gtk_box_pack_end (GTK_BOX (brand), side_text (label), FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (bar), brand, FALSE, FALSE, 0);

	/* ---- command palette trigger ---- */
	{
		GtkWidget *item = gtk_button_new ();
		GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
		GtkStyleContext *ctx;
		AtkObject *atk = gtk_widget_get_accessible (item);

		gtk_box_pack_start (GTK_BOX (inner),
		                    fs_icon_new (FS_ICON_SEARCH, 14),
		                    FALSE, FALSE, 0);
		label = gtk_label_new (_("Search"));
		gtk_label_set_xalign (GTK_LABEL (label), 0.0);
		gtk_box_pack_start (GTK_BOX (inner), side_text (label),
		                    TRUE, TRUE, 0);
		label = gtk_label_new ("Ctrl+K");
		ctx = gtk_widget_get_style_context (label);
		gtk_style_context_add_class (ctx, "fs-kbd");
		gtk_style_context_add_class (ctx, "boxed");
		gtk_box_pack_end (GTK_BOX (inner), side_text (label),
		                  FALSE, FALSE, 0);
		gtk_container_add (GTK_CONTAINER (item), inner);
		side_search = item;
		side_search_row = inner;

		gtk_widget_set_name (item, "nav-search");
		gtk_widget_set_tooltip_text (
			item, _("Search pages and commands (Ctrl+K)"));
		/* Its name does not hang on a label the rail hides. */
		if (atk != NULL)
			atk_object_set_name (atk, _("Search"));
		gtk_style_context_add_class (
			gtk_widget_get_style_context (item), "fs-side-search");
		g_signal_connect (item, "clicked",
		                  G_CALLBACK (on_side_search), NULL);
		gtk_box_pack_start (GTK_BOX (bar), item, FALSE, FALSE, 0);
	}

	/* ---- pages, in groups ---- */
	for (guint i = 0; i < FS_PAGE_COUNT; i++) {
		GtkWidget *item;

		if (group == NULL || strcmp (group, nav_order[i].group) != 0) {
			/* In the rail a thin rule stands where the heading
			 * was; the first group needs none, the search
			 * button is above it. */
			if (group != NULL) {
				GtkWidget *rule = gtk_box_new (
					GTK_ORIENTATION_HORIZONTAL, 0);

				gtk_style_context_add_class (
					gtk_widget_get_style_context (rule),
					"fs-side-rule");
				gtk_widget_set_no_show_all (rule, TRUE);
				gtk_box_pack_start (GTK_BOX (bar), rule,
				                    FALSE, FALSE, 0);
				if (side_rules == NULL)
					side_rules = g_ptr_array_new ();
				g_ptr_array_add (side_rules, rule);
			}

			group = nav_order[i].group;
			label = gtk_label_new (_(group));
			gtk_label_set_xalign (GTK_LABEL (label), 0.0);
			gtk_style_context_add_class (
				gtk_widget_get_style_context (label),
				"fs-side-group");
			gtk_box_pack_start (GTK_BOX (bar), side_text (label),
			                    FALSE, FALSE, 0);
		}

		item = nav_button (gtk_toggle_button_new (), nav_order[i].icon,
		                   _(nav_order[i].label), page_keys[i]);
		{
			gchar *name = g_strdup_printf ("nav-page%u", i + 1);

			gtk_widget_set_name (item, name);
			g_free (name);
		}
		g_signal_connect (item, "toggled", G_CALLBACK (on_nav_toggled),
		                  GUINT_TO_POINTER (nav_order[i].page));
		gtk_box_pack_start (GTK_BOX (bar), item, FALSE, FALSE, 0);
		nav_items[nav_order[i].page] = item;
	}

	spacer = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_pack_start (GTK_BOX (bar), spacer, TRUE, TRUE, 0);

	/* ---- Preferences, Help, About ---- */
	{
		GtkWidget *item;

		item = nav_button (gtk_button_new (), FS_ICON_SETTINGS,
		                   _("Preferences"), "Ctrl+,");
		gtk_widget_set_tooltip_text (item, _("Preferences (Ctrl+,)"));
		g_signal_connect (item, "clicked",
		                  G_CALLBACK (on_nav_preferences), NULL);
		gtk_box_pack_start (GTK_BOX (bar), item, FALSE, FALSE, 0);

		item = nav_button (gtk_button_new (), FS_ICON_HELP, _("Help"),
		                   "F1");
		gtk_widget_set_name (item, "nav-help");
		gtk_widget_set_tooltip_text (item, _("Help (F1)"));
		g_signal_connect (item, "clicked", G_CALLBACK (on_nav_help),
		                  NULL);
		gtk_box_pack_start (GTK_BOX (bar), item, FALSE, FALSE, 0);

		item = nav_button (gtk_button_new (), FS_ICON_INFO,
		                   _("About StockFW"), NULL);
		g_signal_connect (item, "clicked", G_CALLBACK (on_nav_about),
		                  NULL);
		gtk_box_pack_start (GTK_BOX (bar), item, FALSE, FALSE, 0);
	}

	/* ---- verdict ---- */
	footer = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	gtk_style_context_add_class (gtk_widget_get_style_context (footer),
	                             "fs-sidebar-footer");

	row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	side_dot = fs_icon_new (FS_ICON_DOT, 8);
	gtk_style_context_add_class (gtk_widget_get_style_context (side_dot),
	                             "fs-side-dot");
	gtk_box_pack_start (GTK_BOX (row), side_dot, FALSE, FALSE, 0);
	side_state = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (side_state), 0.0);
	gtk_label_set_ellipsize (GTK_LABEL (side_state), PANGO_ELLIPSIZE_END);
	gtk_style_context_add_class (gtk_widget_get_style_context (side_state),
	                             "fs-side-state");
	gtk_box_pack_start (GTK_BOX (row), side_text (side_state),
	                    TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (footer), row, FALSE, FALSE, 0);
	side_footer_row = row;

	side_backend = gtk_label_new (NULL);
	gtk_label_set_xalign (GTK_LABEL (side_backend), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (side_backend), TRUE);
	gtk_style_context_add_class (gtk_widget_get_style_context (side_backend),
	                             "fs-side-backend");
	gtk_box_pack_start (GTK_BOX (footer), side_text (side_backend),
	                    FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (bar), footer, FALSE, FALSE, 0);
	side_footer = footer;

	/* The tooltips the items were built with are the ones they show
	 * expanded; the rail swaps in its own and puts these back. */
	for (guint i = 0; side_items != NULL && i < side_items->len; i++) {
		GtkWidget *item = g_ptr_array_index (side_items, i);

		g_object_set_data_full (G_OBJECT (item), "fs-wide-tip",
		                        gtk_widget_get_tooltip_text (item),
		                        g_free);
	}

	return bar;
}

/* [ apply_dark_mode ]
 * fs-theme.css defines the dark palette; "Dark mode" off lays the
 * light values of the same colour names over it, one priority step
 * up, and on takes them away again.  Both are for the whole screen,
 * so every window and dialog follows at once.  GTK's own dark-variant
 * switch follows too, for the stock widgets the stylesheet leaves
 * alone. */
static void
apply_dark_mode (void)
{
	static GtkCssProvider *light = NULL;
	gboolean dark = fs_prefs_bool (FS_PREFS_DARK_MODE);
	GtkSettings *gtk_settings = gtk_settings_get_default ();
	GdkScreen *screen = gdk_screen_get_default ();

	if (gtk_settings != NULL)
		g_object_set (gtk_settings,
		              "gtk-application-prefer-dark-theme", dark, NULL);

	if (screen != NULL && !dark && light == NULL) {
		light = gtk_css_provider_new ();
		if (gtk_css_provider_load_from_data (light, fs_theme_light_css,
		                                     -1, NULL)) {
			gtk_style_context_add_provider_for_screen (
				screen, GTK_STYLE_PROVIDER (light),
				GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 1);
		} else {
			g_warning ("StockFW light palette failed to load");
			g_clear_object (&light);
		}
	} else if (screen != NULL && dark && light != NULL) {
		gtk_style_context_remove_provider_for_screen (
			screen, GTK_STYLE_PROVIDER (light));
		g_clear_object (&light);
	}

	if (fsapp.window != NULL) {
		GtkStyleContext *ctx = gtk_widget_get_style_context (fsapp.window);

		if (dark)
			gtk_style_context_add_class (ctx, "dark");
		else
			gtk_style_context_remove_class (ctx, "dark");
	}
}

/* [ appearance_sheet ]
 * One of the two small sheets of ui/fs-theme-accent.h over the whole
 * screen, or none of it: `css' is the sheet wanted now (NULL for
 * none), *provider and *installed remember what is up.  They sit two
 * priority steps above fs-theme.css, so above the light palette too,
 * which names the accent colours itself.  Nothing is touched when the
 * sheet wanted is the one installed: every Save of Preferences comes
 * through here, and re-installing would restyle every window for
 * nothing.  TRUE when what is installed changed. */
static gboolean
appearance_sheet (GtkCssProvider **provider, const gchar **installed,
                  const gchar *css, const gchar *what)
{
	GdkScreen *screen = gdk_screen_get_default ();

	if (screen == NULL || css == *installed)
		return FALSE;

	if (*provider != NULL) {
		gtk_style_context_remove_provider_for_screen (
			screen, GTK_STYLE_PROVIDER (*provider));
		g_clear_object (provider);
	}
	*installed = NULL;
	if (css == NULL)
		return TRUE;

	*provider = gtk_css_provider_new ();
	if (gtk_css_provider_load_from_data (*provider, css, -1, NULL)) {
		gtk_style_context_add_provider_for_screen (
			screen, GTK_STYLE_PROVIDER (*provider),
			GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 2);
		*installed = css;
	} else {
		g_warning ("StockFW %s failed to load", what);
		g_clear_object (provider);
	}
	return TRUE;
}

/* [ apply_accent ]
 * The accent colour of Preferences: blue is what the stylesheet and
 * the light palette say already and installs nothing; green and amber
 * rename fs_accent and fs_accent_fill, with the values of the mode
 * that is on.  So it runs after apply_dark_mode, and again whenever
 * either changes.  Everything painted by hand asks the theme for
 * "fs_accent" at each draw (ui/fs-themecolor.h) and follows too. */
static void
apply_accent (void)
{
	static GtkCssProvider *provider = NULL;
	static const gchar *installed = NULL;
	const gchar *accent = fs_prefs_choice (FS_PREFS_ACCENT);
	gboolean dark = fs_prefs_bool (FS_PREFS_DARK_MODE);
	const gchar *css = NULL;

	/* Row 0 is blue. */
	for (guint i = 1; i < G_N_ELEMENTS (fs_theme_accents); i++)
		if (strcmp (accent, fs_theme_accents[i].id) == 0)
			css = dark ? fs_theme_accents[i].dark
			           : fs_theme_accents[i].light;

	appearance_sheet (&provider, &installed, css, "accent colour");
}

/* What density_tree is told: how much to add to every row above and
 * below, and whether the column headings have just been restyled (the
 * comfortable sheet went up or came down). */
typedef struct
{
	gint     extra;
	gboolean restyled;
} DensityPass;

/* [ density_tree ]
 * The rows of every tree view under `widget': a cell renderer takes no
 * padding from CSS, the row is as tall as its tallest cell plus that
 * cell's ypad twice.  So each renderer's ypad becomes the one it was
 * built with (remembered on it the first time it is raised, +1 so that
 * 0 can be told from "never seen") plus the pass's extra.
 *
 * Then the view has to measure its rows again, which it does not do
 * for a renderer property on its own.  Queueing a resize on a column
 * marks every row's height stale.  The Events list is in fixed-height
 * mode, where one measured row stands for all and that height is kept
 * until the mode itself is set: so the mode is switched off and on
 * again around it.
 *
 * The headings are CSS, but need a hand as well.  A scrolled window
 * leaves room for its list's heading from the height the list worked
 * out the last time it was measured, and asks for that before it
 * measures the list again: after the headings grow (and before the
 * very first layout) its answer is one step behind, and a list that
 * is only as tall as it must be (the Policy page's) gave its scrollbar
 * less room than a scrollbar takes, which GTK reports on stderr.  So
 * the headings are measured here, now, and the next layout starts
 * from the right height. */
static void
density_tree (GtkWidget *widget, gpointer data)
{
	const DensityPass *pass = data;

	if (GTK_IS_TREE_VIEW (widget)) {
		GtkTreeView *view = GTK_TREE_VIEW (widget);
		GList *columns = gtk_tree_view_get_columns (view);
		gboolean moved = FALSE;

		for (GList *c = columns; c != NULL; c = c->next) {
			GList *cells = gtk_cell_layout_get_cells (
				GTK_CELL_LAYOUT (c->data));

			for (GList *r = cells; r != NULL; r = r->next) {
				GObject *cell = r->data;
				gpointer seen = g_object_get_data (
					cell, "fs-density-ypad");
				gint xpad = 0, ypad = 0, built;

				gtk_cell_renderer_get_padding (
					GTK_CELL_RENDERER (cell), &xpad, &ypad);
				if (seen != NULL) {
					built = GPOINTER_TO_INT (seen) - 1;
				} else if (pass->extra == 0) {
					/* Compact, and never raised: as built. */
					continue;
				} else {
					built = ypad;
					g_object_set_data (
						cell, "fs-density-ypad",
						GINT_TO_POINTER (built + 1));
				}
				if (ypad != built + pass->extra) {
					gtk_cell_renderer_set_padding (
						GTK_CELL_RENDERER (cell), xpad,
						built + pass->extra);
					moved = TRUE;
				}
			}
			g_list_free (cells);
		}

		if (moved) {
			gboolean fixed =
				gtk_tree_view_get_fixed_height_mode (view);

			if (fixed)
				gtk_tree_view_set_fixed_height_mode (view, FALSE);
			for (GList *c = columns; c != NULL; c = c->next)
				gtk_tree_view_column_queue_resize (c->data);
			if (fixed)
				gtk_tree_view_set_fixed_height_mode (view, TRUE);
		}

		if (moved || pass->restyled) {
			gint height = 0;

			for (GList *c = columns; c != NULL; c = c->next) {
				GtkWidget *heading =
					gtk_tree_view_column_get_button (c->data);

				if (heading != NULL)
					gtk_widget_queue_resize (heading);
			}
			gtk_widget_get_preferred_height (widget, &height, NULL);
			gtk_widget_queue_resize (widget);
		}

		g_list_free (columns);
	}

	if (GTK_IS_CONTAINER (widget))
		gtk_container_forall (GTK_CONTAINER (widget), density_tree,
		                      data);
}

/* [ density_rows ]
 * The row density of Preferences, for the lists CSS does not reach:
 * every tree view in every window that is open now (the main window's
 * pages hold all of them; there may be no window at all, in a test of
 * the Preferences window alone).  Runs once the pages are built and
 * after every change of the setting.  Compact, with nothing ever
 * raised, changes nothing. */
static void
density_rows (gboolean restyled)
{
	gboolean comfortable = strcmp (fs_prefs_choice (FS_PREFS_DENSITY),
	                               "comfortable") == 0;
	DensityPass pass = { comfortable ? FS_THEME_COMFORTABLE_YPAD : 0,
	                     restyled };
	GList *tops = gtk_window_list_toplevels ();

	for (GList *l = tops; l != NULL; l = l->next)
		density_tree (l->data, &pass);
	g_list_free (tops);
}

/* [ apply_density ]
 * Compact is the stylesheet as written.  Comfortable lays the second
 * sheet of ui/fs-theme-accent.h over it (a little more room in the
 * rows of the sidebars, the lists and the menus, in every window) and
 * raises the rows of the tree views to match. */
static void
apply_density (void)
{
	static GtkCssProvider *provider = NULL;
	static const gchar *installed = NULL;
	gboolean comfortable = strcmp (fs_prefs_choice (FS_PREFS_DENSITY),
	                               "comfortable") == 0;

	density_rows (appearance_sheet (&provider, &installed,
	                                comfortable ? fs_theme_comfortable_css
	                                            : NULL,
	                                "comfortable density"));
}

/* [ apply_appearance ]
 * Everything Preferences > General > Appearance offers, from what is
 * stored: Dark mode, then the accent (whose values depend on the
 * mode), then the row density.  At startup, after a Save in
 * Preferences, and from the command palette. */
static void
apply_appearance (void)
{
	apply_dark_mode ();
	apply_accent ();
	apply_density ();
}

/* [ install_theme ]
 * One stylesheet for the whole application: src/ui/fs-theme.css,
 * compiled into the binary (fs-theme-css.h is generated at configure
 * time), so the installed exe needs no data files beside it. */
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

/* What holds a blocklist apply besides audit-only mode: the Overview's
 * Lock, as it holds the policy.  English, like fs_apply_hold_reason():
 * the audit line records it verbatim. */
static const gchar *
app_intel_hold (void)
{
	return fs_statusview_policy_locked ()
	       ? "the policy is locked on the Overview" : NULL;
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
		/* Started: the blocklists follow, through their own gate
		 * (off the main loop; nothing where none was turned on). */
		if (outcome->result == FS_APPLY_OK)
			fs_statusview_intel_follow (TRUE, "start on open");
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
		/* "Show a tray icon" is off, or the desktop has no tray
		 * (Wayland, WSLg: fs_tray_supported): nothing to hide
		 * behind.  The debug line is what tests/test-notray.sh
		 * reads, a Broadway display having no window list. */
		g_debug ("background start: no tray icon, the window is shown");
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

	/* Events still queued for the history file (it is flushed every
	 * second anyway; this is for a sign-out that ends us next). */
	if (everything)
		fs_hitview_flush_history ();
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

	/* The last second of events into the history file, and the
	 * history folder's writer lock let go, before the instance name
	 * is (main.c releases it after the loop): a copy taking over finds
	 * the history free. */
	fs_hitview_shutdown ();

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


/* --- Floating notification toast overlay --- */
static GtkWidget *toast_box = NULL;

static gboolean
toast_timeout_cb (gpointer data)
{
	GtkWidget *card = GTK_WIDGET (data);
	if (card != NULL && GTK_IS_WIDGET (card)) {
		gtk_widget_destroy (card);
	}
	return G_SOURCE_REMOVE;
}

static void
on_toast_close_clicked (GtkButton *btn, gpointer data)
{
	(void) btn;
	GtkWidget *card = GTK_WIDGET (data);
	guint *tid = g_object_get_data (G_OBJECT (card), "toast-timeout-id");
	if (tid != NULL && *tid != 0) {
		g_source_remove (*tid);
		*tid = 0;
	}
	if (card != NULL && GTK_IS_WIDGET (card)) {
		gtk_widget_destroy (card);
	}
}

void
fs_app_show_toast (const gchar *title, const gchar *message, gboolean is_error)
{
	GtkWidget *card, *vbox, *tlabel, *mlabel, *close_btn;
	guint *tid_ptr;

	if (toast_box == NULL)
		return;

	card = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	gtk_style_context_add_class (gtk_widget_get_style_context (card), "toast-card");
	if (is_error)
		gtk_style_context_add_class (gtk_widget_get_style_context (card), "error");

	/* Icon */
	{
		FsIconKind icon_kind = is_error ? FS_ICON_SHIELD_X : FS_ICON_SHIELD;
		GtkWidget *icon = fs_icon_new (icon_kind, 20);
		gtk_widget_set_valign (icon, GTK_ALIGN_CENTER);
		gtk_box_pack_start (GTK_BOX (card), icon, FALSE, FALSE, 0);
	}

	vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	gtk_widget_set_hexpand (vbox, TRUE);
	gtk_widget_set_valign (vbox, GTK_ALIGN_CENTER);

	tlabel = gtk_label_new (title ? title : _("Notification"));
	gtk_label_set_xalign (GTK_LABEL (tlabel), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (tlabel), "toast-title");
	gtk_box_pack_start (GTK_BOX (vbox), tlabel, FALSE, FALSE, 0);

	if (message != NULL && *message != '\0') {
		mlabel = gtk_label_new (message);
		gtk_label_set_xalign (GTK_LABEL (mlabel), 0.0);
		gtk_label_set_line_wrap (GTK_LABEL (mlabel), TRUE);
		gtk_style_context_add_class (gtk_widget_get_style_context (mlabel), "toast-message");
		gtk_box_pack_start (GTK_BOX (vbox), mlabel, FALSE, FALSE, 0);
	}

	gtk_box_pack_start (GTK_BOX (card), vbox, TRUE, TRUE, 0);

	/* Close button */
	close_btn = gtk_button_new_with_label ("×");
	gtk_button_set_relief (GTK_BUTTON (close_btn), GTK_RELIEF_NONE);
	gtk_widget_set_valign (close_btn, GTK_ALIGN_CENTER);
	gtk_style_context_add_class (gtk_widget_get_style_context (close_btn), "toast-close");
	g_signal_connect (close_btn, "clicked", G_CALLBACK (on_toast_close_clicked), card);
	gtk_box_pack_start (GTK_BOX (card), close_btn, FALSE, FALSE, 0);

	tid_ptr = g_new0 (guint, 1);
	*tid_ptr = g_timeout_add_seconds (5, toast_timeout_cb, card);
	g_object_set_data_full (G_OBJECT (card), "toast-timeout-id", tid_ptr, g_free);

	gtk_box_pack_start (GTK_BOX (toast_box), card, FALSE, FALSE, 0);
	gtk_widget_show_all (toast_box);
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
	apply_appearance ();

	{
		GtkWidget *overlay = gtk_overlay_new ();
		gtk_container_add (GTK_CONTAINER (fsapp.window), overlay);

		box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
		gtk_container_add (GTK_CONTAINER (overlay), box);

		toast_box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
		gtk_widget_set_halign (toast_box, GTK_ALIGN_END);
		gtk_widget_set_valign (toast_box, GTK_ALIGN_END);
		gtk_widget_set_margin_end (toast_box, 20);
		gtk_widget_set_margin_bottom (toast_box, 20);
		gtk_overlay_add_overlay (GTK_OVERLAY (overlay), toast_box);

		/* The command palette, above everything, hidden until
		 * Ctrl+K. */
		gtk_overlay_add_overlay (GTK_OVERLAY (overlay),
		                         build_palette ());
	}

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

	/* The pages sit in an overlay of their own, for the detail drawer
	 * (ui/fs-drawer.h): it slides in over the right edge of the page
	 * and never over the sidebar, and the toasts and the command
	 * palette, which are in the window's overlay, stay above it.  The
	 * drawer keeps to its own width at that edge (halign END), so the
	 * rest of the page still takes the mouse. */
	{
		GtkWidget *pages = gtk_overlay_new ();
		GList *chain = NULL;

		gtk_container_add (GTK_CONTAINER (pages), fsapp.notebook);
		gtk_overlay_add_overlay (GTK_OVERLAY (pages),
		                         fs_drawer_widget ());
		/* Tab goes through the page and then into the drawer, and
		 * Shift+Tab back.  Left to sort the two by where they are,
		 * GTK puts the drawer first (an overlay child counts as
		 * being at 0,0), which is between the sidebar and the page:
		 * a whole round of the window away from the list that
		 * opened it.  While the drawer is hidden it is skipped. */
		chain = g_list_append (chain, fsapp.notebook);
		chain = g_list_append (chain, fs_drawer_widget ());
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS
		gtk_container_set_focus_chain (GTK_CONTAINER (pages), chain);
		G_GNUC_END_IGNORE_DEPRECATIONS
		g_list_free (chain);
		gtk_box_pack_start (GTK_BOX (box), pages, TRUE, TRUE, 0);
	}

	g_signal_connect (fsapp.notebook, "switch-page",
	                  G_CALLBACK (on_page_switched), NULL);
	g_signal_connect_after (fsapp.window, "key-press-event",
	                        G_CALLBACK (on_window_key_after), NULL);
	g_signal_connect_after (fsapp.window, "set-focus",
	                        G_CALLBACK (on_window_focus_moved), NULL);

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

	add_page (_("Topology"),
	          _("This computer's open connections, and what the firewall "
	            "blocked in the last 10 minutes."),
	          fs_topology_page (), TRUE);
	policy = fs_policy_new ();

	/* The Events page was built above (before there was a policy to
	 * give it); its right-click Event -> Rule actions need the
	 * pointer now that it exists.  The Overview counts its rules. */
	fs_hitview_set_policy (policy);
	fs_statusview_set_policy (policy);

	settings = fs_settings_new ();
	fs_settings_load_prefs (settings);
	fs_backend_set_context (policy, settings);

	/* Threat Intel (1.0.7): every blocklist apply -- the page's and
	 * a Start's -- is held by the Overview's Lock as well as by
	 * audit-only mode; set before start_at_launch() runs. */
	fs_intelview_set_hold_func (app_intel_hold);

	/* No start here: the policy above is still EMPTY.  The Policy page
	 * below loads it from disk, Sentinel's restore then reconciles its
	 * own rows, and only then does start_at_launch() run.  Starting
	 * here installed a zero-rule policy on Linux (1.0.7 fix). */
	add_page (_("Policy"),
	          _("The rules StockFW enforces, and which addresses each "
	            "one covers."),
	          fs_policyview_page (policy), FALSE);

	/* Threat Intel (1.0.7): the blocklists. */
	add_page (_("Threat Intel"), NULL, fs_intelview_page (), FALSE);

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

	/* No subtitle: the Copilot page draws its own header (the title row
	 * carries the Sentinel switch) and brings its own scroller. */
	add_page (_("Copilot"), NULL,
	          fs_copilot_page_framed (copilot, policy), FALSE);

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

	/* No subtitle: the Nexora page draws its own header, which carries
	 * the "Preview: sample data" badge.  With one here too the page
	 * showed its title and its preview sentence twice. */
	add_page (_("Nexora"), NULL, fs_nexora_page (), FALSE);
	/* Policy loaded, Sentinel reconciled: now the firewall may start. */
	start_at_launch (due);
	fs_policy_free (due);

	/* Everything inside the window is shown now; the window itself
	 * only below, once it is known whether it may stay hidden.
	 * 1.0.9 showed the window here, so a background start (sign-in,
	 * --background) opened it on screen instead of staying in the
	 * tray.  The window's child is the overlay that holds the pages. */
	gtk_widget_show_all (gtk_bin_get_child (GTK_BIN (fsapp.window)));
	sync_nav ((guint) gtk_notebook_get_current_page (
		GTK_NOTEBOOK (fsapp.notebook)));
	/* After the show_all, which would bring back what the rail hides. */
	sidebar_apply ();
	/* The window opens with the keyboard on the search button, as it
	 * did when that was the first control in it; the fold button
	 * above it is not where a first Enter should land. */
	gtk_widget_grab_focus (side_search);

	/* The sidebar's verdict follows the Overview's. */
	fs_statusview_set_changed_cb (sync_sidebar_state, NULL);

	/* Reflect the real firewall state, if the backend knows it. */
	fs_statusview_set_state (fs_backend ()->get_state ());

	/* The lists exist now: give their rows the density Preferences
	 * asks for (apply_appearance ran before there was a page). */
	density_rows (FALSE);

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
	gtk_window_present (GTK_WINDOW (fsapp.window));
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

	/* ... and changed the list size or the history settings. */
	fs_hitview_apply_settings ();

	/* ... and switched Dark mode, the accent or the row density. */
	apply_appearance ();
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

void
fs_app_backend_settings (FsSettings *live)
{
	if (policy == NULL || settings == NULL)
		return;
	fs_backend_set_context (policy, live != NULL ? live : settings);
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