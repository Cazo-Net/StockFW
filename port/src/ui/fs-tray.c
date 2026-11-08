/*---[ fs-tray.c ]-------------------------------------------------------
 * The notification-area surface: StockFW running in the background.
 *
 * GTK3 ships exactly one tray API -- GtkStatusIcon -- deprecated since
 * 3.14 but fully wired on MSYS2: the toolkit calls Shell_NotifyIconW.
 * This whole file compiles inside the deprecation guard on purpose --
 * there is no non-deprecated replacement in GTK3.
 *
 * Whether the icon is really up is where the platforms differ.  On X11
 * gtk_status_icon_is_embedded() is the tray's own answer and
 * "notify::embedded" follows it.  On Windows there is no XEmbed: GTK
 * keeps a hidden "gtkstatusicon-observer" window, calls Shell_NotifyIconW
 * itself, answers FALSE to is_embedded() even with the icon in the tray,
 * and never notifies.  So on Windows fs_tray_active() asks the
 * notification area whether it is hosting an icon (icon_really_present),
 * and falls back to the taskbar's presence only when that cannot be
 * told.  When Explorer (re)creates its taskbar it
 * broadcasts "TaskbarCreated" and GTK adds the icon again; an elevated
 * copy lets that message through UIPI (ChangeWindowMessageFilter), or
 * a restarted Explorer would leave it with no icon for good.  While
 * the window is hidden a slow watch shows it if the tray has no icon
 * and does not get one.
 *
 * The rule that keeps the background app trustworthy: the window may
 * only hide when an icon is really up to bring it back from.  The gate
 * demands BOTH preferences AND an embedded icon -- never a hidden
 * window with no way to reopen it, which would leave the firewall
 * running as an unreachable zombie process.
 *
 * The menu (1.0.7) is what someone running StockFW in the background
 * uses instead of the window: the state and today's blocks at a glance,
 * the last few blocks, every page, pausing protection (through the
 * same confirmed path as the Overview's switch), pausing Sentinel,
 * start at sign-in, Preferences, Help, About and Quit.  Every row that
 * cannot act right now is greyed with a one-line reason as its
 * tooltip.
 *--------------------------------------------------------------------*/

#include "ui/fs-tray.h"
#include "ui/fs-app.h"
#include "ui/fs-copilot.h"
#include "ui/fs-dialogs.h"
#include "ui/fs-helpwindow.h"
#include "ui/fs-intelview.h"
#include "ui/fs-statusview.h"
#include "core/fs-autostart.h"
#include "core/fs-backend.h"
#include "core/fs-blocktally.h"
#include "core/fs-prefs.h"
#include "core/fs-i18n.h"

#ifdef G_OS_WIN32
#include <windows.h>
#include <commctrl.h>          /* TBBUTTON: the tray's toolbar buttons */
#endif
#ifdef GDK_WINDOWING_X11
#include <gdk/gdkx.h>
#endif

G_GNUC_BEGIN_IGNORE_DEPRECATIONS

/* Sentinel's tray pause. */
#define SENTINEL_PAUSE_S (60 * 60)
/* The slow refresh: the firewall's state, the tooltip's count, and
 * midnight.  STOCKFW_TRAY_REFRESH_S shortens it for the tests. */
#define TRAY_REFRESH_S   60

/* The icon (NULL = none), the window Open restores, and the firewall's
 * state and network as fs-statusview.c last reported them. */
static GtkStatusIcon  *tray_icon = NULL;
static GtkWindow      *tray_window = NULL;
static FsFirewallState tray_fw = FS_FW_NONE;
static gchar          *tray_place = NULL;
static guint           tray_timer = 0;

/* The menu, built once; the rows rewritten on every refresh. */
static GtkWidget *tray_menu = NULL;
static GtkWidget *row_firewall = NULL;
static GtkWidget *row_blocked = NULL;
static GtkWidget *recent_menu = NULL;
static GtkWidget *item_protection = NULL;
static GtkWidget *item_sentinel = NULL;
static GtkWidget *item_autostart = NULL;
static gulong     autostart_handler = 0;
static void       refresh_autostart (void);
static gchar    **recent_shown = NULL;   /* what recent_menu lists */
static gboolean   recent_empty_watching = FALSE;

/* ------------------------------------------------------------ the text */

static gboolean
firewall_on (FsFirewallState state)
{
	return state == FS_FW_RUNNING || state == FS_FW_HIT ||
	       state == FS_FW_LOCKED;
}

static gboolean
watching_events (void)
{
	const FsBackend *backend = fs_backend ();

	return backend->log_active != NULL && backend->log_active ();
}

static guint
blocked_today (void)
{
	GDateTime *now = g_date_time_new_now_local ();
	guint n = fs_block_tally_today (now);

	g_date_time_unref (now);
	return n;
}

/* "Firewall: On - Private network". */
static gchar *
header_text (void)
{
	const gchar *word;

	switch (tray_fw) {
	case FS_FW_RUNNING:
	case FS_FW_HIT:     word = _("On"); break;
	case FS_FW_LOCKED:  word = _("On, policy locked"); break;
	case FS_FW_STOPPED: word = _("Off"); break;
	case FS_FW_NONE:
	default:            word = _("state unknown"); break;
	}
	if (tray_place != NULL && firewall_on (tray_fw))
		return g_strdup_printf (_("Firewall: %s - %s"), word, tray_place);
	return g_strdup_printf (_("Firewall: %s"), word);
}

/* "Blocked today: 3" -- or why there is no count.  A zero while the
 * event monitor is not running would read as "nothing happened". */
static gchar *
blocked_text (void)
{
	guint n = blocked_today ();

	if (watching_events ())
		return g_strdup_printf (_("Blocked today: %u"), n);
	if (n > 0)
		return g_strdup_printf (_("Blocked today: %u (no longer "
		                          "watching)"), n);
	return g_strdup (_("Blocked today: not watching events"));
}

/* [ update_tooltip ] -- "StockFW - Firewall on, 3 blocked today". */
static void
update_tooltip (void)
{
	const gchar *state;
	gchar *text;

	if (tray_icon == NULL)
		return;

	state = firewall_on (tray_fw) ? _("Firewall on")
	      : tray_fw == FS_FW_STOPPED ? _("Firewall OFF")
	      : _("Firewall state unknown");
	if (watching_events ())
		text = g_strdup_printf (_("StockFW - %s, %u blocked today"),
		                        state, blocked_today ());
	else
		text = g_strdup_printf (_("StockFW - %s, not watching events"),
		                        state);
	{
		/* The blocklists, as the Threat Intel page last read them
		 * (not in force: with the reason).  Only while the firewall
		 * runs, as on the Overview: a Stop takes them down, and the
		 * page's last read may still be from before it (review
		 * T1). */
		gchar *intel = firewall_on (tray_fw) ? fs_intelview_summary ()
		                                     : NULL;

		if (intel != NULL) {
			gchar *both = g_strdup_printf ("%s\n%s", text, intel);

			g_free (text);
			text = both;
			g_free (intel);
		}
	}

	gtk_status_icon_set_tooltip_text (tray_icon, text);
	g_free (text);
}

/* ------------------------------------------------------------- actions */

/* The window when it is on screen, else no parent: a dialog parented
 * to a hidden window would not show. */
static GtkWidget *
dialog_parent (void)
{
	if (tray_window != NULL &&
	    gtk_widget_get_visible (GTK_WIDGET (tray_window)))
		return GTK_WIDGET (tray_window);
	return NULL;
}

static void
menu_open_activated (GtkMenuItem *item, gpointer data)
{
	(void) item;
	(void) data;

	fs_tray_show_window ();
}

static void
go_to (FsAppPage page)
{
	fs_tray_show_window ();
	fs_app_show_page (page);
}

static void
menu_page_activated (GtkMenuItem *item, gpointer data)
{
	(void) item;

	go_to ((FsAppPage) GPOINTER_TO_INT (data));
}

/* A recent block: the Events page lists it with everything else. */
static void
menu_recent_activated (GtkMenuItem *item, gpointer data)
{
	(void) item;
	(void) data;

	go_to (FS_PAGE_EVENTS);
}

/* Pause / Resume: the Overview's own start and stop, so the stop is
 * confirmed in the same dialog and both go through the gate and the
 * audit log the same way. */
static void
menu_protection_activated (GtkMenuItem *item, gpointer data)
{
	(void) item;
	(void) data;

	if (tray_fw == FS_FW_STOPPED)
		fs_statusview_firewall_start (dialog_parent (), "tray");
	else
		fs_statusview_firewall_stop (dialog_parent (), "tray");
	fs_tray_refresh ();
}

static void
menu_sentinel_activated (GtkMenuItem *item, gpointer data)
{
	(void) item;
	(void) data;

	fs_copilot_sentinel_pause (fs_copilot_sentinel_paused (NULL)
	                           ? 0 : SENTINEL_PAUSE_S);
	fs_tray_refresh ();
}

static void
menu_autostart_toggled (GtkCheckMenuItem *item, gpointer data)
{
	gboolean want = gtk_check_menu_item_get_active (item);
	GError *error = NULL;

	(void) data;

	if (!fs_autostart_set (want, &error)) {
		fs_dialogs_error (dialog_parent (),
		                  want ? _("StockFW could not be set to start "
		                           "at sign-in")
		                       : _("StockFW could not stop starting "
		                           "at sign-in"),
		                  error != NULL ? error->message : NULL);
		g_clear_error (&error);
	}
	/* Whatever happened, the tick shows what is now true -- not what
	 * was asked for -- and so does an open Preferences window. */
	refresh_autostart ();
	fs_dialogs_preferences_autostart_changed ();
}

static void
menu_preferences_activated (GtkMenuItem *item, gpointer data)
{
	(void) item;
	(void) data;

	if (tray_window == NULL)
		return;
	fs_tray_show_window ();
	fs_dialogs_preferences (GTK_WIDGET (tray_window));
}

/* Help opens the Help window at "Running in the background", the
 * topic about this icon and this menu.  It is not transient for the
 * main window and needs no window shown, so in background mode it
 * opens on its own and the main window stays hidden. */
static void
menu_help_activated (GtkMenuItem *item, gpointer data)
{
	(void) item;
	(void) data;

	fs_help_show (dialog_parent (), "background");
}

/* The same dialog Help > About opens, parented the same way. */
static void
menu_about_activated (GtkMenuItem *item, gpointer data)
{
	(void) item;
	(void) data;

	if (tray_window == NULL)
		return;

	fs_dialogs_about (GTK_WIDGET (tray_window));
}

/* The way out of background mode.  Quitting never stops the firewall;
 * the label says so, because "quit the firewall program" reads like
 * "turn the firewall off". */
static void
menu_quit_activated (GtkMenuItem *item, gpointer data)
{
	(void) item;
	(void) data;

	fs_app_quit ();
}

/* ------------------------------------------------------------- refresh */

static void
set_reason (GtkWidget *item, gboolean can, const gchar *why)
{
	gtk_widget_set_sensitive (item, can);
	gtk_widget_set_tooltip_text (item, can ? NULL : why);
}

static gboolean
same_rows (gchar **a, gchar **b)
{
	if (a == NULL || b == NULL)
		return a == b;
	return g_strv_equal ((const gchar * const *) a,
	                     (const gchar * const *) b);
}

/* Rebuilt only when the list changed: a submenu the user is looking
 * at is not rebuilt under the pointer by the slow timer. */
static void
refresh_recent (void)
{
	GList *old;
	gchar **rows = fs_block_tally_recent ();
	GtkWidget *item;

	/* Unchanged: same rows, and for the empty list the same reason. */
	if (recent_shown != NULL && same_rows (rows, recent_shown) &&
	    (rows[0] != NULL || watching_events () == recent_empty_watching)) {
		g_strfreev (rows);
		return;
	}
	recent_empty_watching = watching_events ();
	old = gtk_container_get_children (GTK_CONTAINER (recent_menu));
	for (GList *l = old; l != NULL; l = l->next)
		gtk_widget_destroy (GTK_WIDGET (l->data));
	g_list_free (old);

	for (guint i = 0; rows[i] != NULL; i++) {
		item = gtk_menu_item_new_with_label (rows[i]);
		gtk_widget_set_tooltip_text (item, _("Show it on the Events "
		                                     "page"));
		g_signal_connect (item, "activate",
		                  G_CALLBACK (menu_recent_activated), NULL);
		gtk_menu_shell_append (GTK_MENU_SHELL (recent_menu), item);
	}
	if (rows[0] == NULL) {
		item = gtk_menu_item_new_with_label (
			watching_events ()
			? _("Nothing blocked since StockFW started")
			: _("Not watching events, so nothing to show"));
		gtk_widget_set_sensitive (item, FALSE);
		gtk_menu_shell_append (GTK_MENU_SHELL (recent_menu), item);
	}
	g_strfreev (recent_shown);
	recent_shown = rows;
	gtk_widget_show_all (recent_menu);
}

/* The reason a row that changes the firewall is greyed in a copy
 * without the rights to (the Windows backend reads the firewall
 * without elevation, so "available" alone would enable rows that only
 * fail after their confirmation). */
static const gchar *
needs_rights_reason (void)
{
#ifdef G_OS_WIN32
	return _("Needs StockFW running as administrator.");
#else
	return _("Needs StockFW started with sudo.");
#endif
}

static void
refresh_protection (void)
{
	gboolean available = fs_app_can_change_firewall ();

	gtk_menu_item_set_label (GTK_MENU_ITEM (item_protection),
	                         tray_fw == FS_FW_STOPPED
	                         ? _("_Resume protection")
	                         : _("_Pause protection..."));
	if (!available)
		set_reason (item_protection, FALSE, needs_rights_reason ());
	else if (tray_fw == FS_FW_NONE)
		set_reason (item_protection, FALSE,
		            _("The firewall's state could not be read."));
	else
		set_reason (item_protection, TRUE, NULL);
}

static void
refresh_sentinel (void)
{
	gint64 left = 0;

	if (fs_copilot_sentinel_paused (&left)) {
		gchar *label = g_strdup_printf (
			_("Resume Sentinel auto-block (paused, %d min left)"),
			(gint) ((left + 59) / 60));

		gtk_menu_item_set_label (GTK_MENU_ITEM (item_sentinel), label);
		g_free (label);
		set_reason (item_sentinel, TRUE, NULL);
		return;
	}
	gtk_menu_item_set_label (GTK_MENU_ITEM (item_sentinel),
	                         _("Pause Sentinel auto-block for 1 hour"));
	/* Only where Sentinel could block at all: it acts on events this
	 * copy watches, through rules this copy may apply. */
	if (!fs_app_can_change_firewall ())
		set_reason (item_sentinel, FALSE, needs_rights_reason ());
	else if (!watching_events ())
		set_reason (item_sentinel, FALSE,
		            _("Sentinel is not watching events here, so it "
		              "has nothing to block."));
	else
		set_reason (item_sentinel, fs_copilot_sentinel_can_pause (),
		            _("Sentinel is not blocking anything automatically "
		              "(it is in detect-only mode)."));
}

static void
refresh_autostart (void)
{
	gchar *why = NULL;
	gboolean can = fs_autostart_supported () &&
	               fs_autostart_can_change (&why);

	g_signal_handler_block (item_autostart, autostart_handler);
	gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (item_autostart),
	                                fs_autostart_enabled ());
	g_signal_handler_unblock (item_autostart, autostart_handler);

	gtk_widget_set_sensitive (item_autostart, can);
	gtk_widget_set_tooltip_text (item_autostart,
	                             can ? fs_autostart_description ()
	                                 : (why != NULL ? why
	                                    : _("Not available on this "
	                                        "system.")));
	g_free (why);
}

/* [ refresh_rows ] -- the cheap part, on every state change and
 * block: the two information rows, the recent list, and the two rows
 * whose label or sensitivity follows the state. */
static void
refresh_rows (void)
{
	gchar *text;

	if (tray_menu == NULL)
		return;

	text = header_text ();
	gtk_menu_item_set_label (GTK_MENU_ITEM (row_firewall), text);
	g_free (text);
	text = blocked_text ();
	gtk_menu_item_set_label (GTK_MENU_ITEM (row_blocked), text);
	g_free (text);

	refresh_recent ();
	refresh_protection ();
	refresh_sentinel ();
}

/* [ refresh_menu ] -- everything, at popup time: no row is trusted
 * from build time.  The firewall can be stopped, hit or locked between
 * one right-click and the next, and a security tool whose menu
 * misstates the state of the firewall is worse than one with no menu
 * at all.  Start at sign-in is read here only (on Windows it asks the
 * Task Scheduler). */
static void
refresh_menu (void)
{
	if (tray_menu == NULL)
		return;

	/* The firewall itself, asked again: it may have been stopped from
	 * a terminal or the system's own settings since the last look.
	 * That updates tray_fw (and the Overview) through
	 * fs_tray_set_firewall() when it changed. */
	fs_statusview_reread_state ();
	refresh_rows ();
	refresh_autostart ();
}

/* ---------------------------------------------------------------- menu */

static GtkWidget *
append_item (GtkWidget *menu, const gchar *mnemonic, GCallback cb,
             gpointer data)
{
	GtkWidget *item = gtk_menu_item_new_with_mnemonic (mnemonic);

	if (cb != NULL)
		g_signal_connect (item, "activate", cb, data);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
	return item;
}

static void
append_separator (GtkWidget *menu)
{
	gtk_menu_shell_append (GTK_MENU_SHELL (menu),
	                       gtk_separator_menu_item_new ());
}

static GtkWidget *
append_info_row (GtkWidget *menu)
{
	GtkWidget *row = gtk_menu_item_new_with_label ("");

	/* Greyed on purpose: a greyed row reads as information, an
	 * enabled one that does nothing reads as a broken control. */
	gtk_widget_set_sensitive (row, FALSE);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), row);
	return row;
}

/* [ build_menu ] -- state first, then what to look at, then what to
 * change, then the dialogs, then the way out behind its own separator
 * so it cannot be hit while going for About.  Built once and reused,
 * with only the rows rewritten, so a menu the shell is displaying is
 * never pulled out from under it. */
static void
build_menu (void)
{
	static const struct { const gchar *label; FsAppPage page; } pages[] = {
		{ N_("Overview"), FS_PAGE_OVERVIEW },
		{ N_("Events"),   FS_PAGE_EVENTS },
		{ N_("Activity"), FS_PAGE_ACTIVITY },
		{ N_("Policy"),   FS_PAGE_POLICY },
		{ N_("Copilot"),  FS_PAGE_COPILOT },
		{ N_("Trust"),    FS_PAGE_TRUST },
	};
	GtkWidget *item, *sub;

	tray_menu = gtk_menu_new ();

	row_firewall = append_info_row (tray_menu);
	row_blocked = append_info_row (tray_menu);

	item = append_item (tray_menu, _("_Recent blocks"), NULL, NULL);
	recent_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (item), recent_menu);

	append_separator (tray_menu);

	append_item (tray_menu, _("_Open StockFW"),
	             G_CALLBACK (menu_open_activated), NULL);
	item = append_item (tray_menu, _("_Go to"), NULL, NULL);
	sub = gtk_menu_new ();
	for (guint i = 0; i < G_N_ELEMENTS (pages); i++)
		append_item (sub, _(pages[i].label),
		             G_CALLBACK (menu_page_activated),
		             GINT_TO_POINTER (pages[i].page));
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (item), sub);

	append_separator (tray_menu);

	item_protection = append_item (tray_menu, _("_Pause protection..."),
	                               G_CALLBACK (menu_protection_activated),
	                               NULL);
	item_sentinel = append_item (tray_menu,
	                             _("Pause Sentinel auto-block for 1 hour"),
	                             G_CALLBACK (menu_sentinel_activated),
	                             NULL);
	item_autostart = gtk_check_menu_item_new_with_mnemonic (
		_("_Start at sign-in"));
	autostart_handler = g_signal_connect (
		item_autostart, "toggled",
		G_CALLBACK (menu_autostart_toggled), NULL);
	gtk_menu_shell_append (GTK_MENU_SHELL (tray_menu), item_autostart);

	append_separator (tray_menu);

	append_item (tray_menu, _("Pr_eferences..."),
	             G_CALLBACK (menu_preferences_activated), NULL);
	append_item (tray_menu, _("_Help"),
	             G_CALLBACK (menu_help_activated), NULL);
	append_item (tray_menu, _("_About StockFW"),
	             G_CALLBACK (menu_about_activated), NULL);

	append_separator (tray_menu);

	append_item (tray_menu, _("_Quit (firewall stays on)"),
	             G_CALLBACK (menu_quit_activated), NULL);

	gtk_widget_show_all (tray_menu);
	refresh_menu ();
}

/* ---------------------------------------------------------------- icon */

/* [ on_activate ] -- left click restores the window. */
static void
on_activate (GtkStatusIcon *icon, gpointer data)
{
	(void) icon;
	(void) data;

	fs_tray_show_window ();
}

/* [ position_menu ] -- the status icon's own placement, then kept on
 * the monitor at the width the menu has NOW.  The rows are relabelled
 * just before every popup ("Resume Sentinel auto-block (paused, 60 min
 * left)" is much wider than "Pause ..."), and the first popup after a
 * row grew was otherwise placed for the old width: cut off at the
 * screen edge, its submenu arrows out of sight. */
static void
position_menu (GtkMenu *menu, gint *x, gint *y, gboolean *push_in,
               gpointer icon)
{
	GtkRequisition natural;
	GdkMonitor *monitor;
	GdkRectangle area;

	gtk_status_icon_position_menu (menu, x, y, push_in, icon);

	gtk_widget_get_preferred_size (GTK_WIDGET (menu), NULL, &natural);
	monitor = gdk_display_get_monitor_at_point (
		gtk_widget_get_display (GTK_WIDGET (menu)), *x, *y);
	if (monitor == NULL)
		return;
	gdk_monitor_get_workarea (monitor, &area);
	if (*x + natural.width > area.x + area.width)
		*x = MAX (area.x, area.x + area.width - natural.width);
}

/* [ on_popup_menu ] -- right click opens the menu, freshly read,
 * positioned on the icon the way a notification-area menu must be. */
static void
on_popup_menu (GtkStatusIcon *icon, guint button, guint activate_time,
               gpointer data)
{
	GtkWidget *menu;

	(void) data;

	update_tooltip ();
	menu = fs_tray_menu ();
	/* Measured again now, before it is placed: see position_menu. */
	gtk_widget_queue_resize (menu);
	gtk_menu_popup (GTK_MENU (menu), NULL, NULL, position_menu, icon,
	                button, activate_time);
}

/* [ lost_icon_check ] -- the shell dropped our icon (Explorer
 * restarted, the panel crashed) while the window was hidden behind
 * it.  Shells usually take the icon back within a moment; if this one
 * has not after a few seconds, the window comes back instead, so the
 * running app never ends up with no way in. */
static guint lost_icon_timeout = 0;

static gboolean
lost_icon_check (gpointer data)
{
	(void) data;

	lost_icon_timeout = 0;
	if (tray_icon != NULL && !fs_tray_active () && tray_window != NULL &&
	    !gtk_widget_get_visible (GTK_WIDGET (tray_window)))
		fs_tray_window_back ("the shell dropped the icon");
	return G_SOURCE_REMOVE;
}

static void
on_embedded_changed (GObject *icon, GParamSpec *pspec, gpointer data)
{
	(void) icon;
	(void) pspec;
	(void) data;

	if (!fs_tray_active () && lost_icon_timeout == 0)
		lost_icon_timeout = g_timeout_add_seconds (5, lost_icon_check,
		                                           NULL);
}

/* The slow timer: the firewall's state asked again, the tooltip's
 * count, and midnight resetting it.  It runs with or without an icon
 * (fs_tray_sync); the debug line is what tests/test-notray.sh reads. */
static gboolean
on_refresh_timer (gpointer data)
{
	(void) data;

	g_debug ("slow refresh: the firewall's state read again%s",
	         tray_icon != NULL ? "" : " (no tray icon)");
	fs_statusview_reread_state ();
	fs_tray_refresh ();
	return G_SOURCE_CONTINUE;
}

#ifdef G_OS_WIN32
/* [ taskbar_up ] -- Explorer's taskbar, which holds the notification
 * area, exists.  No taskbar, no icon, whatever GTK says. */
static gboolean
taskbar_up (void)
{
	return FindWindowW (L"Shell_TrayWnd", NULL) != NULL;
}

/* [ icon_really_present ] -- is GTK's icon actually in the tray?
 *
 * GtkStatusIcon is an XEmbed client, but Windows has no XEmbed: GTK
 * creates a "gtkstatusicon-observer" window and calls Shell_NotifyIconW
 * itself, and never tells anyone whether the shell accepted it.
 * Measured: on Windows 11 that observer window exists and is hidden, the
 * icon is in the tray, and gtk_status_icon_is_embedded() still answers
 * FALSE.  So neither GTK's answer nor "is there a taskbar" describes our
 * own icon, and the second one was wrong the other way: it let the
 * window hide on a machine where the tray had refused the icon, which is
 * the hidden firewall nobody can reach (fs-tray.h).
 *
 * The question is asked of the notification area instead.  Windows 11
 * builds it from XAML, so ask whether the icon is hosted there; older
 * shells keep the icons as a toolbar, so fall back to counting that
 * toolbar's buttons.  When the answer cannot be worked out the taskbar's
 * presence is the answer, as before: this must not invent a refusal and
 * start a window nobody asked for. */
#ifndef TB_BUTTONCOUNT
#define TB_BUTTONCOUNT (WM_USER + 24)
#endif
#ifndef TB_GETBUTTON
#define TB_GETBUTTON (WM_USER + 23)
#endif

static gboolean
has_xaml_icons (HWND notify_wnd)
{
	static const gchar *const classes[] = {
		"Microsoft.UI.Content.DesktopChildSiteBridge",
		"Windows.UI.Composition.DesktopWindowContentBridge",
		"Windows.UI.Core.CoreWindow",
		NULL
	};

	for (const gchar *const *c = classes; *c != NULL; c++) {
		if (FindWindowExA (notify_wnd, NULL, *c, NULL) != NULL)
			return TRUE;
	}

	return FALSE;
}

/* Explorer's own XAML island beside the taskbar.  It is a top-level
 * window of Explorer, not a child of the taskbar. */
static gboolean
xaml_island_has_room (void)
{
	HWND island = FindWindowW (L"XamlExplorerHostIslandWindow_WASDK",
	                           NULL);
	RECT r;

	if (island == NULL)
		return FALSE;
	if (!GetWindowRect (island, &r))
		return FALSE;

	/* An empty collapse flyout is about one icon tall; the tray with
	 * icons in it is taller.  40 px is deliberately well below one
	 * icon row at any ordinary scaling. */
	g_debug ("tray island %ldx%ld", (long) (r.right - r.left),
	         (long) (r.bottom - r.top));
	return (r.bottom - r.top) >= 40;
}

/* Ask a toolbar in another process how many buttons it has.  The tool's
 * thread answers; anything else (no access, no such thing) reads as
 * none, which is only ever a reason to fall back. */
static LRESULT
toolbar_button_count (HWND toolbar)
{
	DWORD pid = 0;
	HANDLE process;
	LRESULT count = 0;

	if (GetWindowThreadProcessId (toolbar, &pid) == 0 || pid == 0)
		return 0;
	process = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (process == NULL)
		return 0;
	if (!SendMessageTimeoutA (toolbar, TB_BUTTONCOUNT, 0, 0,
	                          SMTO_ABORTIFHUNG, 1000,
	                          (PDWORD_PTR) &count))
		count = 0;
	CloseHandle (process);

	return count;
}

static gboolean
toolbar_has_buttons (HWND notify_wnd)
{
	static const gchar *const names[] = {
		"ToolbarWindow32",
		"ToolbarWindow64",
		NULL
	};

	for (const gchar *const *n = names; *n != NULL; n++) {
		HWND toolbar = FindWindowExA (notify_wnd, NULL, *n, NULL);

		if (toolbar == NULL)
			continue;
		if (toolbar_button_count (toolbar) > 0)
			return TRUE;
	}

	return FALSE;
}

static gboolean
icon_really_present (void)
{
	HWND taskbar = FindWindowW (L"Shell_TrayWnd", NULL);
	HWND notify_wnd;

	if (taskbar == NULL)
		return FALSE;          /* no taskbar: nowhere for an icon */
	notify_wnd = FindWindowExA (taskbar, NULL, "TrayNotifyWnd", NULL);
	if (notify_wnd == NULL)
		return TRUE;           /* old or odd shell: taskbar's word */

	/* The toolbar came first and is still what a classic shell, a
	 * remote session or a third-party taskbar uses.  Unless a toolbar
	 * there is empty, its buttons are the answer -- met "is there any
	 * icon in the tray". */
	if (toolbar_has_buttons (notify_wnd))
		return TRUE;

	/* Windows 11: the tray is XAML, and the Island window beside the
	 * taskbar hosts it.  Its mere existence proves nothing (measured:
	 * it is there with the window empty), so size it: an empty
	 * collapse flyout is about one icon tall, and a tray with icons in
	 * it is taller. */
	if (has_xaml_icons (notify_wnd) && xaml_island_has_room ())
		return TRUE;

	return taskbar_up ();
}

/* [ win32_icon_watch ] -- the Windows half of lost_icon_check (GTK
 * never notifies there): every few seconds while the window is hidden.
 * Two misses in a row with no icon in the tray bring the window up.
 *
 * If no tray icon has appeared yet, which is the normal state for the
 * first seconds after start-up and after a fresh sign-in, it waits
 * longer before giving up instead of racing start-up: a window that
 * comes up on its own while the icon was about to arrive is as
 * confusing as one that never comes back. */
static guint win32_watch = 0;
static guint win32_misses = 0;

#define WIN32_MISSES_LOST   2      /* icon was there, then gone      */
#define WIN32_MISSES_NEVER  20     /* no icon since the window hid   */

static gboolean
win32_icon_watch (gpointer data)
{
	guint limit;

	(void) data;

	if (tray_icon == NULL || tray_window == NULL ||
	    gtk_widget_get_visible (GTK_WIDGET (tray_window))) {
		win32_misses = 0;
		return G_SOURCE_CONTINUE;
	}
	if (icon_really_present ()) {
		win32_misses = 0;
		return G_SOURCE_CONTINUE;
	}

	/* The taskbar is gone: a restarting Explorer takes the icon with
	 * it and adds it back from "TaskbarCreated", so give that a little
	 * while.  The taskbar up with no icon in it is the shell refusing
	 * it, and only a long wait makes that trustworthy. */
	limit = taskbar_up () ? WIN32_MISSES_NEVER : WIN32_MISSES_LOST;
	if (++win32_misses >= limit) {
		win32_misses = 0;
		fs_tray_window_back (taskbar_up ()
		                     ? "the tray has no icon to come back from"
		                     : "the taskbar went and did not come back");
	}
	return G_SOURCE_CONTINUE;
}
#endif

static guint
refresh_period (void)
{
	const gchar *env = g_getenv ("STOCKFW_TRAY_REFRESH_S");

	if (env != NULL && *env != '\0') {
		gchar *end = NULL;
		guint64 v = g_ascii_strtoull (env, &end, 10);

		if (end != NULL && *end == '\0' && v >= 1 && v <= 86400)
			return (guint) v;
	}
	return TRAY_REFRESH_S;
}

/* [ fs_tray_supported ] -- can this desktop hold a tray icon at all?
 * GtkStatusIcon has a notification area only on X11 (the XEmbed tray)
 * and on Windows.  On Wayland -- GNOME, KDE Plasma, WSL's WSLg -- and
 * on Broadway GTK has none: the icon would never show, and creating it
 * prints "Gtk-CRITICAL: gtk_widget_get_scale_factor: assertion
 * 'GTK_IS_WIDGET (widget)' failed" at every start.  There no icon is
 * made, so the window stays the way in and closing it quits
 * (fs_tray_hide_on_close fails closed without an icon). */
gboolean
fs_tray_supported (void)
{
#ifdef G_OS_WIN32
	return TRUE;
#elif defined GDK_WINDOWING_X11
	GdkDisplay *display = gdk_display_get_default ();

	return display != NULL && GDK_IS_X11_DISPLAY (display);
#else
	return FALSE;
#endif
}

/* [ create_icon ] -- only from fs_tray_sync(), window already known.
 * The icon reuses the window's logo so the tray and the title bar
 * agree; the themed fallback covers a window without one.  Nothing is
 * made where the desktop has no tray (fs_tray_supported). */
static void
create_icon (void)
{
	GdkPixbuf *logo;

	if (!fs_tray_supported ()) {
		g_debug ("no tray icon: this desktop (GDK backend %s) has no "
		         "notification area GTK can use",
		         gdk_display_get_default () != NULL
		         ? G_OBJECT_TYPE_NAME (gdk_display_get_default ())
		         : "none");
		return;
	}

	logo = gtk_window_get_icon (tray_window);

	tray_icon = logo != NULL
	          ? gtk_status_icon_new_from_pixbuf (logo)
	          : gtk_status_icon_new_from_icon_name ("applications-system");

	g_signal_connect (tray_icon, "activate", G_CALLBACK (on_activate),
	                  NULL);
	g_signal_connect (tray_icon, "popup-menu",
	                  G_CALLBACK (on_popup_menu), NULL);
	g_signal_connect (tray_icon, "notify::embedded",
	                  G_CALLBACK (on_embedded_changed), NULL);
	update_tooltip ();
#ifdef G_OS_WIN32
	/* An elevated copy does not receive a medium-integrity Explorer's
	 * broadcasts unless it says so; without "TaskbarCreated" GTK never
	 * re-adds the icon after Explorer restarts. */
	ChangeWindowMessageFilter (RegisterWindowMessageW (L"TaskbarCreated"),
	                           MSGFLT_ADD);
	if (win32_watch == 0)
		win32_watch = g_timeout_add_seconds (3, win32_icon_watch, NULL);
#endif
}

/* [ destroy_icon ] -- visible=FALSE first so the shell drops the icon
 * before the object goes; then release our reference. */
static void
destroy_icon (void)
{
#ifdef G_OS_WIN32
	if (win32_watch != 0) {
		g_source_remove (win32_watch);
		win32_watch = 0;
	}
#endif
	if (tray_icon == NULL)
		return;

	/* Taken down on purpose: not a lost icon to recover from. */
	g_signal_handlers_disconnect_by_func (tray_icon,
	                                      G_CALLBACK (on_embedded_changed),
	                                      NULL);
	gtk_status_icon_set_visible (tray_icon, FALSE);
	g_clear_object (&tray_icon);
}

/* ------------------------------------------------------------- the API */

void
fs_tray_set_window (GtkWindow *window)
{
	tray_window = window;
}

/* [ fs_tray_sync ] -- the icon follows the preference both ways:
 * accepting Preferences with the box ticked brings it up, unticking
 * takes it down while the program keeps running. */
void
fs_tray_sync (void)
{
	gboolean want;

	if (tray_window == NULL)
		return;

	/* The slow timer runs whenever the window is known, icon or not:
	 * it is also how the Overview and the sidebar learn of a firewall
	 * stopped from outside (`stockfw stop' in a terminal,
	 * fs-statusview.h), which a desktop with no tray (Wayland) or the
	 * tray switched off must not lose.  Only fs_tray_uninstall()
	 * stops it. */
	if (tray_timer == 0)
		tray_timer = g_timeout_add_seconds (refresh_period (),
		                                    on_refresh_timer, NULL);

	want = fs_prefs_bool (FS_PREFS_ENABLE_TRAY_ICON);

	if (want && tray_icon == NULL)
		create_icon ();
	else if (!want && tray_icon != NULL)
		destroy_icon ();
}

void
fs_tray_uninstall (void)
{
	if (tray_timer != 0) {
		g_source_remove (tray_timer);
		tray_timer = 0;
	}
	destroy_icon ();
}

/* [ fs_tray_active ] -- "an icon is really up": the object exists AND
 * the shell can be holding it.  The second half is the honest one -- a
 * shell that refused the icon reads as not active, so nothing
 * downstream hides the window on its strength.  X11: the tray's own
 * answer.  Windows: GTK always says embedded there, so the notification
 * area is asked directly (icon_really_present above). */
gboolean
fs_tray_active (void)
{
	if (tray_icon == NULL)
		return FALSE;
#ifdef G_OS_WIN32
	return icon_really_present ();
#else
	return gtk_status_icon_is_embedded (tray_icon);
#endif
}

/* [ fs_tray_hide_on_close ] -- the gate behind close/minimize to tray.
 * All three must hold: the preference asked for it, an icon object
 * exists, and that icon is embedded with the shell.  FALSE with no
 * icon, always: closing the window then quits the program instead of
 * stranding it invisible. */
gboolean
fs_tray_hide_on_close (void)
{
	return fs_prefs_bool (FS_PREFS_MINIMIZE_TO_TRAY) &&
	       fs_tray_active ();
}

void
fs_tray_show_window (void)
{
	if (tray_window == NULL)
		return;

	/* Show, un-minimize, raise -- in that order: a window minimized
	 * behind the icon comes back iconified if it is only shown. */
	gtk_widget_show (GTK_WIDGET (tray_window));
	gtk_window_deiconify (tray_window);
	gtk_window_present (tray_window);
}

/* [ fs_tray_window_back ] -- `reason' is why the window is being brought
 * up without the user asking.  Bringing it up on its own is surprising,
 * and in a session with no folder to open it silently does nothing, so
 * the reason is logged where test-notray.sh and a bug report can see it. */
void
fs_tray_window_back (const gchar *reason)
{
	if (tray_window == NULL)
		return;

	g_message ("bringing the window back: %s",
	           reason != NULL ? reason : "no reason given");
	fs_tray_show_window ();
}

void
fs_tray_set_firewall (FsFirewallState state, const gchar *place)
{
	tray_fw = state;
	g_free (tray_place);
	tray_place = place != NULL && *place != '\0' ? g_strdup (place) : NULL;
	/* The header follows the state here as well as at popup time, so
	 * a menu left open cannot keep showing a stale verdict. */
	fs_tray_refresh ();
}

void
fs_tray_refresh (void)
{
	update_tooltip ();
	refresh_rows ();
}

/* [ fs_tray_autostart_changed ] -- Preferences changed start at
 * sign-in.  Nothing to do before the menu exists: building it reads the
 * setting. */
void
fs_tray_autostart_changed (void)
{
	if (item_autostart != NULL)
		refresh_autostart ();
}

/* [ fs_tray_menu ] -- the popup, built on first use. */
GtkWidget *
fs_tray_menu (void)
{
	if (tray_menu == NULL)
		build_menu ();
	else
		refresh_menu ();

	return tray_menu;
}

GtkStatusIcon *
fs_tray_icon (void)
{
	return tray_icon;
}

G_GNUC_END_IGNORE_DEPRECATIONS
