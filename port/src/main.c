/*---[ main.c ]---------------------------------------------------------
 * Entry point.
 *
 * The original used popt for command line parsing plus
 * gnome_program_init() and gnome_master_client() for session
 * management.  Both are gone from modern GNOME; GLib's GOptionContext
 * and GtkApplication cover what is actually needed.
 *
 * One StockFW per user (core/fs-instance.h): a second launch asks the
 * first to show its window and exits, and --quit asks it to quit
 * cleanly -- the uninstaller's way to stop it with its settings saved.
 * A launch with MORE privileges than the running copy (`sudo StockFW',
 * "StockFW (Elevated)") asks it to quit and takes its place instead:
 * the copy started at sign-in runs without them, and raising its
 * window would not give the user what they elevated for.  None of
 * this needs a display, so it runs before GTK.
 *
 * --enable-autostart / --disable-autostart switch "start at sign-in"
 * for the current user and exit (core/fs-autostart.h); the Windows
 * installer runs the first, the uninstaller --remove-all-autostart.
 *
 * The end of the session (the session manager's query-end, Windows'
 * WM_QUERYENDSESSION) and SIGTERM/SIGINT/SIGHUP save what the running
 * copy holds without touching the firewall: see fs-app.c.
 *--------------------------------------------------------------------*/

#include <gtk/gtk.h>
#include <locale.h>

#ifndef G_OS_WIN32
#include <glib-unix.h>
#include <signal.h>
#endif

#include "core/fs-prefs.h"
#include "core/fs-backend.h"
#include "core/fs-instance.h"
#include "core/fs-autostart.h"
#include "core/fs-i18n.h"
#include "ui/fs-app.h"
#include "ui/fs-dialogs.h"

#ifndef FS_VERSION
#define FS_VERSION "1.0.6"
#endif

static gboolean opt_version = FALSE;
static gboolean opt_quit = FALSE;
static gboolean opt_background = FALSE;
static gboolean opt_autostart_on = FALSE;
static gboolean opt_autostart_off = FALSE;
static gboolean opt_autostart_purge = FALSE;

static const GOptionEntry options[] = {
	{ "version", 'V', 0, G_OPTION_ARG_NONE, &opt_version,
	  "Show the program version and exit", NULL },
	{ "background", 'b', 0, G_OPTION_ARG_NONE, &opt_background,
	  "Start in the notification area with the window hidden (it is "
	  "shown if no notification area takes the icon)", NULL },
	{ "minimized", 'm', 0, G_OPTION_ARG_NONE, &opt_background,
	  "Same as --background", NULL },
	{ "quit", 0, 0, G_OPTION_ARG_NONE, &opt_quit,
	  "Ask the running StockFW to quit (the firewall stays on)", NULL },
	{ "enable-autostart", 0, 0, G_OPTION_ARG_NONE, &opt_autostart_on,
	  "Start StockFW in the background when you sign in, then exit", NULL },
	{ "disable-autostart", 0, 0, G_OPTION_ARG_NONE, &opt_autostart_off,
	  "Stop starting StockFW when you sign in, then exit", NULL },
	{ "remove-all-autostart", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE,
	  &opt_autostart_purge,
	  "Remove start at sign-in for every user (uninstaller)", NULL },
	{ NULL, 0, 0, 0, NULL, NULL, NULL }
};

/* [ on_activate ] */
static void
on_activate (GtkApplication *app, gpointer data)
{
	fs_app_activate (app);
}

/* [ on_instance_command ] -- a later launch (or the uninstaller)
 * reached us through the instance channel. */
static void
on_instance_command (FsInstanceCommand command, gpointer data)
{
	(void) data;

	if (command == FS_INSTANCE_QUIT)
		fs_app_quit ();
	else
		fs_app_present ();
}

#ifndef G_OS_WIN32
/* [ on_quit_signal ] -- SIGTERM (systemd ending the session, a logout
 * without a session manager, kill), SIGINT (Ctrl+C in the terminal it
 * was started from) and SIGHUP (that terminal closed) quit the way the
 * tray's Quit does: settings and what the Copilot learned are written
 * and the firewall stays on.  They used to end the process on the
 * spot.  The source stays: a second signal while quitting is a no-op
 * rather than the default action.  A SIGHUP that was ignored when we
 * started (nohup) stays ignored. */
static gboolean
on_quit_signal (gpointer data)
{
	(void) data;

	fs_app_quit ();
	return G_SOURCE_CONTINUE;
}
#endif

/* [ quit_running ] -- --quit: ask, then wait for it to be gone, so a
 * caller (the uninstaller) can delete the files right after.  Exit 0
 * when nothing runs any more, 1 when it refused or would not go. */
static int
quit_running (void)
{
	switch (fs_instance_send (FS_INSTANCE_QUIT, 3000)) {
	case FS_INSTANCE_NONE_RUNNING:
		g_print ("StockFW is not running.\n");
		return 0;
	case FS_INSTANCE_SENT:
		if (fs_instance_wait_gone (15000)) {
			g_print ("StockFW has quit.  The firewall stays on.\n");
			return 0;
		}
		g_printerr ("StockFW was asked to quit but is still "
		            "running.\n");
		return 1;
	case FS_INSTANCE_REFUSED:
		g_printerr ("The running StockFW refused to quit: it runs with "
		            "more privileges than this command.\n");
		return 1;
	case FS_INSTANCE_UNREACHABLE:
	default:
		g_printerr ("StockFW is running but could not be reached.\n");
		return 1;
	}
}

/* [ take_over ] -- the running copy has fewer privileges than this
 * one: ask it to quit (root and administrators may), wait for it to be
 * gone, and claim the name.  If it will not make way, run beside it
 * -- as every copy did before 1.0.7 -- rather than leave the user
 * without a copy that can change the firewall. */
static FsInstanceRole
take_over (void)
{
#ifdef G_OS_WIN32
	const gchar *what = "administrator rights";
#else
	const gchar *what = "root";
#endif
	FsInstanceRole role;

	switch (fs_instance_send (FS_INSTANCE_QUIT, 3000)) {
	case FS_INSTANCE_SENT:
		if (!fs_instance_wait_gone (15000))
			break;
		/* fall through */
	case FS_INSTANCE_NONE_RUNNING:
		role = fs_instance_acquire ();
		if (role != FS_INSTANCE_SECONDARY) {
			g_message ("StockFW: the copy running without %s quit "
			           "to make way for this one", what);
			return role;
		}
		break;
	default:
		break;
	}
	g_message ("StockFW: the copy running without %s could not be "
	           "replaced; starting beside it", what);
	return FS_INSTANCE_UNGUARDED;
}

/* [ autostart_command ] -- the three autostart switches: change it,
 * say what happened, exit 0 or 1.  No GTK, no instance. */
static int
autostart_command (void)
{
	GError *error = NULL;
	gboolean ok;

	if ((opt_autostart_on ? 1 : 0) + (opt_autostart_off ? 1 : 0) +
	    (opt_autostart_purge ? 1 : 0) > 1) {
		g_printerr ("Give only one of --enable-autostart, "
		            "--disable-autostart and --remove-all-autostart.\n");
		return 1;
	}
	if (opt_autostart_purge)
		ok = fs_autostart_remove_all (&error);
	else
		ok = fs_autostart_set (opt_autostart_on, &error);

	if (!ok) {
		g_printerr ("%s\n", error != NULL ? error->message
		                                  : "Could not change it.");
		g_clear_error (&error);
		return 1;
	}
	if (opt_autostart_on)
		g_print ("StockFW will start in the background when you sign "
		         "in.\n%s\n", fs_autostart_description ());
	else if (opt_autostart_off)
		g_print ("StockFW will no longer start when you sign in.\n");
	else
		g_print ("Start at sign-in removed for every user.\n");
	return 0;
}

/* [ already_running_notice ] -- the second launch could not reach the
 * first (Windows: an elevated first copy and an unelevated second
 * one).  Say where it is rather than starting a rival copy. */
static void
already_running_notice (int *argc, char ***argv)
{
	GtkWidget *dialog;

	if (!gtk_init_check (argc, argv)) {
		g_printerr ("StockFW is already running.\n");
		return;
	}

	dialog = gtk_message_dialog_new (NULL, 0, GTK_MESSAGE_INFO,
	                                 GTK_BUTTONS_OK, "%s",
	                                 _("StockFW is already running in "
	                                   "the notification area"));
	gtk_window_set_title (GTK_WINDOW (dialog), "StockFW");
	gtk_message_dialog_format_secondary_text (
		GTK_MESSAGE_DIALOG (dialog), "%s",
		_("Open it from its icon there.  This copy cannot bring its "
		  "window forward, most likely because it runs with "
		  "administrator rights and this one does not."));
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
}

int
main (int argc, char *argv[])
{
	GtkApplication *app;
	GError *error = NULL;
	GOptionContext *ctx;
	FsInstanceRole role;
	int status;

	setlocale (LC_ALL, "");

	ctx = g_option_context_new ("- StockFW firewall configuration tool");
	g_option_context_add_main_entries (ctx, options, NULL);
	g_option_context_add_group (ctx, gtk_get_option_group (FALSE));

	if (!g_option_context_parse (ctx, &argc, &argv, &error)) {
		g_printerr ("%s\n", error->message);
		g_error_free (error);
		g_option_context_free (ctx);
		return 1;
	}

	g_option_context_free (ctx);

	if (opt_version) {
		g_print ("StockFW %s (%s backend)\n",
		         FS_VERSION, fs_backend ()->display_name);
		return 0;
	}

	if (opt_autostart_on || opt_autostart_off || opt_autostart_purge)
		return autostart_command ();

	if (opt_quit)
		return quit_running ();

	/* One copy per user.  A second launch hands over and exits --
	 * unless it is the more privileged one. */
	role = fs_instance_acquire ();
	if (role == FS_INSTANCE_SECONDARY && fs_instance_holder_weaker ())
		role = take_over ();

	/* A background start (sign-in) finding StockFW already up has
	 * nothing to do: the user did not ask to see a window. */
	if (role == FS_INSTANCE_SECONDARY && opt_background)
		return 0;

	if (role == FS_INSTANCE_SECONDARY) {
		switch (fs_instance_send (FS_INSTANCE_SHOW, 3000)) {
		case FS_INSTANCE_SENT:
			return 0;
		case FS_INSTANCE_NONE_RUNNING:
			/* It quit between the two calls: take its place. */
			role = fs_instance_acquire ();
			if (role != FS_INSTANCE_SECONDARY)
				break;
			/* fall through */
		default:
			already_running_notice (&argc, &argv);
			return 0;
		}
	}

	/* Settings */
	fs_prefs_init ();

	if (!fs_prefs_load ())
		fs_prefs_set_defaults ();

	/* Uniqueness is fs-instance's job, not D-Bus's: see its header. */
	app = gtk_application_new ("org.stockfw.StockFW",
	                           G_APPLICATION_NON_UNIQUE);

	g_signal_connect (app, "activate", G_CALLBACK (on_activate), NULL);
	fs_app_set_start_hidden (opt_background);

	/* Hear the session manager's "about to end" (GtkApplication's
	 * query-end; fs-app.c writes everything then, without delaying
	 * the logout).  Where none is running this does nothing. */
	g_object_set (app, "register-session", TRUE, NULL);

#ifndef G_OS_WIN32
	g_unix_signal_add (SIGTERM, on_quit_signal, NULL);
	g_unix_signal_add (SIGINT, on_quit_signal, NULL);
	{
		/* `nohup StockFW &' asked for the terminal closing to be
		 * ignored: an inherited SIG_IGN for SIGHUP is kept. */
		struct sigaction hup;

		if (sigaction (SIGHUP, NULL, &hup) != 0 ||
		    hup.sa_handler != SIG_IGN)
			g_unix_signal_add (SIGHUP, on_quit_signal, NULL);
	}
#endif

	if (role == FS_INSTANCE_PRIMARY)
		fs_instance_listen (on_instance_command, NULL);

	status = g_application_run (G_APPLICATION (app), argc, argv);

	fs_instance_release ();
	g_object_unref (app);

	return status;
}
