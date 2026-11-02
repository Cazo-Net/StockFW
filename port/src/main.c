/*---[ main.c ]---------------------------------------------------------
 * Entry point.
 *
 * The original used popt for command line parsing plus
 * gnome_program_init() and gnome_master_client() for session
 * management.  Both are gone from modern GNOME; GLib's GOptionContext
 * and GtkApplication cover what is actually needed.
 *
 * One StockFW per desktop session (core/fs-instance.h): a second
 * launch asks the first to show its window and exits, and --quit asks
 * it to quit cleanly -- the uninstaller's way to stop it with its
 * settings saved.  Neither needs a display, so they run before GTK.
 *--------------------------------------------------------------------*/

#include <gtk/gtk.h>
#include <locale.h>

#include "core/fs-prefs.h"
#include "core/fs-backend.h"
#include "core/fs-instance.h"
#include "core/fs-i18n.h"
#include "ui/fs-app.h"
#include "ui/fs-dialogs.h"

#ifndef FS_VERSION
#define FS_VERSION "1.0.6"
#endif

static gboolean opt_version = FALSE;
static gboolean opt_quit = FALSE;

static const GOptionEntry options[] = {
	{ "version", 'V', 0, G_OPTION_ARG_NONE, &opt_version,
	  "Show the program version and exit", NULL },
	{ "quit", 0, 0, G_OPTION_ARG_NONE, &opt_quit,
	  "Ask the running StockFW to quit (the firewall stays on)", NULL },
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

	if (opt_quit)
		return quit_running ();

	/* One copy per session.  A second launch hands over and exits. */
	role = fs_instance_acquire ();
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

	if (role == FS_INSTANCE_PRIMARY)
		fs_instance_listen (on_instance_command, NULL);

	status = g_application_run (G_APPLICATION (app), argc, argv);

	fs_instance_release ();
	g_object_unref (app);

	return status;
}
