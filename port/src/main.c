/*---[ main.c ]---------------------------------------------------------
 * Entry point.
 *
 * The original used popt for command line parsing plus
 * gnome_program_init() and gnome_master_client() for session
 * management.  Both are gone from modern GNOME; GLib's GOptionContext
 * and GtkApplication cover what is actually needed.
 *--------------------------------------------------------------------*/

#include <gtk/gtk.h>
#include <locale.h>

#include "core/fs-prefs.h"
#include "core/fs-backend.h"
#include "ui/fs-app.h"
#include "ui/fs-dialogs.h"

#ifndef FS_VERSION
#define FS_VERSION "1.0.6"
#endif

static gboolean opt_version = FALSE;
static gboolean opt_console = FALSE;

static const GOptionEntry options[] = {
	{ "version", 'V', 0, G_OPTION_ARG_NONE, &opt_version,
	  "Show the program version and exit", NULL },
	{ "console", 'C', 0, G_OPTION_ARG_NONE, &opt_console,
	  "Print firewall activity to the console", NULL },
	{ NULL, 0, 0, 0, NULL, NULL, NULL }
};

/* [ on_activate ] */
static void
on_activate (GtkApplication *app, gpointer data)
{
	fs_app_activate (app);
}

int
main (int argc, char *argv[])
{
	GtkApplication *app;
	GError *error = NULL;
	GOptionContext *ctx;
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

	/* Settings */
	fs_prefs_init ();

	if (!fs_prefs_load ())
		fs_prefs_set_defaults ();

	app = gtk_application_new ("org.stockfw.StockFW",
	                           G_APPLICATION_NON_UNIQUE);

	g_signal_connect (app, "activate", G_CALLBACK (on_activate), NULL);

	status = g_application_run (G_APPLICATION (app), argc, argv);

	g_object_unref (app);

	return status;
}