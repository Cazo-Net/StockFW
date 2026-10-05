/*---[ fs-dialogs.c ]---------------------------------------------------
 * About / error / info / confirm dialogs.
 *
 * Replaces gnome_about_new() and the hand-rolled error window in
 * util.c with stock GTK3 dialogs.
 *--------------------------------------------------------------------*/

#include "ui/fs-dialogs.h"
#include "core/fs-i18n.h"
#include "stockfw-logo-128.h"

#include <gdk-pixbuf/gdk-pixbuf.h>

#ifndef FS_VERSION
#define FS_VERSION "1.0.3"
#endif

/* Load the embedded StockFW logo as a GdkPixbuf. */
static GdkPixbuf *
load_logo_pixbuf (void)
{
	GError *error = NULL;
	GdkPixbufLoader *loader;
	GdkPixbuf *pixbuf = NULL;

	loader = gdk_pixbuf_loader_new ();
	if (gdk_pixbuf_loader_write (loader, stockfw_logo_128_png,
	                             stockfw_logo_128_png_len, &error)) {
		gdk_pixbuf_loader_close (loader, NULL);
		pixbuf = gdk_pixbuf_loader_get_pixbuf (loader);
		if (pixbuf)
			g_object_ref (pixbuf);
	} else {
		g_clear_error (&error);
	}
	g_object_unref (loader);

	return pixbuf;
}

void
fs_dialogs_about (GtkWidget *parent)
{
	static const gchar *authors[] = {
		"Tomas Junnonen <majix@sci.fi> - Original Developer",
		"Paul Drain <pd@cipherfunk.org> - Developer",
		"StockFW Project - GTK3 Port, Windows Backend, Copilot",
		NULL
	};

	GtkWidget *dialog = gtk_about_dialog_new ();
	GdkPixbuf *logo = load_logo_pixbuf ();

	gtk_about_dialog_set_program_name (GTK_ABOUT_DIALOG (dialog), "StockFW");
	gtk_about_dialog_set_version (GTK_ABOUT_DIALOG (dialog), FS_VERSION);
	gtk_about_dialog_set_copyright (GTK_ABOUT_DIALOG (dialog),
	                                "(C) 2000-2026 StockFW Project");
	gtk_about_dialog_set_comments (GTK_ABOUT_DIALOG (dialog),
	                               "Smart Firewall Configuration Tool\n"
	                               "with AI-powered anomaly detection.");
	gtk_about_dialog_set_authors (GTK_ABOUT_DIALOG (dialog), authors);
	gtk_about_dialog_set_license_type (GTK_ABOUT_DIALOG (dialog),
	                                    GTK_LICENSE_GPL_3_0);
	gtk_about_dialog_set_wrap_license (GTK_ABOUT_DIALOG (dialog), TRUE);
	gtk_about_dialog_set_website (GTK_ABOUT_DIALOG (dialog),
	                              "https://github.com/Cazo-Net/StockFW");
	gtk_about_dialog_set_website_label (GTK_ABOUT_DIALOG (dialog),
	                                    "StockFW on GitHub");

	if (logo != NULL) {
		gtk_about_dialog_set_logo (GTK_ABOUT_DIALOG (dialog), logo);
		g_object_unref (logo);
	}

	gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (parent));
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
}

static GtkWidget *
make_message_dialog (GtkWidget *parent,
                     GtkMessageType type,
                     const gchar *header,
                     const gchar *message)
{
	GtkWidget *dialog;

	dialog = gtk_message_dialog_new (GTK_WINDOW (parent),
	                                 GTK_DIALOG_MODAL,
	                                 type,
	                                 GTK_BUTTONS_OK,
	                                 "%s", header ? header : "");

	if (message != NULL)
		gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
		                                           "%s", message);

	return dialog;
}

void
fs_dialogs_error (GtkWidget *parent, const gchar *header,
                  const gchar *message)
{
	GtkWidget *dialog = make_message_dialog (parent, GTK_MESSAGE_ERROR,
	                                         header, message);

	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
}

void
fs_dialogs_info (GtkWidget *parent, const gchar *header,
                 const gchar *message)
{
	GtkWidget *dialog = make_message_dialog (parent, GTK_MESSAGE_INFO,
	                                         header, message);

	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
}

void
fs_dialogs_confirm (GtkWidget *parent, const gchar *question,
                    gboolean *confirmed)
{
	GtkWidget *dialog;
	gint response;

	dialog = gtk_message_dialog_new (GTK_WINDOW (parent),
	                                 GTK_DIALOG_MODAL,
	                                 GTK_MESSAGE_QUESTION,
	                                 GTK_BUTTONS_NONE,
	                                 "%s", question ? question : "");

	gtk_dialog_add_buttons (GTK_DIALOG (dialog),
	                        _("_Cancel"), GTK_RESPONSE_CANCEL,
	                        _("_OK"), GTK_RESPONSE_OK,
	                        NULL);
	gtk_dialog_set_default_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);

	response = gtk_dialog_run (GTK_DIALOG (dialog));

	if (confirmed != NULL)
		*confirmed = (response == GTK_RESPONSE_OK);

	gtk_widget_destroy (dialog);
}