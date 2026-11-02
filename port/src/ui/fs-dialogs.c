/*---[ fs-dialogs.c ]---------------------------------------------------
 * Error / info / confirm dialogs.
 *
 * Replaces the hand-rolled error window in util.c with stock GTK3
 * dialogs.  The About window is in fs-aboutdialog.c, Preferences in
 * fs-prefsdialog.c.
 *--------------------------------------------------------------------*/

#include "ui/fs-dialogs.h"
#include "core/fs-i18n.h"

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

/* The Preferences window is in fs-prefsdialog.c. */
