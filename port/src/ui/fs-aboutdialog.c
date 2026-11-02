/*---[ fs-aboutdialog.c ]-------------------------------------------------
 * The About window (1.0.7).
 *
 * A dialog transient for the main window, not modal, one at a time:
 * the logo, the name and version, one line on what StockFW does, the
 * credits, a licence summary that matches the source (two licence
 * texts, which covers which still under review) with both texts one
 * click away, the website, and "Copy system info" for bug reports.
 *
 * Replaces the stock GtkAboutDialog, which claimed GPL 3.0 (no file
 * in the source says so) and could only show one licence.
 *
 * Credits never carry a full name or an e-mail address.
 *--------------------------------------------------------------------*/

#include "ui/fs-dialogs.h"
#include "ui/fs-icons.h"
#include "core/fs-backend.h"
#include "core/fs-i18n.h"
#include "stockfw-logo-128.h"
#include "fs-licence-text.h"

#include <gdk-pixbuf/gdk-pixbuf.h>

#ifndef FS_VERSION
#define FS_VERSION "1.0.6"
#endif
#ifndef FS_PLATFORM_NAME
#define FS_PLATFORM_NAME "unknown"
#endif

#define FS_WEBSITE "https://github.com/Cazo-Net/StockFW"

static GtkWidget *about_dialog = NULL;

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
		gtk_label_set_width_chars (GTK_LABEL (label), 20);
		gtk_label_set_max_width_chars (GTK_LABEL (label), 60);
	}
	if (klass != NULL)
		add_class (label, klass);
	return label;
}

/* The embedded logo at `size' pixels, or NULL. */
static GdkPixbuf *
logo_pixbuf (gint size)
{
	GdkPixbufLoader *loader = gdk_pixbuf_loader_new ();
	GdkPixbuf *pixbuf = NULL;

	gdk_pixbuf_loader_set_size (loader, size, size);
	if (gdk_pixbuf_loader_write (loader, stockfw_logo_128_png,
	                             stockfw_logo_128_png_len, NULL)
	    && gdk_pixbuf_loader_close (loader, NULL)) {
		pixbuf = gdk_pixbuf_loader_get_pixbuf (loader);
		if (pixbuf != NULL)
			g_object_ref (pixbuf);
	} else {
		gdk_pixbuf_loader_close (loader, NULL);
	}
	g_object_unref (loader);
	return pixbuf;
}

/* [ fs_dialogs_about_credits ]
 * Plain text, one line per credit, NULL-terminated. */
const gchar * const *
fs_dialogs_about_credits (void)
{
	static const gchar *const credits[] = {
		"Stock Team & Qusai - Creator & Original Developer",
		"H3xCore - Developer",
		"StockFW Project - GTK3 Port, Windows Backend, Copilot",
		NULL
	};

	return credits;
}

/* [ fs_dialogs_system_info ]
 * What "Copy system info" copies: versions, platform and backend.
 * Nothing that names the user or the machine -- no user or host name,
 * no paths, no addresses. */
gchar *
fs_dialogs_system_info (void)
{
	const FsBackend *backend = fs_backend ();
	gchar *os = g_get_os_info (G_OS_INFO_KEY_PRETTY_NAME);
	gchar *info;

	if (os == NULL)
		os = g_get_os_info (G_OS_INFO_KEY_NAME);

	info = g_strdup_printf (
		"StockFW %s\n"
		"GTK %u.%u.%u (built with %u.%u.%u)\n"
		"GLib %u.%u.%u\n"
		"Platform: %s (%s build)\n"
		"Firewall backend: %s\n",
		FS_VERSION,
		gtk_get_major_version (), gtk_get_minor_version (),
		gtk_get_micro_version (),
		GTK_MAJOR_VERSION, GTK_MINOR_VERSION, GTK_MICRO_VERSION,
		glib_major_version, glib_minor_version, glib_micro_version,
		os != NULL ? os : "unknown", FS_PLATFORM_NAME,
		backend != NULL && backend->display_name != NULL
		? backend->display_name : "none");
	g_free (os);
	return info;
}

/* ------------------------------------------------------------ licence */

static GtkWidget *
licence_page (const gchar *text)
{
	GtkWidget *scroll = gtk_scrolled_window_new (NULL, NULL);
	GtkWidget *view = gtk_text_view_new ();
	GtkTextBuffer *buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));

	gtk_text_buffer_set_text (buffer, text, -1);
	gtk_text_view_set_editable (GTK_TEXT_VIEW (view), FALSE);
	gtk_text_view_set_cursor_visible (GTK_TEXT_VIEW (view), FALSE);
	gtk_text_view_set_wrap_mode (GTK_TEXT_VIEW (view), GTK_WRAP_WORD_CHAR);
	gtk_text_view_set_monospace (GTK_TEXT_VIEW (view), TRUE);
	gtk_text_view_set_left_margin (GTK_TEXT_VIEW (view), 16);
	gtk_text_view_set_right_margin (GTK_TEXT_VIEW (view), 16);
	gtk_text_view_set_top_margin (GTK_TEXT_VIEW (view), 12);
	gtk_text_view_set_bottom_margin (GTK_TEXT_VIEW (view), 12);
	add_class (view, "licence-text");
	gtk_container_add (GTK_CONTAINER (scroll), view);
	add_class (scroll, "licence-scroll");
	return scroll;
}

static void
on_licence_destroy (GtkWidget *window, gpointer data)
{
	(void) window;
	if (data != NULL)
		g_object_set_data (G_OBJECT (data), "fs-licence-window", NULL);
}

static void
on_view_licence (GtkButton *button, gpointer data)
{
	GtkWidget *dialog = data;
	GtkWidget *window = g_object_get_data (G_OBJECT (dialog),
	                                       "fs-licence-window");
	GtkWidget *box, *switcher, *stack, *note;

	(void) button;
	if (window != NULL) {
		gtk_window_present (GTK_WINDOW (window));
		return;
	}

	window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_widget_set_name (window, "fs-licence");
	gtk_window_set_title (GTK_WINDOW (window), _("StockFW licence texts"));
	gtk_window_set_transient_for (GTK_WINDOW (window), GTK_WINDOW (dialog));
	gtk_window_set_destroy_with_parent (GTK_WINDOW (window), TRUE);
	gtk_window_set_position (GTK_WINDOW (window),
	                         GTK_WIN_POS_CENTER_ON_PARENT);
	gtk_window_set_default_size (GTK_WINDOW (window), 680, 560);

	box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 10);
	add_class (box, "licence-body");
	note = label_new (_("The StockFW source carries both texts below. "
	                    "Which licence covers which part of it is still "
	                    "being reviewed."), "about-text", TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (note), 90);
	gtk_box_pack_start (GTK_BOX (box), note, FALSE, FALSE, 0);

	stack = gtk_stack_new ();
	gtk_widget_set_name (stack, "licence-pages");
	gtk_stack_add_titled (GTK_STACK (stack),
	                      licence_page (fs_licence_copying), "copying",
	                      _("GNU GPL version 2 (COPYING)"));
	gtk_stack_add_titled (GTK_STACK (stack),
	                      licence_page (fs_licence_license), "license",
	                      _("Apache License 2.0 (LICENSE)"));
	switcher = gtk_stack_switcher_new ();
	gtk_stack_switcher_set_stack (GTK_STACK_SWITCHER (switcher),
	                              GTK_STACK (stack));
	gtk_widget_set_halign (switcher, GTK_ALIGN_START);
	add_class (switcher, "licence-switcher");
	gtk_box_pack_start (GTK_BOX (box), switcher, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), stack, TRUE, TRUE, 0);
	gtk_container_add (GTK_CONTAINER (window), box);

	g_object_set_data (G_OBJECT (dialog), "fs-licence-window", window);
	g_signal_connect (window, "destroy", G_CALLBACK (on_licence_destroy),
	                  dialog);
	gtk_widget_show_all (window);
}

/* ---------------------------------------------------------- copy info */

static gboolean
hide_copied (gpointer data)
{
	GtkWidget *label = data;

	gtk_widget_hide (label);
	g_object_set_data (G_OBJECT (label), "fs-hide-id", NULL);
	g_object_unref (label);
	return G_SOURCE_REMOVE;
}

/* The copy itself runs from a low-priority idle, never inside the
 * click.  On Windows each new clipboard owner queues a TARGETS request
 * to itself (gdk/win32/gdkselection-win32.c, send_targets_request) and
 * marks it as the request it expects; a second owner change, or a
 * gtk_clipboard_store, before that request is handled leaves it
 * unmarked, and answering it warns "Setting selection property with
 * ... NULL" (_gdk_win32_selection_property_change).  An idle runs only
 * once the GDK event queue is empty, so the previous owner's request
 * has been answered; and clicks queued together (a double click on a
 * busy app) make one copy, not two. */
static guint copy_idle_id = 0;

static gboolean
copy_info_now (gpointer data)
{
	GtkClipboard *clipboard = data;
	gchar *info = fs_dialogs_system_info ();

	copy_idle_id = 0;
	gtk_clipboard_set_text (clipboard, info, -1);
#ifndef G_OS_WIN32
	/* Hand the text to the clipboard manager now, so it outlives
	 * StockFW even if StockFW does not quit cleanly.  Not on Windows:
	 * there a store renders every format at once
	 * (gdk_win32_display_store_clipboard sends WM_RENDERALLFORMATS)
	 * while the new owner's TARGETS request is still queued, which is
	 * the warning above.  Nothing is lost on a normal quit: the
	 * GtkApplication's shutdown stores the clipboard on every
	 * platform (gtk_application_shutdown, _gtk_clipboard_store_all). */
	gtk_clipboard_store (clipboard);
#endif
	g_free (info);
	return G_SOURCE_REMOVE;
}

static void
on_copy_info (GtkButton *button, gpointer data)
{
	GtkWidget *copied = data;
	guint id;

	if (copy_idle_id == 0)
		copy_idle_id = g_idle_add_full (
			G_PRIORITY_LOW, copy_info_now,
			g_object_ref (gtk_widget_get_clipboard (
				GTK_WIDGET (button), GDK_SELECTION_CLIPBOARD)),
			g_object_unref);

	gtk_widget_show (copied);
	id = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (copied),
	                                          "fs-hide-id"));
	if (id != 0) {
		g_source_remove (id);
		g_object_unref (copied);
	}
	id = g_timeout_add_seconds (4, hide_copied, g_object_ref (copied));
	g_object_set_data (G_OBJECT (copied), "fs-hide-id",
	                   GUINT_TO_POINTER (id));
}

static void
on_copied_destroy (GtkWidget *label, gpointer data)
{
	guint id = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (label),
	                                                "fs-hide-id"));

	(void) data;
	if (id != 0) {
		g_object_set_data (G_OBJECT (label), "fs-hide-id", NULL);
		g_source_remove (id);
		g_object_unref (label);
	}
}

/* ------------------------------------------------------------- dialog */

static GtkWidget *
card (GtkWidget *parent, const gchar *heading)
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);

	add_class (box, "card");
	add_class (box, "about-card");
	gtk_box_pack_start (GTK_BOX (box),
	                    label_new (heading, "card-heading", FALSE),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (parent), box, FALSE, FALSE, 0);
	return box;
}

static void
on_response (GtkDialog *dialog, gint response, gpointer data)
{
	(void) response;
	(void) data;
	gtk_widget_destroy (GTK_WIDGET (dialog));
}

static void
on_about_destroy (GtkWidget *widget, gpointer data)
{
	(void) widget;
	(void) data;
	about_dialog = NULL;
}

static gboolean
on_about_key (GtkWidget *widget, GdkEventKey *event, gpointer data)
{
	guint mods = event->state & gtk_accelerator_get_default_mod_mask ();

	(void) data;
	if (mods == GDK_CONTROL_MASK
	    && (event->keyval == GDK_KEY_w || event->keyval == GDK_KEY_W)) {
		gtk_widget_destroy (widget);
		return TRUE;
	}
	return FALSE;
}

/* [ fs_dialogs_about ]
 * Shows the About window, or raises it when it is open already. */
void
fs_dialogs_about (GtkWidget *parent)
{
	GtkWidget *dialog, *content, *body, *head, *tile, *names, *box;
	GtkWidget *footer, *button, *copied, *icon_row, *link;
	GdkPixbuf *logo;
	gchar *version;
	const gchar * const *credits = fs_dialogs_about_credits ();

	if (about_dialog != NULL) {
		gtk_window_present (GTK_WINDOW (about_dialog));
		return;
	}

	dialog = gtk_dialog_new ();
	about_dialog = dialog;
	gtk_widget_set_name (dialog, "fs-about");
	add_class (dialog, "about-window");
	gtk_window_set_title (GTK_WINDOW (dialog), _("About StockFW"));
	gtk_window_set_resizable (GTK_WINDOW (dialog), FALSE);
	if (parent != NULL) {
		GtkWidget *top = gtk_widget_get_toplevel (parent);

		if (GTK_IS_WINDOW (top)) {
			gtk_window_set_transient_for (GTK_WINDOW (dialog),
			                              GTK_WINDOW (top));
			gtk_window_set_destroy_with_parent (GTK_WINDOW (dialog),
			                                    TRUE);
			gtk_window_set_position (GTK_WINDOW (dialog),
			                         GTK_WIN_POS_CENTER_ON_PARENT);
		}
	}
	g_signal_connect (dialog, "response", G_CALLBACK (on_response), NULL);
	g_signal_connect (dialog, "destroy", G_CALLBACK (on_about_destroy), NULL);
	g_signal_connect (dialog, "key-press-event",
	                  G_CALLBACK (on_about_key), NULL);

	content = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
	gtk_container_set_border_width (GTK_CONTAINER (content), 0);
	gtk_box_set_spacing (GTK_BOX (content), 0);
	body = gtk_box_new (GTK_ORIENTATION_VERTICAL, 14);
	add_class (body, "about-body");
	gtk_box_pack_start (GTK_BOX (content), body, TRUE, TRUE, 0);

	/* Logo, name, version and the line on what it does. */
	head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 18);
	add_class (head, "about-head");
	tile = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	add_class (tile, "about-logo-tile");
	gtk_widget_set_valign (tile, GTK_ALIGN_START);
	logo = logo_pixbuf (72);
	if (logo != NULL) {
		GtkWidget *image = gtk_image_new_from_pixbuf (logo);

		gtk_widget_set_name (image, "about-logo");
		gtk_box_pack_start (GTK_BOX (tile), image, FALSE, FALSE, 0);
		g_object_unref (logo);
	}
	gtk_box_pack_start (GTK_BOX (head), tile, FALSE, FALSE, 0);

	names = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	gtk_widget_set_valign (names, GTK_ALIGN_CENTER);
	box = label_new ("StockFW", "about-name", FALSE);
	gtk_widget_set_name (box, "about-name");
	gtk_box_pack_start (GTK_BOX (names), box, FALSE, FALSE, 0);
	version = g_strdup_printf (_("Version %s"), FS_VERSION);
	box = label_new (version, "about-version", FALSE);
	gtk_widget_set_name (box, "about-version");
	gtk_label_set_selectable (GTK_LABEL (box), TRUE);
	gtk_widget_set_can_focus (box, FALSE);
	gtk_box_pack_start (GTK_BOX (names), box, FALSE, FALSE, 0);
	g_free (version);
	box = label_new (_("Configures the firewall your system already has "
	                   "and shows what it allows and blocks."),
	                 "about-desc", TRUE);
	gtk_widget_set_name (box, "about-desc");
	gtk_box_pack_start (GTK_BOX (names), box, FALSE, FALSE, 4);
	gtk_box_pack_start (GTK_BOX (head), names, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (body), head, FALSE, FALSE, 0);

	/* Credits: each line in one label, as written. */
	box = card (body, _("Credits"));
	gtk_widget_set_name (box, "about-credits");
	for (guint i = 0; credits[i] != NULL; i++) {
		GtkWidget *line = label_new (credits[i], "about-credit", TRUE);
		gchar *name = g_strdup_printf ("about-credit-%u", i);

		gtk_widget_set_name (line, name);
		g_free (name);
		gtk_box_pack_start (GTK_BOX (box), line, FALSE, FALSE, 0);
	}

	/* Licence: what the source carries today, not a wish. */
	box = card (body, _("Licence"));
	gtk_widget_set_name (box, "about-licence");
	gtk_box_pack_start (GTK_BOX (box),
	                    label_new (_("StockFW is free software and comes "
	                                 "with no warranty. Its source carries "
	                                 "two licence texts: the GNU General "
	                                 "Public License version 2 (COPYING) "
	                                 "and the Apache License 2.0 "
	                                 "(LICENSE). The code it was ported "
	                                 "from was released under the GNU GPL, "
	                                 "version 2 or any later version. Which "
	                                 "licence covers which part is still "
	                                 "being reviewed."),
	                               "about-text", TRUE),
	                    FALSE, FALSE, 0);
	button = gtk_button_new_with_mnemonic (_("_View licence texts"));
	gtk_widget_set_name (button, "about-view-licence");
	gtk_widget_set_halign (button, GTK_ALIGN_START);
	add_class (button, "btn-subtle");
	g_signal_connect (button, "clicked", G_CALLBACK (on_view_licence),
	                  dialog);
	gtk_box_pack_start (GTK_BOX (box), button, FALSE, FALSE, 4);

	/* Website. */
	link = gtk_link_button_new_with_label (FS_WEBSITE,
	                                       "github.com/Cazo-Net/StockFW");
	gtk_widget_set_name (link, "about-website");
	gtk_widget_set_halign (link, GTK_ALIGN_START);
	add_class (link, "about-link");
	gtk_box_pack_start (GTK_BOX (body), link, FALSE, FALSE, 0);

	/* Footer: Copy system info on the left, Close on the right. */
	footer = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
	add_class (footer, "about-footer");
	button = gtk_button_new ();
	icon_row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_box_pack_start (GTK_BOX (icon_row), fs_icon_new (FS_ICON_COPY, 16),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (icon_row),
	                    gtk_label_new_with_mnemonic (_("Copy _system info")),
	                    FALSE, FALSE, 0);
	gtk_container_add (GTK_CONTAINER (button), icon_row);
	gtk_widget_set_name (button, "about-copy");
	gtk_widget_set_tooltip_text (button,
		_("Copies the StockFW, GTK and GLib versions, the operating "
		  "system and the firewall backend, for a bug report. Nothing "
		  "about you or this computer's name or addresses."));
	add_class (button, "btn-subtle");
	copied = label_new (_("Copied."), "about-copied", FALSE);
	gtk_widget_set_name (copied, "about-copied");
	gtk_widget_set_no_show_all (copied, TRUE);
	g_signal_connect (copied, "destroy", G_CALLBACK (on_copied_destroy),
	                  NULL);
	g_signal_connect (button, "clicked", G_CALLBACK (on_copy_info), copied);
	gtk_box_pack_start (GTK_BOX (footer), button, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (footer), copied, FALSE, FALSE, 0);

	button = gtk_button_new_with_mnemonic (_("_Close"));
	gtk_widget_set_name (button, "about-close");
	add_class (button, "btn-primary");
	gtk_widget_set_can_default (button, TRUE);
	g_signal_connect_swapped (button, "clicked",
	                          G_CALLBACK (gtk_widget_destroy), dialog);
	gtk_box_pack_end (GTK_BOX (footer), button, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (content), footer, FALSE, FALSE, 0);

	gtk_widget_show_all (dialog);
	gtk_window_set_default (GTK_WINDOW (dialog), button);
	gtk_widget_grab_focus (button);
	/* Ask for the keyboard too.  Shown but never activated (no window
	 * manager to hand it focus, or a desktop that holds focus on the
	 * window it came from), a dialog takes no keyboard focus, and GTK
	 * then re-grabs the focused button on every Tab, so Tab never
	 * left Close.  Presenting it gets it focus where it is opened. */
	gtk_window_present (GTK_WINDOW (dialog));
}
