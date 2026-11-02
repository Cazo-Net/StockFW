/*---[ fs-dialogs.c ]---------------------------------------------------
 * About / error / info / confirm dialogs.
 *
 * Replaces gnome_about_new() and the hand-rolled error window in
 * util.c with stock GTK3 dialogs.
 *--------------------------------------------------------------------*/

#include "ui/fs-dialogs.h"
#include "ui/fs-app.h"
#include "core/fs-backend.h"
#include "core/fs-i18n.h"
#include "core/fs-prefs.h"
#include "stockfw-logo-128.h"

#include <gdk-pixbuf/gdk-pixbuf.h>

#ifndef FS_VERSION
#define FS_VERSION "1.0.6"
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

/* [ fs_dialogs_about_authors ]
 * The About credits, pre-escaped for Pango markup.
 *
 * GtkAboutDialog's credits view wraps every author in
 * <span size="small">... and parses the result as markup WITHOUT
 * escaping the plain-text parts -- it only escapes text around links
 * (gtkaboutdialog.c, add_credits_section).  A bare '&' therefore
 * makes Pango fail to parse, and the label falls back to showing the
 * raw markup: the dialog printed "Created by: <span size=...>Qusai
 * Fethalrahman - Creator & Original Developer</span>" instead of the
 * name.  Escaping here is what makes it render.  Exported so
 * ui-prefs-smoke can run pango_parse_markup() over every string --
 * the escape is the fix, the parse is the proof.
 */
const gchar **
fs_dialogs_about_authors (void)
{
	static const gchar *raw[] = {
		"Qusai Fethalrahman (Qusaifox2@gmail.com) - Creator & Original Developer",
		"H3xCore - Developer",
		"StockFW Project - GTK3 Port, Windows Backend, Copilot",
		NULL
	};
	static gchar *safe[G_N_ELEMENTS (raw)] = { NULL };
	static gboolean done = FALSE;

	if (!done) {
		for (guint i = 0; raw[i] != NULL; i++)
			safe[i] = g_markup_escape_text (raw[i], -1);
		done = TRUE;
	}

	return (const gchar **) safe;
}

void
fs_dialogs_about (GtkWidget *parent)
{
	GtkWidget *dialog = gtk_about_dialog_new ();
	GdkPixbuf *logo = load_logo_pixbuf ();

	gtk_about_dialog_set_program_name (GTK_ABOUT_DIALOG (dialog), "StockFW");
	gtk_about_dialog_set_version (GTK_ABOUT_DIALOG (dialog), FS_VERSION);
	gtk_about_dialog_set_copyright (GTK_ABOUT_DIALOG (dialog),
	                                "(C) 04-10-2026 StockFW Project");
	gtk_about_dialog_set_comments (GTK_ABOUT_DIALOG (dialog),
	                               "Smart Firewall Configuration Tool\n"
	                               "with local, rule-based traffic analysis.");
	gtk_about_dialog_set_authors (GTK_ABOUT_DIALOG (dialog),
	                              fs_dialogs_about_authors ());
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

/* ------------------------------------------------------------------ prefs
 *
 * Rebuilt from the original's preferences.c / preferences.glade: a
 * section tree on the left, the matching notebook page on the right,
 * and Help / Cancel / Accept along the bottom.
 *
 * Honesty rule: a control is only left enabled when the application
 * actually acts on it.  Which Firewall sub-pages exist at all follows
 * the backend's fw_sections bits (core/fs-backend.h); inside an offered
 * page, a control the backend cannot reproduce is disabled with a note,
 * never live and inert.
 *
 *   Effective on both platforms
 *     Interface > Events, Interface > Policy, Firewall > startup,
 *     the Interface tray switches (fs-tray.c follows both)
 *
 *   Effective on both, mapped per backend (core/fs-settings-plan.h)
 *     Firewall > ICMP Filtering (Windows: the same allow-list, as
 *     Windows Firewall ICMP rules; the Linux rate limits have no
 *     Windows equivalent, and the page says so), Advanced Options
 *     (Windows: the broadcast and reserved-source blocks scoped to
 *     the public/private profiles, the honest equivalent of the
 *     iptables rules' external/internal interface scoping)
 *
 *   Effective on Linux only
 *     Firewall > Network Settings (ext/int devices, NAT -- Windows
 *     would need Internet Connection Sharing, not yet carried)
 *
 *   Offered but partially: disabled with a reason
 *     Advanced Options > rejection method on Windows (Windows Firewall
 *     always drops silently; no per-rule reject exists)
 *
 *   Not offered where the backend cannot act at all
 *     Network Settings and ToS Filtering on Windows (ToS has no
 *     marking field in Windows Firewall)
 *
 *   Not wired up anywhere yet, so disabled with a reason
 *     dial-out / DHCP startup, ToS Filtering's controls on Linux
 *     (an admitted-dead page matching the original layout),
 *     the Events host and port filter lists, the DHCP server block
 */

typedef enum
{
	SECTION_INTERFACE,
	SECTION_INTERFACE_EVENTS,
	SECTION_INTERFACE_POLICY,
	SECTION_FIREWALL,
	SECTION_FIREWALL_NETWORK,
	SECTION_FIREWALL_ICMP,
	SECTION_FIREWALL_TOS,
	SECTION_FIREWALL_ADVANCED
} Section;

/* Preferences attached to a widget, collected while the pages are
 * built and written back in one pass when Accept is pressed. */
typedef struct
{
	GList     *widgets;   /* GtkWidget*, each carrying "pref-key" */
	GtkWidget *icmp_master;
	GList     *icmp_types;
	GtkWidget *tos_master;
	GList     *tos_types;
} PrefBinding;

static gboolean prefs_css_installed = FALSE;

/* Used before their definitions below. */
static void on_section_changed (GtkTreeView *view, gpointer data);
static void save_preferences   (PrefBinding *bind);

static void
install_prefs_css (void)
{
	static const gchar *css =
		".fs-pref-title   { font-size: 1.35em; font-weight: bold; }\n"
		".fs-pref-section { font-weight: bold; }\n";
	GtkCssProvider *provider;
	GError *error = NULL;

	if (prefs_css_installed)
		return;

	provider = gtk_css_provider_new ();
	if (gtk_css_provider_load_from_data (provider, css, -1, &error)) {
		gtk_style_context_add_provider_for_screen (
			gdk_screen_get_default (),
			GTK_STYLE_PROVIDER (provider),
			GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	}
	g_clear_error (&error);
	g_object_unref (provider);

	prefs_css_installed = TRUE;
}

/* [ wrap_page ]
 * Wraps a notebook page in a scrolled window.  The dialog is a fixed
 * 640x480 while pages like Events, ICMP and Advanced carry more
 * content than that; without a scrollbar the overflow was simply
 * clipped and unreachable. */
static GtkWidget *
wrap_page (GtkWidget *page)
{
	GtkWidget *scroll = gtk_scrolled_window_new (NULL, NULL);

	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_NEVER,
	                                GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), page);
	gtk_widget_show (page);

	return scroll;
}

/* [ page_new ] -- a titled page of the notebook. */
static GtkWidget *
page_new (const gchar *title)
{
	GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
	GtkWidget *label = gtk_label_new (title);

	gtk_container_set_border_width (GTK_CONTAINER (page), 16);
	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             "fs-pref-title");
	gtk_box_pack_start (GTK_BOX (page), label, FALSE, FALSE, 0);

	return page;
}

static void
add_section (GtkWidget *page, const gchar *text)
{
	GtkWidget *label = gtk_label_new (text);

	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_widget_set_margin_top (label, 10);
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             "fs-pref-section");
	gtk_box_pack_start (GTK_BOX (page), label, FALSE, FALSE, 0);
}

/* Greyed-out explanatory text shown under something that is disabled. */
static void
add_note (GtkWidget *page, const gchar *text)
{
	GtkWidget *label = gtk_label_new (text);

	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	gtk_widget_set_margin_start (label, 4);
	gtk_style_context_add_class (gtk_widget_get_style_context (label),
	                             "dim-label");
	gtk_box_pack_start (GTK_BOX (page), label, FALSE, FALSE, 0);
}

static void
add_explainer (GtkWidget *page, const gchar *text)
{
	GtkWidget *label = gtk_label_new (text);

	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	gtk_box_pack_start (GTK_BOX (page), label, FALSE, FALSE, 0);
}

/* [ add_check ] -- a checkbox bound to a boolean preference. */
static GtkWidget *
add_check (GtkWidget *page, PrefBinding *bind, const gchar *key,
           const gchar *label, gboolean fallback, gboolean sensitive)
{
	GtkWidget *check = gtk_check_button_new_with_label (label);

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (check),
	                              fs_prefs_get_bool (key, fallback));
	g_object_set_data_full (G_OBJECT (check), "pref-key",
	                        g_strdup (key), g_free);
	g_object_set_data (G_OBJECT (check), "pref-type",
	                   (gpointer) "bool");
	g_object_set_data (G_OBJECT (check), "can-work",
	                   GINT_TO_POINTER (sensitive ? 1 : 0));

	bind->widgets = g_list_append (bind->widgets, check);
	gtk_widget_set_sensitive (check, sensitive);
	gtk_box_pack_start (GTK_BOX (page), check, FALSE, FALSE, 0);

	return check;
}

/* [ add_radio_pair ] -- two radios bound to one boolean preference,
 * the first meaning FALSE. */
static void
add_radio_pair (GtkWidget *page, PrefBinding *bind, const gchar *key,
                gboolean fallback, const gchar *label_false,
                const gchar *label_true, gboolean sensitive)
{
	GtkWidget *first = gtk_radio_button_new_with_label (NULL, label_false);
	GtkWidget *second = gtk_radio_button_new_with_label (
		gtk_radio_button_get_group (GTK_RADIO_BUTTON (first)), label_true);

	gtk_toggle_button_set_active (
		GTK_TOGGLE_BUTTON (fs_prefs_get_bool (key, fallback)
		                   ? second : first), TRUE);

	g_object_set_data_full (G_OBJECT (first), "pref-key",
	                        g_strdup (key), g_free);
	g_object_set_data (G_OBJECT (first), "pref-type", (gpointer) "radio");
	g_object_set_data (G_OBJECT (first), "pref-value", GINT_TO_POINTER (0));

	g_object_set_data_full (G_OBJECT (second), "pref-key",
	                        g_strdup (key), g_free);
	g_object_set_data (G_OBJECT (second), "pref-type", (gpointer) "radio");
	g_object_set_data (G_OBJECT (second), "pref-value", GINT_TO_POINTER (1));

	bind->widgets = g_list_append (bind->widgets, first);
	bind->widgets = g_list_append (bind->widgets, second);

	gtk_widget_set_sensitive (first, sensitive);
	gtk_widget_set_sensitive (second, sensitive);

	gtk_box_pack_start (GTK_BOX (page), first, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), second, FALSE, FALSE, 0);
}

/* [ sync_dependents ] -- a master switch and its children.  "can-work"
 * remembers whether the child could ever be on, so a child that is
 * disabled for a different reason stays disabled. */
static void
sync_dependents (GtkToggleButton *master, gpointer data)
{
	GList *children = data;
	gboolean on = gtk_toggle_button_get_active (master);

	for (GList *l = children; l != NULL; l = l->next) {
		GtkWidget *child = l->data;
		gboolean can = GPOINTER_TO_INT (
			g_object_get_data (G_OBJECT (child), "can-work"));

		gtk_widget_set_sensitive (child, on && can);
	}
}

static void
bind_dependents (GtkWidget *master, GList **children)
{
	g_signal_connect (master, "toggled",
	                  G_CALLBACK (sync_dependents), *children);
	sync_dependents (GTK_TOGGLE_BUTTON (master), *children);
}

/* --------------------------------------------------------------- pages */

static GtkWidget *
build_interface_page (PrefBinding *bind)
{
	GtkWidget *page = page_new (_("Interface"));

	add_check (page, bind, FS_PREFS_ENABLE_TRAY_ICON,
	           _("Show a tray icon"), TRUE, TRUE);
	add_check (page, bind, FS_PREFS_MINIMIZE_TO_TRAY,
	           _("Minimize to the tray"), TRUE, TRUE);
	add_note (page,
		_("With the tray icon shown, closing or minimizing this "
		  "window keeps StockFW running in the background; the "
		  "tray menu opens it again or quits the program."));

	return page;
}

static GtkWidget *
build_events_page (PrefBinding *bind)
{
	GtkWidget *page = page_new (_("Events"));

	add_check (page, bind, FS_PREFS_SKIP_REDUNDANT,
	           _("Hide repeated events"), FALSE, TRUE);
	add_note (page,
		_("Drops a hit when the same source, port and action arrived "
		  "a moment ago, so a scan does not flood the list."));

	add_check (page, bind, FS_PREFS_SKIP_NOT_FOR_FIREWALL,
	           _("Skip events that are not for the firewall"), TRUE, TRUE);

	add_section (page, _("Ignored hosts"));
	add_note (page,
		_("The host and port filter lists from the original are not "
		  "wired up yet, so they are shown disabled."));

	{
		GtkWidget *hosts = gtk_scrolled_window_new (NULL, NULL);
		GtkWidget *ports = gtk_scrolled_window_new (NULL, NULL);

		gtk_widget_set_size_request (hosts, -1, 70);
		gtk_widget_set_size_request (ports, -1, 70);
		gtk_widget_set_sensitive (hosts, FALSE);
		gtk_widget_set_sensitive (ports, FALSE);
		gtk_box_pack_start (GTK_BOX (page), hosts, FALSE, FALSE, 0);

		add_section (page, _("Ignored ports"));
		gtk_box_pack_start (GTK_BOX (page), ports, FALSE, FALSE, 0);
	}

	return page;
}

static GtkWidget *
build_policy_page (PrefBinding *bind)
{
	GtkWidget *page = page_new (_("Policy"));

	add_check (page, bind, FS_PREFS_APPLY_POLICY_INSTANTLY,
	           _("Apply policy changes immediately"), TRUE, TRUE);
	add_note (page,
		_("With this on, adding, removing or editing a rule writes it "
		  "to the firewall straight away.  With it off every change "
		  "waits for Apply."));

	return page;
}

static GtkWidget *
build_firewall_page (PrefBinding *bind)
{
	GtkWidget *page = page_new (_("Firewall"));

	add_section (page, _("Startup and persistence"));

	add_check (page, bind, FS_PREFS_START_ON_GUI,
	           _("Start/restart firewall on program startup"), FALSE, TRUE);
	add_check (page, bind, FS_PREFS_START_ON_DIAL_OUT,
	           _("Start/restart firewall on dial-out"), FALSE, FALSE);
	add_check (page, bind, FS_PREFS_START_ON_DHCP,
	           _("Start/restart firewall on DHCP lease renewal"), FALSE, FALSE);

	add_note (page,
		_("Dial-out and DHCP lease renewal are not implemented in this "
		  "port.  Windows also starts its own firewall before any "
		  "program runs, so there is nothing to restore at boot."));

	return page;
}

/* [ build_network_page ] -- Linux-only: the two device choosers are fed
 * from the backend, so they list what is really attached.  Windows does
 * not offer this page (its fw_sections has no FS_FWSEC_NETWORK bit):
 * the Windows equivalent would be Internet Connection Sharing, which
 * the port does not carry, and inert switches are worse than none. */
static GtkWidget *
build_network_page (PrefBinding *bind)
{
	GtkWidget *page = page_new (_("Network Settings"));
	const gchar *any = _("Any device");

	add_section (page, _("Internet connected network device"));
	{
		GtkWidget *combo = gtk_combo_box_text_new ();
		GList *ifaces = fs_backend ()->list_interfaces ();
		gchar *current = fs_prefs_get_string (FS_PREFS_FW_EXT_IF, "");
		gboolean matched = FALSE;

		gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (combo), "", any);

		for (GList *l = ifaces; l != NULL; l = l->next) {
			FsInterface *iface = l->data;
			gchar *label;

			if (iface->name == NULL)
				continue;

			label = (iface->ip != NULL && *iface->ip != '\0')
			      ? g_strdup_printf ("%s (%s)", iface->name, iface->ip)
			      : g_strdup (iface->name);

			gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (combo),
			                           iface->name, label);
			if (g_strcmp0 (current, iface->name) == 0)
				matched = TRUE;

			g_free (label);
		}

		gtk_combo_box_set_active (GTK_COMBO_BOX (combo),
		                          matched && *current != '\0' ? 1 : 0);

		g_object_set_data_full (G_OBJECT (combo), "pref-key",
		                        g_strdup (FS_PREFS_FW_EXT_IF), g_free);
		g_object_set_data (G_OBJECT (combo), "pref-type",
		                   (gpointer) "combo");
		bind->widgets = g_list_append (bind->widgets, combo);
		gtk_box_pack_start (GTK_BOX (page), combo, FALSE, FALSE, 0);

		g_free (current);
		g_list_free_full (ifaces, (GDestroyNotify) fs_interface_free);
	}

	add_section (page, _("Local network connected device"));
	{
		GtkWidget *combo = gtk_combo_box_text_new ();
		gchar *current = fs_prefs_get_string (FS_PREFS_FW_INT_IF, "");

		gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (combo), "", any);
		gtk_combo_box_set_active (GTK_COMBO_BOX (combo),
		                          *current != '\0' ? 1 : 0);

		g_object_set_data_full (G_OBJECT (combo), "pref-key",
		                        g_strdup (FS_PREFS_FW_INT_IF), g_free);
		g_object_set_data (G_OBJECT (combo), "pref-type",
		                   (gpointer) "combo");
		bind->widgets = g_list_append (bind->widgets, combo);
		gtk_box_pack_start (GTK_BOX (page), combo, FALSE, FALSE, 0);

		g_free (current);
	}

	add_check (page, bind, FS_PREFS_FW_NAT,
	           _("Enable Internet connection sharing"), FALSE, TRUE);
	add_check (page, bind, FS_PREFS_FW_DHCP_ENABLE,
	           _("Enable DHCP for the local network"), FALSE, FALSE);

	add_note (page,
		_("The built-in DHCP server is not implemented in this port, "
		  "so its settings are disabled."));

	return page;
}

/* [ build_icmp_page ] -- live on both backends: the checkboxes map onto
 * iptables --icmp-type rules on Linux and onto Windows Firewall ICMP
 * type/code rules through core/fs-settings-plan.h on Windows. */
static GtkWidget *
build_icmp_page (PrefBinding *bind)
{
	static const struct
	{
		const gchar *key;
		const gchar *label;
		gboolean     fallback;   /* matches fs_settings_load_prefs() */
		gboolean     v4_only;    /* no ICMPv6 counterpart (fs-script.c) */
	} types[] = {
		{ FS_PREFS_FW_ICMP_ECHO_REQUEST,    N_("Echo request (ping)"),   TRUE,  FALSE },
		{ FS_PREFS_FW_ICMP_MSTRACEROUTE,    N_("MS Traceroute"),         TRUE,  FALSE },
		{ FS_PREFS_FW_ICMP_MASKING,         N_("Address Masking (IPv4 only)"), FALSE, TRUE },
		{ FS_PREFS_FW_ICMP_ECHO_REPLY,      N_("Echo reply (pong)"),     TRUE,  FALSE },
		{ FS_PREFS_FW_ICMP_TRACEROUTE,      N_("Traceroute"),            TRUE,  FALSE },
		{ FS_PREFS_FW_ICMP_REDIRECTION,     N_("Redirection"),           FALSE, FALSE },
		{ FS_PREFS_FW_ICMP_TIMESTAMPING,    N_("Timestamping (IPv4 only)"), FALSE, TRUE },
		{ FS_PREFS_FW_ICMP_UNREACHABLE,     N_("Unreachable"),           TRUE,  FALSE },
		{ FS_PREFS_FW_ICMP_SOURCE_QUENCHES, N_("Source Quenching (IPv4 only)"), FALSE, TRUE }
	};
	GtkWidget *page = page_new (_("ICMP Filtering"));
	GtkWidget *grid;
	GtkWidget *master;

	add_explainer (page,
		_("ICMP filtering lets you restrict control packet creation and "
		  "reception by the firewall, potentially preventing Denial of "
		  "Service attacks, but also disabling many common network "
		  "tools."));

	master = add_check (page, bind, FS_PREFS_FW_FILTER_ICMP,
	                    _("Enable ICMP filtering"), TRUE, TRUE);
	bind->icmp_master = master;

	add_section (page, _("Allow the following ICMP packet types"));

	grid = gtk_grid_new ();
	gtk_grid_set_row_spacing (GTK_GRID (grid), 4);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 24);

	for (guint i = 0; i < G_N_ELEMENTS (types); i++) {
		GtkWidget *check = gtk_check_button_new_with_label (
			_(types[i].label));

		gtk_toggle_button_set_active (
			GTK_TOGGLE_BUTTON (check),
			fs_prefs_get_bool (types[i].key, types[i].fallback));
		g_object_set_data_full (G_OBJECT (check), "pref-key",
		                        g_strdup (types[i].key), g_free);
		g_object_set_data (G_OBJECT (check), "pref-type",
		                   (gpointer) "bool");
		g_object_set_data (G_OBJECT (check), "can-work",
		                   GINT_TO_POINTER (1));
		if (types[i].v4_only)
			gtk_widget_set_tooltip_text (check,
				_("ICMPv6 has no such message, so this only "
				  "affects IPv4."));

		bind->widgets = g_list_append (bind->widgets, check);
		bind->icmp_types = g_list_append (bind->icmp_types, check);

		gtk_grid_attach (GTK_GRID (grid), check, i % 3, i / 3, 1, 1);
	}

	gtk_box_pack_start (GTK_BOX (page), grid, FALSE, FALSE, 0);
	bind_dependents (master, &bind->icmp_types);

	/* The Linux generator emits -m limit on its ICMP accepts; Windows
	 * Firewall has no per-rule rate field, so the same allow-list
	 * arrives there without one.  Say so rather than let the parity
	 * look exact when it is not. */
	if ((fs_backend ()->fw_honors & FS_FWHON_RATE_LIMIT) == 0)
		add_note (page,
			_("Windows Firewall applies these rules without the rate "
			  "limits the Linux backend puts on its ICMP accepts."));

	/* Linux filters IPv6 too (1.0.7), and IPv6 finds its neighbours
	 * and router with ICMPv6: those types are allowed whatever is
	 * ticked here.  Windows keeps its own core-networking rules. */
	if (fs_backend ()->ipv6_state != NULL)
		add_note (page,
			_("IPv6 uses the same choices. Neighbour discovery, router "
			  "advertisements, \"packet too big\" and DHCPv6 replies "
			  "are always allowed: IPv6 stops working without them."));

	return page;
}

/* [ build_tos_page ] -- offered wherever the backend sets
 * FS_FWSEC_TOS (today: Linux only), and honest there: Type-of-Service
 * marking is not wired into the generator, so every control on the
 * page is dead and says so.  The page exists to match the original's
 * layout; the UI smoke pins the admission note in place. */
static GtkWidget *
build_tos_page (PrefBinding *bind)
{
	static const struct { const gchar *key; const gchar *label; } types[] = {
		{ FS_PREFS_FW_TOS_CLIENT,          N_("Apply to typical client tasks (SSH, HTTP)") },
		{ FS_PREFS_FW_TOS_SERVER,          N_("Apply to typical server tasks (SSH, HTTP, HTTPS, POP3)") },
		{ FS_PREFS_FW_TOS_X,               N_("Apply to remote X server connections") },
		{ FS_PREFS_FW_TOS_OPT_TROUGHPUT,   N_("Maximize-Throughput") },
		{ FS_PREFS_FW_TOS_OPT_RELIABILITY, N_("Maximize Reliability") },
		{ FS_PREFS_FW_TOS_OPT_DELAY,       N_("Minimize-Delay") }
	};
	GtkWidget *page = page_new (_("ToS Filtering"));
	GtkWidget *master;

	add_note (page,
		_("Type-of-Service marking is not wired into the rule generator "
		  "in this port yet, so every setting on this page has no "
		  "effect.  It is shown to match the original layout."));

	add_explainer (page,
		_("Type of Service lets the firewall mark packets so routers "
		  "treat them differently."));

	master = add_check (page, bind, FS_PREFS_FW_FILTER_TOS,
	                    _("Enable ToS filtering"), TRUE, FALSE);
	bind->tos_master = master;

	add_section (page, _("Apply ToS to"));

	for (guint i = 0; i < G_N_ELEMENTS (types); i++) {
		GtkWidget *check = gtk_check_button_new_with_label (
			_(types[i].label));

		gtk_toggle_button_set_active (
			GTK_TOGGLE_BUTTON (check),
			fs_prefs_get_bool (types[i].key, FALSE));
		g_object_set_data_full (G_OBJECT (check), "pref-key",
		                        g_strdup (types[i].key), g_free);
		g_object_set_data (G_OBJECT (check), "pref-type",
		                   (gpointer) "bool");
		g_object_set_data (G_OBJECT (check), "can-work",
		                   GINT_TO_POINTER (0));

		bind->widgets = g_list_append (bind->widgets, check);
		bind->tos_types = g_list_append (bind->tos_types, check);
		gtk_box_pack_start (GTK_BOX (page), check, FALSE, FALSE, 0);
	}

	bind_dependents (master, &bind->tos_types);

	return page;
}

/* [ build_advanced_page ] -- live on both backends, one control per
 * effect the backend can actually reproduce.  The rejection method is
 * the one that is not: iptables offers REJECT as well as DROP, Windows
 * Firewall always drops silently, so on the backend without the
 * FS_FWHON_REJECT_METHOD bit the radio stays disabled with that
 * admission. */
static GtkWidget *
build_advanced_page (PrefBinding *bind)
{
	GtkWidget *page = page_new (_("Advanced Options"));
	gboolean reject_method =
		(fs_backend ()->fw_honors & FS_FWHON_REJECT_METHOD) != 0;

	add_section (page, _("Preferred packet rejection method"));
	add_radio_pair (page, bind, FS_PREFS_FW_DENY_PACKETS, TRUE,
	                _("Reject with error packet"),
	                _("Drop silently"), reject_method);

	if (!reject_method)
		add_note (page,
			_("Windows Firewall always drops blocked packets "
			  "silently and has no per-rule reject, so the "
			  "rejection method is fixed here.  The choice applies "
			  "to the Linux backend."));

	add_section (page, _("Broadcast traffic"));
	add_check (page, bind, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST,
	           _("Block broadcasts from external network"), FALSE, TRUE);
	add_check (page, bind, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST,
	           _("Block broadcasts from internal network"), FALSE, TRUE);

	add_section (page, _("Traffic validation"));
	add_check (page, bind, FS_PREFS_FW_BLOCK_NON_ROUTABLES,
	           _("Block traffic from reserved addresses on public interfaces"),
	           TRUE, TRUE);

	/* 1.0.7: only where the switch changes the generated rules.  Windows
	 * logs accepted connections through its audit policy instead. */
	if ((fs_backend ()->fw_honors & FS_FWHON_LOG_ALLOWED) != 0) {
		add_section (page, _("Event logging"));
		add_check (page, bind, FS_PREFS_FW_LOG_ALLOWED,
		           _("Log allowed connections (the first packet of each "
		             "new connection, at most 10 per second)"),
		           TRUE, TRUE);
	}

	return page;
}

/* [ create_sections_model ] -- identical layout to the original.  The
 * model carries three columns: the Section enum (for the callers that
 * care about semantics), the label, and the notebook page index the
 * row selects.  That third column exists because per-page FS_FWSEC_*
 * gating means the section enums of offered pages are no longer
 * contiguous -- ICMP Filtering may be section 5 while being notebook
 * page 4 -- and the sidebar must still land on the right page. */
static GtkTreeModel *
create_sections_model (void)
{
	GtkTreeStore *store = gtk_tree_store_new (3, G_TYPE_INT,
	                                          G_TYPE_STRING,
	                                          G_TYPE_INT);
	GtkTreeIter iter;
	GtkTreeIter *parent;
	guint page_index = 0;
	static const struct
	{
		Section     section;
		const gchar *label;
		gint        parent_index;   /* -1 for a top level row */
		guint32     bit;            /* FS_FWSEC_* for sub-pages,
		                             * 0 for the always-offered rows */
	} rows[] = {
		{ SECTION_INTERFACE,         N_("Interface"),         -1, 0 },
		{ SECTION_INTERFACE_EVENTS,  N_("Events"),            SECTION_INTERFACE, 0 },
		{ SECTION_INTERFACE_POLICY,  N_("Policy"),            SECTION_INTERFACE, 0 },
		{ SECTION_FIREWALL,          N_("Firewall"),          -1, 0 },
		{ SECTION_FIREWALL_NETWORK,  N_("Network Settings"),  SECTION_FIREWALL,
		  FS_FWSEC_NETWORK },
		{ SECTION_FIREWALL_ICMP,     N_("ICMP Filtering"),    SECTION_FIREWALL,
		  FS_FWSEC_ICMP },
		{ SECTION_FIREWALL_TOS,      N_("ToS Filtering"),     SECTION_FIREWALL,
		  FS_FWSEC_TOS },
		{ SECTION_FIREWALL_ADVANCED, N_("Advanced Options"),  SECTION_FIREWALL,
		  FS_FWSEC_ADVANCED }
	};

	parent = NULL;

	for (guint i = 0; i < G_N_ELEMENTS (rows); i++) {
		GtkTreeIter *container = NULL;

		/* WYSIWYG: only offer the settings pages the backend
		 * actually reads.  The Windows backend used to ignore every
		 * one of them, and showing the pages asked the user to
		 * configure a firewall that was not listening; now that it
		 * reads some (ICMP, Advanced Options) those appear and the
		 * rest stay hidden, each gated by its own FS_FWSEC_* bit.
		 * The notebook below drops the matching pages too, so the
		 * section index and the page index stay aligned. */
		if (rows[i].parent_index == SECTION_FIREWALL &&
		    (fs_backend ()->fw_sections & rows[i].bit) == 0)
			continue;

		if (rows[i].parent_index < 0) {
			gtk_tree_store_append (store, &iter, NULL);
			container = g_new (GtkTreeIter, 1);
			*container = iter;
		} else {
			/* The parent is the top level row added just before
			 * its first sibling. */
			gtk_tree_store_append (store, &iter, parent);
		}

		gtk_tree_store_set (store, &iter,
		                    0, (gint) rows[i].section,
		                    1, _(rows[i].label),
		                    2, (gint) page_index,
		                    -1);
		page_index++;

		if (container != NULL) {
			g_free (parent);
			parent = container;
		}
	}

	g_free (parent);

	return GTK_TREE_MODEL (store);
}

/* [ on_pref_help_clicked ]
 * Help reports and stays put; it must not close the dialog, so it
 * never calls gtk_dialog_response(). */
static void
on_pref_help_clicked (GtkButton *button, gpointer data)
{
	(void) button;

	fs_dialogs_info (GTK_WIDGET (data), _("Preferences help"),
		_("Interface holds how this program behaves, Firewall holds "
		  "what the firewall is told to do.\n\n"
		  "Settings that would change nothing on this system are "
		  "greyed out, with a note saying why."));
}

/* [ on_pref_response_clicked ]
 * Cancel and Accept, answering through the response id each carries. */
static void
on_pref_response_clicked (GtkButton *button, gpointer data)
{
	gint response = GPOINTER_TO_INT (
		g_object_get_data (G_OBJECT (button), "pref-response"));

	gtk_dialog_response (GTK_DIALOG (data), response);
}

/* [ fs_dialogs_preferences ]
 * Modal; settings are written only when Accept is pressed. */
void
fs_dialogs_preferences (GtkWidget *parent)
{
	PrefBinding bind = { NULL, NULL, NULL, NULL, NULL };
	GtkWidget *dialog;
	GtkWidget *hbox, *tree, *notebook, *scroll;
	GtkWidget *area;
	GtkTreeModel *model;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;
	guint32 sections = fs_backend ()->fw_sections;
	gint response;

	install_prefs_css ();

	dialog = gtk_dialog_new ();
	gtk_window_set_title (GTK_WINDOW (dialog), _("Preferences"));
	gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);
	gtk_window_set_default_size (GTK_WINDOW (dialog), 640, 480);

	/* Clamp to the screen: on a narrow or DPI-scaled display a fixed
	 * 640 ran past the right edge and took Accept with it. */
	{
		GdkDisplay *display = gdk_display_get_default ();

		if (display != NULL) {
			GdkMonitor *monitor =
				gdk_display_get_primary_monitor (display);

			if (monitor != NULL) {
				GdkRectangle workarea;

				gdk_monitor_get_workarea (monitor, &workarea);

				if (workarea.width > 0 && 640 > workarea.width)
					gtk_window_set_default_size (
						GTK_WINDOW (dialog),
						MAX (workarea.width - 20, 400),
						MIN (480, workarea.height - 20));
			}
		}
	}

	if (parent != NULL) {
		gtk_window_set_transient_for (GTK_WINDOW (dialog),
		                              GTK_WINDOW (parent));
		gtk_window_set_destroy_with_parent (GTK_WINDOW (dialog), TRUE);
	}

	/* The button row is assembled further down rather than with
	 * gtk_dialog_add_button(): the original put Help alone at the far
	 * left and Cancel/Accept together at the far right, and the
	 * built-in action area cannot be split.  Reading it back would
	 * need gtk_dialog_get_action_area(), which is deprecated. */

	/* Sections on the left. */
	model = create_sections_model ();
	tree = gtk_tree_view_new_with_model (model);
	g_object_unref (model);

	/* Without this the sidebar renders as a blank white box: a
	 * GtkTreeView draws only through cell renderers, so a model with
	 * eight rows and no column still shows nothing.  The original got
	 * this from Glade (preferences.c line 929) and the port initially
	 * dropped it. */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("", renderer,
	                                                   "text", 1, NULL);
	gtk_tree_view_append_column (GTK_TREE_VIEW (tree), column);

	gtk_tree_view_set_headers_visible (GTK_TREE_VIEW (tree), FALSE);
	gtk_tree_view_set_enable_search (GTK_TREE_VIEW (tree), FALSE);
	gtk_widget_set_size_request (tree, 175, 320);
	g_object_set (G_OBJECT (tree), "activate-on-single-click", FALSE, NULL);

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), tree);

	/* Pages on the right, in section order. */
	notebook = gtk_notebook_new ();
	gtk_notebook_set_show_tabs (GTK_NOTEBOOK (notebook), FALSE);
	gtk_notebook_set_show_border (GTK_NOTEBOOK (notebook), FALSE);

	gtk_notebook_append_page (GTK_NOTEBOOK (notebook),
	                          wrap_page (build_interface_page (&bind)), NULL);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook),
	                          wrap_page (build_events_page (&bind)), NULL);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook),
	                          wrap_page (build_policy_page (&bind)), NULL);
	gtk_notebook_append_page (GTK_NOTEBOOK (notebook),
	                          wrap_page (build_firewall_page (&bind)), NULL);

	/* The settings pages exist only for the FS_FWSEC_* bits the
	 * backend sets; create_sections_model() skipped the matching
	 * sidebar rows, so row i stays on page i. */
	if (sections & FS_FWSEC_NETWORK)
		gtk_notebook_append_page (GTK_NOTEBOOK (notebook),
		                          wrap_page (build_network_page (&bind)),
		                          NULL);
	if (sections & FS_FWSEC_ICMP)
		gtk_notebook_append_page (GTK_NOTEBOOK (notebook),
		                          wrap_page (build_icmp_page (&bind)),
		                          NULL);
	if (sections & FS_FWSEC_TOS)
		gtk_notebook_append_page (GTK_NOTEBOOK (notebook),
		                          wrap_page (build_tos_page (&bind)), NULL);
	if (sections & FS_FWSEC_ADVANCED)
		gtk_notebook_append_page (GTK_NOTEBOOK (notebook),
		                          wrap_page (build_advanced_page (&bind)),
		                          NULL);

	hbox = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
	/* The tree expands too: with it packed FALSE it stayed at its
	 * 320px request and the dialog looked half-empty on the left while
	 * pages were clipped on the right. */
	gtk_box_pack_start (GTK_BOX (hbox), scroll, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (hbox), notebook, TRUE, TRUE, 0);

	area = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
	gtk_container_set_border_width (GTK_CONTAINER (area), 10);
	gtk_box_pack_start (GTK_BOX (area), hbox, TRUE, TRUE, 0);

	/* [ Help |  (gap)  | Cancel | Accept ], the original's row.  Every
	 * button is packed with pack_start so the left-to-right order is
	 * simply the order of the calls and cannot depend on how GtkBox
	 * lays out pack_end children. */
	{
		GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
		GtkWidget *help = gtk_button_new_with_mnemonic (_("_Help"));
		GtkWidget *cancel = gtk_button_new_with_mnemonic (_("_Cancel"));
		GtkWidget *accept = gtk_button_new_with_mnemonic (_("_Accept"));
		GtkWidget *spacer = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);

		gtk_button_set_image (GTK_BUTTON (help),
		                      gtk_image_new_from_icon_name (
		                              "help-contents", GTK_ICON_SIZE_BUTTON));
		g_signal_connect (help, "clicked",
		                  G_CALLBACK (on_pref_help_clicked), dialog);

		g_object_set_data (G_OBJECT (cancel), "pref-response",
		                   GINT_TO_POINTER (GTK_RESPONSE_CANCEL));
		g_signal_connect (cancel, "clicked",
		                  G_CALLBACK (on_pref_response_clicked), dialog);

		gtk_button_set_image (GTK_BUTTON (accept),
		                      gtk_image_new_from_icon_name (
		                              "emblem-default", GTK_ICON_SIZE_BUTTON));
		g_object_set_data (G_OBJECT (accept), "pref-response",
		                   GINT_TO_POINTER (GTK_RESPONSE_OK));
		g_signal_connect (accept, "clicked",
		                  G_CALLBACK (on_pref_response_clicked), dialog);

		gtk_widget_set_can_default (accept, TRUE);

		gtk_box_pack_start (GTK_BOX (row), help, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (row), spacer, TRUE, TRUE, 0);
		gtk_box_pack_start (GTK_BOX (row), cancel, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (row), accept, FALSE, FALSE, 0);

		gtk_widget_set_margin_top (row, 8);
		gtk_box_pack_start (GTK_BOX (area), row, FALSE, FALSE, 0);

		/* Only once Accept is inside the dialog: grab_default()
		 * beforehand warns "widget not within a GtkWindow". */
		gtk_widget_grab_default (accept);
		gtk_dialog_set_default_response (GTK_DIALOG (dialog),
		                                 GTK_RESPONSE_OK);
	}

	/* Switch pages as the selection moves, as the original did. */
	g_signal_connect (tree, "cursor-changed",
	                  G_CALLBACK (on_section_changed), notebook);

	/* The original expanded the whole section tree (preferences.c
	 * line 931).  It also has to happen here: a child row that has
	 * never been shown cannot take the cursor, so Events and Policy
	 * would be unselectable. */
	gtk_tree_view_expand_all (GTK_TREE_VIEW (tree));

	{
		GtkTreePath *path = gtk_tree_path_new_from_string ("0");

		gtk_tree_view_set_cursor (GTK_TREE_VIEW (tree), path, NULL, FALSE);
		gtk_tree_path_free (path);
	}

	gtk_widget_show_all (dialog);

	/* Help is handled by its own callback and does not close the
	 * dialog, so every response that reaches here is a real decision. */
	response = gtk_dialog_run (GTK_DIALOG (dialog));

	if (response == GTK_RESPONSE_OK)
		save_preferences (&bind);

	g_list_free (bind.widgets);
	g_list_free (bind.icmp_types);
	g_list_free (bind.tos_types);
	gtk_widget_destroy (dialog);
}

static void
on_section_changed (GtkTreeView *view, gpointer data)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection (view);
	GtkTreeModel *model;
	GtkTreeIter iter;
	gint page = 0;

	if (!gtk_tree_selection_get_selected (selection, &model, &iter))
		return;

	/* Column 2, not the Section enum: with per-page gating the enums
	 * of the offered pages need not be contiguous, while the notebook
	 * index always is. */
	gtk_tree_model_get (model, &iter, 2, &page, -1);
	gtk_notebook_set_current_page (GTK_NOTEBOOK (data), page);
}

static void
save_preferences (PrefBinding *bind)
{
	for (GList *l = bind->widgets; l != NULL; l = l->next) {
		GtkWidget *widget = l->data;
		const gchar *key = g_object_get_data (G_OBJECT (widget), "pref-key");
		const gchar *type = g_object_get_data (G_OBJECT (widget), "pref-type");

		if (key == NULL || type == NULL)
			continue;

		if (g_strcmp0 (type, "bool") == 0) {
			fs_prefs_set_bool (key,
			                   gtk_toggle_button_get_active (
			                   GTK_TOGGLE_BUTTON (widget)));

		} else if (g_strcmp0 (type, "radio") == 0) {
			/* Only the selected radio of the pair reports. */
			if (gtk_toggle_button_get_active (
			        GTK_TOGGLE_BUTTON (widget)))
				fs_prefs_set_bool (key, GPOINTER_TO_INT (
					g_object_get_data (G_OBJECT (widget),
					"pref-value")) != 0);

		} else if (g_strcmp0 (type, "combo") == 0) {
			const gchar *id = gtk_combo_box_get_active_id (
				GTK_COMBO_BOX (widget));

			fs_prefs_set_string (key, id != NULL ? id : "");
		}
	}

	fs_prefs_save ();
	fs_app_reload_settings ();
}