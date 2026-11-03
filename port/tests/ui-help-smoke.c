/* fs-help-smoke: the Help window and the About window (1.0.7).
 *
 * Builds the real main window (fs_app_activate, in a GtkApplication,
 * with every file it reads or writes moved to a scratch directory) and
 * checks, each seen failing with its bug put back (tests/README.md):
 *
 *   H1  the app.help action and F1 on the main window open Help at
 *       the topic for the page shown (Threat Intel included); the
 *       sidebar's Help item too
 *   H2  every topic renders, and shows every block it has; all markup
 *       parses, every help: link and related id resolves, no em dash
 *   H7  claims the code does not back are gone, and what it really
 *       does is said: what is logged on Linux, the Windows broadcast
 *       and reserved-address blocks, when an expired Sentinel block
 *       leaves the firewall, rule names, what the licence is
 *   H8  1.0.7 as merged: threat intel (PR #18), What-If, the tray
 *       menu and its Help item, start at sign-in, one copy per user,
 *       the hidden start, the Linux boot service and blocking by
 *       country or network owner (ASN) are described in the present
 *       tense, as the code does them; no "Not in this build" callout
 *       is left anywhere; the country text says "registered in", warns
 *       about anycast, carries the licence line, says the database is
 *       downloaded at most once a day, and names Windows as a platform
 *       that does not support it
 *   H3  search filters the topic list (and says when nothing matches);
 *       Enter opens the first topic found
 *   H4  links, related chips, Next, Back and Forward navigate
 *   H5  Preferences' Help button and F1 open the topic for the page it
 *       shows, and Help takes input while Preferences is modal
 *   H6  one Help window: asking again raises it
 *   H9  What-If's settings fixes open Preferences at the page that
 *       holds the switch they name, and every switch and page name the
 *       engine may use is in the dialog as written
 *   A1  About: the exact creator credit, no e-mail address, the
 *       licence summary true to the source, both licence texts, one
 *       window, transient for the main window, not modal
 *   A2  "Copy system info": versions, platform, backend; no user name,
 *       host name or home path; the clipboard gets exactly that
 *   K1  keyboard: Tab in About reaches every control; the Help topic
 *       list is one Tab stop and moving focus along it opens nothing
 *       (Enter does); Help opens with focus on the topic, not in the
 *       search field; every focusable control has a name for a
 *       screen reader
 *   L1  layout: key caps keep their height beside wrapped text; Help
 *       fits a 640-pixel window on every topic; the page column stops
 *       at about 80 characters on a wide window; related-topic chips
 *       sit 6 pixels apart; Help and Preferences share one sidebar
 *       width
 *   T1  under the theme in GTK_THEME (Adwaita:dark when unset) every
 *       label in Help and About is 4.5:1 or more against what is
 *       painted behind it
 *   W   no GTK warning or critical while any of it runs
 *
 * STOCKFW_HELP_SHOTS=<dir> saves PNGs of three topics and of About,
 * named after GTK_THEME ("light" or "dark").
 *
 *   ninja -C build-linux fs-help-smoke
 *   xvfb-run -a ./build-linux/fs-help-smoke
 *   GTK_THEME=Adwaita xvfb-run -a ./build-linux/fs-help-smoke
 */

#include "ui/fs-app.h"
#include "ui/fs-dialogs.h"
#include "ui/fs-helpcontent.h"
#include "ui/fs-helpwindow.h"
#include "core/fs-backend.h"
#include "core/fs-prefs.h"
#include "core/fs-whatif.h"

#include <gtk/gtk.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#ifndef FS_VERSION
#define FS_VERSION "1.0.7"
#endif

static int failures = 0;
static int warnings = 0;
static GtkApplication *app = NULL;

#define CHECK(cond, ...) do {                                   \
	if (cond) {                                                \
		printf ("ok:   ");                                \
	} else {                                                  \
		printf ("FAIL: ");                                \
		failures++;                                        \
	}                                                         \
	printf (__VA_ARGS__);                                     \
	printf ("\n");                                            \
} while (0)

/* The step running now, named on stderr before it starts, so a GTK
 * warning in the log sits under the step that caused it; [W] names the
 * step of the first one. */
static const gchar *step = "start";
static const gchar *first_warning_step = NULL;

static void
begin_step (const gchar *name)
{
	step = name;
	g_printerr ("== step: %s\n", name);
}

static GLogWriterOutput
count_warnings (GLogLevelFlags level, const GLogField *fields,
                gsize n_fields, gpointer data)
{
	(void) data;
	if (level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL)) {
		warnings++;
		if (first_warning_step == NULL)
			first_warning_step = step;
	}
	return g_log_writer_default (level, fields, n_fields, NULL);
}

/* ========================================================== helpers */

static void
pump (void)
{
	for (gint i = 0; i < 5; i++) {
		while (gtk_events_pending ())
			gtk_main_iteration ();
		g_usleep (15000);
	}
}

static GtkWidget *
find_named (GtkWidget *root, const gchar *name)
{
	GtkWidget *found = NULL;
	GList *children;

	if (root == NULL)
		return NULL;
	if (g_strcmp0 (gtk_widget_get_name (root), name) == 0)
		return root;
	if (!GTK_IS_CONTAINER (root))
		return NULL;
	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (GList *l = children; l != NULL && found == NULL; l = l->next)
		found = find_named (l->data, name);
	g_list_free (children);
	return found;
}

static GtkWidget *
find_toplevel (const gchar *name)
{
	GList *windows = gtk_window_list_toplevels ();
	GtkWidget *found = NULL;

	for (GList *l = windows; l != NULL; l = l->next)
		if (g_strcmp0 (gtk_widget_get_name (l->data), name) == 0)
			found = l->data;
	g_list_free (windows);
	return found;
}

static guint
count_toplevels (const gchar *name)
{
	GList *windows = gtk_window_list_toplevels ();
	guint n = 0;

	for (GList *l = windows; l != NULL; l = l->next)
		if (g_strcmp0 (gtk_widget_get_name (l->data), name) == 0)
			n++;
	g_list_free (windows);
	return n;
}

/* Every label's text under root, and every button label, joined. */
static void
gather_text (GtkWidget *root, GString *out)
{
	GList *children;

	if (GTK_IS_LABEL (root)) {
		g_string_append (out, gtk_label_get_text (GTK_LABEL (root)));
		g_string_append_c (out, '\n');
	}
	if (GTK_IS_BUTTON (root) && gtk_button_get_label (GTK_BUTTON (root))) {
		g_string_append (out, gtk_button_get_label (GTK_BUTTON (root)));
		g_string_append_c (out, '\n');
	}
	if (!GTK_IS_CONTAINER (root))
		return;
	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (GList *l = children; l != NULL; l = l->next)
		gather_text (l->data, out);
	g_list_free (children);
}

static gchar *
text_of (GtkWidget *root)
{
	GString *s = g_string_new (NULL);

	gather_text (root, s);
	return g_string_free (s, FALSE);
}

/* Collects the labels under root. */
static void
collect_labels (GtkWidget *root, GPtrArray *out)
{
	GList *children;

	if (GTK_IS_LABEL (root))
		g_ptr_array_add (out, root);
	if (!GTK_IS_CONTAINER (root))
		return;
	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (GList *l = children; l != NULL; l = l->next)
		collect_labels (l->data, out);
	g_list_free (children);
}

/* A key press and release on `window', delivered as the display would:
 * through gtk_main_do_event, which honours window groups and grabs. */
static void
send_key (GtkWidget *window, guint keyval, GdkModifierType state)
{
	GdkDisplay *display = gtk_widget_get_display (window);
	GdkKeymap *keymap = gdk_keymap_get_for_display (display);
	GdkDevice *keyboard =
		gdk_seat_get_keyboard (gdk_display_get_default_seat (display));
	GdkKeymapKey *keys = NULL;
	gint n_keys = 0;

	g_object_ref (window);
	for (gint pass = 0; pass < 2; pass++) {
		GdkEvent *ev;

		/* The press may have closed the window (Ctrl+W). */
		if (gtk_widget_in_destruction (window)
		    || gtk_widget_get_window (window) == NULL)
			break;
		ev = gdk_event_new (pass == 0 ? GDK_KEY_PRESS : GDK_KEY_RELEASE);

		ev->key.window = g_object_ref (gtk_widget_get_window (window));
		ev->key.send_event = TRUE;
		ev->key.time = GDK_CURRENT_TIME;
		ev->key.keyval = keyval;
		ev->key.state = state;
		if (gdk_keymap_get_entries_for_keyval (keymap, keyval, &keys,
		                                       &n_keys) && n_keys > 0) {
			ev->key.hardware_keycode = keys[0].keycode;
			ev->key.group = keys[0].group;
		}
		g_free (keys);
		keys = NULL;
		gdk_event_set_device (ev, keyboard);
		gtk_main_do_event (ev);
		gdk_event_free (ev);
	}
	g_object_unref (window);
	pump ();
}

static void
close_help (void)
{
	if (fs_help_window () != NULL)
		gtk_widget_destroy (fs_help_window ());
	pump ();
}

static void
click (GtkWidget *root, const gchar *name)
{
	GtkWidget *w = find_named (root, name);

	if (w != NULL && GTK_IS_BUTTON (w))
		gtk_button_clicked (GTK_BUTTON (w));
	else
		CHECK (FALSE, "button %s exists", name);
	pump ();
}

static const gchar *
theme_tag (void)
{
	const gchar *t = g_getenv ("GTK_THEME");

	return t != NULL && strstr (t, "dark") != NULL ? "dark" : "light";
}

static void
shot (GtkWidget *window, const gchar *name)
{
	const gchar *dir = g_getenv ("STOCKFW_HELP_SHOTS");
	GdkWindow *gw;
	GdkPixbuf *pix;
	gchar *file;

	if (dir == NULL)
		return;
	g_mkdir_with_parents (dir, 0755);
	gtk_window_present (GTK_WINDOW (window));
	for (gint i = 0; i < 4; i++)
		pump ();
	gw = gtk_widget_get_window (window);
	pix = gdk_pixbuf_get_from_window (gw, 0, 0, gdk_window_get_width (gw),
	                                  gdk_window_get_height (gw));
	file = g_strdup_printf ("%s/%s-%s.png", dir, name, theme_tag ());
	if (pix != NULL && gdk_pixbuf_save (pix, file, "png", NULL, NULL))
		printf ("shot: %s\n", file);
	if (pix != NULL)
		g_object_unref (pix);
	g_free (file);
}

/* ======================================================= contrast */

static gdouble
channel (gdouble c)
{
	return c <= 0.03928 ? c / 12.92 : pow ((c + 0.055) / 1.055, 2.4);
}

static gdouble
luminance (const GdkRGBA *c)
{
	return 0.2126 * channel (c->red) + 0.7152 * channel (c->green)
	     + 0.0722 * channel (c->blue);
}

static gdouble
contrast (const GdkRGBA *a, const GdkRGBA *b)
{
	gdouble la = luminance (a), lb = luminance (b);

	return (MAX (la, lb) + 0.05) / (MIN (la, lb) + 0.05);
}

/* What is painted behind `widget': its own background or the nearest
 * ancestor's that is not transparent. */
static void
background_of (GtkWidget *widget, GdkRGBA *out)
{
	for (GtkWidget *w = widget; w != NULL; w = gtk_widget_get_parent (w)) {
		GtkStyleContext *ctx = gtk_widget_get_style_context (w);
		GdkRGBA *bg = NULL;

		gtk_style_context_get (ctx, gtk_style_context_get_state (ctx),
		                       "background-color", &bg, NULL);
		if (bg != NULL && bg->alpha > 0.5) {
			*out = *bg;
			gdk_rgba_free (bg);
			return;
		}
		if (bg != NULL)
			gdk_rgba_free (bg);
	}
	gdk_rgba_parse (out, "#ffffff");
}

/* Every drawable label under root: 4.5:1 at least.  Returns how many
 * were measured; the worst is printed. */
static guint
check_contrast (GtkWidget *root, const gchar *where)
{
	GPtrArray *labels = g_ptr_array_new ();
	gdouble worst = 100.0;
	const gchar *worst_text = "";
	guint measured = 0, bad = 0;

	collect_labels (root, labels);
	for (guint i = 0; i < labels->len; i++) {
		GtkWidget *label = g_ptr_array_index (labels, i);
		GtkStyleContext *ctx = gtk_widget_get_style_context (label);
		GdkRGBA fg, bg;
		gdouble ratio;

		if (!gtk_widget_is_drawable (label)
		    || *gtk_label_get_text (GTK_LABEL (label)) == '\0')
			continue;
		gtk_style_context_get_color (ctx,
		                             gtk_style_context_get_state (ctx),
		                             &fg);
		background_of (label, &bg);
		ratio = contrast (&fg, &bg);
		measured++;
		if (ratio < 4.5) {
			bad++;
			if (bad <= 3)
				printf ("       low contrast %.2f: \"%.40s\"\n",
				        ratio,
				        gtk_label_get_text (GTK_LABEL (label)));
		}
		if (ratio < worst) {
			worst = ratio;
			worst_text = gtk_label_get_text (GTK_LABEL (label));
		}
	}
	CHECK (measured > 0 && bad == 0,
	       "[T1 %s] %s: %u labels at 4.5:1 or more (worst %.2f, \"%.30s\")",
	       theme_tag (), where, measured, worst, worst_text);
	g_ptr_array_unref (labels);
	return measured;
}

/* ===================================================== H2: content */

/* GtkLabel's markup: Pango's plus <a href="...">, which GtkLabel takes
 * out before Pango sees the rest.  Same here. */
static gchar *
without_links (const gchar *markup)
{
	GString *bare = g_string_new (NULL);

	for (const gchar *p = markup; *p != '\0'; ) {
		if (g_str_has_prefix (p, "<a ") || g_str_has_prefix (p, "</a>")) {
			const gchar *end = strchr (p, '>');

			if (end == NULL)
				break;
			p = end + 1;
			continue;
		}
		g_string_append_c (bare, *p++);
	}
	return g_string_free (bare, FALSE);
}

static gboolean
markup_ok (const gchar *markup)
{
	GError *error = NULL;
	gchar *bare = without_links (markup);
	gboolean ok = pango_parse_markup (bare, -1, 0, NULL, NULL, NULL,
	                                  &error);

	g_free (bare);

	if (!ok)
		printf ("       markup: %s\n", error ? error->message : "?");
	g_clear_error (&error);
	return ok;
}

/* Every href in markup: help:ID must name a topic, anything else must
 * be https. */
static gboolean
links_ok (const gchar *markup)
{
	const gchar *p = markup;
	gboolean ok = TRUE;

	while ((p = strstr (p, "href=\"")) != NULL) {
		const gchar *start = p + 6;
		const gchar *end = strchr (start, '"');
		gchar *uri;

		if (end == NULL)
			return FALSE;
		uri = g_strndup (start, end - start);
		if (g_str_has_prefix (uri, "help:")) {
			if (fs_help_topic_find (uri + 5) == NULL) {
				printf ("       dead link %s\n", uri);
				ok = FALSE;
			}
		} else if (!g_str_has_prefix (uri, "https://")) {
			printf ("       odd link %s\n", uri);
			ok = FALSE;
		}
		g_free (uri);
		p = end;
	}
	return ok;
}

/* One topic's text, every block's markup, joined. */
static gchar *
topic_text (const gchar *id)
{
	const FsHelpTopic *t = fs_help_topic_find (id);
	GString *all = g_string_new (NULL);

	if (t != NULL)
		for (const FsHelpBlock *b = t->blocks; b->kind != FS_HELP_END;
		     b++) {
			g_string_append (all, b->text);
			g_string_append_c (all, '\n');
		}
	/* The C source wraps strings; compare with single spaces. */
	for (gchar *c = all->str; *c != '\0'; c++)
		if (*c == '\n')
			*c = ' ';
	return g_string_free (all, FALSE);
}

/* H7: each claim the review found the code does not back (ACC-1 to
 * ACC-9) must be gone, and the true statement there instead. */
static void
check_claims (void)
{
	static const struct
	{
		const gchar *id, *gone, *said, *what;
	} claims[] = {
		{ "events", "Packets your rules block are logged",
		  "your outbound deny rules",
		  "ACC-1: Linux logs only the default drops; deny rules, "
		  "Sentinel and Protection drops are not logged" },
		{ "events", "length and type of service",
		  "In and Out are the network adapters",
		  "HELP-EVENTS-COLS: only the columns Events shows are named "
		  "(Length and ToS are hidden and cannot be shown)" },
		{ "troubleshooting", "blocked traffic only once something is "
		  "blocked", "a quiet list does not mean they blocked nothing",
		  "ACC-1: a quiet Events list is no proof nothing was blocked" },
		{ "prefs-protection", "Internet device on Linux, or on networks "
		  "Windows treats as public",
		  "The two broadcast blocks are not offered on Windows",
		  "ACC-2: the Windows broadcast blocks block nothing" },
		{ "prefs-protection", "public networks on Windows",
		  "including connections your own allow rules let in",
		  "ACC-3: on Windows the reserved block outranks your allows "
		  "on public networks" },
		{ "whatif", "<b>Block outgoing unless allowed</b>, or at rules",
		  "the broadcast and reserved-address blocks",
		  "ACC-3 (1.0.7 What-If): the answer takes the Protection "
		  "settings into account" },
		{ "background", "starts again and lifts it",
		  "a block whose ten minutes ran out meanwhile is taken off",
		  "ACC-4 (1.0.7): an expired Sentinel block is taken off when "
		  "StockFW starts again with the rights to" },
		{ "windows", "<tt>StockFW-</tt> followed", "names start with",
		  "ACC-6: rule names start with StockFW" },
		{ "threat-intel", "Windows, and blocking by country",
		  "Windows Firewall block rules in the group",
		  "ACC-7: threat intel works on Windows too" },
		{ "windows", "the one system setting StockFW changes besides",
		  "turning profiles on or off",
		  "ACC-8: StockFW also turns profiles on and off" },
		{ "about", "version 2 (COPYING), under which",
		  "version 2 or any later version",
		  "ACC-9: the ported code is GPL 2 or later" },
	};

	for (guint i = 0; i < G_N_ELEMENTS (claims); i++) {
		gchar *text = topic_text (claims[i].id);
		gchar *flat = g_strdup (text);
		GString *squeezed = g_string_new (NULL);

		/* Adjacent C strings run together with no space between;
		 * the needles are written as they read. */
		for (const gchar *c = flat; *c != '\0'; c++)
			if (!(*c == ' ' && squeezed->len > 0
			      && squeezed->str[squeezed->len - 1] == ' '))
				g_string_append_c (squeezed, *c);
		CHECK (strstr (squeezed->str, claims[i].gone) == NULL
		       && strstr (squeezed->str, claims[i].said) != NULL,
		       "[H7] %s (%s)", claims[i].what, claims[i].id);
		g_string_free (squeezed, TRUE);
		g_free (flat);
		g_free (text);
	}
}

/* H8: the features PR #14, #17 and #18 and country and network-owner
 * blocking brought into this build are described as present, in the
 * words the code uses; no topic carries a "Not in this build"
 * callout. */
static void
check_merged_107 (void)
{
	static const struct
	{
		const gchar *id, *gone, *said, *what;
	} claims[] = {
		{ "whatif", "A line with no direction is read as outbound",
		  "<b>DEPENDS</b>",
		  "What-If answers DEPENDS and asks both ways when the line "
		  "names no direction" },
		{ "whatif", "It does not look at whether the firewall is running",
		  "whether the firewall is running",
		  "What-If takes the firewall's state into account" },
		{ "whatif", "Create This Rule", "<b>Create allow rule</b>",
		  "What-If's fixes carry the window's button names" },
		{ "background", "<b>Open StockFW</b>, <b>About StockFW</b> and "
		  "<b>Quit StockFW</b>", "<b>Quit (firewall stays on)</b>",
		  "the tray menu is described as it is" },
		{ "background", "Coming in", "<b>Help</b> (which opens this "
		  "topic)", "the tray menu's Help item opens this topic" },
		{ "background", "Coming in", "brings the running window forward",
		  "one StockFW per user" },
		{ "background", "Coming in", "<tt>StockFW --background</tt>",
		  "the hidden start" },
		{ "sentinel", "coming in 1.0.7",
		  "<b>Pause Sentinel auto-block for 1 hour</b>",
		  "pausing Sentinel from the tray" },
		{ "prefs-general", "Starting StockFW at sign-in is coming",
		  "<b>Start StockFW in the background when I sign in</b>",
		  "the sign-in switch on the General page" },
		{ "linux", "is coming in 1.0.7", "<tt>stockfw.service</tt>",
		  "the Linux boot service" },
		{ "cli", "says blocked.",
		  "6 simulate says it depends",
		  "stockfw simulate exits 6 for DEPENDS" },
		/* Threat intel (PR #18) is in this build. */
		{ "threat-intel", "not available in this build",
		  "<b>Accept and turn on</b>",
		  "threat intel: turning a feed on and its terms dialog" },
		{ "threat-intel", "What is planned",
		  "<i>would be blocked once in force</i>",
		  "threat intel: a lookup says blocked only when in force" },
		{ "threat-intel", "Until then", "<tt>inet stockfw_intel</tt>",
		  "threat intel: the Linux nftables table" },
		{ "threat-intel", "planned for both platforms",
		  "<b>StockFW Threat Intel</b>",
		  "threat intel: the Windows Firewall rule group" },
		{ "threat-intel", "comes later",
		  "does not count what each rule blocks",
		  "threat intel: Windows keeps no per-rule counts" },
		{ "threat-intel", "Safeguards planned",
		  "<b>Accept smaller list</b>",
		  "threat intel: the update judge refuses a suspicious copy" },
		{ "threat-intel", "makes no network connection for them",
		  "<tt>/api/intel</tt>",
		  "threat intel: the CLI and the dashboard" },
		{ "events", "Coming in", "offers <b>Add exception</b>",
		  "Events names the list on Linux and offers an exception" },
		{ "whatif", "Blocked by threat intel",
		  "does not consult the",
		  "What-If says it does not consult the blocklists" },
		{ "linux", "Coming in", "<tt>inet stockfw_intel</tt>",
		  "Linux notes name the blocklists' nftables table" },
		{ "windows", "Coming in", "<b>StockFW Threat Intel</b>",
		  "Windows notes name the blocklists' rule group" },
		{ "cli", "Coming in", "<tt>stockfw intel lookup</tt> and an "
		  "address", "the cli topic lists stockfw intel" },
		{ "background", "Coming in", "checks once an hour for",
		  "background says when the blocklists update" },
		/* Country and network-owner blocking is in this build. */
		{ "threat-intel", "not in this build",
		  "<b>Use the location database</b>",
		  "countries: the switch, and the consent dialog naming the host" },
		{ "threat-intel", "is located in",
		  "is registered, not where the computer using it is",
		  "countries: a country is where a range is registered" },
		{ "threat-intel", "Not in this build",
		  "<b>Anycast</b> mark",
		  "countries: the anycast warning and its mark" },
		{ "threat-intel", "CC BY-SA 4.0 licence",
		  "licensed CC BY-SA 4.0, as IPFire has confirmed",
		  "countries: the licence, as IPFire confirmed it" },
		{ "threat-intel", "every hour",
		  "downloaded at most once a day",
		  "countries: the database is downloaded at most once a day" },
		{ "threat-intel", "Windows yet",
		  "not supported on Windows in this version of StockFW",
		  "countries: Windows does not support it, said as a limit" },
		{ "cli", "Coming in", "<tt>stockfw intel geo</tt>",
		  "the cli topic lists stockfw intel geo" },
	};
	guint soon_elsewhere = 0, soon_any = 0;

	for (guint i = 0; i < G_N_ELEMENTS (claims); i++) {
		gchar *text = topic_text (claims[i].id);
		GString *squeezed = g_string_new (NULL);

		for (const gchar *c = text; *c != '\0'; c++)
			if (!(*c == ' ' && squeezed->len > 0
			      && squeezed->str[squeezed->len - 1] == ' '))
				g_string_append_c (squeezed, *c);
		CHECK (strstr (squeezed->str, claims[i].gone) == NULL
		       && strstr (squeezed->str, claims[i].said) != NULL,
		       "[H8] %s (%s)", claims[i].what, claims[i].id);
		g_string_free (squeezed, TRUE);
		g_free (text);
	}

	for (guint i = 0; i < fs_help_topic_count (); i++) {
		const FsHelpTopic *t = fs_help_topic_nth (i);

		for (const FsHelpBlock *b = t->blocks; b->kind != FS_HELP_END;
		     b++) {
			gboolean soon = b->kind == FS_HELP_SOON;
			gboolean says = b->text != NULL &&
			                strstr (b->text, "1.0.7") != NULL;

			/* Outside the callout, no sentence may say a feature
			 * is missing or on its way, whatever its case. */
			if (!soon && b->text != NULL) {
				gchar *low = g_ascii_strdown (b->text, -1);

				if (strstr (low, "in this build") != NULL ||
				    strstr (low, "planned") != NULL ||
				    strstr (low, "coming in") != NULL ||
				    strstr (low, "coming soon") != NULL)
					says = TRUE;
				g_free (low);
			}

			if (soon)
				soon_any++;
			else if (says)
				soon_elsewhere++;
		}
		{
			gchar *low = g_ascii_strdown (t->summary, -1);

			if (strstr (low, "coming") != NULL ||
			    strstr (low, "planned") != NULL ||
			    strstr (low, "in this build") != NULL)
				soon_elsewhere++;
			g_free (low);
		}
	}
	CHECK (soon_elsewhere == 0 && soon_any == 0,
	       "[H8] no \"Not in this build\" callout in any topic, and no "
	       "1.0.7, planned or coming wording (%u callouts, %u such "
	       "sentences)", soon_any, soon_elsewhere);
	{
		const FsHelpTopic *t = fs_help_topic_find ("threat-intel");

		CHECK (strstr (t->summary, "available") == NULL
		       && strstr (t->summary, "build") == NULL
		       && strstr (t->summary, "country") != NULL,
		       "[H8] the threat-intel summary describes blocklists and "
		       "countries as present (%s)", t->summary);
	}
	{
		/* The window shows the country section and no callout
		 * heading. */
		gchar *shown;

		fs_help_show (NULL, "threat-intel");
		pump ();
		shown = text_of (fs_help_window ());
		CHECK (strstr (shown, "Not in this build") == NULL &&
		       strstr (shown, "Coming in") == NULL &&
		       strstr (shown, "Countries and networks") != NULL &&
		       strstr (shown, "Location data: IPFire location "
		                      "database") != NULL,
		       "[H8] the threat-intel topic shows \"Countries and "
		       "networks\" with the licence line, and no \"Not in "
		       "this build\" heading");
		g_free (shown);
	}
}

static void
check_table (void)
{
	guint bad_markup = 0, bad_links = 0, bad_see = 0, dashes = 0;
	guint bad_parent = 0;
	const gchar *const required[] = {
		"getting-started", "overview", "events", "policy", "whatif",
		"sentinel", "trust", "activity", "preferences",
		"prefs-general", "prefs-events", "prefs-policy", "prefs-icmp",
		"prefs-protection", "threat-intel", "background", "cli",
		"linux", "windows", "troubleshooting", "shortcuts", "about",
	};

	CHECK (fs_help_topic_count () >= G_N_ELEMENTS (required),
	       "[H2] %u topics", fs_help_topic_count ());
	for (guint i = 0; i < G_N_ELEMENTS (required); i++)
		CHECK (fs_help_topic_find (required[i]) != NULL,
		       "[H2] topic %s exists", required[i]);

	for (guint i = 0; i < fs_help_topic_count (); i++) {
		const FsHelpTopic *t = fs_help_topic_nth (i);
		const gchar *heads[] = { t->title, t->summary, t->keywords };

		if (t->parent != NULL && fs_help_topic_find (t->parent) == NULL)
			bad_parent++;
		for (guint h = 0; h < G_N_ELEMENTS (heads); h++) {
			if (!markup_ok (heads[h]))
				bad_markup++;
			if (strstr (heads[h], "\xe2\x80\x94") != NULL)
				dashes++;
		}
		for (const FsHelpBlock *b = t->blocks; b->kind != FS_HELP_END;
		     b++) {
			if (strstr (b->text, "\xe2\x80\x94") != NULL)
				dashes++;
			if (b->kind == FS_HELP_SEE) {
				gchar **ids = g_strsplit (b->text, " ", -1);

				for (gchar **id = ids; *id != NULL; id++)
					if (fs_help_topic_find (*id) == NULL) {
						printf ("       %s: unknown "
						        "related %s\n", t->id, *id);
						bad_see++;
					}
				g_strfreev (ids);
				continue;
			}
			if (b->kind == FS_HELP_CODE)
				continue;
			if (!markup_ok (b->text)) {
				printf ("       in %s\n", t->id);
				bad_markup++;
			}
			if (!links_ok (b->text))
				bad_links++;
		}
	}
	CHECK (bad_markup == 0, "[H2] every topic string is valid markup");
	CHECK (bad_links == 0, "[H2] every help: link names a topic");
	CHECK (bad_see == 0, "[H2] every related topic exists");
	CHECK (bad_parent == 0, "[H2] every subtopic's parent exists");
	CHECK (dashes == 0, "[H2] no em dash in the help text");
}

/* The plain words a block must show, or NULL. */
static gchar *
block_words (const FsHelpBlock *b)
{
	gchar *plain = NULL, *bare;
	const gchar *bar;

	switch (b->kind) {
	case FS_HELP_CODE:
		return g_strdup (b->text);
	case FS_HELP_SEE:
	case FS_HELP_END:
		return NULL;
	case FS_HELP_KEYS:
		bar = strchr (b->text, '|');
		return g_strdup (bar != NULL ? bar + 1 : b->text);
	default:
		bare = without_links (b->text);
		if (!pango_parse_markup (bare, -1, 0, NULL, &plain, NULL,
		                         NULL))
			plain = g_strdup ("(markup that does not parse)");
		g_free (bare);
		return plain;
	}
}

static void
check_every_topic (void)
{
	GtkWidget *win;
	guint empty = 0, missing = 0, titles = 0;

	for (guint i = 0; i < fs_help_topic_count (); i++) {
		const FsHelpTopic *t = fs_help_topic_nth (i);
		GtkWidget *article, *title;
		gchar *text, *plain_title = NULL;

		fs_help_show (NULL, t->id);
		pump ();
		win = fs_help_window ();
		article = find_named (win, "help-article");
		title = find_named (win, "help-title");
		text = text_of (article);
		if (g_utf8_strlen (text, -1) < 80) {
			printf ("       %s renders only %ld characters\n",
			        t->id, (long) g_utf8_strlen (text, -1));
			empty++;
		}
		pango_parse_markup (t->title, -1, 0, NULL, &plain_title, NULL,
		                    NULL);
		if (title == NULL || g_strcmp0 (gtk_label_get_text (
		        GTK_LABEL (title)), plain_title) != 0)
			titles++;
		g_free (plain_title);

		for (const FsHelpBlock *b = t->blocks; b->kind != FS_HELP_END;
		     b++) {
			gchar *words = block_words (b);

			if (words != NULL && strstr (text, words) == NULL) {
				printf ("       %s: block %d not shown: "
				        "\"%.50s\"\n", t->id, (gint) b->kind,
				        words);
				missing++;
			}
			if (b->kind == FS_HELP_SEE) {
				gchar **ids = g_strsplit (b->text, " ", -1);

				for (gchar **id = ids; *id != NULL; id++) {
					gchar *chip = g_strconcat ("see:", *id,
					                           NULL);

					if (find_named (article, chip) == NULL) {
						printf ("       %s: no chip %s\n",
						        t->id, *id);
						missing++;
					}
					g_free (chip);
				}
				g_strfreev (ids);
			}
			g_free (words);
		}
		g_free (text);
	}
	CHECK (empty == 0, "[H2] every topic renders an article");
	CHECK (missing == 0, "[H2] every block of every topic is on screen");
	CHECK (titles == 0, "[H2] every topic shows its title");
}

/* ====================================================== H3: search */

static gboolean
row_listed (GtkWidget *win, const gchar *id)
{
	gchar *name = g_strconcat ("topic:", id, NULL);
	GtkWidget *row = find_named (win, name);

	g_free (name);
	return row != NULL && gtk_widget_get_child_visible (row)
	    && gtk_widget_get_visible (row);
}

static guint
rows_listed (GtkWidget *win)
{
	guint n = 0;

	for (guint i = 0; i < fs_help_topic_count (); i++)
		if (row_listed (win, fs_help_topic_nth (i)->id))
			n++;
	return n;
}

static void
check_search (void)
{
	GtkWidget *win, *search, *empty;
	guint all, listed;

	fs_help_show (NULL, "getting-started");
	pump ();
	win = fs_help_window ();
	search = find_named (win, "help-search");
	empty = find_named (win, "help-empty");
	CHECK (search != NULL && GTK_IS_SEARCH_ENTRY (search),
	       "[H3] Help has a search field");
	if (search == NULL)
		return;

	all = rows_listed (win);
	CHECK (!row_listed (win, "prefs-icmp"),
	       "[H3] subtopics fold away while their section is not shown");

	gtk_entry_set_text (GTK_ENTRY (search), "SSH locked");
	pump ();
	listed = rows_listed (win);
	CHECK (row_listed (win, "troubleshooting"),
	       "[H3] \"SSH locked\" finds Troubleshooting");
	CHECK (listed > 0 && listed < all && !row_listed (win, "activity"),
	       "[H3] \"SSH locked\" leaves out the rest (%u of %u listed)",
	       listed, all);
	CHECK (!gtk_widget_get_visible (empty),
	       "[H3] no \"nothing found\" while something is found");

	gtk_entry_set_text (GTK_ENTRY (search), "icmp");
	pump ();
	CHECK (row_listed (win, "prefs-icmp"),
	       "[H3] search lists a subtopic too (\"icmp\")");

	gtk_entry_set_text (GTK_ENTRY (search), "qqzzxv");
	pump ();
	CHECK (rows_listed (win) == 0 && gtk_widget_get_visible (empty),
	       "[H3] a word in no topic lists none and says so");

	gtk_entry_set_text (GTK_ENTRY (search), "feodo");
	pump ();
	g_signal_emit_by_name (search, "activate");
	pump ();
	CHECK (g_strcmp0 (fs_help_current_topic (), "threat-intel") == 0,
	       "[H3] Enter opens the first topic found (%s)",
	       fs_help_current_topic ());

	send_key (win, GDK_KEY_Escape, 0);
	CHECK (*gtk_entry_get_text (GTK_ENTRY (search)) == '\0'
	       && rows_listed (win) == all,
	       "[H3] Escape clears the search and lists every topic again");
}

/* ===================================================== H4: links */

/* The first label in the article whose markup links to help:<id>. */
static GtkWidget *
label_linking (GtkWidget *root, const gchar *id)
{
	GPtrArray *labels = g_ptr_array_new ();
	gchar *needle = g_strdup_printf ("help:%s\"", id);
	GtkWidget *found = NULL;

	collect_labels (root, labels);
	for (guint i = 0; i < labels->len && found == NULL; i++) {
		const gchar *markup = gtk_label_get_label (
			GTK_LABEL (g_ptr_array_index (labels, i)));

		if (strstr (markup, needle) != NULL)
			found = g_ptr_array_index (labels, i);
	}
	g_free (needle);
	g_ptr_array_unref (labels);
	return found;
}

static void
check_links (void)
{
	GtkWidget *win, *label, *back, *forward;
	gboolean handled = FALSE;

	close_help ();
	fs_help_show (NULL, "getting-started");
	pump ();
	win = fs_help_window ();
	back = find_named (win, "help-back");
	forward = find_named (win, "help-forward");
	CHECK (back != NULL && !gtk_widget_is_sensitive (back),
	       "[H4] Back is off on a fresh window");

	label = label_linking (find_named (win, "help-article"), "policy");
	CHECK (label != NULL, "[H4] Getting started links to Policy");
	if (label != NULL) {
		g_signal_emit_by_name (label, "activate-link", "help:policy",
		                       &handled);
		pump ();
	}
	CHECK (handled && g_strcmp0 (fs_help_current_topic (), "policy") == 0,
	       "[H4] following the link opens Policy (%s)",
	       fs_help_current_topic ());

	click (find_named (win, "help-article"), "see:whatif");
	CHECK (g_strcmp0 (fs_help_current_topic (), "whatif") == 0,
	       "[H4] a related-topic chip opens What-If");

	click (win, "help-back");
	CHECK (g_strcmp0 (fs_help_current_topic (), "policy") == 0,
	       "[H4] Back returns to Policy");
	click (win, "help-back");
	CHECK (g_strcmp0 (fs_help_current_topic (), "getting-started") == 0
	       && !gtk_widget_is_sensitive (back),
	       "[H4] Back again returns to Getting started, and Back is off");
	click (win, "help-forward");
	CHECK (g_strcmp0 (fs_help_current_topic (), "policy") == 0,
	       "[H4] Forward goes to Policy again");
	send_key (win, GDK_KEY_Right, GDK_MOD1_MASK);
	CHECK (g_strcmp0 (fs_help_current_topic (), "whatif") == 0
	       && !gtk_widget_is_sensitive (forward),
	       "[H4] Alt+Right goes forward to What-If");
	send_key (win, GDK_KEY_Left, GDK_MOD1_MASK);
	CHECK (g_strcmp0 (fs_help_current_topic (), "policy") == 0,
	       "[H4] Alt+Left goes back");

	click (win, "help-next");
	CHECK (g_strcmp0 (fs_help_current_topic (), "threat-intel") == 0,
	       "[H4] Next opens the topic after Policy, Threat intel as in "
	       "the main window's sidebar (%s)",
	       fs_help_current_topic ());

	fs_help_show (NULL, "prefs-icmp");
	pump ();
	CHECK (row_listed (win, "prefs-icmp") && row_listed (win, "prefs-general"),
	       "[H4] a Preferences subtopic lists its section");
	click (win, "help-crumb");
	CHECK (g_strcmp0 (fs_help_current_topic (), "preferences") == 0,
	       "[H4] the breadcrumb opens Preferences");
	click (find_named (win, "help-article"), "child:prefs-protection");
	CHECK (g_strcmp0 (fs_help_current_topic (), "prefs-protection") == 0,
	       "[H4] Preferences lists its subtopics, and they open");

	{
		GtkWidget *row = find_named (win, "topic:trust");

		/* Enter or a click: the row's "activate". */
		if (row != NULL)
			gtk_widget_activate (row);
		pump ();
		CHECK (g_strcmp0 (fs_help_current_topic (), "trust") == 0,
		       "[H4] choosing a topic in the sidebar opens it");
	}
}

/* ================================================== H1, H6: opening */

static void
check_opening (void)
{
	GtkWidget *main_window =
		GTK_WIDGET (gtk_application_get_active_window (app));
	GtkWidget *first;

	close_help ();
	CHECK (fs_help_window () == NULL, "[H1] no Help window yet");

	fs_app_show_page (FS_PAGE_POLICY);
	pump ();
	g_action_group_activate_action (G_ACTION_GROUP (app), "help", NULL);
	pump ();
	CHECK (fs_help_window () != NULL
	       && gtk_widget_get_mapped (fs_help_window ())
	       && g_strcmp0 (fs_help_current_topic (), "policy") == 0,
	       "[H1] app.help opens Help at the page shown (Policy: %s)",
	       fs_help_current_topic ());
	CHECK (fs_help_window () != NULL
	       && !gtk_window_get_modal (GTK_WINDOW (fs_help_window())),
	       "[H1] Help is not modal");
	close_help ();

	fs_app_show_page (FS_PAGE_EVENTS);
	pump ();
	send_key (main_window, GDK_KEY_F1, 0);
	CHECK (fs_help_window () != NULL
	       && g_strcmp0 (fs_help_current_topic (), "events") == 0,
	       "[H1] F1 on the main window opens Help at Events (%s)",
	       fs_help_current_topic ());

	/* H6: one window.  F1 on another page moves the same one. */
	first = fs_help_window ();
	fs_app_show_page (FS_PAGE_TRUST);
	pump ();
	send_key (main_window, GDK_KEY_F1, 0);
	CHECK (fs_help_window () == first && count_toplevels ("fs-help") == 1
	       && g_strcmp0 (fs_help_current_topic (), "trust") == 0,
	       "[H6] F1 again raises the same Help window, at Trust");
	fs_help_show (main_window, "cli");
	fs_help_show (main_window, "linux");
	pump ();
	CHECK (fs_help_window () == first && count_toplevels ("fs-help") == 1,
	       "[H6] asking twice more still leaves one Help window");
	close_help ();

	/* Every page has its own topic: Threat Intel sits between Policy
	 * and Copilot, so a table that forgot it shifts Copilot and Trust
	 * too. */
	{
		static const struct { gint page; const gchar *id; } pages[] = {
			{ FS_PAGE_OVERVIEW, "overview" },
			{ FS_PAGE_EVENTS,   "events" },
			{ FS_PAGE_ACTIVITY, "activity" },
			{ FS_PAGE_POLICY,   "policy" },
			{ FS_PAGE_INTEL,    "threat-intel" },
			{ FS_PAGE_COPILOT,  "copilot" },
			{ FS_PAGE_TRUST,    "trust" },
		};

		CHECK (G_N_ELEMENTS (pages) == FS_PAGE_COUNT,
		       "[H1] every page is checked (%d pages)", FS_PAGE_COUNT);
		for (guint i = 0; i < G_N_ELEMENTS (pages); i++)
			CHECK (g_strcmp0 (fs_help_topic_for_page (pages[i].page),
			                  pages[i].id) == 0,
			       "[H1] the page %d opens the %s topic (%s)",
			       pages[i].page, pages[i].id,
			       fs_help_topic_for_page (pages[i].page));
	}
	fs_app_show_page (FS_PAGE_INTEL);
	pump ();
	send_key (main_window, GDK_KEY_F1, 0);
	CHECK (fs_help_window () != NULL
	       && g_strcmp0 (fs_help_current_topic (), "threat-intel") == 0,
	       "[H1] F1 on the Threat Intel page opens the threat-intel topic "
	       "(%s)", fs_help_current_topic ());
	close_help ();

	fs_app_show_page (FS_PAGE_ACTIVITY);
	pump ();
	click (main_window, "nav-help");
	CHECK (fs_help_window () != NULL
	       && g_strcmp0 (fs_help_current_topic (), "activity") == 0,
	       "[H1] the sidebar's Help item opens Help at Activity (%s)",
	       fs_help_current_topic ());

	{
		GtkWidget *win = fs_help_window ();

		send_key (win, GDK_KEY_w, GDK_CONTROL_MASK);
		CHECK (fs_help_window () == NULL, "[H1] Ctrl+W closes Help");
	}
	fs_app_show_page (FS_PAGE_OVERVIEW);
	pump ();
}

/* ================================================= H5: Preferences */

static gboolean prefs_driven = FALSE;
static guint prefs_ticks = 0;

static gboolean
prefs_tick (gpointer data)
{
	GtkWidget *prefs = find_toplevel ("fs-preferences");
	GtkWidget *stack, *help;
	GList *pages;
	guint wrong = 0, opened = 0;
	const gchar *before;

	(void) data;
	if (++prefs_ticks > 200) {
		CHECK (FALSE, "[H5] Preferences opened in time");
		return G_SOURCE_REMOVE;
	}
	if (prefs == NULL || !gtk_widget_get_mapped (prefs))
		return G_SOURCE_CONTINUE;
	pump ();
	prefs_driven = TRUE;

	stack = find_named (prefs, "prefs-pages");
	pages = gtk_container_get_children (GTK_CONTAINER (stack));
	for (GList *l = pages; l != NULL; l = l->next) {
		gchar *page = NULL;
		gchar *want;

		gtk_container_child_get (GTK_CONTAINER (stack), l->data,
		                         "name", &page, NULL);
		if (!gtk_widget_get_visible (l->data)) {
			g_free (page);
			continue;
		}
		gtk_stack_set_visible_child_name (GTK_STACK (stack), page);
		pump ();
		click (prefs, "prefs-help");
		want = g_strconcat ("prefs-", page, NULL);
		opened++;
		if (g_strcmp0 (fs_help_current_topic (), want) != 0) {
			printf ("       page %s opened %s\n", page,
			        fs_help_current_topic ());
			wrong++;
		}
		g_free (want);
		g_free (page);
	}
	g_list_free (pages);
	CHECK (opened >= 5 && wrong == 0,
	       "[H5] Help on each of %u Preferences pages opens its topic",
	       opened);

	help = fs_help_window ();
	CHECK (help != NULL && gtk_widget_get_mapped (help)
	       && gtk_window_get_group (GTK_WINDOW (help))
	          != gtk_window_get_group (GTK_WINDOW (prefs)),
	       "[H5] Help is open, outside the Preferences window group");

	gtk_stack_set_visible_child_name (GTK_STACK (stack), "icmp");
	pump ();
	before = fs_help_current_topic ();
	send_key (prefs, GDK_KEY_F1, 0);
	CHECK (g_strcmp0 (fs_help_current_topic (), "prefs-icmp") == 0,
	       "[H5] F1 in Preferences opens the topic for ICMP (%s)",
	       fs_help_current_topic ());

	/* Input reaches Help while Preferences holds its modal grab: a key
	 * on the Help window acts there. */
	if (help != NULL) {
		send_key (help, GDK_KEY_Left, GDK_MOD1_MASK);
		CHECK (g_strcmp0 (fs_help_current_topic (), before) == 0
		       && g_strcmp0 (before, "prefs-icmp") != 0,
		       "[H5] Help takes keys while Preferences is open "
		       "(Alt+Left went back to %s)", fs_help_current_topic ());
		shot (help, "help-from-preferences");
	}

	click (prefs, "prefs-cancel");
	return G_SOURCE_REMOVE;
}

static void
check_preferences (void)
{
	GtkWidget *main_window =
		GTK_WIDGET (gtk_application_get_active_window (app));

	close_help ();
	prefs_driven = FALSE;
	prefs_ticks = 0;
	g_timeout_add (50, prefs_tick, NULL);
	fs_dialogs_preferences (main_window);
	pump ();
	CHECK (prefs_driven, "[H5] the Preferences window was driven");
	CHECK (find_toplevel ("fs-preferences") == NULL
	       && fs_help_window () != NULL,
	       "[H5] closing Preferences leaves Help open");
	close_help ();
}

/* ======================================= H9: What-If's settings fixes */

/* HELP-WI-PREFS: a settings fix opens Preferences at the page that holds
 * the switch it names, and every switch and page the engine may name is
 * there under that name.  The labels exactly, not paraphrased; the page
 * as the window's sidebar titles it. */
static const gchar *h9_page = NULL;
static gboolean     h9_driven = FALSE;
static guint        h9_ticks = 0;

static gboolean
whatif_prefs_tick (gpointer data)
{
	GtkWidget *prefs = find_toplevel ("fs-preferences");
	GtkWidget *stack;
	GPtrArray *labels;
	const gchar *shown;
	guint missing = 0, named = 0;

	(void) data;
	if (++h9_ticks > 200) {
		CHECK (FALSE, "[H9] Preferences opened in time (%s)", h9_page);
		return G_SOURCE_REMOVE;
	}
	if (prefs == NULL || !gtk_widget_get_mapped (prefs))
		return G_SOURCE_CONTINUE;
	pump ();
	h9_driven = TRUE;

	stack = find_named (prefs, "prefs-pages");
	shown = gtk_stack_get_visible_child_name (GTK_STACK (stack));
	CHECK (g_strcmp0 (shown, h9_page) == 0,
	       "[H9] a fix for page %s opens Preferences there (shown: %s)",
	       h9_page, shown);

	labels = g_ptr_array_new ();
	collect_labels (prefs, labels);
	for (guint i = 0; ; i++) {
		const gchar *label, *where, *page, *title_want;
		const gchar *key = fs_whatif_setting_nth (i, &label, &where, &page);
		GtkWidget *child;
		gchar *title = NULL;
		gboolean has_label = FALSE;

		if (key == NULL)
			break;
		if (g_strcmp0 (page, h9_page) != 0)
			continue;
		named++;
		for (guint j = 0; j < labels->len && !has_label; j++)
			has_label = g_strcmp0 (gtk_label_get_text (
				g_ptr_array_index (labels, j)), label) == 0;
		child = gtk_stack_get_child_by_name (GTK_STACK (stack), page);
		if (child != NULL)
			gtk_container_child_get (GTK_CONTAINER (stack), child,
			                         "title", &title, NULL);
		title_want = g_str_has_prefix (where, "Preferences > ")
			? where + strlen ("Preferences > ") : where;
		if (!has_label || g_strcmp0 (title, title_want) != 0) {
			printf ("       %s: switch \"%s\" %s; page \"%s\" is \"%s\"\n",
			        key, label, has_label ? "found" : "MISSING",
			        title_want, title != NULL ? title : "(none)");
			missing++;
		}
		g_free (title);
	}
	g_ptr_array_free (labels, TRUE);
	CHECK (named > 0 && missing == 0,
	       "[H9] every switch a fix names on %s is there by that label, "
	       "on the page it names (%u of %u wrong)", h9_page, missing,
	       named);

	click (prefs, "prefs-cancel");
	return G_SOURCE_REMOVE;
}

static void
check_whatif_prefs (void)
{
	static const gchar *pages[] = { "icmp", "protection", NULL };
	GtkWidget *main_window =
		GTK_WIDGET (gtk_application_get_active_window (app));
	gchar *whatif = topic_text ("whatif");

	CHECK (strstr (whatif, "open Preferences at the ICMP or Protection "
	                       "page") != NULL &&
	       strstr (whatif, "Preferences page that decides") == NULL,
	       "[H9] the What-If topic says which Preferences page a fix "
	       "opens");
	g_free (whatif);

	{
		/* Every page a fix names is one of the pages opened below. */
		const gchar *page = NULL;
		guint stray = 0;

		for (guint i = 0; fs_whatif_setting_nth (i, NULL, NULL, &page)
		     != NULL; i++)
			if (!g_strv_contains (pages, page)) {
				printf ("       a fix names page \"%s\"\n", page);
				stray++;
			}
		CHECK (stray == 0,
		       "[H9] every fix names a Preferences page by its id (%u "
		       "stray)", stray);
	}

	for (guint i = 0; pages[i] != NULL; i++) {
		h9_page = pages[i];
		h9_driven = FALSE;
		h9_ticks = 0;
		g_timeout_add (50, whatif_prefs_tick, NULL);
		fs_dialogs_preferences_at (main_window, pages[i]);
		pump ();
		CHECK (h9_driven, "[H9] Preferences was driven (%s)", pages[i]);
	}
}

/* =========================================================== About */

static void
check_about (void)
{
	GtkWidget *main_window =
		GTK_WIDGET (gtk_application_get_active_window (app));
	GtkWidget *about, *credit, *licence_window;
	const gchar * const *credits = fs_dialogs_about_credits ();
	gchar *text, *info;
	const gchar *user = g_get_user_name ();
	const gchar *host = g_get_host_name ();
	const gchar *home = g_get_home_dir ();

	fs_dialogs_about (main_window);
	pump ();
	about = find_toplevel ("fs-about");
	CHECK (about != NULL && GTK_IS_DIALOG (about)
	       && gtk_widget_get_mapped (about),
	       "[A1] About opens as a dialog");
	if (about == NULL)
		return;
	CHECK (gtk_window_get_transient_for (GTK_WINDOW (about))
	       == GTK_WINDOW (main_window)
	       && !gtk_window_get_modal (GTK_WINDOW (about)),
	       "[A1] About is transient for the main window and not modal");

	credit = find_named (about, "about-credit-0");
	CHECK (credit != NULL && g_strcmp0 (gtk_label_get_text (
	       GTK_LABEL (credit)),
	       "Stock Team & Qusai - Creator & Original Developer") == 0,
	       "[A1] the first credit reads exactly \"Stock Team & Qusai - "
	       "Creator & Original Developer\"");
	{
		guint shown = 0;

		for (guint i = 0; credits[i] != NULL; i++) {
			gchar *name = g_strdup_printf ("about-credit-%u", i);
			GtkWidget *l = find_named (about, name);

			if (l != NULL && g_strcmp0 (gtk_label_get_text (
			    GTK_LABEL (l)), credits[i]) == 0)
				shown++;
			g_free (name);
		}
		CHECK (shown == 3 && credits[3] == NULL,
		       "[A1] the three credits on this base are all shown");
	}

	text = text_of (about);
	CHECK (strchr (text, '@') == NULL,
	       "[A1] no e-mail address anywhere in About");
	CHECK (strstr (text, "Version " FS_VERSION) != NULL,
	       "[A1] About shows the version (%s)", FS_VERSION);
	CHECK (strstr (text, "General Public License version 2") != NULL
	       && strstr (text, "Apache License 2.0") != NULL
	       && strstr (text, "still being reviewed") != NULL
	       && strstr (text, "version 3") == NULL
	       && strstr (text, "3.0") == NULL,
	       "[A1] the licence summary names both texts the source "
	       "carries and claims no GPL 3");
	CHECK (find_named (about, "about-website") != NULL
	       && g_strcmp0 (gtk_link_button_get_uri (GTK_LINK_BUTTON (
	          find_named (about, "about-website"))),
	          "https://github.com/Cazo-Net/StockFW") == 0,
	       "[A1] About links to the website");
	g_free (text);

	click (about, "about-view-licence");
	licence_window = find_toplevel ("fs-licence");
	CHECK (licence_window != NULL && gtk_widget_get_mapped (licence_window),
	       "[A1] View licence texts opens them");
	if (licence_window != NULL) {
		GtkWidget *stack = find_named (licence_window, "licence-pages");
		GList *pages = gtk_container_get_children (GTK_CONTAINER (stack));
		guint good = 0;

		for (GList *l = pages; l != NULL; l = l->next) {
			GtkWidget *view = gtk_bin_get_child (GTK_BIN (l->data));
			GtkTextBuffer *buf;
			GtkTextIter a, b;
			gchar *all;

			if (GTK_IS_VIEWPORT (view))
				view = gtk_bin_get_child (GTK_BIN (view));
			buf = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));
			gtk_text_buffer_get_bounds (buf, &a, &b);
			all = gtk_text_buffer_get_text (buf, &a, &b, FALSE);
			if ((strstr (all, "GNU GENERAL PUBLIC LICENSE") != NULL
			     && strstr (all, "Version 2, June 1991") != NULL)
			    || (strstr (all, "Apache License") != NULL
			        && strstr (all, "Version 2.0, January 2004")
			           != NULL))
				good++;
			if (strchr (all, '\f') != NULL)
				good = 100;
			g_free (all);
		}
		g_list_free (pages);
		CHECK (good == 2,
		       "[A1] the two pages hold GPL v2 (COPYING) and Apache 2.0 "
		       "(LICENSE), with the form feeds dropped");
		check_contrast (licence_window, "licence texts");
		click (about, "about-view-licence");
		CHECK (count_toplevels ("fs-licence") == 1,
		       "[A1] asking again shows the same licence window");
	}

	fs_dialogs_about (main_window);
	pump ();
	CHECK (count_toplevels ("fs-about") == 1
	       && find_toplevel ("fs-about") == about,
	       "[A1] About again raises the same window");

	/* A2 */
	info = fs_dialogs_system_info ();
	printf ("       system info:\n%s", info);
	CHECK (g_str_has_prefix (info, "StockFW " FS_VERSION "\n")
	       && strstr (info, "\nGTK 3.") != NULL
	       && strstr (info, "\nGLib 2.") != NULL
	       && strstr (info, "\nPlatform: ") != NULL
	       && strstr (info, fs_backend ()->display_name) != NULL,
	       "[A2] system info has the version, GTK, GLib, platform and "
	       "backend");
	CHECK ((user == NULL || *user == '\0' || strstr (info, user) == NULL)
	       && (host == NULL || *host == '\0'
	           || strstr (info, host) == NULL)
	       && (home == NULL || strlen (home) < 2
	           || strstr (info, home) == NULL)
	       && strchr (info, '@') == NULL
	       && strchr (info, '/') == NULL,
	       "[A2] system info has no user name, host name, path or "
	       "address");
	{
		GtkClipboard *cb = gtk_clipboard_get_for_display (
			gtk_widget_get_display (about), GDK_SELECTION_CLIPBOARD);
		gchar *got;

		begin_step ("check_about: Copy system info");
		/* Something else on the clipboard first, and the click
		 * straight after, with no main-loop turn between: on
		 * Windows the "before" owner's TARGETS request to itself
		 * is still queued, and Copy must not change the owner
		 * again until it is answered ([W] catches the warning). */
		gtk_clipboard_set_text (cb, "before", -1);
		got = gtk_clipboard_wait_for_text (cb);
		CHECK (g_strcmp0 (got, "before") == 0,
		       "[A2] the clipboard holds other text before the copy");
		g_free (got);
		click (about, "about-copy");
		got = gtk_clipboard_wait_for_text (cb);
		CHECK (g_strcmp0 (got, info) == 0
		       && gtk_widget_get_visible (find_named (about,
		                                              "about-copied")),
		       "[A2] Copy system info puts exactly that on the "
		       "clipboard and says so");
		g_free (got);
	}
	g_free (info);

	check_contrast (about, "About");
	shot (about, "about");

	click (about, "about-close");
	CHECK (find_toplevel ("fs-about") == NULL
	       && find_toplevel ("fs-licence") == NULL,
	       "[A1] Close closes About and its licence window");
}

/* ======================================================= T1, shots */

static void
check_theme (void)
{
	const gchar *const topics[] = {
		"getting-started", "whatif", "troubleshooting", "shortcuts",
		"prefs-protection", "preferences",
	};
	GtkWidget *win;
	guint measured = 0;

	close_help ();
	for (guint i = 0; i < G_N_ELEMENTS (topics); i++) {
		gchar *where = g_strdup_printf ("Help %s", topics[i]);

		fs_help_show (GTK_WIDGET (gtk_application_get_active_window (app)),
		              topics[i]);
		pump ();
		win = fs_help_window ();
		gtk_window_resize (GTK_WINDOW (win), 980, 680);
		pump ();
		measured += check_contrast (win, where);
		if (i < 3) {
			gchar *name = g_strdup_printf ("help-%s", topics[i]);

			shot (win, name);
			g_free (name);
		}
		g_free (where);
	}
	CHECK (measured > 100, "[T1] %u labels measured", measured);

	/* The sidebar mid-search: the "nothing found" line. */
	gtk_entry_set_text (GTK_ENTRY (find_named (win, "help-search")),
	                    "qqzzxv");
	pump ();
	check_contrast (find_named (win, "help-empty") != NULL
	                ? gtk_widget_get_parent (find_named (win, "help-empty"))
	                : win, "Help, nothing found");
	gtk_entry_set_text (GTK_ENTRY (find_named (win, "help-search")), "");
	close_help ();
}

/* ======================================= K1, L1: keyboard and layout */

/* Every focusable, drawn widget under root that a screen reader would
 * announce with no name: buttons, rows, entries.  Labels name
 * themselves by their text. */
static void
unnamed_controls (GtkWidget *root, GString *out)
{
	GList *children;

	if (gtk_widget_get_can_focus (root) && gtk_widget_is_drawable (root)
	    && (GTK_IS_BUTTON (root) || GTK_IS_LIST_BOX_ROW (root)
	        || GTK_IS_ENTRY (root))) {
		const gchar *name = atk_object_get_name (
			gtk_widget_get_accessible (root));

		if (name == NULL || *name == '\0')
			g_string_append_printf (out, " %s(%s)",
			                        G_OBJECT_TYPE_NAME (root),
			                        gtk_widget_get_name (root));
	}
	if (!GTK_IS_CONTAINER (root))
		return;
	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (GList *l = children; l != NULL; l = l->next)
		unnamed_controls (l->data, out);
	g_list_free (children);
}

static const gchar *
focus_name (GtkWidget *window)
{
	GtkWidget *focus = gtk_window_get_focus (GTK_WINDOW (window));

	return focus != NULL ? gtk_widget_get_name (focus) : "(none)";
}

/* The widest a window can be made narrow to, as GTK asks it. */
static gint
min_width (GtkWidget *window)
{
	gint min = 0, nat = 0;

	gtk_widget_get_preferred_width (window, &min, &nat);
	return min;
}

/* K1: Tab in About walks every control and comes back. */
static void
check_about_keys (void)
{
	GtkWidget *main_window =
		GTK_WIDGET (gtk_application_get_active_window (app));
	GtkWidget *about;
	GString *seen = g_string_new (NULL);

	/* The main window holds the keyboard when About is asked for, as
	 * when it is chosen from the sidebar.  About must take it: a
	 * dialog that never gets keyboard focus keeps every Tab on Close
	 * (GTK re-grabs the focused button). */
	gtk_window_present (GTK_WINDOW (main_window));
	pump ();
	fs_dialogs_about (main_window);
	pump ();
	about = find_toplevel ("fs-about");
	if (about == NULL) {
		CHECK (FALSE, "[K1] About opens");
		g_string_free (seen, TRUE);
		return;
	}
	for (gint i = 0; i < 4; i++) {
		send_key (about, GDK_KEY_Tab, 0);
		g_string_append_printf (seen, "%s ", focus_name (about));
	}
	CHECK (strstr (seen->str, "about-view-licence") != NULL
	       && strstr (seen->str, "about-website") != NULL
	       && strstr (seen->str, "about-copy") != NULL
	       && strstr (seen->str, "about-close") != NULL,
	       "[K1] Tab in About reaches View licence texts, the website, "
	       "Copy system info and Close (%s)", seen->str);
	g_string_truncate (seen, 0);
	for (gint i = 0; i < 4; i++) {
		send_key (about, GDK_KEY_ISO_Left_Tab, GDK_SHIFT_MASK);
		g_string_append_printf (seen, "%s ", focus_name (about));
	}
	CHECK (strstr (seen->str, "about-view-licence") != NULL
	       && strstr (seen->str, "about-copy") != NULL,
	       "[K1] Shift+Tab in About walks back through them (%s)",
	       seen->str);
	g_string_truncate (seen, 0);
	unnamed_controls (about, seen);
	CHECK (seen->len == 0,
	       "[K1] every control in About has a screen-reader name (%s)",
	       seen->str);
	gtk_widget_destroy (about);
	pump ();
	g_string_free (seen, TRUE);
}

/* K1: the Help window and the keyboard. */
static void
check_help_keys (void)
{
	GtkWidget *main_window =
		GTK_WIDGET (gtk_application_get_active_window (app));
	GtkWidget *win, *search;
	GString *seen = g_string_new (NULL);
	guint rows = 0;

	close_help ();
	fs_help_show (main_window, "getting-started");
	pump ();
	win = fs_help_window ();
	search = find_named (win, "help-search");

	/* UX8: the search field shows what it is for. */
	CHECK (gtk_window_get_focus (GTK_WINDOW (win)) != search
	       && g_strcmp0 (focus_name (win), "topic:getting-started") == 0,
	       "[K1] Help opens with focus on the topic shown, not in the "
	       "search field, so its placeholder shows (%s)",
	       focus_name (win));

	/* UX3: 30 Tabs pass the topic list once at most, and open
	 * nothing on the way. */
	for (gint i = 0; i < 30; i++) {
		send_key (win, GDK_KEY_Tab, 0);
		if (g_str_has_prefix (focus_name (win), "topic:"))
			rows++;
		g_string_append_printf (seen, "%s ", focus_name (win));
	}
	CHECK (g_strcmp0 (fs_help_current_topic (), "getting-started") == 0,
	       "[K1] Tab through Help opens no topic (now %s)",
	       fs_help_current_topic ());
	CHECK (rows <= 3 && strstr (seen->str, "topic:overview") == NULL,
	       "[K1] the topic list is one Tab stop: %u of 30 Tabs landed "
	       "on a topic, never a second one", rows);
	CHECK (strstr (seen->str, "help-search") != NULL,
	       "[K1] Tab still reaches the search field");

	/* Arrows move along the list; Enter opens. */
	gtk_widget_grab_focus (find_named (win, "topic:getting-started"));
	pump ();
	send_key (win, GDK_KEY_Down, 0);
	CHECK (g_strcmp0 (focus_name (win), "topic:overview") == 0
	       && g_strcmp0 (fs_help_current_topic (), "getting-started") == 0,
	       "[K1] Down moves to the next topic without opening it (%s, "
	       "showing %s)", focus_name (win), fs_help_current_topic ());
	send_key (win, GDK_KEY_Return, 0);
	CHECK (g_strcmp0 (fs_help_current_topic (), "overview") == 0,
	       "[K1] Enter opens the topic (%s)", fs_help_current_topic ());

	/* UX4: names for a screen reader. */
	g_string_truncate (seen, 0);
	unnamed_controls (win, seen);
	CHECK (seen->len == 0,
	       "[K1] every control in Help has a screen-reader name (%s)",
	       seen->str);
	{
		AtkObject *back = gtk_widget_get_accessible (
			find_named (win, "help-back"));
		AtkObject *row = gtk_widget_get_accessible (
			find_named (win, "topic:cli"));

		CHECK (g_strcmp0 (atk_object_get_name (back), "Back") == 0
		       && g_strcmp0 (atk_object_get_name (row),
		                     "Command line and dashboard") == 0,
		       "[K1] the Back button and a topic row are named (%s, %s)",
		       atk_object_get_name (back), atk_object_get_name (row));
	}
	g_string_free (seen, TRUE);
}

/* The allocations of the buttons named prefix* under root, in order. */
static void
collect_named (GtkWidget *root, const gchar *prefix, GPtrArray *out)
{
	GList *children;

	if (g_str_has_prefix (gtk_widget_get_name (root), prefix))
		g_ptr_array_add (out, root);
	if (!GTK_IS_CONTAINER (root))
		return;
	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (GList *l = children; l != NULL; l = l->next)
		collect_named (l->data, prefix, out);
	g_list_free (children);
}

static void
collect_class (GtkWidget *root, const gchar *klass, GPtrArray *out)
{
	GList *children;

	if (gtk_style_context_has_class (gtk_widget_get_style_context (root),
	                                 klass))
		g_ptr_array_add (out, root);
	if (!GTK_IS_CONTAINER (root))
		return;
	children = gtk_container_get_children (GTK_CONTAINER (root));
	for (GList *l = children; l != NULL; l = l->next)
		collect_class (l->data, klass, out);
	g_list_free (children);
}

/* L1: what the window looks like at its edges. */
static void
check_layout (void)
{
	GtkWidget *main_window =
		GTK_WIDGET (gtk_application_get_active_window (app));
	GtkWidget *win;
	gint widest = 0;
	const gchar *widest_topic = "";
	GtkAllocation a;
	GString *nav_cut = g_string_new (NULL);
	guint nav_seen = 0;
	gint help_w = 0, help_h = 0;

	close_help ();
	fs_help_show (main_window, "getting-started");
	pump ();
	win = fs_help_window ();

	/* UX9: the sidebar Preferences has too. */
	gtk_widget_get_allocation (find_named (win, "help-sidebar"), &a);
	CHECK (a.width == FS_SIDE_WIDTH,
	       "[L1] the Help sidebar is %d pixels wide, as Preferences' "
	       "(%d)", a.width, FS_SIDE_WIDTH);

	/* UX5, UX9: no topic makes the window wider than 640.  And at
	 * Help's own size every topic title in the sidebar reads in full
	 * (HELP-NAV-TRUNC): none is cut short with an ellipsis. */
	gtk_window_get_size (GTK_WINDOW (win), &help_w, &help_h);
	for (guint i = 0; i < fs_help_topic_count (); i++) {
		GPtrArray *labels = g_ptr_array_new ();
		gint w;

		fs_help_show (NULL, fs_help_topic_nth (i)->id);
		pump ();
		collect_class (find_named (win, "help-topics"), "help-topic-label",
		               labels);
		for (guint j = 0; j < labels->len; j++) {
			GtkLabel *l = g_ptr_array_index (labels, j);
			const gchar *text = gtk_label_get_text (l);

			if (!gtk_widget_get_mapped (GTK_WIDGET (l)))
				continue;
			nav_seen++;
			if (pango_layout_is_ellipsized (gtk_label_get_layout (l)) &&
			    strstr (nav_cut->str, text) == NULL)
				g_string_append_printf (nav_cut, "%s\"%s\"",
				                        nav_cut->len > 0 ? ", " : "",
				                        text);
		}
		g_ptr_array_free (labels, TRUE);
		w = min_width (win);
		if (w > widest) {
			widest = w;
			widest_topic = fs_help_topic_nth (i)->id;
		}
	}
	CHECK (widest <= 640,
	       "[L1] Help fits a 640-pixel window on every topic (widest "
	       "minimum %d, on %s)", widest, widest_topic);
	CHECK (nav_seen > 0 && nav_cut->len == 0,
	       "[L1] at %dx%d no sidebar topic title is cut short (%u seen; "
	       "cut: %s)", help_w, help_h, nav_seen,
	       nav_cut->len > 0 ? nav_cut->str : "none");
	g_string_free (nav_cut, TRUE);

	/* UX5: the caps keep their own height beside text that wraps. */
	gtk_window_resize (GTK_WINDOW (win), 640, 680);
	fs_help_show (NULL, "shortcuts");
	pump ();
	pump ();
	{
		GPtrArray *caps = g_ptr_array_new ();
		gint lo = G_MAXINT, hi = 0;

		collect_class (find_named (win, "help-article"), "help-key",
		               caps);
		for (guint i = 0; i < caps->len; i++) {
			gint h = gtk_widget_get_allocated_height (
				g_ptr_array_index (caps, i));

			lo = MIN (lo, h);
			hi = MAX (hi, h);
		}
		CHECK (caps->len > 10 && hi - lo <= 2 && hi < 32,
		       "[L1] every key cap is one height (%d to %d pixels, %u "
		       "caps) at 640 wide", lo, hi, caps->len);
		gtk_widget_get_allocation (win, &a);
		CHECK (a.width <= 650,
		       "[L1] the Shortcuts topic does not widen the window "
		       "(%d)", a.width);
		g_ptr_array_unref (caps);

		/* The descriptions start in one column. */
		caps = g_ptr_array_new ();
		collect_class (find_named (win, "help-article"),
		               "help-keys-row", caps);
		lo = G_MAXINT;
		hi = 0;
		for (guint i = 0; i < caps->len; i++) {
			GList *kids = gtk_container_get_children (
				g_ptr_array_index (caps, i));
			gint x = 0, y = 0;

			gtk_widget_translate_coordinates (
				g_list_last (kids)->data, win, 0, 0, &x, &y);
			lo = MIN (lo, x);
			hi = MAX (hi, x);
			g_list_free (kids);
		}
		CHECK (caps->len > 10 && hi == lo,
		       "[L1] the shortcut descriptions line up (x %d to %d)",
		       lo, hi);
		g_ptr_array_unref (caps);
	}

	/* UX6: the column on a wide window. */
	gtk_window_resize (GTK_WINDOW (win), 1600, 900);
	fs_help_show (NULL, "getting-started");
	pump ();
	pump ();
	{
		GtkWidget *page = find_named (win, "help-page");
		GtkAllocation content;

		gtk_widget_get_allocation (page, &a);
		gtk_widget_get_allocation (gtk_widget_get_parent (page),
		                           &content);
		/* Wider than the column by a margin, not "over 1000": Windows
		 * keeps a window inside the work area, and a 1024x768 runner
		 * leaves 768 pixels beside the sidebar. */
		CHECK (a.width <= 700 && content.width >= 700 + 40,
		       "[L1] on a %d-pixel content area the page column is %d "
		       "wide (at most 700)", content.width, a.width);
		CHECK (ABS ((a.x - content.x)
		            - (content.x + content.width - a.x - a.width)) <= 2,
		       "[L1] and centred");
	}

	/* UX7: the chips 6 pixels apart, whatever the width. */
	{
		GPtrArray *chips = g_ptr_array_new ();
		gint worst = 0;

		collect_named (find_named (win, "help-article"), "see:", chips);
		guint pairs = 0;

		for (guint i = 1; i < chips->len; i++) {
			GtkWidget *p = g_ptr_array_index (chips, i - 1);
			GtkWidget *c = g_ptr_array_index (chips, i);
			gint px = 0, py = 0, cx = 0, cy = 0;

			/* In window coordinates: a flow box child may sit in
			 * a window of its own. */
			gtk_widget_translate_coordinates (p, win, 0, 0, &px, &py);
			gtk_widget_translate_coordinates (c, win, 0, 0, &cx, &cy);
			if (cy == py) {
				pairs++;
				worst = MAX (worst, cx - (px +
					gtk_widget_get_allocated_width (p)));
			}
		}
		CHECK (chips->len >= 3 && pairs >= 2 && worst <= 8,
		       "[L1] related-topic chips sit side by side, the widest "
		       "gap %d pixels (%u chips, %u side by side)", worst,
		       chips->len, pairs);
		g_ptr_array_unref (chips);
	}
	gtk_window_resize (GTK_WINDOW (win), 980, 680);
	close_help ();
}

/* ============================================================ main */

static gboolean
run_all (gpointer data)
{
	(void) data;

	pump ();
	printf ("theme: %s\n", g_getenv ("GTK_THEME"));
#define STEP(fn) do { begin_step (#fn); fn (); } while (0)
	STEP (check_table);
	STEP (check_claims);
	STEP (check_merged_107);
	STEP (check_opening);
	STEP (check_every_topic);
	STEP (check_search);
	STEP (check_links);
	STEP (check_preferences);
	STEP (check_whatif_prefs);
	STEP (check_about);
	STEP (check_about_keys);
	STEP (check_help_keys);
	STEP (check_layout);
	STEP (check_theme);
#undef STEP
	begin_step ("quit");

	CHECK (warnings == 0, "[W] no GTK warnings or criticals (%d%s%s)",
	       warnings, first_warning_step != NULL ? ", the first in " : "",
	       first_warning_step != NULL ? first_warning_step : "");
	close_help ();
	g_application_quit (G_APPLICATION (app));
	return G_SOURCE_REMOVE;
}

static void
on_activate (GtkApplication *application, gpointer data)
{
	(void) data;
	fs_app_activate (application);
	g_idle_add (run_all, NULL);
}

int
main (int argc, char **argv)
{
	gchar *scratch = g_dir_make_tmp ("stockfw-help-XXXXXX", NULL);
	gchar *path;
	int status;

	setvbuf (stdout, NULL, _IOLBF, 0);
	if (scratch == NULL) {
		g_printerr ("fs-help-smoke: no scratch directory\n");
		return 1;
	}
	/* Everything the app reads or writes, in the scratch directory,
	 * before anything caches a path. */
	g_setenv ("APPDATA", scratch, TRUE);
	g_setenv ("XDG_CONFIG_HOME", scratch, TRUE);
	g_setenv ("XDG_DATA_HOME", scratch, TRUE);
	g_setenv ("STOCKFW_RULES_DIR", scratch, TRUE);
	path = g_build_filename (scratch, "applied", NULL);
	g_setenv ("STOCKFW_APPLIED_FILE", path, TRUE);
	g_free (path);
	path = g_build_filename (scratch, "audit.log", NULL);
	g_setenv ("STOCKFW_AUDIT_FILE", path, TRUE);
	g_free (path);
	path = g_build_filename (scratch, "behavior", NULL);
	g_setenv ("STOCKFW_BEHAVIOR_FILE", path, TRUE);
	g_free (path);
	path = g_build_filename (scratch, "trust", NULL);
	g_setenv ("STOCKFW_TRUST_FILE", path, TRUE);
	g_free (path);
	if (g_getenv ("GTK_THEME") == NULL)
		g_setenv ("GTK_THEME", "Adwaita:dark", TRUE);

	g_log_set_writer_func (count_warnings, NULL, NULL);

	app = gtk_application_new ("org.stockfw.HelpSmoke",
	                           G_APPLICATION_NON_UNIQUE);
	g_signal_connect (app, "activate", G_CALLBACK (on_activate), NULL);
	status = g_application_run (G_APPLICATION (app), 0, NULL);
	g_object_unref (app);
	(void) argc;
	(void) argv;

	printf ("\n%s: %d failure(s), %d warning(s)\n",
	        failures == 0 && status == 0 ? "PASS" : "FAIL",
	        failures, warnings);
	return failures == 0 && status == 0 ? 0 : 1;
}
