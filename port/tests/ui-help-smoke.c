/* fs-help-smoke: the Help window and the About window (1.0.7).
 *
 * Builds the real main window (fs_app_activate, in a GtkApplication,
 * with every file it reads or writes moved to a scratch directory) and
 * checks, each seen failing with its bug put back (tests/README.md):
 *
 *   H1  the app.help action and F1 on the main window open Help at
 *       the topic for the page shown; the sidebar's Help item too
 *   H2  every topic renders, and shows every block it has; all markup
 *       parses, every help: link and related id resolves, no em dash
 *   H3  search filters the topic list (and says when nothing matches);
 *       Enter opens the first topic found
 *   H4  links, related chips, Next, Back and Forward navigate
 *   H5  Preferences' Help button and F1 open the topic for the page it
 *       shows, and Help takes input while Preferences is modal
 *   H6  one Help window: asking again raises it
 *   A1  About: the exact creator credit, no e-mail address, the
 *       licence summary true to the source, both licence texts, one
 *       window, transient for the main window, not modal
 *   A2  "Copy system info": versions, platform, backend; no user name,
 *       host name or home path; the clipboard gets exactly that
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

#include <gtk/gtk.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#ifndef FS_VERSION
#define FS_VERSION "1.0.6"
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

static GLogWriterOutput
count_warnings (GLogLevelFlags level, const GLogField *fields,
                gsize n_fields, gpointer data)
{
	(void) data;
	if (level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL))
		warnings++;
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

	gtk_entry_set_text (GTK_ENTRY (search), "blocklist");
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
	CHECK (g_strcmp0 (fs_help_current_topic (), "copilot") == 0,
	       "[H4] Next opens the topic after Policy (%s)",
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

		if (row != NULL)
			gtk_list_box_select_row (GTK_LIST_BOX (
				find_named (win, "help-topics")),
				GTK_LIST_BOX_ROW (row));
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

		gtk_clipboard_set_text (cb, "before", -1);
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

/* ============================================================ main */

static gboolean
run_all (gpointer data)
{
	(void) data;

	pump ();
	printf ("theme: %s\n", g_getenv ("GTK_THEME"));
	check_table ();
	check_opening ();
	check_every_topic ();
	check_search ();
	check_links ();
	check_preferences ();
	check_about ();
	check_theme ();

	CHECK (warnings == 0, "[W] no GTK warnings or criticals (%d)",
	       warnings);
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
