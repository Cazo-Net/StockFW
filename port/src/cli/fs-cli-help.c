/*---[ fs-cli-help.c ]--------------------------------------------------
 * `stockfw help topics|TOPIC|--search WORD' and `stockfw about': the
 * desktop app's Help and About in a terminal (master plan PR 4,
 * package 4E; parity rows M1, M2, K17, O1, O3, O4 and O8).
 *
 * The topics are the Help window's own (core/fs-helpcontent.c), Pango
 * markup that fs_help_markup_to_text turns into plain text.  A link to
 * another topic is printed as the command that shows it: `stockfw help
 * ID', or `stockfw help topic ID' when a command has the same name
 * (`stockfw help events' stays the events command's help).  Topics
 * about the desktop app's own windows are listed apart, as "Desktop
 * app topics".  Lines are wrapped to the terminal and never run past
 * 78 columns, piped or not.
 *
 * `stockfw __man topics' writes the same topics as stockfw-topics(7)
 * (fs-cli-complete.c calls fs_cli_help_man_topics).
 *
 * `about' prints what the About window shows, without the GTK
 * versions: the credits (the same lines as ui/fs-aboutdialog.c, which
 * test-cli.sh compares), the licence summary, both licence texts with
 * --licences, and --system's lines for a bug report.
 *
 * Nothing here reads a file or asks a question: it prints text that is
 * compiled in, through fs_cli_out_safe all the same.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-helpcontent.h"
#include "core/fs-json.h"
#include "fs-licence-text.h"

#include <stdio.h>
#include <string.h>

/* === PR4-E === */

#define HELP_WIDTH  78          /* the widest line, piped or not      */
#define FS_WEBSITE  "https://github.com/Cazo-Net/StockFW"

#ifdef G_OS_WIN32
#define FS_CLI_PLATFORM "windows"
#else
#define FS_CLI_PLATFORM "linux"
#endif

/* The About window's credits (ui/fs-aboutdialog.c,
 * fs_dialogs_about_credits): never a full name or an e-mail address. */
static const gchar *const about_credits[] = {
	"Stockfw Team - Creator & Original Developer",
	"H3xCore - Developer",
	"Stock Team - GTK3 Port, Windows Backend, Copilot",
};

static const gchar about_desc[] =
	"Configures the firewall your system already has and shows what it "
	"allows and blocks.";

static const gchar about_licence[] =
	"StockFW is free software and comes with no warranty. Its source "
	"carries two licence texts: the GNU General Public License version 2 "
	"(COPYING) and the Apache License 2.0 (LICENSE). The code it was "
	"ported from was released under the GNU GPL, version 2 or any later "
	"version. Which licence covers which part is still being reviewed.";

/* ------------------------------------------------------------ text */

/* The width to wrap at: the terminal's, never more than HELP_WIDTH. */
static guint
text_width (void)
{
	guint w = fs_cli_term_width ();

	if (w == 0 || w > HELP_WIDTH + 1)
		return HELP_WIDTH;
	return w > 41 ? w - 1 : 40;
}

/* [ wrap_into ] -- `text' (one paragraph; runs of white space are one
 * space) wrapped to `width' columns: the first line starts with
 * `first', the others with `indent' spaces.  A word longer than a line
 * is put on a line of its own, never cut. */
static void
wrap_into (GString *out, const gchar *text, const gchar *first,
           guint indent, guint width)
{
	gchar **words = g_strsplit_set (text != NULL ? text : "", " \t\r\n", -1);
	glong col = g_utf8_strlen (first, -1);
	gboolean line_empty = TRUE;

	g_string_append (out, first);
	for (guint i = 0; words[i] != NULL; i++) {
		glong len = g_utf8_strlen (words[i], -1);

		if (len == 0)
			continue;
		if (!line_empty && col + 1 + len > (glong) width) {
			g_string_append_c (out, '\n');
			for (guint s = 0; s < indent; s++)
				g_string_append_c (out, ' ');
			col = indent;
			line_empty = TRUE;
		}
		if (!line_empty) {
			g_string_append_c (out, ' ');
			col++;
		}
		g_string_append (out, words[i]);
		col += len;
		line_empty = FALSE;
	}
	g_string_append_c (out, '\n');
	g_strfreev (words);
}

/* [ topic_command ] -- the command that prints topic `id'. */
static gchar *
topic_command (const gchar *id)
{
	if (fs_cli_find_command (id) != NULL || strcmp (id, "help") == 0 ||
	    strcmp (id, "version") == 0 || strcmp (id, "topics") == 0 ||
	    strcmp (id, "topic") == 0)
		return g_strdup_printf ("stockfw help topic %s", id);
	return g_strdup_printf ("stockfw help %s", id);
}

/* [ link_text ] -- a link as a terminal or a manual page prints it: a
 * topic as the command that shows it, an https: link with its
 * address, any other scheme as its text alone. */
static gchar *
link_text (const gchar *href, const gchar *text, gpointer data)
{
	(void) data;
	if (g_str_has_prefix (href, "help:")) {
		gchar *cmd = topic_command (href + 5);
		gchar *shown = g_strdup_printf ("%s (%s)", text, cmd);

		g_free (cmd);
		return shown;
	}
	if (g_str_has_prefix (href, "https://")) {
		if (strcmp (text, href) == 0 || strcmp (text, href + 8) == 0)
			return g_strdup (href);
		return g_strdup_printf ("%s (%s)", text, href);
	}
	return NULL;
}

/* [ plain ] -- topic markup as plain text, safe for a terminal, with
 * an ellipsis the locale can show. */
static gchar *
plain (const gchar *markup)
{
	gchar *text = fs_help_markup_to_text (markup, link_text, NULL);
	gchar *safe = fs_cli_out_safe (text);
	const gchar *ell = fs_cli_sym (FS_CLI_SYM_ELLIPSIS);

	g_free (text);
	if (strcmp (ell, "\u2026") != 0 && strstr (safe, "\u2026") != NULL) {
		gchar **parts = g_strsplit (safe, "\u2026", -1);

		g_free (safe);
		safe = g_strjoinv (ell, parts);
		g_strfreev (parts);
	}
	return safe;
}

/* --------------------------------------------------------- one topic */

static const gchar *
kind_name (FsHelpKind kind)
{
	switch (kind) {
	case FS_HELP_PARA: return "para";
	case FS_HELP_HEAD: return "heading";
	case FS_HELP_STEP: return "step";
	case FS_HELP_ITEM: return "item";
	case FS_HELP_NOTE: return "note";
	case FS_HELP_WARN: return "warning";
	case FS_HELP_SOON: return "not_in_build";
	case FS_HELP_KEYS: return "keys";
	case FS_HELP_CODE: return "code";
	case FS_HELP_SEE:  return "see";
	case FS_HELP_END:  break;
	}
	return "end";
}

/* The words a callout starts with, as the Help window labels it. */
static const gchar *
callout_label (FsHelpKind kind)
{
	switch (kind) {
	case FS_HELP_NOTE: return "Good to know: ";
	case FS_HELP_WARN: return "Before you do this: ";
	case FS_HELP_SOON: return "Not in this build: ";
	default:           return "";
	}
}

/* A list of topics as rows "  TITLE   COMMAND" (SEE, and the parts
 * of a topic). */
static void
topic_rows (GString *out, const gchar * const *ids, guint width)
{
	guint wide = 0;

	for (guint i = 0; ids[i] != NULL; i++) {
		const FsHelpTopic *t = fs_help_topic_find (ids[i]);

		if (t != NULL)
			wide = MAX (wide, (guint) g_utf8_strlen (t->title, -1));
	}
	wide = MIN (wide, 30);
	for (guint i = 0; ids[i] != NULL; i++) {
		const FsHelpTopic *t = fs_help_topic_find (ids[i]);
		gchar *cmd = topic_command (ids[i]);
		gchar *title = plain (t != NULL ? t->title : ids[i]);
		GString *first = g_string_new ("  ");

		/* padded by characters, not bytes */
		g_string_append (first, title);
		for (glong p = g_utf8_strlen (title, -1); p < (glong) wide + 2; p++)
			g_string_append_c (first, ' ');
		wrap_into (out, cmd, first->str, wide + 4, width);
		g_string_free (first, TRUE);
		g_free (title);
		g_free (cmd);
	}
}

/* [ topic_children ] -- the ids of the topics whose parent is `id',
 * NULL-ended (g_free the array only), or NULL when none. */
static const gchar **
topic_children (const gchar *id)
{
	GPtrArray *ids = g_ptr_array_new ();

	for (guint i = 0; i < fs_help_topic_count (); i++) {
		const FsHelpTopic *t = fs_help_topic_nth (i);

		if (g_strcmp0 (t->parent, id) == 0)
			g_ptr_array_add (ids, (gpointer) t->id);
	}
	if (ids->len == 0) {
		g_ptr_array_free (ids, TRUE);
		return NULL;
	}
	g_ptr_array_add (ids, NULL);
	return (const gchar **) g_ptr_array_free (ids, FALSE);
}

/* [ topic_text ] -- one topic as a terminal shows it. */
static void
topic_text (GString *out, const FsHelpTopic *topic)
{
	guint width = text_width ();
	FsHelpKind prev = FS_HELP_END;
	guint step = 0;
	gchar *s;
	const gchar **children;

	s = plain (topic->title);
	g_string_append_printf (out, "%s%s%s\n", fs_cli_bold (), s,
	                        fs_cli_reset ());
	g_free (s);
	s = plain (topic->summary);
	wrap_into (out, s, "", 0, width);
	g_free (s);
	if (fs_help_topic_desktop_only (topic))
		wrap_into (out, "This topic is about the desktop app's own "
		           "windows; a terminal has none of them.", "", 0, width);

	for (const FsHelpBlock *b = topic->blocks;
	     b != NULL && b->kind != FS_HELP_END; b++) {
		gboolean run = b->kind == prev &&
		               (b->kind == FS_HELP_STEP || b->kind == FS_HELP_ITEM ||
		                b->kind == FS_HELP_KEYS || b->kind == FS_HELP_CODE);

		if (!run && prev != FS_HELP_HEAD)
			g_string_append_c (out, '\n');
		if (b->kind != FS_HELP_STEP)
			step = 0;

		switch (b->kind) {
		case FS_HELP_PARA:
			s = plain (b->text);
			wrap_into (out, s, "", 0, width);
			g_free (s);
			break;
		case FS_HELP_HEAD:
			if (prev == FS_HELP_HEAD)
				g_string_append_c (out, '\n');
			s = plain (b->text);
			g_string_append_printf (out, "%s%s%s\n", fs_cli_bold (), s,
			                        fs_cli_reset ());
			g_free (s);
			break;
		case FS_HELP_STEP: {
			gchar *first = g_strdup_printf ("  %u. ", ++step);

			s = plain (b->text);
			wrap_into (out, s, first, 5, width);
			g_free (first);
			g_free (s);
			break;
		}
		case FS_HELP_ITEM:
			s = plain (b->text);
			wrap_into (out, s, "  - ", 4, width);
			g_free (s);
			break;
		case FS_HELP_NOTE:
		case FS_HELP_WARN:
		case FS_HELP_SOON:
			s = plain (b->text);
			wrap_into (out, s, callout_label (b->kind), 2, width);
			g_free (s);
			break;
		case FS_HELP_KEYS: {
			gchar *text = plain (b->text);
			gchar *bar = strchr (text, '|');
			GString *first = g_string_new ("  ");

			if (bar != NULL)
				*bar = '\0';
			g_string_append (first, text);
			if (g_utf8_strlen (first->str, -1) > 18) {
				/* keys too wide for the column: their own line */
				g_string_append_c (first, '\n');
				g_string_append (out, first->str);
				g_string_assign (first, "");
			}
			while (g_utf8_strlen (first->str, -1) < 18)
				g_string_append_c (first, ' ');
			g_string_append_c (first, ' ');
			wrap_into (out, bar != NULL ? bar + 1 : "", first->str, 19,
			           width);
			g_string_free (first, TRUE);
			g_free (text);
			break;
		}
		case FS_HELP_CODE:
			/* plain text, not markup: printed as it is */
			s = fs_cli_out_safe (b->text);
			g_string_append_printf (out, "    %s\n", s);
			g_free (s);
			break;
		case FS_HELP_SEE: {
			gchar **ids = g_strsplit (b->text, " ", -1);

			g_string_append (out, "See also:\n");
			topic_rows (out, (const gchar * const *) ids, width);
			g_strfreev (ids);
			break;
		}
		case FS_HELP_END:
			break;
		}
		prev = b->kind;
	}

	children = topic_children (topic->id);
	if (children != NULL) {
		g_string_append (out, "\nIn this topic:\n");
		topic_rows (out, children, width);
		g_free (children);
	}
	if (topic->parent != NULL) {
		const gchar *up[] = { topic->parent, NULL };

		g_string_append (out, "\nPart of:\n");
		topic_rows (out, up, width);
	}
}

/* [ topic_json ] -- one topic, its blocks as plain text. */
static void
topic_json (GString *out, const FsHelpTopic *topic, gboolean blocks)
{
	guint index = 0;
	gchar *cmd = topic_command (topic->id);
	gchar *s;

	for (guint i = 0; i < fs_help_topic_count (); i++)
		if (fs_help_topic_nth (i) == topic)
			index = i;

	g_string_append_c (out, '{');
	fs_json_kv_str (out, "id", topic->id);
	g_string_append_c (out, ',');
	s = fs_help_markup_to_text (topic->title, NULL, NULL);
	fs_json_kv_str (out, "title", s);
	g_free (s);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "section", fs_help_topic_section_at (index));
	g_string_append_c (out, ',');
	fs_json_key (out, "parent");
	if (topic->parent != NULL)
		fs_json_string (out, topic->parent);
	else
		g_string_append (out, "null");
	g_string_append_c (out, ',');
	s = fs_help_markup_to_text (topic->summary, NULL, NULL);
	fs_json_kv_str (out, "summary", s);
	g_free (s);
	g_string_append_c (out, ',');
	fs_json_kv_bool (out, "desktop_app", fs_help_topic_desktop_only (topic));
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "command", cmd);
	g_free (cmd);

	if (blocks) {
		gboolean first = TRUE;

		g_string_append (out, ",\"blocks\":[");
		for (const FsHelpBlock *b = topic->blocks;
		     b != NULL && b->kind != FS_HELP_END; b++) {
			if (!first)
				g_string_append_c (out, ',');
			first = FALSE;
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "kind", kind_name (b->kind));
			g_string_append_c (out, ',');
			if (b->kind == FS_HELP_SEE) {
				gchar **ids = g_strsplit (b->text, " ", -1);

				g_string_append (out, "\"topics\":[");
				for (guint i = 0; ids[i] != NULL; i++) {
					if (i > 0)
						g_string_append_c (out, ',');
					fs_json_string (out, ids[i]);
				}
				g_string_append_c (out, ']');
				g_strfreev (ids);
			} else {
				s = b->kind == FS_HELP_CODE
				    ? g_strdup (b->text)
				    : fs_help_markup_to_text (b->text, link_text, NULL);
				fs_json_kv_str (out, "text", s);
				g_free (s);
			}
			g_string_append_c (out, '}');
		}
		g_string_append_c (out, ']');
	}
	g_string_append_c (out, '}');
}

static gint
show_topic (const FsHelpTopic *topic)
{
	GString *out = g_string_new (NULL);

	if (fs_cli.json) {
		topic_json (out, topic, TRUE);
		fs_cli_print_json (out);
		return FS_EXIT_OK;
	}
	topic_text (out, topic);
	fputs (out->str, stdout);
	g_string_free (out, TRUE);
	return FS_EXIT_OK;
}

/* ------------------------------------------------------- the list */

/* What to type after `stockfw help' to see a topic. */
static gchar *
topic_word (const FsHelpTopic *t)
{
	gchar *cmd = topic_command (t->id);
	gchar *word = g_strdup (cmd + strlen ("stockfw help "));

	g_free (cmd);
	return word;
}

static void
list_rows (GString *out, gboolean desktop, guint width)
{
	const gchar *section = NULL;

	for (guint i = 0; i < fs_help_topic_count (); i++) {
		const FsHelpTopic *t = fs_help_topic_nth (i);
		const gchar *sec = fs_help_topic_section_at (i);
		gchar *word, *title, *first;

		if (fs_help_topic_desktop_only (t) != desktop)
			continue;
		if (!desktop && g_strcmp0 (sec, section) != 0) {
			gchar *h = plain (sec);

			g_string_append_printf (out, "%s%s%s%s\n",
			                        section != NULL ? "\n" : "",
			                        fs_cli_bold (), h, fs_cli_reset ());
			g_free (h);
			section = sec;
		}
		word = topic_word (t);
		title = plain (t->title);
		first = g_strdup_printf ("  %-24s", word);
		wrap_into (out, title, first, 26, width);
		g_free (first);
		g_free (title);
		g_free (word);
	}
}

static gint
list_topics (void)
{
	GString *out = g_string_new (NULL);
	guint width = text_width ();

	if (fs_cli.json) {
		gboolean first = TRUE;

		g_string_append (out, "{\"topics\":[");
		for (guint i = 0; i < fs_help_topic_count (); i++) {
			if (!first)
				g_string_append_c (out, ',');
			first = FALSE;
			topic_json (out, fs_help_topic_nth (i), FALSE);
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		return FS_EXIT_OK;
	}

	wrap_into (out, "The StockFW guide: the topics the desktop app's Help "
	           "shows. Type "
	           "what a line starts with after `stockfw help' to read "
	           "that topic; `stockfw help --search WORD' finds words in "
	           "them.", "", 0, width);
	g_string_append_c (out, '\n');
	list_rows (out, FALSE, width);
	g_string_append_c (out, '\n');
	g_string_append_printf (out, "%sDesktop app topics%s\n", fs_cli_bold (),
	                        fs_cli_reset ());
	wrap_into (out, "About the desktop app's own windows, which a terminal "
	           "does not have:", "", 0, width);
	list_rows (out, TRUE, width);
	fputs (out->str, stdout);
	g_string_free (out, TRUE);
	return FS_EXIT_OK;
}

/* ----------------------------------------------------------- search */

/* [ topic_haystack ] -- everything a search looks in, casefolded. */
static gchar *
topic_haystack (const FsHelpTopic *t, gboolean head_only)
{
	GString *all = g_string_new (t->id);
	gchar *s, *folded;

	g_string_append_c (all, '\n');
	for (guint k = 0; k < 3; k++) {
		const gchar *m = k == 0 ? t->title : k == 1 ? t->summary
		                                            : t->keywords;

		s = fs_help_markup_to_text (m, NULL, NULL);
		g_string_append (all, s);
		g_string_append_c (all, '\n');
		g_free (s);
	}
	for (const FsHelpBlock *b = t->blocks;
	     !head_only && b != NULL && b->kind != FS_HELP_END; b++) {
		if (b->kind == FS_HELP_SEE)
			continue;
		s = b->kind == FS_HELP_CODE ? g_strdup (b->text)
		                            : fs_help_markup_to_text (b->text, NULL,
		                                                      NULL);
		g_string_append (all, s);
		g_string_append_c (all, '\n');
		g_free (s);
	}
	folded = g_utf8_casefold (all->str, -1);
	g_string_free (all, TRUE);
	return folded;
}

static gboolean
holds_all (const gchar *hay, gchar **words)
{
	for (guint i = 0; words[i] != NULL; i++)
		if (*words[i] != '\0' && strstr (hay, words[i]) == NULL)
			return FALSE;
	return TRUE;
}

static gint
search_topics (const gchar *query)
{
	gchar *folded = g_utf8_casefold (query, -1);
	gchar **words = g_strsplit_set (g_strstrip (folded), " \t", -1);
	GPtrArray *found = g_ptr_array_new ();
	GString *out = g_string_new (NULL);
	guint width = text_width ();
	gboolean any_word = FALSE;

	for (guint i = 0; words[i] != NULL; i++)
		any_word = any_word || *words[i] != '\0';
	if (!any_word) {
		fs_cli_error ("--search needs a word to look for");
		fs_cli_hint ("`stockfw help topics' lists every topic");
		g_strfreev (words);
		g_free (folded);
		g_ptr_array_unref (found);
		g_string_free (out, TRUE);
		return FS_EXIT_USAGE;
	}

	/* The topics that name the words in their title, summary or
	 * keywords first, then those that hold them in their text. */
	for (guint pass = 0; pass < 2; pass++)
		for (guint i = 0; i < fs_help_topic_count (); i++) {
			const FsHelpTopic *t = fs_help_topic_nth (i);
			gchar *hay = topic_haystack (t, pass == 0);

			if (holds_all (hay, words) &&
			    !g_ptr_array_find (found, t, NULL))
				g_ptr_array_add (found, (gpointer) t);
			g_free (hay);
		}

	if (fs_cli.json) {
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "search", query);
		g_string_append (out, ",\"topics\":[");
		for (guint i = 0; i < found->len; i++) {
			if (i > 0)
				g_string_append_c (out, ',');
			topic_json (out, g_ptr_array_index (found, i), FALSE);
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		out = NULL;
	} else if (found->len > 0) {
		for (guint i = 0; i < found->len; i++) {
			const FsHelpTopic *t = g_ptr_array_index (found, i);
			gchar *word = topic_word (t);
			gchar *title = plain (t->title);
			gchar *summary = plain (t->summary);
			gchar *first = g_strdup_printf ("  %-24s", word);

			if (fs_help_topic_desktop_only (t)) {
				gchar *more = g_strconcat (title, " (desktop app)", NULL);

				g_free (title);
				title = more;
			}
			wrap_into (out, title, first, 26, width);
			wrap_into (out, summary, "    ", 4, width);
			g_free (first);
			g_free (summary);
			g_free (title);
			g_free (word);
		}
		fputs (out->str, stdout);
	}
	if (out != NULL)
		g_string_free (out, TRUE);

	if (found->len == 0 && !fs_cli.json) {
		gchar *safe = fs_cli_out_safe (query);

		fs_cli_error ("no help topic holds \"%s\"", safe);
		fs_cli_hint ("`stockfw help topics' lists every topic");
		g_free (safe);
	}
	{
		gint rc = found->len > 0 ? FS_EXIT_OK : FS_EXIT_FAILURE;

		g_ptr_array_unref (found);
		g_strfreev (words);
		g_free (folded);
		return rc;
	}
}

/* ------------------------------------------------------------- help */

/* [ unknown_topic ] -- neither a command nor a topic, with the
 * closest of both. */
static gint
unknown_topic (const gchar *word)
{
	GPtrArray *names = g_ptr_array_new ();
	guint n;
	const FsCliCommandDef * const *all = fs_cli_all_commands (&n);
	const gchar *best;
	gchar *safe = fs_cli_out_safe (word);

	for (guint i = 0; i < n; i++)
		g_ptr_array_add (names, (gpointer) all[i]->name);
	g_ptr_array_add (names, (gpointer) "version");
	g_ptr_array_add (names, (gpointer) "topics");
	for (guint i = 0; i < fs_help_topic_count (); i++)
		g_ptr_array_add (names, (gpointer) fs_help_topic_nth (i)->id);
	best = fs_cli_suggest (word, (const gchar * const *) names->pdata,
	                       names->len);
	if (best != NULL)
		fs_cli_error ("no such command or help topic: %s (did you mean "
		              "`stockfw help %s'?)", safe, best);
	else
		fs_cli_error ("no such command or help topic: %s", safe);
	fs_cli_hint ("`stockfw help' lists the commands, `stockfw help topics' "
	             "the topics");
	g_ptr_array_unref (names);
	g_free (safe);
	return FS_EXIT_USAGE;
}

static gint
fs_cli_cmd_help (gint argc, gchar **argv)
{
	GPtrArray *words = g_ptr_array_new ();
	GString *query = NULL;
	const gchar *w0, *w1, *text;
	const FsHelpTopic *topic;
	gint rc = FS_EXIT_OK;

	for (gint i = 1; i < argc; i++) {
		const gchar *v = NULL;
		gint bad = FS_EXIT_OK;

		if (fs_cli_take_opt (argc, argv, &i, "--search", &v, &bad)) {
			if (v == NULL) {
				rc = bad;
				goto out;
			}
			if (query == NULL)
				query = g_string_new (v);
			else
				g_string_append_printf (query, " %s", v);
		} else if (bad != FS_EXIT_OK) {
			rc = bad;
			goto out;
		} else if (fs_cli_is_option_at (argv, i)) {
			fs_cli_unknown_option ("help", argv[i]);
			rc = FS_EXIT_USAGE;
			goto out;
		} else {
			g_ptr_array_add (words, argv[i]);
		}
	}

	if (query != NULL) {
		/* help --search ssh login: every word after it counts */
		for (guint i = 0; i < words->len; i++)
			g_string_append_printf (query, " %s",
			                        (gchar *) g_ptr_array_index (words, i));
		rc = search_topics (query->str);
		goto out;
	}

	w0 = words->len > 0 ? g_ptr_array_index (words, 0) : NULL;
	w1 = words->len > 1 ? g_ptr_array_index (words, 1) : NULL;

	if (w0 == NULL) {
		fputs (fs_cli_command_help (NULL), stdout);
		goto out;
	}
	if (strcmp (w0, "topics") == 0 || strcmp (w0, "topic") == 0) {
		if (w1 == NULL) {
			rc = list_topics ();
		} else if ((topic = fs_help_topic_find (w1)) != NULL) {
			rc = show_topic (topic);
		} else {
			rc = unknown_topic (w1);
		}
		goto out;
	}

	/* A command keeps its own help (`help intel geo' too); a topic of
	 * the same name is pointed at. */
	text = fs_cli_command_help (w0);
	if (text != NULL) {
		fputs (text, stdout);
		if (fs_help_topic_find (w0) != NULL && !fs_cli.json &&
		    !fs_cli.quiet)
			printf ("\nThe guide has a topic on it too: stockfw help "
			        "topic %s\n", w0);
		goto out;
	}
	topic = fs_help_topic_find (w0);
	rc = topic != NULL ? show_topic (topic) : unknown_topic (w0);

out:
	if (query != NULL)
		g_string_free (query, TRUE);
	g_ptr_array_unref (words);
	return rc;
}

/* ------------------------------------------------------------ about */

static gchar *
system_os (void)
{
	gchar *os = g_get_os_info (G_OS_INFO_KEY_PRETTY_NAME);

	if (os == NULL)
		os = g_get_os_info (G_OS_INFO_KEY_NAME);
	return os;
}

static gint
fs_cli_cmd_about (gint argc, gchar **argv)
{
	gboolean credits = FALSE, licences = FALSE, system = FALSE;
	const FsBackend *backend = fs_backend ();
	const gchar *backend_name = backend != NULL && backend->display_name
	                            ? backend->display_name : "none";
	GString *out = g_string_new (NULL);
	guint width = text_width ();

	for (gint i = 1; i < argc; i++) {
		if (!fs_cli_is_option_at (argv, i)) {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			fs_cli_hint ("see `stockfw help about'");
			g_string_free (out, TRUE);
			return FS_EXIT_USAGE;
		}
		if (strcmp (argv[i], "--credits") == 0)
			credits = TRUE;
		else if (strcmp (argv[i], "--licences") == 0 ||
		         strcmp (argv[i], "--licenses") == 0)
			licences = TRUE;
		else if (strcmp (argv[i], "--system") == 0)
			system = TRUE;
		else {
			fs_cli_unknown_option ("about", argv[i]);
			g_string_free (out, TRUE);
			return FS_EXIT_USAGE;
		}
	}
	if (credits + licences + system > 1) {
		fs_cli_error ("--credits, --licences and --system go one at a time");
		g_string_free (out, TRUE);
		return FS_EXIT_USAGE;
	}

	if (system) {
		/* As the About window's "Copy system info", without the GTK
		 * versions: nothing that names the user or the machine. */
		gchar *os = system_os ();
		gchar *safe_os = fs_cli_out_safe (os != NULL ? os : "unknown");

		if (fs_cli.json) {
			gchar *glib = g_strdup_printf ("%u.%u.%u", glib_major_version,
			                               glib_minor_version,
			                               glib_micro_version);
			gchar *built = g_strdup_printf ("%u.%u.%u", GLIB_MAJOR_VERSION,
			                                GLIB_MINOR_VERSION,
			                                GLIB_MICRO_VERSION);

			g_string_append_c (out, '{');
			fs_json_kv_str (out, "stockfw", FS_VERSION);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "glib", glib);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "glib_built", built);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "os", os != NULL ? os : "unknown");
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "platform", FS_CLI_PLATFORM);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "backend", backend_name);
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			out = NULL;
			g_free (glib);
			g_free (built);
		} else {
			g_string_append_printf (out,
				"StockFW %s\n"
				"GLib %u.%u.%u (built with %u.%u.%u)\n"
				"Platform: %s (%s build)\n"
				"Firewall backend: %s\n",
				FS_VERSION,
				glib_major_version, glib_minor_version,
				glib_micro_version, GLIB_MAJOR_VERSION,
				GLIB_MINOR_VERSION, GLIB_MICRO_VERSION,
				safe_os, FS_CLI_PLATFORM, backend_name);
			fputs (out->str, stdout);
			fflush (stdout);
			fs_cli_hint ("these lines name no user, host or address: "
			             "paste them into a bug report as they are");
		}
		g_free (safe_os);
		g_free (os);
	} else if (licences) {
		if (fs_cli.json) {
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "copying", fs_licence_copying);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "license", fs_licence_license);
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			out = NULL;
		} else {
			g_string_append_printf (out,
				"%sCOPYING: the GNU General Public License version 2%s\n\n",
				fs_cli_bold (), fs_cli_reset ());
			g_string_append (out, fs_licence_copying);
			g_string_append_printf (out,
				"\n\n%sLICENSE: the Apache License 2.0%s\n\n",
				fs_cli_bold (), fs_cli_reset ());
			g_string_append (out, fs_licence_license);
			if (out->len > 0 && out->str[out->len - 1] != '\n')
				g_string_append_c (out, '\n');
			fputs (out->str, stdout);
		}
	} else if (fs_cli.json) {
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "name", "StockFW");
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "version", FS_VERSION);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "backend", backend != NULL ? backend->name
		                                                : "none");
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "backend_name", backend_name);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "description", about_desc);
		g_string_append_c (out, ',');
		g_string_append (out, "\"credits\":[");
		for (guint i = 0; i < G_N_ELEMENTS (about_credits); i++) {
			if (i > 0)
				g_string_append_c (out, ',');
			fs_json_string (out, about_credits[i]);
		}
		g_string_append (out, "],");
		fs_json_kv_str (out, "licence", about_licence);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "website", FS_WEBSITE);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		out = NULL;
	} else if (credits) {
		for (guint i = 0; i < G_N_ELEMENTS (about_credits); i++)
			g_string_append_printf (out, "%s\n", about_credits[i]);
		fputs (out->str, stdout);
	} else {
		g_string_append_printf (out, "%sStockFW %s%s %s %s\n",
		                        fs_cli_bold (), FS_VERSION, fs_cli_reset (),
		                        fs_cli_sym (FS_CLI_SYM_SEP), backend_name);
		wrap_into (out, about_desc, "", 0, width);
		g_string_append_printf (out, "\n%sCredits%s\n", fs_cli_bold (),
		                        fs_cli_reset ());
		for (guint i = 0; i < G_N_ELEMENTS (about_credits); i++)
			wrap_into (out, about_credits[i], "  ", 4, width);
		g_string_append_printf (out, "\n%sLicence%s\n", fs_cli_bold (),
		                        fs_cli_reset ());
		wrap_into (out, about_licence, "  ", 2, width);
		wrap_into (out, "Both texts: stockfw about --licences", "  ", 2,
		           width);
		g_string_append_printf (out, "\n%sWebsite%s\n  %s\n", fs_cli_bold (),
		                        fs_cli_reset (), FS_WEBSITE);
		wrap_into (out, "More: stockfw help about (what StockFW keeps on "
		           "this computer, and what it sends)", "\n", 0, width);
		fputs (out->str, stdout);
	}
	if (out != NULL)
		g_string_free (out, TRUE);
	return FS_EXIT_OK;
}

/* ------------------------------------------------- stockfw-topics(7) */

/* [ roff ] -- text as roff, as fs-cli-complete.c writes stockfw(1): a
 * backslash is \e, a line that starts with a dot or quote is guarded,
 * a dash is \-, anything outside ASCII is \[uXXXX]. */
static void
roff (GString *out, const gchar *text)
{
	gboolean bol = TRUE;

	for (const gchar *p = text; *p != '\0'; p = g_utf8_next_char (p)) {
		gunichar c = g_utf8_get_char (p);

		if (c == '\n' || c == '\r' || c == '\t')
			c = ' ';
		if (bol && (c == '.' || c == '\'' || c == ' '))
			g_string_append (out, "\\&");
		bol = FALSE;
		if (c == '\\')
			g_string_append (out, "\\e");
		else if (c == '-')
			g_string_append (out, "\\-");
		else if (c >= 0x80)
			g_string_append_printf (out, "\\[u%04X]", c);
		else if (c < 0x20 || c == 0x7f)
			g_string_append_c (out, ' ');
		else
			g_string_append_c (out, (gchar) c);
	}
}

static void
roff_markup (GString *out, const gchar *markup)
{
	gchar *text = fs_help_markup_to_text (markup, link_text, NULL);

	roff (out, text);
	g_string_append_c (out, '\n');
	g_free (text);
}

static void
roff_topic (GString *out, const FsHelpTopic *t)
{
	gchar *title = fs_help_markup_to_text (t->title, NULL, NULL);
	gchar *up = g_utf8_strup (title, -1);
	gchar *cmd = topic_command (t->id);
	guint step = 0;
	FsHelpKind prev = FS_HELP_END;

	g_string_append (out, ".SH\n");
	roff (out, up);
	g_string_append (out, "\n.B ");
	roff (out, cmd);
	g_string_append (out, "\n.PP\n");
	roff_markup (out, t->summary);

	for (const FsHelpBlock *b = t->blocks;
	     b != NULL && b->kind != FS_HELP_END; b++) {
		if (b->kind != FS_HELP_STEP)
			step = 0;
		switch (b->kind) {
		case FS_HELP_PARA:
			g_string_append (out, ".PP\n");
			roff_markup (out, b->text);
			break;
		case FS_HELP_HEAD:
			g_string_append (out, ".SS\n");
			roff_markup (out, b->text);
			break;
		case FS_HELP_STEP:
			g_string_append_printf (out, ".IP %u. 4\n", ++step);
			roff_markup (out, b->text);
			break;
		case FS_HELP_ITEM:
			g_string_append (out, ".IP \\(bu 2\n");
			roff_markup (out, b->text);
			break;
		case FS_HELP_NOTE:
		case FS_HELP_WARN:
		case FS_HELP_SOON:
			g_string_append (out, ".PP\n\\fB");
			{
				gchar *label = g_strstrip (g_strdup (callout_label (b->kind)));

				roff (out, label);
				g_free (label);
			}
			g_string_append (out, "\\fR\n");
			roff_markup (out, b->text);
			break;
		case FS_HELP_KEYS: {
			gchar *text = fs_help_markup_to_text (b->text, NULL, NULL);
			gchar *bar = strchr (text, '|');

			if (bar != NULL)
				*bar = '\0';
			g_string_append (out, prev == FS_HELP_KEYS ? ".TQ\n" : ".TP 18\n");
			g_string_append (out, ".B ");
			roff (out, text);
			g_string_append_c (out, '\n');
			roff (out, bar != NULL ? bar + 1 : "");
			g_string_append_c (out, '\n');
			g_free (text);
			break;
		}
		case FS_HELP_CODE:
			if (prev != FS_HELP_CODE)
				g_string_append (out, ".PP\n");
			g_string_append (out, ".RS 4\n.nf\n");
			roff (out, b->text);
			g_string_append (out, "\n.fi\n.RE\n");
			break;
		case FS_HELP_SEE: {
			gchar **ids = g_strsplit (b->text, " ", -1);

			g_string_append (out, ".PP\nSee also:\n");
			for (guint i = 0; ids[i] != NULL; i++) {
				gchar *c = topic_command (ids[i]);

				g_string_append (out, ".br\n\\fB");
				roff (out, c);
				g_string_append (out, "\\fR\n");
				g_free (c);
			}
			g_strfreev (ids);
			break;
		}
		case FS_HELP_END:
			break;
		}
		prev = b->kind;
	}
	g_free (cmd);
	g_free (up);
	g_free (title);
}

gint
fs_cli_help_man_topics (void)
{
	GString *out = g_string_new (NULL);

	g_string_append (out,
		".\\\" stockfw-topics(7), made by `stockfw __man topics' from the\n"
		".\\\" help topics.  Do not edit: change src/core/fs-helpcontent.c.\n");
	g_string_append_printf (out,
		".TH STOCKFW\\-TOPICS 7 \"\" \"StockFW %s\" "
		"\"Miscellaneous Information Manual\"\n", FS_VERSION);
	g_string_append (out, ".nh\n");
	g_string_append (out, ".SH NAME\nstockfw\\-topics \\- the StockFW "
	                      "guide: what each page and setting does\n");
	g_string_append (out, ".SH DESCRIPTION\n"
		"The topics the desktop app's Help window shows, one section "
		"each, in its order. \\fBstockfw help\\fR \\fItopic\\fR prints "
		"one in a terminal, \\fBstockfw help topics\\fR lists them and "
		"\\fBstockfw help \\-\\-search\\fR \\fIword\\fR finds words in "
		"them. A link to another topic is written as the command that "
		"shows it. The topics about the desktop app's own windows come "
		"last, under DESKTOP APP TOPICS.\n");

	for (guint i = 0; i < fs_help_topic_count (); i++)
		if (!fs_help_topic_desktop_only (fs_help_topic_nth (i)))
			roff_topic (out, fs_help_topic_nth (i));

	g_string_append (out, ".SH \"DESKTOP APP TOPICS\"\n"
		"These topics are about the desktop app's own windows (the "
		"tray, the Preferences window, its keys), which a terminal does "
		"not have.\n");
	for (guint i = 0; i < fs_help_topic_count (); i++)
		if (fs_help_topic_desktop_only (fs_help_topic_nth (i)))
			roff_topic (out, fs_help_topic_nth (i));

	g_string_append (out, ".SH \"SEE ALSO\"\n.BR stockfw (1)\n");

	fputs (out->str, stdout);
	g_string_free (out, TRUE);
	fflush (stdout);
	return FS_EXIT_OK;
}

/* -------------------------------------------------------- the table */

static const FsCliOption help_opts[] = {
	{ "--search", TRUE,  NULL },
	{ NULL, FALSE, NULL }
};

static const FsCliOption about_opts[] = {
	{ "--credits",  FALSE, NULL },
	{ "--licences", FALSE, NULL },
	{ "--licenses", FALSE, NULL },
	{ "--system",   FALSE, NULL },
	{ NULL, FALSE, NULL }
};

const FsCliCommandDef fs_cli_help_commands[] = {
	{ "help", fs_cli_cmd_help,
"Usage: stockfw help [COMMAND [SUBCOMMAND]]\n"
"       stockfw help TOPIC | topics | topic TOPIC\n"
"       stockfw help --search WORD...\n"
"\n"
"With a command, prints its help, the text `stockfw COMMAND --help'\n"
"prints: `stockfw help intel geo' gives the intel help.\n"
"\n"
"With a topic, prints that topic of the guide the desktop app's Help\n"
"window shows: what StockFW does, its pages, the policy, threat intel,\n"
"the Copilot, What-If, Sentinel, Trust, the settings, the Linux and\n"
"Windows notes and troubleshooting.  A link to another topic is printed\n"
"as the command that shows it.  Where a command has the topic's name\n"
"(events, policy), `stockfw help topic NAME' prints the topic.  Lines\n"
"fit 78 columns, or a narrower terminal.\n"
"\n"
"`help topics' lists the topics.  Those about the desktop app's own\n"
"windows (the tray, the Preferences window, its keys) are listed apart,\n"
"as \"Desktop app topics\".  --search lists the topics that hold every\n"
"WORD in their title, summary or text, and exits 1 when none does.\n"
"stockfw-topics(7) has every topic in one page.\n"
"\n"
"With --json: {topics:[{id, title, section, parent, summary,\n"
"desktop_app, command}]} for the list and a search, and one such object\n"
"with blocks:[{kind, text}] (see: {kind, topics}) for a topic.\n",
	  help_opts, NULL },
	{ "about", fs_cli_cmd_about,
"Usage: stockfw about [--credits | --licences | --system]\n"
"\n"
"The desktop app's About window: the version and the firewall backend,\n"
"what StockFW does, the credits, the licence and the website.\n"
"\n"
"  --credits    the credits alone, one per line\n"
"  --licences   both licence texts the source carries, in full: the GNU\n"
"               General Public License version 2 (COPYING) and the\n"
"               Apache License 2.0 (LICENSE).  --licenses is the same.\n"
"  --system     lines for a bug report: the StockFW and GLib versions,\n"
"               the operating system and the firewall backend.  Nothing\n"
"               that names you or this computer: no user or host name,\n"
"               no paths, no addresses.\n"
"\n"
"With --json: {name, version, backend, backend_name, description,\n"
"credits[], licence, website}; --system {stockfw, glib, glib_built, os,\n"
"platform, backend}; --licences {copying, license}.\n",
	  about_opts, NULL },
	{ NULL, NULL, NULL, NULL, NULL }
};

/* === end PR4-E === */
