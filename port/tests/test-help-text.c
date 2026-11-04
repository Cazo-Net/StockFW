/*---[ test-help-text.c ]------------------------------------------------
 * The help topics as plain text (master plan PR 4, package 4E):
 *
 *   fs_help_markup_to_text (tags out, entities read, links handed to
 *   the caller, a stray '<' or '&' kept), every topic rendered with no
 *   markup left and every help: link naming a topic, the "Desktop app
 *   topics" (O4: the other topics' titles and summaries name no tray,
 *   window, Ctrl+ key or sign-in), and the section each topic is
 *   listed under.
 *
 * Pure GLib against src/core/fs-helpcontent.c alone, so it runs on
 * Windows too.  tests/test-cli.sh checks what `stockfw help' prints.
 *
 * Run by tests/test-core.sh.
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-helpcontent.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do {                                   \
	checks++;                                               \
	if (!(cond)) {                                          \
		printf ("FAIL: ");                              \
		printf (__VA_ARGS__);                           \
		printf ("\n");                                  \
		failures++;                                     \
	} else {                                                \
		printf ("ok:   ");                              \
		printf (__VA_ARGS__);                           \
		printf ("\n");                                  \
	}                                                       \
} while (0)

/* A link as "TEXT [HREF]", and every help: target kept. */
static gchar *
mark_link (const gchar *href, const gchar *text, gpointer data)
{
	GPtrArray *targets = data;

	if (targets != NULL && g_str_has_prefix (href, "help:"))
		g_ptr_array_add (targets, g_strdup (href + 5));
	return g_strdup_printf ("%s [%s]", text, href);
}

static gboolean
render_is (const gchar *markup, const gchar *want, gboolean links)
{
	gchar *got = fs_help_markup_to_text (markup, links ? mark_link : NULL,
	                                     NULL);
	gboolean same = strcmp (got, want) == 0;

	if (!same)
		printf ("      got \"%s\", want \"%s\"\n", got, want);
	g_free (got);
	return same;
}

/* [ markup_left ] -- a tag or an entity that rendering left in. */
static gboolean
markup_left (const gchar *text)
{
	static const gchar *const bits[] = {
		"<b>", "</b>", "<i>", "</i>", "<tt>", "</tt>", "<a ", "</a>",
		"&amp;", "&lt;", "&gt;", "&quot;", "&apos;", "&#"
	};

	for (guint i = 0; i < G_N_ELEMENTS (bits); i++)
		if (strstr (text, bits[i]) != NULL)
			return TRUE;
	return FALSE;
}

/* A word (case-insensitive, whole word for the plain words) that the
 * terminal's main topic list must not show (O4). */
static const gchar *
desktop_word (const gchar *text)
{
	static const gchar *const words[] = { "tray", "window",
	                                      "sign in", "sign-in" };
	gchar *low = g_ascii_strdown (text, -1);
	const gchar *hit = NULL;

	if (strstr (text, "Ctrl+") != NULL)
		hit = "Ctrl+";
	for (guint i = 0; hit == NULL && i < G_N_ELEMENTS (words); i++) {
		const gchar *at = low;
		gsize n = strlen (words[i]);

		while ((at = strstr (at, words[i])) != NULL) {
			gboolean start = at == low || !g_ascii_isalpha (at[-1]);
			gboolean end = !g_ascii_isalpha (at[n]);

			if (start && end) {
				hit = words[i];
				break;
			}
			at += n;
		}
	}
	g_free (low);
	return hit;
}

static void
test_renderer (void)
{
	CHECK (render_is ("<b>Apply</b> and <i>then</i> <tt>stockfw</tt>",
	                  "Apply and then stockfw", FALSE),
	       "renderer: <b>, <i> and <tt> are taken out");
	CHECK (render_is ("A &amp; B &lt;C&gt; &quot;D&quot; &apos;E&apos;",
	                  "A & B <C> \"D\" 'E'", FALSE),
	       "renderer: the five named entities are read");
	CHECK (render_is ("&#38; &#x3C; &#X3e;", "& < >", FALSE),
	       "renderer: decimal and hex entities are read");
	CHECK (render_is ("a < b & c; d &#0; e &#xD800; f &nope;",
	                  "a < b & c; d &#0; e &#xD800; f &nope;", FALSE),
	       "renderer: a '<' or '&' that starts nothing is kept as written");
	CHECK (render_is ("<span weight=\"bold\">x</span><foo>y</foo>", "xy",
	                  FALSE),
	       "renderer: <span> and an unknown tag are dropped, their text kept");
	CHECK (render_is ("See <a href=\"help:linux\">Linux <b>notes</b></a>.",
	                  "See Linux notes [help:linux].", TRUE),
	       "renderer: a link is handed over with its text rendered");
	CHECK (render_is ("See <a href=\"help:linux\">Linux notes</a>.",
	                  "See Linux notes.", FALSE),
	       "renderer: with no link function a link is its text");
	CHECK (render_is ("<a href=\"https://x.test/?a=1&amp;b=2\">x</a>",
	                  "x [https://x.test/?a=1&b=2]", TRUE),
	       "renderer: an entity in an href is read");
	CHECK (render_is ("open <a href=\"help:x\">and never closed",
	                  "open and never closed", TRUE),
	       "renderer: an <a> left open keeps its text");
	CHECK (render_is ("x <b", "x <b", FALSE),
	       "renderer: a tag with no '>' is kept as written");
	CHECK (render_is (NULL, "", FALSE), "renderer: NULL gives \"\"");
}

static void
test_topics (void)
{
	guint n = fs_help_topic_count ();
	GPtrArray *targets = g_ptr_array_new_with_free_func (g_free);
	guint left = 0, sees = 0, bad_see = 0, bad_link = 0, desktop = 0;
	GString *o4 = g_string_new (NULL);
	gchar *first_left = NULL;

	CHECK (n == 25, "topics: 25 of them (%u)", n);

	for (guint i = 0; i < n; i++) {
		const FsHelpTopic *t = fs_help_topic_nth (i);
		const gchar *parts[] = { t->title, t->summary, t->keywords };

		for (guint k = 0; k < G_N_ELEMENTS (parts); k++) {
			gchar *s = fs_help_markup_to_text (parts[k], mark_link, targets);

			if (markup_left (s) && left++ == 0)
				first_left = g_strdup_printf ("%s: %s", t->id, s);
			g_free (s);
		}
		for (const FsHelpBlock *b = t->blocks; b->kind != FS_HELP_END; b++) {
			if (b->kind == FS_HELP_SEE) {
				gchar **ids = g_strsplit (b->text, " ", -1);

				for (guint j = 0; ids[j] != NULL; j++) {
					sees++;
					if (fs_help_topic_find (ids[j]) == NULL)
						bad_see++;
				}
				g_strfreev (ids);
			} else if (b->kind != FS_HELP_CODE) {
				gchar *s = fs_help_markup_to_text (b->text, mark_link,
				                                   targets);

				if (markup_left (s) && left++ == 0)
					first_left = g_strdup_printf ("%s: %s", t->id, s);
				g_free (s);
			}
		}

		if (fs_help_topic_desktop_only (t)) {
			desktop++;
		} else {
			gchar *title = fs_help_markup_to_text (t->title, NULL, NULL);
			gchar *sum = fs_help_markup_to_text (t->summary, NULL, NULL);
			const gchar *w = desktop_word (title);

			if (w == NULL)
				w = desktop_word (sum);
			if (w != NULL)
				g_string_append_printf (o4, " %s (\"%s\")", t->id, w);
			g_free (title);
			g_free (sum);
		}
	}
	for (guint i = 0; i < targets->len; i++)
		if (fs_help_topic_find (g_ptr_array_index (targets, i)) == NULL)
			bad_link++;

	CHECK (left == 0, "every topic renders with no tag or entity left (%u%s%s)",
	       left, first_left != NULL ? "; first: " : "",
	       first_left != NULL ? first_left : "");
	CHECK (targets->len >= 40 && bad_link == 0,
	       "the help: links are handed to the link function, %u of them, "
	       "each naming a topic (%u do not)", targets->len, bad_link);
	CHECK (sees > 0 && bad_see == 0,
	       "every \"see also\" id names a topic (%u, %u do not)", sees,
	       bad_see);
	CHECK (desktop == 4 &&
	       fs_help_topic_desktop_only (fs_help_topic_find ("shortcuts")) &&
	       fs_help_topic_desktop_only (fs_help_topic_find ("background")) &&
	       fs_help_topic_desktop_only (fs_help_topic_find ("prefs-general")) &&
	       fs_help_topic_desktop_only (fs_help_topic_find ("preferences")) &&
	       !fs_help_topic_desktop_only (fs_help_topic_find ("prefs-icmp")) &&
	       !fs_help_topic_desktop_only (NULL),
	       "desktop app topics: shortcuts, background, prefs-general and "
	       "preferences (%u)", desktop);
	CHECK (o4->len == 0,
	       "O4: no other topic's title or summary names a tray, a window, "
	       "a Ctrl+ key or sign-in (%s)", o4->len ? o4->str : "none");

	CHECK (g_strcmp0 (fs_help_topic_section_at (0), "Start here") == 0 &&
	       g_strcmp0 (fs_help_topic_section_at (2), "Using StockFW") == 0 &&
	       fs_help_topic_section_at (n) == NULL,
	       "sections: a topic takes the section of the group it is in");
	{
		gboolean all = TRUE;

		for (guint i = 0; i < n; i++)
			all = all && fs_help_topic_section_at (i) != NULL;
		CHECK (all, "  ...and every topic has one");
	}

	g_free (first_left);
	g_string_free (o4, TRUE);
	g_ptr_array_unref (targets);
}

int
main (void)
{
	test_renderer ();
	test_topics ();
	printf ("help text: %d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
