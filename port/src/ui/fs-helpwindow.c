/*---[ fs-helpwindow.c ]--------------------------------------------------
 * The Help window (1.0.7).  See fs-helpwindow.h.
 *
 * Built like Preferences: the dark sidebar on the left (a search field
 * and the topics, grouped under their sections), the light page on the
 * right (the topic's title, the line under it and the article).  The
 * article is GtkLabels with Pango markup, one per paragraph, step or
 * callout, so links work and nothing needs a web view.
 *
 *   help:ID links           go to another topic (activate-link)
 *   other links             open in the browser (GTK's default)
 *   Back, Forward           Alt+Left, Alt+Right, and the two buttons
 *   Ctrl+F                  the search field; Escape clears it, Enter
 *                           opens the first topic it finds
 *   Ctrl+W                  closes the window
 *
 * Every colour the window shows is set by the theme (fs-theme.css,
 * "Help and About"), so a dark desktop theme cannot leave light text
 * on the light page.
 *--------------------------------------------------------------------*/

#include "ui/fs-helpwindow.h"
#include "ui/fs-helpcontent.h"
#include "ui/fs-icons.h"
#include "core/fs-i18n.h"

#include <string.h>

#ifndef FS_VERSION
#define FS_VERSION "1.0.6"
#endif

#define HELP_WIDTH   980
#define HELP_HEIGHT  680
#define NAV_WIDTH    250
#define TEXT_CHARS    74    /* a readable line, in characters */

typedef struct
{
	GtkWidget      *window;
	GtkWindowGroup *group;
	GtkWidget      *search;
	GtkWidget      *list;
	GtkWidget      *list_scroll;
	GtkWidget      *list_inner;
	GtkWidget      *empty;
	GtkWidget      *scroll;
	GtkWidget      *back;
	GtkWidget      *forward;
	GtkWidget      *crumb;
	GtkWidget      *crumb_sep;
	GtkWidget      *title;
	GtkWidget      *summary;
	GtkWidget      *article;
	GtkSizeGroup   *keys_column;
	GPtrArray      *back_stack;     /* topic ids (borrowed, static) */
	GPtrArray      *forward_stack;
	const gchar    *current;        /* a topic id (static)          */
	gchar         **words;          /* the casefolded search, or NULL */
	GPtrArray      *haystack;       /* per topic: what search reads  */
	gboolean        syncing;
} Help;

static Help *help = NULL;

static void go_to (const gchar *id, gboolean record);

/* ------------------------------------------------------------ helpers */

static void
add_class (GtkWidget *widget, const gchar *klass)
{
	gtk_style_context_add_class (gtk_widget_get_style_context (widget),
	                             klass);
}

static gint
topic_index (const FsHelpTopic *topic)
{
	for (guint i = 0; i < fs_help_topic_count (); i++)
		if (fs_help_topic_nth (i) == topic)
			return (gint) i;
	return -1;
}

/* The sidebar group a topic is listed under: the section set on it or
 * on the nearest topic before it. */
static const gchar *
section_of (const FsHelpTopic *topic)
{
	const gchar *section = NULL;

	for (guint i = 0; i < fs_help_topic_count (); i++) {
		const FsHelpTopic *t = fs_help_topic_nth (i);

		if (t->section != NULL)
			section = t->section;
		if (t == topic)
			break;
	}
	return section;
}

/* Markup to plain text.  Links are GtkLabel's, not Pango's, so their
 * tags come out first; markup that still does not parse is used as
 * is. */
static gchar *
plain_text (const gchar *markup)
{
	GString *bare;
	gchar *text = NULL;
	const gchar *p;

	if (markup == NULL)
		return g_strdup ("");

	bare = g_string_new (NULL);
	for (p = markup; *p != '\0'; ) {
		if (g_str_has_prefix (p, "<a ") || g_str_has_prefix (p, "</a>")) {
			const gchar *end = strchr (p, '>');

			if (end == NULL)
				break;
			p = end + 1;
			continue;
		}
		g_string_append_c (bare, *p++);
	}
	if (!pango_parse_markup (bare->str, -1, 0, NULL, &text, NULL, NULL))
		text = g_strdup (markup);
	g_string_free (bare, TRUE);
	return text;
}

static gboolean
on_link (GtkLabel *label, const gchar *uri, gpointer data)
{
	(void) label;
	(void) data;

	if (g_str_has_prefix (uri, "help:")) {
		go_to (uri + 5, TRUE);
		return TRUE;
	}
	return FALSE;   /* GTK opens it in the browser */
}

/* A wrapped, left-aligned label for a run of the article's text. */
static GtkWidget *
text_label (const gchar *markup, const gchar *klass)
{
	GtkWidget *label = gtk_label_new (NULL);

	gtk_label_set_markup (GTK_LABEL (label), markup);
	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_label_set_yalign (GTK_LABEL (label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	gtk_label_set_line_wrap_mode (GTK_LABEL (label), PANGO_WRAP_WORD_CHAR);
	gtk_label_set_width_chars (GTK_LABEL (label), 20);
	gtk_label_set_max_width_chars (GTK_LABEL (label), TEXT_CHARS);
	gtk_widget_set_halign (label, GTK_ALIGN_FILL);
	gtk_widget_set_hexpand (label, TRUE);
	g_signal_connect (label, "activate-link", G_CALLBACK (on_link), NULL);
#if PANGO_VERSION_CHECK (1, 50, 0)
	{
		PangoAttrList *attrs = pango_attr_list_new ();

		pango_attr_list_insert (attrs, pango_attr_line_height_new (1.3));
		gtk_label_set_attributes (GTK_LABEL (label), attrs);
		pango_attr_list_unref (attrs);
	}
#endif
	if (klass != NULL)
		add_class (label, klass);
	return label;
}

static GtkWidget *
plain_label (const gchar *text, const gchar *klass)
{
	GtkWidget *label = gtk_label_new (text);

	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	if (klass != NULL)
		add_class (label, klass);
	return label;
}

/* ------------------------------------------------------------- search */

static void
build_haystack (void)
{
	help->haystack = g_ptr_array_new_with_free_func (g_free);

	for (guint i = 0; i < fs_help_topic_count (); i++) {
		const FsHelpTopic *t = fs_help_topic_nth (i);
		GString *all = g_string_new (NULL);
		gchar *piece;

		piece = plain_text (_(t->title));
		g_string_append_printf (all, "%s\n", piece);
		g_free (piece);
		piece = plain_text (_(t->summary));
		g_string_append_printf (all, "%s\n", piece);
		g_free (piece);
		g_string_append_printf (all, "%s\n", _(t->keywords));

		for (const FsHelpBlock *b = t->blocks; b->kind != FS_HELP_END; b++) {
			if (b->kind == FS_HELP_SEE)
				continue;
			piece = b->kind == FS_HELP_CODE ? g_strdup (b->text)
			                                : plain_text (_(b->text));
			g_string_append_printf (all, "%s\n", piece);
			g_free (piece);
		}

		g_ptr_array_add (help->haystack,
		                 g_utf8_casefold (all->str, -1));
		g_string_free (all, TRUE);
	}
}

static gboolean
topic_matches (const FsHelpTopic *topic)
{
	gint index = topic_index (topic);
	const gchar *hay;

	if (help->words == NULL)
		return TRUE;
	if (index < 0)
		return FALSE;

	hay = g_ptr_array_index (help->haystack, index);
	for (gchar **w = help->words; *w != NULL; w++)
		if (**w != '\0' && strstr (hay, *w) == NULL)
			return FALSE;
	return TRUE;
}

/* Whether the sidebar lists a topic now: every match while searching;
 * otherwise every top-level topic, and a topic's subtopics while it or
 * one of them is shown. */
static gboolean
topic_listed (const FsHelpTopic *topic)
{
	const FsHelpTopic *current;

	if (help->words != NULL)
		return topic_matches (topic);
	if (topic->parent == NULL)
		return TRUE;

	current = fs_help_topic_find (help->current);
	return current != NULL
	    && (g_strcmp0 (current->id, topic->parent) == 0
	        || g_strcmp0 (current->parent, topic->parent) == 0);
}

static const FsHelpTopic *
row_topic (GtkListBoxRow *row)
{
	return row != NULL ? g_object_get_data (G_OBJECT (row), "topic") : NULL;
}

static gboolean
filter_row (GtkListBoxRow *row, gpointer data)
{
	(void) data;
	return topic_listed (row_topic (row));
}

static void
header_row (GtkListBoxRow *row, GtkListBoxRow *before, gpointer data)
{
	const gchar *section = section_of (row_topic (row));
	const gchar *above = before != NULL ? section_of (row_topic (before))
	                                    : NULL;
	GtkWidget *header;

	(void) data;
	if (section == NULL || (before != NULL && g_strcmp0 (section, above) == 0)) {
		gtk_list_box_row_set_header (row, NULL);
		return;
	}

	header = gtk_list_box_row_get_header (row);
	if (header == NULL) {
		header = plain_label (_(section), "help-section");
		gtk_list_box_row_set_header (row, header);
	} else {
		gtk_label_set_text (GTK_LABEL (header), _(section));
	}
}

static GtkListBoxRow *
row_for (const gchar *id)
{
	GList *rows = gtk_container_get_children (GTK_CONTAINER (help->list));
	GtkListBoxRow *found = NULL;

	for (GList *l = rows; l != NULL; l = l->next) {
		const FsHelpTopic *t = row_topic (l->data);

		if (t != NULL && g_strcmp0 (t->id, id) == 0) {
			found = l->data;
			break;
		}
	}
	g_list_free (rows);
	return found;
}

/* Re-filters the sidebar and selects the topic shown, when listed. */
static void
sync_sidebar (void)
{
	GtkListBoxRow *row = row_for (help->current);
	guint listed = 0;

	help->syncing = TRUE;
	gtk_list_box_invalidate_filter (GTK_LIST_BOX (help->list));
	gtk_list_box_invalidate_headers (GTK_LIST_BOX (help->list));
	if (row != NULL && topic_listed (row_topic (row)))
		gtk_list_box_select_row (GTK_LIST_BOX (help->list), row);
	else
		gtk_list_box_unselect_all (GTK_LIST_BOX (help->list));
	help->syncing = FALSE;

	/* Keep the topic shown in sight in the sidebar. */
	if (row != NULL && topic_listed (row_topic (row))
	    && gtk_widget_get_allocated_height (GTK_WIDGET (row)) > 1) {
		gint x = 0, y = 0;

		if (gtk_widget_translate_coordinates (GTK_WIDGET (row),
		                                      help->list_inner,
		                                      0, 0, &x, &y))
			gtk_adjustment_clamp_page (
				gtk_scrolled_window_get_vadjustment (
					GTK_SCROLLED_WINDOW (help->list_scroll)),
				y - 40, y + gtk_widget_get_allocated_height (
					GTK_WIDGET (row)) + 40);
	}

	for (guint i = 0; i < fs_help_topic_count (); i++)
		if (topic_listed (fs_help_topic_nth (i)))
			listed++;
	gtk_widget_set_visible (help->empty, listed == 0);
}

static void
on_search_changed (GtkEditable *editable, gpointer data)
{
	const gchar *text = gtk_entry_get_text (GTK_ENTRY (editable));
	gchar *folded = g_utf8_casefold (text, -1);
	gchar *stripped = g_strstrip (folded);

	(void) data;
	g_strfreev (help->words);
	help->words = *stripped != '\0'
	            ? g_strsplit_set (stripped, " \t", -1) : NULL;
	g_free (folded);
	sync_sidebar ();
}

/* Enter: the first topic found. */
static void
on_search_activate (GtkEntry *entry, gpointer data)
{
	(void) entry;
	(void) data;

	if (help->words == NULL)
		return;
	for (guint i = 0; i < fs_help_topic_count (); i++) {
		const FsHelpTopic *t = fs_help_topic_nth (i);

		if (topic_matches (t)) {
			go_to (t->id, TRUE);
			return;
		}
	}
}

static void
on_search_stop (GtkSearchEntry *entry, gpointer data)
{
	(void) data;
	gtk_entry_set_text (GTK_ENTRY (entry), "");
}

static void
on_row_selected (GtkListBox *box, GtkListBoxRow *row, gpointer data)
{
	const FsHelpTopic *t = row_topic (row);

	(void) box;
	(void) data;
	if (help->syncing || t == NULL)
		return;
	go_to (t->id, TRUE);
}

/* ------------------------------------------------------------ article */

static void
on_topic_button (GtkButton *button, gpointer data)
{
	(void) data;
	go_to (g_object_get_data (G_OBJECT (button), "topic-id"), TRUE);
}

/* A flat button that goes to a topic. */
static GtkWidget *
topic_button (const FsHelpTopic *topic, const gchar *prefix,
              const gchar *text, const gchar *klass)
{
	GtkWidget *button = gtk_button_new_with_label (text);
	gchar *name = g_strconcat (prefix, topic->id, NULL);

	gtk_widget_set_name (button, name);
	g_free (name);
	gtk_button_set_relief (GTK_BUTTON (button), GTK_RELIEF_NONE);
	gtk_widget_set_halign (button, GTK_ALIGN_START);
	add_class (button, klass);
	g_object_set_data (G_OBJECT (button), "topic-id", (gpointer) topic->id);
	g_signal_connect (button, "clicked", G_CALLBACK (on_topic_button), NULL);
	return button;
}

static void
pack (GtkWidget *child)
{
	gtk_box_pack_start (GTK_BOX (help->article), child, FALSE, FALSE, 0);
}

/* A row with a marker on the left (a step's number, a bullet) and the
 * text on the right. */
static GtkWidget *
marked_row (GtkWidget *marker, const gchar *markup, const gchar *klass)
{
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);

	add_class (row, klass);
	gtk_widget_set_valign (marker, GTK_ALIGN_START);
	gtk_box_pack_start (GTK_BOX (row), marker, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (row), text_label (markup, "help-para"),
	                    TRUE, TRUE, 0);
	return row;
}

static GtkWidget *
callout (FsHelpKind kind, const gchar *markup)
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	GtkWidget *text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *icon;
	const gchar *klass, *heading;
	FsIconKind kind_icon;

	switch (kind) {
	case FS_HELP_WARN:
		klass = "help-warn";
		heading = _("Before you do this");
		kind_icon = FS_ICON_SHIELD_ALERT;
		break;
	case FS_HELP_SOON:
		klass = "help-soon";
		heading = _("Coming in 1.0.7");
		kind_icon = FS_ICON_FORWARD;
		break;
	default:
		klass = "help-note";
		heading = _("Good to know");
		kind_icon = FS_ICON_INFO;
		break;
	}

	add_class (box, "help-callout");
	add_class (box, klass);
	icon = fs_icon_new (kind_icon, 18);
	add_class (icon, "help-callout-icon");
	gtk_widget_set_valign (icon, GTK_ALIGN_START);
	gtk_box_pack_start (GTK_BOX (box), icon, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (text),
	                    plain_label (heading, "help-callout-title"),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (text),
	                    text_label (markup, "help-callout-text"),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (box), text, TRUE, TRUE, 0);
	return box;
}

/* "Ctrl+F|Search the help": key caps on the left, the text after. */
static GtkWidget *
keys_row (const gchar *spec)
{
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 16);
	GtkWidget *caps = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
	const gchar *bar = strchr (spec, '|');
	gchar *keys = bar != NULL ? g_strndup (spec, bar - spec) : g_strdup (spec);
	gchar **tokens = g_strsplit (keys, " ", -1);

	add_class (row, "help-keys-row");
	for (gchar **t = tokens; *t != NULL; t++) {
		gchar **parts;

		if (**t == '\0')
			continue;
		/* "Ctrl+," is two keys; a lone "+" is the key itself. */
		parts = strlen (*t) > 1 ? g_strsplit (*t, "+", -1)
		                        : g_strsplit (*t, "\x01", -1);
		for (gchar **p = parts; *p != NULL; p++) {
			if (p != parts)
				gtk_box_pack_start (GTK_BOX (caps),
				                    plain_label ("+", "help-key-plus"),
				                    FALSE, FALSE, 0);
			gtk_box_pack_start (GTK_BOX (caps),
			                    plain_label (**p != '\0' ? *p : "+",
			                                 "help-key"),
			                    FALSE, FALSE, 0);
		}
		g_strfreev (parts);
	}
	gtk_size_group_add_widget (help->keys_column, caps);
	gtk_box_pack_start (GTK_BOX (row), caps, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (row),
	                    text_label (bar != NULL ? bar + 1 : "", "help-para"),
	                    TRUE, TRUE, 0);
	g_strfreev (tokens);
	g_free (keys);
	return row;
}

static GtkWidget *
code_box (const gchar *text)
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	GtkWidget *label = gtk_label_new (text);

	add_class (box, "help-code");
	gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	gtk_label_set_selectable (GTK_LABEL (label), TRUE);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	gtk_label_set_line_wrap_mode (GTK_LABEL (label), PANGO_WRAP_CHAR);
	gtk_label_set_max_width_chars (GTK_LABEL (label), TEXT_CHARS);
	gtk_widget_set_can_focus (label, FALSE);
	add_class (label, "help-code-text");
	gtk_box_pack_start (GTK_BOX (box), label, TRUE, TRUE, 0);
	return box;
}

/* Small rounded buttons, one per related topic, that wrap. */
static GtkWidget *
chips (const gchar *heading, const gchar *ids)
{
	GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
	GtkWidget *flow = gtk_flow_box_new ();
	gchar **list = g_strsplit (ids, " ", -1);

	add_class (box, "help-related");
	gtk_box_pack_start (GTK_BOX (box), plain_label (heading, "help-h3"),
	                    FALSE, FALSE, 0);
	gtk_flow_box_set_selection_mode (GTK_FLOW_BOX (flow), GTK_SELECTION_NONE);
	gtk_flow_box_set_homogeneous (GTK_FLOW_BOX (flow), FALSE);
	gtk_flow_box_set_max_children_per_line (GTK_FLOW_BOX (flow), 8);
	gtk_flow_box_set_column_spacing (GTK_FLOW_BOX (flow), 6);
	gtk_flow_box_set_row_spacing (GTK_FLOW_BOX (flow), 6);
	gtk_widget_set_hexpand (flow, TRUE);
	add_class (flow, "help-chips");
	for (gchar **id = list; *id != NULL; id++) {
		const FsHelpTopic *t = fs_help_topic_find (*id);
		GtkWidget *chip;

		if (t == NULL)
			continue;
		chip = topic_button (t, "see:", _(t->title), "help-chip");
		gtk_container_add (GTK_CONTAINER (flow), chip);
		/* The flow box's own child need not take focus too. */
		gtk_widget_set_can_focus (gtk_widget_get_parent (chip), FALSE);
	}
	gtk_box_pack_start (GTK_BOX (box), flow, FALSE, FALSE, 0);
	g_strfreev (list);
	return box;
}

/* For a topic with subtopics (Preferences): one line per subtopic. */
static void
add_children (const FsHelpTopic *topic)
{
	GtkWidget *card = NULL;

	for (guint i = 0; i < fs_help_topic_count (); i++) {
		const FsHelpTopic *t = fs_help_topic_nth (i);
		GtkWidget *row;

		if (g_strcmp0 (t->parent, topic->id) != 0)
			continue;
		if (card == NULL) {
			card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
			add_class (card, "help-children");
			gtk_box_pack_start (GTK_BOX (card),
			                    plain_label (_("In this section"),
			                                 "help-h3"),
			                    FALSE, FALSE, 0);
			pack (card);
		}
		row = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
		add_class (row, "help-child");
		gtk_box_pack_start (GTK_BOX (row),
		                    topic_button (t, "child:", _(t->title),
		                                  "help-child-link"),
		                    FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (row),
		                    text_label (_(t->summary), "help-child-summary"),
		                    FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (card), row, FALSE, FALSE, 0);
	}
}

static void
render (const FsHelpTopic *topic)
{
	GList *old = gtk_container_get_children (GTK_CONTAINER (help->article));
	const FsHelpTopic *parent = fs_help_topic_find (topic->parent);
	gint index = topic_index (topic);
	guint step = 0;

	for (GList *l = old; l != NULL; l = l->next)
		gtk_widget_destroy (l->data);
	g_list_free (old);
	g_clear_object (&help->keys_column);
	help->keys_column = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	gtk_window_set_title (GTK_WINDOW (help->window), _("StockFW Help"));
	gtk_label_set_markup (GTK_LABEL (help->title), _(topic->title));
	gtk_label_set_markup (GTK_LABEL (help->summary), _(topic->summary));

	if (parent != NULL) {
		gtk_button_set_label (GTK_BUTTON (help->crumb), _(parent->title));
		g_object_set_data (G_OBJECT (help->crumb), "topic-id",
		                   (gpointer) parent->id);
	}
	gtk_widget_set_visible (help->crumb, parent != NULL);
	gtk_widget_set_visible (help->crumb_sep, parent != NULL);

	for (const FsHelpBlock *b = topic->blocks; b->kind != FS_HELP_END; b++) {
		gchar *number;

		if (b->kind != FS_HELP_STEP)
			step = 0;

		switch (b->kind) {
		case FS_HELP_PARA:
			pack (text_label (_(b->text), "help-para"));
			break;
		case FS_HELP_HEAD:
			pack (text_label (_(b->text), "help-h2"));
			break;
		case FS_HELP_STEP:
			number = g_strdup_printf ("%u", ++step);
			{
				GtkWidget *badge = plain_label (number,
				                                "help-step-num");

				gtk_label_set_xalign (GTK_LABEL (badge), 0.5);
				pack (marked_row (badge, _(b->text),
				                  "help-step"));
			}
			g_free (number);
			break;
		case FS_HELP_ITEM:
			pack (marked_row (plain_label ("\xe2\x80\xa2", "help-bullet"),
			                  _(b->text), "help-item"));
			break;
		case FS_HELP_NOTE:
		case FS_HELP_WARN:
		case FS_HELP_SOON:
			pack (callout (b->kind, _(b->text)));
			break;
		case FS_HELP_KEYS:
			pack (keys_row (_(b->text)));
			break;
		case FS_HELP_CODE:
			pack (code_box (b->text));
			break;
		case FS_HELP_SEE:
			pack (chips (_("Related topics"), b->text));
			break;
		case FS_HELP_END:
		default:
			break;
		}
	}

	add_children (topic);

	if (index >= 0 && (guint) index + 1 < fs_help_topic_count ()) {
		const FsHelpTopic *next = fs_help_topic_nth (index + 1);
		gchar *text = g_strdup_printf (_("Next: %s"), _(next->title));
		GtkWidget *button = topic_button (next, "next:", text, "fs-link");

		gtk_widget_set_name (button, "help-next");
		add_class (button, "help-next");
		pack (button);
		g_free (text);
	}

	gtk_widget_show_all (help->article);
}

static void
sync_history_buttons (void)
{
	gtk_widget_set_sensitive (help->back, help->back_stack->len > 0);
	gtk_widget_set_sensitive (help->forward, help->forward_stack->len > 0);
}

/* [ go_to ]
 * Shows a topic.  `record' puts the topic being left on the Back list
 * (and empties Forward), as following a link does. */
static void
go_to (const gchar *id, gboolean record)
{
	const FsHelpTopic *topic = fs_help_topic_find (id);
	GtkAdjustment *adj;

	if (help == NULL)
		return;
	if (topic == NULL)
		topic = fs_help_topic_find (FS_HELP_TOPIC_START);
	if (help->current != NULL && strcmp (help->current, topic->id) == 0) {
		sync_sidebar ();
		return;
	}

	if (record && help->current != NULL) {
		g_ptr_array_add (help->back_stack, (gpointer) help->current);
		g_ptr_array_set_size (help->forward_stack, 0);
	}
	help->current = topic->id;

	render (topic);
	sync_sidebar ();
	sync_history_buttons ();

	adj = gtk_scrolled_window_get_vadjustment (
		GTK_SCROLLED_WINDOW (help->scroll));
	gtk_adjustment_set_value (adj, gtk_adjustment_get_lower (adj));
}

static void
go_back (void)
{
	const gchar *id;

	if (help->back_stack->len == 0)
		return;
	id = g_ptr_array_index (help->back_stack, help->back_stack->len - 1);
	g_ptr_array_set_size (help->back_stack, help->back_stack->len - 1);
	g_ptr_array_add (help->forward_stack, (gpointer) help->current);
	help->current = NULL;
	go_to (id, FALSE);
}

static void
go_forward (void)
{
	const gchar *id;

	if (help->forward_stack->len == 0)
		return;
	id = g_ptr_array_index (help->forward_stack,
	                        help->forward_stack->len - 1);
	g_ptr_array_set_size (help->forward_stack, help->forward_stack->len - 1);
	g_ptr_array_add (help->back_stack, (gpointer) help->current);
	help->current = NULL;
	go_to (id, FALSE);
}

static void
on_back (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;
	go_back ();
}

static void
on_forward (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;
	go_forward ();
}

/* ------------------------------------------------------------- window */

static gboolean
on_key (GtkWidget *widget, GdkEventKey *event, gpointer data)
{
	guint mods = event->state & gtk_accelerator_get_default_mod_mask ();

	(void) data;
	if (mods == GDK_CONTROL_MASK
	    && (event->keyval == GDK_KEY_f || event->keyval == GDK_KEY_F)) {
		gtk_widget_grab_focus (help->search);
		return TRUE;
	}
	if (mods == GDK_CONTROL_MASK
	    && (event->keyval == GDK_KEY_w || event->keyval == GDK_KEY_W)) {
		gtk_widget_destroy (widget);
		return TRUE;
	}
	if (mods == GDK_MOD1_MASK && event->keyval == GDK_KEY_Left) {
		go_back ();
		return TRUE;
	}
	if (mods == GDK_MOD1_MASK && event->keyval == GDK_KEY_Right) {
		go_forward ();
		return TRUE;
	}
	if (mods == 0 && event->keyval == GDK_KEY_Escape
	    && *gtk_entry_get_text (GTK_ENTRY (help->search)) != '\0') {
		gtk_entry_set_text (GTK_ENTRY (help->search), "");
		return TRUE;
	}
	return FALSE;
}

static void
on_destroy (GtkWidget *widget, gpointer data)
{
	(void) widget;
	(void) data;

	if (help == NULL)
		return;
	g_ptr_array_unref (help->back_stack);
	g_ptr_array_unref (help->forward_stack);
	g_ptr_array_unref (help->haystack);
	g_strfreev (help->words);
	g_clear_object (&help->keys_column);
	g_object_unref (help->group);
	g_free (help);
	help = NULL;
}

/* [ clamp_size ] -- 980x680, or what the work area leaves of it. */
static void
clamp_size (GtkWindow *window, GtkWidget *parent)
{
	GdkDisplay *display = gdk_display_get_default ();
	GdkMonitor *monitor = NULL;
	gint width = HELP_WIDTH, height = HELP_HEIGHT;

	if (display != NULL) {
		GdkWindow *on = parent != NULL ? gtk_widget_get_window (parent)
		                               : NULL;

		monitor = on != NULL
		        ? gdk_display_get_monitor_at_window (display, on)
		        : gdk_display_get_primary_monitor (display);
		if (monitor == NULL && gdk_display_get_n_monitors (display) > 0)
			monitor = gdk_display_get_monitor (display, 0);
	}
	if (monitor != NULL) {
		GdkRectangle area;

		gdk_monitor_get_workarea (monitor, &area);
		if (area.width > 0)
			width = MIN (width, MAX (area.width - 40, 560));
		if (area.height > 0)
			height = MIN (height, MAX (area.height - 40, 400));
	}
	gtk_window_set_default_size (window, width, height);
}

static GtkWidget *
build_nav (void)
{
	GtkWidget *nav = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
	GtkWidget *head = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *scroll = gtk_scrolled_window_new (NULL, NULL);
	gchar *version = g_strdup_printf (_("StockFW %s"), FS_VERSION);

	gtk_widget_set_size_request (nav, NAV_WIDTH, -1);
	add_class (nav, "fs-sidebar");
	add_class (nav, "help-nav");

	add_class (head, "fs-brand");
	gtk_box_pack_start (GTK_BOX (head), plain_label (_("Help"),
	                                                 "fs-brand-name"),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (head), plain_label (version,
	                                                 "fs-brand-version"),
	                    FALSE, FALSE, 0);
	g_free (version);
	gtk_box_pack_start (GTK_BOX (nav), head, FALSE, FALSE, 0);

	help->search = gtk_search_entry_new ();
	gtk_widget_set_name (help->search, "help-search");
	gtk_entry_set_placeholder_text (GTK_ENTRY (help->search),
	                                _("Search the help"));
	add_class (help->search, "help-search");
	g_signal_connect (help->search, "changed",
	                  G_CALLBACK (on_search_changed), NULL);
	g_signal_connect (help->search, "activate",
	                  G_CALLBACK (on_search_activate), NULL);
	g_signal_connect (help->search, "stop-search",
	                  G_CALLBACK (on_search_stop), NULL);
	gtk_box_pack_start (GTK_BOX (nav), help->search, FALSE, FALSE, 0);

	help->list = gtk_list_box_new ();
	gtk_widget_set_name (help->list, "help-topics");
	add_class (help->list, "help-topics");
	gtk_list_box_set_selection_mode (GTK_LIST_BOX (help->list),
	                                 GTK_SELECTION_SINGLE);
	gtk_list_box_set_filter_func (GTK_LIST_BOX (help->list), filter_row,
	                              NULL, NULL);
	gtk_list_box_set_header_func (GTK_LIST_BOX (help->list), header_row,
	                              NULL, NULL);
	for (guint i = 0; i < fs_help_topic_count (); i++) {
		const FsHelpTopic *t = fs_help_topic_nth (i);
		GtkWidget *row = gtk_list_box_row_new ();
		GtkWidget *label = plain_label (_(t->title), "help-topic-label");
		gchar *name = g_strconcat ("topic:", t->id, NULL);

		gtk_widget_set_name (row, name);
		g_free (name);
		gtk_label_set_ellipsize (GTK_LABEL (label), PANGO_ELLIPSIZE_END);
		gtk_widget_set_tooltip_text (row, _(t->summary));
		add_class (row, "help-topic");
		if (t->parent != NULL)
			add_class (row, "help-subtopic");
		g_object_set_data (G_OBJECT (row), "topic", (gpointer) t);
		gtk_container_add (GTK_CONTAINER (row), label);
		gtk_container_add (GTK_CONTAINER (help->list), row);
	}
	g_signal_connect (help->list, "row-selected",
	                  G_CALLBACK (on_row_selected), NULL);

	help->empty = gtk_label_new (_("No topic matches that. Try fewer or "
	                               "other words."));
	gtk_widget_set_name (help->empty, "help-empty");
	gtk_label_set_line_wrap (GTK_LABEL (help->empty), TRUE);
	gtk_label_set_xalign (GTK_LABEL (help->empty), 0.0);
	add_class (help->empty, "help-empty");
	gtk_widget_set_no_show_all (help->empty, TRUE);

	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	add_class (scroll, "help-topics-scroll");
	{
		GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);

		gtk_box_pack_start (GTK_BOX (inner), help->list, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (inner), help->empty, FALSE, FALSE, 0);
		gtk_container_add (GTK_CONTAINER (scroll), inner);
		help->list_inner = inner;
		help->list_scroll = scroll;
	}
	gtk_box_pack_start (GTK_BOX (nav), scroll, TRUE, TRUE, 0);
	return nav;
}

static GtkWidget *
history_button (FsIconKind icon, const gchar *name, const gchar *tip,
                GCallback cb)
{
	GtkWidget *button = gtk_button_new ();

	gtk_container_add (GTK_CONTAINER (button), fs_icon_new (icon, 16));
	gtk_widget_set_name (button, name);
	gtk_widget_set_tooltip_text (button, tip);
	add_class (button, "btn-subtle");
	add_class (button, "help-history");
	g_signal_connect (button, "clicked", cb, NULL);
	return button;
}

static GtkWidget *
build_page (void)
{
	GtkWidget *right = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *bar = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	GtkWidget *page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *head = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);

	add_class (right, "help-content");
	add_class (bar, "help-toolbar");
	help->back = history_button (FS_ICON_BACK, "help-back",
	                             _("Back (Alt+Left)"),
	                             G_CALLBACK (on_back));
	help->forward = history_button (FS_ICON_FORWARD, "help-forward",
	                                _("Forward (Alt+Right)"),
	                                G_CALLBACK (on_forward));
	gtk_box_pack_start (GTK_BOX (bar), help->back, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (bar), help->forward, FALSE, FALSE, 0);

	help->crumb = gtk_button_new_with_label ("");
	gtk_widget_set_name (help->crumb, "help-crumb");
	gtk_button_set_relief (GTK_BUTTON (help->crumb), GTK_RELIEF_NONE);
	add_class (help->crumb, "fs-link");
	add_class (help->crumb, "help-crumb");
	gtk_widget_set_valign (help->crumb, GTK_ALIGN_CENTER);
	g_signal_connect (help->crumb, "clicked",
	                  G_CALLBACK (on_topic_button), NULL);
	gtk_widget_set_no_show_all (help->crumb, TRUE);
	/* "Part of Preferences", for a subtopic. */
	help->crumb_sep = plain_label (_("Part of"), "help-crumb-sep");
	gtk_widget_set_no_show_all (help->crumb_sep, TRUE);
	gtk_box_pack_start (GTK_BOX (bar), help->crumb_sep, FALSE, FALSE, 10);
	gtk_box_pack_start (GTK_BOX (bar), help->crumb, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (right), bar, FALSE, FALSE, 0);

	add_class (page, "help-page");
	add_class (head, "help-head");
	help->title = text_label ("", "help-title");
	gtk_widget_set_name (help->title, "help-title");
	help->summary = text_label ("", "help-summary");
	gtk_widget_set_name (help->summary, "help-summary");
	gtk_box_pack_start (GTK_BOX (head), help->title, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (head), help->summary, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), head, FALSE, FALSE, 0);

	help->article = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	gtk_widget_set_name (help->article, "help-article");
	add_class (help->article, "help-article");
	gtk_box_pack_start (GTK_BOX (page), help->article, FALSE, FALSE, 0);

	help->scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (help->scroll),
	                                GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (help->scroll), page);
	gtk_widget_set_vexpand (help->scroll, TRUE);
	gtk_box_pack_start (GTK_BOX (right), help->scroll, TRUE, TRUE, 0);
	return right;
}

static void
build_window (GtkWidget *parent)
{
	GtkWidget *outer = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	GtkWidget *top = parent != NULL ? gtk_widget_get_toplevel (parent) : NULL;

	help = g_new0 (Help, 1);
	help->back_stack = g_ptr_array_new ();
	help->forward_stack = g_ptr_array_new ();
	build_haystack ();

	help->window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_widget_set_name (help->window, "fs-help");
	add_class (help->window, "help-window");
	gtk_window_set_title (GTK_WINDOW (help->window), _("StockFW Help"));
	gtk_window_set_position (GTK_WINDOW (help->window), GTK_WIN_POS_CENTER);
	if (top != NULL && GTK_IS_WINDOW (top)
	    && gtk_window_get_icon (GTK_WINDOW (top)) != NULL)
		gtk_window_set_icon (GTK_WINDOW (help->window),
		                     gtk_window_get_icon (GTK_WINDOW (top)));
	clamp_size (GTK_WINDOW (help->window), top);

	/* Its own group: a modal window elsewhere (Preferences) holds a
	 * grab on the default group, not on this one. */
	help->group = gtk_window_group_new ();
	gtk_window_group_add_window (help->group, GTK_WINDOW (help->window));

	g_signal_connect (help->window, "key-press-event",
	                  G_CALLBACK (on_key), NULL);
	g_signal_connect (help->window, "destroy",
	                  G_CALLBACK (on_destroy), NULL);

	gtk_box_pack_start (GTK_BOX (outer), build_nav (), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (outer), build_page (), TRUE, TRUE, 0);
	gtk_container_add (GTK_CONTAINER (help->window), outer);
	gtk_widget_show_all (outer);
}

/* --------------------------------------------------------------- API */

void
fs_help_show (GtkWidget *parent, const gchar *topic)
{
	if (help == NULL)
		build_window (parent);

	go_to (topic != NULL ? topic : FS_HELP_TOPIC_START,
	       help->current != NULL);
	sync_history_buttons ();
	gtk_window_present (GTK_WINDOW (help->window));
}

const gchar *
fs_help_topic_for_page (gint page)
{
	/* FsAppPage order: Overview, Events, Activity, Policy, Copilot,
	 * Trust. */
	static const gchar *const ids[] = {
		"overview", "events", "activity", "policy", "copilot", "trust"
	};

	if (page < 0 || page >= (gint) G_N_ELEMENTS (ids))
		return FS_HELP_TOPIC_START;
	return ids[page];
}

const gchar *
fs_help_topic_for_prefs_page (const gchar *page)
{
	gchar *id = g_strconcat ("prefs-", page != NULL ? page : "", NULL);
	const FsHelpTopic *topic = fs_help_topic_find (id);

	g_free (id);
	return topic != NULL ? topic->id : "preferences";
}

GtkWidget *
fs_help_window (void)
{
	return help != NULL ? help->window : NULL;
}

const gchar *
fs_help_current_topic (void)
{
	return help != NULL ? help->current : NULL;
}
