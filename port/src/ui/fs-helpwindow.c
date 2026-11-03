/*---[ fs-helpwindow.c ]--------------------------------------------------
 * The Help window (1.0.7).  See fs-helpwindow.h.
 *
 * Built like Preferences: the dark sidebar on the left (a search field
 * and the topics, grouped under their sections), the light page on the
 * right (the topic's title, the line under it and the article).  The
 * article is GtkLabels with Pango markup, one per paragraph, step or
 * callout, so links work and nothing needs a web view.
 *
 *   the topic list          one Tab stop: arrows move along it, Enter
 *                           or a click opens a topic (focus moving
 *                           does not, so Tab never opens topics)
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
#define NAV_WIDTH    FS_SIDE_WIDTH
#define TEXT_CHARS    74    /* a readable line, in characters */
#define COLUMN_WIDTH 700    /* the page's widest: about 80 characters */

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

/* ------------------------------------------------------------- clamp */

typedef struct
{
	GtkBin parent;
	gint   max;
} FsClamp;

typedef struct
{
	GtkBinClass parent_class;
} FsClampClass;

static GType fs_clamp_get_type (void);
G_DEFINE_TYPE (FsClamp, fs_clamp, GTK_TYPE_BIN)

/* The width the child gets out of `width'. */
static gint
clamp_child_width (FsClamp *clamp, GtkWidget *child, gint width)
{
	gint min = 0, nat = 0;

	gtk_widget_get_preferred_width (child, &min, &nat);
	return MAX (min, MIN (width, clamp->max));
}

static GtkSizeRequestMode
fs_clamp_request_mode (GtkWidget *widget)
{
	(void) widget;
	return GTK_SIZE_REQUEST_HEIGHT_FOR_WIDTH;
}

static void
fs_clamp_width (GtkWidget *widget, gint *min, gint *nat)
{
	GtkWidget *child = gtk_bin_get_child (GTK_BIN (widget));

	*min = *nat = 0;
	if (child != NULL && gtk_widget_get_visible (child)) {
		gtk_widget_get_preferred_width (child, min, nat);
		*nat = MAX (*min, MIN (*nat, ((FsClamp *) widget)->max));
	}
}

static void
fs_clamp_height_for_width (GtkWidget *widget, gint width, gint *min,
                           gint *nat)
{
	GtkWidget *child = gtk_bin_get_child (GTK_BIN (widget));

	*min = *nat = 0;
	if (child != NULL && gtk_widget_get_visible (child))
		gtk_widget_get_preferred_height_for_width (child,
			clamp_child_width ((FsClamp *) widget, child, width),
			min, nat);
}

static void
fs_clamp_height (GtkWidget *widget, gint *min, gint *nat)
{
	GtkWidget *child = gtk_bin_get_child (GTK_BIN (widget));

	*min = *nat = 0;
	if (child != NULL && gtk_widget_get_visible (child))
		gtk_widget_get_preferred_height (child, min, nat);
}

static void
fs_clamp_width_for_height (GtkWidget *widget, gint height, gint *min,
                           gint *nat)
{
	(void) height;
	fs_clamp_width (widget, min, nat);
}

static void
fs_clamp_allocate (GtkWidget *widget, GtkAllocation *allocation)
{
	GtkWidget *child = gtk_bin_get_child (GTK_BIN (widget));

	gtk_widget_set_allocation (widget, allocation);
	if (child != NULL && gtk_widget_get_visible (child)) {
		GtkAllocation box = *allocation;

		box.width = clamp_child_width ((FsClamp *) widget, child,
		                               allocation->width);
		box.x += MAX (0, (allocation->width - box.width) / 2);
		gtk_widget_size_allocate (child, &box);
	}
}

static void
fs_clamp_class_init (FsClampClass *klass)
{
	GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (klass);

	widget_class->get_request_mode = fs_clamp_request_mode;
	widget_class->get_preferred_width = fs_clamp_width;
	widget_class->get_preferred_height = fs_clamp_height;
	widget_class->get_preferred_height_for_width =
		fs_clamp_height_for_width;
	widget_class->get_preferred_width_for_height =
		fs_clamp_width_for_height;
	widget_class->size_allocate = fs_clamp_allocate;
}

static void
fs_clamp_init (FsClamp *clamp)
{
	gtk_widget_set_has_window (GTK_WIDGET (clamp), FALSE);
	clamp->max = G_MAXINT;
}

GtkWidget *
fs_clamp_new (gint max_width)
{
	FsClamp *clamp = g_object_new (fs_clamp_get_type (), NULL);

	clamp->max = max_width > 0 ? max_width : G_MAXINT;
	return GTK_WIDGET (clamp);
}

/* -------------------------------------------------------------- wrap */

/* [ FsWrap ]
 * Children side by side at their natural width, `spacing' apart,
 * wrapping onto a new line when the next one does not fit.  A
 * GtkFlowBox would not do: in GTK 3 its natural width is one child
 * per line, and on a wider line it spreads the spare width between its
 * children, which put 50 to 130 pixels between the related-topic
 * chips. */
typedef struct
{
	GtkContainer parent;
	GList       *children;
	gint         spacing;
} FsWrap;

typedef struct
{
	GtkContainerClass parent_class;
} FsWrapClass;

static GType fs_wrap_get_type (void);
G_DEFINE_TYPE (FsWrap, fs_wrap, GTK_TYPE_CONTAINER)

/* Lays the children out in `width'; places them when `at' is given.
 * Returns the height used. */
static gint
fs_wrap_layout (FsWrap *wrap, gint width, const GtkAllocation *at)
{
	gint x = 0, y = 0, line = 0;

	for (GList *l = wrap->children; l != NULL; l = l->next) {
		GtkWidget *child = l->data;
		gint min_w, nat_w, min_h, nat_h, w;

		if (!gtk_widget_get_visible (child))
			continue;
		gtk_widget_get_preferred_width (child, &min_w, &nat_w);
		w = MAX (min_w, MIN (nat_w, width));
		if (x > 0 && x + w > width) {
			x = 0;
			y += line + wrap->spacing;
			line = 0;
		}
		gtk_widget_get_preferred_height_for_width (child, w, &min_h,
		                                           &nat_h);
		if (at != NULL) {
			GtkAllocation box = { at->x + x, at->y + y, w, nat_h };

			gtk_widget_size_allocate (child, &box);
		}
		x += w + wrap->spacing;
		line = MAX (line, nat_h);
	}
	return y + line;
}

static GtkSizeRequestMode
fs_wrap_request_mode (GtkWidget *widget)
{
	(void) widget;
	return GTK_SIZE_REQUEST_HEIGHT_FOR_WIDTH;
}

static void
fs_wrap_width (GtkWidget *widget, gint *min, gint *nat)
{
	FsWrap *wrap = (FsWrap *) widget;
	gint n = 0;

	*min = *nat = 0;
	for (GList *l = wrap->children; l != NULL; l = l->next) {
		gint cmin, cnat;

		if (!gtk_widget_get_visible (l->data))
			continue;
		gtk_widget_get_preferred_width (l->data, &cmin, &cnat);
		*min = MAX (*min, cmin);
		*nat += cnat;
		n++;
	}
	if (n > 1)
		*nat += (n - 1) * wrap->spacing;
}

static void
fs_wrap_height_for_width (GtkWidget *widget, gint width, gint *min,
                          gint *nat)
{
	*min = *nat = fs_wrap_layout ((FsWrap *) widget, width, NULL);
}

static void
fs_wrap_height (GtkWidget *widget, gint *min, gint *nat)
{
	gint wmin, wnat;

	fs_wrap_width (widget, &wmin, &wnat);
	fs_wrap_height_for_width (widget, wmin, min, nat);
}

static void
fs_wrap_width_for_height (GtkWidget *widget, gint height, gint *min,
                          gint *nat)
{
	(void) height;
	fs_wrap_width (widget, min, nat);
}

static void
fs_wrap_allocate (GtkWidget *widget, GtkAllocation *allocation)
{
	gtk_widget_set_allocation (widget, allocation);
	fs_wrap_layout ((FsWrap *) widget, allocation->width, allocation);
}

static void
fs_wrap_add (GtkContainer *container, GtkWidget *child)
{
	FsWrap *wrap = (FsWrap *) container;

	wrap->children = g_list_append (wrap->children, child);
	gtk_widget_set_parent (child, GTK_WIDGET (container));
}

static void
fs_wrap_remove (GtkContainer *container, GtkWidget *child)
{
	FsWrap *wrap = (FsWrap *) container;
	gboolean was_visible = gtk_widget_get_visible (child);

	if (g_list_find (wrap->children, child) == NULL)
		return;
	gtk_widget_unparent (child);
	wrap->children = g_list_remove (wrap->children, child);
	if (was_visible && gtk_widget_get_visible (GTK_WIDGET (container)))
		gtk_widget_queue_resize (GTK_WIDGET (container));
}

static void
fs_wrap_forall (GtkContainer *container, gboolean internals,
                GtkCallback callback, gpointer data)
{
	GList *l = ((FsWrap *) container)->children;

	(void) internals;
	while (l != NULL) {
		GtkWidget *child = l->data;

		l = l->next;   /* the callback may remove the child */
		callback (child, data);
	}
}

static void
fs_wrap_class_init (FsWrapClass *klass)
{
	GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (klass);
	GtkContainerClass *container_class = GTK_CONTAINER_CLASS (klass);

	widget_class->get_request_mode = fs_wrap_request_mode;
	widget_class->get_preferred_width = fs_wrap_width;
	widget_class->get_preferred_height = fs_wrap_height;
	widget_class->get_preferred_height_for_width = fs_wrap_height_for_width;
	widget_class->get_preferred_width_for_height = fs_wrap_width_for_height;
	widget_class->size_allocate = fs_wrap_allocate;
	container_class->add = fs_wrap_add;
	container_class->remove = fs_wrap_remove;
	container_class->forall = fs_wrap_forall;
}

static void
fs_wrap_init (FsWrap *wrap)
{
	gtk_widget_set_has_window (GTK_WIDGET (wrap), FALSE);
}

static GtkWidget *
fs_wrap_new (gint spacing)
{
	FsWrap *wrap = g_object_new (fs_wrap_get_type (), NULL);

	wrap->spacing = spacing;
	return GTK_WIDGET (wrap);
}

/* ------------------------------------------------------------- topics */

/* The sidebar icon of a top-level topic; subtopics have none. */
static FsIconKind
topic_icon (const gchar *id)
{
	static const struct
	{
		const gchar *id;
		FsIconKind   icon;
	} icons[] = {
		{ "getting-started", FS_ICON_PLAY },
		{ "overview",        FS_ICON_SHIELD },
		{ "events",          FS_ICON_LIST },
		{ "activity",        FS_ICON_ACTIVITY },
		{ "policy",          FS_ICON_SLIDERS },
		{ "copilot",         FS_ICON_CHAT },
		{ "whatif",          FS_ICON_SHIELD_QUESTION },
		{ "sentinel",        FS_ICON_SHIELD_ALERT },
		{ "trust",           FS_ICON_CHECK_CIRCLE },
		{ "preferences",     FS_ICON_SETTINGS },
		{ "threat-intel",    FS_ICON_SHIELD_X },
		{ "background",      FS_ICON_CLOCK },
		{ "cli",             FS_ICON_TERMINAL },
		{ "linux",           FS_ICON_MONITOR },
		{ "windows",         FS_ICON_MONITOR },
		{ "troubleshooting", FS_ICON_HELP },
		{ "shortcuts",       FS_ICON_KEYBOARD },
	};

	for (guint i = 0; i < G_N_ELEMENTS (icons); i++)
		if (g_strcmp0 (icons[i].id, id) == 0)
			return icons[i].icon;
	return FS_ICON_INFO;
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
	/* Body text keeps a floor of 20 characters, so a narrow window
	 * does not squeeze it to a few words a line. A heading has none:
	 * the floor is counted in the label's own font, and 20 characters
	 * of the 24-pixel title are wider than the page column of a
	 * 640-pixel window in a wide font (340 pixels in DejaVu Sans). A
	 * heading's narrowest is its longest word. */
	gtk_label_set_width_chars (GTK_LABEL (label),
	                           g_strcmp0 (klass, "help-title") == 0
	                           || g_strcmp0 (klass, "help-h2") == 0
	                           ? -1 : 20);
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
		add_class (header, "side-section");
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

	GList *rows;

	help->syncing = TRUE;
	gtk_list_box_invalidate_filter (GTK_LIST_BOX (help->list));
	gtk_list_box_invalidate_headers (GTK_LIST_BOX (help->list));
	/* The topic shown is marked, not selected: the list has no
	 * selection, so keyboard focus moving along it opens nothing. */
	rows = gtk_container_get_children (GTK_CONTAINER (help->list));
	for (GList *l = rows; l != NULL; l = l->next) {
		GtkStyleContext *ctx = gtk_widget_get_style_context (l->data);

		if (l->data == (gpointer) row)
			gtk_style_context_add_class (ctx, "help-current");
		else
			gtk_style_context_remove_class (ctx, "help-current");
	}
	g_list_free (rows);
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

/* Enter or a click on a topic in the sidebar. */
static void
on_row_activated (GtkListBox *box, GtkListBoxRow *row, gpointer data)
{
	const FsHelpTopic *t = row_topic (row);

	(void) box;
	(void) data;
	if (help->syncing || t == NULL)
		return;
	go_to (t->id, TRUE);
}

/* [ on_list_focus ]
 * The topic list is one Tab stop.  Tab into it lands on the topic
 * shown (or the first one listed); Tab inside it leaves it, instead of
 * stepping through 25 rows.  The arrow keys still move along it. */
static gboolean
on_list_focus (GtkWidget *list, GtkDirectionType direction, gpointer data)
{
	GtkListBoxRow *row;

	(void) data;
	if (direction != GTK_DIR_TAB_FORWARD
	    && direction != GTK_DIR_TAB_BACKWARD)
		return FALSE;

	if (gtk_container_get_focus_child (GTK_CONTAINER (list)) != NULL) {
		g_signal_stop_emission_by_name (list, "focus");
		return FALSE;
	}

	row = row_for (help->current);
	if (row == NULL || !topic_listed (row_topic (row))) {
		row = NULL;
		for (guint i = 0; i < fs_help_topic_count () && row == NULL; i++)
			if (topic_listed (fs_help_topic_nth (i)))
				row = row_for (fs_help_topic_nth (i)->id);
	}
	if (row == NULL)
		return FALSE;
	gtk_widget_grab_focus (GTK_WIDGET (row));
	return TRUE;
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
	/* A title runs on one line where there is room and wraps where
	 * there is not: "Next: Command line and dashboard" on one line is
	 * 283 pixels in DejaVu Sans, more than a 640-pixel window leaves the
	 * page, and one topic must not widen the window. */
	{
		GtkWidget *label = gtk_bin_get_child (GTK_BIN (button));

		gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
		gtk_label_set_line_wrap_mode (GTK_LABEL (label),
		                              PANGO_WRAP_WORD_CHAR);
		gtk_label_set_xalign (GTK_LABEL (label), 0.0);
	}
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
		heading = _("Not in this build");
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

/* "Ctrl+F|Search the help": key caps on the left, the text after.
 * The caps sit at the top of the row at their own height, however many
 * lines the text takes, and wrap between keys ("Left Right Home End")
 * when the window is narrow, so one topic cannot widen the window. */
static GtkWidget *
keys_row (const gchar *spec)
{
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 16);
	GtkWidget *caps = fs_wrap_new (4);
	const gchar *bar = strchr (spec, '|');
	gchar *keys = bar != NULL ? g_strndup (spec, bar - spec) : g_strdup (spec);
	gchar **tokens = g_strsplit (keys, " ", -1);

	add_class (row, "help-keys-row");
	add_class (caps, "help-key-caps");
	gtk_widget_set_name (caps, "help-key-caps");
	gtk_widget_set_valign (caps, GTK_ALIGN_START);
	gtk_widget_set_halign (caps, GTK_ALIGN_START);
	for (gchar **t = tokens; *t != NULL; t++) {
		GtkWidget *combo;
		gchar **parts;

		if (**t == '\0')
			continue;
		/* One key combination per piece that can wrap: "Ctrl+F"
		 * never breaks inside. */
		combo = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
		gtk_widget_set_valign (combo, GTK_ALIGN_START);
		/* "Ctrl+," is two keys; a lone "+" is the key itself. */
		parts = strlen (*t) > 1 ? g_strsplit (*t, "+", -1)
		                        : g_strsplit (*t, "\x01", -1);
		for (gchar **p = parts; *p != NULL; p++) {
			GtkWidget *cap;

			if (p != parts)
				gtk_box_pack_start (GTK_BOX (combo),
				                    plain_label ("+", "help-key-plus"),
				                    FALSE, FALSE, 0);
			cap = plain_label (**p != '\0' ? *p : "+", "help-key");
			gtk_widget_set_valign (cap, GTK_ALIGN_START);
			gtk_box_pack_start (GTK_BOX (combo), cap, FALSE, FALSE, 0);
		}
		g_strfreev (parts);
		gtk_container_add (GTK_CONTAINER (caps), combo);
	}
	gtk_size_group_add_widget (help->keys_column, caps);
	gtk_box_pack_start (GTK_BOX (row), caps, FALSE, FALSE, 0);
	{
		GtkWidget *what = text_label (bar != NULL ? bar + 1 : "",
		                              "help-para");

		/* One width for every row's text, minimum and natural
		 * alike: the caps get their width first, the same on every
		 * row, so the texts line up, and the text takes (and wraps
		 * in) the rest of the line. 12 characters, not 20: with the
		 * caps beside it, 20 characters of a wide font (DejaVu Sans)
		 * left the window 2 pixels short of being 640 wide. */
		gtk_label_set_width_chars (GTK_LABEL (what), 12);
		gtk_label_set_max_width_chars (GTK_LABEL (what), 12);
		gtk_box_pack_start (GTK_BOX (row), what, TRUE, TRUE, 0);
	}
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
	GtkWidget *flow = fs_wrap_new (6);
	gchar **list = g_strsplit (ids, " ", -1);

	add_class (box, "help-related");
	gtk_box_pack_start (GTK_BOX (box), plain_label (heading, "help-h3"),
	                    FALSE, FALSE, 0);
	gtk_widget_set_name (flow, "help-chips");
	add_class (flow, "help-chips");
	for (gchar **id = list; *id != NULL; id++) {
		const FsHelpTopic *t = fs_help_topic_find (*id);
		GtkWidget *chip;

		if (t == NULL)
			continue;
		chip = topic_button (t, "see:", _(t->title), "help-chip");
		gtk_container_add (GTK_CONTAINER (flow), chip);
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
	gtk_widget_set_name (nav, "help-sidebar");
	add_class (nav, "fs-sidebar");
	add_class (nav, "side-nav");
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
	                                 GTK_SELECTION_NONE);
	gtk_list_box_set_activate_on_single_click (GTK_LIST_BOX (help->list),
	                                           TRUE);
	gtk_list_box_set_filter_func (GTK_LIST_BOX (help->list), filter_row,
	                              NULL, NULL);
	gtk_list_box_set_header_func (GTK_LIST_BOX (help->list), header_row,
	                              NULL, NULL);
	for (guint i = 0; i < fs_help_topic_count (); i++) {
		const FsHelpTopic *t = fs_help_topic_nth (i);
		GtkWidget *row = gtk_list_box_row_new ();
		GtkWidget *line = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
		GtkWidget *label = plain_label (_(t->title), "help-topic-label");
		gchar *name = g_strconcat ("topic:", t->id, NULL);

		gtk_widget_set_name (row, name);
		g_free (name);
		/* A title too long for the sidebar wraps onto a second line
		 * rather than losing its end: the tooltip is the summary, so
		 * a cut title could not be read anywhere in the list. */
		gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
		gtk_label_set_line_wrap_mode (GTK_LABEL (label),
		                              PANGO_WRAP_WORD_CHAR);
		gtk_label_set_max_width_chars (GTK_LABEL (label), 1);
		gtk_widget_set_tooltip_text (row, _(t->summary));
		add_class (row, "help-topic");
		add_class (row, "side-item");
		/* A screen reader names the row by its topic. */
		atk_object_set_name (gtk_widget_get_accessible (row), _(t->title));
		if (t->parent != NULL)
			add_class (row, "help-subtopic");
		else
			gtk_box_pack_start (GTK_BOX (line),
			                    fs_icon_new (topic_icon (t->id), 16),
			                    FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (line), label, TRUE, TRUE, 0);
		g_object_set_data (G_OBJECT (row), "topic", (gpointer) t);
		gtk_container_add (GTK_CONTAINER (row), line);
		gtk_container_add (GTK_CONTAINER (help->list), row);
	}
	g_signal_connect (help->list, "row-activated",
	                  G_CALLBACK (on_row_activated), NULL);
	g_signal_connect (help->list, "focus",
	                  G_CALLBACK (on_list_focus), NULL);

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
history_button (FsIconKind icon, const gchar *name, const gchar *label,
                const gchar *tip, GCallback cb)
{
	GtkWidget *button = gtk_button_new ();

	gtk_container_add (GTK_CONTAINER (button), fs_icon_new (icon, 16));
	gtk_widget_set_name (button, name);
	gtk_widget_set_tooltip_text (button, tip);
	/* Icon only: the name a screen reader says is set here, since a
	 * tooltip only becomes the description. */
	atk_object_set_name (gtk_widget_get_accessible (button), label);
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
	help->back = history_button (FS_ICON_BACK, "help-back", _("Back"),
	                             _("Back (Alt+Left)"),
	                             G_CALLBACK (on_back));
	help->forward = history_button (FS_ICON_FORWARD, "help-forward",
	                                _("Forward"), _("Forward (Alt+Right)"),
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
	/* The toolbar lines up with the page column under it. */
	{
		GtkWidget *clamp = fs_clamp_new (COLUMN_WIDTH);

		gtk_container_add (GTK_CONTAINER (clamp), bar);
		gtk_box_pack_start (GTK_BOX (right), clamp, FALSE, FALSE, 0);
	}

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
	/* A column of about 80 characters, centred on a wide window: lines
	 * of 150 characters are hard to read. */
	{
		GtkWidget *clamp = fs_clamp_new (COLUMN_WIDTH);

		gtk_widget_set_name (page, "help-page");
		gtk_container_add (GTK_CONTAINER (clamp), page);
		gtk_container_add (GTK_CONTAINER (help->scroll), clamp);
	}
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
	gboolean fresh = help == NULL;

	if (fresh)
		build_window (parent);

	go_to (topic != NULL ? topic : FS_HELP_TOPIC_START,
	       help->current != NULL);
	sync_history_buttons ();
	/* A new window starts on the topic in the sidebar, not in the
	 * search field: GTK hides a focused entry's placeholder, and an
	 * empty dark box does not say what it is for.  Ctrl+F gets
	 * there. */
	if (fresh) {
		GtkListBoxRow *row = row_for (help->current);

		if (row != NULL)
			gtk_widget_grab_focus (GTK_WIDGET (row));
	}
	gtk_window_present (GTK_WINDOW (help->window));
}

const gchar *
fs_help_topic_for_page (gint page)
{
	/* FsAppPage order: Overview, Events, Activity, Policy, Threat
	 * Intel, Copilot, Trust. */
	static const gchar *const ids[] = {
		"overview", "events", "activity", "policy", "threat-intel",
		"copilot", "trust"
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
