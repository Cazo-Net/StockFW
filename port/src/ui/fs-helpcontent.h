/*---[ fs-helpcontent.h ]-------------------------------------------------
 * The Help window's topics (1.0.7).
 *
 * Every word the Help window shows lives in fs-helpcontent.c as a
 * string marked N_(), one string per paragraph, step or callout, so a
 * translator gets short units with their markup and xgettext finds
 * them all:
 *
 *   xgettext --keyword=_ --keyword=N_ --add-comments=TRANSLATORS \
 *            port/src/ui/fs-helpcontent.c
 *
 * The window renders them with Pango markup on GtkLabels (no web
 * view).  Text may use <b>, <i>, <tt> and links: <a href="help:ID">
 * goes to another topic, <a href="https://...">  opens the browser.
 *--------------------------------------------------------------------*/
#ifndef FS_HELPCONTENT_H
#define FS_HELPCONTENT_H

#include <glib.h>

G_BEGIN_DECLS

typedef enum
{
	FS_HELP_END = 0,   /* closes a topic's block list               */
	FS_HELP_PARA,      /* a paragraph                               */
	FS_HELP_HEAD,      /* a heading inside the topic                */
	FS_HELP_STEP,      /* a numbered step; a run of them counts 1.. */
	FS_HELP_ITEM,      /* a bullet                                  */
	FS_HELP_NOTE,      /* a callout: good to know                   */
	FS_HELP_WARN,      /* a callout: a consequence worth stopping for */
	FS_HELP_SOON,      /* a callout: "Not in this build", for a
	                    * feature this build does not have yet     */
	FS_HELP_KEYS,      /* "keys|what they do": one shortcut row     */
	FS_HELP_CODE,      /* a command, shown in a fixed-width face    */
	FS_HELP_SEE        /* related topics: ids separated by spaces   */
} FsHelpKind;

typedef struct
{
	FsHelpKind   kind;
	const gchar *text;   /* N_() markup; for SEE, topic ids (not
	                      * translated); for CODE, plain text       */
} FsHelpBlock;

typedef struct
{
	const gchar       *id;        /* "events", "prefs-icmp"          */
	const gchar       *parent;    /* the parent topic's id, or NULL  */
	const gchar       *section;   /* the sidebar group, N_(), set on
	                               * the first topic of each group   */
	const gchar       *title;     /* N_()                            */
	const gchar       *summary;   /* N_(): the line under the title  */
	const gchar       *keywords;  /* N_(): more words search finds   */
	const FsHelpBlock *blocks;    /* ends with an FS_HELP_END block  */
} FsHelpTopic;

/* The topics, in the order the sidebar lists them. */
guint              fs_help_topic_count (void);
const FsHelpTopic *fs_help_topic_nth   (guint index);

/* The topic with this id, or NULL. */
const FsHelpTopic *fs_help_topic_find  (const gchar *id);

/* Where the window opens when nothing more specific is asked for. */
#define FS_HELP_TOPIC_START "getting-started"

G_END_DECLS

#endif /* FS_HELPCONTENT_H */
