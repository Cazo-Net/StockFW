/*---[ fs-helpwindow.h ]--------------------------------------------------
 * The Help window (1.0.7).
 *
 * One window, not modal, built the first time it is asked for and
 * raised (and moved to the asked-for topic) after that.  It lives in
 * its own GtkWindowGroup, so it takes input while the Preferences
 * window, which is modal, is open: Preferences' Help button and F1
 * open the topic for the page it shows.
 *
 * The topics are in fs-helpcontent.c.
 *--------------------------------------------------------------------*/
#ifndef FS_HELPWINDOW_H
#define FS_HELPWINDOW_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

/* Shows the Help window at `topic' (an id from fs-helpcontent.c; NULL
 * or an unknown id opens Getting started).  `parent' only places a new
 * window; the window is not transient for it, so closing the parent
 * (Preferences, say) leaves Help open. */
void         fs_help_show           (GtkWidget *parent, const gchar *topic);

/* The topic for a main-window page (an FsAppPage). */
const gchar *fs_help_topic_for_page (gint page);

/* The topic for a Preferences page id ("general", "icmp", ...). */
const gchar *fs_help_topic_for_prefs_page (const gchar *page);

/* The sidebar width Help and Preferences share, so the two windows
 * match side by side. */
#define FS_SIDE_WIDTH 240

/* A container for one child that gives it at most `max_width' pixels
 * and centres it in any width beyond that: a readable column on a wide
 * window (Help's article, Preferences' pages).  Below `max_width' the
 * child gets the whole width, and its height is asked for that width,
 * so wrapping text keeps working. */
GtkWidget   *fs_clamp_new           (gint max_width);

/* The open Help window, or NULL; and the topic it shows, or NULL. */
GtkWidget   *fs_help_window         (void);
const gchar *fs_help_current_topic  (void);

G_END_DECLS

#endif /* FS_HELPWINDOW_H */
