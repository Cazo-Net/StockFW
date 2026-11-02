/*---[ fs-icons.h ]-----------------------------------------------------
 * Line icons drawn with cairo (1.0.7 redesign).
 *
 * The sidebar and the Overview page draw their own icons instead of
 * asking the icon theme: a theme icon that is missing renders as a
 * broken-image square, and which icons a Windows runtime or a minimal
 * Linux desktop ships is not something the window can count on.  These
 * are drawn on a 24-unit grid, 2-unit strokes, round caps, in the
 * widget's CSS `color', so a nav item's icon follows its hover and
 * selected colours with no extra code.
 *--------------------------------------------------------------------*/
#ifndef FS_ICONS_H
#define FS_ICONS_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

typedef enum
{
	FS_ICON_SHIELD,
	FS_ICON_SHIELD_CHECK,
	FS_ICON_SHIELD_X,
	FS_ICON_SHIELD_ALERT,
	FS_ICON_SHIELD_QUESTION,
	FS_ICON_LIST,
	FS_ICON_ACTIVITY,
	FS_ICON_SLIDERS,
	FS_ICON_CHAT,
	FS_ICON_CHECK_CIRCLE,
	FS_ICON_SETTINGS,
	FS_ICON_INFO,
	FS_ICON_LOCK,
	FS_ICON_UNLOCK,
	FS_ICON_PLAY,
	FS_ICON_STOP,
	FS_ICON_ADAPTER,
	FS_ICON_WIFI,
	FS_ICON_SEARCH,
	FS_ICON_DOT,          /* a filled circle: status dots */
	FS_ICON_HELP,         /* a question mark in a circle */
	FS_ICON_BACK,         /* an arrow pointing left */
	FS_ICON_FORWARD,      /* an arrow pointing right */
	FS_ICON_COPY,         /* two overlapping sheets */
	FS_ICON_N_KINDS
} FsIconKind;

/* A size x size drawing area showing `kind' in its CSS colour. */
GtkWidget *fs_icon_new       (FsIconKind kind, gint size);

/* Changes the icon an fs_icon_new() widget shows. */
void       fs_icon_set_kind  (GtkWidget *icon, FsIconKind kind);
FsIconKind fs_icon_get_kind  (GtkWidget *icon);

/* Draws `kind' into a size x size box at the current point's origin,
 * with the cairo source already set.  For tests and for widgets that
 * draw an icon as part of something larger. */
void       fs_icon_draw      (cairo_t *cr, FsIconKind kind, gdouble size);

G_END_DECLS

#endif /* FS_ICONS_H */
