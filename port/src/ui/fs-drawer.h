/* The detail drawer: one panel that slides in from the right edge of
 * the main window and shows the details of the thing a page's list has
 * selected (an event, a rule, a program), with the actions that apply
 * to it.  The list stays in view and stays usable behind it.
 *
 * There is one drawer for the whole window.  A page fills it with
 * fs_drawer_open () and names itself as the owner, so it can tell
 * later whether what is showing is still its own.
 *
 * The window closes it on Escape, when the page is switched, and when
 * the keyboard goes to a control of the page that is wholly under it.
 * The keyboard stays where it was when the drawer opens (in the list);
 * Tab reaches the drawer's buttons after the page's own controls, and a
 * close gives the keyboard back to the list if it was left on one of
 * them (to the control nearest the list, if the list cannot take it
 * any more: the window is never left without a focus widget).  The
 * body is a stop for Tab only while it is longer than the panel; Page
 * Up and Page Down scroll it then.  The panel is 380 pixels wide
 * whatever is put in it: labels in a body should wrap
 * (fs_drawer_field's do). */
#ifndef FS_DRAWER_H
#define FS_DRAWER_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

typedef void (*FsDrawerRun) (gpointer data);

typedef struct
{
	const gchar *label;   /* translated */
	const gchar *klass;   /* "btn-primary", "btn-subtle" or "btn-danger" */
	FsDrawerRun  run;
	gpointer     data;    /* must outlive the drawer's content */
} FsDrawerAction;

/* The drawer's widget (a GtkRevealer), made on first use.  The main
 * window adds it to an overlay over the pages.  Pages never call this. */
GtkWidget *fs_drawer_widget (void);

/* Show `body' in the drawer under `title' (and `subtitle', which may be
 * NULL), with one button per action.  Takes the floating reference of
 * `body'.  Opening while open swaps the content in place.  `owner' is
 * any pointer that identifies the caller. */
void       fs_drawer_open (gpointer              owner,
                           const gchar          *title,
                           const gchar          *subtitle,
                           GtkWidget            *body,
                           const FsDrawerAction *actions,
                           guint                 n_actions);

void       fs_drawer_close (void);
gboolean   fs_drawer_is_open (void);

/* The owner given to the fs_drawer_open () that filled the open drawer,
 * or NULL when it is closed. */
gpointer   fs_drawer_owner (void);

/* Helpers for the body: a grid of "name   value" rows.  A NULL or empty
 * value adds no row.  `mono' sets the value in the fixed-width face. */
GtkWidget *fs_drawer_fields_new (void);
void       fs_drawer_field (GtkWidget   *fields,
                            const gchar *name,
                            const gchar *value,
                            gboolean     mono);

/* A small heading to put between groups of fields in a body. */
GtkWidget *fs_drawer_section (const gchar *heading);

G_END_DECLS

#endif /* FS_DRAWER_H */
