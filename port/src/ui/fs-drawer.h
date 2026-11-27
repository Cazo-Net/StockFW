/* The detail drawer: one panel that slides in from the right edge of
 * the main window and shows the details of the thing a page's list has
 * selected (an event, a rule, a program), with the actions that apply
 * to it.  The list stays in view and stays usable behind it.
 *
 * There is one drawer for the whole window.  A page fills it with
 * fs_drawer_open () and names itself as the owner, so it can tell
 * later whether what is showing is still its own. */
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
