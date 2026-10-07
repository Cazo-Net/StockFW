#ifndef FS_DIALOGS_H
#define FS_DIALOGS_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

void fs_dialogs_about   (GtkWidget *parent);

/* About credits, escaped for GtkAboutDialog's markup rendering (it
 * parses authors as markup WITHOUT escaping them; see fs-dialogs.c).
 * ui-prefs-smoke asserts pango_parse_markup() accepts every string. */
const gchar **fs_dialogs_about_authors (void);
void fs_dialogs_error   (GtkWidget *parent,
                         const gchar *header,
                         const gchar *message);
void fs_dialogs_info    (GtkWidget *parent,
                         const gchar *header,
                         const gchar *message);
void fs_dialogs_confirm (GtkWidget *parent,
                         const gchar *question,
                         gboolean *confirmed);

/* Preferences.  Every setting it exposes takes effect; see fs-dialogs.c. */
void fs_dialogs_preferences (GtkWidget *parent);

G_END_DECLS

#endif /* FS_DIALOGS_H */