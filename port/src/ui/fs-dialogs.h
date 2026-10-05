#ifndef FS_DIALOGS_H
#define FS_DIALOGS_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

void fs_dialogs_about   (GtkWidget *parent);
void fs_dialogs_error   (GtkWidget *parent,
                         const gchar *header,
                         const gchar *message);
void fs_dialogs_info    (GtkWidget *parent,
                         const gchar *header,
                         const gchar *message);
void fs_dialogs_confirm (GtkWidget *parent,
                         const gchar *question,
                         gboolean *confirmed);

G_END_DECLS

#endif /* FS_DIALOGS_H */