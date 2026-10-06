#ifndef FS_APP_H
#define FS_APP_H

#include <gtk/gtk.h>

G_BEGIN_DECLS

typedef struct _FsApp FsApp;

struct _FsApp
{
	GtkApplication *app;
	GtkWidget      *window;
	GtkWidget      *notebook;
};

void fs_app_activate (GtkApplication *app);
void fs_app_quit    (void);

/* Re-reads the preferences into the shared FsSettings and hands the
 * refreshed context back to the backend.  Called after the Preferences
 * dialog is accepted, so the Firewall pages take effect. */
void fs_app_reload_settings (void);

G_END_DECLS

#endif /* FS_APP_H */