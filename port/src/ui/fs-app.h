#ifndef FS_APP_H
#define FS_APP_H

#include <gtk/gtk.h>
#include "core/fs-apply.h"
#include "core/fs-script.h"

G_BEGIN_DECLS

typedef struct _FsApp FsApp;

struct _FsApp
{
	GtkApplication *app;
	GtkWidget      *window;
	GtkWidget      *notebook;
};

/* The pages, in sidebar order. */
typedef enum
{
	FS_PAGE_OVERVIEW = 0,
	FS_PAGE_EVENTS,
	FS_PAGE_ACTIVITY,
	FS_PAGE_POLICY,
	FS_PAGE_COPILOT,
	FS_PAGE_TRUST,
	FS_PAGE_COUNT
} FsAppPage;

void fs_app_activate (GtkApplication *app);

/* Selects a page, as a click on its sidebar item would.  Does nothing
 * before the window is built. */
void fs_app_show_page (FsAppPage page);
void fs_app_quit    (void);

/* Re-reads the preferences into the shared FsSettings and hands the
 * refreshed context back to the backend.  Called after the Preferences
 * dialog is accepted, so the Firewall pages take effect. */
void fs_app_reload_settings (void);

/* Pushes the policy to the firewall under the settings just reloaded,
 * through the apply gate (fs_settings_apply_safe): `previous' are the
 * settings that were live before the save, for the rollback; `hold' is
 * the audit-only / Lock reason or NULL.  NULL when there is no loaded
 * policy to apply (the main window was never built). */
FsApplyOutcome *fs_app_apply_settings (const FsSettings *previous,
                                       const gchar *hold,
                                       GError **error);

G_END_DECLS

#endif /* FS_APP_H */