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

/* The policy the Policy page edits, or NULL before the main window
 * (and with it the policy) is loaded.  Borrowed. */
FsPolicy *fs_app_policy (void);

/* Pushes `under' to the firewall with the settings just reloaded,
 * through the apply gate (fs_settings_apply_safe).  `under' is the
 * policy to apply them with: Preferences passes the last applied one
 * (the journal's), so Policy-page edits that were never applied do not
 * go out as a side effect, or the loaded policy only when nothing is
 * recorded and the user agreed to apply it.  `previous' are the
 * settings to roll back to; `hold' is the audit-only / Lock reason or
 * NULL.  NULL when under is NULL or no settings are loaded. */
FsApplyOutcome *fs_app_apply_settings (FsPolicy *under,
                                       const FsSettings *previous,
                                       const gchar *hold,
                                       GError **error);

#ifdef FS_PREFS_FAKE_BACKEND
/* tests/ui-prefs-smoke.c only -- compiled into the fake-backend smoke,
 * never into StockFW: the loaded policy and settings, without building
 * the main window. */
void fs_app_test_set_context (FsPolicy *test_policy,
                              FsSettings *test_settings);
#endif

G_END_DECLS

#endif /* FS_APP_H */