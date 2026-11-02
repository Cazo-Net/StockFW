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

/* Builds the window and everything behind it, once.  A second call
 * (GtkApplication activates again when asked to) only brings the
 * existing window forward. */
void fs_app_activate (GtkApplication *app);

/* Show, un-minimize and raise the window: what a second launch asks
 * the running instance for.  Before the window exists it cancels a
 * hidden start instead, so the window opens visible. */
void fs_app_present (void);

/* --background: build everything but keep the window hidden behind the
 * tray icon.  The window is shown anyway when no icon is embedded
 * within a few seconds (or the icon is switched off), so a hidden
 * start never leaves a copy nobody can reach.  Call before activate. */
void fs_app_set_start_hidden (gboolean hidden);

/* Selects a page, as a click on its sidebar item would.  Does nothing
 * before the window is built. */
void fs_app_show_page (FsAppPage page);

/* The page on show; FS_PAGE_COUNT before the window is built. */
FsAppPage fs_app_current_page (void);

/* Quit StockFW, leaving the firewall as it is: the icon goes, the
 * settings and the Copilot baseline are written, and the program
 * ends.  Called again while quitting, it does nothing. */
void fs_app_quit    (void);

/* The Copilot learned from an event: its baseline has changed and the
 * next periodic save writes it (1.0.7 session safety). */
void fs_app_note_learning (void);

/* TRUE when this copy may change the firewall (apply, start, stop):
 * the backend is there and, on Windows, the process is elevated --
 * the Windows backend reads state without elevation, so "available"
 * alone would enable controls that only fail after a confirmation. */
gboolean fs_app_can_change_firewall (void);

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