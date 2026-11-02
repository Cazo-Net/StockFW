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

/* Re-reads the preferences into the shared FsSettings and hands the
 * refreshed context back to the backend.  Called after the Preferences
 * dialog is accepted, so the Firewall pages take effect. */
void fs_app_reload_settings (void);

G_END_DECLS

#endif /* FS_APP_H */