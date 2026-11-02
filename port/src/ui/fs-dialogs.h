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

/* The Preferences window (fs-prefsdialog.c): modal, transient for
 * parent.  It offers only settings this platform acts on, saves only
 * what the user changed, and offers to apply changed firewall settings
 * to a running firewall through the apply gate. */
void fs_dialogs_preferences (GtkWidget *parent);

/* Start at sign-in was changed elsewhere (the tray menu): an open
 * Preferences window shows the new state, unless the user has already
 * moved its switch, which then stays as they left it. */
void fs_dialogs_preferences_autostart_changed (void);

/* Close an open Preferences window as its Cancel button would: nothing
 * is saved.  The quit path (tray Quit, --quit, SIGTERM) uses it, because
 * the window runs its own loop and the quit waits for that loop to end. */
void fs_dialogs_preferences_cancel (void);

#ifdef FS_PREFS_FAKE_BACKEND
/* tests/ui-prefs-smoke.c only -- compiled into the fake-backend smoke,
 * never into StockFW: answers "may this copy change start at sign-in?"
 * in place of the system (an unelevated Windows copy, say).  NULL: ask
 * the system. */
extern gboolean (*fs_prefs_test_signin_can_change) (gchar **why);
#endif

G_END_DECLS

#endif /* FS_DIALOGS_H */