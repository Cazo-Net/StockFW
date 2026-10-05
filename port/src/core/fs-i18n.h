#ifndef FS_I18N_H
#define FS_I18N_H

#include <glib.h>

/* The original sources used gettext's _() directly.  This header keeps
 * that spelling working while routing through GLib's gettext, which is
 * what glib-gettextize produced and needs no libintl headers at the call
 * site. */
#define _(String) (String)
#define N_(String) (String)

#endif /* FS_I18N_H */