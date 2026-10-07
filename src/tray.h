/*---[ tray.h ]---------------------------------------------------------
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Tray icon for the GNOME Notification Area applet
 *--------------------------------------------------------------------*/

#ifndef _STOCKFW_TRAY
#define _STOCKFW_TRAY

#include <config.h>
#include <gnome.h>
#include "statusview.h"

void tray_init (void);
void tray_update (FirewallStatus state);
gboolean tray_is_running (void);
void tray_remove (void);

#endif
