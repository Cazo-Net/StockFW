/*---[ globals.h ]----------------------------------------------------
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Global structs and variables
 *--------------------------------------------------------------------*/
#ifndef _STOCKFW_GLOBLAS
#define _STOCKFW_GLOBALS

#include <config.h>
#include <gnome.h>


typedef struct
{
	GtkWidget     *window;   /* Main window for StockFW */
	GtkWidget     *ruleview; /* TreeView for rules */
	GtkTooltips   *ttips;    /* Tool tips widget */
} StockFWApp;

extern StockFWApp StockFW;

gboolean NETFILTER;
gboolean CONSOLE;

#endif
