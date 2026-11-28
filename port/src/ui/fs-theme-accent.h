/* The accent colours and the comfortable row density: two small
 * sheets that go over fs-theme.css when Preferences > General >
 * Appearance asks for them (fs-app.c, apply_appearance).
 *
 * The accent is two of the theme's named colours: fs_accent, the
 * colour of links and of the "in use" chip's text, and fs_accent_fill,
 * the face of a switch that is on, of a ticked box, of the focus ring
 * and (thinned) of selected text.  An accent sheet gives those two
 * names other values and nothing else, so it is installed one priority
 * step above the light palette (fs-theme-light.h), which defines them
 * too.  Blue is what fs-theme.css and the light palette already say:
 * choosing it installs nothing, and its row here is only for the tests
 * to hold the three accents to the same rules.
 *
 * What the values were chosen for (tests/ui-theme-smoke.c measures
 * every pair): as text, fs_accent is at least 4.5:1 on fs_bg,
 * fs_bg_side, fs_surface and fs_surface_2 of its mode; fs_accent_fill
 * is at least 3:1 against fs_surface and against a switch's slider in
 * both modes, and white (fs_on_accent) on it is at least 3:1.  The
 * green and the amber are kept apart from fs_ok and fs_warn, which
 * still mean a verdict; fs_info stays blue, it is a status tone.
 *
 * The comfortable density gives the rows of the sidebars, the lists
 * and the menus about 3px more room above and below.  Compact is what
 * fs-theme.css says and installs nothing.  The rules name single
 * components and set padding-top and padding-bottom only: this sheet
 * outranks every rule of fs-theme.css whatever its selector, so a bare
 * `button' rule here would flatten every button in the application.
 * button.nav-item gets one rule for all of its states, so a sidebar
 * item is as tall selected as not (ui-theme-smoke measures that too).
 * Rows of a tree view are not reached by CSS at all: their height is
 * the cell renderers' ypad, which fs-app.c raises by
 * FS_THEME_COMFORTABLE_YPAD. */
#ifndef FS_THEME_ACCENT_H
#define FS_THEME_ACCENT_H

#include <glib.h>

typedef struct
{
	const gchar *id;      /* the word the setting stores           */
	const gchar *dark;    /* its sheet over fs-theme.css           */
	const gchar *light;   /* its sheet over the light palette      */
} FsThemeAccent;

static const FsThemeAccent fs_theme_accents[] = {
	{ "blue",
	  "@define-color fs_accent        #5aa2ff;\n"
	  "@define-color fs_accent_fill   #007aff;\n",
	  "@define-color fs_accent        #0059c2;\n"
	  "@define-color fs_accent_fill   #007aff;\n" },
	{ "green",
	  "@define-color fs_accent        #4cc38a;\n"
	  "@define-color fs_accent_fill   #12855a;\n",
	  "@define-color fs_accent        #0b6b47;\n"
	  "@define-color fs_accent_fill   #12855a;\n" },
	{ "amber",
	  "@define-color fs_accent        #f2c14e;\n"
	  "@define-color fs_accent_fill   #a87400;\n",
	  "@define-color fs_accent        #775600;\n"
	  "@define-color fs_accent_fill   #a87400;\n" },
};

/* What a comfortable row gets above and below, in a tree view. */
#define FS_THEME_COMFORTABLE_YPAD 3

static const gchar fs_theme_comfortable_css[] =
	/* Sidebar items: the main window's, and through .side-item the
	 * ones of Preferences and Help.  Every state, one rule. */
	"button.nav-item {\n"
	"	padding-top: 7px;\n"
	"	padding-bottom: 7px;\n"
	"}\n"
	"list.help-topics row {\n"
	"	padding-top: 8px;\n"
	"	padding-bottom: 8px;\n"
	"}\n"
	/* Column headings of the lists. */
	".data-grid header button,\n"
	"treeview header button,\n"
	".overview-grid header button {\n"
	"	padding-top: 9px;\n"
	"	padding-bottom: 9px;\n"
	"	transition: none;\n"
	"}\n"
	/* The command palette's rows. */
	"list.fs-palette-list row {\n"
	"	padding-top: 9px;\n"
	"	padding-bottom: 9px;\n"
	"}\n"
	/* A setting in Preferences. */
	".pref-row {\n"
	"	padding-top: 13px;\n"
	"	padding-bottom: 13px;\n"
	"}\n"
	"menu menuitem,\n"
	".menu menuitem {\n"
	"	padding-top: 8px;\n"
	"	padding-bottom: 8px;\n"
	"}\n"
	/* The Overview's rows. */
	"button.recent-row {\n"
	"	padding-top: 9px;\n"
	"	padding-bottom: 9px;\n"
	"}\n"
	".profile-row {\n"
	"	padding-top: 9px;\n"
	"	padding-bottom: 9px;\n"
	"}\n"
	".card-frame .profile-row {\n"
	"	padding-top: 11px;\n"
	"	padding-bottom: 11px;\n"
	"}\n";

#endif /* FS_THEME_ACCENT_H */
