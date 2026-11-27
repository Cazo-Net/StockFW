/* The light palette: the named colours of fs-theme.css with their
 * light values.  fs-theme.css defines the dark values and every rule;
 * this sheet only renames colours, so it is installed one priority
 * step above the main stylesheet when Dark mode is off and removed
 * again when it is on (fs-app.c, apply_dark_mode).
 *
 * Keep the two lists in step: a name added to fs-theme.css needs a
 * light value here, or the light window shows a dark patch.
 * tests/ui-theme-smoke.c checks that this sheet parses and that it
 * actually changes what a button and the canvas paint. */
#ifndef FS_THEME_LIGHT_H
#define FS_THEME_LIGHT_H

static const gchar fs_theme_light_css[] =
	"@define-color fs_bg_side       #f1eeee;\n"
	"@define-color fs_bg            #f8f7f7;\n"
	"@define-color fs_surface       #fdfcfc;\n"
	"@define-color fs_surface_2     #e9e5e5;\n"
	"@define-color fs_surface_3     #dcd7d7;\n"
	"@define-color fs_border        #dedada;\n"
	"@define-color fs_border_strong #c8c3c3;\n"
	"@define-color fs_text_strong   #201d1d;\n"
	"@define-color fs_text          #3a3636;\n"
	"@define-color fs_text_weak     #575353;\n"
	"@define-color fs_text_weaker   #6c6767;\n"
	"@define-color fs_accent        #0059c2;\n"
	"@define-color fs_accent_fill   #007aff;\n"
	"@define-color fs_on_accent     #ffffff;\n"
	"@define-color fs_primary       #201d1d;\n"
	"@define-color fs_primary_hover #3a3636;\n"
	"@define-color fs_on_primary    #fdfcfc;\n"
	"@define-color fs_ok            #147033;\n"
	"@define-color fs_warn          #8a5200;\n"
	"@define-color fs_bad           #c00f2b;\n"
	"@define-color fs_info          #0059c2;\n"
	"@define-color fs_code_bg       #f1eeee;\n"
	"@define-color fs_scrim         rgba(32,29,29,0.35);\n";

#endif /* FS_THEME_LIGHT_H */
