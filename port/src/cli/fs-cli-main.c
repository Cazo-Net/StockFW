/*---[ fs-cli-main.c ]---------------------------------------------------
 * `stockfw': the command registry, the argument parser and help.
 *
 * Each command file exports a table of its commands (FsCliCommandDef,
 * fs-cli.h) with their help and the options they take; this file joins
 * the tables.  The parser reads the global flags wherever they are,
 * except where a word is the value of a command's option or comes
 * after "--", which is dropped: the command sees everything after it
 * as plain words (fs_cli_is_positional).
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-prefs.h"

#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

FsCliOptions fs_cli = { FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
                        0, NULL, G_MAXINT, NULL, 0, NULL };

/* ----------------------------------------------------------------- help */

static const gchar *main_help =
"Usage: stockfw [--json] [--plain] [--color=WHEN] [-q] <command> [args]\n"
"\n"
"StockFW from the command line: the same policy, simulator and apply\n"
"gate as the desktop app, without a display.\n"
"\n"
"Commands:\n"
"  status                     Firewall state, policy and monitoring\n"
"  policy list|show|add|...   Read, edit and diff the traffic policy\n"
"  check                      Lines of the policy files that are not rules\n"
"  apply [--dry-run]          Push the saved policy to the firewall (root)\n"
"  start | stop               Start or stop the firewall (root)\n"
"  simulate \"<traffic>\"       What-if: would this traffic be allowed?\n"
"  copilot health             Check the policy for overlaps and risks\n"
"  events [-n N] [-f]         Recent firewall events; --history for saved\n"
"  connections                Active TCP connections and their programs\n"
"  listening                  Open ports, their programs and who can reach them\n"
"  interfaces [--watch]       Network adapters with traffic and rates\n"
"  audit [-n N] [-f]          The audit log: every apply, start and stop\n"
"  sentinel [list]            Sentinel's staged blocks (read-only)\n"
"  intel <action>             Threat-intel blocklists (stockfw help intel)\n"
"  config list|get|set|apply  The Preferences settings; set them (root)\n"
"  dashboard [--port N]       Serve the local web dashboard and open it\n"
"  dashboard link             A new link to the running dashboard\n"
"  help [command]             Help for one command\n"
"  version                    Print the version\n"
"\n"
"Global options:\n"
"  --json          Machine-readable output (one JSON document; NDJSON\n"
"                  for -f)\n"
"  --plain, -H     Tables as tab-separated rows, no header, no colour\n"
"  --full, -l      Never cut a table cell to fit the terminal\n"
"  --color=WHEN    auto (the default), always or never; --no-color is\n"
"                  never (NO_COLOR and TERM=dumb are honoured too)\n"
"  -q, --quiet     Only errors and the result: no hints or notes\n"
"  -h, --help      This help;  -V, --version  the version\n"
"  --              The end of the options: what follows is plain words\n"
"\n"
"Exit status:\n"
"  0  success          2  usage error           5  simulate: BLOCKED;\n"
"  1  failure          3  needs root privileges    intel lookup: blocked\n"
"                                               6  simulate: DEPENDS\n"
"                                               7  copilot health: findings\n"
"\n"
"Policy files live in ~/.stockfw (or /etc/stockfw when run as root) --\n"
"the same files the desktop app edits.  Nothing here talks to the\n"
"network, except `stockfw intel update' downloading the blocklists and\n"
"the location database you turned on; the dashboard listens on\n"
"127.0.0.1 only.\n";

static const gchar *help_help =
"Usage: stockfw help [COMMAND]\n"
"\n"
"Prints the help for one command, or the list of commands.  A\n"
"subcommand shows its command's help: `stockfw help intel geo'.  The\n"
"same text is printed by `stockfw COMMAND --help'.\n";

static const gchar *version_help =
"Usage: stockfw version   (or stockfw --version, -V)\n"
"\n"
"Prints the version and the firewall backend this build drives.  With\n"
"--json: {\"version\":\"...\",\"backend\":\"...\"}.\n";

/* ------------------------------------------------------- the registry */

static const FsCliCommandDef * const tables[] = {
	fs_cli_status_commands,
	fs_cli_policy_commands,
	fs_cli_events_commands,
	fs_cli_views_commands,
	fs_cli_intel_commands,
	fs_cli_dashboard_commands,
	fs_cli_config_commands,
	fs_cli_activity_commands,
};

const FsCliCommandDef * const *
fs_cli_all_commands (guint *n)
{
	static GPtrArray *all = NULL;

	if (all == NULL) {
		all = g_ptr_array_new ();
		for (guint t = 0; t < G_N_ELEMENTS (tables); t++)
			for (const FsCliCommandDef *d = tables[t]; d->name != NULL;
			     d++)
				g_ptr_array_add (all, (gpointer) d);
	}
	if (n != NULL)
		*n = all->len;
	return (const FsCliCommandDef * const *) all->pdata;
}

const FsCliCommandDef *
fs_cli_find_command (const gchar *name)
{
	guint n;
	const FsCliCommandDef * const *all = fs_cli_all_commands (&n);

	if (name == NULL)
		return NULL;
	for (guint i = 0; i < n; i++)
		if (strcmp (all[i]->name, name) == 0 ||
		    g_strcmp0 (all[i]->alias, name) == 0)
			return all[i];
	return NULL;
}

/* [ command_names ] -- every name and alias, then "help", "version". */
static GPtrArray *
command_names (void)
{
	guint n;
	const FsCliCommandDef * const *all = fs_cli_all_commands (&n);
	GPtrArray *names = g_ptr_array_new ();

	for (guint i = 0; i < n; i++) {
		g_ptr_array_add (names, (gpointer) all[i]->name);
		if (all[i]->alias != NULL)
			g_ptr_array_add (names, (gpointer) all[i]->alias);
	}
	g_ptr_array_add (names, (gpointer) "help");
	g_ptr_array_add (names, (gpointer) "version");
	return names;
}

const gchar *
fs_cli_command_help (const gchar *command)
{
	const FsCliCommandDef *def;

	if (command == NULL)
		return main_help;
	if (strcmp (command, "help") == 0)
		return help_help;
	if (strcmp (command, "version") == 0)
		return version_help;

	def = fs_cli_find_command (command);
	return def != NULL ? def->help : NULL;
}

/* ------------------------------------------------------- did you mean */

/* [ edit_distance ] -- Damerau-Levenshtein (optimal string alignment)
 * over bytes: a swapped pair of letters counts once. */
static guint
edit_distance (const gchar *a, const gchar *b)
{
	gsize la = strlen (a), lb = strlen (b);
	guint *d;
	guint result;

	if (la > 64 || lb > 64)
		return G_MAXUINT;

	d = g_new0 (guint, (la + 1) * (lb + 1));
#define D(i, j) d[(i) * (lb + 1) + (j)]
	for (gsize i = 0; i <= la; i++)
		D (i, 0) = (guint) i;
	for (gsize j = 0; j <= lb; j++)
		D (0, j) = (guint) j;
	for (gsize i = 1; i <= la; i++) {
		for (gsize j = 1; j <= lb; j++) {
			guint cost = a[i - 1] == b[j - 1] ? 0 : 1;
			guint v = MIN (D (i - 1, j) + 1, D (i, j - 1) + 1);

			v = MIN (v, D (i - 1, j - 1) + cost);
			if (i > 1 && j > 1 && a[i - 1] == b[j - 2] &&
			    a[i - 2] == b[j - 1])
				v = MIN (v, D (i - 2, j - 2) + 1);
			D (i, j) = v;
		}
	}
	result = D (la, lb);
#undef D
	g_free (d);
	return result;
}

const gchar *
fs_cli_suggest (const gchar *word, const gchar * const *candidates, guint n)
{
	const gchar *best = NULL;
	guint best_d = 3;
	gboolean tie = FALSE;

	if (word == NULL || *word == '\0')
		return NULL;

	for (guint i = 0; i < n; i++) {
		guint dist;

		if (candidates[i] == NULL || strcmp (candidates[i], word) == 0)
			continue;
		dist = edit_distance (word, candidates[i]);
		if (dist < best_d) {
			best = candidates[i];
			best_d = dist;
			tie = FALSE;
		} else if (dist == best_d && best != NULL &&
		           strcmp (best, candidates[i]) != 0) {
			tie = TRUE;
		}
	}
	return tie ? NULL : best;
}

/* ------------------------------------------------------- global flags */

static const gchar *global_flags[] = {
	"--json", "--plain", "-H", "--full", "-l", "--color", "--colour",
	"--no-color", "--no-colour", "-q", "--quiet", "-h", "--help",
	"-V", "--version",
};

const gchar * const *
fs_cli_global_flags (guint *n)
{
	if (n != NULL)
		*n = G_N_ELEMENTS (global_flags);
	return global_flags;
}

typedef enum { COLOR_AUTO, COLOR_ALWAYS, COLOR_NEVER } ColorMode;

typedef struct
{
	ColorMode color;
	gboolean  bad_color;      /* --color=WHEN with an unknown WHEN */
	gboolean  want_help;
	gboolean  want_version;
} Globals;

/* [ take_global ] -- TRUE when `a' is a global flag (it is applied). */
static gboolean
take_global (const gchar *a, Globals *g)
{
	if (strcmp (a, "--json") == 0) {
		fs_cli.json = TRUE;
	} else if (strcmp (a, "--plain") == 0 || strcmp (a, "-H") == 0) {
		fs_cli.plain = TRUE;
	} else if (strcmp (a, "--full") == 0 || strcmp (a, "-l") == 0) {
		fs_cli.full = TRUE;
	} else if (strcmp (a, "--no-color") == 0 ||
	           strcmp (a, "--no-colour") == 0) {
		g->color = COLOR_NEVER;
	} else if (strcmp (a, "--color") == 0 || strcmp (a, "--colour") == 0) {
		g->color = COLOR_ALWAYS;
	} else if (g_str_has_prefix (a, "--color=") ||
	           g_str_has_prefix (a, "--colour=")) {
		const gchar *when = strchr (a, '=') + 1;

		if (strcmp (when, "auto") == 0)
			g->color = COLOR_AUTO;
		else if (strcmp (when, "always") == 0)
			g->color = COLOR_ALWAYS;
		else if (strcmp (when, "never") == 0)
			g->color = COLOR_NEVER;
		else
			g->bad_color = TRUE;
	} else if (strcmp (a, "-q") == 0 || strcmp (a, "--quiet") == 0) {
		fs_cli.quiet = TRUE;
	} else if (strcmp (a, "-h") == 0 || strcmp (a, "--help") == 0) {
		g->want_help = TRUE;
	} else if (strcmp (a, "-V") == 0 || strcmp (a, "--version") == 0) {
		g->want_version = TRUE;
	} else {
		return FALSE;
	}
	return TRUE;
}

/* [ set_colour ]
 * Colour on stdout depends on stdout alone, and on stderr on stderr
 * alone: `stockfw events 2>/dev/null' on a terminal keeps its colour.
 * NO_COLOR and TERM=dumb turn the automatic choice off; --color=always
 * wins over both.  JSON and --plain are never coloured. */
static void
set_colour (ColorMode mode)
{
	const gchar *term = g_getenv ("TERM");
	gboolean auto_ok = g_getenv ("NO_COLOR") == NULL &&
	                   (term == NULL || strcmp (term, "dumb") != 0);

	fs_cli.color = !fs_cli.json && !fs_cli.plain &&
	               (mode == COLOR_ALWAYS ||
	                (mode == COLOR_AUTO && auto_ok &&
	                 isatty (STDOUT_FILENO)));
	fs_cli.color_err = mode == COLOR_ALWAYS ||
	                   (mode == COLOR_AUTO && auto_ok &&
	                    isatty (STDERR_FILENO));
}

/* [ option_takes_value ]
 * Does `a' name one of def's options that takes its value as the next
 * word ("--comment TEXT")?  "--comment=TEXT" carries its own.  The
 * subcommand is not asked: within one command an option name always
 * takes a value or never does (`policy --kind X' has none yet). */
static gboolean
option_takes_value (const FsCliCommandDef *def, const gchar *a)
{
	if (def == NULL || def->opts == NULL || strchr (a, '=') != NULL)
		return FALSE;

	for (const FsCliOption *o = def->opts; o->name != NULL; o++)
		if (o->takes_value && strcmp (o->name, a) == 0)
			return TRUE;
	return FALSE;
}

/* ------------------------------------------------------- for commands */

gboolean
fs_cli_is_positional_at (gchar **argv, gint i)
{
	if (fs_cli.argv == NULL || argv == NULL ||
	    argv < fs_cli.argv || argv > fs_cli.argv + fs_cli.argc)
		return FALSE;
	return (argv - fs_cli.argv) + i >= fs_cli.positional_from;
}

gboolean
fs_cli_is_positional (gint i)
{
	return fs_cli_is_positional_at (fs_cli.argv, i);
}

gboolean
fs_cli_is_option_at (gchar **argv, gint i)
{
	return argv[i] != NULL && argv[i][0] == '-' && argv[i][1] != '\0' &&
	       !fs_cli_is_positional_at (argv, i);
}

gboolean
fs_cli_take_opt (gint argc, gchar **argv, gint *i, const gchar *opt,
                 const gchar **value, gint *status)
{
	const gchar *a = argv[*i];
	gsize n = strlen (opt);

	if (fs_cli_is_positional_at (argv, *i))
		return FALSE;

	if (strcmp (a, opt) == 0) {
		if (*i + 1 >= argc) {
			*value = NULL;
			fs_cli_error ("%s needs a value", opt);
			fs_cli_hint ("see `stockfw help %s'",
			             fs_cli.command != NULL ? fs_cli.command : "");
			*status = FS_EXIT_USAGE;
			return TRUE;
		}
		*value = argv[++*i];
		return TRUE;
	}
	if (strncmp (a, opt, n) == 0 && a[n] == '=') {
		*value = a + n + 1;
		return TRUE;
	}
	return FALSE;
}

void
fs_cli_unknown_option (const gchar *command, const gchar *arg)
{
	gchar *word = g_strdup (arg != NULL ? arg : "");
	gchar *first = g_strdup (command != NULL ? command : "");
	gchar *space = strchr (first, ' ');
	gchar *eq = strchr (word, '=');
	const FsCliCommandDef *def;
	GPtrArray *names = g_ptr_array_new ();
	const gchar *best;

	if (space != NULL)
		*space = '\0';
	if (eq != NULL)
		*eq = '\0';

	def = fs_cli_find_command (first);
	for (const FsCliOption *o = def != NULL ? def->opts : NULL;
	     o != NULL && o->name != NULL; o++)
		g_ptr_array_add (names, (gpointer) o->name);
	for (guint i = 0; i < G_N_ELEMENTS (global_flags); i++)
		g_ptr_array_add (names, (gpointer) global_flags[i]);

	best = fs_cli_suggest (word, (const gchar * const *) names->pdata,
	                       names->len);
	if (best != NULL)
		fs_cli_error ("unknown option for %s: %s (did you mean %s?)",
		              command, arg, best);
	else
		fs_cli_error ("unknown option for %s: %s", command, arg);
	fs_cli_hint ("see `stockfw help %s'; a word that starts with a dash "
	             "goes after --", first);

	g_ptr_array_unref (names);
	g_free (first);
	g_free (word);
}

/* ------------------------------------------------------------- main */

/* [ unknown_word ] -- an unknown command or help topic, with the
 * closest name. */
static gint
unknown_word (const gchar *what, const gchar *word)
{
	GPtrArray *names = command_names ();
	const gchar *best = fs_cli_suggest (word,
		(const gchar * const *) names->pdata, names->len);

	if (best != NULL)
		fs_cli_error ("%s: %s (did you mean `stockfw %s'?)", what, word,
		              best);
	else
		fs_cli_error ("%s: %s", what, word);
	fs_cli_hint ("run `stockfw help' for the list of commands");
	g_ptr_array_unref (names);
	return FS_EXIT_USAGE;
}

int
main (int argc, char *argv[])
{
	Globals g = { COLOR_AUTO, FALSE, FALSE, FALSE };
	GPtrArray *rest;
	const gchar *command = NULL, *unknown = NULL;
	const FsCliCommandDef *def;
	gboolean positional = FALSE, value_next = FALSE;
	gint cmd_at = argc, positional_from = G_MAXINT;
	gint status;

	setlocale (LC_ALL, "");

	/* Completion and the manual page (fs-cli-complete.c): hidden, made
	 * from the same tables, and never parsed as a command line. */
	if (argc > 1 && strcmp (argv[1], "__complete") == 0)
		return fs_cli_complete_main (argc - 2, argv + 2);
	if (argc > 1 && strcmp (argv[1], "__man") == 0)
		return fs_cli_man_main (argc - 2, argv + 2);

	fs_cli.user_argc = argc - 1;
	fs_cli.user_argv = argv + 1;

	/* 1. The command: the first word that is not a global flag.  A
	 * dash word before it is an unknown option, not a command. */
	for (gint i = 1; i < argc; i++) {
		const gchar *a = argv[i];

		if (strcmp (a, "--") == 0) {
			if (i + 1 < argc) {
				cmd_at = i + 1;
				positional = TRUE;
				positional_from = 1;
			}
			break;
		}
		if (take_global (a, &g))
			continue;
		if (a[0] == '-' && a[1] != '\0') {
			if (unknown == NULL)
				unknown = a;
			continue;
		}
		cmd_at = i;
		break;
	}
	command = cmd_at < argc ? argv[cmd_at] : NULL;
	def = fs_cli_find_command (command);

	/* 2. The command's words.  The word after one of its options that
	 * takes a value is that value, never a global flag; "--" is
	 * dropped and everything after it is a plain word. */
	rest = g_ptr_array_new ();
	if (command != NULL)
		g_ptr_array_add (rest, (gpointer) command);
	for (gint i = cmd_at + 1; i < argc; i++) {
		const gchar *a = argv[i];

		if (positional || value_next) {
			value_next = FALSE;
			g_ptr_array_add (rest, (gpointer) a);
			continue;
		}
		if (strcmp (a, "--") == 0) {
			positional = TRUE;
			positional_from = (gint) rest->len;
			continue;
		}
		if (take_global (a, &g))
			continue;
		if (a[0] == '-' && option_takes_value (def, a))
			value_next = TRUE;
		g_ptr_array_add (rest, (gpointer) a);
	}

	set_colour (g.color);
	fs_cli.argc = (gint) rest->len;
	fs_cli.positional_from = positional_from;
	fs_cli.command = command;

	if (g.bad_color) {
		fs_cli_error ("--color takes auto, always or never");
		g_ptr_array_unref (rest);
		return FS_EXIT_USAGE;
	}

	if (unknown != NULL) {
		const gchar *best = fs_cli_suggest (unknown, global_flags,
		                                    G_N_ELEMENTS (global_flags));

		if (best != NULL)
			fs_cli_error ("unknown option %s (did you mean %s?)",
			              unknown, best);
		else
			fs_cli_error ("unknown option %s", unknown);
		fs_cli_hint ("a command's own options go after it; see "
		             "`stockfw help%s%s'", command != NULL ? " " : "",
		             def != NULL ? def->name : "");
		g_ptr_array_unref (rest);
		return FS_EXIT_USAGE;
	}

	if (g.want_version || g_strcmp0 (command, "version") == 0) {
		if (fs_cli.json) {
			printf ("{\"version\":\"%s\",\"backend\":\"%s\"}\n",
			        FS_VERSION, fs_backend ()->name);
		} else {
			printf ("stockfw %s %s %s\n", FS_VERSION,
			        fs_cli_sym (FS_CLI_SYM_SEP),
			        fs_backend ()->display_name);
		}
		g_ptr_array_unref (rest);
		return FS_EXIT_OK;
	}

	if (g_strcmp0 (command, "help") == 0) {
		const gchar *topic = rest->len > 1 ? g_ptr_array_index (rest, 1)
		                                   : NULL;
		const gchar *text = fs_cli_command_help (topic);

		if (text == NULL) {
			status = unknown_word ("no such command", topic);
			g_ptr_array_unref (rest);
			return status;
		}
		g_ptr_array_unref (rest);
		fputs (text, stdout);
		return FS_EXIT_OK;
	}

	if (command == NULL) {
		g_ptr_array_unref (rest);
		fputs (main_help, g.want_help ? stdout : stderr);
		return g.want_help ? FS_EXIT_OK : FS_EXIT_USAGE;
	}

	if (def == NULL) {
		status = unknown_word ("unknown command", command);
		g_ptr_array_unref (rest);
		return status;
	}

	if (g.want_help) {
		fputs (def->help, stdout);
		g_ptr_array_unref (rest);
		return FS_EXIT_OK;
	}

	/* Preferences (audit-only mode, Advanced Options): read them here.
	 * The terminal writes them (root's copy) only through the control
	 * layer, fs_prefs_set_persist under the lock, never with
	 * fs_prefs_save on this snapshot. */
	fs_prefs_load ();

	g_ptr_array_add (rest, NULL);
	fs_cli.argv = (gchar **) rest->pdata;
	fs_cli.command = def->name;
	status = def->run (fs_cli.argc, fs_cli.argv);
	fs_cli.argv = NULL;
	g_ptr_array_unref (rest);
	fflush (stdout);
	return status;
}
