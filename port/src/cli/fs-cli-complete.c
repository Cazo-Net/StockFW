/*---[ fs-cli-complete.c ]-----------------------------------------------
 * Two hidden commands made from the command tables (fs-cli.h), so
 * completion and the manual page can never drift from the parser:
 *
 *   stockfw __complete WORD...   one candidate per line for the last
 *                                WORD (it may be empty); the shell
 *                                scripts in contrib/completion call it
 *   stockfw __man                the manual page stockfw(1), in roff
 *
 * fs-cli-main.c runs them before it parses anything, and neither is in
 * a table, so `help', the command list and did-you-mean never show
 * them.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-intel.h"
#include "core/fs-netparse.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------- vocabulary */

static const gchar *policy_subs[] = {
	"list", "show", "add", "remove", "diff", NULL
};
static const gchar *intel_subs[] = {
	"status", "feeds", "terms", "enable", "disable", "on", "off",
	"add-feed", "proxy", "update", "apply", "clear", "import", "lists",
	"list", "remove", "except", "unexcept", "exceptions", "lookup",
	"geo", NULL
};
static const gchar *intel_list_subs[] = { "add", "remove", "show", NULL };
static const gchar *intel_geo_subs[] = {
	"status", "terms", "on", "off", "update", "search", "add", "list",
	"remove", NULL
};
static const gchar *copilot_subs[]  = { "health", NULL };
static const gchar *sentinel_subs[] = { "list", NULL };
static const gchar *config_subs[] = {
	"list", "get", "set", "reset", "apply", "devices", "audit-only", NULL
};

static const gchar *events_by[] = {
	"src", "dst", "port", "service", "dir", "rule", "hour", NULL
};
static const gchar *connections_by[] = { "remote", "program", "port", NULL };
static const gchar *dir_words[] = {
	"in", "out", "both", "inbound", "outbound", NULL
};
static const gchar *conn_dir_words[] = { "in", "out", NULL };
static const gchar *intel_dir_words[] = { "in", "out", "both", NULL };
static const gchar *proto_words[] = { "tcp", "udp", "icmp", "icmpv6", NULL };
static const gchar *severity_words[] = {
	"info", "warning", "critical", NULL
};
static const gchar *audit_actions[] = {
	"apply", "start", "stop", "intel", "sentinel", "health", "trust",
	"policy", NULL
};
static const gchar *feed_formats[] = {
	"plain", "spamhaus-json", "dshield", NULL
};
static const gchar *color_words[] = { "auto", "always", "never", NULL };

/* ------------------------------------------------------- candidates */

typedef struct
{
	const gchar *prefix;   /* what the user typed of the word        */
	const gchar *lead;     /* printed before each value ("--by=")    */
	GHashTable  *seen;
} Out;

static void
emit (Out *o, const gchar *word)
{
	gchar *line;

	if (word == NULL || *word == '\0')
		return;
	line = g_strconcat (o->lead, word, NULL);
	if (g_str_has_prefix (line, o->prefix) &&
	    !g_hash_table_contains (o->seen, line)) {
		g_hash_table_add (o->seen, line);
		puts (line);
		return;
	}
	g_free (line);
}

static void
emit_all (Out *o, const gchar * const *words)
{
	for (guint i = 0; words != NULL && words[i] != NULL; i++)
		emit (o, words[i]);
}

static void
emit_commands (Out *o)
{
	guint n;
	const FsCliCommandDef * const *all = fs_cli_all_commands (&n);

	for (guint i = 0; i < n; i++)
		emit (o, all[i]->name);
	emit (o, "help");
	emit (o, "version");
}

static void
emit_globals (Out *o)
{
	guint n;
	const gchar * const *g = fs_cli_global_flags (&n);

	for (guint i = 0; i < n; i++)
		emit (o, g[i]);
}

/* [ emit_refs ] -- KIND:N of every rule of the saved policy. */
static void
emit_refs (Out *o)
{
	FsPolicy *policy = fs_cli_load_policy (NULL, NULL);

	if (policy == NULL)
		return;
	for (guint k = 0; k < FS_RULE_N_KINDS; k++) {
		GPtrArray *rows = policy->kinds[k];

		for (guint i = 0; rows != NULL && i < rows->len; i++) {
			gchar *ref = fs_cli_rule_ref ((FsRuleKind) k, i + 1);

			emit (o, ref);
			g_free (ref);
		}
	}
	fs_policy_free (policy);
}

typedef enum
{
	INTEL_FEEDS     = 1 << 0,
	INTEL_CUSTOM    = 1 << 1,   /* custom feeds only */
	INTEL_LISTS     = 1 << 2,
	INTEL_LOCATIONS = 1 << 3
} IntelIds;

/* [ emit_intel_ids ]
 * The ids of the threat-intel configuration: the catalog's feeds are
 * known without the store; custom feeds, local lists and location
 * rules only when the store exists and can be read.  Silent when not:
 * completion never prints an error. */
static void
emit_intel_ids (Out *o, IntelIds which)
{
	FsIntelConfig *config = NULL;

	if (fs_intel_store_exists ())
		config = fs_intel_config_load (NULL);
	if (config == NULL)
		config = fs_intel_config_new ();
	if (config == NULL)
		return;

	for (guint i = 0; config->feeds != NULL && i < config->feeds->len;
	     i++) {
		FsIntelFeedConf *f = g_ptr_array_index (config->feeds, i);

		if ((which & INTEL_FEEDS) ||
		    ((which & INTEL_CUSTOM) && f->custom))
			emit (o, f->id);
	}
	for (guint i = 0; (which & INTEL_LISTS) && config->lists != NULL &&
	     i < config->lists->len; i++) {
		FsIntelListConf *l = g_ptr_array_index (config->lists, i);

		emit (o, l->id);
	}
	for (guint i = 0; (which & INTEL_LOCATIONS) &&
	     config->locations != NULL && i < config->locations->len; i++) {
		FsIntelLocationConf *l = g_ptr_array_index (config->locations, i);

		emit (o, l->id);
	}
	fs_intel_config_free (config);
}

/* [ emit_values ] -- the values of one option of one command. */
static void
emit_values (Out *o, const gchar *command, const gchar *opt)
{
	if (strcmp (opt, "--by") == 0) {
		emit_all (o, strcmp (command, "connections") == 0
		             ? connections_by : events_by);
	} else if (strcmp (opt, "--dir") == 0 ||
	           strcmp (opt, "--direction") == 0) {
		emit_all (o, strcmp (command, "connections") == 0
		             ? conn_dir_words
		             : strcmp (command, "intel") == 0 ? intel_dir_words
		                                               : dir_words);
	} else if (strcmp (opt, "--proto") == 0) {
		emit_all (o, proto_words);
	} else if (strcmp (opt, "--severity") == 0) {
		emit_all (o, severity_words);
	} else if (strcmp (opt, "--kind") == 0) {
		emit_all (o, fs_cli_kind_names ());
	} else if (strcmp (opt, "--action") == 0) {
		emit_all (o, audit_actions);
	} else if (strcmp (opt, "--feed") == 0) {
		emit_intel_ids (o, INTEL_FEEDS);
	} else if (strcmp (opt, "--format") == 0) {
		emit_all (o, feed_formats);
	} else if (strcmp (opt, "--state") == 0) {
		for (guint s = 1; s <= 12; s++)
			emit (o, fs_netparse_tcp_state_name (s));
	} else if (strcmp (opt, "--color") == 0 ||
	           strcmp (opt, "--colour") == 0) {
		emit_all (o, color_words);
	}
}

/* [ find_opt ] -- def's option named `name', or NULL. */
static const FsCliOption *
find_opt (const FsCliCommandDef *def, const gchar *name)
{
	for (const FsCliOption *p = def != NULL ? def->opts : NULL;
	     p != NULL && p->name != NULL; p++)
		if (strcmp (p->name, name) == 0)
			return p;
	return NULL;
}

static gboolean
is_global (const gchar *word)
{
	guint n;
	const gchar * const *g = fs_cli_global_flags (&n);

	if (g_str_has_prefix (word, "--color=") ||
	    g_str_has_prefix (word, "--colour="))
		return TRUE;
	for (guint i = 0; i < n; i++)
		if (strcmp (g[i], word) == 0)
			return TRUE;
	return FALSE;
}

/* [ emit_positional ] -- the next plain word of `def', given the plain
 * words already typed after it (pos). */
static void
emit_positional (Out *o, const FsCliCommandDef *def, GPtrArray *pos)
{
	const gchar *name = def->name;
	const gchar *p0 = pos->len > 0 ? g_ptr_array_index (pos, 0) : NULL;
	const gchar *p1 = pos->len > 1 ? g_ptr_array_index (pos, 1) : NULL;

	if (strcmp (name, "policy") == 0) {
		if (pos->len == 0) {
			emit_all (o, policy_subs);
		} else if (pos->len == 1 && (strcmp (p0, "remove") == 0 ||
		                             strcmp (p0, "show") == 0)) {
			emit_refs (o);
		} else if (pos->len == 1 && strcmp (p0, "add") == 0) {
			emit_all (o, fs_cli_kind_names ());
		} else if (pos->len == 1 && strcmp (p0, "list") == 0) {
			emit_all (o, fs_cli_kind_names ());
			emit (o, "in");
			emit (o, "out");
		}
	} else if (strcmp (name, "copilot") == 0) {
		if (pos->len == 0)
			emit_all (o, copilot_subs);
	} else if (strcmp (name, "sentinel") == 0) {
		if (pos->len == 0)
			emit_all (o, sentinel_subs);
	} else if (strcmp (name, "intel") == 0) {
		if (pos->len == 0) {
			emit_all (o, intel_subs);
		} else if (pos->len == 1) {
			if (strcmp (p0, "terms") == 0)
				emit_intel_ids (o, INTEL_FEEDS);
			else if (strcmp (p0, "enable") == 0 ||
			         strcmp (p0, "disable") == 0)
				emit_intel_ids (o, INTEL_FEEDS | INTEL_LISTS |
				                   INTEL_LOCATIONS);
			else if (strcmp (p0, "remove") == 0)
				emit_intel_ids (o, INTEL_CUSTOM | INTEL_LISTS);
			else if (strcmp (p0, "list") == 0)
				emit_all (o, intel_list_subs);
			else if (strcmp (p0, "geo") == 0)
				emit_all (o, intel_geo_subs);
			else if (strcmp (p0, "proxy") == 0)
				emit (o, "none");
		} else if (pos->len == 2) {
			if (strcmp (p0, "list") == 0 &&
			    (strcmp (p1, "show") == 0 || strcmp (p1, "remove") == 0))
				emit_intel_ids (o, INTEL_LISTS);
			else if (strcmp (p0, "geo") == 0 && strcmp (p1, "add") == 0) {
				emit (o, "country");
				emit (o, "asn");
			} else if (strcmp (p0, "geo") == 0 &&
			           strcmp (p1, "remove") == 0)
				emit_intel_ids (o, INTEL_LOCATIONS);
		}
	} else if (strcmp (name, "config") == 0) {
		/* set NAME VALUE NAME VALUE...: a name, then a value. */
		if (pos->len == 0) {
			emit_all (o, config_subs);
		} else if ((strcmp (p0, "get") == 0 && pos->len == 1) ||
		           strcmp (p0, "reset") == 0 ||
		           (strcmp (p0, "set") == 0 && pos->len % 2 == 1)) {
			emit_all (o, fs_cli_config_names ());
		} else if ((strcmp (p0, "set") == 0 && pos->len % 2 == 0) ||
		           (strcmp (p0, "audit-only") == 0 && pos->len == 1)) {
			emit (o, "on");
			emit (o, "off");
		}
	}
}

gint
fs_cli_complete_main (gint argc, gchar **argv)
{
	const gchar *cur = argc > 0 ? argv[argc - 1] : "";
	const gchar *command = NULL;
	const FsCliCommandDef *def = NULL;
	gboolean is_help = FALSE, positional = FALSE;
	GPtrArray *pos = g_ptr_array_new ();
	const gchar *value_of = NULL;   /* the option the word is a value of */
	Out o = { cur, "", g_hash_table_new_full (g_str_hash, g_str_equal,
	                                         g_free, NULL) };

	/* The words before the one being completed. */
	for (gint i = 0; i < argc - 1; i++) {
		const gchar *a = argv[i];

		value_of = NULL;
		if (!positional && strcmp (a, "--") == 0) {
			positional = TRUE;
			continue;
		}
		if (!positional && is_global (a))
			continue;
		if (command == NULL) {
			if (!positional && a[0] == '-')
				continue;
			command = a;
			is_help = strcmp (a, "help") == 0;
			def = fs_cli_find_command (a);
			continue;
		}
		if (!positional && a[0] == '-') {
			const FsCliOption *opt = find_opt (def, a);

			if (opt != NULL && opt->takes_value && strchr (a, '=') == NULL) {
				if (i + 1 < argc - 1)
					i++;          /* its value */
				else
					value_of = opt->name;
			}
			continue;
		}
		g_ptr_array_add (pos, (gpointer) a);
	}

	if (value_of != NULL) {
		emit_values (&o, def->name, value_of);
	} else if (!positional && g_str_has_prefix (cur, "--") &&
	           strchr (cur, '=') != NULL) {
		gchar *opt = g_strndup (cur, strchr (cur, '=') - cur);
		gchar *lead = g_strconcat (opt, "=", NULL);

		o.lead = lead;
		if (def != NULL && find_opt (def, opt) != NULL)
			emit_values (&o, def->name, opt);
		else if (strcmp (opt, "--color") == 0 ||
		         strcmp (opt, "--colour") == 0)
			emit_values (&o, "", opt);
		g_free (lead);
		g_free (opt);
	} else if (command == NULL) {
		if (cur[0] == '-' && !positional)
			emit_globals (&o);
		else
			emit_commands (&o);
	} else if (is_help) {
		if (pos->len == 0)
			emit_commands (&o);
	} else if (def == NULL) {
		/* an unknown command: nothing to offer */
	} else if (cur[0] == '-' && !positional) {
		const gchar *sub = pos->len > 0 ? g_ptr_array_index (pos, 0)
		                                : NULL;

		for (const FsCliOption *p = def->opts; p != NULL && p->name != NULL;
		     p++)
			if (sub == NULL || p->sub == NULL || strcmp (p->sub, sub) == 0)
				emit (&o, p->name);
		emit_globals (&o);
	} else {
		emit_positional (&o, def, pos);
	}

	g_hash_table_unref (o.seen);
	g_ptr_array_unref (pos);
	fflush (stdout);
	return FS_EXIT_OK;
}

/* ------------------------------------------------------------- man */

/* [ roff_text ] -- `text' as roff: a backslash is \e, a line that
 * starts with a dot or quote is guarded with \&, a dash is \-, and
 * every character outside ASCII is \[uXXXX], so the page reads the
 * same under any locale and groff -ww has nothing to warn about. */
static void
roff_text (GString *out, const gchar *text)
{
	gboolean bol = TRUE;

	for (const gchar *p = text; *p != '\0'; p = g_utf8_next_char (p)) {
		gunichar c = g_utf8_get_char (p);

		if (bol && (c == '.' || c == '\''))
			g_string_append (out, "\\&");
		bol = c == '\n';
		if (c == '\\')
			g_string_append (out, "\\e");
		else if (c == '-')
			g_string_append (out, "\\-");
		else if (c >= 0x80)
			g_string_append_printf (out, "\\[u%04X]", c);
		else
			g_string_append_c (out, (gchar) c);
	}
}

/* A block of text kept as it is (no filling), as the help prints it. */
static void
roff_verbatim (GString *out, const gchar *text)
{
	g_string_append (out, ".nf\n");
	roff_text (out, text);
	if (text[0] != '\0' && text[strlen (text) - 1] != '\n')
		g_string_append_c (out, '\n');
	g_string_append (out, ".fi\n");
}

static const struct { const gchar *name, *what; } environment[] = {
	{ "STOCKFW_RULES_DIR",
	  "The policy directory, instead of ~/.stockfw (or /etc/stockfw as root)." },
	{ "STOCKFW_APPLIED_FILE",
	  "The apply journal: the policy last applied (policy diff, status, simulate --applied)." },
	{ "STOCKFW_AUDIT_FILE",
	  "The audit log, instead of ~/.config/stockfw/audit.log." },
	{ "STOCKFW_LOG_FILE",
	  "Read firewall events from this file instead of the kernel log." },
	{ "STOCKFW_EVENTS_DIR",
	  "The event history the desktop app keeps (events --history)." },
	{ "STOCKFW_AUTOBLOCK_FILE",
	  "Sentinel's state file (sentinel list)." },
	{ "STOCKFW_INTEL_DIR",
	  "The threat-intel store, instead of /var/lib/stockfw/intel." },
	{ "STOCKFW_LAN_PREFIX",
	  "The LAN that listening and copilot health ask about, such as 192.168.1.0/24." },
	{ "STOCKFW_PROC_NET_DIR",
	  "Read the socket tables (tcp, tcp6, udp, udp6) from here instead of /proc/net (listening)." },
	{ "STOCKFW_TRUST_FILE",
	  "The Trust store." },
	{ "STOCKFW_BEHAVIOR_FILE",
	  "The baseline the health check compares with." },
	{ "STOCKFW_SYSTEMD_DIR",
	  "Where status looks for stockfw.service, instead of /etc/systemd/system." },
	{ "STOCKFW_INSTANCE_NAME",
	  "The desktop app's instance name that config set looks for, to warn when a StockFW window runs as root." },
	{ "NO_COLOR",
	  "When set, no colour unless --color=always is given." },
	{ "TERM",
	  "TERM=dumb: no colour and no status line under events -f." },
	{ "COLUMNS",
	  "The terminal width, when the terminal does not report one. A pipe is never cut." },
	{ "SSH_CONNECTION",
	  "Read by the lockout guard of apply and start, with the SSH sessions the kernel lists." },
	{ "SUDO_USER",
	  "Under sudo: audit names that user's desktop log." },
};

static const struct { const gchar *path, *what; } files[] = {
	{ "~/.stockfw/", "The policy of a normal user: the files the desktop app edits." },
	{ "/etc/stockfw/", "The policy used as root, which apply and start load." },
	{ "/etc/stockfw/applied.csv", "The apply journal: the policy that was last applied." },
	{ "~/.config/stockfw/audit.log", "The audit log (root: /root/.config/stockfw/audit.log)." },
	{ "~/.config/stockfw/stockfw.conf", "The settings (config); root's copy, /root/.config/stockfw/stockfw.conf, is the one the firewall uses and config set writes." },
	{ "~/.local/share/stockfw/events/", "The event history, when the desktop app keeps it." },
	{ "/var/lib/stockfw/intel/", "The threat-intel store (root)." },
	{ "/etc/systemd/system/stockfw.service", "Puts the rules back at boot (stockfw start)." },
};

static const struct { const gchar *cmd, *what; } examples[] = {
	{ "stockfw status -v", "What runs, what is saved, and the settings." },
	{ "stockfw check", "Lines of the policy files that are not rules." },
	{ "stockfw policy add inbound-allow-service SSH 22 192.168.1.0/24",
	  "Allow SSH from the LAN (saved, not live yet)." },
	{ "stockfw policy diff", "What apply would change." },
	{ "sudo /usr/local/bin/stockfw apply", "Make the saved policy live." },
	{ "stockfw simulate \"inbound tcp 22 from 203.0.113.7\"",
	  "Would this traffic get through?" },
	{ "stockfw events --summary --since 24h", "Who was blocked, and on which ports." },
	{ "stockfw listening", "Which open ports the LAN and the internet can reach." },
	{ "stockfw audit -n 10", "The last ten applies, starts and stops." },
};

gint
fs_cli_man_main (gint argc, gchar **argv)
{
	guint n;
	const FsCliCommandDef * const *all = fs_cli_all_commands (&n);
	GString *out = g_string_new (NULL);
	const gchar *main_help = fs_cli_command_help (NULL);

	g_string_append (out,
		".\\\" stockfw(1), made by `stockfw __man' from the command tables.\n"
		".\\\" Do not edit: change the help texts in src/cli instead.\n");
	g_string_append_printf (out,
		".TH STOCKFW 1 \"\" \"StockFW %s\" \"User Commands\"\n", FS_VERSION);
	/* No hyphenation: a word broken at the line end prints U+2010, so
	 * an option copied from the page (--history) would not be one. */
	g_string_append (out, ".nh\n");

	g_string_append (out, ".SH NAME\nstockfw \\- the StockFW firewall from the "
	                      "command line\n");

	g_string_append (out, ".SH SYNOPSIS\n");
	g_string_append (out, ".B stockfw\n[\\fIglobal options\\fR] "
	                      "\\fIcommand\\fR [\\fIarguments\\fR]\n");

	g_string_append (out, ".SH DESCRIPTION\n");
	roff_verbatim (out, main_help);

	g_string_append (out, ".SH COMMANDS\n");
	g_string_append (out, "Each command has its own section below; "
	                      "\\fBstockfw help\\fR \\fIcommand\\fR prints the "
	                      "same text.\n");

	for (guint i = 0; i < n; i++) {
		const FsCliCommandDef *d = all[i];
		gboolean any = d->opts != NULL && d->opts[0].name != NULL;
		gchar *up = g_ascii_strup (d->name, -1);

		g_string_append_printf (out, ".SH \"STOCKFW %s\"\n", up);
		g_free (up);
		roff_verbatim (out, d->help);
		if (d->alias != NULL)
			g_string_append_printf (out, ".PP\nAlso: \\fBstockfw %s\\fR.\n",
			                        d->alias);
		if (any) {
			/* The parser's own list: "--kind VALUE (list), --both
			 * (add)", the subcommand in brackets where it has one. */
			g_string_append (out, ".PP\nOptions:\n");
			for (const FsCliOption *p = d->opts; p->name != NULL; p++) {
				g_string_append (out, "\\fB");
				roff_text (out, p->name);
				g_string_append (out, "\\fR");
				if (p->takes_value)
					g_string_append (out, " \\fIVALUE\\fR");
				if (p->sub != NULL) {
					g_string_append (out, " (");
					roff_text (out, p->sub);
					g_string_append_c (out, ')');
				}
				g_string_append (out, p[1].name != NULL ? ",\n" : ".\n");
			}
		}
	}

	g_string_append (out, ".SH \"STOCKFW HELP\"\n");
	roff_verbatim (out, fs_cli_command_help ("help"));
	g_string_append (out, ".SH \"STOCKFW VERSION\"\n");
	roff_verbatim (out, fs_cli_command_help ("version"));

	g_string_append (out, ".SH \"GLOBAL OPTIONS\"\n");
	g_string_append (out, "They go before or after the command, and "
	                      "DESCRIPTION says what each does:\n");
	{
		guint ng;
		const gchar * const *g = fs_cli_global_flags (&ng);

		for (guint i = 0; i < ng; i++) {
			g_string_append (out, "\\fB");
			roff_text (out, g[i]);
			g_string_append (out, i + 1 < ng ? "\\fR,\n" : "\\fR.\n");
		}
	}

	g_string_append (out, ".SH \"EXIT STATUS\"\n");
	g_string_append (out,
		".TP\n.B 0\nSuccess.\n"
		".TP\n.B 1\nFailure, or check found problems.\n"
		".TP\n.B 2\nUsage error: an unknown command or option, a "
		"missing value, or a policy line that is not a rule (apply).\n"
		".TP\n.B 3\nNeeds root.\n"
		".TP\n.B 5\nsimulate: BLOCKED; intel lookup: a list blocks the "
		"address.\n"
		".TP\n.B 6\nsimulate: DEPENDS (allowed in some cases).\n"
		".TP\n.B 7\ncopilot health: findings at or above "
		"\\-\\-severity.\n");

	g_string_append (out, ".SH ENVIRONMENT\n");
	for (guint i = 0; i < G_N_ELEMENTS (environment); i++) {
		g_string_append (out, ".TP\n.B ");
		roff_text (out, environment[i].name);
		g_string_append_c (out, '\n');
		roff_text (out, environment[i].what);
		g_string_append_c (out, '\n');
	}

	g_string_append (out, ".SH FILES\n");
	for (guint i = 0; i < G_N_ELEMENTS (files); i++) {
		g_string_append (out, ".TP\n.I ");
		roff_text (out, files[i].path);
		g_string_append_c (out, '\n');
		roff_text (out, files[i].what);
		g_string_append_c (out, '\n');
	}

	g_string_append (out, ".SH EXAMPLES\n");
	for (guint i = 0; i < G_N_ELEMENTS (examples); i++) {
		g_string_append (out, ".TP\n.B ");
		roff_text (out, examples[i].cmd);
		g_string_append_c (out, '\n');
		roff_text (out, examples[i].what);
		g_string_append_c (out, '\n');
	}

	g_string_append (out, ".SH \"SEE ALSO\"\n");
	g_string_append (out, ".BR nft (8),\n.BR iptables (8).\n"
	                      "The desktop app, \\fBStockFW\\fR, has no manual "
	                      "page of its own, and a build with "
	                      "FS_BUILD_GUI=OFF has no desktop app. Shell "
	                      "completion for bash and zsh asks \\fBstockfw\\fR "
	                      "itself for the words it offers.\n");

	fputs (out->str, stdout);
	g_string_free (out, TRUE);
	fflush (stdout);
	return FS_EXIT_OK;
}
