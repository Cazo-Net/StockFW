/*---[ fs-cli-main.c ]---------------------------------------------------
 * `stockfw': argument handling, help, and the shared output helpers.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-prefs.h"

#include <locale.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

FsCliOptions fs_cli = { FALSE, FALSE, FALSE };

/* --------------------------------------------------------------- output */

void
fs_cli_error (const gchar *format, ...)
{
	va_list args;
	gchar *text;

	va_start (args, format);
	text = g_strdup_vprintf (format, args);
	va_end (args);

	fprintf (stderr, "stockfw: %serror:%s %s\n",
	         fs_cli.color ? "\033[1;31m" : "",
	         fs_cli.color ? "\033[0m" : "", text);
	g_free (text);
}

void
fs_cli_hint (const gchar *format, ...)
{
	va_list args;
	gchar *text;

	va_start (args, format);
	text = g_strdup_vprintf (format, args);
	va_end (args);

	fprintf (stderr, "stockfw: %shint:%s %s\n",
	         fs_cli.color ? "\033[1;33m" : "",
	         fs_cli.color ? "\033[0m" : "", text);
	g_free (text);
}

const gchar *fs_cli_bold  (void) { return fs_cli.color ? "\033[1m"  : ""; }
const gchar *fs_cli_dim   (void) { return fs_cli.color ? "\033[2m"  : ""; }
const gchar *fs_cli_red   (void) { return fs_cli.color ? "\033[31m" : ""; }
const gchar *fs_cli_green (void) { return fs_cli.color ? "\033[32m" : ""; }
const gchar *fs_cli_amber (void) { return fs_cli.color ? "\033[33m" : ""; }
const gchar *fs_cli_reset (void) { return fs_cli.color ? "\033[0m"  : ""; }

gchar *
fs_cli_format_bytes (guint64 bytes)
{
	static const gchar *units[] = { "B", "kB", "MB", "GB", "TB", "PB" };
	gdouble value = (gdouble) bytes;
	guint unit = 0;

	while (value >= 1000.0 && unit < G_N_ELEMENTS (units) - 1) {
		value /= 1000.0;
		unit++;
	}

	if (unit == 0)
		return g_strdup_printf ("%" G_GUINT64_FORMAT " B", bytes);

	return g_strdup_printf ("%.1f %s", value, units[unit]);
}

gchar *
fs_cli_format_rate (gdouble bytes_per_second)
{
	gchar *size;
	gchar *text;

	if (bytes_per_second < 0)
		bytes_per_second = 0;

	size = fs_cli_format_bytes ((guint64) (bytes_per_second + 0.5));
	text = g_strconcat (size, "/s", NULL);
	g_free (size);

	return text;
}

/* [ cell_text ] -- a cell cut to max_width characters with an ellipsis. */
static gchar *
cell_text (const gchar *cell, guint max_width)
{
	glong len;

	if (cell == NULL)
		cell = "";

	len = g_utf8_strlen (cell, -1);
	if (max_width == 0 || len <= (glong) max_width)
		return g_strdup (cell);

	{
		const gchar *end = g_utf8_offset_to_pointer (cell, max_width - 1);
		gchar *cut = g_strndup (cell, (gsize) (end - cell));
		gchar *text = g_strconcat (cut, "…", NULL);

		g_free (cut);
		return text;
	}
}

void
fs_cli_table (const gchar * const *headers, guint n_cols, GPtrArray *rows,
              guint max_width)
{
	guint *widths = g_new0 (guint, n_cols);
	GPtrArray *cells = g_ptr_array_new_with_free_func (
		(GDestroyNotify) g_strfreev);

	for (guint c = 0; c < n_cols; c++)
		widths[c] = (guint) g_utf8_strlen (headers[c], -1);

	for (guint r = 0; r < rows->len; r++) {
		gchar **row = g_ptr_array_index (rows, r);
		gchar **cut = g_new0 (gchar *, n_cols + 1);

		for (guint c = 0; c < n_cols; c++) {
			cut[c] = cell_text (row[c], max_width);
			widths[c] = MAX (widths[c],
			                 (guint) g_utf8_strlen (cut[c], -1));
		}
		g_ptr_array_add (cells, cut);
	}

	/* Header. */
	printf ("%s", fs_cli_bold ());
	for (guint c = 0; c < n_cols; c++) {
		if (c + 1 < n_cols)
			printf ("%-*s  ", (gint) (widths[c] + strlen (headers[c]) -
			                          g_utf8_strlen (headers[c], -1)),
			        headers[c]);
		else
			printf ("%s", headers[c]);
	}
	printf ("%s\n", fs_cli_reset ());

	for (guint r = 0; r < cells->len; r++) {
		gchar **row = g_ptr_array_index (cells, r);

		for (guint c = 0; c < n_cols; c++) {
			if (c + 1 < n_cols) {
				/* printf pads by bytes; pad by characters. */
				glong chars = g_utf8_strlen (row[c], -1);

				printf ("%s%*s  ", row[c],
				        (gint) (widths[c] - (guint) chars), "");
			} else {
				printf ("%s", row[c]);
			}
		}
		printf ("\n");
	}

	g_ptr_array_unref (cells);
	g_free (widths);
}

void
fs_cli_print_json (GString *json)
{
	fwrite (json->str, 1, json->len, stdout);
	fputc ('\n', stdout);
}

/* ----------------------------------------------------------------- help */

static const gchar *main_help =
"Usage: stockfw [--json] [--no-color] [-q] <command> [arguments]\n"
"\n"
"StockFW from the command line: the same policy, simulator and apply\n"
"gate as the desktop app, without a display.\n"
"\n"
"Commands:\n"
"  status                     Firewall state, policy and monitoring at a glance\n"
"  policy list|add|remove     Read and edit the traffic policy\n"
"  apply [--dry-run]          Push the saved policy to the firewall (root)\n"
"  start | stop               Start or stop the firewall (root)\n"
"  simulate \"<traffic>\"       What-if: would this traffic be allowed or blocked?\n"
"  copilot health             Check the policy for overlaps, conflicts, risky allows\n"
"  events [-n N] [-f]         Recent firewall events; --history for saved ones\n"
"  connections                Active TCP connections and their programs\n"
"  interfaces [--watch]       Network adapters with traffic counters and rates\n"
"  intel <action>             Threat-intel blocklists (stockfw help intel)\n"
"  dashboard [--port N]       Serve the local web dashboard and open it\n"
"  help [command]             Help for one command\n"
"  version                    Print the version\n"
"\n"
"Global options:\n"
"  --json        Machine-readable output (one JSON document; NDJSON for -f)\n"
"  --no-color    Plain output (also honoured: NO_COLOR, TERM=dumb, pipes)\n"
"  -q, --quiet   Only errors and the essential result\n"
"  -h, --help    This help;  -V, --version  the version\n"
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

typedef struct
{
	const gchar  *name;
	FsCliCommand  run;
	const gchar  *help;
} CommandDef;

static const CommandDef commands[] = {
	{ "status", fs_cli_cmd_status,
"Usage: stockfw status [--json]\n"
"\n"
"Shows the firewall state, the backend, how many rules the saved policy\n"
"holds and where it lives, whether audit-only mode holds applies back,\n"
"whether live event monitoring is available, and the adapters and\n"
"connection count.  Reading the firewall state needs root; without it\n"
"the state is reported as unknown rather than guessed.\n" },

	{ "policy", fs_cli_cmd_policy,
"Usage: stockfw policy list [--kind KIND] [--json]\n"
"       stockfw policy add KIND FIELD... [--comment TEXT] [--both]\n"
"       stockfw policy remove KIND N\n"
"\n"
"Edits the saved policy -- the files the desktop app's Policy page\n"
"shows.  Changes are validated (hosts, ports and ranges fail closed)\n"
"and saved; nothing reaches the firewall until `stockfw apply'.\n"
"\n"
"Kinds and their fields:\n"
"  inbound-allow-from      HOST\n"
"  inbound-allow-service   SERVICE PORT FOR\n"
"  inbound-forward         SERVICE FIREWALL-PORT TO PORT\n"
"  outbound-allow-to       HOST\n"
"  outbound-allow-from     HOST\n"
"  outbound-allow-service  SERVICE PORT FOR\n"
"  outbound-deny-to        HOST\n"
"  outbound-deny-from      HOST\n"
"  outbound-deny-service   SERVICE PORT FOR\n"
"\n"
"FOR is a host, a network (192.168.1.0/24) or \"Anyone\".  --both also\n"
"adds the opposite-direction twin of an allow rule, as one change.\n"
"N is the rule's number in `stockfw policy list --kind KIND'.\n"
"\n"
"Examples:\n"
"  stockfw policy add inbound-allow-service SSH 22 192.168.1.0/24 --comment admin\n"
"  stockfw policy add outbound-deny-to 203.0.113.9\n"
"  stockfw policy remove outbound-deny-to 1\n" },

	{ "apply", fs_cli_cmd_apply,
"Usage: stockfw apply [--dry-run] [--json]\n"
"\n"
"Pushes the saved policy to the firewall through the same apply gate\n"
"the desktop app uses: only what changed is touched, a failed apply is\n"
"rolled back to the last applied policy and the rollback is verified,\n"
"and every attempt is one line in the audit log.  When audit-only mode\n"
"is on (Policy page), the firewall is left untouched and the would-be\n"
"change is recorded.  --dry-run only reports the impact.  Needs root.\n" },

	{ "start", fs_cli_cmd_start,
"Usage: stockfw start\n"
"\n"
"Starts the firewall with the last APPLIED policy -- what `stockfw\n"
"apply' last put live -- so saved changes that were never applied stay\n"
"off, and Sentinel blocks whose ten minutes ran out are left out.  The\n"
"boot unit (stockfw.service) runs this at every boot.  When nothing was\n"
"ever applied, the saved policy is started instead, and the start is\n"
"refused if there is none or a line of it is malformed.  Threat-intel\n"
"blocklists that are turned on are applied again, through the same gate\n"
"(audit-only mode holds them too); if they cannot be, the firewall still\n"
"runs and the exit status is non-zero.  Needs root.\n" },

	{ "stop", fs_cli_cmd_stop,
"Usage: stockfw stop\n"
"\n"
"Removes StockFW's own chains, and its threat-intel blocklists until\n"
"the next start.  Rules owned by Docker, libvirt or anything else are\n"
"left alone.  Needs root.\n" },

	{ "simulate", fs_cli_cmd_simulate,
"Usage: stockfw simulate \"<traffic>\" [--assume-running] [--json]\n"
"\n"
"Answers ALLOWED, BLOCKED or DEPENDS for described traffic against the\n"
"saved policy and Firewall preferences, the way the Copilot page's\n"
"What-If Simulator does: the rules checked, the one that decided, and\n"
"fixes that were checked before they are offered.  What the line\n"
"leaves open (host, port, protocol, direction) is answered for every\n"
"case: DEPENDS names the split.  When the firewall is not running the\n"
"answer says so; --assume-running answers as if it were.  It writes\n"
"nothing: it is a question, not a change.  Exits 0 for ALLOWED, 5 for\n"
"BLOCKED, 6 for DEPENDS and 2 for a line it cannot read, so scripts\n"
"can branch on it.\n"
"\n"
"Examples:\n"
"  stockfw simulate \"allow ssh from 192.168.1.50 on port 22\"\n"
"  stockfw simulate \"inbound rdp\"\n"
"  stockfw simulate \"outbound tcp to 203.0.113.9 port 443\"\n" },

	{ "copilot", fs_cli_cmd_copilot,
"Usage: stockfw copilot health [--json]\n"
"\n"
"Runs the Copilot page's policy health check on the saved policy:\n"
"rules that repeat another, rules another rule already covers, allows a\n"
"deny makes unreachable, outbound allows that do nothing while outbound\n"
"traffic is allowed, wide or risky inbound allows from anyone, and deny\n"
"rules that reach no address family.  These are fixed rules, not a\n"
"model.  Each fix is shown with the What-If checks that verify it, and\n"
"one that does not verify is not offered.  It writes nothing: fixes\n"
"are made on the Copilot page.  The local network a narrowing uses is\n"
"the first adapter with a private IPv4 address.\n"
"\n"
"Exits 0 with no findings, 7 with findings, and 2 when the policy\n"
"cannot be read in full.  In --json, rule.index counts from 0.\n" },

	{ "events", fs_cli_cmd_events,
"Usage: stockfw events [-n N] [-f|--follow] [--history] [--json]\n"
"                      [--since T] [--until T] [--grep TEXT]\n"
"                      [--dir in|out] [--proto P] [--port P]\n"
"                      [--addr A] [--blocked|--allowed]\n"
"\n"
"The last N (default 20, up to 1000000) events, oldest first.  By\n"
"default they are read from the kernel log, which usually needs root\n"
"(or the adm group).  --history reads the history the desktop app\n"
"saves instead (Preferences > Events > Keep event history), in\n"
"~/.local/share/stockfw/events or STOCKFW_EVENTS_DIR; it is the\n"
"account's own, so no root is needed, and under sudo it is root's:\n"
"--history-dir DIR reads another folder.  -f keeps following new\n"
"events until Ctrl-C (with --json, one object per line).\n"
"\n"
"Filters, all of which must match (the Events page has the same):\n"
"  --since T, --until T  a time: 15m, 2h, 3d, 1w, now, 2026-11-01,\n"
"                        \"2026-11-01 14:30\", or ISO with Z; --until\n"
"                        with a date takes in that whole day\n"
"  --grep TEXT           a column of the Events list contains TEXT\n"
"                        (any case): the time, direction, devices,\n"
"                        port, addresses, length, ToS, protocol or\n"
"                        service, or the list that blocked it\n"
"  --dir in|out          the direction\n"
"  --proto P             TCP, UDP, ICMP...\n"
"  --port P              443, 1000-2000 or 1000:2000\n"
"  --addr A              source or destination in A: an address, a\n"
"                        CIDR block (10.0.0.0/8, fd00::/8) or a-b\n"
"  --blocked, --allowed  the verdict\n"
"\n"
"Examples:\n"
"  stockfw events --history --since 1d --port 22 --dir in\n"
"  stockfw events --history -n 1000 --addr 203.0.113.0/24 --json\n" },

	{ "connections", fs_cli_cmd_connections,
"Usage: stockfw connections [--json]\n"
"\n"
"Connected TCP sockets (IPv4 and IPv6) with the remote service, the\n"
"direction and the owning program.  Another user's program shows as\n"
"\"?\" unless run as root.\n" },

	{ "interfaces", fs_cli_cmd_interfaces,
"Usage: stockfw interfaces [--watch] [--json]\n"
"\n"
"Network adapters with their type, address, total traffic and the\n"
"current rate (measured over one second).  --watch refreshes every two\n"
"seconds until Ctrl-C.  Alias: stockfw net\n" },

	{ "intel", fs_cli_cmd_intel,
"Usage: stockfw intel [status]                     State, and the lists turned on\n"
"       stockfw intel feeds                        Every feed: on/off, licence,\n"
"                                                  credit, entries, last update\n"
"       stockfw intel terms FEED                   What turning FEED on means\n"
"       stockfw intel enable ID [--direction D] [--accept-terms]\n"
"       stockfw intel disable ID\n"
"       stockfw intel on | off                     The master switch\n"
"       stockfw intel add-feed NAME URL [--format F] [--direction D]\n"
"       stockfw intel proxy [URL|none]             The download proxy\n"
"       stockfw intel update [--feed ID] [--now] [--accept-shrink]\n"
"                            [--accept-coverage] [--no-apply]\n"
"       stockfw intel apply [--dry-run]            Load the lists into the kernel\n"
"       stockfw intel clear                        Remove them from the kernel\n"
"       stockfw intel import FILE --name NAME [--direction D]\n"
"       stockfw intel lists | list show [ID]       Your own lists (and one's ranges)\n"
"       stockfw intel remove ID                    A local list or custom feed\n"
"       stockfw intel except | unexcept ADDRESS...  Never block / block again\n"
"       stockfw intel exceptions\n"
"       stockfw intel lookup ADDRESS               Which lists hold it; blocked?\n"
"       stockfw intel geo [status]                 Blocking by country or network\n"
"       stockfw intel geo terms | on [--accept-terms] | off\n"
"       stockfw intel geo update [--no-apply]      Download the location database\n"
"       stockfw intel geo search TEXT [--max N]    Find country codes and AS numbers\n"
"       stockfw intel geo add country|asn VALUE... [--dir D] [--name NAME]\n"
"       stockfw intel geo list | remove ID         The country and network rules\n"
"\n"
"Blocklists of addresses known for attacks, botnets or abuse, blocked\n"
"in the kernel before the policy sees a packet (Linux, nftables).  Every\n"
"feed is off until you turn it on and accept its terms: `intel terms'\n"
"says which host it is downloaded from, how often, what that host\n"
"learns, and its licence.  With nothing turned on StockFW makes no\n"
"network request at all.\n"
"\n"
"D is in (stops them connecting to you), out (stops you connecting to\n"
"them) or both.  `intel list add' and `intel list remove' are the same\n"
"as import and remove.  Changes to the configuration are saved and take\n"
"effect with `intel apply'; `update' downloads the feeds that are due\n"
"(--now: all of them) and, when the lists are enforced, the firewall\n"
"runs and audit-only mode is off, enforces the new copies.  A copy that\n"
"shrank to almost nothing or rolled back to an older date is refused\n"
"unless --accept-shrink; one whose coverage jumped needs\n"
"--accept-coverage.  Addresses this computer needs (its own network,\n"
"gateways, DNS servers, SSH sessions, the download servers) are never\n"
"blocked, and `apply' says which ones a list named.\n"
"\n"
"Downloads connect to each feed's host directly; behind a proxy, set it\n"
"with `intel proxy http://HOST:PORT' ([intel] proxy= in intel.conf).\n"
"A proxy with a user name or password is refused: curl's command line\n"
"is readable by every local user.\n"
"\n"
"`intel geo' blocks addresses by the country their range is registered\n"
"in (not where a computer is) or by the network that owns them (its AS\n"
"number), from IPFire's signed location database (location.ipfire.org,\n"
"about 6 MB).  It is off until `geo on --accept-terms'; `geo terms' says\n"
"what turning it on means and the licence the file declares.  Then\n"
"`intel update' downloads the database at most once a day, `geo update'\n"
"at once.  A rule holds countries (DE, or DE,FR) or AS numbers (13335 or\n"
"AS13335); D defaults to both.  `intel enable' and `intel disable' turn\n"
"a rule on and off by its id; `apply' puts the rules in force with the\n"
"lists.  Rules that cover anycast networks may block services outside\n"
"what you chose; `apply' notes how many.  `intel lookup' shows where an\n"
"address is registered and which network owns it.  Linux only: on\n"
"Windows 1.0.7 does not have it.\n"
"\n"
"Exit status: 0 done, 1 failed (update: a feed or the location database\n"
"failed or was refused; geo search: no database yet; apply: the kernel\n"
"refused; geo on Windows), 2 usage (unknown id, terms not accepted),\n"
"3 needs root, 5 lookup: a list blocks the address.  Audit-only mode\n"
"holds `apply' (exit 0, nothing loaded).  `clear', like `stockfw stop',\n"
"is not held.  `apply' and `clear' need root.\n" },

	{ "dashboard", fs_cli_cmd_dashboard,
"Usage: stockfw dashboard [--port N] [--no-open] [--json]\n"
"\n"
"Serves a live dashboard -- status, the Policy activity and Network I/O\n"
"graphs, recent events, connections, the policy, the threat-intel\n"
"blocklists and the what-if simulator -- and opens it in your browser.\n"
"\n"
"Security: it listens on 127.0.0.1 only, every API call needs a token\n"
"generated for this run (it is in the URL printed at start), requests\n"
"for any other Host are refused, and the API is read-only: changing\n"
"the firewall stays with `stockfw apply' and the desktop app.  Under\n"
"sudo the browser is not started as root; open the printed URL\n"
"yourself.  Stop it with Ctrl-C.\n" },
};

const gchar *
fs_cli_command_help (const gchar *command)
{
	if (command == NULL)
		return main_help;

	if (strcmp (command, "net") == 0)
		command = "interfaces";

	for (guint i = 0; i < G_N_ELEMENTS (commands); i++)
		if (strcmp (commands[i].name, command) == 0)
			return commands[i].help;

	return NULL;
}

/* [ want_color ] */
static gboolean
want_color (gboolean disabled)
{
	const gchar *term = g_getenv ("TERM");

	if (disabled || g_getenv ("NO_COLOR") != NULL)
		return FALSE;
	if (term != NULL && strcmp (term, "dumb") == 0)
		return FALSE;

	return isatty (STDOUT_FILENO) && isatty (STDERR_FILENO);
}

int
main (int argc, char *argv[])
{
	gboolean no_color = FALSE, want_help = FALSE, want_version = FALSE;
	GPtrArray *rest;
	const gchar *command;
	gint status;

	setlocale (LC_ALL, "");

	/* Global flags may appear anywhere; everything else is passed to
	 * the command in order.  "--" ends option scanning, so a policy
	 * comment or a what-if line may start with a dash. */
	rest = g_ptr_array_new ();
	for (gint i = 1; i < argc; i++) {
		const gchar *a = argv[i];

		if (strcmp (a, "--") == 0) {
			for (gint j = i; j < argc; j++)
				g_ptr_array_add (rest, argv[j]);
			break;
		} else if (strcmp (a, "--json") == 0) {
			fs_cli.json = TRUE;
		} else if (strcmp (a, "--no-color") == 0 ||
		           strcmp (a, "--no-colour") == 0) {
			no_color = TRUE;
		} else if (strcmp (a, "-q") == 0 || strcmp (a, "--quiet") == 0) {
			fs_cli.quiet = TRUE;
		} else if (strcmp (a, "-h") == 0 || strcmp (a, "--help") == 0) {
			want_help = TRUE;
		} else if (strcmp (a, "-V") == 0 || strcmp (a, "--version") == 0) {
			want_version = TRUE;
		} else {
			g_ptr_array_add (rest, argv[i]);
		}
	}

	fs_cli.color = want_color (no_color || fs_cli.json);
	command = rest->len > 0 ? g_ptr_array_index (rest, 0) : NULL;

	if (want_version || g_strcmp0 (command, "version") == 0) {
		if (fs_cli.json) {
			printf ("{\"version\":\"%s\",\"backend\":\"%s\"}\n",
			        FS_VERSION, fs_backend ()->name);
		} else {
			printf ("stockfw %s (%s)\n", FS_VERSION,
			        fs_backend ()->display_name);
		}
		g_ptr_array_unref (rest);
		return FS_EXIT_OK;
	}

	if (g_strcmp0 (command, "help") == 0) {
		const gchar *topic = rest->len > 1 ? g_ptr_array_index (rest, 1)
		                                   : NULL;
		const gchar *text = fs_cli_command_help (topic);

		g_ptr_array_unref (rest);
		if (text == NULL) {
			fs_cli_error ("no such command: %s", topic);
			fs_cli_hint ("run `stockfw help' for the list");
			return FS_EXIT_USAGE;
		}
		fputs (text, stdout);
		return FS_EXIT_OK;
	}

	if (command == NULL) {
		g_ptr_array_unref (rest);
		fputs (main_help, want_help ? stdout : stderr);
		return want_help ? FS_EXIT_OK : FS_EXIT_USAGE;
	}

	if (strcmp (command, "net") == 0)
		command = "interfaces";

	for (guint i = 0; i < G_N_ELEMENTS (commands); i++) {
		if (strcmp (commands[i].name, command) != 0)
			continue;

		if (want_help) {
			fputs (commands[i].help, stdout);
			g_ptr_array_unref (rest);
			return FS_EXIT_OK;
		}

		/* Preferences (audit-only mode, Advanced Options) are the
		 * desktop app's; read them, never write them from here. */
		fs_prefs_load ();

		g_ptr_array_add (rest, NULL);
		status = commands[i].run ((gint) rest->len - 1,
		                          (gchar **) rest->pdata);
		g_ptr_array_unref (rest);
		fflush (stdout);
		return status;
	}

	fs_cli_error ("unknown command: %s", command);
	fs_cli_hint ("run `stockfw help' for the list of commands");
	g_ptr_array_unref (rest);
	return FS_EXIT_USAGE;
}
