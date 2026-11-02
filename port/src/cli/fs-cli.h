/*---[ fs-cli.h ]--------------------------------------------------------
 * The `stockfw' command-line tool: shared declarations.
 *
 * The CLI is a second front end over the same engine as the desktop
 * app -- fs-core plus the platform backend, no GTK -- so a rule added
 * here is the rule the Policy page shows, a what-if answered here is
 * the verdict the Copilot page gives, and every apply goes through the
 * same gate (fs_policy_apply_safe) with the same audit line.
 *
 * Output contract:
 *   - human output on stdout, diagnostics on stderr, prefixed
 *     "stockfw: error:" / "stockfw: hint:";
 *   - --json on any command prints one JSON document (or, for
 *     `events --follow', one JSON object per line);
 *   - colour only when stdout is a terminal, and never with NO_COLOR
 *     set or --no-color given;
 *   - exit codes are stable and documented in `stockfw help'.
 *--------------------------------------------------------------------*/
#ifndef FS_CLI_H
#define FS_CLI_H

#include <glib.h>
#include "core/fs-backend.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

#ifndef FS_VERSION
#define FS_VERSION "1.0.6"
#endif

/* Where the blocklists are enforced, and how a command gets the rights
 * to change them, in the words of the platform this is built for (every
 * command's text, fs-cli-cmds.c and fs-cli-intel.c; review T5).  The
 * CLI is built on Linux only (CMakeLists.txt), but its text must stay
 * true if it is built elsewhere: on Windows the rules are Windows
 * Firewall rules and there is no sudo (an elevated prompt instead). */
#ifdef __linux__
#define FS_CLI_LIVE      "the kernel"
#define FS_CLI_LIVE_CAP  "The kernel"
#define FS_CLI_SUDO      "sudo "
#define FS_CLI_RIGHTS    "run it with sudo"
#elif defined G_OS_WIN32
#define FS_CLI_LIVE      "Windows Firewall"
#define FS_CLI_LIVE_CAP  "Windows Firewall"
#define FS_CLI_SUDO      ""
#define FS_CLI_RIGHTS    "run it from a prompt opened as administrator"
#else
#define FS_CLI_LIVE      "the firewall"
#define FS_CLI_LIVE_CAP  "The firewall"
#define FS_CLI_SUDO      ""
#define FS_CLI_RIGHTS    "run it with administrator rights"
#endif

/* Exit codes. */
enum
{
	FS_EXIT_OK        = 0,
	FS_EXIT_FAILURE   = 1,
	FS_EXIT_USAGE     = 2,
	FS_EXIT_NEED_ROOT = 3,
	FS_EXIT_BLOCKED   = 5    /* simulate: the traffic would be blocked;
	                          * intel lookup: a list blocks the address */
};

/* Global output switches, set once by main. */
typedef struct
{
	gboolean json;
	gboolean color;
	gboolean quiet;
} FsCliOptions;

extern FsCliOptions fs_cli;

/* ------------------------------------------------------------ output */

void fs_cli_error (const gchar *format, ...) G_GNUC_PRINTF (1, 2);
void fs_cli_hint  (const gchar *format, ...) G_GNUC_PRINTF (1, 2);

/* ANSI styling that collapses to "" when colour is off. */
const gchar *fs_cli_bold  (void);
const gchar *fs_cli_dim   (void);
const gchar *fs_cli_red   (void);
const gchar *fs_cli_green (void);
const gchar *fs_cli_amber (void);
const gchar *fs_cli_reset (void);

/* "1.5 MB", "640 B" -- decimal units, like the Status page. */
gchar *fs_cli_format_bytes (guint64 bytes);
gchar *fs_cli_format_rate  (gdouble bytes_per_second);

/* A plain-text table: columns sized to their widest cell (by
 * character, not byte), the last column left ragged, cells longer
 * than max_width cut with an ellipsis.  rows is a GPtrArray of
 * gchar** (each n_cols long). */
void fs_cli_table (const gchar * const *headers, guint n_cols,
                   GPtrArray *rows, guint max_width);

/* Print a finished JSON document followed by a newline. */
void fs_cli_print_json (GString *json);

/* --------------------------------------------------------- the engine */

/* The policy on disk (the rules directory both front ends share).
 * Sets *on_disk to FALSE when no rule file exists yet. */
FsPolicy *fs_cli_load_policy (gboolean *on_disk, gint *malformed);

/* Command-line names for rule kinds: "inbound-allow-service" ... */
const gchar *fs_cli_kind_name  (FsRuleKind kind);
gboolean     fs_cli_kind_parse (const gchar *name, FsRuleKind *kind);

/* A rule's fields in CSV order, for display. */
gchar *fs_cli_rule_summary (const FsRule *rule);

/* The last `max_lines' lines of the kernel log that carry our marker,
 * parsed, named and marked: $STOCKFW_LOG_FILE, /var/log/kern.log, or
 * the journal.  Returns a GPtrArray of FsHit* (oldest first), or NULL
 * with *error set when no source could be read.  complete_from, when
 * given, receives the unix time of the first stamped line read: from
 * then on the record is complete, so "no event" there is a real zero.
 * It is 0 when nothing stamped was read. */
GPtrArray *fs_cli_log_history (guint max_lines, gint64 *complete_from,
                               GError **error);

/* The uniform refusal for a command that needs root: prints the
 * error and a sudo hint, returns FS_EXIT_NEED_ROOT. */
gint fs_cli_need_root (const gchar *what);

/* Threat intel (fs-cli-intel.c), for `stockfw status' and the
 * dashboard: one JSON object {state, detail, master, hold, lists[]}
 * (lists: the sources turned on, when with_sources), and the status
 * line "  Threat intel  enforced  (...)".  Neither creates the store. */
void fs_cli_intel_json        (GString *out, gboolean with_sources);
void fs_cli_intel_status_line (void);

/* ---------------------------------------------------------- commands */

typedef gint (*FsCliCommand) (gint argc, gchar **argv);

gint fs_cli_cmd_status      (gint argc, gchar **argv);
gint fs_cli_cmd_policy      (gint argc, gchar **argv);
gint fs_cli_cmd_apply       (gint argc, gchar **argv);
gint fs_cli_cmd_start       (gint argc, gchar **argv);
gint fs_cli_cmd_stop        (gint argc, gchar **argv);
gint fs_cli_cmd_simulate    (gint argc, gchar **argv);
gint fs_cli_cmd_events      (gint argc, gchar **argv);
gint fs_cli_cmd_connections (gint argc, gchar **argv);
gint fs_cli_cmd_interfaces  (gint argc, gchar **argv);
gint fs_cli_cmd_dashboard   (gint argc, gchar **argv);
gint fs_cli_cmd_intel       (gint argc, gchar **argv);

/* Per-command help text (NULL for an unknown command). */
const gchar *fs_cli_command_help (const gchar *command);

G_END_DECLS

#endif /* FS_CLI_H */
