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
 *   - colour only when stdout is a terminal (stderr's own colour when
 *     stderr is one), and never with NO_COLOR set, --no-color or
 *     --color=never given; --color=always forces it;
 *   - "--" ends the global options: what follows goes to the command
 *     as plain words, and the value of an option that takes one is
 *     never read as a global flag;
 *   - text from outside (comments, names, log fields) is printed
 *     through fs_cli_out_safe, so it cannot steer the terminal;
 *   - exit codes are stable and documented in `stockfw help'.
 *
 * Files: fs-cli-main.c (the parser and help), fs-cli-out.c (output
 * helpers), fs-cli-cmds.c (helpers the commands share), and one file
 * per group of commands, each exporting its own command table.
 *--------------------------------------------------------------------*/
#ifndef FS_CLI_H
#define FS_CLI_H

#include <glib.h>
#include "core/fs-backend.h"
#include "core/fs-rules.h"
#include "core/fs-whatif.h"

G_BEGIN_DECLS

#ifndef FS_VERSION
#define FS_VERSION "1.0.7"
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
	FS_EXIT_BLOCKED   = 5,   /* simulate: the traffic would be blocked;
	                          * intel lookup: a list blocks the address */
	FS_EXIT_DEPENDS   = 6,   /* simulate: allowed in some cases, blocked
	                          * in others (never 0: scripts that branch
	                          * on "allowed" must not take it as yes) */
	FS_EXIT_FINDINGS  = 7    /* copilot health: the check found something */
};

/* Global output switches, set once by main. */
typedef struct
{
	gboolean json;
	gboolean color;          /* colour on stdout                        */
	gboolean quiet;
	gboolean color_err;      /* colour on stderr (errors and hints)     */
	gboolean plain;          /* --plain / -H: tab-separated, no header  */
	gboolean full;           /* --full / -l: never cut a cell           */
	gboolean utc;            /* times as ISO-8601 UTC (commands set it) */
	/* The command line as the command sees it: argv[0] is the command
	 * name and "--" is dropped; positional_from is the index where the
	 * words after "--" start (G_MAXINT when there was none). */
	gint         argc;
	gchar      **argv;
	gint         positional_from;
	const gchar *command;    /* the command's name: "policy"           */
	/* The user's own arguments (main's argv without the program), for
	 * hints that repeat them. */
	gint         user_argc;
	gchar      **user_argv;
} FsCliOptions;

extern FsCliOptions fs_cli;

/* ------------------------------------------------------------ output */

/* Both make the text safe for a terminal (fs_cli_out_safe, line breaks
 * kept).  Hints are left out under -q. */
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

/* fs_cli_table_ex (headers, n_cols, rows, max_width, -1).  rows is a
 * GPtrArray of gchar** (each n_cols long). */
void fs_cli_table (const gchar * const *headers, guint n_cols,
                   GPtrArray *rows, guint max_width);

/* Print a finished JSON document followed by a newline. */
void fs_cli_print_json (GString *json);

/* --------------------------------------------------------- the engine */

/* The policy on disk (the rules directory both front ends share).
 * Sets *on_disk to FALSE when no rule file exists yet. */
FsPolicy *fs_cli_load_policy (gboolean *on_disk, gint *malformed);

/* One What-If line answered against the saved policy and Firewall
 * preferences, with what the backend can tell about the firewall
 * (unknown without root) and whether the policy is the applied one.
 * assume_running answers as if the firewall ran.  Never NULL; free
 * with fs_whatif_result_free. */
FsWhatIfResult *fs_cli_whatif (const gchar *line, gboolean assume_running);

/* The same against any policy (the saved one, the applied one, one
 * about to be applied); fs_cli_whatif is this with the saved policy. */
FsWhatIfResult *fs_cli_whatif_policy (const FsPolicy *policy,
                                      const gchar *line,
                                      gboolean assume_running);

/* The answer as one JSON object: the flat fields the dashboard reads
 * (verdict, direction, protocol, port, remote, rule, reason,
 * suggestion) and every direction in full (trace, cases, actions). */
void fs_cli_whatif_json (GString *out, const FsWhatIfResult *result,
                         const gchar *input);

/* Command-line names for rule kinds: "inbound-allow-service" ... */
const gchar *fs_cli_kind_name  (FsRuleKind kind);
gboolean     fs_cli_kind_parse (const gchar *name, FsRuleKind *kind);
/* Every kind name, in kind order (FS_RULE_N_KINDS of them). */
const gchar * const *fs_cli_kind_names (void);

/* A rule's fields in CSV order, for display. */
gchar *fs_cli_rule_summary (const FsRule *rule);

/* Rule references: "inbound-allow-service:3", 1-based, numbered as in
 * `policy list'.  Input also takes "KIND#N", and "KIND N" as two words
 * (next_arg is then N, and *used_next is set). */
gchar   *fs_cli_rule_ref       (FsRuleKind kind, guint number);
gboolean fs_cli_rule_ref_parse (const gchar *text, const gchar *next_arg,
                                FsRuleKind *kind, guint *number,
                                gboolean *used_next);

/* Is the saved policy the one that is live? */
typedef enum
{
	FS_CLI_LIVE_SAME,        /* the journal holds the saved rows        */
	FS_CLI_LIVE_PENDING,     /* saved changes are not applied yet       */
	FS_CLI_LIVE_NO_JOURNAL,  /* nothing was ever applied                */
	FS_CLI_LIVE_STOPPED,     /* as root: the firewall is stopped        */
	FS_CLI_LIVE_UNKNOWN      /* the journal cannot be read              */
} FsCliLive;

/* "same", "pending", "no_journal", "stopped", "unknown". */
const gchar *fs_cli_live_name (FsCliLive live);

/* The apply journal compared with `saved'.  applied_out (nullable)
 * receives the journal's policy when it was read (fs_policy_free);
 * settings_pending (nullable) whether saved firewall settings are not
 * applied yet.  STOPPED only as root and only when the backend reads
 * the firewall as stopped; UNKNOWN when the journal cannot be read. */
FsCliLive fs_cli_policy_state (const FsPolicy *saved,
                               FsPolicy **applied_out,
                               gboolean *settings_pending);

/* Can this account read the kernel log?  Decided by trying, never by
 * the user id alone: $STOCKFW_LOG_FILE or /var/log/kern.log is
 * opened; the journal counts as readable for root and for members of
 * systemd-journal or adm.  source and problem (nullable) receive the
 * place and, when FALSE, why; g_free them. */
gboolean fs_cli_log_readable (gchar **source, gchar **problem);

/* The last `max_lines' lines of the kernel log that carry our marker,
 * parsed, named and marked: $STOCKFW_LOG_FILE, /var/log/kern.log, or
 * the journal.  Returns a GPtrArray of FsHit* (oldest first), or NULL
 * with *error set when no source could be read.  complete_from, when
 * given, receives the unix time of the first stamped line read: from
 * then on the record is complete, so "no event" there is a real zero.
 * It is 0 when nothing stamped was read. */
GPtrArray *fs_cli_log_history (guint max_lines, gint64 *complete_from,
                               GError **error);

/* The uniform refusal for a command that needs root: prints the error
 * and a hint that repeats the user's own command with sudo and the
 * full path (fs_cli_sudo_hint), returns FS_EXIT_NEED_ROOT. */
gint fs_cli_need_root (const gchar *what);

/* Pieces several commands share (fs-cli-cmds.c). */
guint       fs_cli_policy_total    (const FsPolicy *policy);
/* Hand the backend the policy and the Advanced Options settings, as
 * the app does at start; fs_settings_free the result. */
FsSettings *fs_cli_backend_context (FsPolicy *policy);
/* One event as the 9 cells of the events table (TIME VERDICT DIR
 * SOURCE DESTINATION PORT SERVICE PROTO RULE), IPv6 addresses
 * compressed and every cell safe for a terminal; g_strfreev. */
gchar     **fs_cli_hit_row         (const FsHit *hit);
void        fs_cli_hit_row_json    (GString *out, const FsHit *hit);
/* An event's ISO UTC stamp as local "Nov 03 10:04:37" (ISO UTC when
 * fs_cli.utc is set); the text itself when it cannot be read. */
gchar      *fs_cli_local_time      (const gchar *iso);
/* "a\nb" as ["a","b"]; NULL as []. */
void        fs_cli_append_lines_json (GString *out, const gchar *text);
/* An apply's notes, one amber "note:" line each (none under -q). */
void        fs_cli_print_notes     (const gchar *notes);

/* Threat intel (fs-cli-intel.c), for `stockfw status' and the
 * dashboard: one JSON object {state, detail, master, hold, lists[]}
 * (lists: the sources turned on, when with_sources), and the status
 * line "  Threat intel  enforced  (...)".  Neither creates the store. */
void fs_cli_intel_json        (GString *out, gboolean with_sources);
void fs_cli_intel_status_line (void);

/* ---------------------------------------------------------- commands */

typedef gint (*FsCliCommand) (gint argc, gchar **argv);

/* An option a command takes.  takes_value: the next word is its value,
 * so it is never read as a global flag (`--comment --json' saves the
 * comment "--json").  sub: the subcommand it belongs to, NULL for any.
 * Completion and the man page are made from these tables, and
 * test-core.sh checks them against every fs_cli_take_opt call. */
typedef struct
{
	const gchar *name;
	gboolean     takes_value;
	const gchar *sub;
} FsCliOption;

/* A command, as its file exports it; fs-cli-main.c joins the tables.
 * A table ends with an entry whose name is NULL, and so does opts.
 * alias: a second name ("net"), or NULL. */
typedef struct
{
	const gchar       *name;
	FsCliCommand       run;
	const gchar       *help;
	const FsCliOption *opts;
	const gchar       *alias;
} FsCliCommandDef;

extern const FsCliCommandDef fs_cli_status_commands[];     /* fs-cli-status.c */
extern const FsCliCommandDef fs_cli_policy_commands[];     /* fs-cli-policy.c */
extern const FsCliCommandDef fs_cli_events_commands[];     /* fs-cli-events.c */
extern const FsCliCommandDef fs_cli_views_commands[];      /* fs-cli-views.c  */
extern const FsCliCommandDef fs_cli_intel_commands[];      /* fs-cli-intel.c  */
extern const FsCliCommandDef fs_cli_dashboard_commands[];  /* fs-dashboard.c  */

/* Every command, in the order the tables are joined (*n of them). */
const FsCliCommandDef * const *fs_cli_all_commands (guint *n);
/* A command by its name or alias; NULL when there is none. */
const FsCliCommandDef         *fs_cli_find_command (const gchar *name);

gint fs_cli_cmd_status      (gint argc, gchar **argv);
gint fs_cli_cmd_policy      (gint argc, gchar **argv);
gint fs_cli_cmd_apply       (gint argc, gchar **argv);
gint fs_cli_cmd_start       (gint argc, gchar **argv);
gint fs_cli_cmd_stop        (gint argc, gchar **argv);
gint fs_cli_cmd_simulate    (gint argc, gchar **argv);
gint fs_cli_cmd_copilot     (gint argc, gchar **argv);
gint fs_cli_cmd_events      (gint argc, gchar **argv);
gint fs_cli_cmd_connections (gint argc, gchar **argv);
gint fs_cli_cmd_interfaces  (gint argc, gchar **argv);
gint fs_cli_cmd_dashboard   (gint argc, gchar **argv);
gint fs_cli_cmd_intel       (gint argc, gchar **argv);

/* Help for a topic: the main help for NULL, NULL for an unknown one.
 * Topics are the commands, their aliases, "help" and "version". */
const gchar *fs_cli_command_help (const gchar *command);

/* ----------------------------------------------------------- parsing */

/* TRUE when argv[*i] is `opt', as "--opt V" or "--opt=V" (never once
 * it came after "--"): *value is set and *i moved onto the value.  A
 * missing value prints "stockfw: error: OPT needs a value" and a hint,
 * sets *status to FS_EXIT_USAGE and leaves *value NULL; the caller
 * then returns *status. */
gboolean fs_cli_take_opt (gint argc, gchar **argv, gint *i, const gchar *opt,
                          const gchar **value, gint *status);
/* TRUE when word i of the command's argv came after "--".
 * fs_cli_is_positional_at is the same for a slice of that argv
 * (`policy add' gets argv + 2); FALSE for an argv outside it. */
gboolean fs_cli_is_positional    (gint i);
gboolean fs_cli_is_positional_at (gchar **argv, gint i);
/* TRUE when argv[i] reads as an option: it starts with "-", is longer
 * than "-", and came before "--". */
gboolean fs_cli_is_option_at     (gchar **argv, gint i);
/* "stockfw: error: unknown option for COMMAND: ARG", with "did you
 * mean" from the command's options and a pointer to its help.  The
 * caller returns FS_EXIT_USAGE. */
void     fs_cli_unknown_option (const gchar *command, const gchar *arg);
/* The one candidate closest to `word' (Damerau-Levenshtein distance 2
 * or less), or NULL when none is that close or two are as close. */
const gchar *fs_cli_suggest (const gchar *word,
                             const gchar * const *candidates, guint n);

/* -------------------------------------------- output (fs-cli-out.c) */

/* The terminal's width when stdout is a terminal (TIOCGWINSZ, else
 * $COLUMNS), else 0: no limit, so a pipe gets every character. */
guint  fs_cli_term_width (void);

/* A table.  Columns are as wide as their widest cell, a cell longer
 * than max_cell is cut (0: no cap), and on a terminal the table is
 * fitted to its width: flex_col shrinks first (-1: none), then the
 * widest columns, never below their header.  --full cuts nothing;
 * --plain prints the rows tab-separated with no header.  Every cell
 * goes through fs_cli_out_safe. */
void   fs_cli_table_ex (const gchar * const *headers, guint n_cols,
                        GPtrArray *rows, guint max_cell, gint flex_col);

/* Prose wrapped to the terminal width with a hanging indent of
 * `indent' spaces; a copy of the text when the width is 0. */
gchar *fs_cli_wrap (const gchar *text, guint indent);

/* Text from outside (a comment, a file name, a program name, a log
 * field) made safe to print on a terminal: C0 controls, DEL and bytes
 * that are not UTF-8 become \xNN; C1 controls and the bidi controls
 * (U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069) become
 * \uNNNN.  A backslash is left as it is, so it is idempotent.  NULL
 * gives "".  g_free the result. */
gchar *fs_cli_out_safe (const gchar *text);

/* Symbols, as ASCII when the locale's charset is not UTF-8. */
typedef enum
{
	FS_CLI_SYM_ON,        /* "●" or "*"   */
	FS_CLI_SYM_OFF,       /* "○" or "o"   */
	FS_CLI_SYM_DOWN,      /* "↓" or "v"   */
	FS_CLI_SYM_UP,        /* "↑" or "^"   */
	FS_CLI_SYM_ARROW,     /* "→" or "->"  */
	FS_CLI_SYM_ELLIPSIS,  /* "…" or "..." */
	FS_CLI_SYM_SEP        /* "·" or "-"   */
} FsCliSym;
const gchar *fs_cli_sym (FsCliSym sym);

typedef enum
{
	FS_CLI_TIME_SHORT,    /* "Nov 03 10:04:37", local time            */
	FS_CLI_TIME_FULL,     /* "2026-11-03 10:04:37 CET", local time    */
	FS_CLI_TIME_ISO       /* "2026-11-03T09:04:37Z"; fs_cli.utc forces */
} FsCliTimeStyle;
gchar *fs_cli_time_text (gint64 epoch, FsCliTimeStyle style);

/* "key":"2026-11-03T09:04:37Z","epoch":1793...: a time as both. */
void   fs_json_kv_time (GString *out, const gchar *key, gint64 epoch);

/* A command to paste: "sudo " (when the user is not root), the full
 * path of this program, a space and `args'.  g_free. */
gchar *fs_cli_sudo_hint (const gchar *args);
/* The user's own arguments, each quoted for a shell where needed. */
gchar *fs_cli_user_args (void);

/* --since and --until (either may be NULL, and either result pointer
 * is left alone then) as microseconds, through
 * fs_event_parse_time_spec.  When one cannot be read: an error and a
 * hint, and FALSE. */
gboolean fs_cli_parse_window (const gchar *since, const gchar *until,
                              gint64 *since_us, gint64 *until_us);

/* ----------------------------------------- status (fs-cli-status.c) */

/* What the live event line shows (master plan PR 1, WP-F), read in one
 * go: the readers of `stockfw status' (fs-cli-status.c), each fact
 * read fresh.  fs_cli_status_snapshot_free. */
typedef struct
{
	FsFirewallState state;           /* FS_FW_NONE: unknown (needs root) */
	FsCliLive       live;
	gboolean        settings_pending;
	gboolean        held;            /* audit-only: applies are held     */
	gint64          blocked_today;   /* -1: unknown (nothing readable)   */
	gchar          *sentinel_mode;   /* the preference: "auto", "detect" */
	gint            sentinel_staged; /* rows in Sentinel's state file    */
	gboolean        monitor_readable;
	gchar          *monitor_source;  /* nullable                         */
	gchar          *monitor_problem; /* nullable                         */
} FsCliStatusSnapshot;

FsCliStatusSnapshot *fs_cli_status_snapshot      (void);
void                 fs_cli_status_snapshot_free (FsCliStatusSnapshot *snap);

/* Each package adds its prototypes in its own block. */

/* === WP-B === */
/* The saved policy and the lines of its files that are not rules
 * (problems: FsPolicyProblem*, never NULL; unref it).  Prints nothing:
 * the command says what it does about them. */
FsPolicy *fs_cli_load_policy_report (gboolean *on_disk,
                                     GPtrArray **problems);
/* Each problem as "stockfw: error: PATH:LINE: reason: \"text\"", then
 * one hint, so a command prints them once. */
void      fs_cli_print_problems     (const GPtrArray *problems);
/* A rule as one JSON object: {ref, kind, number, fields{service, port,
 * target, to, to_port}, comment, summary}; number is 1-based. */
void      fs_cli_rule_json          (GString *out, const FsRule *rule,
                                     guint number);
gint      fs_cli_cmd_check          (gint argc, gchar **argv);
/* === end WP-B === */

/* === WP-C === */

/* One audit log entry, "<ISO UTC> | <action> | <detail>" as
 * fs_audit_log writes it (fs-cli-views.c).  origin is "cli" or "gui"
 * where the layout says (the apply gate's lines, threat intel's
 * "source="), else NULL; detail is what follows the origin. */
typedef struct
{
	gint64  epoch;
	gchar  *action;
	gchar  *origin;
	gchar  *detail;
	gchar  *raw;
} FsCliAuditEntry;

void             fs_cli_audit_entry_free (FsCliAuditEntry *e);
/* NULL for a damaged line. */
FsCliAuditEntry *fs_cli_audit_parse_line (const gchar *line);
/* Every good entry of the file, oldest first; lines_total counts the
 * lines that are not empty, bad_lines those that did not read.  NULL
 * with error when the file cannot be read. */
GPtrArray       *fs_cli_audit_read       (const gchar *path,
                                          guint *lines_total,
                                          guint *bad_lines,
                                          GError **error);
/* The newest apply, start or stop entry of fs_audit_path(), or NULL. */
FsCliAuditEntry *fs_cli_audit_last_apply (void);
/* {"time","epoch","action","origin","detail"[,"raw"]} */
void             fs_cli_audit_entry_json (GString *out,
                                          const FsCliAuditEntry *e,
                                          gboolean with_raw);

/* One row of Sentinel's state file, "S,<epoch>,<kind>,<csv>".  rule is
 * NULL when the csv does not read. */
typedef struct
{
	gint64      epoch;
	FsRuleKind  kind;
	gchar      *csv;
	FsRule     *rule;
} FsCliSentinelBlock;

void       fs_cli_sentinel_block_free (FsCliSentinelBlock *b);
/* The rows of the file at path (read only, never rewritten); NULL with
 * error when it cannot be read (G_FILE_ERROR_NOENT: nothing staged). */
GPtrArray *fs_cli_sentinel_read       (const gchar *path, guint *bad_rows,
                                       GError **error);
/* How many blocks fs_autoblock_state_path() holds, and the next time
 * one lifts (0: none to come). */
gint       fs_cli_sentinel_staged     (gint64 *next_lift);
/* Sentinel's staged outbound blocks that are still in `policy', given
 * to the What-If engine with the time each lifts. */
void       fs_cli_sentinel_whatif     (FsWhatIfContext *ctx,
                                       const FsPolicy *policy);

/* Blocked events since local midnight (fs-cli-status.c): from the
 * saved event history when it is kept, else from the kernel log.
 * -1 when neither can be read.  last_block (nullable) receives a copy
 * of the newest one (fs_hit_free); source (nullable) "history" or
 * "kernel_log". */
gint64     fs_cli_blocked_today       (FsHit **last_block,
                                       const gchar **source);

/* === end WP-C === */

/* === WP-D === */
/* === end WP-D === */

/* === WP-F === */
/* === end WP-F === */

/* === WP-E === */
/* === end WP-E === */

G_END_DECLS

#endif /* FS_CLI_H */
