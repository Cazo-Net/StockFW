/*---[ fs-cli-cmds.c ]---------------------------------------------------
 * The `stockfw' commands, except the dashboard (fs-dashboard.c).
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-apply.h"
#include "core/fs-copilot.h"
#include "core/fs-service.h"
#include "core/fs-json.h"
#include "core/fs-netparse.h"
#include "core/fs-script.h"
#include "core/fs-util.h"

#include <glib-unix.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------- helpers */

static const gchar *kind_names[FS_RULE_N_KINDS] = {
	"inbound-allow-from",
	"inbound-allow-service",
	"inbound-forward",
	"outbound-allow-to",
	"outbound-allow-from",
	"outbound-allow-service",
	"outbound-deny-to",
	"outbound-deny-from",
	"outbound-deny-service",
};

const gchar *
fs_cli_kind_name (FsRuleKind kind)
{
	return (kind >= 0 && kind < FS_RULE_N_KINDS) ? kind_names[kind] : "?";
}

gboolean
fs_cli_kind_parse (const gchar *name, FsRuleKind *kind)
{
	for (gint i = 0; i < FS_RULE_N_KINDS; i++) {
		if (g_strcmp0 (name, kind_names[i]) == 0) {
			*kind = (FsRuleKind) i;
			return TRUE;
		}
	}

	return FALSE;
}

/* [ kind_field_count ] -- fields before the comment, per kind. */
static gint
kind_field_count (FsRuleKind kind)
{
	gint n = 0;

	fs_rule_columns (kind, &n);
	return n - 1;
}

gchar *
fs_cli_rule_summary (const FsRule *rule)
{
	switch (rule->kind) {
	case FS_RULE_INBOUND_FORWARD:
		/* [addr]:port for IPv6, as DNAT writes it: 2001:db8::5:80
		 * reads as a different address. */
		return g_strdup_printf ("%s  port %s -> %s%s%s:%s",
		                        rule->service ? rule->service : "?",
		                        rule->port ? rule->port : "?",
		                        fs_util_target_families (rule->to) ==
		                            FS_FAMILY_IPV6 ? "[" : "",
		                        rule->to ? rule->to : "?",
		                        fs_util_target_families (rule->to) ==
		                            FS_FAMILY_IPV6 ? "]" : "",
		                        rule->to_port ? rule->to_port : "?");
	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		return g_strdup_printf ("%s  port %s  for %s",
		                        rule->service ? rule->service : "?",
		                        rule->port ? rule->port : "?",
		                        rule->target ? rule->target : "?");
	default:
		return g_strdup (rule->target ? rule->target : "?");
	}
}

FsPolicy *
fs_cli_load_policy (gboolean *on_disk, gint *malformed)
{
	FsPolicy *policy = fs_policy_new ();
	gint bad = 0;
	gboolean any = fs_policy_load (policy, &bad);

	if (on_disk != NULL)
		*on_disk = any;
	if (malformed != NULL)
		*malformed = bad;

	return policy;
}

/* [ need_root ] -- the uniform refusal for privileged commands. */
static gint
need_root (const gchar *what)
{
	fs_cli_error ("%s needs root privileges", what);
	fs_cli_hint ("run it with sudo, e.g. `sudo stockfw %s'", what);
	return FS_EXIT_NEED_ROOT;
}

/* [ backend_context ]
 * The Linux backend builds iptables rules from the policy and the
 * Advanced Options settings; hand it both, as the app does at start. */
static FsSettings *
backend_context (FsPolicy *policy)
{
	FsSettings *settings = fs_settings_new ();

	fs_settings_load_prefs (settings);
	fs_backend_set_context (policy, settings);

	return settings;
}

static guint
policy_total (const FsPolicy *policy)
{
	guint total = 0;

	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		total += fs_policy_count (policy, (FsRuleKind) k);

	return total;
}

/* [ hit_row_json ] -- one event as a JSON object. */
static void
hit_row_json (GString *out, const FsHit *hit)
{
	gchar *service = fs_hit_service_name (hit);

	g_string_append_c (out, '{');
	fs_json_kv_str (out, "time", hit->time);             g_string_append_c (out, ',');
	fs_json_kv_str (out, "direction", hit->direction);   g_string_append_c (out, ',');
	fs_json_kv_str (out, "source", hit->source);         g_string_append_c (out, ',');
	fs_json_kv_str (out, "destination", hit->destination); g_string_append_c (out, ',');
	fs_json_kv_str (out, "port", hit->port);             g_string_append_c (out, ',');
	fs_json_kv_str (out, "protocol", hit->protocol);     g_string_append_c (out, ',');
	fs_json_kv_str (out, "service", service);            g_string_append_c (out, ',');
	fs_json_kv_str (out, "in", hit->in);                 g_string_append_c (out, ',');
	fs_json_kv_str (out, "out", hit->out);               g_string_append_c (out, ',');
	fs_json_kv_bool (out, "blocked", fs_hit_is_blocked (hit));
	g_string_append_c (out, '}');
	g_free (service);
}

/* [ local_time ] -- an event's ISO UTC stamp in local time. */
static gchar *
local_time (const gchar *iso)
{
	GDateTime *utc, *local;
	gchar *text;

	if (iso == NULL)
		return g_strdup ("");

	utc = g_date_time_new_from_iso8601 (iso, NULL);
	if (utc == NULL)
		return g_strdup (iso);

	local = g_date_time_to_local (utc);
	text  = g_date_time_format (local, "%b %d %H:%M:%S");
	g_date_time_unref (local);
	g_date_time_unref (utc);

	return text;
}

/* [ append_lines_json ] -- "a\nb" as ["a","b"]; NULL as []. */
static void
append_lines_json (GString *out, const gchar *text)
{
	gchar **lines = g_strsplit (text != NULL ? text : "", "\n", -1);
	gboolean first = TRUE;

	g_string_append_c (out, '[');
	for (gint i = 0; lines[i] != NULL; i++) {
		if (*lines[i] == '\0')
			continue;
		if (!first)
			g_string_append_c (out, ',');
		fs_json_string (out, lines[i]);
		first = FALSE;
	}
	g_string_append_c (out, ']');
	g_strfreev (lines);
}

/* [ print_notes ] -- an apply's notes, one amber line each. */
static void
print_notes (const gchar *notes)
{
	gchar **lines;

	if (notes == NULL)
		return;

	lines = g_strsplit (notes, "\n", -1);
	for (gint i = 0; lines[i] != NULL; i++)
		if (*lines[i] != '\0')
			printf ("%snote:%s %s\n", fs_cli_amber (), fs_cli_reset (),
			        lines[i]);
	g_strfreev (lines);
}

/* -------------------------------------------------------------- status */

gint
fs_cli_cmd_status (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	gboolean root = (geteuid () == 0);
	gboolean on_disk;
	gint malformed;
	FsPolicy *policy;
	FsFirewallState state = FS_FW_NONE;
	const gchar *hold = fs_apply_hold_reason ();
	GList *stats = NULL, *conns = NULL;
	const gchar *state_word;
	FsIpv6State ipv6;
	gchar *ipv6_detail = NULL;

	if (argc > 1) {
		fs_cli_error ("status takes no arguments");
		return FS_EXIT_USAGE;
	}

	policy = fs_cli_load_policy (&on_disk, &malformed);

	/* Reading netfilter needs CAP_NET_ADMIN.  Without it the backend
	 * would answer "stopped" for a firewall it could not see; say
	 * "unknown" instead. */
	if (root)
		state = backend->get_state ();

	switch (state) {
	case FS_FW_RUNNING: state_word = "running"; break;
	case FS_FW_STOPPED: state_word = "stopped"; break;
	case FS_FW_LOCKED:  state_word = "locked";  break;
	default:            state_word = "unknown"; break;
	}

	if (backend->list_interface_stats != NULL)
		stats = backend->list_interface_stats ();
	if (backend->list_connections != NULL)
		conns = backend->list_connections ();

	/* IPv6: Linux answers (1.0.7); a backend without the slot covers
	 * both families with every rule (Windows Firewall). */
	if (backend->ipv6_state != NULL) {
		ipv6 = backend->ipv6_state (&ipv6_detail);
	} else {
		ipv6 = FS_IPV6_FILTERED;
		ipv6_detail = g_strdup ("Windows Firewall applies every rule to "
		                        "IPv4 and IPv6.");
	}

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "version", FS_VERSION);       g_string_append_c (out, ',');
		fs_json_kv_str (out, "backend", backend->name);   g_string_append_c (out, ',');
		fs_json_kv_str (out, "state", state_word);        g_string_append_c (out, ',');
		fs_json_key (out, "ipv6");
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "state", fs_ipv6_state_to_string (ipv6));  g_string_append_c (out, ',');
		fs_json_kv_str (out, "detail", ipv6_detail);
		g_string_append (out, "},");
		fs_json_kv_bool (out, "root", root);              g_string_append_c (out, ',');
		fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ()); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "policy_saved", on_disk);   g_string_append_c (out, ',');
		fs_json_kv_int (out, "malformed_rules", malformed); g_string_append_c (out, ',');
		fs_json_key (out, "rules");
		g_string_append_c (out, '{');
		for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
			if (k > 0)
				g_string_append_c (out, ',');
			fs_json_kv_uint (out, fs_cli_kind_name ((FsRuleKind) k),
			                 fs_policy_count (policy, (FsRuleKind) k));
		}
		g_string_append (out, "},");
		fs_json_kv_str (out, "apply_hold", hold);         g_string_append_c (out, ',');
		fs_json_kv_bool (out, "monitoring_available", root); g_string_append_c (out, ',');
		fs_json_kv_uint (out, "connections", g_list_length (conns));
		g_string_append (out, ",\"interfaces\":[");
		for (GList *l = stats; l != NULL; l = l->next) {
			FsIfaceStat *s = l->data;

			if (l != stats)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "device", s->device);   g_string_append_c (out, ',');
			fs_json_kv_str (out, "type", s->kind);       g_string_append_c (out, ',');
			fs_json_kv_str (out, "ip", s->ip);           g_string_append_c (out, ',');
			fs_json_kv_bool (out, "up", s->up);          g_string_append_c (out, ',');
			fs_json_kv_uint (out, "received", s->received); g_string_append_c (out, ',');
			fs_json_kv_uint (out, "sent", s->sent);
			g_string_append_c (out, '}');
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		const gchar *dot, *color;

		if (state == FS_FW_RUNNING) {
			dot = "●"; color = fs_cli_green ();
		} else if (state == FS_FW_STOPPED) {
			dot = "○"; color = fs_cli_red ();
		} else {
			dot = "?"; color = fs_cli_amber ();
		}

		printf ("%sStockFW %s%s  %s%s%s\n\n", fs_cli_bold (), FS_VERSION,
		        fs_cli_reset (), fs_cli_dim (), backend->display_name,
		        fs_cli_reset ());

		printf ("  %-12s %s%s %s%s", "Firewall", color, dot, state_word,
		        fs_cli_reset ());
		if (!root)
			printf ("%s  (reading the firewall needs root)%s",
			        fs_cli_dim (), fs_cli_reset ());
		printf ("\n");

		/* IPv6 gets its own line: "running" says nothing about a
		 * family that passes unfiltered. */
		{
			const gchar *c6 = ipv6 == FS_IPV6_FILTERED ? fs_cli_green ()
			                : ipv6 == FS_IPV6_UNFILTERED ? fs_cli_amber ()
			                : fs_cli_dim ();
			const gchar *w6 = ipv6 == FS_IPV6_FILTERED ? "filtered"
			                : ipv6 == FS_IPV6_UNFILTERED ? "not filtered"
			                : ipv6 == FS_IPV6_ABSENT ? "none on this system"
			                : "unknown";

			printf ("  %-12s %s%s%s", "IPv6", c6, w6, fs_cli_reset ());
			if (ipv6_detail != NULL && ipv6 != FS_IPV6_FILTERED &&
			    ipv6 != FS_IPV6_ABSENT)
				printf ("%s  (%s)%s", fs_cli_dim (), ipv6_detail,
				        fs_cli_reset ());
			printf ("\n");
		}

		if (on_disk) {
			printf ("  %-12s %u rule%s in %s\n", "Policy",
			        policy_total (policy),
			        policy_total (policy) == 1 ? "" : "s",
			        fs_util_rules_dir ());
			for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
				guint n = fs_policy_count (policy, (FsRuleKind) k);

				if (n > 0)
					printf ("  %-12s %s%3u  %s%s\n", "", fs_cli_dim (), n,
					        fs_cli_kind_name ((FsRuleKind) k),
					        fs_cli_reset ());
			}
		} else {
			printf ("  %-12s none saved yet in %s\n", "Policy",
			        fs_util_rules_dir ());
		}

		if (malformed > 0)
			printf ("  %-12s %s%d malformed rule%s skipped%s\n", "",
			        fs_cli_amber (), malformed, malformed == 1 ? "" : "s",
			        fs_cli_reset ());

		printf ("  %-12s %s\n", "Apply mode",
		        hold != NULL ? "audit-only: applies are recorded, the "
		                       "firewall is left untouched"
		                     : "live");

		printf ("  %-12s %s\n", "Monitoring",
		        root ? "available (stockfw events -f, stockfw dashboard)"
		             : "needs root to read the kernel log");

		for (GList *l = stats; l != NULL; l = l->next) {
			FsIfaceStat *s = l->data;
			gchar *rx = fs_cli_format_bytes (s->received);
			gchar *tx = fs_cli_format_bytes (s->sent);

			printf ("  %-12s %-10s %-15s ↓ %s  ↑ %s%s\n",
			        l == stats ? "Adapters" : "", s->device,
			        s->ip ? s->ip : "-", rx, tx,
			        s->up ? "" : "  (down)");
			g_free (rx);
			g_free (tx);
		}

		printf ("  %-12s %u active\n", "Connections", g_list_length (conns));
	}

	g_list_free_full (stats, (GDestroyNotify) fs_iface_stat_free);
	g_list_free_full (conns, (GDestroyNotify) fs_connection_free);
	g_free (ipv6_detail);
	fs_policy_free (policy);

	return FS_EXIT_OK;
}

/* -------------------------------------------------------------- policy */

static gint
policy_list (gint argc, gchar **argv)
{
	FsRuleKind only = FS_RULE_N_KINDS;
	gboolean on_disk;
	gint malformed;
	FsPolicy *policy;
	gboolean names = (fs_backend ()->fw_honors & FS_FWHON_HOST_NAMES) != 0;

	for (gint i = 0; i < argc; i++) {
		if (strcmp (argv[i], "--kind") == 0 && i + 1 < argc) {
			if (!fs_cli_kind_parse (argv[++i], &only)) {
				fs_cli_error ("unknown rule kind: %s", argv[i]);
				fs_cli_hint ("see `stockfw help policy' for the kinds");
				return FS_EXIT_USAGE;
			}
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
	}

	policy = fs_cli_load_policy (&on_disk, &malformed);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "rules_dir", fs_util_rules_dir ());
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "saved", on_disk);
		g_string_append (out, ",\"rules\":[");
		{
			gboolean first = TRUE;

			for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
				GPtrArray *rules = policy->kinds[k];

				if (only != FS_RULE_N_KINDS && (gint) only != k)
					continue;

				for (guint i = 0; i < rules->len; i++) {
					FsRule *r = g_ptr_array_index (rules, i);

					if (!first)
						g_string_append_c (out, ',');
					first = FALSE;
					g_string_append_c (out, '{');
					fs_json_kv_str (out, "kind", fs_cli_kind_name (r->kind)); g_string_append_c (out, ',');
					fs_json_kv_uint (out, "number", i + 1);   g_string_append_c (out, ',');
					fs_json_kv_str (out, "service", r->service); g_string_append_c (out, ',');
					fs_json_kv_str (out, "port", r->port);    g_string_append_c (out, ',');
					fs_json_kv_str (out, "target", r->target); g_string_append_c (out, ',');
					fs_json_kv_str (out, "to", r->to);        g_string_append_c (out, ',');
					fs_json_kv_str (out, "to_port", r->to_port); g_string_append_c (out, ',');
					fs_json_kv_str (out, "comment", r->comment);
					g_string_append_c (out, ',');
					{
						gchar *why = NULL;
						FsFamily fam = fs_rule_coverage (r, names, &why);

						fs_json_key (out, "covers");
						g_string_append_c (out, '[');
						if (fam & FS_FAMILY_IPV4)
							g_string_append (out, "\"ipv4\"");
						if (fam == FS_FAMILY_BOTH)
							g_string_append_c (out, ',');
						if (fam & FS_FAMILY_IPV6)
							g_string_append (out, "\"ipv6\"");
						g_string_append (out, "],");
						fs_json_kv_str (out, "covers_why", why);
						g_free (why);
					}
					g_string_append_c (out, '}');
				}
			}
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
		fs_policy_free (policy);
		return FS_EXIT_OK;
	}

	if (!on_disk) {
		printf ("No policy saved yet in %s.\n", fs_util_rules_dir ());
		printf ("%sAdd a rule with `stockfw policy add', or open the "
		        "desktop app once to seed the defaults.%s\n",
		        fs_cli_dim (), fs_cli_reset ());
		fs_policy_free (policy);
		return FS_EXIT_OK;
	}

	for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
		GPtrArray *rules = policy->kinds[k];

		if (only != FS_RULE_N_KINDS && (gint) only != k)
			continue;
		if (only == FS_RULE_N_KINDS && rules->len == 0)
			continue;

		printf ("%s%s%s %s(%u)%s\n", fs_cli_bold (),
		        fs_cli_kind_name ((FsRuleKind) k), fs_cli_reset (),
		        fs_cli_dim (), rules->len, fs_cli_reset ());

		for (guint i = 0; i < rules->len; i++) {
			FsRule *r = g_ptr_array_index (rules, i);
			gchar *summary = fs_cli_rule_summary (r);

			FsFamily fam = fs_rule_coverage (r, names, NULL);

			printf ("  %3u  %s", i + 1, summary);
			printf ("  %s[%s]%s",
			        fam == FS_FAMILY_NONE ? fs_cli_amber () : fs_cli_dim (),
			        fam == FS_FAMILY_NONE ? "covers nothing"
			                              : fs_util_families_label (fam),
			        fs_cli_reset ());
			if (r->comment != NULL && *r->comment != '\0')
				printf ("  %s# %s%s", fs_cli_dim (), r->comment,
				        fs_cli_reset ());
			printf ("\n");
			g_free (summary);
		}

		if (rules->len == 0)
			printf ("  %s(none)%s\n", fs_cli_dim (), fs_cli_reset ());
	}

	if (policy_total (policy) == 0 && only == FS_RULE_N_KINDS)
		printf ("The policy in %s is empty.\n", fs_util_rules_dir ());

	if (malformed > 0)
		fs_cli_hint ("%d malformed rule%s in %s %s skipped", malformed,
		             malformed == 1 ? "" : "s", fs_util_rules_dir (),
		             malformed == 1 ? "was" : "were");

	fs_policy_free (policy);
	return FS_EXIT_OK;
}

/* [ service_default_port ]
 * The port of a well-known service named case-insensitively ("ssh",
 * "HTTPS"), or NULL when the name is unknown or the service spans
 * several ports (Samba, NFS) -- those need an explicit port. */
static const gchar *
service_default_port (const gchar *name, const gchar **canonical)
{
	guint n = 0;
	const FsService *list = fs_service_user_list (&n);

	for (guint i = 0; i < n; i++) {
		if (g_ascii_strcasecmp (list[i].name, name) != 0)
			continue;

		for (const gchar *p = list[i].ports; *p != '\0'; p++)
			if (!g_ascii_isdigit (*p))
				return NULL;

		*canonical = list[i].name;
		return list[i].ports;
	}

	return NULL;
}

static gint
policy_add (gint argc, gchar **argv)
{
	FsRuleKind kind;
	const gchar *comment = "";
	gboolean both = FALSE;
	GPtrArray *fields;
	gint want;
	FsRule *rule, *twin = NULL;
	FsPolicy *policy;
	gchar *csv, *summary;
	gboolean ok;

	if (argc < 1 || !fs_cli_kind_parse (argv[0], &kind)) {
		fs_cli_error (argc < 1 ? "policy add needs a rule kind"
		                       : "unknown rule kind: %s",
		              argc < 1 ? "" : argv[0]);
		fs_cli_hint ("see `stockfw help policy' for the kinds and their "
		             "fields");
		return FS_EXIT_USAGE;
	}

	want = kind_field_count (kind);
	fields = g_ptr_array_new ();

	for (gint i = 1; i < argc; i++) {
		if (strcmp (argv[i], "--comment") == 0 && i + 1 < argc)
			comment = argv[++i];
		else if (strcmp (argv[i], "--both") == 0)
			both = TRUE;
		else if (argv[i][0] == '-' && argv[i][1] == '-') {
			/* Never let a mistyped option become a rule field. */
			fs_cli_error ("unknown option for policy add: %s%s", argv[i],
			              strcmp (argv[i], "--comment") == 0
			              ? " (it needs a value)" : "");
			fs_cli_hint ("options are --comment TEXT and --both");
			g_ptr_array_unref (fields);
			return FS_EXIT_USAGE;
		} else
			g_ptr_array_add (fields, argv[i]);
	}

	/* "policy add inbound-allow-service SSH": a known single-port
	 * service needs no port, and a missing FOR means anyone -- the
	 * same defaults the desktop app's Add dialog starts from. */
	if (want == 3 && fields->len == 1 && kind != FS_RULE_INBOUND_FORWARD) {
		const gchar *canonical = NULL;
		const gchar *port = service_default_port (
		                        g_ptr_array_index (fields, 0), &canonical);

		if (port == NULL) {
			fs_cli_error ("no single default port for \"%s\"",
			              (const gchar *) g_ptr_array_index (fields, 0));
			fs_cli_hint ("give the port too: stockfw policy add %s %s "
			             "PORT Anyone", argv[0],
			             (const gchar *) g_ptr_array_index (fields, 0));
			g_ptr_array_unref (fields);
			return FS_EXIT_USAGE;
		}
		g_ptr_array_index (fields, 0) = (gpointer) canonical;
		g_ptr_array_add (fields, (gpointer) port);
		g_ptr_array_add (fields, (gpointer) "Anyone");
	}

	if ((gint) fields->len != want) {
		gint n = 0;
		const gchar * const *labels = fs_rule_columns (kind, &n);
		GString *expect = g_string_new (NULL);

		for (gint c = 0; c < want; c++)
			g_string_append_printf (expect, "%s<%s>",
			                        c ? " " : "", labels[c]);

		fs_cli_error ("%s takes %d field%s, got %u", argv[0], want,
		              want == 1 ? "" : "s", fields->len);
		fs_cli_hint ("stockfw policy add %s %s [--comment TEXT]",
		             argv[0], expect->str);
		g_string_free (expect, TRUE);
		g_ptr_array_unref (fields);
		return FS_EXIT_USAGE;
	}

	/* The policy files are comma-separated with no quoting: a comma
	 * inside a field would silently become a field boundary. */
	g_ptr_array_add (fields, (gpointer) comment);
	for (guint i = 0; i < fields->len; i++) {
		const gchar *f = g_ptr_array_index (fields, i);

		if (strpbrk (f, ",\n\r") != NULL) {
			fs_cli_error ("a field may not contain a comma or a line "
			              "break: \"%s\"", f);
			g_ptr_array_unref (fields);
			return FS_EXIT_USAGE;
		}
	}

	g_ptr_array_add (fields, NULL);
	csv = g_strjoinv (",", (gchar **) fields->pdata);
	g_ptr_array_unref (fields);

	rule = fs_rule_from_csv (kind, csv);
	g_free (csv);

	if (rule == NULL || !fs_rule_fields_sane (rule)) {
		fs_cli_error ("not a valid %s rule: check the host, port or "
		              "range", fs_cli_kind_name (kind));
		fs_cli_hint ("hosts are addresses, networks (10.0.0.0/8) or "
		             "\"Anyone\"; ports are 1-65535 or a range 1024:2048");
		fs_rule_free (rule);
		return FS_EXIT_USAGE;
	}

	if (both) {
		twin = fs_rule_counterpart (rule);
		if (twin == NULL) {
			fs_cli_error ("%s has no opposite-direction twin; --both "
			              "only applies to allow rules",
			              fs_cli_kind_name (kind));
			fs_rule_free (rule);
			return FS_EXIT_USAGE;
		}
	}

	policy = fs_cli_load_policy (NULL, NULL);
	summary = fs_cli_rule_summary (rule);

	if (fs_policy_contains (policy, rule) &&
	    (twin == NULL || fs_policy_contains (policy, twin))) {
		if (!fs_cli.quiet)
			printf ("Already in the policy: %s %s\n",
			        fs_cli_kind_name (kind), summary);
		fs_rule_free (rule);
		fs_rule_free (twin);
		g_free (summary);
		fs_policy_free (policy);
		return FS_EXIT_OK;
	}

	/* Ownership passes to the policy on success; on failure the store
	 * is put back and the rules are ours to free. */
	if (twin != NULL)
		ok = fs_policy_add_persist_pair (policy, rule, twin);
	else
		ok = fs_policy_add_persist (policy, rule);

	if (!ok) {
		fs_cli_error ("could not save the policy in %s",
		              fs_util_rules_dir ());
		if (geteuid () != 0 &&
		    g_str_has_prefix (fs_util_rules_dir (), "/etc"))
			fs_cli_hint ("%s is root's; run with sudo",
			             fs_util_rules_dir ());
		g_free (summary);
		fs_policy_free (policy);
		return FS_EXIT_FAILURE;
	}

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "added", TRUE);           g_string_append_c (out, ',');
		fs_json_kv_str (out, "kind", fs_cli_kind_name (kind)); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "both_directions", twin != NULL); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "applied", FALSE);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		printf ("%s+%s %s %s%s\n", fs_cli_green (), fs_cli_reset (),
		        fs_cli_kind_name (kind), summary,
		        twin != NULL ? "  (and its opposite direction)" : "");
		printf ("%sSaved in %s.  Not live yet: run `sudo stockfw apply'.%s\n",
		        fs_cli_dim (), fs_util_rules_dir (), fs_cli_reset ());
	}

	g_free (summary);
	fs_policy_free (policy);
	return FS_EXIT_OK;
}

static gint
policy_remove (gint argc, gchar **argv)
{
	FsRuleKind kind;
	FsPolicy *policy;
	gchar *end = NULL;
	guint64 n;
	FsRule *rule, *copy;
	gchar *summary;

	if (argc != 2 || !fs_cli_kind_parse (argv[0], &kind)) {
		fs_cli_error ("usage: stockfw policy remove KIND N");
		fs_cli_hint ("`stockfw policy list --kind KIND' shows the numbers");
		return FS_EXIT_USAGE;
	}

	n = g_ascii_strtoull (argv[1], &end, 10);
	policy = fs_cli_load_policy (NULL, NULL);

	if (end == NULL || *end != '\0' || n == 0 ||
	    n > policy->kinds[kind]->len) {
		fs_cli_error ("%s has no rule number %s (it has %u)",
		              fs_cli_kind_name (kind), argv[1],
		              policy->kinds[kind]->len);
		fs_policy_free (policy);
		return FS_EXIT_USAGE;
	}

	rule = g_ptr_array_index (policy->kinds[kind], n - 1);
	copy = fs_rule_copy (rule);
	summary = fs_cli_rule_summary (copy);

	if (!fs_policy_remove_persist (policy, copy)) {
		fs_cli_error ("could not save the policy in %s",
		              fs_util_rules_dir ());
		fs_rule_free (copy);
		g_free (summary);
		fs_policy_free (policy);
		return FS_EXIT_FAILURE;
	}

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "removed", TRUE); g_string_append_c (out, ',');
		fs_json_kv_str (out, "kind", fs_cli_kind_name (kind));
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		printf ("%s-%s %s %s\n", fs_cli_red (), fs_cli_reset (),
		        fs_cli_kind_name (kind), summary);
		printf ("%sSaved.  Not live yet: run `sudo stockfw apply'.%s\n",
		        fs_cli_dim (), fs_cli_reset ());
	}

	fs_rule_free (copy);
	g_free (summary);
	fs_policy_free (policy);
	return FS_EXIT_OK;
}

gint
fs_cli_cmd_policy (gint argc, gchar **argv)
{
	const gchar *sub = argc > 1 ? argv[1] : "list";

	if (strcmp (sub, "list") == 0 || strcmp (sub, "ls") == 0)
		return policy_list (argc > 1 ? argc - 2 : 0, argv + 2);
	if (strcmp (sub, "add") == 0)
		return policy_add (argc - 2, argv + 2);
	if (strcmp (sub, "remove") == 0 || strcmp (sub, "rm") == 0)
		return policy_remove (argc - 2, argv + 2);

	if (g_str_has_prefix (sub, "--"))
		return policy_list (argc - 1, argv + 1);

	fs_cli_error ("unknown policy action: %s", sub);
	fs_cli_hint ("policy list | policy add | policy remove");
	return FS_EXIT_USAGE;
}

/* --------------------------------------------------------------- apply */

gint
fs_cli_cmd_apply (gint argc, gchar **argv)
{
	gboolean dry_run = FALSE;
	FsPolicy *policy;
	FsSettings *settings;
	FsApplyOutcome *outcome;
	GError *error = NULL;
	gboolean on_disk;
	gint status;
	gchar *desc;

	for (gint i = 1; i < argc; i++) {
		if (strcmp (argv[i], "--dry-run") == 0 ||
		    strcmp (argv[i], "-n") == 0) {
			dry_run = TRUE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
	}

	policy = fs_cli_load_policy (&on_disk, NULL);

	if (!on_disk) {
		fs_cli_error ("no policy saved in %s -- nothing to apply",
		              fs_util_rules_dir ());
		if (geteuid () == 0 && g_getenv ("SUDO_USER") != NULL)
			fs_cli_hint ("as root the policy is read from /etc/stockfw; "
			             "a policy edited without sudo lives in "
			             "~/.stockfw");
		fs_policy_free (policy);
		return FS_EXIT_FAILURE;
	}

	if (dry_run) {
		FsPolicyImpact *impact = fs_policy_impact_preview (policy);

		desc = fs_policy_impact_describe (impact);
		if (fs_cli.json) {
			GString *out = g_string_new ("{");

			fs_json_kv_bool (out, "dry_run", TRUE);       g_string_append_c (out, ',');
			fs_json_kv_uint (out, "added", impact->added); g_string_append_c (out, ',');
			fs_json_kv_uint (out, "removed", impact->removed); g_string_append_c (out, ',');
			fs_json_kv_uint (out, "unchanged", impact->unchanged); g_string_append_c (out, ',');
			fs_json_kv_str (out, "impact", desc);
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else {
			printf ("Would apply: %s\n", desc);
			printf ("%sNothing was changed (dry run).%s\n",
			        fs_cli_dim (), fs_cli_reset ());
		}
		g_free (desc);
		fs_policy_impact_free (impact);
		fs_policy_free (policy);
		return FS_EXIT_OK;
	}

	if (geteuid () != 0) {
		fs_policy_free (policy);
		return need_root ("apply");
	}

	settings = backend_context (policy);
	outcome = fs_policy_apply_safe (fs_backend (), policy, "cli",
	                                fs_apply_hold_reason (), &error);
	desc = fs_policy_impact_describe (outcome->impact);

	if (outcome->held) {
		status = FS_EXIT_OK;
	} else if (outcome->result == FS_APPLY_OK) {
		status = FS_EXIT_OK;
	} else if (outcome->result == FS_APPLY_NO_PRIVILEGE) {
		status = FS_EXIT_NEED_ROOT;
	} else {
		status = FS_EXIT_FAILURE;
	}

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "applied", outcome->applied);   g_string_append_c (out, ',');
		fs_json_kv_bool (out, "held", outcome->held);         g_string_append_c (out, ',');
		fs_json_kv_str (out, "hold_reason", outcome->hold_reason); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "narrow", outcome->narrow);     g_string_append_c (out, ',');
		fs_json_kv_str (out, "result",
		                fs_util_apply_result_to_string ((int) outcome->result));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "impact", desc);                 g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", error ? error->message : NULL); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "rollback_attempted", outcome->rollback_attempted); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "rollback_verified", outcome->rollback_verified);
		g_string_append_c (out, ',');
		fs_json_key (out, "notes");
		append_lines_json (out, outcome->notes);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (outcome->held) {
		printf ("%sHeld:%s %s.  The firewall was left untouched.\n",
		        fs_cli_amber (), fs_cli_reset (), outcome->hold_reason);
		printf ("Recorded in the audit log: %s\n", desc);
	} else if (outcome->result == FS_APPLY_OK) {
		if (outcome->impact->added == 0 && outcome->impact->removed == 0)
			printf ("Nothing to change: the policy already matches the "
			        "firewall.\n");
		else
			printf ("%sApplied%s (%s): %s\n", fs_cli_green (),
			        fs_cli_reset (),
			        outcome->narrow ? "only the changes" : "whole policy",
			        desc);
		print_notes (outcome->notes);
	} else {
		fs_cli_error ("%s", error != NULL ? error->message
		              : fs_util_apply_result_to_string ((int) outcome->result));
		if (outcome->rollback_attempted && outcome->rollback_verified)
			fs_cli_hint ("the firewall was restored to the last applied "
			             "policy, and that restore was verified");
		else if (outcome->rollback_attempted)
			fs_cli_error ("the rollback ALSO failed: the firewall may be "
			              "inconsistent -- check `stockfw status'");
		else
			fs_cli_hint ("no applied policy was recorded, so there was "
			             "nothing to roll back to");
	}

	g_free (desc);
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);
	fs_settings_free (settings);
	fs_policy_free (policy);

	return status;
}

/* --------------------------------------------------------- start / stop */

static gint
start_or_stop (gint argc, gboolean start)
{
	FsPolicy *policy;
	FsSettings *settings;
	GError *error = NULL;
	gboolean ok;
	gchar *notes;

	if (argc > 1) {
		fs_cli_error ("%s takes no arguments", start ? "start" : "stop");
		return FS_EXIT_USAGE;
	}

	if (geteuid () != 0)
		return need_root (start ? "start" : "stop");

	policy = fs_cli_load_policy (NULL, NULL);
	settings = backend_context (policy);

	ok = start ? fs_backend ()->start (&error) : fs_backend ()->stop (&error);
	notes = (ok && start && fs_backend ()->apply_notes != NULL)
	        ? fs_backend ()->apply_notes () : NULL;

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "ok", ok);  g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", error ? error->message : NULL);
		g_string_append_c (out, ',');
		fs_json_key (out, "notes");
		append_lines_json (out, notes);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (ok) {
		if (!fs_cli.quiet)
			printf ("Firewall %s.\n", start ? "started" : "stopped");
		print_notes (notes);
	} else {
		fs_cli_error ("could not %s the firewall: %s",
		              start ? "start" : "stop",
		              error ? error->message : "unknown error");
	}

	g_clear_error (&error);
	g_free (notes);
	fs_settings_free (settings);
	fs_policy_free (policy);

	return ok ? FS_EXIT_OK : FS_EXIT_FAILURE;
}

gint fs_cli_cmd_start (gint argc, gchar **argv) { return start_or_stop (argc, TRUE); }
gint fs_cli_cmd_stop  (gint argc, gchar **argv) { return start_or_stop (argc, FALSE); }

/* ------------------------------------------------------------ simulate */

/* [ fs_cli_whatif ] */
FsWhatIfResult *
fs_cli_whatif (const gchar *line, gboolean assume_running)
{
	FsPolicy *policy = fs_cli_load_policy (NULL, NULL);
	FsSettings *settings = fs_settings_new ();
	FsWhatIfContext *ctx;
	FsWhatIfResult *result;

	fs_settings_load_prefs (settings);
	ctx = fs_whatif_context_new (fs_whatif_native_platform (), policy,
	                             settings);

	/* Reading netfilter needs CAP_NET_ADMIN: without it every chain
	 * reads as missing, and "stopped" would turn into "allowed". */
	fs_copilot_whatif_observe (ctx, fs_backend (), geteuid () == 0);
	if (assume_running)
		ctx->firewall = FS_WHATIF_FW_RUNNING;
	fs_copilot_whatif_live (ctx, policy, fs_apply_hold_reason ());

	result = fs_whatif_simulate_text (ctx, line);

	fs_whatif_context_free (ctx);
	fs_settings_free (settings);
	fs_policy_free (policy);
	return result;
}

static const gchar *
whatif_origin_word (FsWhatIfOrigin origin)
{
	switch (origin) {
	case FS_WHATIF_ORIGIN_DEFAULT:  return "default";
	case FS_WHATIF_ORIGIN_POLICY:   return "policy";
	case FS_WHATIF_ORIGIN_SENTINEL: return "sentinel";
	case FS_WHATIF_ORIGIN_SETTINGS: return "settings";
	case FS_WHATIF_ORIGIN_BUILTIN:  return "builtin";
	case FS_WHATIF_ORIGIN_STOPPED:  return "stopped";
	default:                        return "unknown";
	}
}

static const gchar *
whatif_action_word (FsWhatIfActionKind kind)
{
	switch (kind) {
	case FS_WHATIF_ACT_CREATE_ALLOW:       return "create-allow";
	case FS_WHATIF_ACT_CREATE_BLOCK:       return "create-block";
	case FS_WHATIF_ACT_OPEN_RULE:          return "open-rule";
	case FS_WHATIF_ACT_LIFT_SENTINEL:      return "lift-sentinel";
	case FS_WHATIF_ACT_OPEN_ICMP_SETTINGS: return "open-icmp-settings";
	case FS_WHATIF_ACT_OPEN_SETTINGS:      return "open-settings";
	case FS_WHATIF_ACT_START_FIREWALL:     return "start-firewall";
	case FS_WHATIF_ACT_APPLY_POLICY:       return "apply-policy";
	default:                               return "unknown";
	}
}

static void
json_kv_int (GString *out, const gchar *key, gint value)
{
	if (value < 0) {
		fs_json_kv_str (out, key, NULL);
		return;
	}
	fs_json_kv_uint (out, key, (guint64) value);
}

/* The answer the flat fields describe: the only one, or the first
 * whose verdict is the overall one. */
static const FsWhatIfAnswer *
whatif_main_answer (const FsWhatIfResult *r)
{
	if (r->answers->len == 0)
		return NULL;
	if (r->answers->len == 1)
		return g_ptr_array_index (r->answers, 0);

	for (guint i = 0; i < r->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

		if (a->verdict == r->verdict)
			return a;
	}
	return NULL;
}

/* [ fs_cli_whatif_json ] */
void
fs_cli_whatif_json (GString *out, const FsWhatIfResult *r,
                    const gchar *input)
{
	const FsWhatIfQuery *q = r->query;
	const FsWhatIfAnswer *main_a = whatif_main_answer (r);
	const FsWhatIfAction *primary = fs_whatif_result_primary_action (r);
	const FsWhatIfAction *suggest = primary;

	if (suggest == NULL) {
		for (guint i = 0; i < r->answers->len && suggest == NULL; i++) {
			const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

			if (a->actions->len > 0)
				suggest = g_ptr_array_index (a->actions, 0);
		}
	}

	g_string_append_c (out, '{');
	fs_json_kv_str (out, "input", input);              g_string_append_c (out, ',');
	fs_json_kv_str (out, "verdict", fs_whatif_verdict_name (r->verdict));
	g_string_append_c (out, ',');

	if (r->verdict == FS_WHATIF_ERROR || q == NULL) {
		fs_json_kv_str (out, "error", r->error);
		g_string_append_c (out, '}');
		return;
	}

	fs_json_kv_str (out, "summary", r->summary);        g_string_append_c (out, ',');
	fs_json_kv_str (out, "scenario", r->answers->len == 1 && main_a != NULL
	                                 ? main_a->probe : q->text);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "direction",
	                q->direction == FS_WHATIF_DIR_INBOUND ? "inbound"
	                : q->direction == FS_WHATIF_DIR_OUTBOUND ? "outbound"
	                                                        : "both");
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "protocol",
	                q->protocol == FS_WHATIF_PROTO_TCP ? "TCP"
	                : q->protocol == FS_WHATIF_PROTO_UDP ? "UDP"
	                : q->protocol == FS_WHATIF_PROTO_ICMP ? "ICMP" : NULL);
	g_string_append_c (out, ',');
	if (q->port > 0)
		fs_json_kv_uint (out, "port", q->port);
	else
		fs_json_kv_str (out, "port", NULL);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "remote", q->host);            g_string_append_c (out, ',');
	fs_json_kv_str (out, "rule", main_a != NULL ? main_a->rule : NULL);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "reason", r->answers->len == 1 && main_a != NULL
	                               ? main_a->reason : r->summary);
	g_string_append_c (out, ',');
	if (suggest != NULL) {
		gchar *s = g_strdup_printf ("%s: %s", suggest->label,
		                            suggest->explanation != NULL
		                            ? suggest->explanation : "");

		fs_json_kv_str (out, "suggestion", s);
		g_free (s);
	} else {
		fs_json_kv_str (out, "suggestion", NULL);
	}
	g_string_append_c (out, ',');

	/* What the line was read as. */
	g_string_append_printf (out, "\"confidence\":%.2f,", q->confidence);
	g_string_append (out, "\"read_as\":[");
	for (guint i = 0; i < q->pieces->len; i++) {
		const FsWhatIfPiece *p = g_ptr_array_index (q->pieces, i);

		if (i > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "text", p->text);       g_string_append_c (out, ',');
		fs_json_kv_str (out, "meaning", p->meaning);
		g_string_append_c (out, '}');
	}
	g_string_append (out, "],");

	/* Each direction in full: trace, cases, actions. */
	g_string_append (out, "\"answers\":[");
	for (guint i = 0; i < r->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

		if (i > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "direction", a->inbound ? "inbound" : "outbound");
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "verdict", fs_whatif_verdict_name (a->verdict));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "probe", a->probe);      g_string_append_c (out, ',');
		fs_json_kv_str (out, "reason", a->reason);    g_string_append_c (out, ',');
		fs_json_kv_str (out, "rule", a->rule);        g_string_append_c (out, ',');
		fs_json_kv_str (out, "origin", whatif_origin_word (a->origin));
		g_string_append_c (out, ',');
		json_kv_int (out, "policy_kind", a->policy_kind);
		g_string_append_c (out, ',');
		json_kv_int (out, "policy_row", a->policy_index);
		g_string_append (out, ",\"cases\":[");
		for (guint k = 0; k < a->cases->len; k++) {
			const FsWhatIfCase *c = g_ptr_array_index (a->cases, k);

			if (k > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "verdict", fs_whatif_verdict_name (c->verdict));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "condition", c->condition);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "rule", c->rule);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "origin", whatif_origin_word (c->origin));
			g_string_append_c (out, '}');
		}
		g_string_append (out, "],\"trace\":[");
		for (guint k = 0; k < a->steps->len; k++) {
			const FsWhatIfStep *st = g_ptr_array_index (a->steps, k);

			if (k > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "step",
			                st->kind == FS_WHATIF_STEP_MATCHED ? "matched"
			                : st->kind == FS_WHATIF_STEP_NOTE ? "note"
			                                                   : "skipped");
			g_string_append_c (out, ',');
			fs_json_kv_bool (out, "decides", (gint) k == a->decided_by);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "rule", st->rule);  g_string_append_c (out, ',');
			fs_json_kv_str (out, "origin", whatif_origin_word (st->origin));
			g_string_append_c (out, ',');
			json_kv_int (out, "policy_kind", st->policy_kind);
			g_string_append_c (out, ',');
			json_kv_int (out, "policy_row", st->policy_index);
			g_string_append_c (out, ',');
			fs_json_kv_bool (out, "allows", st->allows);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "detail", st->detail);
			g_string_append_c (out, '}');
		}
		g_string_append (out, "],\"actions\":[");
		for (guint k = 0; k < a->actions->len; k++) {
			const FsWhatIfAction *act = g_ptr_array_index (a->actions, k);
			gchar *csv = act->row != NULL ? fs_rule_to_csv (act->row) : NULL;

			if (k > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "kind", whatif_action_word (act->kind));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "label", act->label);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "explanation", act->explanation);
			g_string_append_c (out, ',');
			fs_json_kv_bool (out, "verified", act->verified);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "gives", fs_whatif_verdict_name (act->gives));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "row_kind", act->row != NULL
			                ? fs_cli_kind_name (act->row->kind) : NULL);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "row", csv);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "target", act->target);
			g_string_append_c (out, '}');
			g_free (csv);
		}
		g_string_append (out, "]}");
	}
	g_string_append (out, "],\"notes\":[");
	for (guint i = 0; i < r->notes->len; i++) {
		if (i > 0)
			g_string_append_c (out, ',');
		fs_json_string (out, g_ptr_array_index (r->notes, i));
	}
	g_string_append (out, "]}");
}

gint
fs_cli_cmd_simulate (gint argc, gchar **argv)
{
	FsWhatIfResult *result;
	GPtrArray *words = g_ptr_array_new ();
	gboolean assume_running = FALSE;
	gchar *line;
	gint status;

	for (gint i = 1; i < argc; i++) {
		if (strcmp (argv[i], "--assume-running") == 0)
			assume_running = TRUE;
		else
			g_ptr_array_add (words, argv[i]);
	}
	g_ptr_array_add (words, NULL);

	if (words->len < 2) {
		g_ptr_array_free (words, TRUE);
		fs_cli_error ("simulate needs a description of the traffic");
		fs_cli_hint ("stockfw simulate \"allow ssh from 192.168.1.50 on "
		             "port 22\"");
		return FS_EXIT_USAGE;
	}

	/* Unquoted words are one line, as the user would have typed it. */
	line = g_strjoinv (" ", (gchar **) words->pdata);
	g_ptr_array_free (words, TRUE);

	result = fs_cli_whatif (line, assume_running);

	switch (result->verdict) {
	case FS_WHATIF_ALLOWED: status = FS_EXIT_OK;      break;
	case FS_WHATIF_BLOCKED: status = FS_EXIT_BLOCKED; break;
	case FS_WHATIF_DEPENDS: status = FS_EXIT_DEPENDS; break;
	case FS_WHATIF_ERROR:
	default:                status = FS_EXIT_USAGE;   break;
	}

	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		fs_cli_whatif_json (out, result, line);
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (result->verdict == FS_WHATIF_ERROR) {
		fs_cli_error ("%s", result->error);
		fs_cli_hint ("stockfw simulate \"allow ssh from 192.168.1.50 on "
		             "port 22\"");
	} else {
		gchar *text = fs_whatif_result_describe (result);
		gchar *rest = strchr (text, '\n');
		const gchar *colour =
			result->verdict == FS_WHATIF_ALLOWED ? fs_cli_green ()
			: result->verdict == FS_WHATIF_BLOCKED ? fs_cli_red ()
			                                       : fs_cli_amber ();

		/* The summary names the verdict; it gets the colour. */
		if (rest != NULL)
			*rest++ = '\0';
		printf ("%s%s%s\n%s", colour, text, fs_cli_reset (),
		        rest != NULL ? rest : "");
		printf ("%sA simulation only: nothing was written.%s\n",
		        fs_cli_dim (), fs_cli_reset ());
		g_free (text);
	}

	fs_whatif_result_free (result);
	g_free (line);

	return status;
}

/* -------------------------------------------------------------- events */

/* [ read_tail_lines ] -- the last max_lines lines of a text. */
static gchar **
read_tail_lines (const gchar *text, guint max_lines)
{
	gchar **lines = g_strsplit (text, "\n", -1);
	guint n = g_strv_length (lines);

	if (n > max_lines) {
		gchar **tail = g_new0 (gchar *, max_lines + 1);

		for (guint i = 0; i < max_lines; i++)
			tail[i] = g_strdup (lines[n - max_lines + i]);
		g_strfreev (lines);
		return tail;
	}

	return lines;
}

/* [ read_kmsg_history ]
 * Every record still in the kernel ring buffer (/dev/kmsg, opened at
 * its start), converted to stamped log lines; NULL when it cannot be
 * opened.  The fallback when neither rsyslog nor journald keeps a copy
 * -- WSL, containers, minimal installs -- where the ring is the only
 * kernel log there is. */
static gchar *
read_kmsg_history (void)
{
	int fd = open ("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	GString *out;
	gchar record[8192];
	gint64 now_real = g_get_real_time ();
	gint64 now_mono = g_get_monotonic_time ();

	if (fd < 0)
		return NULL;

	out = g_string_new (NULL);

	for (;;) {
		gssize got = read (fd, record, sizeof (record) - 1);
		gchar *line;

		if (got < 0) {
			if (errno == EPIPE || errno == EINTR)
				continue;     /* overwritten records: go on */
			break;            /* EAGAIN: the end of the ring */
		}
		if (got == 0)
			break;

		record[got] = '\0';
		line = fs_netparse_kmsg_line (record, (gsize) got,
		                              now_real, now_mono);
		if (line != NULL) {
			g_string_append (out, line);
			g_string_append_c (out, '\n');
			g_free (line);
		}
	}

	close (fd);
	return g_string_free (out, FALSE);
}

GPtrArray *
fs_cli_log_history (guint max_lines, gint64 *complete_from, GError **error)
{
	const gchar *override = g_getenv ("STOCKFW_LOG_FILE");
	gchar *text = NULL;
	gchar **lines;
	GPtrArray *hits;
	GError *local = NULL;

	if (override != NULL && *override != '\0') {
		if (!g_file_get_contents (override, &text, NULL, error))
			return NULL;
	} else if (g_file_test ("/var/log/kern.log", G_FILE_TEST_EXISTS)) {
		if (!g_file_get_contents ("/var/log/kern.log", &text, NULL,
		                          &local)) {
			g_set_error (error, local->domain, local->code,
			             "cannot read /var/log/kern.log: %s "
			             "(root or the adm group can)", local->message);
			g_error_free (local);
			return NULL;
		}
	} else {
		/* argv, no shell: nothing here is ever interpolated. */
		gchar *n = g_strdup_printf ("%u", MAX (max_lines * 4, 2000u));
		gchar *argv[] = { (gchar *) "journalctl", (gchar *) "-k",
		                  (gchar *) "-o", (gchar *) "short",
		                  (gchar *) "--no-pager", (gchar *) "-n", n,
		                  NULL };
		gchar *err = NULL;
		gint wait = 0;
		gboolean spawned, journal_ok;

		spawned = g_spawn_sync (NULL, argv, NULL, G_SPAWN_SEARCH_PATH,
		                        NULL, NULL, &text, &err, &wait, &local);
		g_free (n);
		journal_ok = spawned && g_spawn_check_wait_status (wait, NULL) &&
		             (err == NULL ||
		              strstr (err, "No journal files") == NULL);

		if (!journal_ok) {
			/* No usable journal (no journald, as in WSL and most
			 * containers, or no journalctl at all): the kernel's own
			 * ring buffer is then the only copy of the log. */
			gchar *ring = read_kmsg_history ();

			if (ring != NULL) {
				g_free (text);
				text = ring;
				journal_ok = TRUE;
			}
		}

		if (!journal_ok) {
			if (!spawned)
				g_set_error (error, local->domain, local->code,
				             "no kernel log to read: no "
				             "/var/log/kern.log, /dev/kmsg is not "
				             "readable, and journalctl failed (%s)",
				             local->message);
			else if (geteuid () == 0)
				g_set_error (error, G_SPAWN_ERROR,
				             G_SPAWN_ERROR_FAILED,
				             "no kernel log found: there is no "
				             "/var/log/kern.log, /dev/kmsg cannot be "
				             "read, and the journal holds no kernel "
				             "messages");
			else
				g_set_error (error, G_SPAWN_ERROR,
				             G_SPAWN_ERROR_FAILED,
				             "the kernel log is not readable by this "
				             "account (root, or the adm / "
				             "systemd-journal group, can read it)");
			g_clear_error (&local);
			g_free (text);
			g_free (err);
			return NULL;
		}
		g_clear_error (&local);
		g_free (err);
	}

	/* Plenty of foreign kernel lines sit between ours; keep a window
	 * wide enough that max_lines of OUR events usually survive. */
	lines = read_tail_lines (text, MAX (max_lines * 50, 20000u));
	g_free (text);

	hits = g_ptr_array_new_with_free_func ((GDestroyNotify) fs_hit_free);

	if (complete_from != NULL) {
		*complete_from = 0;

		for (guint i = 0; lines[i] != NULL && *complete_from == 0; i++) {
			gchar *stamp = fs_netparse_line_time (lines[i], NULL);
			GDateTime *when = stamp != NULL
				? g_date_time_new_from_iso8601 (stamp, NULL) : NULL;

			if (when != NULL) {
				*complete_from = g_date_time_to_unix (when);
				g_date_time_unref (when);
			}
			g_free (stamp);
		}
	}

	for (guint i = 0; lines[i] != NULL; i++) {
		FsHit parsed = { 0 };
		FsHit *hit;

		if (!fs_netparse_log_line (lines[i], &parsed, NULL))
			continue;

		fs_netparse_name_by_verdict (&parsed,
		                             fs_netparse_log_verdict (lines[i]));
		hit = fs_hit_new ();
		*hit = parsed;          /* the fields move into the heap hit */
		g_ptr_array_add (hits, hit);
	}

	g_strfreev (lines);

	while (hits->len > max_lines)
		g_ptr_array_remove_index (hits, 0);

	return hits;
}

typedef struct
{
	gboolean only_blocked;
	guint    printed;
} EventsState;

/* [ hit_row ] -- one event as table cells (caller frees with g_strfreev). */
static gchar **
hit_row (const FsHit *hit)
{
	gchar **row = g_new0 (gchar *, 9);
	gboolean blocked = fs_hit_is_blocked (hit);
	gchar *service = fs_hit_service_name (hit);

	row[0] = local_time (hit->time);
	row[1] = g_strdup (blocked ? "BLOCKED" : "ALLOWED");
	row[2] = g_strdup (g_ascii_strcasecmp (hit->direction ? hit->direction
	                                                      : "in", "in") == 0
	                   ? "in" : "out");
	row[3] = g_strdup (hit->source ? hit->source : "-");
	row[4] = g_strdup (hit->destination ? hit->destination : "-");
	row[5] = g_strdup (hit->port ? hit->port : "-");
	row[6] = service;
	row[7] = g_strdup (hit->protocol ? hit->protocol : "-");

	return row;
}

static void
print_hit (const FsHit *hit, EventsState *st)
{
	if (st->only_blocked && !fs_hit_is_blocked (hit))
		return;

	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		hit_row_json (out, hit);
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		/* Live lines cannot be sized to the widest row that has not
		 * arrived yet: IPv4-wide columns, longer values push on. */
		gchar **row = hit_row (hit);
		gboolean blocked = fs_hit_is_blocked (hit);

		printf ("%s%s%s  %s%-7s%s  %-3s  %-15s → %-15s  %-5s  %s/%s\n",
		        fs_cli_dim (), row[0], fs_cli_reset (),
		        blocked ? fs_cli_red () : fs_cli_green (), row[1],
		        fs_cli_reset (), row[2], row[3], row[4], row[5], row[6],
		        row[7]);
		g_strfreev (row);
	}

	fflush (stdout);
	st->printed++;
}

static void
on_live_hit (const FsHit *hit, gpointer data)
{
	print_hit (hit, data);
}

static gboolean
on_sigint (gpointer data)
{
	g_main_loop_quit (data);
	return G_SOURCE_REMOVE;
}

gint
fs_cli_cmd_events (gint argc, gchar **argv)
{
	guint count = 20;
	gboolean follow = FALSE;
	EventsState st = { FALSE, 0 };
	GPtrArray *history;
	GError *error = NULL;

	for (gint i = 1; i < argc; i++) {
		if ((strcmp (argv[i], "-n") == 0 || strcmp (argv[i], "--lines") == 0)
		    && i + 1 < argc) {
			gchar *end = NULL;
			guint64 v = g_ascii_strtoull (argv[++i], &end, 10);

			if (end == NULL || *end != '\0' || v > 100000) {
				fs_cli_error ("-n wants a number up to 100000");
				return FS_EXIT_USAGE;
			}
			count = (guint) v;
		} else if (strcmp (argv[i], "-f") == 0 ||
		           strcmp (argv[i], "--follow") == 0) {
			follow = TRUE;
		} else if (strcmp (argv[i], "--blocked") == 0) {
			st.only_blocked = TRUE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
	}

	if (count > 0) {
		history = fs_cli_log_history (count, NULL, &error);

		if (history == NULL) {
			fs_cli_error ("%s", error->message);
			g_error_free (error);
			if (geteuid () != 0)
				fs_cli_hint ("try `sudo stockfw events'");
			return geteuid () != 0 ? FS_EXIT_NEED_ROOT : FS_EXIT_FAILURE;
		}

		if (fs_cli.json && !follow) {
			GString *out = g_string_new ("[");

			for (guint i = 0; i < history->len; i++) {
				const FsHit *hit = g_ptr_array_index (history, i);

				if (st.only_blocked && !fs_hit_is_blocked (hit))
					continue;
				if (out->len > 1)
					g_string_append_c (out, ',');
				hit_row_json (out, hit);
			}
			g_string_append_c (out, ']');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else if (fs_cli.json) {
			/* --follow --json: the history as NDJSON too. */
			for (guint i = 0; i < history->len; i++)
				print_hit (g_ptr_array_index (history, i), &st);
		} else {
			static const gchar *headers[] = {
				"TIME", "VERDICT", "DIR", "SOURCE", "DESTINATION",
				"PORT", "SERVICE", "PROTO"
			};
			GPtrArray *rows = g_ptr_array_new_with_free_func (
				(GDestroyNotify) g_strfreev);

			for (guint i = 0; i < history->len; i++) {
				const FsHit *hit = g_ptr_array_index (history, i);

				if (st.only_blocked && !fs_hit_is_blocked (hit))
					continue;
				g_ptr_array_add (rows, hit_row (hit));
			}

			st.printed = rows->len;
			if (rows->len > 0)
				fs_cli_table (headers, 8, rows, 40);
			g_ptr_array_unref (rows);

			if (st.printed == 0 && !fs_cli.quiet)
				printf ("%sNo StockFW events in the kernel log yet.%s\n",
				        fs_cli_dim (), fs_cli_reset ());
		}

		g_ptr_array_unref (history);
	}

	if (follow) {
		const FsBackend *backend = fs_backend ();
		GMainLoop *loop;

		if (backend->log_start == NULL ||
		    !backend->log_start (on_live_hit, &st, &error)) {
			fs_cli_error ("cannot follow events: %s",
			              error ? error->message : "no event source");
			g_clear_error (&error);
			return geteuid () != 0 ? FS_EXIT_NEED_ROOT : FS_EXIT_FAILURE;
		}

		if (!fs_cli.json && !fs_cli.quiet)
			fprintf (stderr, "%sFollowing new events -- Ctrl-C to stop.%s\n",
			         fs_cli_dim (), fs_cli_reset ());

		loop = g_main_loop_new (NULL, FALSE);
		g_unix_signal_add (SIGINT, on_sigint, loop);
		g_unix_signal_add (SIGTERM, on_sigint, loop);
		g_main_loop_run (loop);
		g_main_loop_unref (loop);

		backend->log_stop ();
	}

	return FS_EXIT_OK;
}

/* --------------------------------------------------------- connections */

gint
fs_cli_cmd_connections (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	GList *conns;

	if (argc > 1) {
		fs_cli_error ("connections takes no arguments");
		return FS_EXIT_USAGE;
	}

	if (backend->list_connections == NULL) {
		fs_cli_error ("this backend cannot list connections");
		return FS_EXIT_FAILURE;
	}

	conns = backend->list_connections ();

	if (fs_cli.json) {
		GString *out = g_string_new ("[");

		for (GList *l = conns; l != NULL; l = l->next) {
			FsConnection *c = l->data;

			if (l != conns)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "local", c->source);          g_string_append_c (out, ',');
			fs_json_kv_str (out, "remote", c->destination);    g_string_append_c (out, ',');
			fs_json_kv_str (out, "port", c->port);             g_string_append_c (out, ',');
			fs_json_kv_str (out, "protocol", c->protocol);     g_string_append_c (out, ',');
			fs_json_kv_str (out, "service", c->service);       g_string_append_c (out, ',');
			fs_json_kv_str (out, "program", c->program);       g_string_append_c (out, ',');
			fs_json_kv_str (out, "direction", c->direction);
			g_string_append_c (out, '}');
		}
		g_string_append_c (out, ']');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (conns == NULL) {
		if (!fs_cli.quiet)
			printf ("No active TCP connections.\n");
	} else {
		static const gchar *headers[] = {
			"LOCAL", "REMOTE", "PORT", "SERVICE", "DIRECTION", "PROGRAM"
		};
		GPtrArray *rows = g_ptr_array_new_with_free_func (g_free);
		gboolean unknown_owner = FALSE;

		for (GList *l = conns; l != NULL; l = l->next) {
			FsConnection *c = l->data;
			gchar **row = g_new0 (gchar *, 7);

			row[0] = c->source;
			row[1] = c->destination;
			row[2] = c->port;
			row[3] = c->service;
			row[4] = c->direction;
			row[5] = c->program;
			g_ptr_array_add (rows, row);

			if (g_strcmp0 (c->program, "?") == 0)
				unknown_owner = TRUE;
		}

		fs_cli_table (headers, 6, rows, 40);
		g_ptr_array_unref (rows);

		if (unknown_owner && geteuid () != 0 && !fs_cli.quiet)
			printf ("%s\"?\" is another user's program; root can see "
			        "every owner.%s\n", fs_cli_dim (), fs_cli_reset ());
	}

	g_list_free_full (conns, (GDestroyNotify) fs_connection_free);
	return FS_EXIT_OK;
}

/* ---------------------------------------------------------- interfaces */

static void
print_interfaces (GList *now, GList *before, gdouble seconds)
{
	if (fs_cli.json) {
		GString *out = g_string_new ("[");

		for (GList *l = now; l != NULL; l = l->next) {
			FsIfaceStat *s = l->data;
			gdouble rx = 0, tx = 0;

			for (GList *b = before; b != NULL; b = b->next) {
				FsIfaceStat *p = b->data;

				if (g_strcmp0 (p->device, s->device) == 0 &&
				    s->received >= p->received && s->sent >= p->sent) {
					rx = (gdouble) (s->received - p->received) / seconds;
					tx = (gdouble) (s->sent - p->sent) / seconds;
				}
			}

			if (l != now)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "device", s->device);     g_string_append_c (out, ',');
			fs_json_kv_str (out, "type", s->kind);         g_string_append_c (out, ',');
			fs_json_kv_str (out, "ip", s->ip);             g_string_append_c (out, ',');
			fs_json_kv_bool (out, "up", s->up);            g_string_append_c (out, ',');
			fs_json_kv_uint (out, "received", s->received); g_string_append_c (out, ',');
			fs_json_kv_uint (out, "sent", s->sent);        g_string_append_c (out, ',');
			g_string_append_printf (out, "\"rx_per_s\":%.0f,\"tx_per_s\":%.0f",
			                        rx, tx);
			g_string_append_c (out, '}');
		}
		g_string_append_c (out, ']');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
		return;
	}

	{
		static const gchar *headers[] = {
			"ADAPTER", "TYPE", "ADDRESS", "RECEIVED", "SENT",
			"↓ NOW", "↑ NOW"
		};
		GPtrArray *rows = g_ptr_array_new_with_free_func (
			(GDestroyNotify) g_strfreev);

		for (GList *l = now; l != NULL; l = l->next) {
			FsIfaceStat *s = l->data;
			gchar **row = g_new0 (gchar *, 8);
			gdouble rx = 0, tx = 0;

			for (GList *b = before; b != NULL; b = b->next) {
				FsIfaceStat *p = b->data;

				if (g_strcmp0 (p->device, s->device) == 0 &&
				    s->received >= p->received && s->sent >= p->sent) {
					rx = (gdouble) (s->received - p->received) / seconds;
					tx = (gdouble) (s->sent - p->sent) / seconds;
				}
			}

			row[0] = g_strconcat (s->device, s->up ? "" : " (down)", NULL);
			row[1] = g_strdup (s->kind ? s->kind : "-");
			row[2] = g_strdup (s->ip ? s->ip : "-");
			row[3] = fs_cli_format_bytes (s->received);
			row[4] = fs_cli_format_bytes (s->sent);
			row[5] = fs_cli_format_rate (rx);
			row[6] = fs_cli_format_rate (tx);
			g_ptr_array_add (rows, row);
		}

		if (rows->len == 0)
			printf ("No network adapters with traffic counters.\n");
		else
			fs_cli_table (headers, 7, rows, 32);
		g_ptr_array_unref (rows);
	}
}

static gboolean watch_stop = FALSE;

static gboolean
on_watch_signal (gpointer data)
{
	(void) data;
	watch_stop = TRUE;
	return G_SOURCE_CONTINUE;
}

gint
fs_cli_cmd_interfaces (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	gboolean watch = FALSE;
	GList *before, *now;

	for (gint i = 1; i < argc; i++) {
		if (strcmp (argv[i], "--watch") == 0 || strcmp (argv[i], "-w") == 0) {
			watch = TRUE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
	}

	if (backend->list_interface_stats == NULL) {
		fs_cli_error ("this backend has no traffic counters");
		return FS_EXIT_FAILURE;
	}

	before = backend->list_interface_stats ();
	g_usleep (G_USEC_PER_SEC);
	now = backend->list_interface_stats ();

	if (!watch) {
		print_interfaces (now, before, 1.0);
	} else {
		g_unix_signal_add (SIGINT, on_watch_signal, NULL);

		while (!watch_stop) {
			if (!fs_cli.json && fs_cli.color)
				printf ("\033[H\033[2J");
			print_interfaces (now, before, 2.0);
			if (!fs_cli.json)
				printf ("%sRefreshing every 2 s -- Ctrl-C to stop.%s\n",
				        fs_cli_dim (), fs_cli_reset ());
			fflush (stdout);

			g_list_free_full (before, (GDestroyNotify) fs_iface_stat_free);
			before = now;

			for (gint t = 0; t < 20 && !watch_stop; t++) {
				g_usleep (G_USEC_PER_SEC / 10);
				while (g_main_context_iteration (NULL, FALSE))
					;
			}
			now = backend->list_interface_stats ();
		}
	}

	g_list_free_full (before, (GDestroyNotify) fs_iface_stat_free);
	g_list_free_full (now, (GDestroyNotify) fs_iface_stat_free);

	return FS_EXIT_OK;
}
