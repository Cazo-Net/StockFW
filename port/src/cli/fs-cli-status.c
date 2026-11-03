/*---[ fs-cli-status.c ]----------------------------------------------------
 * `stockfw status', and the status snapshot the live event line
 * reads.
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-apply.h"
#include "core/fs-audit.h"
#include "core/fs-autoblock.h"
#include "core/fs-prefs.h"
#include "core/fs-toolpath.h"
#include "core/fs-copilot.h"
#include "core/fs-eventlog.h"
#include "core/fs-eventstore.h"
#include "core/fs-intel.h"
#include "core/fs-health.h"
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
		g_string_append_c (out, ',');
		/* Threat intel: the state the kernel is in, never just the
		 * configuration (design 6.6). */
		fs_json_key (out, "intel");
		fs_cli_intel_json (out, FALSE);
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
			dot = fs_cli_sym (FS_CLI_SYM_ON); color = fs_cli_green ();
		} else if (state == FS_FW_STOPPED) {
			dot = fs_cli_sym (FS_CLI_SYM_OFF); color = fs_cli_red ();
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
			        fs_cli_policy_total (policy),
			        fs_cli_policy_total (policy) == 1 ? "" : "s",
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

		fs_cli_intel_status_line ();

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

			gchar *dev = fs_cli_out_safe (s->device);

			printf ("  %-12s %-10s %-15s %s %s  %s %s%s\n",
			        l == stats ? "Adapters" : "", dev,
			        s->ip ? s->ip : "-", fs_cli_sym (FS_CLI_SYM_DOWN), rx,
			        fs_cli_sym (FS_CLI_SYM_UP), tx,
			        s->up ? "" : "  (down)");
			g_free (dev);
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

/* ------------------------------------------------------------ snapshot */

/* [ fs_cli_status_snapshot ]
 * The cheap facts of the live event line: the firewall state (root
 * only), live or pending, the audit-only hold, the Sentinel mode and
 * whether the log can be read.  Blocked today and the staged Sentinel
 * count stay unknown (-1) until WP-C's readers fill them. */
FsCliStatusSnapshot *
fs_cli_status_snapshot (void)
{
	FsCliStatusSnapshot *snap = g_new0 (FsCliStatusSnapshot, 1);
	FsPolicy *saved = fs_cli_load_policy (NULL, NULL);

	snap->state = FS_FW_NONE;
	if (geteuid () == 0 && fs_backend ()->get_state != NULL)
		snap->state = fs_backend ()->get_state ();
	snap->live = fs_cli_policy_state (saved, NULL, &snap->settings_pending);
	snap->held = fs_apply_hold_reason () != NULL;
	snap->blocked_today = -1;
	snap->sentinel_mode = fs_prefs_get_string (FS_PREFS_SENTINEL_MODE,
	                                           "auto");
	snap->sentinel_staged = -1;
	snap->monitor_readable = fs_cli_log_readable (&snap->monitor_source,
	                                              &snap->monitor_problem);
	fs_policy_free (saved);
	return snap;
}

void
fs_cli_status_snapshot_free (FsCliStatusSnapshot *snap)
{
	if (snap == NULL)
		return;
	g_free (snap->sentinel_mode);
	g_free (snap->monitor_source);
	g_free (snap->monitor_problem);
	g_free (snap);
}

/* ------------------------------------------------------- the commands */

static const FsCliOption status_opts[] = {
	{ NULL, FALSE, NULL }
};

const FsCliCommandDef fs_cli_status_commands[] = {
	{ "status", fs_cli_cmd_status,
"Usage: stockfw status [--json]\n"
"\n"
"Shows the firewall state, the backend, how many rules the saved policy\n"
"holds and where it lives, whether audit-only mode holds applies back,\n"
"whether live event monitoring is available, and the adapters and\n"
"connection count.  Reading the firewall state needs root; without it\n"
"the state is reported as unknown rather than guessed.\n",
	  status_opts, NULL },

	{ NULL, NULL, NULL, NULL, NULL }
};

