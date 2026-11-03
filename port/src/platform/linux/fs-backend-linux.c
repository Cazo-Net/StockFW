/*---[ fs-backend-linux.c ]---------------------------------------------
 * Linux firewall backend.
 *
 * Implements the FsBackend vtable against netfilter and the system log.
 * The rule text itself comes from core/fs-script.c, so this file only
 * decides how to execute it and how to observe results.
 *
 * Two deliberate choices:
 *
 *   - Rules are applied by running iptables directly rather than by
 *     writing a shell script and executing it.  There is no shell
 *     dependency, no temp file, and no quoting to get wrong.
 *   - conntrack replaces the old "state" match, and ESTABLISHED is
 *     only paired with RELATED on the outbound chain.
 *--------------------------------------------------------------------*/

#define _GNU_SOURCE

#include "core/fs-backend.h"
#include "core/fs-rules.h"
#include "core/fs-fwrule.h"
#include "core/fs-util.h"
#include "core/fs-service.h"
#include "core/fs-netparse.h"
#include "core/fs-i18n.h"
#include "core/fs-script.h"
#include "core/fs-intel.h"
#include "core/fs-intelset.h"
#include "core/fs-nftset.h"

#include <gio/gio.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <glib-unix.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>

/* ------------------------------------------------------------------ state
 * Netfilter is stateless from our point of view: we decide the firewall
 * is "running" when our INBOUND chain exists. */
static gboolean log_running = FALSE;

/* What the last successful apply left out or could not cover; see
 * FsBackend.apply_notes. */
static gchar *last_notes = NULL;
static int      log_pipe[2] = { -1, -1 };
/* 1.0.7: /dev/kmsg read directly (no child) when it can be opened. */
static int      log_kmsg = -1;
static const gchar *log_source_text = NULL;   /* static strings only */
static gchar   *log_problem_text = NULL;
static GPid     log_pid = 0;
static guint    log_watch = 0;
static FsLogFunc log_callback = NULL;
static gpointer  log_user_data = NULL;

static FsSettings *current_settings = NULL;
static FsPolicy    *current_policy = NULL;

/* -------------------------------------------------------------- helpers */

/* [ run_command_quiet ]
 * Runs argv with stdout and stderr discarded; its exit status, or -1 if
 * it could not be started.  Used by the probes and the delete-until-it-
 * fails loops, where a failure is often the expected answer and would
 * otherwise bury real errors in noise. */
static gint
run_command_quiet (gchar **argv)
{
	GError *error = NULL;
	gint status = 0;

	if (!g_spawn_sync (NULL, argv, NULL,
	                   G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL |
	                   G_SPAWN_STDERR_TO_DEV_NULL,
	                   NULL, NULL, NULL, NULL, &status, &error)) {
		g_clear_error (&error);
		return -1;
	}

	if (WIFEXITED (status))
		return WEXITSTATUS (status);

	return -1;
}

/* [ chain_exists ]
 * Probes for our chain, which is how the backend reports state.
 *
 * Quiet on purpose.  This runs on every status refresh and, for a
 * non-root launch, iptables answers "Could not fetch rule set
 * generation id: Permission denied (you must be root)" on stderr --
 * which is the probe's *expected* failure, not a diagnostic, and was
 * leaking raw iptables noise into the user's terminal.  The exit status
 * is the entire result, so stderr carries nothing a caller can use. */
static gboolean
chain_exists (void)
{
	gchar *args[] = { (gchar *) "iptables", (gchar *) "-w",
	                  (gchar *) "-t",    (gchar *) "filter",
	                  (gchar *) "-n",    (gchar *) "-L",
	                  (gchar *) "INBOUND", NULL };

	return (run_command_quiet (args) == 0);
}

/* [ require_root ]
 * Netfilter needs CAP_NET_ADMIN.  Failing early gives a far better
 * message than a stream of iptables errors. */
static gboolean
require_root (GError **error)
{
	if (geteuid () == 0)
		return TRUE;

	g_set_error_literal (error,
	                     g_quark_from_static_string ("fs-backend-linux"),
	                     0,
	                     "Managing the firewall requires root privileges. "
	                     "Run StockFW with sudo, or grant it "
	                     "CAP_NET_ADMIN.");

	return FALSE;
}

/* [ have_iptables ]
 * Whether the iptables binary is on PATH.  Callers that silence
 * iptables' own output still need to distinguish "nothing to do" from
 * "there is no firewall tool here at all". */
static gboolean
have_iptables (GError **error)
{
	gchar *argv[] = { (gchar *) "iptables", (gchar *) "--version", NULL };
	GError *local = NULL;
	/* The lookup returns the path it found, which is ours to free:
	 * testing it inline leaked one string per apply. */
	gchar *found = g_find_program_in_path ("iptables");

	if (found == NULL) {
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fs-backend-linux"),
		                     0,
		                     "iptables was not found on PATH.");
		return FALSE;
	}
	g_free (found);

	/* A present but unusable binary (missing kernel support, broken
	 * alternatives link) still deserves a message.  The probe's own
	 * output is discarded so it cannot leak into whatever the caller
	 * is printing. */
	if (!g_spawn_sync (NULL, argv, NULL,
	                   G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL |
	                   G_SPAWN_STDERR_TO_DEV_NULL,
	                   NULL, NULL, NULL, NULL, NULL, &local)) {
		g_clear_error (&local);
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fs-backend-linux"),
		                     0,
		                     "iptables could not be executed.");
		return FALSE;
	}

	return TRUE;
}

/* [ default_route_interface ]
 * The interface the kernel would use to reach the internet.  Asking a
 * connected UDP socket which local address gets chosen is far more
 * reliable than parsing /proc/net/route, which is absent on WSL and
 * has varied column layouts over the years. */
static gchar *
default_route_interface (void)
{
	struct sockaddr_in probe = { 0 };
	struct sockaddr_in local = { 0 };
	socklen_t length = sizeof (local);
	gchar *result = NULL;
	int fd;

	/* No packets are sent; connect() on UDP only sets the route. */
	probe.sin_family = AF_INET;
	probe.sin_port = htons (9);
	probe.sin_addr.s_addr = inet_addr ("192.0.2.1");   /* TEST-NET-1 */

	fd = socket (AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return NULL;

	if (connect (fd, (struct sockaddr *) &probe, sizeof (probe)) == 0 &&
	    getsockname (fd, (struct sockaddr *) &local, &length) == 0)
		result = g_strdup (inet_ntoa (local.sin_addr));

	close (fd);

	return result;
}

/* [ interface_is_nat_capable ]
 * An external-facing interface is the one carrying the default route,
 * which is what NAT would be applied to. */
static gboolean
interface_is_nat_capable (const gchar *name)
{
	gchar *default_ifaddr;
	gboolean is_default;

	if (name == NULL)
		return FALSE;

	/* Match on the address the kernel would pick for this name. */
	default_ifaddr = default_route_interface ();

	if (default_ifaddr == NULL)
		return FALSE;

	is_default = FALSE;
	{
		struct ifaddrs *ifaddr = NULL;
		struct ifaddrs *ifa;

		if (getifaddrs (&ifaddr) == 0) {
			for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
				struct sockaddr_in *sin;
				gchar addr[INET_ADDRSTRLEN];

				if (ifa->ifa_addr == NULL ||
				    ifa->ifa_addr->sa_family != AF_INET ||
				    g_strcmp0 (ifa->ifa_name, name) != 0)
					continue;

				sin = (struct sockaddr_in *) ifa->ifa_addr;

				if (inet_ntop (AF_INET, &sin->sin_addr, addr,
				               sizeof (addr)) != NULL &&
				    g_strcmp0 (addr, default_ifaddr) == 0)
					is_default = TRUE;
			}

			freeifaddrs (ifaddr);
		}
	}

	g_free (default_ifaddr);

	return is_default;
}

/* ------------------------------------------------------------- vtable */

/* Referenced by linux_start before its definition. */
static FsApplyResult linux_apply_rules (const FsPolicy *policy,
                                        GError **error);
static void linux_sysctl_forwarding (void);
static void linux_sysctl_forwarding6 (const gchar *ext);
static void linux_log_stop (void);

static gboolean
linux_available (void)
{
	return (geteuid () == 0);
}

static FsFirewallState
linux_get_state (void)
{
	/* Without root iptables cannot be read at all.  That is "unknown",
	 * not "stopped": the boot unit may well have the rules in force
	 * while a copy without root (the one started at sign-in) looks. */
	if (geteuid () != 0)
		return FS_FW_NONE;

	if (!chain_exists ())
		return FS_FW_STOPPED;

	return FS_FW_RUNNING;
}

static gboolean
linux_start (GError **error)
{
	FsApplyResult result;

	if (!require_root (error))
		return FALSE;

	if (current_policy == NULL || current_settings == NULL) {
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fs-backend-linux"),
		                     0, "No traffic policy has been loaded.");
		return FALSE;
	}

	result = linux_apply_rules (current_policy, error);

	return (result == FS_APPLY_OK || result == FS_APPLY_PARTIAL);
}

/* ==================================================================
 * Applying the policy (1.0.7): both address families, one
 * transaction per table, rolled back as a whole on any failure.
 *
 * Before 1.0.7 an apply first stopped the firewall (removing every
 * rule) and then ran one iptables process per rule: for a few hundred
 * milliseconds the machine was unfiltered, a failure halfway left half
 * a policy, and IPv6 was never filtered at all.  Now fs-script renders
 * the policy as iptables-restore input per family, and each table is
 * replaced with `<tool>-restore --noflush', which swaps StockFW's own
 * chains in one kernel transaction and touches nothing else.  The
 * chains stay hooked throughout, so there is no unfiltered moment.
 *
 * filter and nat commit separately, and IPv4 and IPv6 are separate
 * tools, so before anything changes the current contents of our
 * chains are saved; if any later step fails, everything already
 * replaced is put back and the apply reports failure: the kernel ends
 * up with the old policy or the new one, never a mix.
 * ================================================================== */

typedef struct
{
	FsFamily     family;
	const gchar *tool;
	const gchar *restore;
	const gchar *save;
	const gchar *label;
} Family;

static const Family FAMILY4 = { FS_FAMILY_IPV4, "iptables",
                                "iptables-restore", "iptables-save",
                                "IPv4" };
static const Family FAMILY6 = { FS_FAMILY_IPV6, "ip6tables",
                                "ip6tables-restore", "ip6tables-save",
                                "IPv6" };

static const gchar *const FILTER_CHAINS[] = { "INBOUND", "OUTBOUND",
                                              FS_SCRIPT_ACCEPT_CHAIN, NULL };
static const gchar *const NAT_CHAINS[] = { FS_SCRIPT_DNAT_CHAIN,
                                           FS_SCRIPT_SNAT_CHAIN, NULL };

/* [ kernel_has_ipv6 ]
 * /proc/net/if_inet6 exists exactly when the kernel has an IPv6 stack
 * (ipv6.disable=1 or a kernel built without it: nothing to filter).
 * STOCKFW_ASSUME_IPV6=1 lets the test suites drive the IPv6 path on a
 * machine without IPv6; ip6tables can still load rules there. */
static gboolean
kernel_has_ipv6 (void)
{
	if (g_strcmp0 (g_getenv ("STOCKFW_ASSUME_IPV6"), "1") == 0)
		return TRUE;

	return g_file_test ("/proc/net/if_inet6", G_FILE_TEST_EXISTS);
}

static gboolean
have_ip6tables (void)
{
	gchar *a = g_find_program_in_path ("ip6tables");
	gchar *b = g_find_program_in_path ("ip6tables-restore");
	gboolean ok = (a != NULL && b != NULL);

	g_free (a);
	g_free (b);
	return ok;
}

/* [ run_restore ]
 * Feeds `payload' to <tool>-restore --noflush.  On failure *why gets
 * the tool's first error line. */
static gboolean
run_restore (const Family *f, const gchar *payload, gchar **why)
{
	const gchar *argv[] = { f->restore, "-w", "--noflush", NULL };
	GSubprocess *proc;
	GError *error = NULL;
	gchar *err = NULL;
	gboolean ok;

	proc = g_subprocess_newv (argv,
	                          G_SUBPROCESS_FLAGS_STDIN_PIPE |
	                          G_SUBPROCESS_FLAGS_STDOUT_SILENCE |
	                          G_SUBPROCESS_FLAGS_STDERR_PIPE, &error);
	if (proc == NULL) {
		*why = g_strdup (error->message);
		g_error_free (error);
		return FALSE;
	}

	ok = g_subprocess_communicate_utf8 (proc, payload, NULL, NULL, &err,
	                                    &error) &&
	     g_subprocess_get_if_exited (proc) &&
	     g_subprocess_get_exit_status (proc) == 0;

	if (!ok) {
		if (error != NULL)
			*why = g_strdup (error->message);
		else if (err != NULL && *err != '\0') {
			gchar *nl = strchr (err, '\n');

			*why = nl != NULL ? g_strndup (err, (gsize) (nl - err))
			                  : g_strdup (err);
		} else
			*why = g_strdup_printf ("%s failed", f->restore);
	}

	g_clear_error (&error);
	g_free (err);
	g_object_unref (proc);
	return ok;
}

/* [ tool_quiet ] -- one quiet <tool> invocation; its exit status. */
static gint
tool_quiet (const Family *f, const gchar *table, const gchar *const *args)
{
	GPtrArray *argv = g_ptr_array_new ();
	gint status;

	g_ptr_array_add (argv, (gpointer) f->tool);
	g_ptr_array_add (argv, (gpointer) "-w");
	g_ptr_array_add (argv, (gpointer) "-t");
	g_ptr_array_add (argv, (gpointer) table);
	for (gint i = 0; args[i] != NULL; i++)
		g_ptr_array_add (argv, (gpointer) args[i]);
	g_ptr_array_add (argv, NULL);

	status = run_command_quiet ((gchar **) argv->pdata);
	g_ptr_array_free (argv, TRUE);
	return status;
}

/* [ ensure_jump ] -- exactly one "-j chain" in builtin, appended. */
static gboolean
ensure_jump (const Family *f, const gchar *table, const gchar *builtin,
             const gchar *chain)
{
	const gchar *check[] = { "-C", builtin, "-j", chain, NULL };
	const gchar *add[]   = { "-A", builtin, "-j", chain, NULL };

	if (tool_quiet (f, table, check) == 0)
		return TRUE;

	return tool_quiet (f, table, add) == 0;
}

/* [ remove_jump ] -- every "-j chain" in builtin (iptables deletes one
 * match at a time, so until one fails). */
static void
remove_jump (const Family *f, const gchar *table, const gchar *builtin,
             const gchar *chain)
{
	const gchar *del[] = { "-D", builtin, "-j", chain, NULL };

	for (gint i = 0; i < 64; i++)
		if (tool_quiet (f, table, del) != 0)
			break;
}

static void
drop_chains (const Family *f, const gchar *table,
             const gchar *const *chains)
{
	for (gint i = 0; chains[i] != NULL; i++) {
		const gchar *flush[] = { "-F", chains[i], NULL };

		tool_quiet (f, table, flush);
	}
	for (gint i = 0; chains[i] != NULL; i++) {
		const gchar *del[] = { "-X", chains[i], NULL };

		tool_quiet (f, table, del);
	}
}

static void
teardown_filter (const Family *f)
{
	remove_jump (f, "filter", "INPUT", "INBOUND");
	remove_jump (f, "filter", "FORWARD", "INBOUND");
	remove_jump (f, "filter", "OUTPUT", "OUTBOUND");
	drop_chains (f, "filter", FILTER_CHAINS);
}

static void
teardown_nat (const Family *f)
{
	remove_jump (f, "nat", "PREROUTING", FS_SCRIPT_DNAT_CHAIN);
	remove_jump (f, "nat", "POSTROUTING", FS_SCRIPT_SNAT_CHAIN);
	drop_chains (f, "nat", NAT_CHAINS);
}

/* [ legacy_cleanup ]
 * Rules 1.0.6 and earlier wrote straight into the built-in chains,
 * where nothing ever removed them: MASQUERADE in POSTROUTING, DNAT for
 * each forward in PREROUTING, and a FORWARD accept per apply.  They
 * now live in StockFW's own chains; these loops drain the old copies.
 * Only exact matches of what StockFW wrote are deleted. */
static void
legacy_cleanup (void)
{
	const FsSettings *s = current_settings;

	if (s == NULL || !fs_util_is_valid_ifname (s->ext_device))
		return;

	{
		const gchar *masq[] = { "-D", "POSTROUTING", "-o", s->ext_device,
		                        "-j", "MASQUERADE", NULL };

		for (gint i = 0; i < 64; i++)
			if (tool_quiet (&FAMILY4, "nat", masq) != 0)
				break;
	}

	if (fs_util_is_valid_ifname (s->int_device)) {
		const gchar *fwd[] = { "-D", "FORWARD", "-i", s->int_device,
		                       "-o", s->ext_device, "-j", "ACCEPT", NULL };

		for (gint i = 0; i < 64; i++)
			if (tool_quiet (&FAMILY4, "filter", fwd) != 0)
				break;
	}

	if (current_policy != NULL) {
		GPtrArray *fw = current_policy->kinds[FS_RULE_INBOUND_FORWARD];

		for (guint r = 0; r < fw->len; r++) {
			FsRule *rule = g_ptr_array_index (fw, r);
			gchar *to;

			if (rule->port == NULL || rule->to == NULL ||
			    rule->to_port == NULL ||
			    fs_util_target_families (rule->to) != FS_FAMILY_IPV4 ||
			    !fs_util_is_valid_port (rule->port) ||
			    !fs_util_is_valid_port (rule->to_port))
				continue;

			to = g_strdup_printf ("%s:%s", rule->to, rule->to_port);
			{
				const gchar *dnat[] = { "-D", "PREROUTING", "-i",
				                        s->ext_device, "-p", "tcp",
				                        "--dport", rule->port, "-j",
				                        "DNAT", "--to-destination", to,
				                        NULL };

				for (gint i = 0; i < 64; i++)
					if (tool_quiet (&FAMILY4, "nat", dnat) != 0)
						break;
			}
			g_free (to);
		}
	}
}

/* ---- snapshots, for rollback ---------------------------------------- */

typedef struct
{
	gboolean ok;          /* the save tool answered                     */
	gboolean present;     /* chains[0] existed                          */
	gchar   *payload;     /* restore input that puts our chains back    */
} TableSnap;

typedef struct
{
	TableSnap filter;
	TableSnap nat;
	gboolean  forward_hooked;  /* FORWARD jumped to INBOUND before    */
	gboolean  touched_filter;  /* set only once the table has changed */
	gboolean  touched_nat;
} FamilySnap;

static void
take_snapshot (const Family *f, const gchar *table,
               const gchar *const *chains, TableSnap *snap)
{
	gchar *argv[] = { (gchar *) f->save, (gchar *) "-t", (gchar *) table,
	                  NULL };
	gchar *text = NULL;
	gint status = 0;
	gchar **lines;
	GString *decl, *rules;
	gboolean seen[8] = { FALSE };

	memset (snap, 0, sizeof (*snap));

	if (!g_spawn_sync (NULL, argv, NULL,
	                   G_SPAWN_SEARCH_PATH | G_SPAWN_STDERR_TO_DEV_NULL,
	                   NULL, NULL, &text, NULL, &status, NULL) ||
	    !g_spawn_check_wait_status (status, NULL)) {
		g_free (text);
		return;
	}

	decl = g_string_new (NULL);
	rules = g_string_new (NULL);
	lines = g_strsplit (text, "\n", -1);

	for (gint i = 0; lines[i] != NULL; i++)
		for (gint c = 0; chains[c] != NULL && c < 8; c++) {
			gchar *head = g_strdup_printf (":%s ", chains[c]);
			gchar *rule = g_strdup_printf ("-A %s ", chains[c]);

			if (g_str_has_prefix (lines[i], head)) {
				g_string_append_printf (decl, ":%s - [0:0]\n",
				                        chains[c]);
				seen[c] = TRUE;
			} else if (g_str_has_prefix (lines[i], rule)) {
				g_string_append_printf (rules, "%s\n", lines[i]);
			}
			g_free (head);
			g_free (rule);
		}

	/* Chains the failed apply may have created are created-and-deleted,
	 * so putting the old state back also removes them. */
	for (gint c = 0; chains[c] != NULL && c < 8; c++)
		if (!seen[c])
			g_string_append_printf (decl, ":%s - [0:0]\n", chains[c]);
	for (gint c = 0; chains[c] != NULL && c < 8; c++)
		if (!seen[c])
			g_string_append_printf (rules, "-X %s\n", chains[c]);

	snap->ok = TRUE;
	snap->present = seen[0];
	snap->payload = g_strdup_printf ("*%s\n%s%sCOMMIT\n", table, decl->str,
	                                 rules->str);

	g_strfreev (lines);
	g_string_free (decl, TRUE);
	g_string_free (rules, TRUE);
	g_free (text);
}

static void
family_snap_clear (FamilySnap *s)
{
	g_free (s->filter.payload);
	g_free (s->nat.payload);
	memset (s, 0, sizeof (*s));
}

/* [ jump_present ] -- whether builtin already jumps to chain. */
static gboolean
jump_present (const Family *f, const gchar *table, const gchar *builtin,
              const gchar *chain)
{
	const gchar *check[] = { "-C", builtin, "-j", chain, NULL };

	return tool_quiet (f, table, check) == 0;
}

/* [ roll_back ]
 * Puts one family's touched tables back.  Only tables that actually
 * changed are touched: a refused restore changes nothing, so rolling
 * it back would only run the refusing tool a second time.  Restored
 * chains are hooked in again, because the failed apply may have
 * unhooked them (leaving router mode, for example). */
static gboolean
roll_back (const Family *f, FamilySnap *s)
{
	gboolean ok = TRUE;
	gchar *why = NULL;

	if (s->touched_nat) {
		if (s->nat.ok && s->nat.present) {
			ok = run_restore (f, s->nat.payload, &why) && ok;
			ok = ensure_jump (f, "nat", "PREROUTING",
			                  FS_SCRIPT_DNAT_CHAIN) && ok;
			ok = ensure_jump (f, "nat", "POSTROUTING",
			                  FS_SCRIPT_SNAT_CHAIN) && ok;
		} else {
			teardown_nat (f);
		}
		g_clear_pointer (&why, g_free);
	}

	if (s->touched_filter) {
		if (s->filter.ok && s->filter.present) {
			ok = run_restore (f, s->filter.payload, &why) && ok;
			ok = ensure_jump (f, "filter", "INPUT", "INBOUND") && ok;
			ok = ensure_jump (f, "filter", "OUTPUT", "OUTBOUND") && ok;
			if (s->forward_hooked)
				ok = ensure_jump (f, "filter", "FORWARD",
				                  "INBOUND") && ok;
			else
				remove_jump (f, "filter", "FORWARD", "INBOUND");
		} else {
			teardown_filter (f);
		}
		g_clear_pointer (&why, g_free);
	}

	return ok;
}

/* [ load_family ]
 * Replaces one family's chains with `part' and makes sure they are
 * hooked in.  FALSE with *why on the first failure; the caller rolls
 * back. */
static gboolean
load_family (const Family *f, const FsRestorePart *part, FamilySnap *snap,
             gchar **why)
{
	const FsSettings *s = current_settings;

	/* A refused restore is atomic and changed nothing, so the table
	 * only counts as touched once it has been accepted. */
	if (!run_restore (f, part->filter, why))
		return FALSE;
	snap->touched_filter = TRUE;

	if (!ensure_jump (f, "filter", "INPUT", "INBOUND") ||
	    !ensure_jump (f, "filter", "OUTPUT", "OUTBOUND")) {
		*why = g_strdup ("could not hook the chains into INPUT/OUTPUT");
		return FALSE;
	}

	/* Forwarded IPv4 goes through INBOUND, as it always has.  IPv6
	 * forwarding is only filtered in router mode: hooking it
	 * unconditionally would send container and VM traffic, which their
	 * own runtimes accept in other tables, into INBOUND's default drop
	 * -- traffic that worked while IPv6 was not filtered at all. */
	if (f->family == FS_FAMILY_IPV4 || fs_settings_sharing (s)) {
		if (!ensure_jump (f, "filter", "FORWARD", "INBOUND")) {
			*why = g_strdup ("could not hook INBOUND into FORWARD");
			return FALSE;
		}
	} else {
		remove_jump (f, "filter", "FORWARD", "INBOUND");
	}

	if (part->nat != NULL) {
		if (!run_restore (f, part->nat, why))
			return FALSE;
		snap->touched_nat = TRUE;
		if (!ensure_jump (f, "nat", "PREROUTING", FS_SCRIPT_DNAT_CHAIN) ||
		    !ensure_jump (f, "nat", "POSTROUTING", FS_SCRIPT_SNAT_CHAIN)) {
			*why = g_strdup ("could not hook the nat chains");
			return FALSE;
		}
	} else {
		snap->touched_nat = TRUE;
		teardown_nat (f);
	}

	return TRUE;
}

static gboolean
linux_stop (GError **error)
{
	/* Only our own chains are touched.  A blanket -F/-X on the filter
	 * and nat tables would delete rules belonging to Docker, libvirt,
	 * ufw and anything else sharing the machine.  Every step is quiet:
	 * on a first run there is nothing there yet, and "no such chain" is
	 * the expected answer rather than an error worth showing. */
	if (!require_root (error))
		return FALSE;

	if (!have_iptables (error))
		return FALSE;

	/* The threat-intel table is not touched here either: the policy
	 * apply, reload and clear all come through here, and a policy
	 * change must never drop the blocklists or their counters [N6].
	 * Only the user's Stop removes them: the CLI's `stop' and the
	 * status view's Stop call fs_intel_suspend after this slot, and
	 * Start calls fs_intel_resume after `start'. */
	teardown_filter (&FAMILY4);
	teardown_nat (&FAMILY4);

	if (have_ip6tables ()) {
		teardown_filter (&FAMILY6);
		teardown_nat (&FAMILY6);
	}

	legacy_cleanup ();
	return TRUE;
}

static gboolean
linux_reload (GError **error)
{
	if (!linux_stop (error))
		return FALSE;

	return linux_start (error);
}

static FsApplyResult
linux_apply_rules (const FsPolicy *policy, GError **error)
{
	FsRestorePlan *plan;
	GError *local = NULL;
	FamilySnap snap4, snap6;
	gboolean do6, ok;
	gchar *why = NULL;
	FsApplyResult result = FS_APPLY_OK;
	GString *notes;

	if (!require_root (error))
		return FS_APPLY_FAILED;

	if (!have_iptables (error))
		return FS_APPLY_NO_IPTABLES;

	if (current_settings == NULL) {
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fs-backend-linux"),
		                     0, "No firewall settings have been loaded.");
		return FS_APPLY_FAILED;
	}

	/* Everything is rendered (and every host name looked up) before
	 * anything in the kernel changes. */
	/* A block whose name cannot be looked up: while StockFW's rules
	 * are loaded the apply is refused and they stay (they hold the
	 * last good addresses); with nothing loaded, refusing would leave
	 * every host unfiltered, so the block is left out and the apply's
	 * notes say NOT BLOCKED. */
	plan = fs_script_restore_plan_ex (policy, current_settings,
	                                  chain_exists () ? FS_PLAN_STRICT_BLOCKS
	                                                  : FS_PLAN_LENIENT_BLOCKS,
	                                  &local);
	if (plan == NULL) {
		g_propagate_error (error, local);
		return FS_APPLY_FAILED;
	}

	do6 = kernel_has_ipv6 () && have_ip6tables ();

	memset (&snap4, 0, sizeof (snap4));
	memset (&snap6, 0, sizeof (snap6));
	take_snapshot (&FAMILY4, "filter", FILTER_CHAINS, &snap4.filter);
	take_snapshot (&FAMILY4, "nat", NAT_CHAINS, &snap4.nat);
	snap4.forward_hooked = jump_present (&FAMILY4, "filter", "FORWARD",
	                                     "INBOUND");
	if (do6) {
		take_snapshot (&FAMILY6, "filter", FILTER_CHAINS, &snap6.filter);
		take_snapshot (&FAMILY6, "nat", NAT_CHAINS, &snap6.nat);
		snap6.forward_hooked = jump_present (&FAMILY6, "filter",
		                                     "FORWARD", "INBOUND");
	}

	ok = load_family (&FAMILY4, &plan->v4, &snap4, &why);
	if (!ok) {
		gboolean back = roll_back (&FAMILY4, &snap4);

		g_set_error (error, g_quark_from_static_string ("fs-backend-linux"),
		             0, "The IPv4 rules were refused (%s). %s", why,
		             back ? "Nothing was changed."
		                  : "Putting the previous rules back also failed; "
		                    "stop and start the firewall.");
		result = FS_APPLY_FAILED;
	} else if (do6 && !load_family (&FAMILY6, &plan->v6, &snap6, &why)) {
		/* Both families, always: && would skip IPv4 whenever the
		 * IPv6 side could not be put back, leaving IPv4 on the new
		 * policy while the error says nothing changed. */
		gboolean back6 = roll_back (&FAMILY6, &snap6);
		gboolean back4 = roll_back (&FAMILY4, &snap4);
		gboolean back = back6 && back4;

		g_set_error (error, g_quark_from_static_string ("fs-backend-linux"),
		             0, "The IPv6 rules were refused (%s). %s", why,
		             back ? "IPv4 was put back as it was, so nothing "
		                    "changed."
		                  : "Putting the previous rules back also failed; "
		                    "stop and start the firewall.");
		result = FS_APPLY_FAILED;
	}

	g_clear_pointer (&last_notes, g_free);

	if (result == FS_APPLY_OK) {
		legacy_cleanup ();

		if (fs_settings_sharing (current_settings)) {
			linux_sysctl_forwarding ();
			if (do6 && plan->v6.nat != NULL)
				linux_sysctl_forwarding6 (current_settings->ext_device);
		}

		/* Notes, not a PARTIAL result: the policy is in force as
		 * planned.  PARTIAL would make the apply gate roll back to
		 * the previous policy -- on every apply, on a host without
		 * ip6tables. */
		notes = g_string_new (NULL);
		if (!do6 && kernel_has_ipv6 ())
			g_string_append (notes, "IPv6 is not filtered: ip6tables "
			                        "is not installed.\n");
		for (guint i = 0; i < plan->skipped->len; i++)
			g_string_append_printf (notes, "%s\n", (const gchar *)
			                        g_ptr_array_index (plan->skipped, i));
		for (guint i = 0; i < plan->notes->len; i++)
			g_string_append_printf (notes, "%s\n", (const gchar *)
			                        g_ptr_array_index (plan->notes, i));
		if (notes->len > 0) {
			g_string_truncate (notes, notes->len - 1);
			last_notes = g_string_free (notes, FALSE);
		} else {
			g_string_free (notes, TRUE);
		}
	}

	g_free (why);
	family_snap_clear (&snap4);
	family_snap_clear (&snap6);
	fs_restore_plan_free (plan);
	return result;
}

/* [ linux_apply_notes ] -- see FsBackend.apply_notes. */
static gchar *
linux_apply_notes (void)
{
	return g_strdup (last_notes);
}

/* [ linux_ipv6_state ] -- see FsBackend.ipv6_state. */
static FsIpv6State
linux_ipv6_state (gchar **detail)
{
	FsIpv6State state;
	const gchar *text;
	const gchar *hook[] = { "-C", "INPUT", "-j", "INBOUND", NULL };
	const gchar *list[] = { "-n", "-L", "INBOUND", NULL };

	if (!kernel_has_ipv6 ()) {
		state = FS_IPV6_ABSENT;
		text = "This system has no IPv6, so there is nothing to filter.";
	} else if (geteuid () != 0) {
		state = FS_IPV6_UNKNOWN;
		text = "Run StockFW as root to see whether IPv6 is filtered.";
	} else if (!have_ip6tables ()) {
		state = FS_IPV6_UNFILTERED;
		text = "ip6tables is not installed, so IPv6 traffic is not "
		       "filtered.";
	} else if (tool_quiet (&FAMILY6, "filter", list) != 0) {
		state = FS_IPV6_UNFILTERED;
		text = chain_exists ()
			? "The IPv6 rules are not loaded. Apply the policy again."
			: "The firewall is stopped.";
	} else if (tool_quiet (&FAMILY6, "filter", hook) != 0) {
		state = FS_IPV6_UNFILTERED;
		text = "The IPv6 rules are loaded but not in use. Apply the "
		       "policy again.";
	} else {
		state = FS_IPV6_FILTERED;
		text = "IPv4 and IPv6 are filtered by the same policy.";
	}

	if (detail != NULL)
		*detail = g_strdup (text);
	return state;
}

/* [ linux_sysctl_forwarding ] */
static void
linux_sysctl_forwarding (void)
{
	FILE *fp = fopen ("/proc/sys/net/ipv4/ip_forward", "w");

	if (fp == NULL)
		return;

	fputs ("1\n", fp);
	fclose (fp);
}

/* [ linux_sysctl_forwarding6 ]
 * IPv6 port forwards need IPv6 forwarding.  Turning it on makes the
 * kernel treat the host as a router, and a router ignores router
 * advertisements -- the host would lose its own IPv6 default route on
 * the outside interface.  accept_ra=2 there first keeps them ("accept
 * even when forwarding"), and only when it was 1 (the default): 0
 * means someone turned adverts off on purpose. */
static void
linux_sysctl_forwarding6 (const gchar *ext)
{
	FILE *fp;

	if (fs_util_is_valid_ifname (ext)) {
		gchar *path = g_strdup_printf ("/proc/sys/net/ipv6/conf/%s/accept_ra",
		                               ext);
		gchar *now = NULL;

		if (g_file_get_contents (path, &now, NULL, NULL) &&
		    g_strcmp0 (g_strstrip (now), "1") == 0 &&
		    (fp = fopen (path, "w")) != NULL) {
			fputs ("2\n", fp);
			fclose (fp);
		}
		g_free (now);
		g_free (path);
	}

	fp = fopen ("/proc/sys/net/ipv6/conf/all/forwarding", "w");
	if (fp == NULL)
		return;

	fputs ("1\n", fp);
	fclose (fp);
}

static FsApplyResult
linux_clear_rules (GError **error)
{
	if (!require_root (error))
		return FS_APPLY_FAILED;

	return (linux_stop (NULL) ? FS_APPLY_OK : FS_APPLY_FAILED);
}

/* ==================================================================
 * Threat intel (1.0.7, design section 7)
 *
 * The blocklists live in one nftables table of their own, inet
 * stockfw_intel, and these four slots are the only code here that
 * runs nft.  The policy above runs iptables only, so applying,
 * reloading, stopping or clearing the policy never touches the lists
 * [N6, S10.2]; and these slots name no table but theirs, so Docker's,
 * libvirt's, firewalld's, the iptables-nft tables holding the policy
 * and the standalone helper's inet stockfw_blocklist are left alone.
 *
 * The kernel, not nft's exit status, is the answer.  An apply or a
 * clear always ends by reading the live table back: a timeout can fire
 * after nft committed, an nft killed by a signal may have been killed
 * after, and a success is still only "applied" when the table in the
 * kernel carries the digest that was asked for [S10].
 *
 * Errors are G_IO_ERROR: PERMISSION_DENIED (not root), NOT_FOUND (no
 * nft), TIMED_OUT, INVALID_ARGUMENT (a rule set that cannot be
 * rendered), FAILED (everything else).
 * ================================================================== */

/* Listings are small and the status pages read them on a timer, so
 * they get less time than a load (FS_NFT_TIMEOUT_MS, design 7). */
#define INTEL_LIST_TIMEOUT_MS 10000u

static const gchar *const INTEL_CHAINS[] = { "input", "output", "forward",
                                             NULL };

/* [ intel_timeout ]
 * Test builds only (FS_BACKEND_TESTING): $STOCKFW_TEST_NFT_TIMEOUT_MS
 * replaces every nft timeout, so the tests' hanging nft is stopped in
 * a second rather than a minute. */
static guint
intel_timeout (guint normal)
{
#ifdef FS_BACKEND_TESTING
	const gchar *text = g_getenv ("STOCKFW_TEST_NFT_TIMEOUT_MS");

	if (text != NULL) {
		guint64 value = g_ascii_strtoull (text, NULL, 10);

		if (value > 0 && value <= G_MAXUINT)
			return (guint) value;
	}
#endif
	return normal;
}

/* [ intel_ready ]
 * Root and an nft to run, checked before anything is spawned: an nft
 * that is not there, or a kernel that will not answer an ordinary
 * user, gives a sentence the user can act on instead of nft's own
 * complaint. */
static gboolean
intel_ready (GError **error)
{
	gchar *nft;

	if (geteuid () != 0) {
		g_set_error_literal (error, G_IO_ERROR,
		                     G_IO_ERROR_PERMISSION_DENIED,
		                     "Loading or reading the threat-intel "
		                     "blocklists requires root privileges. Run "
		                     "StockFW with sudo.");
		return FALSE;
	}

	nft = g_find_program_in_path ("nft");
	if (nft == NULL) {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
		                     "nft was not found on PATH. Install the "
		                     "nftables package to use blocklists.");
		return FALSE;
	}
	g_free (nft);
	return TRUE;
}

/* [ intel_read_live ]
 * The table in the kernel now.  First `nft -j list chains inet': the
 * script puts the digest on every chain, and listing chains never
 * loads a set element (milliseconds; `nft -j list tables' loads them
 * all: about 2 s at 240k intervals, 11 to 13 s with a large country's
 * 600,000 elements, past the listing timeout -- design 13.7).  Any
 * other answer is read again from `nft -j list tables': a table whose
 * chains carry no common digest (an older StockFW's, or changed by
 * hand) by its own comment, and no chain of ours at all because a
 * table without chains still is a table -- that listing is cheap when
 * there is no table, so the common "not loaded" case stays fast.  A
 * table found that way with no chain of ours blocks nothing, whatever
 * its comment says: present, with no digest, so it reads "differs".
 * UNKNOWN, with error, when it cannot be read -- never
 * ABSENT: a listing nobody could read says nothing about the kernel.
 * *digest (caller frees) is set only for PRESENT, and may still be
 * NULL then. */
static FsIntelLive
intel_read_live (gchar **digest, GError **error)
{
	static const gchar *const chains[] = { "-j", "list", "chains", "inet",
	                                       NULL };
	static const gchar *const tables[] = { "-j", "list", "tables", NULL };
	FsIntelLive live, by_chains;
	gchar *json;

	*digest = NULL;
	if (!intel_ready (error))
		return FS_INTEL_LIVE_UNKNOWN;

	json = fs_nft_capture (chains, intel_timeout (INTEL_LIST_TIMEOUT_MS),
	                       error);
	if (json == NULL)
		return FS_INTEL_LIVE_UNKNOWN;
	by_chains = fs_intelset_nft_parse_live_chains (json, digest);
	g_free (json);
	if (by_chains == FS_INTEL_LIVE_UNKNOWN) {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
		                     "nft printed a chain listing that could not "
		                     "be read");
		return by_chains;
	}
	if (by_chains == FS_INTEL_LIVE_PRESENT && *digest != NULL)
		return by_chains;
	g_clear_pointer (digest, g_free);

	json = fs_nft_capture (tables, intel_timeout (INTEL_LIST_TIMEOUT_MS),
	                       error);
	if (json == NULL)
		return FS_INTEL_LIVE_UNKNOWN;
	live = fs_intelset_nft_parse_live_state (json, digest);
	if (live == FS_INTEL_LIVE_UNKNOWN)
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
		                     "nft printed a table listing that could not "
		                     "be read");
	/* A table with no chain of ours blocks nothing, whatever its own
	 * comment says: present, with no digest, so it reads "differs". */
	if (live == FS_INTEL_LIVE_PRESENT && by_chains == FS_INTEL_LIVE_ABSENT)
		g_clear_pointer (digest, g_free);
	g_free (json);
	return live;
}

/* [ full_stop ]
 * "." unless `text' already ends a sentence: nft's own messages
 * sometimes do, and a message is often followed by another sentence. */
static const gchar *
full_stop (const gchar *text)
{
	gsize len = strlen (text);

	return len > 0 && text[len - 1] == '.' ? "" : ".";
}

/* [ intel_in_force ]
 * One sentence on what the kernel holds after a load or a removal that
 * did not do what it was asked: the user must know whether the old
 * lists still block, or nothing does.  Caller frees. */
static gchar *
intel_in_force (FsIntelLive live, const gchar *have, const GError *why)
{
	switch (live) {
	case FS_INTEL_LIVE_PRESENT:
		if (have == NULL)
			return g_strdup ("A stockfw_intel table that StockFW did "
			                 "not write is loaded.");
		return g_strdup_printf ("The blocklists loaded before "
		                        "(fingerprint %s) are still in force.",
		                        have);
	case FS_INTEL_LIVE_ABSENT:
		return g_strdup ("No blocklists are loaded now.");
	default:
		return g_strdup_printf ("Whether any blocklists are loaded now "
		                        "could not be read: %s%s",
		                        why != NULL ? why->message
		                                    : "no reason given",
		                        why != NULL ? full_stop (why->message)
		                                    : ".");
	}
}

/* [ intel_settle ]
 * The shared end of an apply and a clear: nft has run (`ran', with
 * run_error when it did not end well) and the kernel was read back
 * (`live', `have', read_error); `had' is the digest live before nft
 * ran (NULL: none, or not read).  TRUE when the kernel holds what was
 * asked for -- `want' as the digest, or no table when want is NULL --
 * whatever nft said; otherwise FALSE with an error that says what went
 * wrong and what is in force instead.
 *
 * One exception: nft failed and the kernel holds `want' because it held
 * it before.  That is exactly what a transaction the kernel refused
 * leaves behind when the rule set did not change (the hourly re-apply),
 * so it is no proof the table was replaced: FALSE, saying the same
 * lists are still in force, never a success nobody saw. */
static gboolean
intel_settle (const gchar *what, const gchar *want, const gchar *had,
              gboolean ran, const GError *run_error, FsIntelLive live,
              const gchar *have, const GError *read_error, GError **error)
{
	const gchar *said = run_error != NULL ? run_error->message
	                                      : "nft failed without saying why";
	gchar *now;

	if (want == NULL ? live == FS_INTEL_LIVE_ABSENT
	                 : live == FS_INTEL_LIVE_PRESENT &&
	                   g_strcmp0 (have, want) == 0) {
		if (ran)
			return TRUE;
		if (want != NULL && g_strcmp0 (had, want) == 0) {
			g_set_error (error,
			             run_error != NULL ? run_error->domain
			                               : G_IO_ERROR,
			             run_error != NULL ? run_error->code
			                               : G_IO_ERROR_FAILED,
			             "%s%s The same blocklists (fingerprint %s) "
			             "were already loaded and are still in force.",
			             said, full_stop (said), want);
			return FALSE;
		}
		g_debug ("threat intel: the %s took effect although nft "
		         "reported: %s", what, said);
		return TRUE;
	}

	if (!ran) {
		now = intel_in_force (live, have, read_error);
		g_set_error (error,
		             run_error != NULL ? run_error->domain : G_IO_ERROR,
		             run_error != NULL ? run_error->code
		                               : G_IO_ERROR_FAILED,
		             "%s%s %s", said, full_stop (said), now);
		g_free (now);
		return FALSE;
	}

	/* nft said yes, and the kernel says otherwise -- or says
	 * nothing.  Reporting the lists as loaded would claim a
	 * protection nobody saw [S10]. */
	if (live == FS_INTEL_LIVE_UNKNOWN)
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "nft accepted the %s, but the blocklist table "
		             "could not be read back to confirm it: %s%s", what,
		             read_error != NULL ? read_error->message
		                                : "no reason given",
		             read_error != NULL ? full_stop (read_error->message)
		                                : ".");
	else if (live == FS_INTEL_LIVE_ABSENT)
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "nft accepted the %s, but no blocklist table is "
		             "loaded now: something removed it.", what);
	else if (want == NULL)
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "nft accepted the %s, but a blocklist table "
		             "(fingerprint %s) is still loaded.", what,
		             have != NULL ? have : "none");
	else
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "nft accepted the %s, but the blocklist table "
		             "loaded now is not the one applied (fingerprint "
		             "%s, not %s): something replaced it.", what,
		             have != NULL ? have : "none", want);
	return FALSE;
}

/* [ linux_intel_apply ] -- see FsBackend.intel_apply. */
static gboolean
linux_intel_apply (const FsIntelRuleset *ruleset, GError **error)
{
	GError *run_error = NULL, *read_error = NULL;
	gchar *script, *want = NULL, *have = NULL, *had = NULL;
	FsIntelLive live;
	gboolean ran, ok;

	g_return_val_if_fail (ruleset != NULL, FALSE);

	if (!intel_ready (error))
		return FALSE;

	script = fs_intelset_nft_script (ruleset);
	if (script == NULL) {
		g_set_error_literal (error, G_IO_ERROR,
		                     G_IO_ERROR_INVALID_ARGUMENT,
		                     "The blocklist rule set cannot be loaded: a "
		                     "list id is invalid or repeated. Nothing was "
		                     "changed.");
		return FALSE;
	}

	/* The empty rule set renders no table at all, so what must be
	 * live afterwards is no table -- not a table with the empty rule
	 * set's digest. */
	if (ruleset->sets->len > 0)
		want = fs_intel_ruleset_digest (ruleset);

	/* What was live before: if nft fails and the same digest is live
	 * afterwards, it may never have been replaced (intel_settle).  A
	 * listing, never the elements. */
	if (intel_read_live (&had, NULL) != FS_INTEL_LIVE_PRESENT)
		g_clear_pointer (&had, g_free);

	/* One nft call, one transaction: the script creates the table if
	 * it is missing, deletes it and builds the new one, so the old
	 * lists stay in force unless the new ones load whole.  Deleting
	 * first in a call of its own would leave the computer without
	 * any blocklist whenever the new ones are refused.  A re-apply of
	 * the same digest replaces the table too: it repairs a table
	 * edited behind StockFW's back, and it resets the counters, which
	 * the engine carries over once it sees the table was replaced (a
	 * counter lower than before) -- skipping it would make the engine
	 * count the same packets again next time. */
	ran = fs_nft_run_script_full (script, FALSE,
	                              intel_timeout (FS_NFT_TIMEOUT_MS),
	                              &run_error);
	g_free (script);

	live = intel_read_live (&have, &read_error);
	ok = intel_settle ("blocklists", want, had, ran, run_error, live,
	                   have, read_error, error);

	g_clear_error (&run_error);
	g_clear_error (&read_error);
	g_free (have);
	g_free (had);
	g_free (want);
	return ok;
}

/* [ linux_intel_clear ] -- see FsBackend.intel_clear. */
static gboolean
linux_intel_clear (GError **error)
{
	GError *run_error = NULL, *read_error = NULL;
	gchar *script, *have = NULL;
	FsIntelLive live;
	gboolean ran, ok;

	if (!intel_ready (error))
		return FALSE;

	/* Declares the table first, so removing a table that is not
	 * there is not an error; names nothing else. */
	script = fs_intelset_nft_clear_script ();
	ran = fs_nft_run_script_full (script, FALSE,
	                              intel_timeout (FS_NFT_TIMEOUT_MS),
	                              &run_error);
	g_free (script);

	live = intel_read_live (&have, &read_error);
	ok = intel_settle ("removal", NULL, NULL, ran, run_error, live, have,
	                   read_error, error);

	g_clear_error (&run_error);
	g_clear_error (&read_error);
	g_free (have);
	return ok;
}

/* [ linux_intel_counters ] -- see FsBackend.intel_counters.
 * One `nft list chain' per base chain, never the table or a set: those
 * would print every element, hundreds of thousands of lines on a timer
 * [S8.3].  A chain that cannot be listed (no table, not root, no nft,
 * a timeout) makes the whole answer NULL: a partial count would read
 * as fewer blocks. */
static GHashTable *
linux_intel_counters (void)
{
	GString *listing;
	GHashTable *counters;

	if (!intel_ready (NULL))
		return NULL;

	listing = g_string_new (NULL);
	for (guint c = 0; INTEL_CHAINS[c] != NULL; c++) {
		const gchar *args[] = { "list", "chain", "inet",
		                        FS_INTEL_NFT_TABLE, INTEL_CHAINS[c],
		                        NULL };
		gchar *text = fs_nft_capture (args,
		                              intel_timeout (INTEL_LIST_TIMEOUT_MS),
		                              NULL);

		if (text == NULL) {
			g_string_free (listing, TRUE);
			return NULL;
		}
		g_string_append (listing, text);
		g_string_append_c (listing, '\n');
		g_free (text);
	}

	counters = fs_intelset_nft_parse_counters (listing->str);
	g_string_free (listing, TRUE);
	return counters;
}

/* Why this thread's last linux_intel_live was UNKNOWN. */
static GPrivate live_error = G_PRIVATE_INIT (g_free);

/* [ linux_intel_live ] -- see FsBackend.intel_live. */
static FsIntelLive
linux_intel_live (gchar **digest)
{
	gchar *have = NULL;
	GError *error = NULL;
	FsIntelLive live = intel_read_live (&have, &error);

	g_private_replace (&live_error, live == FS_INTEL_LIVE_UNKNOWN &&
	                   error != NULL ? g_strdup (error->message) : NULL);
	g_clear_error (&error);
	if (digest != NULL)
		*digest = have;
	else
		g_free (have);
	return live;
}

/* [ linux_intel_live_error ] -- see FsBackend.intel_live_error. */
static gchar *
linux_intel_live_error (void)
{
	return g_strdup (g_private_get (&live_error));
}

static GList *
linux_list_interfaces (void)
{
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa;
	GList *list = NULL;

	if (getifaddrs (&ifaddr) != 0)
		return NULL;

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		FsInterface *iface;

		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
			continue;

		/* Skip loopback: it is not a firewall interface. */
		if ((ifa->ifa_flags & IFF_LOOPBACK) != 0)
			continue;

		iface = g_new0 (FsInterface, 1);

		{
			struct sockaddr_in *sin =
				(struct sockaddr_in *) ifa->ifa_addr;
			struct sockaddr_in *mask = NULL;
			char addr[INET_ADDRSTRLEN];
			char netmask[INET_ADDRSTRLEN];

			if (inet_ntop (AF_INET, &sin->sin_addr, addr,
			               sizeof (addr)) != NULL)
				iface->ip = g_strdup (addr);

			/* The netmask lives in a separate getifaddrs entry
			 * whose ifa_addr is NULL and whose ifa_netmask is
			 * set.  Matching on the address family instead would
			 * find the address entry again and report the address
			 * as its own netmask. */
			for (struct ifaddrs *m = ifaddr; m != NULL;
			     m = m->ifa_next) {
				if (m->ifa_netmask != NULL &&
				    m->ifa_netmask->sa_family == AF_INET &&
				    g_strcmp0 (m->ifa_name, ifa->ifa_name) == 0) {
					mask = (struct sockaddr_in *) m->ifa_netmask;
					break;
				}
			}

			if (mask != NULL &&
			    inet_ntop (AF_INET, &mask->sin_addr, netmask,
			               sizeof (netmask)) != NULL)
				iface->netmask = g_strdup (netmask);
		}

		iface->name = g_strdup (ifa->ifa_name);
		iface->nat_capable = interface_is_nat_capable (ifa->ifa_name);

		list = g_list_append (list, iface);
	}

	freeifaddrs (ifaddr);

	return list;
}

/* ------------------------------------------------------- traffic panels
 *
 * The Status page's Network and Active connections panels, and the
 * Activity page's Network I/O graph.  Everything here reads files any
 * user can read -- /proc/net/dev, /proc/net/tcp{,6}, /sys/class/net --
 * so the panels work without root.  Only the owner of a socket is
 * limited: another user's /proc/<pid>/fd cannot be listed unprivileged,
 * and such rows say "?" rather than guess.
 */

/* [ read_sysfs_attr ]
 * One line of /sys/class/net/<dev>/<attr>, stripped, or NULL. */
static gchar *
read_sysfs_attr (const gchar *device, const gchar *attr)
{
	gchar *path = g_build_filename ("/sys/class/net", device, attr, NULL);
	gchar *text = NULL;

	if (!g_file_get_contents (path, &text, NULL, NULL))
		text = NULL;
	else
		g_strstrip (text);

	g_free (path);
	return text;
}

/* [ sysfs_has ] -- TRUE when /sys/class/net/<dev>/<entry> exists. */
static gboolean
sysfs_has (const gchar *device, const gchar *entry)
{
	gchar *path = g_build_filename ("/sys/class/net", device, entry, NULL);
	gboolean exists = g_file_test (path, G_FILE_TEST_EXISTS);

	g_free (path);
	return exists;
}

/* [ interface_kind ]
 * The Type column, in the words the Windows backend uses: a wireless
 * extension or phy80211 link means Wireless, a backing bus device
 * means a real adapter, anything else (bridges, veth, tun, docker0)
 * is Virtual. */
static const gchar *
interface_kind (const gchar *device)
{
	if (sysfs_has (device, "wireless") || sysfs_has (device, "phy80211"))
		return "Wireless";
	if (sysfs_has (device, "device"))
		return "Ethernet";

	return "Virtual";
}

/* [ interface_is_up ]
 * operstate "up", or "unknown" for drivers that never report one
 * (tun devices, some virtual NICs) while the link is administratively
 * up. */
static gboolean
interface_is_up (const gchar *device)
{
	gchar *state = read_sysfs_attr (device, "operstate");
	gboolean up = FALSE;

	if (state != NULL) {
		if (strcmp (state, "up") == 0) {
			up = TRUE;
		} else if (strcmp (state, "unknown") == 0) {
			gchar *flags = read_sysfs_attr (device, "flags");

			up = flags != NULL &&
			     (g_ascii_strtoull (flags, NULL, 16) & IFF_UP) != 0;
			g_free (flags);
		}
	}

	g_free (state);
	return up;
}

/* [ interface_ipv4 ] -- first IPv4 address of a device, or NULL. */
static gchar *
interface_ipv4 (struct ifaddrs *ifaddr, const gchar *device)
{
	for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		char addr[INET_ADDRSTRLEN];

		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET ||
		    g_strcmp0 (ifa->ifa_name, device) != 0)
			continue;

		if (inet_ntop (AF_INET,
		               &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr,
		               addr, sizeof (addr)) != NULL)
			return g_strdup (addr);
	}

	return NULL;
}

/* [ linux_list_interface_stats ]
 * Cumulative rx/tx octets per interface from /proc/net/dev.  The
 * views sample twice and diff, exactly as on Windows.  Loopback is
 * left out by the parser; an adapter that is down and has never
 * carried a byte is still enumerating and is left out here -- the
 * same two rules GetIfTable2's caller applies. */
static GList *
linux_list_interface_stats (void)
{
	gchar *text = NULL;
	GList *stats, *l;
	struct ifaddrs *ifaddr = NULL;

	if (!g_file_get_contents ("/proc/net/dev", &text, NULL, NULL))
		return NULL;

	stats = fs_netparse_proc_dev (text);
	g_free (text);

	if (getifaddrs (&ifaddr) != 0)
		ifaddr = NULL;

	l = stats;
	while (l != NULL) {
		GList *next = l->next;
		FsIfaceStat *stat = l->data;

		stat->up = interface_is_up (stat->device);

		if (!stat->up && stat->received == 0 && stat->sent == 0) {
			fs_iface_stat_free (stat);
			stats = g_list_delete_link (stats, l);
		} else {
			stat->kind = g_strdup (interface_kind (stat->device));
			stat->ip   = interface_ipv4 (ifaddr, stat->device);
		}

		l = next;
	}

	if (ifaddr != NULL)
		freeifaddrs (ifaddr);

	return stats;
}

/* [ program_for_pid ]
 * The executable's basename, as the Windows backend shows it; the
 * kernel's 15-character comm name when the exe link cannot be read
 * (another user's process, a kernel thread). */
static gchar *
program_for_pid (const gchar *pid)
{
	gchar *link = g_build_filename ("/proc", pid, "exe", NULL);
	gchar *target = g_file_read_link (link, NULL);
	gchar *name = NULL;

	g_free (link);

	if (target != NULL) {
		/* A replaced binary reads "/usr/bin/foo (deleted)". */
		if (g_str_has_suffix (target, " (deleted)"))
			target[strlen (target) - strlen (" (deleted)")] = '\0';
		name = g_path_get_basename (target);
		g_free (target);
		return name;
	}

	link = g_build_filename ("/proc", pid, "comm", NULL);
	if (g_file_get_contents (link, &name, NULL, NULL))
		g_strstrip (name);
	else
		name = NULL;
	g_free (link);

	return name;
}

/* [ socket_owners ]
 * socket inode -> program name, for every process whose fd table this
 * account may list.  Built only when there is a socket to look up, so
 * an idle machine does not walk /proc every refresh for nothing. */
static GHashTable *
socket_owners (const GList *sockets)
{
	GHashTable *wanted, *owners;
	GDir *proc;
	const gchar *pid;

	wanted = g_hash_table_new (g_int64_hash, g_int64_equal);
	for (const GList *l = sockets; l != NULL; l = l->next) {
		FsNetSocket *s = l->data;

		if (s->inode != 0)
			g_hash_table_add (wanted, &s->inode);
	}

	owners = g_hash_table_new_full (g_int64_hash, g_int64_equal,
	                                g_free, g_free);

	if (g_hash_table_size (wanted) == 0) {
		g_hash_table_unref (wanted);
		return owners;
	}

	proc = g_dir_open ("/proc", 0, NULL);

	while (proc != NULL && (pid = g_dir_read_name (proc)) != NULL) {
		gchar *fd_path;
		GDir *fds;
		const gchar *fd;
		gchar *program = NULL;

		if (!g_ascii_isdigit (*pid))
			continue;

		fd_path = g_build_filename ("/proc", pid, "fd", NULL);
		fds = g_dir_open (fd_path, 0, NULL);

		while (fds != NULL && (fd = g_dir_read_name (fds)) != NULL) {
			gchar *link = g_build_filename (fd_path, fd, NULL);
			gchar *target = g_file_read_link (link, NULL);
			guint64 inode;

			g_free (link);

			if (target != NULL &&
			    sscanf (target, "socket:[%" G_GUINT64_FORMAT "]",
			            &inode) == 1 &&
			    g_hash_table_contains (wanted, &inode) &&
			    !g_hash_table_contains (owners, &inode)) {
				gint64 *key = g_new (gint64, 1);

				if (program == NULL)
					program = program_for_pid (pid);

				*key = (gint64) inode;
				g_hash_table_insert (owners, key,
				                     g_strdup (program != NULL
				                               ? program : "?"));
			}

			g_free (target);
		}

		if (fds != NULL)
			g_dir_close (fds);
		g_free (fd_path);
		g_free (program);

		/* Every socket placed: the rest of /proc cannot add one. */
		if (g_hash_table_size (owners) == g_hash_table_size (wanted))
			break;
	}

	if (proc != NULL)
		g_dir_close (proc);

	g_hash_table_unref (wanted);

	return owners;
}

/* [ linux_list_connections ]
 * Connected TCP sockets, IPv4 and IPv6, with their owning program. */
static GList *
linux_list_connections (void)
{
	GList *sockets = NULL;
	GList *list;
	GHashTable *owners;
	gchar *text = NULL;

	if (g_file_get_contents ("/proc/net/tcp", &text, NULL, NULL)) {
		sockets = fs_netparse_proc_tcp (text, FALSE);
		g_free (text);
	}

	if (g_file_get_contents ("/proc/net/tcp6", &text, NULL, NULL)) {
		sockets = g_list_concat (sockets,
		                         fs_netparse_proc_tcp (text, TRUE));
		g_free (text);
	}

	owners = socket_owners (sockets);
	list = fs_netparse_connections (sockets, owners);

	g_hash_table_unref (owners);
	g_list_free_full (sockets, (GDestroyNotify) fs_net_socket_free);

	return list;
}

/* ------------------------------------------------------------ syslog tail
 *
 * The original read /var/log/messages with gnome-vfs.  Here the firewall
 * rules log to syslog, so we read from a dedicated file descriptor and
 * parse the kern prefix.  Keeping the child means we do not depend on
 * logrotate's handling of the file.
 *
 * The line parser itself is fs_netparse_log_line() in core, where the
 * core suite pins every field.
 */

/* Bytes after the last newline of the previous read: a line split
 * across two reads is completed on the next poll instead of being
 * parsed as two broken halves. */
static GString *log_partial = NULL;

/* The longest partial line kept.  A kernel log line is well under
 * this; anything longer without a newline is not a log line. */
#define LOG_PARTIAL_MAX 8192

/* [ deliver_log_line ]
 * One complete line: parse it, name it, mark it, hand it over.
 *
 * A DROP or REJECT line is a packet the script is about to refuse, and
 * is marked blocked exactly as the Windows backend marks its 5157s
 * (without the marker no Linux row was ever painted red, the Status
 * page's Serious column stayed at zero and Sentinel's blocked fan-out
 * signal could not fire).  An ALLOW line (1.0.7) is the first packet
 * of a connection the policy accepted, and stays unmarked. */
static void
deliver_log_line (const gchar *line)
{
	FsHit hit = { 0 };
	gchar *intel_id = NULL;

	if (*line == '\0')
		return;

	/* A threat-intel block (design 7): shown only when the id is a set
	 * of the rule set StockFW applied, so a stale or invented
	 * "STOCKFW-TI" line is never attributed to a list [S17.3]. */
	if (fs_netparse_intel_line (line, &hit, NULL, &intel_id)) {
		if (!fs_intel_applied_has (intel_id)) {
			g_free (intel_id);
			fs_netparse_clear_hit (&hit);
			return;
		}
		fs_netparse_name_blocked (&hit);
		hit.rule = fs_intel_rule_text (intel_id);
		g_free (intel_id);
		if (log_callback != NULL)
			log_callback (&hit, log_user_data);
		fs_netparse_clear_hit (&hit);
		return;
	}

	if (!fs_netparse_log_line (line, &hit, NULL))
		return;

	/* DROP/REJECT lines are blocked packets; since 1.0.7 the policy's
	 * accept chain also logs new connections it lets through. */
	fs_netparse_name_by_verdict (&hit, fs_netparse_log_verdict (line));

	if (log_callback != NULL)
		log_callback (&hit, log_user_data);

	/* "hit" is a stack local: free the fields, not the struct. */
	fs_netparse_clear_hit (&hit);
}

/* [ set_log_problem ] -- remember why the monitor stopped on its own. */
static void
set_log_problem (gchar *text)
{
	g_free (log_problem_text);
	log_problem_text = text;
}

/* [ reader_exited ]
 * The tail/journalctl child closed its end: reap it and say why, so the
 * Events page can show the reason instead of an empty list that looks
 * like a quiet network.  journalctl on a machine with no journal
 * (WSL, containers, minimal installs) waits forever printing nothing,
 * which is why /dev/kmsg is preferred; this path catches the rest. */
static void
reader_exited (void)
{
	gint status = 0;
	gchar *why;

	if (log_pid > 0 && waitpid (log_pid, &status, WNOHANG) == log_pid) {
		log_pid = 0;
		if (WIFEXITED (status) && WEXITSTATUS (status) == 127)
			why = g_strdup_printf (
				_("The event reader could not start %s."),
				log_source_text != NULL ? log_source_text
				                        : "its log source");
		else if (WIFEXITED (status))
			why = g_strdup_printf (
				_("The event reader stopped: %s exited with "
				  "status %d."),
				log_source_text != NULL ? log_source_text
				                        : "its log source",
				WEXITSTATUS (status));
		else
			why = g_strdup (_("The event reader stopped unexpectedly."));
	} else {
		why = g_strdup (_("The event reader stopped unexpectedly."));
	}

	set_log_problem (why);
	linux_log_stop ();
}

/* [ drain_kmsg ]
 * /dev/kmsg hands out one record per read().  EAGAIN: nothing more for
 * now.  EPIPE: the ring wrapped and records were overwritten before we
 * read them -- the next read continues with the oldest one left, so it
 * is not an error.  Any other error ends the monitor with a reason. */
static void
drain_kmsg (void)
{
	gchar record[8192];

	for (;;) {
		gssize got = read (log_kmsg, record, sizeof (record) - 1);
		gchar *line;

		if (got < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return;
			if (errno == EPIPE || errno == EINTR)
				continue;

			set_log_problem (g_strdup_printf (
				_("Reading the kernel log failed: %s"),
				g_strerror (errno)));
			linux_log_stop ();
			return;
		}

		if (got == 0)
			return;

		record[got] = '\0';
		line = fs_netparse_kmsg_line (record, (gsize) got,
		                              g_get_real_time (),
		                              g_get_monotonic_time ());
		if (line != NULL) {
			deliver_log_line (line);
			g_free (line);
		}

		/* deliver_log_line may have run a callback that stopped the
		 * monitor. */
		if (log_kmsg < 0)
			return;
	}
}

/* [ on_log_poll ]
 * Drains whatever the source has produced since the last tick. */
static gboolean
on_log_poll (gpointer data)
{
	gchar buffer[4096];
	gssize got;

	(void) data;

	if (log_kmsg >= 0) {
		drain_kmsg ();
		return log_running ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
	}

	/* log_pipe[0] is the READ end -- pipe() order is [0] read, [1]
	 * write, and the child put [1] on stdout.  Reading [1] here read a
	 * write-only fd: EBADF on every poll, so no event ever arrived
	 * while log_active() still read TRUE. */
	if (log_pipe[0] < 0)
		return G_SOURCE_REMOVE;

	if (log_partial == NULL)
		log_partial = g_string_new (NULL);

	/* Read everything available; the fd is non-blocking. */
	while ((got = read (log_pipe[0], buffer, sizeof (buffer))) > 0) {
		gchar *start, *newline;

		g_string_append_len (log_partial, buffer, got);

		start = log_partial->str;
		while ((newline = strchr (start, '\n')) != NULL) {
			*newline = '\0';
			deliver_log_line (start);
			start = newline + 1;
		}

		g_string_erase (log_partial, 0, start - log_partial->str);

		if (log_partial->len > LOG_PARTIAL_MAX)
			g_string_truncate (log_partial, 0);

		if (log_pipe[0] < 0)
			return G_SOURCE_REMOVE;
	}

	/* 0 is end of file: the child is gone.  It used to be read as "no
	 * data yet", forever, while log_active() kept saying TRUE. */
	if (got == 0) {
		log_watch = 0;          /* returning REMOVE drops the source */
		reader_exited ();
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

/* [ open_kmsg ]
 * The kernel's own ring buffer, positioned at its end so only new
 * records are read.  Needs root (or CAP_SYSLOG); -1 when unavailable. */
static int
open_kmsg (void)
{
	int fd = open ("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);

	if (fd < 0)
		return -1;

	if (lseek (fd, 0, SEEK_END) < 0) {
		close (fd);
		return -1;
	}

	return fd;
}

static gboolean
linux_log_start (FsLogFunc callback, gpointer user_data, GError **error)
{
	const gchar *override;

	if (log_running)
		return TRUE;

	log_callback = callback;
	log_user_data = user_data;
	set_log_problem (NULL);

	/* Reporting failure does not fail the app -- fs_hitview_start()
	 * hands the message to the page.  Returning TRUE from here instead
	 * was the real problem: monitoring read as switched on while the
	 * list below stayed empty, with nothing to say why. */
	if (geteuid () != 0) {
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fs-backend-linux"),
		                     EACCES,
		                     _("The kernel log cannot be read without "
		                       "root privileges.  Start StockFW as root "
		                       "to see incoming and outbound traffic."));
		return FALSE;
	}

	/* Sources, in order:
	 *
	 *   STOCKFW_LOG_FILE   an explicit file (tests, relocated logs)
	 *   /dev/kmsg          the kernel ring buffer itself: no daemon in
	 *                      between, so it works on WSL, in containers
	 *                      and on minimal installs where there is no
	 *                      journald and no rsyslog -- the case that left
	 *                      the Events page empty with no error (1.0.7)
	 *   /var/log/kern.log  rsyslog's copy
	 *   journalctl -k -f   systemd's copy */
	override = g_getenv ("STOCKFW_LOG_FILE");

	if (override == NULL || *override == '\0') {
		log_kmsg = open_kmsg ();

		if (log_kmsg >= 0) {
			log_source_text = "the kernel ring buffer (/dev/kmsg)";
			log_watch = g_timeout_add (250, on_log_poll, NULL);
			log_running = TRUE;
			return TRUE;
		}
	}

	if (pipe (log_pipe) != 0) {
		g_set_error (error,
		             g_quark_from_static_string ("fs-backend-linux"),
		             errno, _("Could not create a pipe: %s"),
		             g_strerror (errno));
		return FALSE;
	}

	if (override != NULL && *override != '\0')
		log_source_text = "the log file named by STOCKFW_LOG_FILE";
	else if (g_file_test ("/var/log/kern.log", G_FILE_TEST_EXISTS))
		log_source_text = "/var/log/kern.log";
	else
		log_source_text = "journalctl";

	log_pid = fork ();

	if (log_pid < 0) {
		int saved_errno = errno;

		close (log_pipe[0]);
		close (log_pipe[1]);
		log_pipe[0] = log_pipe[1] = -1;

		g_set_error (error,
		             g_quark_from_static_string ("fs-backend-linux"),
		             saved_errno, _("Could not start the log reader: %s"),
		             g_strerror (saved_errno));
		return FALSE;
	}

	if (log_pid == 0) {
		/* Child: the pipe carries tail's *output*, so it goes on
		 * stdout.  Leaving stdout alone meant the log went to the
		 * terminal and the reader never saw a byte. */
		dup2 (log_pipe[1], STDOUT_FILENO);
		close (log_pipe[0]);
		close (log_pipe[1]);

		if (override != NULL && *override != '\0') {
			execlp ("tail", "tail", "-n", "0", "-F",
			        override, (char *) NULL);
		} else if (g_file_test ("/var/log/kern.log",
		                        G_FILE_TEST_EXISTS)) {
			execlp ("tail", "tail", "-n", "0", "-F",
			        "/var/log/kern.log", (char *) NULL);
		} else {
			execlp ("journalctl", "journalctl",
			        "-k", "-f", "-n", "0", "-o", "short",
			        (char *) NULL);
		}

		_exit (127);
	}

	/* The parent keeps only the READ end [0]; its copy of the write end
	 * [1] must go, or read() would never see EOF when tail exits. */
	close (log_pipe[1]);
	log_pipe[1] = -1;

	/* Poll the pipe rather than using a GIOChannel watch.
	 *
	 * A blocking GIOChannel over a pipe is fragile: the watch and the
	 * buffered reader fight over the same data, and on a busy main loop
	 * the reader can block the whole UI.  Polling on a short timeout is
	 * simpler, cannot starve anything, and is far easier to test. */
	g_unix_set_fd_nonblocking (log_pipe[0], TRUE, NULL);

	log_watch = g_timeout_add (250, on_log_poll, NULL);

	log_running = TRUE;

	return TRUE;
}

static void
linux_log_stop (void)
{
	if (!log_running)
		return;

	if (log_watch != 0) {
		g_source_remove (log_watch);
		log_watch = 0;
	}

	if (log_kmsg >= 0) {
		close (log_kmsg);
		log_kmsg = -1;
	}

	if (log_pipe[0] >= 0) {
		close (log_pipe[0]);
		log_pipe[0] = -1;
	}

	if (log_pid > 0) {
		kill (log_pid, SIGTERM);
		waitpid (log_pid, NULL, 0);
		log_pid = 0;
	}

	if (log_partial != NULL)
		g_string_truncate (log_partial, 0);

	log_running = FALSE;
	log_callback = NULL;
	log_user_data = NULL;
}

static gboolean
linux_log_active (void)
{
	return log_running;
}

static const gchar *
linux_log_source (void)
{
	return log_running ? log_source_text : NULL;
}

static const gchar *
linux_log_problem (void)
{
	return log_problem_text;
}

/* Linux has a single global firewall state, not three profiles, so
 * these report "not supported" and the UI hides the per-profile
 * controls.  Returning FALSE is the contract: it is not an error. */
static gboolean
linux_get_profile_enabled (gint profile, gboolean *enabled)
{
	if (enabled != NULL)
		*enabled = FALSE;

	return FALSE;
}

static gboolean
linux_set_profile_enabled (gint profile, gboolean enabled, GError **error)
{
	g_set_error_literal (error,
	                     g_quark_from_static_string ("fs-backend-linux"),
	                     0,
	                     "Linux has a single firewall state, not "
	                     "per-profile settings.");

	(void) profile;
	(void) enabled;

	return FALSE;
}

static gboolean
linux_dhcp_set_enabled (gboolean enabled, GError **error)
{
	if (!require_root (error))
		return FALSE;

	g_set_error_literal (error,
	                     g_quark_from_static_string ("fs-backend-linux"),
	                     0,
	                     "The built-in DHCP server is not implemented yet. "
	                     "Use an external dhcpd, or add one through the "
	                     "wizard.");

	(void) enabled;

	return FALSE;
}

/* -------------------------------------------------------------- vtable */

/* Attach the policy and settings the generator needs.  Declared in
 * core/fs-backend.h so both backends expose the same hook. */
void
fs_backend_set_context (FsPolicy *policy, FsSettings *settings)
{
	current_policy = policy;
	current_settings = settings;

	(void) policy;
	(void) settings;
}

/* Designated initialisers: adding a field to FsBackend cannot silently
 * shift these the way a positional list would. */
static const FsBackend linux_backend = {
	.name                  = "linux",
	.display_name          = "Linux (iptables)",
	/* Every settings page: the generator reads all three.  REJECT vs
	 * DROP is a real iptables choice, the ICMP rules carry -m limit,
	 * the outbound default is ours to set, and the ICMP choices are
	 * the whole story for both families.  linux_start applies the
	 * whole policy, so Start brings saved settings in too. */
	.fw_sections           = FS_FWSEC_NETWORK | FS_FWSEC_ICMP |
	                         FS_FWSEC_ADVANCED,
	.fw_honors             = FS_FWHON_REJECT_METHOD |
	                         FS_FWHON_RATE_LIMIT |
	                         FS_FWHON_LOG_ALLOWED |
	                         FS_FWHON_HOST_NAMES |
	                         FS_FWHON_OUTBOUND_MODE |
	                         FS_FWHON_ICMP_EXACT,
	/* linux_start is linux_apply_rules (current_policy). */
	.start_applies_policy  = TRUE,
	.available             = linux_available,
	.get_state             = linux_get_state,
	.start                 = linux_start,
	.stop                  = linux_stop,
	.reload                = linux_reload,
	.apply_rules           = linux_apply_rules,
	.clear_rules           = linux_clear_rules,
	.list_interfaces       = linux_list_interfaces,
	.list_interface_stats  = linux_list_interface_stats,
	.list_connections      = linux_list_connections,
	.log_start             = linux_log_start,
	.log_stop              = linux_log_stop,
	.log_active            = linux_log_active,
	.log_source            = linux_log_source,
	.log_problem           = linux_log_problem,
	.dhcp_set_enabled      = linux_dhcp_set_enabled,
	.get_profile_enabled   = linux_get_profile_enabled,
	.set_profile_enabled   = linux_set_profile_enabled,
	.ipv6_state            = linux_ipv6_state,
	.apply_notes           = linux_apply_notes,
	.intel_apply           = linux_intel_apply,
	.intel_clear           = linux_intel_clear,
	.intel_counters        = linux_intel_counters,
	.intel_live            = linux_intel_live,
	.intel_live_error      = linux_intel_live_error
};

const FsBackend *
fs_backend (void)
{
	return &linux_backend;
}

const gchar *
fs_error_domain (void)
{
	return "fs-backend-linux";
}