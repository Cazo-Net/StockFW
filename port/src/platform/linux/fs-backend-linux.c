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

/* [ run_command ]
 * Runs argv and returns its exit status, or -1 if it could not be
 * started.  Output is discarded; callers report their own errors. */
static gint
run_command (gchar **argv)
{
	GError *error = NULL;
	gint status = 0;

	if (!g_spawn_sync (NULL, argv, NULL,
	                   G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL,
	                   NULL, NULL, NULL, NULL, &status, &error)) {
		g_clear_error (&error);
		return -1;
	}

	/* g_spawn_sync reports the raw wait status. */
	if (WIFEXITED (status))
		return WEXITSTATUS (status);

	return -1;
}

/* [ run_command_quiet ]
 * Same as run_command but discards stderr too.  Used by the delete-until
 * it-fails probes, where the final failure is the expected answer and
 * would otherwise bury real errors in noise. */
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

	if (!g_find_program_in_path ("iptables")) {
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fs-backend-linux"),
		                     0,
		                     "iptables was not found on PATH.");
		return FALSE;
	}

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
static gboolean apply_lines (gchar *script);
static gboolean apply_nat (const FsSettings *settings);
static void linux_log_stop (void);

static gboolean
linux_available (void)
{
	return (geteuid () == 0);
}

static FsFirewallState
linux_get_state (void)
{
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

/* [ detach_chain ]
 * Removes every "-j <our_chain>" jump from a built-in chain.  iptables
 * cannot delete all matches in one go, so delete in a loop until one
 * fails (i.e. none are left). */
static void
detach_chain (const gchar *builtin, const gchar *our_chain)
{
	for (gint i = 0; i < 64; i++) {
		gchar *args[] = { (gchar *) "iptables", (gchar *) "-w",
		                  (gchar *) "-D", (gchar *) builtin,
		                  (gchar *) "-j", (gchar *) our_chain, NULL };

		if (run_command_quiet (args) != 0)
			break;
	}
}

static gboolean
linux_stop (GError **error)
{
	/* Only our own chains are touched.  A blanket -F/-X on the filter
	 * and nat tables would delete rules belonging to Docker, libvirt,
	 * ufw and anything else sharing the machine. */
	gchar *flush_in[]  = { (gchar *) "iptables", (gchar *) "-w",
	                       (gchar *) "-F", (gchar *) "INBOUND", NULL };
	gchar *flush_out[] = { (gchar *) "iptables", (gchar *) "-w",
	                       (gchar *) "-F", (gchar *) "OUTBOUND", NULL };
	gchar *del_in[]    = { (gchar *) "iptables", (gchar *) "-w",
	                       (gchar *) "-X", (gchar *) "INBOUND", NULL };
	gchar *del_out[]   = { (gchar *) "iptables", (gchar *) "-w",
	                       (gchar *) "-X", (gchar *) "OUTBOUND", NULL };

	if (!require_root (error))
		return FALSE;

	if (!have_iptables (error))
		return FALSE;

	/* Detach first: -X refuses to remove a chain that is still the
	 * target of a jump.  All four steps are quiet because on a first
	 * run there is nothing there yet, and "no such chain" is the
	 * expected answer rather than an error worth showing the user. */
	detach_chain ("INPUT", "INBOUND");
	detach_chain ("FORWARD", "INBOUND");
	detach_chain ("OUTPUT", "OUTBOUND");

	run_command_quiet (flush_in);
	run_command_quiet (flush_out);
	run_command_quiet (del_in);
	run_command_quiet (del_out);

	/* The logging accept chain is referenced from INBOUND/OUTBOUND, so
	 * it can only go once they are gone. */
	{
		gchar *flush_acc[] = { (gchar *) "iptables", (gchar *) "-w",
		                       (gchar *) "-F",
		                       (gchar *) FS_SCRIPT_ACCEPT_CHAIN, NULL };
		gchar *del_acc[]   = { (gchar *) "iptables", (gchar *) "-w",
		                       (gchar *) "-X",
		                       (gchar *) FS_SCRIPT_ACCEPT_CHAIN, NULL };

		run_command_quiet (flush_acc);
		run_command_quiet (del_acc);
	}

	/* Undo our own NAT rules only.  Deleting a rule that is not there
	 * fails harmlessly, and the loop drains duplicates from earlier
	 * applies. */
	if (current_settings != NULL && current_settings->ext_device != NULL) {
		for (gint i = 0; i < 64; i++) {
			gchar *args[] = { (gchar *) "iptables", (gchar *) "-w",
			                  (gchar *) "-t", (gchar *) "nat",
			                  (gchar *) "-D", (gchar *) "POSTROUTING",
			                  (gchar *) "-o", current_settings->ext_device,
			                  (gchar *) "-j", (gchar *) "MASQUERADE", NULL };

			if (run_command_quiet (args) != 0)
				break;
		}
	}

	return TRUE;
}

static gboolean
linux_reload (GError **error)
{
	if (!linux_stop (error))
		return FALSE;

	return linux_start (error);
}

/* [ apply_lines ]
 * Executes the iptables invocations in a generated script.
 *
 * -N fails harmlessly when the chain already exists, which a repeat
 * apply always hits, so that one status is not treated as an error. */
static gboolean
apply_lines (gchar *script)
{
	gchar **lines;
	gboolean ok = TRUE;

	if (script == NULL)
		return FALSE;

	lines = g_strsplit (script, "\n", -1);

	for (gint i = 0; lines[i] != NULL && ok; i++) {
		GPtrArray *argv;
		gboolean is_new_chain = FALSE;

		if (lines[i] == NULL)
			break;

		g_strstrip (lines[i]);

		if (*lines[i] == '\0' || *lines[i] == '#')
			continue;

		argv = g_ptr_array_new_with_free_func (g_free);

		/* Tokenise, treating a double-quoted run as one word so
		 * --log-prefix "STOCKFW-DROP " survives. */
		{
			GString *word = g_string_new (NULL);
			gboolean in_quotes = FALSE;

			for (const gchar *c = lines[i]; *c != '\0'; c++) {
				if (*c == '"') {
					in_quotes = !in_quotes;
					continue;
				}

				if (!in_quotes && (*c == ' ' || *c == '\t')) {
					if (word->len > 0) {
						if (g_strcmp0 (word->str,
						               "$IPT") == 0)
							g_ptr_array_add (argv,
							                 g_strdup ("iptables"));
						else
							g_ptr_array_add (argv,
							                 g_strdup (word->str));

						g_string_truncate (word, 0);
					}

					continue;
				}

				g_string_append_c (word, *c);
			}

			if (word->len > 0) {
				if (g_strcmp0 (word->str, "$IPT") == 0)
					g_ptr_array_add (argv,
					                 g_strdup ("iptables"));
				else
					g_ptr_array_add (argv, g_strdup (word->str));
			}

			g_string_free (word, TRUE);
		}

		g_ptr_array_add (argv, NULL);

		if (argv->len < 2 ||
		    g_strcmp0 (argv->pdata[0], "iptables") != 0) {
			g_ptr_array_unref (argv);
			continue;
		}

		for (gint a = 1; a + 1 < (gint) argv->len; a++) {
			if (g_strcmp0 (argv->pdata[a], "-N") == 0)
				is_new_chain = TRUE;
		}

		{
			gint status = run_command ((gchar **) argv->pdata);

			if (status != 0 && !is_new_chain) {
				g_printerr ("iptables failed (%d): %s\n",
				            status, lines[i]);
				ok = FALSE;
			}
		}

		g_ptr_array_unref (argv);
	}

	g_strfreev (lines);

	return ok;
}

/* [ apply_nat ]
 * Masquerading and forwarding.
 *
 * -i <internal> -o <external> on FORWARD is what permits traffic to be
 * routed; without it MASQUERADE rewrites addresses that nothing is
 * allowed to pass.  Both interfaces have to exist, and a WSL-style
 * single-interface host has no internal one, so that case is reported
 * rather than silently half-applied. */
static gboolean
apply_nat (const FsSettings *settings)
{
	gchar *masq_args[] = {
		(gchar *) "iptables", (gchar *) "-w",
		(gchar *) "-t", (gchar *) "nat",
		(gchar *) "-A", (gchar *) "POSTROUTING",
		(gchar *) "-o", settings->ext_device,
		(gchar *) "-j", (gchar *) "MASQUERADE", NULL
	};
	gchar *fwd_args[] = {
		(gchar *) "iptables", (gchar *) "-w",
		(gchar *) "-A", (gchar *) "FORWARD",
		(gchar *) "-i", settings->int_device,
		(gchar *) "-o", settings->ext_device,
		(gchar *) "-j", (gchar *) "ACCEPT", NULL
	};
	gboolean ok = TRUE;

	if (run_command (masq_args) != 0) {
		g_printerr ("MASQUERADE on %s failed\n", settings->ext_device);
		ok = FALSE;
	}

	if (settings->int_device != NULL && *settings->int_device != '\0') {
		if (run_command (fwd_args) != 0) {
			g_printerr ("FORWARD %s -> %s failed\n",
			            settings->int_device,
			            settings->ext_device);
			ok = FALSE;
		}
	} else {
		g_printerr ("NAT is enabled but no internal interface is set; "
		            "forwarding rules were skipped\n");
	}

	return ok;
}

static FsApplyResult
linux_apply_rules (const FsPolicy *policy, GError **error)
{
	gchar *script;
	gboolean ok = TRUE;
	FsApplyResult result = FS_APPLY_OK;

	if (!require_root (error))
		return FS_APPLY_FAILED;

	if (!have_iptables (error))
		return FS_APPLY_NO_IPTABLES;

	/* Start from a clean slate so applying twice is idempotent. */
	linux_stop (NULL);

	script = fs_script_generate_inbound (policy, current_settings);
	ok = apply_lines (script);
	g_free (script);

	if (ok) {
		script = fs_script_generate_outbound (policy, current_settings);
		ok = apply_lines (script);
		g_free (script);
	}

	/* Hook the chains into the built-in ones.  Without this the
	 * INBOUND/OUTBOUND chains are created and filled but never
	 * consulted by the kernel, so nothing would actually be filtered
	 * while the UI claimed the policy was applied. */
	if (ok) {
		gchar *hook_input[] = { (gchar *) "iptables", (gchar *) "-w",
		                        (gchar *) "-A", (gchar *) "INPUT",
		                        (gchar *) "-j", (gchar *) "INBOUND", NULL };
		gchar *hook_output[] = { (gchar *) "iptables", (gchar *) "-w",
		                         (gchar *) "-A", (gchar *) "OUTPUT",
		                         (gchar *) "-j", (gchar *) "OUTBOUND", NULL };
		gchar *hook_forward[] = { (gchar *) "iptables", (gchar *) "-w",
		                          (gchar *) "-A", (gchar *) "FORWARD",
		                          (gchar *) "-j", (gchar *) "INBOUND", NULL };

		ok = (run_command (hook_input) == 0 &&
		      run_command (hook_output) == 0 &&
		      run_command (hook_forward) == 0);
	}

	/* NAT lives in the nat table, not the filter table, so the filter
	 * script never touches it.  This is the part that makes the box a
	 * router: masquerade outbound traffic and allow the forward. */
	if (ok && current_settings != NULL && current_settings->nat &&
	    current_settings->ext_device != NULL) {
		ok = apply_nat (current_settings);
	}

	if (ok && current_settings != NULL && current_settings->nat)
		linux_sysctl_forwarding ();

	if (!ok) {
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fs-backend-linux"),
		                     0,
		                     "One or more iptables commands failed. "
		                     "Check that iptables is installed and that "
		                     "the interface names in the policy exist.");
		result = FS_APPLY_FAILED;
	}

	return result;
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

static FsApplyResult
linux_clear_rules (GError **error)
{
	if (!require_root (error))
		return FS_APPLY_FAILED;

	return (linux_stop (NULL) ? FS_APPLY_OK : FS_APPLY_FAILED);
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

	if (*line == '\0' || !fs_netparse_log_line (line, &hit, NULL))
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
	/* Every Firewall sub-page: the generator reads all four (ToS is
	 * offered as an admitted-dead page, matching the original's
	 * layout).  REJECT vs DROP is a real iptables choice, and the
	 * ICMP rules carry -m limit. */
	.fw_sections           = FS_FWSEC_NETWORK | FS_FWSEC_ICMP |
	                         FS_FWSEC_TOS | FS_FWSEC_ADVANCED,
	.fw_honors             = FS_FWHON_REJECT_METHOD |
	                         FS_FWHON_RATE_LIMIT |
	                         FS_FWHON_LOG_ALLOWED,
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
	.set_profile_enabled   = linux_set_profile_enabled
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