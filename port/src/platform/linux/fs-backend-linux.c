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

/* ------------------------------------------------------------------ state
 * Netfilter is stateless from our point of view: we decide the firewall
 * is "running" when our INBOUND chain exists. */
static gboolean log_running = FALSE;
static int      log_pipe[2] = { -1, -1 };
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
 * Probes for our chain, which is how the backend reports state. */
static gboolean
chain_exists (void)
{
	gchar *args[] = { (gchar *) "iptables", (gchar *) "-w",
	                  (gchar *) "-t",    (gchar *) "filter",
	                  (gchar *) "-n",    (gchar *) "-L",
	                  (gchar *) "INBOUND", NULL };

	return (run_command (args) == 0);
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

/* [ linux_list_interface_stats ]
 * Not wired up yet.  Returning NULL hides the Status page's Network
 * panel rather than showing invented numbers. */
static GList *
linux_list_interface_stats (void)
{
	return NULL;
}

/* [ linux_list_connections ]
 * Same: enumerating sockets means walking /proc/net/tcp and matching
 * inodes to processes, which is not written yet. */
static GList *
linux_list_connections (void)
{
	return NULL;
}

/* ------------------------------------------------------------ syslog tail
 *
 * The original read /var/log/messages with gnome-vfs.  Here the firewall
 * rules log to syslog, so we read from a dedicated file descriptor and
 * parse the kern prefix.  Keeping the child means we do not depend on
 * logrotate's handling of the file.
 */

/* [ parse_log_line ]
 * Turns one log line into a hit.
 *
 * The generator's LOG target uses the prefix "STOCKFW-DROP ", so
 * that is what identifies our own drops.  Fields are pulled out of the
 * netfilter key=value pairs that follow it. */
static gboolean
parse_log_line (const gchar *line, FsHit *hit)
{
	gchar *copy;
	gchar *saveptr = NULL;
	gchar *token;
	gboolean is_ours = FALSE;

	if (line == NULL || hit == NULL)
		return FALSE;

	copy = g_strdup (line);

	for (token = strtok_r (copy, " ", &saveptr); token != NULL;
	     token = strtok_r (NULL, " ", &saveptr)) {
		gchar *eq;

		/* The marker is a bare word, not a key=value pair: it
		 * appears as ": STOCKFW-DROP " in the line. */
		if (g_strcmp0 (token, "STOCKFW-DROP") == 0 ||
		    g_str_has_suffix (token, "STOCKFW-DROP")) {
			is_ours = TRUE;
			continue;
		}

		eq = strchr (token, '=');

		if (eq == NULL)
			continue;

		*eq = '\0';

		if (g_strcmp0 (token, "SRC") == 0)
			hit->source = g_strdup (eq + 1);
		else if (g_strcmp0 (token, "DST") == 0)
			hit->destination = g_strdup (eq + 1);
		else if (g_strcmp0 (token, "PROTO") == 0)
			hit->protocol = g_strdup (eq + 1);
		else if (g_strcmp0 (token, "SPT") == 0)
			hit->port = g_strdup (eq + 1);
		else if (g_strcmp0 (token, "DPT") == 0)
			hit->out = g_strdup (eq + 1);
		else if (g_strcmp0 (token, "IN") == 0)
			hit->in = g_strdup (eq + 1);
		else if (g_strcmp0 (token, "OUT") == 0)
			hit->out = g_strdup (eq + 1);
	}

	g_free (copy);

	return is_ours;
}

/* [ on_log_poll ]
 * Drains whatever the tailer has produced since the last tick. */
static gboolean
on_log_poll (gpointer data)
{
	gchar buffer[4096];
	gssize got;

	/* log_pipe[0] is the READ end -- pipe() order is [0] read, [1]
	 * write, and the child put [1] on stdout.  Reading [1] here read a
	 * write-only fd: EBADF on every poll, so no event ever arrived
	 * while log_active() still read TRUE. */
	if (log_pipe[0] < 0)
		return G_SOURCE_REMOVE;

	/* Read everything available; the fd is non-blocking. */
	while ((got = read (log_pipe[0], buffer, sizeof (buffer) - 1)) > 0) {
		gchar **lines;
		gint i;

		buffer[got] = '\0';

		lines = g_strsplit (buffer, "\n", -1);

		for (i = 0; lines[i] != NULL; i++) {
			FsHit hit = { 0 };

			if (*lines[i] == '\0')
				continue;

			if (!parse_log_line (lines[i], &hit))
				continue;

			/* Fill in what the log does not carry. */
			if (hit.time == NULL)
				hit.time = g_strdup (lines[i]);
			if (hit.direction == NULL)
				hit.direction = g_strdup ("in");
			if (hit.service == NULL)
				hit.service = g_strdup (_("Dropped"));

			if (hit.port != NULL) {
				gchar *name = fs_service_lookup_port (atoi (hit.port));

				if (name != NULL) {
					g_free (hit.service);
					hit.service = name;
				}
			}

			if (log_callback != NULL)
				log_callback (&hit, log_user_data);

			/* Free only the fields we allocated: "hit" is a stack
			 * local, so fs_hit_free would try to g_free() it and
			 * corrupt the heap. */
			g_clear_pointer (&hit.time, g_free);
			g_clear_pointer (&hit.in, g_free);
			g_clear_pointer (&hit.out, g_free);
			g_clear_pointer (&hit.source, g_free);
			g_clear_pointer (&hit.destination, g_free);
			g_clear_pointer (&hit.protocol, g_free);
			g_clear_pointer (&hit.service, g_free);
			g_clear_pointer (&hit.direction, g_free);
		}

		g_strfreev (lines);
	}

	return G_SOURCE_CONTINUE;
}

static gboolean
linux_log_start (FsLogFunc callback, gpointer user_data, GError **error)
{
	if (log_running)
		return TRUE;

	log_callback = callback;
	log_user_data = user_data;

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

	if (pipe (log_pipe) != 0) {
		g_set_error (error,
		             g_quark_from_static_string ("fs-backend-linux"),
		             errno, _("Could not create a pipe: %s"),
		             g_strerror (errno));
		return FALSE;
	}

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

		/* Two possible sources.  /var/log/kern.log only exists when
		 * rsyslog is installed, which is no longer the default on a
		 * systemd system -- hardcoding it meant the monitor silently
		 * produced nothing forever.  Prefer the journal when the
		 * traditional file is absent.
		 *
		 * STOCKFW_LOG_FILE overrides both, which is what makes
		 * this testable and also lets someone point at a remote or
		 * relocated log. */
		{
			const gchar *override = g_getenv ("STOCKFW_LOG_FILE");

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

	if (log_pipe[0] >= 0) {
		close (log_pipe[0]);
		log_pipe[0] = -1;
	}

	if (log_pid > 0) {
		kill (log_pid, SIGTERM);
		waitpid (log_pid, NULL, 0);
		log_pid = 0;
	}

	log_running = FALSE;
	log_callback = NULL;
	log_user_data = NULL;
}

static gboolean
linux_log_active (void)
{
	return log_running;
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
	                         FS_FWHON_RATE_LIMIT,
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