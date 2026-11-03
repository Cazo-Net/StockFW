/* End-to-end test of the Linux event monitor reading the kernel ring
 * buffer (/dev/kmsg) -- the source used when there is no
 * /var/log/kern.log and no journal (WSL, containers, minimal installs),
 * which is where the Events page used to stay empty without a word.
 *
 * Real kernel lines only: two temporary iptables LOG rules (tagged with
 * a comment so the script can always remove them) log one TCP SYN with
 * the STOCKFW-DROP prefix and one UDP datagram with STOCKFW-ALLOW, both
 * on loopback to ports nothing listens on.  Then:
 *
 *   - both arrive through log_start's /dev/kmsg reader, with the right
 *     verdict (blocked / allowed) and service names;
 *   - lines written to /dev/kmsg from user space -- plain, and with a
 *     forged "<0>" kernel priority -- do NOT become events: the kernel
 *     stamps them with the user facility, and the reader keeps only
 *     facility 0, so a local program cannot fake firewall events;
 *   - log_source names the ring buffer, log_stop stops it.
 *
 * Needs root and the init network namespace (the kernel drops LOG
 * output from other namespaces unless net.netfilter.nf_log_all_netns
 * is 1).  Run through test-logstart-kmsg.sh.
 */

#include <glib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/fs-backend.h"
#include "core/fs-netparse.h"

#define TEST_COMMENT "stockfw-kmsg-test"
#define DROP_PORT    "39091"
#define ALLOW_PORT   "39092"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (!(cond)) {                                             \
		printf ("FAIL: ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
		failures++;                                         \
	} else {                                                  \
		printf ("ok:   ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
	}                                                         \
} while (0)

/* "port|proto|blocked|service|dir|src" per delivered hit. */
static GPtrArray *seen;

static void
on_hit (const FsHit *hit, gpointer user_data)
{
	(void) user_data;

	g_ptr_array_add (seen,
		g_strdup_printf ("%s|%s|%s|%s|%s|%s",
		                 hit->port ? hit->port : "-",
		                 hit->protocol ? hit->protocol : "-",
		                 fs_hit_is_blocked (hit) ? "blocked" : "allowed",
		                 hit->service ? hit->service : "-",
		                 hit->direction ? hit->direction : "-",
		                 hit->source ? hit->source : "-"));
}

static const gchar *
find_port (const gchar *port)
{
	gchar *prefix = g_strconcat (port, "|", NULL);
	const gchar *found = NULL;

	for (guint i = 0; i < seen->len && found == NULL; i++)
		if (g_str_has_prefix (g_ptr_array_index (seen, i), prefix))
			found = g_ptr_array_index (seen, i);

	g_free (prefix);
	return found;
}

static guint
count_source (const gchar *src)
{
	gchar *suffix = g_strconcat ("|", src, NULL);
	guint n = 0;

	for (guint i = 0; i < seen->len; i++)
		if (g_str_has_suffix (g_ptr_array_index (seen, i), suffix))
			n++;

	g_free (suffix);
	return n;
}

static void
spin_ms (gint ms)
{
	gint64 deadline = g_get_monotonic_time () + (gint64) ms * 1000;

	while (g_get_monotonic_time () < deadline)
		g_main_context_iteration (NULL, FALSE);
}

static gboolean
iptables (const gchar *op, const gchar *proto, const gchar *port,
          const gchar *prefix)
{
	const gchar *argv[] = {
		"iptables", "-w", op, "OUTPUT", "-o", "lo", "-p", proto,
		"--dport", port, "-m", "comment", "--comment", TEST_COMMENT,
		"-j", "LOG", "--log-prefix", prefix, NULL
	};
	gint status = 0;

	return g_spawn_sync (NULL, (gchar **) argv, NULL,
	                     G_SPAWN_SEARCH_PATH |
	                     G_SPAWN_STDOUT_TO_DEV_NULL |
	                     G_SPAWN_STDERR_TO_DEV_NULL,
	                     NULL, NULL, NULL, NULL, &status, NULL) &&
	       g_spawn_check_wait_status (status, NULL);
}

static void
send_traffic (void)
{
	struct sockaddr_in to = { 0 };
	int fd;

	to.sin_family = AF_INET;
	to.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

	/* One TCP SYN (refused; the LOG rule sees it on the way out). */
	fd = socket (AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	to.sin_port = htons (atoi (DROP_PORT));
	(void) connect (fd, (struct sockaddr *) &to, sizeof (to));
	close (fd);

	/* One UDP datagram. */
	fd = socket (AF_INET, SOCK_DGRAM, 0);
	to.sin_port = htons (atoi (ALLOW_PORT));
	(void) sendto (fd, "x", 1, 0, (struct sockaddr *) &to, sizeof (to));
	close (fd);
}

static void
write_kmsg (const gchar *text)
{
	int fd = open ("/dev/kmsg", O_WRONLY | O_CLOEXEC);

	if (fd >= 0) {
		(void) write (fd, text, strlen (text));
		close (fd);
	}
}

int
main (void)
{
	const FsBackend *backend = fs_backend ();
	GError *error = NULL;
	const gchar *source;
	gboolean started;

	seen = g_ptr_array_new_with_free_func (g_free);

	if (backend->log_start == NULL || backend->log_source == NULL) {
		printf ("SKIP: this backend has no ring-buffer reader\n");
		return 0;
	}
	if (access ("/dev/kmsg", R_OK) != 0) {
		printf ("SKIP: /dev/kmsg is not readable here\n");
		return 0;
	}
	/* Since 1.0.7 the backend tries /dev/kmsg before kern.log and the
	 * journal, so a kern.log on the host (the CI runner has one) no
	 * longer decides the source: no skip for it. */

	g_unsetenv ("STOCKFW_LOG_FILE");

	started = backend->log_start (on_hit, NULL, &error);
	CHECK (started, "log_start succeeds with no STOCKFW_LOG_FILE");
	if (!started) {
		printf ("    reason: %s\n", error ? error->message : "(none)");
		return 1;
	}

	source = backend->log_source ();
	CHECK (source != NULL && strstr (source, "/dev/kmsg") != NULL,
	       "the monitor names its source: %s", source ? source : "(null)");
	CHECK (backend->log_problem == NULL || backend->log_problem () == NULL,
	       "and reports no problem while it runs");

	if (!iptables ("-I", "tcp", DROP_PORT, "STOCKFW-DROP ") ||
	    !iptables ("-I", "udp", ALLOW_PORT, "STOCKFW-ALLOW ")) {
		printf ("FAIL: could not add the temporary LOG rules\n");
		backend->log_stop ();
		return 1;
	}

	/* Forged lines first, so they sit in the ring before the real ones
	 * and the wait below has surely drained them. */
	write_kmsg ("STOCKFW-DROP IN=eth0 OUT= SRC=203.0.113.66 "
	            "DST=198.51.100.1 PROTO=TCP SPT=1 DPT=22\n");
	write_kmsg ("<0>STOCKFW-DROP IN=eth0 OUT= SRC=203.0.113.67 "
	            "DST=198.51.100.1 PROTO=TCP SPT=1 DPT=22\n");
	write_kmsg ("<4>STOCKFW-ALLOW IN=eth0 OUT= SRC=203.0.113.68 "
	            "DST=198.51.100.1 PROTO=TCP SPT=1 DPT=22\n");

	send_traffic ();

	{
		gint64 deadline = g_get_monotonic_time () + 5 * G_USEC_PER_SEC;

		while ((find_port (DROP_PORT) == NULL ||
		        find_port (ALLOW_PORT) == NULL) &&
		       g_get_monotonic_time () < deadline)
			spin_ms (50);
	}
	spin_ms (600);     /* a few more polls for anything late */

	iptables ("-D", "tcp", DROP_PORT, "STOCKFW-DROP ");
	iptables ("-D", "udp", ALLOW_PORT, "STOCKFW-ALLOW ");

	CHECK (find_port (DROP_PORT) != NULL &&
	       g_str_has_prefix (find_port (DROP_PORT),
	                         DROP_PORT "|TCP|blocked|"),
	       "a real STOCKFW-DROP kernel line arrives as a blocked TCP "
	       "event -- got [%s]",
	       find_port (DROP_PORT) ? find_port (DROP_PORT) : "(nothing)");
	CHECK (find_port (ALLOW_PORT) != NULL &&
	       g_str_has_prefix (find_port (ALLOW_PORT),
	                         ALLOW_PORT "|UDP|allowed|") &&
	       strstr (find_port (ALLOW_PORT), "BLOCKED") == NULL,
	       "a real STOCKFW-ALLOW kernel line arrives as an allowed UDP "
	       "event, not marked blocked -- got [%s]",
	       find_port (ALLOW_PORT) ? find_port (ALLOW_PORT) : "(nothing)");
	CHECK (find_port (DROP_PORT) != NULL &&
	       g_str_has_suffix (find_port (DROP_PORT), "|out|127.0.0.1"),
	       "outbound direction and source address survive the ring "
	       "record format");

	CHECK (count_source ("203.0.113.66") == 0,
	       "a line a user program writes to /dev/kmsg is not an event");
	CHECK (count_source ("203.0.113.67") == 0,
	       "not even with a forged <0> kernel priority");
	CHECK (count_source ("203.0.113.68") == 0,
	       "nor a forged STOCKFW-ALLOW line");

	backend->log_stop ();
	CHECK (!backend->log_active (), "log_stop really stops it");

	g_clear_error (&error);
	printf ("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
