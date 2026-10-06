/* Verifies the event source refuses to promise monitoring it cannot
 * deliver.
 *
 * The bug this guards against: log_start() returning TRUE (and
 * log_active() reading TRUE) while wevtutil could not read the
 * Security log at all, or while the kernel log needed root.  The user
 * then watched an empty list that looked like a firewall with nothing
 * to report, with no way to learn why.
 *
 * Whichever way it goes, monitoring must be either honestly running
 * or honestly explained -- never both quiet and claimed.
 */

#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"

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

static void
on_hit (const FsHit *hit, gpointer user_data)
{
	(void) hit;
	(void) user_data;
}

int
main (void)
{
	const FsBackend *backend = fs_backend ();
	GError *error = NULL;
	gboolean started;

	if (backend->log_start == NULL) {
		printf ("SKIP: this backend has no event source\n");
		return 0;
	}

	started = backend->log_start (on_hit, NULL, &error);

	printf ("log_start  -> %s\n", started ? "TRUE" : "FALSE");
	printf ("log_active -> %s\n",
	        backend->log_active () ? "TRUE" : "FALSE");
	printf ("reason     -> %s\n", error ? error->message : "(none)");

	CHECK (started == backend->log_active (),
	       "log_active agrees with what log_start reported");

	if (started) {
		CHECK (error == NULL, "a successful start carries no error");
		backend->log_stop ();
		CHECK (!backend->log_active (), "log_stop really stops it");
	} else {
		/* The whole point: a refusal that says nothing would leave
		 * the same silent empty list as before. */
		CHECK (error != NULL, "a failed start explains itself");
		CHECK (error != NULL && *error->message != '\0',
		       "the explanation is not empty");

		if (error != NULL) {
			CHECK (strstr (error->message, "Administrator") != NULL ||
			       strstr (error->message, "root") != NULL,
			       "the explanation names the privilege that is needed");
		}

		CHECK (!backend->log_active (),
		       "nothing is left running after a failure");
	}

	g_clear_error (&error);

	printf ("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
