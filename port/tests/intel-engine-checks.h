/*---[ intel-engine-checks.h ]--------------------------------------------
 * The threat-intel engine's lock and its applied record, driven through
 * a fake backend, on whatever platform the test runs (review M1 of the
 * Linux and Windows merge).  Included by test-intel.c (Linux, every CI
 * run) and by test-intel-windows.c (the CI's Windows runner), so the
 * same checks run the Linux branches of fs-intel.c on one and the
 * G_OS_WIN32 branches on the other:
 *
 *   - Stop then Start with a list turned on returns: each call runs on
 *     a worker thread joined with a deadline, so an engine that waits on
 *     its own lock (engine_held wrong for the platform) fails instead
 *     of hanging the suite;
 *   - fs_intel_applied_has names the list after an apply and a Start,
 *     and not after a Stop or a clear (on Windows its own branch reads
 *     applied.state each time);
 *   - a Stop asked for during an apply waits for it, then takes the
 *     lists down; an apply that waited for a Stop is held.
 *
 * The caller sets STOCKFW_INTEL_DIR's parent: `base' is a directory the
 * store may be made in (Linux: one whose parents pass the store check;
 * Windows: a temporary directory, the test being elevated).  Each check
 * prints "ok:   " or "FAIL: " and the result is the number of failures.
 *--------------------------------------------------------------------*/
#ifndef FS_TEST_INTEL_ENGINE_CHECKS_H
#define FS_TEST_INTEL_ENGINE_CHECKS_H

#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-hostnet.h"
#include "core/fs-intel.h"

/* Long enough for a slow runner, short enough that a self-deadlock
 * ends the run with a FAIL. */
#define EC_DEADLINE_S 30

static guint ec_failures;

#define EC_CHECK(cond, ...) do {                                \
	printf ((cond) ? "ok:   " : "FAIL: ");                  \
	printf (__VA_ARGS__);                                   \
	printf ("\n");                                          \
	fflush (stdout);                                        \
	if (!(cond))                                            \
		ec_failures++;                                  \
} while (0)

/* ---- the fake firewall ------------------------------------------------ */

static struct
{
	FsIntelLive live;
	gchar      *digest;
	void      (*during_apply) (void);
	void      (*during_clear) (void);
} ec_kern;

static gboolean
ec_apply (const FsIntelRuleset *rs, GError **error)
{
	(void) error;
	if (ec_kern.during_apply != NULL)
		ec_kern.during_apply ();
	g_free (ec_kern.digest);
	ec_kern.digest = rs->sets->len > 0 ? fs_intel_ruleset_digest (rs)
	                                   : NULL;
	ec_kern.live = rs->sets->len > 0 ? FS_INTEL_LIVE_PRESENT
	                                 : FS_INTEL_LIVE_ABSENT;
	return TRUE;
}

static gboolean
ec_clear (GError **error)
{
	(void) error;
	if (ec_kern.during_clear != NULL)
		ec_kern.during_clear ();
	ec_kern.live = FS_INTEL_LIVE_ABSENT;
	g_clear_pointer (&ec_kern.digest, g_free);
	return TRUE;
}

static FsIntelLive
ec_live (gchar **digest)
{
	if (digest != NULL)
		*digest = ec_kern.live == FS_INTEL_LIVE_PRESENT
		          ? g_strdup (ec_kern.digest) : NULL;
	return ec_kern.live;
}

static FsBackend ec_backend;

/* ---- a call that must return ------------------------------------------ */

typedef enum { EC_APPLY, EC_SUSPEND, EC_RESUME, EC_CLEAR } EcOp;

typedef struct
{
	EcOp                 op;
	const FsIntelConfig *config;
	const FsHostNet     *host;
	const gchar         *source;
	gboolean             ok;       /* suspend, clear                    */
	FsIntelOutcome      *outcome;  /* apply, resume                     */
	gboolean             done;
	GMutex               mutex;
	GCond                cond;
} EcCall;

static void
ec_do (EcCall *c)
{
	switch (c->op) {
	case EC_APPLY:
		c->outcome = fs_intel_apply_safe (&ec_backend, c->config,
		                                  c->host, c->source, NULL,
		                                  NULL);
		break;
	case EC_SUSPEND:
		c->ok = fs_intel_suspend (&ec_backend, c->source, NULL);
		break;
	case EC_RESUME:
		c->outcome = fs_intel_resume (&ec_backend, c->source, NULL,
		                              NULL);
		break;
	case EC_CLEAR:
		c->ok = fs_intel_clear (&ec_backend, c->source, NULL);
		break;
	}
}

static gpointer
ec_call_thread (gpointer data)
{
	EcCall *c = data;

	ec_do (c);
	g_mutex_lock (&c->mutex);
	c->done = TRUE;
	g_cond_signal (&c->cond);
	g_mutex_unlock (&c->mutex);
	return NULL;
}

/* Run one engine call on a worker thread and wait at most
 * EC_DEADLINE_S.  A call still running then waits on a lock nobody
 * will release: the run cannot go on, so it ends here, failed. */
static void
ec_call (EcCall *c, const gchar *what)
{
	gint64 end = g_get_monotonic_time () +
	             (gint64) EC_DEADLINE_S * G_TIME_SPAN_SECOND;
	GThread *t;
	gboolean done;

	g_mutex_init (&c->mutex);
	g_cond_init (&c->cond);
	c->done = FALSE;
	t = g_thread_new ("engine-call", ec_call_thread, c);
	g_mutex_lock (&c->mutex);
	while (!c->done)
		if (!g_cond_wait_until (&c->cond, &c->mutex, end))
			break;
	done = c->done;
	g_mutex_unlock (&c->mutex);
	if (!done) {
		EC_CHECK (FALSE, "engine: %s returns within %d s (it waits on "
		          "its own engine lock)", what, EC_DEADLINE_S);
		printf ("\nFAILED: the engine is stuck; the run stops here\n");
		fflush (stdout);
		exit (1);
	}
	g_thread_join (t);
	g_mutex_clear (&c->mutex);
	g_cond_clear (&c->cond);
}

/* ---- the race: a Stop during an apply, an apply during a Stop --------- */

static GThread             *ec_racer;
static gint                 ec_racer_done;
static gboolean             ec_racer_waited; /* not done 300 ms in */
static gboolean             ec_racer_ok;
static FsIntelOutcome      *ec_racer_outcome;
static const FsIntelConfig *ec_racer_config;
static const FsHostNet     *ec_racer_host;

static gpointer
ec_stop_thread (gpointer data)
{
	(void) data;
	ec_racer_ok = fs_intel_suspend (&ec_backend, "racer", NULL);
	g_atomic_int_set (&ec_racer_done, 1);
	return NULL;
}

static gpointer
ec_apply_thread (gpointer data)
{
	(void) data;
	ec_racer_outcome = fs_intel_apply_safe (&ec_backend, ec_racer_config,
	                                        ec_racer_host, "racer", NULL,
	                                        NULL);
	g_atomic_int_set (&ec_racer_done, 1);
	return NULL;
}

static void
ec_stop_during_apply (void)
{
	ec_kern.during_apply = NULL;
	g_atomic_int_set (&ec_racer_done, 0);
	ec_racer = g_thread_new ("stop", ec_stop_thread, NULL);
	g_usleep (300 * 1000);
	ec_racer_waited = !g_atomic_int_get (&ec_racer_done);
}

static void
ec_apply_during_stop (void)
{
	ec_kern.during_clear = NULL;
	g_atomic_int_set (&ec_racer_done, 0);
	ec_racer = g_thread_new ("apply", ec_apply_thread, NULL);
	g_usleep (300 * 1000);
	ec_racer_waited = !g_atomic_int_get (&ec_racer_done);
}

/* The store the checks made, files and all. */
static void
ec_rm_tree (const gchar *path)
{
	GDir *d = g_dir_open (path, 0, NULL);
	const gchar *name;

	if (d != NULL) {
		while ((name = g_dir_read_name (d)) != NULL) {
			gchar *child = g_build_filename (path, name, NULL);

			if (g_file_test (child, G_FILE_TEST_IS_DIR) &&
			    !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
				ec_rm_tree (child);
			else
				g_remove (child);
			g_free (child);
		}
		g_dir_close (d);
	}
	g_rmdir (path);
}

/* ---- the checks ------------------------------------------------------- */

static guint
intel_engine_checks (const gchar *base)
{
	gchar *store = g_build_filename (base, "engine-checks", NULL);
	gchar *csv = g_build_filename (base, "engine-checks.csv", NULL);
	gchar *old_dir = g_strdup (g_getenv ("STOCKFW_INTEL_DIR"));
	FsIntelConfig *c = fs_intel_config_new ();
	FsHostNet *h = fs_hostnet_new ();
	gchar *id = NULL;
	GError *e = NULL;
	EcCall call;
	gboolean waited;

	ec_failures = 0;
	memset (&ec_kern, 0, sizeof ec_kern);
	ec_kern.live = FS_INTEL_LIVE_ABSENT;
	memset (&ec_backend, 0, sizeof ec_backend);
	ec_backend.name = "engine-checks";
	ec_backend.intel_apply = ec_apply;
	ec_backend.intel_clear = ec_clear;
	ec_backend.intel_live = ec_live;

	fs_range_set_add_text (h->own, "203.0.113.5");
	fs_range_set_normalize (h->own);
	g_setenv ("STOCKFW_INTEL_DIR", store, TRUE);
	g_file_set_contents (csv, "45.0.9.1\n45.0.9.2\n", -1, NULL);
	EC_CHECK (fs_intel_import_list (c, csv, "Engine checks",
	                                FS_INTEL_DIR_BOTH, NULL, &id, &e) &&
	          id != NULL && fs_intel_config_save (c, &e),
	          "engine: a local list is turned on in a new store (%s)",
	          e != NULL ? e->message : "ok");
	g_clear_error (&e);
	g_unlink (csv);
	if (id == NULL)
		goto out;

	/* An apply: in force, and the record names it. */
	memset (&call, 0, sizeof call);
	call.op = EC_APPLY;
	call.config = c;
	call.host = h;
	call.source = "engine-checks";
	ec_call (&call, "an apply");
	EC_CHECK (call.outcome != NULL &&
	          call.outcome->result == FS_APPLY_OK &&
	          call.outcome->not_in_force == NULL &&
	          ec_kern.live == FS_INTEL_LIVE_PRESENT &&
	          fs_intel_applied_has (id),
	          "engine: after an apply the list is applied "
	          "(fs_intel_applied_has %d)", fs_intel_applied_has (id));
	fs_intel_outcome_free (call.outcome);

	/* Stop: down, and the record no longer names it. */
	memset (&call, 0, sizeof call);
	call.op = EC_SUSPEND;
	call.source = "engine-checks";
	ec_call (&call, "a Stop (fs_intel_suspend)");
	EC_CHECK (call.ok && ec_kern.live == FS_INTEL_LIVE_ABSENT &&
	          !fs_intel_applied_has (id) &&
	          fs_intel_state (&ec_backend, c, NULL) ==
	          FS_INTEL_STATE_SUSPENDED,
	          "engine: after a Stop the list is not applied "
	          "(fs_intel_applied_has %d)", fs_intel_applied_has (id));

	/* Start: Start holds the engine lock and applies under it; it
	 * must not wait for the lock it holds. */
	memset (&call, 0, sizeof call);
	call.op = EC_RESUME;
	call.source = "engine-checks";
	ec_call (&call, "a Start (fs_intel_resume)");
	EC_CHECK (call.outcome != NULL &&
	          call.outcome->result == FS_APPLY_OK &&
	          ec_kern.live == FS_INTEL_LIVE_PRESENT &&
	          fs_intel_applied_has (id),
	          "engine: a Start after a Stop returns and the list is "
	          "applied again (fs_intel_applied_has %d)",
	          fs_intel_applied_has (id));
	fs_intel_outcome_free (call.outcome);

	/* A Stop during an apply waits for it, then takes the lists
	 * down. */
	ec_kern.during_apply = ec_stop_during_apply;
	memset (&call, 0, sizeof call);
	call.op = EC_APPLY;
	call.config = c;
	call.host = h;
	call.source = "engine-checks";
	ec_racer_waited = FALSE;
	ec_call (&call, "an apply with a Stop waiting");
	waited = ec_racer_waited;
	g_thread_join (ec_racer);
	EC_CHECK (call.outcome != NULL &&
	          call.outcome->result == FS_APPLY_OK && waited &&
	          ec_racer_ok && ec_kern.live == FS_INTEL_LIVE_ABSENT &&
	          fs_intel_state (&ec_backend, c, NULL) ==
	          FS_INTEL_STATE_SUSPENDED && !fs_intel_applied_has (id),
	          "engine: a Stop during an apply waits for it (waited=%d), "
	          "then the lists are down and suspended", waited);
	fs_intel_outcome_free (call.outcome);

	/* An apply that waited for a Stop is held. */
	memset (&call, 0, sizeof call);
	call.op = EC_RESUME;
	call.source = "engine-checks";
	ec_call (&call, "a Start");
	fs_intel_outcome_free (call.outcome);
	ec_racer_config = c;
	ec_racer_host = h;
	ec_kern.during_clear = ec_apply_during_stop;
	memset (&call, 0, sizeof call);
	call.op = EC_SUSPEND;
	call.source = "engine-checks";
	ec_racer_waited = FALSE;
	ec_call (&call, "a Stop with an apply waiting");
	waited = ec_racer_waited;
	g_thread_join (ec_racer);
	EC_CHECK (call.ok && ec_racer_outcome != NULL &&
	          ec_racer_outcome->held &&
	          ec_racer_outcome->result == FS_APPLY_DRY_RUN && waited &&
	          ec_kern.live == FS_INTEL_LIVE_ABSENT &&
	          !fs_intel_applied_has (id),
	          "engine: an apply that waited for a Stop is held "
	          "(waited=%d), the lists stay down", waited);
	fs_intel_outcome_free (ec_racer_outcome);
	ec_racer_outcome = NULL;

	/* clear, from a Start: down, not applied. */
	memset (&call, 0, sizeof call);
	call.op = EC_RESUME;
	call.source = "engine-checks";
	ec_call (&call, "a Start");
	fs_intel_outcome_free (call.outcome);
	memset (&call, 0, sizeof call);
	call.op = EC_CLEAR;
	call.source = "engine-checks";
	ec_call (&call, "a clear (fs_intel_clear)");
	EC_CHECK (call.ok && ec_kern.live == FS_INTEL_LIVE_ABSENT &&
	          !fs_intel_applied_has (id),
	          "engine: after a clear the list is not applied");

out:
	g_free (id);
	fs_intel_config_free (c);
	fs_hostnet_free (h);
	g_clear_pointer (&ec_kern.digest, g_free);
	if (old_dir != NULL)
		g_setenv ("STOCKFW_INTEL_DIR", old_dir, TRUE);
	else
		g_unsetenv ("STOCKFW_INTEL_DIR");
	g_free (old_dir);
	ec_rm_tree (store);
	g_free (store);
	g_free (csv);
	return ec_failures;
}

#endif /* FS_TEST_INTEL_ENGINE_CHECKS_H */
