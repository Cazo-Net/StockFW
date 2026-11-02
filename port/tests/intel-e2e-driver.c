/*---[ intel-e2e-driver.c ]----------------------------------------------
 * Test driver for test-intel-e2e.sh: the threat-intel engine (fs-intel)
 * end to end, with nothing replaced -- the default downloader
 * (fs_fetch, curl as nobody), the real store, fs_hostnet_read() of the
 * running system, and the real Linux backend's slots through
 * fs_backend().  Each command loads intel.conf from the store, does one
 * thing, and saves it when it changed, the way a `stockfw intel'
 * command would.
 *
 *   fs-intel-e2e-driver COMMAND [ARGS]
 *
 *   dir                       the store directory (fs_intel_dir)
 *   add-feed NAME URL FMT DIR a custom feed (typing the URL is consent)
 *   import FILE NAME DIR      a local list: "imported <id> <entries>"
 *   update [shrink]           every enabled feed, ignoring the schedule
 *                             (FS_INTEL_UPDATE_NOW; "shrink" adds
 *                             ACCEPT_SHRINK): "<id> <outcome> <entries>
 *                             <message>" per feed
 *   apply [HOLD]              fs_intel_apply_safe, host NULL (so the
 *                             engine reads this computer itself)
 *   resume                    fs_intel_resume
 *   suspend                   fs_intel_suspend
 *   state                     "<word>: <detail>"
 *   counters                  fs_intel_counters: "<id> <packets>
 *                             <bytes>" sorted, or "none"
 *   lookup ADDR               fs_intel_lookup with fs_hostnet_read()
 *                             of the enabled feeds' hosts
 *   source ID                 the source's stored state, one line
 *   applied-has ID            "yes" / "no"
 *   master on|off             the master switch
 *   enable ID | disable ID    a feed or list on / off
 *   except ADDR | unexcept ADDR
 *
 * apply and resume print "result <ok|dry-run|failed> digest=<d> sets=<n>
 * v4=<n> v6=<n>", then "note: <text>" per note, then "error <kind>:
 * <message>" when there was one.  Any other failure prints "error
 * <kind>: <message>" and exits 1 (kind: the FS_INTEL_ERROR code as a
 * word, or "other"); bad usage exits 2.
 *
 * Built with its own copy of fs-fetch.c compiled with FS_FETCH_TESTING,
 * only so $STOCKFW_TEST_CACERT can name the test server's CA; with it
 * unset the download is the release one.  The backend is the release
 * backend (no FS_BACKEND_TESTING).
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-feed.h"
#include "core/fs-hostnet.h"
#include "core/fs-intel.h"
#include "core/fs-intelset.h"
#include "core/fs-iprange.h"

#define SOURCE "e2e-test"

static const gchar *
kind_of (const GError *error)
{
	if (error == NULL || error->domain != FS_INTEL_ERROR)
		return "other";
	switch (error->code) {
	case FS_INTEL_ERR_CONFIG:      return "config";
	case FS_INTEL_ERR_STORE:       return "store";
	case FS_INTEL_ERR_UNSAFE_DIR:  return "unsafe-dir";
	case FS_INTEL_ERR_NEEDS_ROOT:  return "needs-root";
	case FS_INTEL_ERR_UNSUPPORTED: return "unsupported";
	case FS_INTEL_ERR_UNKNOWN:     return "unknown";
	case FS_INTEL_ERR_CONSENT:     return "consent";
	case FS_INTEL_ERR_TAMPERED:    return "tampered";
	case FS_INTEL_ERR_TOO_BIG:     return "too-big";
	case FS_INTEL_ERR_INVALID:     return "invalid";
	default:                       return "other";
	}
}

static int
fail (GError *error)
{
	g_print ("error %s: %s\n", kind_of (error),
	         error != NULL ? error->message : "(no error set)");
	g_clear_error (&error);
	return 1;
}

static FsIntelConfig *
load (void)
{
	GError *error = NULL;
	FsIntelConfig *config = fs_intel_config_load (&error);

	if (config == NULL)
		fail (error);
	return config;
}

static int
save_and_free (FsIntelConfig *config)
{
	GError *error = NULL;
	gboolean ok = fs_intel_config_save (config, &error);

	fs_intel_config_free (config);
	if (!ok)
		return fail (error);
	g_print ("ok\n");
	return 0;
}

/* This computer as fs_intel_apply_safe(host NULL) reads it: the hosts
 * kept reachable are the engine's own list (the feeds' servers and the
 * proxy), never a copy of its logic here. */
static FsHostNet *
read_host (const FsIntelConfig *config)
{
	gchar **hosts = fs_intel_update_hosts (config);
	FsHostNet *host = fs_hostnet_read ((const gchar *const *) hosts);

	g_strfreev (hosts);
	return host;
}

static gboolean
dir_arg (const gchar *text, FsIntelDir *dir)
{
	if (fs_intel_dir_from_string (text, dir))
		return TRUE;
	g_printerr ("not a direction: %s (in, out or both)\n", text);
	return FALSE;
}

static int
cmd_dir (void)
{
	GError *error = NULL;
	gchar *dir = fs_intel_dir (&error);

	if (dir == NULL)
		return fail (error);
	g_print ("%s\n", dir);
	g_free (dir);
	return 0;
}

static int
cmd_add_feed (const gchar *name, const gchar *url, const gchar *fmt_text,
              const gchar *dir_text)
{
	FsIntelConfig *config;
	FsFeedFormat fmt;
	FsIntelDir dir;
	GError *error = NULL;
	gchar *id = NULL;

	if (!fs_feed_format_from_string (fmt_text, &fmt) ||
	    !dir_arg (dir_text, &dir))
		return 2;
	if ((config = load ()) == NULL)
		return 1;
	if (!fs_intel_config_add_custom (config, name, url, fmt, dir, &id,
	                                 &error)) {
		fs_intel_config_free (config);
		return fail (error);
	}
	g_print ("added %s\n", id);
	g_free (id);
	return save_and_free (config);
}

static int
cmd_import (const gchar *path, const gchar *name, const gchar *dir_text)
{
	FsIntelConfig *config;
	FsFeedParseStats st = { 0 };
	FsIntelDir dir;
	GError *error = NULL;
	gchar *id = NULL;

	if (!dir_arg (dir_text, &dir))
		return 2;
	if ((config = load ()) == NULL)
		return 1;
	if (!fs_intel_import_list (config, path, name, dir, &st, &id,
	                           &error)) {
		fs_intel_config_free (config);
		return fail (error);
	}
	g_print ("imported %s %u\n", id, st.entries);
	g_free (id);
	return save_and_free (config);
}

static const gchar *
outcome_word (FsIntelUpdateOutcome o)
{
	switch (o) {
	case FS_INTEL_UPDATED:       return "updated";
	case FS_INTEL_UNCHANGED:     return "unchanged";
	case FS_INTEL_NOT_DUE:       return "not-due";
	case FS_INTEL_NEEDS_CONSENT: return "needs-consent";
	case FS_INTEL_REFUSED:       return "refused";
	case FS_INTEL_FAILED:        return "failed";
	default:                     return "?";
	}
}

static int
cmd_update (gboolean shrink)
{
	FsIntelConfig *config = load ();
	GPtrArray *results;
	guint flags = FS_INTEL_UPDATE_NOW;

	if (config == NULL)
		return 1;
	if (shrink)
		flags |= FS_INTEL_UPDATE_ACCEPT_SHRINK;
	results = fs_intel_update (config, NULL, flags,
	                           g_get_real_time () / G_USEC_PER_SEC);
	if (results->len == 0)
		g_print ("nothing\n");
	for (guint i = 0; i < results->len; i++) {
		const FsIntelUpdateResult *r = g_ptr_array_index (results, i);

		g_print ("%s %s %u %s\n", r->id, outcome_word (r->outcome),
		         r->entries, r->message);
	}
	g_ptr_array_unref (results);
	fs_intel_config_free (config);
	return 0;
}

static int
print_outcome (FsIntelOutcome *o, GError *error)
{
	int rc = 0;

	if (o == NULL) {
		g_print ("result none\n");
		if (error != NULL)
			return fail (error);
		return 0;
	}
	g_print ("result %s digest=%s sets=%u v4=%u v6=%u\n",
	         o->result == FS_APPLY_OK ? "ok"
	         : o->result == FS_APPLY_DRY_RUN ? "dry-run" : "failed",
	         o->digest, o->sets, o->count4, o->count6);
	for (guint i = 0; i < o->notes->len; i++)
		g_print ("note: %s\n", (const gchar *) g_ptr_array_index (o->notes,
		                                                         i));
	if (o->result != FS_APPLY_OK && o->result != FS_APPLY_DRY_RUN)
		rc = 1;
	if (error != NULL) {
		g_print ("error %s: %s\n", kind_of (error), error->message);
		g_error_free (error);
	}
	fs_intel_outcome_free (o);
	return rc;
}

static int
cmd_apply (const gchar *hold)
{
	FsIntelConfig *config = load ();
	FsIntelOutcome *o;
	GError *error = NULL;

	if (config == NULL)
		return 1;
	o = fs_intel_apply_safe (fs_backend (), config, NULL, SOURCE, hold,
	                         &error);
	fs_intel_config_free (config);
	if (o == NULL)
		return fail (error);
	return print_outcome (o, error);
}

static int
cmd_resume (void)
{
	GError *error = NULL;
	FsIntelOutcome *o = fs_intel_resume (fs_backend (), SOURCE, NULL,
	                                     &error);

	return print_outcome (o, error);
}

static int
cmd_suspend (void)
{
	GError *error = NULL;

	if (!fs_intel_suspend (fs_backend (), SOURCE, &error))
		return fail (error);
	g_print ("suspended\n");
	return 0;
}

static int
cmd_state (void)
{
	gchar *detail = NULL;
	FsIntelState s = fs_intel_state (fs_backend (), NULL, &detail);

	g_print ("%s: %s\n", fs_intel_state_to_string (s),
	         detail != NULL ? detail : "");
	g_free (detail);
	return 0;
}

static int
cmd_counters (void)
{
	GHashTable *counters = fs_intel_counters (fs_backend ());
	GList *ids = g_list_sort (g_hash_table_get_keys (counters),
	                          (GCompareFunc) strcmp);

	if (ids == NULL)
		g_print ("none\n");
	for (GList *l = ids; l != NULL; l = l->next) {
		const FsIntelCounter *c = g_hash_table_lookup (counters, l->data);

		g_print ("%s %" G_GUINT64_FORMAT " %" G_GUINT64_FORMAT "\n",
		         (const gchar *) l->data, c->packets, c->bytes);
	}
	g_list_free (ids);
	g_hash_table_unref (counters);
	return 0;
}

static int
cmd_lookup (const gchar *addr)
{
	FsIntelConfig *config = load ();
	FsHostNet *host;
	FsIntelLookup r;
	GString *ids;
	gchar *sentence;
	const gchar *dir;

	if (config == NULL)
		return 1;
	host = read_host (config);
	if (!fs_intel_lookup (config, host, addr, &r)) {
		g_print ("not an address\n");
		fs_intel_lookup_clear (&r);
		fs_hostnet_free (host);
		fs_intel_config_free (config);
		return 1;
	}
	ids = g_string_new (NULL);
	for (guint i = 0; i < r.sources->len; i++)
		g_string_append_printf (ids, "%s%s", i ? "," : "",
		                        (const gchar *) g_ptr_array_index (r.sources,
		                                                           i));
	dir = r.dir != 0 ? fs_intel_dir_to_string (r.dir) : "-";
	g_print ("listed=%s dir=%s protected=%d exception=%d host=%d "
	         "blocked=%d\n", ids->len ? ids->str : "-", dir,
	         r.is_protected ? 1 : 0, r.is_exception ? 1 : 0,
	         r.is_host ? 1 : 0, r.blocked ? 1 : 0);
	sentence = fs_intel_lookup_sentence (config, &r);
	if (sentence != NULL)
		g_print ("%s\n", sentence);
	g_free (sentence);
	g_string_free (ids, TRUE);
	fs_intel_lookup_clear (&r);
	fs_hostnet_free (host);
	fs_intel_config_free (config);
	return 0;
}

static int
cmd_source (const gchar *id)
{
	FsIntelSourceState *s = fs_intel_source_state (id);

	if (s == NULL) {
		g_print ("never stored\n");
		return 0;
	}
	g_print ("entries=%u v4=%u v6=%u content_date=%" G_GINT64_FORMAT
	         " carried=%" G_GUINT64_FORMAT "/%" G_GUINT64_FORMAT
	         " refused=%s error=%s\n", s->entries, s->count4, s->count6,
	         s->content_date, s->carried_packets, s->carried_bytes,
	         s->refused != NULL ? s->refused : "-",
	         s->last_error != NULL ? s->last_error : "-");
	fs_intel_source_state_free (s);
	return 0;
}

static int
cmd_master (const gchar *what)
{
	FsIntelConfig *config;

	if (strcmp (what, "on") != 0 && strcmp (what, "off") != 0)
		return 2;
	if ((config = load ()) == NULL)
		return 1;
	config->enabled = strcmp (what, "on") == 0;
	return save_and_free (config);
}

static int
cmd_enable (const gchar *id, gboolean on)
{
	FsIntelConfig *config = load ();
	GError *error = NULL;

	if (config == NULL)
		return 1;
	if (!fs_intel_config_set_enabled (config, id, on, &error)) {
		fs_intel_config_free (config);
		return fail (error);
	}
	return save_and_free (config);
}

static int
cmd_except (const gchar *addr, gboolean add)
{
	FsIntelConfig *config = load ();
	FsRangeSet *one = fs_range_set_new ();

	if (config == NULL) {
		fs_range_set_free (one);
		return 1;
	}
	if (!fs_range_set_add_text (one, addr)) {
		g_printerr ("not an address or range: %s\n", addr);
		fs_range_set_free (one);
		fs_intel_config_free (config);
		return 2;
	}
	fs_range_set_normalize (one);
	if (add)
		fs_range_set_union (config->exceptions, one);
	else
		fs_range_set_subtract (config->exceptions, one);
	fs_range_set_normalize (config->exceptions);
	fs_range_set_free (one);
	return save_and_free (config);
}

static int
usage (void)
{
	g_printerr ("usage: fs-intel-e2e-driver dir | add-feed NAME URL FMT "
	            "DIR | import FILE NAME DIR | update [shrink] | apply "
	            "[HOLD] | resume | suspend | state | counters | lookup "
	            "ADDR | source ID | applied-has ID | master on|off | "
	            "enable ID | disable ID | except ADDR | unexcept ADDR\n");
	return 2;
}

int
main (int argc, char **argv)
{
	const gchar *cmd = argc > 1 ? argv[1] : "";

	if (argc == 2 && strcmp (cmd, "dir") == 0)
		return cmd_dir ();
	if (argc == 6 && strcmp (cmd, "add-feed") == 0)
		return cmd_add_feed (argv[2], argv[3], argv[4], argv[5]);
	if (argc == 5 && strcmp (cmd, "import") == 0)
		return cmd_import (argv[2], argv[3], argv[4]);
	if (argc == 2 && strcmp (cmd, "update") == 0)
		return cmd_update (FALSE);
	if (argc == 3 && strcmp (cmd, "update") == 0 &&
	    strcmp (argv[2], "shrink") == 0)
		return cmd_update (TRUE);
	if ((argc == 2 || argc == 3) && strcmp (cmd, "apply") == 0)
		return cmd_apply (argc == 3 ? argv[2] : NULL);
	if (argc == 2 && strcmp (cmd, "resume") == 0)
		return cmd_resume ();
	if (argc == 2 && strcmp (cmd, "suspend") == 0)
		return cmd_suspend ();
	if (argc == 2 && strcmp (cmd, "state") == 0)
		return cmd_state ();
	if (argc == 2 && strcmp (cmd, "counters") == 0)
		return cmd_counters ();
	if (argc == 3 && strcmp (cmd, "lookup") == 0)
		return cmd_lookup (argv[2]);
	if (argc == 3 && strcmp (cmd, "source") == 0)
		return cmd_source (argv[2]);
	if (argc == 3 && strcmp (cmd, "applied-has") == 0) {
		g_print ("%s\n", fs_intel_applied_has (argv[2]) ? "yes" : "no");
		return 0;
	}
	if (argc == 3 && strcmp (cmd, "master") == 0)
		return cmd_master (argv[2]);
	if (argc == 3 && strcmp (cmd, "enable") == 0)
		return cmd_enable (argv[2], TRUE);
	if (argc == 3 && strcmp (cmd, "disable") == 0)
		return cmd_enable (argv[2], FALSE);
	if (argc == 3 && strcmp (cmd, "except") == 0)
		return cmd_except (argv[2], TRUE);
	if (argc == 3 && strcmp (cmd, "unexcept") == 0)
		return cmd_except (argv[2], FALSE);
	return usage ();
}
