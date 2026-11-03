/*---[ fs-cli-intel.c ]--------------------------------------------------
 * `stockfw intel': the threat-intel blocklists from the command line
 * (docs/1.0.7-threat-intel-design.md, section 8).
 *
 * A front end over the engine (core/fs-intel.h) and nothing more: the
 * consent check, the store, the update guards, the build and its
 * subtractions, the apply gate with its hold and its audit line, and
 * the honest state all live there, so this file decides only what to
 * print and which exit status to give.
 *
 * `stockfw intel geo ...' does the same for blocking by country or
 * network owner (design 13.11), Linux only in 1.0.7.
 *
 * Read-only commands (status, feeds, lists, exceptions, lookup, terms,
 * geo status, geo search, geo list) never create the store: where no list was ever turned on they show
 * the defaults.  Commands that change the kernel (apply, clear) need
 * root; the others need whatever the store needs (root on Linux).
 *--------------------------------------------------------------------*/
#include "cli/fs-cli.h"
#include "core/fs-apply.h"
#include "core/fs-feed.h"
#include "core/fs-hostnet.h"
#include "core/fs-intel.h"
#include "core/fs-json.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SOURCE "cli"

/* FS_CLI_LIVE, FS_CLI_SUDO, FS_CLI_RIGHTS: fs-cli.h. */

static void     geo_json        (GString *out, const FsIntelConfig *config,
                                 FsIntelState state);
static gboolean geo_status_read (FsIntelGeoStatus *st, GError **error);
static gchar   *day_text        (gint64 t);

/* ------------------------------------------------------------- helpers */

/* The exit status for an engine error: a bad argument (unknown id,
 * invalid value, terms not accepted) is a usage error, a store that
 * needs root is 3, everything else a failure. */
static gint
exit_for (const GError *error)
{
	if (error == NULL)
		return FS_EXIT_FAILURE;
	if (g_error_matches (error, FS_INTEL_ERROR, FS_INTEL_ERR_NEEDS_ROOT))
		return FS_EXIT_NEED_ROOT;
	if (g_error_matches (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNKNOWN) ||
	    g_error_matches (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID) ||
	    g_error_matches (error, FS_INTEL_ERROR, FS_INTEL_ERR_CONSENT))
		return FS_EXIT_USAGE;
	return FS_EXIT_FAILURE;
}

/* [ fail ] -- print an engine error with a hint where one helps; frees
 * it and returns the exit status. */
static gint
fail (GError *error, const gchar *what)
{
	gint status = exit_for (error);

	fs_cli_error ("%s", error != NULL ? error->message : what);
	if (status == FS_EXIT_NEED_ROOT)
		fs_cli_hint (FS_CLI_RIGHTS ", e.g. `" FS_CLI_SUDO
		             "stockfw intel %s'", what);
	else if (g_error_matches (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNKNOWN))
		fs_cli_hint ("`stockfw intel feeds' and `stockfw intel lists' "
		             "show the ids");
	g_clear_error (&error);
	return status;
}

/* [ load_config ]
 * The configuration.  Without `create', a computer with no store (no
 * list was ever turned on) gets the defaults and no store is made. */
static FsIntelConfig *
load_config (gboolean create, GError **error)
{
	if (!create && !fs_intel_store_exists ())
		return fs_intel_config_new ();
	return fs_intel_config_load (error);
}

static gboolean
save_config (const FsIntelConfig *config, gint *status)
{
	GError *error = NULL;

	if (fs_intel_config_save (config, &error))
		return TRUE;
	*status = fail (error, "save");
	return FALSE;
}

/* "in" "out" "both" for the table; words for prose. */
static const gchar *
dir_word (FsIntelDir dir)
{
	const gchar *w = fs_intel_dir_to_string (dir);

	return w != NULL ? w : "?";
}

static const gchar *
dir_prose (FsIntelDir dir)
{
	switch (dir) {
	case FS_INTEL_DIR_IN:   return "stops them connecting to you";
	case FS_INTEL_DIR_OUT:  return "stops you connecting to them";
	case FS_INTEL_DIR_BOTH: return "blocks both directions";
	default:                return "?";
	}
}

/* [ parse_dir ] -- --direction VALUE, with a usage error. */
static gboolean
parse_dir (const gchar *text, FsIntelDir *dir)
{
	if (fs_intel_dir_from_string (text, dir))
		return TRUE;
	fs_cli_error ("the direction must be in, out or both, not \"%s\"",
	              text);
	return FALSE;
}

/* A unix time as local "2026-11-02 14:05", or "never". */
static gchar *
time_text (gint64 t)
{
	GDateTime *dt;
	gchar *text;

	if (t <= 0)
		return g_strdup ("never");
	dt = g_date_time_new_from_unix_local (t);
	if (dt == NULL)
		return g_strdup ("?");
	text = g_date_time_format (dt, "%Y-%m-%d %H:%M");
	g_date_time_unref (dt);
	return text;
}

/* "time": unix seconds, or null for never. */
static void
kv_time (GString *out, const gchar *key, gint64 t)
{
	if (t > 0) {
		fs_json_kv_int (out, key, t);
	} else {
		fs_json_key (out, key);
		g_string_append (out, "null");
	}
}

static gchar *
grouped (guint64 v)
{
	gchar *digits = g_strdup_printf ("%" G_GUINT64_FORMAT, v);
	GString *out = g_string_new (NULL);
	gsize n = strlen (digits);

	for (gsize i = 0; i < n; i++) {
		if (i > 0 && (n - i) % 3 == 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, digits[i]);
	}
	g_free (digits);
	return g_string_free (out, FALSE);
}

static void
notes_json (GString *out, const GPtrArray *notes)
{
	g_string_append_c (out, '[');
	for (guint i = 0; notes != NULL && i < notes->len; i++) {
		if (i > 0)
			g_string_append_c (out, ',');
		fs_json_string (out, g_ptr_array_index (notes, i));
	}
	g_string_append_c (out, ']');
}

static void
notes_print (const GPtrArray *notes)
{
	for (guint i = 0; notes != NULL && i < notes->len; i++)
		printf ("%snote:%s %s\n", fs_cli_amber (), fs_cli_reset (),
		        (const gchar *) g_ptr_array_index (notes, i));
}

/* ------------------------------------------------------------ sources */

/* One feed or local list, as every listing shows it. */
typedef struct
{
	const gchar           *id;
	const gchar           *name;
	const gchar           *kind;     /* "catalog" "custom" "local"   */
	gboolean               enabled;
	FsIntelDir             dir;
	const FsFeedInfo      *info;     /* catalog only                 */
	const FsIntelFeedConf *feed;     /* feeds                        */
	const FsIntelListConf *list;     /* local lists                  */
	FsIntelSourceState    *state;    /* NULL: never stored           */
} Src;

static void
src_free (gpointer p)
{
	Src *s = p;

	fs_intel_source_state_free (s->state);
	g_free (s);
}

/* Every source in display order (catalog, custom feeds, local lists);
 * with only_enabled, the ones turned on. */
static GPtrArray *
sources_of (const FsIntelConfig *config, gboolean only_enabled)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (src_free);
	gboolean stored = fs_intel_store_exists ();

	for (guint i = 0; i < config->feeds->len; i++) {
		const FsIntelFeedConf *f = g_ptr_array_index (config->feeds, i);
		Src *s;

		if (only_enabled && !f->enabled)
			continue;
		s = g_new0 (Src, 1);
		s->id = f->id;
		s->name = fs_intel_config_label (config, f->id);
		s->kind = f->custom ? "custom" : "catalog";
		s->enabled = f->enabled;
		s->dir = f->dir;
		s->feed = f;
		s->info = f->custom ? NULL : fs_feed_catalog_find (f->id);
		s->state = stored ? fs_intel_source_state (f->id) : NULL;
		g_ptr_array_add (out, s);
	}
	for (guint i = 0; i < config->lists->len; i++) {
		const FsIntelListConf *l = g_ptr_array_index (config->lists, i);
		Src *s;

		if (only_enabled && !l->enabled)
			continue;
		s = g_new0 (Src, 1);
		s->id = l->id;
		s->name = l->name;
		s->kind = "local";
		s->enabled = l->enabled;
		s->dir = l->dir;
		s->list = l;
		s->state = stored ? fs_intel_source_state (l->id) : NULL;
		g_ptr_array_add (out, s);
	}
	return out;
}

/* The source's status word: what a user should know first. */
static const gchar *
src_status (const FsIntelConfig *config, const Src *s, gint64 now)
{
	if (!s->enabled)
		return "off";
	if (s->feed != NULL && s->feed->accepted_at <= 0)
		return "needs-consent";
	if (s->state == NULL || s->state->fetched_at <= 0)
		return s->list != NULL ? "missing" : "not-downloaded";
	if (s->state->refused != NULL)
		return "refused";
	if (s->state->last_error != NULL)
		return "failed";
	if (s->feed != NULL && fs_intel_source_is_stale (config, s->id, now))
		return "stale";
	return "ok";
}

/* The `intel update' flag that takes a refused copy anyway (design 4.5),
 * from the override the engine recorded with the refusal: the same one
 * the Threat Intel page offers as "Accept smaller list" or "Accept
 * larger list".  NULL when nothing overrides it (not a list, over a
 * cap, dated in the future). */
static const gchar *
accept_flag (const FsIntelSourceState *st)
{
	if (st == NULL || st->refused == NULL)
		return NULL;
	switch (st->refused_override) {
	case FS_INTEL_UPDATE_ACCEPT_SHRINK:   return "--accept-shrink";
	case FS_INTEL_UPDATE_ACCEPT_COVERAGE: return "--accept-coverage";
	default:                              return NULL;
	}
}

/* The licence column: the verified name, or where the terms are. */
static gchar *
src_licence (const Src *s)
{
	if (s->info == NULL)
		return g_strdup (s->list != NULL ? "your own list"
		                                 : "the provider's terms");
	return g_strdup_printf ("%s%s",
	                        s->info->license != NULL ? s->info->license
	                                                 : "see terms",
	                        s->info->noncommercial ? ", non-commercial"
	                                               : "");
}

/* The BLOCKED column: the count, or "n/a" where the platform counts
 * nothing per rule (Windows Firewall), so no list reads "blocked 0". */
static gchar *
blocked_text (const FsIntelCounter *c)
{
	if (fs_intel_counts_unavailable (fs_backend ()) != NULL)
		return g_strdup ("n/a");
	return grouped (c != NULL ? c->packets : 0);
}

/* Under a table with a BLOCKED column: why it says "n/a". */
static void
counts_note (void)
{
	const gchar *why = fs_intel_counts_unavailable (fs_backend ());

	if (why != NULL)
		printf ("%s%s%s\n", fs_cli_dim (), why, fs_cli_reset ());
}

static void
src_json (GString *out, const FsIntelConfig *config, const Src *s,
          GHashTable *counters, gint64 now)
{
	const FsIntelCounter *c = counters != NULL
	                          ? g_hash_table_lookup (counters, s->id) : NULL;
	const FsIntelSourceState *st = s->state;

	g_string_append_c (out, '{');
	fs_json_kv_str (out, "id", s->id);                     g_string_append_c (out, ',');
	fs_json_kv_str (out, "name", s->name);                 g_string_append_c (out, ',');
	fs_json_kv_str (out, "kind", s->kind);                 g_string_append_c (out, ',');
	fs_json_kv_bool (out, "enabled", s->enabled);          g_string_append_c (out, ',');
	fs_json_kv_str (out, "direction", dir_word (s->dir));  g_string_append_c (out, ',');
	fs_json_kv_str (out, "status", src_status (config, s, now));
	g_string_append_c (out, ',');
	if (s->info != NULL) {
		fs_json_kv_str (out, "category", s->info->category);     g_string_append_c (out, ',');
		fs_json_kv_str (out, "licence", s->info->license);       g_string_append_c (out, ',');
		fs_json_kv_str (out, "terms_url", s->info->terms_url);   g_string_append_c (out, ',');
		fs_json_kv_str (out, "info_url", s->info->info_url);     g_string_append_c (out, ',');
		fs_json_kv_str (out, "credit", s->info->credit);         g_string_append_c (out, ',');
		fs_json_kv_bool (out, "noncommercial", s->info->noncommercial); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "recommended", s->info->recommended); g_string_append_c (out, ',');
		fs_json_kv_str (out, "host", s->info->host);             g_string_append_c (out, ',');
		fs_json_kv_uint (out, "interval_hours", s->info->interval_hours);
		g_string_append_c (out, ',');
	} else if (s->feed != NULL) {
		gchar *shown = fs_feed_url_redacted (s->feed->url);

		/* A query string can hold a key: never printed [S18]. */
		fs_json_kv_str (out, "url", shown);                      g_string_append_c (out, ',');
		fs_json_kv_str (out, "format",
		                fs_feed_format_to_string (s->feed->format)); g_string_append_c (out, ',');
		g_free (shown);
	}
	if (s->feed != NULL) {
		kv_time (out, "terms_accepted_at", s->feed->accepted_at);
		g_string_append_c (out, ',');
	}
	fs_json_kv_uint (out, "entries", st != NULL ? st->entries : 0); g_string_append_c (out, ',');
	fs_json_kv_uint (out, "ipv4_ranges", st != NULL ? st->count4 : 0); g_string_append_c (out, ',');
	fs_json_kv_uint (out, "ipv6_ranges", st != NULL ? st->count6 : 0); g_string_append_c (out, ',');
	kv_time (out, "updated_at", st != NULL ? st->fetched_at : 0);  g_string_append_c (out, ',');
	kv_time (out, "attempted_at", st != NULL ? st->attempted_at : 0); g_string_append_c (out, ',');
	kv_time (out, "content_date", st != NULL ? st->content_date : 0); g_string_append_c (out, ',');
	fs_json_kv_bool (out, "stale", s->feed != NULL && st != NULL &&
	                 fs_intel_source_is_stale (config, s->id, now));
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "last_error", st != NULL ? st->last_error : NULL); g_string_append_c (out, ',');
	fs_json_kv_str (out, "refused", st != NULL ? st->refused : NULL); g_string_append_c (out, ',');
	fs_json_kv_str (out, "accept_with", accept_flag (st));     g_string_append_c (out, ',');
	if (fs_intel_counts_unavailable (fs_backend ()) != NULL) {
		/* Windows Firewall counts nothing per rule: null, never a
		 * 0 that reads as "blocked nothing" [S10]. */
		g_string_append (out, "\"blocked_packets\":null,"
		                      "\"blocked_bytes\":null,");
	} else {
		fs_json_kv_uint (out, "blocked_packets", c != NULL ? c->packets : 0); g_string_append_c (out, ',');
		fs_json_kv_uint (out, "blocked_bytes", c != NULL ? c->bytes : 0);    g_string_append_c (out, ',');
	}
	kv_time (out, "counted_since", st != NULL ? st->counted_since : 0);
	g_string_append_c (out, '}');
}

/* ------------------------------------------------------- state/summary */

static const gchar *
state_color (FsIntelState state)
{
	switch (state) {
	case FS_INTEL_STATE_ENFORCED:   return fs_cli_green ();
	case FS_INTEL_STATE_OFF:
	case FS_INTEL_STATE_SUSPENDED:
	case FS_INTEL_STATE_UNSUPPORTED: return fs_cli_dim ();
	default:                        return fs_cli_amber ();
	}
}

void
fs_cli_intel_json (GString *out, gboolean with_sources)
{
	const FsBackend *backend = fs_backend ();
	GError *error = NULL;
	FsIntelConfig *config = load_config (FALSE, &error);
	gchar *detail = NULL;
	FsIntelState state;
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;

	g_string_append_c (out, '{');
	if (config == NULL) {
		/* The store could not be read (not root, or unsafe): the
		 * state says so; nothing about the lists is guessed. */
		state = fs_intel_state (backend, NULL, &detail);
		fs_json_kv_str (out, "state", fs_intel_state_to_string (state));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "detail", detail != NULL ? detail
		                : error->message);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", error->message);
		g_string_append (out, ",\"lists\":[]}");
		g_free (detail);
		g_clear_error (&error);
		return;
	}
	state = fs_intel_state (backend, config, &detail);
	fs_json_kv_str (out, "state", fs_intel_state_to_string (state));
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "detail", detail);           g_string_append_c (out, ',');
	fs_json_kv_bool (out, "master", config->enabled); g_string_append_c (out, ',');
	fs_json_kv_str (out, "proxy", config->proxy);     g_string_append_c (out, ',');
	fs_json_kv_str (out, "hold", fs_apply_hold_reason ());
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "counts_unavailable",
	                fs_intel_counts_unavailable (backend));
	g_string_append_c (out, ',');
	fs_json_key (out, "lists");
	g_string_append_c (out, '[');
	if (with_sources) {
		GPtrArray *srcs = sources_of (config, TRUE);
		GHashTable *counters = fs_intel_counters (backend);

		for (guint i = 0; i < srcs->len; i++) {
			if (i > 0)
				g_string_append_c (out, ',');
			src_json (out, config, g_ptr_array_index (srcs, i),
			          counters, now);
		}
		g_hash_table_unref (counters);
		g_ptr_array_unref (srcs);
	}
	g_string_append_c (out, ']');
	if (with_sources) {
		/* Country and network-owner blocking (design 13.11), read
		 * only: the switch, the database in the store, the licence
		 * line, and the rules. */
		g_string_append_c (out, ',');
		fs_json_key (out, "location");
		geo_json (out, config, state);
	}
	g_string_append_c (out, '}');
	g_free (detail);
	fs_intel_config_free (config);
}

void
fs_cli_intel_status_line (void)
{
	gchar *detail = NULL;
	FsIntelState state = fs_intel_state (fs_backend (), NULL, &detail);

	printf ("  %-12s %s%s%s", "Threat intel", state_color (state),
	        fs_intel_state_to_string (state), fs_cli_reset ());
	if (detail != NULL)
		printf ("%s  (%s)%s", fs_cli_dim (), detail, fs_cli_reset ());
	printf ("\n");
	g_free (detail);
}

static gint
intel_status (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	FsIntelConfig *config;
	GError *error = NULL;
	gchar *detail = NULL;
	FsIntelState state;
	GPtrArray *srcs, *rows;
	GHashTable *counters;
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;
	const gchar *hold = fs_apply_hold_reason ();

	(void) argv;
	if (argc > 0) {
		fs_cli_error ("intel status takes no arguments");
		return FS_EXIT_USAGE;
	}
	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		fs_cli_intel_json (out, TRUE);
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
		return FS_EXIT_OK;
	}

	config = load_config (FALSE, &error);
	if (config == NULL) {
		state = fs_intel_state (backend, NULL, &detail);
		printf ("  %-12s %s%s%s  %s(%s)%s\n", "Threat intel",
		        state_color (state), fs_intel_state_to_string (state),
		        fs_cli_reset (), fs_cli_dim (),
		        detail != NULL ? detail : error->message, fs_cli_reset ());
		g_free (detail);
		return fail (error, "status");
	}

	state = fs_intel_state (backend, config, &detail);
	printf ("  %-12s %s%s%s\n", "Threat intel", state_color (state),
	        fs_intel_state_to_string (state), fs_cli_reset ());
	if (detail != NULL)
		printf ("  %-12s %s\n", "", detail);
	printf ("  %-12s %s\n", "Switch", config->enabled
	        ? "on" : "off: no list is downloaded or enforced");
	printf ("  %-12s %s\n", "Proxy", config->proxy != NULL ? config->proxy
	        : "none (`stockfw intel proxy URL' sets one)");
	if (hold != NULL)
		printf ("  %-12s %saudit-only: applies are recorded, " FS_CLI_LIVE " "
		        "is left untouched%s\n", "Apply mode", fs_cli_amber (),
		        fs_cli_reset ());

	if (fs_intel_geo_supported () &&
	    (config->geo_enabled || config->locations->len > 0)) {
		FsIntelGeoStatus st;
		guint on = 0;

		for (guint i = 0; i < config->locations->len; i++)
			on += ((FsIntelLocationConf *) g_ptr_array_index (
				config->locations, i))->enabled ? 1 : 0;
		if (geo_status_read (&st, NULL)) {
			gchar *day = day_text (st.created_at);

			printf ("  %-12s %s; %u of %u country or network rules on; "
			        "database %s%s (`stockfw intel geo')\n", "Location",
			        config->geo_enabled ? "on" : "off", on,
			        config->locations->len,
			        st.present ? "of " : "not downloaded",
			        st.present ? day : "");
			g_free (day);
			fs_intel_geo_status_clear (&st);
		}
	}

	srcs = sources_of (config, TRUE);
	if (srcs->len == 0) {
		printf ("\nNo blocklist is turned on.  `stockfw intel feeds' "
		        "lists them; `" FS_CLI_SUDO "stockfw intel enable ID' turns one "
		        "on.\n");
	} else {
		static const gchar *headers[] = {
			"ID", "NAME", "DIR", "ENTRIES", "UPDATED", "BLOCKED", "STATUS"
		};

		counters = fs_intel_counters (backend);
		rows = g_ptr_array_new_with_free_func ((GDestroyNotify) g_strfreev);
		for (guint i = 0; i < srcs->len; i++) {
			const Src *s = g_ptr_array_index (srcs, i);
			const FsIntelCounter *c = g_hash_table_lookup (counters, s->id);
			gchar **row = g_new0 (gchar *, 8);

			row[0] = g_strdup (s->id);
			row[1] = g_strdup (s->name);
			row[2] = g_strdup (dir_word (s->dir));
			row[3] = grouped (s->state != NULL ? s->state->entries : 0);
			row[4] = time_text (s->state != NULL ? s->state->fetched_at
			                                     : 0);
			row[5] = blocked_text (c);
			row[6] = g_strdup (src_status (config, s, now));
			g_ptr_array_add (rows, row);
		}
		printf ("\n");
		fs_cli_table (headers, 7, rows, 40);
		counts_note ();
		g_ptr_array_unref (rows);
		g_hash_table_unref (counters);
	}

	g_ptr_array_unref (srcs);
	g_free (detail);
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

/* -------------------------------------------------------------- feeds */

static gint
intel_feeds (gint argc, gchar **argv)
{
	FsIntelConfig *config;
	GError *error = NULL;
	GPtrArray *srcs;
	GHashTable *counters;
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;

	(void) argv;
	if (argc > 0) {
		fs_cli_error ("intel feeds takes no arguments");
		return FS_EXIT_USAGE;
	}
	config = load_config (FALSE, &error);
	if (config == NULL)
		return fail (error, "feeds");

	srcs = sources_of (config, FALSE);
	counters = fs_intel_counters (fs_backend ());

	if (fs_cli.json) {
		GString *out = g_string_new ("{");
		gboolean first = TRUE;

		fs_json_kv_bool (out, "master", config->enabled);
		g_string_append (out, ",\"feeds\":[");
		for (guint i = 0; i < srcs->len; i++) {
			const Src *s = g_ptr_array_index (srcs, i);

			if (s->list != NULL)
				continue;
			if (!first)
				g_string_append_c (out, ',');
			first = FALSE;
			src_json (out, config, s, counters, now);
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		static const gchar *headers[] = {
			"ID", "ON", "DIR", "ENTRIES", "UPDATED", "STATUS", "LICENCE",
			"CREDIT"
		};
		GPtrArray *rows = g_ptr_array_new_with_free_func (
			(GDestroyNotify) g_strfreev);

		for (guint i = 0; i < srcs->len; i++) {
			const Src *s = g_ptr_array_index (srcs, i);
			gchar **row;

			if (s->list != NULL)
				continue;
			row = g_new0 (gchar *, 9);
			row[0] = g_strdup (s->id);
			row[1] = g_strdup (s->enabled ? "on" : "-");
			row[2] = g_strdup (dir_word (s->dir));
			row[3] = s->state != NULL ? grouped (s->state->entries)
			                          : g_strdup ("-");
			row[4] = time_text (s->state != NULL ? s->state->fetched_at
			                                     : 0);
			row[5] = g_strdup (src_status (config, s, now));
			row[6] = src_licence (s);
			if (s->info != NULL) {
				row[7] = g_strdup (s->info->credit);
			} else {
				gchar *shown = fs_feed_url_redacted (s->feed->url);

				row[7] = g_strdup_printf ("%s (%s)", s->name, shown);
				g_free (shown);
			}
			g_ptr_array_add (rows, row);
		}
		fs_cli_table (headers, 8, rows, 60);
		g_ptr_array_unref (rows);
		if (!config->enabled)
			printf ("\n%sThreat intel is switched off: `" FS_CLI_SUDO "stockfw "
			        "intel on' switches it on.%s\n", fs_cli_amber (),
			        fs_cli_reset ());
		printf ("\n%sTurning a feed on needs its terms accepted: `stockfw "
		        "intel terms ID' shows them, `" FS_CLI_SUDO "stockfw intel enable ID "
		        "--accept-terms' turns it on.  Lists contain mistakes: "
		        "`stockfw intel except ADDRESS' lets one through.%s\n",
		        fs_cli_dim (), fs_cli_reset ());
	}

	g_hash_table_unref (counters);
	g_ptr_array_unref (srcs);
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

static gint
intel_terms (gint argc, gchar **argv)
{
	FsIntelConfig *config;
	GError *error = NULL;
	gchar *text;

	if (argc != 1) {
		fs_cli_error ("usage: stockfw intel terms FEED");
		return FS_EXIT_USAGE;
	}
	config = load_config (FALSE, &error);
	if (config == NULL)
		return fail (error, "terms");
	text = fs_intel_consent_text (config, argv[0]);
	if (text == NULL) {
		fs_intel_config_free (config);
		g_set_error (&error, FS_INTEL_ERROR, FS_INTEL_ERR_UNKNOWN,
		             "there is no feed called \"%s\"", argv[0]);
		return fail (error, "terms");
	}
	if (fs_cli.json) {
		GString *out = g_string_new ("{");
		FsIntelFeedConf *f = fs_intel_config_feed (config, argv[0]);

		fs_json_kv_str (out, "id", argv[0]);          g_string_append_c (out, ',');
		kv_time (out, "accepted_at", f->accepted_at); g_string_append_c (out, ',');
		fs_json_kv_str (out, "terms", text);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		printf ("%s\n", text);
	}
	g_free (text);
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

/* ----------------------------------------------------- enable/disable */

/* The overlap note of design 4.1: "FireHOL level 1 already contains
 * Spamhaus DROP (IPv4)", for each enabled feed that contains this one
 * or that this one contains. */
static GPtrArray *
overlap_notes (const FsIntelConfig *config, const gchar *id)
{
	GPtrArray *notes = g_ptr_array_new_with_free_func (g_free);

	for (guint i = 0; i < config->feeds->len; i++) {
		const FsIntelFeedConf *f = g_ptr_array_index (config->feeds, i);
		const FsFeedInfo *a = fs_feed_catalog_find (f->id);
		const FsFeedInfo *b = fs_feed_catalog_find (id);
		const FsFeedInfo *outer = NULL, *inner = NULL;

		if (!f->enabled || strcmp (f->id, id) == 0 || a == NULL || b == NULL)
			continue;
		for (gint pass = 0; pass < 2 && outer == NULL; pass++) {
			const FsFeedInfo *o = pass ? b : a, *n = pass ? a : b;
			gchar **ids = o->includes != NULL
			              ? g_strsplit (o->includes, " ", -1) : NULL;

			if (ids != NULL && g_strv_contains (
			        (const gchar *const *) ids, n->id)) {
				outer = o;
				inner = n;
			}
			g_strfreev (ids);
		}
		if (outer != NULL)
			g_ptr_array_add (notes, g_strdup_printf (
				"%s already contains %s; both stay on.",
				outer->name, inner->name));
	}
	return notes;
}

static gint
intel_enable (gint argc, gchar **argv, gboolean enable)
{
	const gchar *id = NULL;
	FsIntelDir dir = 0;
	gboolean accept = FALSE;
	FsIntelConfig *config;
	GError *error = NULL;
	GPtrArray *notes = NULL;
	gboolean ok, newly_accepted = FALSE, is_list;
	gint status = FS_EXIT_OK;
	const gchar *verb = enable ? "enable" : "disable";

	for (gint i = 0; i < argc; i++) {
		if (enable && strcmp (argv[i], "--accept-terms") == 0) {
			accept = TRUE;
		} else if (enable && (strcmp (argv[i], "--direction") == 0 ||
		                      strcmp (argv[i], "--dir") == 0) &&
		           i + 1 < argc) {
			if (!parse_dir (argv[++i], &dir))
				return FS_EXIT_USAGE;
		} else if (argv[i][0] == '-') {
			fs_cli_error ("unknown option for intel %s: %s", verb,
			              argv[i]);
			if (enable)
				fs_cli_hint ("options are --direction in|out|both and "
				             "--accept-terms");
			return FS_EXIT_USAGE;
		} else if (id == NULL) {
			id = argv[i];
		} else {
			fs_cli_error ("intel %s takes one feed or list id", verb);
			return FS_EXIT_USAGE;
		}
	}
	if (id == NULL) {
		fs_cli_error ("usage: stockfw intel %s ID%s", verb,
		              enable ? " [--direction in|out|both] "
		                       "[--accept-terms]" : "");
		fs_cli_hint ("`stockfw intel feeds' lists the ids");
		return FS_EXIT_USAGE;
	}

	config = load_config (TRUE, &error);
	if (config == NULL)
		return fail (error, verb);

	is_list = fs_intel_config_list (config, id) != NULL ||
	          fs_intel_config_location (config, id) != NULL;
	if (!enable) {
		ok = is_list ? fs_intel_config_set_enabled (config, id, FALSE,
		                                            &error)
		             : fs_intel_config_disable_feed (config, id, &error);
	} else if (is_list) {
		ok = fs_intel_config_set_enabled (config, id, TRUE, &error) &&
		     (dir == 0 || fs_intel_config_set_dir (config, id, dir,
		                                           &error));
	} else {
		FsIntelFeedConf *f = fs_intel_config_feed (config, id);

		newly_accepted = f != NULL && f->accepted_at <= 0 && accept;
		ok = fs_intel_config_enable_feed (config, id, dir, accept, &error);
	}

	if (!ok && g_error_matches (error, FS_INTEL_ERROR,
	                            FS_INTEL_ERR_CONSENT)) {
		/* Never a way around the consent [S14]: show the terms and
		 * say how to accept them; nothing is saved. */
		gboolean location = fs_intel_config_location (config, id) != NULL;
		gchar *text = location ? fs_intel_geo_consent_text (config)
		                       : fs_intel_consent_text (config, id);

		if (fs_cli.json) {
			GString *out = g_string_new ("{");

			fs_json_kv_str (out, "id", id);              g_string_append_c (out, ',');
			fs_json_kv_bool (out, "enabled", FALSE);     g_string_append_c (out, ',');
			fs_json_kv_bool (out, "needs_consent", TRUE); g_string_append_c (out, ',');
			fs_json_kv_str (out, "terms", text);
			g_string_append_c (out, '}');
			fs_cli_print_json (out);
			g_string_free (out, TRUE);
		} else {
			printf ("%s\n\n", text);
		}
		fs_cli_error ("%s", error->message);
		if (location)
			fs_cli_hint ("read the terms above; to accept them: "
			             FS_CLI_SUDO "stockfw intel geo on "
			             "--accept-terms");
		else
			fs_cli_hint ("read the terms above; to accept them: "
			             FS_CLI_SUDO "stockfw intel enable %s "
			             "--accept-terms", id);
		g_free (text);
		g_clear_error (&error);
		fs_intel_config_free (config);
		return FS_EXIT_USAGE;
	}
	if (!ok) {
		fs_intel_config_free (config);
		return fail (error, verb);
	}
	if (!save_config (config, &status)) {
		fs_intel_config_free (config);
		return status;
	}
	if (enable && !is_list)
		notes = overlap_notes (config, id);

	if (fs_cli.json) {
		GString *out = g_string_new ("{");
		const FsIntelFeedConf *f = fs_intel_config_feed (config, id);
		const FsIntelListConf *l = fs_intel_config_list (config, id);
		const FsIntelLocationConf *g = fs_intel_config_location (config, id);

		fs_json_kv_str (out, "id", id);                         g_string_append_c (out, ',');
		fs_json_kv_bool (out, "enabled", enable);               g_string_append_c (out, ',');
		fs_json_kv_str (out, "direction",
		                dir_word (f != NULL ? f->dir : l != NULL ? l->dir
		                          : g->dir));                   g_string_append_c (out, ',');
		fs_json_kv_bool (out, "terms_accepted_now", newly_accepted);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "applied", FALSE);                g_string_append_c (out, ',');
		fs_json_key (out, "notes");
		notes_json (out, notes);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		const FsIntelFeedConf *f = fs_intel_config_feed (config, id);
		const FsIntelListConf *l = fs_intel_config_list (config, id);
		const FsIntelLocationConf *g = fs_intel_config_location (config, id);
		FsIntelDir d = f != NULL ? f->dir : l != NULL ? l->dir : g->dir;

		if (enable)
			printf ("%s+%s %s turned on (%s: %s).\n", fs_cli_green (),
			        fs_cli_reset (), fs_intel_config_label (config, id),
			        dir_word (d), dir_prose (d));
		else
			printf ("%s-%s %s turned off.\n", fs_cli_red (),
			        fs_cli_reset (), fs_intel_config_label (config, id));
		if (newly_accepted)
			printf ("Terms accepted now; `stockfw intel terms %s' shows "
			        "them again.\n", id);
		notes_print (notes);
		if (enable && f != NULL)
			printf ("%sNot live yet: run `" FS_CLI_SUDO "stockfw intel update', "
			        "then `" FS_CLI_SUDO "stockfw intel apply'.%s\n", fs_cli_dim (),
			        fs_cli_reset ());
		else
			printf ("%sNot live yet: run `" FS_CLI_SUDO "stockfw intel apply'.%s\n",
			        fs_cli_dim (), fs_cli_reset ());
	}

	if (notes != NULL)
		g_ptr_array_unref (notes);
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

/* ------------------------------------------------- master switch */

static gint
intel_switch (gint argc, gboolean on)
{
	FsIntelConfig *config;
	GError *error = NULL;
	gint status = FS_EXIT_OK;

	if (argc > 0) {
		fs_cli_error ("intel %s takes no arguments", on ? "on" : "off");
		return FS_EXIT_USAGE;
	}
	config = load_config (TRUE, &error);
	if (config == NULL)
		return fail (error, on ? "on" : "off");
	config->enabled = on;
	if (!save_config (config, &status)) {
		fs_intel_config_free (config);
		return status;
	}
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "master", on);     g_string_append_c (out, ',');
		fs_json_kv_bool (out, "applied", FALSE);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		printf ("Threat intel switched %s.  %sNot live yet: run `" FS_CLI_SUDO
		        "stockfw intel apply'.%s\n", on ? "on" : "off",
		        fs_cli_dim (), fs_cli_reset ());
	}
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

/* ------------------------------------------------------------- proxy */

/* `stockfw intel proxy [URL|none]': show or set the download proxy.
 * Without one every download runs with --noproxy *, so a network that
 * only reaches the internet through a proxy needs this. */
static gint
intel_proxy (gint argc, gchar **argv)
{
	FsIntelConfig *config;
	GError *error = NULL;
	gint status = FS_EXIT_OK;
	gboolean set = argc == 1;

	if (argc > 1) {
		fs_cli_error ("usage: stockfw intel proxy [URL|none]");
		return FS_EXIT_USAGE;
	}
	config = load_config (set, &error);
	if (config == NULL)
		return fail (error, "proxy");
	if (set) {
		const gchar *v = argv[0];

		if (g_ascii_strcasecmp (v, "none") == 0 ||
		    g_ascii_strcasecmp (v, "off") == 0)
			v = NULL;
		if (!fs_intel_config_set_proxy (config, v, &error)) {
			fs_intel_config_free (config);
			fs_cli_error ("%s", error->message);
			fs_cli_hint ("e.g. http://proxy.example:3128, or none");
			g_clear_error (&error);
			return FS_EXIT_USAGE;
		}
		if (!save_config (config, &status)) {
			fs_intel_config_free (config);
			return status;
		}
	}
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "proxy", config->proxy);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		if (config->proxy != NULL)
			printf ("Downloads go through the proxy %s.\n", config->proxy);
		else
			printf ("No proxy: downloads connect to each feed's host "
			        "directly.\n");
		if (set)
			printf ("%sThe next `stockfw intel update' uses it.%s\n",
			        fs_cli_dim (), fs_cli_reset ());
	}
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

/* ------------------------------------------------------ custom feeds */

static gint
intel_add_feed (gint argc, gchar **argv)
{
	const gchar *name = NULL, *url = NULL;
	FsFeedFormat format = FS_FEED_FMT_PLAIN;
	FsIntelDir dir = FS_INTEL_DIR_IN;
	FsIntelConfig *config;
	GError *error = NULL;
	gchar *id = NULL, *shown;
	gint status = FS_EXIT_OK;

	for (gint i = 0; i < argc; i++) {
		if ((strcmp (argv[i], "--direction") == 0 ||
		     strcmp (argv[i], "--dir") == 0) && i + 1 < argc) {
			if (!parse_dir (argv[++i], &dir))
				return FS_EXIT_USAGE;
		} else if (strcmp (argv[i], "--format") == 0 && i + 1 < argc) {
			if (!fs_feed_format_from_string (argv[++i], &format)) {
				fs_cli_error ("the format must be plain, spamhaus-json "
				              "or dshield, not \"%s\"", argv[i]);
				return FS_EXIT_USAGE;
			}
		} else if (argv[i][0] == '-' && argv[i][1] == '-') {
			fs_cli_error ("unknown option for intel add-feed: %s",
			              argv[i]);
			fs_cli_hint ("options are --format and --direction");
			return FS_EXIT_USAGE;
		} else if (name == NULL) {
			name = argv[i];
		} else if (url == NULL) {
			url = argv[i];
		} else {
			fs_cli_error ("intel add-feed takes a name and an https:// "
			              "address");
			return FS_EXIT_USAGE;
		}
	}
	if (url == NULL) {
		fs_cli_error ("usage: stockfw intel add-feed NAME URL "
		              "[--format plain|spamhaus-json|dshield] "
		              "[--direction in|out|both]");
		return FS_EXIT_USAGE;
	}

	config = load_config (TRUE, &error);
	if (config == NULL)
		return fail (error, "add-feed");
	if (!fs_intel_config_add_custom (config, name, url, format, dir, &id,
	                                 &error)) {
		fs_intel_config_free (config);
		return fail (error, "add-feed");
	}
	if (!save_config (config, &status)) {
		g_free (id);
		fs_intel_config_free (config);
		return status;
	}
	shown = fs_feed_url_redacted (url);
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "id", id);                    g_string_append_c (out, ',');
		fs_json_kv_str (out, "url", shown);                g_string_append_c (out, ',');
		fs_json_kv_str (out, "direction", dir_word (dir)); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "enabled", TRUE);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		printf ("%s+%s %s (%s) from %s, %s: %s.\n", fs_cli_green (),
		        fs_cli_reset (), name, id, shown, dir_word (dir),
		        dir_prose (dir));
		printf ("%sYou typed the address, which is the consent to contact "
		        "that host.  Not live yet: run `" FS_CLI_SUDO "stockfw intel update "
		        "--feed %s', then `" FS_CLI_SUDO "stockfw intel apply'.%s\n",
		        fs_cli_dim (), id, fs_cli_reset ());
	}
	g_free (shown);
	g_free (id);
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

/* -------------------------------------------------------------- update */

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

static gint
intel_update (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	const gchar *only = NULL;
	guint flags = 0;
	gboolean no_apply = FALSE, any_new = FALSE, bad = FALSE;
	FsIntelConfig *config;
	GError *error = NULL;
	GPtrArray *results;
	FsIntelOutcome *o = NULL;
	const gchar *reapply = "none";
	const gchar **accept;
	gchar *reapply_why = NULL;
	GError *apply_error = NULL;

	for (gint i = 0; i < argc; i++) {
		if (strcmp (argv[i], "--feed") == 0 && i + 1 < argc)
			only = argv[++i];
		else if (strcmp (argv[i], "--now") == 0)
			flags |= FS_INTEL_UPDATE_NOW;
		else if (strcmp (argv[i], "--accept-shrink") == 0)
			flags |= FS_INTEL_UPDATE_ACCEPT_SHRINK;
		else if (strcmp (argv[i], "--accept-coverage") == 0)
			flags |= FS_INTEL_UPDATE_ACCEPT_COVERAGE;
		else if (strcmp (argv[i], "--no-apply") == 0)
			no_apply = TRUE;
		else {
			fs_cli_error ("unexpected argument for intel update: %s",
			              argv[i]);
			fs_cli_hint ("options are --feed ID (or location), --now, "
			             "--accept-shrink, --accept-coverage and "
			             "--no-apply");
			return FS_EXIT_USAGE;
		}
	}

	config = load_config (FALSE, &error);
	if (config == NULL)
		return fail (error, "update");
	if (only != NULL && strcmp (only, FS_INTEL_GEO_ID) == 0) {
		/* The location database (`intel geo update'). */
		if (!fs_intel_geo_supported ()) {
			fs_intel_config_free (config);
			fs_cli_error ("%s", fs_intel_geo_unsupported_text ());
			return FS_EXIT_FAILURE;
		}
		if (!config->geo_enabled) {
			fs_intel_config_free (config);
			fs_cli_error ("the location database is turned off");
			fs_cli_hint ("turn it on first: " FS_CLI_SUDO "stockfw intel "
			             "geo on --accept-terms");
			return FS_EXIT_USAGE;
		}
	} else if (only != NULL) {
		FsIntelFeedConf *f = fs_intel_config_feed (config, only);

		if (f == NULL) {
			gboolean list = fs_intel_config_list (config, only) != NULL;

			fs_intel_config_free (config);
			if (list) {
				fs_cli_error ("%s is a local list: lists are imported, "
				              "not downloaded", only);
				fs_cli_hint ("import it again: stockfw intel import FILE "
				             "--name NAME");
				return FS_EXIT_USAGE;
			}
			g_set_error (&error, FS_INTEL_ERROR, FS_INTEL_ERR_UNKNOWN,
			             "there is no feed called \"%s\"", only);
			return fail (error, "update");
		}
		if (!f->enabled) {
			fs_intel_config_free (config);
			fs_cli_error ("%s is turned off", only);
			fs_cli_hint ("turn it on first: " FS_CLI_SUDO "stockfw intel enable %s",
			             only);
			return FS_EXIT_USAGE;
		}
	}

	/* Only enabled feeds whose terms were accepted are fetched: the
	 * engine checks, so nothing turned on means no request at all. */
	results = fs_intel_update (config, only, flags,
	                           g_get_real_time () / G_USEC_PER_SEC);
	accept = g_new0 (const gchar *, results->len + 1);
	for (guint i = 0; i < results->len; i++) {
		const FsIntelUpdateResult *r = g_ptr_array_index (results, i);

		if (r->outcome == FS_INTEL_UPDATED)
			any_new = TRUE;
		if (r->outcome == FS_INTEL_FAILED || r->outcome == FS_INTEL_REFUSED ||
		    r->outcome == FS_INTEL_NEEDS_CONSENT)
			bad = TRUE;
		if (r->outcome == FS_INTEL_REFUSED) {
			FsIntelSourceState *st = fs_intel_source_state (r->id);

			accept[i] = accept_flag (st);
			fs_intel_source_state_free (st);
		}
	}

	/* An unattended re-apply only where it keeps what the user already
	 * has: the firewall running, the lists enforced (or someone else's
	 * table in their place), and no hold (design 6.5). */
	if (any_new && no_apply) {
		reapply = "skipped";
		reapply_why = g_strdup ("--no-apply");
	} else if (any_new) {
		const gchar *hold = fs_apply_hold_reason ();
		FsIntelState st = fs_intel_state (backend, config, NULL);
		FsFirewallState fw = geteuid () == 0 ? backend->get_state ()
		                                     : FS_FW_NONE;

		if (hold != NULL) {
			reapply = "skipped";
			reapply_why = g_strdup (hold);
		} else if (fw != FS_FW_RUNNING) {
			reapply = "skipped";
			reapply_why = g_strdup ("the firewall is not running");
		} else if (st != FS_INTEL_STATE_ENFORCED &&
		           st != FS_INTEL_STATE_DIFFERS) {
			reapply = "skipped";
			reapply_why = g_strdup_printf ("the blocklists are %s, not "
			                               "enforced",
			                               fs_intel_state_to_string (st));
		} else {
			o = fs_intel_apply_safe (backend, config, NULL, SOURCE, NULL,
			                         &apply_error);
			reapply = o != NULL && o->result == FS_APPLY_OK ? "applied"
			                                                : "failed";
			if (o == NULL || o->result != FS_APPLY_OK)
				bad = TRUE;
		}
	}

	if (fs_cli.json) {
		GString *out = g_string_new ("{\"results\":[");

		for (guint i = 0; i < results->len; i++) {
			const FsIntelUpdateResult *r = g_ptr_array_index (results, i);

			if (i > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "id", r->id);  g_string_append_c (out, ',');
			fs_json_kv_str (out, "name",
			                fs_intel_config_label (config, r->id));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "outcome", outcome_word (r->outcome));
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "message", r->message);
			g_string_append_c (out, ',');
			fs_json_kv_uint (out, "entries", r->entries);
			g_string_append_c (out, ',');
			fs_json_kv_str (out, "accept_with", accept[i]);
			g_string_append_c (out, '}');
		}
		g_string_append (out, "],\"reapply\":{");
		fs_json_kv_str (out, "result", reapply);     g_string_append_c (out, ',');
		fs_json_kv_str (out, "reason", reapply_why); g_string_append_c (out, ',');
		fs_json_kv_str (out, "digest", o != NULL ? o->digest : NULL);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", apply_error != NULL
		                ? apply_error->message : NULL);
		g_string_append_c (out, ',');
		fs_json_key (out, "notes");
		notes_json (out, o != NULL ? o->notes : NULL);
		g_string_append (out, "}}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		if (results->len == 0)
			printf ("No feed is turned on: nothing to download.\n");
		for (guint i = 0; i < results->len; i++) {
			const FsIntelUpdateResult *r = g_ptr_array_index (results, i);
			const gchar *color =
				r->outcome == FS_INTEL_UPDATED ? fs_cli_green ()
				: r->outcome == FS_INTEL_UNCHANGED ||
				  r->outcome == FS_INTEL_NOT_DUE ? fs_cli_dim ()
				: fs_cli_red ();
			gchar *n = grouped (r->entries);

			printf ("  %-18s %s%-13s%s %10s entries  %s\n", r->id, color,
			        outcome_word (r->outcome), fs_cli_reset (), n,
			        r->message != NULL ? r->message : "");
			if (accept[i] != NULL)
				printf ("%s  To take this copy anyway: " FS_CLI_SUDO "stockfw "
				        "intel update --feed %s --now %s%s\n",
				        fs_cli_dim (), r->id, accept[i],
				        fs_cli_reset ());
			g_free (n);
		}
		if (strcmp (reapply, "applied") == 0) {
			printf ("The new copies are enforced (fingerprint %s).\n",
			        o->digest);
			notes_print (o->notes);
		} else if (strcmp (reapply, "failed") == 0) {
			fs_cli_error ("the new copies could not be applied: %s",
			              apply_error != NULL ? apply_error->message
			                                  : FS_CLI_LIVE " refused them");
			if (o != NULL)
				notes_print (o->notes);
		} else if (strcmp (reapply, "skipped") == 0) {
			printf ("%sNot applied (%s): run `" FS_CLI_SUDO "stockfw intel apply' "
			        "to enforce the new copies.%s\n", fs_cli_dim (),
			        reapply_why, fs_cli_reset ());
		}
	}

	g_free (reapply_why);
	g_free (accept);
	g_clear_error (&apply_error);
	fs_intel_outcome_free (o);
	g_ptr_array_unref (results);
	fs_intel_config_free (config);
	return bad ? FS_EXIT_FAILURE : FS_EXIT_OK;
}

/* --------------------------------------------------------- apply/clear */

static gint
intel_apply_dry (FsIntelConfig *config)
{
	gchar **hosts = fs_intel_update_hosts (config);
	FsHostNet *host = fs_hostnet_read ((const gchar *const *) hosts);
	GPtrArray *notes = NULL;
	GError *error = NULL;
	FsIntelRuleset *rs = fs_intel_build (config, host, &notes, &error);
	gchar *digest;

	g_strfreev (hosts);
	fs_hostnet_free (host);
	if (rs == NULL) {
		if (notes != NULL)
			g_ptr_array_unref (notes);
		return fail (error, "apply --dry-run");
	}
	digest = fs_intel_ruleset_digest (rs);
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "dry_run", TRUE);     g_string_append_c (out, ',');
		fs_json_kv_str (out, "digest", digest);     g_string_append_c (out, ',');
		g_string_append (out, "\"sets\":[");
		for (guint i = 0; i < rs->sets->len; i++) {
			const FsIntelSet *set = g_ptr_array_index (rs->sets, i);

			if (i > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "id", set->id);                g_string_append_c (out, ',');
			fs_json_kv_str (out, "name", set->label);           g_string_append_c (out, ',');
			fs_json_kv_str (out, "direction", dir_word (set->dir)); g_string_append_c (out, ',');
			fs_json_kv_uint (out, "ipv4_ranges",
			                 fs_range_set_count4 (set->ranges)); g_string_append_c (out, ',');
			fs_json_kv_uint (out, "ipv6_ranges",
			                 fs_range_set_count6 (set->ranges));
			g_string_append_c (out, '}');
		}
		g_string_append (out, "],");
		fs_json_key (out, "notes");
		notes_json (out, notes);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		if (rs->sets->len == 0)
			printf ("Would apply: no list (the blocklist table would be "
			        "removed).\n");
		else
			printf ("Would apply %u list%s (fingerprint %s):\n",
			        rs->sets->len, rs->sets->len == 1 ? "" : "s", digest);
		for (guint i = 0; i < rs->sets->len; i++) {
			const FsIntelSet *set = g_ptr_array_index (rs->sets, i);

			printf ("  %-24s %-5s %u IPv4 and %u IPv6 ranges  %s%s%s\n",
			        set->id, dir_word (set->dir),
			        fs_range_set_count4 (set->ranges),
			        fs_range_set_count6 (set->ranges), fs_cli_dim (),
			        set->label != NULL ? set->label : "", fs_cli_reset ());
		}
		notes_print (notes);
		printf ("%sNothing was changed (dry run).%s\n", fs_cli_dim (),
		        fs_cli_reset ());
	}
	g_free (digest);
	if (notes != NULL)
		g_ptr_array_unref (notes);
	fs_intel_ruleset_free (rs);
	return FS_EXIT_OK;
}

static gint
intel_apply (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	gboolean dry_run = FALSE;
	FsIntelConfig *config;
	GError *error = NULL;
	FsIntelOutcome *o;
	FsIntelState state;
	gchar *detail = NULL;
	gint status;

	for (gint i = 0; i < argc; i++) {
		if (strcmp (argv[i], "--dry-run") == 0 ||
		    strcmp (argv[i], "-n") == 0) {
			dry_run = TRUE;
		} else {
			fs_cli_error ("unexpected argument: %s", argv[i]);
			return FS_EXIT_USAGE;
		}
	}
	if (!dry_run && geteuid () != 0)
		return fs_cli_need_root ("intel apply");

	config = load_config (!dry_run, &error);
	if (config == NULL)
		return fail (error, "apply");
	if (dry_run) {
		status = intel_apply_dry (config);
		fs_intel_config_free (config);
		return status;
	}

	o = fs_intel_apply_safe (backend, config, NULL, SOURCE,
	                         fs_apply_hold_reason (), &error);
	if (o == NULL) {
		/* The build refused (a tampered list, over a limit): nothing
		 * reached the kernel. */
		fs_intel_config_free (config);
		return fail (error, "apply");
	}
	state = fs_intel_state (backend, config, &detail);

	if (o->held || o->result == FS_APPLY_OK)
		status = FS_EXIT_OK;
	else
		status = FS_EXIT_FAILURE;

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "applied", o->result == FS_APPLY_OK);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "held", o->held);               g_string_append_c (out, ',');
		fs_json_kv_str (out, "hold_reason", o->hold_reason);  g_string_append_c (out, ',');
		fs_json_kv_str (out, "result",
		                fs_util_apply_result_to_string ((int) o->result));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "digest", o->digest);            g_string_append_c (out, ',');
		fs_json_kv_uint (out, "sets", o->sets);               g_string_append_c (out, ',');
		fs_json_kv_uint (out, "ipv4_ranges", o->count4);      g_string_append_c (out, ',');
		fs_json_kv_uint (out, "ipv6_ranges", o->count6);      g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", error ? error->message : NULL);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "state", fs_intel_state_to_string (state));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "detail", detail);               g_string_append_c (out, ',');
		fs_json_key (out, "notes");
		notes_json (out, o->notes);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (o->held) {
		printf ("%sHeld:%s %s.  " FS_CLI_LIVE_CAP " was left untouched.\n",
		        fs_cli_amber (), fs_cli_reset (), o->hold_reason);
		notes_print (o->notes);
	} else if (o->result == FS_APPLY_OK) {
		if (o->sets == 0)
			printf ("%sApplied:%s no list is turned on, so no blocklist "
			        "is loaded.\n", fs_cli_green (), fs_cli_reset ());
		else
			printf ("%sApplied%s %u list%s: %u IPv4 and %u IPv6 ranges "
			        "(fingerprint %s).\n", fs_cli_green (), fs_cli_reset (),
			        o->sets, o->sets == 1 ? "" : "s", o->count4,
			        o->count6, o->digest);
		notes_print (o->notes);
		printf ("  %-12s %s%s%s  %s\n", "Now", state_color (state),
		        fs_intel_state_to_string (state), fs_cli_reset (),
		        detail != NULL ? detail : "");
	} else {
		fs_cli_error ("%s", error != NULL ? error->message
		              : "the blocklists could not be applied");
		notes_print (o->notes);
		fs_cli_hint (FS_CLI_LIVE " keeps what it held before; "
		             "`stockfw intel status' shows what that is");
	}

	g_free (detail);
	g_clear_error (&error);
	fs_intel_outcome_free (o);
	fs_intel_config_free (config);
	return status;
}

static gint
intel_clear (gint argc, gchar **argv)
{
	const FsBackend *backend = fs_backend ();
	GError *error = NULL;
	FsIntelState state;
	gchar *detail = NULL;
	gboolean ok;

	(void) argv;
	if (argc > 0) {
		fs_cli_error ("intel clear takes no arguments");
		return FS_EXIT_USAGE;
	}
	if (geteuid () != 0)
		return fs_cli_need_root ("intel clear");

	ok = fs_intel_clear (backend, SOURCE, &error);
	state = fs_intel_state (backend, NULL, &detail);
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "cleared", ok);                   g_string_append_c (out, ',');
		fs_json_kv_str (out, "error", error ? error->message : NULL);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "state", fs_intel_state_to_string (state));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "detail", detail);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (ok) {
		if (!fs_cli.quiet)
			printf ("The blocklists were removed from " FS_CLI_LIVE ".  They "
			        "stay configured: `" FS_CLI_SUDO "stockfw intel apply' loads them "
			        "again.\n");
	} else {
		fs_cli_error ("the blocklists could not be removed: %s",
		              error != NULL ? error->message : "unknown error");
	}
	g_free (detail);
	g_clear_error (&error);
	return ok ? FS_EXIT_OK : FS_EXIT_FAILURE;
}

/* --------------------------------------------------------- local lists */

static gint
intel_import (gint argc, gchar **argv)
{
	const gchar *path = NULL, *name = NULL;
	FsIntelDir dir = 0;
	FsIntelConfig *config;
	GError *error = NULL;
	FsFeedParseStats stats = { 0 };
	gchar *id = NULL;
	gint status = FS_EXIT_OK;

	for (gint i = 0; i < argc; i++) {
		if (strcmp (argv[i], "--name") == 0 && i + 1 < argc) {
			name = argv[++i];
		} else if ((strcmp (argv[i], "--direction") == 0 ||
		            strcmp (argv[i], "--dir") == 0) && i + 1 < argc) {
			if (!parse_dir (argv[++i], &dir))
				return FS_EXIT_USAGE;
		} else if (argv[i][0] == '-' && argv[i][1] == '-') {
			fs_cli_error ("unknown option for intel import: %s", argv[i]);
			fs_cli_hint ("options are --name NAME and --direction "
			             "in|out|both");
			return FS_EXIT_USAGE;
		} else if (path == NULL) {
			path = argv[i];
		} else {
			fs_cli_error ("intel import takes one file");
			return FS_EXIT_USAGE;
		}
	}
	if (path == NULL || name == NULL) {
		fs_cli_error ("usage: stockfw intel import FILE --name NAME "
		              "[--direction in|out|both]");
		return FS_EXIT_USAGE;
	}

	config = load_config (TRUE, &error);
	if (config == NULL)
		return fail (error, "import");
	/* dir 0 (no --direction): a list imported again keeps its
	 * direction -- the engine finds it by name in any case or spacing,
	 * as it does to replace it -- and a new one blocks both ways. */
	if (!fs_intel_import_list (config, path, name, dir, &stats, &id,
	                           &error)) {
		fs_intel_config_free (config);
		return fail (error, "import");
	}
	{
		const FsIntelListConf *l = fs_intel_config_list (config, id);

		dir = l != NULL ? l->dir : FS_INTEL_DIR_BOTH;
	}
	if (!save_config (config, &status)) {
		g_free (id);
		fs_intel_config_free (config);
		return status;
	}
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "id", id);                    g_string_append_c (out, ',');
		fs_json_kv_str (out, "name", name);                g_string_append_c (out, ',');
		fs_json_kv_str (out, "direction", dir_word (dir)); g_string_append_c (out, ',');
		fs_json_kv_uint (out, "entries", stats.entries);   g_string_append_c (out, ',');
		fs_json_kv_uint (out, "invalid", stats.invalid);   g_string_append_c (out, ',');
		fs_json_kv_uint (out, "too_broad", stats.too_broad); g_string_append_c (out, ',');
		fs_json_kv_uint (out, "protected", stats.protected_hits);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "applied", FALSE);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		gchar *n = grouped (stats.entries);

		printf ("%s+%s %s (%s): %s entr%s, %s: %s.\n", fs_cli_green (),
		        fs_cli_reset (), name, id, n,
		        stats.entries == 1 ? "y" : "ies", dir_word (dir),
		        dir_prose (dir));
		if (stats.invalid > 0)
			printf ("%snote:%s %u line%s did not parse (the first is line "
			        "%u) and %s skipped.\n", fs_cli_amber (),
			        fs_cli_reset (), stats.invalid,
			        stats.invalid == 1 ? "" : "s", stats.first_invalid,
			        stats.invalid == 1 ? "was" : "were");
		if (stats.too_broad > 0)
			printf ("%snote:%s %u entr%s too broad to block and "
			        "left out.\n", fs_cli_amber (), fs_cli_reset (),
			        stats.too_broad,
			        stats.too_broad == 1 ? "y was" : "ies were");
		if (stats.protected_hits > 0)
			printf ("%snote:%s %u entr%s overlapped addresses that are "
			        "never blocked (private, loopback, multicast ...); "
			        "that part was left out.\n", fs_cli_amber (),
			        fs_cli_reset (), stats.protected_hits,
			        stats.protected_hits == 1 ? "y" : "ies");
		printf ("%sNot live yet: run `" FS_CLI_SUDO "stockfw intel apply'.%s\n",
		        fs_cli_dim (), fs_cli_reset ());
		g_free (n);
	}
	g_free (id);
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

static gint
intel_remove (gint argc, gchar **argv)
{
	FsIntelConfig *config;
	GError *error = NULL;
	gchar *label;
	gint status = FS_EXIT_OK;

	if (argc != 1) {
		fs_cli_error ("usage: stockfw intel remove ID");
		fs_cli_hint ("removes a local list or a custom feed; built-in "
		             "feeds are turned off with `intel disable'");
		return FS_EXIT_USAGE;
	}
	config = load_config (FALSE, &error);
	if (config == NULL)
		return fail (error, "remove");
	label = g_strdup (fs_intel_config_label (config, argv[0]));
	if (!fs_intel_config_remove (config, argv[0], &error)) {
		g_free (label);
		fs_intel_config_free (config);
		return fail (error, "remove");
	}
	if (!save_config (config, &status)) {
		g_free (label);
		fs_intel_config_free (config);
		return status;
	}
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "id", argv[0]);    g_string_append_c (out, ',');
		fs_json_kv_bool (out, "removed", TRUE); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "applied", FALSE);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		printf ("%s-%s %s (%s) removed, with its stored copy.\n",
		        fs_cli_red (), fs_cli_reset (), label, argv[0]);
		printf ("%sNot live yet: run `" FS_CLI_SUDO "stockfw intel apply'.%s\n",
		        fs_cli_dim (), fs_cli_reset ());
	}
	g_free (label);
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

/* `intel lists', `intel list show [ID]': the local lists; with an id,
 * that list and its stored ranges. */
static gint
intel_lists (gint argc, gchar **argv)
{
	FsIntelConfig *config;
	GError *error = NULL;
	GPtrArray *srcs;
	GHashTable *counters;
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;
	const gchar *only = argc > 0 ? argv[0] : NULL;
	FsRangeSet *ranges = NULL;
	gboolean found = FALSE;

	if (argc > 1) {
		fs_cli_error ("usage: stockfw intel list show [ID]");
		return FS_EXIT_USAGE;
	}
	config = load_config (FALSE, &error);
	if (config == NULL)
		return fail (error, "lists");
	if (only != NULL) {
		if (fs_intel_config_list (config, only) == NULL) {
			fs_intel_config_free (config);
			g_set_error (&error, FS_INTEL_ERROR, FS_INTEL_ERR_UNKNOWN,
			             "there is no local list called \"%s\"", only);
			return fail (error, "list show");
		}
		ranges = fs_intel_source_load (only, &error);
		if (ranges == NULL) {
			fs_intel_config_free (config);
			return fail (error, "list show");
		}
	}

	srcs = sources_of (config, FALSE);
	counters = fs_intel_counters (fs_backend ());
	if (fs_cli.json) {
		GString *out = g_string_new ("{\"lists\":[");
		gboolean first = TRUE;

		for (guint i = 0; i < srcs->len; i++) {
			const Src *s = g_ptr_array_index (srcs, i);

			if (s->list == NULL ||
			    (only != NULL && strcmp (s->id, only) != 0))
				continue;
			if (!first)
				g_string_append_c (out, ',');
			first = FALSE;
			src_json (out, config, s, counters, now);
		}
		g_string_append_c (out, ']');
		if (ranges != NULL) {
			gchar *text = fs_range_set_to_text (ranges);
			gchar **lines = g_strsplit (text, "\n", -1);
			gboolean f2 = TRUE;

			g_string_append (out, ",\"ranges\":[");
			for (gint i = 0; lines[i] != NULL; i++) {
				if (*lines[i] == '\0')
					continue;
				if (!f2)
					g_string_append_c (out, ',');
				f2 = FALSE;
				fs_json_string (out, lines[i]);
			}
			g_string_append_c (out, ']');
			g_strfreev (lines);
			g_free (text);
		}
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		static const gchar *headers[] = {
			"ID", "ON", "DIR", "ENTRIES", "IMPORTED", "BLOCKED", "NAME"
		};
		GPtrArray *rows = g_ptr_array_new_with_free_func (
			(GDestroyNotify) g_strfreev);

		for (guint i = 0; i < srcs->len; i++) {
			const Src *s = g_ptr_array_index (srcs, i);
			const FsIntelCounter *c = g_hash_table_lookup (counters, s->id);
			gchar **row;

			if (s->list == NULL ||
			    (only != NULL && strcmp (s->id, only) != 0))
				continue;
			found = TRUE;
			row = g_new0 (gchar *, 8);
			row[0] = g_strdup (s->id);
			row[1] = g_strdup (s->enabled ? "on" : "-");
			row[2] = g_strdup (dir_word (s->dir));
			row[3] = grouped (s->state != NULL ? s->state->entries : 0);
			row[4] = time_text (s->list->imported_at);
			row[5] = blocked_text (c);
			row[6] = g_strdup (s->name);
			g_ptr_array_add (rows, row);
		}
		if (found) {
			fs_cli_table (headers, 7, rows, 48);
			counts_note ();
		} else
			printf ("No local list yet.  `" FS_CLI_SUDO "stockfw intel import FILE "
			        "--name NAME' adds one (a CSV or plain file of "
			        "addresses, networks or ranges).\n");
		g_ptr_array_unref (rows);
		if (ranges != NULL) {
			gchar *text = fs_range_set_to_text (ranges);

			printf ("\n%s", text);
			g_free (text);
		}
	}
	fs_range_set_free (ranges);
	g_hash_table_unref (counters);
	g_ptr_array_unref (srcs);
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

static gint
intel_list (gint argc, gchar **argv)
{
	const gchar *sub = argc > 0 ? argv[0] : "show";

	if (strcmp (sub, "show") == 0 || strcmp (sub, "ls") == 0)
		return intel_lists (argc > 0 ? argc - 1 : 0, argv + 1);
	if (strcmp (sub, "add") == 0 || strcmp (sub, "import") == 0)
		return intel_import (argc - 1, argv + 1);
	if (strcmp (sub, "remove") == 0 || strcmp (sub, "rm") == 0)
		return intel_remove (argc - 1, argv + 1);
	fs_cli_error ("unknown intel list action: %s", sub);
	fs_cli_hint ("intel list show [ID] | intel list add FILE --name NAME | "
	             "intel list remove ID");
	return FS_EXIT_USAGE;
}

/* ---------------------------------------------------------- exceptions */

static void
exceptions_json (GString *out, const FsRangeSet *set)
{
	gchar *text = fs_range_set_to_text (set);
	gchar **lines = g_strsplit (text, "\n", -1);
	gboolean first = TRUE;

	g_string_append_c (out, '[');
	for (gint i = 0; lines[i] != NULL; i++) {
		if (*lines[i] == '\0')
			continue;
		if (!first)
			g_string_append_c (out, ',');
		first = FALSE;
		fs_json_string (out, lines[i]);
	}
	g_string_append_c (out, ']');
	g_strfreev (lines);
	g_free (text);
}

static gint
intel_exceptions (gint argc, gchar **argv)
{
	FsIntelConfig *config;
	GError *error = NULL;

	(void) argv;
	if (argc > 0) {
		fs_cli_error ("intel exceptions takes no arguments");
		return FS_EXIT_USAGE;
	}
	config = load_config (FALSE, &error);
	if (config == NULL)
		return fail (error, "exceptions");
	if (fs_cli.json) {
		GString *out = g_string_new ("{\"exceptions\":");

		exceptions_json (out, config->exceptions);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (fs_range_set_is_empty (config->exceptions)) {
		printf ("No exception.  `" FS_CLI_SUDO "stockfw intel except ADDRESS' lets "
		        "an address through every list.\n");
	} else {
		gchar *text = fs_range_set_to_text (config->exceptions);

		printf ("Never blocked by a list:\n%s", text);
		g_free (text);
	}
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

/* `except ADDR...' adds, `unexcept ADDR...' takes away (a part of a
 * wider exception too).  Every argument must parse, or nothing is
 * saved. */
static gint
intel_except (gint argc, gchar **argv, gboolean add)
{
	FsIntelConfig *config;
	GError *error = NULL;
	FsRangeSet *given;
	gint status = FS_EXIT_OK;
	const gchar *verb = add ? "except" : "unexcept";

	if (argc == 0) {
		fs_cli_error ("usage: stockfw intel %s ADDRESS|NETWORK|RANGE...",
		              verb);
		return FS_EXIT_USAGE;
	}
	given = fs_range_set_new ();
	for (gint i = 0; i < argc; i++) {
		if (!fs_range_set_add_text (given, argv[i])) {
			fs_cli_error ("not an address, network or range: \"%s\"",
			              argv[i]);
			fs_cli_hint ("e.g. 203.0.113.9, 198.51.100.0/24, "
			             "192.0.2.10-192.0.2.20 or 2001:db8::/48");
			fs_range_set_free (given);
			return FS_EXIT_USAGE;
		}
	}
	fs_range_set_normalize (given);

	config = load_config (TRUE, &error);
	if (config == NULL) {
		fs_range_set_free (given);
		return fail (error, verb);
	}
	if (add)
		fs_range_set_union (config->exceptions, given);
	else
		fs_range_set_subtract (config->exceptions, given);
	fs_range_set_free (given);
	if (!save_config (config, &status)) {
		fs_intel_config_free (config);
		return status;
	}
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "applied", FALSE);
		g_string_append (out, ",\"exceptions\":");
		exceptions_json (out, config->exceptions);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		for (gint i = 0; i < argc; i++)
			printf ("%s%s%s %s\n", add ? fs_cli_green () : fs_cli_red (),
			        add ? "+" : "-", fs_cli_reset (), argv[i]);
		printf ("%sSaved.  Not live yet: run `" FS_CLI_SUDO "stockfw intel "
		        "apply'.%s\n", fs_cli_dim (), fs_cli_reset ());
	}
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

/* ------------------------------------------- countries and networks */

/* `stockfw intel geo': blocking by the country an address range is
 * registered in, or by the network that owns it (its AS number), from
 * IPFire's location database (design section 13).  Linux only in
 * 1.0.7: elsewhere every command says so (fs_intel_geo_supported). */

static const gchar *
location_kind_word (FsIntelLocationKind kind)
{
	return kind == FS_INTEL_LOCATION_COUNTRY ? "country" : "asn";
}

/* "DE, FR" or "AS64500, AS64501". */
static gchar *
location_values_text (const FsIntelLocationConf *l)
{
	GString *out = g_string_new (NULL);

	if (l->kind == FS_INTEL_LOCATION_COUNTRY) {
		for (guint i = 0; l->countries != NULL && l->countries[i] != NULL;
		     i++)
			g_string_append_printf (out, "%s%s", i ? ", " : "",
			                        l->countries[i]);
	} else {
		for (guint i = 0; l->asns != NULL && i < l->asns->len; i++)
			g_string_append_printf (out, "%sAS%u", i ? ", " : "",
			                        g_array_index (l->asns, guint32, i));
	}
	return g_string_free (out, FALSE);
}

static void
location_values_json (GString *out, const FsIntelLocationConf *l)
{
	g_string_append (out, "\"values\":[");
	if (l->kind == FS_INTEL_LOCATION_COUNTRY) {
		for (guint i = 0; l->countries != NULL && l->countries[i] != NULL;
		     i++) {
			if (i > 0)
				g_string_append_c (out, ',');
			fs_json_string (out, l->countries[i]);
		}
	} else {
		for (guint i = 0; l->asns != NULL && i < l->asns->len; i++)
			g_string_append_printf (out, "%s%u", i ? "," : "",
			                        g_array_index (l->asns, guint32, i));
	}
	g_string_append_c (out, ']');
}

/* The database in the store, read without creating the store: with no
 * store, an empty status (nothing was ever downloaded).  FALSE with an
 * error only when the store cannot be read (not root). */
static gboolean
geo_status_read (FsIntelGeoStatus *st, GError **error)
{
	if (!fs_intel_store_exists ()) {
		memset (st, 0, sizeof *st);
		return TRUE;
	}
	return fs_intel_geo_status (st, g_get_real_time () / G_USEC_PER_SEC,
	                            error);
}

/* The location database is in use: threat intel on, the database
 * switch on and its terms accepted (the engine's geo_usable). */
static gboolean
geo_in_use (const FsIntelConfig *config)
{
	return config->enabled && config->geo_enabled &&
	       config->geo_accepted_at > 0;
}

/* A rule's status word: off, database-off (the database is turned
 * off, so nothing is enforced), no-database (not downloaded yet),
 * not-applied (not in the rule set last applied), in-force (in that
 * rule set, and the live rules are that rule set: the state is
 * enforced) or not-in-force (applied, but the live rules are missing,
 * differ or cannot be read; never "in-force" from the record alone). */
static const gchar *
location_status (const FsIntelConfig *config, const FsIntelLocationConf *l,
                 const FsIntelGeoStatus *st, FsIntelState state)
{
	if (!l->enabled)
		return "off";
	if (!geo_in_use (config))
		return "database-off";
	if (st == NULL || !st->present)
		return "no-database";
	if (!fs_intel_applied_has (l->id))
		return "not-applied";
	return state == FS_INTEL_STATE_ENFORCED ? "in-force" : "not-in-force";
}

static void
location_json (GString *out, const FsIntelConfig *config,
               const FsIntelLocationConf *l, const FsIntelGeoStatus *st,
               FsIntelState state)
{
	g_string_append_c (out, '{');
	fs_json_kv_str (out, "id", l->id);                     g_string_append_c (out, ',');
	fs_json_kv_str (out, "name", l->name);                 g_string_append_c (out, ',');
	fs_json_kv_str (out, "kind", location_kind_word (l->kind));
	g_string_append_c (out, ',');
	location_values_json (out, l);                         g_string_append_c (out, ',');
	fs_json_kv_str (out, "direction", dir_word (l->dir));  g_string_append_c (out, ',');
	fs_json_kv_bool (out, "enabled", l->enabled);          g_string_append_c (out, ',');
	fs_json_kv_str (out, "status", location_status (config, l, st, state));
	g_string_append_c (out, '}');
}

/* {supported, enabled, terms_accepted_at, url, database{...},
 * attribution, rules[]}: `intel geo status --json' and the "location"
 * object of /api/intel.  Read-only; creates nothing.  state is the
 * overall state (fs_intel_state), which the rules' status words need. */
static void
geo_json (GString *out, const FsIntelConfig *config, FsIntelState state)
{
	FsIntelGeoStatus st;
	GError *error = NULL;
	gboolean have = geo_status_read (&st, &error);
	gchar *attribution = fs_intel_geo_attribution ();

	g_string_append_c (out, '{');
	fs_json_kv_bool (out, "supported", fs_intel_geo_supported ());
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "unsupported_reason", fs_intel_geo_supported ()
	                ? NULL : fs_intel_geo_unsupported_text ());
	g_string_append_c (out, ',');
	fs_json_kv_bool (out, "enabled", config->geo_enabled);
	g_string_append_c (out, ',');
	kv_time (out, "terms_accepted_at", config->geo_accepted_at);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "url", FS_GEODB_URL);
	g_string_append_c (out, ',');
	fs_json_key (out, "database");
	if (!have) {
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "error", error->message);
		g_string_append_c (out, '}');
		g_clear_error (&error);
	} else {
		g_string_append_c (out, '{');
		fs_json_kv_bool (out, "present", st.present);    g_string_append_c (out, ',');
		kv_time (out, "created_at", st.created_at);      g_string_append_c (out, ',');
		fs_json_kv_bool (out, "stale", st.stale);        g_string_append_c (out, ',');
		kv_time (out, "updated_at", st.fetched_at);      g_string_append_c (out, ',');
		kv_time (out, "attempted_at", st.attempted_at);  g_string_append_c (out, ',');
		fs_json_kv_str (out, "last_error", st.last_error); g_string_append_c (out, ',');
		fs_json_kv_str (out, "refused", st.refused);     g_string_append_c (out, ',');
		fs_json_kv_str (out, "damaged", st.damaged);     g_string_append_c (out, ',');
		fs_json_kv_str (out, "licence", st.license);     g_string_append_c (out, ',');
		fs_json_kv_uint (out, "networks", st.networks);  g_string_append_c (out, ',');
		fs_json_kv_uint (out, "countries", st.countries); g_string_append_c (out, ',');
		fs_json_kv_uint (out, "ases", st.ases);
		g_string_append_c (out, '}');
	}
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "attribution", attribution);
	g_string_append (out, ",\"rules\":[");
	for (guint i = 0; i < config->locations->len; i++) {
		if (i > 0)
			g_string_append_c (out, ',');
		location_json (out, config, g_ptr_array_index (config->locations, i),
		               have ? &st : NULL, state);
	}
	g_string_append (out, "]}");
	g_free (attribution);
	if (have)
		fs_intel_geo_status_clear (&st);
}

/* Every location command starts here: FALSE (and the platform's
 * sentence, exit 1) where the feature does not exist. */
static gboolean
geo_check_supported (gint *status)
{
	if (fs_intel_geo_supported ())
		return TRUE;
	fs_cli_error ("%s", fs_intel_geo_unsupported_text ());
	*status = FS_EXIT_FAILURE;
	return FALSE;
}

/* "2023-11-14" for a creation time. */
static gchar *
day_text (gint64 t)
{
	GDateTime *dt = t > 0 ? g_date_time_new_from_unix_utc (t) : NULL;
	gchar *out;

	if (dt == NULL)
		return g_strdup ("?");
	out = g_date_time_format (dt, "%Y-%m-%d");
	g_date_time_unref (dt);
	return out;
}

static void
geo_print_rules (const FsIntelConfig *config, const FsIntelGeoStatus *st,
                 FsIntelState state)
{
	static const gchar *headers[] = {
		"ID", "ON", "KIND", "DIR", "BLOCKED", "STATUS", "VALUES", "NAME"
	};
	GPtrArray *rows;
	GHashTable *counters;

	if (config->locations->len == 0) {
		printf ("No country or network rule yet.  `" FS_CLI_SUDO "stockfw "
		        "intel geo add country CODE' adds one; `stockfw intel "
		        "geo search TEXT' finds codes and AS numbers.\n");
		return;
	}
	counters = fs_intel_counters (fs_backend ());
	rows = g_ptr_array_new_with_free_func ((GDestroyNotify) g_strfreev);
	for (guint i = 0; i < config->locations->len; i++) {
		const FsIntelLocationConf *l =
			g_ptr_array_index (config->locations, i);
		gchar **row = g_new0 (gchar *, 9);

		row[0] = g_strdup (l->id);
		row[1] = g_strdup (l->enabled ? "on" : "-");
		row[2] = g_strdup (location_kind_word (l->kind));
		row[3] = g_strdup (dir_word (l->dir));
		row[4] = blocked_text (g_hash_table_lookup (counters, l->id));
		row[5] = g_strdup (location_status (config, l, st, state));
		row[6] = location_values_text (l);
		row[7] = g_strdup (l->name);
		g_ptr_array_add (rows, row);
	}
	fs_cli_table (headers, 8, rows, 48);
	counts_note ();
	g_ptr_array_unref (rows);
	g_hash_table_unref (counters);
}

static gint
geo_status (gint argc, gchar **argv)
{
	FsIntelConfig *config;
	FsIntelGeoStatus st;
	GError *error = NULL;
	gchar *attribution, *t;
	gint status = FS_EXIT_OK;

	(void) argv;
	if (argc > 0) {
		fs_cli_error ("intel geo status takes no arguments");
		return FS_EXIT_USAGE;
	}
	config = load_config (FALSE, &error);
	if (config == NULL)
		return fail (error, "geo status");
	if (fs_cli.json) {
		GString *out = g_string_new (NULL);

		geo_json (out, config, fs_intel_state (fs_backend (), config,
		                                       NULL));
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
		fs_intel_config_free (config);
		return FS_EXIT_OK;
	}
	if (!fs_intel_geo_supported ()) {
		printf ("  %-13s %s%s%s\n", "Location", fs_cli_dim (),
		        fs_intel_geo_unsupported_text (), fs_cli_reset ());
		fs_intel_config_free (config);
		return FS_EXIT_OK;
	}
	if (!geo_status_read (&st, &error)) {
		fs_intel_config_free (config);
		return fail (error, "geo status");
	}
	t = time_text (config->geo_accepted_at);
	printf ("  %-13s %s\n", "Location", config->geo_enabled
	        ? "on" : "off: the location database is not downloaded or used");
	printf ("  %-13s %s\n", "Terms", config->geo_accepted_at > 0 ? t
	        : "not accepted (`stockfw intel geo terms' shows them)");
	g_free (t);
	if (st.present) {
		gchar *day = day_text (st.created_at);
		gchar *n = grouped (st.networks);

		printf ("  %-13s copy of %s: %s networks, %u countries, %u "
		        "ASes%s%s%s\n", "Database", day, n, st.countries, st.ases,
		        st.stale ? fs_cli_amber () : "",
		        !st.stale ? "" : geo_in_use (config)
		        ? "; out of date (older than 30 days), still used by "
		          "the rules" : "; out of date (older than 30 days)",
		        st.stale ? fs_cli_reset () : "");
		g_free (day);
		g_free (n);
	} else if (st.damaged != NULL) {
		printf ("  %-13s %scannot be used: %s%s\n", "Database",
		        fs_cli_red (), st.damaged, fs_cli_reset ());
	} else {
		printf ("  %-13s not downloaded yet%s\n", "Database",
		        config->geo_enabled ? " (`" FS_CLI_SUDO "stockfw intel geo "
		                              "update')" : "");
	}
	t = time_text (st.fetched_at);
	printf ("  %-13s %s", "Updated", t);
	g_free (t);
	if (st.attempted_at > 0 && st.attempted_at != st.fetched_at) {
		t = time_text (st.attempted_at);
		printf (" (last attempt %s)", t);
		g_free (t);
	}
	printf ("\n");
	if (st.refused != NULL)
		printf ("  %-13s %srefused: %s%s\n", "Last update",
		        fs_cli_amber (), st.refused, fs_cli_reset ());
	else if (st.last_error != NULL)
		printf ("  %-13s %sfailed: %s%s\n", "Last update", fs_cli_red (),
		        st.last_error, fs_cli_reset ());
	printf ("  %-13s %s\n\n", "Source", FS_GEODB_URL);
	geo_print_rules (config, &st, fs_intel_state (fs_backend (), config,
	                                              NULL));
	attribution = fs_intel_geo_attribution ();
	printf ("\n%sA country is where an address range is registered, not "
	        "where a computer is.\n%s%s\n", fs_cli_dim (), attribution,
	        fs_cli_reset ());
	g_free (attribution);
	fs_intel_geo_status_clear (&st);
	fs_intel_config_free (config);
	return status;
}

static gint
geo_terms (gint argc, gchar **argv)
{
	FsIntelConfig *config;
	GError *error = NULL;
	gchar *text;
	gint status = FS_EXIT_OK;

	(void) argv;
	if (argc > 0) {
		fs_cli_error ("intel geo terms takes no arguments");
		return FS_EXIT_USAGE;
	}
	if (!geo_check_supported (&status))
		return status;
	config = load_config (FALSE, &error);
	if (config == NULL)
		return fail (error, "geo terms");
	text = fs_intel_geo_consent_text (config);
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		kv_time (out, "accepted_at", config->geo_accepted_at);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "terms", text);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		printf ("%s\n", text);
	}
	g_free (text);
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

/* `geo on [--accept-terms]', `geo off': the location database's switch.
 * Turning it on the first time needs its terms accepted, exactly like a
 * feed: without --accept-terms the terms are shown, nothing is saved
 * and the exit status is 2. */
static gint
geo_switch (gint argc, gchar **argv, gboolean on)
{
	FsIntelConfig *config;
	GError *error = NULL;
	gboolean accept = FALSE, newly = FALSE;
	gint status = FS_EXIT_OK;
	FsIntelGeoStatus st;

	for (gint i = 0; i < argc; i++) {
		if (on && strcmp (argv[i], "--accept-terms") == 0) {
			accept = TRUE;
		} else {
			fs_cli_error ("unexpected argument for intel geo %s: %s",
			              on ? "on" : "off", argv[i]);
			if (on)
				fs_cli_hint ("the only option is --accept-terms");
			return FS_EXIT_USAGE;
		}
	}
	if (on && !geo_check_supported (&status))
		return status;
	/* A refusal must not create the store: only an accepted switch,
	 * or one that was accepted before (and so has a store), saves;
	 * and off with no store has nothing to turn off. */
	config = load_config (on && accept, &error);
	if (config == NULL)
		return fail (error, on ? "geo on" : "geo off");
	if (on) {
		newly = config->geo_accepted_at <= 0 && accept;
		if (!fs_intel_config_enable_geo (config, accept, &error)) {
			if (g_error_matches (error, FS_INTEL_ERROR,
			                     FS_INTEL_ERR_CONSENT)) {
				gchar *text = fs_intel_geo_consent_text (config);

				if (fs_cli.json) {
					GString *out = g_string_new ("{");

					fs_json_kv_bool (out, "enabled", FALSE);
					g_string_append_c (out, ',');
					fs_json_kv_bool (out, "needs_consent", TRUE);
					g_string_append_c (out, ',');
					fs_json_kv_str (out, "terms", text);
					g_string_append_c (out, '}');
					fs_cli_print_json (out);
					g_string_free (out, TRUE);
				} else {
					printf ("%s\n\n", text);
				}
				fs_cli_error ("%s", error->message);
				fs_cli_hint ("read the terms above; to accept them: "
				             FS_CLI_SUDO "stockfw intel geo on "
				             "--accept-terms");
				g_free (text);
				g_clear_error (&error);
				fs_intel_config_free (config);
				return FS_EXIT_USAGE;
			}
			fs_intel_config_free (config);
			return fail (error, "geo on");
		}
	} else {
		fs_intel_config_disable_geo (config);
	}
	if ((on || fs_intel_store_exists ()) && !save_config (config, &status)) {
		fs_intel_config_free (config);
		return status;
	}
	if (!geo_status_read (&st, NULL))
		memset (&st, 0, sizeof st);
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_bool (out, "enabled", on);              g_string_append_c (out, ',');
		fs_json_kv_bool (out, "terms_accepted_now", newly); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "database_present", st.present);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "applied", FALSE);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		printf ("The location database is turned %s.\n", on ? "on" : "off");
		if (newly)
			printf ("Terms accepted now; `stockfw intel geo terms' shows "
			        "them again.\n");
		if (on && !st.present)
			printf ("%sNot downloaded yet: run `" FS_CLI_SUDO "stockfw intel "
			        "geo update', then `" FS_CLI_SUDO "stockfw intel apply'.%s\n",
			        fs_cli_dim (), fs_cli_reset ());
		else if (on)
			printf ("%sNot live yet: run `" FS_CLI_SUDO "stockfw intel "
			        "apply'.%s\n", fs_cli_dim (), fs_cli_reset ());
		else
			printf ("%sYour rules are kept and enforce nothing.  Not live "
			        "yet: run `" FS_CLI_SUDO "stockfw intel apply'.%s\n",
			        fs_cli_dim (), fs_cli_reset ());
	}
	fs_intel_geo_status_clear (&st);
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

/* `geo update [--no-apply]': download the database now (intel update
 * --feed location --now).  `intel update' alone also updates it, at
 * most once a day. */
static gint
geo_update (gint argc, gchar **argv)
{
	gchar *args[4] = { (gchar *) "--feed", (gchar *) FS_INTEL_GEO_ID,
	                   (gchar *) "--now", NULL };
	gint n = 3;

	for (gint i = 0; i < argc; i++) {
		if (strcmp (argv[i], "--no-apply") == 0 && n == 3) {
			args[n++] = (gchar *) "--no-apply";
		} else {
			fs_cli_error ("unexpected argument for intel geo update: %s",
			              argv[i]);
			fs_cli_hint ("the only option is --no-apply");
			return FS_EXIT_USAGE;
		}
	}
	return intel_update (n, args);
}

/* ASCII case-insensitive "contains". */
static gboolean
contains_ci (const gchar *hay, const gchar *needle)
{
	gchar *a = g_ascii_strdown (hay != NULL ? hay : "", -1);
	gchar *b = g_ascii_strdown (needle, -1);
	gboolean hit = strstr (a, b) != NULL;

	g_free (a);
	g_free (b);
	return hit;
}

/* The copy in use, or the error that says why there is none; never
 * creates the store. */
static gboolean
geo_need_database (GError **error)
{
	if (fs_intel_store_exists ())
		return TRUE;
	g_set_error_literal (error, FS_INTEL_ERROR, FS_INTEL_ERR_STORE,
	                     "The location database has not been downloaded "
	                     "yet.");
	return FALSE;
}

static gint
geo_search (gint argc, gchar **argv)
{
	const gchar *text = NULL;
	guint max = 50;
	GError *error = NULL;
	GPtrArray *countries, *ases, *hits;
	gchar *attribution;
	gint status = FS_EXIT_OK;

	for (gint i = 0; i < argc; i++) {
		if (strcmp (argv[i], "--max") == 0 && i + 1 < argc) {
			gchar *end = NULL;
			guint64 v = g_ascii_strtoull (argv[++i], &end, 10);

			if (end == NULL || *end != '\0' || v == 0 || v > 100000) {
				fs_cli_error ("--max takes a number from 1 to 100000, "
				              "not \"%s\"", argv[i]);
				return FS_EXIT_USAGE;
			}
			max = (guint) v;
		} else if (argv[i][0] == '-' && argv[i][1] == '-') {
			fs_cli_error ("unknown option for intel geo search: %s",
			              argv[i]);
			return FS_EXIT_USAGE;
		} else if (text == NULL) {
			text = argv[i];
		} else {
			fs_cli_error ("intel geo search takes one text; quote one "
			              "with spaces");
			return FS_EXIT_USAGE;
		}
	}
	if (text == NULL || *text == '\0') {
		fs_cli_error ("usage: stockfw intel geo search TEXT [--max N]");
		fs_cli_hint ("a country's code or name (DE, germany), an AS "
		             "number (AS13335) or part of a network's name");
		return FS_EXIT_USAGE;
	}
	if (!geo_check_supported (&status))
		return status;
	if (!geo_need_database (&error))
		goto failed;
	countries = fs_intel_geo_countries (&error);
	if (countries == NULL)
		goto failed;
	ases = fs_intel_geo_search_as (text, max, &error);
	if (ases == NULL) {
		g_ptr_array_unref (countries);
		goto failed;
	}
	hits = g_ptr_array_new ();
	for (guint i = 0; i < countries->len; i++) {
		FsGeodbCountry *c = g_ptr_array_index (countries, i);

		if (g_ascii_strcasecmp (c->code, text) == 0 ||
		    contains_ci (c->name, text))
			g_ptr_array_add (hits, c);
	}
	attribution = fs_intel_geo_attribution ();
	if (fs_cli.json) {
		GString *out = g_string_new ("{\"countries\":[");

		for (guint i = 0; i < hits->len; i++) {
			FsGeodbCountry *c = g_ptr_array_index (hits, i);

			if (i > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "code", c->code);  g_string_append_c (out, ',');
			fs_json_kv_str (out, "name", c->name);  g_string_append_c (out, ',');
			fs_json_kv_str (out, "continent",
			                *c->continent ? c->continent : NULL);
			g_string_append_c (out, '}');
		}
		g_string_append (out, "],\"ases\":[");
		for (guint i = 0; i < ases->len; i++) {
			FsGeodbAs *a = g_ptr_array_index (ases, i);

			if (i > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_uint (out, "asn", a->asn);  g_string_append_c (out, ',');
			fs_json_kv_str (out, "name", a->name);
			g_string_append_c (out, '}');
		}
		g_string_append (out, "],");
		fs_json_kv_str (out, "attribution", attribution);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (hits->len == 0 && ases->len == 0) {
		printf ("Nothing in the location database matches \"%s\".\n", text);
	} else {
		static const gchar *headers[] = { "KIND", "VALUE", "NAME" };
		GPtrArray *rows = g_ptr_array_new_with_free_func (
			(GDestroyNotify) g_strfreev);

		for (guint i = 0; i < hits->len; i++) {
			FsGeodbCountry *c = g_ptr_array_index (hits, i);
			gchar **row = g_new0 (gchar *, 4);

			row[0] = g_strdup ("country");
			row[1] = g_strdup (c->code);
			row[2] = g_strdup (c->name != NULL ? c->name : "");
			g_ptr_array_add (rows, row);
		}
		for (guint i = 0; i < ases->len; i++) {
			FsGeodbAs *a = g_ptr_array_index (ases, i);
			gchar **row = g_new0 (gchar *, 4);

			row[0] = g_strdup ("asn");
			row[1] = g_strdup_printf ("AS%u", a->asn);
			row[2] = g_strdup (a->name != NULL ? a->name : "");
			g_ptr_array_add (rows, row);
		}
		fs_cli_table (headers, 3, rows, 60);
		g_ptr_array_unref (rows);
		if (ases->len == max)
			printf ("%sThe first %u networks; --max N shows more.%s\n",
			        fs_cli_dim (), max, fs_cli_reset ());
	}
	if (!fs_cli.json)
		printf ("%s%s%s\n", fs_cli_dim (), attribution, fs_cli_reset ());
	g_free (attribution);
	g_ptr_array_unref (hits);
	g_ptr_array_unref (ases);
	g_ptr_array_unref (countries);
	return FS_EXIT_OK;

failed:
	status = fail (error, "geo search");
	fs_cli_hint ("turn it on and download it: " FS_CLI_SUDO "stockfw intel "
	             "geo on --accept-terms, then " FS_CLI_SUDO "stockfw intel geo "
	             "update");
	return status;
}

/* The rule's name when --name is not given: the country's name (or
 * its code without a database), "AS13335 Cloudflare" (or "AS13335"),
 * and the values joined for more than one. */
static gchar *
location_default_name (FsIntelLocationKind kind, gchar **values)
{
	GPtrArray *countries = NULL;
	gchar *out = NULL;

	if (g_strv_length (values) != 1) {
		GString *joined = g_string_new (NULL);

		for (guint i = 0; values[i] != NULL; i++) {
			const gchar *v = values[i];

			if (kind == FS_INTEL_LOCATION_ASN &&
			    g_ascii_strncasecmp (v, "AS", 2) == 0)
				v += 2;
			if (kind == FS_INTEL_LOCATION_ASN)
				g_string_append_printf (joined, "%sAS%s",
				                        i ? ", " : "", v);
			else {
				gchar *up = g_ascii_strup (v, -1);

				g_string_append_printf (joined, "%s%s",
				                        i ? ", " : "", up);
				g_free (up);
			}
		}
		return g_string_free (joined, FALSE);
	}
	if (kind == FS_INTEL_LOCATION_COUNTRY) {
		countries = fs_intel_store_exists ()
		            ? fs_intel_geo_countries (NULL) : NULL;
		for (guint i = 0; countries != NULL && i < countries->len; i++) {
			FsGeodbCountry *c = g_ptr_array_index (countries, i);

			if (g_ascii_strcasecmp (c->code, values[0]) == 0 &&
			    c->name != NULL && *c->name != '\0')
				out = g_strdup (c->name);
		}
		if (countries != NULL)
			g_ptr_array_unref (countries);
		return out != NULL ? out : g_ascii_strup (values[0], -1);
	} else {
		const gchar *v = values[0];
		GPtrArray *ases;

		if (g_ascii_strncasecmp (v, "AS", 2) == 0)
			v += 2;
		ases = fs_intel_store_exists ()
		       ? fs_intel_geo_search_as (v, 0, NULL) : NULL;
		for (guint i = 0; ases != NULL && i < ases->len; i++) {
			FsGeodbAs *a = g_ptr_array_index (ases, i);

			if (g_strcmp0 (v, "") != 0 &&
			    a->asn == g_ascii_strtoull (v, NULL, 10) &&
			    a->name != NULL && *a->name != '\0')
				out = g_strdup_printf ("AS%u %s", a->asn, a->name);
		}
		if (ases != NULL)
			g_ptr_array_unref (ases);
		return out != NULL ? out : g_strdup_printf ("AS%s", v);
	}
}

/* Notes for values the copy in use does not name (the rule is saved
 * anyway: the next copy may name them, and the build notes it too). */
static GPtrArray *
location_unknown_notes (const FsIntelLocationConf *l)
{
	GPtrArray *notes = g_ptr_array_new_with_free_func (g_free);
	GPtrArray *countries;

	if (!fs_intel_store_exists ())
		return notes;
	if (l->kind == FS_INTEL_LOCATION_COUNTRY) {
		countries = fs_intel_geo_countries (NULL);
		if (countries == NULL)
			return notes;
		for (guint i = 0; l->countries[i] != NULL; i++) {
			gboolean known = FALSE;

			for (guint j = 0; j < countries->len && !known; j++)
				known = strcmp (((FsGeodbCountry *)
				                 g_ptr_array_index (countries, j))->code,
				                l->countries[i]) == 0;
			if (!known)
				g_ptr_array_add (notes, g_strdup_printf (
					"the location database names no country %s; the "
					"rule blocks nothing for it", l->countries[i]));
		}
		g_ptr_array_unref (countries);
	} else {
		for (guint i = 0; i < l->asns->len; i++) {
			guint32 asn = g_array_index (l->asns, guint32, i);
			gchar *q = g_strdup_printf ("%u", asn);
			GPtrArray *a = fs_intel_geo_search_as (q, 0, NULL);
			gboolean known = FALSE;

			for (guint j = 0; a != NULL && j < a->len && !known; j++)
				known = ((FsGeodbAs *) g_ptr_array_index (a, j))->asn ==
				        asn;
			if (a != NULL && !known)
				g_ptr_array_add (notes, g_strdup_printf (
					"the location database names no AS%u; its networks "
					"may still be listed under that number", asn));
			if (a != NULL)
				g_ptr_array_unref (a);
			g_free (q);
		}
	}
	return notes;
}

static gint
geo_add (gint argc, gchar **argv)
{
	FsIntelLocationKind kind = 0;
	FsIntelDir dir = FS_INTEL_DIR_BOTH;
	const gchar *name = NULL;
	GPtrArray *values = g_ptr_array_new_with_free_func (g_free);
	FsIntelConfig *config = NULL;
	GError *error = NULL;
	gchar *id = NULL, *auto_name = NULL;
	GPtrArray *notes = NULL;
	gint status = FS_EXIT_OK;
	const FsIntelLocationConf *l;

	for (gint i = 0; i < argc; i++) {
		if ((strcmp (argv[i], "--dir") == 0 ||
		     strcmp (argv[i], "--direction") == 0) && i + 1 < argc) {
			if (!parse_dir (argv[++i], &dir))
				goto usage_quiet;
		} else if (strcmp (argv[i], "--name") == 0 && i + 1 < argc) {
			name = argv[++i];
		} else if (argv[i][0] == '-' && argv[i][1] == '-') {
			fs_cli_error ("unknown option for intel geo add: %s", argv[i]);
			fs_cli_hint ("options are --dir in|out|both and --name NAME");
			goto usage_quiet;
		} else if (kind == 0) {
			if (strcmp (argv[i], "country") == 0)
				kind = FS_INTEL_LOCATION_COUNTRY;
			else if (strcmp (argv[i], "asn") == 0 ||
			         strcmp (argv[i], "as") == 0)
				kind = FS_INTEL_LOCATION_ASN;
			else {
				fs_cli_error ("intel geo add takes country or asn first, "
				              "not \"%s\"", argv[i]);
				goto usage;
			}
		} else {
			/* "DE,FR" and "DE FR" alike. */
			gchar **parts = g_strsplit (argv[i], ",", -1);

			for (guint j = 0; parts[j] != NULL; j++) {
				g_strstrip (parts[j]);
				if (*parts[j] != '\0')
					g_ptr_array_add (values, g_strdup (parts[j]));
			}
			g_strfreev (parts);
		}
	}
	if (kind == 0 || values->len == 0) {
		fs_cli_error ("intel geo add needs a kind and at least one value");
		goto usage;
	}
	g_ptr_array_add (values, NULL);
	if (!geo_check_supported (&status))
		goto out;
	/* Never create the store for a rule the consent check refuses:
	 * accepted terms mean a store already exists. */
	config = load_config (FALSE, &error);
	if (config == NULL) {
		status = fail (error, "geo add");
		goto out;
	}
	if (name == NULL)
		name = auto_name = location_default_name (kind,
		                                          (gchar **) values->pdata);
	if (!fs_intel_config_add_location (config, name, kind,
	                                   (const gchar *const *) values->pdata,
	                                   dir, &id, &error)) {
		gboolean consent = g_error_matches (error, FS_INTEL_ERROR,
		                                    FS_INTEL_ERR_CONSENT);

		status = fail (error, "geo add");
		if (consent)
			fs_cli_hint ("read `stockfw intel geo terms', then accept "
			             "them: " FS_CLI_SUDO "stockfw intel geo on "
			             "--accept-terms");
		goto out;
	}
	if (!save_config (config, &status))
		goto out;
	l = fs_intel_config_location (config, id);
	notes = location_unknown_notes (l);
	if (!config->geo_enabled)
		g_ptr_array_add (notes, g_strdup ("the location database is turned "
		                                  "off: this rule is enforced once "
		                                  "`stockfw intel geo on' turns it "
		                                  "on"));
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "id", id);                g_string_append_c (out, ',');
		fs_json_kv_str (out, "name", l->name);         g_string_append_c (out, ',');
		fs_json_kv_str (out, "kind", location_kind_word (kind));
		g_string_append_c (out, ',');
		location_values_json (out, l);                 g_string_append_c (out, ',');
		fs_json_kv_str (out, "direction", dir_word (dir)); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "enabled", TRUE);        g_string_append_c (out, ',');
		fs_json_kv_bool (out, "applied", FALSE);       g_string_append_c (out, ',');
		fs_json_key (out, "notes");
		notes_json (out, notes);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		gchar *v = location_values_text (l);

		printf ("%s+%s %s (%s): %s, %s: %s.\n", fs_cli_green (),
		        fs_cli_reset (), l->name, id, v, dir_word (dir),
		        dir_prose (dir));
		g_free (v);
		notes_print (notes);
		printf ("%sNot live yet: run `" FS_CLI_SUDO "stockfw intel apply'.%s\n",
		        fs_cli_dim (), fs_cli_reset ());
	}
	goto out;

usage:
	fs_cli_hint ("usage: stockfw intel geo add country|asn VALUE... "
	             "[--dir in|out|both] [--name NAME]");
usage_quiet:
	status = FS_EXIT_USAGE;
out:
	if (notes != NULL)
		g_ptr_array_unref (notes);
	g_ptr_array_unref (values);
	g_free (auto_name);
	g_free (id);
	fs_intel_config_free (config);
	return status;
}

static gint
geo_remove (gint argc, gchar **argv)
{
	FsIntelConfig *config;
	GError *error = NULL;
	gchar *label;
	gint status = FS_EXIT_OK;
	FsIntelSourceKind kind;

	if (argc != 1) {
		fs_cli_error ("usage: stockfw intel geo remove ID");
		fs_cli_hint ("`stockfw intel geo list' shows the ids");
		return FS_EXIT_USAGE;
	}
	kind = fs_intel_source_kind (argv[0]);
	if (kind != FS_INTEL_KIND_COUNTRY && kind != FS_INTEL_KIND_ASN) {
		fs_cli_error ("%s is not a country or network rule", argv[0]);
		fs_cli_hint ("`stockfw intel remove ID' removes a local list or "
		             "custom feed");
		return FS_EXIT_USAGE;
	}
	config = load_config (FALSE, &error);
	if (config == NULL)
		return fail (error, "geo remove");
	label = g_strdup (fs_intel_config_label (config, argv[0]));
	if (!fs_intel_config_remove (config, argv[0], &error)) {
		g_free (label);
		fs_intel_config_free (config);
		status = fail (error, "geo remove");
		return status;
	}
	if (!save_config (config, &status)) {
		g_free (label);
		fs_intel_config_free (config);
		return status;
	}
	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "id", argv[0]);    g_string_append_c (out, ',');
		fs_json_kv_bool (out, "removed", TRUE); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "applied", FALSE);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else if (!fs_cli.quiet) {
		printf ("%s-%s %s (%s) removed.\n", fs_cli_red (), fs_cli_reset (),
		        label, argv[0]);
		printf ("%sNot live yet: run `" FS_CLI_SUDO "stockfw intel apply'.%s\n",
		        fs_cli_dim (), fs_cli_reset ());
	}
	g_free (label);
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

static gint
geo_list (gint argc, gchar **argv)
{
	FsIntelConfig *config;
	FsIntelGeoStatus st;
	GError *error = NULL;
	gboolean have;
	FsIntelState state;

	(void) argv;
	if (argc > 0) {
		fs_cli_error ("intel geo list takes no arguments");
		return FS_EXIT_USAGE;
	}
	config = load_config (FALSE, &error);
	if (config == NULL)
		return fail (error, "geo list");
	have = geo_status_read (&st, NULL);
	state = fs_intel_state (fs_backend (), config, NULL);
	if (fs_cli.json) {
		GString *out = g_string_new ("{\"rules\":[");

		for (guint i = 0; i < config->locations->len; i++) {
			if (i > 0)
				g_string_append_c (out, ',');
			location_json (out, config,
			               g_ptr_array_index (config->locations, i),
			               have ? &st : NULL, state);
		}
		g_string_append (out, "]}");
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		geo_print_rules (config, have ? &st : NULL, state);
	}
	if (have)
		fs_intel_geo_status_clear (&st);
	fs_intel_config_free (config);
	return FS_EXIT_OK;
}

static gint
intel_geo (gint argc, gchar **argv)
{
	const gchar *sub = argc > 0 ? argv[0] : "status";
	gint n = argc > 0 ? argc - 1 : 0;
	gchar **rest = argv + 1;

	if (strcmp (sub, "status") == 0)  return geo_status (n, rest);
	if (strcmp (sub, "terms") == 0)   return geo_terms (n, rest);
	if (strcmp (sub, "on") == 0)      return geo_switch (n, rest, TRUE);
	if (strcmp (sub, "off") == 0)     return geo_switch (n, rest, FALSE);
	if (strcmp (sub, "update") == 0)  return geo_update (n, rest);
	if (strcmp (sub, "search") == 0)  return geo_search (n, rest);
	if (strcmp (sub, "add") == 0)     return geo_add (n, rest);
	if (strcmp (sub, "remove") == 0 ||
	    strcmp (sub, "rm") == 0)      return geo_remove (n, rest);
	if (strcmp (sub, "list") == 0 ||
	    strcmp (sub, "rules") == 0)   return geo_list (n, rest);
	fs_cli_error ("unknown intel geo action: %s", sub);
	fs_cli_hint ("see `stockfw help intel'");
	return FS_EXIT_USAGE;
}

/* -------------------------------------------------------------- lookup */

/* Whether the lookup consulted the location database (design 13.8):
 * on, its terms accepted, the master switch on, and the platform. */
static gboolean
lookup_geo_on (const FsIntelConfig *config)
{
	return fs_intel_geo_supported () && config->enabled &&
	       config->geo_enabled && config->geo_accepted_at > 0;
}

/* Why the lookup has no location for the address, when it consulted
 * the database and it found none: the copy is missing, or no network
 * holds the address.  Caller frees. */
static gchar *
lookup_geo_missing (const FsIntelConfig *config, const gchar *addr)
{
	FsGeodbMatch m;
	GError *error = NULL;
	gchar *why;

	if (!fs_intel_geo_lookup (config, addr, &m, &error)) {
		why = g_strdup (error->message);
		g_clear_error (&error);
		return why;
	}
	fs_geodb_match_clear (&m);
	return g_strdup ("the location database has no network for it");
}

/* "Germany (DE)", "DE", or NULL when the network names no country. */
static gchar *
lookup_country_text (const FsIntelLookup *r)
{
	if (r->country[0] == '\0')
		return NULL;
	if (r->country_name != NULL && *r->country_name != '\0')
		return g_strdup_printf ("%s (%s)", r->country_name, r->country);
	return g_strdup (r->country);
}

/* "AS64500 Example One", "AS64500", or NULL. */
static gchar *
lookup_as_text (const FsIntelLookup *r)
{
	if (r->asn == 0)
		return NULL;
	if (r->as_name != NULL && *r->as_name != '\0')
		return g_strdup_printf ("AS%u %s", r->asn, r->as_name);
	return g_strdup_printf ("AS%u", r->asn);
}

static void
lookup_geo_print (const FsIntelConfig *config, const FsIntelLookup *r,
                  const gchar *addr)
{
	gchar *attribution, *c, *a;

	if (!lookup_geo_on (config))
		return;
	if (r->geo_unknown) {
		printf ("  %-14s %sunknown: the location database in use cannot "
		        "be read%s\n", "Registered in", fs_cli_amber (),
		        fs_cli_reset ());
	} else if (!r->geo_found) {
		gchar *why = lookup_geo_missing (config, addr);

		printf ("  %-14s unknown: %s\n", "Registered in", why);
		g_free (why);
		return;
	} else {
		c = lookup_country_text (r);
		a = lookup_as_text (r);
		printf ("  %-14s %s\n", "Registered in",
		        c != NULL ? c : "no country (the database names none)");
		printf ("  %-14s %s%s%s%s\n", "Network",
		        r->network != NULL ? r->network : "?",
		        a != NULL ? ", " : "", a != NULL ? a : "",
		        (r->geo_flags & FS_GEODB_FLAG_ANYCAST)
		        ? ", anycast (answered from many places)" : "");
		if (r->geo_via_nat64)
			printf ("  %-14s a NAT64 address: the country and network "
			        "are those of the IPv4 address it carries\n", "");
		g_free (c);
		g_free (a);
	}
	attribution = fs_intel_geo_attribution ();
	printf ("%s  \"Registered in\" is where the range is registered, not "
	        "where the computer is.\n  %s%s\n", fs_cli_dim (), attribution,
	        fs_cli_reset ());
	g_free (attribution);
}

static void
lookup_geo_json (GString *out, const FsIntelConfig *config,
                 const FsIntelLookup *r, const gchar *addr)
{
	gchar *attribution;

	g_string_append (out, "\"locations\":[");
	for (guint i = 0; i < r->locations->len; i++) {
		const gchar *id = g_ptr_array_index (r->locations, i);

		if (i > 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, '{');
		fs_json_kv_str (out, "id", id);   g_string_append_c (out, ',');
		fs_json_kv_str (out, "name", fs_intel_config_label (config, id));
		g_string_append_c (out, '}');
	}
	g_string_append (out, "],\"locations_unknown\":[");
	for (guint i = 0; i < r->locations_unknown->len; i++) {
		if (i > 0)
			g_string_append_c (out, ',');
		fs_json_string (out, g_ptr_array_index (r->locations_unknown, i));
	}
	g_string_append (out, "],");
	fs_json_key (out, "location");
	if (!lookup_geo_on (config)) {
		g_string_append (out, "null");
		return;
	}
	g_string_append_c (out, '{');
	fs_json_kv_bool (out, "found", r->geo_found);       g_string_append_c (out, ',');
	fs_json_kv_bool (out, "unknown", r->geo_unknown);   g_string_append_c (out, ',');
	if (!r->geo_found && !r->geo_unknown) {
		gchar *why = lookup_geo_missing (config, addr);

		fs_json_kv_str (out, "why_none", why);
		g_string_append_c (out, ',');
		g_free (why);
	}
	fs_json_kv_str (out, "country", r->country[0] ? r->country : NULL);
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "country_name", r->country_name);
	g_string_append_c (out, ',');
	if (r->asn != 0)
		fs_json_kv_uint (out, "asn", r->asn);
	else
		g_string_append (out, "\"asn\":null");
	g_string_append_c (out, ',');
	fs_json_kv_str (out, "as_name", r->as_name);        g_string_append_c (out, ',');
	fs_json_kv_str (out, "network", r->network);        g_string_append_c (out, ',');
	fs_json_kv_bool (out, "anycast",
	                 (r->geo_flags & FS_GEODB_FLAG_ANYCAST) != 0);
	g_string_append_c (out, ',');
	fs_json_kv_uint (out, "flags", r->geo_flags);       g_string_append_c (out, ',');
	fs_json_kv_bool (out, "via_nat64", r->geo_via_nat64); g_string_append_c (out, ',');
	fs_json_kv_str (out, "meaning", "registered in");    g_string_append_c (out, ',');
	attribution = fs_intel_geo_attribution ();
	fs_json_kv_str (out, "attribution", attribution);
	g_free (attribution);
	g_string_append_c (out, '}');
}


static gint
intel_lookup (gint argc, gchar **argv)
{
	FsIntelConfig *config;
	GError *error = NULL;
	FsIntelLookup r = { 0 };
	FsHostNet *host;
	gchar **hosts, *sentence;
	gint status;

	if (argc != 1) {
		fs_cli_error ("usage: stockfw intel lookup ADDRESS");
		return FS_EXIT_USAGE;
	}
	config = load_config (FALSE, &error);
	if (config == NULL)
		return fail (error, "lookup");

	/* What the build would keep reachable, read the same way. */
	hosts = fs_intel_update_hosts (config);
	host = fs_hostnet_read ((const gchar *const *) hosts);
	g_strfreev (hosts);
	if (!fs_intel_lookup (config, host, argv[0], &r)) {
		fs_cli_error ("not a single address: \"%s\"", argv[0]);
		fs_cli_hint ("e.g. 203.0.113.9 or 2001:db8::1");
		fs_intel_lookup_clear (&r);
		fs_hostnet_free (host);
		fs_intel_config_free (config);
		return FS_EXIT_USAGE;
	}
	/* What the kernel does, not just what the configuration asks for
	 * (design 6.6): exit 5 only when the kernel blocks it now. */
	fs_intel_lookup_live (fs_backend (), config, argv[0], &r);
	sentence = fs_intel_lookup_sentence (config, &r);
	status = r.in_force ? FS_EXIT_BLOCKED : FS_EXIT_OK;

	if (fs_cli.json) {
		GString *out = g_string_new ("{");

		fs_json_kv_str (out, "address", argv[0]);       g_string_append_c (out, ',');
		fs_json_kv_bool (out, "blocked", r.blocked);    g_string_append_c (out, ',');
		fs_json_kv_bool (out, "in_force", r.in_force);  g_string_append_c (out, ',');
		fs_json_kv_bool (out, "pending", r.pending);    g_string_append_c (out, ',');
		fs_json_kv_bool (out, "uncertain", r.uncertain && !r.in_force);
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "state", fs_intel_state_to_string (r.state));
		g_string_append_c (out, ',');
		fs_json_kv_str (out, "state_detail", r.state_detail);
		g_string_append_c (out, ',');
		g_string_append (out, "\"in_force_lists\":[");
		for (guint i = 0; i < r.kernel_sources->len; i++) {
			if (i > 0)
				g_string_append_c (out, ',');
			fs_json_string (out, g_ptr_array_index (r.kernel_sources, i));
		}
		g_string_append (out, "],");
		fs_json_kv_str (out, "direction",
		                r.dir != 0 ? dir_word (r.dir) : NULL);
		g_string_append_c (out, ',');
		fs_json_kv_bool (out, "protected", r.is_protected); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "exception", r.is_exception); g_string_append_c (out, ',');
		fs_json_kv_bool (out, "kept_reachable", r.is_host); g_string_append_c (out, ',');
		fs_json_kv_str (out, "sentence", sentence);         g_string_append_c (out, ',');
		g_string_append (out, "\"lists\":[");
		for (guint i = 0; i < r.sources->len; i++) {
			const gchar *id = g_ptr_array_index (r.sources, i);

			if (i > 0)
				g_string_append_c (out, ',');
			g_string_append_c (out, '{');
			fs_json_kv_str (out, "id", id);   g_string_append_c (out, ',');
			fs_json_kv_str (out, "name", fs_intel_config_label (config, id));
			g_string_append_c (out, '}');
		}
		g_string_append (out, "],");
		lookup_geo_json (out, config, &r, argv[0]);
		g_string_append_c (out, '}');
		fs_cli_print_json (out);
		g_string_free (out, TRUE);
	} else {
		if (r.blocked && r.in_force)
			printf ("%sBLOCKED%s  %s (%s: %s)\n", fs_cli_red (),
			        fs_cli_reset (), sentence, dir_word (r.dir),
			        dir_prose (r.dir));
		else if (r.in_force) {
			/* The kernel still blocks what the configuration no
			 * longer does: an exception or a change not applied. */
			GString *names = g_string_new (NULL);

			for (guint i = 0; i < r.kernel_sources->len; i++) {
				const gchar *id = g_ptr_array_index (r.kernel_sources, i);
				const gchar *l = fs_intel_config_label (config, id);

				g_string_append_printf (names, "%s%s", i ? ", " : "",
				                        l != NULL ? l : id);
			}
			printf ("%sBLOCKED%s  " FS_CLI_LIVE " still blocks %s (%s): the "
			        "change that lets it through is not applied yet; "
			        "`" FS_CLI_SUDO "stockfw intel apply' puts it in force.\n",
			        fs_cli_red (), fs_cli_reset (), argv[0], names->str);
			g_string_free (names, TRUE);
		} else if (r.blocked && r.uncertain) {
			printf ("%sMAYBE BLOCKED%s  %s (%s), but a list changed "
			        "since the last apply, so whether " FS_CLI_LIVE " blocks "
			        "it now cannot be told; `" FS_CLI_SUDO "stockfw intel apply' "
			        "puts the new copy in force.\n", fs_cli_amber (),
			        fs_cli_reset (), sentence, dir_word (r.dir));
		} else if (r.blocked) {
			const gchar *why =
				r.state == FS_INTEL_STATE_ENFORCED
				? "the lists have changes that are not applied yet; "
				  "`" FS_CLI_SUDO "stockfw intel apply' puts them in force"
				: r.state_detail != NULL ? r.state_detail
				: "the lists are not in force";

			printf ("%sLISTED, NOT BLOCKED NOW%s  %s once in force "
			        "(%s), but " FS_CLI_LIVE " does not block it: %s "
			        "(threat intel %s).\n", fs_cli_amber (),
			        fs_cli_reset (), sentence, dir_word (r.dir), why,
			        fs_intel_state_to_string (r.state));
		} else if (r.locations_unknown->len > 0 && !r.blocked) {
			/* Review GEO-1: never "not listed" for what cannot be
			 * read. */
			printf ("%sMAYBE BLOCKED%s  %s\n", fs_cli_amber (),
			        fs_cli_reset (), sentence);
		} else if (r.sources->len == 0 && r.locations->len == 0)
			printf ("%sNOT LISTED%s  no list or country or network rule "
			        "that is turned on holds %s.\n",
			        fs_cli_green (), fs_cli_reset (), argv[0]);
		else {
			GString *names = g_string_new (NULL);
			const gchar *why = r.is_exception
				? "it is an exception"
				: r.is_protected
				? "it is in a range that is never blocked"
				: "it is kept reachable (this computer's own network, "
				  "a gateway, a DNS server, an SSH session or a "
				  "download server)";

			for (guint i = 0; i < r.sources->len; i++) {
				const gchar *id = g_ptr_array_index (r.sources, i);

				g_string_append_printf (names, "%s%s", i ? ", " : "",
				                        fs_intel_config_label (config, id));
			}
			for (guint i = 0; i < r.locations->len; i++) {
				const gchar *id = g_ptr_array_index (r.locations, i);

				g_string_append_printf (names, "%s%s",
				                        names->len ? ", " : "",
				                        fs_intel_config_label (config, id));
			}
			printf ("%sLISTED, NOT BLOCKED%s  %s holds %s, but %s.\n",
			        fs_cli_amber (), fs_cli_reset (), names->str, argv[0],
			        why);
			g_string_free (names, TRUE);
		}
		lookup_geo_print (config, &r, argv[0]);
		if (r.blocked || r.in_force)
			printf ("%sA mistake?  `" FS_CLI_SUDO "stockfw intel except %s' lets it "
			        "through.%s\n", fs_cli_dim (), argv[0], fs_cli_reset ());
	}

	g_free (sentence);
	fs_intel_lookup_clear (&r);
	fs_hostnet_free (host);
	fs_intel_config_free (config);
	return status;
}

/* ------------------------------------------------------------ dispatch */

gint
fs_cli_cmd_intel (gint argc, gchar **argv)
{
	const gchar *sub = argc > 1 ? argv[1] : "status";
	gint n = argc > 1 ? argc - 2 : 0;
	gchar **rest = argv + 2;

	if (strcmp (sub, "status") == 0)          return intel_status (n, rest);
	if (strcmp (sub, "feeds") == 0)           return intel_feeds (n, rest);
	if (strcmp (sub, "terms") == 0)           return intel_terms (n, rest);
	if (strcmp (sub, "enable") == 0)          return intel_enable (n, rest, TRUE);
	if (strcmp (sub, "disable") == 0)         return intel_enable (n, rest, FALSE);
	if (strcmp (sub, "on") == 0)              return intel_switch (n, TRUE);
	if (strcmp (sub, "off") == 0)             return intel_switch (n, FALSE);
	if (strcmp (sub, "add-feed") == 0)        return intel_add_feed (n, rest);
	if (strcmp (sub, "proxy") == 0)           return intel_proxy (n, rest);
	if (strcmp (sub, "update") == 0)          return intel_update (n, rest);
	if (strcmp (sub, "apply") == 0)           return intel_apply (n, rest);
	if (strcmp (sub, "clear") == 0)           return intel_clear (n, rest);
	if (strcmp (sub, "import") == 0)          return intel_import (n, rest);
	if (strcmp (sub, "remove") == 0 ||
	    strcmp (sub, "rm") == 0)              return intel_remove (n, rest);
	if (strcmp (sub, "lists") == 0)           return intel_lists (n, rest);
	if (strcmp (sub, "list") == 0)            return intel_list (n, rest);
	if (strcmp (sub, "except") == 0)          return intel_except (n, rest, TRUE);
	if (strcmp (sub, "unexcept") == 0)        return intel_except (n, rest, FALSE);
	if (strcmp (sub, "exceptions") == 0)      return intel_exceptions (n, rest);
	if (strcmp (sub, "lookup") == 0)          return intel_lookup (n, rest);
	if (strcmp (sub, "geo") == 0)             return intel_geo (n, rest);

	fs_cli_error ("unknown intel action: %s", sub);
	fs_cli_hint ("see `stockfw help intel'");
	return FS_EXIT_USAGE;
}
