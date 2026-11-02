/*---[ fs-intelview.c ]--------------------------------------------------
 * The Threat Intel page (1.0.7, design section 8).
 *
 * Top to bottom:
 *   header     "Threat Intel", one line on what it is, Update now
 *   state      one coloured card: what the kernel is doing (never just
 *              the configuration: design 6.6), the master switch,
 *              Apply when the lists are not in force, four facts, and
 *              the progress of whatever is running
 *   feeds      one row per catalog or custom feed: name, what it
 *              blocks, licence and credit links, entries, last and next
 *              update, status (a refused update offers "Accept smaller
 *              list" or "Accept larger list"), blocked count, switch
 *   your lists the allow list (exceptions), your own blocklist, and
 *              imported list files
 *   lookup     "Is 203.0.113.7 on a list?"
 *   notes      what the last build kept reachable or left out
 *
 * Threading.  Every job (refresh, update, apply, a switch, a save, a
 * lookup) runs in a GTask worker under one lock, so jobs never overlap
 * and the window never waits on curl or nft.  A job loads the config
 * from the store, changes it, saves it, applies when the firewall is
 * running, and ends with a fresh snapshot that the main thread shows.
 * The main thread never holds engine state other than that snapshot.
 *--------------------------------------------------------------------*/

#include "ui/fs-intelview.h"
#include "ui/fs-icons.h"
#include "core/fs-apply.h"
#include "core/fs-feed.h"
#include "core/fs-hostnet.h"
#include "core/fs-intel.h"
#include "core/fs-iprange.h"
#include "core/fs-i18n.h"

#include <glib/gstdio.h>
#include <string.h>
#ifdef G_OS_UNIX
#include <unistd.h>
#endif

/* The page's own classes, on top of fs-theme.css (cards, hero, tiles,
 * switches and buttons come from there).  Installed once, for the
 * screen, so the page needs no edit to the shared stylesheet. */
static const gchar intel_css[] =
	".intel-body { padding: 0 0 6px 0; }\n"
	".intel-pad { padding: 4px 16px 12px 16px; }\n"
	".intel-row { padding: 14px 16px; }\n"
	".intel-subhead { padding: 10px 16px 4px 16px;"
	" border-top: 1px solid #eef0f3; }\n"
	".intel-lists { padding: 0 0 6px 0; }\n"
	".intel-meta { color: #5b6472; font-size: 12px; }\n"
	".intel-status { font-size: 12px; font-weight: 600; }\n"
	".intel-ok { color: #1e7f4f; }\n"
	".intel-warn { color: #8a5300; }\n"
	".intel-bad { color: #b42318; }\n"
	".intel-chip { font-size: 11px; color: #3a4250;"
	" background-color: #eef2f7; border-radius: 9px;"
	" padding: 1px 8px; }\n"
	".intel-chip-good { color: #145a38; background-color: #ddf2e6; }\n"
	".intel-message { font-size: 13px; color: #3a4250; }\n"
	".intel-message.intel-error { color: #b42318; }\n"
	".intel-lookup-result { font-size: 13px; color: #16181d; }\n"
	".intel-lookup-result.intel-hit { color: #b42318;"
	" font-weight: bold; }\n"
	".intel-editor, .intel-editor text { font-size: 12px;"
	" background-color: #ffffff; color: #16181d; }\n"
	".intel-editor-frame { border: 1px solid #cdd2da;"
	" border-radius: 8px; }\n"
	".intel-page progressbar trough { min-height: 6px;"
	" border-radius: 3px; background-color: #e3e6eb; }\n"
	".intel-page progressbar progress { min-height: 6px;"
	" border-radius: 3px; background-color: #16181d; }\n";

static void
install_css (void)
{
	static gboolean done = FALSE;
	GtkCssProvider *provider;
	GdkScreen *screen = gdk_screen_get_default ();

	if (done || screen == NULL)
		return;
	done = TRUE;
	provider = gtk_css_provider_new ();
	if (gtk_css_provider_load_from_data (provider, intel_css, -1, NULL))
		gtk_style_context_add_provider_for_screen (
			screen, GTK_STYLE_PROVIDER (provider),
			GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 1);
	g_object_unref (provider);
}

#define DOT " \xc2\xb7 "       /* " . " middle dot */
#define ELLIPSIS "\xe2\x80\xa6"

/* The local list the "Your blocklist" editor writes. */
#define DENY_NAME N_("My blocklist")
#define DENY_ID   "local-my-blocklist"

/* Unattended update check (design 6.7), and the counters' refresh
 * while the page is on screen. */
#define SCHEDULE_S  3600
#define COUNTERS_S  30

/* ------------------------------------------------------------ snapshot */

typedef struct
{
	FsIntelState   state;
	gchar         *detail;
	FsIntelConfig *config;       /* never NULL                          */
	gchar         *config_error; /* the store could not be read         */
	gboolean       store;        /* the store directory exists          */
	gboolean       supported;    /* the backend has the intel slots     */
	gboolean       needs_root;
	gboolean       fw_running;
	GHashTable    *sources;      /* id -> FsIntelSourceState*           */
	GHashTable    *counters;     /* id -> FsIntelCounter*               */
	GHashTable    *in_force;     /* ids in the applied rule set         */
	gchar         *exceptions;   /* text form                           */
	gchar         *deny;         /* the "My blocklist" text form        */
	gint64         now;
} Snapshot;

static void
snapshot_free (Snapshot *s)
{
	if (s == NULL)
		return;
	g_free (s->detail);
	fs_intel_config_free (s->config);
	g_free (s->config_error);
	g_clear_pointer (&s->sources, g_hash_table_unref);
	g_clear_pointer (&s->counters, g_hash_table_unref);
	g_clear_pointer (&s->in_force, g_hash_table_unref);
	g_free (s->exceptions);
	g_free (s->deny);
	g_free (s);
}

/* ---------------------------------------------------------------- jobs */

typedef enum
{
	JOB_REFRESH = 0,
	JOB_UPDATE,          /* Update now: every enabled feed, then apply   */
	JOB_SCHEDULED,       /* the hourly check: due feeds, apply if in force */
	JOB_ACCEPT,          /* one feed with an override flag, then apply   */
	JOB_FEED,            /* a feed's switch                              */
	JOB_LIST,            /* an imported list's switch                    */
	JOB_MASTER,          /* the master switch                            */
	JOB_EXCEPTIONS,      /* save the allow list                          */
	JOB_ADD_EXCEPTION,   /* one address from the Events page             */
	JOB_DENY,            /* save "My blocklist"                          */
	JOB_IMPORT,          /* a list file                                  */
	JOB_REMOVE,          /* a list or custom feed                        */
	JOB_APPLY,
	JOB_LOOKUP
} JobKind;

typedef struct
{
	JobKind          kind;
	const FsBackend *backend;
	gchar           *id;
	gboolean         on;
	gboolean         accept_terms;
	guint            flags;
	gchar           *text;
	gchar           *name;
	gchar           *hold;       /* computed on the main thread       */
	GtkWindow       *report_to;  /* show the outcome in a dialog      */

	/* results */
	Snapshot        *snap;
	gchar           *message;
	gboolean         failed;
	gboolean         warned;     /* done, but something was left out  */
	GPtrArray       *notes;      /* gchar*; NULL: keep the last ones  */
	gchar           *lookup;
	gboolean         lookup_blocked;
} Job;

static void
job_free (gpointer data)
{
	Job *job = data;

	g_free (job->id);
	g_free (job->text);
	g_free (job->name);
	g_free (job->hold);
	if (job->report_to != NULL)
		g_object_unref (job->report_to);
	snapshot_free (job->snap);
	g_free (job->message);
	if (job->notes != NULL)
		g_ptr_array_unref (job->notes);
	g_free (job->lookup);
	g_free (job);
}

/* -------------------------------------------------------------- statics */

static const FsBackend *test_backend = NULL;
static FsIntelHoldFunc  hold_func = NULL;
static FsIntelResponder responder = NULL;
static gpointer         responder_data = NULL;
static gchar           *import_path = NULL;

static GMutex engine_lock;
static guint  jobs_pending = 0;

/* Widgets. */
static GtkWidget *page_root = NULL;
static GtkWidget *update_button, *hero, *hero_icon, *hero_title, *hero_body;
static GtkWidget *hero_note, *master_switch, *master_row, *apply_button;
static GtkWidget *tile_value[4];
static GtkWidget *progress_row, *progress_label, *progress_bar, *spinner;
static GtkWidget *message_label;
static GtkWidget *feeds_box, *lists_box;
static GtkWidget *allow_view, *deny_view, *allow_save, *deny_save;
static GtkWidget *import_button;
static GtkWidget *lookup_entry, *lookup_button, *lookup_result;
static GtkWidget *notes_card, *notes_label;
static GtkWidget *edit_cards[2];

static Snapshot *shown = NULL;     /* the snapshot on screen           */
static gboolean  syncing = FALSE;  /* switches set from a snapshot     */
static guint     pulse_id = 0;

/* ---------------------------------------------------------------- utils */

static const FsBackend *
backend (void)
{
	return test_backend != NULL ? test_backend : fs_backend ();
}

/* A signal's g_strdup'ed user data, freed with the handler. */
static void
free_closure_data (gpointer data, GClosure *closure)
{
	(void) closure;
	g_free (data);
}

static void
add_class (GtkWidget *widget, const gchar *klass)
{
	gtk_style_context_add_class (gtk_widget_get_style_context (widget),
	                             klass);
}

static void
remove_class (GtkWidget *widget, const gchar *klass)
{
	gtk_style_context_remove_class (gtk_widget_get_style_context (widget),
	                                klass);
}

static GtkWidget *
label_new (const gchar *text, const gchar *klass, gfloat xalign)
{
	GtkWidget *label = gtk_label_new (text);

	gtk_label_set_xalign (GTK_LABEL (label), xalign);
	if (klass != NULL)
		add_class (label, klass);
	return label;
}

static GtkWidget *
wrap_label (const gchar *text, const gchar *klass)
{
	GtkWidget *label = label_new (text, klass, 0.0);

	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	gtk_label_set_line_wrap_mode (GTK_LABEL (label), PANGO_WRAP_WORD_CHAR);
	return label;
}

static gchar *
grouped (guint64 n)
{
	gchar *digits = g_strdup_printf ("%" G_GUINT64_FORMAT, n);
	GString *out = g_string_new (NULL);
	gsize len = strlen (digits);

	for (gsize i = 0; i < len; i++) {
		if (i > 0 && (len - i) % 3 == 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, digits[i]);
	}
	g_free (digits);
	return g_string_free (out, FALSE);
}

/* "just now", "12 min ago", "5 h ago", "3 days ago". */
static gchar *
ago_text (gint64 now, gint64 then)
{
	gint64 d = now - then;

	if (d < 60)
		return g_strdup (_("just now"));
	if (d < 3600)
		return g_strdup_printf (_("%d min ago"), (gint) (d / 60));
	if (d < 86400)
		return g_strdup_printf (_("%d h ago"), (gint) (d / 3600));
	return g_strdup_printf (g_dngettext (NULL, "%d day ago",
	                                     "%d days ago",
	                                     (gulong) (d / 86400)),
	                        (gint) (d / 86400));
}

/* "due now", "in 40 min", "in 9 h", "in 2 days". */
static gchar *
in_text (gint64 now, gint64 when)
{
	gint64 d = when - now;

	if (d <= 0)
		return g_strdup (_("due now"));
	if (d < 3600)
		return g_strdup_printf (_("in %d min"), (gint) MAX (1, d / 60));
	/* Rounded, so a 24 h interval read a few seconds later is still
	 * "in 24 h". */
	if (d < 2 * 86400)
		return g_strdup_printf (_("in %d h"), (gint) ((d + 1800) / 3600));
	return g_strdup_printf (g_dngettext (NULL, "in %d day", "in %d days",
	                                     (gulong) (d / 86400)),
	                        (gint) (d / 86400));
}

static gchar *
date_text (gint64 t)
{
	GDateTime *dt = g_date_time_new_from_unix_local (t);
	gchar *out;

	if (dt == NULL)
		return g_strdup ("?");
	out = g_date_time_format (dt, "%-d %b %Y");
	g_date_time_unref (dt);
	return out;
}

/* "(both ways)" in the lookup's answer and the list rows' facts. */
static const gchar *
dir_words (FsIntelDir dir)
{
	switch (dir) {
	case FS_INTEL_DIR_IN:   return _("only when they connect to you");
	case FS_INTEL_DIR_OUT:  return _("only when you connect to them");
	case FS_INTEL_DIR_BOTH: return _("both ways");
	}
	return "";
}

/* What a feed row says it blocks, after its description. */
static const gchar *
dir_sentence (FsIntelDir dir)
{
	switch (dir) {
	case FS_INTEL_DIR_IN:
		return _("Stops them connecting to you.");
	case FS_INTEL_DIR_OUT:
		return _("Stops you connecting to them.");
	case FS_INTEL_DIR_BOTH:
		return _("Blocks traffic with them both ways.");
	}
	return "";
}

/* The display name of a source: catalog names are translated. */
static const gchar *
source_name (const FsIntelConfig *config, const gchar *id)
{
	const FsFeedInfo *fi = fs_feed_catalog_find (id);
	const gchar *label;

	if (fi != NULL)
		return _(fi->name);
	label = fs_intel_config_label (config, id);
	return label != NULL ? label : id;
}

static gint64
interval_s (const FsIntelFeedConf *f)
{
	const FsFeedInfo *fi = f->custom ? NULL : fs_feed_catalog_find (f->id);

	return (gint64) (fi != NULL ? fi->interval_hours : 24) * 3600;
}

static gint
run_dialog (GtkDialog *dialog)
{
	if (responder != NULL)
		return responder (dialog, responder_data);
	return gtk_dialog_run (dialog);
}

static GtkWindow *
toplevel (void)
{
	GtkWidget *top = page_root != NULL ? gtk_widget_get_toplevel (page_root)
	                                   : NULL;

	return top != NULL && GTK_IS_WINDOW (top) &&
	       gtk_widget_is_toplevel (top) ? GTK_WINDOW (top) : NULL;
}

/* A plain message dialog; `secondary' may be NULL. */
static void
tell_user (GtkWindow *parent, GtkMessageType type, const gchar *primary,
      const gchar *secondary)
{
	GtkWidget *dialog = gtk_message_dialog_new (parent, GTK_DIALOG_MODAL,
	                                            type, GTK_BUTTONS_OK,
	                                            "%s", primary);

	if (secondary != NULL)
		gtk_message_dialog_format_secondary_text (
			GTK_MESSAGE_DIALOG (dialog), "%s", secondary);
	gtk_widget_set_name (dialog, "intel-result-dialog");
	run_dialog (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
}

/* ------------------------------------------------------------ progress */

typedef struct
{
	gchar  *text;
	gdouble fraction;     /* < 0: pulse                               */
} Progress;

static gboolean
pulse_tick (gpointer data)
{
	(void) data;
	if (progress_bar != NULL)
		gtk_progress_bar_pulse (GTK_PROGRESS_BAR (progress_bar));
	return G_SOURCE_CONTINUE;
}

static gboolean
progress_show (gpointer data)
{
	Progress *p = data;

	if (progress_row != NULL && jobs_pending > 0) {
		gtk_label_set_text (GTK_LABEL (progress_label), p->text);
		if (p->fraction < 0) {
			if (pulse_id == 0)
				pulse_id = g_timeout_add (120, pulse_tick, NULL);
		} else {
			if (pulse_id != 0) {
				g_source_remove (pulse_id);
				pulse_id = 0;
			}
			gtk_progress_bar_set_fraction (
				GTK_PROGRESS_BAR (progress_bar), p->fraction);
		}
		gtk_widget_show (progress_row);
	}
	return G_SOURCE_REMOVE;
}

static void
progress_free (gpointer data)
{
	Progress *p = data;

	g_free (p->text);
	g_free (p);
}

/* From the worker: put a line and a fraction on the page. */
static void
progress (const gchar *text, gdouble fraction)
{
	Progress *p = g_new0 (Progress, 1);

	p->text = g_strdup (text);
	p->fraction = fraction;
	g_main_context_invoke_full (NULL, G_PRIORITY_DEFAULT, progress_show, p,
	                            progress_free);
}

/* -------------------------------------------------------------- worker */

static gboolean
firewall_running (const FsBackend *b)
{
	FsFirewallState st;

	if (b->get_state == NULL)
		return FALSE;
	st = b->get_state ();
	return st == FS_FW_RUNNING || st == FS_FW_LOCKED || st == FS_FW_HIT;
}

static gboolean
is_root (void)
{
#ifdef G_OS_UNIX
	return geteuid () == 0;
#else
	return FALSE;
#endif
}

static Snapshot *
take_snapshot (const FsBackend *b)
{
	Snapshot *s = g_new0 (Snapshot, 1);
	GError *error = NULL;

	s->now = g_get_real_time () / G_USEC_PER_SEC;
	s->supported = b->intel_apply != NULL && b->intel_live != NULL;
	s->store = fs_intel_store_exists ();
	s->sources = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
		(GDestroyNotify) fs_intel_source_state_free);
	s->in_force = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
	                                     NULL);
	s->fw_running = s->supported && firewall_running (b);

	if (!s->supported) {
		s->state = FS_INTEL_STATE_UNSUPPORTED;
		s->config = fs_intel_config_new ();
		s->counters = g_hash_table_new (g_str_hash, g_str_equal);
		return s;
	}

	/* No store: no list was ever turned on.  Opening the page must not
	 * create one (Stop and Start then do nothing, design 6.5). */
	if (!s->store) {
		s->config = fs_intel_config_new ();
		s->counters = g_hash_table_new (g_str_hash, g_str_equal);
		if (!is_root () && g_getenv ("STOCKFW_INTEL_DIR") == NULL) {
			s->state = FS_INTEL_STATE_NEEDS_ROOT;
			s->needs_root = TRUE;
			s->detail = g_strdup (_("Changing the blocklists needs "
			                        "administrator rights."));
		} else {
			s->state = FS_INTEL_STATE_OFF;
			s->detail = g_strdup (_("No blocklist is turned on."));
		}
		s->exceptions = g_strdup ("");
		s->deny = g_strdup ("");
		return s;
	}

	s->config = fs_intel_config_load (&error);
	if (s->config == NULL) {
		s->needs_root = g_error_matches (error, FS_INTEL_ERROR,
		                                 FS_INTEL_ERR_NEEDS_ROOT);
		s->config_error = g_strdup (error->message);
		g_clear_error (&error);
		s->config = fs_intel_config_new ();
		s->state = s->needs_root ? FS_INTEL_STATE_NEEDS_ROOT
		                         : FS_INTEL_STATE_UNKNOWN;
		s->detail = g_strdup (s->config_error);
		s->counters = g_hash_table_new (g_str_hash, g_str_equal);
		s->exceptions = g_strdup ("");
		s->deny = g_strdup ("");
		return s;
	}

	s->state = fs_intel_state (b, s->config, &s->detail);
	if (s->state == FS_INTEL_STATE_NEEDS_ROOT)
		s->needs_root = TRUE;
	s->counters = fs_intel_counters (b);

	for (guint i = 0; i < s->config->feeds->len; i++) {
		FsIntelFeedConf *f = g_ptr_array_index (s->config->feeds, i);
		FsIntelSourceState *st = fs_intel_source_state (f->id);

		if (st != NULL)
			g_hash_table_replace (s->sources, g_strdup (f->id), st);
		if (fs_intel_applied_has (f->id))
			g_hash_table_add (s->in_force, g_strdup (f->id));
	}
	for (guint i = 0; i < s->config->lists->len; i++) {
		FsIntelListConf *l = g_ptr_array_index (s->config->lists, i);
		FsIntelSourceState *st = fs_intel_source_state (l->id);

		if (st != NULL)
			g_hash_table_replace (s->sources, g_strdup (l->id), st);
		if (fs_intel_applied_has (l->id))
			g_hash_table_add (s->in_force, g_strdup (l->id));
	}

	s->exceptions = fs_range_set_to_text (s->config->exceptions);
	if (fs_intel_config_list (s->config, DENY_ID) != NULL) {
		FsRangeSet *set = fs_intel_source_load (DENY_ID, NULL);

		s->deny = set != NULL ? fs_range_set_to_text (set) : g_strdup ("");
		fs_range_set_free (set);
	} else {
		s->deny = g_strdup ("");
	}
	return s;
}

/* Each line cut at its first '#': a trailing comment, as the
 * blocklist's CSV reader allows.  Caller frees. */
static gchar *
strip_comments (const gchar *text)
{
	gchar **lines = g_strsplit (text != NULL ? text : "", "\n", -1);
	gchar *out;

	for (guint i = 0; lines[i] != NULL; i++) {
		gchar *hash = strchr (lines[i], '#');

		if (hash != NULL)
			*hash = '\0';
	}
	out = g_strjoinv ("\n", lines);
	g_strfreev (lines);
	return out;
}

/* Append a sentence to the job's message. */
static void
say (Job *job, const gchar *text)
{
	gchar *old = job->message;

	if (old != NULL && *old != '\0') {
		gsize n = strlen (old);
		gboolean stop = old[n - 1] == '.' || old[n - 1] == '!' ||
		                old[n - 1] == '?';

		job->message = g_strconcat (old, stop ? " " : ". ", text, NULL);
	} else {
		job->message = g_strdup (text);
	}
	g_free (old);
}

static void
fail (Job *job, const gchar *text)
{
	job->failed = TRUE;
	say (job, text);
}

/* Put the config in force when the firewall runs; otherwise say when
 * it will be.  `unattended': the hourly check, which re-applies only a
 * table that is enforced or differs (design 6.5). */
static void
apply_now (Job *job, const FsIntelConfig *config, gboolean unattended)
{
	const FsBackend *b = job->backend;
	FsIntelOutcome *o;
	GError *error = NULL;

	if (b->intel_apply == NULL)
		return;
	if (!firewall_running (b)) {
		say (job, _("Saved. The lists are put in force when the "
		            "firewall starts."));
		return;
	}
	if (unattended) {
		FsIntelState st = fs_intel_state (b, config, NULL);

		if (job->hold != NULL ||
		    (st != FS_INTEL_STATE_ENFORCED && st != FS_INTEL_STATE_DIFFERS))
			return;
	}

	progress (_("Putting the lists in force" ELLIPSIS), -1);
	o = fs_intel_apply_safe (b, config, NULL, "threat intel page",
	                         job->hold, &error);
	if (o == NULL) {
		gchar *t = g_strdup_printf (_("The lists were not put in force: "
		                              "%s"), error->message);

		fail (job, t);
		g_free (t);
		g_clear_error (&error);
		return;
	}
	if (job->notes != NULL)
		g_ptr_array_unref (job->notes);
	job->notes = g_ptr_array_ref (o->notes);

	if (o->result == FS_APPLY_DRY_RUN) {
		gchar *t = g_strdup_printf (_("Saved, but not put in force: %s"),
		                            o->hold_reason != NULL
		                            ? o->hold_reason : job->hold);

		say (job, t);
		g_free (t);
	} else if (o->result == FS_APPLY_OK) {
		say (job, o->sets == 0 ? _("No list is in force now.")
		                       : _("The lists are in force."));
	} else {
		gchar *t = g_strdup_printf (_("The lists were not put in force: "
		                              "%s"),
		                            error != NULL ? error->message
		                                          : _("the apply failed"));

		fail (job, t);
		g_free (t);
	}
	g_clear_error (&error);
	fs_intel_outcome_free (o);
}

static FsIntelConfig *
load_config (Job *job)
{
	GError *error = NULL;
	FsIntelConfig *config = fs_intel_config_load (&error);

	if (config == NULL) {
		fail (job, error->message);
		g_clear_error (&error);
	}
	return config;
}

static gboolean
save_config (Job *job, const FsIntelConfig *config)
{
	GError *error = NULL;

	if (fs_intel_config_save (config, &error))
		return TRUE;
	fail (job, error->message);
	g_clear_error (&error);
	return FALSE;
}

/* Download one feed, saying how it went.  Returns TRUE when a copy is
 * stored afterwards (new or kept). */
static gboolean
update_feed (Job *job, const FsIntelConfig *config, const gchar *id,
             guint flags, guint index, guint count)
{
	GPtrArray *results;
	gchar *line;
	gboolean stored = FALSE;

	line = count > 1
	       ? g_strdup_printf (_("Downloading %s (%u of %u)" ELLIPSIS),
	                          source_name (config, id), index + 1, count)
	       : g_strdup_printf (_("Downloading %s" ELLIPSIS),
	                          source_name (config, id));
	progress (line, count > 1 ? (gdouble) index / count : -1);
	g_free (line);

	results = fs_intel_update (config, id, flags,
	                           g_get_real_time () / G_USEC_PER_SEC);
	for (guint i = 0; i < results->len; i++) {
		FsIntelUpdateResult *r = g_ptr_array_index (results, i);
		gchar *t = g_strdup_printf ("%s: %s", source_name (config, r->id),
		                            r->message);

		if (r->outcome == FS_INTEL_FAILED ||
		    r->outcome == FS_INTEL_REFUSED ||
		    r->outcome == FS_INTEL_NEEDS_CONSENT)
			fail (job, t);
		else if (r->outcome != FS_INTEL_NOT_DUE)
			say (job, t);
		g_free (t);
	}
	g_ptr_array_unref (results);
	{
		FsIntelSourceState *st = fs_intel_source_state (id);

		stored = st != NULL && st->fetched_at > 0;
		fs_intel_source_state_free (st);
	}
	return stored;
}

static void
job_update_all (Job *job, gboolean scheduled)
{
	FsIntelConfig *config = load_config (job);
	GPtrArray *ids;
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;

	if (config == NULL)
		return;
	ids = g_ptr_array_new ();
	for (guint i = 0; i < config->feeds->len; i++) {
		FsIntelFeedConf *f = g_ptr_array_index (config->feeds, i);

		if (!f->enabled || !config->enabled)
			continue;
		if (scheduled && !fs_intel_source_is_due (config, f->id, now))
			continue;
		g_ptr_array_add (ids, f->id);
	}
	if (ids->len == 0 && !scheduled)
		say (job, config->enabled ? _("No feed is turned on.")
		                          : _("Threat intel is switched off."));
	for (guint i = 0; i < ids->len; i++)
		update_feed (job, config, g_ptr_array_index (ids, i),
		             scheduled ? 0 : FS_INTEL_UPDATE_NOW, i, ids->len);
	if (ids->len > 0 || !scheduled)
		apply_now (job, config, scheduled);
	g_ptr_array_unref (ids);
	fs_intel_config_free (config);
}

static void
job_feed (Job *job)
{
	FsIntelConfig *config = load_config (job);
	GError *error = NULL;
	gboolean ok;

	if (config == NULL)
		return;
	ok = job->on
	     ? fs_intel_config_enable_feed (config, job->id, 0,
	                                    job->accept_terms, &error)
	     : fs_intel_config_disable_feed (config, job->id, &error);
	if (!ok) {
		fail (job, error->message);
		g_clear_error (&error);
		fs_intel_config_free (config);
		return;
	}
	if (!save_config (job, config)) {
		fs_intel_config_free (config);
		return;
	}
	if (job->on) {
		FsIntelSourceState *st = fs_intel_source_state (job->id);
		gboolean have = st != NULL && st->fetched_at > 0;

		fs_intel_source_state_free (st);
		/* A list never downloaded is fetched now, so turning it on
		 * blocks something. */
		if (!have && config->enabled)
			update_feed (job, config, job->id, FS_INTEL_UPDATE_NOW,
			             0, 1);
	}
	apply_now (job, config, FALSE);
	fs_intel_config_free (config);
}

static void
job_simple (Job *job)
{
	FsIntelConfig *config = load_config (job);
	GError *error = NULL;
	gboolean ok = TRUE;

	if (config == NULL)
		return;

	switch (job->kind) {
	case JOB_LIST:
		ok = fs_intel_config_set_enabled (config, job->id, job->on,
		                                  &error);
		break;
	case JOB_MASTER:
		config->enabled = job->on;
		break;
	case JOB_REMOVE:
		ok = fs_intel_config_remove (config, job->id, &error);
		break;
	case JOB_EXCEPTIONS: {
		/* "203.0.113.6 # mail" is accepted here as it is in your
		 * blocklist: the comment is cut, never kept. */
		gchar *bare = strip_comments (job->text);
		FsRangeSet *set = fs_range_set_from_text (bare, &error);

		g_free (bare);

		ok = set != NULL;
		if (ok) {
			fs_range_set_free (config->exceptions);
			config->exceptions = set;
		}
		break;
	}
	case JOB_ADD_EXCEPTION: {
		FsRangeSet *one = fs_range_set_new ();

		ok = fs_range_set_add_text (one, job->text);
		if (ok) {
			fs_range_set_normalize (one);
			fs_range_set_union (config->exceptions, one);
		} else {
			g_set_error (&error, FS_INTEL_ERROR,
			             FS_INTEL_ERR_INVALID,
			             _("%s is not an address."), job->text);
		}
		fs_range_set_free (one);
		break;
	}
	case JOB_DENY:
	case JOB_IMPORT: {
		gchar *path = NULL;
		FsFeedParseStats stats = { 0 };

		if (job->kind == JOB_DENY) {
			gchar *trimmed = g_strstrip (g_strdup (job->text));

			if (*trimmed == '\0') {
				g_free (trimmed);
				/* An empty blocklist is no list at all. */
				if (fs_intel_config_list (config, DENY_ID) != NULL)
					ok = fs_intel_config_remove (config,
					                             DENY_ID,
					                             &error);
				break;
			}
			g_free (trimmed);
			{
				gint fd = g_file_open_tmp ("stockfw-deny-XXXXXX",
				                           &path, &error);

				ok = fd >= 0;
				if (ok) {
					g_close (fd, NULL);
					ok = g_file_set_contents (path, job->text,
					                          -1, &error);
				}
			}
		} else {
			path = g_strdup (job->text);
		}
		/* Direction 0: a list imported again keeps the direction
		 * it had (set with the CLI); a new one blocks both ways. */
		if (ok)
			ok = fs_intel_import_list (config, path, job->name, 0,
			                           &stats, NULL, &error);
		if (job->kind == JOB_DENY && path != NULL)
			g_unlink (path);
		g_free (path);
		if (ok) {
			gchar *n = grouped (stats.entries);
			gchar *t = g_strdup_printf (
				g_dngettext (NULL, "%s: %s entry.",
				             "%s: %s entries.", stats.entries),
				job->name, n);

			say (job, t);
			g_free (t);
			g_free (n);
			/* What was left out, as the CLI says it: a mistyped
			 * or private address must not just disappear. */
			if (stats.invalid > 0) {
				t = g_strdup_printf (g_dngettext (NULL,
					"%u line did not parse (the first is line %u) "
					"and was skipped.",
					"%u lines did not parse (the first is line %u) "
					"and were skipped.", stats.invalid),
					stats.invalid, stats.first_invalid);
				say (job, t);
				g_free (t);
				job->warned = TRUE;
			}
			if (stats.too_broad > 0) {
				t = g_strdup_printf (g_dngettext (NULL,
					"%u entry was too broad to block and was left "
					"out.",
					"%u entries were too broad to block and were "
					"left out.", stats.too_broad), stats.too_broad);
				say (job, t);
				g_free (t);
				job->warned = TRUE;
			}
			if (stats.protected_hits > 0) {
				t = g_strdup_printf (g_dngettext (NULL,
					"%u entry overlapped addresses that are never "
					"blocked (private, loopback, multicast...); that "
					"part was left out.",
					"%u entries overlapped addresses that are never "
					"blocked (private, loopback, multicast...); that "
					"part was left out.", stats.protected_hits),
					stats.protected_hits);
				say (job, t);
				g_free (t);
				job->warned = TRUE;
			}
		}
		break;
	}
	default:
		break;
	}

	if (!ok) {
		fail (job, error != NULL ? error->message : _("Not changed."));
		g_clear_error (&error);
	} else if (save_config (job, config)) {
		apply_now (job, config, FALSE);
	}
	fs_intel_config_free (config);
}

static void
job_accept (Job *job)
{
	FsIntelConfig *config = load_config (job);

	if (config == NULL)
		return;
	update_feed (job, config, job->id, FS_INTEL_UPDATE_NOW | job->flags,
	             0, 1);
	apply_now (job, config, FALSE);
	fs_intel_config_free (config);
}

static void
job_apply (Job *job)
{
	FsIntelConfig *config = load_config (job);

	if (config == NULL)
		return;
	apply_now (job, config, FALSE);
	fs_intel_config_free (config);
}

static void
job_lookup (Job *job)
{
	FsIntelConfig *config;
	FsIntelLookup r = { 0 };
	FsHostNet *host;
	gchar **hosts;
	gchar *addr = g_strstrip (g_strdup (job->text));
	GString *out = g_string_new (NULL);

	if (!fs_intel_store_exists ()) {
		config = fs_intel_config_new ();
	} else {
		config = fs_intel_config_load (NULL);
		if (config == NULL)
			config = fs_intel_config_new ();
	}
	hosts = fs_intel_update_hosts (config);
	host = fs_hostnet_read ((const gchar *const *) hosts);
	g_strfreev (hosts);

	if (!fs_intel_lookup (config, host, addr, &r)) {
		g_string_printf (out, _("\"%s\" is not one address. Type one "
		                        "address, like 203.0.113.7 or "
		                        "2001:db8::1."), addr);
		goto out;
	}
	/* What the kernel does, never just the configuration (design
	 * 6.6): "is blocked" only while a set in the kernel holds it. */
	fs_intel_lookup_live (job->backend, config, addr, &r);
	if (r.in_force && !r.blocked) {
		GString *names = g_string_new (NULL);

		for (guint i = 0; i < r.kernel_sources->len; i++) {
			if (i > 0)
				g_string_append (names, ", ");
			g_string_append (names, source_name (config,
				g_ptr_array_index (r.kernel_sources, i)));
		}
		g_string_printf (out, _("%s is still blocked by %s: the change "
		                        "that lets it through is not in force "
		                        "yet. Press Apply."), addr, names->str);
		job->lookup_blocked = TRUE;
		g_string_free (names, TRUE);
	} else if (r.sources->len == 0) {
		g_string_printf (out, _("%s is on none of the lists that are "
		                        "turned on."), addr);
	} else {
		GString *names = g_string_new (NULL);

		for (guint i = 0; i < r.sources->len; i++) {
			if (i > 0)
				g_string_append (names, ", ");
			g_string_append (names, source_name (config,
				g_ptr_array_index (r.sources, i)));
		}
		if (r.blocked && r.in_force) {
			g_string_printf (out, _("%s is on %s, and is blocked (%s)."),
			                 addr, names->str, dir_words (r.dir));
			job->lookup_blocked = TRUE;
		} else if (r.blocked && r.uncertain) {
			g_string_printf (out, _("%s is on %s, and is blocked (%s) "
			                        "once your changes are in force. A "
			                        "list changed since the last apply, so "
			                        "whether it is blocked now cannot be "
			                        "told: press Apply."),
			                 addr, names->str, dir_words (r.dir));
		} else if (r.blocked && r.state == FS_INTEL_STATE_ENFORCED) {
			g_string_printf (out, _("%s is on %s, and would be blocked "
			                        "(%s) once your changes are in force. "
			                        "It is not blocked yet: press Apply."),
			                 addr, names->str, dir_words (r.dir));
		} else if (r.blocked) {
			g_string_printf (out, _("%s is on %s, and would be blocked "
			                        "(%s) once the lists are in force. It "
			                        "is not blocked now: %s"),
			                 addr, names->str, dir_words (r.dir),
			                 r.state_detail != NULL ? r.state_detail
			                 : _("the lists are not in force."));
		} else if (r.is_exception) {
			g_string_printf (out, _("%s is on %s, but never blocked: it "
			                        "is on your allow list."),
			                 addr, names->str);
		} else if (r.is_protected) {
			g_string_printf (out, _("%s is on %s, but never blocked: it "
			                        "is a special-purpose address."),
			                 addr, names->str);
		} else {
			g_string_printf (out, _("%s is on %s, but never blocked: "
			                        "this computer needs it (its own "
			                        "network, a gateway, a DNS server or "
			                        "a session)."), addr, names->str);
		}
		g_string_free (names, TRUE);
	}
out:
	fs_intel_lookup_clear (&r);
	fs_hostnet_free (host);
	fs_intel_config_free (config);
	g_free (addr);
	job->lookup = g_string_free (out, FALSE);
}

static void
job_thread (GTask *task, gpointer source, gpointer data,
            GCancellable *cancellable)
{
	Job *job = data;

	(void) source;
	(void) cancellable;

	g_mutex_lock (&engine_lock);
	switch (job->kind) {
	case JOB_REFRESH:                                         break;
	case JOB_UPDATE:     job_update_all (job, FALSE);         break;
	case JOB_SCHEDULED:  job_update_all (job, TRUE);          break;
	case JOB_ACCEPT:     job_accept (job);                    break;
	case JOB_FEED:       job_feed (job);                      break;
	case JOB_APPLY:      job_apply (job);                     break;
	case JOB_LOOKUP:     job_lookup (job);                    break;
	default:             job_simple (job);                    break;
	}
	if (job->kind != JOB_LOOKUP)
		job->snap = take_snapshot (job->backend);
	g_mutex_unlock (&engine_lock);

	g_task_return_boolean (task, TRUE);
}

/* --------------------------------------------------------------- render */

static void show_snapshot (void);

static void
set_busy_widgets (void)
{
	gboolean idle = jobs_pending == 0;

	if (page_root == NULL)
		return;
	if (idle) {
		if (pulse_id != 0) {
			g_source_remove (pulse_id);
			pulse_id = 0;
		}
		gtk_widget_hide (progress_row);
		gtk_spinner_stop (GTK_SPINNER (spinner));
	} else {
		gtk_spinner_start (GTK_SPINNER (spinner));
		gtk_widget_show (progress_row);
	}
	show_snapshot ();
}

static void
job_done (GObject *source, GAsyncResult *result, gpointer data)
{
	GTask *task = G_TASK (result);
	Job *job = g_task_get_task_data (task);

	(void) source;
	(void) data;

	if (jobs_pending > 0)
		jobs_pending--;

	if (job->snap != NULL) {
		/* A lookup's answer describes the kernel as it was: once the
		 * state changes, or anything was changed or applied, it may
		 * be wrong, so it goes rather than stay on screen. */
		if (lookup_result != NULL &&
		    (job->kind != JOB_REFRESH || shown == NULL ||
		     shown->state != job->snap->state))
			gtk_widget_hide (lookup_result);
		snapshot_free (shown);
		shown = job->snap;
		job->snap = NULL;
	}
	if (job->notes != NULL && notes_label != NULL) {
		GString *t = g_string_new (NULL);

		for (guint i = 0; i < job->notes->len; i++)
			g_string_append_printf (t, "%s%s", i ? "\n" : "",
			                        (const gchar *)
			                        g_ptr_array_index (job->notes, i));
		gtk_label_set_text (GTK_LABEL (notes_label), t->str);
		if (t->len > 0)
			gtk_widget_show_all (notes_card);
		else
			gtk_widget_hide (notes_card);
		g_string_free (t, TRUE);
	}
	if (job->kind == JOB_LOOKUP && lookup_result != NULL) {
		gtk_label_set_text (GTK_LABEL (lookup_result), job->lookup);
		remove_class (lookup_result, "intel-hit");
		if (job->lookup_blocked)
			add_class (lookup_result, "intel-hit");
		gtk_widget_show (lookup_result);
	}
	if (job->kind == JOB_REFRESH && message_label != NULL)
		gtk_widget_hide (message_label);
	if (job->message != NULL && message_label != NULL) {
		gtk_label_set_text (GTK_LABEL (message_label), job->message);
		remove_class (message_label, "intel-error");
		remove_class (message_label, "intel-warn");
		if (job->failed)
			add_class (message_label, "intel-error");
		else if (job->warned)
			add_class (message_label, "intel-warn");
		gtk_widget_show (message_label);
	}
	set_busy_widgets ();

	if (job->report_to != NULL)
		tell_user (job->report_to, job->failed ? GTK_MESSAGE_WARNING
		                                  : GTK_MESSAGE_INFO,
		      job->failed ? _("The exception was not added")
		                  : _("Exception added"),
		      job->message);
}

/* The page is redrawn from an idle, never from inside a widget's own
 * signal: a redraw rebuilds the rows, and a switch must not be
 * destroyed while it is still emitting "state-set". */
static gboolean
redraw_idle (gpointer data)
{
	(void) data;
	set_busy_widgets ();
	return G_SOURCE_REMOVE;
}

const gchar *
fs_intelview_hold_reason (void)
{
	const gchar *h = fs_apply_hold_reason ();

	if (h == NULL && hold_func != NULL)
		h = hold_func ();
	return h;
}

static Job *
job_new (JobKind kind)
{
	Job *job = g_new0 (Job, 1);

	job->kind = kind;
	job->backend = backend ();
	job->hold = g_strdup (fs_intelview_hold_reason ());
	return job;
}

static void
job_start (Job *job, const gchar *first_line)
{
	GTask *task = g_task_new (NULL, NULL, job_done, NULL);

	g_task_set_task_data (task, job, job_free);
	jobs_pending++;
	if (page_root != NULL && first_line != NULL) {
		gtk_label_set_text (GTK_LABEL (progress_label), first_line);
		gtk_progress_bar_set_fraction (GTK_PROGRESS_BAR (progress_bar), 0);
		if (pulse_id == 0)
			pulse_id = g_timeout_add (120, pulse_tick, NULL);
	}
	if (page_root != NULL && first_line != NULL)
		g_idle_add (redraw_idle, NULL);
	g_task_run_in_thread (task, job_thread);
	g_object_unref (task);
}

/* --------------------------------------------------------------- feeds */

/* A source that is on and has a copy, but that the kernel was not
 * given, while the table is loaded: saved under the Lock or audit-only
 * mode, or not applied yet.  The hero can read Protected for the other
 * lists, so the row must say this one blocks nothing; it is the only
 * notice left once the message line goes.  NULL when there is nothing
 * to say (in force, or the hero already says nothing is). */
static gchar *
not_in_force_text (const Snapshot *s, const gchar *id)
{
	const gchar *h;

	if ((s->state != FS_INTEL_STATE_ENFORCED &&
	     s->state != FS_INTEL_STATE_DIFFERS) ||
	    g_hash_table_contains (s->in_force, id))
		return NULL;
	h = fs_intelview_hold_reason ();
	if (h != NULL && *h != '\0')
		return g_strdup_printf (_("On, but not in force: %s. It blocks "
		                          "nothing until that is lifted and the "
		                          "lists are applied."), h);
	return g_strdup (_("On, but not in force yet: it blocks nothing until "
	                   "you press Apply."));
}

/* One feed row's status: a sentence and its level (0 ok, 1 warn,
 * 2 bad, 3 quiet). */
static gchar *
feed_status (const Snapshot *s, const FsIntelFeedConf *f,
             const FsIntelSourceState *st, gint *level)
{
	gchar *out, *when;

	*level = 3;
	if (!f->enabled) {
		if (st != NULL && st->fetched_at > 0) {
			when = date_text (st->fetched_at);
			out = g_strdup_printf (_("Off. The copy from %s is kept."),
			                       when);
			g_free (when);
			return out;
		}
		return g_strdup (_("Off."));
	}
	if (!f->custom && f->accepted_at <= 0) {
		*level = 1;
		return g_strdup (_("On, but its terms have not been accepted: "
		                   "nothing is downloaded."));
	}
	if (st != NULL && st->refused != NULL) {
		*level = 1;
		return g_strdup_printf (_("The last update was refused: %s"),
		                        st->refused);
	}
	if (st != NULL && st->last_error != NULL) {
		*level = 2;
		if (st->fetched_at > 0) {
			/* "Still used" read as "still blocking" under a hero
			 * that says the lists are off: say "kept", and "in
			 * force" only when the kernel holds it. */
			when = date_text (st->fetched_at);
			out = g_strdup_printf (
				s->state == FS_INTEL_STATE_ENFORCED &&
				g_hash_table_contains (s->in_force, f->id)
				? _("The last update failed: %s. The copy from %s "
				    "is kept and in force.")
				: _("The last update failed: %s. The copy from %s "
				    "is kept."),
				st->last_error, when);
			g_free (when);
			return out;
		}
		return g_strdup_printf (_("The download failed: %s"),
		                        st->last_error);
	}
	if (st == NULL || st->fetched_at == 0) {
		*level = 1;
		return g_strdup (_("Not downloaded yet: press Update now."));
	}
	if (fs_intel_source_is_stale (s->config, f->id, s->now)) {
		*level = 1;
		return g_strdup (_("Out of date: no fresh copy for a long time."));
	}
	out = not_in_force_text (s, f->id);
	if (out != NULL) {
		*level = 1;
		return out;
	}
	*level = 0;
	if (s->state == FS_INTEL_STATE_ENFORCED &&
	    g_hash_table_contains (s->in_force, f->id))
		return g_strdup (_("Up to date and in force."));
	return g_strdup (_("Up to date."));
}

static gchar *
blocked_text (const Snapshot *s, const gchar *id,
              const FsIntelSourceState *st)
{
	const FsIntelCounter *c = g_hash_table_lookup (s->counters, id);
	gchar *n, *since, *out;

	if (c == NULL || c->packets == 0)
		return g_strdup (_("Nothing blocked yet"));
	n = grouped (c->packets);
	if (st != NULL && st->counted_since > 0) {
		since = date_text (st->counted_since);
		out = g_strdup_printf (g_dngettext (NULL,
		                       "Blocked %s packet since %s",
		                       "Blocked %s packets since %s",
		                       (gulong) MIN (c->packets, G_MAXULONG)),
		                       n, since);
		g_free (since);
	} else {
		out = g_strdup_printf (g_dngettext (NULL, "Blocked %s packet",
		                                    "Blocked %s packets",
		                                    (gulong) MIN (c->packets,
		                                                  G_MAXULONG)),
		                       n);
	}
	g_free (n);
	return out;
}

static gboolean
on_feed_state_set (GtkSwitch *sw, gboolean on, gpointer data)
{
	const gchar *id = data;
	gboolean accept = FALSE;
	Job *job;
	gchar *line;

	if (syncing || shown == NULL)
		return FALSE;

	if (on) {
		FsIntelFeedConf *f = fs_intel_config_feed (shown->config, id);

		/* The consent dialog, the first time (design 8, [S14.3]). */
		if (f != NULL && !f->custom && f->accepted_at <= 0) {
			gchar *text = fs_intel_consent_text (shown->config, id);
			GtkWidget *dialog = gtk_message_dialog_new (
				toplevel (), GTK_DIALOG_MODAL,
				GTK_MESSAGE_QUESTION, GTK_BUTTONS_NONE,
				_("Turn on %s?"), source_name (shown->config, id));
			gint response;

			gtk_widget_set_name (dialog, "intel-consent-dialog");
			gtk_message_dialog_format_secondary_text (
				GTK_MESSAGE_DIALOG (dialog), "%s",
				text != NULL ? text : "");
			gtk_dialog_add_buttons (GTK_DIALOG (dialog),
			                        _("_Cancel"), GTK_RESPONSE_CANCEL,
			                        _("Accept and turn on"),
			                        GTK_RESPONSE_ACCEPT, NULL);
			gtk_dialog_set_default_response (GTK_DIALOG (dialog),
			                                 GTK_RESPONSE_CANCEL);
			response = run_dialog (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);
			g_free (text);
			if (response != GTK_RESPONSE_ACCEPT) {
				/* Put the switch back as it was. */
				g_idle_add (redraw_idle, NULL);
				return TRUE;
			}
			accept = TRUE;
		}
	}

	job = job_new (JOB_FEED);
	job->id = g_strdup (id);
	job->on = on;
	job->accept_terms = accept;
	line = g_strdup_printf (on ? _("Turning on %s" ELLIPSIS)
	                           : _("Turning off %s" ELLIPSIS),
	                        source_name (shown->config, id));
	job_start (job, line);
	g_free (line);
	(void) sw;
	/* The switch follows the snapshot once the job is done. */
	return TRUE;
}

static void
on_accept_clicked (GtkButton *button, gpointer data)
{
	const gchar *id = data;
	Job *job = job_new (JOB_ACCEPT);
	gchar *line;

	job->id = g_strdup (id);
	job->flags = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (button),
	                                                  "flags"));
	line = g_strdup_printf (_("Downloading %s again" ELLIPSIS),
	                        source_name (shown->config, id));
	job_start (job, line);
	g_free (line);
}

static void
on_remove_clicked (GtkButton *button, gpointer data)
{
	const gchar *id = data;
	GtkWidget *dialog;
	Job *job;

	(void) button;
	dialog = gtk_message_dialog_new (toplevel (), GTK_DIALOG_MODAL,
	                                 GTK_MESSAGE_QUESTION,
	                                 GTK_BUTTONS_NONE, _("Remove %s?"),
	                                 source_name (shown->config, id));
	gtk_widget_set_name (dialog, "intel-remove-dialog");
	gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
		"%s", _("Its addresses are no longer blocked, and its stored "
		        "copy is deleted."));
	gtk_dialog_add_buttons (GTK_DIALOG (dialog), _("_Cancel"),
	                        GTK_RESPONSE_CANCEL, _("Remove"),
	                        GTK_RESPONSE_ACCEPT, NULL);
	if (run_dialog (GTK_DIALOG (dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy (dialog);
		return;
	}
	gtk_widget_destroy (dialog);
	job = job_new (JOB_REMOVE);
	job->id = g_strdup (id);
	job_start (job, _("Removing the list" ELLIPSIS));
}

static gboolean
on_activate_link (GtkLabel *label, const gchar *uri, gpointer data)
{
	(void) data;
	gtk_show_uri_on_window (toplevel (), uri, GDK_CURRENT_TIME, NULL);
	(void) label;
	return TRUE;
}

/* "Licence: CC0 . Data: abuse.ch Feodo Tracker, ..." with links to the
 * terms and the publisher's page. */
static GtkWidget *
credit_label (const FsIntelFeedConf *f)
{
	const FsFeedInfo *fi = f->custom ? NULL : fs_feed_catalog_find (f->id);
	GString *m = g_string_new (NULL);
	GtkWidget *label;
	gchar *e;

	if (fi == NULL) {
		gchar *shown_url = fs_feed_url_redacted (f->url);

		e = g_markup_escape_text (shown_url, -1);
		g_string_append_printf (m, _("Your own feed: %s"), e);
		g_free (e);
		g_free (shown_url);
	} else {
		e = g_markup_escape_text (fi->terms_url, -1);
		if (fi->license != NULL) {
			gchar *lic = g_markup_escape_text (fi->license, -1);

			g_string_append_printf (m, _("Licence: <a href=\"%s\">%s</a>"),
			                        e, lic);
			g_free (lic);
		} else {
			g_string_append_printf (m, _("<a href=\"%s\">See the "
			                             "provider's terms</a>"), e);
		}
		g_free (e);
		if (fi->noncommercial)
			g_string_append_printf (m, DOT "%s",
			                        _("Non-commercial use only"));
		{
			/* The catalog's credit line, the same one `stockfw
			 * intel feeds' and the dashboard print (Spamhaus asks
			 * to be credited by name). */
			gchar *u = g_markup_escape_text (fi->info_url, -1);
			gchar *c = g_markup_escape_text (fi->credit, -1);

			g_string_append (m, DOT);
			g_string_append_printf (m, _("Data: <a href=\"%s\">%s</a>"),
			                        u, c);
			g_free (u);
			g_free (c);
		}
	}
	label = label_new (NULL, "intel-meta", 0.0);
	gtk_label_set_markup (GTK_LABEL (label), m->str);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	g_signal_connect (label, "activate-link", G_CALLBACK (on_activate_link),
	                  NULL);
	g_string_free (m, TRUE);
	return label;
}

static gchar *
facts_text (const Snapshot *s, const FsIntelFeedConf *f,
            const FsIntelSourceState *st)
{
	GString *t = g_string_new (NULL);
	gchar *n, *x;

	if (st != NULL && st->fetched_at > 0) {
		n = grouped (st->entries);
		g_string_append_printf (t, g_dngettext (NULL, "%s entry",
		                                        "%s entries",
		                                        st->entries), n);
		g_free (n);
		x = ago_text (s->now, st->fetched_at);
		g_string_append_printf (t, DOT);
		g_string_append_printf (t, _("updated %s"), x);
		g_free (x);
		if (st->content_date > 0) {
			x = date_text (st->content_date);
			g_string_append (t, DOT);
			g_string_append_printf (t, _("list dated %s"), x);
			g_free (x);
		}
	} else {
		g_string_append (t, _("No copy yet"));
	}
	if (f->enabled) {
		gint64 base = st != NULL && st->attempted_at > 0 &&
		              st->fetched_at > 0 ? st->attempted_at : 0;

		x = in_text (s->now, base + interval_s (f));
		g_string_append (t, DOT);
		g_string_append_printf (t, _("next update %s"),
		                        base == 0 ? _("due now") : x);
		g_free (x);
	}
	g_string_append (t, DOT);
	x = blocked_text (s, f->id, st);
	g_string_append (t, x);
	g_free (x);
	return g_string_free (t, FALSE);
}

static GtkWidget *
feed_row (const Snapshot *s, const FsIntelFeedConf *f, gboolean locked)
{
	const FsFeedInfo *fi = f->custom ? NULL : fs_feed_catalog_find (f->id);
	const FsIntelSourceState *st = g_hash_table_lookup (s->sources, f->id);
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 14);
	GtkWidget *text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 3);
	GtkWidget *head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	GtkWidget *sw = gtk_switch_new ();
	GtkWidget *label;
	gchar *name, *t;
	gint level;

	add_class (row, "intel-row");
	name = g_strdup_printf ("feed-row-%s", f->id);
	gtk_widget_set_name (row, name);
	g_free (name);

	gtk_box_pack_start (GTK_BOX (head),
	                    label_new (source_name (s->config, f->id),
	                               "profile-label", 0.0), FALSE, FALSE, 0);
	label = label_new (fi != NULL ? _(fi->category) : _("Custom"),
	                   "intel-chip", 0.5);
	gtk_widget_set_valign (label, GTK_ALIGN_CENTER);
	gtk_box_pack_start (GTK_BOX (head), label, FALSE, FALSE, 0);
	if (fi != NULL && fi->recommended) {
		label = label_new (_("Recommended"), "intel-chip", 0.5);
		add_class (label, "intel-chip-good");
		gtk_widget_set_valign (label, GTK_ALIGN_CENTER);
		gtk_box_pack_start (GTK_BOX (head), label, FALSE, FALSE, 0);
	}
	gtk_box_pack_start (GTK_BOX (text), head, FALSE, FALSE, 0);

	{
		gchar *blocks = g_strdup_printf ("%s%s%s",
			fi != NULL ? _(fi->description) : "",
			fi != NULL ? " " : "", dir_sentence (f->dir));

		gtk_box_pack_start (GTK_BOX (text), wrap_label (blocks, "muted"),
		                    FALSE, FALSE, 0);
		g_free (blocks);
	}
	gtk_box_pack_start (GTK_BOX (text), credit_label (f), FALSE, FALSE, 0);

	t = facts_text (s, f, st);
	label = wrap_label (t, "intel-meta");
	name = g_strdup_printf ("feed-facts-%s", f->id);
	gtk_widget_set_name (label, name);
	g_free (name);
	gtk_box_pack_start (GTK_BOX (text), label, FALSE, FALSE, 0);
	g_free (t);

	{
		GtkWidget *line = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
		static const gchar *const levels[] = {
			"intel-ok", "intel-warn", "intel-bad", "muted"
		};

		t = feed_status (s, f, st, &level);
		label = wrap_label (t, levels[level]);
		add_class (label, "intel-status");
		name = g_strdup_printf ("feed-status-%s", f->id);
		gtk_widget_set_name (label, name);
		g_free (name);
		gtk_box_pack_start (GTK_BOX (line), label, TRUE, TRUE, 0);
		g_free (t);

		/* A refused update: the one override that lets that copy
		 * in, never both (design 4.5). */
		if (f->enabled && st != NULL && st->refused != NULL &&
		    st->refused_override != 0) {
			GtkWidget *b = gtk_button_new_with_label (
				st->refused_override ==
				FS_INTEL_UPDATE_ACCEPT_COVERAGE
				? _("Accept larger list")
				: _("Accept smaller list"));

			add_class (b, "btn-subtle");
			gtk_widget_set_valign (b, GTK_ALIGN_CENTER);
			name = g_strdup_printf ("feed-accept-%s", f->id);
			gtk_widget_set_name (b, name);
			g_free (name);
			gtk_widget_set_tooltip_text (b,
				_("Download the list again and use it even "
				  "though it changed this much."));
			g_object_set_data (G_OBJECT (b), "flags",
			                   GUINT_TO_POINTER (st->refused_override));
			g_signal_connect_data (b, "clicked",
			                       G_CALLBACK (on_accept_clicked),
			                       g_strdup (f->id),
			                       free_closure_data, 0);
			gtk_widget_set_sensitive (b, !locked);
			gtk_box_pack_start (GTK_BOX (line), b, FALSE, FALSE, 0);
		}
		gtk_box_pack_start (GTK_BOX (text), line, FALSE, FALSE, 0);
	}

	gtk_box_pack_start (GTK_BOX (row), text, TRUE, TRUE, 0);

	if (f->custom) {
		GtkWidget *b = gtk_button_new_with_label (_("Remove"));

		add_class (b, "fs-link");
		gtk_widget_set_valign (b, GTK_ALIGN_CENTER);
		g_signal_connect_data (b, "clicked", G_CALLBACK (on_remove_clicked),
		                       g_strdup (f->id), free_closure_data,
		                       0);
		gtk_widget_set_sensitive (b, !locked);
		gtk_box_pack_start (GTK_BOX (row), b, FALSE, FALSE, 0);
	}

	gtk_widget_set_valign (sw, GTK_ALIGN_CENTER);
	name = g_strdup_printf ("feed-switch-%s", f->id);
	gtk_widget_set_name (sw, name);
	g_free (name);
	atk_object_set_name (gtk_widget_get_accessible (sw),
	                     source_name (s->config, f->id));
	gtk_switch_set_active (GTK_SWITCH (sw), f->enabled);
	gtk_switch_set_state (GTK_SWITCH (sw), f->enabled);
	g_signal_connect_data (sw, "state-set", G_CALLBACK (on_feed_state_set),
	                       g_strdup (f->id), free_closure_data, 0);
	gtk_widget_set_sensitive (sw, !locked);
	gtk_box_pack_start (GTK_BOX (row), sw, FALSE, FALSE, 0);
	return row;
}

static gboolean
on_list_state_set (GtkSwitch *sw, gboolean on, gpointer data)
{
	Job *job;

	(void) sw;
	if (syncing)
		return FALSE;
	job = job_new (JOB_LIST);
	job->id = g_strdup (data);
	job->on = on;
	job_start (job, on ? _("Turning the list on" ELLIPSIS)
	                   : _("Turning the list off" ELLIPSIS));
	return TRUE;
}

static GtkWidget *
list_row (const Snapshot *s, const FsIntelListConf *l, gboolean locked)
{
	const FsIntelSourceState *st = g_hash_table_lookup (s->sources, l->id);
	GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 14);
	GtkWidget *text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 3);
	GtkWidget *sw = gtk_switch_new ();
	GtkWidget *b;
	GString *t = g_string_new (NULL);
	gchar *x, *name;

	add_class (row, "intel-row");
	name = g_strdup_printf ("list-row-%s", l->id);
	gtk_widget_set_name (row, name);
	g_free (name);
	gtk_box_pack_start (GTK_BOX (text),
	                    label_new (l->name, "profile-label", 0.0),
	                    FALSE, FALSE, 0);
	if (st != NULL) {
		x = grouped (st->entries);
		g_string_append_printf (t, g_dngettext (NULL, "%s entry",
		                                        "%s entries",
		                                        st->entries), x);
		g_free (x);
		g_string_append (t, DOT);
	}
	if (l->imported_at > 0) {
		x = date_text (l->imported_at);
		g_string_append_printf (t, _("imported %s"), x);
		g_free (x);
		g_string_append (t, DOT);
	}
	g_string_append (t, dir_sentence (l->dir));
	g_string_append (t, " ");
	x = blocked_text (s, l->id, st);
	g_string_append (t, x);
	g_free (x);
	gtk_box_pack_start (GTK_BOX (text), wrap_label (t->str, "intel-meta"),
	                    FALSE, FALSE, 0);
	g_string_free (t, TRUE);
	x = l->enabled && st != NULL ? not_in_force_text (s, l->id) : NULL;
	if (x != NULL) {
		GtkWidget *warn = wrap_label (x, "intel-status");

		add_class (warn, "intel-warn");
		name = g_strdup_printf ("list-status-%s", l->id);
		gtk_widget_set_name (warn, name);
		g_free (name);
		gtk_box_pack_start (GTK_BOX (text), warn, FALSE, FALSE, 0);
		g_free (x);
	}
	gtk_box_pack_start (GTK_BOX (row), text, TRUE, TRUE, 0);

	b = gtk_button_new_with_label (_("Remove"));
	add_class (b, "fs-link");
	gtk_widget_set_valign (b, GTK_ALIGN_CENTER);
	name = g_strdup_printf ("list-remove-%s", l->id);
	gtk_widget_set_name (b, name);
	g_free (name);
	g_signal_connect_data (b, "clicked", G_CALLBACK (on_remove_clicked),
	                       g_strdup (l->id), free_closure_data, 0);
	gtk_widget_set_sensitive (b, !locked);
	gtk_box_pack_start (GTK_BOX (row), b, FALSE, FALSE, 0);

	gtk_widget_set_valign (sw, GTK_ALIGN_CENTER);
	atk_object_set_name (gtk_widget_get_accessible (sw), l->name);
	gtk_switch_set_active (GTK_SWITCH (sw), l->enabled);
	gtk_switch_set_state (GTK_SWITCH (sw), l->enabled);
	g_signal_connect_data (sw, "state-set", G_CALLBACK (on_list_state_set),
	                       g_strdup (l->id), free_closure_data, 0);
	gtk_widget_set_sensitive (sw, !locked);
	gtk_box_pack_start (GTK_BOX (row), sw, FALSE, FALSE, 0);
	return row;
}

static void
clear_box (GtkWidget *box)
{
	GList *children = gtk_container_get_children (GTK_CONTAINER (box));

	for (GList *l = children; l != NULL; l = l->next)
		gtk_widget_destroy (GTK_WIDGET (l->data));
	g_list_free (children);
}

static void
set_text_view (GtkWidget *view, const gchar *text)
{
	GtkTextBuffer *buf = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));

	/* Never over what the user is typing: only an unmodified buffer
	 * follows the store. */
	if (gtk_text_buffer_get_modified (buf))
		return;
	gtk_text_buffer_set_text (buf, text != NULL ? text : "", -1);
	gtk_text_buffer_set_modified (buf, FALSE);
}

static gchar *
text_view_text (GtkWidget *view)
{
	GtkTextBuffer *buf = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));
	GtkTextIter a, b;

	gtk_text_buffer_get_bounds (buf, &a, &b);
	return gtk_text_buffer_get_text (buf, &a, &b, FALSE);
}

/* The state card: the words for what the kernel does (design 6.6). */
static void
show_state (const Snapshot *s)
{
	static const gchar *const levels[] = {
		"level-ok", "level-warn", "level-bad", "level-unknown"
	};
	const gchar *title;
	gint level;
	FsIconKind icon;
	GString *body = g_string_new (s->detail != NULL ? s->detail : "");
	guint on = 0;
	guint64 entries = 0, blocked = 0;
	gint64 newest = 0;

	switch (s->state) {
	case FS_INTEL_STATE_ENFORCED:
		title = _("Protected");
		level = 0;
		icon = FS_ICON_SHIELD_CHECK;
		break;
	case FS_INTEL_STATE_OFF:
		title = _("Off");
		level = 3;
		icon = FS_ICON_SHIELD;
		if (!s->config->enabled || s->detail == NULL)
			break;
		g_string_append (body, " ");
		g_string_append (body, _("Turn on a list below to block the "
		                         "addresses it names."));
		break;
	case FS_INTEL_STATE_NOT_LOADED:
		title = _("Not loaded");
		level = 1;
		icon = FS_ICON_SHIELD_ALERT;
		if (!s->fw_running) {
			g_string_append (body, " ");
			g_string_append (body, _("They are put in force when the "
			                         "firewall starts."));
		}
		break;
	case FS_INTEL_STATE_SUSPENDED:
		title = _("Paused");
		level = 1;
		icon = FS_ICON_SHIELD_ALERT;
		break;
	case FS_INTEL_STATE_DIFFERS:
		title = _("Changed outside StockFW");
		level = 2;
		icon = FS_ICON_SHIELD_X;
		break;
	case FS_INTEL_STATE_UNSUPPORTED:
#ifdef G_OS_WIN32
		title = _("Not supported on Windows yet");
#else
		title = _("Not supported on this platform");
#endif
		level = 3;
		icon = FS_ICON_SHIELD_QUESTION;
		g_string_assign (body, _("Blocklists are not available here "
		                         "yet. Nothing on this page is "
		                         "enforced."));
		break;
	case FS_INTEL_STATE_NEEDS_ROOT:
		title = _("Needs administrator rights");
		level = 3;
		icon = FS_ICON_LOCK;
		break;
	case FS_INTEL_STATE_UNKNOWN:
	default:
		title = _("Unknown");
		level = 3;
		icon = FS_ICON_SHIELD_QUESTION;
		break;
	}

	gtk_label_set_text (GTK_LABEL (hero_title), title);
	gtk_label_set_text (GTK_LABEL (hero_body), body->str);
	g_string_free (body, TRUE);
	fs_icon_set_kind (hero_icon, icon);
	for (guint i = 0; i < G_N_ELEMENTS (levels); i++)
		remove_class (hero, levels[i]);
	add_class (hero, levels[level]);

	/* Apply while the firewall runs: it is also how a change saved
	 * under a hold goes in once the hold is gone. */
	gtk_widget_set_visible (apply_button, s->fw_running &&
	                        s->state != FS_INTEL_STATE_UNSUPPORTED &&
	                        s->store);

	/* Four facts. */
	for (guint i = 0; i < s->config->feeds->len; i++) {
		FsIntelFeedConf *f = g_ptr_array_index (s->config->feeds, i);
		FsIntelSourceState *st = g_hash_table_lookup (s->sources, f->id);
		FsIntelCounter *c = g_hash_table_lookup (s->counters, f->id);

		if (!f->enabled)
			continue;
		on++;
		if (st != NULL) {
			entries += st->entries;
			newest = MAX (newest, st->fetched_at);
		}
		if (c != NULL)
			blocked += c->packets;
	}
	for (guint i = 0; i < s->config->lists->len; i++) {
		FsIntelListConf *l = g_ptr_array_index (s->config->lists, i);
		FsIntelSourceState *st = g_hash_table_lookup (s->sources, l->id);
		FsIntelCounter *c = g_hash_table_lookup (s->counters, l->id);

		if (!l->enabled)
			continue;
		on++;
		if (st != NULL)
			entries += st->entries;
		if (c != NULL)
			blocked += c->packets;
	}
	if (!s->config->enabled)
		on = 0;
	{
		gchar *v[4];

		v[0] = g_strdup_printf ("%u", on);
		v[1] = grouped (entries);
		v[2] = grouped (blocked);
		v[3] = newest > 0 ? ago_text (s->now, newest) : g_strdup (_("never"));
		for (guint i = 0; i < 4; i++) {
			gtk_label_set_text (GTK_LABEL (tile_value[i]), v[i]);
			g_free (v[i]);
		}
	}

	/* The reboot note [P4b] and the master switch: only where the
	 * lists can be enforced at all. */
	gtk_widget_set_visible (hero_note, s->supported);
	gtk_widget_set_visible (master_row, s->supported);
}

static void
show_snapshot (void)
{
	const Snapshot *s = shown;
	gboolean busy = jobs_pending > 0;
	gboolean locked;

	if (page_root == NULL || s == NULL)
		return;

	locked = busy || !s->supported || s->needs_root ||
	         s->config_error != NULL;

	syncing = TRUE;
	show_state (s);

	gtk_switch_set_active (GTK_SWITCH (master_switch), s->config->enabled);
	gtk_switch_set_state (GTK_SWITCH (master_switch), s->config->enabled);
	gtk_widget_set_sensitive (master_switch, !locked);
	gtk_widget_set_sensitive (update_button, !locked);
	gtk_widget_set_sensitive (apply_button, !locked);

	clear_box (feeds_box);
	for (guint i = 0; i < s->config->feeds->len; i++) {
		FsIntelFeedConf *f = g_ptr_array_index (s->config->feeds, i);

		if (i > 0)
			gtk_box_pack_start (GTK_BOX (feeds_box),
			                    gtk_separator_new (GTK_ORIENTATION_HORIZONTAL),
			                    FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (feeds_box),
		                    feed_row (s, f, locked || !s->config->enabled),
		                    FALSE, FALSE, 0);
	}

	clear_box (lists_box);
	for (guint i = 0; i < s->config->lists->len; i++) {
		FsIntelListConf *l = g_ptr_array_index (s->config->lists, i);

		if (strcmp (l->id, DENY_ID) == 0)
			continue;
		gtk_box_pack_start (GTK_BOX (lists_box),
		                    list_row (s, l, locked || !s->config->enabled),
		                    FALSE, FALSE, 0);
	}
	{
		GList *kids = gtk_container_get_children (GTK_CONTAINER (lists_box));

		if (kids == NULL) {
			/* Padded like the rows, in the card's text column. */
			GtkWidget *none = label_new (_("No list file imported."),
			                             "muted", 0.0);

			add_class (none, "intel-pad");
			gtk_widget_set_name (none, "intel-lists-empty");
			gtk_box_pack_start (GTK_BOX (lists_box), none, FALSE,
			                    FALSE, 0);
		}
		g_list_free (kids);
	}
	gtk_widget_show_all (feeds_box);
	gtk_widget_show_all (lists_box);

	set_text_view (allow_view, s->exceptions);
	set_text_view (deny_view, s->deny);
	gtk_widget_set_sensitive (allow_view, !locked);
	gtk_widget_set_sensitive (deny_view, !locked);
	gtk_widget_set_sensitive (allow_save, !locked);
	gtk_widget_set_sensitive (deny_save, !locked);
	gtk_widget_set_sensitive (import_button, !locked);
	gtk_widget_set_sensitive (lookup_button, !busy);

	for (guint i = 0; i < G_N_ELEMENTS (edit_cards); i++)
		gtk_widget_set_visible (edit_cards[i], s->supported);

	syncing = FALSE;
}

/* ------------------------------------------------------------- actions */

static void
on_update_clicked (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;
	job_start (job_new (JOB_UPDATE), _("Starting the update" ELLIPSIS));
}

static void
on_apply_clicked (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;
	job_start (job_new (JOB_APPLY),
	           _("Putting the lists in force" ELLIPSIS));
}

static gboolean
on_master_state_set (GtkSwitch *sw, gboolean on, gpointer data)
{
	Job *job;

	(void) sw;
	(void) data;
	if (syncing)
		return FALSE;
	job = job_new (JOB_MASTER);
	job->on = on;
	job_start (job, on ? _("Switching threat intel on" ELLIPSIS)
	                   : _("Switching threat intel off" ELLIPSIS));
	return TRUE;
}

static void
on_allow_save (GtkButton *button, gpointer data)
{
	Job *job = job_new (JOB_EXCEPTIONS);

	(void) button;
	(void) data;
	job->text = text_view_text (allow_view);
	gtk_text_buffer_set_modified (
		gtk_text_view_get_buffer (GTK_TEXT_VIEW (allow_view)), FALSE);
	job_start (job, _("Saving the allow list" ELLIPSIS));
}

static void
on_deny_save (GtkButton *button, gpointer data)
{
	Job *job = job_new (JOB_DENY);

	(void) button;
	(void) data;
	job->text = text_view_text (deny_view);
	job->name = g_strdup (_(DENY_NAME));
	gtk_text_buffer_set_modified (
		gtk_text_view_get_buffer (GTK_TEXT_VIEW (deny_view)), FALSE);
	job_start (job, _("Saving your blocklist" ELLIPSIS));
}

static void
on_import_clicked (GtkButton *button, gpointer data)
{
	gchar *path = NULL;
	Job *job;
	gchar *base, *dot;

	(void) button;
	(void) data;
	if (import_path != NULL) {
		path = g_strdup (import_path);
	} else {
		GtkWidget *chooser = gtk_file_chooser_dialog_new (
			_("Import a list file"), toplevel (),
			GTK_FILE_CHOOSER_ACTION_OPEN, _("_Cancel"),
			GTK_RESPONSE_CANCEL, _("Import"), GTK_RESPONSE_ACCEPT,
			NULL);

		if (run_dialog (GTK_DIALOG (chooser)) == GTK_RESPONSE_ACCEPT)
			path = gtk_file_chooser_get_filename (
				GTK_FILE_CHOOSER (chooser));
		gtk_widget_destroy (chooser);
	}
	if (path == NULL)
		return;
	base = g_path_get_basename (path);
	dot = strrchr (base, '.');
	if (dot != NULL && dot != base)
		*dot = '\0';
	job = job_new (JOB_IMPORT);
	job->text = path;
	job->name = base;
	job_start (job, _("Importing the list" ELLIPSIS));
}

static void
on_lookup (GtkWidget *widget, gpointer data)
{
	const gchar *text = gtk_entry_get_text (GTK_ENTRY (lookup_entry));
	Job *job;

	(void) widget;
	(void) data;
	if (*text == '\0' || jobs_pending > 0)
		return;
	job = job_new (JOB_LOOKUP);
	job->text = g_strdup (text);
	job_start (job, NULL);
}

void
fs_intelview_refresh (void)
{
	job_start (job_new (JOB_REFRESH), NULL);
}

static gboolean
on_schedule (gpointer data)
{
	(void) data;
	if (jobs_pending == 0 && shown != NULL && shown->supported &&
	    shown->store)
		job_start (job_new (JOB_SCHEDULED), NULL);
	return G_SOURCE_CONTINUE;
}

static gboolean
on_counters_tick (gpointer data)
{
	(void) data;
	if (page_root != NULL && gtk_widget_get_mapped (page_root) &&
	    jobs_pending == 0)
		fs_intelview_refresh ();
	return G_SOURCE_CONTINUE;
}

static void
on_page_map (GtkWidget *widget, gpointer data)
{
	(void) widget;
	(void) data;
	if (jobs_pending == 0)
		fs_intelview_refresh ();
}

/* --------------------------------------------------------------- build */

static GtkWidget *
card_new (const gchar *title, const gchar *subtitle, GtkWidget **body_out)
{
	GtkWidget *card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	GtkWidget *head = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
	GtkWidget *body = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);

	add_class (card, "card");
	add_class (head, "card-head");
	gtk_box_pack_start (GTK_BOX (head), label_new (title, "card-heading", 0.0),
	                    FALSE, FALSE, 0);
	if (subtitle != NULL)
		gtk_box_pack_start (GTK_BOX (head), wrap_label (subtitle, "muted"),
		                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (card), head, FALSE, FALSE, 0);
	add_class (body, "intel-body");
	gtk_box_pack_start (GTK_BOX (card), body, TRUE, TRUE, 0);
	*body_out = body;
	return card;
}

static GtkWidget *
editor_new (GtkWidget **view_out, const gchar *name)
{
	GtkWidget *scroll = gtk_scrolled_window_new (NULL, NULL);
	GtkWidget *view = gtk_text_view_new ();

	gtk_widget_set_name (view, name);
	gtk_text_view_set_wrap_mode (GTK_TEXT_VIEW (view), GTK_WRAP_NONE);
	gtk_text_view_set_monospace (GTK_TEXT_VIEW (view), TRUE);
	gtk_text_view_set_left_margin (GTK_TEXT_VIEW (view), 8);
	gtk_text_view_set_top_margin (GTK_TEXT_VIEW (view), 6);
	add_class (view, "intel-editor");
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_min_content_height (
		GTK_SCROLLED_WINDOW (scroll), 110);
	add_class (scroll, "intel-editor-frame");
	gtk_container_add (GTK_CONTAINER (scroll), view);
	*view_out = view;
	return scroll;
}

static GtkWidget *
build_header (void)
{
	GtkWidget *header = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
	GtkWidget *titles = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);

	add_class (header, "page-head");
	gtk_box_pack_start (GTK_BOX (titles),
	                    label_new (_("Threat Intel"), "page-title", 0.0),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (titles),
	                    wrap_label (_("Blocklists of addresses known for "
	                                  "attacks, botnets and hijacked "
	                                  "networks, kept up to date and "
	                                  "blocked in the kernel."),
	                                "page-subtitle"),
	                    TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (header), titles, TRUE, TRUE, 0);

	update_button = gtk_button_new_with_label (_("Update now"));
	gtk_widget_set_name (update_button, "intel-update");
	add_class (update_button, "btn-primary");
	gtk_widget_set_valign (update_button, GTK_ALIGN_CENTER);
	gtk_widget_set_tooltip_text (update_button,
		_("Download every list that is turned on, then put them in "
		  "force."));
	g_signal_connect (update_button, "clicked",
	                  G_CALLBACK (on_update_clicked), NULL);
	gtk_box_pack_start (GTK_BOX (header), update_button, FALSE, FALSE, 0);
	return header;
}

static GtkWidget *
build_hero (void)
{
	static const gchar *captions[4] = {
		N_("Lists on"), N_("Entries"), N_("Blocked"), N_("Last update")
	};
	GtkWidget *left, *tile, *text, *row, *grid, *col;

	hero = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 24);
	gtk_widget_set_name (hero, "intel-hero");
	add_class (hero, "hero");
	add_class (hero, "level-unknown");

	col = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	left = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 18);
	tile = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_widget_set_size_request (tile, 56, 56);
	gtk_widget_set_valign (tile, GTK_ALIGN_START);
	add_class (tile, "hero-icon-tile");
	hero_icon = fs_icon_new (FS_ICON_SHIELD_QUESTION, 30);
	add_class (hero_icon, "hero-icon");
	gtk_box_pack_start (GTK_BOX (tile), hero_icon, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (left), tile, FALSE, FALSE, 0);

	text = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
	hero_title = label_new (_("Reading the state" ELLIPSIS), "hero-title",
	                        0.0);
	gtk_widget_set_name (hero_title, "intel-state-title");
	gtk_box_pack_start (GTK_BOX (text), hero_title, FALSE, FALSE, 0);
	hero_body = wrap_label (NULL, "hero-body");
	gtk_widget_set_name (hero_body, "intel-state-body");
	gtk_label_set_max_width_chars (GTK_LABEL (hero_body), 60);
	gtk_box_pack_start (GTK_BOX (text), hero_body, FALSE, FALSE, 0);

	row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
	master_row = row;
	gtk_widget_set_margin_top (row, 6);
	master_switch = gtk_switch_new ();
	gtk_widget_set_name (master_switch, "intel-master");
	gtk_widget_set_valign (master_switch, GTK_ALIGN_CENTER);
	atk_object_set_name (gtk_widget_get_accessible (master_switch),
	                     _("Use blocklists"));
	g_signal_connect (master_switch, "state-set",
	                  G_CALLBACK (on_master_state_set), NULL);
	gtk_box_pack_start (GTK_BOX (row), master_switch, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (row),
	                    label_new (_("Use blocklists"), "profile-label", 0.0),
	                    FALSE, FALSE, 0);
	apply_button = gtk_button_new_with_label (_("Apply"));
	gtk_widget_set_name (apply_button, "intel-apply");
	add_class (apply_button, "btn-subtle");
	gtk_widget_set_no_show_all (apply_button, TRUE);
	g_signal_connect (apply_button, "clicked",
	                  G_CALLBACK (on_apply_clicked), NULL);
	gtk_box_pack_end (GTK_BOX (row), apply_button, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (text), row, FALSE, FALSE, 0);

	hero_note = wrap_label (_("After a restart the lists, like the "
	                          "firewall's rules, stay off until the "
	                          "firewall is started."), "stat-note");
	gtk_widget_set_no_show_all (hero_note, TRUE);
	gtk_box_pack_start (GTK_BOX (text), hero_note, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (left), text, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (col), left, FALSE, FALSE, 0);

	/* Progress: whatever the worker is doing, with a bar. */
	progress_row = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
	gtk_widget_set_name (progress_row, "intel-progress");
	add_class (progress_row, "hero-tile");
	{
		GtkWidget *line = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);

		spinner = gtk_spinner_new ();
		gtk_box_pack_start (GTK_BOX (line), spinner, FALSE, FALSE, 0);
		progress_label = label_new (NULL, "tile-value", 0.0);
		gtk_widget_set_name (progress_label, "intel-progress-label");
		gtk_label_set_ellipsize (GTK_LABEL (progress_label),
		                         PANGO_ELLIPSIZE_END);
		gtk_box_pack_start (GTK_BOX (line), progress_label, TRUE, TRUE, 0);
		gtk_box_pack_start (GTK_BOX (progress_row), line, FALSE, FALSE, 0);
		progress_bar = gtk_progress_bar_new ();
		gtk_box_pack_start (GTK_BOX (progress_row), progress_bar,
		                    FALSE, FALSE, 0);
		/* The row is no-show-all (it shows only while a job
		 * runs), so the page's show_all never reaches inside. */
		gtk_widget_show_all (line);
		gtk_widget_show (progress_bar);
	}
	gtk_widget_set_no_show_all (progress_row, TRUE);
	gtk_box_pack_start (GTK_BOX (col), progress_row, FALSE, FALSE, 0);

	message_label = wrap_label (NULL, "intel-message");
	gtk_widget_set_name (message_label, "intel-message");
	gtk_label_set_selectable (GTK_LABEL (message_label), TRUE);
	gtk_widget_set_no_show_all (message_label, TRUE);
	gtk_box_pack_start (GTK_BOX (col), message_label, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (hero), col, TRUE, TRUE, 0);

	grid = gtk_grid_new ();
	gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 10);
	gtk_grid_set_column_homogeneous (GTK_GRID (grid), TRUE);
	gtk_widget_set_size_request (grid, 320, -1);
	gtk_widget_set_valign (grid, GTK_ALIGN_START);
	for (gint i = 0; i < 4; i++) {
		GtkWidget *fact = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
		gchar *name = g_strdup_printf ("intel-tile-%d", i);

		add_class (fact, "hero-tile");
		gtk_box_pack_start (GTK_BOX (fact),
		                    label_new (_(captions[i]), "tile-caption", 0.0),
		                    FALSE, FALSE, 0);
		tile_value[i] = label_new ("", "tile-value", 0.0);
		gtk_widget_set_name (tile_value[i], name);
		g_free (name);
		gtk_label_set_ellipsize (GTK_LABEL (tile_value[i]),
		                         PANGO_ELLIPSIZE_END);
		gtk_box_pack_start (GTK_BOX (fact), tile_value[i], FALSE, FALSE, 0);
		gtk_grid_attach (GTK_GRID (grid), fact, i % 2, i / 2, 1, 1);
	}
	gtk_box_pack_start (GTK_BOX (hero), grid, FALSE, FALSE, 0);
	return hero;
}

GtkWidget *
fs_intelview_page (void)
{
	GtkWidget *page, *scroll, *card, *body, *row, *col;

	page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 16);
	add_class (page, "overview");
	add_class (page, "intel-page");
	page_root = page;

	gtk_box_pack_start (GTK_BOX (page), build_header (), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), build_hero (), FALSE, FALSE, 0);

	/* ---- feeds ---- */
	card = card_new (_("Blocklists"),
	                 _("Each list is downloaded from its publisher only "
	                   "while it is on. Lists contain mistakes: put an "
	                   "address on your allow list to stop blocking it."),
	                 &body);
	gtk_widget_set_name (card, "intel-feeds");
	feeds_box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_pack_start (GTK_BOX (body), feeds_box, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), card, FALSE, FALSE, 0);

	/* ---- your lists ---- */
	card = card_new (_("Your lists"),
	                 _("One address, network (203.0.113.0/24) or range "
	                   "(203.0.113.5-203.0.113.9) per line. # starts a "
	                   "comment; comments are not kept."), &body);
	gtk_widget_set_name (card, "intel-yours");
	edit_cards[0] = card;
	row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 16);
	add_class (row, "intel-pad");
	gtk_box_set_homogeneous (GTK_BOX (row), TRUE);

	col = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
	gtk_box_pack_start (GTK_BOX (col),
	                    label_new (_("Allow list: never blocked"),
	                               "profile-label", 0.0), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (col),
	                    wrap_label (_("Addresses no list may block, "
	                                  "whatever it says."), "muted"),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (col), editor_new (&allow_view,
	                                               "intel-allow-text"),
	                    TRUE, TRUE, 0);
	allow_save = gtk_button_new_with_label (_("Save allow list"));
	gtk_widget_set_name (allow_save, "intel-allow-save");
	add_class (allow_save, "btn-subtle");
	gtk_widget_set_halign (allow_save, GTK_ALIGN_START);
	g_signal_connect (allow_save, "clicked", G_CALLBACK (on_allow_save),
	                  NULL);
	gtk_box_pack_start (GTK_BOX (col), allow_save, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (row), col, TRUE, TRUE, 0);

	col = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
	gtk_box_pack_start (GTK_BOX (col),
	                    label_new (_("Your blocklist: always blocked"),
	                               "profile-label", 0.0), FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (col),
	                    wrap_label (_("Blocked in both directions, like a "
	                                  "list you imported."), "muted"),
	                    FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (col), editor_new (&deny_view,
	                                               "intel-deny-text"),
	                    TRUE, TRUE, 0);
	deny_save = gtk_button_new_with_label (_("Save blocklist"));
	gtk_widget_set_name (deny_save, "intel-deny-save");
	add_class (deny_save, "btn-subtle");
	gtk_widget_set_halign (deny_save, GTK_ALIGN_START);
	g_signal_connect (deny_save, "clicked", G_CALLBACK (on_deny_save), NULL);
	gtk_box_pack_start (GTK_BOX (col), deny_save, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (row), col, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (body), row, FALSE, FALSE, 0);

	/* Imported list files. */
	{
		GtkWidget *head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);

		add_class (head, "intel-subhead");
		gtk_box_pack_start (GTK_BOX (head),
		                    label_new (_("Imported list files"),
		                               "profile-label", 0.0),
		                    TRUE, TRUE, 0);
		import_button = gtk_button_new_with_label (_("Import" ELLIPSIS));
		gtk_widget_set_name (import_button, "intel-import");
		add_class (import_button, "btn-subtle");
		g_signal_connect (import_button, "clicked",
		                  G_CALLBACK (on_import_clicked), NULL);
		gtk_box_pack_start (GTK_BOX (head), import_button, FALSE, FALSE, 0);
		gtk_box_pack_start (GTK_BOX (body), head, FALSE, FALSE, 0);
	}
	lists_box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
	add_class (lists_box, "intel-lists");
	gtk_box_pack_start (GTK_BOX (body), lists_box, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), card, FALSE, FALSE, 0);

	/* ---- lookup ---- */
	card = card_new (_("Look up an address"),
	                 _("Which of the lists that are on name an address, "
	                   "and whether it is blocked."), &body);
	gtk_widget_set_name (card, "intel-lookup");
	edit_cards[1] = card;
	row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
	add_class (row, "intel-pad");
	lookup_entry = gtk_entry_new ();
	gtk_widget_set_name (lookup_entry, "intel-lookup-entry");
	gtk_entry_set_placeholder_text (GTK_ENTRY (lookup_entry),
	                                _("Is 203.0.113.7 on a list?"));
	gtk_entry_set_width_chars (GTK_ENTRY (lookup_entry), 32);
	g_signal_connect (lookup_entry, "activate", G_CALLBACK (on_lookup),
	                  NULL);
	gtk_box_pack_start (GTK_BOX (row), lookup_entry, FALSE, FALSE, 0);
	lookup_button = gtk_button_new_with_label (_("Look up"));
	gtk_widget_set_name (lookup_button, "intel-lookup-button");
	add_class (lookup_button, "btn-subtle");
	g_signal_connect (lookup_button, "clicked", G_CALLBACK (on_lookup),
	                  NULL);
	gtk_box_pack_start (GTK_BOX (row), lookup_button, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (body), row, FALSE, FALSE, 0);
	lookup_result = wrap_label (NULL, "intel-lookup-result");
	gtk_widget_set_name (lookup_result, "intel-lookup-result");
	gtk_label_set_selectable (GTK_LABEL (lookup_result), TRUE);
	add_class (lookup_result, "intel-pad");
	gtk_widget_set_no_show_all (lookup_result, TRUE);
	gtk_box_pack_start (GTK_BOX (body), lookup_result, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), card, FALSE, FALSE, 0);

	/* ---- notes ---- */
	notes_card = card_new (_("Notes from the last apply"),
	                       _("What was left out or kept reachable, so a "
	                         "list never cuts this computer off."),
	                       &body);
	gtk_widget_set_name (notes_card, "intel-notes");
	notes_label = wrap_label (NULL, "intel-meta");
	gtk_widget_set_name (notes_label, "intel-notes-text");
	gtk_label_set_selectable (GTK_LABEL (notes_label), TRUE);
	add_class (notes_label, "intel-pad");
	gtk_box_pack_start (GTK_BOX (body), notes_label, FALSE, FALSE, 0);
	gtk_widget_set_no_show_all (notes_card, TRUE);
	gtk_box_pack_start (GTK_BOX (page), notes_card, FALSE, FALSE, 0);

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_container_add (GTK_CONTAINER (scroll), page);

	g_signal_connect (page, "map", G_CALLBACK (on_page_map), NULL);
	g_timeout_add_seconds (SCHEDULE_S, on_schedule, NULL);
	g_timeout_add_seconds (COUNTERS_S, on_counters_tick, NULL);

	install_css ();
	fs_intelview_refresh ();
	return scroll;
}

/* --------------------------------------------------------------- hooks */

void
fs_intelview_set_hold_func (FsIntelHoldFunc func)
{
	hold_func = func;
}

gboolean
fs_intelview_rule_is_intel (const gchar *rule)
{
	/* The backend writes _("Threat intel: %s"); compare with the
	 * same translated text up to the name. */
	const gchar *fmt = _("Threat intel: %s");
	const gchar *cut = strstr (fmt, "%s");
	gsize n = cut != NULL ? (gsize) (cut - fmt) : strlen (fmt);

	return rule != NULL && n > 0 && strncmp (rule, fmt, n) == 0;
}

void
fs_intelview_add_exception (GtkWindow *parent, const gchar *addr,
                            const gchar *rule)
{
	GtkWidget *dialog;
	Job *job;

	if (addr == NULL || *addr == '\0')
		return;
	dialog = gtk_message_dialog_new (parent, GTK_DIALOG_MODAL,
	                                 GTK_MESSAGE_QUESTION, GTK_BUTTONS_NONE,
	                                 _("Never block %s?"), addr);
	gtk_widget_set_name (dialog, "intel-exception-dialog");
	gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (dialog),
		_("%s\n\nIt goes on your allow list on the Threat Intel page, "
		  "and no blocklist blocks it any more. Your firewall rules "
		  "still apply to it."),
		rule != NULL ? rule : "");
	gtk_dialog_add_buttons (GTK_DIALOG (dialog), _("_Cancel"),
	                        GTK_RESPONSE_CANCEL, _("Add exception"),
	                        GTK_RESPONSE_ACCEPT, NULL);
	if (run_dialog (GTK_DIALOG (dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy (dialog);
		return;
	}
	gtk_widget_destroy (dialog);

	job = job_new (JOB_ADD_EXCEPTION);
	job->text = g_strdup (addr);
	if (parent != NULL)
		job->report_to = g_object_ref (parent);
	job_start (job, _("Adding the exception" ELLIPSIS));
}

void
fs_intelview_set_backend (const FsBackend *b)
{
	test_backend = b;
}

void
fs_intelview_set_responder (FsIntelResponder r, gpointer data)
{
	responder = r;
	responder_data = data;
}

gboolean
fs_intelview_busy (void)
{
	return jobs_pending > 0;
}

void
fs_intelview_set_import_path (const gchar *path)
{
	g_free (import_path);
	import_path = g_strdup (path);
}
