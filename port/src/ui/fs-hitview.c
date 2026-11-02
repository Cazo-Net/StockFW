/*---[ fs-hitview.c ]--------------------------------------------------
 * The Events page.
 *
 * A bounded list of firewall hits, fed by the platform backend.  The
 * original kept every hit in a GList and appended straight to the
 * model; on a busy machine that grows without limit, so rows are capped
 * and the oldest dropped.
 *
 * 1.0.7: the rows live in the core event store (100,000 by default,
 * up to 1,000,000), the view reads them through a model that copies
 * nothing (fs-eventmodel.c), the filter bar narrows by text, direction,
 * action, protocol, port, address block and time, and every accepted
 * event is also kept in the history files (fs-eventlog.c), so the list
 * survives a restart.
 *--------------------------------------------------------------------*/

#include "ui/fs-hitview.h"
#include "ui/fs-eventmodel.h"
#include "ui/fs-activityview.h"
#include "ui/fs-dialogs.h"
#include "ui/fs-copilot.h"
#include "ui/fs-statusview.h"
#include "ui/fs-policyview.h"
#include "ui/fs-app.h"
#include "core/fs-backend.h"
#include "core/fs-service.h"
#include "core/fs-prefs.h"
#include "core/fs-copilot.h"
#include "core/fs-eventrule.h"
#include "core/fs-rules.h"
#include "core/fs-audit.h"
#include "core/fs-util.h"
#include "core/fs-apply.h"
#include "core/fs-eventlog.h"
#include "core/fs-i18n.h"

#include <string.h>

static GtkWidget    *view;
static GtkWidget    *count_label;

/* Shown over the empty list, so an empty list says what it is waiting
 * for (or that the filter hides everything) instead of being a blank
 * white box. */
static GtkWidget    *empty_label;
static GtkWidget    *monitor_warning;        /* strip; hidden unless needed */
static GtkWidget    *monitor_warning_label;
static GtkWidget    *monitor_toggle = NULL;   /* the Monitor switch     */
static guint         monitor_watchdog = 0;

/* [ the store ]
 * The events live in core (fs-eventstore.c): a ring of compact records
 * with interned strings, deduplicated against the last 64 accepted.
 * The view reads them through FsEventModel, which holds only the seqs
 * the filter lets through, so nothing is copied per row. */
static FsEventStore *estore = NULL;
static FsEventModel *emodel = NULL;

/* [ history ]
 * Accepted events are also appended to the history files
 * (fs-eventlog.c) and the newest are read back when the page is built,
 * so the list survives a restart.  Flushed every second. */
static FsEventLog   *elog = NULL;
static guint         elog_flush_id = 0;
static guint         elog_retry_id = 0;   /* another copy holds it */
static guint         history_loaded = 0;
static gchar        *history_problem = NULL;
/* The history warning on the strip, while it is there, and what the
 * strip said before it (a reason monitoring cannot run): put back when
 * writing works again, unless something else took the strip since. */
static gchar        *history_warning = NULL;
static gchar        *history_warning_was = NULL;

/* The filter bar: the search entry plus the row of boxes under it.
 * The matching lives in core (FsEventQuery), decided once per distinct
 * string, so filtering 100,000 events takes milliseconds. */
static GtkWidget    *filter_entry = NULL;
static GtkWidget    *filter_direction = NULL;
static GtkWidget    *filter_action = NULL;
static GtkWidget    *filter_protocol = NULL;
static GtkWidget    *filter_port = NULL;
static GtkWidget    *filter_address = NULL;
static GtkWidget    *filter_since = NULL;
static GtkWidget    *filter_until = NULL;
static GtkWidget    *filter_error = NULL;     /* why a box is refused */
static guint         filter_timeout = 0;
static gboolean      filter_active = FALSE;   /* any part set         */

/* The policy the Event -> Rule actions stage into; NULL until
 * fs-app.c hands it over (the page is built before the policy). */
static FsPolicy     *hitview_policy = NULL;

/* Column order matches FsHitColumn; the colour column is last. */
enum
{
	COL_TIME,
	COL_DIRECTION,
	COL_IN,
	COL_OUT,
	COL_PORT,
	COL_SOURCE,
	COL_DESTINATION,
	COL_LENGTH,
	COL_TOS,
	COL_PROTOCOL,
	COL_SERVICE,
	COL_COLOR,
	COL_COUNT
};

static const struct
{
	const gchar *label;
	gboolean     visible;
	const gchar *pref_key;
} column_defs[FS_NUM_HITCOLUMNS] = {
	{ N_("Time"),        TRUE,  "/apps/stockfw/client/ui/hitview_time_col" },
	{ N_("Direction"),   TRUE,  "/apps/stockfw/client/ui/hitview_direction_col" },
	{ N_("In"),          TRUE,  "/apps/stockfw/client/ui/hitview_in_col" },
	{ N_("Out"),         TRUE,  "/apps/stockfw/client/ui/hitview_out_col" },
	{ N_("Port"),        TRUE,  "/apps/stockfw/client/ui/hitview_port_col" },
	{ N_("Source"),      TRUE,  "/apps/stockfw/client/ui/hitview_source_col" },
	{ N_("Destination"), TRUE,  "/apps/stockfw/client/ui/hitview_destination_col" },
	{ N_("Length"),      FALSE, "/apps/stockfw/client/ui/hitview_length_col" },
	{ N_("ToS"),         FALSE, "/apps/stockfw/client/ui/hitview_tos_col" },
	{ N_("Protocol"),    TRUE,  "/apps/stockfw/client/ui/hitview_protocol_col" },
	{ N_("Service"),     TRUE,  "/apps/stockfw/client/ui/hitview_service_col" },
	{ N_(""),            FALSE, NULL },   /* colour, never shown */
};

/* [ color_cell_data ]
 * Paints each row:
 *   - selected   -> left to the theme, so the blue highlight and the
 *                   inverted text are not painted over by cell colours;
 *   - blocked    -> soft pastel alert tint with dark red text, the
 *                   whole row, as the spec has it;
 *   - otherwise  -> alternating white / off-white by visible position
 *                   (position, not append index: the list trims its
 *                   oldest row at the cap, which shifts every row).
 * The colour column is only the blocked flag here. */
static void
color_cell_data (GtkTreeViewColumn *column, GtkCellRenderer *renderer,
                 GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	gchar *color = NULL;
	const gchar *background = NULL;
	const gchar *foreground = NULL;
	gboolean blocked;
	gboolean selected = FALSE;

	(void) column;
	(void) data;

	gtk_tree_model_get (model, iter, COL_COLOR, &color, -1);
	blocked = (color != NULL && *color != '\0');
	g_free (color);

	if (view != NULL) {
		GtkTreeSelection *sel =
			gtk_tree_view_get_selection (GTK_TREE_VIEW (view));

		selected = gtk_tree_selection_iter_is_selected (sel, iter);
	}

	if (blocked) {
		background = "#ffebee";
		foreground = "#b71c1c";
	} else {
		GtkTreePath *path = gtk_tree_model_get_path (model, iter);

		if (path != NULL) {
			gint *indices = gtk_tree_path_get_indices (path);

			if (indices != NULL && indices[0] % 2 == 1)
				background = "#f9f9f9";

			gtk_tree_path_free (path);
		}
	}

	if (selected) {
		background = NULL;
		foreground = NULL;
	}

	g_object_set (renderer,
	              "background", background,
	              "foreground", foreground,
	              NULL);
}

/* [ fs_hitview_format_time ]
 * What the Time column shows.  The backend hands over the wevtutil
 * stamp verbatim -- ISO-8601 UTC with a seven-digit fraction
 * ("2026-10-09T12:35:34.0780000Z") -- honest as a key, but far too
 * wide for the column and on the wrong clock.  Show local time,
 * seconds only, with the date only for events from another day.
 * Anything that does not parse (the smoke test's "12:00:00", a
 * backend with a different stamp) is returned unchanged: a display
 * helper must not invent a time.  Exposed for the smoke test. */
gchar *
fs_hitview_format_time (const gchar *raw)
{
	gchar rebuilt[21];
	GDateTime *utc, *local, *now;
	gchar *text;

	if (raw == NULL || *raw == '\0')
		return g_strdup ("");

	/* The first 19 characters are "YYYY-MM-DDTHH:MM:SS"; the
	 * fraction and the 'Z' follow. */
	if (strlen (raw) < 19)
		return g_strdup (raw);

	memcpy (rebuilt, raw, 19);
	rebuilt[19] = 'Z';
	rebuilt[20] = '\0';

	utc = g_date_time_new_from_iso8601 (rebuilt, NULL);
	if (utc == NULL)
		return g_strdup (raw);

	local = g_date_time_to_local (utc);
	now = g_date_time_new_now_local ();

	if (g_date_time_get_year (local) == g_date_time_get_year (now) &&
	    g_date_time_get_month (local) == g_date_time_get_month (now) &&
	    g_date_time_get_day_of_month (local) ==
	    g_date_time_get_day_of_month (now))
		text = g_date_time_format (local, "%H:%M:%S");
	else
		text = g_date_time_format (local, "%m-%d %H:%M:%S");

	g_date_time_unref (utc);
	g_date_time_unref (local);
	g_date_time_unref (now);

	return text != NULL ? text : g_strdup (raw);
}

/* [ time_cell_data ]
 * The Time column's cell function: the formatted text first, then
 * the same row paint every other column gets. */
static void
time_cell_data (GtkTreeViewColumn *column, GtkCellRenderer *renderer,
                GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	gchar *raw = NULL;
	gchar *text;

	gtk_tree_model_get (model, iter, COL_TIME, &raw, -1);
	text = fs_hitview_format_time (raw);
	g_object_set (renderer, "text", text, NULL);
	g_free (text);
	g_free (raw);

	color_cell_data (column, renderer, model, iter, data);
}

/* [ update_count_label ]
 * With a filter set the label reports both numbers, so an empty list
 * under a filter cannot be mistaken for an idle firewall.  Numbers
 * are grouped ("100,000"), since they now run to six digits. */
static const gchar *empty_text (void);

static gchar *
grouped (guint n)
{
	if (n < 1000)
		return g_strdup_printf ("%u", n);
	if (n < 1000000)
		return g_strdup_printf ("%u,%03u", n / 1000, n % 1000);
	return g_strdup_printf ("%u,%03u,%03u", n / 1000000, (n / 1000) % 1000,
	                        n % 1000);
}

/* Any size, thousands grouped with commas. */
static gchar *
grouped64 (guint64 n)
{
	gchar *digits = g_strdup_printf ("%" G_GUINT64_FORMAT, n);
	gsize len = strlen (digits);
	GString *out = g_string_new (NULL);

	for (gsize i = 0; i < len; i++) {
		if (i > 0 && (len - i) % 3 == 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, digits[i]);
	}
	g_free (digits);
	return g_string_free (out, FALSE);
}

/* What the source says it skipped this session (0: nothing, or a
 * source that never skips). */
static guint64 skipped_shown = 0;

static guint64
monitor_skipped (void)
{
	const FsBackend *backend = fs_backend ();

	return backend->log_skipped != NULL ? backend->log_skipped () : 0;
}

static void
update_count_label (void)
{
	guint total = fs_hitview_count ();
	guint shown = fs_hitview_visible_count ();
	gchar *text, *a, *b;

	if (count_label == NULL)
		return;

	a = grouped (shown);
	b = grouped (total);
	if (filter_active)
		text = g_strdup_printf (_("%s of %s events"), a, b);
	else
		text = g_strdup_printf (total == 1 ? _("%s event") : _("%s events"),
		                        b);

	/* Events the source could not read (Windows: more than one
	 * five-second read takes, up to 10,000 and fewer after a slow
	 * read or without the record condition).  Said where the count
	 * is, so the count is never read as everything that happened. */
	skipped_shown = monitor_skipped ();
	if (skipped_shown > 0) {
		gchar *n = grouped64 (skipped_shown);
		gchar *more = g_strdup_printf (_("%s (up to %s skipped)"), text, n);

		g_free (text);
		g_free (n);
		text = more;
	}
	gtk_widget_set_tooltip_text (count_label, skipped_shown > 0
		? _("More events arrived at once than one read of the event "
		    "log takes (up to 10,000 every five seconds; fewer after "
		    "a slow read, or when the event log refuses the record "
		    "condition). The newest were listed; the older ones of "
		    "that burst were skipped. The number is an upper bound: "
		    "the log numbers every security event, not only firewall "
		    "events.")
		: NULL);
	gtk_label_set_text (GTK_LABEL (count_label), text);
	g_free (text);
	g_free (a);
	g_free (b);

	if (empty_label != NULL) {
		gtk_label_set_text (GTK_LABEL (empty_label), empty_text ());
		gtk_widget_set_visible (empty_label, shown == 0);
	}
}

/* [ empty_text ]
 * What an empty list means, said plainly.  "No events yet" while the
 * firewall is stopped read as a quiet network; with no rules loaded
 * nothing is logged at all, and the page now says so (1.0.7). */
static const gchar *
empty_text (void)
{
	const FsBackend *backend = fs_backend ();

	if (fs_hitview_count () > 0)
		return _("No event matches the filter.");

	if (!fs_hitview_active ())
		return _("Event monitoring is off.\nTurn on Monitor to list "
		         "traffic here.");

	if (backend->get_state != NULL &&
	    backend->get_state () != FS_FW_RUNNING &&
	    backend->get_state () != FS_FW_HIT)
		return _("The firewall is stopped, so nothing is being logged.\n"
		         "Start it on the Status page to see traffic here.");

	if ((backend->fw_honors & FS_FWHON_LOG_ALLOWED) != 0 &&
	    !fs_prefs_bool (FS_PREFS_FW_LOG_ALLOWED))
		return _("Nothing has been blocked yet.\nOnly blocked traffic is "
		         "logged.  Turn on \"Log allowed connections\" in "
		         "Preferences to see the rest.");

	return _("No events yet.\nStockFW lists new connections here as its "
	         "rules allow or block them.");
}

/* ---- the filter bar ----------------------------------------------- */

static const gchar *
entry_text (GtkWidget *entry)
{
	return entry != NULL ? gtk_entry_get_text (GTK_ENTRY (entry)) : NULL;
}

/* [ mark_entry ]
 * A box whose text is refused turns red and says why in its tooltip;
 * the reason is also shown beside the boxes. */
static void
mark_entry (GtkWidget *entry, const gchar *why)
{
	GtkStyleContext *ctx;

	if (entry == NULL)
		return;

	ctx = gtk_widget_get_style_context (entry);
	if (why != NULL)
		gtk_style_context_add_class (ctx, "error");
	else
		gtk_style_context_remove_class (ctx, "error");
	gtk_widget_set_tooltip_text (entry, why != NULL
	                             ? why
	                             : g_object_get_data (G_OBJECT (entry),
	                                                  "fs-tip"));
}

static void
show_filter_error (const gchar *text)
{
	if (filter_error == NULL)
		return;

	gtk_label_set_text (GTK_LABEL (filter_error), text != NULL ? text : "");
	gtk_widget_set_visible (filter_error, text != NULL);
}

/* [ swap_model ]
 * Rebuilding the rows under a new filter or after a reload is done
 * with the model detached: one rebuild instead of a row-deleted and a
 * row-inserted per event. */
static void
model_detach (void)
{
	if (view != NULL)
		gtk_tree_view_set_model (GTK_TREE_VIEW (view), NULL);
}

static void
model_attach (void)
{
	if (view != NULL && emodel != NULL)
		gtk_tree_view_set_model (GTK_TREE_VIEW (view),
		                         GTK_TREE_MODEL (emodel));
}

gboolean
fs_hitview_refilter_now (void)
{
	FsEventFilter f;
	FsEventQuery *query;
	GError *error = NULL;
	const gint64 now = g_get_real_time ();
	gint64 since = 0, until = 0;
	gboolean ok = TRUE;

	if (filter_timeout != 0) {
		g_source_remove (filter_timeout);
		filter_timeout = 0;
	}

	if (emodel == NULL)
		return FALSE;

	memset (&f, 0, sizeof f);
	f.text     = entry_text (filter_entry);
	f.protocol = entry_text (filter_protocol);
	f.port     = entry_text (filter_port);
	f.address  = entry_text (filter_address);
	if (filter_direction != NULL)
		f.direction = (FsEventDirFilter) gtk_combo_box_get_active (
			GTK_COMBO_BOX (filter_direction));
	if (filter_action != NULL)
		f.action = (FsEventActionFilter) gtk_combo_box_get_active (
			GTK_COMBO_BOX (filter_action));

	mark_entry (filter_since, NULL);
	mark_entry (filter_until, NULL);
	mark_entry (filter_port, NULL);
	mark_entry (filter_address, NULL);

	if (!fs_event_parse_time_spec (entry_text (filter_since), now, FALSE,
	                               &since, &error)) {
		mark_entry (filter_since, error->message);
		ok = FALSE;
	} else if (!fs_event_parse_time_spec (entry_text (filter_until), now,
	                                      TRUE, &until, &error)) {
		mark_entry (filter_until, error->message);
		ok = FALSE;
	}
	f.since_us = since;
	f.until_us = until;

	query = ok ? fs_eventquery_new (&f, &error) : NULL;
	if (query == NULL) {
		gchar *msg;

		if (ok && error != NULL) {
			if (error->code == FS_EVENTQUERY_ERROR_PORT)
				mark_entry (filter_port, error->message);
			else if (error->code == FS_EVENTQUERY_ERROR_ADDRESS)
				mark_entry (filter_address, error->message);
			else {
				mark_entry (filter_since, error->message);
				mark_entry (filter_until, error->message);
			}
		}
		msg = g_strdup_printf (_("Filter not changed: %s."),
		                       error != NULL ? error->message : "?");
		show_filter_error (msg);
		g_free (msg);
		g_clear_error (&error);
		return FALSE;
	}

	show_filter_error (NULL);
	filter_active = !fs_eventquery_is_empty (query);

	model_detach ();
	fs_event_model_set_query (emodel, filter_active ? query : NULL);
	if (!filter_active)
		fs_eventquery_free (query);
	model_attach ();

	update_count_label ();
	return TRUE;
}

static gboolean
on_filter_timeout (gpointer data)
{
	(void) data;

	filter_timeout = 0;
	fs_hitview_refilter_now ();
	return G_SOURCE_REMOVE;
}

/* [ on_filter_changed ]
 * Any box: wait for a short pause in the typing, then filter once. */
static void
on_filter_changed (GtkWidget *widget, gpointer data)
{
	(void) widget;
	(void) data;

	if (filter_timeout != 0)
		g_source_remove (filter_timeout);
	filter_timeout = g_timeout_add (250, on_filter_timeout, NULL);
}

/* The search entry already waits for a pause (search-changed). */
static void
on_search_changed (GtkSearchEntry *entry, gpointer data)
{
	(void) entry;
	(void) data;

	fs_hitview_refilter_now ();
}

static void
on_filter_reset (GtkButton *button, gpointer data)
{
	GtkWidget *entries[] = { filter_entry, filter_protocol, filter_port,
	                         filter_address, filter_since, filter_until };

	(void) button;
	(void) data;

	for (guint i = 0; i < G_N_ELEMENTS (entries); i++)
		if (entries[i] != NULL)
			gtk_entry_set_text (GTK_ENTRY (entries[i]), "");
	if (filter_direction != NULL)
		gtk_combo_box_set_active (GTK_COMBO_BOX (filter_direction), 0);
	if (filter_action != NULL)
		gtk_combo_box_set_active (GTK_COMBO_BOX (filter_action), 0);

	fs_hitview_refilter_now ();
}

guint
fs_hitview_visible_count (void)
{
	return emodel != NULL ? fs_event_model_n_rows (emodel) : 0;
}

FsEventStore *
fs_hitview_store (void)
{
	return estore;
}

gboolean
fs_hitview_export_csv (const gchar *path, guint *written, GError **error)
{
	GArray *rows;
	gboolean ok;

	if (written != NULL)
		*written = 0;
	if (emodel == NULL) {
		g_set_error_literal (error, G_FILE_ERROR, G_FILE_ERROR_FAILED,
		                     _("The Events page is not built."));
		return FALSE;
	}

	rows = fs_event_model_rows (emodel);
	ok = fs_eventstore_write_csv (estore, (const guint64 *) rows->data,
	                              rows->len, path, written, error);
	g_array_unref (rows);
	return ok;
}

/* [ on_export_clicked ]
 * The rows as shown -- filtered and in the shown order -- to a CSV file
 * the user picks. */
static void
on_export_clicked (GtkButton *button, gpointer data)
{
	GtkFileChooserNative *chooser;
	GtkWidget *top = gtk_widget_get_toplevel (GTK_WIDGET (button));
	GDateTime *now = g_date_time_new_now_local ();
	gchar *name = g_date_time_format (now, "stockfw-events-%Y%m%d-%H%M%S.csv");

	(void) data;

	chooser = gtk_file_chooser_native_new (
		_("Export events"),
		GTK_IS_WINDOW (top) ? GTK_WINDOW (top) : NULL,
		GTK_FILE_CHOOSER_ACTION_SAVE, _("_Export"), _("_Cancel"));
	gtk_file_chooser_set_do_overwrite_confirmation (
		GTK_FILE_CHOOSER (chooser), TRUE);
	gtk_file_chooser_set_current_name (GTK_FILE_CHOOSER (chooser), name);

	if (gtk_native_dialog_run (GTK_NATIVE_DIALOG (chooser)) ==
	    GTK_RESPONSE_ACCEPT) {
		gchar *path = gtk_file_chooser_get_filename (
			GTK_FILE_CHOOSER (chooser));
		GError *error = NULL;
		guint written = 0;

		if (path != NULL &&
		    fs_hitview_export_csv (path, &written, &error)) {
			gchar *msg = g_strdup_printf (
				filter_active
				? _("%u events, the ones the filter shows, were "
				    "written to\n%s")
				: _("%u events were written to\n%s"),
				written, path);

			fs_dialogs_info (NULL, _("Events exported"), msg);
			g_free (msg);
		} else {
			fs_dialogs_error (NULL, _("Could not export the events"),
			                  error != NULL ? error->message : NULL);
		}
		g_clear_error (&error);
		g_free (path);
	}

	g_object_unref (chooser);
	g_free (name);
	g_date_time_unref (now);
}

/* [ hit_is_blocked ]
 * The Windows backend marks dropped events by appending " [BLOCKED]"
 * to the service field.  Everything the Status page counts as "serious"
 * and everything the Events page paints red comes from this. */
static gboolean
hit_is_blocked (const FsHit *hit)
{
	return hit != NULL && hit->service != NULL &&
	       strstr (hit->service, "[BLOCKED]") != NULL;
}

/* [ hit_is_inbound ]
 * Direction arrives as "In"/"Out" from the parser and as the
 * "Inbound"/"Outbound" wording from other paths, so both are accepted. */
static gboolean
hit_is_inbound (const FsHit *hit)
{
	if (hit == NULL || hit->direction == NULL)
		return FALSE;

	return g_ascii_strcasecmp (hit->direction, "In") == 0 ||
	       g_ascii_strcasecmp (hit->direction, "Inbound") == 0;
}

/* [ hit_is_outbound ] */
static gboolean
hit_is_outbound (const FsHit *hit)
{
	if (hit == NULL || hit->direction == NULL)
		return FALSE;

	return g_ascii_strcasecmp (hit->direction, "Out") == 0 ||
	       g_ascii_strcasecmp (hit->direction, "Outbound") == 0;
}

/* ---- the two Interface > Events filters -----------------------------
 *
 * Ported from the original hitview.c, which ran both inside
 * hitview_append_hit() before the status counters were touched.  So a
 * filtered event produces no row, no counter tick and no Copilot
 * input -- it is as if the firewall had not logged it. */

/* The row the list accepted most recently, kept as copies rather than
 * as a pointer into the model because rows are trimmed once the cap
 * is passed. */
static gchar *last_port = NULL;
static gchar *last_proto = NULL;
static gchar *last_src = NULL;
static gchar *last_dst = NULL;

/* [ hit_is_redundant ]
 * The original compared port, protocol, source and destination
 * against the previous hit and treated a match as one event repeated.
 * Checked most likely to differ first. */
static gboolean
hit_is_redundant (const FsHit *hit)
{
	if (hit == NULL || last_dst == NULL ||
	    hit->port == NULL || hit->protocol == NULL ||
	    hit->source == NULL || hit->destination == NULL)
		return FALSE;

	if (g_strcmp0 (hit->port, last_port) != 0)
		return FALSE;

	if (g_strcmp0 (hit->protocol, last_proto) != 0)
		return FALSE;

	if (g_strcmp0 (hit->source, last_src) != 0)
		return FALSE;

	return g_strcmp0 (hit->destination, last_dst) == 0;
}

static void
remember_hit (const FsHit *hit)
{
	if (hit == NULL)
		return;

	g_free (last_port);
	g_free (last_proto);
	g_free (last_src);
	g_free (last_dst);

	last_port  = g_strdup (hit->port);
	last_proto = g_strdup (hit->protocol);
	last_src   = g_strdup (hit->source);
	last_dst   = g_strdup (hit->destination);
}

/* Local addresses are refreshed on a timer rather than read per event:
 * the Windows implementation asks GetAdaptersAddresses, which is far
 * too heavy to call for every packet in a flood. */
static GList  *local_addresses = NULL;
static gint64  local_addresses_checked = 0;

static GList *
current_local_addresses (void)
{
	const gint64 now = g_get_monotonic_time ();

	if (local_addresses == NULL || now - local_addresses_checked > 10 * G_USEC_PER_SEC) {
		g_list_free_full (local_addresses,
		                  (GDestroyNotify) fs_interface_free);
		local_addresses = fs_backend ()->list_interfaces ();
		local_addresses_checked = now;
	}

	return local_addresses;
}

/* [ hit_is_for_me ]
 * TRUE when the destination is one of this machine's own addresses.
 *
 * The original compared against the single external interface's IP.
 * Asking every interface is both more accurate and something that can
 * work on Windows, which has no one "external device" to query.  The
 * useful effect is the same: broadcast and multicast destinations are
 * not us, so discovery noise stops flooding the list. */
static gboolean
hit_is_for_me (const FsHit *hit)
{
	GList *ifaces;
	gboolean found = FALSE;

	if (hit == NULL || hit->destination == NULL)
		return FALSE;

	ifaces = current_local_addresses ();

	for (GList *l = ifaces; l != NULL; l = l->next) {
		FsInterface *iface = l->data;

		if (iface->ip != NULL &&
		    g_ascii_strcasecmp (iface->ip, hit->destination) == 0) {
			found = TRUE;
			break;
		}
	}

	return found;
}

/* [ on_hit ]
 * Backend log callback.  Runs on the main loop because the backend
 * delivers through a GLib source. */
static void
on_hit (const FsHit *hit, gpointer user_data)
{
	gboolean blocked;

	/* Both filters run before anything is counted, as they did in the
	 * original. */
	if (fs_prefs_bool (FS_PREFS_SKIP_REDUNDANT) &&
	    hit_is_redundant (hit))
		return;

	if (fs_prefs_bool (FS_PREFS_SKIP_NOT_FOR_FIREWALL) &&
	    !hit_is_for_me (hit) && !hit_is_outbound (hit))
		return;

	if (!fs_hitview_append (hit))
		return;

	blocked = hit_is_blocked (hit);
	remember_hit (hit);

	/* The Activity page counts exactly what this list shows. */
	fs_activityview_note_hit (hit);

	/* Feed to copilot for learning and anomaly detection. */
	extern FsCopilot *copilot;
	if (copilot != NULL) {
		fs_copilot_feed_event (copilot, hit);
		/* The baseline changed: the next periodic save writes it. */
		fs_app_note_learning ();
	}

	/* Sentinel auto-block: in auto mode a fresh beacon insight is
	 * staged into the policy right here, not the next time someone
	 * opens the Copilot page.  The pass itself is a cheap walk; the
	 * insight list is only rebuilt when a block was actually staged. */
	if (fs_copilot_sentinel_auto_pass ())
		fs_copilot_view_refresh ();

	/* Update copilot stats counter. */
	fs_copilot_note_event ();

	/* Status page counters.  These were declared but never called,
	 * which is why the panel always read 0. */
	if (hit_is_inbound (hit))
		fs_statusview_event_in (blocked);
	else
		fs_statusview_event_out (blocked);

	/* And the Overview's Recent blocks card. */
	if (blocked)
		fs_statusview_note_block (hit);
}

/* ---- history ------------------------------------------------------- */

gchar *
fs_hitview_history_dir (void)
{
	return fs_eventlog_default_dir ();
}

const gchar *
fs_hitview_history_problem (void)
{
	if (elog != NULL && fs_eventlog_problem (elog) != NULL)
		return fs_eventlog_problem (elog);
	return history_problem;
}

guint
fs_hitview_history_loaded (void)
{
	return history_loaded;
}

static void set_monitor_warning (const gchar *reason);
static gboolean monitor_warning_is (const gchar *text);
static const gchar *monitor_warning_text (void);

/* [ history_warning_sync ]
 * The strip says so as soon as history stops being saved, at the page
 * build or in the middle of a session (a full disk), and the warning
 * goes when writing works again.  The flush tick used to drop the
 * error, so history could stop for the rest of the session with
 * nothing on the page. */
static void
history_warning_sync (void)
{
	const gchar *problem = fs_hitview_history_problem ();

	if (problem != NULL) {
		guint64 lost = elog != NULL ? fs_eventlog_dropped (elog) : 0;
		gchar *msg = lost > 0
			? g_strdup_printf (
				_("Event history is not being saved: %s.  Trying "
				  "again; %" G_GUINT64_FORMAT " events not "
				  "saved so far."), problem, lost)
			: g_strdup_printf (
				_("Event history is not being saved: %s"),
				problem);

		if (g_strcmp0 (msg, history_warning) != 0) {
			if (history_warning == NULL) {
				g_free (history_warning_was);
				history_warning_was =
					g_strdup (monitor_warning_text ());
			}
			set_monitor_warning (msg);
			g_free (history_warning);
			history_warning = msg;
		} else {
			g_free (msg);
		}
		return;
	}

	if (history_warning != NULL) {
		if (monitor_warning_is (history_warning))
			set_monitor_warning (history_warning_was);
		g_clear_pointer (&history_warning, g_free);
		g_clear_pointer (&history_warning_was, g_free);
	}
}

static gboolean
on_history_flush (gpointer data)
{
	(void) data;

	if (elog != NULL)
		fs_eventlog_flush (elog, NULL);
	history_warning_sync ();
	return G_SOURCE_CONTINUE;
}

static void
history_close (void)
{
	if (elog_flush_id != 0) {
		g_source_remove (elog_flush_id);
		elog_flush_id = 0;
	}
	if (elog_retry_id != 0) {
		g_source_remove (elog_retry_id);
		elog_retry_id = 0;
	}
	if (elog != NULL) {
		fs_eventlog_close (elog);
		elog = NULL;
	}
}

static void history_open (void);

/* [ on_history_retry ]
 * Another copy of StockFW had the history (FS_EVENTLOG_ERROR_IN_USE):
 * try again every few seconds, so this copy takes over writing once
 * that one has gone, and the page stops saying it does not save. */
static gboolean
on_history_retry (gpointer data)
{
	(void) data;

	elog_retry_id = 0;
	history_open ();
	history_warning_sync ();
	return G_SOURCE_REMOVE;
}

/* [ history_open ]
 * Opens the history folder under the saved limits, or closes it when
 * history is switched off.  Opening prunes it to the limits. */
static void
history_open (void)
{
	guint days = fs_prefs_uint (FS_PREFS_EVENTS_HISTORY_DAYS,
	                            FS_EVENTLOG_MIN_DAYS, FS_EVENTLOG_MAX_DAYS);
	guint mb = fs_prefs_uint (FS_PREFS_EVENTS_HISTORY_MB,
	                          FS_EVENTLOG_MIN_MB, FS_EVENTLOG_MAX_MB);

	if (!fs_prefs_bool (FS_PREFS_EVENTS_HISTORY)) {
		history_close ();
		g_clear_pointer (&history_problem, g_free);
		return;
	}

	if (elog != NULL) {
		fs_eventlog_set_limits (elog, days, (guint64) mb * 1024 * 1024);
		return;
	}

	{
		gchar *dir = fs_eventlog_default_dir ();
		GError *error = NULL;

		elog = fs_eventlog_open (dir, days, (guint64) mb * 1024 * 1024,
		                         &error);
		g_clear_pointer (&history_problem, g_free);
		if (elog == NULL)
			history_problem = g_strdup (error != NULL ? error->message
			                                          : dir);
		if (elog == NULL &&
		    g_error_matches (error, FS_EVENTLOG_ERROR,
		                     FS_EVENTLOG_ERROR_IN_USE) &&
		    elog_retry_id == 0)
			elog_retry_id = g_timeout_add_seconds (
				5, on_history_retry, NULL);
		g_clear_error (&error);
		g_free (dir);
	}

	if (elog != NULL && elog_flush_id == 0)
		elog_flush_id = g_timeout_add_seconds (1, on_history_flush, NULL);
}

void
fs_hitview_shutdown (void)
{
	history_close ();
}

void
fs_hitview_flush_history (void)
{
	if (elog != NULL)
		fs_eventlog_flush (elog, NULL);
}

guint
fs_hitview_clear_history (GError **error)
{
	gchar *dir;
	guint removed;

	if (elog != NULL)
		return fs_eventlog_clear (elog, error);

	/* Not the writer.  fs_eventlog_clear_dir deletes nothing (and says
	 * FS_EVENTLOG_ERROR_IN_USE) while another copy holds the history:
	 * that copy would go on writing into the file deleted under it. */
	dir = fs_eventlog_default_dir ();
	removed = fs_eventlog_clear_dir (dir, error);
	g_free (dir);
	return removed;
}

/* [ fs_hitview_apply_settings ]
 * After Preferences > Events was saved.  A smaller list drops its
 * oldest events at once; that is done with the model detached, so
 * 100,000 drops are one rebuild and not 100,000 row-deleted signals. */
void
fs_hitview_apply_settings (void)
{
	guint cap = fs_prefs_uint (FS_PREFS_EVENTS_MAX,
	                           FS_EVENTSTORE_MIN_CAPACITY,
	                           FS_EVENTSTORE_MAX_CAPACITY);

	/* No Events page (a test, or the page not built yet): nothing to
	 * resize, and the history is opened when the page is built. */
	if (estore == NULL)
		return;

	history_open ();

	if (cap == fs_eventstore_capacity (estore))
		return;

	model_detach ();
	fs_eventstore_set_evict_func (estore, NULL, NULL);
	fs_eventstore_set_capacity (estore, cap);
	g_object_unref (emodel);
	emodel = fs_event_model_new (estore);
	fs_hitview_refilter_now ();       /* the filter, and attach */
	model_attach ();
	update_count_label ();
}

gboolean
fs_hitview_append (const FsHit *hit)
{
	guint64 seq;

	if (estore == NULL || hit == NULL)
		return FALSE;

	/* The same row twice is one event, not two: the backend forgets
	 * its seen-set when monitoring restarts, and the trailing window
	 * comes back to a list that still holds those rows (and, since
	 * 1.0.7, to history read back at start).  The store refuses it. */
	seq = fs_eventstore_append (estore, hit, g_get_real_time ());
	if (seq == 0)
		return FALSE;

	if (elog != NULL)
		fs_eventlog_append (elog, hit, fs_eventstore_ticks (estore, seq));

	/* Placed by time (or the chosen column), not by arrival: a batch
	 * comes newest first.  No follow-scroll: the newest row goes to
	 * the TOP, where a list parked at the top already looks, and a
	 * reader further down is reading history and must not be yanked
	 * anywhere. */
	fs_event_model_note_append (emodel, seq);

	update_count_label ();

	return TRUE;
}

guint
fs_hitview_count (void)
{
	return estore != NULL ? fs_eventstore_length (estore) : 0;
}

void
fs_hitview_set_policy (FsPolicy *policy)
{
	hitview_policy = policy;
}

void
fs_hitview_clear (void)
{
	if (estore != NULL) {
		model_detach ();
		/* The rows go, and so does what they stood for: a Reload
		 * re-reads the tail instead of suppressing it as a
		 * duplicate.  The history files are not touched. */
		fs_eventstore_clear (estore);
		fs_event_model_rebuild (emodel);
		model_attach ();
	}

	update_count_label ();
}

/* [ set_monitor_warning ]
 * The reason monitoring cannot run, shown as a strip above the list.
 * It stays on the page rather than flashing past in a dialog, because
 * the user needs the cause to still be there when they look again and
 * an empty list with no explanation is indistinguishable from a
 * firewall with nothing to report.  NULL clears it. */
static void
set_monitor_warning (const gchar *reason)
{
	if (monitor_warning == NULL)
		return;

	if (reason == NULL) {
		gtk_widget_hide (monitor_warning);
		return;
	}

	gtk_label_set_text (GTK_LABEL (monitor_warning_label), reason);
	gtk_widget_show (monitor_warning);
}

/* What the strip says, or NULL when it is not up. */
static const gchar *
monitor_warning_text (void)
{
	if (monitor_warning == NULL || !gtk_widget_get_visible (monitor_warning))
		return NULL;
	return gtk_label_get_text (GTK_LABEL (monitor_warning_label));
}

/* TRUE when the strip is up and says text. */
static gboolean
monitor_warning_is (const gchar *text)
{
	return text != NULL && g_strcmp0 (monitor_warning_text (), text) == 0;
}

void
fs_hitview_reload (void)
{
	GError *error = NULL;

	/* The list is a live tail, not a file to re-read: restarting the
	 * source is the equivalent of a reload. */
	fs_hitview_clear ();
	fs_hitview_stop  ();

	if (!fs_hitview_start (&error)) {
		set_monitor_warning (error != NULL
		                     ? error->message
		                     : _("Monitoring could not be restarted."));
		g_clear_error (&error);
	}
}

gboolean
fs_hitview_start (GError **error)
{
	const FsBackend *backend = fs_backend ();

	gboolean ok;

	if (fs_hitview_active ())
		return TRUE;

	ok = backend->log_start (on_hit, NULL, error);
	update_count_label ();     /* the empty list's wording follows */
	return ok;
}

void
fs_hitview_stop (void)
{
	if (fs_hitview_active ())
		fs_backend ()->log_stop ();
	update_count_label ();
}

gboolean
fs_hitview_active (void)
{
	return fs_backend ()->log_active ();
}

const FsHit *
fs_hitview_selected (void)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	static FsHit *hit = NULL;     /* valid until the next call */
	guint64 seq;

	if (view == NULL || emodel == NULL)
		return NULL;

	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (view));

	if (!gtk_tree_selection_get_selected (selection, &model, &iter))
		return NULL;

	seq = fs_event_model_iter_seq (emodel, &iter);
	if (seq == 0)
		return NULL;

	g_clear_pointer (&hit, fs_hit_free);
	hit = fs_eventstore_get_hit (estore, seq);

	return hit;
}

/* ---- right-click: Event -> Rule -----------------------------------
 *
 * The menu offers only what the event can actually express: outbound
 * events can block/allow their destination or its service, inbound
 * events can trust their source (or drop that trust again).  Every
 * action follows the same confirm -> add -> save (rollback on
 * failure) -> reload -> push ceremony the Copilot uses, and the
 * result message says honestly whether the change reached the
 * firewall. */

/* [ push_policy ]
 * Put the policy in front of the actual firewall and report the
 * outcome without spin: staged is staged, live is live, and a
 * rolled-back failure says so. */
static void
push_policy (const gchar *what, const gchar *csv)
{
	GError *error = NULL;
	FsApplyOutcome *outcome = fs_policy_apply_safe (
		fs_backend (), hitview_policy, "event menu",
		fs_policyview_hold_reason (), &error);
	gchar *msg;

	if (outcome->held) {
		msg = g_strdup_printf (
			_("%s\n\nRule: %s\n\nSaved in the policy and written "
			  "to the audit log, but held back (%s) -- the "
			  "firewall was deliberately not touched."),
			what, csv != NULL ? csv : "-", outcome->hold_reason);
		fs_dialogs_info (NULL, _("Policy updated, held"), msg);
	} else if (outcome->applied) {
		msg = g_strdup_printf (_("%s\n\nRule: %s\n\n%s"),
		                       what, csv != NULL ? csv : "-",
		                       fs_util_apply_result_to_string (
		                               (int) outcome->result));
		fs_dialogs_info (NULL, _("Policy updated"), msg);
	} else {
		const gchar *rollback;

		if (outcome->rollback_attempted &&
		    outcome->rollback_verified)
			rollback = _(" The firewall was restored to the last "
			              "applied policy and that restore was "
			              "verified.");
		else if (outcome->rollback_attempted)
			rollback = _(" The rollback ALSO failed: the firewall "
			              "may be in an inconsistent state -- check "
			              "the Status page.");
		else
			rollback = _(" There is no recorded previously "
			              "applied policy, so nothing could be "
			              "restored.");

		msg = g_strdup_printf (
			_("%s\n\nRule: %s\n\nSaved in the policy but NOT live "
			  "yet: %s.%s Run StockFW as administrator and apply "
			  "the policy to activate it."),
			what, csv != NULL ? csv : "-",
			fs_util_apply_result_to_string ((int) outcome->result),
			rollback);
		fs_dialogs_info (NULL, _("Policy updated, not live yet"), msg);
	}

	g_free (msg);
	g_clear_error (&error);
	fs_apply_outcome_free (outcome);
}

/* [ confirm_stage ]
 * The confirm step, carrying the Direction setting for kinds that have
 * a twin.  The default entry is the rule's own direction: one rule is
 * the narrower grant, so the pair has to be asked for, never slipped
 * in.  Returns whether to stage; *bidirectional follows the combo and
 * is FALSE whenever the setting does not apply. */
static gboolean
confirm_stage (const gchar *question, const gchar *direction_label,
               gboolean *bidirectional)
{
	GtkWidget *dialog;
	GtkWidget *content;
	GtkWidget *label;
	GtkWidget *row;
	GtkWidget *combo;
	gint response;

	*bidirectional = FALSE;

	if (direction_label == NULL) {
		gboolean confirmed = FALSE;

		fs_dialogs_confirm (NULL, question, &confirmed);
		return confirmed;
	}

	dialog = gtk_dialog_new_with_buttons (
		_("Stage this rule"), NULL, GTK_DIALOG_MODAL,
		_("_Cancel"), GTK_RESPONSE_CANCEL,
		_("_Stage"), GTK_RESPONSE_OK,
		NULL);

	content = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
	gtk_container_set_border_width (GTK_CONTAINER (content), 8);
	gtk_box_set_spacing (GTK_BOX (content), 8);

	label = gtk_label_new (question);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	gtk_label_set_max_width_chars (GTK_LABEL (label), 60);
	gtk_box_pack_start (GTK_BOX (content), label, FALSE, FALSE, 0);

	row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_box_pack_start (GTK_BOX (row), gtk_label_new (_("Direction:")),
	                    FALSE, FALSE, 0);

	combo = gtk_combo_box_text_new ();
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo),
	                                direction_label);
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo),
	                                _("Bi-directional"));
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0);
	gtk_box_pack_start (GTK_BOX (row), combo, TRUE, TRUE, 0);
	gtk_box_pack_start (GTK_BOX (content), row, FALSE, FALSE, 0);

	gtk_widget_show_all (content);
	response = gtk_dialog_run (GTK_DIALOG (dialog));

	*bidirectional = (response == GTK_RESPONSE_OK &&
	                  gtk_combo_box_get_active (
	                 	GTK_COMBO_BOX (combo)) == 1);

	gtk_widget_destroy (dialog);

	return response == GTK_RESPONSE_OK;
}

/* [ stage_rule ]
 * Confirm one rule built from the selected event, persist it (with its
 * twin when the Direction setting asked for one) and push it.  Takes
 * ownership of rule. */
static void
stage_rule (FsRule *rule, const gchar *what)
{
	gchar *csv;
	gchar *question;
	gboolean confirmed = FALSE;
	gboolean bidirectional = FALSE;
	gboolean present;
	const gchar *direction_label;
	FsRule *counterpart = NULL;

	if (rule == NULL)
		return;

	if (hitview_policy == NULL) {
		fs_rule_free (rule);
		fs_dialogs_error (NULL, _("No policy is loaded"),
		                  _("Open the Policy page first; without a "
		                    "policy there is nowhere to stage this rule."));
		return;
	}

	csv     = fs_rule_to_csv (rule);
	present = fs_policy_contains (hitview_policy, rule);

	question = g_strdup_printf (
		"%s\n\nRule: %s\n\nThe rule is added to your policy and saved "
		"to disk, then pushed to the firewall.",
		what, csv != NULL ? csv : "?");

	direction_label = fs_rule_direction_label (rule->kind);
	confirmed = confirm_stage (question, direction_label, &bidirectional);
	g_free (question);

	if (!confirmed) {
		fs_rule_free (rule);
		g_free (csv);
		return;
	}

	if (present) {
		gchar *msg = g_strdup_printf (
			_("The rule is already in your policy, nothing was added:"
			  "\n\n%s"), csv != NULL ? csv : "-");

		fs_dialogs_info (NULL, _("Already in the policy"), msg);
		g_free (msg);
		fs_rule_free (rule);
		g_free (csv);
		return;
	}

	/* The twin: same host or service, opposite direction.  A NULL here
	 * would silently stage one direction while the dialog said two. */
	if (bidirectional) {
		counterpart = fs_rule_counterpart (rule);
		if (counterpart == NULL)
			bidirectional = FALSE;
	}

	/* Save the pair as one change, rolling the store back when the
	 * write fails, so the Policy page and the disk never disagree. */
	if (!fs_policy_add_persist_pair (hitview_policy, rule, counterpart)) {
		fs_dialogs_error (NULL, _("Could not save the rule"),
		                  counterpart != NULL
		                  ? _("Neither half of the bi-directional "
		                    "pair was written to disk, so the "
		                    "policy was left as it was. Nothing "
		                    "changed.")
		                  : _("The rule was not written to disk, so it "
		                    "was taken back out of the policy. Nothing "
		                    "changed."));
		fs_rule_free (counterpart);
		fs_rule_free (rule);
		g_free (csv);
		return;
	}

	/* P6: the user's Allow is the last word for this destination --
	 * on Windows a block rule outranks an allow rule, so a Sentinel
	 * block left standing would make this Allow a silent no-op (the
	 * "user's Allow lost silently" half of the 2026-10-10 incident).
	 * Staged auto-blocks and Sentinel's own persisted rows for the
	 * destination go; the push below takes the Allow and that
	 * removal to the firewall together.  Runs only on the success
	 * path, so the "Nothing changed" refusal above stays true. */
	if (rule->kind == FS_RULE_OUTBOUND_ALLOW_TO && rule->target != NULL)
		fs_copilot_lift_auto_blocks_for_dest (rule->target);

	fs_rule_free (rule);
	fs_policyview_reload (hitview_policy);
	fs_audit_log ("event rule added", csv);

	if (counterpart != NULL) {
		gchar *cp_csv = fs_rule_to_csv (counterpart);
		gchar *both;

		fs_audit_log ("event rule added (bi-directional twin)",
		              cp_csv);
		both = g_strdup_printf ("%s\n%s", csv,
		                        cp_csv != NULL ? cp_csv : "?");
		g_free (cp_csv);
		fs_rule_free (counterpart);
		push_policy (what, both);
		g_free (both);
	} else {
		push_policy (what, csv);
	}

	g_free (csv);
}

/* [ on_menu_rule_activated ] */
static void
on_menu_rule_activated (GtkMenuItem *item, gpointer data)
{
	FsEventRuleAction action = GPOINTER_TO_INT (data);
	const FsHit *hit = fs_hitview_selected ();
	FsRule *rule;
	gchar *what = NULL;

	(void) item;

	if (hit == NULL)
		return;

	rule = fs_eventrule_build (hit, action);
	if (rule == NULL)
		return;

	switch (action) {
	case FS_EVENTRULE_BLOCK_DEST:
		what = g_strdup_printf (_("Block all traffic to %s"),
		                        hit->destination);
		break;
	case FS_EVENTRULE_ALLOW_DEST:
		what = g_strdup_printf (_("Allow traffic to %s"),
		                        hit->destination);
		break;
	case FS_EVENTRULE_BLOCK_SERVICE:
		what = g_strdup_printf (
			_("Block %s to %s"),
			(hit->service != NULL && *hit->service != '\0')
				? hit->service : (hit->port ? hit->port : "?"),
			hit->destination);
		break;
	case FS_EVENTRULE_TRUST_SOURCE:
		what = g_strdup_printf (
			_("Trust %s for inbound traffic"), hit->source);
		break;
	default:
		fs_rule_free (rule);
		return;
	}

	stage_rule (rule, what);
	g_free (what);
}

/* [ on_menu_untrust_activated ]
 * The inbound mirror: there is no inbound DENY kind, so "untrust" is
 * removing the stored allow -- default-deny already does the
 * blocking. */
static void
on_menu_untrust_activated (GtkMenuItem *item, gpointer data)
{
	const FsHit *hit = fs_hitview_selected ();
	FsRule *existing;
	gchar *source;
	gchar *question;
	gboolean confirmed = FALSE;

	(void) item;
	(void) data;

	if (hit == NULL || hitview_policy == NULL)
		return;

	existing = fs_eventrule_find_trust (hitview_policy, hit);
	if (existing == NULL) {
		fs_dialogs_info (NULL, _("Source is not trusted"),
		                  _("No inbound allow exists for this source, "
		                    "so the default-deny inbound policy already "
		                    "blocks it."));
		return;
	}

	/* The store frees its copy on removal, so keep the address for
	 * the messages first. */
	source  = g_strdup (existing->target);
	question = g_strdup_printf (
		_("Remove the inbound allow for %s?\n\nThe default-deny "
		  "inbound policy blocks it again as soon as the change is "
		  "applied."), source != NULL ? source : "?");

	fs_dialogs_confirm (NULL, question, &confirmed);
	g_free (question);

	if (!confirmed) {
		g_free (source);
		return;
	}

	if (!fs_eventrule_untrust (hitview_policy, hit)) {
		fs_dialogs_error (NULL, _("Could not remove the rule"),
		                  _("The change was not written to disk, so "
		                    "the allow rule was kept. Nothing changed."));
		g_free (source);
		return;
	}

	fs_policyview_reload (hitview_policy);
	fs_audit_log ("event trust removed", source);

	push_policy (_("Inbound allow removed"), source);
	g_free (source);
}

/* [ on_view_button_press ]
 * Right-click selects the row under the cursor and pops the menu of
 * actions that fit this event's direction. */
static gboolean
on_view_button_press (GtkWidget *widget, GdkEventButton *event,
                      gpointer data)
{
	GtkWidget *menu;
	const FsHit *hit;
	gboolean added = FALSE;

	(void) data;

	if (event->type != GDK_BUTTON_PRESS || event->button != 3)
		return FALSE;

	{
		GtkTreePath *path = NULL;

		if (gtk_tree_view_get_path_at_pos (GTK_TREE_VIEW (widget),
		                                   (gint) event->x,
		                                   (gint) event->y,
		                                   &path, NULL, NULL, NULL)) {
			gtk_tree_view_set_cursor (GTK_TREE_VIEW (widget), path,
			                          NULL, FALSE);
			gtk_tree_path_free (path);
		}
	}

	hit = fs_hitview_selected ();
	if (hit == NULL)
		return FALSE;

	menu = gtk_menu_new ();

	if (hit_is_outbound (hit) &&
	    hit->destination != NULL && *hit->destination != '\0') {
		GtkWidget *item;
		gchar *label;

		label = g_strdup_printf (_("Block %s (all traffic)"),
		                         hit->destination);
		item = gtk_menu_item_new_with_label (label);
		g_free (label);
		g_signal_connect (item, "activate",
		                  G_CALLBACK (on_menu_rule_activated),
		                  GINT_TO_POINTER (FS_EVENTRULE_BLOCK_DEST));
		gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
		added = TRUE;

		label = g_strdup_printf (_("Allow %s (all traffic)"),
		                         hit->destination);
		item = gtk_menu_item_new_with_label (label);
		g_free (label);
		g_signal_connect (item, "activate",
		                  G_CALLBACK (on_menu_rule_activated),
		                  GINT_TO_POINTER (FS_EVENTRULE_ALLOW_DEST));
		gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);

		if (hit->port != NULL && *hit->port != '\0') {
			label = g_strdup_printf (
				_("Block this service to %s"), hit->destination);
			item = gtk_menu_item_new_with_label (label);
			g_free (label);
			g_signal_connect (item, "activate",
			                  G_CALLBACK (on_menu_rule_activated),
			                  GINT_TO_POINTER (
			                  FS_EVENTRULE_BLOCK_SERVICE));
			gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
		}
	} else if (hit_is_inbound (hit) &&
	           hit->source != NULL && *hit->source != '\0') {
		GtkWidget *item;
		gchar *label;

		if (hitview_policy != NULL &&
		    fs_eventrule_find_trust (hitview_policy, hit) != NULL) {
			label = g_strdup_printf (
				_("Remove trust for %s"), hit->source);
			item = gtk_menu_item_new_with_label (label);
			g_free (label);
			g_signal_connect (item, "activate",
			                  G_CALLBACK (
			                  on_menu_untrust_activated),
			                  NULL);
		} else {
			label = g_strdup_printf (
				_("Trust %s (inbound allow)"), hit->source);
			item = gtk_menu_item_new_with_label (label);
			g_free (label);
			g_signal_connect (item, "activate",
			                  G_CALLBACK (on_menu_rule_activated),
			                  GINT_TO_POINTER (
			                  FS_EVENTRULE_TRUST_SOURCE));
		}

		gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
		added = TRUE;
	}

	if (!added) {
		gtk_widget_destroy (menu);
		return FALSE;
	}

	gtk_widget_show_all (menu);
	gtk_menu_popup_at_pointer (GTK_MENU (menu), (GdkEvent *) event);

	return TRUE;
}

/* [ on_clear_clicked ] */
static void
on_clear_clicked (GtkButton *button, gpointer data)
{
	fs_hitview_clear ();
}

/* [ on_reload_clicked ] */
static void
on_reload_clicked (GtkButton *button, gpointer data)
{
	fs_hitview_reload ();
}

/* [ on_monitor_watchdog ]
 * The source can stop on its own (a log reader that exits, a kernel
 * log that becomes unreadable).  Every two seconds: if the switch says
 * "on" but nothing is reading, say why and turn the switch off, rather
 * than leaving an empty list that looks like a quiet network.  While
 * the list is empty the empty-state wording also follows the firewall
 * state (started or stopped elsewhere). */
static gboolean
on_monitor_watchdog (gpointer data)
{
	const FsBackend *backend = fs_backend ();

	(void) data;

	if (monitor_toggle == NULL) {
		monitor_watchdog = 0;
		return G_SOURCE_REMOVE;
	}

	if (gtk_switch_get_active (GTK_SWITCH (monitor_toggle)) &&
	    !fs_hitview_active ()) {
		const gchar *why = backend->log_problem != NULL
		                   ? backend->log_problem () : NULL;

		set_monitor_warning (why != NULL
		                     ? why
		                     : _("Event monitoring stopped."));
		gtk_switch_set_active (GTK_SWITCH (monitor_toggle), FALSE);
	}

	if ((fs_hitview_count () == 0 && gtk_widget_get_mapped (monitor_toggle)) ||
	    monitor_skipped () != skipped_shown)
		update_count_label ();

	return G_SOURCE_CONTINUE;
}

/* [ on_start_toggled ]
 * Starts or stops the event source.  The control is a GtkSwitch now
 * (the spec's "toggle switch for Monitor"), so it reports through
 * notify::active rather than a button's toggled. */
static void
on_start_toggled (GtkSwitch *sw, GParamSpec *pspec, gpointer data)
{
	GError *error = NULL;

	(void) pspec;
	(void) data;

	if (gtk_switch_get_active (sw)) {
		if (!fs_hitview_start (&error)) {
			fs_dialogs_error (NULL,
			                  _("Could not monitor firewall events"),
			                  error ? error->message : NULL);
			set_monitor_warning (error != NULL
			                     ? error->message
			                     : _("Monitoring could not start."));
			g_clear_error (&error);

			/* Leave the switch off rather than pretending to
			 * monitor.  The re-entry sees FALSE and calls stop
			 * on a source that never started -- a no-op. */
			gtk_switch_set_active (sw, FALSE);
			return;
		}

		set_monitor_warning (NULL);
	} else {
		fs_hitview_stop ();
	}
}

/* [ filter_box ] -- a narrow entry in the filter row. */
static GtkWidget *
filter_box (GtkWidget *row, const gchar *name, const gchar *placeholder,
            const gchar *tip, gint width_chars)
{
	GtkWidget *entry = gtk_entry_new ();

	gtk_widget_set_name (entry, name);
	gtk_entry_set_placeholder_text (GTK_ENTRY (entry), placeholder);
	gtk_entry_set_width_chars (GTK_ENTRY (entry), width_chars);
	g_object_set_data_full (G_OBJECT (entry), "fs-tip", g_strdup (tip),
	                        g_free);
	gtk_widget_set_tooltip_text (entry, tip);
	atk_object_set_name (gtk_widget_get_accessible (entry), placeholder);
	g_signal_connect (entry, "changed", G_CALLBACK (on_filter_changed), NULL);
	gtk_box_pack_start (GTK_BOX (row), entry, FALSE, FALSE, 0);
	return entry;
}

static GtkWidget *
filter_combo (GtkWidget *row, const gchar *name, const gchar *const *items)
{
	GtkWidget *combo = gtk_combo_box_text_new ();

	gtk_widget_set_name (combo, name);
	for (guint i = 0; items[i] != NULL; i++)
		gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (combo),
		                                _(items[i]));
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), 0);
	gtk_widget_set_valign (combo, GTK_ALIGN_CENTER);
	g_signal_connect (combo, "changed", G_CALLBACK (on_filter_changed), NULL);
	gtk_box_pack_start (GTK_BOX (row), combo, FALSE, FALSE, 0);
	return combo;
}

/* [ build_store ]
 * The store at the size Preferences gives, filled from history when
 * history is kept, then the model over it. */
static void
build_store (void)
{
	guint cap = fs_prefs_uint (FS_PREFS_EVENTS_MAX,
	                           FS_EVENTSTORE_MIN_CAPACITY,
	                           FS_EVENTSTORE_MAX_CAPACITY);

	if (estore != NULL)
		return;

	estore = fs_eventstore_new (cap);
	history_loaded = 0;

	history_open ();
	if (elog != NULL) {
		FsEventLogStats stats;

		history_loaded = fs_eventlog_load_recent (fs_eventlog_dir (elog),
		                                          estore, cap, &stats);
	}

	emodel = fs_event_model_new (estore);
}

/* Fixed widths, so the view can run in fixed-height mode: it never
 * measures rows it is not drawing.  Resizable all the same. */
static const gint column_width[FS_NUM_HITCOLUMNS] = {
	120, 80, 70, 70, 70, 190, 190, 70, 60, 80, 170, 0
};

GtkWidget *
fs_hitview_page (void)
{
	GtkWidget *page, *scroll, *button_box, *button, *toggle;
	GtkWidget *header, *image, *frow;

	build_store ();

	page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);

	/* Sub-header utility bar: live counter, filter, monitor switch,
	 * Clear and Refresh, as the spec has them. */
	header = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_style_context_add_class (gtk_widget_get_style_context (header),
	                             "events-toolbar");

	count_label = gtk_label_new ("0 events");
	gtk_label_set_xalign (GTK_LABEL (count_label), 0.0);
	gtk_style_context_add_class (gtk_widget_get_style_context (count_label),
	                             "events-count");
	/* The label absorbs the slack, which parks the filter bar
	 * directly left of the Monitor/Clear/Refresh group -- where the
	 * bar has sat since 1.0.4, and where it goes back to after a
	 * centreing experiment moved it mid-bar. */
	gtk_box_pack_start (GTK_BOX (header), count_label, TRUE, TRUE, 0);

	/* Search.  SearchEntry, so Escape clears and the list filters
	 * once typing pauses. */
	filter_entry = gtk_search_entry_new ();
	gtk_widget_set_name (filter_entry, "events-filter-text");
	gtk_entry_set_placeholder_text (
		GTK_ENTRY (filter_entry),
		_("Search events (time, host, port, service)"));
	gtk_widget_set_tooltip_text (
		filter_entry,
		_("Shows the rows where a column contains this text, in any "
		  "case: the time as shown, direction, devices, port, "
		  "addresses, length, ToS, protocol or service."));
	gtk_widget_set_size_request (filter_entry, 260, -1);
	g_signal_connect (filter_entry, "search-changed",
	                  G_CALLBACK (on_search_changed), NULL);
	gtk_box_pack_start (GTK_BOX (header), filter_entry, FALSE, FALSE, 0);

	button_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);

	/* Monitor: a switch, not a checkbox -- the spec's toggle. */
	{
		GtkWidget *mlabel = gtk_label_new_with_mnemonic (_("_Monitor"));

		gtk_box_pack_start (GTK_BOX (button_box), mlabel, FALSE,
		                    FALSE, 0);

		toggle = gtk_switch_new ();
		/* A horizontal GtkBox allocates every child the full row
		 * height (the pack "fill" flag is main-axis only, and the
		 * default valign is FILL), so the 46x22 switch would
		 * stretch to the taller search entry beside it and render
		 * as a tall blob.  Center it at its natural size instead. */
		gtk_widget_set_valign (toggle, GTK_ALIGN_CENTER);
		g_signal_connect (toggle, "notify::active",
		                  G_CALLBACK (on_start_toggled), NULL);
		gtk_box_pack_start (GTK_BOX (button_box), toggle, FALSE,
		                    FALSE, 0);
	}

	button = gtk_button_new_with_mnemonic (_("_Clear"));
	gtk_style_context_add_class (gtk_widget_get_style_context (button),
	                             "btn-subtle");
	gtk_widget_set_tooltip_text (button,
		_("Empties the list.  Saved history is kept: delete it in "
		  "Preferences > Events."));
	g_signal_connect (button, "clicked", G_CALLBACK (on_clear_clicked),
	                  NULL);
	gtk_box_pack_start (GTK_BOX (button_box), button, FALSE, FALSE, 0);

	button = gtk_button_new_with_mnemonic (_("Re_fresh"));
	gtk_style_context_add_class (gtk_widget_get_style_context (button),
	                             "btn-subtle");
	g_signal_connect (button, "clicked", G_CALLBACK (on_reload_clicked),
	                  NULL);
	gtk_box_pack_start (GTK_BOX (button_box), button, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (header), button_box, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (page), header, FALSE, FALSE, 0);

	/* The filter row: the parts of an event that are worth narrowing
	 * by, each optional, all applied together. */
	frow = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_widget_set_name (frow, "events-filter-row");
	gtk_style_context_add_class (gtk_widget_get_style_context (frow),
	                             "events-toolbar");
	{
		static const gchar *const dirs[] = {
			N_("Both directions"), N_("Inbound"), N_("Outbound"), NULL
		};
		static const gchar *const actions[] = {
			N_("Blocked and allowed"), N_("Blocked"), N_("Allowed"), NULL
		};

		filter_direction = filter_combo (frow, "events-filter-direction",
		                                 dirs);
		filter_action = filter_combo (frow, "events-filter-action",
		                              actions);
	}
	filter_protocol = filter_box (frow, "events-filter-protocol",
		_("Protocol"), _("TCP, UDP, ICMP ... the whole name"), 7);
	filter_port = filter_box (frow, "events-filter-port", _("Port"),
		_("A port (443) or a range (1000-2000)"), 9);
	filter_address = filter_box (frow, "events-filter-address",
		_("Address or CIDR"),
		_("Source or destination: an address, a block such as "
		  "10.0.0.0/8 or 2001:db8::/32, or a range a-b"), 16);
	filter_since = filter_box (frow, "events-filter-since", _("From"),
		_("15m, 2h, 3d, 2026-11-01 or 2026-11-01 14:30 (local time)"),
		10);
	filter_until = filter_box (frow, "events-filter-until", _("To"),
		_("Before this time: 1h, 2026-11-01 (the whole day) or "
		  "2026-11-01 14:30"), 10);

	button = gtk_button_new_with_mnemonic (_("Rese_t"));
	gtk_widget_set_name (button, "events-filter-reset");
	gtk_style_context_add_class (gtk_widget_get_style_context (button),
	                             "btn-subtle");
	gtk_widget_set_tooltip_text (button, _("Clears every filter."));
	g_signal_connect (button, "clicked", G_CALLBACK (on_filter_reset), NULL);
	gtk_box_pack_start (GTK_BOX (frow), button, FALSE, FALSE, 0);

	filter_error = gtk_label_new (NULL);
	gtk_widget_set_name (filter_error, "events-filter-error");
	gtk_label_set_xalign (GTK_LABEL (filter_error), 0.0);
	gtk_label_set_ellipsize (GTK_LABEL (filter_error), PANGO_ELLIPSIZE_END);
	gtk_style_context_add_class (gtk_widget_get_style_context (filter_error),
	                             "pref-reason");
	gtk_widget_set_no_show_all (filter_error, TRUE);
	gtk_box_pack_start (GTK_BOX (frow), filter_error, TRUE, TRUE, 0);

	button = gtk_button_new_with_mnemonic (_("_Export CSV..."));
	gtk_widget_set_name (button, "events-export");
	gtk_style_context_add_class (gtk_widget_get_style_context (button),
	                             "btn-subtle");
	gtk_widget_set_tooltip_text (button,
		_("Saves the events the list shows, filtered and in this "
		  "order, as a CSV file."));
	g_signal_connect (button, "clicked", G_CALLBACK (on_export_clicked),
	                  NULL);
	gtk_box_pack_end (GTK_BOX (frow), button, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (page), frow, FALSE, FALSE, 0);

	/* Strip that carries the reason monitoring is not running.  Hidden
	 * by default, and marked no-show-all so gtk_widget_show_all() on
	 * the page does not reveal it before it has a reason to be seen. */
	monitor_warning = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	monitor_warning_label = gtk_label_new ("");
	gtk_label_set_xalign (GTK_LABEL (monitor_warning_label), 0.0);
	gtk_label_set_line_wrap (GTK_LABEL (monitor_warning_label), TRUE);

	/* The contents are shown once here and then left alone: only the
	 * strip itself is ever toggled.  no_show_all on the strip is what
	 * keeps the page-wide gtk_widget_show_all() from revealing a bare
	 * one, but that same flag stops the walk from reaching these
	 * children -- so letting show_all do it would render a blank bar
	 * exactly when a reason had to be read. */
	image = gtk_image_new_from_icon_name ("dialog-warning",
	                                      GTK_ICON_SIZE_BUTTON);
	gtk_widget_show (image);
	gtk_widget_show (monitor_warning_label);

	gtk_box_pack_start (GTK_BOX (monitor_warning), image, FALSE, FALSE, 0);
	gtk_box_pack_start (GTK_BOX (monitor_warning), monitor_warning_label,
	                    TRUE, TRUE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (monitor_warning), 6);
	gtk_style_context_add_class (
		gtk_widget_get_style_context (monitor_warning), "warning");
	gtk_style_context_add_class (
		gtk_widget_get_style_context (monitor_warning), "warning-strip");
	gtk_widget_set_no_show_all (monitor_warning, TRUE);
	gtk_box_pack_start (GTK_BOX (page), monitor_warning, FALSE, FALSE, 0);

	/* The list: a view over FsEventModel, which answers each cell from
	 * the store when it is drawn. */
	view = gtk_tree_view_new_with_model (GTK_TREE_MODEL (emodel));
	gtk_widget_set_name (view, "events-list");
	gtk_style_context_add_class (gtk_widget_get_style_context (view),
	                             "data-grid");
	/* Hairlines between rows only, as on the Overview. */
	gtk_tree_view_set_grid_lines (GTK_TREE_VIEW (view),
	                              GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);
	/* Type-ahead would walk every row looking for a match. */
	gtk_tree_view_set_enable_search (GTK_TREE_VIEW (view), FALSE);

	/* Right-click: Event -> Rule menu. */
	g_signal_connect (view, "button-press-event",
	                  G_CALLBACK (on_view_button_press), NULL);

	for (gint i = 0; i < FS_NUM_HITCOLUMNS; i++) {
		GtkCellRenderer *renderer;
		GtkTreeViewColumn *column;

		/* The colour column carries no text. */
		if (column_defs[i].label[0] == '\0')
			continue;

		renderer = gtk_cell_renderer_text_new ();

		/* Addresses and ports in a fixed-width face, so a column
		 * of them lines up digit for digit; words stay in the UI
		 * font. */
		if (i == COL_PORT || i == COL_SOURCE || i == COL_DESTINATION)
			g_object_set (renderer, "family", "monospace", NULL);
		g_object_set (renderer, "ellipsize", PANGO_ELLIPSIZE_END, NULL);

		column = gtk_tree_view_column_new_with_attributes (
			_(column_defs[i].label), renderer, "text", i, NULL);
		gtk_tree_view_column_set_resizable (column, TRUE);
		gtk_tree_view_column_set_sizing (column,
		                                 GTK_TREE_VIEW_COLUMN_FIXED);
		gtk_tree_view_column_set_fixed_width (column, column_width[i]);
		/* Click a heading to sort by it; again to reverse. */
		gtk_tree_view_column_set_sort_column_id (column, i);

		/* Every visible text column reads the colour column so a
		 * blocked event is red right across the row; the Time
		 * column also formats the stamp the store holds. */
		if (i == COL_TIME)
			gtk_tree_view_column_set_cell_data_func (
				column, renderer, time_cell_data, NULL, NULL);
		else
			gtk_tree_view_column_set_cell_data_func (
				column, renderer, color_cell_data, NULL, NULL);

		/* Column visibility is remembered, as in the original. */
		if (column_defs[i].pref_key != NULL)
			gtk_tree_view_column_set_visible (
				column,
				fs_prefs_get_bool (column_defs[i].pref_key,
				                   column_defs[i].visible));

		gtk_tree_view_append_column (GTK_TREE_VIEW (view), column);
	}

	/* Every row one height, every column a set width: the view lays
	 * out only the rows on screen, which is what keeps 100,000 rows
	 * smooth. */
	gtk_tree_view_set_fixed_height_mode (GTK_TREE_VIEW (view), TRUE);

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	/* The card around the list is the border. */
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll),
	                                     GTK_SHADOW_NONE);
	gtk_widget_set_vexpand (scroll, TRUE);
	gtk_container_add (GTK_CONTAINER (scroll), view);
	{
		GtkWidget *overlay = gtk_overlay_new ();
		GtkWidget *card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);

		empty_label = gtk_label_new (NULL);
		gtk_label_set_justify (GTK_LABEL (empty_label), GTK_JUSTIFY_CENTER);
		gtk_widget_set_halign (empty_label, GTK_ALIGN_CENTER);
		gtk_widget_set_valign (empty_label, GTK_ALIGN_CENTER);
		gtk_style_context_add_class (
			gtk_widget_get_style_context (empty_label), "empty-state");
		/* Its visibility is the row count's to decide, not the
		 * window's show_all. */
		gtk_widget_set_no_show_all (empty_label, TRUE);

		gtk_container_add (GTK_CONTAINER (overlay), scroll);
		gtk_overlay_add_overlay (GTK_OVERLAY (overlay), empty_label);
		gtk_overlay_set_overlay_pass_through (GTK_OVERLAY (overlay),
		                                      empty_label, TRUE);
		gtk_widget_set_vexpand (overlay, TRUE);
		gtk_style_context_add_class (
			gtk_widget_get_style_context (card), "card");
		gtk_style_context_add_class (
			gtk_widget_get_style_context (card), "list-card");
		gtk_box_pack_start (GTK_BOX (card), overlay, TRUE, TRUE, 0);
		gtk_box_pack_start (GTK_BOX (page), card, TRUE, TRUE, 0);
	}

	/* History that could not be opened is said, not swallowed. */
	g_clear_pointer (&history_warning, g_free);
	g_clear_pointer (&history_warning_was, g_free);
	history_warning_sync ();

	/* Start monitoring straight away: the whole point of the page is
	 * watching events, and the original did this too.  A failure here
	 * used to be dropped on the floor, leaving an empty list that read
	 * as a working firewall with nothing to report; it now has to say
	 * why. */
	{
		GError *error = NULL;

		if (!fs_hitview_start (&error)) {
			set_monitor_warning (error != NULL
			                     ? error->message
			                     : _("Monitoring could not start."));
			g_clear_error (&error);
		} else if (toggle != NULL) {
			/* Monitoring really runs: the switch must say so.
			 * The re-entry calls start again, which answers
			 * "already active" and changes nothing. */
			gtk_switch_set_active (GTK_SWITCH (toggle), TRUE);
		}
	}

	monitor_toggle = toggle;
	if (toggle != NULL)
		g_signal_connect (toggle, "destroy",
		                  G_CALLBACK (gtk_widget_destroyed),
		                  &monitor_toggle);
	if (toggle != NULL && monitor_watchdog == 0)
		monitor_watchdog = g_timeout_add_seconds (2, on_monitor_watchdog,
		                                          NULL);

	g_signal_connect (view, "destroy", G_CALLBACK (gtk_widget_destroyed),
	                  &view);

	update_count_label ();

	return page;
}
