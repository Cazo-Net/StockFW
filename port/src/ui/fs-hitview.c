/*---[ fs-hitview.c ]--------------------------------------------------
 * The Events page.
 *
 * A bounded list of firewall hits, fed by the platform backend.  The
 * original kept every hit in a GList and appended straight to the
 * model; on a busy machine that grows without limit, so rows are capped
 * and the oldest dropped.
 *--------------------------------------------------------------------*/

#include "ui/fs-hitview.h"
#include "ui/fs-activityview.h"
#include "ui/fs-dialogs.h"
#include "ui/fs-copilot.h"
#include "ui/fs-statusview.h"
#include "ui/fs-policyview.h"
#include "core/fs-backend.h"
#include "core/fs-service.h"
#include "core/fs-prefs.h"
#include "core/fs-copilot.h"
#include "core/fs-eventrule.h"
#include "ui/fs-intelview.h"
#include "core/fs-rules.h"
#include "core/fs-audit.h"
#include "core/fs-util.h"
#include "core/fs-apply.h"
#include "core/fs-i18n.h"

#include <string.h>

static GtkWidget    *view;
static GtkListStore *store;
static GtkWidget    *count_label;

/* Shown over the empty list, so an empty list says what it is waiting
 * for (or that the filter hides everything) instead of being a blank
 * white box. */
static GtkWidget    *empty_label;
static GtkWidget    *monitor_warning;        /* strip; hidden unless needed */
static GtkWidget    *monitor_warning_label;
static GtkWidget    *monitor_toggle = NULL;   /* the Monitor switch     */
static guint         monitor_watchdog = 0;

/* Filter bar state.  The matcher lives in core (fs_util_filter_match)
 * so the test suite can cover it without GTK. */
static gchar        *filter_text  = NULL;
static GtkTreeModel *filter_model = NULL;    /* GtkTreeModelFilter over store */
static GtkWidget    *filter_entry = NULL;

/* [ shown_rows ] -- the de-duplication append runs against, keyed on
 * the row itself.  The backend keeps its own seen-set while its
 * source runs, but a Monitor restart (stop -> start) forgets it and
 * re-delivers the trailing window -- into a list that still holds
 * those rows, which is how one event could appear twice.  These keys
 * live exactly as long as the rows: fs_hitview_clear drops both, so
 * Clear and Reload keep their meaning (cleared stays cleared, a
 * reload re-reads the tail). */
#define SHOWN_ROWS_MAX 64
static GHashTable *shown_rows  = NULL;          /* key -> TRUE      */
static GQueue      shown_order = G_QUEUE_INIT;  /* newest at the head */

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

/* The colour column holds "" for an allowed event, ROW_BLOCKED for a
 * block, or -- 1.0.7 -- the rule that blocked it when the event says
 * ("Threat intel: Spamhaus DROP (IPv4)", FsHit.rule).  Any non-empty
 * value paints the row red; a rule is also shown after the service. */
#define ROW_BLOCKED "#cc0000"

/* The rule stored in a row's colour column, or NULL. */
static const gchar *
row_rule (const gchar *color)
{
	return color != NULL && *color != '\0' &&
	       strcmp (color, ROW_BLOCKED) != 0 ? color : NULL;
}

static guint row_count = 0;

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

	/* The Service column also names the rule that blocked it. */
	if (GPOINTER_TO_INT (data) == COL_SERVICE) {
		gchar *service = NULL, *flag = NULL;

		gtk_tree_model_get (model, iter, COL_SERVICE, &service,
		                    COL_COLOR, &flag, -1);
		if (row_rule (flag) != NULL) {
			gchar *text = g_strdup_printf ("%s \xc2\xb7 %s",
			                               service ? service : "",
			                               row_rule (flag));

			g_object_set (renderer, "text", text, NULL);
			g_free (text);
		}
		g_free (service);
		g_free (flag);
	}
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
 * With a filter typed in the label reports both numbers, so an empty
 * list under a filter cannot be mistaken for an idle firewall. */
static const gchar *empty_text (void);

static void
update_count_label (void)
{
	gchar *text;

	if (count_label == NULL)
		return;

	if (filter_text != NULL && *filter_text != '\0' &&
	    filter_model != NULL) {
		guint shown = (guint) gtk_tree_model_iter_n_children (
			filter_model, NULL);

		text = g_strdup_printf ("%u of %u events", shown, row_count);
	} else {
		text = g_strdup_printf (row_count == 1 ? "%u event" : "%u events",
		                        row_count);
	}

	gtk_label_set_text (GTK_LABEL (count_label), text);
	g_free (text);

	if (empty_label != NULL) {
		gboolean filtering = filter_text != NULL && *filter_text != '\0';
		guint shown = row_count;

		if (filtering && filter_model != NULL)
			shown = (guint) gtk_tree_model_iter_n_children (filter_model,
			                                                NULL);

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

	if (row_count > 0)
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
	    !fs_prefs_get_bool (FS_PREFS_FW_LOG_ALLOWED, TRUE))
		return _("Nothing has been blocked yet.\nOnly blocked traffic is "
		         "logged.  Turn on \"Log allowed connections\" in "
		         "Preferences to see the rest.");

	return _("No events yet.\nStockFW lists new connections here as its "
	         "rules allow or block them.");
}

/* [ filter_visible ]
 * The filter bar's visible-function: show the row when the needle
 * appears in any of its fields. */
static gboolean
filter_visible (GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	gchar *fields[FS_NUM_HITCOLUMNS - 1];         /* everything but colour */
	gboolean visible;
	gint i;

	(void) data;

	for (i = 0; i < FS_NUM_HITCOLUMNS - 1; i++)
		gtk_tree_model_get (model, iter, i, &fields[i], -1);

	visible = fs_util_filter_match (filter_text,
	                                (const gchar *const *) fields,
	                                FS_NUM_HITCOLUMNS - 1);
	if (!visible) {
		gchar *flag = NULL;
		const gchar *one[1];

		gtk_tree_model_get (model, iter, COL_COLOR, &flag, -1);
		one[0] = row_rule (flag);
		if (one[0] != NULL)
			visible = fs_util_filter_match (filter_text, one, 1);
		g_free (flag);
	}

	for (i = 0; i < FS_NUM_HITCOLUMNS - 1; i++)
		g_free (fields[i]);

	return visible;
}

/* [ on_filter_changed ] */
static void
on_filter_changed (GtkSearchEntry *entry, gpointer data)
{
	(void) data;

	g_clear_pointer (&filter_text, g_free);
	filter_text = g_strdup (gtk_entry_get_text (GTK_ENTRY (entry)));

	if (filter_model != NULL)
		gtk_tree_model_filter_refilter (
			GTK_TREE_MODEL_FILTER (filter_model));

	update_count_label ();
}

guint
fs_hitview_visible_count (void)
{
	if (filter_model == NULL)
		return row_count;

	return (guint) gtk_tree_model_iter_n_children (filter_model, NULL);
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
	if (fs_prefs_get_bool (FS_PREFS_SKIP_REDUNDANT, FALSE) &&
	    hit_is_redundant (hit))
		return;

	if (fs_prefs_get_bool (FS_PREFS_SKIP_NOT_FOR_FIREWALL, TRUE) &&
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
	if (copilot != NULL)
		fs_copilot_feed_event (copilot, hit);

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

/* [ row_key_new ] / [ row_shown ] / [ remember_row ] /
 * [ forget_shown_rows ]
 * Append-level de-duplication: a row identical to one already listed
 * is one event, not two.  The key is every field the row stores
 * (the colour flag included, though it only restates the service),
 * joined with a separator that cannot appear in a field.  Bounded
 * like the backend's seen-set: a batch or two of the most recently
 * listed rows, never history. */
static gchar *
row_key_new (const gchar **fields)
{
	GString *key = g_string_sized_new (96);
	gint i;

	for (i = 0; i < COL_COUNT; i++) {
		if (i > 0)
			g_string_append_c (key, '\x1f');
		g_string_append (key, fields[i] != NULL ? fields[i] : "");
	}

	return g_string_free (key, FALSE);
}

static gboolean
row_shown (const gchar *key)
{
	return shown_rows != NULL && g_hash_table_contains (shown_rows, key);
}

static void
remember_row (gchar *key)             /* takes ownership of key */
{
	if (shown_rows == NULL)
		shown_rows = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                    g_free, NULL);

	while (g_queue_get_length (&shown_order) >= SHOWN_ROWS_MAX) {
		gchar *oldest = g_queue_pop_tail (&shown_order);

		g_hash_table_remove (shown_rows, oldest);
	}

	g_queue_push_head (&shown_order, key);
	g_hash_table_insert (shown_rows, key, GINT_TO_POINTER (1));
}

static void
forget_shown_rows (void)
{
	g_queue_clear (&shown_order);
	g_clear_pointer (&shown_rows, g_hash_table_destroy);
}

gboolean
fs_hitview_append (const FsHit *hit)
{
	GtkTreeIter iter;
	const gchar *fields[FS_NUM_HITCOLUMNS];
	gchar *key;

	if (store == NULL || hit == NULL)
		return FALSE;

	fields[COL_TIME]        = hit->time;
	fields[COL_DIRECTION]   = hit->direction;
	fields[COL_IN]          = hit->in;
	fields[COL_OUT]         = hit->out;
	fields[COL_PORT]        = hit->port;
	fields[COL_SOURCE]      = hit->source;
	fields[COL_DESTINATION] = hit->destination;
	fields[COL_LENGTH]      = hit->length;
	fields[COL_TOS]         = hit->tos;
	fields[COL_PROTOCOL]    = hit->protocol;
	fields[COL_SERVICE]     = hit->service;
	/* Blocked flag for the row painter below: a separate column
	 * because GtkCellRendererText has no per-row colour, and the
	 * cell-data-func turns a non-empty value into the whole-row
	 * alert tint. */
	fields[COL_COLOR]       = !hit_is_blocked (hit) ? ""
	                          : hit->rule != NULL && *hit->rule != '\0'
	                          ? hit->rule : ROW_BLOCKED;

	key = row_key_new (fields);

	/* The same row twice is one event, not two: the backend forgets
	 * its seen-set when monitoring restarts, and the trailing window
	 * comes back to a list that still holds those rows. */
	if (row_shown (key)) {
		g_free (key);
		return FALSE;
	}

	remember_row (key);

	/* Newest first -- the documented order (prepend, then drop the
	 * oldest).  wevtutil hands a batch newest-first, so a plain
	 * append stacked each fresh batch UNDER older rows and the list
	 * read as shuffled after every poll.  Walk until a row older
	 * than the new one and insert above it; equal stamps keep
	 * arrival order, and a row older than everything lands last,
	 * where the oldest row is trimmed. */
	{
		GtkTreeIter pos;
		gboolean placed = FALSE;

		if (gtk_tree_model_get_iter_first (GTK_TREE_MODEL (store),
		                                    &pos)) {
			do {
				gchar *row_time = NULL;

				gtk_tree_model_get (GTK_TREE_MODEL (store), &pos,
				                    COL_TIME, &row_time, -1);

				if (row_time != NULL && *row_time != '\0' &&
				    fields[COL_TIME] != NULL &&
				    *fields[COL_TIME] != '\0' &&
				    strcmp (row_time, fields[COL_TIME]) < 0)
					placed = TRUE;

				g_free (row_time);

				if (placed)
					break;
			} while (gtk_tree_model_iter_next (
				GTK_TREE_MODEL (store), &pos));
		}

		if (placed)
			gtk_list_store_insert_before (store, &iter, &pos);
		else
			gtk_list_store_append (store, &iter);
	}

	for (gint i = 0; i < FS_NUM_HITCOLUMNS; i++)
		gtk_list_store_set (store, &iter, i, fields[i] ? fields[i] : "", -1);

	row_count++;

	/* Drop the oldest row once the cap is passed.  The oldest is the
	 * LAST row now (the list reads newest-first), and GtkListStore
	 * has no "remove last" helper: locate it by index -- iter_n_children
	 * is O(1) on GtkListStore -- and remove it. */
	while (row_count > FS_HITVIEW_MAX_ROWS) {
		GtkTreeIter last;
		GtkTreePath *path;
		gint n = gtk_tree_model_iter_n_children (GTK_TREE_MODEL (store),
		                                         NULL);

		if (n <= 0)
			break;

		path = gtk_tree_path_new_from_indices (n - 1, -1);

		if (!gtk_tree_model_get_iter (GTK_TREE_MODEL (store), &last,
		                              path)) {
			gtk_tree_path_free (path);
			break;
		}

		gtk_list_store_remove (store, &last);
		gtk_tree_path_free (path);
		row_count--;
	}

	/* No follow-scroll.  The newest row is inserted at the TOP,
	 * where a list parked at the top already looks, and a reader
	 * further down is reading history and must not be yanked
	 * anywhere.  The old scroll-to-last-row chased the bottom,
	 * which under newest-first is the oldest end of the list. */

	update_count_label ();

	return TRUE;
}

guint
fs_hitview_count (void)
{
	return row_count;
}

void
fs_hitview_set_policy (FsPolicy *policy)
{
	hitview_policy = policy;
}

void
fs_hitview_clear (void)
{
	if (store != NULL)
		gtk_list_store_clear (store);

	/* The rows are gone, and so is what they stood for: a Reload
	 * re-reads the tail instead of suppressing it as a duplicate. */
	forget_shown_rows ();

	row_count = 0;
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
	static gchar *fields[FS_NUM_HITCOLUMNS];
	static FsHit hit;

	if (view == NULL)
		return NULL;

	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (view));

	if (!gtk_tree_selection_get_selected (selection, &model, &iter))
		return NULL;

	for (gint i = 0; i < FS_NUM_HITCOLUMNS; i++) {
		g_clear_pointer (&fields[i], g_free);
		gtk_tree_model_get (model, &iter, i, &fields[i], -1);
	}

	hit.time        = fields[COL_TIME];
	hit.direction   = fields[COL_DIRECTION];
	hit.in          = fields[COL_IN];
	hit.out         = fields[COL_OUT];
	hit.port        = fields[COL_PORT];
	hit.source      = fields[COL_SOURCE];
	hit.destination = fields[COL_DESTINATION];
	hit.length      = fields[COL_LENGTH];
	hit.tos         = fields[COL_TOS];
	hit.protocol    = fields[COL_PROTOCOL];
	hit.service     = fields[COL_SERVICE];
	hit.rule        = (gchar *) row_rule (fields[COL_COLOR]);

	return &hit;
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

/* [ on_menu_intel_exception ] -- "Add exception for <address>". */
static void
on_menu_intel_exception (GtkMenuItem *item, gpointer data)
{
	const FsHit *hit = fs_hitview_selected ();
	GtkWidget *top;

	(void) item;
	(void) data;
	if (hit == NULL)
		return;
	top = view != NULL ? gtk_widget_get_toplevel (view) : NULL;
	fs_intelview_add_exception (top != NULL && GTK_IS_WINDOW (top)
	                            ? GTK_WINDOW (top) : NULL,
	                            hit_is_outbound (hit) ? hit->destination
	                                                  : hit->source,
	                            hit->rule);
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

	/* A blocklist's block (design 8, [P2]): an Allow rule would not
	 * help, the list would still block it; the way out is an
	 * exception on the Threat Intel page. */
	if (fs_intelview_rule_is_intel (hit->rule)) {
		const gchar *remote = hit_is_outbound (hit) ? hit->destination
		                                            : hit->source;
		GtkWidget *item;
		gchar *label;

		if (remote == NULL || *remote == '\0') {
			gtk_widget_destroy (menu);
			return FALSE;
		}
		label = g_strdup_printf (_("Add exception for %s"), remote);
		item = gtk_menu_item_new_with_label (label);
		g_free (label);
		g_signal_connect (item, "activate",
		                  G_CALLBACK (on_menu_intel_exception), NULL);
		gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
		gtk_widget_show_all (menu);
		gtk_menu_popup_at_pointer (GTK_MENU (menu), (GdkEvent *) event);
		return TRUE;
	}

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

	if (row_count == 0 && gtk_widget_get_mapped (monitor_toggle))
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

GtkWidget *
fs_hitview_page (void)
{
	GtkWidget *page, *box, *scroll, *button_box, *button, *toggle;
	GtkWidget *header, *image;

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

	/* Filter bar.  SearchEntry, so Escape clears and typing filters
	 * the list live through the GtkTreeModelFilter below. */
	filter_entry = gtk_search_entry_new ();
	gtk_entry_set_placeholder_text (
		GTK_ENTRY (filter_entry),
		_("Filter events (host, port, protocol)"));
	gtk_widget_set_size_request (filter_entry, 240, -1);
	g_signal_connect (filter_entry, "search-changed",
	                  G_CALLBACK (on_filter_changed), NULL);
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

	/* The list. */
	store = gtk_list_store_newv (FS_NUM_HITCOLUMNS, (GType[FS_NUM_HITCOLUMNS])
		{ G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
		  G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
		  G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING });

	/* The view shows the filtered model; rows are still appended to
	 * and trimmed from the store underneath. */
	filter_model = gtk_tree_model_filter_new (GTK_TREE_MODEL (store),
	                                          NULL);
	gtk_tree_model_filter_set_visible_func (
		GTK_TREE_MODEL_FILTER (filter_model), filter_visible,
		NULL, NULL);

	view = gtk_tree_view_new_with_model (filter_model);
	gtk_style_context_add_class (gtk_widget_get_style_context (view),
	                             "data-grid");
	/* Hairlines between rows only, as on the Overview. */
	gtk_tree_view_set_grid_lines (GTK_TREE_VIEW (view),
	                              GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);

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

		column = gtk_tree_view_column_new_with_attributes (
			_(column_defs[i].label), renderer, "text", i, NULL);
		gtk_tree_view_column_set_resizable (column, TRUE);

		/* Every visible text column reads the colour column so a
		 * blocked event is red right across the row; the Time
		 * column also formats the stamp the store holds. */
		if (i == COL_TIME)
			gtk_tree_view_column_set_cell_data_func (
				column, renderer, time_cell_data, NULL, NULL);
		else
			gtk_tree_view_column_set_cell_data_func (
				column, renderer, color_cell_data,
				GINT_TO_POINTER (i), NULL);

		/* Column visibility is remembered, as in the original. */
		if (column_defs[i].pref_key != NULL)
			gtk_tree_view_column_set_visible (
				column,
				fs_prefs_get_bool (column_defs[i].pref_key,
				                   column_defs[i].visible));

		gtk_tree_view_append_column (GTK_TREE_VIEW (view), column);
	}

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

	(void) box;

	return page;
}