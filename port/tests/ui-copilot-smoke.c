/*---[ ui-copilot-smoke.c ]------------------------------------------------
 *
 * UI smoke test for Sentinel's P6 auto-block state machine.
 *
 * The 2026-10-10 incident was three silent loops in this exact code:
 * an expiry that re-staged forever, staging records that died with the
 * process while their policy rows survived, and a user Allow that a
 * block rule outranked.  None of that is visible to fs-core: it lives
 * in the Copilot page's statics.  So this smoke drives the REAL page
 * and the exported functions end to end against scratch files:
 *
 *   1. boot restore  -- a stale row comes out of the policy, a fresh
 *      row is re-armed with its ORIGINAL clock, the state file is
 *      rewritten to match, and the episode is audited;
 *   2. cooldown      -- a restored (retired) rule is refused even
 *      when a live beacon insight asks for it again;
 *   3. staging       -- a metronomic stranger to a public host
 *      stages, persists to the state file, and pushes (held=staged
 *      without elevation, which is the honest verdict, not a lie);
 *   4. dest lift     -- the user's Allow takes down Sentinel's rows
 *      for that destination (staged or persisted) and NEVER the
 *      user's own rules, and the cooldown blocks the re-stage;
 *   5. lift all      -- one call retires every staged block;
 *   6. detect mode   -- with the pref switched, auto_pass stages
 *      nothing at all;
 *   8. the page      -- tiles that count what the lists hold, findings
 *      with a severity word and an evidence drawer Enter opens, policy
 *      health fixes that are offered only when verified, asked before
 *      writing, written exactly, and undone byte for byte; the empty
 *      states; a dark-theme run in a child process.  FS_SHOT_DIR gets
 *      the screenshots.
 *   7. What-If card  -- the entry keeps its line, the chips say how it
 *      was read, the answer row and Recent (five, newest first) fill
 *      in, Details opens a window beside the page (never modal), and
 *      Create writes only the verified row the user saw and said Yes
 *      to -- held by audit-only, in a network namespace of its own when
 *      run as root on Linux, and on Windows against a stand-in backend
 *      with a known state that refuses every write (the machine's own
 *      network profile would otherwise decide the answers), so nothing
 *      reaches the host's firewall.
 *
 * Everything runs against a mkdtemp scratch tree (rules dir, audit,
 * journal, autoblocks, APPDATA) set before the first path is
 * resolved, so the user's real policy is never in scope.  The push
 * attempts reach the real backend but run unelevated: no rule can
 * reach the firewall from a test, which is exactly the "staged, not
 * live" path being asserted.
 *
 * Deliberately NOT part of StockFW.exe -- the CMake target is
 * EXCLUDE_FROM_ALL -- so no test hook is ever shipped to a user.
 *
 *----------------------------------------------------------------------*/
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE   /* unshare() for the What-If section */
#endif
#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "core/fs-copilot.h"
#include "core/fs-rules.h"
#include "core/fs-prefs.h"
#include "core/fs-audit.h"
#include "core/fs-util.h"
#include "ui/fs-copilot.h"
#include "ui/fs-policyview.h"
#include "ui/fs-simviz.h"
#include "core/fs-apply.h"
#include "fs-theme-css.h"

#ifdef __linux__
#include <sched.h>
#include <unistd.h>
#endif

#ifdef G_OS_WIN32
#include "core/fs-backend.h"
#include "core/fs-netplace.h"
#endif

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

/* ---- scratch isolation ---------------------------------------------- */

static gchar *scratch = NULL;

static gchar *
scratch_path (const gchar *name)
{
	return g_build_filename (scratch, name, NULL);
}

static void
isolate (void)
{
	gchar *rules;
	gchar *audit;
	gchar *journal;
	gchar *blocks;
	gchar *behavior;

	scratch = g_dir_make_tmp ("stockfw-copilot-smoke-XXXXXX", NULL);
	if (scratch == NULL) {
		fprintf (stderr, "cannot create scratch dir\n");
		exit (1);
	}

	rules    = scratch_path ("rules");
	audit    = scratch_path ("audit.log");
	journal  = scratch_path ("applied.csv");
	blocks   = scratch_path ("autoblocks");
	behavior = scratch_path ("behavior.csv");

	g_mkdir_with_parents (rules, 0700);

	g_setenv ("STOCKFW_RULES_DIR", rules, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit, TRUE);
	g_setenv ("STOCKFW_APPLIED_FILE", journal, TRUE);
	g_setenv ("STOCKFW_AUTOBLOCK_FILE", blocks, TRUE);
	g_setenv ("STOCKFW_BEHAVIOR_FILE", behavior, TRUE);
	/* Prefs follow APPDATA on Windows (and XDG_CONFIG_HOME on
	 * Linux): the Sentinel mode switch below writes there. */
	g_setenv ("APPDATA", scratch, TRUE);
	g_setenv ("XDG_CONFIG_HOME", scratch, TRUE);
	/* The local network a health fix narrows to: fixed, so the checks
	 * do not depend on this machine's adapters. */
	g_setenv ("STOCKFW_LAN_PREFIX", "192.168.1.0/24", TRUE);

	g_free (rules);
	g_free (audit);
	g_free (journal);
	g_free (blocks);
	g_free (behavior);
}

/* ---- small helpers --------------------------------------------------- */

static gboolean
policy_has (FsPolicy *policy, FsRuleKind kind, const gchar *csv)
{
	FsRule *rule = fs_rule_from_csv (kind, csv);
	gboolean in = rule != NULL && fs_policy_contains (policy, rule);

	fs_rule_free (rule);
	return in;
}

static void
policy_add (FsPolicy *policy, FsRuleKind kind, const gchar *csv)
{
	FsRule *rule = fs_rule_from_csv (kind, csv);

	if (rule == NULL) {
		printf ("FAIL: test setup cannot parse \"%s\"\n", csv);
		failures++;
		return;
	}

	fs_policy_add (policy, rule);
	fs_rule_free (rule);
}

static gchar *
file_contents (const gchar *path)
{
	gchar *text = NULL;

	if (!g_file_get_contents (path, &text, NULL, NULL))
		return g_strdup ("");

	return text;
}

/* How many staged rows ("S,...") the state file holds right now. */
static guint
state_row_count (void)
{
	gchar *path = scratch_path ("autoblocks");
	gchar *text = file_contents (path);
	gchar **lines = g_strsplit (text, "\n", -1);
	guint n = 0;
	guint i;

	for (i = 0; lines[i] != NULL; i++)
		if (g_str_has_prefix (lines[i], "S,"))
			n++;

	g_strfreev (lines);
	g_free (text);
	g_free (path);
	return n;
}

static gboolean
state_mentions (const gchar *needle)
{
	gchar *path = scratch_path ("autoblocks");
	gchar *text = file_contents (path);
	gboolean hit = strstr (text, needle) != NULL;

	g_free (text);
	g_free (path);
	return hit;
}

static gboolean
audit_mentions (const gchar *needle)
{
	gchar *path = scratch_path ("audit.log");
	gchar *text = file_contents (path);
	gboolean hit = strstr (text, needle) != NULL;

	g_free (text);
	g_free (path);
	return hit;
}

/* Eight metronomic contacts: enough for Sentinel to auto-block, at dst:port
 * with exact 60 s intervals. */
static void
feed_beacon (FsCopilot *copilot, const gchar *dest, gint64 t0)
{
	FsHit hit;
	gint i;

	memset (&hit, 0, sizeof hit);
	hit.direction   = "Out";
	hit.source      = "192.168.1.7";
	hit.destination = (gchar *) dest;
	hit.port        = "443";
	hit.protocol    = "TCP";
	hit.service     = "smoke.exe";

	for (i = 0; i < 8; i++)
		fs_copilot_feed_event_at (copilot, &hit,
		                          t0 + (gint64) i * 60 * G_USEC_PER_SEC);
}

static const FsInsight *
find_beacon (FsCopilot *copilot)
{
	GList *insights = fs_copilot_get_insights (copilot);
	GList *l;
	const FsInsight *found = NULL;

	for (l = insights; l != NULL; l = l->next) {
		FsInsight *ins = l->data;

		if (ins->type == FS_INSIGHT_BEACON) {
			found = ins;
			break;
		}
	}

	g_list_free (insights);
	return found;
}

/* ---- 7. the What-If card --------------------------------------------- */

/* Rows of the card, found by name: the page is the real one. */
static GtkWidget *
named (GtkWidget *root, const gchar *name)
{
	return fs_simviz_find_named (root, name);
}

static void
pump (guint ms)
{
	gint64 until = g_get_monotonic_time () + (gint64) ms * 1000;

	do {
		while (gtk_events_pending ())
			gtk_main_iteration_do (FALSE);
		g_usleep (2000);
	} while (g_get_monotonic_time () < until);
}

/* The open What-If window, if any. */
static GtkWidget *
whatif_window_open (void)
{
	GList *tops = gtk_window_list_toplevels ();
	GtkWidget *hit = NULL;

	for (GList *l = tops; l != NULL && hit == NULL; l = l->next)
		if (gtk_widget_get_visible (l->data) &&
		    gtk_style_context_has_class (
			    gtk_widget_get_style_context (l->data), "fs-wi-dialog"))
			hit = l->data;
	g_list_free (tops);
	return hit;
}

/* The confirmation dialogs: answered from a timer inside their own
 * gtk_dialog_run, the way a user would, and their text kept. */
static gint     confirm_answer = GTK_RESPONSE_NO;
static gint     confirm_seen = 0;
static gchar   *confirm_text = NULL;
static gboolean confirm_parent_ok = FALSE;

static gboolean
answer_confirm (gpointer data)
{
	GList *tops = gtk_window_list_toplevels ();

	(void) data;
	for (GList *l = tops; l != NULL; l = l->next) {
		GtkWidget *w = l->data;
		gchar *text = NULL;

		if (!GTK_IS_MESSAGE_DIALOG (w) || !gtk_widget_get_visible (w))
			continue;
		g_object_get (w, "text", &text, NULL);
		g_free (confirm_text);
		confirm_text = text;
		confirm_seen++;
		confirm_parent_ok =
			gtk_window_get_transient_for (GTK_WINDOW (w)) ==
			GTK_WINDOW (whatif_window_open ());
		gtk_dialog_response (GTK_DIALOG (w), confirm_answer);
		break;
	}
	g_list_free (tops);
	return G_SOURCE_CONTINUE;
}

static void
ask (GtkWidget *card, const gchar *line)
{
	gtk_entry_set_text (GTK_ENTRY (named (card, "whatif-entry")), line);
	gtk_button_clicked (GTK_BUTTON (named (card, "whatif-simulate")));
	pump (30);
}

static guint
history_rows (GtkWidget *card)
{
	GtkWidget *h = named (card, "whatif-history");
	guint n = 0;
	GList *kids;

	if (h == NULL || !gtk_widget_get_visible (h))
		return 0;
	/* The second child of the history box holds one button a row. */
	kids = gtk_container_get_children (GTK_CONTAINER (h));
	if (g_list_length (kids) > 1) {
		GList *rows = gtk_container_get_children (
			GTK_CONTAINER (g_list_nth_data (kids, 1)));

		n = g_list_length (rows);
		g_list_free (rows);
	}
	g_list_free (kids);
	return n;
}

/* The line on history row i (0 = newest). */
static const gchar *
history_line (GtkWidget *card, guint i, GtkWidget **button)
{
	GtkWidget *h = named (card, "whatif-history");
	GList *kids = gtk_container_get_children (GTK_CONTAINER (h));
	GList *rows = gtk_container_get_children (
		GTK_CONTAINER (g_list_nth_data (kids, 1)));
	GtkWidget *b = g_list_nth_data (rows, i);
	const gchar *line = b != NULL
		? g_object_get_data (G_OBJECT (b), "fs-wi-line") : NULL;

	if (button != NULL)
		*button = b;
	g_list_free (rows);
	g_list_free (kids);
	return line;
}

static const gchar *
card_summary (GtkWidget *card)
{
	return gtk_label_get_text (GTK_LABEL (named (card, "whatif-summary")));
}

static gboolean
card_verdict_is (GtkWidget *card, const gchar *name)
{
	GtkWidget *slot = named (card, "whatif-verdict");

	return slot != NULL && gtk_widget_get_visible (
		       named (card, "whatif-result")) &&
	       fs_simviz_find_label (slot, name) != NULL;
}

static gboolean
chip_says (GtkWidget *card, const gchar *text)
{
	return fs_simviz_find_label (named (card, "whatif-chips"), text) != NULL;
}

static void
shoot (GtkWidget *w, const gchar *name)
{
	const gchar *dir = g_getenv ("FS_SHOT_DIR");
	GdkWindow *win;
	GdkPixbuf *pb;
	gchar *path;

	if (dir == NULL || *dir == '\0' || w == NULL)
		return;
	pump (200);
	win = gtk_widget_get_window (w);
	if (win == NULL)
		return;
	pb = gdk_pixbuf_get_from_window (win, 0, 0,
	                                 gdk_window_get_width (win),
	                                 gdk_window_get_height (win));
	if (pb == NULL)
		return;
	path = g_strdup_printf ("%s/%s.png", dir, name);
	gdk_pixbuf_save (pb, path, "png", NULL, NULL);
	g_object_unref (pb);
	g_free (path);
}

#ifdef G_OS_WIN32
/* ---- Windows: the What-If section's own firewall ---------------------
 *
 * Windows has no network namespace, and the section must not answer
 * for whatever firewall the machine running it has: a CI runner sits
 * on a Public network, where StockFW's own "block reserved source
 * addresses on public networks" rule decides an inbound from
 * 192.168.x.x -- and on Windows a block wins over any allow, so the
 * engine rightly offers no allow row there.  The section asks its
 * questions of a known Windows firewall instead: running, every
 * profile on, inbound blocked and outbound allowed by default, "block
 * all incoming" off, and the network in use the one whatif_profile
 * names (Private, a home network, unless a check says otherwise).
 *
 * The stand-in is the real backend's table with these readings and
 * with every slot that could change the firewall replaced by one that
 * refuses and is counted; sections 1 to 6 keep the real backend
 * (ui-copilot-backend-win.c compiles it as fs_backend_real). */
const FsBackend *fs_backend_real (void);

static gboolean     whatif_fake_on = FALSE;
static gint         whatif_profile = FS_PROFILE_PRIVATE;
static guint        whatif_writes = 0;
static FsBackend    whatif_backend;

static gboolean
wf_available (void)
{
	return TRUE;
}

static FsFirewallState
wf_get_state (void)
{
	return FS_FW_RUNNING;
}

static gboolean
wf_profile_enabled (gint profile, gboolean *on)
{
	if (profile < 0 || profile >= FS_PROFILE_COUNT)
		return FALSE;
	if (on != NULL)
		*on = TRUE;
	return TRUE;
}

static gboolean
wf_profile_defaults (gint profile, gboolean *in_block, gboolean *out_block)
{
	if (profile < 0 || profile >= FS_PROFILE_COUNT)
		return FALSE;
	if (in_block != NULL)
		*in_block = TRUE;
	if (out_block != NULL)
		*out_block = FALSE;
	return TRUE;
}

static gboolean
wf_block_all_inbound (gint profile, gboolean *on)
{
	if (profile < 0 || profile >= FS_PROFILE_COUNT)
		return FALSE;
	if (on != NULL)
		*on = FALSE;
	return TRUE;
}

static FsNetworkPlace *
wf_network_place (void)
{
	FsNetworkPlace *place = fs_network_place_new ();

	fs_network_place_add (place,
	                      whatif_profile == FS_PROFILE_PUBLIC ? "CafeNet"
	                                                          : "HomeNet",
	                      whatif_profile, "Ethernet", TRUE);
	place->in_use |= FS_PROFILE_BIT (whatif_profile);
	return place;
}

static GList *
wf_no_interfaces (void)
{
	return NULL;
}

/* Every slot that could change the firewall: refused, and counted. */
static gboolean
wf_refuse (GError **error)
{
	whatif_writes++;
	g_set_error_literal (error, g_quark_from_static_string ("whatif-fake"),
	                     1, "the What-If section never changes a firewall");
	return FALSE;
}

static FsApplyResult
wf_refuse_apply (const FsPolicy *policy, GError **error)
{
	(void) policy;
	wf_refuse (error);
	return FS_APPLY_FAILED;
}

static FsApplyResult
wf_refuse_delta (const GList *remove, const GList *add, const GList *repair,
                 GError **error)
{
	(void) remove; (void) add; (void) repair;
	wf_refuse (error);
	return FS_APPLY_FAILED;
}

static FsApplyResult
wf_refuse_clear (GError **error)
{
	wf_refuse (error);
	return FS_APPLY_FAILED;
}

static gboolean
wf_refuse_bool (gboolean on, GError **error)
{
	(void) on;
	return wf_refuse (error);
}

static gboolean
wf_refuse_profile (gint profile, gboolean on, GError **error)
{
	(void) profile; (void) on;
	return wf_refuse (error);
}

const FsBackend *
fs_backend (void)
{
	if (!whatif_fake_on)
		return fs_backend_real ();

	if (whatif_backend.name == NULL) {
		whatif_backend = *fs_backend_real ();
		whatif_backend.name = "whatif-windows";
		whatif_backend.available = wf_available;
		whatif_backend.get_state = wf_get_state;
		whatif_backend.get_profile_enabled = wf_profile_enabled;
		whatif_backend.get_profile_defaults = wf_profile_defaults;
		whatif_backend.get_profile_block_all_inbound = wf_block_all_inbound;
		whatif_backend.network_place = wf_network_place;
		whatif_backend.list_interfaces = wf_no_interfaces;
		whatif_backend.start = wf_refuse;
		whatif_backend.stop = wf_refuse;
		whatif_backend.reload = wf_refuse;
		whatif_backend.apply_rules = wf_refuse_apply;
		whatif_backend.apply_delta = wf_refuse_delta;
		whatif_backend.clear_rules = wf_refuse_clear;
		whatif_backend.dhcp_set_enabled = wf_refuse_bool;
		whatif_backend.set_profile_enabled = wf_refuse_profile;
		/* Blocklists: not on Windows yet (NULL in the real table). */
		whatif_backend.intel_apply = NULL;
		whatif_backend.intel_clear = NULL;
	}
	return &whatif_backend;
}
#endif /* G_OS_WIN32 */

/* Linux, as root: a network namespace of its own with an empty
 * INBOUND chain, so the backend reads "running" and nothing this test
 * does can reach the host's firewall.  Windows: the stand-in above, a
 * known firewall that refuses every write.  Applies are on hold
 * (audit-only) on top of that, so every push is held, never sent. */
static void
whatif_isolate (void)
{
	static gboolean done = FALSE;

	if (done)
		return;
	done = TRUE;
#ifdef __linux__
	if (geteuid () == 0 && unshare (CLONE_NEWNET) == 0) {
		gint status = 0;

		g_spawn_command_line_sync ("iptables -w -N INBOUND", NULL, NULL,
		                           &status, NULL);
		(void) status;
	}
#endif
#ifdef G_OS_WIN32
	whatif_fake_on = TRUE;
	whatif_profile = FS_PROFILE_PRIVATE;
	CHECK (g_strcmp0 (fs_backend ()->name, "whatif-windows") == 0,
	       "what-if: the section asks a known Windows firewall, not the "
	       "machine's");
#endif
	fs_apply_set_audit_only (TRUE);
}

static void
test_whatif_card (FsPolicy *policy, GtkWidget *page)
{
	GtkWidget *top = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	GtkWidget *card;
	GtkWidget *win;
	GtkWidget *btn;
	const gchar *line;
	guint timer;
	static const gchar *lines[] = {
		"inbound tcp 8000", "inbound tcp 8001", "inbound tcp 8002",
		"inbound tcp 8003", "inbound tcp 8004", "inbound tcp 8005",
	};

	whatif_isolate ();
	{
		/* The app's stylesheet, as fs-app.c installs it, so the card
		 * is seen (and shot) as the user sees it. */
		GtkCssProvider *css = gtk_css_provider_new ();

		if (gtk_css_provider_load_from_data (css, fs_theme_css, -1, NULL))
			gtk_style_context_add_provider_for_screen (
				gdk_screen_get_default (), GTK_STYLE_PROVIDER (css),
				GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
		g_object_unref (css);
	}
	CHECK (fs_policyview_hold_reason () != NULL,
	       "what-if: applies are on hold for this section");

	gtk_window_set_default_size (GTK_WINDOW (top), 980, 900);
	gtk_container_add (GTK_CONTAINER (top), page);
	gtk_widget_show_all (top);
	pump (100);
	card = named (page, "whatif-card");
	CHECK (card != NULL, "what-if: the card is on the Copilot page");
	if (card == NULL)
		return;
	CHECK (!gtk_widget_get_visible (named (card, "whatif-result")) &&
	       !gtk_widget_get_visible (named (card, "whatif-history")),
	       "what-if: no answer and no history before the first question");
	CHECK (fs_simviz_find_button (named (card, "whatif-examples"),
	                              "Can 192.168.1.50 reach my SSH?") &&
	       fs_simviz_find_button (named (card, "whatif-examples"),
	                              "Is outbound DNS to 8.8.8.8 allowed?") &&
	       fs_simviz_find_button (named (card, "whatif-examples"),
	                              "block RDP from the internet"),
	       "what-if: the three example chips are offered");
	shoot (top, "card-empty");

	/* The entry keeps the line; the chips say how it was read. */
	ask (card, "Can 192.168.1.50 reach my SSH?");
	CHECK (g_strcmp0 (gtk_entry_get_text (GTK_ENTRY (named (card,
	                  "whatif-entry"))), "Can 192.168.1.50 reach my SSH?")
	       == 0, "what-if: the entry keeps its text after Simulate");
	CHECK (chip_says (card, "Inbound") && chip_says (card, "TCP") &&
	       chip_says (card, "SSH · port 22") &&
	       chip_says (card, "From 192.168.1.50 (LAN host)"),
	       "what-if: chips show direction, protocol, service and port, "
	       "and the host with its zone");
	CHECK (card_verdict_is (card, "BLOCKED"),
	       "what-if: the inline row carries the verdict badge");
	CHECK (g_str_has_prefix (card_summary (card),
	                         "Saved policy, applies on hold: "),
	       "what-if: with applies on hold the one line says it describes "
	       "the saved policy (got \"%s\")", card_summary (card));
	CHECK (named (card, "whatif-details") != NULL &&
	       gtk_widget_get_visible (named (card, "whatif-details")),
	       "what-if: a Details button sits on the answer row");
	CHECK (history_rows (card) == 1,
	       "what-if: the question is in Recent");
	/* The chips are words, not Tab stops; and the rows they sit in can
	 * shrink again to their widest chip. */
	{
		GList *kids = gtk_container_get_children (
			GTK_CONTAINER (named (card, "whatif-chips")));
		gboolean focusable = FALSE;
		gint min = 0, nat = 0;

		for (GList *l = kids; l != NULL; l = l->next)
			if (gtk_widget_get_can_focus (l->data))
				focusable = TRUE;
		CHECK (kids != NULL && !focusable,
		       "what-if: no chip takes a Tab stop");
		g_list_free (kids);
		gtk_widget_get_preferred_width (named (card, "whatif-examples"),
		                                &min, &nat);
		CHECK (min > 0 && min < nat,
		       "what-if: the examples row can shrink below one line "
		       "(%d < %d)", min, nat);
	}
	shoot (top, "card-answer");

	/* An example chip asks its line. */
	gtk_button_clicked (GTK_BUTTON (fs_simviz_find_button (
		named (card, "whatif-examples"), "block RDP from the internet")));
	pump (30);
	CHECK (g_strcmp0 (gtk_entry_get_text (GTK_ENTRY (named (card,
	                  "whatif-entry"))), "block RDP from the internet") == 0,
	       "what-if: an example chip fills the entry and asks it");
	CHECK (chip_says (card, "You want it blocked") &&
	       chip_says (card, "Inbound") &&
	       chip_says (card, "Remote Desktop · port 3389") &&
	       chip_says (card, "Any host"),
	       "what-if: \"from the internet\" reads inbound from any host");

	/* Five at most, newest first, a repeat moves up. */
	for (guint i = 0; i < G_N_ELEMENTS (lines); i++)
		ask (card, lines[i]);
	CHECK (history_rows (card) == 5,
	       "what-if: Recent keeps the last five (got %u)",
	       history_rows (card));
	ask (card, "inbound tcp 8002");
	CHECK (history_rows (card) == 5 &&
	       g_strcmp0 (history_line (card, 0, NULL), "inbound tcp 8002") == 0 &&
	       g_strcmp0 (history_line (card, 1, NULL), "inbound tcp 8005") == 0,
	       "what-if: asking again moves the line to the top, no duplicate");
	line = history_line (card, 3, &btn);
	CHECK (g_strcmp0 (line, "inbound tcp 8003") == 0 && btn != NULL,
	       "what-if: the rows are newest first");
	if (btn != NULL) {
		gtk_button_clicked (GTK_BUTTON (btn));
		pump (30);
	}
	CHECK (g_strcmp0 (gtk_entry_get_text (GTK_ENTRY (named (card,
	                  "whatif-entry"))), "inbound tcp 8003") == 0 &&
	       g_strcmp0 (history_line (card, 0, NULL), "inbound tcp 8003") == 0,
	       "what-if: a Recent row asks its line again");

	/* Details: a window beside the page, not over it. */
	ask (card, "allow tcp port 8443 inbound from 192.168.1.20");
	CHECK (card_verdict_is (card, "BLOCKED"),
	       "what-if: TCP 8443 inbound is blocked by the default");
	gtk_button_clicked (GTK_BUTTON (named (card, "whatif-details")));
	pump (120);
	win = whatif_window_open ();
	CHECK (win != NULL, "what-if: Details opens the What-If window");
	if (win == NULL)
		return;
	CHECK (!gtk_window_get_modal (GTK_WINDOW (win)) &&
	       gtk_grab_get_current () == NULL,
	       "what-if: the window is not modal and holds no grab");
	CHECK (gtk_window_get_transient_for (GTK_WINDOW (win)) ==
	       GTK_WINDOW (top),
	       "what-if: the window belongs to the main window");
	CHECK (gtk_widget_is_sensitive (named (card, "whatif-entry")),
	       "what-if: the page stays usable while it is open");

	btn = fs_simviz_find_button (win, "Create allow rule");
	CHECK (btn != NULL, "what-if: a verified allow row is offered");
	CHECK (fs_simviz_find_label (win, "TCP, 8443, 192.168.1.20, What-If: "
	                                  "allow TCP 8443") != NULL,
	       "what-if: the exact row is shown before anything is written");

	timer = g_timeout_add (40, answer_confirm, NULL);

	/* No: nothing is written. */
	confirm_answer = GTK_RESPONSE_NO;
	confirm_seen = 0;
	if (btn != NULL)
		gtk_button_clicked (GTK_BUTTON (btn));
	pump (60);
	CHECK (confirm_seen == 1 && confirm_text != NULL &&
	       strstr (confirm_text, "TCP, 8443, 192.168.1.20, What-If: allow TCP 8443")
	       != NULL && confirm_parent_ok,
	       "what-if: Create asks first, over the window, with the literal "
	       "row");
	CHECK (!policy_has (policy, FS_RULE_INBOUND_ALLOW_SERVICE,
	                    "TCP, 8443, 192.168.1.20, What-If: allow TCP 8443"),
	       "what-if: answering No writes nothing");

	/* Yes: one row, held, and asked again. */
	confirm_answer = GTK_RESPONSE_YES;
	confirm_seen = 0;
	btn = fs_simviz_find_button (win, "Create allow rule");
	if (btn != NULL)
		gtk_button_clicked (GTK_BUTTON (btn));
	pump (120);
	CHECK (confirm_seen == 1 &&
	       policy_has (policy, FS_RULE_INBOUND_ALLOW_SERVICE,
	                   "TCP, 8443, 192.168.1.20, What-If: allow TCP 8443"),
	       "what-if: answering Yes writes exactly the row shown");
	CHECK (audit_mentions ("what-if rule created"),
	       "what-if: the new rule is audited");
	CHECK (whatif_window_open () == win &&
	       fs_simviz_find_named (win, "whatif-status") != NULL &&
	       gtk_widget_get_visible (fs_simviz_find_named (win,
	                                                     "whatif-status")) &&
	       fs_simviz_find_label (win, "Held back on purpose") != NULL,
	       "what-if: the window reports the push was held, not applied");
	CHECK (fs_simviz_find_label (named (win, "whatif-window-header"),
	                             "ALLOWED") != NULL &&
	       fs_simviz_find_button (win, "Create allow rule") == NULL,
	       "what-if: asked again, the window shows the new answer and no "
	       "second Create");
	CHECK (card_verdict_is (card, "ALLOWED") &&
	       g_str_has_prefix (card_summary (card),
	                         "Saved policy, applies on hold: "),
	       "what-if: the card's ALLOWED says it is the saved policy, not "
	       "what runs");
	shoot (win, "card-created-window");

	/* A user's own block rule decides: open it, never a Create that
	 * would have to out-rank it. */
	ask (card, "allow outbound tcp to 8.8.8.8 port 443");
	CHECK (whatif_window_open () == win,
	       "what-if: a new question updates the open window in place");
	CHECK (fs_simviz_find_label (named (win, "whatif-window-header"),
	                             "BLOCKED") != NULL &&
	       fs_simviz_find_button (win, "Open rule in Policy") != NULL &&
	       fs_simviz_find_button (win, "Create allow rule") == NULL &&
	       fs_simviz_find_button (win, "Create block rule") == NULL,
	       "what-if: a block rule decided: Open rule, no Create");

	/* What the parser cannot read. */
	ask (card, "zqxv");
	CHECK (card_verdict_is (card, "ERROR") &&
	       strstr (card_summary (card), "Saved policy") == NULL,
	       "what-if: an unreadable line is an ERROR, with no policy caveat");
	CHECK (fs_simviz_find_named (win, "whatif-error-help") != NULL,
	       "what-if: the window shows how to ask");

	g_source_remove (timer);
	ask (card, "Can 192.168.1.50 reach my SSH?");
	gtk_widget_destroy (win);
	pump (40);
	CHECK (whatif_window_open () == NULL, "what-if: Close goes away");
	shoot (top, "card-history");

#ifdef G_OS_WIN32
	/* The network a CI runner is on: Public.  There StockFW's own
	 * reserved-source block decides an inbound from 192.168.x.x, and a
	 * Windows block wins over any allow -- so no allow row is offered,
	 * not even the one just written. */
	whatif_profile = FS_PROFILE_PUBLIC;
	ask (card, "allow tcp port 8443 inbound from 192.168.1.40");
	CHECK (card_verdict_is (card, "BLOCKED") &&
	       strstr (card_summary (card), "reserved source addresses") != NULL,
	       "what-if: on a Public network the reserved-source block decides "
	       "(got \"%s\")", card_summary (card));
	gtk_button_clicked (GTK_BUTTON (named (card, "whatif-details")));
	pump (120);
	win = whatif_window_open ();
	CHECK (win != NULL &&
	       fs_simviz_find_button (win, "Create allow rule") == NULL &&
	       fs_simviz_find_button (win, "Create allow rule for everyone")
	       == NULL,
	       "what-if: on Windows no allow row is offered against a block "
	       "that wins");
	if (win != NULL)
		gtk_widget_destroy (win);
	pump (40);
	whatif_profile = FS_PROFILE_PRIVATE;
	CHECK (whatif_writes == 0,
	       "what-if: nothing in the section tried to change the firewall "
	       "(%u writes refused)", whatif_writes);
	whatif_fake_on = FALSE;
#endif

	gtk_container_remove (GTK_CONTAINER (top), page);
	gtk_widget_destroy (top);
	g_free (confirm_text);
	confirm_text = NULL;
}

/* ---- 8. the page: tiles, findings, policy health, changes ------------ */

static guint
list_rows (GtkWidget *root, const gchar *name)
{
	GtkWidget *list = named (root, name);
	GList *kids;
	guint n;

	if (list == NULL)
		return 0;
	kids = gtk_container_get_children (GTK_CONTAINER (list));
	n = g_list_length (kids);
	g_list_free (kids);
	return n;
}

static GtkWidget *
list_row (GtkWidget *root, const gchar *name, guint i)
{
	GtkWidget *list = named (root, name);
	GList *kids;
	GtkWidget *row;

	if (list == NULL)
		return NULL;
	kids = gtk_container_get_children (GTK_CONTAINER (list));
	row = g_list_nth_data (kids, i);
	g_list_free (kids);
	return row;
}

/* The row whose text carries `needle'. */
static GtkWidget *
row_with (GtkWidget *root, const gchar *name, const gchar *needle)
{
	for (guint i = 0; i < list_rows (root, name); i++) {
		GtkWidget *row = list_row (root, name, i);

		if (fs_simviz_find_label (row, needle) != NULL)
			return row;
	}
	return NULL;
}

static const gchar *
text_of (GtkWidget *root, const gchar *name)
{
	GtkWidget *w = named (root, name);

	return w != NULL && GTK_IS_LABEL (w)
	       ? gtk_label_get_text (GTK_LABEL (w)) : "";
}

static gboolean
shown (GtkWidget *root, const gchar *name)
{
	GtkWidget *w = named (root, name);

	return w != NULL && gtk_widget_is_visible (w);
}

static guint
tile_value (GtkWidget *page, const gchar *tile)
{
	gchar *n = g_strdup_printf ("%s-value", tile);
	guint v = (guint) g_ascii_strtoull (text_of (page, n), NULL, 10);

	g_free (n);
	return v;
}

static gint
path_cmp (gconstpointer a, gconstpointer b)
{
	return g_strcmp0 (*(const gchar * const *) a, *(const gchar * const *) b);
}

static void
rules_walk (const gchar *dir, GPtrArray *paths)
{
	GDir *d = g_dir_open (dir, 0, NULL);
	const gchar *n;

	while (d != NULL && (n = g_dir_read_name (d)) != NULL) {
		gchar *p = g_build_filename (dir, n, NULL);

		if (g_file_test (p, G_FILE_TEST_IS_DIR)) {
			rules_walk (p, paths);
			g_free (p);
		} else {
			g_ptr_array_add (paths, p);
		}
	}
	if (d != NULL)
		g_dir_close (d);
}

/* Every rules file, in path order, with its bytes: what `cmp' would
 * compare. */
static gchar *
rules_bytes (void)
{
	gchar *dir = scratch_path ("rules");
	GPtrArray *paths = g_ptr_array_new_with_free_func (g_free);
	GString *all = g_string_new (NULL);

	rules_walk (dir, paths);
	g_ptr_array_sort (paths, path_cmp);
	for (guint i = 0; i < paths->len; i++) {
		const gchar *p = g_ptr_array_index (paths, i);
		gchar *t = file_contents (p);

		g_string_append_printf (all, "== %s\n%s", p, t);
		g_free (t);
	}
	g_ptr_array_unref (paths);
	g_free (dir);
	return g_string_free (all, FALSE);
}

static void
click (GtkWidget *root, const gchar *name)
{
	GtkWidget *b = named (root, name);

	if (b != NULL)
		gtk_button_clicked (GTK_BUTTON (b));
	pump (60);
}

/* A widget drawn to a PNG at its full size, whether or not all of it
 * fits on the screen. */
static void
shoot_widget (GtkWidget *w, const gchar *name)
{
	const gchar *dir = g_getenv ("FS_SHOT_DIR");
	cairo_surface_t *s;
	cairo_t *cr;
	gchar *path;
	GtkAllocation a;

	if (dir == NULL || *dir == '\0' || w == NULL)
		return;
	pump (150);
	gtk_widget_get_allocation (w, &a);
	if (a.width < 2 || a.height < 2)
		return;
	s = cairo_image_surface_create (CAIRO_FORMAT_ARGB32, a.width, a.height);
	cr = cairo_create (s);
	gtk_widget_draw (w, cr);
	cairo_destroy (cr);
	path = g_strdup_printf ("%s/%s.png", dir, name);
	cairo_surface_write_to_png (s, path);
	cairo_surface_destroy (s);
	g_free (path);
}

/* Enter on a focused widget, as the keyboard delivers it: a key event
 * the window hands to its focus widget, whose key bindings act. */
static void
press_enter (GtkWidget *top, GtkWidget *w)
{
	GdkEvent *ev = gdk_event_new (GDK_KEY_PRESS);

	gtk_window_present (GTK_WINDOW (top));
	gtk_widget_grab_focus (w);
	pump (30);
	ev->key.window = g_object_ref (gtk_widget_get_window (top));
	ev->key.send_event = TRUE;
	ev->key.time = GDK_CURRENT_TIME;
	ev->key.keyval = GDK_KEY_Return;
	/* Key bindings match on the hardware keycode, as a real key
	 * press carries it. */
	{
		GdkKeymapKey *keys = NULL;
		gint n = 0;

		if (gdk_keymap_get_entries_for_keyval (
			    gdk_keymap_get_for_display (gdk_display_get_default ()),
			    GDK_KEY_Return, &keys, &n) && n > 0)
			ev->key.hardware_keycode = (guint16) keys[0].keycode;
		g_free (keys);
	}
	gdk_event_set_device (ev, gdk_seat_get_keyboard (
		gdk_display_get_default_seat (gdk_display_get_default ())));
	gtk_main_do_event (ev);
	gdk_event_free (ev);
	pump (80);
}

static void
install_app_css (void)
{
	static gboolean done = FALSE;
	GtkCssProvider *css;

	if (done)
		return;
	done = TRUE;
	css = gtk_css_provider_new ();
	if (gtk_css_provider_load_from_data (css, fs_theme_css, -1, NULL))
		gtk_style_context_add_provider_for_screen (
			gdk_screen_get_default (), GTK_STYLE_PROVIDER (css),
			GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	g_object_unref (css);
}

static GtkWidget *
page_window (GtkWidget *page, GtkWidget **scroller)
{
	GtkWidget *top = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	GtkWidget *sw = gtk_scrolled_window_new (NULL, NULL);

	gtk_window_set_default_size (GTK_WINDOW (top), 1040, 900);
	gtk_container_set_border_width (GTK_CONTAINER (page), 24);
	gtk_container_add (GTK_CONTAINER (sw), page);
	gtk_container_add (GTK_CONTAINER (top), sw);
	gtk_widget_show_all (top);
	pump (120);
	if (scroller != NULL)
		*scroller = sw;
	return top;
}

static void
feed_intel_inbound (FsCopilot *copilot, gint64 t0)
{
	FsHit hit;

	memset (&hit, 0, sizeof hit);
	hit.direction   = "In";
	hit.source      = "198.51.100.9";
	hit.destination = "192.168.1.7";
	hit.port        = "23";
	hit.protocol    = "TCP";
	hit.service     = "TELNET [BLOCKED]";
	hit.rule        = "Threat intel: smoke list";
	fs_copilot_feed_event_at (copilot, &hit, t0);
}

/* The empty states, on a Copilot that has seen nothing, then one that
 * has seen events and found nothing. */
static void
test_page_empty (FsPolicy *policy, FsCopilot *copilot)
{
	FsCopilot *fresh = fs_copilot_new ();
	GtkWidget *page = fs_copilot_page (fresh, policy);
	GtkWidget *top = page_window (page, NULL);

	CHECK (shown (page, "findings-empty") &&
	       strstr (text_of (page, "findings-empty-text"),
	               "The Copilot learns from the event log. Nothing to "
	               "check yet.") != NULL,
	       "page: no events yet says the Copilot has nothing to check");
	CHECK (shown (page, "findings-reason") &&
	       strstr (text_of (page, "findings-reason"),
	               "No events are arriving: ") != NULL,
	       "page: monitoring off: the reason is shown (\"%s\")",
	       text_of (page, "findings-reason"));
	CHECK (!shown (page, "findings-list"),
	       "page: no empty list is drawn");
	shoot_widget (page, "copilot-empty");
	gtk_widget_destroy (top);
	fs_copilot_free (fresh);

	/* Events seen, nothing found: all clear, and honest about it. */
	page = fs_copilot_page (copilot, policy);
	fs_copilot_clear_insights (copilot);
	fs_copilot_view_refresh ();
	top = page_window (page, NULL);
	CHECK (shown (page, "findings-empty") &&
	       strstr (text_of (page, "findings-empty-text"), "No findings from")
	       != NULL &&
	       strstr (text_of (page, "findings-empty-text"),
	               "This is not a guarantee that nothing is wrong.") != NULL,
	       "page: all clear says it is not a guarantee (\"%s\")",
	       text_of (page, "findings-empty-text"));
	CHECK (shown (page, "findings-checked") &&
	       fs_simviz_find_label (named (page, "findings-checked"),
	                             "12 ports in 60 s") != NULL,
	       "page: \"What is checked\" lists the checks and their limits");
	CHECK (tile_value (page, "tile-attention") == 0,
	       "page: nothing needs attention");
	gtk_widget_destroy (top);
}

static void
test_page (FsPolicy *policy, FsCopilot *copilot)
{
	GtkWidget *page, *top, *row, *rev, *b;
	gchar *before, *after;
	guint timer, n;
	const gint64 t0 = (gint64) 900000 * G_USEC_PER_SEC;

	whatif_isolate ();
	install_app_css ();
	fs_prefs_set_string ("/apps/stockfw/client/sentinel/mode", "detect");

	test_page_empty (policy, copilot);

	/* ---- policy health ---- */
	policy_add (policy, FS_RULE_INBOUND_ALLOW_SERVICE, "RDP, 3389, Anyone");
	policy_add (policy, FS_RULE_INBOUND_ALLOW_SERVICE, "TCP, 3389, Anyone");
	CHECK (fs_policy_save (policy), "page: the risky rows save");

	page = fs_copilot_page (copilot, policy);
	top = page_window (page, NULL);
	click (page, "health-again");

	n = list_rows (page, "health-list");
	CHECK (n >= 2 && tile_value (page, "tile-health") == n,
	       "page: the Policy health tile is the number of findings "
	       "(tile %u, rows %u)", tile_value (page, "tile-health"), n);
	row = row_with (page, "health-list", "open to the internet");
	CHECK (row != NULL && named (row, "cp-health-fix") == NULL &&
	       named (row, "cp-health-nofix") != NULL &&
	       strstr (text_of (row, "cp-health-nofix"), "No fix offered") != NULL,
	       "page: an unverified fix gets no Fix button, only its reason "
	       "(\"%s\")", row != NULL ? text_of (row, "cp-health-nofix") : "");
	CHECK (row != NULL && fs_simviz_find_label (row, "Critical") != NULL,
	       "page: a health row's pill says its severity in a word");

	/* One row left: the narrowing is verified now. */
	{
		FsRule *r = fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_SERVICE,
		                              "TCP, 3389, Anyone");

		fs_policy_remove (policy, r);
		fs_rule_free (r);
		CHECK (fs_policy_save (policy), "page: the second row is gone");
	}
	click (page, "health-again");
	n = list_rows (page, "health-list");
	CHECK (tile_value (page, "tile-health") == n,
	       "page: the tile follows the check (tile %u, rows %u)",
	       tile_value (page, "tile-health"), n);
	row = row_with (page, "health-list", "RDP (3389)");
	CHECK (row != NULL && named (row, "cp-health-fix") != NULL,
	       "page: a verified narrowing gets a Fix button");
	CHECK (row != NULL &&
	       strstr (text_of (row, "cp-health-fixline"),
	               "RDP, 3389, 192.168.1.0/24") != NULL &&
	       strstr (text_of (row, "cp-health-checks"),
	               "from 203.0.113.10: ALLOWED -> BLOCKED") != NULL &&
	       strstr (text_of (row, "cp-health-checks"),
	               "from 192.168.1.20: ALLOWED -> ALLOWED") != NULL,
	       "page: the fix and its What-If checks are shown before anything "
	       "is written");
	shoot_widget (page, "copilot-health");

	before = rules_bytes ();
	timer = g_timeout_add (40, answer_confirm, NULL);

	confirm_answer = GTK_RESPONSE_NO;
	confirm_seen = 0;
	if (row != NULL)
		click (row, "cp-health-fix");
	pump (60);
	after = rules_bytes ();
	CHECK (confirm_seen == 1 && confirm_text != NULL &&
	       strstr (confirm_text, "Before: RDP, 3389, Anyone") != NULL &&
	       strstr (confirm_text, "After:  RDP, 3389, 192.168.1.0/24") != NULL &&
	       strstr (confirm_text, "ALLOWED -> BLOCKED") != NULL,
	       "page: Fix asks first, with the before and after rows and the "
	       "checks");
	CHECK (g_strcmp0 (before, after) == 0,
	       "page: answering No writes nothing (rules files unchanged)");
	if (g_strcmp0 (before, after) != 0)
		printf ("--- before\n%s\n--- after\n%s\n", before, after);
	g_free (after);

	confirm_answer = GTK_RESPONSE_YES;
	confirm_seen = 0;
	row = row_with (page, "health-list", "RDP (3389)");
	if (row != NULL)
		click (row, "cp-health-fix");
	pump (120);
	CHECK (confirm_seen == 1 &&
	       policy_has (policy, FS_RULE_INBOUND_ALLOW_SERVICE,
	                   "RDP, 3389, 192.168.1.0/24") &&
	       !policy_has (policy, FS_RULE_INBOUND_ALLOW_SERVICE,
	                    "RDP, 3389, Anyone"),
	       "page: answering Yes writes exactly the after row");
	CHECK (audit_mentions ("copilot health fix"),
	       "page: the fix is audited");
	CHECK (shown (page, "cp-health-card-strip") &&
	       strstr (text_of (page, "cp-health-card-strip"),
	               "Held back on purpose") != NULL,
	       "page: the push is reported as held, not applied (\"%s\")",
	       text_of (page, "cp-health-card-strip"));
	CHECK (row_with (page, "health-list", "RDP (3389)") == NULL &&
	       tile_value (page, "tile-health") ==
	       list_rows (page, "health-list"),
	       "page: checked again, the finding is gone and the tile follows");
	CHECK (row_with (page, "changes-list", "Policy fix") != NULL,
	       "page: the fix is listed under Changes with an Undo");
	shoot_widget (page, "copilot-health-fixed");

	row = row_with (page, "changes-list", "Policy fix");
	if (row != NULL)
		click (row, "cp-change-undo");
	pump (60);
	after = rules_bytes ();
	CHECK (g_strcmp0 (before, after) == 0,
	       "page: Undo restores the rules files byte for byte");
	if (g_strcmp0 (before, after) != 0)
		printf ("--- before\n%s\n--- after\n%s\n", before, after);
	CHECK (audit_mentions ("copilot health fix undone"),
	       "page: the undo is audited");
	CHECK (row_with (page, "changes-list", "Policy fix") == NULL,
	       "page: the undone change leaves the Changes card");
	g_free (after);
	g_free (before);

	/* ---- findings ---- */
	fs_copilot_clear_insights (copilot);
	feed_beacon (copilot, "5.5.5.5", t0);
	feed_intel_inbound (copilot, t0 + 10 * G_USEC_PER_SEC);
	fs_copilot_view_refresh ();
	pump (60);

	n = list_rows (page, "findings-list");
	CHECK (n == 2, "page: two findings, two rows (got %u)", n);
	for (guint i = 0; i < n; i++) {
		GtkWidget *r = list_row (page, "findings-list", i);
		GtkWidget *pill = named (r, "cp-pill");
		const gchar *acc = atk_object_get_name (gtk_widget_get_accessible (r));
		gboolean word = pill != NULL &&
			(fs_simviz_find_label (pill, "Critical") != NULL ||
			 fs_simviz_find_label (pill, "Warning") != NULL ||
			 fs_simviz_find_label (pill, "Info") != NULL);

		CHECK (word, "page: row %u has a severity pill with a word", i);
		CHECK (acc != NULL && (g_str_has_prefix (acc, "Critical: ") ||
		                       g_str_has_prefix (acc, "Warning: ") ||
		                       g_str_has_prefix (acc, "Info: ")),
		       "page: row %u's accessible name is \"severity: title\" "
		       "(\"%s\")", i, acc != NULL ? acc : "");
	}
	CHECK (tile_value (page, "tile-attention") == 1,
	       "page: Needs attention counts the Warning, not the Info "
	       "(got %u)", tile_value (page, "tile-attention"));

	row = row_with (page, "findings-list", "near-fixed interval");
	rev = row != NULL ? named (row, "cp-drawer") : NULL;
	CHECK (rev != NULL &&
	       !gtk_revealer_get_reveal_child (GTK_REVEALER (rev)),
	       "page: the beacon's drawer starts closed");
	if (row != NULL)
		press_enter (top, row);
	CHECK (rev != NULL && gtk_revealer_get_reveal_child (GTK_REVEALER (rev)),
	       "page: Enter opens the drawer");
	CHECK (row != NULL && named (row, "cp-evidence") != NULL &&
	       fs_simviz_find_label (named (row, "cp-evidence"), "5.5.5.5")
	       != NULL,
	       "page: the drawer shows the events behind the finding");
	CHECK (row != NULL && fs_simviz_find_label (row, "Why flagged") != NULL &&
	       fs_simviz_find_label (row, "Could be harmless") != NULL &&
	       strstr (text_of (row, "cp-autoblock-status"), "Detect only")
	       != NULL,
	       "page: why, could be harmless, and what Sentinel did (\"%s\")",
	       row != NULL ? text_of (row, "cp-autoblock-status") : "");
	b = row != NULL ? named (row, "cp-add-block") : NULL;
	CHECK (b != NULL,
	       "page: a block rule verified with What-If is offered");
	shoot_widget (page, "copilot-findings");

	/* Add block rule: asks, No writes nothing, Yes writes the row. */
	confirm_answer = GTK_RESPONSE_NO;
	confirm_seen = 0;
	if (b != NULL)
		gtk_button_clicked (GTK_BUTTON (b));
	pump (60);
	CHECK (confirm_seen == 1 && strstr (confirm_text, "BLOCKED with the rule")
	       != NULL &&
	       !policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "5.5.5.5, Sentinel: periodic beacon"),
	       "page: Add block rule asks first; No writes nothing");
	confirm_answer = GTK_RESPONSE_YES;
	confirm_seen = 0;
	row = row_with (page, "findings-list", "near-fixed interval");
	b = row != NULL ? named (row, "cp-add-block") : NULL;
	if (b != NULL)
		gtk_button_clicked (GTK_BUTTON (b));
	pump (120);
	CHECK (confirm_seen == 1 &&
	       policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                   "5.5.5.5, Sentinel: periodic beacon") &&
	       audit_mentions ("copilot block rule added"),
	       "page: Yes adds exactly the rule, audited");
	row = row_with (page, "changes-list", "Block rule added");
	CHECK (row != NULL, "page: the rule is under Changes");
	if (row != NULL)
		click (row, "cp-change-undo");
	pump (60);
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "5.5.5.5, Sentinel: periodic beacon") &&
	       audit_mentions ("copilot block rule undone"),
	       "page: Undo takes it out again, audited");

	/* Ask What-If fills the card. */
	row = row_with (page, "findings-list", "near-fixed interval");
	if (row != NULL && named (row, "cp-ask-whatif") != NULL)
		click (row, "cp-ask-whatif");
	CHECK (g_strcmp0 (gtk_entry_get_text (GTK_ENTRY (named (page,
	                  "whatif-entry"))),
	                  "outbound tcp port 443 to 5.5.5.5") == 0,
	       "page: Ask What-If puts the finding's line in the card (\"%s\")",
	       gtk_entry_get_text (GTK_ENTRY (named (page, "whatif-entry"))));

	/* Dismiss hides it for the session. */
	row = row_with (page, "findings-list", "smoke list");
	if (row != NULL)
		click (row, "cp-dismiss");
	CHECK (list_rows (page, "findings-list") == 1 &&
	       row_with (page, "findings-list", "smoke list") == NULL,
	       "page: Dismiss hides the finding");

	g_source_remove (timer);
	shoot_widget (page, "copilot-light");
	gtk_widget_destroy (top);
	fs_prefs_set_string ("/apps/stockfw/client/sentinel/mode", "auto");
}

/* Dark theme: the page takes its dark classes from the desktop theme;
 * run in a child with Adwaita's dark variant, as fs-simviz-smoke
 * does. */
static void
test_dark (void)
{
	FsPolicy *policy = fs_policy_new ();
	FsCopilot *copilot = fs_copilot_new ();
	GtkWidget *page, *top, *row, *title;
	GdkRGBA fg;
	gint malformed = 0;

	whatif_isolate ();
	install_app_css ();
	fs_prefs_set_string ("/apps/stockfw/client/sentinel/mode", "detect");
	fs_policy_load (policy, &malformed);
	policy_add (policy, FS_RULE_INBOUND_ALLOW_SERVICE, "RDP, 3389, Anyone");
	page = fs_copilot_page (copilot, policy);
	top = page_window (page, NULL);
	feed_beacon (copilot, "5.5.5.5", (gint64) 900000 * G_USEC_PER_SEC);
	fs_copilot_view_refresh ();
	pump (60);

	CHECK (gtk_style_context_has_class (gtk_widget_get_style_context (page),
	                                    "cp-dark"),
	       "dark: a dark desktop theme gets the page's dark classes");
	row = list_row (page, "findings-list", 0);
	if (row != NULL) {
		g_signal_emit_by_name (named (page, "findings-list"), "row-activated",
		                       row);
		pump (80);
	}
	title = row != NULL ? named (row, "cp-finding-title") : NULL;
	if (title != NULL) {
		GtkStyleContext *sc = gtk_widget_get_style_context (title);

		gtk_style_context_get_color (sc, gtk_style_context_get_state (sc),
		                             &fg);
	}
	CHECK (title != NULL &&
	       0.2126 * fg.red + 0.7152 * fg.green + 0.0722 * fg.blue > 0.6,
	       "dark: a finding's title is light text on the dark page");
	CHECK (row != NULL && named (row, "cp-pill") != NULL &&
	       gtk_revealer_get_reveal_child (GTK_REVEALER (named (row,
	                                                         "cp-drawer"))),
	       "dark: the pill and the open drawer render");
	shoot_widget (page, "copilot-dark");
	gtk_widget_destroy (top);
}

static void
run_dark_child (const gchar *self)
{
	gchar *argv[] = { (gchar *) self, (gchar *) "--dark", NULL };
	gchar **envp = g_get_environ ();
	gint status = 1;
	GError *error = NULL;

	envp = g_environ_setenv (envp, "GTK_THEME", "Adwaita:dark", TRUE);
	if (!g_spawn_sync (NULL, argv, envp, G_SPAWN_CHILD_INHERITS_STDIN,
	                   NULL, NULL, NULL, NULL, &status, &error)) {
		CHECK (FALSE, "dark: could not start the dark run: %s",
		       error->message);
		g_clear_error (&error);
	} else {
		CHECK (status == 0, "dark: the dark-theme run passed");
	}
	g_strfreev (envp);
}

/* ---- the smoke ------------------------------------------------------- */

int
main (int argc, char **argv)
{
	/* Scratch FIRST: every path below is resolved lazily on first
	 * use, and none of them may ever point at the real user data. */
	isolate ();

	gtk_init (&argc, &argv);

	if (argc > 1 && strcmp (argv[1], "--dark") == 0) {
		test_dark ();
		printf ("\n%d failure(s) in the dark run\n", failures);
		return failures ? 1 : 0;
	}

	FsPolicy *policy = fs_policy_new ();
	FsCopilot *copilot = fs_copilot_new ();
	gint malformed = 0;
	GtkWidget *page;
	const gint64 now_epoch = g_get_real_time () / G_USEC_PER_SEC;
	const gint64 t0 = (gint64) 800000 * G_USEC_PER_SEC;

	/* A virgin scratch dir holds no rule files: load's FALSE here is
	 * "nothing saved yet", not a failure -- and the empty store it
	 * leaves behind is exactly the blank slate the restore needs. */
	fs_policy_load (policy, &malformed);

	/* The real page: it owns the statics (global copilot, shared
	 * policy, cached Sentinel mode) the whole state machine runs
	 * through, exactly as fs-app.c builds it. */
	page = fs_copilot_page (copilot, policy);
	CHECK (page != NULL, "the Copilot page builds");

	/* ---- 1. boot restore ------------------------------------------ */

	policy_add (policy, FS_RULE_OUTBOUND_DENY_TO,
	            "3.3.3.3, Sentinel: periodic beacon");   /* fresh */
	policy_add (policy, FS_RULE_OUTBOUND_DENY_TO,
	            "1.2.3.4, Sentinel: periodic beacon");   /* stale */
	CHECK (fs_policy_save (policy), "the seeded policy saves");

	{
		gchar *path = scratch_path ("autoblocks");
		GString *out = g_string_new (NULL);

		g_string_append_printf (out,
			"S,%" G_GINT64_FORMAT ",6,"
			"3.3.3.3, Sentinel: periodic beacon\n",
			now_epoch - 60);                    /* inside TTL  */
		g_string_append_printf (out,
			"S,%" G_GINT64_FORMAT ",6,"
			"1.2.3.4, Sentinel: periodic beacon\n",
			now_epoch - 3600);                  /* past TTL    */
		g_string_append (out, "S,0,6,broken epoch row\n");
		g_string_append (out, "not a row at all\n");
		CHECK (g_file_set_contents (path, out->str, -1, NULL),
		       "the previous session's staged list is written");
		g_string_free (out, TRUE);
		g_free (path);
	}

	fs_copilot_autoblocks_restore (policy, NULL);

	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "1.2.3.4, Sentinel: periodic beacon"),
	       "restore takes the stale block out of the policy");
	CHECK (policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                   "3.3.3.3, Sentinel: periodic beacon"),
	       "restore keeps the fresh block in the policy");
	CHECK (state_row_count () == 1 && state_mentions ("3.3.3.3"),
	       "the state file now holds exactly the fresh row");
	CHECK (audit_mentions ("expired while StockFW was not running"),
	       "the stale expiry is audited");
	CHECK (audit_mentions ("sentinel auto-blocks restored"),
	       "the restore episode is audited");

	/* ---- 2. cooldown: the stale rule is refused again ------------- */

	feed_beacon (copilot, "1.2.3.4", t0);
	{
		const FsInsight *b = find_beacon (copilot);

		CHECK (b != NULL && b->auto_applicable,
		       "the 1.2.3.4 beacon still asks to be auto-blocked");
	}
	CHECK (!fs_copilot_sentinel_auto_pass (),
	       "the auto pass stages nothing: the stale rule is cooled");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "1.2.3.4, Sentinel: periodic beacon"),
	       "the cooled rule is not re-staged into the policy");

	/* ---- 3. staging: a metronomic stranger to a public host -------- */

	feed_beacon (copilot, "5.6.7.8", t0 + (gint64) 1000 * G_USEC_PER_SEC);
	CHECK (fs_copilot_sentinel_auto_pass (),
	       "the auto pass stages the stranger's beacon");
	CHECK (policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                   "5.6.7.8, Sentinel: periodic beacon"),
	       "the staged block is in the policy");
	CHECK (state_row_count () == 2 && state_mentions ("5.6.7.8"),
	       "the staged block is persisted with its fresh row");
	CHECK (audit_mentions ("sentinel auto-block staged, not live") ||
	       audit_mentions ("sentinel auto-block is live"),
	       "the push reports its real verdict");

	/* ---- 4. dest lift: the user's Allow is the last word ----------- */

	policy_add (policy, FS_RULE_OUTBOUND_DENY_TO,
	            "9.9.9.9, Sentinel: periodic beacon");  /* persisted sentinel */
	policy_add (policy, FS_RULE_OUTBOUND_DENY_TO,
	            "8.8.8.8, user manual rule");           /* the user's own    */
	CHECK (fs_policy_save (policy),
	       "the earlier-session sentinel row and the user rule save");

	CHECK (fs_copilot_lift_auto_blocks_for_dest ("9.9.9.9"),
	       "lifting a persisted sentinel row reports a change");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "9.9.9.9, Sentinel: periodic beacon"),
	       "the persisted sentinel row is gone");
	CHECK (policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                   "8.8.8.8, user manual rule"),
	       "the user's own rule is untouched");

	CHECK (fs_copilot_lift_auto_blocks_for_dest ("5.6.7.8"),
	       "lifting a staged block reports a change");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "5.6.7.8, Sentinel: periodic beacon"),
	       "the staged block is out of the policy");
	CHECK (state_row_count () == 1 && !state_mentions ("5.6.7.8"),
	       "the staged block is out of the state file");

	CHECK (!fs_copilot_lift_auto_blocks_for_dest ("203.0.113.1"),
	       "lifting a destination nothing blocks reports no change");

	CHECK (!fs_copilot_sentinel_auto_pass (),
	       "the lifted rule cannot be staged straight back (cooldown)");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "5.6.7.8, Sentinel: periodic beacon"),
	       "the policy stays free of the lifted block");

	/* ---- 5. lift all: one call retires every staged block ---------- */

	feed_beacon (copilot, "6.6.6.6", t0 + (gint64) 2000 * G_USEC_PER_SEC);
	CHECK (fs_copilot_sentinel_auto_pass (),
	       "a second stranger stages");
	CHECK (policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                   "6.6.6.6, Sentinel: periodic beacon"),
	       "the second stranger is in the policy");

	CHECK (fs_copilot_lift_all_auto_blocks ("smoke test"),
	       "lift-all retires every staged block");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "6.6.6.6, Sentinel: periodic beacon"),
	       "nothing staged remains in the policy");
	CHECK (state_row_count () == 0,
	       "nothing staged remains in the state file");
	CHECK (!fs_copilot_sentinel_auto_pass (),
	       "after lift-all the cooldown keeps everything down");

	/* ---- 6. detect mode: auto_pass stages nothing ------------------ */

	fs_prefs_set_string ("/apps/stockfw/client/sentinel/mode", "detect");
	page = fs_copilot_page (copilot, policy);   /* re-caches the mode */
	CHECK (page != NULL, "the Copilot page rebuilds in detect mode");

	feed_beacon (copilot, "7.7.7.7", t0 + (gint64) 3000 * G_USEC_PER_SEC);
	CHECK (!fs_copilot_sentinel_auto_pass (),
	       "detect mode refuses to stage anything");
	CHECK (!policy_has (policy, FS_RULE_OUTBOUND_DENY_TO,
	                    "7.7.7.7, Sentinel: periodic beacon"),
	       "detect mode leaves the policy free of the block");

	test_whatif_card (policy, page);
	test_page (policy, copilot);
	run_dark_child (argv[0]);

	printf ("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
