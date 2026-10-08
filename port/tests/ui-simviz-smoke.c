/* Checks the What-If Simulation Visualizer does what its three
 * verdicts promise, in two layers:
 *
 *   1. the timeline -- fs_simviz_state_at() is pure math, so every
 *      phase is asserted without a display: the packet travels, the
 *      firewall answers green or red, a blocked packet bounces back
 *      and fades while the far line grays out, an allowed one lands
 *      and lights the far node, and an unreadable line has no
 *      timeline at all;
 *
 *   2. the window -- each variant is built and read the way a user
 *      reads it: by what is on screen.  The badge says ALLOWED or
 *      BLOCKED (or stays absent for an error), the details row
 *      carries the parsed facts, and "Create This Rule" exists only
 *      when it could actually create something.
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-copilot.h"
#include "ui/fs-simviz.h"

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

/* A minimal result: the visualizer never judges, it only presents,
 * so the tests hand it verdicts directly. */
static FsSimulationResult *
make_result (gboolean would_block, const gchar *reason)
{
	FsSimulationResult *r = g_new0 (FsSimulationResult, 1);

	r->scenario = g_strdup ("simulated line");
	r->would_block = would_block;
	r->reason = g_strdup (reason);
	r->explanation = g_strdup_printf ("Simulation: simulated line would be %s.",
	                                  would_block ? "BLOCKED" : "ALLOWED");
	return r;
}

static gboolean
label_has_class (GtkWidget *label, const gchar *class_name)
{
	return gtk_style_context_has_class (
		gtk_widget_get_style_context (label), class_name);
}

/* ---------------------------------------------------------------- */
/* 1. The timeline                                                   */
/* ---------------------------------------------------------------- */
static void
test_timeline (void)
{
	FsSimvizState s;
	gdouble prev;
	gint i;

	CHECK (fs_simviz_outcome_of (NULL) == FS_SIMVIZ_ERROR,
	       "no result maps to the error state");
	CHECK (fs_simviz_outcome_of (make_result (TRUE, "x")) ==
	       FS_SIMVIZ_BLOCKED, "a blocking result maps to blocked");
	CHECK (fs_simviz_outcome_of (make_result (FALSE, "x")) ==
	       FS_SIMVIZ_ALLOWED, "a passing result maps to allowed");

	/* Allowed: travel, hold, continue, glow. */
	s = fs_simviz_state_at (FS_SIMVIZ_ALLOWED, 0.5);
	CHECK (s.packet > 0.0 && s.packet < 0.5,
	       "allowed at 0.5s: the packet is on the first leg");
	CHECK (!s.show_check && !s.show_x && s.dest_glow == 0.0 && !s.done,
	       "allowed at 0.5s: no verdict yet");

	s = fs_simviz_state_at (FS_SIMVIZ_ALLOWED, 1.3);
	CHECK (s.show_check && !s.show_x,
	       "allowed at 1.3s: the check is up, no X");
	CHECK (s.fw_green > 0.0, "allowed at 1.3s: the wall flashes green");
	CHECK (s.packet > 0.4 && s.packet < 0.6,
	       "allowed at 1.3s: the packet holds at the wall");

	s = fs_simviz_state_at (FS_SIMVIZ_ALLOWED, 2.0);
	CHECK (s.packet > 0.5 && s.packet < 1.0,
	       "allowed at 2.0s: the packet is on the second leg");
	CHECK (!s.tail_blocked,
	       "allowed: the far line never grays out");

	s = fs_simviz_state_at (FS_SIMVIZ_ALLOWED, FS_SIMVIZ_DURATION);
	CHECK (s.done && s.packet == 1.0,
	       "allowed at the end: the packet arrived");
	CHECK (s.dest_glow > 0.0, "allowed at the end: the far node glows");
	CHECK (s.fw_red == 0.0 && !s.show_x && !s.tail_blocked,
	       "allowed at the end: nothing red anywhere");

	s = fs_simviz_state_at (FS_SIMVIZ_ALLOWED, FS_SIMVIZ_DURATION + 99.0);
	CHECK (s.done && s.packet == 1.0 && s.dest_glow == 1.0,
	       "time past the end freezes on the allowed end state");

	/* The allowed packet never moves backwards. */
	prev = 0.0;
	for (i = 0; i <= 52; i++) {
		s = fs_simviz_state_at (FS_SIMVIZ_ALLOWED, i * 0.05);
		if (s.packet < prev) {
			CHECK (FALSE, "allowed packet moved backwards at t=%.2f",
			       i * 0.05);
			break;
		}
		prev = s.packet;
	}
	CHECK (i > 52, "the allowed packet only ever moves forward");

	/* Blocked: travel, hit, bounce, gray. */
	s = fs_simviz_state_at (FS_SIMVIZ_BLOCKED, 1.3);
	CHECK (s.show_x && !s.show_check,
	       "blocked at 1.3s: the X is up, no check");
	CHECK (s.fw_red > 0.0 && s.shake > 0.0,
	       "blocked at 1.3s: the wall shakes red");
	CHECK (s.tail_blocked,
	       "blocked at 1.3s: the far line has turned gray");

	s = fs_simviz_state_at (FS_SIMVIZ_BLOCKED, 1.5);
	CHECK (s.packet > 0.0 && s.packet < 0.5,
	       "blocked at 1.5s: the packet bounces back");
	CHECK (s.packet_alpha < 1.0 && s.packet_alpha > 0.0,
	       "blocked at 1.5s: the bounced packet is fading");

	s = fs_simviz_state_at (FS_SIMVIZ_BLOCKED, 1.8);
	CHECK (s.packet < 0.0 && s.packet_alpha == 0.0,
	       "blocked after the bounce: the packet is gone");

	s = fs_simviz_state_at (FS_SIMVIZ_BLOCKED, FS_SIMVIZ_DURATION);
	CHECK (s.done && s.show_x && s.fw_red == 1.0 && s.shake == 0.0,
	       "blocked at the end: a still red wall, no shaking");
	CHECK (s.dest_glow == 0.0,
	       "blocked at the end: the far node never lights");

	s = fs_simviz_state_at (FS_SIMVIZ_BLOCKED, FS_SIMVIZ_DURATION + 99.0);
	CHECK (s.done && s.show_x && s.tail_blocked && s.dest_glow == 0.0,
	       "time past the end freezes on the blocked end state");

	/* Error: one frozen frame, no matter the clock. */
	s = fs_simviz_state_at (FS_SIMVIZ_ERROR, 0.0);
	CHECK (s.done && s.packet < 0.0 && !s.show_check && !s.show_x &&
	       s.fw_green == 0.0 && s.fw_red == 0.0,
	       "error at 0s: no packet, no verdict, already done");
	s = fs_simviz_state_at (FS_SIMVIZ_ERROR, 42.0);
	CHECK (s.done && s.packet < 0.0 && !s.tail_blocked,
	       "error at 42s: still nothing, still done");
}

/* ---------------------------------------------------------------- */
/* 2. The window                                                     */
/* ---------------------------------------------------------------- */
static void
test_allowed_window (void)
{
	FsScenario *sc = fs_copilot_parse_scenario (
		"allow ssh from 192.168.1.50 on port 22");
	FsSimulationResult *r = make_result (FALSE,
		"Matched rule 3: Allow inbound TCP 22.");
	GtkWidget *dialog;
	GtkWidget *badge;
	GtkWidget *hit;

	CHECK (sc != NULL, "the test scenario parses");
	if (sc == NULL)
		return;

	dialog = fs_simviz_dialog_new (r, sc,
	                               "allow ssh from 192.168.1.50 on port 22");
	gtk_widget_show_all (dialog);

	CHECK (GTK_IS_DIALOG (dialog), "the window is a dialog");
	CHECK (g_strcmp0 (gtk_window_get_title (GTK_WINDOW (dialog)),
	                  "What-If Simulation") == 0,
	       "the window is titled 'What-If Simulation'");

	hit = fs_simviz_find_label (dialog, "allow ssh from 192.168.1.50");
	CHECK (hit != NULL, "the chip shows the original question");

	badge = fs_simviz_find_label (dialog, "ALLOWED");
	CHECK (badge != NULL, "the banner says ALLOWED");
	if (badge != NULL)
		CHECK (label_has_class (badge, "fs-simviz-badge-ok"),
		       "the ALLOWED badge carries its green style");

	CHECK (fs_simviz_find_label (dialog, "TCP") != NULL,
	       "the details row names the protocol");
	CHECK (fs_simviz_find_label (dialog, "22") != NULL,
	       "the details row names the port");
	CHECK (fs_simviz_find_label (dialog, "192.168.1.50") != NULL,
	       "the details row names the source");
	CHECK (fs_simviz_find_label (dialog, "Inbound") != NULL,
	       "the details row names the direction");
	CHECK (fs_simviz_find_label (dialog, "Matched rule 3") != NULL,
	       "the explanation carries the bare reason");

	CHECK (fs_simviz_find_label (dialog, "To allow this") == NULL,
	       "an allowed verdict offers no fix-it line");
	CHECK (fs_simviz_find_button (dialog, "Create This Rule") == NULL,
	       "an allowed verdict has no Create This Rule button");

	hit = fs_simviz_find_button (dialog, "Replay");
	CHECK (hit != NULL, "the footer offers Replay");
	if (hit != NULL)
		CHECK (gtk_widget_get_sensitive (hit),
		       "the Replay button is actually clickable");
	hit = fs_simviz_find_button (dialog, "Close");
	CHECK (hit != NULL, "the footer offers Close");
	if (hit != NULL)
		CHECK (label_has_class (hit, "fs-simviz-primary"),
		       "the Close button carries the primary style");

	gtk_widget_destroy (dialog);
	fs_scenario_free (sc);
	fs_simulation_result_free (r);
}

static void
test_blocked_window (void)
{
	FsScenario *sc = fs_copilot_parse_scenario (
		"allow ssh from 192.168.1.50 on port 22");
	FsSimulationResult *r = make_result (TRUE,
		"No rule in the loaded policy matches this connection.");
	GtkWidget *dialog;
	GtkWidget *badge;

	CHECK (sc != NULL, "the blocked test scenario parses");
	if (sc == NULL)
		return;

	dialog = fs_simviz_dialog_new (r, sc, "ssh is open at 22 port");
	gtk_widget_show_all (dialog);

	badge = fs_simviz_find_label (dialog, "BLOCKED");
	CHECK (badge != NULL, "the banner says BLOCKED");
	if (badge != NULL)
		CHECK (label_has_class (badge, "fs-simviz-badge-bad"),
		       "the BLOCKED badge carries its red style");

	CHECK (fs_simviz_find_label (dialog,
		"To allow this, add a rule: Allow inbound TCP port 22 from 192.168.1.50.")
	       != NULL,
	       "the suggestion spells out the exact rule to add");
	CHECK (fs_simviz_find_label (dialog,
		"No rule in the loaded policy matches") != NULL,
	       "the explanation carries the bare reason");
	CHECK (fs_simviz_find_button (dialog, "Create This Rule") != NULL,
	       "a blocked, parsed line offers Create This Rule");
	CHECK (fs_simviz_find_button (dialog, "Replay") != NULL,
	       "a blocked verdict can be replayed");

	gtk_widget_destroy (dialog);
	fs_scenario_free (sc);
	fs_simulation_result_free (r);

	/* Blocked but never parsed: the button that would build a rule
	 * from the scenario must be absent, not sitting there dead. */
	r = make_result (TRUE, "Could not parse the line.");
	dialog = fs_simviz_dialog_new (r, NULL, "!!");
	gtk_widget_show_all (dialog);

	CHECK (fs_simviz_find_button (dialog, "Create This Rule") == NULL,
	       "a blocked but unparsed line has no Create This Rule");
	CHECK (fs_simviz_find_label (dialog, "To allow this") == NULL,
	       "a blocked but unparsed line has no rule suggestion");
	CHECK (fs_simviz_find_button (dialog, "Replay") != NULL,
	       "the verdict itself still replays");

	gtk_widget_destroy (dialog);
	fs_simulation_result_free (r);
}

static void
test_error_window (void)
{
	GtkWidget *dialog = fs_simviz_dialog_new (NULL, NULL,
	                                          "zqxv gibberish 42");

	gtk_widget_show_all (dialog);

	CHECK (fs_simviz_find_label (dialog, "Couldn't understand") != NULL,
	       "the error state says the query was not understood");
	CHECK (fs_simviz_find_label (dialog, "allow SSH from") != NULL,
	       "the error state shows an example query");
	CHECK (fs_simviz_find_label (dialog, "zqxv gibberish 42") != NULL,
	       "the chip still shows what was typed");

	CHECK (fs_simviz_find_label (dialog, "ALLOWED") == NULL &&
	       fs_simviz_find_label (dialog, "BLOCKED") == NULL,
	       "an unreadable line shows no verdict badge");
	CHECK (fs_simviz_find_label (dialog, "PROTOCOL") == NULL,
	       "an unreadable line shows no packet details");
	CHECK (fs_simviz_find_button (dialog, "Replay") == NULL,
	       "there is no animation to replay");
	CHECK (fs_simviz_find_button (dialog, "Create This Rule") == NULL,
	       "there is no rule to create");
	CHECK (fs_simviz_find_button (dialog, "Close") != NULL,
	       "the window can still be closed");

	gtk_widget_destroy (dialog);
}

int
main (int argc, char **argv)
{
	gtk_init (&argc, &argv);

	test_timeline ();
	test_allowed_window ();
	test_blocked_window ();
	test_error_window ();

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
