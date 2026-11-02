/* Checks the What-If Simulation Visualizer does what its four
 * outcomes promise, in two layers:
 *
 *   1. the timeline -- fs_simviz_state_at() is pure math, so every
 *      phase is asserted without a display: the packet travels, the
 *      firewall answers green or red, a blocked packet bounces back
 *      and fades while the far line grays out, an allowed one lands
 *      and lights the far node, a DEPENDS one waits at the wall under
 *      an amber question mark, and an unreadable line has no timeline
 *      at all;
 *
 *   2. the window -- each variant is built from a real What-If answer
 *      (the engine run against a small policy) and read the way a
 *      user reads it: by what is on screen.  The badge says ALLOWED,
 *      BLOCKED or DEPENDS (or stays absent for an error), the details
 *      row carries what the line was read as, and the action button
 *      exists only when the engine verified something it can run:
 *      "Create This Rule" for a checked row, "Lift Sentinel's Block"
 *      for a Sentinel block -- never an allow next to a block rule.
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/fs-whatif.h"
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

static gboolean
label_has_class (GtkWidget *label, const gchar *class_name)
{
	return gtk_style_context_has_class (
		gtk_widget_get_style_context (label), class_name);
}

/* A policy of the given rows ("kind:csv", NULL-terminated). */
static FsPolicy *
policy_of (const gchar *const *rows)
{
	FsPolicy *p = fs_policy_new ();

	for (guint i = 0; rows != NULL && rows[i] != NULL; i++) {
		gchar *colon = strchr (rows[i], ':');
		FsRule *r = fs_rule_from_csv ((FsRuleKind) atoi (rows[i]),
		                              colon + 1);

		if (r == NULL) {
			CHECK (FALSE, "fixture row parses: %s", rows[i]);
			continue;
		}
		fs_policy_add (p, r);
	}
	return p;
}

/* The engine's answer to one line, Linux model, firewall running. */
static FsWhatIfResult *
ask (FsWhatIfPlatform platform, const FsPolicy *policy,
     const gchar *sentinel, const gchar *line)
{
	FsSettings *s = fs_settings_new ();
	FsWhatIfContext *ctx = fs_whatif_context_new (platform, policy, s);
	FsWhatIfResult *r;

	ctx->firewall = FS_WHATIF_FW_RUNNING;
	ctx->live = FS_WHATIF_LIVE_YES;
	if (sentinel != NULL)
		fs_whatif_context_add_auto_block (
			ctx, sentinel, g_get_real_time () / G_USEC_PER_SEC + 420);

	r = fs_whatif_simulate_text (ctx, line);

	fs_whatif_context_free (ctx);
	fs_settings_free (s);
	return r;
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

	/* Depends: travel to the wall and wait there, neither green nor
	 * red, never past the wall, never bounced. */
	s = fs_simviz_state_at (FS_SIMVIZ_DEPENDS, 0.5);
	CHECK (s.packet > 0.0 && s.packet < 0.5 && !s.show_question,
	       "depends at 0.5s: on the first leg, no verdict yet");
	s = fs_simviz_state_at (FS_SIMVIZ_DEPENDS, 1.3);
	CHECK (s.show_question && s.fw_amber > 0.0 && s.packet == 0.5,
	       "depends at 1.3s: the question mark is up, the packet waits");
	prev = 0.0;
	for (i = 0; i <= 60; i++) {
		s = fs_simviz_state_at (FS_SIMVIZ_DEPENDS, i * 0.05);
		if (s.packet > 0.5 || s.packet < prev || s.show_check ||
		    s.show_x || s.fw_green > 0.0 || s.fw_red > 0.0 ||
		    s.dest_glow > 0.0 || s.tail_blocked)
			break;
		prev = s.packet;
	}
	CHECK (i > 60,
	       "a DEPENDS packet never passes the wall, bounces, or gets a "
	       "check, an X, green, red or a glow");
	s = fs_simviz_state_at (FS_SIMVIZ_DEPENDS, FS_SIMVIZ_DURATION + 9.0);
	CHECK (s.done && s.packet == 0.5 && s.fw_amber == 1.0 &&
	       s.show_question,
	       "depends at the end: waiting at an amber wall under a '?'");

	/* Error: one frozen frame, no matter the clock. */
	s = fs_simviz_state_at (FS_SIMVIZ_ERROR, 0.0);
	CHECK (s.done && s.packet < 0.0 && !s.show_check && !s.show_x &&
	       !s.show_question && s.fw_green == 0.0 && s.fw_red == 0.0,
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
	static const gchar *rows[] = { "1:SSH,22,192.168.1.50,lab", NULL };
	FsPolicy *p = policy_of (rows);
	FsWhatIfResult *r = ask (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL,
	                         "allow ssh from 192.168.1.50");
	GtkWidget *dialog;
	GtkWidget *badge;
	GtkWidget *hit;

	CHECK (fs_simviz_outcome_of (r) == FS_SIMVIZ_ALLOWED,
	       "an allowed answer maps to the allowed script");

	dialog = fs_simviz_dialog_new (r, "allow ssh from 192.168.1.50");
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
	CHECK (fs_simviz_find_label (dialog, "You asked to allow this") != NULL,
	       "the explanation answers the user's verb");
	CHECK (fs_simviz_find_label (dialog, "Allow SSH (inbound, 192.168.1.50)") != NULL,
	       "the explanation names the deciding rule");

	CHECK (fs_simviz_find_button (dialog, "Create This Rule") == NULL,
	       "an allowed answer has no Create This Rule button");

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
	fs_whatif_result_free (r);
	fs_policy_free (p);
}

static void
test_blocked_window (void)
{
	static const gchar *deny[] = { "6:203.0.113.9,known bad", NULL };
	FsPolicy *empty = fs_policy_new ();
	FsPolicy *p = policy_of (deny);
	FsWhatIfResult *r = ask (FS_WHATIF_LINUX_FIRST_MATCH, empty, NULL,
	                         "allow ssh from 192.168.1.50");
	const FsWhatIfAction *act = fs_whatif_result_create_action (r);
	GtkWidget *dialog;
	GtkWidget *badge;

	CHECK (fs_simviz_outcome_of (r) == FS_SIMVIZ_BLOCKED,
	       "a blocked answer maps to the blocked script");
	CHECK (act != NULL && act->verified &&
	       act->kind == FS_WHATIF_ACT_CREATE_ALLOW,
	       "the default decided, so a verified allow row is offered");

	dialog = fs_simviz_dialog_new (r, "allow ssh from 192.168.1.50");
	gtk_widget_show_all (dialog);

	badge = fs_simviz_find_label (dialog, "BLOCKED");
	CHECK (badge != NULL, "the banner says BLOCKED");
	if (badge != NULL)
		CHECK (label_has_class (badge, "fs-simviz-badge-bad"),
		       "the BLOCKED badge carries its red style");
	CHECK (fs_simviz_find_label (dialog,
		"Allow inbound TCP port 22 from 192.168.1.50") != NULL,
	       "the suggestion spells out the exact row");
	CHECK (fs_simviz_find_label (dialog, "Checked:") != NULL,
	       "the suggestion says it was checked");
	CHECK (fs_simviz_find_button (dialog, "Create This Rule") != NULL,
	       "a verified row offers Create This Rule");
	CHECK (fs_simviz_find_button (dialog, "Replay") != NULL,
	       "a blocked verdict can be replayed");
	gtk_widget_destroy (dialog);

	/* The same answer with the row's check taken away: no button. */
	((FsWhatIfAction *) act)->verified = FALSE;
	dialog = fs_simviz_dialog_new (r, "allow ssh from 192.168.1.50");
	CHECK (fs_simviz_find_button (dialog, "Create This Rule") == NULL,
	       "an unverified row has no Create This Rule button");
	gtk_widget_destroy (dialog);
	fs_whatif_result_free (r);

	/* A block rule decided: the way out is that rule, never an allow
	 * row next to it. */
	r = ask (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL,
	         "allow outbound tcp to 203.0.113.9 port 443");
	dialog = fs_simviz_dialog_new (r, "allow outbound tcp to 203.0.113.9 "
	                                  "port 443");
	CHECK (fs_simviz_outcome_of (r) == FS_SIMVIZ_BLOCKED,
	       "the denied host is blocked");
	CHECK (fs_whatif_result_create_action (r) == NULL &&
	       fs_simviz_find_button (dialog, "Create This Rule") == NULL,
	       "a block rule decided: no allow row, no Create This Rule");
	CHECK (fs_simviz_find_label (dialog, "Open rule") != NULL,
	       "the suggestion points at the rule that decided");
	gtk_widget_destroy (dialog);
	fs_whatif_result_free (r);

	/* Sentinel decided: the button lifts Sentinel's block. */
	{
		static const gchar *sent[] = {
			"6:203.0.113.50,Sentinel: beaconing", NULL };
		FsPolicy *sp = policy_of (sent);

		r = ask (FS_WHATIF_LINUX_FIRST_MATCH, sp, "203.0.113.50",
		         "allow outbound tcp to 203.0.113.50 port 443");
		dialog = fs_simviz_dialog_new (r, "allow outbound tcp to "
		                                  "203.0.113.50 port 443");
		CHECK (fs_simviz_find_button (dialog, "Lift Sentinel's Block")
		       != NULL &&
		       fs_simviz_find_button (dialog, "Create This Rule") == NULL,
		       "a Sentinel block offers Lift Sentinel's Block, not a rule");
		CHECK (fs_simviz_find_label (dialog, "minutes") != NULL,
		       "the suggestion says when Sentinel's block expires");
		gtk_widget_destroy (dialog);
		fs_whatif_result_free (r);
		fs_policy_free (sp);
	}

	fs_policy_free (p);
	fs_policy_free (empty);
}

static void
test_depends_window (void)
{
	static const gchar *rows[] = { "1:SSH,22,10.0.0.0/8,lan", NULL };
	FsPolicy *p = policy_of (rows);
	FsWhatIfResult *r = ask (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL,
	                         "inbound ssh");
	GtkWidget *dialog;
	GtkWidget *badge;

	CHECK (fs_simviz_outcome_of (r) == FS_SIMVIZ_DEPENDS,
	       "a split answer maps to the depends script");

	dialog = fs_simviz_dialog_new (r, "inbound ssh");
	gtk_widget_show_all (dialog);

	badge = fs_simviz_find_label (dialog, "DEPENDS");
	CHECK (badge != NULL, "the banner says DEPENDS");
	if (badge != NULL)
		CHECK (label_has_class (badge, "fs-simviz-badge-warn"),
		       "the DEPENDS badge carries its amber style");
	CHECK (fs_simviz_find_label (dialog, "ALLOWED") == NULL &&
	       fs_simviz_find_label (dialog, "BLOCKED") == NULL,
	       "a split answer is never shown as one verdict");
	CHECK (fs_simviz_find_label (dialog, "allowed from 10.0.0.0/8") != NULL,
	       "the explanation names the split");
	gtk_widget_destroy (dialog);
	fs_whatif_result_free (r);

	/* No direction: both ways. */
	r = ask (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL, "ssh");
	dialog = fs_simviz_dialog_new (r, "ssh");
	gtk_widget_show_all (dialog);
	CHECK (fs_simviz_find_label (dialog, "Both ways") != NULL,
	       "a line with no direction is shown as both ways");
	CHECK (fs_simviz_find_label (dialog, "Outbound: ALLOWED") != NULL,
	       "the explanation answers each direction");
	gtk_widget_destroy (dialog);
	fs_whatif_result_free (r);

	/* Windows: what was assumed is on screen. */
	r = ask (FS_WHATIF_WINDOWS_BLOCK_WINS, p, NULL, "inbound rdp");
	dialog = fs_simviz_dialog_new (r, "inbound rdp");
	gtk_widget_show_all (dialog);
	CHECK (fs_simviz_find_label (dialog, "Good to know") != NULL &&
	       fs_simviz_find_label (dialog, "Only the rules StockFW manages")
	       != NULL,
	       "the assumptions are shown, not hidden");
	gtk_widget_destroy (dialog);
	fs_whatif_result_free (r);

	fs_policy_free (p);
}

static void
test_error_window (void)
{
	FsPolicy *p = fs_policy_new ();
	FsWhatIfResult *r = ask (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL,
	                         "zqxv gibberish");
	GtkWidget *dialog;

	CHECK (fs_simviz_outcome_of (NULL) == FS_SIMVIZ_ERROR &&
	       fs_simviz_outcome_of (r) == FS_SIMVIZ_ERROR,
	       "no answer, or an unreadable line, maps to the error state");

	dialog = fs_simviz_dialog_new (r, "zqxv gibberish");
	gtk_widget_show_all (dialog);

	CHECK (fs_simviz_find_label (dialog, "Couldn't understand") != NULL,
	       "the error state says the query was not understood");
	CHECK (fs_simviz_find_label (dialog, "I could not find a port") != NULL,
	       "the error state says what it looked for");
	CHECK (fs_simviz_find_label (dialog, "allow SSH from") != NULL,
	       "the error state shows an example query");
	CHECK (fs_simviz_find_label (dialog, "zqxv gibberish") != NULL,
	       "the chip still shows what was typed");

	CHECK (fs_simviz_find_label (dialog, "ALLOWED") == NULL &&
	       fs_simviz_find_label (dialog, "BLOCKED") == NULL &&
	       fs_simviz_find_label (dialog, "DEPENDS") == NULL,
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
	fs_whatif_result_free (r);

	r = ask (FS_WHATIF_LINUX_FIRST_MATCH, p, NULL, "inbound tcp port 0");
	dialog = fs_simviz_dialog_new (r, "inbound tcp port 0");
	CHECK (fs_simviz_outcome_of (r) == FS_SIMVIZ_ERROR &&
	       fs_simviz_find_label (dialog, "Couldn't understand") != NULL,
	       "port 0 is an error, not an answer for every port");
	gtk_widget_destroy (dialog);
	fs_whatif_result_free (r);

	dialog = fs_simviz_dialog_new (NULL, "zqxv");
	CHECK (fs_simviz_find_label (dialog, "Couldn't understand") != NULL,
	       "no answer at all is the error state too");
	gtk_widget_destroy (dialog);

	fs_policy_free (p);
}

int
main (int argc, char **argv)
{
	gtk_init (&argc, &argv);

	test_timeline ();
	test_allowed_window ();
	test_blocked_window ();
	test_depends_window ();
	test_error_window ();

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);

	return failures ? 1 : 0;
}
