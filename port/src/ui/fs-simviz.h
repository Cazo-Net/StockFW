/*---[ fs-simviz.h ]----------------------------------------------------
 * The What-If Simulation Visualizer: a small modal window that plays
 * a verdict as a flat, Packet-Tracer-style diagram -- source, the
 * StockFW firewall, destination, and a packet that travels one and
 * learns whether it may continue.
 *
 * The component only presents.  The verdict comes from the What-If
 * engine (fs-whatif.h) untouched.  The one action button -- "Create
 * This Rule" for a verified CREATE_* action, "Lift Sentinel's Block"
 * for a Sentinel auto-block that decided -- merely returns a response;
 * what gets written to the policy stays the caller's decision, and the
 * caller checks the action again before it writes anything.
 *
 * The animation timeline is a pure function of (outcome, seconds),
 * so the tests can assert every frame without a display.
 *--------------------------------------------------------------------*/
#ifndef FS_SIMVIZ_H
#define FS_SIMVIZ_H

#include <gtk/gtk.h>
#include "core/fs-whatif.h"

G_BEGIN_DECLS

/* What the window is about to show. */
typedef enum
{
	FS_SIMVIZ_ALLOWED,   /* the traffic passes            */
	FS_SIMVIZ_BLOCKED,   /* the firewall stops it         */
	FS_SIMVIZ_DEPENDS,   /* it depends on what the line left
	                      * open: the packet waits at the
	                      * wall under a question mark    */
	FS_SIMVIZ_ERROR      /* the line could not be read    */
} FsSimvizOutcome;

/* Why the window closed. */
typedef enum
{
	FS_SIMVIZ_CLOSED,      /* Close, (X) or Esc            */
	FS_SIMVIZ_CREATE_RULE  /* the action button was pressed:
	                        * run fs_whatif_result_primary_action() */
} FsSimvizResponse;

/* One frame of the animation.  The drawing code only ever reads
 * this, which is what makes the timeline unit-testable. */
typedef struct
{
	gdouble  packet;       /* 0 = at source, 1 = at destination,
	                        * negative = hidden                */
	gdouble  packet_alpha; /* 0..1, fades out on a bounce back */
	gdouble  fw_green;     /* firewall flashes green, 0..1     */
	gdouble  fw_red;       /* firewall flashes red, 0..1       */
	gdouble  fw_amber;     /* firewall turns amber, 0..1       */
	gdouble  dest_glow;    /* destination glows green, 0..1    */
	gdouble  shake;        /* firewall shake amplitude, 0..1   */
	gdouble  t;            /* seconds since the play started   */
	gboolean show_check;   /* green check above the firewall   */
	gboolean show_x;       /* red X above the firewall         */
	gboolean show_question; /* amber "?" above the firewall    */
	gboolean tail_blocked; /* the far line turns gray/dashed   */
	gboolean done;         /* the timeline finished            */
} FsSimvizState;

/* The whole animation, in seconds.  Plays once when the window
 * opens; Replay restarts it from zero. */
#define FS_SIMVIZ_DURATION 2.6

/* Custom response id for the action button. */
#define FS_SIMVIZ_RESPONSE_CREATE 1001

/* Which animation a result maps to.  NULL or an ERROR verdict -- an
 * unreadable line -- is the error state: a neutral window with the
 * reason and examples, no verdict. */
FsSimvizOutcome fs_simviz_outcome_of (const FsWhatIfResult *result);

/* The frame at t seconds.  Times past the duration freeze on the
 * end state.  Pure: no GTK, no clock, no state. */
FsSimvizState fs_simviz_state_at (FsSimvizOutcome outcome, gdouble t);

/* Build the window: not shown, not run.  Tests build it, look at
 * it and destroy it.  result may be NULL (the error state); what the
 * window shows is copied out of it. */
GtkWidget *fs_simviz_dialog_new (const FsWhatIfResult *result,
                                 const gchar *query);

/* Show it modally over parent (may be NULL) and wait.  Returns what
 * the user chose; the dialog is destroyed before returning. */
FsSimvizResponse fs_simviz_run (GtkWidget *parent,
                                const FsWhatIfResult *result,
                                const gchar *query);

/* Widget walkers: the first label (or button) whose text carries
 * `needle`, depth-first.  The smoke test reads the window this way,
 * the way a user does -- by what is on screen. */
GtkWidget *fs_simviz_find_label  (GtkWidget *root, const gchar *needle);
GtkWidget *fs_simviz_find_button (GtkWidget *root, const gchar *needle);

G_END_DECLS

#endif /* FS_SIMVIZ_H */
