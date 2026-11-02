/*---[ fs-simviz.h ]----------------------------------------------------
 * The What-If Details window: one answer of the What-If engine
 * (fs-whatif.h), laid out so a person can check it.
 *
 *   - a header with the verdict and the question in plain words;
 *     a line asked without a direction gets one tab per direction;
 *   - a diagram that plays the verdict: the device the traffic starts
 *     from, the StockFW wall, the device it is going to -- each card
 *     says what it is (this computer, a LAN host, an Internet host) --
 *     and a packet that learns whether it may pass;
 *   - the facts the answer is about, the engine's trace with the step
 *     that decided, every fix the engine checked, and what the answer
 *     had to assume.
 *
 * The window is not modal: the Copilot page stays usable while it is
 * open, and asking again refreshes it in place.  It only presents.  A
 * button for a fix calls the action handler the caller installed; what
 * gets written to the policy stays the caller's decision, and the
 * caller checks a CREATE_* action again before it writes anything.
 *
 * The animation timeline is a pure function of (outcome, seconds), so
 * the tests can assert every frame without a display.  With animations
 * turned off (gtk-enable-animations, which follows the system setting)
 * the diagram shows its final frame at once.
 *--------------------------------------------------------------------*/
#ifndef FS_SIMVIZ_H
#define FS_SIMVIZ_H

#include <gtk/gtk.h>
#include "core/fs-whatif.h"

G_BEGIN_DECLS

/* What a diagram is about to show. */
typedef enum
{
	FS_SIMVIZ_ALLOWED,   /* the traffic passes            */
	FS_SIMVIZ_BLOCKED,   /* the firewall stops it         */
	FS_SIMVIZ_DEPENDS,   /* it depends on what the line left
	                      * open: the packet waits at the
	                      * wall under a question mark    */
	FS_SIMVIZ_ERROR      /* the line could not be read    */
} FsSimvizOutcome;

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

/* Which animation a result maps to.  NULL or an ERROR verdict -- an
 * unreadable line -- is the error state: no diagram, no verdict. */
FsSimvizOutcome fs_simviz_outcome_of (const FsWhatIfResult *result);

/* The same for one direction's answer. */
FsSimvizOutcome fs_simviz_outcome_of_answer (const FsWhatIfAnswer *answer);

/* The frame at t seconds.  Times past the duration freeze on the
 * end state.  Pure: no GTK, no clock, no state. */
FsSimvizState fs_simviz_state_at (FsSimvizOutcome outcome, gdouble t);

/* Where an address is, as the diagram's device cards say it.  Pure. */
typedef enum
{
	FS_SIMVIZ_ZONE_ANY,       /* the line named no host           */
	FS_SIMVIZ_ZONE_THIS,      /* this computer (loopback)         */
	FS_SIMVIZ_ZONE_LAN,       /* private, link-local or multicast */
	FS_SIMVIZ_ZONE_INTERNET   /* anything else                    */
} FsSimvizZone;

FsSimvizZone fs_simviz_zone_of (const gchar *host);

/* "This computer", "LAN host", "Internet hosts", "Any host" ... for
 * the card of `host' (NULL: any host). */
const gchar *fs_simviz_zone_title (const gchar *host);

/* ---- the window ---------------------------------------------------- */

/* Called when a fix's button is pressed (and when a rule name in the
 * trace is clicked: then `action' is an OPEN_RULE action naming that
 * row).  `action' and `result' stay valid for the duration of the call
 * even if the handler refreshes the window with a new result. */
typedef void (*FsSimvizActionFunc) (GtkWidget            *window,
                                    const FsWhatIfResult *result,
                                    const FsWhatIfAction *action,
                                    gpointer              user_data);

/* Builds the window, not shown.  Takes ownership of `result' (NULL is
 * the error state).  `ctx' is the context the answer was given in; the
 * window copies the facts it shows (platform, firewall state, network
 * profiles, whether the saved policy is live) and keeps no pointer.
 * NULL ctx: those facts are shown as not known.  `typed' is the line
 * as the user typed it (NULL: the query's own text), shown in the
 * header even when the line could not be read. */
GtkWidget *fs_simviz_window_new (FsWhatIfResult        *result,
                                 const FsWhatIfContext *ctx,
                                 const gchar           *typed);

/* Shows the answer to a new question (or the same question asked
 * again) in an existing window, in place.  Takes ownership of
 * `result'; the old one is released once the current event is done. */
void fs_simviz_window_set_result (GtkWidget             *window,
                                  FsWhatIfResult        *result,
                                  const FsWhatIfContext *ctx,
                                  const gchar           *typed);

const FsWhatIfResult *fs_simviz_window_get_result (GtkWidget *window);

void fs_simviz_window_set_action_func (GtkWidget         *window,
                                       FsSimvizActionFunc func,
                                       gpointer           user_data);

/* Transient for `parent' (may be NULL), not modal, shown, playing. */
void fs_simviz_window_present (GtkWidget *window, GtkWidget *parent);

/* Which direction's tab is shown, for a line answered both ways. */
void  fs_simviz_window_show_answer (GtkWidget *window, guint index);
guint fs_simviz_window_get_answer (GtkWidget *window);

/* A line under the header saying what a fix did: written to the
 * policy, live or not, and the answer asked again. */
typedef enum
{
	FS_SIMVIZ_STATUS_OK,
	FS_SIMVIZ_STATUS_WARN,
	FS_SIMVIZ_STATUS_BAD
} FsSimvizStatus;

void fs_simviz_window_set_status (GtkWidget     *window,
                                  FsSimvizStatus level,
                                  const gchar   *text);

/* TRUE when the system lets windows animate (gtk-enable-animations). */
gboolean fs_simviz_animations_enabled (void);

/* The What-If styles (window and Copilot card), installed once per
 * display.  The window installs them itself; the card calls this. */
void fs_simviz_install_css (void);

/* The verdict as a badge: a label with the What-If badge style and an
 * accessible name ("Verdict: BLOCKED").  Shared by the card and the
 * window so the two always look alike. */
GtkWidget *fs_simviz_badge_new (FsWhatIfVerdict verdict);

/* Widget walkers: the first label (or button) whose text carries
 * `needle', depth-first.  The smoke tests read the window this way,
 * the way a user does -- by what is on screen. */
GtkWidget *fs_simviz_find_label  (GtkWidget *root, const gchar *needle);
GtkWidget *fs_simviz_find_button (GtkWidget *root, const gchar *needle);
/* The first widget with this name (gtk_widget_set_name). */
GtkWidget *fs_simviz_find_named  (GtkWidget *root, const gchar *name);

G_END_DECLS

#endif /* FS_SIMVIZ_H */
