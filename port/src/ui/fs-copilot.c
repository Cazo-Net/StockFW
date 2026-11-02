/*---[ fs-copilot.c ]---------------------------------------------------
 * The Copilot page (1.0.7).
 *
 * Rule-based checks of the event log and the policy, run on this
 * computer.  Nothing here learns a model or sends anything anywhere;
 * every finding names the check that raised it and the events behind
 * it.  The page has:
 *
 *   - Sentinel: Detect only, or Detect + auto-block (outbound blocks to
 *     unknown public addresses, ten minutes each);
 *   - four tiles: findings that need attention, policy health findings,
 *     auto-blocks active, and apps (services on Linux) learned;
 *   - Findings: one row per finding with a severity pill (icon and
 *     word); Enter or a click opens its drawer: what was seen, why it
 *     was flagged, why it could be harmless, and what Sentinel did;
 *   - Policy health (core/fs-health.h): overlaps, conflicts and risky
 *     open services, each fix checked with What-If before it is
 *     offered, asked again before it is written, confirmed, and undone
 *     from the Changes card;
 *   - the What-If card;
 *   - Changes made by the Copilot, newest first, each with Undo.
 *
 * Colours come from the theme classes (fs-theme.css, and the What-If
 * styles for the pills); a dark desktop theme gets the dark variants.
 *--------------------------------------------------------------------*/

#include "fs-copilot.h"
#include "core/fs-copilot.h"
#include "core/fs-health.h"
#include "core/fs-rules.h"
#include "core/fs-fwrule.h"
#include "core/fs-backend.h"
#include "core/fs-prefs.h"
#include "core/fs-audit.h"
#include "core/fs-util.h"
#include "ui/fs-app.h"
#include "ui/fs-icons.h"
#include "ui/fs-policyview.h"
#include "ui/fs-hitview.h"
#include "ui/fs-simviz.h"
#include "ui/fs-dialogs.h"
#include "ui/fs-statusview.h"
#include "core/fs-apply.h"
#include "core/fs-i18n.h"
#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#endif

/* =====================================================================
 * Widget state
 * ===================================================================== */
static GtkWidget     *scenario_entry   = NULL;   /* What-If card */
static GtkWidget     *sim_output       = NULL;   /* What-If log  */
static GtkWidget     *copilot_vbox     = NULL;   /* the page     */

static GtkWidget     *sentinel_detect  = NULL;
static GtkWidget     *sentinel_auto    = NULL;
static GtkWidget     *sentinel_strip   = NULL;

static GtkWidget     *tile_attention   = NULL;   /* value labels */
static GtkWidget     *tile_attention_note = NULL;
static GtkWidget     *tile_health      = NULL;
static GtkWidget     *tile_health_note = NULL;
static GtkWidget     *tile_blocks      = NULL;
static GtkWidget     *tile_blocks_note = NULL;
static GtkWidget     *tile_learned     = NULL;
static GtkWidget     *tile_learned_note = NULL;

static GtkWidget     *findings_list    = NULL;
static GtkWidget     *findings_frame   = NULL;   /* the list's card */
static GtkWidget     *findings_count   = NULL;
static GtkWidget     *findings_empty   = NULL;
static GtkWidget     *findings_empty_text = NULL;
static GtkWidget     *findings_reason  = NULL;
static GtkWidget     *findings_checked = NULL;
static GtkWidget     *findings_strip   = NULL;

static GtkWidget     *health_list      = NULL;
static GtkWidget     *health_frame     = NULL;
static GtkWidget     *health_summary   = NULL;
static GtkWidget     *health_empty     = NULL;
static GtkWidget     *health_strip     = NULL;

static GtkWidget     *changes_list     = NULL;
static GtkWidget     *changes_frame    = NULL;
static GtkWidget     *changes_empty    = NULL;
static GtkWidget     *changes_strip    = NULL;

static FsCopilot     *global_copilot   = NULL;
static FsPolicy      *copilot_policy   = NULL;
static guint          total_events     = 0;
static guint          refresh_id       = 0;

/* The last health check: FsHealthFinding*, most severe first. */
static GPtrArray     *health_findings  = NULL;
static guint          health_rules     = 0;
static gint64         health_at        = 0;

/* Session memory, by a finding's key. */
static GHashTable    *dismissed        = NULL;   /* key -> TRUE        */
static GHashTable    *expanded         = NULL;   /* key -> TRUE        */
static GHashTable    *verify_cache     = NULL;   /* key -> reason, ""
                                                  * when verified     */

/* ===== Sentinel state (1.0.4) =====================================
 *
 * Mode is detect|auto (default auto), cached so the per-event pass
 * does not read the key file.  Auto-blocked rules are tracked with
 * the time they were staged: the user can undo any of them, and
 * every one expires ten minutes after staging unless it was staged
 * manually through the Policy page first. */
static gchar          sentinel_mode[16] = "auto";

#define FS_AUTOBLOCK_TTL_S 600     /* auto-blocks lift after 10 min */
#define FS_AUTOBLOCK_RETRY_US (60 * G_USEC_PER_SEC)

typedef struct
{
    FsRuleKind kind;
    gchar     *csv;                /* the staged rule, for removal */
    gchar     *title;              /* insight title, for messages  */
    gint64     at_us;              /* when it was staged (monotonic) */
    gint64     at_epoch;           /* staging time, wall clock (persisted) */
} AutoBlock;

static GPtrArray *auto_blocks       = NULL;  /* AutoBlock*, free_func set */
static guint      auto_block_expiry_id = 0;
static gint64     auto_block_last_fail = 0;
static gboolean   auto_block_failed_once = FALSE;

/* P6: session memory of every auto-block this process staged and then
 * took down (expiry, Undo, user allow, mode switch).  Staging the
 * same rule again is the 2026-10-10 incident -- drop after ten
 * minutes, re-block the next second, forever -- so the auto pass
 * refuses it.  Memory-only by design: it protects the session from a
 * loop and never outlives the process, so a restart makes a fresh
 * decision instead of inheriting a grudge. */
static GHashTable *auto_block_cooldown = NULL;  /* "kind|csv" -> TRUE */

/* Changes made from this page (block rules added, health fixes), for
 * the Changes card.  Auto-blocks are listed from auto_blocks. */
typedef enum
{
    CP_CHANGE_BLOCK_RULE,
    CP_CHANGE_HEALTH_FIX
} CpChangeKind;

typedef struct
{
    CpChangeKind  kind;
    gint64        at;              /* unix seconds                 */
    gchar        *label;
    FsRuleKind    rule_kind;       /* BLOCK_RULE                   */
    gchar        *csv;             /* BLOCK_RULE                   */
    FsHealthUndo *undo;            /* HEALTH_FIX                   */
} CpChange;

static GPtrArray *changes = NULL;    /* CpChange*, oldest first */

/* =====================================================================
 * Forward declarations
 * ===================================================================== */
static void refresh_insights (void);
static void update_stats (void);
static void health_run (void);
static void changes_render (void);
static GtkWidget *whatif_card_new (void);
static void whatif_ask (const gchar *line);
static void on_simulate_clicked (GtkButton *btn, gpointer data);
static FsWhatIfContext *whatif_context_build (FsSettings *settings);
static const gchar *apply_result_text (FsApplyResult result);
static gboolean auto_block_expire_cb (gpointer data);
static void auto_block_retire (AutoBlock *ab, const gchar *why);
static void auto_block_push (void);
static gboolean auto_block_cooldown_contains (FsRuleKind kind,
                                              const gchar *csv);

/* =====================================================================
 * Small helpers
 * ===================================================================== */
/* One class, or several separated by spaces. */
static void
add_class (GtkWidget *w, const gchar *names)
{
    gchar **v;

    if (w == NULL || names == NULL)
        return;
    v = g_strsplit (names, " ", -1);
    for (guint i = 0; v[i] != NULL; i++)
        if (*v[i] != '\0')
            gtk_style_context_add_class (gtk_widget_get_style_context (w),
                                         v[i]);
    g_strfreev (v);
}

static GtkWidget *
text_new (const gchar *text, const gchar *cls, gboolean wrap)
{
    GtkWidget *l = gtk_label_new (text);

    add_class (l, cls);
    gtk_label_set_xalign (GTK_LABEL (l), 0.0);
    if (wrap) {
        gtk_label_set_line_wrap (GTK_LABEL (l), TRUE);
        gtk_label_set_line_wrap_mode (GTK_LABEL (l), PANGO_WRAP_WORD_CHAR);
    }
    gtk_label_set_selectable (GTK_LABEL (l), FALSE);
    return l;
}

static GtkWidget *
button_new (const gchar *label, const gchar *cls, const gchar *name)
{
    GtkWidget *b = gtk_button_new_with_label (label);

    add_class (b, cls);
    if (name != NULL)
        gtk_widget_set_name (b, name);
    gtk_widget_set_valign (b, GTK_ALIGN_CENTER);
    return b;
}

/* =====================================================================
 * Helper: button with one of the app's drawn icons + label
 *
 * FS_ICON_N_KINDS means no icon.  The drawn icons replace the theme's
 * ("system-search", "list-add" ...): which of those a Windows runtime
 * ships is not something the page can count on, and a missing one
 * renders as a broken-image square.
 * ===================================================================== */
static GtkWidget *
button_with_icon (FsIconKind icon, const gchar *label)
{
    GtkWidget *btn = gtk_button_new ();
    GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *lbl = gtk_label_new (label);

    if (icon != FS_ICON_N_KINDS)
        gtk_box_pack_start (GTK_BOX (box), fs_icon_new (icon, 14),
                            FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (box), lbl, FALSE, FALSE, 0);
    gtk_widget_set_halign (box, GTK_ALIGN_CENTER);
    gtk_container_add (GTK_CONTAINER (btn), box);
    return btn;
}

/* Shows or hides a widget that stays out of the page's show_all while
 * it is empty (no_show_all). */
static void
reveal (GtkWidget *w, gboolean on)
{
    if (w == NULL)
        return;
    gtk_widget_set_no_show_all (w, !on);
    if (on)
        gtk_widget_show_all (w);
    else
        gtk_widget_hide (w);
}

/* A status line inside a card: what an action did.  level is "ok",
 * "warn" or "bad"; NULL text hides it. */
static void
strip_set (GtkWidget *strip, const gchar *level, const gchar *text)
{
    GtkStyleContext *sc;

    if (strip == NULL)
        return;
    if (text == NULL || *text == '\0') {
        reveal (strip, FALSE);
        return;
    }
    sc = gtk_widget_get_style_context (strip);
    gtk_style_context_remove_class (sc, "ok-strip");
    gtk_style_context_remove_class (sc, "warning-strip");
    gtk_style_context_remove_class (sc, "error-strip");
    gtk_style_context_add_class (sc,
        g_strcmp0 (level, "bad") == 0 ? "error-strip"
        : g_strcmp0 (level, "warn") == 0 ? "warning-strip" : "ok-strip");
    gtk_label_set_text (GTK_LABEL (strip), text);
    reveal (strip, TRUE);
}

static GtkWidget *
strip_new (const gchar *name)
{
    GtkWidget *s = text_new ("", "cp-strip", TRUE);

    gtk_widget_set_name (s, name);
    gtk_widget_set_no_show_all (s, TRUE);
    return s;
}

static void
clear_container (GtkWidget *box)
{
    GList *kids, *l;

    if (box == NULL)
        return;
    kids = gtk_container_get_children (GTK_CONTAINER (box));
    for (l = kids; l != NULL; l = l->next)
        gtk_widget_destroy (l->data);
    g_list_free (kids);
}

/* "just now", "4 min ago", "3 h ago", or the date. */
static gchar *
ago_text (gint64 when)
{
    gint64 now = g_get_real_time () / G_USEC_PER_SEC;
    gint64 d = now - when;

    if (when <= 0)
        return g_strdup ("");
    if (d < 60)
        return g_strdup (_("just now"));
    if (d < 3600)
        return g_strdup_printf (_("%d min ago"), (gint) (d / 60));
    if (d < 86400)
        return g_strdup_printf (_("%d h ago"), (gint) (d / 3600));
    {
        GDateTime *dt = g_date_time_new_from_unix_local (when);
        gchar *s = g_date_time_format (dt, "%Y-%m-%d");

        g_date_time_unref (dt);
        return s;
    }
}

static gchar *
clock_text (gint64 when)
{
    GDateTime *dt = g_date_time_new_from_unix_local (when);
    gchar *s = g_date_time_format (dt, "%H:%M");

    g_date_time_unref (dt);
    return s;
}

static const gchar *
severity_word (FsCopilotSeverity sev)
{
    switch (sev) {
    case FS_COPILOT_CRITICAL: return _("Critical");
    case FS_COPILOT_WARNING:  return _("Warning");
    case FS_COPILOT_INFO:
    default:                  return _("Info");
    }
}

/* A severity pill: an icon and the word, in the What-If badge styles,
 * so it never depends on colour alone. */
static GtkWidget *
severity_pill (FsCopilotSeverity sev)
{
    GtkWidget *pill = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
    FsIconKind icon = sev == FS_COPILOT_CRITICAL ? FS_ICON_SHIELD_X
                      : sev == FS_COPILOT_WARNING ? FS_ICON_SHIELD_ALERT
                                                  : FS_ICON_INFO;

    fs_simviz_install_css ();
    add_class (pill, "fs-wi-badge");
    add_class (pill, "cp-pill");
    add_class (pill, sev == FS_COPILOT_CRITICAL ? "bad"
                     : sev == FS_COPILOT_WARNING ? "warn" : "ok");
    gtk_box_pack_start (GTK_BOX (pill), fs_icon_new (icon, 12),
                        FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (pill), gtk_label_new (severity_word (sev)),
                        FALSE, FALSE, 0);
    gtk_widget_set_name (pill, "cp-pill");
    gtk_widget_set_valign (pill, GTK_ALIGN_START);
    gtk_widget_set_halign (pill, GTK_ALIGN_START);
    return pill;
}

static const gchar *
rule_kind_words (gint kind)
{
    switch (kind) {
    case FS_RULE_INBOUND_ALLOW_FROM:     return _("Inbound allow from host");
    case FS_RULE_INBOUND_ALLOW_SERVICE:  return _("Inbound service");
    case FS_RULE_INBOUND_FORWARD:        return _("Port forward");
    case FS_RULE_OUTBOUND_ALLOW_TO:      return _("Outbound allow to host");
    case FS_RULE_OUTBOUND_ALLOW_FROM:    return _("Outbound allow from host");
    case FS_RULE_OUTBOUND_ALLOW_SERVICE: return _("Outbound service");
    case FS_RULE_OUTBOUND_DENY_TO:       return _("Outbound deny to host");
    case FS_RULE_OUTBOUND_DENY_FROM:     return _("Outbound deny from host");
    case FS_RULE_OUTBOUND_DENY_SERVICE:  return _("Outbound deny service");
    default:                             return _("Rule");
    }
}

/* Dark when the theme writes light text, as the What-If window
 * decides it. */
static gboolean
theme_is_dark (void)
{
    /* A window, not a bare label: an unparented label inherits no
     * theme colour (CSS initial is white), a window gets the theme's. */
    GtkWidget *probe = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    GtkStyleContext *sc = gtk_widget_get_style_context (probe);
    GdkRGBA fg;
    gboolean dark;

    gtk_style_context_get_color (sc, gtk_style_context_get_state (sc), &fg);
    dark = (0.2126 * fg.red + 0.7152 * fg.green + 0.0722 * fg.blue) > 0.6;
    gtk_widget_destroy (probe);
    return dark;
}

/* =====================================================================
 * Helper: create a styled text view for output (the What-If log)
 * ===================================================================== */
static GtkWidget *
make_output_view (void)
{
    GtkWidget *scrolled = gtk_scrolled_window_new (NULL, NULL);
    gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled),
                                    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    /* The theme's .output-view draws the border; no double frame. */
    gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scrolled),
                                         GTK_SHADOW_NONE);
    gtk_style_context_add_class (gtk_widget_get_style_context (scrolled),
                                 "output-view");

    GtkWidget *view = gtk_text_view_new ();
    gtk_text_view_set_editable (GTK_TEXT_VIEW (view), FALSE);
    gtk_text_view_set_cursor_visible (GTK_TEXT_VIEW (view), FALSE);
    gtk_text_view_set_wrap_mode (GTK_TEXT_VIEW (view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin (GTK_TEXT_VIEW (view), 8);
    gtk_text_view_set_right_margin (GTK_TEXT_VIEW (view), 8);
    gtk_text_view_set_top_margin (GTK_TEXT_VIEW (view), 6);
    gtk_text_view_set_bottom_margin (GTK_TEXT_VIEW (view), 6);

    gtk_container_add (GTK_CONTAINER (scrolled), view);
    return scrolled;
}

/* The colour of a tone class (tone-ok, tone-bad ...) on this widget,
 * from the theme: the stylesheet has a light and a dark value for
 * each, so the log stays readable on either. */
static void
tone_color (GtkWidget *w, const gchar *tone, GdkRGBA *out)
{
    GtkStyleContext *sc = gtk_widget_get_style_context (w);

    gtk_style_context_save (sc);
    gtk_style_context_add_class (sc, tone);
    gtk_style_context_get_color (sc, gtk_style_context_get_state (sc), out);
    gtk_style_context_restore (sc);
}

/* =====================================================================
 * Helper: append text to a GtkTextView with optional style tag.  The
 * tags keep their old names (green, red, orange, blue, dim); their
 * colours come from the theme's tone classes.
 * ===================================================================== */
static void
text_view_append (GtkWidget *scrolled, const gchar *text, const gchar *tag)
{
    GtkWidget *view = gtk_bin_get_child (GTK_BIN (scrolled));
    if (!GTK_IS_TEXT_VIEW (view))
        return;

    GtkTextBuffer *buf = gtk_text_view_get_buffer (GTK_TEXT_VIEW (view));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter (buf, &end);

    if (tag) {
        GtkTextTag *t = gtk_text_tag_table_lookup (
            gtk_text_buffer_get_tag_table (buf), tag);
        if (!t) {
            const gchar *tone = NULL;

            t = gtk_text_tag_new (tag);
            if (g_strcmp0 (tag, "bold") == 0)
                g_object_set (t, "weight", PANGO_WEIGHT_BOLD, NULL);
            else if (g_strcmp0 (tag, "title") == 0)
                g_object_set (t, "weight", PANGO_WEIGHT_BOLD,
                              "scale", 1.15, NULL);
            else if (g_strcmp0 (tag, "green") == 0)
                tone = "tone-ok";
            else if (g_strcmp0 (tag, "red") == 0)
                tone = "tone-bad";
            else if (g_strcmp0 (tag, "orange") == 0)
                tone = "tone-warn";
            else if (g_strcmp0 (tag, "blue") == 0)
                tone = "tone-info";
            else if (g_strcmp0 (tag, "dim") == 0)
                tone = "tone-dim";
            if (tone != NULL) {
                GdkRGBA c;

                tone_color (view, tone, &c);
                g_object_set (t, "foreground-rgba", &c, NULL);
                if (g_strcmp0 (tone, "tone-bad") == 0 ||
                    g_strcmp0 (tone, "tone-warn") == 0)
                    g_object_set (t, "weight", PANGO_WEIGHT_SEMIBOLD, NULL);
            }
            gtk_text_tag_table_add (
                gtk_text_buffer_get_tag_table (buf), t);
            g_object_unref (t);
        }
        gtk_text_buffer_insert_with_tags_by_name (buf, &end, text, -1, tag, NULL);
    } else {
        gtk_text_buffer_insert (buf, &end, text, -1);
    }

    gtk_text_view_scroll_to_iter (GTK_TEXT_VIEW (view), &end, 0, FALSE, 0, 0);
}

/* =====================================================================
 * The apply gate, reported into a card's strip
 * ===================================================================== */
static void
cp_push (const gchar *why, GtkWidget *strip, const gchar *done)
{
    GError *error = NULL;
    FsApplyOutcome *outcome;
    gchar *text;

    if (copilot_policy == NULL)
        return;

    outcome = fs_policy_apply_safe (fs_backend (), copilot_policy, why,
                                    fs_policyview_hold_reason (), &error);
    if (outcome->applied) {
        text = g_strdup_printf (_("%s Saved, and %s."), done,
                                apply_result_text (outcome->result));
        strip_set (strip, outcome->result == FS_APPLY_OK ? "ok" : "warn",
                   text);
    } else if (outcome->held) {
        text = g_strdup_printf (_("%s Saved. Held back on purpose (%s), so "
                                  "it is not on the firewall yet."),
                                done, outcome->hold_reason);
        strip_set (strip, "warn", text);
    } else {
        text = g_strdup_printf (
            _("%s Saved, but it is not live: %s%s%s. %s"), done,
            apply_result_text (outcome->result),
            error != NULL ? " - " : "",
            error != NULL ? error->message : "",
            outcome->rollback_attempted && outcome->rollback_verified
            ? _("The previous policy was restored and the restore was "
                "verified.")
            : outcome->rollback_attempted
              ? _("The rollback also failed; check the Status page.")
              : _("No applied policy is recorded, so nothing was "
                  "restored."));
        strip_set (strip, "bad", text);
    }
    g_free (text);
    fs_apply_outcome_free (outcome);
    g_clear_error (&error);
}

/* =====================================================================
 * Findings
 * ===================================================================== */

/* The finding with this key, or NULL when it is gone. */
static FsInsight *
insight_by_key (const gchar *key)
{
    GList *all, *l;
    FsInsight *hit = NULL;

    if (global_copilot == NULL || key == NULL)
        return NULL;
    all = fs_copilot_get_insights (global_copilot);
    for (l = all; l != NULL && hit == NULL; l = l->next) {
        FsInsight *ins = l->data;

        if (g_strcmp0 (ins->key, key) == 0)
            hit = ins;
    }
    g_list_free (all);
    return hit;
}

/* A stable key for a finding, also for one the core gave none. */
static gchar *
insight_key (const FsInsight *ins)
{
    if (ins->key != NULL)
        return g_strdup (ins->key);
    return g_strdup_printf ("%d|%s|%s", (gint) ins->type,
                            ins->application != NULL ? ins->application : "",
                            ins->title != NULL ? ins->title : "");
}

static AutoBlock *auto_block_find (FsRuleKind kind, const gchar *csv);

static AutoBlock *
insight_auto_block (const FsInsight *ins)
{
    if (ins->rule_csv == NULL || *ins->rule_csv == '\0')
        return NULL;
    return auto_block_find (ins->rule_kind, ins->rule_csv);
}

/* What Sentinel did, or will not do, for this finding. */
static gchar *
auto_block_words (const FsInsight *ins)
{
    AutoBlock *ab = insight_auto_block (ins);

    if (ab != NULL) {
        gchar *at = clock_text (ab->at_epoch);
        gchar *until = clock_text (ab->at_epoch + FS_AUTOBLOCK_TTL_S);
        gchar *s = g_strdup_printf (
            _("Blocked automatically at %s; the block lifts at %s. Undo "
              "lifts it now."), at, until);

        g_free (at);
        g_free (until);
        return s;
    }
    if (ins->withheld != NULL)
        return g_strdup_printf (_("Not blocked automatically: %s"),
                                ins->withheld);
    if (ins->auto_applicable && ins->rule_csv != NULL &&
        auto_block_cooldown_contains (ins->rule_kind, ins->rule_csv))
        return g_strdup (_("Not blocked again: its automatic block was "
                           "lifted earlier in this session."));
    if (ins->auto_applicable && g_strcmp0 (sentinel_mode, "auto") != 0)
        return g_strdup (_("Not blocked: Sentinel is set to Detect only."));
    if (ins->auto_applicable)
        return g_strdup (_("Sentinel may block this automatically, for 10 "
                           "minutes."));
    return g_strdup (_("Never blocked automatically: only outbound "
                       "contacts to unknown public addresses are."));
}

/* Is "Add block rule" honest for this finding?  The What-If engine
 * answers the finding's line against the policy as it is and with the
 * rule added: offered only when that turns ALLOWED into BLOCKED.  The
 * answer is about the saved policy, so the firewall is taken as
 * running it.  TRUE, or FALSE with *why. */
static gboolean
block_rule_verify (const FsInsight *ins, gchar **why)
{
    FsSettings *settings;
    FsWhatIfContext *ctx;
    FsWhatIfResult *r;
    FsRule *rule;
    FsWhatIfVerdict before, after;

    *why = NULL;
    if (copilot_policy == NULL) {
        *why = g_strdup (_("no traffic policy is loaded"));
        return FALSE;
    }
    if (ins->rule_csv == NULL || ins->rule_kind != FS_RULE_OUTBOUND_DENY_TO) {
        *why = g_strdup (_("this kind of finding has no block rule to "
                           "offer"));
        return FALSE;
    }
    rule = fs_insight_to_rule (ins);
    if (rule == NULL) {
        *why = g_strdup (_("the rule could not be read"));
        return FALSE;
    }
    if (fs_policy_contains (copilot_policy, rule)) {
        fs_rule_free (rule);
        *why = g_strdup (_("that rule is already in your policy"));
        return FALSE;
    }
    if (ins->whatif_line == NULL) {
        fs_rule_free (rule);
        *why = g_strdup (_("there is no What-If line to check it with"));
        return FALSE;
    }

    settings = fs_settings_new ();
    ctx = whatif_context_build (settings);
    ctx->firewall = FS_WHATIF_FW_RUNNING;
    ctx->live = FS_WHATIF_LIVE_YES;

    r = fs_whatif_simulate_text (ctx, ins->whatif_line);
    before = r->verdict;
    fs_whatif_result_free (r);

    fs_policy_add (copilot_policy, rule);
    r = fs_whatif_simulate_text (ctx, ins->whatif_line);
    after = r->verdict;
    fs_whatif_result_free (r);
    fs_policy_remove (copilot_policy, rule);

    fs_whatif_context_free (ctx);
    fs_settings_free (settings);
    fs_rule_free (rule);

    if (before != FS_WHATIF_ALLOWED) {
        *why = g_strdup_printf (_("What-If says \"%s\" is %s already, so a "
                                  "block rule would change nothing"),
                                ins->whatif_line,
                                fs_whatif_verdict_name (before));
        return FALSE;
    }
    if (after != FS_WHATIF_BLOCKED) {
        *why = g_strdup_printf (_("What-If says the rule would leave \"%s\" "
                                  "%s"), ins->whatif_line,
                                fs_whatif_verdict_name (after));
        return FALSE;
    }
    return TRUE;
}

/* Cached per finding for the session; "" means verified.  The cache
 * is cleared whenever this page changes the policy, and the check runs
 * once more just before anything is written. */
static const gchar *
block_rule_verdict (const FsInsight *ins, const gchar *key)
{
    gchar *why = NULL;
    const gchar *cached;

    if (verify_cache == NULL)
        verify_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
                                              g_free, g_free);
    cached = g_hash_table_lookup (verify_cache, key);
    if (cached != NULL)
        return cached;

    if (block_rule_verify (ins, &why))
        why = g_strdup ("");
    g_hash_table_insert (verify_cache, g_strdup (key), why);
    return why;
}

static void
verify_cache_clear (void)
{
    if (verify_cache != NULL)
        g_hash_table_remove_all (verify_cache);
}

static gboolean
cp_confirm (const gchar *title, const gchar *text)
{
    GtkWidget *top = copilot_vbox != NULL
                     ? gtk_widget_get_toplevel (copilot_vbox) : NULL;
    GtkWidget *confirm = gtk_message_dialog_new (
        GTK_IS_WINDOW (top) ? GTK_WINDOW (top) : NULL,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "%s", text);
    gint response;

    gtk_window_set_title (GTK_WINDOW (confirm), title);
    response = gtk_dialog_run (GTK_DIALOG (confirm));
    gtk_widget_destroy (confirm);
    return response == GTK_RESPONSE_YES;
}

static void
change_free (gpointer data)
{
    CpChange *c = data;

    g_free (c->label);
    g_free (c->csv);
    if (c->undo != NULL)
        fs_health_undo_free (c->undo);
    g_free (c);
}

static void
change_add (CpChange *c)
{
    if (changes == NULL)
        changes = g_ptr_array_new_with_free_func (change_free);
    c->at = g_get_real_time () / G_USEC_PER_SEC;
    g_ptr_array_add (changes, c);
}

/* "Add block rule": checked again, confirmed, saved, pushed. */
static void
on_add_block_clicked (GtkButton *btn, gpointer data)
{
    const gchar *key = g_object_get_data (G_OBJECT (btn), "cp-key");
    FsInsight *ins = insight_by_key (key);
    FsRule *rule;
    gchar *why = NULL;
    gchar *question;
    gchar *done;
    CpChange *c;

    (void) data;
    if (ins == NULL) {
        strip_set (findings_strip, "warn",
                   _("That finding is gone; nothing was written."));
        refresh_insights ();
        return;
    }

    /* The policy may have changed since the drawer opened. */
    if (!block_rule_verify (ins, &why)) {
        gchar *t = g_strdup_printf (_("No rule was written: %s."), why);

        strip_set (findings_strip, "warn", t);
        g_free (t);
        g_free (why);
        verify_cache_clear ();
        refresh_insights ();
        return;
    }

    question = g_strdup_printf (
        _("Add this block rule?\n\n"
          "Rule: %s (outbound deny to host)\n\n"
          "Checked by What-If: \"%s\" is ALLOWED now and BLOCKED with "
          "the rule.\n\n"
          "This adds the rule to your policy, saves it and pushes it to "
          "the firewall. Undo is under Changes made by the Copilot."),
        ins->rule_csv, ins->whatif_line);
    if (!cp_confirm (_("Add Block Rule"), question)) {
        g_free (question);
        strip_set (findings_strip, "ok", _("Nothing was written."));
        return;
    }
    g_free (question);

    rule = fs_insight_to_rule (ins);
    if (rule == NULL || !fs_policy_add_persist (copilot_policy, rule)) {
        strip_set (findings_strip, "bad",
                   _("The rule could not be saved, so nothing was "
                     "added."));
        fs_rule_free (rule);
        return;
    }
    fs_rule_free (rule);
    fs_audit_log ("copilot block rule added", ins->rule_csv);
    fs_policyview_reload (copilot_policy);

    c = g_new0 (CpChange, 1);
    c->kind = CP_CHANGE_BLOCK_RULE;
    c->rule_kind = ins->rule_kind;
    c->csv = g_strdup (ins->rule_csv);
    c->label = g_strdup_printf (_("Block rule added: %s"), ins->rule_csv);
    change_add (c);

    done = g_strdup_printf (_("Block rule added: %s."), ins->rule_csv);
    cp_push ("copilot block rule", findings_strip, done);
    g_free (done);

    verify_cache_clear ();
    refresh_insights ();
    health_run ();
}

static void
on_undo_block_clicked (GtkButton *btn, gpointer data)
{
    const gchar *key = g_object_get_data (G_OBJECT (btn), "cp-key");
    FsInsight *ins = insight_by_key (key);
    AutoBlock *ab = ins != NULL ? insight_auto_block (ins) : NULL;
    gchar *done;

    (void) data;
    if (ab == NULL) {
        strip_set (findings_strip, "warn",
                   _("That automatic block has already been lifted."));
        refresh_insights ();
        return;
    }
    done = g_strdup_printf (_("Automatic block lifted: %s."), ab->csv);
    auto_block_retire (ab, "undone by user");
    cp_push ("sentinel auto-block undone", findings_strip, done);
    g_free (done);
    verify_cache_clear ();
    refresh_insights ();
}

/* "Ask What-If": the line in the card's entry, asked, and the card
 * scrolled into view. */
static void
ask_whatif_line (const gchar *line)
{
    GtkWidget *card;
    GtkWidget *sw;

    if (line == NULL || scenario_entry == NULL)
        return;
    gtk_entry_set_text (GTK_ENTRY (scenario_entry), line);
    whatif_ask (line);

    card = fs_simviz_find_named (copilot_vbox, "whatif-card");
    sw = card != NULL ? gtk_widget_get_ancestor (card,
                                                 GTK_TYPE_SCROLLED_WINDOW)
                      : NULL;
    if (sw != NULL) {
        gint x = 0, y = 0;
        GtkWidget *child = gtk_bin_get_child (GTK_BIN (sw));

        if (child != NULL &&
            gtk_widget_translate_coordinates (card, child, 0, 0, &x, &y))
            gtk_adjustment_set_value (
                gtk_scrolled_window_get_vadjustment (GTK_SCROLLED_WINDOW (sw)),
                y);
    }
    gtk_widget_grab_focus (scenario_entry);
}

static void
on_ask_whatif_clicked (GtkButton *btn, gpointer data)
{
    (void) data;
    ask_whatif_line (g_object_get_data (G_OBJECT (btn), "cp-line"));
}

static void
on_show_events_clicked (GtkButton *btn, gpointer data)
{
    (void) data;
    fs_hitview_set_filter (g_object_get_data (G_OBJECT (btn), "cp-filter"));
    fs_app_show_page (FS_PAGE_EVENTS);
}

static void
on_dismiss_clicked (GtkButton *btn, gpointer data)
{
    const gchar *key = g_object_get_data (G_OBJECT (btn), "cp-key");

    (void) data;
    if (key == NULL)
        return;
    if (dismissed == NULL)
        dismissed = g_hash_table_new_full (g_str_hash, g_str_equal,
                                           g_free, NULL);
    g_hash_table_add (dismissed, g_strdup (key));
    strip_set (findings_strip, "ok",
               _("Finding dismissed for this session. It comes back when "
                 "StockFW restarts and it is seen again."));
    refresh_insights ();
}

/* The evidence table: one mono row per event. */
static GtkWidget *
evidence_table (const FsInsight *ins)
{
    GtkWidget *grid = gtk_grid_new ();
    static const gchar *heads[] = { N_("Time"), N_("Direction"),
                                    N_("Remote"), N_("Port"),
                                    N_("Protocol"), N_("Verdict") };
    guint n = ins->evidence != NULL ? ins->evidence->len : 0;

    gtk_widget_set_name (grid, "cp-evidence");
    gtk_grid_set_column_spacing (GTK_GRID (grid), 16);
    gtk_grid_set_row_spacing (GTK_GRID (grid), 2);
    for (guint c = 0; c < G_N_ELEMENTS (heads); c++)
        gtk_grid_attach (GTK_GRID (grid),
                         text_new (_(heads[c]), "cp-caption", FALSE),
                         (gint) c, 0, 1, 1);

    for (guint i = 0; i < n; i++) {
        /* Newest first. */
        const FsEvidence *ev = g_ptr_array_index (ins->evidence, n - 1 - i);
        GDateTime *dt = g_date_time_new_from_unix_local (ev->when);
        gchar *when = g_date_time_format (dt, "%H:%M:%S");
        gchar *port = ev->port > 0 ? g_strdup_printf ("%u", ev->port)
                                   : g_strdup ("-");
        gchar *verdict = ev->rule != NULL && *ev->rule != '\0'
            ? g_strdup_printf ("%s (%s)", ev->blocked ? _("Blocked")
                                                      : _("Allowed"),
                               ev->rule)
            : g_strdup (ev->blocked ? _("Blocked") : _("Allowed"));
        const gchar *cells[6];

        cells[0] = when;
        cells[1] = ev->inbound ? _("in") : _("out");
        cells[2] = ev->remote != NULL ? ev->remote : "-";
        cells[3] = port;
        cells[4] = ev->protocol != NULL ? ev->protocol : "-";
        cells[5] = verdict;
        for (guint c = 0; c < 6; c++)
            gtk_grid_attach (GTK_GRID (grid),
                             text_new (cells[c], "mono", FALSE),
                             (gint) c, (gint) i + 1, 1, 1);
        g_date_time_unref (dt);
        g_free (when);
        g_free (port);
        g_free (verdict);
    }
    return grid;
}

static void
drawer_part (GtkWidget *box, const gchar *heading, GtkWidget *body)
{
    GtkWidget *h = text_new (heading, "cp-drawer-head", FALSE);

    gtk_box_pack_start (GTK_BOX (box), h, FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (box), body, FALSE, FALSE, 0);
}

/* The actions that need What-If are added when the drawer first opens:
 * a check per row on every refresh would ask the backend far too
 * often. */
static void
drawer_fill_actions (GtkWidget *row)
{
    GtkWidget *actions = g_object_get_data (G_OBJECT (row), "cp-actions");
    GtkWidget *note = g_object_get_data (G_OBJECT (row), "cp-action-note");
    const gchar *key = g_object_get_data (G_OBJECT (row), "cp-key");
    FsInsight *ins = insight_by_key (key);
    const gchar *verdict;
    GtkWidget *b;

    if (actions == NULL || ins == NULL ||
        g_object_get_data (G_OBJECT (row), "cp-filled") != NULL)
        return;
    g_object_set_data (G_OBJECT (row), "cp-filled", GINT_TO_POINTER (1));

    if (ins->rule_csv == NULL || insight_auto_block (ins) != NULL)
        return;

    verdict = block_rule_verdict (ins, key);
    if (verdict != NULL && *verdict == '\0') {
        b = button_new (_("Add block rule"), "btn-primary", "cp-add-block");
        g_object_set_data_full (G_OBJECT (b), "cp-key", g_strdup (key),
                                g_free);
        g_signal_connect (b, "clicked", G_CALLBACK (on_add_block_clicked),
                          NULL);
        gtk_box_pack_start (GTK_BOX (actions), b, FALSE, FALSE, 0);
        gtk_box_reorder_child (GTK_BOX (actions), b, 0);
        gtk_widget_show (b);
    } else if (note != NULL && verdict != NULL) {
        gchar *t = g_strdup_printf (_("No block rule offered: %s."), verdict);

        gtk_label_set_text (GTK_LABEL (note), t);
        reveal (note, TRUE);
        g_free (t);
    }
}

static void
row_set_open (GtkWidget *row, gboolean open, gboolean animate)
{
    GtkWidget *rev = g_object_get_data (G_OBJECT (row), "cp-drawer");
    GtkWidget *arrow = g_object_get_data (G_OBJECT (row), "cp-arrow");
    const gchar *key = g_object_get_data (G_OBJECT (row), "cp-key");

    if (rev == NULL)
        return;
    if (open)
        drawer_fill_actions (row);
    gtk_revealer_set_transition_duration (
        GTK_REVEALER (rev),
        animate && fs_simviz_animations_enabled () ? 150 : 0);
    gtk_revealer_set_reveal_child (GTK_REVEALER (rev), open);
    if (arrow != NULL)
        gtk_label_set_text (GTK_LABEL (arrow), open ? "\u25BE" : "\u25B8");
    if (expanded == NULL)
        expanded = g_hash_table_new_full (g_str_hash, g_str_equal,
                                          g_free, NULL);
    if (key != NULL) {
        if (open)
            g_hash_table_add (expanded, g_strdup (key));
        else
            g_hash_table_remove (expanded, key);
    }
    {
        AtkObject *acc = gtk_widget_get_accessible (row);

        atk_object_set_description (acc, open ? _("Details shown")
                                              : _("Press Enter for the "
                                                  "details"));
    }
}

static void
on_finding_activated (GtkListBox *box, GtkListBoxRow *row, gpointer data)
{
    GtkWidget *rev = g_object_get_data (G_OBJECT (row), "cp-drawer");

    (void) box;
    (void) data;
    if (rev == NULL)
        return;
    row_set_open (GTK_WIDGET (row),
                  !gtk_revealer_get_reveal_child (GTK_REVEALER (rev)), TRUE);
}

static GtkWidget *
finding_row_new (const FsInsight *ins)
{
    GtkWidget *row = gtk_list_box_row_new ();
    GtkWidget *outer = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget *head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *texts = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *rev = gtk_revealer_new ();
    GtkWidget *drawer = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *actions = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *note, *l, *b, *arrow;
    AutoBlock *ab = insight_auto_block (ins);
    gchar *key = insight_key (ins);
    gchar *ago = ago_text ((gint64) ins->timestamp);
    gchar *line, *a11y, *first, *nl, *aw;

    add_class (row, "cp-row");
    gtk_widget_set_name (row, "cp-finding");
    gtk_list_box_row_set_activatable (GTK_LIST_BOX_ROW (row), TRUE);
    g_object_set_data_full (G_OBJECT (row), "cp-key", g_strdup (key), g_free);

    a11y = g_strdup_printf ("%s: %s", severity_word (ins->severity),
                            ins->title != NULL ? ins->title : "");
    atk_object_set_name (gtk_widget_get_accessible (row), a11y);
    g_free (a11y);

    /* Head: pill, title and one line, the auto-block tag, the arrow. */
    gtk_box_pack_start (GTK_BOX (head), severity_pill (ins->severity),
                        FALSE, FALSE, 0);
    l = text_new (ins->title, "cp-title", TRUE);
    gtk_widget_set_name (l, "cp-finding-title");
    gtk_box_pack_start (GTK_BOX (texts), l, FALSE, FALSE, 0);

    first = g_strdup (ins->description != NULL ? ins->description : "");
    nl = strchr (first, '\n');
    if (nl != NULL)
        *nl = '\0';
    line = g_strdup_printf ("%s%s%s%s%s", fs_insight_type_name (ins->type),
                            ins->application != NULL ? " · " : "",
                            ins->application != NULL ? ins->application : "",
                            *ago != '\0' ? " · " : "", ago);
    l = text_new (first, "cp-sub", TRUE);
    gtk_box_pack_start (GTK_BOX (texts), l, FALSE, FALSE, 0);
    l = text_new (line, "cp-meta", TRUE);
    gtk_box_pack_start (GTK_BOX (texts), l, FALSE, FALSE, 0);
    g_free (first);
    g_free (line);
    gtk_box_pack_start (GTK_BOX (head), texts, TRUE, TRUE, 0);

    if (ab != NULL) {
        gint64 left = ab->at_epoch + FS_AUTOBLOCK_TTL_S -
                      g_get_real_time () / G_USEC_PER_SEC;
        gchar *t = g_strdup_printf (_("Auto-blocked · %d min left"),
                                    (gint) MAX (1, (left + 59) / 60));

        l = text_new (t, "fs-wi-tag", FALSE);
        add_class (l, "warn");
        gtk_widget_set_name (l, "cp-autotag");
        gtk_widget_set_valign (l, GTK_ALIGN_START);
        gtk_box_pack_start (GTK_BOX (head), l, FALSE, FALSE, 0);
        g_free (t);
    }
    arrow = text_new ("\u25B8", "cp-arrow", FALSE);
    gtk_widget_set_valign (arrow, GTK_ALIGN_START);
    gtk_box_pack_end (GTK_BOX (head), arrow, FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (outer), head, FALSE, FALSE, 0);

    /* The drawer. */
    add_class (drawer, "cp-drawer");
    if (ins->evidence != NULL && ins->evidence->len > 0) {
        GtkWidget *seen = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);

        gtk_box_pack_start (GTK_BOX (seen), evidence_table (ins),
                            FALSE, FALSE, 0);
        if (ins->count > ins->evidence->len) {
            gchar *t = g_strdup_printf (
                _("The last %u of %u matching events."),
                ins->evidence->len, ins->count);

            gtk_box_pack_start (GTK_BOX (seen), text_new (t, "cp-meta", TRUE),
                                FALSE, FALSE, 0);
            g_free (t);
        }
        drawer_part (drawer, _("What we saw"), seen);
    }
    if (ins->description != NULL)
        drawer_part (drawer, _("In full"),
                     text_new (ins->description, "cp-body", TRUE));
    if (ins->why != NULL)
        drawer_part (drawer, _("Why flagged"),
                     text_new (ins->why, "cp-body", TRUE));
    if (ins->benign != NULL)
        drawer_part (drawer, _("Could be harmless"),
                     text_new (ins->benign, "cp-body", TRUE));
    aw = auto_block_words (ins);
    l = text_new (aw, "cp-body", TRUE);
    gtk_widget_set_name (l, "cp-autoblock-status");
    drawer_part (drawer, _("Auto-block"), l);
    g_free (aw);

    gtk_widget_set_name (actions, "cp-actions");
    if (ab != NULL) {
        b = button_new (_("Undo block"), "btn-primary", "cp-undo-block");
        g_object_set_data_full (G_OBJECT (b), "cp-key", g_strdup (key),
                                g_free);
        g_signal_connect (b, "clicked", G_CALLBACK (on_undo_block_clicked),
                          NULL);
        gtk_box_pack_start (GTK_BOX (actions), b, FALSE, FALSE, 0);
    }
    if (ins->whatif_line != NULL) {
        b = button_new (_("Ask What-If"), "btn-subtle", "cp-ask-whatif");
        g_object_set_data_full (G_OBJECT (b), "cp-line",
                                g_strdup (ins->whatif_line), g_free);
        g_signal_connect (b, "clicked", G_CALLBACK (on_ask_whatif_clicked),
                          NULL);
        gtk_box_pack_start (GTK_BOX (actions), b, FALSE, FALSE, 0);
    }
    if (ins->events_filter != NULL) {
        b = button_new (_("Show in Events"), "btn-subtle", "cp-show-events");
        g_object_set_data_full (G_OBJECT (b), "cp-filter",
                                g_strdup (ins->events_filter), g_free);
        g_signal_connect (b, "clicked", G_CALLBACK (on_show_events_clicked),
                          NULL);
        gtk_box_pack_start (GTK_BOX (actions), b, FALSE, FALSE, 0);
    }
    b = button_new (_("Dismiss"), "btn-subtle", "cp-dismiss");
    g_object_set_data_full (G_OBJECT (b), "cp-key", g_strdup (key), g_free);
    g_signal_connect (b, "clicked", G_CALLBACK (on_dismiss_clicked), NULL);
    gtk_box_pack_start (GTK_BOX (actions), b, FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (drawer), actions, FALSE, FALSE, 4);

    note = text_new ("", "cp-meta", TRUE);
    gtk_widget_set_name (note, "cp-action-note");
    gtk_widget_set_no_show_all (note, TRUE);
    gtk_box_pack_start (GTK_BOX (drawer), note, FALSE, FALSE, 0);

    gtk_revealer_set_transition_type (GTK_REVEALER (rev),
                                      GTK_REVEALER_TRANSITION_TYPE_SLIDE_DOWN);
    gtk_container_add (GTK_CONTAINER (rev), drawer);
    gtk_widget_set_name (rev, "cp-drawer");
    gtk_box_pack_start (GTK_BOX (outer), rev, FALSE, FALSE, 0);

    gtk_container_add (GTK_CONTAINER (row), outer);
    g_object_set_data (G_OBJECT (row), "cp-drawer", rev);
    g_object_set_data (G_OBJECT (row), "cp-arrow", arrow);
    g_object_set_data (G_OBJECT (row), "cp-actions", actions);
    g_object_set_data (G_OBJECT (row), "cp-action-note", note);

    g_free (ago);
    g_free (key);
    return row;
}

static gint
severity_rank_cmp (gconstpointer a, gconstpointer b)
{
    const FsInsight *x = a, *y = b;

    return (gint) y->severity - (gint) x->severity;
}

/* What the checks look for, for the all-clear state. */
static GtkWidget *
checked_list_new (void)
{
    static const gchar *checks[] = {
        N_("Contacts at a near-fixed interval: 6 or more, timing varying "
           "under 30 % (auto-block needs 8, to an unknown public address)."),
        N_("Fan-out: one app reaching 60 or more hosts in a minute."),
        N_("Inbound scan: one source trying 12 ports in 60 s, or 25 in "
           "10 min."),
        N_("Login attempts: 10 in 5 min to SSH, RDP, VNC, Telnet, FTP or "
           "SMB, and whether your policy lets that source in."),
        N_("Block list or country rule hits, outbound and inbound."),
        N_("A known app using a new port, a new public destination (after "
           "7 days and 50 connections), a new hour, or a rate spike."),
        N_("Policy health: duplicates, rules another rule covers, allows a "
           "deny overrides, wide or risky inbound allows, deny rules that "
           "reach nothing."),
    };
    GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);

    for (guint i = 0; i < G_N_ELEMENTS (checks); i++) {
        gchar *t = g_strdup_printf ("- %s", _(checks[i]));

        gtk_box_pack_start (GTK_BOX (box), text_new (t, "cp-body", TRUE),
                            FALSE, FALSE, 0);
        g_free (t);
    }
    gtk_widget_set_margin_start (box, 8);
    return box;
}

static guint
learned_count (gint64 *since)
{
    GList *profiles, *l;
    guint n;

    *since = 0;
    if (global_copilot == NULL)
        return 0;
    profiles = fs_copilot_get_all_profiles (global_copilot);
    n = g_list_length (profiles);
    for (l = profiles; l != NULL; l = l->next) {
        const FsAppProfile *p = l->data;

        if (p->first_seen > 0 &&
            (*since == 0 || (gint64) p->first_seen < *since))
            *since = (gint64) p->first_seen;
    }
    g_list_free (profiles);
    return n;
}

static void
findings_render (void)
{
    GList *all, *l;
    GList *shown = NULL;
    guint n = 0;

    if (findings_list == NULL)
        return;

    clear_container (findings_list);
    all = global_copilot != NULL ? fs_copilot_get_insights (global_copilot)
                                 : NULL;
    for (l = all; l != NULL; l = l->next) {
        FsInsight *ins = l->data;
        gchar *key = insight_key (ins);

        if (dismissed == NULL || !g_hash_table_contains (dismissed, key))
            shown = g_list_prepend (shown, ins);
        g_free (key);
    }
    g_list_free (all);
    shown = g_list_reverse (shown);
    shown = g_list_sort (shown, severity_rank_cmp)  /* a stable merge sort */;

    for (l = shown; l != NULL; l = l->next) {
        FsInsight *ins = l->data;
        GtkWidget *row = finding_row_new (ins);
        const gchar *key = g_object_get_data (G_OBJECT (row), "cp-key");

        gtk_container_add (GTK_CONTAINER (findings_list), row);
        gtk_widget_show_all (row);
        if (expanded != NULL && g_hash_table_contains (expanded, key))
            row_set_open (row, TRUE, FALSE);
        n++;
    }
    g_list_free (shown);

    {
        gchar *t = g_strdup_printf (n == 1 ? _("%u finding")
                                           : _("%u findings"), n);

        gtk_label_set_text (GTK_LABEL (findings_count), t);
        g_free (t);
    }

    /* The empty states. */
    reveal (findings_frame, n > 0);
    if (n > 0) {
        reveal (findings_empty, FALSE);
        return;
    }
    {
        guint64 seen = global_copilot != NULL
                       ? fs_copilot_events_seen (global_copilot) : 0;
        gchar *problem = fs_hitview_monitor_problem ();
        gint64 since;
        guint apps = learned_count (&since);
        gchar *t;

        if (seen == 0) {
            t = g_strdup (_("The Copilot learns from the event log. Nothing "
                            "to check yet."));
        } else {
            gchar *events = g_strdup_printf ("%" G_GUINT64_FORMAT, seen);

            t = g_strdup_printf (
                _("No findings from %s events across %u %s. None of the "
                  "checks matched. This is not a guarantee that nothing is "
                  "wrong."), events, apps,
#ifdef G_OS_WIN32
                apps == 1 ? _("app") : _("apps"));
#else
                apps == 1 ? _("service") : _("services"));
#endif
            g_free (events);
        }
        gtk_label_set_text (GTK_LABEL (findings_empty_text), t);
        g_free (t);

        if (problem != NULL) {
            t = g_strdup_printf (_("No events are arriving: %s"), problem);
            gtk_label_set_text (GTK_LABEL (findings_reason), t);
            g_free (t);
        }
        reveal (findings_empty, TRUE);
        reveal (findings_reason, problem != NULL);
        reveal (findings_checked, seen > 0);
        g_free (problem);
    }
}

/* =====================================================================
 * Policy health
 * ===================================================================== */

static const FsHealthFinding *
health_by_index (gint i)
{
    if (health_findings == NULL || i < 0 || (guint) i >= health_findings->len)
        return NULL;
    return g_ptr_array_index (health_findings, i);
}

static gchar *
health_checks_text (const FsHealthFinding *f)
{
    GString *s = g_string_new (NULL);

    for (guint i = 0; f->checks != NULL && i < f->checks->len; i++) {
        const FsHealthCheck *c = g_ptr_array_index (f->checks, i);

        g_string_append_printf (s, "%s%s: %s -> %s", s->len ? "\n" : "",
                                c->probe, fs_whatif_verdict_name (c->before),
                                fs_whatif_verdict_name (c->after));
    }
    return g_string_free (s, FALSE);
}

static void
on_health_fix_clicked (GtkButton *btn, gpointer data)
{
    const FsHealthFinding *old = health_by_index (
        GPOINTER_TO_INT (g_object_get_data (G_OBJECT (btn), "cp-index")));
    FsHealthFinding *now = NULL;
    FsSettings *settings;
    FsWhatIfContext *ctx;
    GPtrArray *fresh;
    gchar *prefix;
    gchar *table, *question, *why = NULL, *done;
    FsHealthUndo *undo = NULL;
    CpChange *c;

    (void) data;
    if (old == NULL || copilot_policy == NULL)
        return;

    /* Run the check again on the policy as it is now: the fix is
     * written only when the same finding, with the same fix and the
     * same What-If results, is still there. */
    settings = fs_settings_new ();
    ctx = whatif_context_build (settings);
    prefix = fs_health_lan_prefix_auto (fs_backend ());
    fresh = fs_health_check (ctx, prefix);
    g_free (prefix);
    for (guint i = 0; i < fresh->len && now == NULL; i++)
        if (fs_health_finding_same (old, g_ptr_array_index (fresh, i)))
            now = g_ptr_array_index (fresh, i);
    fs_whatif_context_free (ctx);
    fs_settings_free (settings);

    if (now == NULL || !now->verified || now->fix == FS_HEALTH_FIX_NONE) {
        strip_set (health_strip, "warn",
                   _("The policy changed since this was checked, so "
                     "nothing was written. The check ran again."));
        g_ptr_array_unref (fresh);
        health_run ();
        return;
    }

    table = health_checks_text (now);
    question = g_strdup_printf (
        _("%s?\n\n"
          "Before: %s\n"
          "After:  %s\n\n"
          "Checked by What-If (before -> after):\n%s\n\n"
          "This changes your policy, saves it and pushes it to the "
          "firewall. Undo is under Changes made by the Copilot."),
        now->fix_label, now->fix_before,
        now->fix_after != NULL ? now->fix_after : _("(rule removed)"),
        table);
    g_free (table);

    if (!cp_confirm (_("Fix Policy"), question)) {
        g_free (question);
        g_ptr_array_unref (fresh);
        strip_set (health_strip, "ok", _("Nothing was changed."));
        return;
    }
    g_free (question);

    if (!fs_health_fix_apply (copilot_policy, now, &undo, &why)) {
        gchar *t = g_strdup_printf (_("Nothing was changed: %s"),
                                    why != NULL ? why : "");

        strip_set (health_strip, "bad", t);
        g_free (t);
        g_free (why);
        g_ptr_array_unref (fresh);
        health_run ();
        return;
    }
    fs_policyview_reload (copilot_policy);

    c = g_new0 (CpChange, 1);
    c->kind = CP_CHANGE_HEALTH_FIX;
    c->undo = undo;
    c->label = g_strdup_printf (_("Policy fix: %s"), now->fix_label);
    change_add (c);

    done = g_strdup_printf (_("%s: done."), now->fix_label);
    cp_push ("copilot health fix", health_strip, done);
    g_free (done);
    g_ptr_array_unref (fresh);

    verify_cache_clear ();
    health_run ();
    update_stats ();
}

static void
on_health_rule_clicked (GtkButton *btn, gpointer data)
{
    gint kind = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (btn),
                                                    "cp-kind"));
    gint index = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (btn),
                                                     "cp-row"));

    (void) data;
    fs_app_show_page (FS_PAGE_POLICY);
    if (kind >= 0 && kind < FS_RULE_N_KINDS)
        fs_policyview_select ((FsRuleKind) kind, index);
}

static GtkWidget *
health_row_new (const FsHealthFinding *f, gint index)
{
    GtkWidget *row = gtk_list_box_row_new ();
    GtkWidget *head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *texts = gtk_box_new (GTK_ORIENTATION_VERTICAL, 3);
    GtkWidget *buttons = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget *l, *b;
    gchar *t;

    add_class (row, "cp-row");
    gtk_widget_set_name (row, "cp-health");
    gtk_list_box_row_set_activatable (GTK_LIST_BOX_ROW (row), FALSE);
    t = g_strdup_printf ("%s: %s", severity_word (f->severity), f->title);
    atk_object_set_name (gtk_widget_get_accessible (row), t);
    g_free (t);

    gtk_box_pack_start (GTK_BOX (head), severity_pill (f->severity),
                        FALSE, FALSE, 0);
    l = text_new (f->title, "cp-title", TRUE);
    gtk_box_pack_start (GTK_BOX (texts), l, FALSE, FALSE, 0);

    t = g_strdup_printf (_("%s rule %d: %s"),
                         rule_kind_words (f->policy_kind),
                         f->policy_index + 1, f->rule_csv);
    gtk_box_pack_start (GTK_BOX (texts), text_new (t, "cp-sub mono", TRUE),
                        FALSE, FALSE, 0);
    g_free (t);
    if (f->why != NULL)
        gtk_box_pack_start (GTK_BOX (texts), text_new (f->why, "cp-body",
                                                       TRUE),
                            FALSE, FALSE, 0);
    /* The other row involved, in the same words (the core's evidence
     * line names kinds the way the JSON does). */
    if (f->other_csv != NULL && f->other_kind >= 0) {
        t = g_strdup_printf (_("The other row: %s rule %d: %s"),
                             rule_kind_words (f->other_kind),
                             f->other_index + 1, f->other_csv);
        gtk_box_pack_start (GTK_BOX (texts), text_new (t, "cp-meta mono",
                                                       TRUE),
                            FALSE, FALSE, 0);
        g_free (t);
    }

    if (f->fix != FS_HEALTH_FIX_NONE && f->verified) {
        gchar *checks = health_checks_text (f);

        t = g_strdup_printf (_("Fix: %s -> %s"), f->fix_before,
                             f->fix_after != NULL ? f->fix_after
                                                  : _("(removed)"));
        l = text_new (t, "cp-sub mono", TRUE);
        gtk_widget_set_name (l, "cp-health-fixline");
        gtk_box_pack_start (GTK_BOX (texts), l, FALSE, FALSE, 0);
        g_free (t);
        t = g_strdup_printf (_("Checked by What-If:\n%s"), checks);
        l = text_new (t, "cp-meta mono", TRUE);
        gtk_widget_set_name (l, "cp-health-checks");
        gtk_box_pack_start (GTK_BOX (texts), l, FALSE, FALSE, 0);
        g_free (t);
        g_free (checks);

        b = button_new (_("Fix…"), "btn-primary", "cp-health-fix");
        g_object_set_data (G_OBJECT (b), "cp-index",
                           GINT_TO_POINTER (index));
        g_signal_connect (b, "clicked", G_CALLBACK (on_health_fix_clicked),
                          NULL);
        t = g_strdup_printf (_("Fix: %s"), f->fix_label);
        atk_object_set_name (gtk_widget_get_accessible (b), t);
        g_free (t);
        gtk_box_pack_start (GTK_BOX (buttons), b, FALSE, FALSE, 0);
    } else if (f->no_fix_reason != NULL) {
        t = g_strdup_printf (_("No fix offered: %s"), f->no_fix_reason);
        l = text_new (t, "cp-meta", TRUE);
        gtk_widget_set_name (l, "cp-health-nofix");
        gtk_box_pack_start (GTK_BOX (texts), l, FALSE, FALSE, 0);
        g_free (t);
    }
    gtk_box_pack_start (GTK_BOX (head), texts, TRUE, TRUE, 0);

    b = button_new (_("Show rule"), "btn-subtle", "cp-health-rule");
    g_object_set_data (G_OBJECT (b), "cp-kind",
                       GINT_TO_POINTER (f->policy_kind));
    g_object_set_data (G_OBJECT (b), "cp-row",
                       GINT_TO_POINTER (f->policy_index));
    g_signal_connect (b, "clicked", G_CALLBACK (on_health_rule_clicked),
                      NULL);
    gtk_box_pack_start (GTK_BOX (buttons), b, FALSE, FALSE, 0);
    if (f->whatif_line != NULL) {
        b = button_new (_("Ask What-If"), "btn-subtle", "cp-ask-whatif");
        g_object_set_data_full (G_OBJECT (b), "cp-line",
                                g_strdup (f->whatif_line), g_free);
        g_signal_connect (b, "clicked", G_CALLBACK (on_ask_whatif_clicked),
                          NULL);
        gtk_box_pack_start (GTK_BOX (buttons), b, FALSE, FALSE, 0);
    }
    gtk_box_pack_end (GTK_BOX (head), buttons, FALSE, FALSE, 0);
    gtk_container_add (GTK_CONTAINER (row), head);
    return row;
}

static guint
policy_row_count (void)
{
    guint n = 0;

    if (copilot_policy == NULL)
        return 0;
    for (gint k = 0; k < FS_RULE_N_KINDS; k++)
        n += copilot_policy->kinds[k]->len;
    return n;
}

static void
health_render (void)
{
    guint n = health_findings != NULL ? health_findings->len : 0;
    gchar *t, *ago;

    if (health_list == NULL)
        return;
    clear_container (health_list);
    for (guint i = 0; i < n; i++) {
        GtkWidget *row = health_row_new (g_ptr_array_index (health_findings,
                                                            i), (gint) i);

        gtk_container_add (GTK_CONTAINER (health_list), row);
        gtk_widget_show_all (row);
    }

    ago = ago_text (health_at);
    t = g_strdup_printf (_("%u %s checked · %u %s · %s"), health_rules,
                         health_rules == 1 ? _("rule") : _("rules"), n,
                         n == 1 ? _("finding") : _("findings"), ago);
    gtk_label_set_text (GTK_LABEL (health_summary), t);
    g_free (t);
    g_free (ago);

    reveal (health_frame, n > 0);
    if (n == 0) {
        t = copilot_policy == NULL
            ? g_strdup (_("No traffic policy is loaded."))
            : g_strdup_printf (_("%u %s checked. No overlaps, conflicts "
                                 "or open risky services."), health_rules,
                               health_rules == 1 ? _("rule") : _("rules"));
        gtk_label_set_text (GTK_LABEL (health_empty), t);
        g_free (t);
    }
    reveal (health_empty, n == 0);
}

/* [ health_run ] -- the check on the policy as it is now. */
static void
health_run (void)
{
    FsSettings *settings;
    FsWhatIfContext *ctx;
    gchar *prefix;

    if (health_findings != NULL)
        g_ptr_array_unref (health_findings);
    health_findings = NULL;
    health_rules = policy_row_count ();
    health_at = g_get_real_time () / G_USEC_PER_SEC;

    if (copilot_policy != NULL) {
        settings = fs_settings_new ();
        ctx = whatif_context_build (settings);
        prefix = fs_health_lan_prefix_auto (fs_backend ());
        health_findings = fs_health_check (ctx, prefix);
        g_free (prefix);
        fs_whatif_context_free (ctx);
        fs_settings_free (settings);
    }
    health_render ();
    update_stats ();
}

static void
on_health_again_clicked (GtkButton *btn, gpointer data)
{
    (void) btn;
    (void) data;
    strip_set (health_strip, NULL, NULL);
    health_run ();
}

/* =====================================================================
 * Changes made by the Copilot
 * ===================================================================== */

static void
on_change_undo_clicked (GtkButton *btn, gpointer data)
{
    gint kind = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (btn),
                                                    "cp-kind"));
    gpointer ref = g_object_get_data (G_OBJECT (btn), "cp-ref");
    gchar *why = NULL;
    gchar *done = NULL;

    (void) data;

    if (kind == 0) {
        /* An automatic block: still staged? */
        AutoBlock *ab = ref;

        if (auto_blocks == NULL || !g_ptr_array_find (auto_blocks, ab, NULL)) {
            strip_set (changes_strip, "warn",
                       _("That automatic block has already been lifted."));
            changes_render ();
            return;
        }
        done = g_strdup_printf (_("Automatic block lifted: %s."), ab->csv);
        auto_block_retire (ab, "undone by user");
        cp_push ("sentinel auto-block undone", changes_strip, done);
    } else {
        CpChange *c = ref;

        if (changes == NULL || !g_ptr_array_find (changes, c, NULL))
            return;
        if (c->kind == CP_CHANGE_BLOCK_RULE) {
            FsRule *rule = fs_rule_from_csv (c->rule_kind, c->csv);
            gboolean ok = rule != NULL &&
                          fs_policy_remove_persist (copilot_policy, rule);

            fs_rule_free (rule);
            if (!ok) {
                strip_set (changes_strip, "bad",
                           _("The rule is no longer in the policy, or the "
                             "policy could not be saved; nothing was "
                             "changed."));
                return;
            }
            fs_audit_log ("copilot block rule undone", c->csv);
            done = g_strdup_printf (_("Block rule removed: %s."), c->csv);
        } else {
            if (!fs_health_undo_apply (copilot_policy, c->undo, &why)) {
                gchar *t = g_strdup_printf (_("Nothing was changed: %s"),
                                            why != NULL ? why : "");

                strip_set (changes_strip, "bad", t);
                g_free (t);
                g_free (why);
                return;
            }
            done = g_strdup_printf (_("Undone: %s."), c->label);
        }
        g_ptr_array_remove (changes, c);
        /* What the other cards said about it is old news now. */
        strip_set (health_strip, NULL, NULL);
        strip_set (findings_strip, NULL, NULL);
        fs_policyview_reload (copilot_policy);
        cp_push ("copilot change undone", changes_strip, done);
    }
    g_free (done);
    verify_cache_clear ();
    refresh_insights ();
    health_run ();
}

typedef struct
{
    gint64       at;
    gchar       *text;
    gint         kind;      /* 0 auto-block, 1 page change */
    gpointer     ref;
} ChangeLine;

static gint
change_line_cmp (gconstpointer a, gconstpointer b)
{
    const ChangeLine *x = *(ChangeLine * const *) a;
    const ChangeLine *y = *(ChangeLine * const *) b;

    return x->at < y->at ? 1 : x->at > y->at ? -1 : 0;
}

static void
change_line_free (gpointer data)
{
    ChangeLine *l = data;

    g_free (l->text);
    g_free (l);
}

static void
changes_render (void)
{
    GPtrArray *lines;

    if (changes_list == NULL)
        return;
    clear_container (changes_list);
    lines = g_ptr_array_new_with_free_func (change_line_free);

    for (guint i = 0; auto_blocks != NULL && i < auto_blocks->len; i++) {
        AutoBlock *ab = g_ptr_array_index (auto_blocks, i);
        ChangeLine *l = g_new0 (ChangeLine, 1);
        FsRule *r = fs_rule_from_csv (ab->kind, ab->csv);
        gchar *until = clock_text (ab->at_epoch + FS_AUTOBLOCK_TTL_S);

        l->at = ab->at_epoch;
        l->kind = 0;
        l->ref = ab;
        l->text = g_strdup_printf (_("Auto-block %s (lifts at %s)"),
                                   r != NULL && r->target != NULL
                                   ? r->target : ab->csv, until);
        fs_rule_free (r);
        g_free (until);
        g_ptr_array_add (lines, l);
    }
    for (guint i = 0; changes != NULL && i < changes->len; i++) {
        CpChange *c = g_ptr_array_index (changes, i);
        ChangeLine *l = g_new0 (ChangeLine, 1);

        l->at = c->at;
        l->kind = 1;
        l->ref = c;
        l->text = g_strdup (c->label);
        g_ptr_array_add (lines, l);
    }
    g_ptr_array_sort (lines, change_line_cmp);

    for (guint i = 0; i < lines->len; i++) {
        ChangeLine *l = g_ptr_array_index (lines, i);
        GtkWidget *row = gtk_list_box_row_new ();
        GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
        gchar *at = clock_text (l->at);
        GtkWidget *b;

        add_class (row, "cp-row");
        gtk_widget_set_name (row, "cp-change");
        gtk_list_box_row_set_activatable (GTK_LIST_BOX_ROW (row), FALSE);
        gtk_box_pack_start (GTK_BOX (box), text_new (at, "cp-meta mono",
                                                     FALSE),
                            FALSE, FALSE, 0);
        gtk_box_pack_start (GTK_BOX (box), text_new (l->text, "cp-body",
                                                     TRUE),
                            TRUE, TRUE, 0);
        b = button_new (_("Undo"), "btn-subtle", "cp-change-undo");
        g_object_set_data (G_OBJECT (b), "cp-kind", GINT_TO_POINTER (l->kind));
        g_object_set_data (G_OBJECT (b), "cp-ref", l->ref);
        g_signal_connect (b, "clicked", G_CALLBACK (on_change_undo_clicked),
                          NULL);
        {
            gchar *a11y = g_strdup_printf (_("Undo: %s"), l->text);

            atk_object_set_name (gtk_widget_get_accessible (b), a11y);
            g_free (a11y);
        }
        gtk_box_pack_end (GTK_BOX (box), b, FALSE, FALSE, 0);
        gtk_container_add (GTK_CONTAINER (row), box);
        gtk_container_add (GTK_CONTAINER (changes_list), row);
        gtk_widget_show_all (row);
        g_free (at);
    }

    reveal (changes_frame, lines->len > 0);
    reveal (changes_empty, lines->len == 0);
    g_ptr_array_unref (lines);
}

/* =====================================================================
 * Tiles
 * ===================================================================== */
static void
tile_set (GtkWidget *value, GtkWidget *note, guint n, const gchar *text)
{
    gchar buf[32];

    if (value == NULL)
        return;
    g_snprintf (buf, sizeof buf, "%u", n);
    gtk_label_set_text (GTK_LABEL (value), buf);
    gtk_label_set_text (GTK_LABEL (note), text != NULL ? text : "");
}

static void
update_stats (void)
{
    GList *all, *l;
    guint attention = 0, critical = 0;
    gchar *t;

    if (tile_attention == NULL)
        return;

    all = global_copilot != NULL ? fs_copilot_get_insights (global_copilot)
                                 : NULL;
    for (l = all; l != NULL; l = l->next) {
        FsInsight *ins = l->data;
        gchar *key = insight_key (ins);

        if ((dismissed == NULL || !g_hash_table_contains (dismissed, key)) &&
            ins->severity >= FS_COPILOT_WARNING) {
            attention++;
            if (ins->severity == FS_COPILOT_CRITICAL)
                critical++;
        }
        g_free (key);
    }
    g_list_free (all);
    t = critical > 0 ? g_strdup_printf (_("%u critical"), critical)
                     : g_strdup (_("Critical and warning findings"));
    tile_set (tile_attention, tile_attention_note, attention, t);
    g_free (t);

    {
        guint n = health_findings != NULL ? health_findings->len : 0;

        t = g_strdup_printf (_("%u %s checked"), health_rules,
                             health_rules == 1 ? _("rule") : _("rules"));
        tile_set (tile_health, tile_health_note, n, t);
        g_free (t);
    }

    {
        guint n = auto_blocks != NULL ? auto_blocks->len : 0;
        gint64 soonest = 0;

        for (guint i = 0; i < n; i++) {
            AutoBlock *ab = g_ptr_array_index (auto_blocks, i);
            gint64 due = ab->at_epoch + FS_AUTOBLOCK_TTL_S;

            if (soonest == 0 || due < soonest)
                soonest = due;
        }
        if (n > 0) {
            gint64 left = soonest - g_get_real_time () / G_USEC_PER_SEC;

            t = g_strdup_printf (_("next lifts in %d min"),
                                 (gint) MAX (1, (left + 59) / 60));
        } else {
            t = g_strdup (g_strcmp0 (sentinel_mode, "auto") == 0
                          ? _("None staged") : _("Detect only"));
        }
        tile_set (tile_blocks, tile_blocks_note, n, t);
        g_free (t);
    }

    {
        gint64 since;
        guint n = learned_count (&since);

        if (since > 0) {
            GDateTime *dt = g_date_time_new_from_unix_local (since);
            gchar *d = g_date_time_format (dt, "%Y-%m-%d");

            t = g_strdup_printf (_("since %s"), d);
            g_free (d);
            g_date_time_unref (dt);
        } else {
            t = g_strdup (_("Nothing learned yet"));
        }
        tile_set (tile_learned, tile_learned_note, n, t);
        g_free (t);
    }

    changes_render ();
}

static GtkWidget *
tile_new (const gchar *caption, const gchar *name, GtkWidget **value,
          GtkWidget **note)
{
    GtkWidget *card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *v;
    gchar *vn = g_strdup_printf ("%s-value", name);

    add_class (card, "card");
    add_class (card, "stat-card");
    gtk_widget_set_name (card, name);
    gtk_box_pack_start (GTK_BOX (card), text_new (caption, "stat-caption",
                                                  FALSE),
                        FALSE, FALSE, 0);
    v = text_new ("0", "stat-big", FALSE);
    gtk_widget_set_name (v, vn);
    gtk_box_pack_start (GTK_BOX (card), v, FALSE, FALSE, 0);
    *note = text_new ("", "stat-note", TRUE);
    gtk_box_pack_start (GTK_BOX (card), *note, FALSE, FALSE, 0);
    *value = v;
    g_free (vn);
    return card;
}

/* =====================================================================
 * Refresh
 * ===================================================================== */
static void
refresh_insights (void)
{
    findings_render ();
    update_stats ();
}

static gboolean
refresh_cb (gpointer data)
{
    (void) data;
    refresh_id = 0;
    refresh_insights ();
    return G_SOURCE_REMOVE;
}

void
fs_copilot_view_refresh (void)
{
    refresh_insights ();
}

/* fs_copilot_note_event -- called from the Events page for every
 * event the checks saw: the page follows at most once a second. */
void
fs_copilot_note_event (void)
{
    total_events++;
    if (findings_list != NULL && refresh_id == 0)
        refresh_id = g_timeout_add (1000, refresh_cb, NULL);
}

/* =====================================================================
 * Sentinel control
 * ===================================================================== */
static void
sentinel_sync_buttons (void)
{
    if (sentinel_detect == NULL)
        return;
    gtk_toggle_button_set_active (
        GTK_TOGGLE_BUTTON (g_strcmp0 (sentinel_mode, "auto") == 0
                           ? sentinel_auto : sentinel_detect), TRUE);
}

static void
on_sentinel_toggled (GtkToggleButton *btn, gpointer data)
{
    const gchar *id = data;

    if (!gtk_toggle_button_get_active (btn) ||
        g_strcmp0 (id, sentinel_mode) == 0)
        return;

    g_strlcpy (sentinel_mode, id, sizeof sentinel_mode);
    fs_prefs_set_string ("/apps/stockfw/client/sentinel/mode",
                         sentinel_mode);

    if (g_strcmp0 (sentinel_mode, "auto") == 0) {
        gboolean staged = fs_copilot_sentinel_auto_pass ();

        strip_set (sentinel_strip, "ok",
                   staged
                   ? _("Detect + auto-block is on. A finding was blocked "
                       "for 10 minutes; Undo is in its drawer and under "
                       "Changes.")
                   : _("Detect + auto-block is on. Nothing needed "
                       "blocking."));
    } else {
        guint n = auto_blocks != NULL ? auto_blocks->len : 0;
        gchar *t;

        /* P6: leaving auto mode takes down what auto mode staged --
         * detect means detect, not "whatever is still lingering". */
        fs_copilot_lift_all_auto_blocks ("Sentinel switched to detect");
        t = n == 0
            ? g_strdup (_("Detect only: findings are reported, nothing is "
                          "blocked automatically."))
            : g_strdup_printf (_("Detect only: findings are reported, "
                                 "nothing is blocked automatically. %u "
                                 "automatic blocks were lifted."), n);
        strip_set (sentinel_strip, "ok", t);
        g_free (t);
    }
    refresh_insights ();
}

/* The page is gone: forget its widgets (a rebuilt page has its own). */
static void
on_page_destroy (GtkWidget *w, gpointer data)
{
    (void) data;
    if (w != copilot_vbox)
        return;
    copilot_vbox = NULL;
    scenario_entry = sim_output = NULL;
    sentinel_detect = sentinel_auto = sentinel_strip = NULL;
    tile_attention = tile_attention_note = tile_health = NULL;
    tile_health_note = tile_blocks = tile_blocks_note = NULL;
    tile_learned = tile_learned_note = NULL;
    findings_list = findings_frame = findings_count = NULL;
    findings_empty = findings_empty_text = findings_reason = NULL;
    findings_checked = findings_strip = NULL;
    health_list = health_frame = health_summary = NULL;
    health_empty = health_strip = NULL;
    changes_list = changes_frame = changes_empty = changes_strip = NULL;
    if (refresh_id != 0) {
        g_source_remove (refresh_id);
        refresh_id = 0;
    }
}

static void
on_open_events_clicked (GtkButton *b, gpointer data)
{
    (void) b;
    (void) data;
    fs_app_show_page (FS_PAGE_EVENTS);
}

static void
on_page_map (GtkWidget *w, gpointer data)
{
    (void) w;
    (void) data;
    /* The Policy page may have changed the policy meanwhile. */
    health_run ();
    refresh_insights ();
}

/* A card: heading, an optional muted count on the right, a strip. */
static GtkWidget *
section_card (const gchar *heading, const gchar *name, GtkWidget **right,
              GtkWidget **strip, GtkWidget **body)
{
    GtkWidget *card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *inner = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
    gchar *sn = g_strdup_printf ("%s-strip", name);

    add_class (card, "card");
    gtk_widget_set_name (card, name);
    add_class (head, "card-head");
    gtk_box_pack_start (GTK_BOX (head), text_new (heading, "card-heading",
                                                  FALSE),
                        FALSE, FALSE, 0);
    if (right != NULL) {
        *right = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_box_pack_end (GTK_BOX (head), *right, FALSE, FALSE, 0);
    }
    gtk_box_pack_start (GTK_BOX (card), head, FALSE, FALSE, 0);

    gtk_widget_set_margin_start (inner, 16);
    gtk_widget_set_margin_end (inner, 16);
    gtk_widget_set_margin_bottom (inner, 14);
    *strip = strip_new (sn);
    gtk_box_pack_start (GTK_BOX (inner), *strip, FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (card), inner, FALSE, FALSE, 0);
    *body = inner;
    g_free (sn);
    return card;
}

static GtkWidget *
list_new (const gchar *name, GtkWidget **frame)
{
    GtkWidget *list = gtk_list_box_new ();

    gtk_widget_set_name (list, name);
    gtk_list_box_set_selection_mode (GTK_LIST_BOX (list),
                                     GTK_SELECTION_NONE);
    add_class (list, "cp-list");
    *frame = gtk_frame_new (NULL);
    add_class (*frame, "list-card");
    add_class (*frame, "cp-list-frame");
    gtk_container_add (GTK_CONTAINER (*frame), list);
    gtk_widget_set_no_show_all (*frame, TRUE);
    return list;
}

/* =====================================================================
 * fs_copilot_page - Build the full Copilot tab
 * ===================================================================== */
GtkWidget *
fs_copilot_page (FsCopilot *copilot, FsPolicy *policy)
{
    GtkWidget *row, *card, *body, *right, *b, *l;

    global_copilot = copilot;
    copilot_policy = policy;

    /* Attach the policy to the copilot for real rule-matching simulation. */
    fs_copilot_set_policy (copilot, policy);

    /* Sentinel mode, default auto.  Cached in sentinel_mode so the
     * per-event pass never touches the key file. */
    {
        gchar *pref = fs_prefs_get_string (
            "/apps/stockfw/client/sentinel/mode", "auto");

        g_strlcpy (sentinel_mode,
                   (pref != NULL && *pref != '\0') ? pref : "auto",
                   sizeof sentinel_mode);
        g_free (pref);
    }

    fs_simviz_install_css ();

    /* The window's page frame supplies the title and the margins. */
    copilot_vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 14);
    gtk_widget_set_name (copilot_vbox, "copilot-page");
    add_class (copilot_vbox, "cp-page");
    if (theme_is_dark ()) {
        add_class (copilot_vbox, "cp-dark");
        add_class (copilot_vbox, "fs-wi-dark");
    }
    g_signal_connect (copilot_vbox, "map", G_CALLBACK (on_page_map), NULL);
    g_signal_connect (copilot_vbox, "destroy", G_CALLBACK (on_page_destroy),
                      NULL);

    gtk_box_pack_start (GTK_BOX (copilot_vbox), text_new (
        _("Rule-based checks of your event log and policy, run on this "
          "computer. Nothing is sent anywhere, and every finding shows "
          "the events and the rule behind it."), "muted", TRUE),
        FALSE, FALSE, 0);

    /* ===== Sentinel ===== */
    card = section_card (_("Sentinel"), "cp-sentinel", &right,
                         &sentinel_strip, &body);
    {
        GtkWidget *seg = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);

        add_class (seg, "segmented");
        gtk_widget_set_name (seg, "sentinel-mode");
        sentinel_detect = gtk_radio_button_new_with_label (NULL,
                                                           _("Detect only"));
        sentinel_auto = gtk_radio_button_new_with_label_from_widget (
            GTK_RADIO_BUTTON (sentinel_detect), _("Detect + auto-block"));
        gtk_widget_set_name (sentinel_detect, "sentinel-detect");
        gtk_widget_set_name (sentinel_auto, "sentinel-auto");
        gtk_toggle_button_set_mode (GTK_TOGGLE_BUTTON (sentinel_detect),
                                    FALSE);
        gtk_toggle_button_set_mode (GTK_TOGGLE_BUTTON (sentinel_auto), FALSE);
        add_class (sentinel_detect, "seg-button");
        add_class (sentinel_auto, "seg-button");
        gtk_box_pack_start (GTK_BOX (seg), sentinel_detect, FALSE, FALSE, 0);
        gtk_box_pack_start (GTK_BOX (seg), sentinel_auto, FALSE, FALSE, 0);
        sentinel_sync_buttons ();
        g_signal_connect (sentinel_detect, "toggled",
                          G_CALLBACK (on_sentinel_toggled), (gpointer) "detect");
        g_signal_connect (sentinel_auto, "toggled",
                          G_CALLBACK (on_sentinel_toggled), (gpointer) "auto");
        gtk_box_pack_start (GTK_BOX (right), seg, FALSE, FALSE, 0);
    }
    gtk_box_pack_start (GTK_BOX (body), text_new (
        _("Auto-block only stages outbound blocks to unknown public "
          "addresses, for 10 minutes. Everything else waits for you."),
        "cp-body", TRUE), FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (copilot_vbox), card, FALSE, FALSE, 0);

    /* ===== Tiles ===== */
    row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_set_homogeneous (GTK_BOX (row), TRUE);
    gtk_box_pack_start (GTK_BOX (row),
        tile_new (_("Needs attention"), "tile-attention", &tile_attention,
                  &tile_attention_note), TRUE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (row),
        tile_new (_("Policy health"), "tile-health", &tile_health,
                  &tile_health_note), TRUE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (row),
        tile_new (_("Auto-blocks active"), "tile-blocks", &tile_blocks,
                  &tile_blocks_note), TRUE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (row),
#ifdef G_OS_WIN32
        tile_new (_("Apps learned"), "tile-learned", &tile_learned,
                  &tile_learned_note),
#else
        /* The Linux log names no programs: one profile per service. */
        tile_new (_("Services learned"), "tile-learned", &tile_learned,
                  &tile_learned_note),
#endif
        TRUE, TRUE, 0);
    gtk_box_pack_start (GTK_BOX (copilot_vbox), row, FALSE, FALSE, 0);

    /* ===== Findings ===== */
    card = section_card (_("Findings"), "cp-findings", &right,
                         &findings_strip, &body);
    findings_count = text_new ("", "muted", FALSE);
    gtk_widget_set_name (findings_count, "findings-count");
    gtk_box_pack_start (GTK_BOX (right), findings_count, FALSE, FALSE, 0);
    findings_list = list_new ("findings-list", &findings_frame);
    g_signal_connect (findings_list, "row-activated",
                      G_CALLBACK (on_finding_activated), NULL);
    gtk_box_pack_start (GTK_BOX (body), findings_frame, FALSE, FALSE, 0);

    findings_empty = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_name (findings_empty, "findings-empty");
    findings_empty_text = text_new ("", "empty-state", TRUE);
    gtk_widget_set_name (findings_empty_text, "findings-empty-text");
    gtk_box_pack_start (GTK_BOX (findings_empty), findings_empty_text,
                        FALSE, FALSE, 0);
    findings_reason = text_new ("", "warning-strip", TRUE);
    add_class (findings_reason, "cp-strip");
    gtk_widget_set_name (findings_reason, "findings-reason");
    gtk_widget_set_no_show_all (findings_reason, TRUE);
    gtk_box_pack_start (GTK_BOX (findings_empty), findings_reason,
                        FALSE, FALSE, 0);
    findings_checked = gtk_expander_new (_("What is checked"));
    gtk_widget_set_name (findings_checked, "findings-checked");
    gtk_container_add (GTK_CONTAINER (findings_checked), checked_list_new ());
    gtk_widget_set_no_show_all (findings_checked, TRUE);
    gtk_box_pack_start (GTK_BOX (findings_empty), findings_checked,
                        FALSE, FALSE, 0);
    b = button_new (_("Open Events"), "fs-link", "findings-open-events");
    gtk_widget_set_halign (b, GTK_ALIGN_START);
    g_signal_connect (b, "clicked", G_CALLBACK (on_open_events_clicked),
                      NULL);
    gtk_box_pack_start (GTK_BOX (findings_empty), b, FALSE, FALSE, 0);
    gtk_widget_set_no_show_all (findings_empty, TRUE);
    gtk_box_pack_start (GTK_BOX (body), findings_empty, FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (copilot_vbox), card, FALSE, FALSE, 0);

    /* ===== Policy health ===== */
    card = section_card (_("Policy health"), "cp-health-card", &right,
                         &health_strip, &body);
    health_summary = text_new ("", "muted", FALSE);
    gtk_widget_set_name (health_summary, "health-summary");
    gtk_box_pack_start (GTK_BOX (right), health_summary, FALSE, FALSE, 0);
    b = button_new (_("Check again"), "btn-subtle", "health-again");
    g_signal_connect (b, "clicked", G_CALLBACK (on_health_again_clicked),
                      NULL);
    gtk_box_pack_start (GTK_BOX (right), b, FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (body), text_new (
        _("Overlaps, conflicts and open risky services in the saved "
          "policy. A fix is offered only when What-If shows it does what "
          "it says."), "cp-body", TRUE), FALSE, FALSE, 0);
    health_list = list_new ("health-list", &health_frame);
    gtk_box_pack_start (GTK_BOX (body), health_frame, FALSE, FALSE, 0);
    health_empty = text_new ("", "empty-state", TRUE);
    gtk_widget_set_name (health_empty, "health-empty");
    gtk_widget_set_no_show_all (health_empty, TRUE);
    gtk_box_pack_start (GTK_BOX (body), health_empty, FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (copilot_vbox), card, FALSE, FALSE, 0);

    /* ===== What-If simulator ===== */
    gtk_box_pack_start (GTK_BOX (copilot_vbox), whatif_card_new (),
                        FALSE, FALSE, 0);

    /* ===== Changes ===== */
    card = section_card (_("Changes made by the Copilot"), "cp-changes",
                         NULL, &changes_strip, &body);
    changes_list = list_new ("changes-list", &changes_frame);
    gtk_box_pack_start (GTK_BOX (body), changes_frame, FALSE, FALSE, 0);
    l = text_new (_("No changes yet. Automatic blocks, block rules added "
                    "here and policy fixes are listed with an Undo."),
                  "empty-state", TRUE);
    gtk_widget_set_name (l, "changes-empty");
    changes_empty = l;
    gtk_widget_set_no_show_all (changes_empty, TRUE);
    gtk_box_pack_start (GTK_BOX (body), changes_empty, FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (copilot_vbox), card, FALSE, FALSE, 0);

    /* Initial data */
    health_run ();
    refresh_insights ();

    return copilot_vbox;
}

/* =====================================================================
 * Sentinel auto-block: stage, undo, expire
 *
 * In auto mode every auto-applicable insight whose rule is not already
 * in the policy is staged (add + save, rolled back on a failed write)
 * and pushed at the firewall.  Each staged rule carries the time it
 * was staged: Undo lifts one immediately, and all of them lift ten
 * minutes after staging -- a false positive must not be a permanent
 * policy change.  Every step is written to the append-only audit log.
 * ===================================================================== */
static AutoBlock *
auto_block_find (FsRuleKind kind, const gchar *csv)
{
    guint i;

    if (auto_blocks == NULL || csv == NULL)
        return NULL;

    for (i = 0; i < auto_blocks->len; i++) {
        AutoBlock *ab = g_ptr_array_index (auto_blocks, i);

        if (ab->kind == kind && g_strcmp0 (ab->csv, csv) == 0)
            return ab;
    }

    return NULL;
}

static void
auto_block_free (gpointer data)
{
    AutoBlock *ab = data;

    if (ab == NULL)
        return;

    g_free (ab->csv);
    g_free (ab->title);
    g_free (ab);
}

/* =====================================================================
 * P6 (false-outage hardening): cooldown memory + persistent staging
 *
 * The 2026-10-10 incident was three silent loops stacked: a
 * ten-minute expiry whose re-stage ran forever, staging records that
 * lived only in memory while the policy rows they created survived
 * every restart, and a user Allow that the block rule outranked on
 * Windows.  These helpers close all three: the cooldown breaks the
 * re-stage loop, the state file gives the boot restore something to
 * expire, and the lift functions give the user's Allow the last word.
 * ===================================================================== */

static gchar *
auto_block_key (FsRuleKind kind, const gchar *csv)
{
    return g_strdup_printf ("%d|%s", (int) kind, csv != NULL ? csv : "");
}

static void
auto_block_cooldown_add (FsRuleKind kind, const gchar *csv)
{
    if (auto_block_cooldown == NULL)
        auto_block_cooldown = g_hash_table_new_full (g_str_hash,
                                                     g_str_equal,
                                                     g_free, NULL);

    g_hash_table_add (auto_block_cooldown, auto_block_key (kind, csv));
}

static gboolean
auto_block_cooldown_contains (FsRuleKind kind, const gchar *csv)
{
    gboolean hit;
    gchar *key;

    if (auto_block_cooldown == NULL)
        return FALSE;

    key = auto_block_key (kind, csv);
    hit = g_hash_table_contains (auto_block_cooldown, key);
    g_free (key);

    return hit;
}

/* [ auto_block_state_path ] -- next to behavior.csv and trust.csv;
 * STOCKFW_AUTOBLOCK_FILE overrides it for the tests. */
static gchar *
auto_block_state_path (void)
{
    const gchar *env = g_getenv ("STOCKFW_AUTOBLOCK_FILE");

    if (env != NULL && *env != '\0')
        return g_strdup (env);

#ifdef G_OS_WIN32
    {
        const gchar *appdata = g_getenv ("APPDATA");

        if (appdata != NULL && *appdata != '\0')
            return g_build_filename (appdata, "stockfw", "autoblocks",
                                     NULL);

        return g_build_filename (g_get_home_dir (), "AppData", "Roaming",
                                 "stockfw", "autoblocks", NULL);
    }
#else
    return g_build_filename (g_get_user_config_dir (), "stockfw",
                             "autoblocks", NULL);
#endif
}

/* [ auto_block_state_save ]
 * Rewrite the staged list from the array: one row per block this
 * session staged -- "S,<epoch>,<kind>,<csv>", csv last so its commas
 * survive the split.  Called on every stage and every retire, so the
 * file mirrors the session's OWN blocks and never a user's manual
 * rule.  A failed write is audited, not swallowed: without this file
 * a restart turns managed blocks into orphans nobody expires. */
static void
auto_block_state_save (void)
{
    gchar *path = auto_block_state_path ();
    gchar *dir;
    GString *out;
    GError *error = NULL;
    guint i;

    out = g_string_new (NULL);

    if (auto_blocks != NULL) {
        for (i = 0; i < auto_blocks->len; i++) {
            AutoBlock *ab = g_ptr_array_index (auto_blocks, i);

            g_string_append_printf (out, "S,%" G_GINT64_FORMAT ",%d,%s\n",
                                    ab->at_epoch, (int) ab->kind,
                                    ab->csv != NULL ? ab->csv : "");
        }
    }

    dir = g_path_get_dirname (path);
    g_mkdir_with_parents (dir, 0700);
    g_free (dir);

    if (!g_file_set_contents (path, out->str, -1, &error)) {
        fs_audit_log ("sentinel auto-block state save failed",
                      error != NULL ? error->message : path);
        g_clear_error (&error);
    }

    g_string_free (out, TRUE);
    g_free (path);
}

/* [ auto_block_push ]
 * Put the current policy in front of the firewall and record honestly
 * whether it went live -- through the P3 gate, so a held or rolled-back
 * push never gets an "is live" line. */
static void
auto_block_push (void)
{
    GError *error = NULL;
    FsApplyOutcome *outcome;

    if (copilot_policy == NULL)
        return;

    outcome = fs_policy_apply_safe (fs_backend (), copilot_policy,
                                    "sentinel auto-block",
                                    fs_policyview_hold_reason (), &error);

    if (outcome->applied)
        fs_audit_log ("sentinel auto-block is live",
                      fs_util_apply_result_to_string ((int) outcome->result));
    else if (outcome->held)
        fs_audit_log ("sentinel auto-block staged, not live",
                      outcome->hold_reason);
    else
        fs_audit_log ("sentinel auto-block staged, not live",
                      fs_util_apply_result_to_string ((int) outcome->result));

    fs_apply_outcome_free (outcome);
    g_clear_error (&error);
}

/* [ auto_block_drop ]
 * Take one staged auto-block back out of the policy.  The removal is
 * persisted with the same rollback-on-failure discipline as the add,
 * so a failed write keeps the rule (and says so) rather than
 * pretending the block is gone.  Does not touch the array; callers
 * remove the entry. */
static void
auto_block_drop (AutoBlock *ab, const gchar *why)
{
    FsRule *rule;
    gboolean removed = FALSE;
    gchar *detail;

    if (ab == NULL)
        return;

    if (copilot_policy != NULL) {
        rule = fs_rule_from_csv (ab->kind, ab->csv);

        if (rule != NULL) {
            removed = fs_policy_remove_persist (copilot_policy, rule);
            fs_rule_free (rule);
        }
    }

    detail = g_strdup_printf ("%s (%s)", ab->csv, why);
    fs_audit_log (removed ? "sentinel auto-block removed"
                          : "sentinel auto-block removal had no effect",
                  detail);
    g_free (detail);

    if (removed)
        fs_policyview_reload (copilot_policy);
}

/* [ auto_block_rule_in_policy ]
 * TRUE when the staged rule is (still) in the policy: either the user
 * put it there, or the removal just failed.  The boot restore keeps
 * tracking such a row so the expiry timer retries the drop instead of
 * leaving a block nobody manages. */
static gboolean
auto_block_rule_in_policy (AutoBlock *ab)
{
    FsRule *rule;
    gboolean in;

    if (ab == NULL || copilot_policy == NULL)
        return FALSE;

    rule = fs_rule_from_csv (ab->kind, ab->csv);
    if (rule == NULL)
        return TRUE;   /* cannot see it: assume the worst */

    in = fs_policy_contains (copilot_policy, rule);
    fs_rule_free (rule);

    return in;
}

/* [ auto_block_retire ]
 * Take a staged auto-block down for good: out of the policy, into the
 * session cooldown so the auto pass cannot stage it right back, and
 * out of the array (freeing it) when it was in one -- which also
 * rewrites the state file, so a retirement never leaves a stale row
 * behind.  Rows that were never in the array (the boot restore's
 * stale file rows) are the caller's to save afterwards. */
static void
auto_block_retire (AutoBlock *ab, const gchar *why)
{
    if (ab == NULL)
        return;

    auto_block_drop (ab, why);
    auto_block_cooldown_add (ab->kind, ab->csv);

    if (auto_blocks != NULL && g_ptr_array_remove (auto_blocks, ab))
        auto_block_state_save ();
}

/* [ auto_block_expire_cb ]
 * The ten-minute time-box.  First call is one TTL after the first
 * auto-block; later calls reschedule for the earliest rule still
 * inside its window. */
static gboolean
auto_block_expire_cb (gpointer data)
{
    gint64 now = g_get_monotonic_time ();
    gboolean dropped = FALSE;
    guint i;

    (void) data;

    if (auto_blocks == NULL) {
        auto_block_expiry_id = 0;
        return G_SOURCE_REMOVE;
    }

    for (i = 0; i < auto_blocks->len; ) {
        AutoBlock *ab = g_ptr_array_index (auto_blocks, i);

        if (now - ab->at_us >=
            (gint64) FS_AUTOBLOCK_TTL_S * G_USEC_PER_SEC) {
            /* Retire, not plain drop: the cooldown is what stops the
             * expiry -> immediate re-stage loop that ran for two days
             * in the 2026-10-10 incident. */
            auto_block_retire (ab, "expired after 10 minutes");
            dropped = TRUE;
        } else {
            i++;
        }
    }

    if (dropped)
        auto_block_push ();

    if (auto_blocks->len == 0) {
        auto_block_expiry_id = 0;
        return G_SOURCE_REMOVE;
    }

    /* Some rule is still inside its window: come back for the
     * earliest of those, not a fixed tick. */
    {
        gint64 next = -1;

        for (i = 0; i < auto_blocks->len; i++) {
            AutoBlock *ab = g_ptr_array_index (auto_blocks, i);
            gint64 due = ab->at_us +
                (gint64) FS_AUTOBLOCK_TTL_S * G_USEC_PER_SEC;

            if (next < 0 || due < next)
                next = due;
        }

        auto_block_expiry_id = g_timeout_add (
            (guint) (((next - now) / G_USEC_PER_SEC) * 1000 + 1000),
            auto_block_expire_cb, NULL);
    }

    return G_SOURCE_REMOVE;
}

gboolean
fs_copilot_sentinel_auto_pass (void)
{
    GList *insights, *l;
    gboolean changed = FALSE;
    gint64 now;

    if (global_copilot == NULL || copilot_policy == NULL ||
        g_strcmp0 (sentinel_mode, "auto") != 0)
        return FALSE;

    if (auto_blocks == NULL)
        auto_blocks = g_ptr_array_new_with_free_func (auto_block_free);

    now = g_get_monotonic_time ();

    /* While the disk is refusing writes, do not hammer it once per
     * event: one attempt per minute, one audit line per episode. */
    if (auto_block_failed_once &&
        now - auto_block_last_fail < FS_AUTOBLOCK_RETRY_US)
        return FALSE;

    insights = fs_copilot_get_insights (global_copilot);

    for (l = insights; l != NULL; l = l->next) {
        FsInsight *ins = l->data;
        AutoBlock *ab;
        FsRule *probe;

        if (!ins->auto_applicable)
            continue;

        /* The auto-block invariant: stage only rules that TIGHTEN the
         * policy, whatever the insight's own flag claims -- legacy
         * insights flag service allows TRUE for the user's confirmed
         * Apply button, and those are never staged here. */
        if (!fs_insight_is_auto_safe (ins))
            continue;

        if (auto_block_find (ins->rule_kind, ins->rule_csv) != NULL)
            continue;

        /* P6: never re-stage what this session staged and took back
         * down (expiry, Undo, user allow, mode switch).  The incident
         * was exactly this loop: drop after ten minutes, stage again
         * the next second. */
        if (auto_block_cooldown_contains (ins->rule_kind,
                                          ins->rule_csv))
            continue;

        /* Already in the policy but not staged by us: the user put
         * it there, so it is not ours to manage or expire. */
        probe = fs_insight_to_rule (ins);
        if (probe == NULL)
            continue;

        if (fs_policy_contains (copilot_policy, probe)) {
            fs_rule_free (probe);
            continue;
        }
        fs_rule_free (probe);

        if (!fs_insight_apply (ins, copilot_policy)) {
            if (!auto_block_failed_once) {
                fs_audit_log ("sentinel auto-block failed",
                              ins->rule_csv);
                auto_block_failed_once = TRUE;
            }
            auto_block_last_fail = now;
            continue;
        }

        auto_block_failed_once = FALSE;

        ab = g_new0 (AutoBlock, 1);
        ab->kind  = ins->rule_kind;
        ab->csv   = g_strdup (ins->rule_csv);
        ab->title = g_strdup (ins->title);
        ab->at_us = now;
        ab->at_epoch = g_get_real_time () / G_USEC_PER_SEC;
        g_ptr_array_add (auto_blocks, ab);

        fs_audit_log ("sentinel auto-block", ins->rule_csv);
        changed = TRUE;

        if (auto_block_expiry_id == 0)
            auto_block_expiry_id = g_timeout_add_seconds (
                FS_AUTOBLOCK_TTL_S, auto_block_expire_cb, NULL);
    }

    g_list_free (insights);

    if (changed) {
        auto_block_state_save ();
        fs_policyview_reload (copilot_policy);
        auto_block_push ();
    }

    return changed;
}

/* [ fs_copilot_lift_all_auto_blocks ]
 * Take every staged auto-block down at once -- the Undo button does
 * one, this does the set.  Leaving auto mode uses it, and it is what
 * a "stop blocking things NOW" would want.  Returns TRUE when
 * anything was staged. */
gboolean
fs_copilot_lift_all_auto_blocks (const gchar *why)
{
    gboolean lifted = FALSE;

    while (auto_blocks != NULL && auto_blocks->len > 0) {
        AutoBlock *ab = g_ptr_array_index (auto_blocks,
                                           auto_blocks->len - 1);

        auto_block_retire (ab, why != NULL ? why : "lifted by user");
        lifted = TRUE;
    }

    if (lifted) {
        fs_policyview_reload (copilot_policy);
        auto_block_push ();
        refresh_insights ();
    }

    return lifted;
}

/* [ comment_is_sentinel ]
 * A policy comment belongs to Sentinel when it starts with the
 * Sentinel prefix, allowing for however many spaces the CSV split
 * left in front of it. */
static gboolean
comment_is_sentinel (const gchar *comment)
{
    if (comment == NULL)
        return FALSE;

    while (g_ascii_isspace (*comment))
        comment++;

    return g_str_has_prefix (comment, "Sentinel:");
}

/* [ fs_copilot_lift_auto_blocks_for_dest ]
 * The user's explicit Allow for a destination is the last word.  On
 * Windows a block rule outranks an allow rule, so an event-view Allow
 * that left the Sentinel block standing was a silent no-op -- the
 * "user's Allow lost silently" failure of the 2026-10-10 incident.
 * Staged blocks for this destination are retired (cooldown included,
 * so the next pass cannot stage them straight back) and persisted
 * rows that SENTINEL created for it are removed from the policy;
 * the user's own rules are never touched.  Returns TRUE when anything
 * changed -- the caller's own push then takes the result to the
 * firewall. */
gboolean
fs_copilot_lift_auto_blocks_for_dest (const gchar *dest)
{
    gboolean changed = FALSE;
    guint i;

    if (dest == NULL || *dest == '\0')
        return FALSE;

    /* 1. Blocks this session staged. */
    if (auto_blocks != NULL) {
        for (i = 0; i < auto_blocks->len; ) {
            AutoBlock *ab = g_ptr_array_index (auto_blocks, i);
            FsRule *probe = fs_rule_from_csv (ab->kind, ab->csv);
            gboolean match = probe != NULL && probe->target != NULL &&
                g_ascii_strcasecmp (probe->target, dest) == 0;

            fs_rule_free (probe);

            if (match) {
                auto_block_retire (ab, "user allowed this destination");
                changed = TRUE;
            } else {
                i++;
            }
        }
    }

    /* 2. Rows Sentinel wrote to the policy in an earlier session:
     *    outbound deny, this destination, a Sentinel comment. */
    if (copilot_policy != NULL) {
        GPtrArray *rows = copilot_policy->kinds[FS_RULE_OUTBOUND_DENY_TO];

        for (i = 0; i < rows->len; ) {
            FsRule *r = g_ptr_array_index (rows, i);

            if (r->target != NULL && r->comment != NULL &&
                g_ascii_strcasecmp (r->target, dest) == 0 &&
                comment_is_sentinel (r->comment)) {
                gchar *target = g_strdup (r->target);

                if (fs_policy_remove_persist (copilot_policy, r)) {
                    fs_audit_log ("sentinel rule removed "
                                  "(user allow for destination)",
                                  target);
                    changed = TRUE;
                    /* index i now points at the next row */
                } else {
                    fs_audit_log ("sentinel rule removal had no effect",
                                  target);
                    i++;
                }

                g_free (target);
            } else {
                i++;
            }
        }
    }

    if (changed)
        fs_policyview_reload (copilot_policy);

    return changed;
}

/* [ fs_copilot_autoblocks_restore ]
 * Boot restore, called once from fs-app.c after the Copilot page owns
 * the shared policy -- before any apply can push a stale block.
 * Reads the staged list the previous session persisted: rows older
 * than the ten-minute TTL come out of the policy (they expired while
 * StockFW was not running to expire them), a Sentinel mode that is
 * not "auto" takes the lot down, and fresh rows are re-staged with
 * their original wall-clock time so the REMAINING TTL is honored --
 * a restart must not grant a fresh ten minutes.  The state file is
 * rewritten to mirror what survived, and any row whose removal
 * failed stays tracked so the expiry timer retries it instead of
 * leaving a block nobody manages. */
void
fs_copilot_autoblocks_restore (FsPolicy *policy)
{
    gchar *path;
    gchar *contents = NULL;
    gchar **lines;
    guint i;
    gint64 now_epoch;
    guint stale = 0, lifted = 0, armed = 0, gone = 0, retried = 0;

    if (policy == NULL)
        return;

    /* The shared policy, even if the Copilot page is not built yet:
     * the drop helper works through this pointer. */
    copilot_policy = policy;

    path = auto_block_state_path ();

    if (!g_file_get_contents (path, &contents, NULL, NULL)) {
        g_free (path);
        return;                    /* nothing was staged last session */
    }

    now_epoch = g_get_real_time () / G_USEC_PER_SEC;
    lines = g_strsplit (contents, "\n", -1);

    if (auto_blocks == NULL)
        auto_blocks = g_ptr_array_new_with_free_func (auto_block_free);

    for (i = 0; lines[i] != NULL; i++) {
        const gchar *line = lines[i];
        gchar **parts;
        AutoBlock *ab;
        gint64 epoch;
        gint kind;

        if (*line == '\0' || *line == '#')
            continue;

        parts = g_strsplit (line, ",", 4);

        if (g_strv_length (parts) != 4 || g_strcmp0 (parts[0], "S") != 0 ||
            *parts[3] == '\0') {
            g_strfreev (parts);
            continue;
        }

        epoch = g_ascii_strtoll (parts[1], NULL, 10);
        kind  = (gint) g_ascii_strtoll (parts[2], NULL, 10);

        if (epoch <= 0 || epoch > now_epoch ||
            kind < 0 || kind >= FS_RULE_N_KINDS) {
            g_strfreev (parts);
            continue;
        }

        ab = g_new0 (AutoBlock, 1);
        ab->kind     = (FsRuleKind) kind;
        ab->csv      = g_strdup (parts[3]);
        ab->at_epoch = epoch;
        /* Backdate the monotonic clock from the wall clock: the TTL
         * counts from staging, not from boot. */
        ab->at_us    = g_get_monotonic_time () -
                       (now_epoch - epoch) * G_USEC_PER_SEC;
        g_strfreev (parts);

        if (now_epoch - epoch >= FS_AUTOBLOCK_TTL_S ||
            g_strcmp0 (sentinel_mode, "auto") != 0) {
            const gchar *why =
                now_epoch - epoch >= FS_AUTOBLOCK_TTL_S
                ? "expired while StockFW was not running"
                : "Sentinel is not in auto mode";

            if (auto_block_rule_in_policy (ab))
                auto_block_drop (ab, why);

            if (auto_block_rule_in_policy (ab)) {
                /* The removal failed (disk or ACL): keep the row
                 * tracked, the expiry timer retries the drop. */
                g_ptr_array_add (auto_blocks, ab);
                retried++;
            } else {
                auto_block_cooldown_add (ab->kind, ab->csv);
                auto_block_free (ab);

                if (g_strcmp0 (why, "Sentinel is not in auto mode") == 0)
                    lifted++;
                else
                    stale++;
            }
        } else if (!auto_block_rule_in_policy (ab)) {
            /* The user already deleted the rule themselves: forget
             * the row, remember the cooldown. */
            auto_block_cooldown_add (ab->kind, ab->csv);
            auto_block_free (ab);
            gone++;
        } else {
            g_ptr_array_add (auto_blocks, ab);
            armed++;
        }
    }

    g_strfreev (lines);

    /* The file now mirrors what survived. */
    auto_block_state_save ();

    /* Re-arm the expiry timer for the earliest survivor: restored
     * rows may have under a minute of TTL left. */
    if (auto_blocks->len > 0 && auto_block_expiry_id == 0) {
        gint64 next = -1;
        gint64 remain_s;

        for (i = 0; i < auto_blocks->len; i++) {
            AutoBlock *ab = g_ptr_array_index (auto_blocks, i);
            gint64 due = ab->at_us +
                (gint64) FS_AUTOBLOCK_TTL_S * G_USEC_PER_SEC;

            if (next < 0 || due < next)
                next = due;
        }

        remain_s = (next - g_get_monotonic_time ()) / G_USEC_PER_SEC;
        if (remain_s < 1)
            remain_s = 1;

        auto_block_expiry_id = g_timeout_add_seconds (
            (guint) remain_s, auto_block_expire_cb, NULL);
    }

    if (stale > 0 || lifted > 0 || armed > 0 || gone > 0 || retried > 0) {
        gchar *detail = g_strdup_printf (
            "%u expired while StockFW was not running, %u lifted "
            "(Sentinel not in auto mode), %u re-armed, %u already "
            "gone from the policy, %u kept for a removal retry",
            stale, lifted, armed, gone, retried);

        fs_audit_log ("sentinel auto-blocks restored", detail);
        g_free (detail);
    }

    g_free (contents);
    g_free (path);
}

/* =====================================================================
 * The What-If context
 *
 * Everything this page can learn about the firewall for one
 * question; the card and its fixes are further down, after the
 * apply helpers they share with the suggestion path.
 * ===================================================================== */

/* [ whatif_state_reliable ]
 * Linux reads "stopped" for a running firewall when it may not list
 * the chains (no root); that reading must not become "allowed, the
 * firewall is off". */
static gboolean
whatif_state_reliable (void)
{
#ifdef G_OS_WIN32
    return TRUE;
#else
    return geteuid () == 0;
#endif
}

/* [ whatif_context_build ]
 * The context for one question, against the policy as it is now.
 * settings is filled from the saved preferences and must outlive the
 * context; the caller frees both. */
static FsWhatIfContext *
whatif_context_build (FsSettings *settings)
{
    FsWhatIfContext *ctx;

    fs_settings_load_prefs (settings);

    ctx = fs_whatif_context_new (fs_whatif_native_platform (),
                                 copilot_policy, settings);
    fs_copilot_whatif_observe (ctx, fs_backend (), whatif_state_reliable ());
    fs_copilot_whatif_live (ctx, copilot_policy,
                            fs_policyview_hold_reason ());

    /* Sentinel's staged blocks, with the time each one lifts. */
    if (auto_blocks != NULL) {
        for (guint i = 0; i < auto_blocks->len; i++) {
            AutoBlock *ab = g_ptr_array_index (auto_blocks, i);
            FsRule *rule;

            if (ab->kind != FS_RULE_OUTBOUND_DENY_TO)
                continue;
            rule = fs_rule_from_csv (ab->kind, ab->csv);
            if (rule != NULL && rule->target != NULL)
                fs_whatif_context_add_auto_block (
                    ctx, rule->target,
                    ab->at_epoch > 0 ? ab->at_epoch + FS_AUTOBLOCK_TTL_S
                                     : 0);
            fs_rule_free (rule);
        }
    }

    return ctx;
}

/* =====================================================================
 * Helpers for applying a suggestion for real
 * ===================================================================== */

/* [ apply_result_text ]
 * Turns the backend's verdict into a sentence.  Kept in one place so
 * the same result never gets reported two different ways. */
static const gchar *
apply_result_text (FsApplyResult result)
{
    switch (result) {
    case FS_APPLY_OK:            return "the policy is live on the firewall";
    case FS_APPLY_PARTIAL:       return "the firewall only accepted the policy partially";
    case FS_APPLY_NO_IPTABLES:   return "iptables was not found on this system";
    case FS_APPLY_NO_PRIVILEGE:  return "this account may not change the firewall";
    case FS_APPLY_EXT_IF_FAILED: return "the external-interface rules were rejected";
    case FS_APPLY_INT_IF_FAILED: return "the internal-interface rules were rejected";
    case FS_APPLY_DRY_RUN:       return "held back on purpose (audit-only mode or the Policy Lock), never sent to the firewall";
    case FS_APPLY_FAILED:
    default:                     return "the firewall rejected the change";
    }
}

/* =====================================================================
 * The What-If card (1.0.7)
 *
 * One line of plain text in, an answer out, on the page itself:
 *
 *   - the entry keeps what was typed, so a question is refined, not
 *     retyped;
 *   - "Read as" shows, as small chips, how the line was read: the
 *     direction, protocol, port or service and host -- and, dashed,
 *     what the line left open, which is what a DEPENDS answer splits
 *     on;
 *   - three example questions as chips, one click each;
 *   - the answer as one row: the verdict badge, one line, and Details,
 *     which opens the What-If window (fs-simviz) beside the page -- it
 *     is not modal, and asking again refreshes it in place;
 *   - the last five questions, each one click from being asked again.
 *
 * The line is answered by the What-If engine (fs-whatif.h) with
 * everything this page can learn about the firewall: the native
 * platform's model, the shared policy, the saved Firewall preferences,
 * whether the firewall runs (and on Windows which network profiles are
 * in force with their default actions), whether the saved policy is
 * the applied one, and Sentinel's auto-blocks with their expiry.
 *
 * Asking changes nothing.  A fix runs only from the window's buttons,
 * in whatif_window_action(), after the user asked for it -- and a rule
 * is written only after the engine checked it once more against the
 * policy as it is by then.  What a fix did is reported in the window
 * and in the card's "What changed" log, because "the row exists" and
 * "the firewall enforces it" are two different claims.
 * ===================================================================== */

#define WHATIF_HISTORY_MAX 5

typedef struct
{
    gchar          *line;
    FsWhatIfVerdict verdict;
} WhatIfPast;

static GtkWidget     *whatif_readas      = NULL;  /* "Read as" + chips   */
static GtkWidget     *whatif_chips       = NULL;
static GtkWidget     *whatif_result      = NULL;  /* the answer row      */
static GtkWidget     *whatif_badge_slot  = NULL;
static GtkWidget     *whatif_summary     = NULL;
static GtkWidget     *whatif_history     = NULL;  /* "Recent" + rows     */
static GtkWidget     *whatif_history_rows = NULL;
static GtkWidget     *whatif_log_box     = NULL;  /* "What changed"      */
static GtkWidget     *whatif_window      = NULL;  /* Details, while open */
static gchar         *whatif_line        = NULL;  /* the line last asked */
static GQueue         whatif_past        = G_QUEUE_INIT;
static GString       *whatif_report      = NULL;  /* what a fix did      */
static FsSimvizStatus whatif_report_level = FS_SIMVIZ_STATUS_OK;

static void whatif_reveal (GtkWidget *w, gboolean on);
static void whatif_flow_queue_refit (GtkWidget *flow);
static void whatif_window_action (GtkWidget *window,
                                  const FsWhatIfResult *result,
                                  const FsWhatIfAction *act,
                                  gpointer data);

/* [ whatif_log ]
 * One line of what a fix did: into the card's log (shown from the
 * first entry on) and into the report the window shows when the fix
 * is done.  The tag is the scrollback colour; red and orange also set
 * how the window's report reads. */
static void
whatif_log (const gchar *text, const gchar *tag)
{
    if (whatif_log_box != NULL)
        whatif_reveal (whatif_log_box, TRUE);
    if (sim_output != NULL)
        text_view_append (sim_output, text, tag);

    if (whatif_report != NULL) {
        g_string_append (whatif_report, text);
        if (g_strcmp0 (tag, "red") == 0)
            whatif_report_level = FS_SIMVIZ_STATUS_BAD;
        else if (g_strcmp0 (tag, "orange") == 0 &&
                 whatif_report_level == FS_SIMVIZ_STATUS_OK)
            whatif_report_level = FS_SIMVIZ_STATUS_WARN;
    }
}

static void
whatif_report_begin (void)
{
    if (whatif_report != NULL)
        g_string_free (whatif_report, TRUE);
    whatif_report = g_string_new (NULL);
    whatif_report_level = FS_SIMVIZ_STATUS_OK;
}

/* The report, tidied (the log's markers and indents dropped), onto
 * the window. */
static void
whatif_report_end (void)
{
    gchar **lines;
    GString *out;

    if (whatif_report == NULL)
        return;

    lines = g_strsplit (whatif_report->str, "\n", -1);
    out = g_string_new (NULL);
    for (guint i = 0; lines[i] != NULL; i++) {
        gchar *l = g_strstrip (lines[i]);

        if (g_str_has_prefix (l, "[OK]") || g_str_has_prefix (l, "[!]") ||
            g_str_has_prefix (l, "[=]"))
            l = g_strstrip (strchr (l, ']') + 1);
        if (*l == '\0')
            continue;
        if (out->len > 0)
            g_string_append_c (out, (g_str_has_suffix (out->str, ":"))
                                    ? ' ' : '\n');
        g_string_append (out, l);
    }
    g_strfreev (lines);

    if (whatif_window != NULL)
        fs_simviz_window_set_status (whatif_window, whatif_report_level,
                                     out->str);
    g_string_free (out, TRUE);
    g_string_free (whatif_report, TRUE);
    whatif_report = NULL;
}

/* ---- the card's pieces -------------------------------------------- */

/* Shows or hides one of the card's optional rows.  They are kept out
 * of the page's show_all (no_show_all) while empty; gtk_widget_show_all
 * does nothing on such a widget, so the flag is lifted to show it. */
static void
whatif_reveal (GtkWidget *w, gboolean on)
{
    gtk_widget_set_no_show_all (w, !on);
    if (on)
        gtk_widget_show_all (w);
    else
        gtk_widget_hide (w);
}

/* The words the line was read from, for a chip's tooltip. */
static gchar *
whatif_piece_tip (const FsWhatIfQuery *q, FsWhatIfPieceKind kind,
                  FsWhatIfPieceKind also)
{
    for (guint i = 0; i < q->pieces->len; i++) {
        const FsWhatIfPiece *p = g_ptr_array_index (q->pieces, i);

        if (p->kind == kind || p->kind == also)
            return g_strdup_printf (_("Read from “%s”: %s"),
                                    p->text, p->meaning);
    }
    return NULL;
}

static void
whatif_chip (const gchar *text, const gchar *cls, gchar *tip /* owned */)
{
    GtkWidget *chip = gtk_label_new (text);

    gtk_style_context_add_class (gtk_widget_get_style_context (chip),
                                 "fs-wi-chip");
    if (cls != NULL)
        gtk_style_context_add_class (gtk_widget_get_style_context (chip),
                                     cls);
    if (tip != NULL)
        gtk_widget_set_tooltip_text (chip, tip);
    gtk_widget_set_valign (chip, GTK_ALIGN_CENTER);
    gtk_container_add (GTK_CONTAINER (whatif_chips), chip);
    gtk_widget_show (chip);
    g_free (tip);
}

/* [ whatif_show_chips ] -- how the line was read, piece by piece. */
static void
whatif_show_chips (const FsWhatIfQuery *q)
{
    GList *old;
    gchar *t;
    gboolean icmp;

    if (whatif_chips == NULL)
        return;

    old = gtk_container_get_children (GTK_CONTAINER (whatif_chips));
    for (GList *l = old; l != NULL; l = l->next)
        gtk_widget_destroy (l->data);
    g_list_free (old);

    if (q == NULL) {
        whatif_reveal (whatif_readas, FALSE);
        return;
    }
    icmp = (q->protocol == FS_WHATIF_PROTO_ICMP || q->icmp_type != NULL);

    if (q->verb != FS_WHATIF_VERB_NONE)
        whatif_chip (q->verb == FS_WHATIF_VERB_ALLOW ? _("You want it allowed")
                                                     : _("You want it blocked"),
                     "verb",
                     whatif_piece_tip (q, FS_WHATIF_PIECE_VERB,
                                       FS_WHATIF_PIECE_VERB));

    if (q->direction == FS_WHATIF_DIR_BOTH)
        whatif_chip (_("Both directions"), "open",
                     g_strdup (_("The line names no direction, so it is "
                                 "answered both ways.")));
    else
        whatif_chip (q->direction == FS_WHATIF_DIR_INBOUND ? _("Inbound")
                                                           : _("Outbound"),
                     NULL,
                     whatif_piece_tip (q, FS_WHATIF_PIECE_DIRECTION,
                                       FS_WHATIF_PIECE_DIRECTION));

    if (q->icmp_type != NULL)
        whatif_chip (g_str_equal (q->icmp_type, "echo-request")
                     ? _("ICMP ping") : q->icmp_type, NULL,
                     whatif_piece_tip (q, FS_WHATIF_PIECE_ICMP,
                                       FS_WHATIF_PIECE_PROTOCOL));
    else if (q->protocol != FS_WHATIF_PROTO_ANY)
        whatif_chip (q->protocol == FS_WHATIF_PROTO_TCP ? "TCP"
                     : q->protocol == FS_WHATIF_PROTO_UDP ? "UDP" : "ICMP",
                     NULL,
                     whatif_piece_tip (q, FS_WHATIF_PIECE_PROTOCOL,
                                       FS_WHATIF_PIECE_SERVICE));
    else
        whatif_chip (q->port != 0 ? _("TCP or UDP") : _("Any protocol"),
                     "open",
                     g_strdup (_("The line names no single protocol, so "
                                 "each one is checked.")));

    if (!icmp) {
        if (q->port == 0)
            whatif_chip (_("Any port"), "open",
                         g_strdup (_("The line names no port, so every "
                                     "port is checked.")));
        else {
            t = q->service != NULL
                ? g_strdup_printf (_("%s · port %u"), q->service, q->port)
                : g_strdup_printf (_("Port %u"), q->port);
            whatif_chip (t, NULL,
                         whatif_piece_tip (q, FS_WHATIF_PIECE_SERVICE,
                                           FS_WHATIF_PIECE_PORT));
            g_free (t);
        }
    }

    if (q->host != NULL) {
        t = g_strdup_printf (
            q->direction == FS_WHATIF_DIR_INBOUND ? _("From %s (%s)")
            : q->direction == FS_WHATIF_DIR_OUTBOUND ? _("To %s (%s)")
            : _("Host %s (%s)"),
            q->host, fs_simviz_zone_title (q->host));
        whatif_chip (t, NULL,
                     whatif_piece_tip (q, FS_WHATIF_PIECE_HOST,
                                       FS_WHATIF_PIECE_HOST));
        g_free (t);
    } else {
        whatif_chip (_("Any host"), "open",
                     g_strdup (_("The line names no host, so every "
                                 "address is checked.")));
    }

    /* What was seen and deliberately not used: a host name, an ICMP
     * port.  Shown, so the line is never silently half-read. */
    for (guint i = 0; i < q->pieces->len; i++) {
        const FsWhatIfPiece *p = g_ptr_array_index (q->pieces, i);

        if (p->kind == FS_WHATIF_PIECE_IGNORED) {
            t = g_strdup_printf (_("Not used: %s"), p->text);
            whatif_chip (t, "ignored", g_strdup (p->meaning));
            g_free (t);
        }
    }

    whatif_reveal (whatif_readas, TRUE);
    whatif_flow_queue_refit (whatif_chips);
}

/* The answer in one line: the engine's summary, or for a line asked
 * both ways each direction's verdict. */
static gchar *
whatif_one_line (const FsWhatIfResult *r)
{
    if (r->verdict == FS_WHATIF_ERROR || r->answers->len == 0)
        return g_strdup (r->error != NULL ? r->error : r->summary);

    if (r->answers->len > 1) {
        const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, 0);
        const FsWhatIfAnswer *b = g_ptr_array_index (r->answers, 1);

        return g_strdup_printf (
            _("%s%s: %s. %s: %s. Details shows each direction."),
            r->query->verb == FS_WHATIF_VERB_ALLOW
            ? _("You asked to allow this. ")
            : r->query->verb == FS_WHATIF_VERB_BLOCK
            ? _("You asked to block this. ") : "",
            a->inbound ? _("Inbound") : _("Outbound"),
            fs_whatif_verdict_name (a->verdict),
            b->inbound ? _("Inbound") : _("Outbound"),
            fs_whatif_verdict_name (b->verdict));
    }

    return g_strdup (r->summary);
}

/* [ whatif_show_result ] -- the verdict row under the entry.  When
 * the answer describes a saved policy the firewall is not running, the
 * line says so first: a bare ALLOWED there would be read as what the
 * firewall does now. */
static void
whatif_show_result (const FsWhatIfResult *r, FsWhatIfLive live)
{
    GtkStyleContext *style;
    GList *old;
    gchar *line;
    gchar *a11y;
    const gchar *caveat = NULL;

    if (whatif_result == NULL)
        return;

    old = gtk_container_get_children (GTK_CONTAINER (whatif_badge_slot));
    for (GList *l = old; l != NULL; l = l->next)
        gtk_widget_destroy (l->data);
    g_list_free (old);
    gtk_container_add (GTK_CONTAINER (whatif_badge_slot),
                       fs_simviz_badge_new (r->verdict));

    line = whatif_one_line (r);
    if (r->verdict != FS_WHATIF_ERROR)
        caveat = live == FS_WHATIF_LIVE_HELD
                 ? _("Saved policy, applies on hold: ")
                 : live == FS_WHATIF_LIVE_FAILED
                 ? _("Saved policy, the last apply failed: ")
                 : live == FS_WHATIF_LIVE_STALE
                 ? _("Saved policy, not applied since it changed: ")
                 : NULL;
    if (caveat != NULL) {
        gchar *with = g_strconcat (caveat, line, NULL);

        g_free (line);
        line = with;
    }
    gtk_label_set_text (GTK_LABEL (whatif_summary), line);
    gtk_widget_set_tooltip_text (whatif_summary, line);
    a11y = g_strdup_printf ("%s: %s", fs_whatif_verdict_name (r->verdict),
                            line);
    atk_object_set_name (gtk_widget_get_accessible (whatif_result), a11y);
    g_free (a11y);
    g_free (line);

    style = gtk_widget_get_style_context (whatif_result);
    gtk_style_context_remove_class (style, "ok");
    gtk_style_context_remove_class (style, "bad");
    gtk_style_context_remove_class (style, "warn");
    gtk_style_context_add_class (style,
        r->verdict == FS_WHATIF_ALLOWED ? "ok"
        : r->verdict == FS_WHATIF_BLOCKED ? "bad"
        : r->verdict == FS_WHATIF_DEPENDS ? "warn" : "err");

    whatif_reveal (whatif_result, TRUE);
}

static void
whatif_past_free (gpointer data)
{
    WhatIfPast *p = data;

    g_free (p->line);
    g_free (p);
}

static void
on_whatif_history_clicked (GtkButton *btn, gpointer data)
{
    const gchar *line = g_object_get_data (G_OBJECT (btn), "fs-wi-line");

    (void) data;
    if (line == NULL || scenario_entry == NULL)
        return;
    gtk_entry_set_text (GTK_ENTRY (scenario_entry), line);
    on_simulate_clicked (NULL, NULL);
}

/* [ whatif_history_render ] -- the last five questions, newest first. */
static void
whatif_history_render (void)
{
    GList *old;

    if (whatif_history_rows == NULL)
        return;

    old = gtk_container_get_children (GTK_CONTAINER (whatif_history_rows));
    for (GList *l = old; l != NULL; l = l->next)
        gtk_widget_destroy (l->data);
    g_list_free (old);

    for (GList *l = whatif_past.head; l != NULL; l = l->next) {
        WhatIfPast *p = l->data;
        GtkWidget *btn = gtk_button_new ();
        GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *dot = gtk_label_new ("●");
        GtkWidget *text = gtk_label_new (p->line);
        GtkWidget *verdict = gtk_label_new (fs_whatif_verdict_name (p->verdict));
        gchar *a11y = g_strdup_printf (_("Ask again: %s (was %s)"), p->line,
                                       fs_whatif_verdict_name (p->verdict));

        gtk_style_context_add_class (gtk_widget_get_style_context (btn),
                                     "fs-wi-history");
        gtk_style_context_add_class (gtk_widget_get_style_context (dot),
                                     "fs-wi-dot");
        gtk_style_context_add_class (gtk_widget_get_style_context (dot),
            p->verdict == FS_WHATIF_ALLOWED ? "ok"
            : p->verdict == FS_WHATIF_BLOCKED ? "bad"
            : p->verdict == FS_WHATIF_DEPENDS ? "warn" : "err");
        gtk_label_set_xalign (GTK_LABEL (text), 0.0);
        gtk_label_set_ellipsize (GTK_LABEL (text), PANGO_ELLIPSIZE_END);
        gtk_style_context_add_class (gtk_widget_get_style_context (verdict),
                                     "stat-note");

        gtk_box_pack_start (GTK_BOX (row), dot, FALSE, FALSE, 0);
        gtk_box_pack_start (GTK_BOX (row), text, TRUE, TRUE, 0);
        gtk_box_pack_end (GTK_BOX (row), verdict, FALSE, FALSE, 0);
        gtk_container_add (GTK_CONTAINER (btn), row);
        gtk_widget_set_tooltip_text (btn, _("Ask this again"));
        atk_object_set_name (gtk_widget_get_accessible (btn), a11y);
        g_object_set_data_full (G_OBJECT (btn), "fs-wi-line",
                                g_strdup (p->line), g_free);
        g_signal_connect (btn, "clicked",
                          G_CALLBACK (on_whatif_history_clicked), NULL);
        gtk_box_pack_start (GTK_BOX (whatif_history_rows), btn,
                            FALSE, FALSE, 0);
        g_free (a11y);
    }

    whatif_reveal (whatif_history, whatif_past.length > 0);
}

/* Newest first, one entry per line, five at most. */
static void
whatif_history_push (const gchar *line, FsWhatIfVerdict verdict)
{
    WhatIfPast *p;

    for (GList *l = whatif_past.head; l != NULL; l = l->next) {
        WhatIfPast *old = l->data;

        if (g_strcmp0 (old->line, line) == 0) {
            g_queue_delete_link (&whatif_past, l);
            whatif_past_free (old);
            break;
        }
    }

    p = g_new0 (WhatIfPast, 1);
    p->line = g_strdup (line);
    p->verdict = verdict;
    g_queue_push_head (&whatif_past, p);

    while (whatif_past.length > WHATIF_HISTORY_MAX)
        whatif_past_free (g_queue_pop_tail (&whatif_past));

    whatif_history_render ();
}

/* [ whatif_present ]
 * An answer to the line last asked, wherever it shows: the chips, the
 * row, the newest history entry, and the window if it is open (which
 * then owns `result').  Frees `result' otherwise. */
static void
whatif_present (FsWhatIfResult *result, const FsWhatIfContext *ctx)
{
    whatif_show_chips (result->query);
    whatif_show_result (result, ctx != NULL ? ctx->live
                                            : FS_WHATIF_LIVE_UNKNOWN);
    if (whatif_line != NULL)
        whatif_history_push (whatif_line, result->verdict);

    if (whatif_window != NULL)
        fs_simviz_window_set_result (whatif_window, result, ctx, whatif_line);
    else
        fs_whatif_result_free (result);
}

/* [ whatif_ask ] -- answers `line' and shows the answer. */
static void
whatif_ask (const gchar *line)
{
    FsSettings *settings = fs_settings_new ();
    FsWhatIfContext *ctx = whatif_context_build (settings);
    FsWhatIfResult *result = fs_whatif_simulate_text (ctx, line);

    g_free (whatif_line);
    whatif_line = g_strdup (line);
    whatif_present (result, ctx);

    fs_whatif_context_free (ctx);
    fs_settings_free (settings);
}

static void
on_simulate_clicked (GtkButton *btn, gpointer data)
{
    const gchar *text;
    gchar *line;

    (void) btn; (void) data;

    if (scenario_entry == NULL)
        return;
    text = gtk_entry_get_text (GTK_ENTRY (scenario_entry));
    line = g_strstrip (g_strdup (text != NULL ? text : ""));
    if (*line == '\0') {
        g_free (line);
        return;
    }

    /* The entry keeps the line: a question is refined, not retyped. */
    whatif_ask (line);
    g_free (line);
}

static void
on_whatif_example_clicked (GtkButton *btn, gpointer data)
{
    (void) data;
    gtk_entry_set_text (GTK_ENTRY (scenario_entry),
                        gtk_button_get_label (btn));
    on_simulate_clicked (NULL, NULL);
}

/* [ on_whatif_details_clicked ] -- the What-If window, beside the page. */
static void
on_whatif_details_clicked (GtkButton *btn, gpointer data)
{
    FsSettings *settings;
    FsWhatIfContext *ctx;
    FsWhatIfResult *result;

    (void) btn; (void) data;

    if (whatif_line == NULL)
        return;

    settings = fs_settings_new ();
    ctx = whatif_context_build (settings);
    result = fs_whatif_simulate_text (ctx, whatif_line);

    if (whatif_window != NULL) {
        fs_simviz_window_set_result (whatif_window, result, ctx, whatif_line);
        gtk_window_present (GTK_WINDOW (whatif_window));
    } else {
        whatif_window = fs_simviz_window_new (result, ctx, whatif_line);
        fs_simviz_window_set_action_func (whatif_window,
                                          whatif_window_action, NULL);
        g_signal_connect (whatif_window, "destroy",
                          G_CALLBACK (gtk_widget_destroyed), &whatif_window);
        fs_simviz_window_present (whatif_window, copilot_vbox);
    }

    fs_whatif_context_free (ctx);
    fs_settings_free (settings);
}

/* [ whatif_flow_fit ]
 * Chips as wide as their words, wrapping only when the row is full.
 * A GtkFlowBox either spreads spare width over its children or, kept
 * to its natural width, stacks them one per line; so the row works out
 * how many fit and asks for that many on the first line. */
static gboolean
whatif_flow_refit (gpointer data)
{
    GtkWidget *flow = data;
    GtkWidget *row = gtk_widget_get_parent (flow);
    GList *kids;
    gint avail, used = 0, fit = 0;
    guint spacing;

    g_object_set_data (G_OBJECT (flow), "fs-wi-refit", NULL);
    if (row == NULL)
        return G_SOURCE_REMOVE;

    avail = gtk_widget_get_allocated_width (row);
    kids = gtk_container_get_children (GTK_CONTAINER (row));
    for (GList *l = kids; l != NULL; l = l->next)
        if (l->data != flow && gtk_widget_get_visible (l->data))
            avail -= gtk_widget_get_allocated_width (l->data) +
                     gtk_box_get_spacing (GTK_BOX (row));
    g_list_free (kids);

    spacing = gtk_flow_box_get_column_spacing (GTK_FLOW_BOX (flow));
    kids = gtk_container_get_children (GTK_CONTAINER (flow));
    for (GList *l = kids; l != NULL; l = l->next) {
        gint nat = 0;

        if (!gtk_widget_get_visible (l->data))
            continue;
        gtk_widget_get_preferred_width (l->data, NULL, &nat);
        if (fit > 0 && used + (gint) spacing + nat > avail)
            break;
        used += (fit > 0 ? (gint) spacing : 0) + nat;
        fit++;
    }
    g_list_free (kids);

    if (fit < 1)
        fit = 1;
    if ((guint) fit != gtk_flow_box_get_min_children_per_line (
                           GTK_FLOW_BOX (flow)))
        gtk_flow_box_set_min_children_per_line (GTK_FLOW_BOX (flow),
                                                (guint) fit);
    return G_SOURCE_REMOVE;
}

static void
whatif_flow_queue_refit (GtkWidget *flow)
{
    if (g_object_get_data (G_OBJECT (flow), "fs-wi-refit") != NULL)
        return;
    g_object_set_data (G_OBJECT (flow), "fs-wi-refit", GINT_TO_POINTER (1));
    g_idle_add_full (G_PRIORITY_HIGH_IDLE, whatif_flow_refit,
                     g_object_ref (flow), g_object_unref);
}

static void
on_whatif_row_allocated (GtkWidget *row, GdkRectangle *a, gpointer flow)
{
    gint last = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (row),
                                                    "fs-wi-width"));

    (void) a;
    if (last == gtk_widget_get_allocated_width (row))
        return;
    g_object_set_data (G_OBJECT (row), "fs-wi-width",
                       GINT_TO_POINTER (gtk_widget_get_allocated_width (row)));
    whatif_flow_queue_refit (flow);
}

/* A flow box of chips in `row', fitted as above. */
static GtkWidget *
whatif_flow_new (GtkWidget *row)
{
    GtkWidget *flow = gtk_flow_box_new ();

    gtk_flow_box_set_selection_mode (GTK_FLOW_BOX (flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_column_spacing (GTK_FLOW_BOX (flow), 6);
    gtk_flow_box_set_row_spacing (GTK_FLOW_BOX (flow), 6);
    gtk_flow_box_set_max_children_per_line (GTK_FLOW_BOX (flow), 12);
    gtk_widget_set_halign (flow, GTK_ALIGN_START);
    gtk_widget_set_valign (flow, GTK_ALIGN_START);
    g_signal_connect (row, "size-allocate",
                      G_CALLBACK (on_whatif_row_allocated), flow);
    return flow;
}

/* [ whatif_card_new ] -- the card on the Copilot page. */
static GtkWidget *
whatif_card_new (void)
{
    /* Typed as a person would type them: the parser reads English. */
    static const gchar *examples[] = {
        "Can 192.168.1.50 reach my SSH?",
        "Is outbound DNS to 8.8.8.8 allowed?",
        "block RDP from the internet",
    };
    GtkWidget *card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *body = gtk_box_new (GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *row, *lbl, *flow, *btn;

    fs_simviz_install_css ();
    gtk_style_context_add_class (gtk_widget_get_style_context (card), "card");
    gtk_widget_set_name (card, "whatif-card");

    /* Heading. */
    gtk_style_context_add_class (gtk_widget_get_style_context (head),
                                 "card-head");
    lbl = gtk_label_new (_("What-If simulator"));
    gtk_style_context_add_class (gtk_widget_get_style_context (lbl),
                                 "card-heading");
    gtk_label_set_xalign (GTK_LABEL (lbl), 0.0);
    gtk_box_pack_start (GTK_BOX (head), lbl, FALSE, FALSE, 0);
    lbl = gtk_label_new (_("Ask whether a connection would get through "
                           "the firewall, in plain words. Asking changes "
                           "nothing."));
    gtk_style_context_add_class (gtk_widget_get_style_context (lbl), "muted");
    gtk_label_set_xalign (GTK_LABEL (lbl), 0.0);
    gtk_label_set_line_wrap (GTK_LABEL (lbl), TRUE);
    gtk_box_pack_start (GTK_BOX (head), lbl, FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (card), head, FALSE, FALSE, 0);

    gtk_widget_set_margin_start (body, 16);
    gtk_widget_set_margin_end (body, 16);
    gtk_widget_set_margin_bottom (body, 16);
    gtk_box_pack_start (GTK_BOX (card), body, FALSE, FALSE, 0);

    /* The question. */
    row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    scenario_entry = gtk_entry_new ();
    gtk_widget_set_name (scenario_entry, "whatif-entry");
    gtk_entry_set_placeholder_text (GTK_ENTRY (scenario_entry),
        _("e.g. allow SSH from 192.168.1.50"));
    atk_object_set_name (gtk_widget_get_accessible (scenario_entry),
                         _("What-If question"));
    gtk_widget_set_hexpand (scenario_entry, TRUE);
    g_signal_connect (scenario_entry, "activate",
                      G_CALLBACK (on_simulate_clicked), NULL);
    gtk_box_pack_start (GTK_BOX (row), scenario_entry, TRUE, TRUE, 0);

    btn = button_with_icon (FS_ICON_PLAY, _("Simulate"));
    gtk_widget_set_name (btn, "whatif-simulate");
    gtk_style_context_add_class (gtk_widget_get_style_context (btn),
                                 "btn-primary");
    atk_object_set_name (gtk_widget_get_accessible (btn),
                         _("Simulate this question"));
    g_signal_connect (btn, "clicked", G_CALLBACK (on_simulate_clicked), NULL);
    gtk_box_pack_start (GTK_BOX (row), btn, FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (body), row, FALSE, FALSE, 0);

    /* Examples. */
    row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    lbl = gtk_label_new (_("Try"));
    gtk_style_context_add_class (gtk_widget_get_style_context (lbl), "muted");
    gtk_widget_set_valign (lbl, GTK_ALIGN_CENTER);
    gtk_box_pack_start (GTK_BOX (row), lbl, FALSE, FALSE, 0);
    flow = whatif_flow_new (row);
    gtk_widget_set_name (flow, "whatif-examples");
    for (guint i = 0; i < G_N_ELEMENTS (examples); i++) {
        gchar *a11y = g_strdup_printf (_("Try the example: %s"), examples[i]);

        btn = gtk_button_new_with_label (examples[i]);
        gtk_style_context_add_class (gtk_widget_get_style_context (btn),
                                     "fs-wi-example");
        atk_object_set_name (gtk_widget_get_accessible (btn), a11y);
        g_signal_connect (btn, "clicked",
                          G_CALLBACK (on_whatif_example_clicked), NULL);
        gtk_container_add (GTK_CONTAINER (flow), btn);
        g_free (a11y);
    }
    gtk_box_pack_start (GTK_BOX (row), flow, FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (body), row, FALSE, FALSE, 0);

    /* How the line was read. */
    whatif_readas = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_name (whatif_readas, "whatif-readas");
    lbl = gtk_label_new (_("Read as"));
    gtk_style_context_add_class (gtk_widget_get_style_context (lbl), "muted");
    gtk_widget_set_valign (lbl, GTK_ALIGN_START);
    gtk_widget_set_margin_top (lbl, 2);
    gtk_box_pack_start (GTK_BOX (whatif_readas), lbl, FALSE, FALSE, 0);
    whatif_chips = whatif_flow_new (whatif_readas);
    gtk_widget_set_name (whatif_chips, "whatif-chips");
    gtk_box_pack_start (GTK_BOX (whatif_readas), whatif_chips, FALSE, FALSE,
                        0);
    gtk_widget_set_no_show_all (whatif_readas, TRUE);
    gtk_box_pack_start (GTK_BOX (body), whatif_readas, FALSE, FALSE, 0);

    /* The answer: badge, one line, Details. */
    whatif_result = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_name (whatif_result, "whatif-result");
    gtk_style_context_add_class (gtk_widget_get_style_context (whatif_result),
                                 "fs-wi-result");
    whatif_badge_slot = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_name (whatif_badge_slot, "whatif-verdict");
    gtk_widget_set_valign (whatif_badge_slot, GTK_ALIGN_CENTER);
    gtk_box_pack_start (GTK_BOX (whatif_result), whatif_badge_slot,
                        FALSE, FALSE, 0);
    whatif_summary = gtk_label_new (NULL);
    gtk_widget_set_name (whatif_summary, "whatif-summary");
    gtk_label_set_xalign (GTK_LABEL (whatif_summary), 0.0);
    gtk_label_set_line_wrap (GTK_LABEL (whatif_summary), TRUE);
    gtk_label_set_line_wrap_mode (GTK_LABEL (whatif_summary),
                                  PANGO_WRAP_WORD_CHAR);
    gtk_label_set_lines (GTK_LABEL (whatif_summary), 2);
    gtk_label_set_ellipsize (GTK_LABEL (whatif_summary), PANGO_ELLIPSIZE_END);
    gtk_label_set_max_width_chars (GTK_LABEL (whatif_summary), 90);
    gtk_box_pack_start (GTK_BOX (whatif_result), whatif_summary,
                        TRUE, TRUE, 0);
    btn = gtk_button_new_with_label (_("Details"));
    gtk_widget_set_name (btn, "whatif-details");
    gtk_style_context_add_class (gtk_widget_get_style_context (btn),
                                 "btn-subtle");
    gtk_widget_set_valign (btn, GTK_ALIGN_CENTER);
    atk_object_set_name (gtk_widget_get_accessible (btn),
                         _("Show the details of this answer"));
    g_signal_connect (btn, "clicked",
                      G_CALLBACK (on_whatif_details_clicked), NULL);
    gtk_box_pack_end (GTK_BOX (whatif_result), btn, FALSE, FALSE, 0);
    gtk_widget_set_no_show_all (whatif_result, TRUE);
    gtk_box_pack_start (GTK_BOX (body), whatif_result, FALSE, FALSE, 0);

    /* Recent questions. */
    whatif_history = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_name (whatif_history, "whatif-history");
    lbl = gtk_label_new (_("Recent"));
    gtk_style_context_add_class (gtk_widget_get_style_context (lbl), "muted");
    gtk_label_set_xalign (GTK_LABEL (lbl), 0.0);
    gtk_box_pack_start (GTK_BOX (whatif_history), lbl, FALSE, FALSE, 2);
    whatif_history_rows = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_pack_start (GTK_BOX (whatif_history), whatif_history_rows,
                        FALSE, FALSE, 0);
    gtk_widget_set_no_show_all (whatif_history, TRUE);
    gtk_box_pack_start (GTK_BOX (body), whatif_history, FALSE, FALSE, 0);

    /* What a fix did, kept as a log. */
    whatif_log_box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_name (whatif_log_box, "whatif-log");
    lbl = gtk_label_new (_("What changed"));
    gtk_style_context_add_class (gtk_widget_get_style_context (lbl), "muted");
    gtk_label_set_xalign (GTK_LABEL (lbl), 0.0);
    gtk_box_pack_start (GTK_BOX (whatif_log_box), lbl, FALSE, FALSE, 0);
    sim_output = make_output_view ();
    gtk_widget_set_size_request (sim_output, -1, 90);
    gtk_box_pack_start (GTK_BOX (whatif_log_box), sim_output, TRUE, TRUE, 0);
    gtk_widget_set_no_show_all (whatif_log_box, TRUE);
    gtk_box_pack_start (GTK_BOX (body), whatif_log_box, FALSE, FALSE, 0);

    whatif_history_render ();
    return card;
}

/* =====================================================================
 * The What-If window's fixes
 *
 * The window only presents; everything that changes state happens
 * here, after the user pressed a button, on the same shared policy the
 * Policy page edits:
 *
 *   CREATE_ALLOW / CREATE_BLOCK  one row the engine built for exactly
 *       the question asked.  It is written only when the engine
 *       verified it, the row passes fs_whatif_row_is_safe() (one port,
 *       one protocol, a literal host, nothing that widens on either
 *       platform), and -- because the policy may have changed while
 *       the window was open -- the engine checks it once more against
 *       the policy as it is now.  Then the user confirms the literal
 *       row, it is saved with the usual rollback, pushed through the
 *       apply gate, and the question is asked again so the window says
 *       whether the verdict really changed.
 *   LIFT_SENTINEL  Sentinel's own auto-block for the destination is
 *       lifted the way an Allow from the Events page lifts it (the
 *       user's rules are never touched), after a confirmation.
 *   OPEN_RULE  the Policy page, at that row.
 *   OPEN_ICMP_SETTINGS / OPEN_SETTINGS  the Preferences; the question
 *       is asked again when they close.
 *   START_FIREWALL  the firewall is started, after a confirmation.
 *   APPLY_POLICY  the saved policy goes through the apply gate, after
 *       a confirmation.
 * ===================================================================== */

/* [ whatif_push ] -- the apply gate, reported. */
static void
whatif_push (const gchar *why)
{
    GError *error = NULL;
    FsApplyOutcome *outcome = fs_policy_apply_safe (
        fs_backend (), copilot_policy, why,
        fs_policyview_hold_reason (), &error);

    if (outcome->applied) {
        whatif_log ("     ", NULL);
        whatif_log (apply_result_text (outcome->result),
                    outcome->result == FS_APPLY_OK ? "green" : "orange");
        whatif_log (".\n", NULL);
    } else if (outcome->held) {
        whatif_log ("     Held back on purpose (", "orange");
        whatif_log (outcome->hold_reason, "orange");
        whatif_log ("): saved, not applied.\n", "orange");
    } else {
        /* The change really is in the policy -- say so rather than
         * implying the whole thing failed. */
        whatif_log ("     Saved, but it is NOT live yet: ", "orange");
        whatif_log (apply_result_text (outcome->result), "orange");
        if (error != NULL) {
            whatif_log (" - ", NULL);
            whatif_log (error->message, "dim");
        }
        whatif_log (".\n     ", NULL);
        if (outcome->rollback_attempted && outcome->rollback_verified)
            whatif_log ("The previous policy was restored to the firewall "
                        "and that restore was verified.", "dim");
        else if (outcome->rollback_attempted)
            whatif_log ("The rollback ALSO failed -- the firewall may be in "
                        "an inconsistent state; check the Status page.",
                        "red");
        else
            whatif_log ("No previously applied policy is recorded, so "
                        "nothing could be restored.", "dim");
        whatif_log ("\n     Re-run StockFW as administrator and apply the "
                    "policy to activate it.\n", "dim");
    }
    fs_apply_outcome_free (outcome);
    g_clear_error (&error);
}

/* [ whatif_ask_again ]
 * The question once more, against the policy as it is now: did the
 * change give the verdict it promised?  The new answer replaces the
 * old one on the card and in the window. */
static void
whatif_ask_again (const FsWhatIfResult *before, FsWhatIfVerdict promised)
{
    FsSettings *settings = fs_settings_new ();
    FsWhatIfContext *ctx = whatif_context_build (settings);
    FsWhatIfResult *after = fs_whatif_simulate (ctx, before->query);
    gchar *line;

    /* The answer describes the saved policy.  Unless the apply journal
     * shows the firewall loaded exactly that policy, the new verdict is
     * not what the firewall does yet, and a green line would say it
     * is. */
    if (ctx->live != FS_WHATIF_LIVE_YES) {
        line = g_strdup_printf (
            "     Asked again: with the saved policy \"%s\" would be %s, "
            "but the firewall is not running that policy yet (%s).\n",
            before->query->text, fs_whatif_verdict_name (after->verdict),
            ctx->live == FS_WHATIF_LIVE_HELD ? "applies are on hold"
            : ctx->live == FS_WHATIF_LIVE_UNKNOWN
              ? "there is no record that it was applied"
              : "the apply did not go through");
        whatif_log (line, "orange");
    } else if (after->verdict == promised) {
        line = g_strdup_printf (
            "     Asked again: \"%s\" is now %s (it was %s).\n",
            before->query->text, fs_whatif_verdict_name (after->verdict),
            fs_whatif_verdict_name (before->verdict));
        whatif_log (line, "green");
    } else {
        line = g_strdup_printf (
            "     Asked again: \"%s\" is %s, not %s as checked: %s\n",
            before->query->text, fs_whatif_verdict_name (after->verdict),
            fs_whatif_verdict_name (promised), after->summary);
        whatif_log (line, "orange");
    }
    g_free (line);

    /* The card and the window show the new answer. */
    if (before->query->text != NULL &&
        g_strcmp0 (whatif_line, before->query->text) != 0) {
        g_free (whatif_line);
        whatif_line = g_strdup (before->query->text);
    }
    whatif_present (after, ctx);

    fs_whatif_context_free (ctx);
    fs_settings_free (settings);
}

/* [ whatif_confirm ] -- Yes / No over the What-If window, or the page. */
static gboolean
whatif_confirm (const gchar *title, const gchar *text)
{
    GtkWidget *parent = whatif_window != NULL
                        ? whatif_window : gtk_widget_get_toplevel (sim_output);
    GtkWidget *confirm = gtk_message_dialog_new (
        GTK_IS_WINDOW (parent) ? GTK_WINDOW (parent) : NULL,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "%s", text);
    gint response;

    gtk_window_set_title (GTK_WINDOW (confirm), title);
    response = gtk_dialog_run (GTK_DIALOG (confirm));
    gtk_widget_destroy (confirm);

    return response == GTK_RESPONSE_YES;
}

/* [ create_rule_from_whatif ] */
static void
create_rule_from_whatif (const FsWhatIfResult *result,
                         const FsWhatIfAction *act)
{
    FsSettings *settings;
    FsWhatIfContext *ctx;
    FsRule *rule;
    gchar *csv;
    gchar *why = NULL;
    gchar *question;
    gboolean still;

    if (copilot_policy == NULL) {
        whatif_log ("\n[!] No traffic policy is loaded, so no rule was "
                    "created.\n", "orange");
        return;
    }

    /* Only a verified row, and only one that is safe to write. */
    if ((act->kind != FS_WHATIF_ACT_CREATE_ALLOW &&
         act->kind != FS_WHATIF_ACT_CREATE_BLOCK) ||
        !act->verified || act->row == NULL ||
        !fs_whatif_row_is_safe (act, &why)) {
        whatif_log ("\n[!] That rule was not written: ", "orange");
        whatif_log (why != NULL ? why : "it was not checked", "orange");
        whatif_log (".\n", NULL);
        g_free (why);
        return;
    }

    /* The policy may have changed while the window was open: check the
     * row once more against the policy as it is now. */
    settings = fs_settings_new ();
    ctx = whatif_context_build (settings);
    still = fs_whatif_action_verify (ctx, result->query, act, &why);
    fs_whatif_context_free (ctx);
    fs_settings_free (settings);

    if (!still) {
        whatif_log ("\n[!] The policy changed since this was checked, and "
                    "the rule no longer does only what was asked (", "orange");
        whatif_log (why != NULL ? why : "", "orange");
        whatif_log ("). Nothing was written; simulate the line again.\n",
                    "orange");
        g_free (why);
        return;
    }

    rule = fs_rule_copy (act->row);
    csv = fs_rule_to_csv (rule);

    if (fs_policy_contains (copilot_policy, rule)) {
        whatif_log ("\n[=] Already in your policy, not added again:\n  ",
                    "dim");
        whatif_log (csv, "bold");
        whatif_log ("\n", NULL);
        fs_rule_free (rule);
        g_free (csv);
        return;
    }

    /* The same guardrail the suggestion path uses (Ch. 4.4): a dialog
     * that prints the literal rule and what it does, and nothing is
     * written until a human answers Yes to that exact row. */
    question = g_strdup_printf (
        _("Create this rule?\n\n"
          "%s\n"
          "Rule: %s\n\n"
          "%s\n\n"
          "This will add the rule to your policy, save it to disk and\n"
          "push it to the firewall."),
        act->label, csv, act->explanation);

    if (!whatif_confirm (_("Create This Rule"), question)) {
        whatif_log ("\n[=] Rule creation cancelled; nothing was written.\n",
                    "dim");
        g_free (question);
        fs_rule_free (rule);
        g_free (csv);
        return;
    }
    g_free (question);

    /* Persist.  A failed write must leave no row behind, so the
     * store and the disk never disagree -- add_persist rolls back. */
    if (!fs_policy_add_persist (copilot_policy, rule)) {
        whatif_log ("\n[!] Could not save the new rule to disk, nothing "
                    "was added:\n  ", "red");
        whatif_log (csv, "bold");
        whatif_log ("\n", NULL);
        fs_rule_free (rule);
        g_free (csv);
        return;
    }

    fs_audit_log ("what-if rule created", csv);

    /* Show it on the Policy page straight away. */
    fs_policyview_reload (copilot_policy);
    update_stats ();

    whatif_log ("\n[OK] Rule created and saved to your policy:\n  ",
                "green");
    whatif_log (csv, "bold");
    whatif_log ("\n", NULL);

    /* And put it in front of the actual firewall. */
    whatif_push ("what-if create");

    /* Did it do what was promised? */
    whatif_ask_again (result, act->gives);

    fs_rule_free (rule);
    g_free (csv);
}

/* [ lift_sentinel_from_whatif ] */
static void
lift_sentinel_from_whatif (const FsWhatIfResult *result,
                           const FsWhatIfAction *act)
{
    gchar *question;

    if (act->target == NULL || *act->target == '\0' || !act->verified)
        return;

    question = g_strdup_printf (
        _("Lift Sentinel's block?\n\n%s\n\n"
          "Sentinel blocked %s automatically. Lifting it removes only "
          "Sentinel's own block (your rules are not touched) and keeps "
          "Sentinel from blocking it again this session."),
        act->explanation != NULL ? act->explanation : "", act->target);

    if (!whatif_confirm (_("Lift Sentinel's Block"), question)) {
        whatif_log ("\n[=] Sentinel's block left in place; nothing "
                    "changed.\n", "dim");
        g_free (question);
        return;
    }
    g_free (question);

    if (!fs_copilot_lift_auto_blocks_for_dest (act->target)) {
        whatif_log ("\n[!] No Sentinel block for ", "orange");
        whatif_log (act->target, "bold");
        whatif_log (" could be lifted (it may have expired already, or "
                    "could not be removed from the policy file).\n",
                    "orange");
        whatif_ask_again (result, act->gives);
        return;
    }

    update_stats ();
    refresh_insights ();
    whatif_log ("\n[OK] Sentinel's block of ", "green");
    whatif_log (act->target, "bold");
    whatif_log (" was lifted.\n", "green");

    whatif_push ("what-if lift sentinel");
    whatif_ask_again (result, act->gives);
}

/* [ whatif_open_rule ] -- the Policy page, at the row that decided. */
static void
whatif_open_rule (const FsWhatIfAction *act)
{
    fs_app_show_page (FS_PAGE_POLICY);
    if (act->policy_kind < 0 || act->policy_kind >= FS_RULE_N_KINDS ||
        !fs_policyview_select ((FsRuleKind) act->policy_kind,
                               act->policy_index)) {
        whatif_log ("\n[=] The Policy page is open; that rule is not shown "
                    "there as a row of its own.\n", "dim");
        return;
    }
    whatif_log ("\n[=] The rule is selected on the Policy page.\n", "dim");
}

/* [ whatif_start_firewall ] */
static void
whatif_start_firewall (const FsWhatIfResult *result,
                       const FsWhatIfAction *act)
{
    GError *error = NULL;

    if (!act->verified)
        return;
    if (!whatif_confirm (act->label, _("Start the firewall now?\n\n"
                                       "It loads the saved policy and "
                                       "starts filtering."))) {
        whatif_log ("\n[=] The firewall was not started.\n", "dim");
        return;
    }

    if (!fs_backend ()->start (&error)) {
        whatif_log ("\n[!] The firewall did not start: ", "red");
        whatif_log (error != NULL ? error->message : "no reason given",
                    "red");
        whatif_log ("\n", NULL);
        g_clear_error (&error);
        return;
    }

    fs_statusview_set_state (fs_backend ()->get_state ());
    whatif_log ("\n[OK] The firewall was started.\n", "green");
    whatif_ask_again (result, act->gives);
}

/* [ whatif_apply_policy ] */
static void
whatif_apply_policy (const FsWhatIfResult *result,
                     const FsWhatIfAction *act)
{
    if (copilot_policy == NULL)
        return;
    if (!whatif_confirm (_("Apply the policy"),
                         _("Apply the saved policy to the firewall now?\n\n"
                           "The firewall then runs exactly the rules on the "
                           "Policy page."))) {
        whatif_log ("\n[=] The policy was not applied.\n", "dim");
        return;
    }

    whatif_log ("\n[=] Applying the saved policy:\n", NULL);
    whatif_push ("what-if apply");
    whatif_ask_again (result, act->gives);
}

/* [ whatif_window_action ] -- a button in the What-If window. */
static void
whatif_window_action (GtkWidget *window, const FsWhatIfResult *result,
                      const FsWhatIfAction *act, gpointer data)
{
    (void) data;

    if (act == NULL || result == NULL || result->query == NULL)
        return;

    whatif_report_begin ();

    switch (act->kind) {
    case FS_WHATIF_ACT_CREATE_ALLOW:
    case FS_WHATIF_ACT_CREATE_BLOCK:
        create_rule_from_whatif (result, act);
        break;
    case FS_WHATIF_ACT_LIFT_SENTINEL:
        lift_sentinel_from_whatif (result, act);
        break;
    case FS_WHATIF_ACT_OPEN_RULE:
        whatif_open_rule (act);
        break;
    case FS_WHATIF_ACT_OPEN_ICMP_SETTINGS:
    case FS_WHATIF_ACT_OPEN_SETTINGS:
        fs_dialogs_preferences (window);
        /* Whatever was changed there, the answer is asked again. */
        whatif_log ("\n[=] Asked again with the Preferences as saved now:\n",
                    NULL);
        whatif_ask_again (result, act->gives);
        break;
    case FS_WHATIF_ACT_START_FIREWALL:
        whatif_start_firewall (result, act);
        break;
    case FS_WHATIF_ACT_APPLY_POLICY:
        whatif_apply_policy (result, act);
        break;
    default:
        break;
    }

    whatif_report_end ();
}
