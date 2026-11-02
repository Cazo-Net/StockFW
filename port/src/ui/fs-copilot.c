/*---[ fs-copilot.c ]---------------------------------------------------
 * AI-Powered Smart Firewall Copilot - UI.
 *
 * Features:
 *   - Dashboard stats (learned apps, insights, events, rules)
 *   - Policy rule analyzer (conflicts, redundancies, gaps)
 *   - Anomaly detection insights with color-coded severity
 *   - What-if traffic simulation against real rules
 *   - One-click rule suggestion application
 *--------------------------------------------------------------------*/

#include "fs-copilot.h"
#include "core/fs-copilot.h"
#include "core/fs-rules.h"
#include "core/fs-fwrule.h"
#include "core/fs-backend.h"
#include "core/fs-prefs.h"
#include "core/fs-audit.h"
#include "core/fs-util.h"
#include "ui/fs-app.h"
#include "ui/fs-icons.h"
#include "ui/fs-policyview.h"
#include "ui/fs-simviz.h"
#include "core/fs-apply.h"
#include "core/fs-autoblock.h"
#include "core/fs-i18n.h"
#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* =====================================================================
 * Column indices for the insights tree
 * ===================================================================== */
enum
{
    COL_ICON,        /* stock icon name */
    COL_TITLE,
    COL_TYPE,
    COL_SEVERITY,
    COL_DESC,
    COL_APP,
    COL_DEST,
    COL_SUGGESTION,
    COL_RULE_CSV,
    COL_KIND,        /* FsRuleKind that rule_csv parses as (int) */
    COL_STATUS,      /* Sentinel auto-block state, or empty */
    COL_N_COLS
};

/* =====================================================================
 * Widget state
 * ===================================================================== */
static GtkListStore  *insights_store   = NULL;
static GtkWidget     *insights_tree    = NULL;
static GtkWidget     *scenario_entry   = NULL;
static GtkWidget     *sim_output       = NULL;
static GtkWidget     *stat_apps        = NULL;
static GtkWidget     *stat_insights    = NULL;
static GtkWidget     *stat_events      = NULL;
static GtkWidget     *stat_rules       = NULL;
static GtkWidget     *analysis_output  = NULL;
static GtkWidget     *copilot_vbox     = NULL;

static FsCopilot     *global_copilot   = NULL;
static FsPolicy      *copilot_policy   = NULL;
static guint          total_events     = 0;

/* ===== Sentinel state (1.0.4) =====================================
 *
 * Mode is detect|auto (default auto), cached so the per-event pass
 * does not read the key file.  Auto-blocked rules are tracked with
 * the time they were staged: the user can undo any of them, and
 * every one expires ten minutes after staging unless it was staged
 * manually through the Policy page first. */
static GtkWidget     *sentinel_combo   = NULL;
static gchar          sentinel_mode[16] = "auto";

/* FS_AUTOBLOCK_TTL_S (core/fs-autoblock.h): auto-blocks lift after
 * 10 min. */
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
/* Tray "Pause Sentinel auto-block for 1 hour": while this monotonic
 * time is in the future, the auto pass stages nothing.  Blocks already
 * staged keep their own ten minutes.  Not persisted: a restart
 * resumes auto-block. */
static gint64     sentinel_paused_until = 0;
static guint      sentinel_resume_id = 0;
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

/* =====================================================================
 * Forward declarations
 * ===================================================================== */
static void refresh_insights (void);
static void update_stats (void);
static void run_policy_analysis (void);
static void on_simulate_clicked (GtkButton *btn, gpointer data);
static void create_rule_from_scenario (const FsScenario *sc);
static void on_apply_suggestion_clicked (GtkButton *btn, gpointer data);
static void on_analyze_clicked (GtkButton *btn, gpointer data);
static void on_clear_clicked (GtkButton *btn, gpointer data);
static void on_sentinel_mode_changed (GtkComboBox *combo, gpointer data);
static void on_undo_auto_clicked (GtkButton *btn, gpointer data);
static gboolean auto_block_expire_cb (gpointer data);
static void on_row_activated (GtkTreeView *tree, GtkTreePath *path,
                              GtkTreeViewColumn *col, gpointer data);
static const gchar *severity_to_icon (FsCopilotSeverity sev);
static const gchar *insight_type_to_string (FsInsightType type);
static const gchar *severity_to_string (FsCopilotSeverity sev);

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

/* =====================================================================
 * Helper: create a stat card (big value + label)
 * ===================================================================== */
static GtkWidget *
make_stat_card (const gchar *label, GtkWidget **value_out)
{
    /* The Overview's stat card: the name small on top, the number
     * large under it.  No theme icon: which icons a Windows runtime
     * ships is not something the page can count on, and a missing one
     * renders as a broken-image square. */
    GtkWidget *card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
    gtk_style_context_add_class (gtk_widget_get_style_context (card), "card");
    gtk_style_context_add_class (gtk_widget_get_style_context (card),
                                 "stat-card");

    GtkWidget *lbl = gtk_label_new (label);
    gtk_style_context_add_class (gtk_widget_get_style_context (lbl), "muted");
    gtk_label_set_xalign (GTK_LABEL (lbl), 0.0);
    gtk_box_pack_start (GTK_BOX (card), lbl, FALSE, FALSE, 0);

    GtkWidget *val = gtk_label_new ("0");
    gtk_style_context_add_class (gtk_widget_get_style_context (val), "stat-big");
    gtk_label_set_xalign (GTK_LABEL (val), 0.0);
    gtk_box_pack_start (GTK_BOX (card), val, FALSE, FALSE, 0);

    *value_out = val;
    return card;
}

/* =====================================================================
 * Helper: create a styled text view for output
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

/* =====================================================================
 * Helper: append text to a GtkTextView with optional style tag
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
            t = gtk_text_tag_new (tag);
            if (g_strcmp0(tag, "bold") == 0)
                g_object_set(t, "weight", PANGO_WEIGHT_BOLD, NULL);
            else if (g_strcmp0(tag, "title") == 0) {
                g_object_set(t, "weight", PANGO_WEIGHT_BOLD,
                             "scale", 1.15, NULL);
            } else if (g_strcmp0(tag, "green") == 0)
                g_object_set(t, "foreground", "#2e7d32", NULL);
            else if (g_strcmp0(tag, "red") == 0)
                g_object_set(t, "foreground", "#c62828", NULL);
            else if (g_strcmp0(tag, "orange") == 0)
                g_object_set(t, "foreground", "#e65100", NULL);
            else if (g_strcmp0(tag, "blue") == 0)
                g_object_set(t, "foreground", "#1565c0", NULL);
            else if (g_strcmp0(tag, "dim") == 0)
                g_object_set(t, "foreground", "#757575", NULL);
            gtk_text_tag_table_add (
                gtk_text_buffer_get_tag_table (buf), t);
        }
        gtk_text_buffer_insert_with_tags_by_name (buf, &end, text, -1, tag, NULL);
    } else {
        gtk_text_buffer_insert (buf, &end, text, -1);
    }

    gtk_text_view_scroll_to_iter (GTK_TEXT_VIEW (view), &end, 0, FALSE, 0, 0);
}

/* =====================================================================
 * build_insights_tree - Create the insights tree view
 * ===================================================================== */
static GtkWidget *
build_insights_tree (void)
{
    /* G_TYPE_STRING for every string column above (COL_ICON ..
     * COL_RULE_CSV, COL_STATUS), G_TYPE_INT for COL_KIND, in enum
     * order ending at COL_N_COLS.  Passing fewer columns leaves
     * GObject reading an uninitialised GType out of the varargs,
     * which is a crash waiting to happen. */
    insights_store = gtk_list_store_new (COL_N_COLS,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_INT,   G_TYPE_STRING);

    GtkWidget *tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (insights_store));
    g_object_unref (GTK_TREE_MODEL (insights_store));
    gtk_tree_view_set_headers_visible (GTK_TREE_VIEW (tree), TRUE);
    gtk_style_context_add_class (gtk_widget_get_style_context (tree),
                                 "data-grid");
    gtk_tree_view_set_grid_lines (GTK_TREE_VIEW (tree),
                                  GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);

    g_signal_connect (tree, "row-activated", G_CALLBACK (on_row_activated), NULL);

    GtkCellRenderer *r;
    GtkTreeViewColumn *c;

    /* Severity icon */
    r = gtk_cell_renderer_pixbuf_new ();
    c = gtk_tree_view_column_new_with_attributes ("", r,
                                                  "icon-name", COL_ICON, NULL);
    gtk_tree_view_column_set_sizing (c, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_fixed_width (c, 32);
    gtk_tree_view_append_column (GTK_TREE_VIEW (tree), c);

    /* Title */
    r = gtk_cell_renderer_text_new ();
    g_object_set (r, "weight", PANGO_WEIGHT_BOLD, NULL);
    c = gtk_tree_view_column_new_with_attributes (_("Title"), r,
                                                  "text", COL_TITLE, NULL);
    gtk_tree_view_column_set_min_width (c, 160);
    gtk_tree_view_column_set_expand (c, TRUE);
    gtk_tree_view_append_column (GTK_TREE_VIEW (tree), c);

    /* Type */
    r = gtk_cell_renderer_text_new ();
    c = gtk_tree_view_column_new_with_attributes (_("Type"), r,
                                                  "text", COL_TYPE, NULL);
    gtk_tree_view_column_set_min_width (c, 90);
    gtk_tree_view_append_column (GTK_TREE_VIEW (tree), c);

    /* Severity */
    r = gtk_cell_renderer_text_new ();
    c = gtk_tree_view_column_new_with_attributes (_("Severity"), r,
                                                  "text", COL_SEVERITY, NULL);
    gtk_tree_view_column_set_min_width (c, 70);
    gtk_tree_view_append_column (GTK_TREE_VIEW (tree), c);

    /* Description */
    r = gtk_cell_renderer_text_new ();
    g_object_set (r, "ellipsize", PANGO_ELLIPSIZE_END, NULL);
    c = gtk_tree_view_column_new_with_attributes (_("Description"), r,
                                                  "text", COL_DESC, NULL);
    gtk_tree_view_column_set_min_width (c, 250);
    gtk_tree_view_append_column (GTK_TREE_VIEW (tree), c);

    /* App */
    r = gtk_cell_renderer_text_new ();
    c = gtk_tree_view_column_new_with_attributes (_("App"), r,
                                                  "text", COL_APP, NULL);
    gtk_tree_view_column_set_min_width (c, 80);
    gtk_tree_view_append_column (GTK_TREE_VIEW (tree), c);

    /* Sentinel auto-block status */
    r = gtk_cell_renderer_text_new ();
    c = gtk_tree_view_column_new_with_attributes (_("Status"), r,
                                                  "text", COL_STATUS, NULL);
    gtk_tree_view_column_set_min_width (c, 90);
    gtk_tree_view_append_column (GTK_TREE_VIEW (tree), c);

    return tree;
}

/* =====================================================================
 * fs_copilot_page - Build the full Copilot tab
 * ===================================================================== */
GtkWidget *
fs_copilot_page (FsCopilot *copilot, FsPolicy *policy)
{
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

    /* The window's page frame supplies the title and the margins. */
    copilot_vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);

    /* ===== Header ===== */
    {
        /* The page's name and description are in the window's page
         * header; this row keeps the page's two controls. */
        GtkWidget *hdr = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);

        /* Sentinel mode: detect only, or detect + auto-block.  The
         * auto path stages critical insights into the policy with a
         * ten-minute time-box (see fs_copilot_sentinel_auto_pass). */
        {
            GtkWidget *mode_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
            GtkWidget *mode_lbl = gtk_label_new (_("Sentinel:"));

            sentinel_combo = gtk_combo_box_text_new ();
            gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (sentinel_combo),
                                       "detect", _("Detect only"));
            gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (sentinel_combo),
                                       "auto", _("Detect + auto-block"));
            gtk_combo_box_set_active_id (GTK_COMBO_BOX (sentinel_combo),
                                         sentinel_mode);
            g_signal_connect (sentinel_combo, "changed",
                              G_CALLBACK (on_sentinel_mode_changed), NULL);

            gtk_box_pack_start (GTK_BOX (mode_box), mode_lbl,
                                FALSE, FALSE, 0);
            gtk_box_pack_start (GTK_BOX (mode_box), sentinel_combo,
                                FALSE, FALSE, 0);
            gtk_widget_set_valign (sentinel_combo, GTK_ALIGN_CENTER);
            gtk_box_pack_start (GTK_BOX (hdr), mode_box, FALSE, FALSE, 0);
        }

        GtkWidget *analyze_btn = button_with_icon (FS_ICON_SEARCH, _("Run analysis"));
        gtk_style_context_add_class (gtk_widget_get_style_context (analyze_btn),
                                     "btn-primary");
        g_signal_connect (analyze_btn, "clicked",
                          G_CALLBACK (on_analyze_clicked), NULL);
        gtk_box_pack_end (GTK_BOX (hdr), analyze_btn, FALSE, FALSE, 0);

        gtk_box_pack_start (GTK_BOX (copilot_vbox), hdr, FALSE, FALSE, 0);
    }

    /* ===== Stats dashboard ===== */
    {
        GtkWidget *stats = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 12);
        gtk_box_set_homogeneous (GTK_BOX (stats), TRUE);

        GtkWidget *c1, *c2, *c3, *c4;
        c1 = make_stat_card (_("Apps learned"),    &stat_apps);
        c2 = make_stat_card (_("Active insights"), &stat_insights);
        c3 = make_stat_card (_("Events analyzed"), &stat_events);
        c4 = make_stat_card (_("Policy rules"),    &stat_rules);

        gtk_box_pack_start (GTK_BOX (stats), c1, TRUE, TRUE, 0);
        gtk_box_pack_start (GTK_BOX (stats), c2, TRUE, TRUE, 0);
        gtk_box_pack_start (GTK_BOX (stats), c3, TRUE, TRUE, 0);
        gtk_box_pack_start (GTK_BOX (stats), c4, TRUE, TRUE, 0);

        gtk_box_pack_start (GTK_BOX (copilot_vbox), stats, FALSE, FALSE, 0);
    }

    /* ===== Insights tree ===== */
    {
        /* One card, as on the Overview: heading, list, actions. */
        GtkWidget *card = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);
        gtk_style_context_add_class (gtk_widget_get_style_context (card), "card");

        GtkWidget *lbl = gtk_label_new (_("Insights and suggestions"));
        gtk_style_context_add_class (gtk_widget_get_style_context (lbl),
                                     "card-heading");
        gtk_style_context_add_class (gtk_widget_get_style_context (lbl),
                                     "card-head");
        gtk_label_set_xalign (GTK_LABEL (lbl), 0.0);
        gtk_box_pack_start (GTK_BOX (card), lbl, FALSE, FALSE, 0);

        insights_tree = build_insights_tree ();
        GtkWidget *scrolled = gtk_scrolled_window_new (NULL, NULL);
        gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled),
                                        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
        gtk_scrolled_window_set_min_content_height (
            GTK_SCROLLED_WINDOW (scrolled), 140);
        gtk_container_add (GTK_CONTAINER (scrolled), insights_tree);
        gtk_box_pack_start (GTK_BOX (card), scrolled, TRUE, TRUE, 0);

        /* Buttons row */
        GtkWidget *btn_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
        gtk_style_context_add_class (gtk_widget_get_style_context (btn_box),
                                     "card-foot");

        GtkWidget *apply_btn = button_with_icon (FS_ICON_N_KINDS,
                                                 _("Apply selected rule"));
        gtk_style_context_add_class (gtk_widget_get_style_context (apply_btn),
                                     "btn-primary");
        g_signal_connect (apply_btn, "clicked",
                          G_CALLBACK (on_apply_suggestion_clicked), NULL);
        gtk_box_pack_start (GTK_BOX (btn_box), apply_btn, FALSE, FALSE, 0);

        GtkWidget *clear_btn = button_with_icon (FS_ICON_N_KINDS, _("Clear insights"));
        gtk_style_context_add_class (gtk_widget_get_style_context (clear_btn),
                                     "btn-subtle");
        g_signal_connect (clear_btn, "clicked", G_CALLBACK (on_clear_clicked), NULL);
        gtk_box_pack_start (GTK_BOX (btn_box), clear_btn, FALSE, FALSE, 0);

        GtkWidget *undo_btn = button_with_icon (FS_ICON_N_KINDS,
                                                _("Undo auto-block"));
        gtk_style_context_add_class (gtk_widget_get_style_context (undo_btn),
                                     "btn-subtle");
        g_signal_connect (undo_btn, "clicked",
                          G_CALLBACK (on_undo_auto_clicked), NULL);
        gtk_box_pack_start (GTK_BOX (btn_box), undo_btn, FALSE, FALSE, 0);

        gtk_box_pack_start (GTK_BOX (card), btn_box, FALSE, FALSE, 0);
        gtk_box_pack_start (GTK_BOX (copilot_vbox), card, TRUE, TRUE, 0);
    }

    /* ===== What-if simulator ===== */
    {
        GtkWidget *frame = gtk_frame_new (_("What-if simulator"));
        gtk_style_context_add_class (gtk_widget_get_style_context (frame),
                                     "card-frame");
        gtk_frame_set_shadow_type (GTK_FRAME (frame), GTK_SHADOW_NONE);
        GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
        gtk_container_set_border_width (GTK_CONTAINER (box), 6);

        GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);

        scenario_entry = gtk_entry_new ();
        gtk_entry_set_placeholder_text (GTK_ENTRY (scenario_entry),
            _("e.g. allow SSH from 192.168.1.50 on port 22"));
        gtk_widget_set_hexpand (scenario_entry, TRUE);
        gtk_box_pack_start (GTK_BOX (row), scenario_entry, TRUE, TRUE, 0);

        GtkWidget *sim_btn = button_with_icon (FS_ICON_PLAY, _("Simulate"));
        gtk_style_context_add_class (gtk_widget_get_style_context (sim_btn),
                                     "btn-primary");
        g_signal_connect (sim_btn, "clicked",
                          G_CALLBACK (on_simulate_clicked), NULL);
        gtk_box_pack_start (GTK_BOX (row), sim_btn, FALSE, FALSE, 0);

        g_signal_connect (scenario_entry, "activate",
                          G_CALLBACK (on_simulate_clicked), NULL);

        gtk_box_pack_start (GTK_BOX (box), row, FALSE, FALSE, 0);

        /* The parsed reading and the verdict, in the panel itself:
         * iterating on a scenario must not cost a dialog per try. */
        sim_output = make_output_view ();
        gtk_widget_set_size_request (sim_output, -1, 90);
        gtk_box_pack_start (GTK_BOX (box), sim_output, TRUE, TRUE, 0);

        gtk_container_add (GTK_CONTAINER (frame), box);
        gtk_box_pack_start (GTK_BOX (copilot_vbox), frame, FALSE, FALSE, 0);
    }

    /* ===== Policy Analysis ===== */
    {
        GtkWidget *a_lbl = gtk_label_new (_("Policy analysis"));
        gtk_style_context_add_class (gtk_widget_get_style_context (a_lbl),
                                     "card-heading");
        gtk_label_set_xalign (GTK_LABEL (a_lbl), 0.0);
        gtk_box_pack_start (GTK_BOX (copilot_vbox), a_lbl, FALSE, FALSE, 0);

        analysis_output = make_output_view ();
        gtk_widget_set_size_request (analysis_output, -1, 80);
        gtk_box_pack_start (GTK_BOX (copilot_vbox), analysis_output, FALSE, FALSE, 0);
    }

    /* Initial data */
    refresh_insights ();
    update_stats ();

    return copilot_vbox;
}

/* =====================================================================
 * fs_copilot_view_refresh - Public refresh
 * ===================================================================== */
void
fs_copilot_view_refresh (void)
{
    refresh_insights ();
    update_stats ();
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
    /* One definition, shared with `stockfw start' (core). */
    return fs_autoblock_state_path ();
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

    if (fs_copilot_sentinel_paused (NULL))
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

static const gchar *
auto_block_status (FsInsight *ins)
{
    if (ins->rule_csv == NULL || *ins->rule_csv == '\0')
        return "";

    return auto_block_find (ins->rule_kind, ins->rule_csv) != NULL
           ? _("Auto-blocked") : "";
}

/* [ on_undo_auto_clicked ]
 * Lift the most recent Sentinel auto-block right now. */
static void
on_undo_auto_clicked (GtkButton *btn, gpointer data)
{
    AutoBlock *ab;
    gchar *csv;

    (void) btn;
    (void) data;

    if (auto_blocks == NULL || auto_blocks->len == 0) {
        text_view_append (analysis_output,
            "\n[=] No Sentinel auto-block is staged.\n", "dim");
        return;
    }

    ab  = g_ptr_array_index (auto_blocks, auto_blocks->len - 1);
    csv = g_strdup (ab->csv);

    /* Retire: drop + cooldown + out of the state file, so the next
     * auto pass cannot stage the very rule the user just lifted. */
    auto_block_retire (ab, "undone by user");

    auto_block_push ();
    refresh_insights ();
    update_stats ();

    text_view_append (analysis_output,
        "\n[OK] Sentinel auto-block undone:\n  ", "green");
    text_view_append (analysis_output, csv, "bold");
    text_view_append (analysis_output, "\n", NULL);
    g_free (csv);
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
gboolean
fs_copilot_autoblocks_restore (FsPolicy *policy)
{
    gchar *path;
    gchar *contents = NULL;
    gchar **lines;
    guint i;
    gint64 now_epoch;
    guint stale = 0, lifted = 0, armed = 0, gone = 0, retried = 0;

    if (policy == NULL)
        return FALSE;

    /* The shared policy, even if the Copilot page is not built yet:
     * the drop helper works through this pointer. */
    copilot_policy = policy;

    path = auto_block_state_path ();

    if (!g_file_get_contents (path, &contents, NULL, NULL)) {
        g_free (path);
        return FALSE;              /* nothing was staged last session */
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

    /* Rows came out of the policy: the firewall still holds them until
     * a push or a start.  The caller decides which (fs-app.c). */
    return stale > 0 || lifted > 0;
}

/* [ fs_copilot_autoblocks_push ] -- see fs-copilot.h. */
void
fs_copilot_autoblocks_push (void)
{
    auto_block_push ();
}

/* ===== Sentinel pause (tray menu) ================================ */

gboolean
fs_copilot_sentinel_can_pause (void)
{
    return global_copilot != NULL && copilot_policy != NULL &&
           g_strcmp0 (sentinel_mode, "auto") == 0;
}

gboolean
fs_copilot_sentinel_paused (gint64 *seconds_left)
{
    gint64 now = g_get_monotonic_time ();

    if (sentinel_paused_until <= now) {
        if (seconds_left != NULL)
            *seconds_left = 0;
        return FALSE;
    }
    if (seconds_left != NULL)
        *seconds_left = (sentinel_paused_until - now + G_USEC_PER_SEC - 1) /
                        G_USEC_PER_SEC;
    return TRUE;
}

static gboolean
sentinel_resume_cb (gpointer data)
{
    (void) data;

    sentinel_resume_id = 0;
    fs_copilot_sentinel_pause (0);
    return G_SOURCE_REMOVE;
}

void
fs_copilot_sentinel_pause (guint seconds)
{
    gboolean was_paused = fs_copilot_sentinel_paused (NULL);

    if (sentinel_resume_id != 0) {
        g_source_remove (sentinel_resume_id);
        sentinel_resume_id = 0;
    }

    if (seconds == 0) {
        sentinel_paused_until = 0;
        if (!was_paused)
            return;
        fs_audit_log ("sentinel auto-block resumed",
                      "tray | auto-block stages critical insights again");
        if (analysis_output != NULL)
            text_view_append (analysis_output,
                "\n[Sentinel] auto-block resumed.\n", "dim");
        /* Catch up on what arrived while paused. */
        if (fs_copilot_sentinel_auto_pass ())
            refresh_insights ();
        return;
    }

    sentinel_paused_until = g_get_monotonic_time () +
                            (gint64) seconds * G_USEC_PER_SEC;
    sentinel_resume_id = g_timeout_add_seconds (seconds,
                                                sentinel_resume_cb, NULL);
    {
        gchar *detail = g_strdup_printf (
            "tray | nothing new is staged for %u minutes; blocks already "
            "staged keep their own ten minutes", seconds / 60);

        fs_audit_log ("sentinel auto-block paused", detail);
        g_free (detail);
    }
    if (analysis_output != NULL)
        text_view_append (analysis_output,
            "\n[Sentinel] auto-block paused from the tray menu: insights "
            "are still reported, nothing new is staged.\n", "dim");
}

/* [ on_sentinel_mode_changed ] */
static void
on_sentinel_mode_changed (GtkComboBox *combo, gpointer data)
{
    const gchar *id = gtk_combo_box_get_active_id (combo);

    (void) data;

    if (id == NULL)
        return;

    g_strlcpy (sentinel_mode, id, sizeof sentinel_mode);
    fs_prefs_set_string ("/apps/stockfw/client/sentinel/mode",
                         sentinel_mode);

    if (g_strcmp0 (sentinel_mode, "auto") == 0) {
        gboolean staged = fs_copilot_sentinel_auto_pass ();

        if (staged)
            refresh_insights ();

        text_view_append (analysis_output,
            "\n[Sentinel] auto-block armed: critical insights with a "
            "ready rule are staged into the policy for 10 minutes "
            "(Undo on this page lifts one early).\n", "dim");
    } else {
        /* P6: leaving auto mode takes down what auto mode staged --
         * detect means detect, not "whatever is still lingering". */
        fs_copilot_lift_all_auto_blocks ("Sentinel switched to detect");

        text_view_append (analysis_output,
            "\n[Sentinel] detect only: insights are reported, nothing "
            "is staged.\n", "dim");
    }
}

/* =====================================================================
 * refresh_insights - Reload insights into the tree
 * ===================================================================== */
static void
refresh_insights (void)
{
    if (!global_copilot || !insights_store)
        return;

    gtk_list_store_clear (insights_store);

    GList *insights = fs_copilot_get_insights (global_copilot);
    GList *l;

    for (l = insights; l != NULL; l = l->next)
    {
        FsInsight *ins = l->data;
        GtkTreeIter iter;

        gtk_list_store_append (insights_store, &iter);
        gtk_list_store_set (insights_store, &iter,
            COL_ICON,       severity_to_icon (ins->severity),
            COL_TITLE,      ins->title,
            COL_TYPE,       insight_type_to_string (ins->type),
            COL_SEVERITY,   severity_to_string (ins->severity),
            COL_DESC,       ins->description,
            COL_APP,        ins->application ? ins->application : "-",
            COL_DEST,       ins->destination ? ins->destination : "-",
            COL_SUGGESTION, ins->suggested_rule ? ins->suggested_rule : "-",
            COL_RULE_CSV,   ins->rule_csv ? ins->rule_csv : "",
            COL_KIND,       (gint) ins->rule_kind,
            COL_STATUS,     auto_block_status (ins),
            -1);
    }

    g_list_free (insights);
}

/* =====================================================================
 * update_stats - Refresh the stat cards
 * ===================================================================== */
static void
update_stats (void)
{
    gchar buf[32];

    if (global_copilot && stat_apps) {
        GList *profiles = fs_copilot_get_all_profiles (global_copilot);
        g_snprintf (buf, sizeof buf, "%u", g_list_length (profiles));
        gtk_label_set_text (GTK_LABEL (stat_apps), buf);
        g_list_free (profiles);
    }

    if (global_copilot && stat_insights) {
        GList *ins = fs_copilot_get_insights (global_copilot);
        g_snprintf (buf, sizeof buf, "%u", g_list_length (ins));
        gtk_label_set_text (GTK_LABEL (stat_insights), buf);
        g_list_free (ins);
    }

    if (stat_events) {
        g_snprintf (buf, sizeof buf, "%u", total_events);
        gtk_label_set_text (GTK_LABEL (stat_events), buf);
    }

    if (stat_rules) {
        g_snprintf (buf, sizeof buf, "0");
        gtk_label_set_text (GTK_LABEL (stat_rules), buf);
    }
}

/* =====================================================================
 * fs_copilot_note_event - called from hitview
 * ===================================================================== */
void
fs_copilot_note_event (void)
{
    total_events++;
    if (stat_events) {
        gchar buf[32];
        g_snprintf (buf, sizeof buf, "%u", total_events);
        gtk_label_set_text (GTK_LABEL (stat_events), buf);
    }
}

/* =====================================================================
 * run_policy_analysis - Analyze learned profiles for issues
 * ===================================================================== */
static void
run_policy_analysis (void)
{
    text_view_append (analysis_output,
        "\n=== Policy Analysis ===\n", "title");

    GList *profiles = fs_copilot_get_all_profiles (global_copilot);
    guint num_apps = g_list_length (profiles);

    text_view_append (analysis_output,
        g_strdup_printf ("Learned %u application profiles\n", num_apps),
        NULL);

    GList *l;
    guint issues = 0;
    for (l = profiles; l != NULL; l = l->next) {
        FsAppProfile *p = l->data;
        if (p->total_connections < 10) continue;

        guint port_count = g_hash_table_size (p->common_ports);
        if (port_count > 20) {
            text_view_append (analysis_output,
                g_strdup_printf (
                    "  [!] %s: used %u different ports - possible port scanning\n",
                    p->app_name, port_count), "orange");
            issues++;
        }

        guint dest_count = g_hash_table_size (p->common_destinations);
        if (dest_count > 50) {
            text_view_append (analysis_output,
                g_strdup_printf (
                    "  [!] %s: connected to %u unique hosts - possible C2\n",
                    p->app_name, dest_count), "orange");
            issues++;
        }
    }

    if (issues == 0) {
        text_view_append (analysis_output,
            "  [OK] No issues detected in learned profiles\n", "green");
    }

    text_view_append (analysis_output,
        g_strdup_printf ("\nAnalysis complete. %u event(s) analyzed.\n",
                         total_events), "dim");
}

/* =====================================================================
 * on_analyze_clicked
 * ===================================================================== */
static void
on_analyze_clicked (GtkButton *btn, gpointer data)
{
    (void)btn; (void)data;
    run_policy_analysis ();
    refresh_insights ();
    update_stats ();
}

/* =====================================================================
 * on_simulate_clicked - What-if simulation
 *
 * The line is parsed and simulated in core (fs_copilot_simulate_text),
 * and the result lands in two places:
 *
 *   - the panel below the entry, as the scrollback: the parsed
 *     reading first, so a grammar misreading is visible instead of
 *     hiding behind the verdict.  Iterating on a line stays one
 *     glance at text.
 *   - the Simulation Visualizer window (fs-simviz), which plays the
 *     verdict: source, firewall, destination, the packet, and the
 *     wall's answer.  Same result, different presentation -- the
 *     component never re-judges anything.
 *
 * Nothing is written to the policy by simulating -- that stays a
 * question, not a change.  The visualizer's "Create This Rule"
 * button only returns a response; the rule is built and persisted
 * here, in create_rule_from_scenario(), after the user asked for it.
 * ===================================================================== */
static void
on_simulate_clicked (GtkButton *btn, gpointer data)
{
    const gchar *text;
    FsScenario *sc = NULL;
    FsSimulationResult *result;
    GtkWidget *parent;

    (void)btn; (void)data;

    text = gtk_entry_get_text (GTK_ENTRY (scenario_entry));
    if (!text || !*text) return;

    parent = gtk_widget_get_toplevel (scenario_entry);

    result = fs_copilot_simulate_text (global_copilot, text, &sc);
    if (result == NULL) {
        /* An honest refusal: no verdict at all beats a verdict for a
         * line nobody could read.  The visualizer shows the same
         * refusal in its neutral state -- examples instead of an
         * animation, because there is nothing to animate. */
        text_view_append (sim_output, "\n> ", "bold");
        text_view_append (sim_output, text, "blue");
        text_view_append (sim_output, "\n  ", NULL);
        text_view_append (sim_output,
            "Nothing could be read from that line: no direction, host, "
            "port or service was recognized. Nothing was evaluated.\n",
            "dim");
        fs_simviz_run (parent, NULL, NULL, text);
        gtk_entry_set_text (GTK_ENTRY (scenario_entry), "");
        return;
    }

    text_view_append (sim_output, "\n> ", "bold");
    text_view_append (sim_output, text, "blue");
    text_view_append (sim_output, "\n  ", NULL);
    text_view_append (sim_output, result->explanation,
                      result->would_block ? "red" : "green");
    text_view_append (sim_output, "\n", NULL);

    /* Say out loud what the line did not say, and point at where the
     * answer to the omission lives: the verdict names any port or
     * host that decided it.  ICMP has no ports at all, so the port
     * note would be a question the line never asked. */
    if (sc != NULL && !sc->had_port &&
        g_strcmp0 (sc->protocol, "ICMP") != 0)
        text_view_append (sim_output,
            "  Note: the line named no port; the verdict names any "
            "port that decided it.\n",
            "dim");
    if (sc != NULL && !sc->had_addr)
        text_view_append (sim_output,
            "  Note: the line named no host; the verdict names any "
            "host that decided it.\n",
            "dim");

    /* The window: same verdict, played.  Returns only when closed. */
    if (fs_simviz_run (parent, result, sc, text) == FS_SIMVIZ_CREATE_RULE)
        create_rule_from_scenario (sc);

    fs_simulation_result_free (result);
    fs_scenario_free (sc);
    gtk_entry_set_text (GTK_ENTRY (scenario_entry), "");
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
 * on_apply_suggestion_clicked
 *
 * Adds the selected suggestion to the shared policy, saves it, refreshes
 * the Policy page and pushes it to the live firewall.  Every outcome is
 * reported honestly: before this, the button printed "[OK] Applied" and
 * touched nothing at all.
 * ===================================================================== */
static void
on_apply_suggestion_clicked (GtkButton *btn, gpointer data)
{
    (void)btn; (void)data;

    GtkTreeSelection *sel = gtk_tree_view_get_selection (
        GTK_TREE_VIEW (insights_tree));
    GtkTreeModel *model;
    GtkTreeIter iter;

    if (!gtk_tree_selection_get_selected (sel, &model, &iter))
        return;

    gchar *rule_csv = NULL;
    gchar *title = NULL;
    gint rule_kind = FS_RULE_OUTBOUND_ALLOW_SERVICE;
    gtk_tree_model_get (model, &iter,
                        COL_RULE_CSV, &rule_csv,
                        COL_TITLE, &title,
                        COL_KIND, &rule_kind,
                        -1);

    if (!rule_csv || !*rule_csv) {
        text_view_append (analysis_output,
            "\n[!] Selected insight has no auto-applicable rule.\n",
            "orange");
        g_free (rule_csv);
        g_free (title);
        return;
    }

    if (copilot_policy == NULL) {
        text_view_append (analysis_output,
            "\n[!] No traffic policy is loaded, so nothing can be applied.\n",
            "orange");
        g_free (rule_csv);
        g_free (title);
        return;
    }

    /* Parse before promising anything: a malformed suggestion must not
     * be reported as applied.  The kind comes from the insight itself
     * -- a Sentinel block suggestion parses as a deny, not as the
     * service-allow every legacy suggestion used. */
    FsRule *rule = fs_rule_from_csv ((FsRuleKind) rule_kind, rule_csv);

    if (rule == NULL) {
        text_view_append (analysis_output,
            "\n[!] Could not parse the suggested rule, nothing was applied:\n  ",
            "orange");
        text_view_append (analysis_output, rule_csv, "bold");
        text_view_append (analysis_output, "\n", NULL);
        g_free (rule_csv);
        g_free (title);
        return;
    }

    if (fs_policy_contains (copilot_policy, rule)) {
        text_view_append (analysis_output,
            "\n[=] Already in your policy, not added again:\n  ", "dim");
        text_view_append (analysis_output, rule_csv, "bold");
        text_view_append (analysis_output, "\n", NULL);
        fs_rule_free (rule);
        g_free (rule_csv);
        g_free (title);
        return;
    }

    GtkWidget *dialog = gtk_message_dialog_new (
        GTK_WINDOW (gtk_widget_get_toplevel (copilot_vbox)),
        GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO,
        _("Apply this AI-suggested rule?\n\n"
          "Insight: %s\n"
          "Rule: %s\n\n"
          "This will add the rule to your policy, save it to disk and\n"
          "push it to the firewall."),
        title ? title : "?", rule_csv);

    gtk_window_set_title (GTK_WINDOW (dialog), _("Apply AI Suggestion"));

    gint response = gtk_dialog_run (GTK_DIALOG (dialog));
    gtk_widget_destroy (dialog);

    if (response != GTK_RESPONSE_YES) {
        fs_rule_free (rule);
        g_free (rule_csv);
        g_free (title);
        return;
    }

    fs_policy_add (copilot_policy, rule);
    fs_rule_free (rule);
    rule = NULL;

    /* Persist.  If the write fails, take the row back out so what the
     * Policy page shows and what is on disk stay the same thing. */
    if (!fs_policyview_save (copilot_policy)) {
        FsRule *rollback = fs_rule_from_csv ((FsRuleKind) rule_kind,
                                             rule_csv);

        if (rollback != NULL) {
            fs_policy_remove (copilot_policy, rollback);
            fs_rule_free (rollback);
        }

        text_view_append (analysis_output,
            "\n[!] Could not save the rule to disk, nothing was applied:\n  ",
            "red");
        text_view_append (analysis_output, rule_csv, "bold");
        text_view_append (analysis_output, "\n", NULL);
        g_free (rule_csv);
        g_free (title);
        return;
    }

    /* Show it on the Policy page straight away. */
    fs_policyview_reload (copilot_policy);
    update_stats ();

    /* And put it in front of the actual firewall. */
    {
        GError *error = NULL;
        FsApplyOutcome *outcome = fs_policy_apply_safe (
            fs_backend (), copilot_policy, "copilot suggestion",
            fs_policyview_hold_reason (), &error);

        if (outcome->applied) {
            text_view_append (analysis_output,
                "\n[OK] Rule added, saved and applied:\n  ", "green");
            text_view_append (analysis_output, rule_csv, "bold");
            text_view_append (analysis_output, "\n     ", NULL);
            text_view_append (analysis_output, apply_result_text (outcome->result),
                              outcome->result == FS_APPLY_OK ? "green" : "orange");
            text_view_append (analysis_output, "\n", NULL);
        } else if (outcome->held) {
            text_view_append (analysis_output,
                "\n[..] Rule added to your policy and saved, but held "
                "back on purpose -- not applied:\n  ", "orange");
            text_view_append (analysis_output, rule_csv, "bold");
            text_view_append (analysis_output, "\n     ", NULL);
            text_view_append (analysis_output, outcome->hold_reason, "orange");
            text_view_append (analysis_output,
                "\n     Turn the hold off (Audit-only on the Policy page, "
                "or the Lock on the Status page) and apply again.\n",
                "dim");
        } else {
            /* The row really is in the policy -- say so rather than
             * implying the whole thing failed. */
            text_view_append (analysis_output,
                "\n[!] Rule added to your policy and saved, but it is NOT "
                "live yet:\n  ", "orange");
            text_view_append (analysis_output, rule_csv, "bold");
            text_view_append (analysis_output, "\n     ", NULL);
            text_view_append (analysis_output, apply_result_text (outcome->result), "orange");
            if (error != NULL) {
                text_view_append (analysis_output, "\n     ", NULL);
                text_view_append (analysis_output, error->message, "dim");
            }
            /* The rollback truth sits right under the failure. */
            text_view_append (analysis_output, "\n     ", NULL);
            if (outcome->rollback_attempted && outcome->rollback_verified)
                text_view_append (analysis_output,
                    "The previous policy was restored to the firewall and "
                    "that restore was verified.", "dim");
            else if (outcome->rollback_attempted)
                text_view_append (analysis_output,
                    "The rollback ALSO failed -- the firewall may be in an "
                    "inconsistent state; check the Status page.", "dim");
            else
                text_view_append (analysis_output,
                    "No previously applied policy is recorded, so nothing "
                    "could be restored.", "dim");
            text_view_append (analysis_output,
                "\n     Re-run StockFW as administrator and apply the "
                "policy to activate it.\n", "dim");
        }
        fs_apply_outcome_free (outcome);
        g_clear_error (&error);
    }

    refresh_insights ();

    g_free (rule_csv);
    g_free (title);
}

/* =====================================================================
 * create_rule_from_scenario - the "Create This Rule" response
 *
 * The visualizer only returns a response; everything that changes
 * state happens here, after the user pressed the button, on the same
 * shared policy the Policy page edits: build the rule from the very
 * scenario the verdict answered, refuse duplicates, persist with the
 * usual rollback, refresh the Policy page, then push the policy to
 * the live firewall -- reporting each step honestly, because "the row
 * exists" and "the firewall enforces it" are two different claims.
 * ===================================================================== */
static void
create_rule_from_scenario (const FsScenario *sc)
{
    FsRule *rule;
    gchar *csv;

    if (sc == NULL)
        return;

    if (copilot_policy == NULL) {
        text_view_append (sim_output,
            "\n[!] No traffic policy is loaded, so no rule was created.\n",
            "orange");
        return;
    }

    rule = fs_copilot_allow_rule_for (sc);
    if (rule == NULL) {
        text_view_append (sim_output,
            "\n[!] The scenario could not be turned into a rule; "
            "nothing was created.\n", "orange");
        return;
    }

    csv = fs_rule_to_csv (rule);

    if (fs_policy_contains (copilot_policy, rule)) {
        text_view_append (sim_output,
            "\n[=] Already in your policy, not added again:\n  ", "dim");
        text_view_append (sim_output, csv, "bold");
        text_view_append (sim_output, "\n", NULL);
        fs_rule_free (rule);
        g_free (csv);
        return;
    }

    /* The same guardrail the suggestion path uses (Ch. 4.4): a dialog
     * that prints the literal rule, and nothing is written until a
     * human answers Yes to that exact CSV row. */
    {
        GtkWidget *confirm = gtk_message_dialog_new (
            GTK_WINDOW (gtk_widget_get_toplevel (sim_output)),
            GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO,
            _("Create this rule?\n\n"
              "Rule: %s\n\n"
              "This will add the rule to your policy, save it to disk and\n"
              "push it to the firewall."),
            csv);
        gint response;

        gtk_window_set_title (GTK_WINDOW (confirm),
                              _("Create This Rule"));
        response = gtk_dialog_run (GTK_DIALOG (confirm));
        gtk_widget_destroy (confirm);

        if (response != GTK_RESPONSE_YES) {
            text_view_append (sim_output,
                "\n[=] Rule creation cancelled; nothing was written.\n",
                "dim");
            fs_rule_free (rule);
            g_free (csv);
            return;
        }
    }

    /* Persist.  A failed write must leave no row behind, so the
     * store and the disk never disagree -- add_persist rolls back. */
    if (!fs_policy_add_persist (copilot_policy, rule)) {
        text_view_append (sim_output,
            "\n[!] Could not save the new rule to disk, "
            "nothing was added:\n  ", "red");
        text_view_append (sim_output, csv, "bold");
        text_view_append (sim_output, "\n", NULL);
        fs_rule_free (rule);
        g_free (csv);
        return;
    }

    /* Show it on the Policy page straight away. */
    fs_policyview_reload (copilot_policy);
    update_stats ();

    text_view_append (sim_output,
        "\n[OK] Rule created from the simulation and saved "
        "to your policy:\n  ", "green");
    text_view_append (sim_output, csv, "bold");
    text_view_append (sim_output, "\n", NULL);

    /* And put it in front of the actual firewall. */
    {
        GError *error = NULL;
        FsApplyOutcome *outcome = fs_policy_apply_safe (
            fs_backend (), copilot_policy, "what-if create",
            fs_policyview_hold_reason (), &error);

        if (outcome->applied) {
            text_view_append (sim_output, "     ", NULL);
            text_view_append (sim_output, apply_result_text (outcome->result),
                              outcome->result == FS_APPLY_OK ? "green" : "orange");
            text_view_append (sim_output, "\n", NULL);
        } else if (outcome->held) {
            text_view_append (sim_output, "     held back on purpose (",
                              "orange");
            text_view_append (sim_output, outcome->hold_reason, "orange");
            text_view_append (sim_output,
                              ") -- saved, not applied\n", "orange");
        } else {
            /* The row really is in the policy -- say so rather than
             * implying the whole thing failed. */
            text_view_append (sim_output,
                "     Saved, but it is NOT live yet: ", "orange");
            text_view_append (sim_output, apply_result_text (outcome->result),
                              "orange");
            if (error != NULL) {
                text_view_append (sim_output, " - ", NULL);
                text_view_append (sim_output, error->message, "dim");
            }
            text_view_append (sim_output, "\n     ", NULL);
            if (outcome->rollback_attempted && outcome->rollback_verified)
                text_view_append (sim_output,
                    "The previous policy was restored to the firewall and "
                    "that restore was verified.", "dim");
            else if (outcome->rollback_attempted)
                text_view_append (sim_output,
                    "The rollback ALSO failed -- the firewall may be in an "
                    "inconsistent state; check the Status page.", "dim");
            else
                text_view_append (sim_output,
                    "No previously applied policy is recorded, so nothing "
                    "could be restored.", "dim");
            text_view_append (sim_output,
                "\n     Re-run StockFW as administrator and apply the "
                "policy to activate it.\n", "dim");
        }
        fs_apply_outcome_free (outcome);
        g_clear_error (&error);
    }

    fs_rule_free (rule);
    g_free (csv);
}

/* =====================================================================
 * on_clear_clicked
 * ===================================================================== */
static void
on_clear_clicked (GtkButton *btn, gpointer data)
{
    (void)btn; (void)data;
    if (global_copilot)
        fs_copilot_clear_insights (global_copilot);
    refresh_insights ();
    update_stats ();
    text_view_append (analysis_output, "\nInsights cleared.\n", "dim");
}

/* =====================================================================
 * on_row_activated - Double-click for details
 * ===================================================================== */
static void
on_row_activated (GtkTreeView *tree, GtkTreePath *path,
                  GtkTreeViewColumn *col, gpointer data)
{
    (void)path; (void)col; (void)data;

    GtkTreeModel *model = gtk_tree_view_get_model (tree);
    GtkTreeIter iter;
    if (!gtk_tree_model_get_iter (model, &iter, path)) return;

    gchar *title = NULL, *desc = NULL, *sugg = NULL, *app = NULL;
    gtk_tree_model_get (model, &iter,
        COL_TITLE, &title, COL_DESC, &desc,
        COL_SUGGESTION, &sugg, COL_APP, &app, -1);

    GtkWidget *dialog = gtk_message_dialog_new (
        GTK_WINDOW (gtk_widget_get_toplevel (copilot_vbox)),
        GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
        "%s\n\n%s\n\nApp: %s\nSuggestion: %s",
        title ? title : "", desc ? desc : "",
        app ? app : "-", sugg ? sugg : "-");
    gtk_window_set_title (GTK_WINDOW (dialog), _("Insight Details"));
    gtk_dialog_run (GTK_DIALOG (dialog));
    gtk_widget_destroy (dialog);

    g_free (title); g_free (desc); g_free (sugg); g_free (app);
}

/* =====================================================================
 * severity_to_icon - Map severity to stock GTK icon
 * ===================================================================== */
static const gchar *
severity_to_icon (FsCopilotSeverity sev)
{
    switch (sev) {
    case FS_COPILOT_CRITICAL: return "dialog-error";
    case FS_COPILOT_WARNING:  return "dialog-warning";
    case FS_COPILOT_INFO:     return "dialog-information";
    default:                  return "dialog-question";
    }
}

/* =====================================================================
 * insight_type_to_string
 * ===================================================================== */
static const gchar *
insight_type_to_string (FsInsightType type)
{
    switch (type) {
    case FS_INSIGHT_NEW_APPLICATION:      return _("New App");
    case FS_INSIGHT_UNUSUAL_PORT:         return _("Unusual Port");
    case FS_INSIGHT_UNUSUAL_DESTINATION:  return _("Unusual Dest");
    case FS_INSIGHT_UNUSUAL_VOLUME:       return _("Unusual Volume");
    case FS_INSIGHT_UNUSUAL_TIME:         return _("Unusual Time");
    case FS_INSIGHT_RULE_CONFLICT:        return _("Rule Conflict");
    case FS_INSIGHT_REDUNDANT_RULE:       return _("Redundant Rule");
    case FS_INSIGHT_MISSING_RULE:         return _("Missing Rule");
    case FS_INSIGHT_SUSPICIOUS_BEHAVIOR:  return _("Suspicious");
    case FS_INSIGHT_RULE_OPTIMIZATION:    return _("Optimization");
    case FS_INSIGHT_BEACON:               return _("Beacon");
    case FS_INSIGHT_FANOUT:               return _("Fan-Out");
    default:                              return _("Unknown");
    }
}

/* =====================================================================
 * severity_to_string
 * ===================================================================== */
static const gchar *
severity_to_string (FsCopilotSeverity sev)
{
    switch (sev) {
    case FS_COPILOT_INFO:     return _("Info");
    case FS_COPILOT_WARNING:  return _("Warning");
    case FS_COPILOT_CRITICAL: return _("Critical");
    default:                  return _("Unknown");
    }
}
