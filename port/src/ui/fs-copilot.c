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

/* =====================================================================
 * Forward declarations
 * ===================================================================== */
static void refresh_insights (void);
static void update_stats (void);
static void run_policy_analysis (void);
static void on_simulate_clicked (GtkButton *btn, gpointer data);
static GtkWidget *whatif_card_new (void);
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

    /* ===== What-If simulator ===== */
    gtk_box_pack_start (GTK_BOX (copilot_vbox), whatif_card_new (),
                        FALSE, FALSE, 0);

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
