/*---[ fs-copilot.c ]---------------------------------------------------
 * AI-Powered Smart Firewall Copilot - UI.
 *
 * Features:
 *   - Dashboard stats (learned apps, insights, events, rules)
 *   - Conversational AI assistant (natural language Q&A)
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
#include "ui/fs-app.h"
#include "ui/fs-policyview.h"
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
    COL_N_COLS
};

/* =====================================================================
 * Widget state
 * ===================================================================== */
static GtkListStore  *insights_store   = NULL;
static GtkWidget     *insights_tree    = NULL;
static GtkWidget     *scenario_entry   = NULL;
static GtkWidget     *ask_entry        = NULL;
static GtkWidget     *ask_output       = NULL;
static GtkWidget     *stat_apps        = NULL;
static GtkWidget     *stat_insights    = NULL;
static GtkWidget     *stat_events      = NULL;
static GtkWidget     *stat_rules       = NULL;
static GtkWidget     *analysis_output  = NULL;
static GtkWidget     *copilot_vbox     = NULL;

static FsCopilot     *global_copilot   = NULL;
static FsPolicy      *copilot_policy   = NULL;
static guint          total_events     = 0;

/* =====================================================================
 * Forward declarations
 * ===================================================================== */
static void refresh_insights (void);
static void update_stats (void);
static void run_policy_analysis (void);
static void on_simulate_clicked (GtkButton *btn, gpointer data);
static void on_apply_suggestion_clicked (GtkButton *btn, gpointer data);
static void on_ask_clicked (GtkButton *btn, gpointer data);
static void on_analyze_clicked (GtkButton *btn, gpointer data);
static void on_clear_clicked (GtkButton *btn, gpointer data);
static void on_row_activated (GtkTreeView *tree, GtkTreePath *path,
                              GtkTreeViewColumn *col, gpointer data);
static const gchar *severity_to_icon (FsCopilotSeverity sev);
static const gchar *insight_type_to_string (FsInsightType type);
static const gchar *severity_to_string (FsCopilotSeverity sev);

/* =====================================================================
 * Helper: button with a stock GTK icon + label
 * ===================================================================== */
static GtkWidget *
button_with_icon (const gchar *icon_name, const gchar *label)
{
    GtkWidget *btn = gtk_button_new ();
    GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *img = gtk_image_new_from_icon_name (icon_name, GTK_ICON_SIZE_BUTTON);
    GtkWidget *lbl = gtk_label_new (label);

    gtk_box_pack_start (GTK_BOX (box), img, FALSE, FALSE, 0);
    gtk_box_pack_start (GTK_BOX (box), lbl, FALSE, FALSE, 0);
    gtk_container_add (GTK_CONTAINER (btn), box);
    return btn;
}

/* =====================================================================
 * Helper: create a stat card (big value + label)
 * ===================================================================== */
static GtkWidget *
make_stat_card (const gchar *label, const gchar *icon_name, GtkWidget **value_out)
{
    GtkWidget *frame = gtk_frame_new (NULL);
    gtk_widget_set_size_request (frame, 120, 72);
    gtk_frame_set_shadow_type (GTK_FRAME (frame), GTK_SHADOW_ETCHED_IN);

    GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 2);
    gtk_container_set_border_width (GTK_CONTAINER (box), 8);
    gtk_container_add (GTK_CONTAINER (frame), box);

    /* Value + icon row */
    GtkWidget *row = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 4);

    GtkWidget *icon = gtk_image_new_from_icon_name (icon_name, GTK_ICON_SIZE_LARGE_TOOLBAR);
    gtk_box_pack_start (GTK_BOX (row), icon, FALSE, FALSE, 0);

    GtkWidget *val = gtk_label_new ("0");
    GtkStyleContext *ctx = gtk_widget_get_style_context (val);
    gtk_style_context_add_class (ctx, "title");
    gtk_box_pack_start (GTK_BOX (row), val, FALSE, FALSE, 0);

    gtk_box_pack_start (GTK_BOX (box), row, FALSE, FALSE, 0);

    GtkWidget *lbl = gtk_label_new (label);
    gtk_style_context_add_class (gtk_widget_get_style_context (lbl), "dim-label");
    gtk_label_set_xalign (GTK_LABEL (lbl), 0.5);
    gtk_box_pack_start (GTK_BOX (box), lbl, FALSE, FALSE, 0);

    *value_out = val;
    return frame;
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
    gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scrolled),
                                         GTK_SHADOW_IN);

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
    /* One G_TYPE_STRING per column above, in enum order, ending with
     * COL_RULE_CSV.  Passing fewer than COL_N_COLS leaves GObject
     * reading an uninitialised GType out of the varargs, which is a
     * crash waiting to happen. */
    insights_store = gtk_list_store_new (COL_N_COLS,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING);

    GtkWidget *tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (insights_store));
    g_object_unref (GTK_TREE_MODEL (insights_store));
    gtk_tree_view_set_headers_visible (GTK_TREE_VIEW (tree), TRUE);
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

    copilot_vbox = gtk_box_new (GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width (GTK_CONTAINER (copilot_vbox), 8);

    /* ===== Header ===== */
    {
        GtkWidget *hdr = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);

        /* security-high is the shield, which is what a firewall tool's
         * header should carry.  The original pick,
         * "utilities-system-monitor", is not shipped by any theme we
         * bundle, so it would have rendered as a blank space. */
        GtkWidget *icon = gtk_image_new_from_icon_name (
            "security-high", GTK_ICON_SIZE_DIALOG);
        gtk_box_pack_start (GTK_BOX (hdr), icon, FALSE, FALSE, 0);

        GtkWidget *titles = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);

        GtkWidget *t1 = gtk_label_new (_("Smart Firewall Copilot"));
        gtk_style_context_add_class (gtk_widget_get_style_context (t1), "title");
        gtk_label_set_xalign (GTK_LABEL (t1), 0.0);
        gtk_box_pack_start (GTK_BOX (titles), t1, FALSE, FALSE, 0);

        GtkWidget *t2 = gtk_label_new (
            _("AI-powered anomaly detection, rule analysis & natural-language assistant"));
        gtk_style_context_add_class (gtk_widget_get_style_context (t2), "dim-label");
        gtk_label_set_xalign (GTK_LABEL (t2), 0.0);
        gtk_box_pack_start (GTK_BOX (titles), t2, FALSE, FALSE, 0);

        gtk_box_pack_start (GTK_BOX (hdr), titles, TRUE, TRUE, 0);

        GtkWidget *analyze_btn = button_with_icon ("system-search", _("Run Analysis"));
        gtk_style_context_add_class (gtk_widget_get_style_context (analyze_btn),
                                     "suggested-action");
        g_signal_connect (analyze_btn, "clicked",
                          G_CALLBACK (on_analyze_clicked), NULL);
        gtk_box_pack_end (GTK_BOX (hdr), analyze_btn, FALSE, FALSE, 0);

        gtk_box_pack_start (GTK_BOX (copilot_vbox), hdr, FALSE, FALSE, 0);
    }

    /* ===== Stats dashboard ===== */
    {
        GtkWidget *stats = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_widget_set_margin_top (stats, 4);
        gtk_widget_set_margin_bottom (stats, 4);

        GtkWidget *c1, *c2, *c3, *c4;
        c1 = make_stat_card (_("Apps Learned"),     "system-users",       &stat_apps);
        c2 = make_stat_card (_("Active Insights"),  "dialog-warning",     &stat_insights);
        c3 = make_stat_card (_("Events Analyzed"),  "view-list",          &stat_events);
        c4 = make_stat_card (_("Policy Rules"),     "preferences-system", &stat_rules);

        gtk_box_pack_start (GTK_BOX (stats), c1, TRUE, TRUE, 0);
        gtk_box_pack_start (GTK_BOX (stats), c2, TRUE, TRUE, 0);
        gtk_box_pack_start (GTK_BOX (stats), c3, TRUE, TRUE, 0);
        gtk_box_pack_start (GTK_BOX (stats), c4, TRUE, TRUE, 0);

        gtk_box_pack_start (GTK_BOX (copilot_vbox), stats, FALSE, FALSE, 0);
    }

    /* ===== Insights tree ===== */
    {
        GtkWidget *lbl = gtk_label_new (_("Insights & Suggestions"));
        gtk_style_context_add_class (gtk_widget_get_style_context (lbl), "heading");
        gtk_label_set_xalign (GTK_LABEL (lbl), 0.0);
        gtk_box_pack_start (GTK_BOX (copilot_vbox), lbl, FALSE, FALSE, 0);

        insights_tree = build_insights_tree ();
        GtkWidget *scrolled = gtk_scrolled_window_new (NULL, NULL);
        gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled),
                                        GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
        gtk_scrolled_window_set_min_content_height (
            GTK_SCROLLED_WINDOW (scrolled), 140);
        gtk_container_add (GTK_CONTAINER (scrolled), insights_tree);
        gtk_box_pack_start (GTK_BOX (copilot_vbox), scrolled, TRUE, TRUE, 0);

        /* Buttons row */
        GtkWidget *btn_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);

        GtkWidget *apply_btn = button_with_icon ("list-add", _("Apply Selected Rule"));
        gtk_style_context_add_class (gtk_widget_get_style_context (apply_btn),
                                     "suggested-action");
        g_signal_connect (apply_btn, "clicked",
                          G_CALLBACK (on_apply_suggestion_clicked), NULL);
        gtk_box_pack_start (GTK_BOX (btn_box), apply_btn, FALSE, FALSE, 0);

        GtkWidget *clear_btn = button_with_icon ("edit-clear", _("Clear Insights"));
        g_signal_connect (clear_btn, "clicked", G_CALLBACK (on_clear_clicked), NULL);
        gtk_box_pack_start (GTK_BOX (btn_box), clear_btn, FALSE, FALSE, 0);

        gtk_box_pack_start (GTK_BOX (copilot_vbox), btn_box, FALSE, FALSE, 0);
    }

    /* ===== What-if simulator ===== */
    {
        GtkWidget *frame = gtk_frame_new (_("What-If Simulator"));
        GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
        gtk_container_set_border_width (GTK_CONTAINER (box), 6);

        scenario_entry = gtk_entry_new ();
        gtk_entry_set_placeholder_text (GTK_ENTRY (scenario_entry),
            _("e.g. allow SSH from 192.168.1.50 on port 22"));
        gtk_widget_set_hexpand (scenario_entry, TRUE);
        gtk_box_pack_start (GTK_BOX (box), scenario_entry, TRUE, TRUE, 0);

        GtkWidget *sim_btn = button_with_icon ("media-playback-start", _("Simulate"));
        g_signal_connect (sim_btn, "clicked",
                          G_CALLBACK (on_simulate_clicked), NULL);
        gtk_box_pack_start (GTK_BOX (box), sim_btn, FALSE, FALSE, 0);

        g_signal_connect (scenario_entry, "activate",
                          G_CALLBACK (on_simulate_clicked), NULL);

        gtk_container_add (GTK_CONTAINER (frame), box);
        gtk_box_pack_start (GTK_BOX (copilot_vbox), frame, FALSE, FALSE, 0);
    }

    /* ===== AI Assistant ===== */
    {
        GtkWidget *frame = gtk_frame_new (_("AI Assistant"));
        GtkWidget *box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 4);
        gtk_container_set_border_width (GTK_CONTAINER (box), 6);

        /* Ask input row */
        GtkWidget *ask_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);

        ask_entry = gtk_entry_new ();
        gtk_entry_set_placeholder_text (GTK_ENTRY (ask_entry),
            _("Ask: What rules do I have? Show anomalies. Is port 8080 open?"));
        gtk_widget_set_hexpand (ask_entry, TRUE);
        gtk_box_pack_start (GTK_BOX (ask_box), ask_entry, TRUE, TRUE, 0);

        GtkWidget *ask_btn = button_with_icon ("go-next", _("Ask"));
        g_signal_connect (ask_btn, "clicked", G_CALLBACK (on_ask_clicked), NULL);
        gtk_box_pack_start (GTK_BOX (ask_box), ask_btn, FALSE, FALSE, 0);
        g_signal_connect (ask_entry, "activate",
                          G_CALLBACK (on_ask_clicked), NULL);

        gtk_box_pack_start (GTK_BOX (box), ask_box, FALSE, FALSE, 0);

        /* Output */
        ask_output = make_output_view ();
        gtk_widget_set_size_request (ask_output, -1, 90);
        gtk_box_pack_start (GTK_BOX (box), ask_output, TRUE, TRUE, 0);

        gtk_container_add (GTK_CONTAINER (frame), box);
        gtk_box_pack_start (GTK_BOX (copilot_vbox), frame, FALSE, FALSE, 0);
    }

    /* ===== Policy Analysis ===== */
    {
        GtkWidget *a_lbl = gtk_label_new (_("Policy Analysis"));
        gtk_label_set_xalign (GTK_LABEL (a_lbl), 0.0);
        gtk_box_pack_start (GTK_BOX (copilot_vbox), a_lbl, FALSE, FALSE, 0);

        analysis_output = make_output_view ();
        gtk_widget_set_size_request (analysis_output, -1, 80);
        gtk_box_pack_start (GTK_BOX (copilot_vbox), analysis_output, FALSE, FALSE, 0);
    }

    /* Initial data */
    refresh_insights ();
    update_stats ();

    /* Welcome message */
    text_view_append (ask_output,
        "StockFW Copilot ready. Ask me about your firewall rules,\n"
        "anomalies, or type a natural-language question.\n", "dim");

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
 * on_ask_clicked - AI assistant Q&A
 * ===================================================================== */
static void
on_ask_clicked (GtkButton *btn, gpointer data)
{
    (void)btn; (void)data;

    const gchar *q = gtk_entry_get_text (GTK_ENTRY (ask_entry));
    if (!q || !*q) return;

    text_view_append (ask_output, "\n> ", "bold");
    text_view_append (ask_output, q, "blue");

    gchar *qlower = g_ascii_strdown (q, -1);

    /* Rule questions */
    if (strstr (qlower, "rule") &&
        (strstr (qlower, "how many") || strstr (qlower, "count") ||
         strstr (qlower, "what"))) {
        text_view_append (ask_output, "\nYour policy rules:\n", "bold");
        text_view_append (ask_output,
            "  Check the Policy tab for the full list.\n"
            "  Rules are organized by: Inbound Allow, Outbound Allow,\n"
            "  Deny, and Forward.\n", NULL);
    }
    /* Anomaly questions */
    else if (strstr (qlower, "anomal") || strstr (qlower, "insight") ||
             strstr (qlower, "suspicious") || strstr (qlower, "unusual")) {
        GList *ins = fs_copilot_get_insights (global_copilot);
        guint n = g_list_length (ins);
        g_list_free (ins);

        if (n == 0) {
            text_view_append (ask_output,
                "\n[OK] No active anomalies. The copilot is monitoring traffic.\n"
                "Anomalies appear when apps use unusual ports, destinations,\n"
                "or hours.\n", "green");
        } else {
            text_view_append (ask_output,
                g_strdup_printf ("\nFound %u active insight(s):\n", n),
                "orange");
            GList *list = fs_copilot_get_insights (global_copilot);
            for (GList *l = list; l; l = l->next) {
                FsInsight *ins2 = l->data;
                text_view_append (ask_output,
                    g_strdup_printf ("  [%s] %s\n",
                                     severity_to_string (ins2->severity),
                                     ins2->title), NULL);
            }
            g_list_free (list);
        }
    }
    /* Port questions */
    else if (strstr (qlower, "port")) {
        const gchar *p = qlower;
        while (*p && !g_ascii_isdigit (*p)) p++;
        if (*p) {
            guint port = (guint) atoi (p);
            text_view_append (ask_output,
                g_strdup_printf ("\nPort %u analysis:\n", port), "bold");

            if (port == 22 || port == 80 || port == 443)
                text_view_append (ask_output,
                    "  Common service port - usually safe to allow.\n",
                    "green");
            else if (port >= 1 && port <= 1023)
                text_view_append (ask_output,
                    "  Well-known port range. Verify the service needs it.\n",
                    "orange");
            else if (port >= 49152)
                text_view_append (ask_output,
                    "  Dynamic/private port - often used by ephemeral\n"
                    "  connections.\n", NULL);
            else
                text_view_append (ask_output,
                    "  Registered port. Check if any app legitimately\n"
                    "  uses it.\n", NULL);

            text_view_append (ask_output,
                "  Use the What-If Simulator to test if it would be\n"
                "  allowed.\n", "dim");
        } else {
            text_view_append (ask_output,
                "\nPlease specify a port number,\n"
                "e.g. \"is port 8080 open?\"\n", "dim");
        }
    }
    /* Help */
    else if (strstr (qlower, "help") || strstr (qlower, "what can") ||
             strstr (qlower, "capabilit")) {
        text_view_append (ask_output,
            "\nI can help with:\n"
            "  - Analyze your firewall rules for conflicts & gaps\n"
            "  - Detect anomalies in network traffic\n"
            "  - Simulate what-if scenarios before applying rules\n"
            "  - Suggest new rules in natural language\n"
            "  - Show learned application behavior profiles\n"
            "  - Answer questions like \"is port 443 open?\"\n", NULL);
    }
    /* Status */
    else if (strstr (qlower, "status") || strstr (qlower, "summary") ||
             strstr (qlower, "overview")) {
        GList *ins = fs_copilot_get_insights (global_copilot);
        guint ni = g_list_length (ins);
        g_list_free (ins);
        GList *pr = fs_copilot_get_all_profiles (global_copilot);
        guint na = g_list_length (pr);
        g_list_free (pr);

        text_view_append (ask_output, "\nCopilot Status:\n", "title");
        text_view_append (ask_output,
            g_strdup_printf ("  Apps learned:      %u\n", na), NULL);
        text_view_append (ask_output,
            g_strdup_printf ("  Active insights:   %u\n", ni), NULL);
        text_view_append (ask_output,
            g_strdup_printf ("  Events analyzed:   %u\n", total_events), NULL);
        text_view_append (ask_output,
            g_strdup_printf ("  Learning:          %s\n",
                             global_copilot ? "ON" : "OFF"), NULL);
    }
    /* Default */
    else {
        text_view_append (ask_output,
            "\nTry asking:\n"
            "  \"What anomalies do you see?\"\n"
            "  \"Is port 443 open?\"\n"
            "  \"Show me a status summary\"\n"
            "  \"What can you do?\"\n", "dim");
    }

    g_free (qlower);
    gtk_entry_set_text (GTK_ENTRY (ask_entry), "");
}

/* =====================================================================
 * on_simulate_clicked - What-if simulation
 * ===================================================================== */
static void
on_simulate_clicked (GtkButton *btn, gpointer data)
{
    (void)btn; (void)data;

    const gchar *text = gtk_entry_get_text (GTK_ENTRY (scenario_entry));
    if (!text || !*text) return;

    gboolean inbound = TRUE;
    guint port = 0;
    gchar remote_ip[64] = "any";
    gchar app_name[64] = "Unknown";

    if (strstr (text, "outbound") || strstr (text, "outgoing"))
        inbound = FALSE;

    gchar *ps = strstr (text, "port ");
    if (ps) port = (guint) atoi (ps + 5);

    const gchar *dot = strchr (text, '.');
    if (dot) {
        const gchar *s = dot;
        while (s > text && (g_ascii_isdigit (*s) || *s == '.')) s--;
        s++;
        g_strlcpy (remote_ip, s, sizeof remote_ip);
        for (gchar *c = remote_ip; *c; c++) {
            if (!g_ascii_isdigit (*c) && *c != '.') { *c = '\0'; break; }
        }
    }

    const gchar *a = strstr (text, "allow ");
    if (!a) a = strstr (text, "allowing ");
    if (a) {
        a = strchr (a, ' ');
        while (*a == ' ') a++;
        g_strlcpy (app_name, a, sizeof app_name);
        for (gchar *c = app_name; *c; c++) {
            if (*c == ' ' || *c == ',') { *c = '\0'; break; }
        }
    }

    FsSimulationResult *result = fs_copilot_simulate (
        global_copilot, app_name, remote_ip, port, "TCP", inbound);

    /* Result dialog */
    GtkWidget *dialog = gtk_message_dialog_new (
        GTK_WINDOW (gtk_widget_get_toplevel (copilot_vbox)),
        GTK_DIALOG_MODAL,
        result->would_block ? GTK_MESSAGE_WARNING : GTK_MESSAGE_INFO,
        GTK_BUTTONS_OK,
        "%s", result->explanation);
    gtk_window_set_title (GTK_WINDOW (dialog), _("What-If Simulation"));
    gtk_dialog_run (GTK_DIALOG (dialog));
    gtk_widget_destroy (dialog);

    /* Log to AI output */
    text_view_append (ask_output, "\nSimulation: ", "title");
    text_view_append (ask_output, text, "bold");
    text_view_append (ask_output, result->would_block ?
                      " -> BLOCKED\n" : " -> ALLOWED\n",
                      result->would_block ? "red" : "green");
    text_view_append (ask_output, result->explanation, NULL);
    text_view_append (ask_output, "\n", NULL);

    fs_simulation_result_free (result);
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
    gtk_tree_model_get (model, &iter,
                        COL_RULE_CSV, &rule_csv,
                        COL_TITLE, &title,
                        -1);

    if (!rule_csv || !*rule_csv) {
        text_view_append (ask_output,
            "\n[!] Selected insight has no auto-applicable rule.\n",
            "orange");
        g_free (rule_csv);
        g_free (title);
        return;
    }

    if (copilot_policy == NULL) {
        text_view_append (ask_output,
            "\n[!] No traffic policy is loaded, so nothing can be applied.\n",
            "orange");
        g_free (rule_csv);
        g_free (title);
        return;
    }

    /* Parse before promising anything: a malformed suggestion must not
     * be reported as applied. */
    FsRule *rule = fs_rule_from_csv (FS_RULE_OUTBOUND_ALLOW_SERVICE, rule_csv);

    if (rule == NULL) {
        text_view_append (ask_output,
            "\n[!] Could not parse the suggested rule, nothing was applied:\n  ",
            "orange");
        text_view_append (ask_output, rule_csv, "bold");
        text_view_append (ask_output, "\n", NULL);
        g_free (rule_csv);
        g_free (title);
        return;
    }

    if (fs_policy_contains (copilot_policy, rule)) {
        text_view_append (ask_output,
            "\n[=] Already in your policy, not added again:\n  ", "dim");
        text_view_append (ask_output, rule_csv, "bold");
        text_view_append (ask_output, "\n", NULL);
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
        FsRule *rollback = fs_rule_from_csv (FS_RULE_OUTBOUND_ALLOW_SERVICE,
                                             rule_csv);

        if (rollback != NULL) {
            fs_policy_remove (copilot_policy, rollback);
            fs_rule_free (rollback);
        }

        text_view_append (ask_output,
            "\n[!] Could not save the rule to disk, nothing was applied:\n  ",
            "red");
        text_view_append (ask_output, rule_csv, "bold");
        text_view_append (ask_output, "\n", NULL);
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
        FsApplyResult result = fs_backend ()->apply_rules (copilot_policy,
                                                           &error);

        if (result == FS_APPLY_OK || result == FS_APPLY_PARTIAL) {
            text_view_append (ask_output,
                "\n[OK] Rule added, saved and applied:\n  ", "green");
            text_view_append (ask_output, rule_csv, "bold");
            text_view_append (ask_output, "\n     ", NULL);
            text_view_append (ask_output, apply_result_text (result),
                              result == FS_APPLY_OK ? "green" : "orange");
            text_view_append (ask_output, "\n", NULL);
        } else {
            /* The row really is in the policy -- say so rather than
             * implying the whole thing failed. */
            text_view_append (ask_output,
                "\n[!] Rule added to your policy and saved, but it is NOT "
                "live yet:\n  ", "orange");
            text_view_append (ask_output, rule_csv, "bold");
            text_view_append (ask_output, "\n     ", NULL);
            text_view_append (ask_output, apply_result_text (result), "orange");
            if (error != NULL) {
                text_view_append (ask_output, "\n     ", NULL);
                text_view_append (ask_output, error->message, "dim");
            }
            text_view_append (ask_output,
                "\n     Re-run StockFW as administrator and apply the "
                "policy to activate it.\n", "dim");
        }
        g_clear_error (&error);
    }

    refresh_insights ();

    g_free (rule_csv);
    g_free (title);
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
    text_view_append (ask_output, "\nInsights cleared.\n", "dim");
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
