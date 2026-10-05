/*---[ fs-copilot.c ]---------------------------------------------------
 * UI for the Smart Firewall Copilot.
 * A tab in the main notebook showing copilot insights, anomalies,
 * and rule suggestions with a conversational interface.
 *--------------------------------------------------------------------*/

#include "fs-copilot.h"
#include "core/fs-copilot.h"
#include "ui/fs-app.h"
#include "core/fs-i18n.h"
#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>

enum
{
    COL_TITLE,
    COL_TYPE,
    COL_SEVERITY,
    COL_DESC,
    COL_APP,
    COL_DEST,
    COL_SUGGESTION,
    COL_N_COLS
};

static GtkListStore *insights_store = NULL;

static GtkWidget *copilot_window = NULL;
static GtkWidget *insights_tree = NULL;
static GtkWidget *scenario_entry = NULL;
static GtkWidget *simulate_btn = NULL;
static GtkWidget *apply_sugg_btn = NULL;

static FsCopilot *global_copilot = NULL;

/* Forward declarations */
static void on_simulate_clicked (GtkButton *btn, gpointer data);
static void on_apply_suggestion_clicked (GtkButton *btn, gpointer data);
static void on_row_activated (GtkTreeView *tree, GtkTreePath *path,
                              GtkTreeViewColumn *col, gpointer data);
static void refresh_insights (void);
static const gchar *insight_type_to_string (FsInsightType type);
static const gchar *severity_to_string (FsCopilotSeverity sev);

/**********************************************************************
 * fs_copilot_page - Create the copilot tab content.
 **********************************************************************/
GtkWidget *
fs_copilot_page (FsCopilot *copilot)
{
    GtkWidget *frame;
    GtkWidget *box;
    GtkWidget *scrolled;
    GtkWidget *tree_view;
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *col;

    global_copilot = copilot;

    frame = gtk_frame_new (_("Smart Firewall Copilot"));
    box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_top (box, 6);
    gtk_widget_set_margin_bottom (box, 6);
    gtk_widget_set_margin_start (box, 6);
    gtk_widget_set_margin_end (box, 6);

    /* Insights list. */
    scrolled = gtk_scrolled_window_new (NULL, NULL);
    gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled),
                                    GTK_POLICY_AUTOMATIC,
                                    GTK_POLICY_ALWAYS);
    gtk_scrolled_window_set_min_content_height (GTK_SCROLLED_WINDOW (scrolled), 300);

    insights_store = gtk_list_store_new (COL_N_COLS,
                                         G_TYPE_STRING,    /* title */
                                         G_TYPE_STRING,    /* type */
                                         G_TYPE_STRING,    /* severity */
                                         G_TYPE_STRING,    /* description */
                                         G_TYPE_STRING,    /* application */
                                         G_TYPE_STRING,    /* destination */
                                         G_TYPE_STRING     /* suggested_rule */
                                         );

    insights_tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (insights_store));
    g_object_unref (GTK_TREE_MODEL (insights_store));

    g_signal_connect (insights_tree, "row-activated",
                      G_CALLBACK (on_row_activated), NULL);

    /* Column: Title */
    renderer = gtk_cell_renderer_text_new ();
    col = gtk_tree_view_column_new_with_attributes (_("Title"), renderer,
                                        "text", COL_TITLE, NULL);
    gtk_tree_view_column_set_min_width (col, 150);
    gtk_tree_view_append_column (GTK_TREE_VIEW (insights_tree), col);

    /* Column: Type */
    renderer = gtk_cell_renderer_text_new ();
    col = gtk_tree_view_column_new_with_attributes (_("Type"), renderer,
                                        "text", COL_TYPE, NULL);
    gtk_tree_view_column_set_min_width (col, 120);
    gtk_tree_view_append_column (GTK_TREE_VIEW (insights_tree), col);

    /* Column: Severity */
    renderer = gtk_cell_renderer_text_new ();
    col = gtk_tree_view_column_new_with_attributes (_("Severity"), renderer,
                                        "text", COL_SEVERITY, NULL);
    gtk_tree_view_column_set_min_width (col, 80);
    gtk_tree_view_append_column (GTK_TREE_VIEW (insights_tree), col);

    /* Column: Description */
    renderer = gtk_cell_renderer_text_new ();
    col = gtk_tree_view_column_new_with_attributes (_("Description"), renderer,
                                        "text", COL_DESC, NULL);
    gtk_tree_view_column_set_min_width (col, 250);
    gtk_tree_view_column_set_expand (col, TRUE);
    gtk_tree_view_append_column (GTK_TREE_VIEW (insights_tree), col);

    /* Column: Application */
    renderer = gtk_cell_renderer_text_new ();
    col = gtk_tree_view_column_new_with_attributes (_("App"), renderer,
                                        "text", COL_APP, NULL);
    gtk_tree_view_column_set_min_width (col, 100);
    gtk_tree_view_append_column (GTK_TREE_VIEW (insights_tree), col);

    /* Column: Destination */
    renderer = gtk_cell_renderer_text_new ();
    col = gtk_tree_view_column_new_with_attributes (_("Dest"), renderer,
                                        "text", COL_DEST, NULL);
    gtk_tree_view_column_set_min_width (col, 120);
    gtk_tree_view_append_column (GTK_TREE_VIEW (insights_tree), col);

    /* Column: Suggestion */
    renderer = gtk_cell_renderer_text_new ();
    col = gtk_tree_view_column_new_with_attributes (_("Sugg."), renderer,
                                        "text", COL_SUGGESTION, NULL);
    gtk_tree_view_column_set_min_width (col, 150);
    gtk_tree_view_append_column (GTK_TREE_VIEW (insights_tree), col);

    gtk_container_add (GTK_CONTAINER (scrolled), insights_tree);
    gtk_box_pack_start (GTK_BOX (box), scrolled, TRUE, TRUE, 0);

    /* Action buttons box */
    GtkWidget *btn_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_margin_top (btn_box, 6);

    simulate_btn = gtk_button_new_with_label (_("Simulate What-If"));
    g_signal_connect (simulate_btn, "clicked",
                      G_CALLBACK (on_simulate_clicked), NULL);
    gtk_box_pack_start (GTK_BOX (btn_box), simulate_btn, FALSE, FALSE, 0);

    apply_sugg_btn = gtk_button_new_with_label (_("Apply Selected Suggestion"));
    g_signal_connect (apply_sugg_btn, "clicked",
                      G_CALLBACK (on_apply_suggestion_clicked), NULL);
    gtk_box_pack_start (GTK_BOX (btn_box), apply_sugg_btn, FALSE, FALSE, 0);

    GtkWidget *clear_btn = gtk_button_new_with_label (_("Clear Insights"));
    g_signal_connect (clear_btn, "clicked",
                      G_CALLBACK (fs_copilot_clear_insights), copilot);
    g_signal_connect (clear_btn, "clicked",
                      G_CALLBACK (refresh_insights), NULL);
    gtk_box_pack_start (GTK_BOX (btn_box), clear_btn, FALSE, FALSE, 0);

    gtk_box_pack_end (GTK_BOX (box), btn_box, FALSE, FALSE, 0);

    /* What-if simulation entry */
    GtkWidget *sim_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_margin_top (sim_box, 6);

    GtkWidget *sim_label = gtk_label_new (_("What-if: "));
    gtk_box_pack_start (GTK_BOX (sim_box), sim_label, FALSE, FALSE, 0);

    scenario_entry = gtk_entry_new ();
    gtk_entry_set_placeholder_text (GTK_ENTRY (scenario_entry),
                                     _("e.g. allow SSH from 192.168.1.50 on port 22"));
    gtk_widget_set_hexpand (scenario_entry, TRUE);
    gtk_box_pack_start (GTK_BOX (sim_box), scenario_entry, TRUE, TRUE, 0);

    gtk_box_pack_end (GTK_BOX (box), sim_box, FALSE, FALSE, 0);

    gtk_container_add (GTK_CONTAINER (frame), box);

    /* Initial refresh */
    refresh_insights ();

    return frame;
}

/**********************************************************************
 * fs_copilot_view_refresh - Public refresh function.
 **********************************************************************/
void
fs_copilot_view_refresh (void)
{
    refresh_insights ();
}

/**********************************************************************
 * refresh_insights - Reload insights from copilot into the list store.
 **********************************************************************/
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
        FsInsight *insight = l->data;
        GtkTreeIter iter;

        gtk_list_store_append (insights_store, &iter);
        gtk_list_store_set (insights_store, &iter,
                            COL_TITLE, insight->title,
                            COL_TYPE, insight_type_to_string (insight->type),
                            COL_SEVERITY, severity_to_string (insight->severity),
                            COL_DESC, insight->description,
                            COL_APP, insight->application,
                            COL_DEST, insight->destination ? insight->destination : "-",
                            COL_SUGGESTION, insight->suggested_rule ? insight->suggested_rule : "-",
                            -1);
    }

    g_list_free (insights); /* list copy, not the insights themselves */
}

/**********************************************************************
 * on_simulate_clicked - Handle what-if simulation.
 **********************************************************************/
static void
on_simulate_clicked (GtkButton *btn, gpointer data)
{
    const gchar *text = gtk_entry_get_text (GTK_ENTRY (scenario_entry));
    if (!text || !*text)
        return;

    /* Simple parser for what-if scenarios */
    gboolean inbound = TRUE;
    const gchar *app = "Unknown";
    const gchar *remote_ip = "any";
    guint port = 0;
    const gchar *protocol = "TCP";

    /* Very basic parsing - in production use a proper parser */
    if (strstr (text, "outbound") || strstr (text, "outgoing"))
        inbound = FALSE;

    /* Extract port */
    gchar *port_str = strstr (text, "port ");
    if (port_str)
        port = atoi (port_str + 5);

    /* Extract IP - simplified */
    /* In reality, use regex or proper parsing */

    FsSimulationResult *result = fs_copilot_simulate (global_copilot,
                                                      app,
                                                      remote_ip,
                                                      port,
                                                      protocol,
                                                      inbound);

    /* Show result in dialog */
    GtkWidget *dialog = gtk_message_dialog_new (GTK_WINDOW (copilot_window),
                                                GTK_DIALOG_MODAL,
                                                result->would_block ?
                                                GTK_MESSAGE_WARNING : GTK_MESSAGE_INFO,
                                                GTK_BUTTONS_OK,
                                                "%s",
                                                result->explanation);
    gtk_window_set_title (GTK_WINDOW (dialog), _("What-If Simulation Result"));
    gtk_dialog_run (GTK_DIALOG (dialog));
    gtk_widget_destroy (dialog);

    fs_simulation_result_free (result);
}

/**********************************************************************
 * on_apply_suggestion_clicked - Apply the selected rule suggestion.
 **********************************************************************/
static void
on_apply_suggestion_clicked (GtkButton *btn, gpointer data)
{
    GtkTreeSelection *sel = gtk_tree_view_get_selection (GTK_TREE_VIEW (insights_tree));
    GtkTreeModel *model;
    GtkTreeIter iter;

    if (!gtk_tree_selection_get_selected (sel, &model, &iter))
        return;

    gchar *rule_csv = NULL;
    gtk_tree_model_get (model, &iter, COL_SUGGESTION, &rule_csv, -1);

    if (!rule_csv || g_strcmp0 (rule_csv, "-") == 0)
    {
        g_free (rule_csv);
        return;
    }

    /* Show confirmation dialog */
    GtkWidget *dialog = gtk_message_dialog_new (GTK_WINDOW (copilot_window),
                                                GTK_DIALOG_MODAL,
                                                GTK_MESSAGE_QUESTION,
                                                GTK_BUTTONS_YES_NO,
                                                _("Apply this rule suggestion?\n\n%s"),
                                                rule_csv);
    gtk_window_set_title (GTK_WINDOW (dialog), _("Apply Rule Suggestion"));

    gint response = gtk_dialog_run (GTK_DIALOG (dialog));
    gtk_widget_destroy (dialog);

    if (response == GTK_RESPONSE_YES)
    {
        /* TODO: Parse rule_csv and add to policy */
        g_print ("Apply rule: %s\n", rule_csv);
        /* fs_policy_add_from_csv (policy, rule_csv); */
        /* fs_app_apply_rules (); */
    }

    g_free (rule_csv);
}

/**********************************************************************
 * on_row_activated - Double-click shows full details.
 **********************************************************************/
static void
on_row_activated (GtkTreeView *tree, GtkTreePath *path,
                  GtkTreeViewColumn *col, gpointer data)
{
    GtkTreeModel *model;
    GtkTreeIter iter;

    model = gtk_tree_view_get_model (tree);
    if (!gtk_tree_model_get_iter (model, &iter, path))
        return;

    gchar *title = NULL, *desc = NULL, *sugg = NULL;
    gtk_tree_model_get (model, &iter,
                        COL_TITLE, &title,
                        COL_DESC, &desc,
                        COL_SUGGESTION, &sugg,
                        -1);

    GtkWidget *dialog = gtk_message_dialog_new (GTK_WINDOW (copilot_window),
                                                GTK_DIALOG_MODAL,
                                                GTK_MESSAGE_INFO,
                                                GTK_BUTTONS_OK,
                                                "%s\n\n%s\n\n%s: %s",
                                                title,
                                                desc,
                                                _("Suggestion"),
                                                sugg ? sugg : _("None"));
    gtk_window_set_title (GTK_WINDOW (dialog), _("Insight Details"));
    gtk_dialog_run (GTK_DIALOG (dialog));
    gtk_widget_destroy (dialog);

    g_free (title);
    g_free (desc);
    g_free (sugg);
}

/**********************************************************************
 * insight_type_to_string - Convert enum to display string.
 **********************************************************************/
static const gchar *
insight_type_to_string (FsInsightType type)
{
    switch (type)
    {
    case FS_INSIGHT_NEW_APPLICATION: return _("New App");
    case FS_INSIGHT_UNUSUAL_PORT: return _("Unusual Port");
    case FS_INSIGHT_UNUSUAL_DESTINATION: return _("Unusual Dest");
    case FS_INSIGHT_UNUSUAL_VOLUME: return _("Unusual Volume");
    case FS_INSIGHT_UNUSUAL_TIME: return _("Unusual Time");
    case FS_INSIGHT_RULE_CONFLICT: return _("Rule Conflict");
    case FS_INSIGHT_REDUNDANT_RULE: return _("Redundant Rule");
    case FS_INSIGHT_MISSING_RULE: return _("Missing Rule");
    case FS_INSIGHT_SUSPICIOUS_BEHAVIOR: return _("Suspicious");
    case FS_INSIGHT_RULE_OPTIMIZATION: return _("Optimization");
    default: return _("Unknown");
    }
}

/**********************************************************************
 * severity_to_string - Convert enum to display string.
 **********************************************************************/
static const gchar *
severity_to_string (FsCopilotSeverity sev)
{
    switch (sev)
    {
    case FS_COPILOT_INFO: return _("Info");
    case FS_COPILOT_WARNING: return _("Warning");
    case FS_COPILOT_CRITICAL: return _("Critical");
    default: return _("Unknown");
    }
}