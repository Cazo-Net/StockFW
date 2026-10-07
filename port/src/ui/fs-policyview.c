/*---[ fs-policyview.c ]------------------------------------------------
 * The Policy page.
 *
 * Column layout comes from fs_rule_columns() so the table headers and
 * the on-disk CSV can never disagree; the original hard-coded both
 * separately in policyview.c.
 *
 * Each group keeps a GPtrArray of FsRule* mirroring its rows.  That
 * mirror is what makes in-place editing work: the store only holds
 * strings, so an edit has to be turned back into a rule and swapped
 * into the policy, and the pre-edit rule is needed to find it.
 *--------------------------------------------------------------------*/

#include "ui/fs-policyview.h"
#include "ui/fs-dialogs.h"
#include "core/fs-prefs.h"
#include "core/fs-backend.h"
#include "core/fs-fwrule.h"
#include "core/fs-util.h"
#include "core/fs-i18n.h"

#include <stdlib.h>
#include <string.h>

typedef struct
{
	FsRuleKind     kind;
	const gchar   *title;
	GtkWidget     *view;
	GtkListStore  *store;
	GPtrArray     *rules;      /* mirrors the store rows */
	gint           num_columns;
} FsPolicyGroup;

/* The kinds shown, in the order they appear on the page. */
static const struct
{
	FsRuleKind   kind;
	const gchar *title;
} group_defs[] = {
	{ FS_RULE_INBOUND_ALLOW_FROM,     N_("Allow connections from host") },
	{ FS_RULE_INBOUND_ALLOW_SERVICE,  N_("Allow inbound service") },
	{ FS_RULE_INBOUND_FORWARD,        N_("Forward service") },
	{ FS_RULE_OUTBOUND_ALLOW_SERVICE, N_("Allow outbound service") },
	{ FS_RULE_OUTBOUND_ALLOW_TO,      N_("Allow connections to host") },
	{ FS_RULE_OUTBOUND_DENY_TO,       N_("Deny connections to host") },
};

static GList    *groups = NULL;
static FsPolicy *current_policy = NULL;

/* [ column_count ] */
static gint
column_count (FsRuleKind kind)
{
	gint n = 0;

	fs_rule_columns (kind, &n);

	return n;
}

/* [ store_for_kind ]
 * A list store with one string column per CSV field. */
static GtkListStore *
store_for_kind (FsRuleKind kind)
{
	GType *types;
	GtkListStore *store;
	gint n = column_count (kind);

	types = g_new0 (GType, n ? n : 1);

	for (gint i = 0; i < n; i++)
		types[i] = G_TYPE_STRING;

	store = gtk_list_store_newv (n, types);
	g_free (types);

	return store;
}

/* [ rule_fields ]
 * The CSV-ordered fields of a rule, as an array of borrowed strings.
 * Returns the number written. */
static gint
rule_fields (const FsRule *rule, const gchar **fields, gint max)
{
	gint n = 0;

	switch (rule->kind) {
	case FS_RULE_INBOUND_FORWARD:
		if (n < max) fields[n++] = rule->service;
		if (n < max) fields[n++] = rule->port;
		if (n < max) fields[n++] = rule->to;
		if (n < max) fields[n++] = rule->to_port;
		if (n < max) fields[n++] = rule->comment;
		break;

	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		if (n < max) fields[n++] = rule->service;
		if (n < max) fields[n++] = rule->port;
		if (n < max) fields[n++] = rule->target;
		if (n < max) fields[n++] = rule->comment;
		break;

	default:
		if (n < max) fields[n++] = rule->target;
		if (n < max) fields[n++] = rule->comment;
		break;
	}

	return n;
}

/* [ rule_from_fields ] */
static FsRule *
rule_from_fields (FsRuleKind kind, gchar **fields, gint count)
{
	FsRule *rule = fs_rule_new (kind);

	switch (kind) {
	case FS_RULE_INBOUND_FORWARD:
		rule->service = g_strdup (count > 0 ? fields[0] : NULL);
		rule->port    = g_strdup (count > 1 ? fields[1] : NULL);
		rule->to      = g_strdup (count > 2 ? fields[2] : NULL);
		rule->to_port = g_strdup (count > 3 ? fields[3] : NULL);
		rule->comment = g_strdup (count > 4 ? fields[4] : NULL);
		break;

	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		rule->service = g_strdup (count > 0 ? fields[0] : NULL);
		rule->port    = g_strdup (count > 1 ? fields[1] : NULL);
		rule->target  = g_strdup (count > 2 ? fields[2] : NULL);
		rule->comment = g_strdup (count > 3 ? fields[3] : NULL);
		break;

	default:
		rule->target  = g_strdup (count > 0 ? fields[0] : NULL);
		rule->comment = g_strdup (count > 1 ? fields[1] : NULL);
		break;
	}

	return rule;
}

/* [ rule_from_store_row ]
 * Reads one store row back into a rule.  Free with fs_rule_free. */
static FsRule *
rule_from_store_row (FsPolicyGroup *group, gint row)
{
	GtkTreeIter iter;
	gchar *values[5] = { NULL, NULL, NULL, NULL, NULL };
	gint n = column_count (group->kind);
	FsRule *rule;

	if (n > 5)
		n = 5;

	if (!gtk_tree_model_iter_nth_child (GTK_TREE_MODEL (group->store), &iter,
	                                     NULL, row))
		return NULL;

	for (gint i = 0; i < n; i++) {
		GValue value = G_VALUE_INIT;

		gtk_tree_model_get_value (GTK_TREE_MODEL (group->store), &iter, i,
		                          &value);
		values[i] = g_value_dup_string (&value);
		g_value_unset (&value);
	}

	rule = rule_from_fields (group->kind, values, n);

	for (gint i = 0; i < n; i++)
		g_free (values[i]);

	return rule;
}

/* [ selected_row ]
 * Row index under the cursor, or -1. */
static gint
selected_row (FsPolicyGroup *group)
{
	GtkTreeSelection *selection;
	GtkTreeModel *model;
	GtkTreeIter iter;
	GtkTreePath *path;
	gint row;

	selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (group->view));

	if (!gtk_tree_selection_get_selected (selection, &model, &iter))
		return -1;

	path = gtk_tree_model_get_path (model, &iter);
	row = gtk_tree_path_get_indices (path)[0];
	gtk_tree_path_free (path);

	return row;
}

/* [ select_row ] */
static void
select_row (FsPolicyGroup *group, gint row)
{
	GtkTreeIter iter;

	if (!gtk_tree_model_iter_nth_child (GTK_TREE_MODEL (group->store), &iter,
	                                     NULL, row))
		return;

	gtk_tree_selection_select_iter (
		gtk_tree_view_get_selection (GTK_TREE_VIEW (group->view)),
		&iter);
}

/* [ refresh_group ]
 * Rebuilds the rows and the mirror from the policy. */
static void
refresh_group (FsPolicyGroup *group, const FsPolicy *policy)
{
	GtkTreeIter iter;

	gtk_list_store_clear (group->store);
	g_ptr_array_set_size (group->rules, 0);

	if (policy == NULL)
		return;

	for (guint i = 0; i < policy->kinds[group->kind]->len; i++) {
		FsRule *rule = g_ptr_array_index (policy->kinds[group->kind], i);
		const gchar *fields[5] = { NULL, NULL, NULL, NULL, NULL };
		gint n = rule_fields (rule, fields, 5);

		gtk_list_store_append (group->store, &iter);

		for (gint col = 0; col < n; col++) {
			gtk_list_store_set (group->store, &iter, col,
			                    fields[col] ? fields[col] : "", -1);
		}

		g_ptr_array_add (group->rules, fs_rule_copy (rule));
	}
}

/* Defined below; runs the policy through the backend when the
 * "Apply policy changes immediately" preference is on. */
static void maybe_apply_instantly (void);

/* [ on_remove_clicked ] */
static void
on_remove_clicked (GtkButton *button, gpointer data)
{
	FsPolicyGroup *group = data;
	gint row;

	if (current_policy == NULL)
		return;

	row = selected_row (group);

	if (row < 0 || (guint) row >= group->rules->len)
		return;

	if (fs_policy_remove (current_policy,
	                      g_ptr_array_index (group->rules, row))) {
		refresh_group (group, current_policy);
		fs_policyview_save (current_policy);
		maybe_apply_instantly ();
	}
}

/* [ blank_rule ]
 * A sensible starting point for a new row of this kind. */
static FsRule *
blank_rule (FsRuleKind kind)
{
	FsRule *rule = fs_rule_new (kind);

	switch (kind) {
	case FS_RULE_INBOUND_FORWARD:
		rule->service = g_strdup (_("Service"));
		rule->to      = g_strdup ("");
		rule->to_port = g_strdup ("");
		break;

	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		rule->service = g_strdup (_("Service"));
		rule->target  = g_strdup (FS_TARGET_ANY);
		break;

	default:
		/* "Anyone" rather than 0.0.0.0/0: a host rule with no host
		 * is meaningless, and netsh rejects 0.0.0.0/0 as a
		 * remoteip. */
		rule->target = g_strdup (FS_TARGET_ANY);
		break;
	}

	return rule;
}

/* [ on_add_clicked ] */
static void
on_add_clicked (GtkButton *button, gpointer data)
{
	FsPolicyGroup *group = data;
	FsRule *rule;

	if (current_policy == NULL)
		return;

	rule = blank_rule (group->kind);
	fs_policy_add (current_policy, rule);
	fs_rule_free (rule);

	refresh_group (group, current_policy);
	select_row (group, (gint) group->rules->len - 1);

	fs_policyview_save (current_policy);
	maybe_apply_instantly ();
}

/* [ on_cell_edited ]
 * Commits an in-place edit.  The store already holds the new text by
 * the time this runs, so the edited rule is read back from the row and
 * swapped into the policy in place of its previous version. */
static void
on_cell_edited (GtkCellRendererText *renderer, gchar *path_string,
                gchar *new_text, gpointer data)
{
	FsPolicyGroup *group = data;
	gint row = atoi (path_string);
	FsRule *old_rule;
	FsRule *new_rule;

	if (current_policy == NULL)
		return;

	if (row < 0 || (guint) row >= group->rules->len)
		return;

	new_rule = rule_from_store_row (group, row);

	if (new_rule == NULL)
		return;

	old_rule = g_ptr_array_index (group->rules, row);

	/* The mirror still holds the pre-edit rule, so it matches the
	 * copy inside the policy and can be removed by content. */
	if (!fs_policy_remove (current_policy, old_rule)) {
		fs_rule_free (new_rule);
		return;
	}

	fs_policy_add (current_policy, new_rule);

	fs_rule_free (old_rule);
	group->rules->pdata[row] = fs_rule_copy (new_rule);
	fs_rule_free (new_rule);

	fs_policyview_save (current_policy);
	maybe_apply_instantly ();
}

/* [ apply_policy_now ]
 * Shared by the Apply button and the "Apply policy changes
 * immediately" preference.
 *
 * announce=TRUE is the confirmation the Apply button owes the user.
 * Auto-apply is silent on success -- a dialog per edited cell would
 * make the table unusable -- but every failure still reports, because
 * a refusal that vanished would be exactly the kind of quiet lie this
 * port has been removing. */
static void
apply_policy_now (gboolean announce)
{
	const FsBackend *backend = fs_backend ();
	FsApplyResult result;
	GError *error = NULL;
	GList *rules;
	guint count;

	if (current_policy == NULL)
		return;

	if (!fs_policyview_save (current_policy))
		return;

	rules = fs_fwrule_from_policy (current_policy);
	count = g_list_length (rules);
	fs_fwrule_list_free (rules);

	if (!backend->available ()) {
		fs_dialogs_error (NULL, _("Cannot apply the policy"),
		                  _("No firewall backend is available on this "
		                    "system."));
		return;
	}

	result = backend->apply_rules (current_policy, &error);

	switch (result) {
	case FS_APPLY_OK:
		if (announce)
			fs_dialogs_info (NULL, _("Policy applied"),
			                 g_strdup_printf (
			                         _("%u rule(s) were applied to the "
			                           "firewall."), count));
		break;

	case FS_APPLY_NO_PRIVILEGE:
		fs_dialogs_error (NULL, _("Administrator privileges required"),
		                  error ? error->message
		                        : _("Changing the firewall needs elevated "
		                          "privileges."));
		break;

	case FS_APPLY_PARTIAL:
		fs_dialogs_error (NULL, _("Policy only partly applied"),
		                  error ? error->message
		                        : _("Some rules could not be created."));
		break;

	case FS_APPLY_NO_IPTABLES:
	case FS_APPLY_EXT_IF_FAILED:
	case FS_APPLY_INT_IF_FAILED:
	case FS_APPLY_FAILED:
	default:
		fs_dialogs_error (NULL, _("Failed to apply the policy"),
		                  error ? error->message
		                        : _(fs_util_apply_result_to_string (
		                              (int) result)));
		break;
	}

	g_clear_error (&error);
}

static void
on_apply_clicked (GtkButton *button, gpointer data)
{
	(void) button;
	(void) data;

	apply_policy_now (TRUE);
}

/* [ maybe_apply_instantly ]
 * Called by every handler that changes the policy.  With the
 * preference on the change reaches the firewall at once instead of
 * waiting for Apply. */
static void
maybe_apply_instantly (void)
{
	/* Default to FALSE: the original StockFW required an explicit
	 * Apply click.  Auto-apply on every edit was noisy and showed
	 * "Administrator required" dialogs when not elevated.  The user
	 * can enable it in Preferences → Interface if they run elevated. */
	if (!fs_prefs_get_bool (FS_PREFS_APPLY_POLICY_INSTANTLY, FALSE))
		return;

	apply_policy_now (FALSE);
}

/* [ build_group ] */
static GtkWidget *
build_group (FsRuleKind kind, const gchar *title)
{
	FsPolicyGroup *group = g_new0 (FsPolicyGroup, 1);
	const gchar * const *columns;
	GtkWidget *frame, *box, *scroll, *button_box, *button;
	gint n = 0;

	group->kind = kind;
	group->title = title;
	group->num_columns = column_count (kind);
	group->store = store_for_kind (kind);
	group->rules = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_rule_free);

	frame = gtk_frame_new (title);
	box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
	gtk_container_set_border_width (GTK_CONTAINER (box), 6);
	gtk_container_add (GTK_CONTAINER (frame), box);

	group->view = gtk_tree_view_new_with_model (
		GTK_TREE_MODEL (group->store));

	columns = fs_rule_columns (kind, &n);

	for (gint i = 0; i < n; i++) {
		GtkCellRenderer *renderer = gtk_cell_renderer_text_new ();
		GtkTreeViewColumn *column;

		g_object_set (renderer, "editable", TRUE, NULL);
		g_signal_connect (renderer, "edited",
		                  G_CALLBACK (on_cell_edited), group);

		column = gtk_tree_view_column_new_with_attributes (_(columns[i]),
		                                                    renderer,
		                                                    "text", i,
		                                                    NULL);
		gtk_tree_view_column_set_resizable (column, TRUE);
		gtk_tree_view_append_column (GTK_TREE_VIEW (group->view), column);
	}

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll),
	                                     GTK_SHADOW_IN);
	gtk_widget_set_vexpand (scroll, TRUE);
	gtk_container_add (GTK_CONTAINER (scroll), group->view);
	gtk_box_pack_start (GTK_BOX (box), scroll, TRUE, TRUE, 0);

	button_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_widget_set_halign (button_box, GTK_ALIGN_END);

	button = gtk_button_new_with_label (_("_Add"));
	g_signal_connect (button, "clicked", G_CALLBACK (on_add_clicked), group);
	gtk_box_pack_start (GTK_BOX (button_box), button, FALSE, FALSE, 0);

	button = gtk_button_new_with_label (_("_Remove"));
	g_signal_connect (button, "clicked", G_CALLBACK (on_remove_clicked),
	                  group);
	gtk_box_pack_start (GTK_BOX (button_box), button, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (box), button_box, FALSE, FALSE, 0);

	groups = g_list_append (groups, group);

	return frame;
}

GtkWidget *
fs_policyview_page (FsPolicy *policy)
{
	GtkWidget *page, *scroll, *outer, *bar, *button;
	gint malformed = 0;

	current_policy = policy;

	outer = gtk_box_new (GTK_ORIENTATION_VERTICAL, 0);

	/* Toolbar: Apply lives here rather than in a menu because it is the
	 * one action a user comes to this page for. */
	bar = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_container_set_border_width (GTK_CONTAINER (bar), 6);

	button = gtk_button_new_with_mnemonic (_("_Apply policy"));
	g_signal_connect (button, "clicked", G_CALLBACK (on_apply_clicked),
	                  NULL);
	gtk_box_pack_start (GTK_BOX (bar), button, FALSE, FALSE, 0);

	gtk_box_pack_start (GTK_BOX (outer), bar, FALSE, FALSE, 0);

	page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 12);
	gtk_container_set_border_width (GTK_CONTAINER (page), 12);

	/* An empty policy would leave the user with nothing, so seed the
	 * documented defaults on a first run. */
	if (!fs_policy_load (policy, &malformed))
		fs_policy_install_defaults (policy);

	if (malformed > 0)
		g_warning ("%d malformed policy rule(s) were skipped", malformed);

	for (gsize i = 0; i < G_N_ELEMENTS (group_defs); i++)
		gtk_box_pack_start (GTK_BOX (page),
		                    build_group (group_defs[i].kind,
		                                 _(group_defs[i].title)),
		                    TRUE, TRUE, 0);

	for (GList *iter = groups; iter != NULL; iter = iter->next)
		refresh_group (iter->data, policy);

	/* Six groups each wanting the full window height is unusable, so
	 * the whole column scrolls instead. */
	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_widget_set_vexpand (scroll, TRUE);
	gtk_container_add (GTK_CONTAINER (scroll), page);

	gtk_box_pack_start (GTK_BOX (outer), scroll, TRUE, TRUE, 0);

	return outer;
}

void
fs_policyview_reload (FsPolicy *policy)
{
	gint malformed = 0;

	if (policy == NULL)
		return;

	current_policy = policy;
	fs_policy_load (policy, &malformed);

	for (GList *iter = groups; iter != NULL; iter = iter->next)
		refresh_group (iter->data, policy);
}

gboolean
fs_policyview_save (FsPolicy *policy)
{
	if (policy == NULL)
		return FALSE;

	if (!fs_policy_save (policy)) {
		fs_dialogs_error (NULL, _("Could not save the policy"),
		                  _("The rule files could not be written. Check "
		                    "that the directory is writable."));
		return FALSE;
	}

	return TRUE;
}