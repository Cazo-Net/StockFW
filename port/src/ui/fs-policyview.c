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
#include "ui/fs-statusview.h"
#include "core/fs-prefs.h"
#include "core/fs-backend.h"
#include "core/fs-fwrule.h"
#include "core/fs-util.h"
#include "core/fs-apply.h"
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
	GtkWidget     *direction;  /* Direction combo, or NULL when the
	                              kind has no counterpart */
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
 * A list store with one string column per CSV field, then two that are
 * never saved: what the rule covers ("IPv4 + IPv6") and the sentence
 * saying why, shown as the row's tooltip. */
static GtkListStore *
store_for_kind (FsRuleKind kind)
{
	GType *types;
	GtkListStore *store;
	gint n = column_count (kind);

	types = g_new0 (GType, n + 2);

	for (gint i = 0; i < n + 2; i++)
		types[i] = G_TYPE_STRING;

	store = gtk_list_store_newv (n + 2, types);
	g_free (types);

	return store;
}

/* [ set_coverage ]
 * Fills the two display-only columns of one row from its rule.  The
 * answer comes from core (fs_rule_coverage), which follows what the
 * generator writes, so the column cannot claim more than the firewall
 * does. */
static void
set_coverage (FsPolicyGroup *group, GtkTreeIter *iter, const FsRule *rule)
{
	gboolean names = (fs_backend ()->fw_honors & FS_FWHON_HOST_NAMES) != 0;
	gchar *detail = NULL;
	FsFamily fam = fs_rule_coverage (rule, names, &detail);
	gchar *tip = g_markup_escape_text (detail != NULL ? detail : "", -1);
	gint n = group->num_columns;

	gtk_list_store_set (group->store, iter,
	                    n, fam == FS_FAMILY_NONE ? _("Nothing")
	                                             : _(fs_util_families_label (fam)),
	                    n + 1, tip, -1);
	g_free (tip);
	g_free (detail);
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
		set_coverage (group, &iter, rule);

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

/* [ group_for_kind ]
 * The group displaying this kind, or NULL.  Needed when a bi-
 * directional add stages a rule into a group other than the one whose
 * Add button was pressed. */
static FsPolicyGroup *
group_for_kind (FsRuleKind kind)
{
	for (GList *l = groups; l != NULL; l = l->next) {
		FsPolicyGroup *g = l->data;

		if (g->kind == kind)
			return g;
	}

	return NULL;
}

/* [ on_add_clicked ] */
static void
on_add_clicked (GtkButton *button, gpointer data)
{
	FsPolicyGroup *group = data;
	FsRule *rule;
	gboolean pair;

	if (current_policy == NULL)
		return;

	/* The Direction setting: the default entry stages only this
	 * group's rule; "Bi-directional" stages the twin as well. */
	pair = (group->direction != NULL &&
	        gtk_combo_box_get_active (
	        	GTK_COMBO_BOX (group->direction)) == 1);

	rule = blank_rule (group->kind);
	fs_policy_add (current_policy, rule);

	if (pair) {
		FsRule *counterpart = fs_rule_counterpart (rule);

		if (counterpart != NULL) {
			fs_policy_add (current_policy, counterpart);
			fs_rule_free (counterpart);

			/* The twin lives in another group; its mirror must
			 * see it too. */
			FsPolicyGroup *other =
				group_for_kind (fs_rule_counterpart_kind (
				                 group->kind));

			if (other != NULL)
				refresh_group (other, current_policy);
		}
	}

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
	{
		GtkTreeIter iter;

		if (gtk_tree_model_iter_nth_child (GTK_TREE_MODEL (group->store),
		                                   &iter, NULL, row))
			set_coverage (group, &iter, new_rule);
	}
	fs_rule_free (new_rule);

	fs_policyview_save (current_policy);
	maybe_apply_instantly ();
}

/* [ fs_policyview_hold_reason ]
 * The single answer to "may this apply touch the firewall?" for every
 * page that pushes policy: audit-only testing mode first (a core
 * preference), then the Status page's Lock.  English on purpose --
 * the reason is recorded verbatim in the append-only audit log. */
const gchar *
fs_policyview_hold_reason (void)
{
	const gchar *hold = fs_apply_hold_reason ();

	if (hold == NULL && fs_statusview_policy_locked ())
		return "policy locked on the Status page";

	return hold;
}

/* [ on_audit_only_toggled ]
 * The Policy page's Audit-only switch.  While it is on, Apply stages
 * and audits but never reaches the firewall -- and the toggle's own
 * state is what makes that visible instead of a silent lie. */
static void
on_audit_only_toggled (GtkToggleButton *button, gpointer data)
{
	(void) data;

	fs_apply_set_audit_only (gtk_toggle_button_get_active (button));
}

/* [ apply_policy_now ]
 * Shared by the Apply button and the "Apply policy changes
 * immediately" preference.
 *
 * announce=TRUE is the confirmation the Apply button owes the user:
 * the impact preview (P3) is shown before anything is touched, and a
 * cancelled preview leaves the firewall alone.  Auto-apply is silent
 * on success -- a dialog per edited cell would make the table
 * unusable -- but every failure still reports, because a refusal that
 * vanished would be exactly the kind of quiet lie this port has been
 * removing. */
static void
apply_policy_now (gboolean announce)
{
	const FsBackend *backend = fs_backend ();
	const gchar *hold;
	FsApplyOutcome *outcome;
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

	hold = fs_policyview_hold_reason ();

	/* The preview only owes a question when the apply could actually
	 * bite: a hold never reaches the firewall, so it gets its own
	 * message below instead of confirmation theatre. */
	if (announce && hold == NULL) {
		FsPolicyImpact *preview =
			fs_policy_impact_preview (current_policy);
		gboolean changes = (preview->added > 0 ||
		                    preview->removed > 0);

		if (changes) {
			gchar *desc = fs_policy_impact_describe (preview);
			gchar *question = g_strdup_printf (
				_("Apply these policy changes to the firewall?"
				  "\n\n%s"),
				desc);
			gboolean confirmed = FALSE;

			fs_dialogs_confirm (NULL, question, &confirmed);
			g_free (question);
			g_free (desc);
			fs_policy_impact_free (preview);

			if (!confirmed)
				return;
		} else {
			fs_policy_impact_free (preview);
		}
	}

	outcome = fs_policy_apply_safe (backend, current_policy,
	                                "policy page", hold, &error);

	if (outcome->held) {
		if (announce) {
			gchar *desc = fs_policy_impact_describe (outcome->impact);
			gchar *msg = g_strdup_printf (
				_("Reason: %s.\n\n%s\n\nThe change is saved in "
				  "your policy and written to the audit log, "
				  "but the firewall was deliberately left "
				  "untouched. Turn the hold off (Audit-only on "
				  "this page, or the Lock on the Status page) "
				  "and apply again to make it live."),
				hold, desc);

			fs_dialogs_info (NULL, _("Policy staged, not applied"),
			                 msg);
			g_free (msg);
			g_free (desc);
		}
	} else if (outcome->result == FS_APPLY_OK) {
		if (announce) {
			/* The backend's notes (Linux: a rule left out, IPv6
			 * not filtered) ride on the success: the policy is
			 * in force, and this is what it does not cover. */
			gchar *notes = outcome->notes != NULL
				? g_strdup_printf (_("\n\nPlease note:\n%s"),
				                   outcome->notes)
				: g_strdup ("");

			if (outcome->impact->added == 0 &&
			    outcome->impact->removed == 0) {
				gchar *msg = g_strdup_printf (
					_("The policy already matches what is "
					  "live on the firewall.%s"), notes);

				fs_dialogs_info (NULL, _("Nothing to change"), msg);
				g_free (msg);
			} else {
				gchar *desc =
					fs_policy_impact_describe (outcome->impact);
				gchar *msg = g_strdup_printf (
					_("%u rule(s) were applied to the "
					  "firewall.\n\n%s%s"),
					count, desc, notes);

				fs_dialogs_info (NULL, _("Policy applied"), msg);
				g_free (msg);
				g_free (desc);
			}
			g_free (notes);
		}
	} else {
		/* Every failure tells the rollback truth next to the
		 * reason: restored-and-verified, failed-too, or honestly
		 * nothing to restore. */
		const gchar *body = error != NULL
			? _(error->message)
			: _(fs_util_apply_result_to_string (
			       (int) outcome->result));
		const gchar *rollback;
		gchar *msg;

		if (outcome->rollback_attempted &&
		    outcome->rollback_verified)
			rollback = _("The firewall was restored to the last "
			              "applied policy, and that restore was "
			              "verified.");
		else if (outcome->rollback_attempted)
			rollback = _("The rollback ALSO failed: the firewall "
			              "may be in an inconsistent state. Check "
			              "the Status page and apply again from a "
			              "session running as administrator.");
		else
			rollback = _("No previously applied policy is "
			              "recorded, so there was nothing to "
			              "restore.");

		msg = g_strdup_printf ("%s\n\n%s", body, rollback);

		switch (outcome->result) {
		case FS_APPLY_NO_PRIVILEGE:
			fs_dialogs_error (NULL,
			                  _("Administrator privileges required"),
			                  msg);
			break;

		case FS_APPLY_NO_IPTABLES:
			fs_dialogs_error (NULL, _("Cannot apply the policy"),
			                  msg);
			break;

		case FS_APPLY_PARTIAL:
			fs_dialogs_error (NULL, _("Policy only partly applied"),
			                  msg);
			break;

		case FS_APPLY_DRY_RUN:
			/* Held paths are handled above; belt and braces so no
			 * result value is silently unclassified. */
		case FS_APPLY_EXT_IF_FAILED:
		case FS_APPLY_INT_IF_FAILED:
		case FS_APPLY_FAILED:
		default:
			fs_dialogs_error (NULL, _("Failed to apply the policy"),
			                  msg);
			break;
		}

		g_free (msg);
	}

	fs_apply_outcome_free (outcome);
	g_clear_error (&error);

	/* An apply can change what the Status page says about IPv6
	 * (loaded, unhooked, not installed). */
	fs_statusview_refresh_ipv6 ();
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
	/* Off unless set: the original StockFW required an explicit
	 * Apply click.  The default lives in the settings table
	 * (core/fs-prefs.c); the user turns it on in Preferences >
	 * Policy. */
	if (!fs_prefs_bool (FS_PREFS_APPLY_POLICY_INSTANTLY))
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
	gtk_style_context_add_class (gtk_widget_get_style_context (frame),
	                             "card-frame");
	/* The card's own border is the frame; a second, etched one inside
	 * it read as a box in a box. */
	gtk_frame_set_shadow_type (GTK_FRAME (frame), GTK_SHADOW_NONE);
	box = gtk_box_new (GTK_ORIENTATION_VERTICAL, 6);
	gtk_container_set_border_width (GTK_CONTAINER (box), 6);
	gtk_container_add (GTK_CONTAINER (frame), box);

	group->view = gtk_tree_view_new_with_model (
		GTK_TREE_MODEL (group->store));
	gtk_style_context_add_class (gtk_widget_get_style_context (group->view),
	                             "data-grid");
	gtk_tree_view_set_grid_lines (GTK_TREE_VIEW (group->view),
	                              GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);

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

	/* What the rule reaches: read-only, recomputed on every edit.  The
	 * tooltip says why ("an IPv4 address, so IPv4 only"). */
	{
		GtkCellRenderer *renderer = gtk_cell_renderer_text_new ();
		GtkTreeViewColumn *column;

		g_object_set (renderer, "editable", FALSE, NULL);
		column = gtk_tree_view_column_new_with_attributes (_("Covers"),
		                                                    renderer,
		                                                    "text", n,
		                                                    NULL);
		gtk_tree_view_column_set_resizable (column, TRUE);
		gtk_tree_view_append_column (GTK_TREE_VIEW (group->view), column);
		gtk_tree_view_set_tooltip_column (GTK_TREE_VIEW (group->view),
		                                  n + 1);
	}

	scroll = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll),
	                                GTK_POLICY_AUTOMATIC,
	                                GTK_POLICY_AUTOMATIC);
	/* The card frame is the border; no etched shadow inside it. */
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll),
	                                     GTK_SHADOW_NONE);
	gtk_widget_set_vexpand (scroll, TRUE);
	gtk_container_add (GTK_CONTAINER (scroll), group->view);
	gtk_box_pack_start (GTK_BOX (box), scroll, TRUE, TRUE, 0);

	button_box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
	gtk_widget_set_halign (button_box, GTK_ALIGN_END);

	/* The Direction setting -- only where the kind has a twin.  On the
	 * kinds without one a second entry would be a choice that does
	 * nothing (the policy has no inbound-deny kind: inbound is
	 * default-deny already), so the control is simply absent. */
	if (fs_rule_direction_label (kind) != NULL) {
		group->direction = gtk_combo_box_text_new ();
		gtk_combo_box_text_append_text (
			GTK_COMBO_BOX_TEXT (group->direction),
			fs_rule_direction_label (kind));
		gtk_combo_box_text_append_text (
			GTK_COMBO_BOX_TEXT (group->direction),
			_("Bi-directional"));
		gtk_combo_box_set_active (GTK_COMBO_BOX (group->direction), 0);
		gtk_box_pack_start (GTK_BOX (button_box), group->direction,
		                    FALSE, FALSE, 0);
	}

	/* Plain labels, not mnemonics: every group has its own Add and
	 * Remove, so one Alt+A could only ever cycle between nine of them
	 * -- and as labels the underscores were printed literally
	 * ("_Add"), which is how this was found. */
	button = gtk_button_new_with_label (_("Add"));
	gtk_style_context_add_class (gtk_widget_get_style_context (button),
	                             "btn-subtle");
	g_signal_connect (button, "clicked", G_CALLBACK (on_add_clicked), group);
	gtk_box_pack_start (GTK_BOX (button_box), button, FALSE, FALSE, 0);

	button = gtk_button_new_with_label (_("Remove"));
	gtk_style_context_add_class (gtk_widget_get_style_context (button),
	                             "btn-subtle");
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
	gtk_widget_set_margin_bottom (bar, 14);

	button = gtk_button_new_with_mnemonic (_("_Apply policy"));
	gtk_style_context_add_class (gtk_widget_get_style_context (button),
	                             "btn-primary");
	g_signal_connect (button, "clicked", G_CALLBACK (on_apply_clicked),
	                  NULL);
	gtk_box_pack_start (GTK_BOX (bar), button, FALSE, FALSE, 0);

	/* Audit-only (P3): the testing mode switch, beside the button it
	 * guards.  Its state is the honest signal that Apply will stage
	 * and audit without touching the firewall. */
	button = gtk_toggle_button_new_with_label (_("Audit-only"));
	gtk_style_context_add_class (gtk_widget_get_style_context (button),
	                             "btn-subtle");
	gtk_widget_set_tooltip_text (button,
	                             _("Stage changes and write audit "
	                               "lines without touching the "
	                               "firewall. While this is on, Apply "
	                               "never reaches the firewall."));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (button),
	                              fs_apply_audit_only ());
	g_signal_connect (button, "toggled",
	                  G_CALLBACK (on_audit_only_toggled), NULL);
	gtk_box_pack_start (GTK_BOX (bar), button, FALSE, FALSE, 0);

	/* What the new column means, once, where the tables start. */
	{
		GtkWidget *hint = gtk_label_new (
			_("Covers: whether each rule reaches IPv4, IPv6 or both. "
			  "Point at a row to see why."));

		gtk_style_context_add_class (gtk_widget_get_style_context (hint),
		                             "dim-label");
		gtk_label_set_xalign (GTK_LABEL (hint), 1.0);
		gtk_label_set_ellipsize (GTK_LABEL (hint), PANGO_ELLIPSIZE_END);
		gtk_box_pack_end (GTK_BOX (bar), hint, TRUE, TRUE, 0);
	}

	gtk_box_pack_start (GTK_BOX (outer), bar, FALSE, FALSE, 0);

	page = gtk_box_new (GTK_ORIENTATION_VERTICAL, 14);
	/* Room for an overlay scrollbar beside the cards. */
	gtk_widget_set_margin_end (page, 6);

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