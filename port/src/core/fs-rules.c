/*---[ fs-rules.c ]-----------------------------------------------------
 * The traffic policy rule store.
 *--------------------------------------------------------------------*/

#include "core/fs-rules.h"
#include "core/fs-util.h"
#include "core/fs-i18n.h"

#include <string.h>

/* Column layout per kind.  This is the on-disk CSV contract and must not
 * be reordered without a migration.  The UI reads the labels from here so
 * the tree view and the CSV can never drift apart. */
static const gchar *in_allow_from_columns[]   = { N_("Allow connections from host"), N_("Comment"), NULL };
static const gchar *in_allow_service_columns[]= { N_("Allow service"), N_("Port"), N_("For"), N_("Comment"), NULL };
static const gchar *in_forward_columns[]      = { N_("Forward service"), N_("Firewall port"), N_("To"), N_("Port"), N_("Comment"), NULL };
static const gchar *out_host_columns[]        = { N_("Host"), N_("Comment"), NULL };
static const gchar *out_service_columns[]     = { N_("Allow service"), N_("Port"), N_("For"), N_("Comment"), NULL };

static const gchar * const *
columns_for (FsRuleKind kind, gint *num_columns)
{
	const gchar * const *cols;
	gint n;

	switch (kind) {
	case FS_RULE_INBOUND_ALLOW_FROM:
		cols = in_allow_from_columns;
		n = 2;
		break;

	case FS_RULE_OUTBOUND_ALLOW_TO:
	case FS_RULE_OUTBOUND_ALLOW_FROM:
	case FS_RULE_OUTBOUND_DENY_TO:
	case FS_RULE_OUTBOUND_DENY_FROM:
		cols = out_host_columns;
		n = 2;
		break;

	case FS_RULE_INBOUND_FORWARD:
		cols = in_forward_columns;
		n = 5;
		break;

	case FS_RULE_INBOUND_ALLOW_SERVICE:
		cols = in_allow_service_columns;
		n = 4;
		break;

	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		cols = out_service_columns;
		n = 4;
		break;

	default:
		cols = NULL;
		n = 0;
		break;
	}

	if (num_columns != NULL)
		*num_columns = n;

	return cols;
}

const gchar * const *
fs_rule_columns (FsRuleKind kind, gint *num_columns)
{
	return columns_for (kind, num_columns);
}

FsRule *
fs_rule_new (FsRuleKind kind)
{
	FsRule *rule = g_new0 (FsRule, 1);

	rule->kind = kind;

	return rule;
}

FsRule *
fs_rule_copy (const FsRule *rule)
{
	FsRule *copy;

	if (rule == NULL)
		return NULL;

	copy = fs_rule_new (rule->kind);
	copy->service = g_strdup (rule->service);
	copy->port    = g_strdup (rule->port);
	copy->target  = g_strdup (rule->target);
	copy->to      = g_strdup (rule->to);
	copy->to_port = g_strdup (rule->to_port);
	copy->comment = g_strdup (rule->comment);

	return copy;
}

void
fs_rule_free (FsRule *rule)
{
	if (rule == NULL)
		return;

	g_free (rule->service);
	g_free (rule->port);
	g_free (rule->target);
	g_free (rule->to);
	g_free (rule->to_port);
	g_free (rule->comment);

	g_free (rule);
}

gchar *
fs_rule_to_csv (const FsRule *rule)
{
	GString *out;

	if (rule == NULL)
		return g_strdup ("");

	out = g_string_new (NULL);

	switch (rule->kind) {
	case FS_RULE_INBOUND_FORWARD:
		g_string_append_printf (out, "%s, %s, %s, %s, %s",
		                        rule->service  ? rule->service  : "",
		                        rule->port     ? rule->port     : "",
		                        rule->to       ? rule->to       : "",
		                        rule->to_port  ? rule->to_port  : "",
		                        rule->comment  ? rule->comment  : "");
		break;

	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		g_string_append_printf (out, "%s, %s, %s, %s",
		                        rule->service ? rule->service : "",
		                        rule->port    ? rule->port    : "",
		                        rule->target  ? rule->target  : "",
		                        rule->comment ? rule->comment : "");
		break;

	default:
		g_string_append_printf (out, "%s, %s",
		                        rule->target ? rule->target : "",
		                        rule->comment ? rule->comment : "");
		break;
	}

	return g_string_free (out, FALSE);
}

FsRule *
fs_rule_from_csv (FsRuleKind kind, const gchar *csv)
{
	gchar **tokens;
	FsRule *rule;
	gsize n_tokens;
	gint expected = 0;

	if (csv == NULL)
		return NULL;

	columns_for (kind, &expected);

	tokens = g_strsplit (csv, ",", -1);
	n_tokens = g_strv_length (tokens);

	/* The original accepted rows with a missing trailing comment, so
	 * allow fewer fields but reject more than the layout defines. */
	if (n_tokens > (gsize) expected) {
		g_strfreev (tokens);
		return NULL;
	}

	for (gsize i = 0; i < n_tokens; i++)
		g_strstrip (tokens[i]);

	rule = fs_rule_new (kind);

	switch (kind) {
	case FS_RULE_INBOUND_FORWARD:
		rule->service = g_strdup (n_tokens > 0 ? tokens[0] : NULL);
		rule->port    = g_strdup (n_tokens > 1 ? tokens[1] : NULL);
		rule->to      = g_strdup (n_tokens > 2 ? tokens[2] : NULL);
		rule->to_port = g_strdup (n_tokens > 3 ? tokens[3] : NULL);
		rule->comment = g_strdup (n_tokens > 4 ? tokens[4] : NULL);
		break;

	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		rule->service = g_strdup (n_tokens > 0 ? tokens[0] : NULL);
		rule->port    = g_strdup (n_tokens > 1 ? tokens[1] : NULL);
		rule->target  = g_strdup (n_tokens > 2 ? tokens[2] : NULL);
		rule->comment = g_strdup (n_tokens > 3 ? tokens[3] : NULL);
		break;

	default:
		rule->target  = g_strdup (n_tokens > 0 ? tokens[0] : NULL);
		rule->comment = g_strdup (n_tokens > 1 ? tokens[1] : NULL);
		break;
	}

	g_strfreev (tokens);

	return rule;
}

FsPolicy *
fs_policy_new (void)
{
	FsPolicy *policy = g_new0 (FsPolicy, 1);

	for (gint i = 0; i < FS_RULE_N_KINDS; i++)
		policy->kinds[i] = g_ptr_array_new_with_free_func (
			(GDestroyNotify) fs_rule_free);

	return policy;
}

void
fs_policy_clear (FsPolicy *policy)
{
	if (policy == NULL)
		return;

	for (gint i = 0; i < FS_RULE_N_KINDS; i++)
		g_ptr_array_set_size (policy->kinds[i], 0);
}

void
fs_policy_free (FsPolicy *policy)
{
	if (policy == NULL)
		return;

	fs_policy_clear (policy);

	for (gint i = 0; i < FS_RULE_N_KINDS; i++)
		g_ptr_array_unref (policy->kinds[i]);

	g_free (policy);
}

gchar *
fs_rule_kind_path (FsRuleKind kind)
{
	switch (kind) {
	case FS_RULE_INBOUND_ALLOW_FROM:
		return g_strdup ("inbound/allow-from");
	case FS_RULE_INBOUND_ALLOW_SERVICE:
		return g_strdup ("inbound/allow-service");
	case FS_RULE_INBOUND_FORWARD:
		return g_strdup ("inbound/forward");
	case FS_RULE_OUTBOUND_ALLOW_TO:
		return g_strdup ("outbound/allow-to");
	case FS_RULE_OUTBOUND_ALLOW_FROM:
		return g_strdup ("outbound/allow-from");
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
		return g_strdup ("outbound/allow-service");
	case FS_RULE_OUTBOUND_DENY_TO:
		return g_strdup ("outbound/deny-to");
	case FS_RULE_OUTBOUND_DENY_FROM:
		return g_strdup ("outbound/deny-from");
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		return g_strdup ("outbound/deny-service");
	default:
		return NULL;
	}
}

/* [ rule_fields_sane ]
 * F-1: reject rows whose host or port fields cannot name a real host
 * or port, before the row ever reaches netsh's own parser.  An empty
 * field means "any" and is legitimate; a present-but-bad value is
 * not.  Unknown kinds validate their target field as a host. */
static gboolean
sane_host_field (const gchar *host)
{
	return (host == NULL || *host == '\0' || fs_util_is_valid_host (host));
}

static gboolean
sane_port_field (const gchar *port)
{
	return (port == NULL || *port == '\0' || fs_util_is_valid_port (port));
}

static gboolean
rule_fields_sane (const FsRule *rule)
{
	switch (rule->kind) {
	case FS_RULE_INBOUND_FORWARD:
		return sane_port_field (rule->port) &&
		       sane_host_field (rule->to) &&
		       sane_port_field (rule->to_port);

	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		return sane_port_field (rule->port) &&
		       sane_host_field (rule->target);

	default:
		return sane_host_field (rule->target);
	}
}

gboolean
fs_policy_load (FsPolicy *policy, gint *malformed)
{
	gint bad = 0;
	gboolean any = FALSE;

	if (policy == NULL)
		return FALSE;

	fs_policy_clear (policy);

	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++) {
		gchar *relative = fs_rule_kind_path ((FsRuleKind) kind);
		gchar *path = fs_util_rules_path (relative);
		gchar *contents = NULL;
		gchar **lines;
		gsize length = 0;

		if (path == NULL)
			continue;

		if (!g_file_get_contents (path, &contents, &length, NULL)) {
			/* No rules of this kind yet: fine. */
			g_free (path);
			g_free (relative);
			continue;
		}

		any = TRUE;
		lines = g_strsplit (contents, "\n", -1);

		for (gint i = 0; lines[i] != NULL; i++) {
			FsRule *rule;
			gchar *line = g_strstrip (lines[i]);

			if (*line == '\0' || *line == '#')
				continue;

			rule = fs_rule_from_csv ((FsRuleKind) kind, line);

			if (rule == NULL) {
				g_printerr ("Malformed rule in %s: %s\n", relative, line);
				bad++;
				continue;
			}

			/* F-1: a row that cannot name a valid host or port is
			 * rejected here, not handed to netsh to fail on later. */
			if (!rule_fields_sane (rule)) {
				g_printerr ("Invalid host/port in %s: %s\n",
				            relative, line);
				fs_rule_free (rule);
				bad++;
				continue;
			}

			g_ptr_array_add (policy->kinds[kind], rule);
		}

		g_strfreev (lines);
		g_free (contents);
		g_free (path);
		g_free (relative);
	}

	if (malformed != NULL)
		*malformed = bad;

	return any;
}

gboolean
fs_policy_save (FsPolicy *policy)
{
	gboolean ok = TRUE;

	if (policy == NULL)
		return FALSE;

	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++) {
		gchar *relative = fs_rule_kind_path ((FsRuleKind) kind);
		gchar *path;
		GString *out;

		if (relative == NULL)
			continue;

		path = fs_util_rules_path (relative);

		if (path == NULL) {
			g_free (relative);
			continue;
		}

		out = g_string_new (NULL);

		for (guint i = 0; i < policy->kinds[kind]->len; i++) {
			FsRule *rule = g_ptr_array_index (policy->kinds[kind], i);
			gchar *csv = fs_rule_to_csv (rule);

			/* Skip rows that carry no information at all: every
			 * field empty gives a row of just separators. */
			if (csv != NULL && strspn (csv, ", ") < strlen (csv)) {
				g_string_append (out, csv);
				g_string_append_c (out, '\n');
			}

			g_free (csv);
		}

		if (!fs_util_ensure_parent_dir (path))
			ok = FALSE;

		if (g_file_set_contents (path, out->str, out->len, NULL) != TRUE)
			ok = FALSE;

		g_string_free (out, TRUE);
		g_free (path);
		g_free (relative);
	}

	return ok;
}

/* [ fs_policy_add ]
 * Stores a *copy*; the caller keeps ownership of the rule it passed in.
 * That way a rule built by a dialog can be inspected or discarded
 * without the store taking it away. */
void
fs_policy_add (FsPolicy *policy, FsRule *rule)
{
	if (policy == NULL || rule == NULL)
		return;

	if (rule->kind < 0 || rule->kind >= FS_RULE_N_KINDS)
		return;

	g_ptr_array_add (policy->kinds[rule->kind], fs_rule_copy (rule));
}

/* [ fs_policy_add_persist ]
 * Add a copy of the rule and save; if the write fails the copy comes
 * back out, so the store and the disk never disagree about what the
 * policy is. */
gboolean
fs_policy_add_persist (FsPolicy *policy, FsRule *rule)
{
	if (policy == NULL || rule == NULL)
		return FALSE;

	if (fs_policy_contains (policy, rule))
		return FALSE;

	fs_policy_add (policy, rule);

	if (!fs_policy_save (policy)) {
		fs_policy_remove (policy, rule);
		return FALSE;
	}

	return TRUE;
}

/* [ fs_rule_counterpart_kind ] */
FsRuleKind
fs_rule_counterpart_kind (FsRuleKind kind)
{
	switch (kind) {
	case FS_RULE_OUTBOUND_ALLOW_TO:
		return FS_RULE_INBOUND_ALLOW_FROM;
	case FS_RULE_INBOUND_ALLOW_FROM:
		return FS_RULE_OUTBOUND_ALLOW_TO;
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
		return FS_RULE_INBOUND_ALLOW_SERVICE;
	case FS_RULE_INBOUND_ALLOW_SERVICE:
		return FS_RULE_OUTBOUND_ALLOW_SERVICE;
	default:
		/* Deny kinds have no inbound twin -- the policy has no
		 * inbound-deny kind, because inbound is default-deny
		 * already -- the forward points one way, and
		 * OUTBOUND_ALLOW_FROM would need an INBOUND_ALLOW_TO that
		 * does not exist. */
		return FS_RULE_N_KINDS;
	}
}

/* [ fs_rule_counterpart ] */
FsRule *
fs_rule_counterpart (const FsRule *rule)
{
	FsRuleKind kind;
	FsRule *copy;

	if (rule == NULL)
		return NULL;

	kind = fs_rule_counterpart_kind (rule->kind);
	if (kind == FS_RULE_N_KINDS)
		return NULL;

	/* The paired kinds share their fields (host: target+comment,
	 * service: service+port+target+comment), so the twin is the same
	 * row under the other kind. */
	copy = fs_rule_copy (rule);
	copy->kind = kind;

	return copy;
}

/* [ fs_rule_direction_label ]
 * What the Direction setting's first entry says for this kind, or
 * NULL when the kind has no twin and the setting has nothing to
 * choose. */
const gchar *
fs_rule_direction_label (FsRuleKind kind)
{
	if (fs_rule_counterpart_kind (kind) == FS_RULE_N_KINDS)
		return NULL;

	switch (kind) {
	case FS_RULE_INBOUND_ALLOW_FROM:
	case FS_RULE_INBOUND_ALLOW_SERVICE:
		return _("Inbound only");
	default:
		return _("Outbound only");
	}
}

/* [ fs_policy_add_persist_pair ]
 * The bi-directional add: stage both copies, save once, and take both
 * back out together when the write fails, so a pair is either fully
 * stored or not there at all. */
gboolean
fs_policy_add_persist_pair (FsPolicy *policy, FsRule *rule,
                            FsRule *counterpart)
{
	if (counterpart == NULL)
		return fs_policy_add_persist (policy, rule);

	if (policy == NULL || rule == NULL)
		return FALSE;

	/* A stored primary is refused the same way add_persist refuses
	 * it: nothing changes. */
	if (fs_policy_contains (policy, rule))
		return FALSE;

	/* The twin already stored: writing the other half completes the
	 * intent (both directions present) on its own. */
	if (fs_policy_contains (policy, counterpart))
		return fs_policy_add_persist (policy, rule);

	fs_policy_add (policy, rule);
	fs_policy_add (policy, counterpart);

	if (!fs_policy_save (policy)) {
		fs_policy_remove (policy, rule);
		fs_policy_remove (policy, counterpart);
		return FALSE;
	}

	return TRUE;
}

/* [ fs_policy_remove_persist ]
 * Remove the matching rule and save; if the write fails the rule is
 * re-added, because a removal that did not reach disk must not look
 * like it did. */
gboolean
fs_policy_remove_persist (FsPolicy *policy, FsRule *rule)
{
	if (policy == NULL || rule == NULL)
		return FALSE;

	if (!fs_policy_remove (policy, rule))
		return FALSE;

	if (!fs_policy_save (policy)) {
		fs_policy_add (policy, rule);
		return FALSE;
	}

	return TRUE;
}

/* [ fs_policy_remove ]
 * Drops the first stored rule whose CSV form matches, and frees the
 * copy the store held.  Returns FALSE when nothing matched. */
gboolean
fs_policy_remove (FsPolicy *policy, FsRule *rule)
{
	gchar *needle;

	if (policy == NULL || rule == NULL)
		return FALSE;

	if (rule->kind < 0 || rule->kind >= FS_RULE_N_KINDS)
		return FALSE;

	/* Rules are identified by their CSV form. */
	needle = fs_rule_to_csv (rule);

	for (guint i = 0; i < policy->kinds[rule->kind]->len; i++) {
		FsRule *candidate = g_ptr_array_index (policy->kinds[rule->kind], i);
		gchar *csv = fs_rule_to_csv (candidate);

		if (g_strcmp0 (csv, needle) == 0) {
			g_free (csv);
			g_free (needle);
			g_ptr_array_remove_index (policy->kinds[rule->kind], i);
			return TRUE;
		}

		g_free (csv);
	}

	g_free (needle);

	return FALSE;
}

/* [ fs_policy_contains ]
 * TRUE when an identical row is already stored.  Rules are identified
 * the same way fs_policy_remove identifies them: by their CSV form.
 * Callers use this to avoid stacking duplicates, e.g. when a suggestion
 * is applied more than once. */
gboolean
fs_policy_contains (const FsPolicy *policy, const FsRule *rule)
{
	gchar *needle;
	gboolean found = FALSE;

	if (policy == NULL || rule == NULL)
		return FALSE;

	if (rule->kind < 0 || rule->kind >= FS_RULE_N_KINDS)
		return FALSE;

	needle = fs_rule_to_csv (rule);

	for (guint i = 0; i < policy->kinds[rule->kind]->len; i++) {
		const FsRule *candidate =
			g_ptr_array_index (policy->kinds[rule->kind], i);
		gchar *csv = fs_rule_to_csv (candidate);

		if (g_strcmp0 (csv, needle) == 0)
			found = TRUE;

		g_free (csv);

		if (found)
			break;
	}

	g_free (needle);

	return found;
}

void
fs_policy_install_defaults (FsPolicy *policy)
{
	FsRule *rule;

	if (policy == NULL)
		return;

	fs_policy_clear (policy);

	/* A sensible starting point: DHCP and DNS out, nothing inbound
	 * beyond loopback.  The user is expected to open this up. */
	rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_SERVICE);
	rule->service = g_strdup (_("DHCP"));
	rule->port    = g_strdup ("67-68");
	rule->target  = g_strdup (FS_TARGET_ANY);
	fs_policy_add (policy, rule);
	fs_rule_free (rule);

	rule = fs_rule_new (FS_RULE_OUTBOUND_ALLOW_SERVICE);
	rule->service = g_strdup (_("DNS"));
	rule->port    = g_strdup ("53");
	rule->target  = g_strdup (FS_TARGET_ANY);
	fs_policy_add (policy, rule);
	fs_rule_free (rule);
}

guint
fs_policy_count (const FsPolicy *policy, FsRuleKind kind)
{
	if (policy == NULL || kind < 0 || kind >= FS_RULE_N_KINDS)
		return 0;

	return policy->kinds[kind]->len;
}