/*---[ fs-rules.c ]-----------------------------------------------------
 * The traffic policy rule store.
 *--------------------------------------------------------------------*/

#include "core/fs-rules.h"
#include "core/fs-util.h"
#include "core/fs-i18n.h"
#include "core/fs-service.h"

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

/* [ port_problem ] -- why a present port field is no port, or NULL. */
static gchar *
port_problem (const gchar *port)
{
	if (port == NULL || *port == '\0' || fs_util_is_valid_port (port))
		return NULL;

	/* All digits: a number, only too big. */
	if (strspn (port, "0123456789") == strlen (port))
		return g_strdup_printf ("port \"%s\" is out of range (1-65535)",
		                        port);
	return g_strdup_printf ("port \"%s\" is not a port or a range "
	                        "(1-65535, or A:B)", port);
}

static gchar *
host_problem (const gchar *host)
{
	if (sane_host_field (host))
		return NULL;
	return g_strdup_printf ("host \"%s\" is not an address, network or "
	                        "name", host);
}

/* Exported: the apply gate's journal rows get the same F-1 gate the
 * policy files get, so a tampered rollback target can never name a
 * host or port the live policy would have refused.  The journal uses
 * this check only, not the service rule of fs_rule_problem: a row a
 * 1.0.7 apply wrote stays readable, so `stockfw start' at boot still
 * finds what was live (master plan Q6). */
gboolean
fs_rule_addresses_sane (const FsRule *rule)
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

static gboolean
kind_is_service (FsRuleKind kind)
{
	return kind == FS_RULE_INBOUND_ALLOW_SERVICE ||
	       kind == FS_RULE_OUTBOUND_ALLOW_SERVICE ||
	       kind == FS_RULE_OUTBOUND_DENY_SERVICE;
}

/* [ fs_rule_problem ] */
gchar *
fs_rule_problem (const FsRule *rule)
{
	gchar *why;

	if (rule == NULL)
		return g_strdup ("no rule");

	switch (rule->kind) {
	case FS_RULE_INBOUND_FORWARD:
		if ((why = port_problem (rule->port)) != NULL ||
		    (why = host_problem (rule->to)) != NULL ||
		    (why = port_problem (rule->to_port)) != NULL)
			return why;
		return NULL;

	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		if ((why = port_problem (rule->port)) != NULL ||
		    (why = host_problem (rule->target)) != NULL)
			return why;
		/* No port: the generator writes nothing for the row
		 * (fs-script.c skips it), so it is only a rule when the
		 * name is a service that brings its own ports. */
		if ((rule->port == NULL || *rule->port == '\0') &&
		    fs_service_find (rule->service) == NULL)
			return g_strdup_printf (
				"no port, and \"%s\" is not a known service",
				rule->service != NULL ? rule->service : "");
		return NULL;

	default:
		return host_problem (rule->target);
	}
}

gboolean
fs_rule_fields_sane (const FsRule *rule)
{
	gchar *why = fs_rule_problem (rule);
	gboolean ok = (why == NULL);

	g_free (why);
	return ok;
}

/* [ field_list ] -- "NAME, PORT, FOR" for a kind's fields. */
static const gchar *
field_list (FsRuleKind kind)
{
	switch (kind) {
	case FS_RULE_INBOUND_FORWARD:
		return "NAME, FIREWALL-PORT, TO, PORT";
	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		return "NAME, PORT, FOR";
	default:
		return "HOST";
	}
}

/* [ line_problem ]
 * Why one line of a rule file is not a rule, or NULL when it is one
 * (*rule_out then holds it). */
static gchar *
line_problem (FsRuleKind kind, const gchar *line, FsRule **rule_out)
{
	FsRule *rule;
	gchar *why;

	*rule_out = NULL;
	rule = fs_rule_from_csv (kind, line);
	if (rule == NULL)
		return g_strdup_printf ("too many fields (expected %s, then a "
		                        "comment)", field_list (kind));

	/* A service or forward line with no comma at all is text, not a
	 * row: "garbage line without commas" would read as a service
	 * named that.  A bare known service name ("SSH") is still a row. */
	if ((kind_is_service (kind) || kind == FS_RULE_INBOUND_FORWARD) &&
	    strchr (line, ',') == NULL &&
	    (kind == FS_RULE_INBOUND_FORWARD ||
	     fs_service_find (rule->service) == NULL)) {
		fs_rule_free (rule);
		return g_strdup_printf ("expected %s (no commas)",
		                        field_list (kind));
	}

	why = fs_rule_problem (rule);
	if (why != NULL) {
		fs_rule_free (rule);
		return why;
	}
	*rule_out = rule;
	return NULL;
}

void
fs_policy_problem_free (FsPolicyProblem *problem)
{
	if (problem == NULL)
		return;
	g_free (problem->file);
	g_free (problem->text);
	g_free (problem->reason);
	g_free (problem);
}

gboolean
fs_policy_load_report (FsPolicy *policy, GPtrArray **problems)
{
	gboolean any = FALSE;

	if (problems != NULL)
		*problems = g_ptr_array_new_with_free_func (
			(GDestroyNotify) fs_policy_problem_free);
	if (policy == NULL)
		return FALSE;

	fs_policy_clear (policy);

	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++) {
		gchar *relative = fs_rule_kind_path ((FsRuleKind) kind);
		gchar *path = fs_util_rules_path (relative);
		gchar *contents = NULL;
		gchar **lines;
		gsize length = 0;

		if (path == NULL) {
			g_free (relative);
			continue;
		}

		if (!g_file_get_contents (path, &contents, &length, NULL)) {
			/* No rules of this kind yet: fine. */
			g_free (path);
			g_free (relative);
			continue;
		}

		any = TRUE;
		lines = g_strsplit (contents, "\n", -1);

		for (gint i = 0; lines[i] != NULL; i++) {
			FsRule *rule = NULL;
			gchar *line = g_strstrip (lines[i]);
			gchar *why;

			if (*line == '\0' || *line == '#')
				continue;

			/* F-1 and the service rule: a row that cannot name a
			 * valid host, port or service is rejected here, not
			 * handed to the firewall to fail on (or skip) later. */
			why = line_problem ((FsRuleKind) kind, line, &rule);
			if (why != NULL) {
				if (problems != NULL) {
					FsPolicyProblem *p = g_new0 (FsPolicyProblem, 1);

					p->file = g_strdup (relative);
					p->line = (guint) i + 1;
					p->text = g_strdup (line);
					p->reason = why;
					g_ptr_array_add (*problems, p);
				} else {
					g_free (why);
				}
				continue;
			}

			g_ptr_array_add (policy->kinds[kind], rule);
		}

		g_strfreev (lines);
		g_free (contents);
		g_free (path);
		g_free (relative);
	}

	return any;
}

/* [ fs_policy_load ]
 * The report, with each problem printed on stderr the way the desktop
 * app always printed them (for its log). */
gboolean
fs_policy_load (FsPolicy *policy, gint *malformed)
{
	GPtrArray *problems = NULL;
	gboolean any = fs_policy_load_report (policy, &problems);

	for (guint i = 0; i < problems->len; i++) {
		const FsPolicyProblem *p = g_ptr_array_index (problems, i);

		g_printerr ("Malformed rule in %s:%u: %s (%s)\n", p->file,
		            p->line, p->text, p->reason);
	}
	if (malformed != NULL)
		*malformed = (gint) problems->len;
	g_ptr_array_unref (problems);
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

/* [ fs_rule_coverage ] -- see fs-rules.h. */
FsFamily
fs_rule_coverage (const FsRule *rule, gboolean names_resolved,
                  gchar **detail)
{
	const gchar *target;
	FsFamily fam;
	gchar *text = NULL;

	if (rule == NULL) {
		if (detail != NULL)
			*detail = NULL;
		return FS_FAMILY_NONE;
	}

	target = (rule->kind == FS_RULE_INBOUND_FORWARD) ? rule->to
	                                                 : rule->target;
	fam = fs_util_target_families (target);

	if (rule->kind == FS_RULE_INBOUND_FORWARD) {
		if (target == NULL || *target == '\0') {
			fam = FS_FAMILY_NONE;
			text = g_strdup (_("A forward needs a destination address."));
		} else if (fam == FS_FAMILY_IPV4 || fam == FS_FAMILY_IPV6) {
			if (strchr (target, '/') != NULL) {
				fam = FS_FAMILY_NONE;
				text = g_strdup_printf (_("A forward goes to one address, "
				                          "not a range like %s; it is "
				                          "left out when applied."),
				                        target);
			} else {
				text = g_strdup_printf (_("Forwarded to %s, an %s "
				                          "address."), target,
				                        fam == FS_FAMILY_IPV4 ? "IPv4"
				                                              : "IPv6");
			}
		} else {
			fam = FS_FAMILY_NONE;
			text = g_strdup_printf (_("A forward needs an IP address, not "
			                          "\"%s\"; it is left out when "
			                          "applied."), target);
		}
	} else if (fs_util_target_is_anyone (target)) {
		text = g_strdup (_("Anyone: the rule applies to IPv4 and IPv6."));
	} else if (fam == FS_FAMILY_IPV4) {
		text = g_strdup_printf (strchr (target, '/') != NULL
			? _("%s is an IPv4 range, so the rule covers IPv4 only. "
			    "Add a second rule for the IPv6 range if there is one.")
			: _("%s is an IPv4 address, so the rule covers IPv4 only. "
			    "Add a second rule for the host's IPv6 address if it "
			    "has one."), target);
	} else if (fam == FS_FAMILY_IPV6) {
		text = g_strdup_printf (strchr (target, '/') != NULL
			? _("%s is an IPv6 range, so the rule covers IPv6 only.")
			: _("%s is an IPv6 address, so the rule covers IPv6 only."),
			target);
	} else if (fam == FS_FAMILY_BOTH) {
		if (names_resolved) {
			text = g_strdup_printf (_("%s is a name. It is looked up "
			                          "each time the policy is applied, "
			                          "and the rule covers every IPv4 "
			                          "and IPv6 address it has then."),
			                        target);
		} else {
			fam = FS_FAMILY_NONE;
			text = g_strdup_printf (_("%s is a name, and Windows "
			                          "Firewall takes addresses only. "
			                          "Use the host's IP address."),
			                        target);
		}
	} else {
		text = g_strdup_printf (_("\"%s\" is not an address or host "
		                          "name; the rule is left out when "
		                          "applied."), target);
	}

	if (detail != NULL)
		*detail = text;
	else
		g_free (text);

	return fam;
}
