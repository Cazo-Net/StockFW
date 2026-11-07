/*---[ fs-rules.c ]-----------------------------------------------------
 * The traffic policy rule store.
 *--------------------------------------------------------------------*/

#include "core/fs-rules.h"
#include "core/fs-util.h"
#include "core/fs-i18n.h"
#include "core/fs-service.h"

#include <string.h>
#ifndef G_OS_WIN32
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

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
	rule->enabled = TRUE;

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
	copy->enabled = rule->enabled;

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
			gboolean enabled = TRUE;

			if (*line == '\0')
				continue;

			/* A plain comment line. */
			if (*line == '#' && !g_str_has_prefix (line, "#off:"))
				continue;

			/* A rule that is switched off: #off: + the CSV row. */
			if (g_str_has_prefix (line, "#off:")) {
				enabled = FALSE;
				line = g_strstrip (line + 5);  /* skip "#off:" */
			}

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

			rule->enabled = enabled;
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
	FsPolicyLock *lock;

	if (policy == NULL)
		return FALSE;

	/* T15: a row whose fields would change shape on the way back in
	 * (a comma is a field boundary, a line break a row boundary) is
	 * never written, and neither is anything else: every file stays
	 * as it was. */
	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++)
		for (guint i = 0; i < policy->kinds[kind]->len; i++)
			if (!fs_rule_validate (g_ptr_array_index (policy->kinds[kind],
			                                          i), NULL))
				return FALSE;

	lock = fs_policy_lock (NULL);
	if (lock == NULL)
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
				/* A rule that is switched off: write #off: + the CSV. */
				if (!rule->enabled)
					g_string_append (out, "#off:");

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

	fs_policy_unlock (lock);
	return ok;
}

/* [ policy_exchange_kind ] -- stable names for the portable exchange
 * format. Keep this table independent of the control layer: core must
 * remain usable by the desktop app and its tests. */
static const gchar * const policy_exchange_kinds[FS_RULE_N_KINDS] = {
	"inbound-allow-from", "inbound-allow-service", "inbound-forward",
	"outbound-allow-to", "outbound-allow-from", "outbound-allow-service",
	"outbound-deny-to", "outbound-deny-from", "outbound-deny-service"
};

static gint
policy_exchange_kind (const gchar *name)
{
	for (gint i = 0; i < FS_RULE_N_KINDS; i++)
		if (g_strcmp0 (name, policy_exchange_kinds[i]) == 0)
			return i;
	return -1;
}

gchar *
fs_policy_export_text (const FsPolicy *policy, GError **error)
{
	GString *out;

	if (policy == NULL) {
		g_set_error_literal (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID,
		                     "no policy to export");
		return NULL;
	}
	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < policy->kinds[k]->len; i++)
			if (!fs_rule_validate (g_ptr_array_index (policy->kinds[k], i), error))
				return NULL;

	out = g_string_new ("# StockFW policy export v1\n");
	for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
		for (guint i = 0; i < policy->kinds[k]->len; i++) {
			FsRule *rule = g_ptr_array_index (policy->kinds[k], i);
			gchar *csv = fs_rule_to_csv (rule);

			g_string_append_printf (out, "%s\t%s\t%s\n",
			                        policy_exchange_kinds[k],
			                        rule->enabled ? "on" : "off", csv);
			g_free (csv);
		}
	}
	return g_string_free (out, FALSE);
}

static void
policy_import_problem (GPtrArray *problems, guint line, const gchar *text,
                       const gchar *reason)
{
	FsPolicyProblem *p = g_new0 (FsPolicyProblem, 1);
	p->file = g_strdup ("policy-export");
	p->line = line;
	p->text = g_strdup (text);
	p->reason = g_strdup (reason);
	g_ptr_array_add (problems, p);
}

FsPolicy *
fs_policy_import_parse (const gchar *text, GPtrArray **problems, GError **error)
{
	FsPolicy *policy = fs_policy_new ();
	GPtrArray *bad = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_policy_problem_free);
	gchar **lines;

	if (problems != NULL)
		*problems = bad;
	if (text == NULL) {
		g_set_error_literal (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID,
		                     "no policy text");
		if (problems == NULL) g_ptr_array_unref (bad);
		fs_policy_free (policy);
		return NULL;
	}
	lines = g_strsplit (text, "\n", -1);
	for (guint n = 0; lines[n] != NULL; n++) {
		gchar *line = g_strstrip (lines[n]);
		gchar **fields;
		gint kind;
		FsRule *rule;
		gchar *why;

		if (*line == '\0' || *line == '#')
			continue;
		fields = g_strsplit (line, "\t", 3);
		if (g_strv_length (fields) != 3 ||
		    (kind = policy_exchange_kind (fields[0])) < 0 ||
		    (strcmp (fields[1], "on") != 0 && strcmp (fields[1], "off") != 0)) {
			policy_import_problem (bad, n + 1, line,
			                       "expected KIND<TAB>on|off<TAB>CSV");
			g_strfreev (fields);
			continue;
		}
		rule = fs_rule_from_csv ((FsRuleKind) kind, fields[2]);
		why = rule == NULL ? g_strdup ("invalid CSV fields")
		                   : fs_rule_problem (rule);
		if (why == NULL && !fs_rule_validate (rule, NULL))
			why = g_strdup ("a field contains a comma, line break or invalid prefix");
		if (why != NULL || rule == NULL) {
			policy_import_problem (bad, n + 1, line, why);
			g_free (why);
			fs_rule_free (rule);
			g_strfreev (fields);
			continue;
		}
		rule->enabled = strcmp (fields[1], "on") == 0;
		fs_policy_add (policy, rule);
		fs_rule_free (rule);
		g_strfreev (fields);
	}
	g_strfreev (lines);
	if (problems == NULL) {
		if (bad->len > 0) {
			g_set_error (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID,
			             "policy export contains %u invalid line%s", bad->len,
			             bad->len == 1 ? "" : "s");
			g_ptr_array_unref (bad);
			fs_policy_free (policy);
			return NULL;
		}
		g_ptr_array_unref (bad);
	}
	return policy;
}

gboolean
fs_policy_has_rule (const FsPolicy *policy, const FsRule *rule)
{
	return fs_policy_contains (policy, rule);
}

gboolean
fs_policy_merge (FsPolicy *destination, const FsPolicy *source,
                 gboolean replace, guint *added, guint *duplicates,
                 GError **error)
{
	guint a = 0, d = 0;
	FsPolicy *copy;

	if (destination == NULL || source == NULL) {
		g_set_error_literal (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID,
		                     "no policy to merge");
		return FALSE;
	}
	copy = fs_policy_new ();
	if (!replace) {
		for (gint k = 0; k < FS_RULE_N_KINDS; k++)
			for (guint i = 0; i < destination->kinds[k]->len; i++)
				fs_policy_add (copy, g_ptr_array_index (destination->kinds[k], i));
	}
	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < source->kinds[k]->len; i++) {
			FsRule *rule = g_ptr_array_index (source->kinds[k], i);
			gchar *why;
			if (!fs_rule_validate (rule, error)) {
				fs_policy_free (copy);
				return FALSE;
			}
			why = fs_rule_problem (rule);
			if (why != NULL) {
				g_set_error (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID,
				             "not a valid imported rule: %s", why);
				g_free (why);
				fs_policy_free (copy);
				return FALSE;
			}
			if (fs_policy_contains (copy, rule)) { d++; continue; }
			fs_policy_add (copy, rule); a++;
		}
	fs_policy_clear (destination);
	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < copy->kinds[k]->len; i++)
			fs_policy_add (destination, g_ptr_array_index (copy->kinds[k], i));
	fs_policy_free (copy);
	if (added != NULL) *added = a;
	if (duplicates != NULL) *duplicates = d;
	return TRUE;
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

/* =====================================================================
 * Validation, the policy lock and edit in place (PR 3)
 * ===================================================================== */

GQuark
fs_rules_error_quark (void)
{
	return g_quark_from_static_string ("stockfw-rules-error");
}

/* [ fs_rule_validate ] */
gboolean
fs_rule_validate (const FsRule *rule, GError **error)
{
	const gchar *fields[6];

	if (rule == NULL || rule->kind < 0 || rule->kind >= FS_RULE_N_KINDS) {
		g_set_error_literal (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID,
		                     "not a rule");
		return FALSE;
	}

	fields[0] = rule->service;
	fields[1] = rule->port;
	fields[2] = rule->target;
	fields[3] = rule->to;
	fields[4] = rule->to_port;
	fields[5] = rule->comment;

	/* The policy files are comma-separated with no quoting: a comma
	 * inside a field would silently become a field boundary, and a
	 * line break a new row nobody typed. */
	for (guint i = 0; i < G_N_ELEMENTS (fields); i++) {
		if (fields[i] != NULL && strpbrk (fields[i], ",\n\r") != NULL) {
			g_set_error (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID,
			             "a field may not contain a comma or a line "
			             "break: \"%s\"", fields[i]);
			return FALSE;
		}
	}

	/* The row's first field starts the line: one that starts with '#'
	 * (after blanks, which the loader strips) would read back as a
	 * comment, and the rule would be gone. */
	{
		const gchar *first;

		switch (rule->kind) {
		case FS_RULE_INBOUND_FORWARD:
		case FS_RULE_INBOUND_ALLOW_SERVICE:
		case FS_RULE_OUTBOUND_ALLOW_SERVICE:
		case FS_RULE_OUTBOUND_DENY_SERVICE:
			first = rule->service;
			break;
		default:
			first = rule->target;
			break;
		}
		while (first != NULL && g_ascii_isspace (*first))
			first++;
		if (first != NULL && *first == '#') {
			g_set_error (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID,
			             "the first field may not start with '#' (the "
			             "line would read back as a comment): \"%s\"",
			             first);
			return FALSE;
		}
	}

	return TRUE;
}

/* [ the policy lock ]
 * One writer at a time.  On Linux: flock on <run>/apply.lock (the
 * directory created 0750 if absent), then on <rules_dir>/.lock, always
 * in that order.  Re-entrant within the process (a depth counter under
 * a recursive mutex): a flock taken twice through two descriptors
 * would wait for itself.  Windows: the mutex alone. */
struct _FsPolicyLock
{
	guint depth_at;
};

static GRecMutex policy_mutex;
static guint     policy_depth = 0;
#ifndef G_OS_WIN32
static int       policy_fd_apply = -1;
static int       policy_fd_rules = -1;
#endif

gchar *
fs_policy_run_dir (void)
{
	const gchar *env = g_getenv ("STOCKFW_RUN_DIR");

	if (env != NULL && *env != '\0')
		return g_strdup (env);
	return g_strdup ("/run/stockfw");
}

#ifndef G_OS_WIN32
/* [ lock_take ]
 * Open (creating) and flock `path'.  -2: skipped, because this account
 * may not create it; an account that cannot open the lock cannot write
 * what it guards either, and root is never skipped.  -1: failed, with
 * *error set. */
static int
lock_take (const gchar *path, GError **error)
{
	int fd = open (path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);

	if (fd < 0) {
		int e = errno;

		if (geteuid () != 0 &&
		    (e == EACCES || e == EPERM || e == EROFS || e == ENOENT))
			return -2;
		g_set_error (error, FS_RULES_ERROR, FS_RULES_ERR_LOCK,
		             "cannot open the lock %s: %s", path,
		             g_strerror (e));
		return -1;
	}

	while (flock (fd, LOCK_EX) != 0) {
		int e = errno;

		if (e == EINTR)
			continue;
		close (fd);
		g_set_error (error, FS_RULES_ERROR, FS_RULES_ERR_LOCK,
		             "cannot lock %s: %s", path, g_strerror (e));
		return -1;
	}

	return fd;
}

/* [ lock_files ] -- both flocks, in order; FALSE with *error set. */
static gboolean
lock_files (GError **error)
{
	gchar *run = fs_policy_run_dir ();
	gchar *apply = g_build_filename (run, "apply.lock", NULL);
	gchar *rules = fs_util_rules_path (".lock");
	gboolean ok = FALSE;
	int fd;

	/* The run directory: 0750, root's when root makes it (tmpfiles
	 * makes it at boot from PR 7 on). */
	if (g_mkdir_with_parents (run, 0750) != 0 && geteuid () == 0) {
		g_set_error (error, FS_RULES_ERROR, FS_RULES_ERR_LOCK,
		             "cannot create %s: %s", run, g_strerror (errno));
		goto out;
	}
	fd = lock_take (apply, error);
	if (fd == -1)
		goto out;
	policy_fd_apply = fd;

	/* No rules directory: nothing there to guard, and apply.lock
	 * already orders every writer.  It is not made just for the lock:
	 * a start or an apply (the gate takes the lock too) must not
	 * create an empty policy folder where there was none. */
	if (rules != NULL && !g_file_test (fs_util_rules_dir (),
	                                   G_FILE_TEST_IS_DIR)) {
		g_free (rules);
		rules = NULL;
	}
	if (rules != NULL) {
		if (!fs_util_ensure_parent_dir (rules) && geteuid () == 0) {
			g_set_error (error, FS_RULES_ERROR, FS_RULES_ERR_LOCK,
			             "cannot create the rules directory %s",
			             fs_util_rules_dir ());
			fd = -1;
		} else {
			fd = lock_take (rules, error);
		}
		if (fd == -1) {
			if (policy_fd_apply >= 0)
				close (policy_fd_apply);
			policy_fd_apply = -1;
			goto out;
		}
		policy_fd_rules = fd;
	}
	ok = TRUE;

out:
	g_free (rules);
	g_free (apply);
	g_free (run);
	return ok;
}
#endif

FsPolicyLock *
fs_policy_lock (GError **error)
{
	FsPolicyLock *lock;

	g_rec_mutex_lock (&policy_mutex);

#ifndef G_OS_WIN32
	if (policy_depth == 0 && !lock_files (error)) {
		g_rec_mutex_unlock (&policy_mutex);
		return NULL;
	}
#else
	(void) error;
#endif

	lock = g_new0 (FsPolicyLock, 1);
	lock->depth_at = ++policy_depth;
	return lock;
}

void
fs_policy_unlock (FsPolicyLock *lock)
{
	if (lock == NULL)
		return;

	g_warn_if_fail (lock->depth_at == policy_depth);
	g_free (lock);

	if (policy_depth > 0 && --policy_depth == 0) {
#ifndef G_OS_WIN32
		/* Closing releases the flock: rules first, the reverse of
		 * the order they were taken in. */
		if (policy_fd_rules >= 0)
			close (policy_fd_rules);
		if (policy_fd_apply >= 0)
			close (policy_fd_apply);
		policy_fd_rules = -1;
		policy_fd_apply = -1;
#endif
	}

	g_rec_mutex_unlock (&policy_mutex);
}

/* [ fs_policy_replace_persist ] */
gboolean
fs_policy_replace_persist (FsPolicy *policy, const FsRule *old,
                           const FsRule *rule, GError **error)
{
	return fs_policy_replace_nth_persist (policy, -1, old, rule, error);
}

/* [ fs_policy_replace_nth_persist ] */
gboolean
fs_policy_replace_nth_persist (FsPolicy *policy, gint nth, const FsRule *old,
                               const FsRule *rule, GError **error)
{
	GPtrArray *rows;
	gchar *needle, *want, *why;
	gint at = -1;
	gboolean twice = FALSE;
	FsRule *was;
	FsPolicyLock *lock;

	if (policy == NULL || old == NULL || rule == NULL ||
	    old->kind < 0 || old->kind >= FS_RULE_N_KINDS) {
		g_set_error_literal (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID,
		                     "nothing to replace");
		return FALSE;
	}
	if (rule->kind != old->kind) {
		g_set_error_literal (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID,
		                     "an edit keeps the rule's kind");
		return FALSE;
	}
	if (!fs_rule_validate (rule, error))
		return FALSE;
	why = fs_rule_problem (rule);
	if (why != NULL) {
		g_set_error (error, FS_RULES_ERROR, FS_RULES_ERR_INVALID,
		             "not a valid rule: %s", why);
		g_free (why);
		return FALSE;
	}

	rows = policy->kinds[old->kind];
	needle = fs_rule_to_csv (old);
	want = fs_rule_to_csv (rule);
	/* A row named by its number is that row, never an identical one
	 * before it: a hand-edited file can hold the same row twice. */
	for (guint i = 0; i < rows->len; i++) {
		gchar *csv = fs_rule_to_csv (g_ptr_array_index (rows, i));

		if (at < 0 && (nth < 0 || (guint) nth == i) &&
		    g_strcmp0 (csv, needle) == 0)
			at = (gint) i;
		else if (g_strcmp0 (csv, want) == 0)
			twice = TRUE;
		g_free (csv);
	}
	g_free (needle);
	g_free (want);

	if (at < 0) {
		g_set_error_literal (error, FS_RULES_ERROR, FS_RULES_ERR_NOT_FOUND,
		                     "the rule is no longer in the policy");
		return FALSE;
	}
	if (twice) {
		g_set_error_literal (error, FS_RULES_ERROR, FS_RULES_ERR_DUPLICATE,
		                     "the policy already holds that rule");
		return FALSE;
	}

	lock = fs_policy_lock (error);
	if (lock == NULL)
		return FALSE;

	/* In place, so the row keeps its number; one save. */
	was = g_ptr_array_index (rows, at);
	rows->pdata[at] = fs_rule_copy (rule);

	if (!fs_policy_save (policy)) {
		fs_rule_free (rows->pdata[at]);
		rows->pdata[at] = was;
		fs_policy_unlock (lock);
		g_set_error (error, FS_RULES_ERROR, FS_RULES_ERR_SAVE,
		             "could not save the policy in %s",
		             fs_util_rules_dir ());
		return FALSE;
	}

	fs_policy_unlock (lock);
	fs_rule_free (was);
	return TRUE;
}
/*---[ fs-rules-enabled.c ]----------------------------------------------
 * Rule enable/disable support: fs_policy_active_view and
 * fs_policy_set_enabled, which belong in fs-rules.c but are kept
 * separate during development to make the patch cleaner.
 *--------------------------------------------------------------------*/

#include "core/fs-rules.h"
#include <string.h>

/* [ fs_policy_active_view ]
 * A view of the policy containing only enabled rules.  Every engine
 * that decides or writes (generators, What-If, health, journal, impact)
 * reads this, never the raw policy. */
FsPolicy *
fs_policy_active_view (const FsPolicy *policy)
{
	FsPolicy *view;

	if (policy == NULL)
		return NULL;

	view = fs_policy_new ();

	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++) {
		for (guint i = 0; i < policy->kinds[kind]->len; i++) {
			FsRule *rule = g_ptr_array_index (policy->kinds[kind], i);

			if (rule->enabled)
				g_ptr_array_add (view->kinds[kind], fs_rule_copy (rule));
		}
	}

	return view;
}

/* [ fs_policy_set_enabled ]
 * Enable or disable a rule.  The rule must already be in the policy.
 * Returns TRUE and persists the change, or FALSE when the rule is not
 * found or the save fails (the policy is unchanged in that case). */
gboolean
fs_policy_set_enabled (FsPolicy *policy, const FsRule *rule, gboolean enabled)
{
	FsRule *stored;
	gboolean was_enabled;
	gchar *csv;

	if (policy == NULL || rule == NULL)
		return FALSE;

	if (rule->kind < 0 || rule->kind >= FS_RULE_N_KINDS)
		return FALSE;

	/* Find the rule by its CSV form (same matching as fs_policy_remove). */
	csv = fs_rule_to_csv (rule);
	stored = NULL;

	for (guint i = 0; i < policy->kinds[rule->kind]->len; i++) {
		FsRule *r = g_ptr_array_index (policy->kinds[rule->kind], i);
		gchar *r_csv = fs_rule_to_csv (r);

		if (g_strcmp0 (csv, r_csv) == 0) {
			stored = r;
			g_free (r_csv);
			break;
		}
		g_free (r_csv);
	}

	g_free (csv);

	if (stored == NULL)
		return FALSE;

	/* Already in the desired state: success. */
	if (stored->enabled == enabled)
		return TRUE;

	/* Change state and persist; roll back if save fails. */
	was_enabled = stored->enabled;
	stored->enabled = enabled;

	if (!fs_policy_save (policy)) {
		stored->enabled = was_enabled;
		return FALSE;
	}

	return TRUE;
}
