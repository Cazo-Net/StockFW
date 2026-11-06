/* The Overview's verdict as a golden table (PR 3, B3).
 *
 * One table, run twice: by tests/test-pr3-core.c against
 * fs_verdict_compute (core, what `stockfw status' prints on line 1),
 * and by tests/ui-verdict-smoke.c against the desktop app's Overview
 * card (ui/fs-statusview.c update_overview), the rows the window can
 * be given (`gui').  The smoke also checks the two give the same
 * title, word, level and body for each of those rows, so the terminal
 * and the window cannot drift apart while both exist.
 *
 * Each row: the inputs, then the answer.  `in_body' must occur in the
 * body; `body', when set, is the whole body.
 */
#ifndef STOCKFW_VERDICT_GOLDEN_H
#define STOCKFW_VERDICT_GOLDEN_H

#include <glib.h>
#include <string.h>
#include "core/fs-backend.h"
#include "core/fs-verdict.h"

typedef struct
{
	/* inputs */
	FsFirewallState state;
	gboolean        usable;     /* backend->available ()             */
	gboolean        v6_known;   /* the backend has an ipv6_state slot */
	FsIpv6State     v6;
	const gchar    *v6_detail;
	const gchar    *hold;       /* the terminal's audit-only hold     */
	gboolean        gui;        /* the window can be given these      */
	/* answer */
	FsVerdictLevel  level;
	const gchar    *key;
	const gchar    *word;
	const gchar    *title;
	const gchar    *in_body;
	const gchar    *body;       /* NULL: only in_body is checked      */
} VerdictGolden;

static const VerdictGolden verdict_golden[] = {
	{ FS_FW_STOPPED, TRUE, TRUE, FS_IPV6_FILTERED, NULL, NULL, TRUE,
	  FS_VERDICT_LEVEL_BAD, "stopped", "Not protected",
	  "This computer is not protected", "The firewall is stopped",
	  "The firewall is stopped, so no traffic is filtered. Start it to "
	  "put your policy in force." },
	{ FS_FW_NONE, FALSE, FALSE, FS_IPV6_UNKNOWN, NULL, NULL, TRUE,
	  FS_VERDICT_LEVEL_UNKNOWN, "unknown", "State unknown",
	  "The firewall's state is unknown", "not available to this account",
	  "StockFW could not read the firewall's state. The firewall tools "
	  "are not available to this account." },
	{ FS_FW_NONE, TRUE, TRUE, FS_IPV6_FILTERED, NULL, NULL, TRUE,
	  FS_VERDICT_LEVEL_UNKNOWN, "unknown", "State unknown",
	  "The firewall's state is unknown", "could not read",
	  "StockFW could not read the firewall's state." },
	{ FS_FW_RUNNING, TRUE, TRUE, FS_IPV6_FILTERED, NULL, NULL, TRUE,
	  FS_VERDICT_LEVEL_OK, "protected", "Protected",
	  "This computer is protected", "IPv4 and IPv6",
	  "Your policy is in force for IPv4 and IPv6." },
	{ FS_FW_RUNNING, TRUE, TRUE, FS_IPV6_ABSENT, NULL, NULL, TRUE,
	  FS_VERDICT_LEVEL_OK, "protected", "Protected",
	  "This computer is protected", "has no IPv6", NULL },
	{ FS_FW_RUNNING, TRUE, TRUE, FS_IPV6_UNFILTERED,
	  "ip6tables has no StockFW chains.", NULL, TRUE,
	  FS_VERDICT_LEVEL_WARN, "ipv6-unprotected", "IPv6 not protected",
	  "IPv6 is not protected", "IPv6 traffic passes unfiltered.",
	  "IPv4 is filtered, but IPv6 traffic passes unfiltered. ip6tables "
	  "has no StockFW chains." },
	{ FS_FW_RUNNING, TRUE, TRUE, FS_IPV6_UNKNOWN, NULL, NULL, TRUE,
	  FS_VERDICT_LEVEL_OK, "running", "Running",
	  "The firewall is running", "could not check", NULL },
	{ FS_FW_RUNNING, TRUE, TRUE, FS_IPV6_UNKNOWN,
	  "ip6tables could not be read.", NULL, TRUE,
	  FS_VERDICT_LEVEL_OK, "running", "Running",
	  "The firewall is running", "ip6tables could not be read.",
	  "ip6tables could not be read." },
	/* No IPv6 slot (Windows Firewall filters both with every rule). */
	{ FS_FW_RUNNING, TRUE, FALSE, FS_IPV6_UNFILTERED, NULL, NULL, TRUE,
	  FS_VERDICT_LEVEL_OK, "protected", "Protected",
	  "This computer is protected", "IPv4 and IPv6", NULL },
	{ FS_FW_LOCKED, TRUE, TRUE, FS_IPV6_FILTERED, NULL, NULL, TRUE,
	  FS_VERDICT_LEVEL_OK, "protected", "Protected",
	  "This computer is protected", "Policy changes are locked.",
	  "Your policy is in force for IPv4 and IPv6. Policy changes are "
	  "locked." },
	{ FS_FW_HIT, TRUE, TRUE, FS_IPV6_FILTERED, NULL, NULL, TRUE,
	  FS_VERDICT_LEVEL_OK, "protected", "Protected",
	  "This computer is protected", "IPv4 and IPv6", NULL },
	/* The terminal only: audit-only holds changes (B2). */
	{ FS_FW_RUNNING, TRUE, TRUE, FS_IPV6_FILTERED, NULL,
	  "audit-only mode", FALSE,
	  FS_VERDICT_LEVEL_OK, "protected", "Protected",
	  "This computer is protected",
	  "Policy changes are held: audit-only mode.",
	  "Your policy is in force for IPv4 and IPv6. Policy changes are "
	  "held: audit-only mode." },
	{ FS_FW_STOPPED, TRUE, TRUE, FS_IPV6_FILTERED, NULL,
	  "audit-only mode", FALSE,
	  FS_VERDICT_LEVEL_BAD, "stopped", "Not protected",
	  "This computer is not protected", "The firewall is stopped", NULL },
};

/* The row's inputs as fs_verdict_compute takes them. */
static inline void
verdict_golden_input (const VerdictGolden *row, FsVerdictInput *in)
{
	memset (in, 0, sizeof *in);
	in->state = row->state;
	in->backend_usable = row->usable;
	in->ipv6_known = row->v6_known;
	in->ipv6 = row->v6;
	in->ipv6_detail = row->v6_detail;
	in->hold_reason = row->hold;
	in->display_name = "test firewall";
}

/* The row's answer, checked; NULL when it holds, else what differs
 * (g_free). */
static inline gchar *
verdict_golden_mismatch (const VerdictGolden *row, FsVerdictLevel level,
                         const gchar *key, const gchar *word,
                         const gchar *title, const gchar *body)
{
	if (level != row->level)
		return g_strdup_printf ("level %s, wanted %s",
		                        fs_verdict_level_name (level),
		                        fs_verdict_level_name (row->level));
	if (key != NULL && g_strcmp0 (key, row->key) != 0)
		return g_strdup_printf ("key %s, wanted %s", key, row->key);
	if (g_strcmp0 (word, row->word) != 0)
		return g_strdup_printf ("word \"%s\", wanted \"%s\"", word,
		                        row->word);
	if (g_strcmp0 (title, row->title) != 0)
		return g_strdup_printf ("title \"%s\", wanted \"%s\"", title,
		                        row->title);
	if (body == NULL || strstr (body, row->in_body) == NULL ||
	    (row->body != NULL && strcmp (body, row->body) != 0))
		return g_strdup_printf ("body \"%s\"", body ? body : "(null)");
	return NULL;
}

#endif /* STOCKFW_VERDICT_GOLDEN_H */
