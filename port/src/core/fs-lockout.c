/*---[ fs-lockout.c ]----------------------------------------------------
 * The lockout guard (see fs-lockout.h).
 *--------------------------------------------------------------------*/
#include "core/fs-lockout.h"
#include "core/fs-hostnet.h"
#include "core/fs-netparse.h"

#include <stdlib.h>
#include <string.h>

static void
pair_free (FsLockoutPair *pair)
{
	if (pair == NULL)
		return;
	g_free (pair->peer);
	g_free (pair->reason);
	g_free (pair->rule);
	g_free (pair);
}

/* [ verdict_rank ] -- BLOCKED is worse than DEPENDS is worse than
 * ALLOWED; an error counts as DEPENDS (not known to be safe). */
static gint
verdict_rank (FsWhatIfVerdict v)
{
	switch (v) {
	case FS_WHATIF_ALLOWED: return 0;
	case FS_WHATIF_BLOCKED: return 2;
	default:                return 1;
	}
}

/* [ peer_texts ] -- every address of every range, appended to `out'
 * until it holds `cap'; an address `skip' contains is left out.  The
 * set is normalized, so two peers next to each other (10.0.0.5 and
 * 10.0.0.6) are one range: each address in it is a peer of its own,
 * not only the first.  Returns how many addresses (not in `skip') did
 * not fit, saturating at G_MAXUINT. */
static guint
peer_texts (GPtrArray *out, const FsRangeSet *peers, const FsRangeSet *skip,
            guint cap)
{
	guint64 total = 0, taken = 0;

	if (peers == NULL)
		return 0;
	/* How many addresses there are, so the report can say how many
	 * were not asked about. */
	for (guint i = 0; peers->v4 != NULL && i < peers->v4->len; i++) {
		FsRange4 r = g_array_index (peers->v4, FsRange4, i);

		total += (guint64) r.end - r.start + 1;
	}
	for (guint i = 0; peers->v6 != NULL && i < peers->v6->len; i++) {
		FsRange6 r = g_array_index (peers->v6, FsRange6, i);

		total += r.end.hi != r.start.hi || r.end.lo - r.start.lo >= G_MAXUINT
		         ? G_MAXUINT : r.end.lo - r.start.lo + 1;
	}
	for (guint i = 0; i < out->len; i++)
		if (fs_range_set_contains_text (peers, g_ptr_array_index (out, i)))
			total = total > 0 ? total - 1 : 0;

	for (guint i = 0; peers->v4 != NULL && i < peers->v4->len &&
	                  out->len < cap; i++) {
		FsRange4 r = g_array_index (peers->v4, FsRange4, i);
		guint32 a = r.start;

		for (;;) {
			gchar *text = g_strdup_printf ("%u.%u.%u.%u",
			                               (a >> 24) & 0xff,
			                               (a >> 16) & 0xff,
			                               (a >> 8) & 0xff, a & 0xff);

			if (skip != NULL && fs_range_set_contains_text (skip, text)) {
				g_free (text);
			} else {
				g_ptr_array_add (out, text);
				taken++;
			}
			if (a >= r.end || out->len >= cap)
				break;
			a++;
		}
	}
	for (guint i = 0; peers->v6 != NULL && i < peers->v6->len &&
	                  out->len < cap; i++) {
		FsRange6 r = g_array_index (peers->v6, FsRange6, i);
		FsRange6 one;

		one.start = r.start;
		for (;;) {
			gchar *text;

			one.end = one.start;
			text = fs_range6_to_string (&one);
			if (skip != NULL && fs_range_set_contains_text (skip, text)) {
				g_free (text);
			} else {
				g_ptr_array_add (out, text);
				taken++;
			}
			if ((one.start.hi == r.end.hi &&
			     one.start.lo == r.end.lo) || out->len >= cap)
				break;
			if (++one.start.lo == 0)
				one.start.hi++;
		}
	}
	return (guint) MIN (total > taken ? total - taken : 0, G_MAXUINT);
}

FsLockoutReport *
fs_lockout_check (const FsPolicy *policy, const FsSettings *settings,
                  const FsRangeSet *peers, const GArray *ports)
{
	return fs_lockout_check_own (policy, settings, NULL, peers, ports);
}

FsLockoutReport *
fs_lockout_check_own (const FsPolicy *policy, const FsSettings *settings,
                      const FsRangeSet *own, const FsRangeSet *peers,
                      const GArray *ports)
{
	FsLockoutReport *report = g_new0 (FsLockoutReport, 1);
	GPtrArray *texts = g_ptr_array_new_with_free_func (g_free);
	guint n_own;
	FsWhatIfContext *ctx;

	/* The session's own peers first, outside the cap (there are one
	 * or two); then the others up to the cap, the own ones not twice. */
	peer_texts (texts, own, NULL, FS_LOCKOUT_MAX_PEERS);
	n_own = texts->len;
	report->skipped = peer_texts (texts, peers, own,
	                              n_own + FS_LOCKOUT_MAX_PEERS);

	report->pairs = g_ptr_array_new_with_free_func (
		(GDestroyNotify) pair_free);
	report->verdict = FS_WHATIF_ALLOWED;

	if (texts->len == 0 || ports == NULL || ports->len == 0) {
		report->why_not = "not an SSH session";
		g_ptr_array_unref (texts);
		return report;
	}

	report->checked = TRUE;
	ctx = fs_whatif_context_new (fs_whatif_native_platform (), policy,
	                             settings);
	/* The policy about to be applied, so: running. */
	ctx->firewall = FS_WHATIF_FW_RUNNING;

	for (guint p = 0; p < texts->len; p++) {
		for (guint k = 0; k < ports->len; k++) {
			guint port = g_array_index (ports, guint16, k);
			gchar *line;
			FsWhatIfResult *r;
			FsLockoutPair *pair;

			if (port == 0)
				continue;
			line = g_strdup_printf ("inbound tcp port %u from %s",
			                        port,
			                        (const gchar *) g_ptr_array_index (
			                        	texts, p));
			r = fs_whatif_simulate_text (ctx, line);
			g_free (line);

			pair = g_new0 (FsLockoutPair, 1);
			pair->peer = g_strdup (g_ptr_array_index (texts, p));
			pair->port = port;
			pair->verdict = r->verdict == FS_WHATIF_ERROR
			              ? FS_WHATIF_DEPENDS : r->verdict;
			pair->policy_kind = -1;
			pair->policy_index = -1;
			pair->own = p < n_own;
			if (r->answers != NULL && r->answers->len > 0) {
				const FsWhatIfAnswer *a =
					g_ptr_array_index (r->answers, 0);

				pair->reason = g_strdup (a->reason);
				pair->rule = g_strdup (a->rule);
				pair->policy_kind = a->policy_kind;
				pair->policy_index = a->policy_index;
			} else {
				pair->reason = g_strdup (r->error != NULL
				                         ? r->error : r->summary);
			}
			fs_whatif_result_free (r);

			if (report->worst == NULL ||
			    verdict_rank (pair->verdict) >
			    verdict_rank (report->verdict)) {
				report->verdict = pair->verdict;
				report->worst = pair;
			}
			g_ptr_array_add (report->pairs, pair);
		}
	}

	fs_whatif_context_free (ctx);
	g_ptr_array_unref (texts);
	if (report->pairs->len == 0) {
		report->checked = FALSE;
		report->why_not = "not an SSH session";
	}
	return report;
}

gboolean
fs_lockout_report_cuts (const FsLockoutReport *report)
{
	return report != NULL && report->checked &&
	       report->verdict != FS_WHATIF_ALLOWED;
}

void
fs_lockout_report_free (FsLockoutReport *report)
{
	if (report == NULL)
		return;
	g_ptr_array_unref (report->pairs);
	g_free (report);
}

guint
fs_lockout_env_port (const gchar *ssh_connection)
{
	gchar **words;
	guint port = 0;

	if (ssh_connection == NULL)
		return 0;
	words = g_strsplit_set (ssh_connection, " \t", -1);
	{
		/* "client cport server sport", empty words skipped. */
		guint n = 0;

		for (guint i = 0; words[i] != NULL; i++) {
			gchar *end = NULL;
			guint64 v;

			if (*words[i] == '\0')
				continue;
			if (n++ != 3)
				continue;
			v = g_ascii_strtoull (words[i], &end, 10);
			if (end != NULL && *end == '\0' && v > 0 && v <= 65535)
				port = (guint) v;
		}
	}
	g_strfreev (words);
	return port;
}

static void
add_port (GArray *ports, guint port)
{
	guint16 p = (guint16) port;

	if (port == 0 || port > 65535)
		return;
	for (guint i = 0; i < ports->len; i++)
		if (g_array_index (ports, guint16, i) == p)
			return;
	g_array_append_val (ports, p);
}

void
fs_lockout_sessions (FsRangeSet **own, FsRangeSet **peers, GArray **ports)
{
	FsHostNet *host = fs_hostnet_read (NULL);
	GArray *out = g_array_new (FALSE, FALSE, sizeof (guint16));

#ifdef G_OS_WIN32
	/* Windows keeps SSH and Remote Desktop sessions (fs-hostnet.c). */
	add_port (out, 22);
	add_port (out, 3389);
#else
	{
		GArray *listen = fs_hostnet_ssh_listen_ports ();

		for (guint i = 0; listen != NULL && i < listen->len; i++)
			add_port (out, g_array_index (listen, guint16, i));
		if (listen != NULL)
			g_array_unref (listen);
		if (out->len == 0)
			add_port (out, 22);
	}
#endif
	add_port (out, fs_lockout_env_port (g_getenv ("SSH_CONNECTION")));

	*own = fs_hostnet_own_ssh_peers (out);
	*peers = fs_range_set_copy (host->sessions);
	fs_range_set_union (*peers, *own);
	fs_range_set_normalize (*peers);
	*ports = out;
	fs_hostnet_free (host);
}
