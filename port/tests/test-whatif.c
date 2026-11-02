/* The What-If engine (core/fs-whatif.c): the golden table.
 *
 * Built and run by tests/test-core.sh (and as the fs-whatif-test
 * target).  Pure GLib: no display, no firewall, no root.  What it pins:
 *
 *   1. the reading of a line: what was recognised, the confidence, and
 *      refusals instead of guesses (nothing recognisable, port 0 or
 *      above 65535, a bad address);
 *   2. the answers, for both firewall models, against small policies:
 *      first match on Linux, block-wins and per-profile defaults on
 *      Windows, CIDR blocks both ways, IPv6, ICMP types, DEPENDS with
 *      the split spelled out, both directions for a line without one,
 *      the user's verb, Sentinel's blocks, a stopped firewall,
 *      restrictive outbound, and what the answer assumed;
 *   3. the Linux model against the generator: fs_whatif_linux_chain_text
 *      must equal the INBOUND / OUTBOUND chains fs-script writes (both
 *      the "$IPT" text and the iptables-restore form the backend loads)
 *      for a table of policies and settings -- the model cannot drift
 *      from what is enforced without this failing;
 *   4. the fixes: every kind is offered where it should be and verified,
 *      a created row gives the verdict asked and changes nothing it does
 *      not name, the check runs again against a policy that changed,
 *      and no fix ever opens a port range, every port, or every
 *      protocol (a brute-force sweep over lines, policies and both
 *      platforms).
 */

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/fs-whatif.h"
#include "core/fs-fwrule.h"
#include "core/fs-backend.h"
#include "core/fs-netplace.h"

static int failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (!(cond)) {                                             \
		printf ("FAIL: ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
		failures++;                                         \
	} else {                                                  \
		printf ("ok:   ");                                \
		printf (__VA_ARGS__);                              \
		printf ("\n");                                     \
	}                                                         \
} while (0)

#define L FS_WHATIF_LINUX_FIRST_MATCH
#define W FS_WHATIF_WINDOWS_BLOCK_WINS

/* ================================================================
 * Fixtures
 * ================================================================ */

/* "kind:csv|kind:csv|..." -> a policy. */
static FsPolicy *
policy_of (const gchar *rows)
{
	FsPolicy *p = fs_policy_new ();
	gchar **v;

	if (rows == NULL)
		return p;

	v = g_strsplit (rows, "|", -1);
	for (guint i = 0; v[i] != NULL; i++) {
		gchar *colon = strchr (v[i], ':');
		FsRule *r;

		if (colon == NULL)
			continue;
		r = fs_rule_from_csv ((FsRuleKind) atoi (v[i]), colon + 1);
		if (r == NULL) {
			CHECK (FALSE, "fixture row parses: %s", v[i]);
			continue;
		}
		fs_policy_add (p, r);
		fs_rule_free (r);
	}
	g_strfreev (v);
	return p;
}

/* Whether a stripped line is one of v's (already stripped) lines. */
static gboolean
strv_has (gchar **v, const gchar *line)
{
	gchar *s = g_strstrip (g_strdup (line));
	gboolean found = FALSE;

	for (guint i = 0; v[i] != NULL && !found; i++)
		found = (strcmp (v[i], s) == 0);
	g_free (s);
	return found;
}

static gboolean
has_word (const gchar *words, const gchar *w)
{
	gchar **v;
	gboolean found = FALSE;

	if (words == NULL)
		return FALSE;
	v = g_strsplit (words, " ", -1);
	for (guint i = 0; v[i] != NULL && !found; i++)
		found = (strcmp (v[i], w) == 0);
	g_strfreev (v);
	return found;
}

/* Settings words: ext int nat restrictive noecho noreply nofilter
 * bcast noreserved reject nolog allicmp. */
static FsSettings *
settings_of (const gchar *words)
{
	FsSettings *s = fs_settings_new ();

	if (has_word (words, "ext"))
		s->ext_device = g_strdup ("eth0");
	if (has_word (words, "int"))
		s->int_device = g_strdup ("eth1");
	if (has_word (words, "nat"))
		s->nat = TRUE;
	if (has_word (words, "restrictive"))
		s->restrictive_outbound = TRUE;
	if (has_word (words, "noecho"))
		s->icmp_echo_request = FALSE;
	if (has_word (words, "noreply"))
		s->icmp_echo_reply = FALSE;
	if (has_word (words, "nofilter"))
		s->filter_icmp = FALSE;
	if (has_word (words, "bcast"))
		s->block_external_broadcast = s->block_internal_broadcast = TRUE;
	if (has_word (words, "noreserved"))
		s->block_non_routables = FALSE;
	if (has_word (words, "reject"))
		s->deny_packets = FALSE;
	if (has_word (words, "nolog"))
		s->log_allowed = FALSE;
	if (has_word (words, "allicmp"))
		s->icmp_timestamping = s->icmp_masking = s->icmp_redirection =
			s->icmp_source_quenches = TRUE;
	return s;
}

typedef struct
{
	FsPolicy        *policy;
	FsSettings      *settings;
	FsWhatIfContext *ctx;
} Env;

/* Environment words:
 *   stopped / unknown        the firewall's state (default: running)
 *   held stale failed nolive whether the saved policy is in force
 *                            (default: it is)
 *   sentinel=HOST            a Sentinel auto-block lifting in 7 minutes
 *   public / private / domain  the profile in use (Windows)
 *   public-off               the Public profile is switched off
 *   public-in-allow          Public's default inbound action is Allow
 *   all-defaults             every profile's defaults read: block in,
 *                            allow out
 *   out-block                every profile blocks outbound by default
 *   local=ADDR               an address of this computer */
static Env
env_new (FsWhatIfPlatform plat, const gchar *rows, const gchar *settings,
         const gchar *env)
{
	Env e;
	gchar **v;

	e.policy = policy_of (rows);
	e.settings = settings_of (settings);
	e.ctx = fs_whatif_context_new (plat, e.policy, e.settings);
	e.ctx->firewall = FS_WHATIF_FW_RUNNING;
	e.ctx->live = FS_WHATIF_LIVE_YES;
	e.ctx->now_unix = 1700000000;

	v = g_strsplit (env != NULL ? env : "", " ", -1);
	for (guint i = 0; v[i] != NULL; i++) {
		const gchar *w = v[i];

		if (strcmp (w, "stopped") == 0)
			e.ctx->firewall = FS_WHATIF_FW_STOPPED;
		else if (strcmp (w, "unknown") == 0)
			e.ctx->firewall = FS_WHATIF_FW_UNKNOWN;
		else if (strcmp (w, "held") == 0) {
			e.ctx->live = FS_WHATIF_LIVE_HELD;
			e.ctx->live_detail = g_strdup ("audit-only mode");
		} else if (strcmp (w, "stale") == 0)
			e.ctx->live = FS_WHATIF_LIVE_STALE;
		else if (strcmp (w, "failed") == 0)
			e.ctx->live = FS_WHATIF_LIVE_FAILED;
		else if (strcmp (w, "nolive") == 0)
			e.ctx->live = FS_WHATIF_LIVE_UNKNOWN;
		else if (g_str_has_prefix (w, "sentinel="))
			fs_whatif_context_add_auto_block (e.ctx, w + 9,
			                                  e.ctx->now_unix + 420);
		else if (g_str_has_prefix (w, "local="))
			fs_whatif_context_add_local_address (e.ctx, w + 6);
		else if (strcmp (w, "public") == 0)
			e.ctx->profiles_in_use |= FS_PROFILE_BIT (FS_PROFILE_PUBLIC);
		else if (strcmp (w, "private") == 0)
			e.ctx->profiles_in_use |= FS_PROFILE_BIT (FS_PROFILE_PRIVATE);
		else if (strcmp (w, "domain") == 0)
			e.ctx->profiles_in_use |= FS_PROFILE_BIT (FS_PROFILE_DOMAIN);
		else if (strcmp (w, "public-off") == 0)
			e.ctx->profile_enabled[FS_PROFILE_PUBLIC] = 0;
		else if (strcmp (w, "shields") == 0)
			e.ctx->block_all_inbound[FS_PROFILE_PUBLIC] = 1;
		else if (strcmp (w, "all-defaults") == 0 ||
		         strcmp (w, "public-in-allow") == 0 ||
		         strcmp (w, "out-block") == 0) {
			for (gint p = 0; p < 3; p++) {
				if (e.ctx->default_inbound[p] == FS_WHATIF_DEFAULT_UNKNOWN)
					e.ctx->default_inbound[p] = FS_WHATIF_DEFAULT_BLOCK;
				if (e.ctx->default_outbound[p] == FS_WHATIF_DEFAULT_UNKNOWN)
					e.ctx->default_outbound[p] = FS_WHATIF_DEFAULT_ALLOW;
			}
			if (strcmp (w, "public-in-allow") == 0)
				e.ctx->default_inbound[FS_PROFILE_PUBLIC] =
					FS_WHATIF_DEFAULT_ALLOW;
			if (strcmp (w, "out-block") == 0)
				for (gint p = 0; p < 3; p++)
					e.ctx->default_outbound[p] = FS_WHATIF_DEFAULT_BLOCK;
		}
	}
	g_strfreev (v);
	return e;
}

static void
env_free (Env *e)
{
	fs_whatif_context_free (e->ctx);
	fs_settings_free (e->settings);
	fs_policy_free (e->policy);
}

static FsWhatIfResult *
ask (FsWhatIfPlatform plat, const gchar *rows, const gchar *settings,
     const gchar *env, const gchar *line)
{
	Env e = env_new (plat, rows, settings, env);
	FsWhatIfResult *r = fs_whatif_simulate_text (e.ctx, line);

	env_free (&e);
	return r;
}

static const FsWhatIfAnswer *
answer (const FsWhatIfResult *r, guint i)
{
	return (r != NULL && r->answers != NULL && i < r->answers->len)
	       ? g_ptr_array_index (r->answers, i) : NULL;
}

static const FsWhatIfAction *
find_action (const FsWhatIfResult *r, FsWhatIfActionKind kind)
{
	for (guint i = 0; r != NULL && i < r->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

		for (guint k = 0; k < a->actions->len; k++) {
			const FsWhatIfAction *act = g_ptr_array_index (a->actions, k);

			if (act->kind == kind)
				return act;
		}
	}
	return NULL;
}

static gboolean
notes_have (const FsWhatIfResult *r, const gchar *needle)
{
	for (guint i = 0; r != NULL && i < r->notes->len; i++)
		if (strstr (g_ptr_array_index (r->notes, i), needle) != NULL)
			return TRUE;
	return FALSE;
}

static const gchar *
vname (FsWhatIfVerdict v)
{
	return fs_whatif_verdict_name (v);
}

/* ================================================================
 * 1. Reading a line
 * ================================================================ */

typedef struct
{
	const gchar       *line;
	gint               error;       /* FS_WHATIF_ERR_*, or 0          */
	FsWhatIfVerb       verb;
	FsWhatIfDirection  dir;
	FsWhatIfProto      proto;
	guint              port;
	const gchar       *host;
	const gchar       *icmp;
} ReadCase;

static void
test_reading (void)
{
	static const ReadCase cases[] = {
		{ "allow SSH from 192.168.1.50 on port 22", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 22, "192.168.1.50", NULL },
		{ "block DNS to 8.8.8.8 on port 53 udp", 0, FS_WHATIF_VERB_BLOCK,
		  FS_WHATIF_DIR_OUTBOUND, FS_WHATIF_PROTO_UDP, 53, "8.8.8.8", NULL },
		{ "allow HTTPS to 10.0.0.1", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_OUTBOUND, FS_WHATIF_PROTO_TCP, 443, "10.0.0.1", NULL },
		{ "outbound to 203.0.113.9:8443", 0, FS_WHATIF_VERB_NONE,
		  FS_WHATIF_DIR_OUTBOUND, FS_WHATIF_PROTO_ANY, 8443, "203.0.113.9",
		  NULL },
		{ "can [2001:db8::5]:443 reach me", 0, FS_WHATIF_VERB_NONE,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_ANY, 443, "2001:db8::5",
		  NULL },
		{ "inbound ssh from 2001:db8::/48", 0, FS_WHATIF_VERB_NONE,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 22, "2001:db8::/48",
		  NULL },
		{ "ssh is open at 22 port", 0, FS_WHATIF_VERB_NONE,
		  FS_WHATIF_DIR_BOTH, FS_WHATIF_PROTO_TCP, 22, NULL, NULL },
		{ "scan at 8080 port", 0, FS_WHATIF_VERB_NONE, FS_WHATIF_DIR_BOTH,
		  FS_WHATIF_PROTO_ANY, 8080, NULL, NULL },
		{ "allow anything to :22", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_BOTH, FS_WHATIF_PROTO_ANY, 22, NULL, NULL },
		{ "block local:22 inbound", 0, FS_WHATIF_VERB_BLOCK,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_ANY, 22, NULL, NULL },
		{ "allow RDP to 10.0.0.9", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_OUTBOUND, FS_WHATIF_PROTO_TCP, 3389, "10.0.0.9", NULL },
		{ "block ftp to 1.2.3.4", 0, FS_WHATIF_VERB_BLOCK,
		  FS_WHATIF_DIR_OUTBOUND, FS_WHATIF_PROTO_TCP, 21, "1.2.3.4", NULL },
		{ "block port 80 outbound", 0, FS_WHATIF_VERB_BLOCK,
		  FS_WHATIF_DIR_OUTBOUND, FS_WHATIF_PROTO_ANY, 80, NULL, NULL },
		{ "allow ping from 192.168.1.5", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_ICMP, 0, "192.168.1.5",
		  "echo-request" },
		{ "is 10.0.0.0/8 able to reach me on udp 161", 0, FS_WHATIF_VERB_NONE,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_UDP, 161, "10.0.0.0/8", NULL },
		{ "ssh", 0, FS_WHATIF_VERB_NONE, FS_WHATIF_DIR_BOTH,
		  FS_WHATIF_PROTO_TCP, 22, NULL, NULL },
		{ "block 8.8.8.8", 0, FS_WHATIF_VERB_BLOCK, FS_WHATIF_DIR_BOTH,
		  FS_WHATIF_PROTO_ANY, 0, "8.8.8.8", NULL },
		/* the What-If card's examples, read as the card shows them */
		{ "Can 192.168.1.50 reach my SSH?", 0, FS_WHATIF_VERB_NONE,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 22, "192.168.1.50",
		  NULL },
		{ "Is outbound DNS to 8.8.8.8 allowed?", 0, FS_WHATIF_VERB_NONE,
		  FS_WHATIF_DIR_OUTBOUND, FS_WHATIF_PROTO_ANY, 53, "8.8.8.8", NULL },
		/* "the internet" names the far side, not a host: inbound
		 * from any host, never both ways */
		{ "block RDP from the internet", 0, FS_WHATIF_VERB_BLOCK,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 3389, NULL, NULL },
		{ "allow https to anywhere", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_OUTBOUND, FS_WHATIF_PROTO_TCP, 443, NULL, NULL },
		{ "inbound ssh to the internet", 0, FS_WHATIF_VERB_NONE,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 22, NULL, NULL },
		/* refusals, never guesses */
		{ "", FS_WHATIF_ERR_EMPTY, 0, 0, 0, 0, NULL, NULL },
		{ "   ", FS_WHATIF_ERR_EMPTY, 0, 0, 0, 0, NULL, NULL },
		{ "hello there", FS_WHATIF_ERR_UNREADABLE, 0, 0, 0, 0, NULL, NULL },
		{ "zqxv gibberish", FS_WHATIF_ERR_UNREADABLE, 0, 0, 0, 0, NULL, NULL },
		{ "inbound tcp port 0", FS_WHATIF_ERR_BAD_PORT, 0, 0, 0, 0, NULL,
		  NULL },
		{ "inbound tcp port 70000", FS_WHATIF_ERR_BAD_PORT, 0, 0, 0, 0, NULL,
		  NULL },
		{ "outbound to 203.0.113.9:0", FS_WHATIF_ERR_BAD_PORT, 0, 0, 0, 0,
		  NULL, NULL },
		{ "inbound from 999.1.1.1", FS_WHATIF_ERR_BAD_HOST, 0, 0, 0, 0, NULL,
		  NULL },
		/* More than one port or host, or a host that cannot be read
		 * as one: refused, never answered for part of it. */
		{ "allow tcp 22-25 from 198.51.100.4", FS_WHATIF_ERR_BAD_PORT, 0, 0,
		  0, 0, NULL, NULL },
		{ "allow tcp 80 and 443 from 198.51.100.4", FS_WHATIF_ERR_BAD_PORT,
		  0, 0, 0, 0, NULL, NULL },
		{ "allow tcp 80,443 from 10.0.0.5", FS_WHATIF_ERR_BAD_PORT, 0, 0, 0,
		  0, NULL, NULL },
		{ "allow tcp 8080 from 10.0.0.5 and 10.0.0.6", FS_WHATIF_ERR_BAD_HOST,
		  0, 0, 0, 0, NULL, NULL },
		{ "allow ssh from 192.168.1.*", FS_WHATIF_ERR_BAD_HOST, 0, 0, 0, 0,
		  NULL, NULL },
		{ "allow ssh from fe80::1%eth0", FS_WHATIF_ERR_BAD_HOST, 0, 0, 0, 0,
		  NULL, NULL },
		{ "allow ssh from 10.0.0.0/abc", FS_WHATIF_ERR_BAD_HOST, 0, 0, 0, 0,
		  NULL, NULL },
		{ "allow tcp 443 from caf\xc3\xa9.example", FS_WHATIF_ERR_BAD_HOST,
		  0, 0, 0, 0, NULL, NULL },
		/* A request turned around is not guessed at; a question with
		 * "not" in it is still a question. */
		{ "don't allow ssh from 198.51.100.4", FS_WHATIF_ERR_UNREADABLE, 0,
		  0, 0, 0, NULL, NULL },
		{ "let nobody in on port 22", FS_WHATIF_ERR_UNREADABLE, 0, 0, 0, 0,
		  NULL, NULL },
		{ "block outbound to 198.51.100.4 except port 53",
		  FS_WHATIF_ERR_UNREADABLE, 0, 0, 0, 0, NULL, NULL },
		{ "block ssh from everyone but 10.0.0.5", FS_WHATIF_ERR_UNREADABLE,
		  0, 0, 0, 0, NULL, NULL },
		{ "is ssh from 198.51.100.4 not allowed?", 0, FS_WHATIF_VERB_NONE,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 22, "198.51.100.4",
		  NULL },
		/* Host names: not looked up, but still the far end -- the
		 * direction is read, and the service's name inside one is not
		 * a service. */
		{ "allow ssh from server.example.com", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 22, NULL, NULL },
		{ "allow tcp 8080 from ssh-gateway", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 8080, NULL, NULL },
		{ "allow sshd-host port 80", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_BOTH, FS_WHATIF_PROTO_ANY, 80, NULL, NULL },
		/* Numbers that are not ports: durations and counts. */
		{ "allow ssh from 192.168.1.20 for 10 minutes", 0,
		  FS_WHATIF_VERB_ALLOW, FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP,
		  22, "192.168.1.20", NULL },
		{ "allow ssh from 10.0.0.5 3 times", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 22, "10.0.0.5", NULL },
		{ "is port 022 open", 0, FS_WHATIF_VERB_NONE, FS_WHATIF_DIR_BOTH,
		  FS_WHATIF_PROTO_ANY, 22, NULL, NULL },
		/* Exposure and "my <service>" put this computer at the near
		 * end. */
		{ "expose tcp 8080 to the internet", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 8080, NULL, NULL },
		{ "open tcp port 22 to the local network", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 22, NULL, NULL },
		{ "can the internet reach my ssh", 0, FS_WHATIF_VERB_NONE,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 22, NULL, NULL },
		{ "allow ssh from this computer to 10.0.0.9", 0,
		  FS_WHATIF_VERB_ALLOW, FS_WHATIF_DIR_OUTBOUND, FS_WHATIF_PROTO_TCP,
		  22, "10.0.0.9", NULL },
		{ "let's allow ssh from 10.0.0.5", 0, FS_WHATIF_VERB_ALLOW,
		  FS_WHATIF_DIR_INBOUND, FS_WHATIF_PROTO_TCP, 22, "10.0.0.5", NULL },
	};

	for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
		const ReadCase *c = &cases[i];
		GError *error = NULL;
		FsWhatIfQuery *q = fs_whatif_parse (c->line, &error);

		if (c->error != 0) {
			CHECK (q == NULL && error != NULL && error->code == c->error,
			       "read: \"%s\" is refused (code %d, got %d: %s)", c->line,
			       c->error, error != NULL ? error->code : 0,
			       error != NULL ? error->message : "a query");
			fs_whatif_query_free (q);
			g_clear_error (&error);
			continue;
		}

		CHECK (q != NULL, "read: \"%s\" is read (%s)", c->line,
		       error != NULL ? error->message : "ok");
		if (q == NULL) {
			g_clear_error (&error);
			continue;
		}
		CHECK (q->verb == c->verb && q->direction == c->dir &&
		       q->protocol == c->proto && q->port == c->port &&
		       g_strcmp0 (q->host, c->host) == 0 &&
		       g_strcmp0 (q->icmp_type, c->icmp) == 0,
		       "read: \"%s\" -> verb %d dir %d proto %d port %u host %s "
		       "icmp %s", c->line, q->verb, q->direction, q->protocol,
		       q->port, q->host ? q->host : "-",
		       q->icmp_type ? q->icmp_type : "-");
		CHECK (q->pieces->len > 0 && q->confidence > 0.0 &&
		       q->confidence <= 1.0,
		       "read: \"%s\" lists what it recognised (%u pieces, "
		       "confidence %.2f)", c->line, q->pieces->len, q->confidence);
		fs_whatif_query_free (q);
	}

	/* The refusal names what it looked for. */
	{
		GError *error = NULL;

		fs_whatif_parse ("hello there", &error);
		CHECK (error != NULL &&
		       strstr (error->message, "I could not find a port, service, "
		                               "host or direction in") != NULL,
		       "read: an unreadable line says what it looked for (%s)",
		       error != NULL ? error->message : "no error");
		g_clear_error (&error);
	}

	/* A line with less in it is read with less confidence. */
	{
		FsWhatIfQuery *full = fs_whatif_parse (
			"allow inbound tcp port 22 from 10.0.0.1", NULL);
		FsWhatIfQuery *bare = fs_whatif_parse ("ssh is open at 22 port", NULL);

		CHECK (full != NULL && bare != NULL &&
		       full->confidence > bare->confidence,
		       "read: a complete line is read with more confidence than a "
		       "loose one (%.2f > %.2f)", full ? full->confidence : 0.0,
		       bare ? bare->confidence : 0.0);
		fs_whatif_query_free (full);
		fs_whatif_query_free (bare);
	}

	/* A host name is kept aside as unread, never as "any host". */
	{
		FsWhatIfQuery *q = fs_whatif_parse ("allow ssh from server.example.com",
		                                    NULL);

		CHECK (q != NULL && q->host == NULL &&
		       g_strcmp0 (q->host_unread, "server.example.com") == 0,
		       "read: a host name is set aside as unread");
		fs_whatif_query_free (q);
		q = fs_whatif_parse ("allow tcp port 443 from anyone", NULL);
		CHECK (q != NULL && q->host_any_said && q->host_unread == NULL,
		       "read: \"from anyone\" is said, not left open");
		fs_whatif_query_free (q);
		q = fs_whatif_parse ("allow tcp port 443", NULL);
		CHECK (q != NULL && !q->host_any_said,
		       "read: a line naming no host did not say \"anyone\"");
		fs_whatif_query_free (q);
	}

	/* "don't": the refusal quotes the word as typed. */
	{
		GError *error = NULL;

		fs_whatif_parse ("don't allow ssh from 198.51.100.4", &error);
		CHECK (error != NULL && strstr (error->message, "\"don't\"") != NULL,
		       "read: the refusal quotes \"don't\" whole (%s)",
		       error != NULL ? error->message : "no error");
		g_clear_error (&error);
	}

	/* An unreadable line answers ERROR, never a verdict. */
	{
		FsWhatIfResult *r = ask (L, NULL, NULL, NULL, "hello there");

		CHECK (r->verdict == FS_WHATIF_ERROR && r->answers->len == 0 &&
		       r->error != NULL && r->query == NULL,
		       "read: an unreadable line has no verdict at all");
		fs_whatif_result_free (r);
	}
}

/* ================================================================
 * 2. The golden table
 * ================================================================ */

#define NONE (-1)

typedef struct
{
	FsWhatIfPlatform plat;
	const gchar *rows;
	const gchar *settings;
	const gchar *env;
	const gchar *line;
	FsWhatIfVerdict verdict;     /* both directions together           */
	const gchar *says;           /* in the summary, or NULL            */
	gint action;                 /* an action kind that must be offered,
	                              * or NONE                             */
	gint never;                  /* an action kind that must NOT be, or
	                              * NONE                                */
} Golden;

/* Policies the table uses. */
#define P_SSH_LAN   "1:SSH,22,10.0.0.0/8,lan"
#define P_DENY      "6:203.0.113.9,known bad"
#define P_DENY_NET  "6:203.0.113.0/24,bad net"
#define P_MIX       "3:203.0.113.5,ok|6:203.0.113.5,bad"
#define P_SMTP      "8:SMTP,25,Anyone,no mail"
#define P_DNS_IN    "1:DNS,53,Anyone,dns"
#define P_DHCP_OUT  "5:DHCP,67-68,Anyone,dhcp"
#define P_FWD       "2:HTTP,8080,10.0.0.5,80,web"
#define P_GAME      "1:Game,7000-7010 7100,Anyone,game"
#define P_V6        "1:SSH,22,2001:db8::/32,v6 lan"
#define P_NAMED     "1:SSH,22,host.example,named"
#define P_SENT      "6:203.0.113.50,Sentinel: beaconing"
#define P_ANYONE_IN "0:Anyone,everything"
#define P_OUT_FROM  "4:192.168.1.20,laptop"
#define P_HTTPS_OUT "5:HTTPS,443,Anyone,web"

static const Golden golden[] = {
	/* --- defaults ------------------------------------------------- */
	{ L, NULL, NULL, NULL, "inbound ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, "default drops it", NONE, NONE },
	{ W, NULL, NULL, NULL, "inbound ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, "assumed", NONE, NONE },
	{ L, NULL, NULL, NULL, "outbound tcp to 198.51.100.4 port 443",
	  FS_WHATIF_ALLOWED, "allowed by default", NONE, NONE },
	{ W, NULL, NULL, "all-defaults", "outbound tcp to 198.51.100.4 port 443",
	  FS_WHATIF_ALLOWED, "default outbound action", NONE, NONE },
	{ L, NULL, "reject", NULL, "inbound tcp port 80 from 198.51.100.4",
	  FS_WHATIF_BLOCKED, "rejects it", NONE, NONE },

	/* --- a rule decides, CIDR both ways, IPv6 ---------------------- */
	{ L, P_SSH_LAN, NULL, NULL, "inbound ssh from 10.1.2.3",
	  FS_WHATIF_ALLOWED, "Allow SSH", NONE, NONE },
	{ W, P_SSH_LAN, NULL, "private", "inbound ssh from 10.1.2.3",
	  FS_WHATIF_ALLOWED, "Allow SSH", NONE, NONE },
	{ W, P_SSH_LAN, NULL, NULL, "inbound ssh from 10.1.2.3",
	  FS_WHATIF_DEPENDS, "Blocked on Public networks by the setting", NONE,
	  NONE },
	{ L, P_SSH_LAN, NULL, NULL, "inbound ssh from 10.20.0.0/16",
	  FS_WHATIF_ALLOWED, "Allow SSH", NONE, NONE },
	{ L, P_SSH_LAN, NULL, NULL, "inbound ssh from 8.0.0.0/6",
	  FS_WHATIF_DEPENDS, "10.0.0.0/8", NONE, NONE },
	{ L, P_SSH_LAN, NULL, NULL, "inbound ssh from 11.0.0.1",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	{ L, P_V6, NULL, NULL, "inbound ssh from 2001:db8::7",
	  FS_WHATIF_ALLOWED, "2001:db8::/32", NONE, NONE },
	{ L, P_V6, NULL, NULL, "inbound ssh from 2001:db8:1::/48",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },
	{ L, P_V6, NULL, NULL, "inbound ssh from 3fff::7",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	{ W, P_V6, NULL, NULL, "inbound ssh from 2001:db8::7",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },
	{ L, P_V6, NULL, NULL, "inbound ssh from 10.1.2.3",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },

	/* --- DEPENDS: what the line left open is answered for every case */
	{ L, P_SSH_LAN, NULL, NULL, "inbound ssh",
	  FS_WHATIF_DEPENDS, "Blocked for most hosts; allowed from 10.0.0.0/8",
	  NONE, NONE },
	{ W, P_SSH_LAN, NULL, "all-defaults", "inbound ssh",
	  FS_WHATIF_DEPENDS,
	  "Allowed from 10.0.0.0/8 on Private and Domain networks", NONE, NONE },
	{ L, P_DENY, NULL, NULL, "outbound tcp port 443",
	  FS_WHATIF_DEPENDS, "Allowed for most hosts; blocked to 203.0.113.9",
	  NONE, NONE },
	{ L, P_DENY, NULL, NULL, "block outbound",
	  FS_WHATIF_DEPENDS, "203.0.113.9", NONE, NONE },
	{ L, "1:mystery,22,192.168.1.50,x", NULL, NULL,
	  "inbound port 22 from 192.168.1.50",
	  FS_WHATIF_ALLOWED, "Allow mystery", NONE, NONE },
	{ L, "1:mystery,22,192.168.1.50,x", NULL, NULL,
	  "inbound port 80 from 192.168.1.50",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },

	/* --- both directions when the line names none ----------------- */
	{ L, P_SSH_LAN, NULL, NULL, "ssh",
	  FS_WHATIF_DEPENDS, "Outbound: ALLOWED", NONE, NONE },
	{ L, NULL, NULL, NULL, "ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	{ L, NULL, NULL, NULL, "https to 198.51.100.4",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },

	/* --- first match vs block wins -------------------------------- */
	{ W, P_MIX, NULL, NULL, "outbound tcp to 203.0.113.5 port 22",
	  FS_WHATIF_BLOCKED, "Block outbound", NONE, NONE },
	{ L, P_DENY, NULL, NULL, "outbound tcp to 203.0.113.9 port 443",
	  FS_WHATIF_BLOCKED, "Rule 'StockFW: Block outbound (203.0.113.9)'",
	  NONE, NONE },
	{ W, P_DENY, NULL, NULL, "outbound tcp to 203.0.113.9 port 443",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	{ L, P_DENY_NET, NULL, NULL, "outbound tcp to 203.0.113.77 port 80",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	{ L, P_DENY_NET, NULL, NULL, "outbound udp to 203.0.112.255 port 53",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },
	/* Linux accepts outbound ICMP before the deny rows; Windows blocks */
	{ L, P_DENY_NET, NULL, NULL, "outbound ping to 203.0.113.77",
	  FS_WHATIF_ALLOWED, "Outbound ICMP", NONE, NONE },
	{ W, P_DENY_NET, NULL, NULL, "outbound ping to 203.0.113.77",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	{ W, P_SMTP, NULL, NULL, "outbound tcp to 198.51.100.25 port 25",
	  FS_WHATIF_BLOCKED, "SMTP", NONE, NONE },
	{ W, P_SMTP, NULL, NULL, "outbound tcp to 198.51.100.25 port 587",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },
	{ L, P_SMTP, NULL, NULL, "outbound tcp to 198.51.100.25 port 25",
	  FS_WHATIF_BLOCKED, "SMTP", NONE, NONE },
	{ W, P_DNS_IN, NULL, NULL, "inbound udp port 53 from 203.0.113.5",
	  FS_WHATIF_ALLOWED, "(UDP)", NONE, NONE },
	{ W, P_DNS_IN, NULL, NULL, "inbound tcp port 3389 from 203.0.113.5",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	{ W, P_DHCP_OUT, NULL, "all-defaults out-block",
	  "outbound udp port 68 to 203.0.113.5",
	  FS_WHATIF_ALLOWED, "DHCP", NONE, NONE },
	{ W, P_DHCP_OUT, NULL, "all-defaults out-block",
	  "outbound tcp port 67 to 203.0.113.5",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	/* Windows opens a service with its own protocols; Linux opens a
	 * service row's port for TCP and UDP both. */
	{ W, P_SSH_LAN, NULL, NULL, "inbound udp port 22 from 10.1.2.3",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	{ L, P_SSH_LAN, NULL, NULL, "inbound udp port 22 from 10.1.2.3",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },
	/* Port lists: Windows reads them, Linux leaves the row out. */
	{ W, P_GAME, NULL, NULL, "inbound udp port 7005 from 203.0.113.5",
	  FS_WHATIF_ALLOWED, "Game", NONE, NONE },
	{ W, P_GAME, NULL, NULL, "inbound udp port 7011 from 203.0.113.5",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	{ W, P_GAME, NULL, NULL, "inbound udp port 7100 from 203.0.113.5",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },
	{ L, P_GAME, NULL, NULL, "inbound udp port 7005 from 203.0.113.5",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	/* "Allow from Anyone": Linux accepts everything; Windows writes no
	 * rule for it. */
	{ L, P_ANYONE_IN, NULL, NULL, "inbound tcp port 3389 from 198.51.100.4",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },
	/* A forward lets its port in and says where it goes -- through the
	 * external device's DNAT; with no external device it reaches
	 * nothing.  Outside router mode StockFW never turns IP forwarding
	 * on, so a forward to another computer depends on whether something
	 * else did. */
	{ L, P_FWD, "ext int nat", NULL,
	  "inbound tcp port 8080 from 198.51.100.4",
	  FS_WHATIF_DEPENDS, "forwards it to 10.0.0.5", NONE, NONE },
	{ L, P_FWD, "ext", NULL, "inbound tcp port 8080 from 198.51.100.4",
	  FS_WHATIF_DEPENDS, "IP forwarding is off", NONE, NONE },
	{ L, P_FWD, "ext", NULL, "inbound tcp port 8081 from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	{ L, P_FWD, NULL, NULL, "inbound tcp port 8080 from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },

	/* --- host names: the answer depends on DNS -------------------- */
	{ L, P_NAMED, NULL, NULL, "inbound ssh from 198.51.100.4",
	  FS_WHATIF_DEPENDS, "host.example", NONE, NONE },
	{ W, P_NAMED, NULL, NULL, "inbound ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },

	/* --- ICMP: types and the settings that decide them ------------ */
	{ L, NULL, NULL, NULL, "inbound ping from 198.51.100.4",
	  FS_WHATIF_ALLOWED, "ping requests", NONE, NONE },
	{ L, NULL, "noecho", NULL, "inbound ping from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL, FS_WHATIF_ACT_OPEN_ICMP_SETTINGS,
	  FS_WHATIF_ACT_CREATE_ALLOW },
	{ L, NULL, "noecho", NULL, "allow ping from 198.51.100.4",
	  FS_WHATIF_BLOCKED, "currently BLOCKED",
	  FS_WHATIF_ACT_OPEN_ICMP_SETTINGS, FS_WHATIF_ACT_CREATE_ALLOW },
	{ W, NULL, "noecho", "all-defaults", "inbound ping from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL, FS_WHATIF_ACT_OPEN_ICMP_SETTINGS,
	  FS_WHATIF_ACT_CREATE_ALLOW },
	{ L, NULL, NULL, NULL, "block ping from 198.51.100.4",
	  FS_WHATIF_ALLOWED, "currently ALLOWED",
	  FS_WHATIF_ACT_OPEN_ICMP_SETTINGS, NONE },
	{ L, NULL, "nofilter", NULL, "inbound ping from 198.51.100.4",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },
	{ L, NULL, NULL, NULL, "outbound ping to 198.51.100.4",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },

	/* --- the user's verb ------------------------------------------ */
	{ L, NULL, NULL, NULL, "allow ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, "You asked to allow this. It is currently BLOCKED",
	  FS_WHATIF_ACT_CREATE_ALLOW, NONE },
	{ L, NULL, NULL, NULL, "block ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, "You asked to block this. It is already BLOCKED",
	  NONE, FS_WHATIF_ACT_CREATE_BLOCK },
	{ L, P_SSH_LAN, NULL, NULL, "allow ssh from 10.1.2.3",
	  FS_WHATIF_ALLOWED, "already ALLOWED", NONE,
	  FS_WHATIF_ACT_CREATE_ALLOW },
	{ L, NULL, NULL, NULL, "block outbound tcp port 6667",
	  FS_WHATIF_ALLOWED, "You asked to block this. It is currently ALLOWED",
	  FS_WHATIF_ACT_CREATE_BLOCK, NONE },
	{ W, NULL, NULL, "all-defaults",
	  "block outbound tcp to 198.51.100.4 port 443",
	  FS_WHATIF_ALLOWED, "currently ALLOWED", FS_WHATIF_ACT_CREATE_BLOCK,
	  NONE },
	{ L, P_SSH_LAN, NULL, NULL, "block ssh from 10.1.2.3",
	  FS_WHATIF_ALLOWED, "currently ALLOWED", FS_WHATIF_ACT_OPEN_RULE,
	  FS_WHATIF_ACT_CREATE_BLOCK },

	/* --- a block rule decided: never an allow next to it ---------- */
	{ L, P_DENY, NULL, NULL, "allow outbound tcp to 203.0.113.9 port 443",
	  FS_WHATIF_BLOCKED, NULL, FS_WHATIF_ACT_OPEN_RULE,
	  FS_WHATIF_ACT_CREATE_ALLOW },
	{ W, P_DENY, NULL, NULL, "allow outbound tcp to 203.0.113.9 port 443",
	  FS_WHATIF_BLOCKED, NULL, FS_WHATIF_ACT_OPEN_RULE,
	  FS_WHATIF_ACT_CREATE_ALLOW },
	{ W, P_SMTP, NULL, NULL, "allow outbound tcp port 25",
	  FS_WHATIF_BLOCKED, NULL, FS_WHATIF_ACT_OPEN_RULE,
	  FS_WHATIF_ACT_CREATE_ALLOW },

	/* --- Sentinel ------------------------------------------------- */
	{ L, P_SENT, NULL, "sentinel=203.0.113.50",
	  "allow outbound tcp to 203.0.113.50 port 443",
	  FS_WHATIF_BLOCKED, "Sentinel", FS_WHATIF_ACT_LIFT_SENTINEL,
	  FS_WHATIF_ACT_CREATE_ALLOW },
	{ W, P_SENT, NULL, "sentinel=203.0.113.50",
	  "outbound tcp to 203.0.113.50 port 443",
	  FS_WHATIF_BLOCKED, "Sentinel", FS_WHATIF_ACT_LIFT_SENTINEL,
	  FS_WHATIF_ACT_CREATE_ALLOW },
	{ L, P_SENT, NULL, NULL, "outbound tcp to 203.0.113.51 port 443",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },

	/* --- the firewall is off ------------------------------------- */
	{ L, P_DENY, NULL, "stopped", "outbound tcp to 203.0.113.9 port 443",
	  FS_WHATIF_ALLOWED, "not running", NONE, NONE },
	{ L, NULL, NULL, "stopped", "block ssh from 198.51.100.4",
	  FS_WHATIF_ALLOWED, "With the firewall off it is ALLOWED",
	  FS_WHATIF_ACT_START_FIREWALL, NONE },
	{ W, NULL, NULL, "all-defaults public public-off",
	  "inbound tcp port 3389 from 198.51.100.4",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },
	{ W, NULL, NULL, "all-defaults public public-off",
	  "block inbound tcp port 3389 from 198.51.100.4",
	  FS_WHATIF_ALLOWED, NULL, FS_WHATIF_ACT_START_FIREWALL, NONE },
	{ W, NULL, NULL, "all-defaults private public-off",
	  "inbound tcp port 3389 from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },

	/* --- Windows profiles and their defaults ---------------------- */
	{ W, NULL, NULL, "public-in-allow public",
	  "inbound tcp port 80 from 198.51.100.4",
	  FS_WHATIF_ALLOWED, "Public", NONE, NONE },
	{ W, NULL, NULL, "public-in-allow",
	  "inbound tcp port 80 from 198.51.100.4",
	  FS_WHATIF_DEPENDS, "Public", NONE, NONE },
	{ W, NULL, NULL, "public-in-allow private",
	  "inbound tcp port 80 from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },
	{ W, NULL, NULL, "all-defaults out-block",
	  "outbound tcp to 198.51.100.4 port 443",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },

	/* --- restrictive outbound ------------------------------------- */
	{ L, NULL, "restrictive", NULL, "outbound tcp to 198.51.100.4 port 443",
	  FS_WHATIF_BLOCKED, "restrictive", NONE, NONE },
	{ L, P_HTTPS_OUT, "restrictive", NULL,
	  "outbound tcp to 198.51.100.4 port 443",
	  FS_WHATIF_ALLOWED, "HTTPS", NONE, NONE },
	/* No host named: no row for every host unless the line says so. */
	{ L, NULL, "restrictive", NULL, "allow outbound tcp port 443",
	  FS_WHATIF_BLOCKED, NULL, NONE, FS_WHATIF_ACT_CREATE_ALLOW },
	{ L, NULL, "restrictive", NULL, "allow outbound tcp port 443 to anywhere",
	  FS_WHATIF_BLOCKED, NULL, FS_WHATIF_ACT_CREATE_ALLOW, NONE },
	/* b6: Linux reads an outbound service row's host as the source */
	{ L, NULL, "restrictive", NULL,
	  "allow outbound tcp to 198.51.100.4 port 443",
	  FS_WHATIF_BLOCKED, NULL, NONE, FS_WHATIF_ACT_CREATE_ALLOW },
	{ W, NULL, NULL, "all-defaults out-block",
	  "allow outbound tcp to 198.51.100.4 port 443",
	  FS_WHATIF_BLOCKED, NULL, FS_WHATIF_ACT_CREATE_ALLOW, NONE },
	/* Linux "outbound from" matches this computer's own address */
	{ L, P_OUT_FROM, "restrictive", "local=192.168.1.20",
	  "outbound tcp to 198.51.100.4 port 443",
	  FS_WHATIF_ALLOWED, "Allow outbound (192.168.1.20)", NONE, NONE },
	{ L, P_OUT_FROM, "restrictive", "local=192.168.1.99",
	  "outbound tcp to 198.51.100.4 port 443",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },

	/* --- settings that are not ICMP ------------------------------- */
	{ W, "1:SSH,22,Anyone,x", NULL, "all-defaults",
	  "allow ssh from 10.1.2.3",
	  FS_WHATIF_DEPENDS, "Public", FS_WHATIF_ACT_OPEN_SETTINGS,
	  FS_WHATIF_ACT_CREATE_ALLOW },
	{ L, "1:SSH,22,Anyone,x", "ext", NULL, "inbound ssh from 10.1.2.3",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },
	{ L, NULL, "ext", NULL, "inbound tcp port 80 from 10.1.2.3",
	  FS_WHATIF_BLOCKED, NULL, NONE, NONE },

	/* --- the saved policy is not what is in force ---------------- */
	/* On hold is a choice (audit-only, a dry run): applying is not
	 * offered over it. */
	{ L, NULL, NULL, "held", "inbound ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL, NONE, FS_WHATIF_ACT_APPLY_POLICY },
	{ L, NULL, NULL, "failed", "inbound ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL,
	  FS_WHATIF_ACT_APPLY_POLICY, NONE },
	{ L, NULL, NULL, "stale", "inbound ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL, FS_WHATIF_ACT_APPLY_POLICY, NONE },
	{ L, NULL, NULL, NULL, "inbound ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL, NONE, FS_WHATIF_ACT_APPLY_POLICY },

	/* --- an allow never opens more than the line named ------------ */
	{ L, NULL, NULL, NULL, "allow ssh from server.example.com",
	  FS_WHATIF_BLOCKED, NULL, NONE, FS_WHATIF_ACT_CREATE_ALLOW },
	{ L, NULL, NULL, NULL, "allow tcp 8080 from ssh-gateway",
	  FS_WHATIF_BLOCKED, NULL, NONE, FS_WHATIF_ACT_CREATE_ALLOW },
	{ L, NULL, NULL, NULL, "allow ssh from the local network",
	  FS_WHATIF_BLOCKED, NULL, NONE, FS_WHATIF_ACT_CREATE_ALLOW },
	{ L, NULL, NULL, NULL, "allow inbound ssh",
	  FS_WHATIF_BLOCKED, NULL, NONE, FS_WHATIF_ACT_CREATE_ALLOW },
	{ L, NULL, NULL, NULL, "expose tcp 8080 to the internet",
	  FS_WHATIF_BLOCKED, NULL, FS_WHATIF_ACT_CREATE_ALLOW, NONE },
	{ L, NULL, NULL, NULL, "allow ssh from anyone",
	  FS_WHATIF_BLOCKED, NULL, FS_WHATIF_ACT_CREATE_ALLOW, NONE },
	/* a forward that goes nowhere is not fixed by an allow row */
	{ L, P_FWD, "ext", NULL, "allow tcp port 8080 from 198.51.100.4",
	  FS_WHATIF_DEPENDS, NULL, NONE, FS_WHATIF_ACT_CREATE_ALLOW },

	/* --- connection state, loopback, interfaces ------------------- */
	{ L, NULL, "noreply", NULL, "inbound echo-reply from 198.51.100.4",
	  FS_WHATIF_DEPENDS, "answers a connection already open", NONE, NONE },
	{ L, NULL, "restrictive", NULL, "outbound tcp to 127.0.0.1 port 5432",
	  FS_WHATIF_ALLOWED, "Loopback", NONE, NONE },
	{ L, P_SSH_LAN, "ext int nat", NULL, "inbound ssh from 10.1.2.3",
	  FS_WHATIF_ALLOWED, "eth1", NONE, NONE },
	{ L, NULL, "ext int nat", NULL, "inbound tcp port 9000 from 10.1.2.3",
	  FS_WHATIF_DEPENDS, "arrives on eth1", NONE, NONE },

	/* --- Windows: no forwarding, "Block all incoming" -------------- */
	{ W, P_FWD, NULL, "all-defaults public",
	  "inbound tcp port 8080 from 198.51.100.4",
	  FS_WHATIF_ALLOWED, "not forwarded to 10.0.0.5", NONE, NONE },
	{ W, "1:SSH,22,Anyone,ssh", NULL, "all-defaults public shields",
	  "inbound ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, "Block all incoming connections", NONE, NONE },
	{ W, NULL, NULL, "all-defaults public shields",
	  "allow ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, NULL, NONE, FS_WHATIF_ACT_CREATE_ALLOW },
	{ W, NULL, NULL, "all-defaults public shields",
	  "outbound ssh to 198.51.100.4",
	  FS_WHATIF_ALLOWED, NULL, NONE, NONE },

	/* --- the summary claims "already" only of what is in force ----- */
	{ L, NULL, NULL, "stale", "block ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, "The saved policy has it BLOCKED", NONE, NONE },
	{ L, NULL, NULL, "held", "block ssh from 198.51.100.4",
	  FS_WHATIF_BLOCKED, "The saved policy has it BLOCKED", NONE, NONE },
};

static void
test_golden (void)
{
	for (guint i = 0; i < G_N_ELEMENTS (golden); i++) {
		const Golden *g = &golden[i];
		FsWhatIfResult *r = ask (g->plat, g->rows, g->settings, g->env,
		                         g->line);
		const gchar *plat = g->plat == L ? "Linux" : "Windows";

		CHECK (r->verdict == g->verdict,
		       "golden %u (%s): \"%s\" [%s|%s] is %s (got %s: %s)", i, plat,
		       g->line, g->rows ? g->rows : "-", g->env ? g->env : "-",
		       vname (g->verdict), vname (r->verdict),
		       r->summary ? r->summary : "");
		if (g->says != NULL)
			CHECK (r->summary != NULL && strstr (r->summary, g->says) != NULL,
			       "golden %u (%s): \"%s\" says \"%s\" (%s)", i, plat,
			       g->line, g->says, r->summary ? r->summary : "");
		if (g->action != NONE) {
			const FsWhatIfAction *a = find_action (r, g->action);

			CHECK (a != NULL && a->label != NULL && a->explanation != NULL,
			       "golden %u (%s): \"%s\" offers action %d", i, plat,
			       g->line, g->action);
			if (a != NULL && g->action != FS_WHATIF_ACT_APPLY_POLICY)
				CHECK (a->verified,
				       "golden %u (%s): and that action was verified "
				       "(%s)", i, plat, a->explanation);
		}
		if (g->never != NONE)
			CHECK (find_action (r, g->never) == NULL,
			       "golden %u (%s): \"%s\" does not offer action %d", i,
			       plat, g->line, g->never);

		/* Every answer has a trace with the deciding step in it. */
		for (guint k = 0; k < r->answers->len; k++) {
			const FsWhatIfAnswer *a = answer (r, k);

			if (a->verdict == FS_WHATIF_DEPENDS) {
				gboolean allowed = FALSE, blocked = FALSE;

				for (guint c = 0; c < a->cases->len; c++) {
					const FsWhatIfCase *cs = g_ptr_array_index (a->cases, c);

					allowed = allowed || cs->verdict == FS_WHATIF_ALLOWED;
					blocked = blocked || cs->verdict == FS_WHATIF_BLOCKED;
				}
				if (!(allowed && blocked))
					CHECK (FALSE, "golden %u: a DEPENDS answer lists an "
					       "allowed and a blocked case", i);
			} else if (a->decided_by < 0 ||
			           (guint) a->decided_by >= a->steps->len) {
				CHECK (FALSE, "golden %u: the trace marks the deciding step",
				       i);
			}
		}
		fs_whatif_result_free (r);
	}
}

/* Details the table cannot hold. */
static void
test_details (void)
{
	FsWhatIfResult *r;
	const FsWhatIfAnswer *a;

	/* The trace: Windows block-wins names the shadowed allow too. */
	r = ask (W, P_MIX, NULL, NULL, "outbound tcp to 203.0.113.5 port 22");
	a = answer (r, 0);
	{
		gboolean shadowed_allow = FALSE;
		const FsWhatIfStep *d = (a && a->decided_by >= 0)
		                        ? g_ptr_array_index (a->steps, a->decided_by)
		                        : NULL;

		for (guint i = 0; a != NULL && i < a->steps->len; i++) {
			const FsWhatIfStep *st = g_ptr_array_index (a->steps, i);

			if (st->kind == FS_WHATIF_STEP_MATCHED && st->allows &&
			    (gint) i != a->decided_by)
				shadowed_allow = TRUE;
		}
		CHECK (d != NULL && !d->allows &&
		       d->origin == FS_WHATIF_ORIGIN_POLICY &&
		       d->policy_kind == FS_RULE_OUTBOUND_DENY_TO &&
		       d->policy_index == 0,
		       "detail: the deciding step is the deny row, kind and row "
		       "index named");
		CHECK (shadowed_allow,
		       "detail: the matching allow is in the trace, not deciding");
		CHECK (a != NULL && a->policy_kind == FS_RULE_OUTBOUND_DENY_TO &&
		       a->rule != NULL && strstr (a->rule, "203.0.113.5") != NULL,
		       "detail: the answer names its deciding rule and row");
	}
	fs_whatif_result_free (r);

	/* Linux first match on the same policy: the chain order decides,
	 * and the answer says which row. */
	r = ask (L, P_MIX, NULL, NULL, "outbound tcp to 203.0.113.5 port 22");
	a = answer (r, 0);
	CHECK (a != NULL && a->origin == FS_WHATIF_ORIGIN_POLICY &&
	       a->policy_kind >= 0 && a->policy_index == 0,
	       "detail: Linux names the first matching row (%s)",
	       a ? a->rule : "-");
	fs_whatif_result_free (r);

	/* DEPENDS: the concrete split, common case first. */
	r = ask (L, P_DENY, NULL, NULL, "outbound tcp port 443");
	a = answer (r, 0);
	CHECK (a != NULL && a->cases->len == 2 &&
	       ((FsWhatIfCase *) g_ptr_array_index (a->cases, 0))->verdict ==
	       FS_WHATIF_ALLOWED &&
	       ((FsWhatIfCase *) g_ptr_array_index (a->cases, 1))->verdict ==
	       FS_WHATIF_BLOCKED &&
	       strstr (((FsWhatIfCase *) g_ptr_array_index (a->cases, 1))
	               ->condition, "203.0.113.9") != NULL &&
	       ((FsWhatIfCase *) g_ptr_array_index (a->cases, 1))->policy_kind ==
	       FS_RULE_OUTBOUND_DENY_TO,
	       "detail: DEPENDS lists the common case and the blocked host with "
	       "its row");
	fs_whatif_result_free (r);

	/* A /24 block against a /16 question: the block is named. */
	r = ask (L, P_DENY_NET, NULL, NULL, "outbound tcp to 203.0.0.0/16 port 80");
	CHECK (r->verdict == FS_WHATIF_DEPENDS &&
	       strstr (r->summary, "203.0.113.0/24") != NULL,
	       "detail: a wider question meets the narrower block by name (%s)",
	       r->summary);
	fs_whatif_result_free (r);

	/* One row's TCP and UDP lines that decide together are credited to
	 * the row, not to its TCP line. */
	r = ask (L, "1:mystery,22,192.168.1.50,x", NULL, NULL,
	         "inbound from 192.168.1.50");
	CHECK (r->summary != NULL &&
	       strstr (r->summary, "TCP and UDP on port 22 by rule "
	                           "'StockFW: Allow mystery (inbound, "
	                           "192.168.1.50)'") != NULL,
	       "detail: both lines of one row are named as the row (%s)",
	       r->summary);
	CHECK (find_action (r, FS_WHATIF_ACT_CREATE_ALLOW) == NULL &&
	       notes_have (r, "names no port"),
	       "detail: no allow for a portless question, and the note says why");
	fs_whatif_result_free (r);

	/* Sentinel: the expiry is in the answer. */
	r = ask (L, P_SENT, NULL, "sentinel=203.0.113.50",
	         "outbound tcp to 203.0.113.50 port 443");
	{
		const FsWhatIfAction *lift = find_action (r,
		                                          FS_WHATIF_ACT_LIFT_SENTINEL);

		CHECK (lift != NULL && g_strcmp0 (lift->target, "203.0.113.50") == 0 &&
		       lift->expires_unix == 1700000000 + 420 &&
		       strstr (lift->explanation, "7 minutes") != NULL,
		       "detail: Sentinel's block says it lifts in 7 minutes (%s)",
		       lift ? lift->explanation : "-");
		CHECK (answer (r, 0)->origin == FS_WHATIF_ORIGIN_SENTINEL,
		       "detail: the origin is Sentinel, not the policy");
		CHECK (fs_whatif_result_primary_action (r) == lift,
		       "detail: lifting it is the window's action");
	}
	fs_whatif_result_free (r);

	/* A Sentinel row with no tracked expiry still is Sentinel's. */
	r = ask (L, P_SENT, NULL, NULL, "outbound tcp to 203.0.113.50 port 443");
	CHECK (answer (r, 0)->origin == FS_WHATIF_ORIGIN_SENTINEL &&
	       find_action (r, FS_WHATIF_ACT_LIFT_SENTINEL) != NULL,
	       "detail: a Sentinel row from an earlier session is still lifted "
	       "as Sentinel's");
	fs_whatif_result_free (r);

	/* Stopped: the answer says what happens once it runs. */
	r = ask (L, P_DENY, NULL, "stopped", "outbound tcp to 203.0.113.9 port 443");
	CHECK (r->notes->len > 0 &&
	       g_str_has_prefix (g_ptr_array_index (r->notes, 0),
	                         "Once the firewall runs: BLOCKED"),
	       "detail: a stopped firewall's answer says what the rules do once "
	       "it runs");
	fs_whatif_result_free (r);

	/* Unknown firewall state: assumed running, and said. */
	r = ask (L, P_DENY, NULL, "unknown", "outbound tcp to 203.0.113.9 port 443");
	CHECK (r->verdict == FS_WHATIF_BLOCKED &&
	       notes_have (r, "could not tell whether the firewall is running"),
	       "detail: an unknown state is assumed running, and the answer "
	       "says so");
	fs_whatif_result_free (r);

	/* Windows: the defaults were assumed, and said; read, and not. */
	r = ask (W, NULL, NULL, NULL, "inbound tcp port 80 from 198.51.100.4");
	CHECK (notes_have (r, "Windows' own default was assumed"),
	       "detail: Windows' assumed default is said");
	fs_whatif_result_free (r);
	r = ask (W, NULL, NULL, "all-defaults public",
	         "inbound tcp port 80 from 198.51.100.4");
	CHECK (!notes_have (r, "Windows' own default was assumed") &&
	       !notes_have (r, "could not tell which network profile"),
	       "detail: with the defaults and profile read, nothing is assumed");
	fs_whatif_result_free (r);

	/* Held: the note names why. */
	r = ask (L, NULL, NULL, "held", "inbound ssh from 198.51.100.4");
	CHECK (notes_have (r, "Applies are on hold (audit-only mode)"),
	       "detail: a held policy is said, with the reason");
	fs_whatif_result_free (r);

	/* No policy at all. */
	{
		FsSettings *s = fs_settings_new ();
		FsWhatIfContext *ctx = fs_whatif_context_new (L, NULL, s);

		ctx->firewall = FS_WHATIF_FW_RUNNING;
		r = fs_whatif_simulate_text (ctx, "inbound ssh from 198.51.100.4");
		CHECK (r->verdict == FS_WHATIF_BLOCKED &&
		       notes_have (r, "No policy is loaded"),
		       "detail: without a policy the answer says so");
		fs_whatif_result_free (r);
		fs_whatif_context_free (ctx);
		fs_settings_free (s);
	}

	/* The described text carries the reading and the trace. */
	r = ask (L, P_SSH_LAN, NULL, NULL, "allow ssh from 10.1.2.3");
	{
		gchar *d = fs_whatif_result_describe (r);

		CHECK (strstr (d, "Read as: you want it allowed") != NULL &&
		       strstr (d, "How it was decided:") != NULL &&
		       strstr (d, "=> StockFW: Allow SSH") != NULL,
		       "detail: the description shows the reading and the deciding "
		       "step");
		g_free (d);
	}
	fs_whatif_result_free (r);
}

/* ================================================================
 * 3. The Linux model is the generator
 * ================================================================ */

/* The "-A CHAIN ..." lines of one chain in generator output; the
 * "$IPT " of the text form is dropped. */
static gchar *
chain_lines (const gchar *text, const gchar *chain, gboolean dollar)
{
	GString *out = g_string_new (NULL);
	gchar **lines = g_strsplit (text != NULL ? text : "", "\n", -1);
	gchar *want = g_strdup_printf ("%s-A %s ", dollar ? "$IPT " : "", chain);

	for (guint i = 0; lines[i] != NULL; i++) {
		const gchar *l = lines[i];

		while (*l == ' ' || *l == '\t')
			l++;
		if (g_str_has_prefix (l, want))
			g_string_append_printf (out, "%s\n", l + (dollar ? 5 : 0));
	}
	g_strfreev (lines);
	g_free (want);
	return g_string_free (out, FALSE);
}

static const gchar *pin_policies[] = {
	"",
	P_SSH_LAN "|" P_DENY "|" P_SMTP "|" P_FWD,
	"1:SSH,22,10.0.0.0/8,lan|6:203.0.113.9,bad|3:198.51.100.0/24,x|"
	"8:SMTP,25,Anyone,x|0:192.168.1.7,x|2:HTTP,8080,10.0.0.5,80,x|"
	"5:DNS,53,Anyone,x|4:10.1.1.1,x|7:10.2.2.2,x|"
	"1:Samba (SMB),137-139 445,Anyone,x|1:mystery,,Anyone,x|"
	"1:SSH,22,2001:db8::/32,v6|5:HTTPS,443,203.0.113.0/24,x|"
	"8:Port 6000,6000,Anyone,x|0:Anyone,all|3:Anyone,all|"
	"1:TCP,8443,Anyone,x|5:UDP,5000,10.9.9.9,x|"
	"1:Game,7000-7010 7100,Anyone,x",
	P_V6 "|6:2001:db8:bad::/48,v6 bad|3:2001:db8:ffff::1,v6 ok|"
	"8:DNS,53,2001:db8::53,v6 dns",
	P_SENT "|" P_OUT_FROM "|" P_ANYONE_IN,
	NULL
};

static const gchar *pin_settings[] = {
	"", "ext", "ext restrictive", "ext int nat", "ext int nat restrictive bcast",
	"ext reject", "ext nolog", "ext nofilter", "ext noecho allicmp", "int",
	"bcast", "restrictive nolog reject", "ext noreserved", NULL
};

static void
test_pin_to_generator (void)
{
	guint compared = 0, differ = 0;

	for (guint pi = 0; pin_policies[pi] != NULL; pi++) {
		for (guint si = 0; pin_settings[si] != NULL; si++) {
			FsPolicy *p = policy_of (pin_policies[pi]);
			FsSettings *s = settings_of (pin_settings[si]);
			FsRestorePlan *plan;
			GError *error = NULL;

			plan = fs_script_restore_plan_ex (p, s, FS_PLAN_LENIENT_BLOCKS,
			                                  &error);
			if (plan == NULL) {
				CHECK (FALSE, "pin: the plan builds for policy %u [%s]: %s",
				       pi, pin_settings[si], error ? error->message : "?");
				g_clear_error (&error);
			}

			for (gint fam = 0; fam < 2; fam++) {
				FsFamily f = fam == 0 ? FS_FAMILY_IPV4 : FS_FAMILY_IPV6;

				for (gint in = 0; in < 2; in++) {
					const gchar *chain = in ? "INBOUND" : "OUTBOUND";
					gchar *model = fs_whatif_linux_chain_text (p, s, f, in);
					gchar *gen = in ? fs_script_generate_inbound_family (p, s, f)
					                : fs_script_generate_outbound_family (p, s,
					                                                      f);
					gchar *text = chain_lines (gen, chain, TRUE);
					gchar *restore = chain_lines (
						plan == NULL ? NULL
						: fam == 0 ? plan->v4.filter : plan->v6.filter,
						chain, FALSE);

					compared += 2;
					if (strcmp (model, text) != 0) {
						differ++;
						CHECK (FALSE, "pin: policy %u [%s] %s %s: the model is "
						       "the generator's text form\n--- model\n%s"
						       "--- generator\n%s", pi, pin_settings[si],
						       fam ? "IPv6" : "IPv4", chain, model, text);
					}
					if (strcmp (model, restore) != 0) {
						differ++;
						CHECK (FALSE, "pin: policy %u [%s] %s %s: the model is "
						       "the restore form the backend loads\n--- model\n"
						       "%s--- restore\n%s", pi, pin_settings[si],
						       fam ? "IPv6" : "IPv4", chain, model, restore);
					}
					if (*model == '\0') {
						differ++;
						CHECK (FALSE, "pin: the model wrote no rules");
					}
					g_free (model);
					g_free (gen);
					g_free (text);
					g_free (restore);
				}
			}

			fs_restore_plan_free (plan);
			fs_settings_free (s);
			fs_policy_free (p);
		}
	}

	CHECK (differ == 0 && compared > 400,
	       "pin: the Linux model's chains equal the generator's, line for "
	       "line, in %u comparisons (both families, both directions, text "
	       "and restore forms)", compared);

	/* A host-name row: the text form keeps the name for IPv4 and leaves
	 * it out for IPv6, and the model with it. */
	{
		FsPolicy *p = policy_of (P_NAMED "|6:bad.example,named bad");
		FsSettings *s = settings_of ("ext");
		gboolean same = TRUE;

		for (gint fam = 0; fam < 2; fam++)
			for (gint in = 0; in < 2; in++) {
				FsFamily f = fam == 0 ? FS_FAMILY_IPV4 : FS_FAMILY_IPV6;
				gchar *model = fs_whatif_linux_chain_text (p, s, f, in);
				gchar *gen = in ? fs_script_generate_inbound_family (p, s, f)
				                : fs_script_generate_outbound_family (p, s, f);
				gchar *text = chain_lines (gen, in ? "INBOUND" : "OUTBOUND",
				                           TRUE);

				same = same && strcmp (model, text) == 0;
				g_free (model);
				g_free (gen);
				g_free (text);
			}
		CHECK (same, "pin: host-name rows sit where the generator puts them");
		fs_settings_free (s);
		fs_policy_free (p);
	}
}

/* ================================================================
 * 4. Fixes
 * ================================================================ */

/* Adds an action's row and asks again: the verdict it promised. */
static FsWhatIfVerdict
verdict_with_row (FsWhatIfPlatform plat, const gchar *rows,
                  const gchar *settings, const gchar *env,
                  const FsRule *row, const gchar *line)
{
	Env e = env_new (plat, rows, settings, env);
	FsWhatIfResult *r;
	FsWhatIfVerdict v;

	fs_policy_add (e.policy, (FsRule *) row);
	r = fs_whatif_simulate_text (e.ctx, line);
	v = r->verdict;
	fs_whatif_result_free (r);
	env_free (&e);
	return v;
}

static void
test_fixes (void)
{
	FsWhatIfResult *r;
	const FsWhatIfAction *act;
	gchar *why = NULL;

	/* CREATE_ALLOW: one protocol, one port, the asked host. */
	r = ask (L, NULL, NULL, NULL, "allow ssh from 192.168.1.50");
	act = find_action (r, FS_WHATIF_ACT_CREATE_ALLOW);
	CHECK (act != NULL && act->verified && act->gives == FS_WHATIF_ALLOWED &&
	       act->row->kind == FS_RULE_INBOUND_ALLOW_SERVICE &&
	       g_strcmp0 (act->row->service, "TCP") == 0 &&
	       g_strcmp0 (act->row->port, "22") == 0 &&
	       g_strcmp0 (act->row->target, "192.168.1.50") == 0 &&
	       act->row->comment != NULL,
	       "fix: \"allow ssh from 192.168.1.50\" offers inbound TCP 22 from "
	       "192.168.1.50, nothing wider");
	CHECK (act != NULL && strstr (act->label,
	       "Allow inbound TCP port 22 from 192.168.1.50") != NULL,
	       "fix: the label spells out the row (%s)", act ? act->label : "-");
	CHECK (fs_whatif_result_create_action (r) == act &&
	       fs_whatif_result_primary_action (r) == act,
	       "fix: it is what Create This Rule writes");
	CHECK (act != NULL && fs_whatif_row_is_safe (act, NULL),
	       "fix: the row passes the safety check");
	if (act != NULL) {
		static const struct { const gchar *line; FsWhatIfVerdict v; }
		after[] = {
			{ "inbound tcp port 22 from 192.168.1.50", FS_WHATIF_ALLOWED },
			{ "inbound tcp port 22 from 192.168.1.51", FS_WHATIF_BLOCKED },
			{ "inbound udp port 22 from 192.168.1.50", FS_WHATIF_BLOCKED },
			{ "inbound tcp port 23 from 192.168.1.50", FS_WHATIF_BLOCKED },
			{ "inbound tcp port 21 from 192.168.1.50", FS_WHATIF_BLOCKED },
			{ "outbound tcp to 192.168.1.50 port 22", FS_WHATIF_ALLOWED },
		};

		for (guint i = 0; i < G_N_ELEMENTS (after); i++) {
			FsWhatIfVerdict v = verdict_with_row (L, NULL, NULL, NULL,
			                                      act->row, after[i].line);

			CHECK (v == after[i].v, "fix: with the row, \"%s\" is %s (got %s)",
			       after[i].line, vname (after[i].v), vname (v));
		}
		for (guint i = 0; i < G_N_ELEMENTS (after); i++) {
			FsWhatIfVerdict v = verdict_with_row (W, NULL, NULL,
			                                      "all-defaults private",
			                                      act->row, after[i].line);

			CHECK (v == after[i].v, "fix: on Windows too, \"%s\" is %s "
			       "(got %s)", after[i].line, vname (after[i].v), vname (v));
		}
	}

	fs_whatif_result_free (r);

	/* The check runs again against the policy as it is now: a deny for
	 * that host added since makes the same row not do what it said. */
	r = ask (W, NULL, NULL, "out-block",
	         "allow outbound tcp to 203.0.113.9 port 443");
	act = find_action (r, FS_WHATIF_ACT_CREATE_ALLOW);
	CHECK (act != NULL && act->verified &&
	       act->row->kind == FS_RULE_OUTBOUND_ALLOW_SERVICE,
	       "fix: Windows, outbound blocked by default: an outbound row");
	if (act != NULL) {
		Env e = env_new (W, "6:203.0.113.9,blocked since", NULL,
		                 "out-block");
		Env same = env_new (W, NULL, NULL, "out-block");
		gboolean ok_now;

		CHECK (fs_whatif_action_verify (same.ctx, r->query, act, NULL),
		       "fix: re-checked against an unchanged policy, it still holds");
		ok_now = fs_whatif_action_verify (e.ctx, r->query, act, &why);
		CHECK (!ok_now && why != NULL,
		       "fix: re-checked after a block for the host was added, it is "
		       "refused (%s)", why ? why : "-");
		g_clear_pointer (&why, g_free);
		env_free (&e);
		env_free (&same);
	}
	fs_whatif_result_free (r);

	/* A host block: the row is the narrowest that gives the answer. */
	r = ask (L, NULL, NULL, NULL, "allow inbound tcp port 8080 from 10.0.0.0/24");
	act = find_action (r, FS_WHATIF_ACT_CREATE_ALLOW);
	CHECK (act != NULL && g_strcmp0 (act->row->target, "10.0.0.0/24") == 0 &&
	       g_strcmp0 (act->row->port, "8080") == 0,
	       "fix: a block of hosts gets a row for that block, one port");
	fs_whatif_result_free (r);

	/* IPv6 host. */
	r = ask (L, NULL, NULL, NULL, "allow inbound tcp port 443 from 2001:db8::9");
	act = find_action (r, FS_WHATIF_ACT_CREATE_ALLOW);
	CHECK (act != NULL && act->verified &&
	       g_strcmp0 (act->row->target, "2001:db8::9") == 0,
	       "fix: an IPv6 host gets its row");
	fs_whatif_result_free (r);

	/* No port, no protocol: no allow at all, and the note says why. */
	r = ask (L, NULL, NULL, NULL, "allow inbound from 198.51.100.4");
	CHECK (find_action (r, FS_WHATIF_ACT_CREATE_ALLOW) == NULL &&
	       notes_have (r, "names no port"),
	       "fix: a portless question gets no allow row");
	fs_whatif_result_free (r);
	r = ask (L, NULL, NULL, NULL, "allow inbound port 8080 from 198.51.100.4");
	CHECK (find_action (r, FS_WHATIF_ACT_CREATE_ALLOW) == NULL &&
	       notes_have (r, "TCP or UDP"),
	       "fix: a port without a protocol gets no allow row either");
	fs_whatif_result_free (r);

	/* CREATE_BLOCK. */
	r = ask (L, NULL, NULL, NULL, "block outbound tcp port 6667");
	act = find_action (r, FS_WHATIF_ACT_CREATE_BLOCK);
	CHECK (act != NULL && act->verified && act->gives == FS_WHATIF_BLOCKED &&
	       act->row->kind == FS_RULE_OUTBOUND_DENY_SERVICE &&
	       g_strcmp0 (act->row->port, "6667") == 0 &&
	       fs_whatif_row_is_safe (act, NULL),
	       "fix: \"block outbound tcp port 6667\" offers a deny for that port");
	if (act != NULL) {
		CHECK (verdict_with_row (L, NULL, NULL, NULL, act->row,
		                         "outbound tcp port 6667") ==
		       FS_WHATIF_BLOCKED &&
		       verdict_with_row (L, NULL, NULL, NULL, act->row,
		                         "outbound tcp to 198.51.100.4 port 6668") ==
		       FS_WHATIF_ALLOWED,
		       "fix: with it the port is blocked and its neighbour is not");
	}
	fs_whatif_result_free (r);

	r = ask (W, NULL, NULL, "all-defaults", "block outbound to 198.51.100.4");
	act = find_action (r, FS_WHATIF_ACT_CREATE_BLOCK);
	CHECK (act != NULL && act->verified &&
	       act->row->kind == FS_RULE_OUTBOUND_DENY_TO &&
	       g_strcmp0 (act->row->target, "198.51.100.4") == 0,
	       "fix: on Windows a whole host is blocked with a deny-to row");
	fs_whatif_result_free (r);

	/* On Linux the same deny-to would leave outbound ICMP open (it is
	 * accepted first), so it is not offered as a block of everything. */
	r = ask (L, NULL, NULL, NULL, "block outbound to 198.51.100.4");
	CHECK (find_action (r, FS_WHATIF_ACT_CREATE_BLOCK) == NULL &&
	       notes_have (r, "considered and not offered"),
	       "fix: Linux does not offer a block that would leave ICMP through");
	fs_whatif_result_free (r);

	/* OPEN_RULE: verified -- without the row it is allowed. */
	r = ask (L, P_DENY, NULL, NULL, "allow outbound tcp to 203.0.113.9 port 443");
	act = find_action (r, FS_WHATIF_ACT_OPEN_RULE);
	CHECK (act != NULL && act->verified &&
	       act->policy_kind == FS_RULE_OUTBOUND_DENY_TO &&
	       act->policy_index == 0 &&
	       strstr (act->explanation, "Without it, this is allowed") != NULL,
	       "fix: the deciding deny row is offered for editing, by row");
	fs_whatif_result_free (r);

	/* OPEN_ICMP_SETTINGS names the field and the value. */
	r = ask (L, NULL, "noecho", NULL, "allow ping from 198.51.100.4");
	act = find_action (r, FS_WHATIF_ACT_OPEN_ICMP_SETTINGS);
	CHECK (act != NULL && act->verified &&
	       g_strcmp0 (act->setting, "icmp_echo_request") == 0 &&
	       act->setting_on && g_strcmp0 (act->page, "icmp") == 0,
	       "fix: ping is a Preferences checkbox: icmp_echo_request on");
	fs_whatif_result_free (r);

	/* START_FIREWALL. */
	r = ask (L, NULL, NULL, "stopped", "block ssh from 198.51.100.4");
	act = find_action (r, FS_WHATIF_ACT_START_FIREWALL);
	CHECK (act != NULL && act->verified,
	       "fix: with the firewall off, starting it is the fix and is "
	       "checked");
	fs_whatif_result_free (r);

	/* Windows: a reserved-source block wins over any allow, so the
	 * setting -- not a row -- is the fix; and with the default deciding
	 * the rest, an allow is offered with the exception named. */
	r = ask (W, "1:SSH,22,Anyone,x", NULL, "all-defaults",
	         "allow ssh from 10.1.2.3");
	act = find_action (r, FS_WHATIF_ACT_OPEN_SETTINGS);
	CHECK (act != NULL && act->verified &&
	       g_strcmp0 (act->setting, "block_non_routables") == 0 &&
	       !act->setting_on,
	       "fix: the reserved-source setting is the fix on Windows");
	fs_whatif_result_free (r);
	r = ask (W, NULL, NULL, "all-defaults", "allow ssh from 10.1.2.3");
	act = find_action (r, FS_WHATIF_ACT_CREATE_ALLOW);
	CHECK (act != NULL && act->verified && act->gives == FS_WHATIF_DEPENDS &&
	       strstr (act->explanation, "still blocks") != NULL,
	       "fix: an allow that the setting still overrides on Public says so "
	       "and promises DEPENDS, not ALLOWED");
	fs_whatif_result_free (r);

	/* b6 on Linux: an outbound service row with a host is never
	 * offered, and the note says why. */
	r = ask (L, NULL, "restrictive", NULL,
	         "allow outbound tcp to 198.51.100.4 port 443");
	CHECK (find_action (r, FS_WHATIF_ACT_CREATE_ALLOW) == NULL &&
	       notes_have (r, "source"),
	       "fix: Linux offers no outbound row for one port to one host");
	fs_whatif_result_free (r);

	/* fs_whatif_row_is_safe refuses the rows a fix must never write. */
	{
		static const struct { FsWhatIfActionKind kind; FsRuleKind rk;
		                      const gchar *csv; } bad[] = {
			{ FS_WHATIF_ACT_CREATE_ALLOW, FS_RULE_INBOUND_ALLOW_SERVICE,
			  "TCP,,Anyone,x" },
			{ FS_WHATIF_ACT_CREATE_ALLOW, FS_RULE_INBOUND_ALLOW_SERVICE,
			  "SSH,22,Anyone,x" },
			{ FS_WHATIF_ACT_CREATE_ALLOW, FS_RULE_INBOUND_ALLOW_SERVICE,
			  "TCP,1-65535,Anyone,x" },
			{ FS_WHATIF_ACT_CREATE_ALLOW, FS_RULE_INBOUND_ALLOW_SERVICE,
			  "TCP,22 23,Anyone,x" },
			{ FS_WHATIF_ACT_CREATE_ALLOW, FS_RULE_INBOUND_ALLOW_SERVICE,
			  "TCP,0,Anyone,x" },
			{ FS_WHATIF_ACT_CREATE_ALLOW, FS_RULE_INBOUND_ALLOW_SERVICE,
			  "TCP,22,host.example,x" },
			{ FS_WHATIF_ACT_CREATE_ALLOW, FS_RULE_INBOUND_ALLOW_SERVICE,
			  "TCP,22,0.0.0.0/0,x" },
			{ FS_WHATIF_ACT_CREATE_ALLOW, FS_RULE_INBOUND_ALLOW_FROM,
			  "198.51.100.4,x" },
			{ FS_WHATIF_ACT_CREATE_ALLOW, FS_RULE_OUTBOUND_ALLOW_TO,
			  "198.51.100.4,x" },
			{ FS_WHATIF_ACT_CREATE_ALLOW, FS_RULE_INBOUND_FORWARD,
			  "TCP,8080,10.0.0.5,80,x" },
			{ FS_WHATIF_ACT_CREATE_BLOCK, FS_RULE_OUTBOUND_DENY_TO,
			  "Anyone,x" },
			{ FS_WHATIF_ACT_CREATE_BLOCK, FS_RULE_OUTBOUND_DENY_SERVICE,
			  "TCP,,Anyone,x" },
			{ FS_WHATIF_ACT_OPEN_RULE, FS_RULE_INBOUND_ALLOW_SERVICE,
			  "TCP,22,Anyone,x" },
		};

		for (guint i = 0; i < G_N_ELEMENTS (bad); i++) {
			FsWhatIfAction a;

			memset (&a, 0, sizeof a);
			a.kind = bad[i].kind;
			a.row = fs_rule_from_csv (bad[i].rk, bad[i].csv);
			if (a.row == NULL) {
				CHECK (TRUE, "safe: \"%s\" does not even parse", bad[i].csv);
				continue;
			}
			CHECK (!fs_whatif_row_is_safe (&a, &why) && why != NULL,
			       "safe: kind %d row \"%s\" is refused (%s)", bad[i].rk,
			       bad[i].csv, why ? why : "accepted");
			g_clear_pointer (&why, g_free);
			fs_rule_free (a.row);
		}
	}
}

/* No fix the engine offers ever opens more than one protocol on one
 * port: a sweep over lines, policies, settings and both platforms. */
static void
test_no_wide_allow (void)
{
	static const gchar *lines[] = {
		"allow inbound", "allow outbound", "allow everything",
		"allow inbound from 198.51.100.4", "allow outbound to 198.51.100.4",
		"allow inbound tcp", "allow inbound udp", "allow inbound tcp from 10.0.0.0/8",
		"allow inbound port 22", "allow port 443", "allow ssh", "allow samba",
		"allow inbound samba from 10.1.2.3", "allow dns", "allow inbound dns",
		"allow inbound tcp port 22", "allow inbound udp port 53 from 10.1.2.3",
		"allow outbound tcp port 443", "allow outbound udp to 8.8.8.8 port 53",
		"allow ping", "allow inbound ping from 198.51.100.4",
		"allow inbound icmp", "allow rdp from 0.0.0.0/0",
		"allow inbound tcp port 22 from 2001:db8::/32",
		"allow from 203.0.113.9", "allow to 203.0.113.9 port 443",
		"inbound ssh", "ssh", "can 198.51.100.4 reach me", "port 8080",
		"allow inbound tcp port 65535", "allow inbound udp port 1",
		"allow ftp from 10.1.2.3", "allow http", "allow https to 10.0.0.1",
		NULL
	};
	static const gchar *policies[] = {
		NULL, P_SSH_LAN, P_DENY "|" P_SMTP, P_SENT, P_GAME "|" P_V6, NULL
	};
	static const gchar *settings[] = { NULL, "restrictive", "noecho ext" };
	guint offered = 0, bad = 0, added = 0;
	gchar **base[2];

	/* What the script holds with no rows at all. */
	{
		FsPolicy *none = fs_policy_new ();
		FsSettings *s = fs_settings_new ();
		gchar *in = fs_script_generate_inbound (none, s);
		gchar *out = fs_script_generate_outbound (none, s);

		base[0] = g_strsplit (in, "\n", -1);
		base[1] = g_strsplit (out, "\n", -1);
		for (guint n = 0; base[0][n] != NULL; n++)
			g_strstrip (base[0][n]);
		for (guint n = 0; base[1][n] != NULL; n++)
			g_strstrip (base[1][n]);
		g_free (in);
		g_free (out);
		fs_settings_free (s);
		fs_policy_free (none);
	}

	for (guint li = 0; lines[li] != NULL; li++)
	for (guint pi = 0; pi < G_N_ELEMENTS (policies); pi++)
	for (guint si = 0; si < G_N_ELEMENTS (settings); si++)
	for (gint plat = 0; plat < 2; plat++) {
		FsWhatIfResult *r = ask (plat ? W : L, policies[pi], settings[si],
		                         plat ? "all-defaults out-block" : NULL,
		                         lines[li]);

		for (guint i = 0; i < r->answers->len; i++) {
			const FsWhatIfAnswer *a = answer (r, i);

			for (guint k = 0; k < a->actions->len; k++) {
				const FsWhatIfAction *act = g_ptr_array_index (a->actions, k);
				const FsRule *row = act->row;
				gboolean ok;

				if (act->kind == FS_WHATIF_ACT_CREATE_ALLOW ||
				    act->kind == FS_WHATIF_ACT_CREATE_BLOCK)
					offered++;
				if (act->kind != FS_WHATIF_ACT_CREATE_ALLOW)
					continue;

				ok = act->verified && row != NULL &&
				     (row->kind == FS_RULE_INBOUND_ALLOW_SERVICE ||
				      row->kind == FS_RULE_OUTBOUND_ALLOW_SERVICE) &&
				     (g_strcmp0 (row->service, "TCP") == 0 ||
				      g_strcmp0 (row->service, "UDP") == 0) &&
				     row->port != NULL && *row->port != '\0' &&
				     strspn (row->port, "0123456789") == strlen (row->port) &&
				     atoi (row->port) >= 1 && atoi (row->port) <= 65535 &&
				     fs_whatif_row_is_safe (act, NULL);

				/* And what each platform would write for it. */
				if (ok) {
					FsPolicy *one = fs_policy_new ();
					GPtrArray *refused = NULL;
					GList *rules;
					FsSettings *s = fs_settings_new ();
					gchar *text;
					gchar **v;

					fs_policy_add (one, (FsRule *) row);
					rules = fs_fwrule_from_policy_checked (one, &refused);
					ok = rules != NULL && refused->len == 0;
					for (GList *l = rules; l != NULL && ok; l = l->next) {
						const FsFwRule *fw = l->data;

						ok = (fw->protocol == FS_PROTO_TCP ||
						      fw->protocol == FS_PROTO_UDP) &&
						     g_strcmp0 (row->kind ==
						                FS_RULE_INBOUND_ALLOW_SERVICE
						                ? fw->local_ports : fw->remote_ports,
						                row->port) == 0;
					}
					fs_fwrule_list_free (rules);
					g_ptr_array_unref (refused);

					/* The lines the row adds to the script: each
					 * names one protocol and the one port. */
					text = row->kind == FS_RULE_INBOUND_ALLOW_SERVICE
					       ? fs_script_generate_inbound (one, s)
					       : fs_script_generate_outbound (one, s);
					v = g_strsplit (text, "\n", -1);
					for (guint n = 0; v[n] != NULL && ok; n++) {
						gchar *dport;

						if (strv_has (base[row->kind ==
						              FS_RULE_INBOUND_ALLOW_SERVICE ? 0 : 1],
						              v[n]) ||
						    !g_str_has_prefix (g_strstrip (v[n]), "$IPT -A"))
							continue;
						added++;
						dport = g_strdup_printf ("--dport %s ", row->port);
						ok = strstr (v[n], dport) != NULL &&
						     (strstr (v[n], "-p tcp") != NULL) !=
						     (strstr (v[n], "-p udp") != NULL);
						g_free (dport);
					}
					g_strfreev (v);
					g_free (text);
					fs_settings_free (s);
					fs_policy_free (one);
				}

				if (!ok) {
					bad++;
					CHECK (FALSE, "wide: \"%s\" (%s) offered %s",
					       lines[li], plat ? "Windows" : "Linux",
					       act->label ? act->label : "an unchecked row");
				}
			}
		}
		fs_whatif_result_free (r);
	}

	CHECK (bad == 0 && offered > 20 && added > 20,
	       "wide: none of %u rows offered over %u lines x %u policies x %u "
	       "settings x 2 platforms opens more than one protocol on one port "
	       "(%u script lines checked)",
	       offered, (guint) (G_N_ELEMENTS (lines) - 1),
	       (guint) G_N_ELEMENTS (policies), (guint) G_N_ELEMENTS (settings),
	       added);
	g_strfreev (base[0]);
	g_strfreev (base[1]);
}

/* The compatibility wrappers in fs-copilot.c still answer. */
/* ================================================================
 * The second review: what a reader is told and offered
 * ================================================================ */

static void
test_review (void)
{
	FsWhatIfResult *r;
	const FsWhatIfAction *act;

	/* A stopped firewall: the result says so in fields the window
	 * reads, and the verdict once it runs. */
	r = ask (L, NULL, NULL, "stopped", "inbound ssh from 198.51.100.4");
	CHECK (r->verdict == FS_WHATIF_ALLOWED && r->stopped_decides &&
	       r->verdict_running == FS_WHATIF_BLOCKED,
	       "review: stopped -- ALLOWED now, BLOCKED once it runs");
	act = find_action (r, FS_WHATIF_ACT_START_FIREWALL);
	CHECK (act != NULL && act->verified && act->gives == FS_WHATIF_BLOCKED,
	       "review: a plain question offers starting it, and says what "
	       "that gives");
	fs_whatif_result_free (r);

	r = ask (L, NULL, NULL, NULL, "inbound ssh from 198.51.100.4");
	CHECK (!r->stopped_decides && r->verdict_running == r->verdict,
	       "review: running -- the running verdict is the verdict");
	fs_whatif_result_free (r);

	r = ask (W, NULL, NULL, "all-defaults public public-off",
	         "inbound tcp port 3389 from 198.51.100.4");
	CHECK (r->stopped_decides && r->verdict_running == FS_WHATIF_BLOCKED,
	       "review: a profile switched off counts as stopped");
	fs_whatif_result_free (r);

	/* With the firewall off, an allow is still judged by the rules. */
	r = ask (L, NULL, NULL, "stopped", "allow ssh from 198.51.100.4");
	act = find_action (r, FS_WHATIF_ACT_CREATE_ALLOW);
	CHECK (act != NULL && act->verified &&
	       strstr (act->explanation, "once the firewall runs") != NULL,
	       "review: stopped -- the allow row is offered for when it runs");
	fs_whatif_result_free (r);

	/* An unread host: no row, and the notes say why and what was
	 * answered instead. */
	r = ask (L, NULL, NULL, NULL, "allow ssh from server.example.com");
	CHECK (notes_have (r, "not looked up") &&
	       notes_have (r, "not an address StockFW can read"),
	       "review: an unread host is named in the notes");
	fs_whatif_result_free (r);

	/* "Anyone" and a name in one line: the name wins, and no row for
	 * every host is offered in its place. */
	{
		FsWhatIfQuery *q = fs_whatif_parse (
			"allow ssh from anyone at nas.example.com", NULL);

		CHECK (q != NULL && q->host_any_said && q->host_unread != NULL,
		       "review: \"anyone at <name>\" reads both");
		fs_whatif_query_free (q);
	}
	r = ask (L, NULL, NULL, NULL, "allow ssh from anyone at nas.example.com");
	CHECK (find_action (r, FS_WHATIF_ACT_CREATE_ALLOW) == NULL &&
	       notes_have (r, "nas.example.com"),
	       "review: an unread name is never widened to anyone");
	fs_whatif_result_free (r);

	/* No host named: the note says how to ask for anyone. */
	r = ask (L, NULL, NULL, NULL, "allow inbound ssh");
	CHECK (notes_have (r, "names no host") && notes_have (r, "from anyone"),
	       "review: a hostless allow says how to name a host or anyone");
	fs_whatif_result_free (r);

	/* "From anyone": offered, and labelled for what it is. */
	r = ask (L, NULL, NULL, NULL, "allow ssh from anyone");
	act = find_action (r, FS_WHATIF_ACT_CREATE_ALLOW);
	CHECK (act != NULL && act->verified &&
	       strstr (act->label, "every address") != NULL &&
	       strstr (act->explanation, "Careful") != NULL &&
	       strstr (act->explanation, "forwards") != NULL,
	       "review: an allow for anyone says so in its label and warns");
	fs_whatif_result_free (r);

	/* A forward outside router mode: the note names router mode. */
	r = ask (L, P_FWD, "ext", NULL, "allow tcp port 8080 from 198.51.100.4");
	CHECK (notes_have (r, "router mode") &&
	       notes_have (r, "Enable Internet connection sharing"),
	       "review: a forward that goes nowhere names the switch");
	fs_whatif_result_free (r);

	/* "Block all incoming": the note says where to turn it off. */
	r = ask (W, NULL, NULL, "all-defaults public shields",
	         "allow ssh from 198.51.100.4");
	CHECK (notes_have (r, "Block all incoming connections"),
	       "review: Block all incoming is named as the reason");
	fs_whatif_result_free (r);

	/* A settings checkbox says how far it reaches. */
	r = ask (L, NULL, "noecho", NULL, "allow ping from 198.51.100.4");
	act = find_action (r, FS_WHATIF_ACT_OPEN_ICMP_SETTINGS);
	CHECK (act != NULL && strstr (act->explanation, "every host") != NULL,
	       "review: a settings fix says it applies to every host (%s)",
	       act != NULL ? act->explanation : "no action");
	fs_whatif_result_free (r);

	/* A reply type: no setting is offered for the unsolicited half. */
	r = ask (L, NULL, "noreply", NULL, "allow echo-reply from 198.51.100.4");
	CHECK (find_action (r, FS_WHATIF_ACT_CREATE_ALLOW) == NULL,
	       "review: no allow row for an ICMP reply type");
	fs_whatif_result_free (r);

	/* Blocking a host: ICMP answers to open connections are said to
	 * pass, and the row is still offered. */
	r = ask (W, NULL, NULL, "all-defaults", "block outbound to 198.51.100.4");
	CHECK (find_action (r, FS_WHATIF_ACT_CREATE_BLOCK) != NULL &&
	       notes_have (r, "still pass"),
	       "review: a block of a host notes that ICMP answers still pass");
	fs_whatif_result_free (r);

	/* Linux: the note about other programs' rules. */
	r = ask (L, NULL, NULL, NULL, "inbound ssh from 198.51.100.4");
	CHECK (notes_have (r, "other programs"),
	       "review: Linux answers say other programs' rules are not seen");
	/* Threat intel is not in this build (Help says so): no note may
	 * speak of threat lists or blocklists as if Sentinel had them. */
	CHECK (!notes_have (r, "threat") && !notes_have (r, "blocklist"),
	       "review: no What-If note mentions threat lists (not in this "
	       "build)");
	fs_whatif_result_free (r);
	r = ask (W, NULL, NULL, "all-defaults", "inbound ssh from 198.51.100.4");
	CHECK (!notes_have (r, "threat") && !notes_have (r, "blocklist"),
	       "review: no Windows What-If note mentions threat lists");
	fs_whatif_result_free (r);

	/* The trace caption is plain words. */
	r = ask (L, NULL, NULL, NULL, "inbound ssh");
	{
		const FsWhatIfAnswer *a = answer (r, 0);
		gboolean found = FALSE;

		for (guint i = 0; a != NULL && i < a->steps->len; i++) {
			const FsWhatIfStep *st = g_ptr_array_index (a->steps, i);

			if (st->detail != NULL &&
			    strstr (st->detail, "Shown for one example") != NULL)
				found = TRUE;
		}
		CHECK (found, "review: the trace says it is one example");
	}
	fs_whatif_result_free (r);
}

static void
test_query_api (void)
{
	FsWhatIfQuery *q = fs_whatif_query_new ();
	FsWhatIfQuery *c;
	Env e = env_new (L, P_SSH_LAN, NULL, NULL);
	FsWhatIfResult *r;

	q->direction = FS_WHATIF_DIR_INBOUND;
	q->protocol = FS_WHATIF_PROTO_TCP;
	q->port = 22;
	q->host = g_strdup ("10.9.9.9");
	q->text = g_strdup ("built by hand");
	c = fs_whatif_query_copy (q);
	CHECK (c != NULL && c->port == 22 && g_strcmp0 (c->host, "10.9.9.9") == 0,
	       "api: a query copies");
	r = fs_whatif_simulate (e.ctx, c);
	CHECK (r->verdict == FS_WHATIF_ALLOWED && r->answers->len == 1,
	       "api: a query built by hand is answered");
	fs_whatif_result_free (r);
	r = fs_whatif_simulate (e.ctx, NULL);
	CHECK (r != NULL && r->verdict == FS_WHATIF_ERROR,
	       "api: no query is an ERROR result, never NULL");
	fs_whatif_result_free (r);
	fs_whatif_query_free (q);
	fs_whatif_query_free (c);
	env_free (&e);

	{
		FsPolicy *a = policy_of (P_SSH_LAN "|" P_DENY);
		FsPolicy *b = policy_of (P_SSH_LAN "|" P_DENY);
		FsPolicy *d = policy_of (P_DENY "|" P_SSH_LAN);
		FsPolicy *x = policy_of (P_SSH_LAN);

		CHECK (fs_whatif_policy_same (a, b) && fs_whatif_policy_same (a, d) &&
		       !fs_whatif_policy_same (a, x),
		       "api: policy_same compares rows kind by kind");
		fs_policy_free (a);
		fs_policy_free (b);
		fs_policy_free (d);
		fs_policy_free (x);
	}

	CHECK (strcmp (vname (FS_WHATIF_DEPENDS), "DEPENDS") == 0 &&
	       strcmp (vname (FS_WHATIF_ERROR), "ERROR") == 0,
	       "api: verdict names");
}

int
main (void)
{
	test_reading ();
	test_golden ();
	test_details ();
	test_pin_to_generator ();
	test_fixes ();
	test_no_wide_allow ();
	test_review ();
	test_query_api ();

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);
	return failures ? 1 : 0;
}
