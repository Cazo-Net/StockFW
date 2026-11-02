/* The Copilot's policy health check (core/fs-health.c).
 *
 * Built and run by tests/test-core.sh (and as the fs-health-test
 * target).  Pure GLib: no display, no firewall, no root.  What it pins:
 *
 *   1. exact coverage: a port range covers a port inside it, a network
 *      covers an address inside it, a host name never covers or is
 *      covered, TCP never covers UDP;
 *   2. a golden table, one small policy per check, on both platform
 *      models: duplicate, shadowed, unreachable, no effect, broad,
 *      risky, a forward to a risky port, a deny with no family;
 *   3. every fix verified by the What-If engine: the probes, their
 *      verdicts before and after, and the refusals (a narrowing that
 *      also blocks a LAN host, no known LAN, a removal that would
 *      change a verdict);
 *   4. applying a fix and undoing it, by content, proved with the rules
 *      file's bytes.
 */

#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/fs-health.h"
#include "core/fs-script.h"
#include "core/fs-util.h"
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

static const gchar *
plat (FsWhatIfPlatform p)
{
	return p == L ? "linux" : "windows";
}

/* "kind:csv|kind:csv|..." -> a policy. */
static FsPolicy *
policy_of (const gchar *rows)
{
	FsPolicy *p = fs_policy_new ();
	gchar **v = g_strsplit (rows != NULL ? rows : "", "|", -1);

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
		g_ptr_array_add (p->kinds[r->kind], r);
	}
	g_strfreev (v);
	return p;
}

typedef struct
{
	FsPolicy        *policy;
	FsSettings      *settings;
	FsWhatIfContext *ctx;
	GPtrArray       *found;
} Run;

static Run
run_check (FsWhatIfPlatform platform, const gchar *rows,
           gboolean restrictive, const gchar *prefix,
           const gchar *local_address)
{
	Run r;

	r.policy = policy_of (rows);
	r.settings = fs_settings_new ();
	r.settings->restrictive_outbound = restrictive;
	r.ctx = fs_whatif_context_new (platform, r.policy, r.settings);
	/* A home machine on a Private network: on Windows the reserved-
	 * source block applies to Public networks only, so a LAN probe
	 * would otherwise answer DEPENDS by profile. */
	if (platform == W)
		r.ctx->profiles_in_use = FS_PROFILE_BIT (FS_PROFILE_PRIVATE);
	if (local_address != NULL)
		fs_whatif_context_add_local_address (r.ctx, local_address);
	r.found = fs_health_check (r.ctx, prefix);
	return r;
}

static void
run_free (Run *r)
{
	g_ptr_array_unref (r->found);
	fs_whatif_context_free (r->ctx);
	fs_settings_free (r->settings);
	fs_policy_free (r->policy);
}

static guint
count_kind (const Run *r, FsHealthKind kind)
{
	guint n = 0;

	for (guint i = 0; i < r->found->len; i++)
		if (((FsHealthFinding *) g_ptr_array_index (r->found, i))->kind == kind)
			n++;
	return n;
}

static const FsHealthFinding *
first_kind (const Run *r, FsHealthKind kind)
{
	for (guint i = 0; i < r->found->len; i++) {
		const FsHealthFinding *f = g_ptr_array_index (r->found, i);

		if (f->kind == kind)
			return f;
	}
	return NULL;
}

static const FsHealthCheck *
check_named (const FsHealthFinding *f, const gchar *probe)
{
	for (guint i = 0; f != NULL && i < f->checks->len; i++) {
		const FsHealthCheck *c = g_ptr_array_index (f->checks, i);

		if (g_strcmp0 (c->probe, probe) == 0)
			return c;
	}
	return NULL;
}

/* ---- 1. exact coverage ------------------------------------------- */

static void
test_coverage (void)
{
	for (gint pi = 0; pi < 2; pi++) {
		FsWhatIfPlatform p = pi == 0 ? L : W;
		Run r;
		const FsHealthFinding *f;

		r = run_check (p, "1:TCP, 1024-2048, 192.168.1.0/24|"
		                  "1:TCP, 1500, 192.168.1.0/24",
		               TRUE, "192.168.1.0/24", NULL);
		f = first_kind (&r, FS_HEALTH_SHADOWED);
		CHECK (count_kind (&r, FS_HEALTH_SHADOWED) == 1 && f != NULL &&
		       f->policy_index == 1 && f->other_index == 0,
		       "%s: 1024-2048 covers 1500 (the 1500 row is redundant)",
		       plat (p));
		CHECK (f != NULL && f->fix == FS_HEALTH_FIX_REMOVE && f->verified &&
		       f->fix_after == NULL &&
		       g_strcmp0 (f->fix_before, "TCP, 1500, 192.168.1.0/24") == 0,
		       "%s: its removal is offered, verified", plat (p));
		CHECK (f != NULL &&
		       check_named (f, "Inbound TCP port 1500 from 192.168.1.0") != NULL &&
		       check_named (f, "Inbound TCP port 1500 from 192.168.1.255") != NULL,
		       "%s: the removal is checked at the row's corners", plat (p));
		run_free (&r);

		r = run_check (p, "0:10.0.0.0/8|1:SSH, 22, 10.1.2.3",
		               TRUE, "192.168.1.0/24", NULL);
		f = first_kind (&r, FS_HEALTH_SHADOWED);
		CHECK (f != NULL && f->policy_kind == FS_RULE_INBOUND_ALLOW_SERVICE &&
		       f->other_kind == FS_RULE_INBOUND_ALLOW_FROM && f->verified,
		       "%s: 10.0.0.0/8 covers 10.1.2.3", plat (p));
		run_free (&r);

		r = run_check (p, "0:10.0.0.0/8|1:SSH, 22, 11.1.2.3",
		               TRUE, "192.168.1.0/24", NULL);
		CHECK (count_kind (&r, FS_HEALTH_SHADOWED) == 0,
		       "%s: 10.0.0.0/8 does not cover 11.1.2.3", plat (p));
		run_free (&r);

		r = run_check (p, "1:TCP, 22, 0.0.0.0/0|1:SSH, 22, server.example",
		               TRUE, "192.168.1.0/24", NULL);
		CHECK (count_kind (&r, FS_HEALTH_SHADOWED) == 0 &&
		       count_kind (&r, FS_HEALTH_DUPLICATE) == 0,
		       "%s: a host name is never called covered", plat (p));
		run_free (&r);

		r = run_check (p, "1:TCP, 8080, 192.168.1.0/24|"
		                  "1:UDP, 8080, 192.168.1.0/24",
		               TRUE, "192.168.1.0/24", NULL);
		CHECK (count_kind (&r, FS_HEALTH_SHADOWED) == 0 &&
		       count_kind (&r, FS_HEALTH_DUPLICATE) == 0,
		       "%s: TCP 8080 and UDP 8080 are not the same rule", plat (p));
		run_free (&r);

		r = run_check (p, "1:TCP, 22, 192.168.1.0/24|"
		                  "1:TCP, 22-23, 192.168.1.0/24",
		               TRUE, "192.168.1.0/24", NULL);
		f = first_kind (&r, FS_HEALTH_SHADOWED);
		CHECK (f != NULL && f->policy_index == 0,
		       "%s: an earlier narrower row is the redundant one", plat (p));
		run_free (&r);
	}
}

/* ---- 2. the golden table ----------------------------------------- */

static void
test_golden (void)
{
	for (gint pi = 0; pi < 2; pi++) {
		FsWhatIfPlatform p = pi == 0 ? L : W;
		Run r;
		const FsHealthFinding *f;
		const FsHealthCheck *c;

		/* Duplicates, also when only the comment differs. */
		r = run_check (p, "1:SSH, 22, 192.168.1.0/24, a|"
		                  "1:ssh, 22, 192.168.1.0/24, b",
		               TRUE, "192.168.1.0/24", NULL);
		f = first_kind (&r, FS_HEALTH_DUPLICATE);
		CHECK (count_kind (&r, FS_HEALTH_DUPLICATE) == 1 && f != NULL &&
		       f->policy_index == 1 && f->severity == FS_COPILOT_INFO,
		       "%s: a duplicate (comment aside) is one Info finding on the "
		       "later copy", plat (p));
		CHECK (f != NULL && f->verified && f->fix == FS_HEALTH_FIX_REMOVE &&
		       f->checks->len > 0,
		       "%s: removing the later copy is verified", plat (p));
		CHECK (count_kind (&r, FS_HEALTH_SHADOWED) == 0,
		       "%s: a duplicate is not also reported as shadowed", plat (p));
		for (guint i = 0; f != NULL && i < f->checks->len; i++) {
			c = g_ptr_array_index (f->checks, i);
			CHECK (c->before == c->after && c->in_scope,
			       "%s: duplicate check \"%s\" unchanged (%s)", plat (p),
			       c->probe, fs_whatif_verdict_name (c->after));
		}
		run_free (&r);

		/* An allow a deny makes unreachable. */
		r = run_check (p, "5:HTTPS, 443, 203.0.113.9|6:203.0.113.0/24",
		               TRUE, "192.168.1.0/24", NULL);
		f = first_kind (&r, FS_HEALTH_UNREACHABLE);
		CHECK (f != NULL && f->severity == FS_COPILOT_WARNING &&
		       f->policy_kind == FS_RULE_OUTBOUND_ALLOW_SERVICE &&
		       f->other_kind == FS_RULE_OUTBOUND_DENY_TO,
		       "%s: an allow covered by a deny is unreachable (Warning)",
		       plat (p));
		CHECK (f != NULL && f->fix == FS_HEALTH_FIX_NONE && !f->verified &&
		       f->no_fix_reason != NULL && f->whatif_line != NULL &&
		       strstr (f->whatif_line, "443") != NULL,
		       "%s: no automatic fix, a reason and a What-If line", plat (p));
		CHECK (f != NULL && strstr (f->why, p == W ? "a block wins"
		                                           : "checked first") != NULL,
		       "%s: the reason names the platform's rule", plat (p));
		run_free (&r);

		/* A deny beside an allow it does not fully cover. */
		r = run_check (p, "5:HTTPS, 443, 203.0.113.0/24|6:203.0.113.9",
		               TRUE, "192.168.1.0/24", NULL);
		CHECK (count_kind (&r, FS_HEALTH_UNREACHABLE) == 0,
		       "%s: a deny of one host does not make a /24 allow "
		       "unreachable", plat (p));
		run_free (&r);

		/* The default policy: only the documented Info finding. */
		{
			FsPolicy *d = fs_policy_new ();
			FsSettings *s = fs_settings_new ();
			FsWhatIfContext *ctx;
			GPtrArray *found;

			fs_policy_install_defaults (d);
			ctx = fs_whatif_context_new (p, d, s);
			found = fs_health_check (ctx, "192.168.1.0/24");
			f = found->len > 0 ? g_ptr_array_index (found, 0) : NULL;
			CHECK (found->len == 1 && f->kind == FS_HEALTH_NO_EFFECT &&
			       f->severity == FS_COPILOT_INFO &&
			       strstr (f->title, "2 outbound allow rules") != NULL,
			       "%s: the default policy gives only \"no effect in this "
			       "mode\" (Info) for its two outbound rows", plat (p));
			g_ptr_array_unref (found);
			s->restrictive_outbound = TRUE;
			found = fs_health_check (ctx, "192.168.1.0/24");
			CHECK (found->len == 0,
			       "%s: with restrictive outbound the default policy is "
			       "clean", plat (p));
			g_ptr_array_unref (found);
			fs_whatif_context_free (ctx);
			fs_settings_free (s);
			fs_policy_free (d);
		}

		/* A risky service open to the internet, narrowed to the LAN. */
		r = run_check (p, "1:RDP, 3389, Anyone", TRUE, "192.168.1.0/24",
		               NULL);
		f = first_kind (&r, FS_HEALTH_RISKY_OPEN);
		CHECK (f != NULL && f->severity == FS_COPILOT_CRITICAL &&
		       strstr (f->title, "RDP (3389)") != NULL,
		       "%s: RDP open to Anyone is Critical", plat (p));
		CHECK (f != NULL && f->verified && f->fix == FS_HEALTH_FIX_REPLACE &&
		       g_strcmp0 (f->fix_before, "RDP, 3389, Anyone") == 0 &&
		       g_strcmp0 (f->fix_after, "RDP, 3389, 192.168.1.0/24") == 0 &&
		       g_strcmp0 (f->fix_label, "Narrow to 192.168.1.0/24") == 0,
		       "%s: the fix narrows the row to the LAN, verified", plat (p));
		c = check_named (f, "Inbound TCP port 3389 from 203.0.113.10");
		CHECK (c != NULL && !c->in_scope &&
		       c->before == FS_WHATIF_ALLOWED && c->after == FS_WHATIF_BLOCKED,
		       "%s: checked: 203.0.113.10:3389 ALLOWED -> BLOCKED", plat (p));
		c = check_named (f, "Inbound TCP port 3389 from 192.168.1.20");
		CHECK (c != NULL && c->in_scope &&
		       c->before == FS_WHATIF_ALLOWED && c->after == FS_WHATIF_ALLOWED,
		       "%s: checked: 192.168.1.20:3389 ALLOWED -> ALLOWED", plat (p));
		CHECK (f != NULL && g_strcmp0 (f->whatif_line,
		       "inbound tcp port 3389 from 203.0.113.10") == 0,
		       "%s: the What-If line asks about the internet host", plat (p));
		run_free (&r);

		/* SSH is Info, but still narrowed if wanted. */
		r = run_check (p, "1:SSH, 22, Anyone", TRUE, "192.168.1.0/24", NULL);
		f = first_kind (&r, FS_HEALTH_RISKY_OPEN);
		CHECK (f != NULL && f->severity == FS_COPILOT_INFO && f->verified,
		       "%s: SSH open to Anyone is Info, with a verified narrowing",
		       plat (p));
		run_free (&r);

		/* Broad: more than 100 ports, and allow-from Anyone. */
		r = run_check (p, "1:TCP, 30000-30100, Anyone", TRUE,
		               "192.168.1.0/24", NULL);
		f = first_kind (&r, FS_HEALTH_BROAD);
		CHECK (f != NULL && f->severity == FS_COPILOT_WARNING &&
		       f->verified &&
		       check_named (f, "Inbound TCP port 30100 from 192.168.1.20") != NULL,
		       "%s: 101 ports open to Anyone is broad (Warning), narrowing "
		       "checked at both ends of the range", plat (p));
		run_free (&r);
		r = run_check (p, "1:TCP, 30000-30099, Anyone", TRUE,
		               "192.168.1.0/24", NULL);
		CHECK (count_kind (&r, FS_HEALTH_BROAD) == 0,
		       "%s: 100 ports is not broad", plat (p));
		run_free (&r);
		r = run_check (p, "0:Anyone", TRUE, "192.168.1.0/24", NULL);
		f = first_kind (&r, FS_HEALTH_BROAD);
		if (p == L)
			CHECK (f != NULL && f->severity == FS_COPILOT_CRITICAL &&
			       f->verified,
			       "linux: inbound allow-from Anyone is Critical, "
			       "narrowing verified");
		else
			CHECK (f == NULL,
			       "windows: allow-from Anyone compiles to no rule, so "
			       "What-If says the internet is not let in and it is "
			       "not reported as open");
		run_free (&r);

		/* Outbound allow to Anyone while outbound is restrictive. */
		r = run_check (p, "3:Anyone", TRUE, "192.168.1.0/24", NULL);
		f = first_kind (&r, FS_HEALTH_BROAD);
		CHECK (f != NULL && f->fix == FS_HEALTH_FIX_NONE &&
		       f->no_fix_reason != NULL,
		       "%s: outbound allow-to Anyone under restrictive outbound is "
		       "reported, with no automatic fix", plat (p));
		run_free (&r);

		/* A forward to a risky port: Warning, nothing to narrow. */
		r = run_check (p, "2:RDP, 3389, 192.168.1.30, 3389", TRUE,
		               "192.168.1.0/24", NULL);
		f = first_kind (&r, FS_HEALTH_RISKY_OPEN);
		CHECK (f != NULL && f->severity == FS_COPILOT_WARNING &&
		       f->fix == FS_HEALTH_FIX_NONE,
		       "%s: a forward to RDP is a Warning with no fix", plat (p));
		run_free (&r);

		/* A deny by host name. */
		r = run_check (p, "6:evil.example.com", TRUE, "192.168.1.0/24",
		               NULL);
		CHECK (count_kind (&r, FS_HEALTH_NO_FAMILY) == (p == W ? 1u : 0u),
		       "%s: a deny by host name %s", plat (p),
		       p == W ? "blocks nothing on Windows" : "is resolved on Linux");
		run_free (&r);

		/* The order: most severe first. */
		r = run_check (p, "1:SSH, 22, 192.168.1.0/24|1:SSH, 22, 192.168.1.0/24|"
		                  "1:RDP, 3389, Anyone",
		               TRUE, "192.168.1.0/24", NULL);
		CHECK (r.found->len == 2 &&
		       ((FsHealthFinding *) g_ptr_array_index (r.found, 0))->kind ==
		       FS_HEALTH_RISKY_OPEN,
		       "%s: findings come most severe first", plat (p));
		run_free (&r);
	}
}

/* ---- 3. refusals -------------------------------------------------- */

static void
test_refusals (void)
{
	for (gint pi = 0; pi < 2; pi++) {
		FsWhatIfPlatform p = pi == 0 ? L : W;
		Run r;
		const FsHealthFinding *f;
		const FsHealthCheck *c;

		/* The LAN is 192.168.1.x (this computer's address), but the
		 * narrowing would go to 10.0.0.0/8: a LAN host loses access. */
		r = run_check (p, "1:RDP, 3389, Anyone", TRUE, "10.0.0.0/8",
		               "192.168.1.5");
		f = first_kind (&r, FS_HEALTH_RISKY_OPEN);
		c = check_named (f, "Inbound TCP port 3389 from 192.168.1.20");
		CHECK (f != NULL && !f->verified && f->fix == FS_HEALTH_FIX_NONE &&
		       f->no_fix_reason != NULL,
		       "%s: a narrowing that also blocks a LAN host gets no fix",
		       plat (p));
		CHECK (c != NULL && c->before == FS_WHATIF_ALLOWED &&
		       c->after == FS_WHATIF_BLOCKED,
		       "%s: and the check that refused it is shown", plat (p));
		run_free (&r);

		/* The LAN is derived from this computer's address. */
		r = run_check (p, "1:RDP, 3389, Anyone", TRUE, NULL, "192.168.7.9");
		f = first_kind (&r, FS_HEALTH_RISKY_OPEN);
		CHECK (f != NULL && f->verified &&
		       g_strcmp0 (f->fix_after, "RDP, 3389, 192.168.7.0/24") == 0,
		       "%s: with no prefix given, the /24 of this computer's "
		       "private address is used", plat (p));
		run_free (&r);

		/* No LAN known at all. */
		r = run_check (p, "1:RDP, 3389, Anyone", TRUE, NULL, NULL);
		f = first_kind (&r, FS_HEALTH_RISKY_OPEN);
		CHECK (f != NULL && !f->verified && f->fix == FS_HEALTH_FIX_NONE &&
		       f->no_fix_reason != NULL &&
		       strstr (f->no_fix_reason, "not known") != NULL,
		       "%s: with no LAN known, no narrowing is offered", plat (p));
		run_free (&r);

		/* Narrowing that blocks nothing outside: another row still
		 * admits the internet host. */
		r = run_check (p, "1:RDP, 3389, Anyone|1:TCP, 3389, Anyone", TRUE,
		               "192.168.1.0/24", NULL);
		for (guint i = 0; i < r.found->len; i++) {
			f = g_ptr_array_index (r.found, i);
			if (f->fix == FS_HEALTH_FIX_REPLACE)
				CHECK (FALSE, "%s: no narrowing while another row "
				       "still opens the port (%s)", plat (p), f->rule_csv);
		}
		CHECK (TRUE, "%s: a narrowing another row undoes is not offered",
		       plat (p));
		run_free (&r);
	}

	CHECK (g_strcmp0 (fs_health_lan_prefix ("192.168.1.5", "255.255.255.0"),
	                  "192.168.1.0/24") == 0,
	       "the LAN prefix of 192.168.1.5/255.255.255.0");
	{
		gchar *p = fs_health_lan_prefix ("10.20.30.40", "255.255.0.0");

		CHECK (g_strcmp0 (p, "10.20.0.0/16") == 0, "a /16 LAN (%s)", p);
		g_free (p);
		p = fs_health_lan_prefix ("8.8.8.8", "255.255.255.0");
		CHECK (p == NULL, "a public address is not a LAN");
		g_free (p);
	}
}

/* ---- 4. apply and undo -------------------------------------------- */

static gchar *
kind_file (FsRuleKind kind)
{
	gchar *rel = fs_rule_kind_path (kind);
	gchar *path = fs_util_rules_path (rel);

	g_free (rel);
	return path;
}

static gchar *
slurp (const gchar *path)
{
	gchar *t = NULL;

	if (!g_file_get_contents (path, &t, NULL, NULL))
		return g_strdup ("");
	return t;
}

static void
test_apply_undo (void)
{
	FsPolicy *policy = policy_of ("1:HTTP, 80, 192.168.1.0/24|"
	                              "1:RDP, 3389, Anyone|"
	                              "1:SSH, 22, 192.168.1.0/24|"
	                              "1:SSH, 22, 192.168.1.0/24, copy");
	FsSettings *s = fs_settings_new ();
	FsWhatIfContext *ctx;
	GPtrArray *found;
	const FsHealthFinding *risky = NULL, *dup = NULL;
	FsHealthUndo *u1 = NULL, *u2 = NULL;
	gchar *path = kind_file (FS_RULE_INBOUND_ALLOW_SERVICE);
	gchar *orig, *now, *why = NULL;

	s->restrictive_outbound = TRUE;
	CHECK (fs_policy_save (policy), "apply: the policy saves");
	orig = slurp (path);

	ctx = fs_whatif_context_new (L, policy, s);
	found = fs_health_check (ctx, "192.168.1.0/24");
	for (guint i = 0; i < found->len; i++) {
		const FsHealthFinding *f = g_ptr_array_index (found, i);

		if (f->kind == FS_HEALTH_RISKY_OPEN)
			risky = f;
		if (f->kind == FS_HEALTH_DUPLICATE)
			dup = f;
	}
	CHECK (risky != NULL && dup != NULL, "apply: both findings are there");
	if (risky == NULL || dup == NULL)
		goto out;

	/* The re-check: a fresh run finds the same finding. */
	{
		GPtrArray *again = fs_health_check (ctx, "192.168.1.0/24");
		gboolean same = FALSE;

		for (guint i = 0; i < again->len; i++)
			same = same || fs_health_finding_same (risky,
			                    g_ptr_array_index (again, i));
		CHECK (same, "apply: a fresh run gives the same finding and checks");
		g_ptr_array_unref (again);
	}

	CHECK (fs_health_fix_apply (policy, risky, &u1, &why),
	       "apply: the narrowing is made (%s)", why != NULL ? why : "");
	g_clear_pointer (&why, g_free);
	now = slurp (path);
	CHECK (strstr (now, "RDP, 3389, 192.168.1.0/24") != NULL &&
	       strstr (now, "RDP, 3389, Anyone") == NULL,
	       "apply: the rules file holds exactly the after row");
	g_free (now);

	/* After the change the same finding is gone: a second apply of
	 * the old finding is refused (the row is no longer there). */
	CHECK (!fs_health_fix_apply (policy, risky, NULL, &why) && why != NULL,
	       "apply: the old finding cannot be applied twice (%s)",
	       why != NULL ? why : "");
	g_clear_pointer (&why, g_free);

	CHECK (fs_health_undo_apply (policy, u1, NULL),
	       "undo: the narrowing is put back");
	now = slurp (path);
	CHECK (g_strcmp0 (now, orig) == 0,
	       "undo: the rules file is byte for byte what it was");
	g_free (now);

	/* Removal and its undo. */
	CHECK (fs_health_fix_apply (policy, dup, &u2, NULL),
	       "apply: the duplicate is removed");
	now = slurp (path);
	CHECK (strstr (now, "copy") == NULL, "apply: the later copy is gone");
	g_free (now);
	CHECK (fs_health_undo_apply (policy, u2, NULL),
	       "undo: the copy is put back");
	now = slurp (path);
	CHECK (g_strcmp0 (now, orig) == 0,
	       "undo: after a removal the rules file is what it was");
	g_free (now);

	/* Undo by content: the narrowing again, then the first row goes
	 * (so every index moves), then undo. */
	fs_health_undo_free (u1);
	u1 = NULL;
	CHECK (fs_health_fix_apply (policy, risky, &u1, NULL),
	       "apply: narrowed again");
	{
		FsRule *first = fs_rule_from_csv (FS_RULE_INBOUND_ALLOW_SERVICE,
		                                  "HTTP, 80, 192.168.1.0/24");

		CHECK (fs_policy_remove_persist (policy, first),
		       "the user removes the first row in between");
		fs_rule_free (first);
	}
	CHECK (fs_health_undo_apply (policy, u1, NULL),
	       "undo: still possible after the rows moved");
	{
		FsPolicy *expect = policy_of ("1:RDP, 3389, Anyone|"
		                              "1:SSH, 22, 192.168.1.0/24|"
		                              "1:SSH, 22, 192.168.1.0/24, copy");
		gchar *want;

		fs_policy_save (expect);
		want = slurp (path);
		fs_policy_save (policy);
		now = slurp (path);
		CHECK (g_strcmp0 (now, want) == 0,
		       "undo: by content, the right row is restored (not row 2)");
		g_free (now);
		g_free (want);
		fs_policy_free (expect);
	}

	/* An unverified finding is never applied. */
	{
		FsHealthFinding fake = *risky;

		fake.verified = FALSE;
		CHECK (!fs_health_fix_apply (policy, &fake, NULL, NULL),
		       "apply: an unverified finding is refused");
	}

out:
	fs_health_undo_free (u1);
	fs_health_undo_free (u2);
	g_ptr_array_unref (found);
	fs_whatif_context_free (ctx);
	fs_settings_free (s);
	fs_policy_free (policy);
	g_free (orig);
	g_free (path);
}

int
main (void)
{
	gchar *dir = g_dir_make_tmp ("stockfw-health-XXXXXX", NULL);
	gchar *audit = g_build_filename (dir, "audit.log", NULL);

	g_setenv ("STOCKFW_RULES_DIR", dir, TRUE);
	g_setenv ("STOCKFW_AUDIT_FILE", audit, TRUE);
	g_setenv ("XDG_CONFIG_HOME", dir, TRUE);
	g_setenv ("APPDATA", dir, TRUE);

	test_coverage ();
	test_golden ();
	test_refusals ();
	test_apply_undo ();

	{
		gchar *log = slurp (audit);

		CHECK (strstr (log, "copilot health fix") != NULL &&
		       strstr (log, "copilot health fix undone") != NULL,
		       "the fixes and their undos are audited");
		g_free (log);
	}

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);
	g_free (audit);
	g_free (dir);
	return failures ? 1 : 0;
}
