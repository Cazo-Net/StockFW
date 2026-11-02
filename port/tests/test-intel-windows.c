/*---[ test-intel-windows.c ]--------------------------------------------
 * Threat intel on the real Windows Firewall (1.0.7 Round 3, design
 * section 11): the Windows backend's intel slots against the firewall
 * itself, and every rule they leave read back independently, through
 * INetFwPolicy2 here, not through the backend's own reader.
 *
 * What it checks:
 *   - apply writes the planned rules: names, group, block, direction,
 *     every profile and protocol, the addresses (chunked at the real
 *     1000-address limit), the disabled manifest;
 *   - intel_live reads them PRESENT with the rule set's digest;
 *   - applying the same rule set again changes nothing; a changed one
 *     replaces every old rule;
 *   - a rule disabled or added in the group by hand reads PARTIAL, and
 *     an apply repairs it;
 *   - with every profile off the rules read INACTIVE and
 *     intel_not_in_force says why (profiles restored afterwards);
 *   - clear removes every rule in the group and nothing else: a rule
 *     with one of our names in another group survives, and every rule
 *     outside the group is exactly as it was before the test;
 *   - the store directory (STOCKFW_INTEL_DIR override) gets a protected
 *     DACL naming only SYSTEM, Administrators and the current user.
 *
 * Windows only, elevated only: a plain shell prints SKIP and exits 0,
 * as does a computer whose firewall service is stopped or that already
 * holds StockFW blocklist rules (they are the user's; never touched).
 * Built by `ninja -C build fs-intel-windows-test'; tests/full-suite.sh
 * runs it on Windows.
 *--------------------------------------------------------------------*/

#define _WIN32_WINNT 0x0601
#define COBJMACROS
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <netfw.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-intel.h"
#include "core/fs-intelset.h"
#include "core/fs-intelwin.h"
#include "core/fs-iprange.h"
#include "platform/windows/netfw-compat.h"

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

/* A rule of somebody else's with one of our names, in another group:
 * removing ours must never take it. */
#define DECOY_GROUP "StockFW Test Decoy"
#define FOREIGN_IN_GROUP "Not StockFW's rule"

/* ------------------------------------------------------------- COM */

static INetFwPolicy2 *policy;
static INetFwRules   *rules;

static BSTR
bstr (const gchar *utf8)
{
	gunichar2 *w = g_utf8_to_utf16 (utf8, -1, NULL, NULL, NULL);
	BSTR b = SysAllocString ((const OLECHAR *) w);

	g_free (w);
	return b;
}

static gchar *
utf8 (BSTR b)
{
	gchar *s = b != NULL ? g_utf16_to_utf8 ((const gunichar2 *) b,
	                                        (glong) SysStringLen (b),
	                                        NULL, NULL, NULL)
	                     : g_strdup ("");

	SysFreeString (b);
	return s;
}

/* One rule as this test sees it. */
typedef struct
{
	gchar *name, *group, *desc, *remote, *local, *lports, *rports, *app,
	      *svc, *iftypes;
	LONG   dir, action, profiles, protocol;
	gboolean enabled;
} Rule;

static void
rule_free (gpointer p)
{
	Rule *r = p;

	if (r == NULL)
		return;
	g_free (r->name); g_free (r->group); g_free (r->desc);
	g_free (r->remote); g_free (r->local); g_free (r->lports);
	g_free (r->rports); g_free (r->app); g_free (r->svc);
	g_free (r->iftypes);
	g_free (r);
}

/* Every rule on the firewall, read here, not by the backend. */
static GPtrArray *
list_rules (void)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (rule_free);
	IUnknown *unk = NULL;
	IEnumVARIANT *en = NULL;

	if (FAILED (rules->lpVtbl->get__NewEnum (rules, &unk)) || unk == NULL)
		return out;
	unk->lpVtbl->QueryInterface (unk, &FS_IID_IEnumVARIANT, (void **) &en);
	unk->lpVtbl->Release (unk);
	if (en == NULL)
		return out;
	for (;;) {
		VARIANT v;
		ULONG got = 0;
		INetFwRule *r = NULL;

		VariantInit (&v);
		if (en->lpVtbl->Next (en, 1, &v, &got) != S_OK || got == 0)
			break;
		if (v.vt == VT_DISPATCH && v.pdispVal != NULL &&
		    SUCCEEDED (v.pdispVal->lpVtbl->QueryInterface (
			    v.pdispVal, &FS_IID_INetFwRule, (void **) &r))) {
			Rule *x = g_new0 (Rule, 1);
			BSTR b;
			NET_FW_RULE_DIRECTION d = 0;
			NET_FW_ACTION a = 0;
			VARIANT_BOOL on = VARIANT_FALSE;

			b = NULL; r->lpVtbl->get_Name (r, &b);           x->name = utf8 (b);
			b = NULL; r->lpVtbl->get_Grouping (r, &b);       x->group = utf8 (b);
			b = NULL; r->lpVtbl->get_Description (r, &b);    x->desc = utf8 (b);
			b = NULL; r->lpVtbl->get_RemoteAddresses (r, &b);x->remote = utf8 (b);
			b = NULL; r->lpVtbl->get_LocalAddresses (r, &b); x->local = utf8 (b);
			b = NULL; r->lpVtbl->get_LocalPorts (r, &b);     x->lports = utf8 (b);
			b = NULL; r->lpVtbl->get_RemotePorts (r, &b);    x->rports = utf8 (b);
			b = NULL; r->lpVtbl->get_ApplicationName (r, &b);x->app = utf8 (b);
			b = NULL; r->lpVtbl->get_ServiceName (r, &b);    x->svc = utf8 (b);
			b = NULL; r->lpVtbl->get_InterfaceTypes (r, &b); x->iftypes = utf8 (b);
			r->lpVtbl->get_Direction (r, &d);
			r->lpVtbl->get_Action (r, &a);
			r->lpVtbl->get_Enabled (r, &on);
			r->lpVtbl->get_Profiles (r, &x->profiles);
			r->lpVtbl->get_Protocol (r, &x->protocol);
			x->dir = (LONG) d;
			x->action = (LONG) a;
			x->enabled = on != VARIANT_FALSE;
			g_ptr_array_add (out, x);
			r->lpVtbl->Release (r);
		}
		VariantClear (&v);
	}
	en->lpVtbl->Release (en);
	return out;
}

static gchar *
rule_line (const Rule *r)
{
	return g_strdup_printf ("%s|%s|%s|%ld|%ld|%ld|%ld|%d|%s|%s|%s|%s|%s|%s|%s",
	                        r->name, r->group, r->desc, r->dir, r->action,
	                        r->profiles, r->protocol, r->enabled,
	                        r->remote, r->local, r->lports, r->rports,
	                        r->app, r->svc, r->iftypes);
}

/* Every rule outside our group, sorted, as one text. */
static gchar *
others_snapshot (void)
{
	GPtrArray *all = list_rules ();
	GPtrArray *lines = g_ptr_array_new_with_free_func (g_free);
	GString *out = g_string_new (NULL);

	for (guint i = 0; i < all->len; i++) {
		const Rule *r = all->pdata[i];

		if (!fs_intelwin_in_group (r->group))
			g_ptr_array_add (lines, rule_line (r));
	}
	g_ptr_array_sort (lines, (GCompareFunc) g_strcmp0);
	for (guint i = 0; i < lines->len; i++) {
		g_string_append (out, lines->pdata[i]);
		g_string_append_c (out, '\n');
	}
	g_ptr_array_unref (lines);
	g_ptr_array_unref (all);
	return g_string_free (out, FALSE);
}

static GPtrArray *
ours (void)
{
	GPtrArray *all = list_rules ();
	GPtrArray *out = g_ptr_array_new_with_free_func (rule_free);

	for (guint i = 0; i < all->len; i++)
		if (fs_intelwin_in_group (((Rule *) all->pdata[i])->group))
			g_ptr_array_add (out, g_steal_pointer (&all->pdata[i]));
	g_ptr_array_unref (all);
	return out;
}

static gboolean
add_rule (const gchar *name, const gchar *group, NET_FW_RULE_DIRECTION dir,
          NET_FW_ACTION action, const gchar *remote, gboolean enabled)
{
	INetFwRule *r = NULL;
	BSTR n, g, a;
	HRESULT hr;

	hr = CoCreateInstance (&FS_CLSID_NetFwRule, NULL, CLSCTX_INPROC_SERVER,
	                       &FS_IID_INetFwRule, (void **) &r);
	if (FAILED (hr) || r == NULL)
		return FALSE;
	n = bstr (name);
	g = bstr (group);
	a = bstr (remote);
	r->lpVtbl->put_Name (r, n);
	r->lpVtbl->put_Grouping (r, g);
	r->lpVtbl->put_Direction (r, dir);
	r->lpVtbl->put_Action (r, action);
	r->lpVtbl->put_RemoteAddresses (r, a);
	r->lpVtbl->put_Enabled (r, enabled ? VARIANT_TRUE : VARIANT_FALSE);
	hr = rules->lpVtbl->Add (rules, r);
	SysFreeString (n);
	SysFreeString (g);
	SysFreeString (a);
	r->lpVtbl->Release (r);
	return SUCCEEDED (hr);
}

/* Removes every rule called `name' in `group' (by renaming it to a
 * unique name first, so a same-named rule elsewhere is never hit). */
static guint
remove_rules (const gchar *name, const gchar *group)
{
	IUnknown *unk = NULL;
	IEnumVARIANT *en = NULL;
	GPtrArray *hit = g_ptr_array_new ();
	guint removed = 0;

	if (FAILED (rules->lpVtbl->get__NewEnum (rules, &unk)) || unk == NULL)
		return 0;
	unk->lpVtbl->QueryInterface (unk, &FS_IID_IEnumVARIANT, (void **) &en);
	unk->lpVtbl->Release (unk);
	for (;;) {
		VARIANT v;
		ULONG got = 0;
		INetFwRule *r = NULL;

		VariantInit (&v);
		if (en == NULL || en->lpVtbl->Next (en, 1, &v, &got) != S_OK ||
		    got == 0)
			break;
		if (v.vt == VT_DISPATCH && v.pdispVal != NULL &&
		    SUCCEEDED (v.pdispVal->lpVtbl->QueryInterface (
			    v.pdispVal, &FS_IID_INetFwRule, (void **) &r))) {
			BSTR b = NULL;
			gchar *n, *g;

			r->lpVtbl->get_Name (r, &b);
			n = utf8 (b);
			b = NULL;
			r->lpVtbl->get_Grouping (r, &b);
			g = utf8 (b);
			if (g_strcmp0 (n, name) == 0 && g_strcmp0 (g, group) == 0)
				g_ptr_array_add (hit, r);
			else
				r->lpVtbl->Release (r);
			g_free (n);
			g_free (g);
		}
		VariantClear (&v);
	}
	if (en != NULL)
		en->lpVtbl->Release (en);
	for (guint i = 0; i < hit->len; i++) {
		INetFwRule *r = hit->pdata[i];
		gchar *tmp = g_strdup_printf ("StockFW test removal %u %08x", i,
		                              g_random_int ());
		BSTR t = bstr (tmp);

		if (SUCCEEDED (r->lpVtbl->put_Name (r, t)) &&
		    SUCCEEDED (rules->lpVtbl->Remove (rules, t)))
			removed++;
		SysFreeString (t);
		g_free (tmp);
		r->lpVtbl->Release (r);
	}
	g_ptr_array_free (hit, TRUE);
	return removed;
}

static gboolean
set_enabled (const gchar *name, gboolean on)
{
	INetFwRule *r = NULL;
	BSTR n = bstr (name);
	HRESULT hr = rules->lpVtbl->Item (rules, n, &r);

	SysFreeString (n);
	if (FAILED (hr) || r == NULL)
		return FALSE;
	hr = r->lpVtbl->put_Enabled (r, on ? VARIANT_TRUE : VARIANT_FALSE);
	r->lpVtbl->Release (r);
	return SUCCEEDED (hr);
}

/* ----------------------------------------------------------- checks */

static FsRangeSet *
set_of (const gchar *const *tokens)
{
	FsRangeSet *s = fs_range_set_new ();

	for (guint i = 0; tokens[i] != NULL; i++)
		fs_range_set_add_text (s, tokens[i]);
	fs_range_set_normalize (s);
	return s;
}

static FsIntelRuleset *
ruleset (gboolean changed)
{
	static const gchar *const a[] = {
		"192.0.2.0/28", "198.51.100.7", "203.0.113.10-203.0.113.20",
		"2001:db8:1::/48", "2001:db8:2::5", NULL };
	static const gchar *const b[] = {
		"192.0.2.0/28", "198.51.100.8", "203.0.113.10-203.0.113.20",
		"2001:db8:1::/48", NULL };
	FsIntelRuleset *rs = fs_intel_ruleset_new ();
	FsRangeSet *big = fs_range_set_new ();

	fs_intel_ruleset_add (rs, "wintest", "StockFW Windows test",
	                      FS_INTEL_DIR_BOTH, set_of (changed ? b : a));
	/* 2500 separate addresses in 240.0.0.0/4 (reserved, never routed):
	 * three rules at the real 1000-address limit. */
	for (guint i = 0; i < 2500; i++)
		fs_range_set_add4 (big, 0xf0000000u + i * 4, 0xf0000000u + i * 4);
	fs_range_set_normalize (big);
	fs_intel_ruleset_add (rs, "wintest-big", "StockFW Windows test, big",
	                      FS_INTEL_DIR_IN, big);
	return rs;
}

/* The rules on the firewall are exactly the plan for `rs' under the
 * generation they carry. */
static void
check_rules_are_plan (const FsIntelRuleset *rs, const gchar *what,
                      gchar **gen_out)
{
	GPtrArray *got = ours ();
	const gchar *gen = NULL;
	FsIntelWinPlan *plan;
	gboolean same = TRUE;

	for (guint i = 0; i < got->len && gen == NULL; i++)
		gen = fs_intelwin_name_gen (((Rule *) got->pdata[i])->name);
	plan = gen != NULL ? fs_intelwin_plan (rs, gen, FS_INTELWIN_MAX_TOKENS,
	                                       FS_INTELWIN_MAX_CHARS)
	                   : NULL;
	CHECK (plan != NULL && got->len == plan->rules->len,
	       "%s: the group holds %u rules, the plan %u", what, got->len,
	       plan ? plan->rules->len : 0);
	for (guint i = 0; plan != NULL && i < plan->rules->len; i++) {
		const FsIntelWinRule *want = plan->rules->pdata[i];
		const Rule *r = NULL;

		for (guint k = 0; k < got->len; k++)
			if (strcmp (((Rule *) got->pdata[k])->name, want->name) == 0)
				r = got->pdata[k];
		if (r == NULL) {
			printf ("      missing: %s\n", want->name);
			same = FALSE;
			continue;
		}
		if (r->dir != (LONG) want->dir || r->action != NET_FW_ACTION_BLOCK ||
		    (r->profiles & FS_NETFW_PROFILE_ALL) != FS_NETFW_PROFILE_ALL ||
		    r->protocol != FS_NETFW_PROTO_ANY ||
		    r->enabled != want->enabled ||
		    strcmp (r->desc, want->description) != 0 ||
		    (strcmp (r->local, "*") != 0 && *r->local != '\0') ||
		    *r->app != '\0' || *r->svc != '\0') {
			printf ("      differs: %s\n", want->name);
			same = FALSE;
		}
		{
			FsRangeSet *a = fs_range_set_new (), *b = fs_range_set_new ();
			gchar *ta, *tb;

			fs_intelwin_parse_remote (r->remote, a);
			fs_intelwin_parse_remote (want->remote, b);
			fs_range_set_normalize (a);
			fs_range_set_normalize (b);
			ta = fs_range_set_to_text (a);
			tb = fs_range_set_to_text (b);
			if (strcmp (ta, tb) != 0) {
				printf ("      addresses differ: %s\n", want->name);
				same = FALSE;
			}
			g_free (ta); g_free (tb);
			fs_range_set_free (a); fs_range_set_free (b);
		}
	}
	CHECK (plan != NULL && same,
	       "%s: every rule, read back through INetFwRules, has the "
	       "planned name, direction, block action, every profile and "
	       "protocol, description and addresses", what);
	if (gen_out != NULL)
		*gen_out = g_strdup (gen);
	fs_intelwin_plan_free (plan);
	g_ptr_array_unref (got);
}

static FsIntelLive
live (gchar **digest)
{
	return fs_backend ()->intel_live (digest);
}

static void
check_store_dacl (void)
{
	gchar *tmp = g_dir_make_tmp ("sfw-intel-XXXXXX", NULL);
	gchar *dir = tmp ? g_build_filename (tmp, "intel", NULL) : NULL;
	gchar *got;
	GError *e = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;
	PACL dacl = NULL;
	SECURITY_DESCRIPTOR_CONTROL ctl = 0;
	DWORD rev = 0;
	gboolean only_known = TRUE;
	gunichar2 *w;

	if (dir == NULL) {
		CHECK (FALSE, "store: a temporary directory");
		return;
	}
	g_setenv ("STOCKFW_INTEL_DIR", dir, TRUE);
	got = fs_intel_dir (&e);
	CHECK (got != NULL, "store: the override directory is created (%s)",
	       e ? e->message : "ok");
	g_clear_error (&e);
	w = g_utf8_to_utf16 (dir, -1, NULL, NULL, NULL);
	if (got != NULL &&
	    GetNamedSecurityInfoW ((LPWSTR) w, SE_FILE_OBJECT,
	                           DACL_SECURITY_INFORMATION, NULL, NULL,
	                           &dacl, NULL, &sd) == ERROR_SUCCESS &&
	    dacl != NULL) {
		HANDLE token = NULL;
		BYTE ub[256];
		DWORD ul = sizeof ub;
		PSID me = NULL;

		if (OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token) &&
		    GetTokenInformation (token, TokenUser, ub, ul, &ul))
			me = ((TOKEN_USER *) ub)->User.Sid;
		GetSecurityDescriptorControl (sd, &ctl, &rev);
		for (DWORD i = 0; i < dacl->AceCount; i++) {
			ACCESS_ALLOWED_ACE *ace = NULL;
			PSID sid;
			LPSTR text = NULL;

			if (!GetAce (dacl, i, (LPVOID *) &ace))
				continue;
			sid = (PSID) &ace->SidStart;
			if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
			    !(IsWellKnownSid (sid, WinLocalSystemSid) ||
			      IsWellKnownSid (sid, WinBuiltinAdministratorsSid) ||
			      (me != NULL && EqualSid (sid, me)))) {
				ConvertSidToStringSidA (sid, &text);
				printf ("      unexpected ACE for %s\n",
				        text ? text : "?");
				LocalFree (text);
				only_known = FALSE;
			}
		}
		if (token != NULL)
			CloseHandle (token);
		CHECK ((ctl & SE_DACL_PROTECTED) != 0 && only_known,
		       "store: the directory's DACL is protected (nothing "
		       "inherited) and names only SYSTEM, Administrators and "
		       "the current user");
	} else if (got != NULL) {
		CHECK (FALSE, "store: the directory's DACL can be read");
	}
	if (sd != NULL)
		LocalFree (sd);
	g_free (w);
	g_free (got);
	g_rmdir (dir);
	g_rmdir (tmp);
	g_unsetenv ("STOCKFW_INTEL_DIR");
	g_free (dir);
	g_free (tmp);
}

/* ------------------------------------------------------------- main */

static gboolean
elevated (void)
{
	HANDLE token = NULL;
	TOKEN_ELEVATION te = { 0 };
	DWORD len = sizeof te;
	gboolean yes = FALSE;

	if (OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token)) {
		yes = GetTokenInformation (token, TokenElevation, &te, len,
		                           &len) && te.TokenIsElevated;
		CloseHandle (token);
	}
	return yes;
}

int
main (void)
{
	const FsBackend *b = fs_backend ();
	FsIntelRuleset *rs1, *rs2;
	gchar *before, *after, *digest = NULL, *gen1 = NULL, *gen2 = NULL,
	      *gen = NULL, *why, *want1, *want2;
	gboolean saved[FS_PROFILE_COUNT] = { TRUE, TRUE, TRUE };
	GError *e = NULL;
	FsIntelLive l;
	HRESULT hr;

	if (!elevated ()) {
		printf ("SKIP: not elevated; the Windows Firewall rules cannot be "
		        "changed. Re-run from an elevated shell.\n");
		return 0;
	}
	if (b->intel_apply == NULL || b->intel_clear == NULL ||
	    b->intel_live == NULL) {
		printf ("FAIL: the Windows backend has no threat-intel slots\n");
		return 1;
	}
	why = b->intel_not_in_force != NULL ? b->intel_not_in_force () : NULL;
	if (why != NULL && strstr (why, "MpsSvc") != NULL) {
		printf ("SKIP: %s\n", why);
		g_free (why);
		return 0;
	}
	g_free (why);
	l = live (NULL);
	if (l != FS_INTEL_LIVE_ABSENT) {
		printf ("SKIP: this computer already holds StockFW blocklist rules "
		        "(or they cannot be read: %d); they are left alone.\n",
		        (int) l);
		return 0;
	}

	hr = CoInitializeEx (NULL, COINIT_APARTMENTTHREADED);
	if (FAILED (hr) && hr != RPC_E_CHANGED_MODE) {
		printf ("FAIL: COM\n");
		return 1;
	}
	if (FAILED (CoCreateInstance (&FS_CLSID_NetFwPolicy2, NULL,
	                              CLSCTX_INPROC_SERVER,
	                              &FS_IID_INetFwPolicy2,
	                              (void **) &policy)) ||
	    FAILED (policy->lpVtbl->get_Rules (policy, &rules))) {
		printf ("FAIL: INetFwPolicy2\n");
		return 1;
	}

	rs1 = ruleset (FALSE);
	rs2 = ruleset (TRUE);
	want1 = fs_intel_ruleset_digest (rs1);
	want2 = fs_intel_ruleset_digest (rs2);

	/* The decoy: one of the names apply will use is not known yet (the
	 * generation is random), so the decoy is planted after the first
	 * apply, with that apply's manifest name. */
	before = others_snapshot ();

	/* ---- apply ------------------------------------------------------ */
	CHECK (b->intel_apply (rs1, &e), "apply: the backend reports success "
	       "(%s)", e ? e->message : "ok");
	g_clear_error (&e);
	check_rules_are_plan (rs1, "apply", &gen1);
	l = live (&digest);
	CHECK ((l == FS_INTEL_LIVE_PRESENT || l == FS_INTEL_LIVE_INACTIVE) &&
	       g_strcmp0 (digest, want1) == 0,
	       "apply: intel_live reads the rules whole with the rule set's "
	       "digest (%d, %s)", (int) l, digest);
	g_clear_pointer (&digest, g_free);

	{
		gchar *decoy = g_strdup_printf ("SFW-TI wintest in IPv4 1/1 %s",
		                                gen1 ? gen1 : "g00000000");

		CHECK (add_rule (decoy, DECOY_GROUP, NET_FW_RULE_DIR_IN,
		                 NET_FW_ACTION_BLOCK, "192.0.2.250", FALSE),
		       "setup: a disabled decoy rule named like ours, in "
		       "another group");
		g_free (decoy);
		g_free (before);
		before = others_snapshot ();
	}

	/* ---- the same rule set again: nothing changes -------------------- */
	CHECK (b->intel_apply (rs1, &e), "re-apply: success (%s)",
	       e ? e->message : "ok");
	g_clear_error (&e);
	check_rules_are_plan (rs1, "re-apply", &gen);
	CHECK (g_strcmp0 (gen, gen1) == 0,
	       "re-apply: the same rule set leaves the same rules (%s)", gen);
	g_clear_pointer (&gen, g_free);

	/* ---- a changed rule set replaces every old rule ------------------ */
	CHECK (b->intel_apply (rs2, &e), "changed apply: success (%s)",
	       e ? e->message : "ok");
	g_clear_error (&e);
	check_rules_are_plan (rs2, "changed apply", &gen2);
	CHECK (g_strcmp0 (gen2, gen1) != 0,
	       "changed apply: a new generation, and (above) no rule of the "
	       "old one is left");
	l = live (&digest);
	CHECK (g_strcmp0 (digest, want2) == 0,
	       "changed apply: intel_live reads the new digest");
	g_clear_pointer (&digest, g_free);

	/* ---- tampering reads PARTIAL; an apply repairs it ---------------- */
	{
		gchar *one = g_strdup_printf ("SFW-TI wintest-big in IPv4 2/3 %s",
		                              gen2);

		CHECK (set_enabled (one, FALSE), "tamper: one rule disabled by "
		       "hand");
		l = live (&digest);
		CHECK (l == FS_INTEL_LIVE_PARTIAL && digest == NULL,
		       "tamper: a disabled rule reads PARTIAL, no digest (%d)",
		       (int) l);
		g_clear_pointer (&digest, g_free);
		CHECK (b->intel_apply (rs2, &e),
		       "tamper: an apply of the same rule set succeeds (%s)",
		       e ? e->message : "ok");
		g_clear_error (&e);
		check_rules_are_plan (rs2, "repaired", NULL);
		g_free (one);
	}
	CHECK (add_rule (FOREIGN_IN_GROUP, FS_INTELWIN_GROUP,
	                 NET_FW_RULE_DIR_IN, NET_FW_ACTION_ALLOW, "192.0.2.251",
	                 FALSE),
	       "tamper: a rule StockFW did not write added to its group");
	l = live (NULL);
	CHECK (l == FS_INTEL_LIVE_PARTIAL,
	       "tamper: a foreign rule in the group reads PARTIAL (%d)", (int) l);

	/* ---- not in force ------------------------------------------------ */
	for (gint i = 0; i < FS_PROFILE_COUNT; i++)
		b->get_profile_enabled (i, &saved[i]);
	if (b->intel_apply (rs2, NULL)) {
		gboolean off_ok = TRUE;

		for (gint i = 0; i < FS_PROFILE_COUNT; i++)
			off_ok &= b->set_profile_enabled (i, FALSE, NULL);
		l = live (&digest);
		why = b->intel_not_in_force ();
		CHECK (off_ok && l == FS_INTEL_LIVE_INACTIVE &&
		       g_strcmp0 (digest, want2) == 0 && why != NULL,
		       "not in force: every profile off reads INACTIVE with the "
		       "digest, and says why (%s)", why ? why : "nothing");
		g_free (why);
		g_clear_pointer (&digest, g_free);
		for (gint i = 0; i < FS_PROFILE_COUNT; i++)
			b->set_profile_enabled (i, saved[i], NULL);
	}

	/* ---- clear ------------------------------------------------------- */
	CHECK (b->intel_clear (&e), "clear: success (%s)", e ? e->message : "ok");
	g_clear_error (&e);
	{
		GPtrArray *left = ours ();

		CHECK (left->len == 0, "clear: no rule is left in the group (%u)",
		       left->len);
		g_ptr_array_unref (left);
	}
	CHECK (live (NULL) == FS_INTEL_LIVE_ABSENT, "clear: intel_live reads "
	       "ABSENT");
	after = others_snapshot ();
	CHECK (g_strcmp0 (before, after) == 0,
	       "clear: every rule outside the group, the decoy named like ours "
	       "included, is exactly as it was");
	CHECK (b->intel_clear (&e), "clear: clearing nothing succeeds");
	g_clear_error (&e);

	/* ---- leave the firewall as it was -------------------------------- */
	{
		gchar *decoy = g_strdup_printf ("SFW-TI wintest in IPv4 1/1 %s",
		                                gen1 ? gen1 : "g00000000");

		CHECK (remove_rules (decoy, DECOY_GROUP) == 1,
		       "cleanup: the decoy is removed");
		g_free (decoy);
	}
	remove_rules (FOREIGN_IN_GROUP, FS_INTELWIN_GROUP);

	check_store_dacl ();

	g_free (before);
	g_free (after);
	g_free (gen1);
	g_free (gen2);
	g_free (want1);
	g_free (want2);
	fs_intel_ruleset_free (rs1);
	fs_intel_ruleset_free (rs2);
	rules->lpVtbl->Release (rules);
	policy->lpVtbl->Release (policy);

	printf ("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED",
	        failures);
	return failures ? 1 : 0;
}
