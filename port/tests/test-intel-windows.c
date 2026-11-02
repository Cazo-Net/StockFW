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
 * With STOCKFW_REQUIRE_WINDOWS_INTEL=1 (the CI's Windows job) every
 * skip is a failure, and rules that cannot be read always are.
 *
 * Review additions: an apply over a foreign rule in the group repairs
 * it; the policy's own clear works beside blocklists of more than
 * 16 MiB of addresses and leaves them whole; a %ProgramData%\StockFW
 * another account made first (a folder, a link) is moved aside.
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
#include <shlobj.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "core/fs-backend.h"
#include "core/fs-intel.h"
#include "core/fs-intelset.h"
#include "core/fs-intelwin.h"
#include "core/fs-iprange.h"
#include "core/fs-util.h"
#include "core/fs-winstore.h"
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

/* The engine lock on Windows (fs_winstore_lock, design 11.12): a
 * second holder, even a thread of this process with its own handle,
 * waits until the first lets go, and says it waited. */
static void skip_part (const gchar *why);

typedef struct
{
	const gchar *dir;
	gpointer     handle;
	gboolean     waited;
	volatile gint done;
} LockWaiter;

static gpointer
lock_waiter (gpointer data)
{
	LockWaiter *w = data;

	w->handle = fs_winstore_lock (w->dir, "engine.lock", &w->waited);
	g_atomic_int_set (&w->done, 1);
	return NULL;
}

static void
check_engine_lock (void)
{
	gchar *tmp = g_dir_make_tmp ("sfw-lock-XXXXXX", NULL);
	gchar *link_path, *target;
	gpointer first;
	gboolean waited = TRUE;
	LockWaiter w = { 0 };
	GThread *t;

	if (tmp == NULL) {
		CHECK (FALSE, "engine lock: a temporary directory");
		return;
	}
	first = fs_winstore_lock (tmp, "engine.lock", &waited);
	CHECK (first != NULL && !waited,
	       "engine lock: taken at once when nobody holds it");
	w.dir = tmp;
	t = g_thread_new ("lock-waiter", lock_waiter, &w);
	g_usleep (300 * 1000);
	CHECK (g_atomic_int_get (&w.done) == 0,
	       "engine lock: a second holder (another handle, another "
	       "thread) waits while the first holds it");
	fs_winstore_unlock (first);
	g_thread_join (t);
	CHECK (w.handle != NULL && w.waited,
	       "engine lock: ... and gets it once the first lets go, "
	       "saying it waited");
	fs_winstore_unlock (w.handle);

	/* A link where the lock file goes is refused, never followed. */
	link_path = g_build_filename (tmp, "linked.lock", NULL);
	target = g_build_filename (tmp, "elsewhere", NULL);
	g_file_set_contents (target, "x", 1, NULL);
	{
		gunichar2 *wl = g_utf8_to_utf16 (link_path, -1, NULL, NULL, NULL);
		gunichar2 *wt = g_utf8_to_utf16 (target, -1, NULL, NULL, NULL);

		if (CreateSymbolicLinkW ((LPCWSTR) wl, (LPCWSTR) wt, 0)) {
			gpointer h = fs_winstore_lock (tmp, "linked.lock", NULL);

			CHECK (h == NULL, "engine lock: a symbolic link in its "
			       "place is refused");
			fs_winstore_unlock (h);
			DeleteFileW ((LPCWSTR) wl);
		} else {
			skip_part ("engine lock: cannot make a symbolic link "
			           "here");
		}
		g_free (wl);
		g_free (wt);
	}
	g_remove (target);
	g_remove (link_path);
	{
		gchar *f = g_build_filename (tmp, "engine.lock", NULL);

		g_remove (f);
		g_free (f);
	}
	g_rmdir (tmp);
	g_free (target);
	g_free (link_path);
	g_free (tmp);
}

/* ------------------------------------------------------------- main */

/* A test that could not run.  On a developer's computer that is a SKIP
 * and exit 0; with STOCKFW_REQUIRE_WINDOWS_INTEL=1 (set by the CI's
 * Windows job, where everything is in place) it is a failure, so a
 * skip can never pass the job silently (review W1). */
static gboolean
required (void)
{
	return g_strcmp0 (g_getenv ("STOCKFW_REQUIRE_WINDOWS_INTEL"), "1") == 0;
}

static int
skip (const gchar *why)
{
	if (required ()) {
		printf ("FAIL: the test could not run, and "
		        "STOCKFW_REQUIRE_WINDOWS_INTEL=1 requires it: %s\n", why);
		return 1;
	}
	printf ("SKIP: %s\n", why);
	return 0;
}

/* Inside a run: a part that cannot be checked here is a failure when
 * the run is required, and a note otherwise. */
static void
skip_part (const gchar *why)
{
	if (required ())
		CHECK (FALSE, "%s (STOCKFW_REQUIRE_WINDOWS_INTEL=1)", why);
	else
		printf ("SKIP: %s\n", why);
}

/* ---------------------------------------- the policy beside big lists */

/* One of the policy's names ("StockFW-"), outside every group. */
#define POLICY_DECOY "StockFW- wintel test policy rule"

static gboolean
rule_named (const gchar *name)
{
	GPtrArray *all = list_rules ();
	gboolean found = FALSE;

	for (guint i = 0; i < all->len; i++)
		if (strcmp (((Rule *) all->pdata[i])->name, name) == 0)
			found = TRUE;
	g_ptr_array_unref (all);
	return found;
}

/* Review W3: the policy's own clear listed its rules through
 * `netsh show rule name=all', whose output prints every address of
 * every blocklist rule and was cut at 16 MiB (and 30 s).  With lists
 * this long a policy rule enumerated after them was never seen, and
 * the clear "verified" zero.  Here: blocklists whose addresses alone
 * are past 16 MiB of text, then a policy rule, then the policy's clear,
 * which must remove that rule and leave every blocklist rule alone. */
static void
check_policy_beside_big_lists (const FsBackend *b)
{
	GPtrArray *all = list_rules ();
	gboolean theirs = FALSE;
	FsIntelRuleset *big;
	FsRangeSet *v6;
	gchar *want, *digest = NULL;
	GError *e = NULL;
	FsApplyResult res;
	FsIntelLive l;
	gint64 t0;
	const guint n = 140000;

	for (guint i = 0; i < all->len; i++)
		if (fs_netsh_rule_name_is_ours (((Rule *) all->pdata[i])->name))
			theirs = TRUE;
	g_ptr_array_unref (all);
	if (theirs) {
		skip_part ("policy beside big lists: this computer holds StockFW "
		           "policy rules, and clearing them is not the test's to "
		           "do");
		return;
	}

	/* Long "a-b" IPv6 ranges inside 2001:db8::/32 (documentation). */
	big = fs_intel_ruleset_new ();
	v6 = fs_range_set_new ();
	for (guint i = 0; i < n; i++) {
		FsU128 lo = { G_GUINT64_CONSTANT (0x20010db8a0000001) + i * 2,
		              G_GUINT64_CONSTANT (0x123456789abcdef1) };
		FsU128 hi = { lo.hi, G_GUINT64_CONSTANT (0xfedcba9876543210) };

		fs_range_set_add6 (v6, lo, hi);
	}
	fs_range_set_normalize (v6);
	fs_intel_ruleset_add (big, "wintest-huge", "StockFW Windows test, huge",
	                      FS_INTEL_DIR_BOTH, v6);
	want = fs_intel_ruleset_digest (big);

	t0 = g_get_monotonic_time ();
	CHECK (b->intel_apply (big, &e),
	       "policy beside big lists: %u long IPv6 ranges both ways are "
	       "applied (%.0f s; %s)", n,
	       (g_get_monotonic_time () - t0) / 1e6, e ? e->message : "ok");
	g_clear_error (&e);
	CHECK (add_rule (POLICY_DECOY, "", NET_FW_RULE_DIR_IN,
	                 NET_FW_ACTION_BLOCK, "192.0.2.252", FALSE),
	       "policy beside big lists: setup: a rule with a policy name, "
	       "added after the blocklists");

	t0 = g_get_monotonic_time ();
	res = b->clear_rules (&e);
	CHECK (res == FS_APPLY_OK,
	       "policy beside big lists: the policy's clear succeeds (%d, "
	       "%.0f s; %s)", (int) res, (g_get_monotonic_time () - t0) / 1e6,
	       e ? e->message : "ok");
	g_clear_error (&e);
	CHECK (!rule_named (POLICY_DECOY),
	       "policy beside big lists: the policy's clear removed its rule, "
	       "listed after more than 16 MiB of blocklist addresses");
	l = live (&digest);
	CHECK (l == FS_INTEL_LIVE_PRESENT && g_strcmp0 (digest, want) == 0,
	       "policy beside big lists: every blocklist rule is still there, "
	       "whole (%d)", (int) l);
	g_clear_pointer (&digest, g_free);

	CHECK (b->intel_clear (&e), "policy beside big lists: the blocklists "
	       "are cleared (%s)", e ? e->message : "ok");
	g_clear_error (&e);
	CHECK (live (NULL) == FS_INTEL_LIVE_ABSENT,
	       "policy beside big lists: intel_live reads ABSENT");
	remove_rules (POLICY_DECOY, "");
	g_free (want);
	fs_intel_ruleset_free (big);
}

/* ------------------------------------------- a store another made first */

static gboolean
enable_privilege (const wchar_t *name)
{
	HANDLE token = NULL;
	TOKEN_PRIVILEGES tp = { 0 };
	gboolean ok = FALSE;

	if (!OpenProcessToken (GetCurrentProcess (),
	                       TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		return FALSE;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (LookupPrivilegeValueW (NULL, name, &tp.Privileges[0].Luid) &&
	    AdjustTokenPrivileges (token, FALSE, &tp, 0, NULL, NULL) &&
	    GetLastError () == ERROR_SUCCESS)
		ok = TRUE;
	CloseHandle (token);
	return ok;
}

static DWORD
attrs_of (const gchar *path)
{
	gunichar2 *w = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
	DWORD a = w != NULL ? GetFileAttributesW ((LPCWSTR) w)
	                    : INVALID_FILE_ATTRIBUTES;

	g_free (w);
	return a;
}

static gboolean
remove_dir (const gchar *path)
{
	gunichar2 *w = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
	gboolean ok = w != NULL && RemoveDirectoryW ((LPCWSTR) w);

	g_free (w);
	return ok;
}

/* A real directory (no link), owned by Administrators or SYSTEM, with
 * a protected access list. */
static gboolean
store_is_ours (const gchar *path)
{
	DWORD a = attrs_of (path);
	gunichar2 *w;
	PSID owner = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;
	SECURITY_DESCRIPTOR_CONTROL ctl = 0;
	DWORD rev = 0;
	gboolean ok = FALSE;

	if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY) ||
	    (a & FILE_ATTRIBUTE_REPARSE_POINT))
		return FALSE;
	w = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
	if (GetNamedSecurityInfoW ((LPWSTR) w, SE_FILE_OBJECT,
	                           OWNER_SECURITY_INFORMATION |
	                           DACL_SECURITY_INFORMATION, &owner, NULL,
	                           NULL, NULL, &sd) == ERROR_SUCCESS) {
		GetSecurityDescriptorControl (sd, &ctl, &rev);
		ok = (IsWellKnownSid (owner, WinBuiltinAdministratorsSid) ||
		      IsWellKnownSid (owner, WinLocalSystemSid)) &&
		     (ctl & SE_DACL_PROTECTED) != 0;
		LocalFree (sd);
	}
	g_free (w);
	return ok;
}

/* Removes every "StockFW.untrusted-*" in `pd' (a link is removed as a
 * link); returns how many there were. */
static guint
remove_asides (const gchar *pd)
{
	GDir *d = g_dir_open (pd, 0, NULL);
	const gchar *name;
	guint n = 0;

	while (d != NULL && (name = g_dir_read_name (d)) != NULL) {
		if (g_str_has_prefix (name, "StockFW.untrusted-")) {
			gchar *p = g_build_filename (pd, name, NULL);

			n++;
			if (!remove_dir (p))
				printf ("      could not remove %s\n", p);
			g_free (p);
		}
	}
	if (d != NULL)
		g_dir_close (d);
	return n;
}

/* Review W7: %ProgramData% lets every user create a folder, so a
 * standard user could make %ProgramData%\StockFW first and switch
 * threat intel off for good.  An elevated StockFW now moves such a
 * folder (or a link) aside and makes its own.  Run only when the
 * computer has no StockFW store yet. */
static void
check_store_squatted (void)
{
	wchar_t buf[MAX_PATH + 1];
	gchar *pd, *parent, *got;
	gunichar2 *w;
	GError *e = NULL;
	guint asides;

	if (SHGetFolderPathW (NULL, CSIDL_COMMON_APPDATA, NULL,
	                      SHGFP_TYPE_CURRENT, buf) != S_OK) {
		CHECK (FALSE, "store squatted: %%ProgramData%% is found");
		return;
	}
	pd = g_utf16_to_utf8 ((const gunichar2 *) buf, -1, NULL, NULL, NULL);
	parent = g_build_filename (pd, "StockFW", NULL);
	if (attrs_of (parent) != INVALID_FILE_ATTRIBUTES) {
		skip_part ("store squatted: %ProgramData%\\StockFW already exists "
		           "on this computer; it is the user's and is left alone");
		g_free (parent);
		g_free (pd);
		return;
	}
	g_unsetenv ("STOCKFW_INTEL_DIR");
	remove_asides (pd);
	w = g_utf8_to_utf16 (parent, -1, NULL, NULL, NULL);

	/* 1. A folder another account owns (BUILTIN\Users stands in for
	 *    the standard user who made it). */
	{
		BYTE sid[SECURITY_MAX_SID_SIZE];
		DWORD len = sizeof sid;
		gboolean made;

		made = CreateDirectoryW ((LPCWSTR) w, NULL) &&
		       enable_privilege (L"SeRestorePrivilege") &&
		       CreateWellKnownSid (WinBuiltinUsersSid, NULL, sid, &len) &&
		       SetNamedSecurityInfoW ((LPWSTR) w, SE_FILE_OBJECT,
		                              OWNER_SECURITY_INFORMATION, sid,
		                              NULL, NULL, NULL) == ERROR_SUCCESS;
		CHECK (made, "store squatted: setup: %%ProgramData%%\\StockFW "
		       "made first, owned by BUILTIN\\Users");
		got = fs_intel_dir (&e);
		asides = remove_asides (pd);
		CHECK (got != NULL && store_is_ours (parent) && asides == 1,
		       "store squatted: a folder another account made first is "
		       "moved aside, and StockFW's own is made in its place "
		       "(%u moved; %s)", asides, e ? e->message : "ok");
		g_clear_error (&e);
		if (got != NULL)
			remove_dir (got);
		g_free (got);
		remove_dir (parent);
	}

	/* 2. A link to a folder elsewhere: moved aside as a link, never
	 *    followed, and the folder it points to is not touched. */
	{
		gchar *target = g_dir_make_tmp ("sfw-squat-XXXXXX", NULL);
		gchar *marker = target ? g_build_filename (target, "marker", NULL)
		                       : NULL;
		gchar *inside = target ? g_build_filename (target, "intel", NULL)
		                       : NULL;
		gunichar2 *wt = target ? g_utf8_to_utf16 (target, -1, NULL, NULL,
		                                          NULL)
		                       : NULL;
		gboolean made;

		made = wt != NULL &&
		       g_file_set_contents (marker, "x", 1, NULL) &&
		       CreateSymbolicLinkW ((LPCWSTR) w, (LPCWSTR) wt,
		                            SYMBOLIC_LINK_FLAG_DIRECTORY);
		CHECK (made, "store squatted: setup: %%ProgramData%%\\StockFW is a "
		       "link to another folder");
		got = fs_intel_dir (&e);
		asides = remove_asides (pd);
		CHECK (got != NULL && store_is_ours (parent) && asides == 1 &&
		       g_file_test (marker, G_FILE_TEST_EXISTS) &&
		       attrs_of (inside) == INVALID_FILE_ATTRIBUTES,
		       "store squatted: a link is moved aside as a link, never "
		       "followed, and StockFW's own folder is made in its place "
		       "(%u moved; %s)", asides, e ? e->message : "ok");
		g_clear_error (&e);
		if (got != NULL)
			remove_dir (got);
		g_free (got);
		remove_dir (parent);
		if (marker != NULL)
			g_remove (marker);
		if (inside != NULL)
			remove_dir (inside);
		if (target != NULL)
			remove_dir (target);
		g_free (wt);
		g_free (inside);
		g_free (marker);
		g_free (target);
	}
	CHECK (attrs_of (parent) == INVALID_FILE_ATTRIBUTES,
	       "store squatted: cleanup: %%ProgramData%%\\StockFW is gone again");
	g_free (w);
	g_free (parent);
	g_free (pd);
}

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

	if (!elevated ())
		return skip ("not elevated; the Windows Firewall rules cannot be "
		             "changed. Re-run from an elevated shell.");
	if (b->intel_apply == NULL || b->intel_clear == NULL ||
	    b->intel_live == NULL) {
		printf ("FAIL: the Windows backend has no threat-intel slots\n");
		return 1;
	}
	why = b->intel_not_in_force != NULL ? b->intel_not_in_force () : NULL;
	if (why != NULL && strstr (why, "MpsSvc") != NULL) {
		int rc = skip (why);

		g_free (why);
		return rc;
	}
	g_free (why);
	l = live (NULL);
	/* Rules that cannot be read are the backend failing, not a reason
	 * to skip: a broken reader must never pass (review W1). */
	if (l == FS_INTEL_LIVE_UNKNOWN) {
		printf ("FAIL: intel_live cannot read the Windows Firewall rules "
		        "(UNKNOWN) in an elevated shell with the firewall "
		        "service running\n");
		return 1;
	}
	if (l != FS_INTEL_LIVE_ABSENT) {
		gchar *msg = g_strdup_printf ("this computer already holds StockFW "
		                              "blocklist rules (%d); they are the "
		                              "user's and are left alone.",
		                              (int) l);
		int rc = skip (msg);

		g_free (msg);
		return rc;
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
	/* The apply over the foreign rule is checked, never just used as a
	 * condition: it is the only check that an apply takes a foreign
	 * rule out of the group, and the not-in-force checks below must
	 * run whatever it returns (review W2). */
	CHECK (b->intel_apply (rs2, &e),
	       "tamper: an apply over a foreign rule in the group succeeds (%s)",
	       e ? e->message : "ok");
	g_clear_error (&e);
	l = live (&digest);
	CHECK (l == FS_INTEL_LIVE_PRESENT && g_strcmp0 (digest, want2) == 0,
	       "tamper: after that apply the group reads PRESENT with the "
	       "digest, so the foreign rule was taken out (%d)", (int) l);
	g_clear_pointer (&digest, g_free);
	{
		GPtrArray *left = ours ();
		gboolean foreign = FALSE;

		for (guint i = 0; i < left->len; i++)
			if (strcmp (((Rule *) left->pdata[i])->name,
			            FOREIGN_IN_GROUP) == 0)
				foreign = TRUE;
		CHECK (!foreign, "tamper: the foreign rule is no longer in the "
		       "group");
		g_ptr_array_unref (left);
	}

	/* ---- not in force ------------------------------------------------ */
	{
		gboolean off_ok = TRUE, got_ok = TRUE;

		for (gint i = 0; i < FS_PROFILE_COUNT; i++)
			got_ok &= b->get_profile_enabled (i, &saved[i]);
		CHECK (got_ok, "not in force: every profile's state is read, so "
		       "it can be put back");
		for (gint i = 0; got_ok && i < FS_PROFILE_COUNT; i++)
			off_ok &= b->set_profile_enabled (i, FALSE, NULL);
		l = live (&digest);
		why = b->intel_not_in_force ();
		CHECK (got_ok && off_ok && l == FS_INTEL_LIVE_INACTIVE &&
		       g_strcmp0 (digest, want2) == 0 && why != NULL,
		       "not in force: every profile off reads INACTIVE with the "
		       "digest, and says why (%s)", why ? why : "nothing");
		g_free (why);
		g_clear_pointer (&digest, g_free);
		for (gint i = 0; got_ok && i < FS_PROFILE_COUNT; i++)
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

	check_policy_beside_big_lists (b);

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
	check_store_squatted ();
	check_engine_lock ();

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
