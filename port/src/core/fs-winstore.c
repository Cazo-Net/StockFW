/*---[ fs-winstore.c ]---------------------------------------------------
 * The threat-intel store on Windows.  See fs-winstore.h and
 * docs/1.0.7-threat-intel-design.md, section 11.5.
 *
 * [Unverified on Windows here] This file is compiled and linked for
 * Windows in the development container (mingw), and run on the CI's
 * Windows runner by fs-intel-windows-test; it cannot run in the
 * container itself.
 *--------------------------------------------------------------------*/

#ifdef _WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>

#include "core/fs-winstore.h"
#include "core/fs-intel.h"
#include "core/fs-i18n.h"

#include <string.h>

/* Rights that let an account change what a directory holds or who
 * may: add or remove entries, delete or rename it, rewrite its access
 * list or take it over. */
#define CHANGE_RIGHTS (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | \
                       FILE_DELETE_CHILD | DELETE | WRITE_DAC | \
                       WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL | \
                       MAXIMUM_ALLOWED)
/* Rights that let an account see what a directory holds. */
#define READ_RIGHTS   (FILE_LIST_DIRECTORY | GENERIC_READ | GENERIC_ALL | \
                       MAXIMUM_ALLOWED)

/* Protected access lists (nothing inherited from above): the store's
 * parent, readable by Users; the store, Administrators and SYSTEM
 * only.  OICI: files and folders inside take the same. */
#define SDDL_PARENT L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
#define SDDL_STORE  L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

/* TrustedInstaller owns some system folders. */
#define SID_TRUSTED_INSTALLER \
	L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

/* ============================================================ helpers */

static gunichar2 *
wide (const gchar *utf8)
{
	return g_utf8_to_utf16 (utf8, -1, NULL, NULL, NULL);
}

static void
unsafe (GError **error, const gchar *path, const gchar *why)
{
	g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNSAFE_DIR,
	             _("The threat-intel directory %s is not safe to use: %s."),
	             path, why);
}

static void
store_error (GError **error, const gchar *name, const gchar *why)
{
	g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_STORE,
	             _("Threat-intel file %s: %s."), name, why);
}

static gchar *
win_error (DWORD code)
{
	return g_win32_error_message ((gint) code);
}

/* The SID of this process's user.  Caller frees with g_free. */
static PSID
token_user (void)
{
	HANDLE token = NULL;
	DWORD size = 0;
	TOKEN_USER *tu;
	PSID copy = NULL;

	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
		return NULL;
	GetTokenInformation (token, TokenUser, NULL, 0, &size);
	tu = size > 0 ? g_malloc (size) : NULL;
	if (tu != NULL &&
	    GetTokenInformation (token, TokenUser, tu, size, &size)) {
		DWORD len = GetLengthSid (tu->User.Sid);

		copy = g_malloc (len);
		CopySid (len, copy, tu->User.Sid);
	}
	g_free (tu);
	CloseHandle (token);
	return copy;
}

/* Administrators, SYSTEM, TrustedInstaller -- and `user' when given. */
static gboolean
sid_is_trusted (PSID sid, PSID user)
{
	BYTE buf[SECURITY_MAX_SID_SIZE];
	DWORD len;
	PSID ti = NULL;
	gboolean ok = FALSE;

	if (sid == NULL || !IsValidSid (sid))
		return FALSE;
	len = sizeof buf;
	if (CreateWellKnownSid (WinBuiltinAdministratorsSid, NULL, buf, &len) &&
	    EqualSid (sid, buf))
		return TRUE;
	len = sizeof buf;
	if (CreateWellKnownSid (WinLocalSystemSid, NULL, buf, &len) &&
	    EqualSid (sid, buf))
		return TRUE;
	if (ConvertStringSidToSidW (SID_TRUSTED_INSTALLER, &ti)) {
		ok = EqualSid (sid, ti);
		LocalFree (ti);
		if (ok)
			return TRUE;
	}
	return user != NULL && EqualSid (sid, user);
}

/* What is wrong with a security descriptor's owner and access list for
 * a store directory, or NULL.  *readable is set when an untrusted
 * account may list it. */
static const gchar *
security_fault (PSID owner, PACL dacl, PSID user, gboolean *readable,
                gboolean *foreign)
{
	*readable = FALSE;
	if (!sid_is_trusted (owner, user)) {
		*foreign = TRUE;
		return _("it is owned by an account other than Administrators "
		         "or SYSTEM");
	}
	if (dacl == NULL)
		return _("it has no access list, so every account may change "
		         "it");
	for (DWORD i = 0; i < dacl->AceCount; i++) {
		ACE_HEADER *ace = NULL;
		ACCESS_MASK mask;
		PSID sid;

		if (!GetAce (dacl, i, (LPVOID *) &ace))
			return _("its access list cannot be read");
		if (ace->AceFlags & INHERIT_ONLY_ACE)
			continue;   /* applies to what is created inside only */
		switch (ace->AceType) {
		case ACCESS_DENIED_ACE_TYPE:
		case ACCESS_DENIED_CALLBACK_ACE_TYPE:
		case SYSTEM_AUDIT_ACE_TYPE:
		case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
			continue;
		case ACCESS_ALLOWED_ACE_TYPE:
		case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
			mask = ((ACCESS_ALLOWED_ACE *) ace)->Mask;
			sid = (PSID) &((ACCESS_ALLOWED_ACE *) ace)->SidStart;
			break;
		default:
			return _("its access list has entries StockFW cannot "
			         "check");
		}
		if (sid_is_trusted (sid, user))
			continue;
		if (mask & CHANGE_RIGHTS)
			return _("accounts other than Administrators and SYSTEM "
			         "may change it");
		if (mask & READ_RIGHTS)
			*readable = TRUE;
	}
	return NULL;
}

/* "DOMAIN\name" of an account, or its SID string.  Caller frees. */
static gchar *
account_text (PSID sid)
{
	wchar_t name[256], domain[256];
	DWORD nlen = G_N_ELEMENTS (name), dlen = G_N_ELEMENTS (domain);
	SID_NAME_USE use;
	LPWSTR str = NULL;
	gchar *out = NULL;

	if (sid == NULL || !IsValidSid (sid))
		return g_strdup ("?");
	if (LookupAccountSidW (NULL, sid, name, &nlen, domain, &dlen, &use)) {
		gchar *n = g_utf16_to_utf8 ((const gunichar2 *) name, -1, NULL,
		                            NULL, NULL);
		gchar *d = g_utf16_to_utf8 ((const gunichar2 *) domain, -1, NULL,
		                            NULL, NULL);

		if (n != NULL)
			out = d != NULL && *d != '\0'
			      ? g_strdup_printf ("%s\\%s", d, n)
			      : g_strdup (n);
		g_free (n);
		g_free (d);
	}
	if (out == NULL && ConvertSidToStringSidW (sid, &str)) {
		out = g_utf16_to_utf8 ((const gunichar2 *) str, -1, NULL, NULL,
		                       NULL);
		LocalFree (str);
	}
	return out != NULL ? out : g_strdup ("?");
}

/* Checks one existing directory by path.  *foreign is set when the
 * fault means another account put something there (a link, a file,
 * a folder it owns; review W7), and then *owner (when not NULL)
 * receives the owning account's name for the message, if it could be
 * read. */
static const gchar *
dir_fault (const gchar *path, PSID user, gboolean *readable,
           gboolean *foreign, gchar **owner_name)
{
	gunichar2 *w = wide (path);
	DWORD attrs;
	PSID owner = NULL;
	PACL dacl = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;
	const gchar *why;

	*readable = FALSE;
	*foreign = FALSE;
	if (owner_name != NULL)
		*owner_name = NULL;
	if (w == NULL)
		return _("its name is not valid");
	attrs = GetFileAttributesW ((LPCWSTR) w);
	if (attrs == INVALID_FILE_ATTRIBUTES) {
		g_free (w);
		return _("it cannot be opened");
	}
	if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) {
		g_free (w);
		*foreign = TRUE;
		return _("it is not a directory");
	}
	if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
		g_free (w);
		*foreign = TRUE;
		return _("it is a link (a junction or symbolic link)");
	}
	if (GetNamedSecurityInfoW ((LPWSTR) w, SE_FILE_OBJECT,
	                           OWNER_SECURITY_INFORMATION |
	                           DACL_SECURITY_INFORMATION,
	                           &owner, NULL, &dacl, NULL,
	                           &sd) != ERROR_SUCCESS) {
		g_free (w);
		return _("its owner and access list cannot be read");
	}
	why = security_fault (owner, dacl, user, readable, foreign);
	if (why != NULL && *foreign && owner_name != NULL)
		*owner_name = account_text (owner);
	LocalFree (sd);
	g_free (w);
	return why;
}

/* The refusal of a directory, with who owns it and how an
 * administrator gets threat intel working again (review W7). */
static void
unsafe_dir (GError **error, const gchar *path, const gchar *why,
            gboolean foreign, const gchar *owner_name)
{
	gchar *full;

	if (!foreign) {
		unsafe (error, path, why);
		return;
	}
	full = owner_name != NULL
	       ? g_strdup_printf (_("%s (%s). An administrator can delete or "
	                            "rename the folder; StockFW then creates "
	                            "it again"), why, owner_name)
	       : g_strdup_printf (_("%s. An administrator can delete or "
	                            "rename it; StockFW then creates the "
	                            "folder again"), why);
	unsafe (error, path, full);
	g_free (full);
}

/* Creates `path' with the access list `sddl', or checks the one that is
 * there.  `tighten': an existing directory others can read gets `sddl'
 * (protected) instead.  `extra_sddl' (may be NULL) is appended to the
 * new access list (the current user, for an override). */
static gboolean
ensure_dir (const gchar *path, const wchar_t *sddl, const gchar *extra_sddl,
            PSID user, gboolean tighten, gboolean *foreign_out,
            GError **error)
{
	gunichar2 *w = wide (path);
	gunichar2 *full_sddl;
	gchar *sddl8, *joined;
	SECURITY_ATTRIBUTES sa;
	PSECURITY_DESCRIPTOR sd = NULL;
	gboolean readable = FALSE, ok = TRUE, foreign = FALSE;
	gchar *owner_name = NULL;
	const gchar *why;

	if (foreign_out != NULL)
		*foreign_out = FALSE;
	if (w == NULL) {
		unsafe (error, path, _("its name is not valid"));
		return FALSE;
	}
	sddl8 = g_utf16_to_utf8 ((const gunichar2 *) sddl, -1, NULL, NULL,
	                         NULL);
	joined = g_strconcat (sddl8, extra_sddl != NULL ? extra_sddl : "",
	                      NULL);
	full_sddl = wide (joined);
	g_free (joined);
	g_free (sddl8);
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW (
		    (LPCWSTR) full_sddl, SDDL_REVISION_1, &sd, NULL)) {
		unsafe (error, path, _("its access list cannot be built"));
		g_free (full_sddl);
		g_free (w);
		return FALSE;
	}
	sa.nLength = sizeof sa;
	sa.lpSecurityDescriptor = sd;
	sa.bInheritHandle = FALSE;
	if (!CreateDirectoryW ((LPCWSTR) w, &sa) &&
	    GetLastError () != ERROR_ALREADY_EXISTS) {
		gchar *msg = win_error (GetLastError ());

		unsafe (error, path, msg);
		g_free (msg);
		ok = FALSE;
	}
	if (ok) {
		why = dir_fault (path, user, &readable, &foreign, &owner_name);
		if (why != NULL) {
			unsafe_dir (error, path, why, foreign, owner_name);
			if (foreign_out != NULL)
				*foreign_out = foreign;
			ok = FALSE;
		} else if (readable && tighten) {
			BOOL present = FALSE, defaulted = FALSE;
			PACL dacl = NULL;

			if (!GetSecurityDescriptorDacl (sd, &present, &dacl,
			                                &defaulted) ||
			    !present ||
			    SetNamedSecurityInfoW ((LPWSTR) w, SE_FILE_OBJECT,
			                           DACL_SECURITY_INFORMATION |
			                           PROTECTED_DACL_SECURITY_INFORMATION,
			                           NULL, NULL, dacl,
			                           NULL) != ERROR_SUCCESS) {
				unsafe (error, path,
				        _("other accounts can read it, and its access "
				          "list could not be set back to "
				          "Administrators and SYSTEM only"));
				ok = FALSE;
			}
		}
	}
	LocalFree (sd);
	g_free (owner_name);
	g_free (full_sddl);
	g_free (w);
	return ok;
}

/* Moves whatever another account put at `path' (a folder it owns, a
 * link, a file) aside to "<path>.untrusted-<random>", within the same
 * parent, so StockFW can create its own in its place (review W7).
 * %ProgramData% lets every user create a folder there, and one made
 * before StockFW's own used to switch threat intel off for good.
 * Only an administrator gets here: renaming a child of %ProgramData%
 * needs the delete-child right Administrators hold on it.  A rename
 * moves a link itself, never what it points to, and nothing is
 * deleted, so an administrator can look at what was there.  FALSE,
 * with *error set, when it cannot be moved (another program holds a
 * file in it open, for one). */
static gboolean
move_aside (const gchar *path, const gchar *why, GError **error)
{
	gchar *aside = g_strdup_printf ("%s.untrusted-%08x", path,
	                                g_random_int ());
	gunichar2 *from = wide (path), *to = wide (aside);
	gboolean ok = from != NULL && to != NULL &&
	              MoveFileExW ((LPCWSTR) from, (LPCWSTR) to, 0);

	if (!ok) {
		gchar *msg = win_error (GetLastError ());

		/* `why' is the whole refusal, which already says how an
		 * administrator gets out of it. */
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNSAFE_DIR,
		             _("%s StockFW could not move it aside: %s."), why,
		             msg != NULL ? msg : "");
		g_free (msg);
	} else {
		g_message ("StockFW: %s was not made by StockFW (%s); it was "
		           "moved to %s and a new one is created", path, why,
		           aside);
	}
	g_free (from);
	g_free (to);
	g_free (aside);
	return ok;
}

/* %ProgramData%, from the shell, not from the environment (an elevated
 * process inherits the user's environment).  Caller frees. */
static gchar *
program_data (void)
{
	wchar_t buf[MAX_PATH + 1];

	if (SHGetFolderPathW (NULL, CSIDL_COMMON_APPDATA, NULL,
	                      SHGFP_TYPE_CURRENT, buf) != S_OK)
		return NULL;
	return g_utf16_to_utf8 ((const gunichar2 *) buf, -1, NULL, NULL, NULL);
}

static gchar *
default_parent (void)
{
	gchar *pd = program_data ();
	gchar *out = pd != NULL ? g_build_filename (pd, "StockFW", NULL) : NULL;

	g_free (pd);
	return out;
}

static const gchar *
override_dir (void)
{
	const gchar *o = g_getenv ("STOCKFW_INTEL_DIR");

	return o != NULL && *o != '\0' ? o : NULL;
}

/* ================================================================= API */

gboolean
fs_winstore_is_admin (void)
{
	BYTE buf[SECURITY_MAX_SID_SIZE];
	DWORD len = sizeof buf;
	BOOL member = FALSE;

	if (!CreateWellKnownSid (WinBuiltinAdministratorsSid, NULL, buf, &len))
		return FALSE;
	if (!CheckTokenMembership (NULL, buf, &member))
		return FALSE;
	return member != FALSE;
}

gchar *
fs_winstore_dir (GError **error)
{
	const gchar *override = override_dir ();
	gchar *parent, *full;

	if (override != NULL) {
		PSID user = token_user ();
		gchar *trimmed, *user_sddl = NULL;
		gboolean ok;

		if (!g_path_is_absolute (override)) {
			unsafe (error, override, _("it must be an absolute path"));
			g_free (user);
			return NULL;
		}
		if (user == NULL) {
			unsafe (error, override,
			        _("the current account cannot be read"));
			return NULL;
		}
		{
			LPWSTR s = NULL;

			if (ConvertSidToStringSidW (user, &s)) {
				gchar *s8 = g_utf16_to_utf8 ((const gunichar2 *) s,
				                             -1, NULL, NULL, NULL);

				user_sddl = g_strdup_printf ("(A;OICI;FA;;;%s)", s8);
				g_free (s8);
				LocalFree (s);
			}
		}
		trimmed = g_strdup (override);
		while (strlen (trimmed) > 3 &&
		       (g_str_has_suffix (trimmed, "\\") ||
		        g_str_has_suffix (trimmed, "/")))
			trimmed[strlen (trimmed) - 1] = '\0';
		parent = g_path_get_dirname (trimmed);
		{
			gboolean readable, foreign;
			gchar *owner_name = NULL;
			const gchar *why = dir_fault (parent, user, &readable,
			                              &foreign, &owner_name);

			ok = why == NULL;
			if (!ok)
				unsafe_dir (error, override, why, foreign,
				            owner_name);
			g_free (owner_name);
		}
		if (ok && user_sddl == NULL) {
			unsafe (error, override,
			        _("the current account cannot be read"));
			ok = FALSE;
		}
		ok = ok && ensure_dir (trimmed, SDDL_STORE, user_sddl, user,
		                       FALSE, NULL, error);
		g_free (parent);
		g_free (user_sddl);
		g_free (user);
		if (!ok) {
			g_free (trimmed);
			return NULL;
		}
		return trimmed;
	}

	if (!fs_winstore_is_admin ()) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_NEEDS_ROOT,
		             _("Threat intel needs administrator rights on "
		               "Windows: run StockFW as administrator."));
		return NULL;
	}
	parent = default_parent ();
	if (parent == NULL) {
		unsafe (error, "%ProgramData%\\StockFW",
		        _("the ProgramData folder cannot be found"));
		return NULL;
	}
	{
		GError *local = NULL;
		gboolean foreign = FALSE;

		/* Something another account made first is moved aside, once,
		 * and StockFW's own folder is made in its place (review W7);
		 * anything else wrong with the folder is refused as before. */
		if (!ensure_dir (parent, SDDL_PARENT, NULL, NULL, FALSE, &foreign,
		                 &local) &&
		    (!foreign || !move_aside (parent, local->message, error) ||
		     !ensure_dir (parent, SDDL_PARENT, NULL, NULL, FALSE, NULL,
		                  error))) {
			if (!foreign)
				g_propagate_error (error, local);
			else
				g_clear_error (&local);
			g_free (parent);
			return NULL;
		}
		g_clear_error (&local);
	}
	full = g_build_filename (parent, "intel", NULL);
	g_free (parent);
	if (!ensure_dir (full, SDDL_STORE, NULL, NULL, TRUE, NULL, error)) {
		g_free (full);
		return NULL;
	}
	return full;
}

gboolean
fs_winstore_exists (void)
{
	const gchar *override = override_dir ();
	gchar *path, *parent = NULL;
	gunichar2 *w;
	DWORD attrs, err;

	if (override != NULL)
		path = g_strdup (override);
	else {
		parent = default_parent ();
		if (parent == NULL)
			return FALSE;
		path = g_build_filename (parent, "intel", NULL);
	}
	w = wide (path);
	g_free (path);
	g_free (parent);
	if (w == NULL)
		return FALSE;
	attrs = GetFileAttributesW ((LPCWSTR) w);
	err = GetLastError ();
	g_free (w);
	if (attrs != INVALID_FILE_ATTRIBUTES)
		return TRUE;
	/* Anything but "not there" counts as there: opening it then says
	 * what is wrong. */
	return err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND;
}

gpointer
fs_winstore_pin (const gchar *dir, GError **error)
{
	gunichar2 *w = wide (dir);
	HANDLE h;
	BY_HANDLE_FILE_INFORMATION info;
	PSID owner = NULL, user = NULL;
	PACL dacl = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;
	gboolean readable;
	const gchar *why = NULL;

	if (w == NULL) {
		unsafe (error, dir, _("its name is not valid"));
		return NULL;
	}
	/* FILE_READ_ATTRIBUTES alone puts no sharing demand on anyone
	 * else's reads or writes; leaving FILE_SHARE_DELETE out is what
	 * stops a rename or a delete of the directory (or of any folder
	 * above it) while it is pinned. */
	h = CreateFileW ((LPCWSTR) w, FILE_READ_ATTRIBUTES | READ_CONTROL,
	                 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
	                 OPEN_EXISTING,
	                 FILE_FLAG_BACKUP_SEMANTICS |
	                 FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	g_free (w);
	if (h == INVALID_HANDLE_VALUE) {
		gchar *msg = win_error (GetLastError ());

		unsafe (error, dir, msg);
		g_free (msg);
		return NULL;
	}
	if (!GetFileInformationByHandle (h, &info) ||
	    (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
	    (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
		why = _("it changed while it was opened");
	else if (GetSecurityInfo (h, SE_FILE_OBJECT,
	                          OWNER_SECURITY_INFORMATION |
	                          DACL_SECURITY_INFORMATION,
	                          &owner, NULL, &dacl, NULL,
	                          &sd) != ERROR_SUCCESS)
		why = _("its owner and access list cannot be read");
	else {
		if (override_dir () != NULL)
			user = token_user ();
		gboolean foreign = FALSE;

		why = security_fault (owner, dacl, user, &readable, &foreign);
		LocalFree (sd);
		g_free (user);
	}
	if (why != NULL) {
		CloseHandle (h);
		unsafe (error, dir, why);
		return NULL;
	}
	return (gpointer) h;
}

void
fs_winstore_unpin (gpointer pin)
{
	if (pin != NULL)
		CloseHandle ((HANDLE) pin);
}

/* A file name inside the store: never a path, never a stream. */
static gboolean
name_ok (const gchar *name, GError **error)
{
	if (name != NULL && *name != '\0' && strpbrk (name, "\\/:") == NULL &&
	    strcmp (name, ".") != 0 && strcmp (name, "..") != 0)
		return TRUE;
	store_error (error, name != NULL ? name : "", _("not a file name"));
	return FALSE;
}

static gunichar2 *
file_path (const gchar *dir, const gchar *name)
{
	gchar *p = g_build_filename (dir, name, NULL);
	gunichar2 *w = wide (p);

	g_free (p);
	return w;
}

/* Reads an open handle whole, at most `cap' bytes. */
static gchar *
read_handle (HANDLE h, gsize cap, gsize *len, const gchar *name,
             GError **error, gboolean store)
{
	GByteArray *buf = g_byte_array_new ();

	for (;;) {
		guint8 chunk[64 * 1024];
		DWORD got = 0;

		if (!ReadFile (h, chunk, sizeof chunk, &got, NULL)) {
			gchar *msg = win_error (GetLastError ());

			if (store)
				store_error (error, name, msg);
			else
				g_set_error (error, FS_INTEL_ERROR,
				             FS_INTEL_ERR_INVALID,
				             _("Cannot read %s: %s."), name, msg);
			g_free (msg);
			g_byte_array_free (buf, TRUE);
			return NULL;
		}
		if (got == 0)
			break;
		if (buf->len + (gsize) got > cap) {
			if (store)
				store_error (error, name,
				             _("it is larger than expected"));
			else
				g_set_error (error, FS_INTEL_ERROR,
				             FS_INTEL_ERR_INVALID,
				             _("%s is larger than 32 MiB."), name);
			g_byte_array_free (buf, TRUE);
			return NULL;
		}
		g_byte_array_append (buf, chunk, got);
	}
	if (len != NULL)
		*len = buf->len;
	g_byte_array_append (buf, (const guint8 *) "", 1);
	return (gchar *) g_byte_array_free (buf, FALSE);
}

gchar *
fs_winstore_read (const gchar *dir, const gchar *name, gsize cap, gsize *len,
                  gboolean *missing, GError **error)
{
	gunichar2 *w;
	HANDLE h;
	BY_HANDLE_FILE_INFORMATION info;
	gchar *out;

	if (missing != NULL)
		*missing = FALSE;
	if (!name_ok (name, error))
		return NULL;
	w = file_path (dir, name);
	h = CreateFileW ((LPCWSTR) w, GENERIC_READ, FILE_SHARE_READ, NULL,
	                 OPEN_EXISTING,
	                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
	                 NULL);
	g_free (w);
	if (h == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError ();
		gchar *msg = win_error (err);

		if (missing != NULL && (err == ERROR_FILE_NOT_FOUND ||
		                        err == ERROR_PATH_NOT_FOUND))
			*missing = TRUE;
		store_error (error, name, msg);
		g_free (msg);
		return NULL;
	}
	if (!GetFileInformationByHandle (h, &info) ||
	    (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
	                              FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
	    GetFileType (h) != FILE_TYPE_DISK) {
		CloseHandle (h);
		store_error (error, name,
		             (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		             ? _("it is a symbolic link")
		             : _("it is not a regular file"));
		return NULL;
	}
	if (info.nFileSizeHigh != 0 || (gsize) info.nFileSizeLow > cap) {
		CloseHandle (h);
		store_error (error, name, _("it is larger than expected"));
		return NULL;
	}
	out = read_handle (h, cap, len, name, error, TRUE);
	CloseHandle (h);
	return out;
}

gboolean
fs_winstore_write (const gchar *dir, const gchar *name, const gchar *data,
                   gsize len, GError **error)
{
	gchar *tmp = NULL;
	gunichar2 *wtmp = NULL, *wfinal;
	HANDLE h = INVALID_HANDLE_VALUE;
	DWORD err = 0;
	gsize done = 0;

	if (!name_ok (name, error))
		return FALSE;
	for (guint tries = 0; tries < 16 && h == INVALID_HANDLE_VALUE;
	     tries++) {
		g_free (tmp);
		g_free (wtmp);
		tmp = g_strdup_printf (".%s.%08x.tmp", name, g_random_int ());
		wtmp = file_path (dir, tmp);
		h = CreateFileW ((LPCWSTR) wtmp, GENERIC_WRITE, 0, NULL,
		                 CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		err = GetLastError ();
		if (h == INVALID_HANDLE_VALUE && err != ERROR_FILE_EXISTS &&
		    err != ERROR_ALREADY_EXISTS)
			break;
	}
	if (h == INVALID_HANDLE_VALUE) {
		gchar *msg = win_error (err);

		store_error (error, name, msg);
		g_free (msg);
		g_free (tmp);
		g_free (wtmp);
		return FALSE;
	}
	while (done < len) {
		DWORD put = 0;
		DWORD want = (DWORD) MIN (len - done, (gsize) (1u << 30));

		if (!WriteFile (h, data + done, want, &put, NULL) || put == 0) {
			err = GetLastError ();
			goto fail;
		}
		done += put;
	}
	if (!FlushFileBuffers (h)) {
		err = GetLastError ();
		goto fail;
	}
	CloseHandle (h);
	h = INVALID_HANDLE_VALUE;
	wfinal = file_path (dir, name);
	if (!MoveFileExW ((LPCWSTR) wtmp, (LPCWSTR) wfinal,
	                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		err = GetLastError ();
		g_free (wfinal);
		goto fail;
	}
	g_free (wfinal);
	g_free (tmp);
	g_free (wtmp);
	return TRUE;

fail:
	{
		gchar *msg = win_error (err ? err : ERROR_WRITE_FAULT);

		store_error (error, name, msg);
		g_free (msg);
	}
	if (h != INVALID_HANDLE_VALUE)
		CloseHandle (h);
	DeleteFileW ((LPCWSTR) wtmp);
	g_free (tmp);
	g_free (wtmp);
	return FALSE;
}

gboolean
fs_winstore_unlink (const gchar *dir, const gchar *name, GError **error)
{
	gunichar2 *w;
	DWORD err;

	if (!name_ok (name, error))
		return FALSE;
	w = file_path (dir, name);
	if (DeleteFileW ((LPCWSTR) w)) {
		g_free (w);
		return TRUE;
	}
	err = GetLastError ();
	g_free (w);
	if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
		return TRUE;
	{
		gchar *msg = win_error (err);

		store_error (error, name, msg);
		g_free (msg);
	}
	return FALSE;
}

gchar *
fs_winstore_read_user_file (const gchar *path, gsize cap, gsize *len,
                            GError **error)
{
	gunichar2 *w = wide (path);
	HANDLE h;
	BY_HANDLE_FILE_INFORMATION info;
	gchar *out;

	if (w == NULL) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("Cannot open %s: %s."), path,
		             _("the name is not valid"));
		return NULL;
	}
	h = CreateFileW ((LPCWSTR) w, GENERIC_READ,
	                 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
	                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	g_free (w);
	if (h == INVALID_HANDLE_VALUE) {
		gchar *msg = win_error (GetLastError ());

		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("Cannot open %s: %s."), path, msg);
		g_free (msg);
		return NULL;
	}
	if (GetFileType (h) != FILE_TYPE_DISK ||
	    !GetFileInformationByHandle (h, &info) ||
	    (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
		CloseHandle (h);
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("%s is not a regular file."), path);
		return NULL;
	}
	out = read_handle (h, cap, len, path, error, FALSE);
	CloseHandle (h);
	return out;
}

#else  /* !_WIN32 */

/* Nothing on other platforms: fs-intel.c keeps its own Linux store. */
typedef int fs_winstore_unused;

#endif /* _WIN32 */
