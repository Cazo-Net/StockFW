/*---[ fs-autostart.c ]--------------------------------------------------
 * Start at sign-in: see fs-autostart.h for the two mechanisms.
 *--------------------------------------------------------------------*/

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <taskschd.h>
#else
#define _GNU_SOURCE              /* setfsuid / setfsgid */
#endif

#include "core/fs-autostart.h"
#include "core/fs-i18n.h"
#include "core/fs-util.h"

#include <glib/gstdio.h>
#include <string.h>

#ifndef G_OS_WIN32
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

G_DEFINE_QUARK (fs-autostart-error-quark, fs_autostart_error)

/* =====================================================================
 * The Task Scheduler task, as XML.  Portable, so the Linux test suite
 * can check what Windows is handed.
 * ===================================================================== */

/* [ fs_autostart_task_xml ] -- the task registered for `user'
 * ("DOMAIN\name") to run `exe' (a Windows path) at that user's logon,
 * WITHOUT elevation, hidden in the notification area.  Caller frees. */
gchar *
fs_autostart_task_xml (const gchar *user, const gchar *exe)
{
	const gchar *slash = strrchr (exe, '\\');
	gchar *dir = slash != NULL ? g_strndup (exe, (gsize) (slash - exe))
	                           : g_strdup (".");
	gchar *e_user = g_markup_escape_text (user, -1);
	gchar *e_exe  = g_markup_escape_text (exe, -1);
	gchar *e_dir  = g_markup_escape_text (dir, -1);
	gchar *xml;

	/* LogonTrigger with a UserId: this user's sign-in only, not
	 * everyone's.  InteractiveToken + LeastPrivilege: it runs in the
	 * user's own desktop session with their ordinary, unelevated
	 * token, and needs no stored password.  Never HighestAvailable: a
	 * task that comes up elevated with no prompt would run a GTK
	 * program -- which loads modules, settings and loaders named by
	 * the user's environment and profile, and DLLs from wherever the
	 * exe sits -- with an administrator's rights, so anything running
	 * unelevated as that user could get code in at the next sign-in
	 * (a silent UAC bypass).  Windows Firewall keeps its own rules
	 * across restarts; the sign-in copy only shows the state, and
	 * starting StockFW as administrator takes over from it.  Not
	 * startable on demand: it is a sign-in task, nothing else.  The
	 * short delay lets Explorer
	 * put up the notification area first (the app shows its window
	 * if no icon docks within five seconds).  No time limit: the
	 * default would stop it after three days.  Normal priority: the
	 * Task Scheduler default (7) runs a task below normal, CPU and
	 * I/O both. */
	xml = g_strdup_printf (
		"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
		"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
		"  <RegistrationInfo>\n"
		"    <Author>StockFW</Author>\n"
		"    <Description>Starts StockFW in the notification area when %s signs in. "
		"Turn it off from StockFW (tray menu, Start at sign-in) or delete this task.</Description>\n"
		"  </RegistrationInfo>\n"
		"  <Triggers>\n"
		"    <LogonTrigger>\n"
		"      <Enabled>true</Enabled>\n"
		"      <UserId>%s</UserId>\n"
		"      <Delay>PT10S</Delay>\n"
		"    </LogonTrigger>\n"
		"  </Triggers>\n"
		"  <Principals>\n"
		"    <Principal id=\"Author\">\n"
		"      <UserId>%s</UserId>\n"
		"      <LogonType>InteractiveToken</LogonType>\n"
		"      <RunLevel>LeastPrivilege</RunLevel>\n"
		"    </Principal>\n"
		"  </Principals>\n"
		"  <Settings>\n"
		"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
		"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
		"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
		"    <AllowHardTerminate>true</AllowHardTerminate>\n"
		"    <StartWhenAvailable>false</StartWhenAvailable>\n"
		"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n"
		"    <IdleSettings>\n"
		"      <StopOnIdleEnd>false</StopOnIdleEnd>\n"
		"      <RestartOnIdle>false</RestartOnIdle>\n"
		"    </IdleSettings>\n"
		"    <AllowStartOnDemand>false</AllowStartOnDemand>\n"
		"    <Enabled>true</Enabled>\n"
		"    <Hidden>false</Hidden>\n"
		"    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n"
		"    <WakeToRun>false</WakeToRun>\n"
		"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n"
		"    <Priority>5</Priority>\n"
		"  </Settings>\n"
		"  <Actions Context=\"Author\">\n"
		"    <Exec>\n"
		"      <Command>%s</Command>\n"
		"      <Arguments>--background</Arguments>\n"
		"      <WorkingDirectory>%s</WorkingDirectory>\n"
		"    </Exec>\n"
		"  </Actions>\n"
		"</Task>\n",
		e_user, e_user, e_user, e_exe, e_dir);

	g_free (e_user);
	g_free (e_exe);
	g_free (e_dir);
	g_free (dir);
	return xml;
}

/* [ fs_autostart_task_name ] -- one task per user in \StockFW, named
 * after the account with the characters a task name may not hold
 * replaced.  Caller frees. */
gchar *
fs_autostart_task_name (const gchar *user)
{
	gchar *safe = g_strdelimit (g_strdup (user), "\\/:*?\"<>|", '_');
	gchar *name = g_strdup_printf ("Start at sign-in (%s)", safe);

	g_free (safe);
	return name;
}

/* [ fs_autostart_desktop_exec ] -- the Exec= value for `binary' per
 * the Desktop Entry spec: a bare "StockFW" when that is what PATH
 * finds (`bare'), else the absolute path, quoted when it holds a
 * reserved character.  Caller frees. */
gchar *
fs_autostart_desktop_exec (const gchar *binary, gboolean bare)
{
	GString *s;
	const gchar *p;

	if (bare)
		return g_strdup ("StockFW --background");

	s = g_string_new (NULL);
	if (strpbrk (binary, " \t\n\"'\\><~|&;$*?#()`%=") != NULL) {
		g_string_append_c (s, '"');
		for (p = binary; *p != '\0'; p++) {
			if (*p == '"' || *p == '`' || *p == '$' || *p == '\\')
				g_string_append_c (s, '\\');
			if (*p == '%')
				g_string_append_c (s, '%');
			g_string_append_c (s, *p);
		}
		g_string_append_c (s, '"');
	} else {
		g_string_append (s, binary);
	}
	g_string_append (s, " --background");
	return g_string_free (s, FALSE);
}

#ifdef G_OS_WIN32
/* =====================================================================
 * Windows: the Task Scheduler, through its COM API
 * ===================================================================== */

/* The class and interface ids, spelled out so the build needs no
 * import library beyond ole32/oleaut32 (taskschd.h only declares
 * them). */
static const CLSID fs_clsid_task_scheduler =
	{ 0x0f87369f, 0xa4e5, 0x4cfc,
	  { 0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd } };
static const IID fs_iid_task_service =
	{ 0x2faba4c7, 0x4da9, 0x4013,
	  { 0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85 } };

#define FS_TASK_FOLDER   L"\\StockFW"
#define FS_TASK_FOLDER_NAME L"StockFW"

static const gchar ADMIN_NEEDED[] =
	N_("Only an administrator can change this. Start StockFW as "
	   "administrator and try again.");

typedef struct {
	gboolean      com_owned;   /* we initialised COM: uninitialise */
	ITaskService *service;
} TaskSession;

static gboolean
hr_is_access_denied (HRESULT hr)
{
	return hr == E_ACCESSDENIED ||
	       hr == HRESULT_FROM_WIN32 (ERROR_ACCESS_DENIED);
}

static gboolean
hr_is_not_found (HRESULT hr)
{
	return hr == HRESULT_FROM_WIN32 (ERROR_FILE_NOT_FOUND) ||
	       hr == HRESULT_FROM_WIN32 (ERROR_PATH_NOT_FOUND);
}

static void
set_hr_error (GError **error, HRESULT hr, const gchar *what)
{
	gchar *detail;

	if (hr_is_access_denied (hr)) {
		g_set_error_literal (error, FS_AUTOSTART_ERROR,
		                     FS_AUTOSTART_ERROR_DENIED, ADMIN_NEEDED);
		return;
	}
	if (HRESULT_FACILITY (hr) == FACILITY_WIN32)
		detail = g_win32_error_message ((gint) HRESULT_CODE (hr));
	else
		detail = g_strdup_printf ("error 0x%08lx", (unsigned long) hr);
	g_set_error (error, FS_AUTOSTART_ERROR, FS_AUTOSTART_ERROR_FAILED,
	             "%s: %s", what, detail);
	g_free (detail);
}

static gboolean
session_open (TaskSession *ts, GError **error)
{
	VARIANT empty;
	HRESULT hr;

	memset (ts, 0, sizeof *ts);
	hr = CoInitializeEx (NULL, COINIT_APARTMENTTHREADED);
	ts->com_owned = SUCCEEDED (hr);   /* RPC_E_CHANGED_MODE: use theirs */

	hr = CoCreateInstance (&fs_clsid_task_scheduler, NULL,
	                       CLSCTX_INPROC_SERVER, &fs_iid_task_service,
	                       (void **) &ts->service);
	if (FAILED (hr)) {
		ts->service = NULL;
		set_hr_error (error, hr, "Task Scheduler unavailable");
		goto fail;
	}
	VariantInit (&empty);
	hr = ITaskService_Connect (ts->service, empty, empty, empty, empty);
	if (FAILED (hr)) {
		set_hr_error (error, hr, "Could not connect to the Task Scheduler");
		goto fail;
	}
	return TRUE;

fail:
	if (ts->service != NULL)
		ITaskService_Release (ts->service);
	ts->service = NULL;
	if (ts->com_owned)
		CoUninitialize ();
	ts->com_owned = FALSE;
	return FALSE;
}

static void
session_close (TaskSession *ts)
{
	if (ts->service != NULL)
		ITaskService_Release (ts->service);
	ts->service = NULL;
	if (ts->com_owned)
		CoUninitialize ();
	ts->com_owned = FALSE;
}

static HRESULT
get_folder (TaskSession *ts, const wchar_t *path, ITaskFolder **folder)
{
	BSTR b = SysAllocString (path);
	HRESULT hr = ITaskService_GetFolder (ts->service, b, folder);

	SysFreeString (b);
	if (FAILED (hr))
		*folder = NULL;
	return hr;
}

/* [ token_user_name ] -- "DOMAIN\name" of `token's user, the form a
 * task's UserId takes.  NULL when it cannot be read.  Caller frees. */
static gchar *
token_user_name (HANDLE token)
{
	BYTE buffer[256];
	DWORD len = 0;
	wchar_t name[256], domain[256];
	DWORD nlen = G_N_ELEMENTS (name), dlen = G_N_ELEMENTS (domain);
	SID_NAME_USE use;
	gchar *n, *d, *user = NULL;

	if (GetTokenInformation (token, TokenUser, buffer, sizeof buffer,
	                         &len) &&
	    LookupAccountSidW (NULL, ((TOKEN_USER *) buffer)->User.Sid,
	                       name, &nlen, domain, &dlen, &use)) {
		n = g_utf16_to_utf8 ((const gunichar2 *) name, -1, NULL, NULL, NULL);
		d = g_utf16_to_utf8 ((const gunichar2 *) domain, -1, NULL, NULL, NULL);
		if (n != NULL)
			user = d != NULL && *d != '\0'
			     ? g_strdup_printf ("%s\\%s", d, n) : g_strdup (n);
		g_free (n);
		g_free (d);
	}
	return user;
}

/* [ shell_user ] -- the account that owns this desktop's shell
 * (Explorer), i.e. the person who is signed in.  With over-the-shoulder
 * elevation -- a standard user types an administrator's credentials --
 * this process runs as that administrator, but "when I sign in" means
 * the person at the desktop.  NULL when there is no shell to ask. */
static gchar *
shell_user (void)
{
	HWND shell = GetShellWindow ();
	DWORD pid = 0;
	HANDLE process, token = NULL;
	gchar *user = NULL;

	if (shell == NULL)
		return NULL;
	GetWindowThreadProcessId (shell, &pid);
	if (pid == 0)
		return NULL;
	process = OpenProcess (PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (process == NULL)
		return NULL;
	if (OpenProcessToken (process, TOKEN_QUERY, &token)) {
		user = token_user_name (token);
		CloseHandle (token);
	}
	CloseHandle (process);
	return user;
}

/* [ current_user ] -- whose sign-in the task is for: the signed-in
 * person (the shell's account), else this process's own token user.
 * Caller frees. */
static gchar *
current_user (void)
{
	HANDLE token = NULL;
	gchar *user = shell_user ();

	if (user != NULL)
		return user;
	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
		return NULL;
	user = token_user_name (token);
	CloseHandle (token);
	return user;
}

static gboolean
token_elevated (void)
{
	return fs_util_privileged ();
}

static gunichar2 *
task_name_w (const gchar *user)
{
	gchar *name = fs_autostart_task_name (user);
	gunichar2 *w = g_utf8_to_utf16 (name, -1, NULL, NULL, NULL);

	g_free (name);
	return w;
}

gboolean
fs_autostart_supported (void)
{
	return TRUE;
}

gboolean
fs_autostart_can_change (gchar **why)
{
	if (why != NULL)
		*why = NULL;
	if (token_elevated ())
		return TRUE;
	if (why != NULL)
		*why = g_strdup (_(ADMIN_NEEDED));
	return FALSE;
}

gboolean
fs_autostart_enabled (void)
{
	TaskSession ts;
	ITaskFolder *folder = NULL;
	IRegisteredTask *task = NULL;
	VARIANT_BOOL on = VARIANT_FALSE;
	gchar *user = current_user ();
	gunichar2 *wname;
	BSTR bname;
	gboolean enabled = FALSE;

	if (user == NULL || !session_open (&ts, NULL)) {
		g_free (user);
		return FALSE;
	}
	wname = task_name_w (user);
	if (wname != NULL &&
	    SUCCEEDED (get_folder (&ts, FS_TASK_FOLDER, &folder))) {
		bname = SysAllocString ((const OLECHAR *) wname);
		if (SUCCEEDED (ITaskFolder_GetTask (folder, bname, &task))) {
			if (SUCCEEDED (IRegisteredTask_get_Enabled (task, &on)))
				enabled = on != VARIANT_FALSE;
			IRegisteredTask_Release (task);
		}
		SysFreeString (bname);
		ITaskFolder_Release (folder);
	}
	g_free (wname);
	g_free (user);
	session_close (&ts);
	return enabled;
}

/* [ folder_is_empty ] -- no tasks (hidden ones included) and no
 * subfolders, so deleting it loses nothing someone else put there. */
static gboolean
folder_is_empty (ITaskFolder *folder)
{
	IRegisteredTaskCollection *tasks = NULL;
	ITaskFolderCollection *subs = NULL;
	LONG ntasks = 1, nsubs = 1;

	if (SUCCEEDED (ITaskFolder_GetTasks (folder, TASK_ENUM_HIDDEN, &tasks))) {
		IRegisteredTaskCollection_get_Count (tasks, &ntasks);
		IRegisteredTaskCollection_Release (tasks);
	}
	if (SUCCEEDED (ITaskFolder_GetFolders (folder, 0, &subs))) {
		ITaskFolderCollection_get_Count (subs, &nsubs);
		ITaskFolderCollection_Release (subs);
	}
	return ntasks == 0 && nsubs == 0;
}

static void
drop_folder_if_empty (TaskSession *ts, ITaskFolder *folder)
{
	ITaskFolder *root = NULL;
	BSTR bname;

	if (!folder_is_empty (folder) ||
	    FAILED (get_folder (ts, L"\\", &root)))
		return;
	bname = SysAllocString (FS_TASK_FOLDER_NAME);
	ITaskFolder_DeleteFolder (root, bname, 0);
	SysFreeString (bname);
	ITaskFolder_Release (root);
}

static gboolean
register_task (TaskSession *ts, const gchar *user, GError **error)
{
	wchar_t exe_w[MAX_PATH * 2];
	DWORD n = GetModuleFileNameW (NULL, exe_w, G_N_ELEMENTS (exe_w));
	ITaskFolder *root = NULL, *folder = NULL;
	IRegisteredTask *task = NULL;
	gchar *exe, *xml;
	gunichar2 *xml_w, *user_w, *name_w;
	BSTR bxml, bname, bfolder;
	VARIANT vuser, empty;
	HRESULT hr;
	gboolean ok = FALSE;

	if (n == 0 || n >= G_N_ELEMENTS (exe_w)) {
		g_set_error_literal (error, FS_AUTOSTART_ERROR,
		                     FS_AUTOSTART_ERROR_FAILED,
		                     "Could not find StockFW.exe's own path.");
		return FALSE;
	}
	exe = g_utf16_to_utf8 ((const gunichar2 *) exe_w, -1, NULL, NULL, NULL);
	if (exe == NULL) {
		g_set_error_literal (error, FS_AUTOSTART_ERROR,
		                     FS_AUTOSTART_ERROR_FAILED,
		                     "StockFW.exe's path is not valid text.");
		return FALSE;
	}

	/* The folder, created on first use with the default security
	 * (administrators and SYSTEM may change it). */
	hr = get_folder (ts, FS_TASK_FOLDER, &folder);
	if (hr_is_not_found (hr)) {
		hr = get_folder (ts, L"\\", &root);
		if (SUCCEEDED (hr)) {
			VariantInit (&empty);
			bfolder = SysAllocString (FS_TASK_FOLDER_NAME);
			hr = ITaskFolder_CreateFolder (root, bfolder, empty, &folder);
			SysFreeString (bfolder);
			ITaskFolder_Release (root);
		}
	}
	if (FAILED (hr)) {
		folder = NULL;
		set_hr_error (error, hr, "Could not open the StockFW task folder");
		g_free (exe);
		return FALSE;
	}

	xml = fs_autostart_task_xml (user, exe);
	xml_w = g_utf8_to_utf16 (xml, -1, NULL, NULL, NULL);
	user_w = g_utf8_to_utf16 (user, -1, NULL, NULL, NULL);
	name_w = task_name_w (user);
	if (xml_w != NULL && user_w != NULL && name_w != NULL) {
		bxml = SysAllocString ((const OLECHAR *) xml_w);
		bname = SysAllocString ((const OLECHAR *) name_w);
		VariantInit (&vuser);
		vuser.vt = VT_BSTR;
		vuser.bstrVal = SysAllocString ((const OLECHAR *) user_w);
		VariantInit (&empty);

		hr = ITaskFolder_RegisterTask (folder, bname, bxml,
		                               TASK_CREATE_OR_UPDATE, vuser,
		                               empty,
		                               TASK_LOGON_INTERACTIVE_TOKEN,
		                               empty, &task);
		if (SUCCEEDED (hr)) {
			IRegisteredTask_Release (task);
			ok = TRUE;
		} else {
			set_hr_error (error, hr, "Could not register the sign-in task");
		}
		VariantClear (&vuser);
		SysFreeString (bname);
		SysFreeString (bxml);
	} else {
		g_set_error_literal (error, FS_AUTOSTART_ERROR,
		                     FS_AUTOSTART_ERROR_FAILED,
		                     "Could not convert the task to UTF-16.");
	}
	g_free (xml_w);
	g_free (user_w);
	g_free (name_w);
	g_free (xml);
	g_free (exe);
	ITaskFolder_Release (folder);
	return ok;
}

static gboolean
delete_task (TaskSession *ts, const gchar *user, GError **error)
{
	ITaskFolder *folder = NULL;
	gunichar2 *name_w = task_name_w (user);
	BSTR bname;
	HRESULT hr;
	gboolean ok = TRUE;

	hr = get_folder (ts, FS_TASK_FOLDER, &folder);
	if (hr_is_not_found (hr)) {
		g_free (name_w);
		return TRUE;   /* never set up: already off */
	}
	if (FAILED (hr) || name_w == NULL) {
		set_hr_error (error, FAILED (hr) ? hr : E_OUTOFMEMORY,
		              "Could not open the StockFW task folder");
		if (folder != NULL)
			ITaskFolder_Release (folder);
		g_free (name_w);
		return FALSE;
	}
	bname = SysAllocString ((const OLECHAR *) name_w);
	hr = ITaskFolder_DeleteTask (folder, bname, 0);
	SysFreeString (bname);
	if (FAILED (hr) && !hr_is_not_found (hr)) {
		set_hr_error (error, hr, "Could not delete the sign-in task");
		ok = FALSE;
	}
	if (ok)
		drop_folder_if_empty (ts, folder);
	ITaskFolder_Release (folder);
	g_free (name_w);
	return ok;
}

gboolean
fs_autostart_set (gboolean on, GError **error)
{
	TaskSession ts;
	gchar *user;
	gboolean ok;

	if (!token_elevated ()) {
		g_set_error_literal (error, FS_AUTOSTART_ERROR,
		                     FS_AUTOSTART_ERROR_DENIED, _(ADMIN_NEEDED));
		return FALSE;
	}
	user = current_user ();
	if (user == NULL) {
		g_set_error_literal (error, FS_AUTOSTART_ERROR,
		                     FS_AUTOSTART_ERROR_FAILED,
		                     "Could not tell which account is signed in.");
		return FALSE;
	}
	if (!session_open (&ts, error)) {
		g_free (user);
		return FALSE;
	}
	ok = on ? register_task (&ts, user, error)
	        : delete_task (&ts, user, error);
	session_close (&ts);
	g_free (user);
	return ok;
}

gboolean
fs_autostart_remove_all (GError **error)
{
	TaskSession ts;
	ITaskFolder *folder = NULL;
	IRegisteredTaskCollection *tasks = NULL;
	IRegisteredTask *task = NULL;
	LONG count = 0, i;
	VARIANT index;
	BSTR bname;
	HRESULT hr;
	gboolean ok = TRUE;

	if (!session_open (&ts, error))
		return FALSE;
	hr = get_folder (&ts, FS_TASK_FOLDER, &folder);
	if (hr_is_not_found (hr)) {
		session_close (&ts);
		return TRUE;
	}
	if (FAILED (hr)) {
		set_hr_error (error, hr, "Could not open the StockFW task folder");
		session_close (&ts);
		return FALSE;
	}

	/* Collect the names first: deleting while walking the live
	 * collection would shift the indices under us. */
	if (SUCCEEDED (ITaskFolder_GetTasks (folder, TASK_ENUM_HIDDEN, &tasks))) {
		GPtrArray *names = g_ptr_array_new_with_free_func (
			(GDestroyNotify) SysFreeString);

		IRegisteredTaskCollection_get_Count (tasks, &count);
		for (i = 1; i <= count; i++) {      /* the collection is 1-based */
			VariantInit (&index);
			index.vt = VT_I4;
			index.lVal = i;
			if (SUCCEEDED (IRegisteredTaskCollection_get_Item (tasks, index, &task))) {
				if (SUCCEEDED (IRegisteredTask_get_Name (task, &bname)))
					g_ptr_array_add (names, bname);
				IRegisteredTask_Release (task);
			}
		}
		IRegisteredTaskCollection_Release (tasks);

		for (i = 0; i < (LONG) names->len; i++) {
			hr = ITaskFolder_DeleteTask (folder, g_ptr_array_index (names, i), 0);
			if (FAILED (hr) && !hr_is_not_found (hr) && ok) {
				set_hr_error (error, hr, "Could not delete a sign-in task");
				ok = FALSE;
			}
		}
		g_ptr_array_unref (names);
	}
	if (ok)
		drop_folder_if_empty (&ts, folder);
	ITaskFolder_Release (folder);
	session_close (&ts);
	return ok;
}

const gchar *
fs_autostart_description (void)
{
	return _("Starts StockFW in the notification area when you sign in, "
	         "through a Task Scheduler task, without administrator "
	         "rights: it shows the firewall's state but cannot change it "
	         "or watch blocked traffic. Windows Firewall keeps its rules "
	         "across restarts by itself. For monitoring and changes, "
	         "start StockFW (Elevated); it takes over from this copy.");
}

/* Windows Firewall keeps its own rules across restarts: no boot unit. */
FsBootUnit
fs_autostart_boot_unit (void)
{
	return FS_BOOT_UNIT_NONE;
}

#else
/* =====================================================================
 * Linux: an XDG autostart entry
 * ===================================================================== */

#define AUTOSTART_FILE "stockfw.desktop"

/* Where the entry goes and whose file permissions to write it with. */
typedef struct {
	gchar   *dir;     /* .../autostart                               */
	gboolean drop;    /* root on behalf of a user: act as that user  */
	uid_t    uid;
	gid_t    gid;
} Target;

/* [ desktop_user ] -- the user root is acting for, through sudo or
 * pkexec (the same rule fs-instance.c uses for the instance name). */
static gboolean
desktop_user (uid_t *uid, gid_t *gid, gchar **home)
{
	const gchar *vars[] = { "SUDO_UID", "PKEXEC_UID" };
	guint i;

	if (geteuid () != 0)
		return FALSE;
	for (i = 0; i < G_N_ELEMENTS (vars); i++) {
		const gchar *v = g_getenv (vars[i]);
		gchar *end = NULL;
		guint64 u;
		struct passwd *pw;

		if (v == NULL || *v == '\0')
			continue;
		u = g_ascii_strtoull (v, &end, 10);
		if (end == NULL || *end != '\0' || u == 0 || u > G_MAXUINT32)
			continue;
		pw = getpwuid ((uid_t) u);
		if (pw == NULL)
			continue;
		*uid = pw->pw_uid;
		*gid = pw->pw_gid;
		*home = g_strdup (pw->pw_dir);
		return TRUE;
	}
	return FALSE;
}

static void
target_init (Target *t)
{
	const gchar *override = g_getenv ("STOCKFW_AUTOSTART_DIR");
	gchar *home = NULL;

	memset (t, 0, sizeof *t);
	t->drop = desktop_user (&t->uid, &t->gid, &home);

	if (override != NULL && *override != '\0')
		t->dir = g_strdup (override);              /* tests */
	else if (t->drop)
		t->dir = g_build_filename (home, ".config", "autostart", NULL);
	else
		t->dir = g_build_filename (g_get_user_config_dir (),
		                           "autostart", NULL);
	g_free (home);
}

static void
target_clear (Target *t)
{
	g_free (t->dir);
	t->dir = NULL;
}

/* [ act_as_user / act_as_root ] -- while root works in a user's home,
 * the file-system checks are made as that user (setfsuid is per
 * thread, so nothing else in the process loses root).  A symlink the
 * user planted, ~/.config/autostart -> /etc say, then fails with
 * EACCES instead of letting root write where the user may not. */
static gboolean
act_as_user (const Target *t)
{
	if (!t->drop)
		return TRUE;
	setfsgid (t->gid);
	setfsuid (t->uid);
	/* setfsuid reports the previous value, not success: read it back. */
	if ((uid_t) setfsuid ((uid_t) -1) != t->uid ||
	    (gid_t) setfsgid ((gid_t) -1) != t->gid) {
		setfsuid (0);
		setfsgid (0);
		return FALSE;
	}
	return TRUE;
}

static void
act_as_root (const Target *t)
{
	if (!t->drop)
		return;
	setfsuid (0);
	setfsgid (0);
}

static gchar *
entry_path (const Target *t)
{
	return g_build_filename (t->dir, AUTOSTART_FILE, NULL);
}

gboolean
fs_autostart_supported (void)
{
	return TRUE;
}

gboolean
fs_autostart_can_change (gchar **why)
{
	if (why != NULL)
		*why = NULL;
	return TRUE;
}

gboolean
fs_autostart_enabled (void)
{
	Target t;
	GKeyFile *kf = g_key_file_new ();
	gchar *path, *exec;
	gboolean on = FALSE;

	target_init (&t);
	path = entry_path (&t);
	if (act_as_user (&t)) {
		if (g_key_file_load_from_file (kf, path, G_KEY_FILE_NONE, NULL) &&
		    g_key_file_has_group (kf, G_KEY_FILE_DESKTOP_GROUP)) {
			GError *e = NULL;
			gboolean hidden, gnome_on;

			exec = g_key_file_get_string (kf, G_KEY_FILE_DESKTOP_GROUP,
			                              G_KEY_FILE_DESKTOP_KEY_EXEC,
			                              NULL);
			hidden = g_key_file_get_boolean (kf, G_KEY_FILE_DESKTOP_GROUP,
			                                 G_KEY_FILE_DESKTOP_KEY_HIDDEN,
			                                 NULL);
			/* Desktops' own "startup applications" tools switch an
			 * entry off by these keys rather than deleting it. */
			gnome_on = g_key_file_get_boolean (kf, G_KEY_FILE_DESKTOP_GROUP,
			                                   "X-GNOME-Autostart-enabled",
			                                   &e);
			if (e != NULL) {        /* key absent: on */
				gnome_on = TRUE;
				g_clear_error (&e);
			}
			on = exec != NULL && *exec != '\0' && !hidden && gnome_on;
			g_free (exec);
		}
		act_as_root (&t);
	}
	g_key_file_free (kf);
	g_free (path);
	target_clear (&t);
	return on;
}

/* [ exec_line ] -- run this binary: by name when PATH finds this very
 * file, else by its absolute path. */
static gchar *
exec_line (void)
{
	gchar *self = g_file_read_link ("/proc/self/exe", NULL);
	gchar *found = g_find_program_in_path ("StockFW");
	gboolean bare = FALSE;
	gchar *line;

	if (self != NULL && found != NULL) {
		char *real_found = realpath (found, NULL);

		bare = real_found != NULL && strcmp (real_found, self) == 0;
		free (real_found);
	}
	line = fs_autostart_desktop_exec (self != NULL ? self : "StockFW",
	                                  bare || self == NULL);
	g_free (self);
	g_free (found);
	return line;
}

static gboolean
write_entry (const Target *t, GError **error)
{
	GKeyFile *kf = g_key_file_new ();
	gchar *exec = exec_line ();
	gchar *path = entry_path (t);
	gchar *data;
	gboolean ok = FALSE;

	g_key_file_set_comment (kf, NULL, NULL,
		" Written by StockFW (Start at sign-in).  Turn the option off\n"
		" in StockFW, or delete this file, to stop it.", NULL);
	g_key_file_set_string (kf, G_KEY_FILE_DESKTOP_GROUP,
	                       G_KEY_FILE_DESKTOP_KEY_TYPE, "Application");
	g_key_file_set_string (kf, G_KEY_FILE_DESKTOP_GROUP,
	                       G_KEY_FILE_DESKTOP_KEY_NAME, "StockFW");
	g_key_file_set_string (kf, G_KEY_FILE_DESKTOP_GROUP,
	                       G_KEY_FILE_DESKTOP_KEY_COMMENT,
	                       "StockFW in the notification area");
	g_key_file_set_string (kf, G_KEY_FILE_DESKTOP_GROUP,
	                       G_KEY_FILE_DESKTOP_KEY_EXEC, exec);
	g_key_file_set_string (kf, G_KEY_FILE_DESKTOP_GROUP,
	                       G_KEY_FILE_DESKTOP_KEY_ICON, "stockfw");
	g_key_file_set_boolean (kf, G_KEY_FILE_DESKTOP_GROUP,
	                        G_KEY_FILE_DESKTOP_KEY_TERMINAL, FALSE);
	g_key_file_set_boolean (kf, G_KEY_FILE_DESKTOP_GROUP,
	                        "X-GNOME-Autostart-enabled", TRUE);
	data = g_key_file_to_data (kf, NULL, NULL);

	if (!act_as_user (t)) {
		g_set_error_literal (error, FS_AUTOSTART_ERROR,
		                     FS_AUTOSTART_ERROR_FAILED,
		                     "Could not switch to the desktop user's "
		                     "file permissions.");
	} else {
		if (g_mkdir_with_parents (t->dir, 0700) != 0) {
			int err = errno;
			g_set_error (error, FS_AUTOSTART_ERROR,
			             FS_AUTOSTART_ERROR_FAILED,
			             "Could not create %s: %s", t->dir,
			             g_strerror (err));
		} else if (g_file_set_contents (path, data, -1, error)) {
			g_chmod (path, 0644);
			ok = TRUE;
		}
		act_as_root (t);
	}

	g_free (data);
	g_free (path);
	g_free (exec);
	g_key_file_free (kf);
	return ok;
}

static gboolean
remove_entry (const Target *t, GError **error)
{
	gchar *path = entry_path (t);
	gboolean ok = TRUE;

	if (!act_as_user (t)) {
		g_set_error_literal (error, FS_AUTOSTART_ERROR,
		                     FS_AUTOSTART_ERROR_FAILED,
		                     "Could not switch to the desktop user's "
		                     "file permissions.");
		ok = FALSE;
	} else {
		if (g_unlink (path) != 0 && errno != ENOENT) {
			int err = errno;
			g_set_error (error, FS_AUTOSTART_ERROR,
			             FS_AUTOSTART_ERROR_FAILED,
			             "Could not remove %s: %s", path,
			             g_strerror (err));
			ok = FALSE;
		}
		act_as_root (t);
	}
	g_free (path);
	return ok;
}

gboolean
fs_autostart_set (gboolean on, GError **error)
{
	Target t;
	gboolean ok;

	target_init (&t);
	ok = on ? write_entry (&t, error) : remove_entry (&t, error);
	target_clear (&t);
	return ok;
}

gboolean
fs_autostart_remove_all (GError **error)
{
	return fs_autostart_set (FALSE, error);
}

const gchar *
fs_autostart_description (void)
{
	return _("Starts StockFW in the notification area when you sign in "
	         "to the desktop. It starts without root, so it can neither "
	         "read nor change the rules nor watch blocked traffic. The "
	         "rules themselves are loaded at boot by the stockfw "
	         "service; start StockFW with sudo to manage them.");
}

/* [ fs_autostart_boot_unit ]
 * Where installer/linux/install.sh puts the unit, and where enabling it
 * links it (its [Install] section says WantedBy=multi-user.target).
 * Read from the file system, so it needs neither root nor systemctl.
 * The link is followed: a link to a unit that is gone reads as not
 * enabled.  STOCKFW_SYSTEMD_DIR points it elsewhere for the tests. */
FsBootUnit
fs_autostart_boot_unit (void)
{
	const gchar *env = g_getenv ("STOCKFW_SYSTEMD_DIR");
	const gchar *dir = (env != NULL && *env != '\0') ? env
	                                                 : "/etc/systemd/system";
	gchar *unit = g_build_filename (dir, "stockfw.service", NULL);
	gchar *wants = g_build_filename (dir, "multi-user.target.wants",
	                                 "stockfw.service", NULL);
	FsBootUnit state;

	if (!g_file_test (unit, G_FILE_TEST_IS_REGULAR))
		state = FS_BOOT_UNIT_ABSENT;
	else if (g_file_test (wants, G_FILE_TEST_EXISTS))
		state = FS_BOOT_UNIT_ENABLED;
	else
		state = FS_BOOT_UNIT_DISABLED;

	g_free (unit);
	g_free (wants);
	return state;
}
#endif
