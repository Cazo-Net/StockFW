/*---[ fs-backend-windows.c ]-------------------------------------------
 * Windows firewall backend (milestone M4).
 *
 * Implements the FsBackend vtable against the Windows Firewall with
 * Advanced Security COM API (HNetCfg.FwPolicy2):
 *
 *   INetFwPolicy2    profile enumeration and global state
 *   INetFwRules      rule listing
 *   INetFwRule       creating / editing allow and block rules
 *
 * Rules are applied through the COM API where possible; two commands
 * still have to be run as processes -- netsh for rule CRUD and
 * wevtutil for the event log -- and both are launched through
 * spawn_capture() below, never GLib's g_spawn (which cannot suppress
 * the console window a console child would otherwise get).
 *
 * Build: add the object to the stockfw target in CMakeLists.txt,
 * link against ole32/oleaut32/hnetcfg.h and drop the
 * fs-backend-null.c entry.
 *--------------------------------------------------------------------*/

/* PROC_THREAD_ATTRIBUTE_HANDLE_LIST (restricting which handles a child
 * inherits) needs Vista or later; the feature test must precede every
 * Windows header or the declaration never appears. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

/* Windows headers come first and in this exact order: winsock2 must
 * precede windows.h, and doing it before the GLib headers avoids the
 * two sets fighting over the same declarations.  Getting this wrong
 * makes CoCreateInstance fail with CO_E_CLASSSTRING. */
#include <winsock2.h>
#include <windows.h>
/* netioapi.h must precede iphlpapi.h: it only defines MIB_IF_TABLE2
 * (and pulls in ws2ipdef.h) on the path where __IPHLPAPI_H__ is not
 * already set, so including iphlpapi.h first silently drops the whole
 * GetIfTable2 API. */
#include <netioapi.h>
#include <iphlpapi.h>
#include <netfw.h>

#include <stdio.h>   /* _snwprintf */

#include "core/fs-backend.h"
#include "core/fs-fwrule.h"
#include "core/fs-service.h"
#include "core/fs-i18n.h"
#include "netfw-compat.h"

/* Linked through CMake: ole32, oleaut32, iphlpapi, ws2_32 */

/* Windows exposes three independently switchable firewall profiles. */
static const NET_FW_PROFILE_TYPE2 profiles[] = {
	NET_FW_PROFILE2_DOMAIN,
	NET_FW_PROFILE2_PRIVATE,
	NET_FW_PROFILE2_PUBLIC
};

/* [ firewalled_com_available ]
 * Instantiates the policy interface.  A desktop Windows install always
 * has it; the check keeps us honest on Server Core and inside odd
 * containers. */
static gboolean
firewalled_com_available (void)
{
	INetFwPolicy2 *policy = NULL;
	HRESULT hr;

	/* Called during startup, so keep it side-effect free. */
	CoInitializeEx (NULL, COINIT_APARTMENTTHREADED);

	hr = CoCreateInstance (&FS_CLSID_NetFwPolicy2, NULL, CLSCTX_ALL,
	                       &FS_IID_INetFwPolicy2, (void **) &policy);

	if (FAILED (hr) || policy == NULL) {
		CoUninitialize ();
		return FALSE;
	}

	policy->lpVtbl->Release (policy);
	CoUninitialize ();

	return TRUE;
}

static FsFirewallState
firewalled_get_state (void)
{
	INetFwPolicy2 *policy = NULL;
	HRESULT hr;
	gsize i;
	gboolean any_on = FALSE;
	gboolean any_off = FALSE;

	CoInitializeEx (NULL, COINIT_APARTMENTTHREADED);

	hr = CoCreateInstance (&FS_CLSID_NetFwPolicy2, NULL, CLSCTX_ALL,
	                       &FS_IID_INetFwPolicy2, (void **) &policy);

	if (FAILED (hr) || policy == NULL) {
		CoUninitialize ();
		return FS_FW_NONE;
	}

	/* Windows has three independent profiles (domain / private /
	 * public) rather than the single on-off state StockFW models.
	 * get_FirewallEnabled() takes a VARIANT_BOOL (-1 / 0), not a
	 * VARIANT. */
	for (i = 0; i < G_N_ELEMENTS (profiles); i++) {
		VARIANT_BOOL on = VARIANT_FALSE;

		if (FAILED (policy->lpVtbl->get_FirewallEnabled (policy,
		                                                profiles[i], &on)))
			continue;

		if (on != VARIANT_FALSE)
			any_on = TRUE;
		else
			any_off = TRUE;
	}

	policy->lpVtbl->Release (policy);
	CoUninitialize ();

	if (!any_on && !any_off)
		return FS_FW_NONE;

	/* Only a state where *every* profile reports off counts as
	 * stopped.  The previous test was (any_on || any_off), which is
	 * true whenever a single profile answered at all -- so the state
	 * read RUNNING even after a successful stop, and the Start button
	 * stayed greyed out forever.  With all profiles off any_on is
	 * FALSE, so this now reports STOPPED correctly.  A mix keeps
	 * reporting RUNNING because at least one profile is still
	 * filtering; the per-profile detail is available from the backend
	 * for anyone who needs it. */
	return any_on ? FS_FW_RUNNING : FS_FW_STOPPED;
}

/* [ set_profiles_enabled ]
 * Turns every profile on or off.  Changing the firewall profile state
 * needs elevation, so a plain (non-"run as administrator") session gets
 * a clear error rather than a silent failure. */
static gboolean
set_profiles_enabled (GError **error, VARIANT_BOOL enabled)
{
	INetFwPolicy2 *policy = NULL;
	HRESULT hr;
	gsize i;
	gboolean ok = TRUE;

	CoInitializeEx (NULL, COINIT_APARTMENTTHREADED);

	hr = CoCreateInstance (&FS_CLSID_NetFwPolicy2, NULL, CLSCTX_ALL,
	                       &FS_IID_INetFwPolicy2, (void **) &policy);

	if (FAILED (hr) || policy == NULL) {
		g_set_error (error, g_quark_from_static_string ("fs-backend-windows"),
		             (int) hr,
		             "Could not connect to the Windows Firewall service. "
		             "Check that the MpsSvc service is running.");
		CoUninitialize ();
		return FALSE;
	}

	for (i = 0; i < G_N_ELEMENTS (profiles); i++) {
		hr = policy->lpVtbl->put_FirewallEnabled (policy, profiles[i],
		                                          enabled);

		if (FAILED (hr)) {
			g_set_error (error,
			             g_quark_from_static_string ("fs-backend-windows"),
			             (int) hr,
			             "Changing the firewall state requires "
			             "administrator privileges. Restart StockFW "
			             "as an administrator and try again.");
			ok = FALSE;
			break;
		}
	}

	policy->lpVtbl->Release (policy);
	CoUninitialize ();

	return ok;
}

static gboolean
firewalled_start (GError **error)
{
	return set_profiles_enabled (error, VARIANT_TRUE);
}

static gboolean
firewalled_stop (GError **error)
{
	return set_profiles_enabled (error, VARIANT_FALSE);
}

static gboolean
firewalled_reload (GError **error)
{
	/* Windows has no separate "reload"; rules take effect on commit. */
	return TRUE;
}

/* ---------------------------------------------------------------------
 * Rule management through netsh.
 *
 * The first implementation drove INetFwRules / INetFwRule directly over
 * COM.  MinGW-w64's netfw.h is unusable for that:
 *
 *   - INetFwRules is declared with INetFwAuthorizedApplications'
 *     method signatures, so Add/Remove/Item have the wrong calling
 *     conventions;
 *   - INetFwPolicy2's vtable does not match the real COM server, so
 *     calls past a point in the vtable crash the process.
 *
 * Reading the profile state via INetFwPolicy2 still works and is kept,
 * but rule creation goes through `netsh advfirewall`, the documented
 * command line interface.  It is stable across SDK versions, needs no
 * header shims, and its failure messages are already good enough to
 * show the user.
 * ------------------------------------------------------------------ */

/* [ run_netsh ]
 * netsh rejects rule names containing ':' , parentheses and slashes,
 * which the display names generated for the UI do contain.  Replace the
 * characters it dislikes so the same name can be used for both the
 * dialog and the command line. */
/* [ netsh_safe_name ]
 * netsh rejects rule names containing ':' , parentheses and slashes,
 * which the display names generated for the UI do contain.  Replace the
 * characters it dislikes so one name can serve both the dialog and the
 * command line.
 */
static gchar *
netsh_safe_name (const gchar *name)
{
	GString *out = g_string_new (NULL);

	for (const gchar *p = (name != NULL) ? name : "StockFW rule";
	     *p != '\0'; p++) {
		switch (*p) {
		case ':':
		case '(':
		case ')':
		case '/':
		case ',':
			g_string_append_c (out, '-');
			break;
		default:
			g_string_append_c (out, *p);
			break;
		}
	}

	return g_string_free (out, FALSE);
}

/* ---------------------------------------------------------------------
 * Child processes: spawn_capture() and its helpers.
 *
 * g_spawn_sync cannot be used on Windows here, for two reasons that
 * were seen live, not theorised:
 *
 *  1. GLib never passes CREATE_NO_WINDOW, so every console-mode child
 *     (netsh, wevtutil) inherited or created a console window.  The
 *     screenshot showed conhost titled "Select
 *     C:\Windows\system32\wevtutil.exe" flashing every five seconds
 *     while the event poll ran.
 *
 *  2. Its synchronous wait runs on the GTK main loop with no timeout,
 *     so a child that stopped responding (that "Select" prompt is
 *     exactly the paused state) froze the whole window in "(Not
 *     Responding)".
 *
 * Everything below fixes both: CreateProcessW with CREATE_NO_WINDOW,
 * output through temporary files, and a hard timeout that kills a
 * wedged child instead of hanging the caller.
 * ------------------------------------------------------------------ */

/* Budgets.  wevtutil answers a ten-record query well under a second
 * when it works at all, so ten seconds means "wedged" and killing it
 * costs nothing but that poll's results.  netsh reconfigures the
 * firewall and can legitimately take a while on a loaded machine. */
#define SPAWN_TIMEOUT_WEVTUTIL_MS 10000
#define SPAWN_TIMEOUT_NETSH_MS    30000

/* [ win32_error_text ]
 * The system's own message for a GetLastError() code, trimmed of the
 * line break FormatMessage appends, or a numeric fallback. */
static gchar *
win32_error_text (DWORD code)
{
	WCHAR *wide = NULL;
	gchar *text = NULL;

	if (FormatMessageW (FORMAT_MESSAGE_ALLOCATE_BUFFER |
	                    FORMAT_MESSAGE_FROM_SYSTEM |
	                    FORMAT_MESSAGE_IGNORE_INSERTS,
	                    NULL, code, 0, (LPWSTR) &wide, 0, NULL) != 0 &&
	    wide != NULL)
		text = g_utf16_to_utf8 (wide, -1, NULL, NULL, NULL);

	if (wide != NULL)
		LocalFree (wide);

	if (text == NULL)
		return g_strdup_printf ("Windows error %lu",
		                        (unsigned long) code);

	return g_strstrip (text);   /* drops the trailing CR/LF */
}

/* [ append_spawn_arg ]
 * Appends one argv element the way CommandLineToArgvW (and therefore
 * the child's CRT startup code) will parse it back: plain when that
 * is unambiguous, otherwise quoted, with embedded quotes escaped and
 * runs of backslashes that touch a quote doubled.  netsh rule names
 * and wevtutil's "/q:*[System[(EventID=5156 ...)]]" both contain
 * spaces, so this is not theoretical. */
static void
append_spawn_arg (GString *cmd, const gchar *arg)
{
	gint backslashes = 0;
	const gchar *p;

	if (*arg != '\0' && strpbrk (arg, " \t\"\n\r") == NULL) {
		g_string_append (cmd, arg);
		return;
	}

	g_string_append_c (cmd, '"');

	for (p = arg; *p != '\0'; p++) {
		if (*p == '\\') {
			backslashes++;
			continue;
		}

		if (*p == '"')
			backslashes = backslashes * 2 + 1;

		while (backslashes > 0) {
			g_string_append_c (cmd, '\\');
			backslashes--;
		}

		if (*p == '"')
			g_string_append_c (cmd, '\\');

		g_string_append_c (cmd, *p);
	}

	/* Backslashes running into the closing quote must be doubled,
	 * or they would escape it. */
	backslashes *= 2;
	while (backslashes > 0) {
		g_string_append_c (cmd, '\\');
		backslashes--;
	}

	g_string_append_c (cmd, '"');
}

/* [ build_command_line ]
 * The full command line for CreateProcessW.  May contain arguments
 * with spaces; argv[0] is looked up through the standard search order
 * when it carries no directory, exactly as g_spawn did. */
static gchar *
build_command_line (gchar **argv)
{
	GString *cmd = g_string_new (NULL);
	gsize i;

	for (i = 0; argv[i] != NULL; i++) {
		if (i > 0)
			g_string_append_c (cmd, ' ');
		append_spawn_arg (cmd, argv[i]);
	}

	return g_string_free (cmd, FALSE);
}

/* [ read_handle_output ]
 * Whatever the child wrote to the temp file.  The file object (and
 * its write offset) is shared with the child through inheritance, so
 * the offset sits at the end after the wait -- rewind first. */
static gchar *
read_handle_output (HANDLE handle)
{
	LARGE_INTEGER size;
	LARGE_INTEGER zero;
	gchar *text;
	DWORD got = 0;

	if (handle == INVALID_HANDLE_VALUE)
		return NULL;

	zero.QuadPart = 0;
	if (!SetFilePointerEx (handle, zero, NULL, FILE_BEGIN))
		return NULL;

	if (!GetFileSizeEx (handle, &size) || size.QuadPart < 0)
		return NULL;

	/* A ten-record text query is a few kilobytes; a child gone wrong
	 * must not get to allocate gigabytes of heap for us. */
	if (size.QuadPart > 16 * 1024 * 1024)
		size.QuadPart = 16 * 1024 * 1024;

	text = g_malloc ((gsize) size.QuadPart + 1);

	{
		DWORD want = (DWORD) size.QuadPart;
		DWORD chunk = 0;

		while (got < want &&
		       ReadFile (handle, text + got, want - got, &chunk, NULL) &&
		       chunk > 0)
			got += chunk;
	}

	if (got == 0 && size.QuadPart > 0) {
		g_free (text);
		return NULL;
	}

	/* wevtutil /f:text pads fixed-width header values with NUL bytes
	 * ("Level: Information\0") and terminates the description the
	 * same way -- seen in real output, not guessed.  Everything
	 * downstream is C-string based: g_strsplit/strlen would stop at
	 * the first NUL, discarding every line after it -- addresses,
	 * ports, direction -- and the record would be rejected as
	 * address-less, so the list stayed empty with a perfectly
	 * readable log.  Strip them while the byte count is still known;
	 * the output is text, and no caller wants the padding. */
	{
		gsize j = 0;
		gsize k;

		for (k = 0; k < got; k++) {
			if (text[k] != '\0')
				text[j++] = text[k];
		}
		text[j] = '\0';
	}

	return text;
}

/* [ spawn_capture ]
 * Runs argv with stdout and stderr captured and, critically, with no
 * console window of its own (CREATE_NO_WINDOW).
 *
 * Output goes to temporary files rather than pipes on purpose: we
 * block in WaitForSingleObject while the child writes, a pipe's
 * buffer is finite, and a chatty child whose parent is not draining
 * it yet deadlocks -- precisely the freeze we are eliminating.  stdin
 * comes from the null device.  PROC_THREAD_ATTRIBUTE_HANDLE_LIST, for
 * which _WIN32_WINNT is set at the top of this file, restricts the
 * child to inheriting exactly those three handles instead of every
 * inheritable handle in the process; if that setup fails we fall back
 * to plain inheritance, which is merely untidy, never broken.
 *
 * Returns TRUE once the process was started, FALSE with @error set if
 * it could not be.  *exit_status receives the raw process exit code
 * -- the same value g_spawn_sync reported on Windows, so
 * ERROR_ACCESS_DENIED (5) from an unprivileged wevtutil still means
 * what it always did -- or ERROR_TIMEOUT (1460) when the budget ran
 * out and the child was killed. */
static gboolean
spawn_capture (gchar **argv, gint timeout_ms,
               gchar **standard_output, gchar **standard_error,
               gint *exit_status, GError **error)
{
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOEXW si;
	PROCESS_INFORMATION pi;
	WCHAR temp_dir[MAX_PATH];
	WCHAR out_path[MAX_PATH] = { 0 };
	WCHAR err_path[MAX_PATH] = { 0 };
	HANDLE in_handle = INVALID_HANDLE_VALUE;
	HANDLE out_handle = INVALID_HANDLE_VALUE;
	HANDLE err_handle = INVALID_HANDLE_VALUE;
	HANDLE inherit_list[3];
	PPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
	gchar *cmd_line = NULL;
	gunichar2 *wide_cmd = NULL;
	gchar *out_text = NULL;
	gchar *err_text = NULL;
	GQuark quark = g_quark_from_static_string ("fs-backend-windows");
	SIZE_T attr_size = 0;
	guint n_handles = 0;
	gboolean use_attrs = FALSE;
	DWORD wait_result = WAIT_FAILED;   /* early exits must return FALSE */
	DWORD code = 0;

	if (standard_output != NULL)
		*standard_output = NULL;
	if (standard_error != NULL)
		*standard_error = NULL;

	cmd_line = build_command_line (argv);

	wide_cmd = g_utf8_to_utf16 (cmd_line, -1, NULL, NULL, NULL);
	g_free (cmd_line);

	if (wide_cmd == NULL) {
		if (error != NULL)
			g_set_error_literal (error, quark, 0,
			                     "The command line is not valid UTF-8");
		return FALSE;
	}

	/* Two temp files for the output streams, opened inheritable so
	 * the child writes straight into them. */
	memset (&sa, 0, sizeof sa);
	sa.nLength = sizeof sa;
	sa.bInheritHandle = TRUE;

	out_path[0] = L'\0';
	err_path[0] = L'\0';

	if (GetTempPathW (G_N_ELEMENTS (temp_dir), temp_dir) == 0 ||
	    GetTempFileNameW (temp_dir, L"sfw", 0, out_path) == 0 ||
	    GetTempFileNameW (temp_dir, L"sfw", 0, err_path) == 0) {
		if (error != NULL)
			g_set_error_literal (
				error, quark, 0,
				"Could not create temporary files to capture "
				"process output");
		goto out;
	}

	out_handle = CreateFileW (out_path, GENERIC_READ | GENERIC_WRITE,
	                          FILE_SHARE_READ, &sa, OPEN_EXISTING,
	                          FILE_ATTRIBUTE_TEMPORARY, NULL);
	err_handle = CreateFileW (err_path, GENERIC_READ | GENERIC_WRITE,
	                          FILE_SHARE_READ, &sa, OPEN_EXISTING,
	                          FILE_ATTRIBUTE_TEMPORARY, NULL);
	in_handle = CreateFileW (L"NUL", GENERIC_READ,
	                         FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
	                         OPEN_EXISTING, 0, NULL);

	if (out_handle == INVALID_HANDLE_VALUE ||
	    err_handle == INVALID_HANDLE_VALUE ||
	    in_handle == INVALID_HANDLE_VALUE) {
		if (error != NULL)
			g_set_error (error, quark, (gint) GetLastError (),
			             "Could not open a temporary file: %s",
			             win32_error_text (GetLastError ()));
		goto out;
	}

	inherit_list[n_handles++] = in_handle;
	inherit_list[n_handles++] = out_handle;
	inherit_list[n_handles++] = err_handle;

	/* Ask for the child to inherit our three handles and nothing
	 * else.  The first call only measures the attribute list. */
	InitializeProcThreadAttributeList (NULL, 1, 0, &attr_size);
	if (attr_size > 0) {
		attrs = g_malloc (attr_size);
		if (attrs == NULL ||
		    !InitializeProcThreadAttributeList (attrs, 1, 0,
		                                        &attr_size)) {
			g_clear_pointer (&attrs, g_free);
		} else if (!UpdateProcThreadAttribute (
			attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
			inherit_list, n_handles * sizeof (HANDLE),
			NULL, NULL)) {
			DeleteProcThreadAttributeList (attrs);
			g_clear_pointer (&attrs, g_free);
		} else {
			use_attrs = TRUE;
		}
	}

	memset (&si, 0, sizeof si);
	si.StartupInfo.cb = use_attrs ? sizeof (STARTUPINFOEXW)
	                              : sizeof (STARTUPINFOW);
	si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
	si.StartupInfo.hStdInput = in_handle;
	si.StartupInfo.hStdOutput = out_handle;
	si.StartupInfo.hStdError = err_handle;

	memset (&pi, 0, sizeof pi);

	if (!CreateProcessW (NULL, wide_cmd, NULL, NULL, TRUE,
	                     CREATE_NO_WINDOW |
	                     (use_attrs ? EXTENDED_STARTUPINFO_PRESENT : 0),
	                     NULL, NULL, &si.StartupInfo, &pi)) {
		if (error != NULL)
			g_set_error (error, quark, (gint) GetLastError (),
			             "Could not run %s: %s", argv[0],
			             win32_error_text (GetLastError ()));
		goto out;
	}

	/* Our copies of the inherited handles are no longer needed to
	 * hand over, but the same file object stays open for reading the
	 * output back after the wait. */
	CloseHandle (pi.hThread);
	CloseHandle (in_handle);
	in_handle = INVALID_HANDLE_VALUE;

	wait_result = WaitForSingleObject (pi.hProcess,
	                                    (DWORD) timeout_ms);

	if (wait_result == WAIT_TIMEOUT) {
		/* The point of the timeout: a child that never finishes
		 * must not take the caller -- and through the caller, the
		 * UI -- down with it. */
		TerminateProcess (pi.hProcess, ERROR_TIMEOUT);
		if (WaitForSingleObject (pi.hProcess, 5000) == WAIT_OBJECT_0)
			GetExitCodeProcess (pi.hProcess, &code);
		else
			code = (DWORD) -1;   /* the kill failed: report it */
	} else if (wait_result == WAIT_OBJECT_0) {
		if (!GetExitCodeProcess (pi.hProcess, &code))
			code = (DWORD) -1;
	} else {
		/* WAIT_FAILED: not expected with a valid handle; do not
		 * pretend the child succeeded. */
		code = (DWORD) -1;
	}

	CloseHandle (pi.hProcess);

	out_text = read_handle_output (out_handle);
	err_text = read_handle_output (err_handle);

	if (out_text == NULL)
		out_text = g_strdup ("");
	if (err_text == NULL)
		err_text = g_strdup ("");

	if (standard_output != NULL) {
		*standard_output = out_text;
		out_text = NULL;
	}
	if (standard_error != NULL) {
		*standard_error = err_text;
		err_text = NULL;
	}
	if (exit_status != NULL)
		*exit_status = (gint) code;

out:
	if (attrs != NULL) {
		if (use_attrs)
			DeleteProcThreadAttributeList (attrs);
		g_free (attrs);
	}
	if (in_handle != INVALID_HANDLE_VALUE)
		CloseHandle (in_handle);
	if (out_handle != INVALID_HANDLE_VALUE)
		CloseHandle (out_handle);
	if (err_handle != INVALID_HANDLE_VALUE)
		CloseHandle (err_handle);
	if (out_path[0] != L'\0')
		DeleteFileW (out_path);
	if (err_path[0] != L'\0')
		DeleteFileW (err_path);
	g_free (out_text);
	g_free (err_text);
	g_free (wide_cmd);

	return wait_result == WAIT_OBJECT_0 || wait_result == WAIT_TIMEOUT;
}

/* [ run_netsh ]
 * Runs netsh with the given arguments.  Returns TRUE on success, with
 * the exit status in *exit_status and any output in *output. */
static gboolean
run_netsh (gchar **args, GError **error, gint *exit_status,
           gchar **output)
{
	gchar *out = NULL;
	gchar *err_text = NULL;
	gint status = 0;

	if (output != NULL)
		*output = NULL;

	if (!spawn_capture (args, SPAWN_TIMEOUT_NETSH_MS,
	                    &out, &err_text, &status, error)) {
		g_free (out);
		g_free (err_text);
		return FALSE;
	}

	if (exit_status != NULL)
		*exit_status = status;

	/* netsh reports some failures, the elevation ones especially, on
	 * stderr only.  Handing that message to the caller is what lets
	 * netsh_needs_elevation() fire instead of the reason vanishing. */
	if (out == NULL || *out == '\0') {
		g_free (out);
		out = err_text;
		err_text = NULL;
	}

	g_free (err_text);

	if (output != NULL)
		*output = out;
	else
		g_free (out);

	return TRUE;
}

/* [ netsh_needs_elevation ]
 * netsh reports a specific error for a non-administrator caller; map
 * that onto our own result so the UI can explain what to do. */
static gboolean
netsh_needs_elevation (const gchar *output)
{
	return (output != NULL &&
	        (strstr (output, "requested operation requires elevation") != NULL ||
	         strstr (output, "Access is denied") != NULL));
}

/* [ netsh_add_rule ]
 * Creates one rule.  Returns FALSE and sets error on failure. */
static gboolean
netsh_add_rule (const FsFwRule *rule, GError **error)
{
	GPtrArray *args;
	gchar *name;
	gchar *port;
	gchar *protocol;
	const gchar *direction;
	const gchar *action;
	gchar *output = NULL;
	gint status = 0;
	gboolean ok = FALSE;

	args = g_ptr_array_new_with_free_func (g_free);
	g_ptr_array_add (args, g_strdup ("netsh.exe"));
	g_ptr_array_add (args, g_strdup ("advfirewall"));
	g_ptr_array_add (args, g_strdup ("firewall"));
	g_ptr_array_add (args, g_strdup ("add"));
	g_ptr_array_add (args, g_strdup ("rule"));

	/* spawn_capture() passes argv straight to CreateProcess with no
	 * shell parsing, so arguments must not carry quote characters: the whole
	 * "name=..." pair goes across as one element.  Adding quotes here
	 * makes netsh mis-parse the value and then complain about the
	 * profiles argument. */
	name = netsh_safe_name (rule->name);
	g_ptr_array_add (args, g_strdup_printf ("name=%s", name));
	g_free (name);

	/* Every profile, so the rule applies wherever the firewall is on. */
	g_ptr_array_add (args, g_strdup ("profile=any"));

	direction = (rule->direction == FS_DIR_INBOUND) ? "in" : "out";
	action = (rule->action == FS_ACTION_ALLOW) ? "allow" : "block";
	protocol = (rule->protocol == FS_PROTO_TCP) ? "TCP"
	           : (rule->protocol == FS_PROTO_UDP) ? "UDP" : "any";

	g_ptr_array_add (args, g_strdup_printf ("dir=%s", direction));
	g_ptr_array_add (args, g_strdup_printf ("action=%s", action));
	g_ptr_array_add (args, g_strdup_printf ("protocol=%s", protocol));
	g_ptr_array_add (args, g_strdup ("enable=yes"));

	/* netsh rejects any port specification when the protocol is
	 * "any": "Ports can only be specified if the protocol is TCP or
	 * UDP."  Omit localport in that case. */
	if (rule->protocol != FS_PROTO_ANY) {
		if (rule->local_port > 0) {
			port = g_strdup_printf ("localport=%d", rule->local_port);
			g_ptr_array_add (args, port);
		} else {
			g_ptr_array_add (args, g_strdup ("localport=any"));
		}
	}

	if (rule->remote_address != NULL && *rule->remote_address != '\0')
		g_ptr_array_add (args,
		                 g_strdup_printf ("remoteip=%s",
		                                  rule->remote_address));

	g_ptr_array_add (args, NULL);

	if (!run_netsh ((gchar **) args->pdata, error, &status, &output))
		goto out;

	if (status == 0) {
		ok = TRUE;
		goto out;
	}

	if (netsh_needs_elevation (output)) {
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fs-backend-windows"),
		                     0,
		                     "Creating firewall rules requires "
		                     "administrator privileges. Restart "
		                     "StockFW as an administrator and try "
		                     "again.");
	} else {
		g_set_error (error,
		             g_quark_from_static_string ("fs-backend-windows"),
		             status, "netsh could not create the rule \"%s\": %s",
		             rule->name ? rule->name : "(unnamed)",
		             output ? g_strstrip (output) : "no output");
	}

out:
	if (output != NULL)
		g_print ("netsh add rule: %s\n",
		         output ? g_strstrip (output) : "(no output)");

	g_free (output);
	g_ptr_array_unref (args);

	return ok;
}

/* [ netsh_delete_one ]
 * Deletes a single rule by exact name.  Returns TRUE when netsh exited
 * cleanly; a "no rules match" result is not an error here. */
static gboolean
netsh_delete_one (const gchar *rule_name, GError **error)
{
	GPtrArray *args;
	gchar *name;
	gchar *output = NULL;
	gint status = 0;
	gboolean ok;

	args = g_ptr_array_new_with_free_func (g_free);
	g_ptr_array_add (args, g_strdup ("netsh.exe"));
	g_ptr_array_add (args, g_strdup ("advfirewall"));
	g_ptr_array_add (args, g_strdup ("firewall"));
	g_ptr_array_add (args, g_strdup ("delete"));
	g_ptr_array_add (args, g_strdup ("rule"));

	name = netsh_safe_name (rule_name);
	g_ptr_array_add (args, g_strdup_printf ("name=%s", name));
	g_free (name);

	g_ptr_array_add (args, NULL);

	if (!run_netsh ((gchar **) args->pdata, error, &status, &output)) {
		g_ptr_array_unref (args);
		return FALSE;
	}

	ok = (status == 0);

	if (!ok && netsh_needs_elevation (output)) {
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fs-backend-windows"),
		                     0,
		                     "Removing firewall rules requires "
		                     "administrator privileges.");
	}

	g_free (output);
	g_ptr_array_unref (args);

	return ok;
}

/* [ firewalled_clear_rules ]
 * Removes the rules this application installed on a previous apply.
 *
 * Deliberately NOT "name=all": that would delete every rule on the
 * machine, including ones the user or Windows created.  Instead we ask
 * netsh for the current rule list, keep the names that match our own
 * prefix, and delete exactly those.
 *
 * Returns the number of rules removed through *removed when given. */
static FsApplyResult
firewalled_clear_rules (GError **error)
{
	gint removed = 0;
	GHashTable *ours;
	GList *names, *iter;
	gchar *output = NULL;
	gint status = 0;
	FsApplyResult result = FS_APPLY_OK;

	/* Ask for every rule as CSV: Name, dir, action, ... */
	{
		gchar *args[] = {
			"netsh.exe", "advfirewall", "firewall", "show", "rule",
			"name=all", NULL
		};

		if (!run_netsh (args, error, &status, &output)) {
			g_free (output);
			return FS_APPLY_FAILED;
		}
	}

	if (status != 0) {
		/* Decide the verdict while `output` is still alive: it is
		 * freed below, and reading it afterwards would be a
		 * use-after-free. */
		gboolean needs_elevation = netsh_needs_elevation (output);

		/* Cannot enumerate, so cannot safely delete anything. */
		if (needs_elevation)
			g_set_error_literal (error,
			                     g_quark_from_static_string (
				                     "fs-backend-windows"),
			                     0,
			                     "Listing firewall rules requires "
			                     "administrator privileges.");

		g_free (output);
		return needs_elevation ? FS_APPLY_NO_PRIVILEGE : FS_APPLY_FAILED;
	}

	ours = g_hash_table_new (g_str_hash, g_str_equal);

	/* Output is CSV-ish; the first field of each record is the rule
	 * name.  Collect the ones we created. */
	{
		gchar **lines = g_strsplit (output, "\r\n", -1);

		for (gint i = 0; lines[i] != NULL; i++) {
			gchar *line = g_strstrip (lines[i]);
			gchar *comma;

			if (line == NULL || *line == '\0')
				continue;

			comma = strchr (line, ',');

			if (comma != NULL)
				*comma = '\0';

			/* Names we created, in every spelling they have shipped
			 * with.  netsh_safe_name rewrites the ':' of the display
			 * name into '-', so ours arrive here as "StockFW- ...";
			 * earlier builds produced "StockFW- ...", and the
			 * nameless fallback used "StockFW ...".  Testing only
			 * for the newest spelling would skip every rule a previous
			 * version left behind, so each apply would pile another
			 * copy of each rule on top. */
			if (g_str_has_prefix (line, "StockFW-") ||
			    g_str_has_prefix (line, "StockFW ") ||
			    g_str_has_prefix (line, "StockFW-") ||
			    g_str_has_prefix (line, "StockFW "))
				g_hash_table_add (ours, g_strdup (line));
		}

		g_strfreev (lines);
	}

	names = g_hash_table_get_keys (ours);

	for (iter = names; iter != NULL; iter = iter->next) {
		GError *local = NULL;

		if (netsh_delete_one (iter->data, &local))
			removed++;

		g_clear_error (&local);
	}

	if (error != NULL && removed > 0 && g_hash_table_size (ours) > 0) {
		/* Silent on success: deleting our own rules is not something
		 * the user needs a dialog about. */
	}

	g_list_free (names);
	g_hash_table_destroy (ours);
	g_free (output);

	return result;
}

/* [ firewalled_apply_rules ]
 * Replaces the rules we own with the ones the policy describes. */
static FsApplyResult
firewalled_apply_rules (const FsPolicy *policy, GError **error)
{
	GList *rules, *iter;
	guint applied = 0;
	guint failed = 0;
	GError *first_error = NULL;

	if (policy == NULL)
		return FS_APPLY_FAILED;

	rules = fs_fwrule_from_policy (policy);

	/* Drop the previous set first so applying twice does not
	 * accumulate duplicates. */
	firewalled_clear_rules (NULL);

	for (iter = rules; iter != NULL; iter = iter->next) {
		GError *local = NULL;

		if (netsh_add_rule (iter->data, &local))
			applied++;
		else {
			failed++;

			/* Keep the first real failure for the dialog. */
			if (first_error == NULL && local != NULL)
				first_error = g_error_copy (local);

			g_clear_error (&local);
		}
	}

	fs_fwrule_list_free (rules);

	if (failed > 0 && applied == 0) {
		/* Decide the verdict first: g_propagate_error() hands
		 * ownership of first_error to *error (and g_clear_error()
		 * would free it), so reading first_error->message afterwards
		 * would be a use-after-free. */
		gboolean needs_elevation =
			netsh_needs_elevation (first_error != NULL
			                       ? first_error->message : NULL);

		if (error != NULL && first_error != NULL)
			g_propagate_error (error, first_error);
		else {
			if (error != NULL)
				g_set_error_literal (
					error,
					g_quark_from_static_string (
						"fs-backend-windows"),
					0,
					"None of the rules could be created.");

			/* Not propagated, so nobody else will free it. */
			g_clear_error (&first_error);
		}

		return needs_elevation ? FS_APPLY_NO_PRIVILEGE : FS_APPLY_FAILED;
	}

	if (failed > 0) {
		g_set_error (error, g_quark_from_static_string ("fs-backend-windows"),
		             (int) failed, "%u of %u rules could not be created",
		             failed, applied + failed);
		return FS_APPLY_PARTIAL;
	}

	return FS_APPLY_OK;
}
static GList *
firewalled_list_interfaces (void)
{
	GList *list = NULL;
	IP_ADAPTER_ADDRESSES *adapters = NULL;
	ULONG size = 0;
	ULONG status;
	IP_ADAPTER_ADDRESSES *adapter;

	status = GetAdaptersAddresses (AF_UNSPEC,
	                               GAA_FLAG_SKIP_ANYCAST |
	                               GAA_FLAG_SKIP_MULTICAST |
	                               GAA_FLAG_SKIP_DNS_SERVER,
	                               NULL, NULL, &size);

	if (status != ERROR_BUFFER_OVERFLOW || size == 0)
		return NULL;

	adapters = g_malloc0 (size);
	status = GetAdaptersAddresses (AF_UNSPEC,
	                               GAA_FLAG_SKIP_ANYCAST |
	                               GAA_FLAG_SKIP_MULTICAST |
	                               GAA_FLAG_SKIP_DNS_SERVER,
	                               NULL, adapters, &size);

	if (status != NO_ERROR) {
		g_free (adapters);
		return NULL;
	}

	for (adapter = adapters; adapter != NULL; adapter = adapter->Next) {
		FsInterface *iface = g_new0 (FsInterface, 1);
		IP_ADAPTER_UNICAST_ADDRESS *unicast;

		iface->name = g_strdup (adapter->AdapterName);
		iface->ip = NULL;
		iface->netmask = NULL;

		for (unicast = adapter->FirstUnicastAddress;
		     unicast != NULL; unicast = unicast->Next) {
			if (iface->ip == NULL &&
			    unicast->Address.lpSockaddr->sa_family == AF_INET) {
				struct sockaddr_in *in =
					(struct sockaddr_in *) unicast->Address.lpSockaddr;

				iface->ip = g_strdup (inet_ntoa (in->sin_addr));

				if (unicast->OnLinkPrefixLength != 0)
					iface->netmask = g_strdup_printf ("%u",
					                                 unicast->OnLinkPrefixLength);
			}
		}

		/* Skip the software loopback adapter. */
		if (iface->ip == NULL) {
			fs_interface_free (iface);
			continue;
		}

		list = g_list_append (list, iface);
	}

	g_free (adapters);

	return list;
}

/* ---------------------------------------------------------------------
 * Status page data sources.
 *
 * The original Status page had two live panels -- "Network" (per-device
 * throughput) and "Active connections".  Neither is firewall state, so
 * they come from the IP Helper API rather than from INetFwPolicy2.
 *--------------------------------------------------------------------*/

/* [ iface_type_name ]
 * IANAifType-MIB numbers rendered the way the panel labels them.  The
 * numeric literals are used rather than the IF_TYPE_* macros so this
 * compiles against any SDK. */
static const gchar *
iface_type_name (ULONG type)
{
	switch (type) {
	case 6:  return "Ethernet";    /* ethernetCsmacd      */
	case 71: return "Wireless";    /* ieee80211           */
	case 23: return "PPP";         /* ppp                 */
	case 24: return "Loopback";    /* softwareLoopback    */
	case 131: return "Tunnel";     /* tunnel               */
	case 209: return "IPv4";       /* ipv4                 */
	case 244: return "IPv6";       /* ipv6                 */
	default: return "Other";
	}
}

/* [ firewalled_list_interface_stats ]
 * Cumulative rx/tx octets per interface.  The view samples twice and
 * diffs these, which is where the "Activity" column comes from. */
static GList *
firewalled_list_interface_stats (void)
{
	MIB_IF_TABLE2 *table = NULL;
	GList *list = NULL;

	if (GetIfTable2 (&table) != NO_ERROR || table == NULL)
		return NULL;

	for (ULONG i = 0; i < table->NumEntries; i++) {
		const MIB_IF_ROW2 *row = &table->Table[i];
		FsIfaceStat *stat;

		/* Loopback would dominate the list and is never interesting
		 * in a firewall's traffic panel. */
		if (row->Type == 24)
			continue;

		/* Skip adapters that are down and have never carried
		 * anything: they are still enumerating. */
		if (row->OperStatus != IfOperStatusUp &&
		    row->InOctets == 0 && row->OutOctets == 0)
			continue;

		stat = g_new0 (FsIfaceStat, 1);

		/* Alias is the friendly name Windows shows in the tray
		 * ("Ethernet", "Wi-Fi"); Description is the hardware name. */
		stat->device = g_utf16_to_utf8 (row->Alias, -1, NULL, NULL, NULL);
		if (stat->device == NULL)
			stat->device = g_utf16_to_utf8 (row->Description, -1,
			                                NULL, NULL, NULL);
		if (stat->device == NULL)
			stat->device = g_strdup ("?");

		stat->kind     = g_strdup (iface_type_name (row->Type));
		stat->received = row->InOctets;
		stat->sent     = row->OutOctets;
		stat->up       = (row->OperStatus == IfOperStatusUp);

		list = g_list_prepend (list, stat);
	}

	FreeMibTable (table);

	return g_list_reverse (list);
}

/* [ ipv4_str ]
 * A DWORD from the MIB is a network-order address; render it. */
static gchar *
ipv4_str (DWORD addr)
{
	struct in_addr in;

	in.s_addr = addr;
	return g_strdup (inet_ntoa (in));
}

/* [ program_for_pid ]
 * Process image basename for a PID.  Returns NULL when the process has
 * exited or is a protected system one we may not open. */
static gchar *
program_for_pid (DWORD pid)
{
	HANDLE process;
	gchar path[MAX_PATH];
	gchar *result = NULL;
	DWORD length = MAX_PATH;

	if (pid == 0)
		return g_strdup ("System Idle");
	if (pid == 4)
		return g_strdup ("System");

	process = OpenProcess (PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

	if (process == NULL)
		return NULL;

	if (QueryFullProcessImageNameA (process, 0, path, &length))
		result = g_path_get_basename (path);

	CloseHandle (process);
	return result;
}

/* [ guess_direction ]
 * TCP tells us the endpoints but not who dialled.  The heuristic: a
 * well-known local port means someone reached a service we run, a
 * well-known remote port means we reached one.  With neither, assume
 * outbound, which is what a desktop mostly does. */
static const gchar *
guess_direction (guint local_port, guint remote_port)
{
	if (remote_port < 1024 && local_port >= 1024)
		return "Outbound";
	if (local_port < 1024)
		return "Inbound";
	if (local_port >= 49152)
		return "Outbound";
	if (remote_port >= 49152)
		return "Inbound";

	return "Outbound";
}

/* [ firewalled_list_connections ]
 * Established TCP connections with their owning process.  Needs no
 * elevation: GetExtendedTcpTable works for a normal user, and opening
 * the process only fails for a handful of protected system processes. */
static GList *
firewalled_list_connections (void)
{
	MIB_TCPTABLE_OWNER_PID *table = NULL;
	GList *list = NULL;
	DWORD size = 0;
	DWORD status;

	status = GetExtendedTcpTable (NULL, &size, TRUE, AF_INET,
	                              TCP_TABLE_OWNER_PID_CONNECTIONS, 0);

	if (status != ERROR_INSUFFICIENT_BUFFER || size == 0)
		return NULL;

	table = g_malloc (size);

	status = GetExtendedTcpTable (table, &size, TRUE, AF_INET,
	                              TCP_TABLE_OWNER_PID_CONNECTIONS, 0);

	if (status != NO_ERROR) {
		g_free (table);
		return NULL;
	}

	for (DWORD i = 0; i < table->dwNumEntries; i++) {
		const MIB_TCPROW_OWNER_PID *row = &table->table[i];
		FsConnection *conn;
		guint local_port, remote_port;
		gchar *service;

		/* Unconnected rows would show as 0.0.0.0:0. */
		if (row->dwRemoteAddr == 0 || row->dwRemotePort == 0)
			continue;

		local_port  = ntohs ((u_short) row->dwLocalPort);
		remote_port = ntohs ((u_short) row->dwRemotePort);

		conn = g_new0 (FsConnection, 1);

		conn->source      = ipv4_str (row->dwLocalAddr);
		conn->destination = ipv4_str (row->dwRemoteAddr);
		conn->port        = g_strdup_printf ("%u", remote_port);
		conn->protocol    = g_strdup ("TCP");
		conn->direction   = g_strdup (guess_direction (local_port,
		                                               remote_port));
		conn->program     = program_for_pid (row->dwOwningPid);

		service = fs_service_lookup_port ((gint) remote_port);
		conn->service = service != NULL ? service
		                                : g_strdup ("Unknown");

		if (conn->program == NULL)
			conn->program = g_strdup ("?");

		list = g_list_prepend (list, conn);
	}

	g_free (table);

	return g_list_reverse (list);
}

/* ---------------------------------------------------------------------
 * Event monitoring.
 *
 * Windows records dropped packets in the
 * Microsoft-Windows-WindowsFirewallWithAdvancedSecurity/Firewall
 * channel, but only when auditing is turned on for filtering:
 *
 *   auditpol /set /subcategory:"Filtering Platform Connection" ^
 *              /success:enable /failure:enable
 *
 * wevtutil is used rather than the Event Log COM API because MinGW's
 * headers for the latter are as unreliable as netfw.h was.  A GIO
 * timeout ticks every few seconds; each tick dispatches a worker
 * thread that runs the query and hands the result back to the main
 * loop with g_idle_add, so neither the child's runtime nor a hang can
 * freeze the UI.
 * ------------------------------------------------------------------ */

static guint     log_source_id = 0;
static FsLogFunc log_callback = NULL;
static gpointer  log_user_data = NULL;

/* The wevtutil query runs on a worker thread and its result comes
 * back through g_idle_add.  Even with no console window of its own, a
 * synchronous query on the GTK main loop freezes the whole window for
 * as long as the child takes -- which is how the app sat in "(Not
 * Responding)" behind a paused conhost.
 *
 *   poll_in_flight  in-flight guard: a tick that finds a query still
 *                   running skips instead of stacking another child.
 *   log_generation  identifies the monitoring session; stop() bumps
 *                   it so a result from a session that has already
 *                   ended is dropped instead of delivered late.
 */
static gboolean poll_in_flight = FALSE;
static guint    log_generation = 0;

/* One finished (or timed out) query, waiting for the main loop. */
typedef struct {
	gchar *output;
	gchar *err_text;
	gint   exit_code;
	guint  generation;
} PollResult;

/* Records already handed to the UI.  The query re-reads the latest ten
 * events on every poll, so each poll must drop whatever earlier ones
 * delivered.  Remembering a single timestamp was not enough: the batch
 * shifts as new events arrive, and the old check only recognised the
 * one record that happened to carry that exact timestamp -- everything
 * else was re-announced, so the list filled with copies every five
 * seconds.  Bounded well above the ten the query ever returns. */
#define SEEN_RECORDS_MAX 64
static GHashTable *seen_records = NULL;     /* record text -> TRUE      */
static GQueue      seen_order = G_QUEUE_INIT; /* oldest at the tail     */

/* [ parse_firewall_event ]
 * wevtutil text output from the Security log has the shape:
 *
 *   Date: 2026-10-06T10:58:39.1040000Z
 *   Event ID: 5157
 *   ...
 *   Description:
 *   The Windows Filtering Platform has blocked a connection.
 *
 *   Application Information:
 *       Process ID:     11964
 *       Application Name:  \device\harddiskvolume9\...brave.exe
 *
 *   Network Information:
 *       Direction:      Inbound
 *       Source Address:     fe80::...
 *       Source Port:        5353
 *       Destination Address: ff02::fb
 *       Destination Port:   5353
 *       Protocol:       17
 *
 * Pull the labelled fields out of it. */
static gboolean
parse_firewall_event (const gchar *text, FsHit *hit)
{
	gchar **lines = g_strsplit (text, "\r\n", -1);
	gboolean got_address = FALSE;
	gboolean is_blocked = FALSE;
	gchar *app_path = NULL;
	gchar *direction_str = NULL;

	/* Detect blocked vs permitted from the description. */
	if (strstr (text, "blocked a connection") != NULL)
		is_blocked = TRUE;

	for (gint i = 0; lines[i] != NULL; i++) {
		gchar *line = g_strstrip (lines[i]);
		gchar *colon;

		if (line == NULL || *line == '\0')
			continue;

		/* Timestamp line. */
		if (g_str_has_prefix (line, "Date:")) {
			hit->time = g_strdup (g_strstrip (line + 5));
			continue;
		}

		colon = strchr (line, ':');
		if (colon == NULL)
			continue;

		*colon = '\0';
		line = g_strstrip (line);

		{
			const gchar *value = g_strstrip (colon + 1);

			if (g_strcmp0 (line, "Protocol") == 0) {
				gchar *sp = strchr (value, ' ');
				if (sp != NULL)
					*sp = '\0';
				hit->protocol = g_strdup (value);
			} else if (g_strcmp0 (line, "Source Address") == 0) {
				hit->source = g_strdup (value);
			} else if (g_strcmp0 (line, "Destination Address") == 0) {
				hit->destination = g_strdup (value);
				got_address = TRUE;
			} else if (g_strcmp0 (line, "Destination Port") == 0) {
				/* DPT=: the port the original displayed -- the
				 * service port for inbound, the remote port for
				 * outbound.  The source port is an ephemeral
				 * client port and was never shown; putting it in
				 * "port" made every service lookup miss. */
				hit->port = g_strdup (value);
			} else if (g_strcmp0 (line, "Direction") == 0) {
				direction_str = g_strdup (value);
			} else if (g_strcmp0 (line, "Application Name") == 0) {
				app_path = g_strdup (value);
			}
		}
	}

	g_strfreev (lines);

	if (!got_address) {
		g_clear_pointer (&hit->time, g_free);
		g_clear_pointer (&hit->in, g_free);
		g_clear_pointer (&hit->out, g_free);
		g_clear_pointer (&hit->source, g_free);
		g_clear_pointer (&hit->destination, g_free);
		g_clear_pointer (&hit->port, g_free);
		g_clear_pointer (&hit->protocol, g_free);
		g_clear_pointer (&hit->service, g_free);
		g_clear_pointer (&direction_str, g_free);
		g_clear_pointer (&app_path, g_free);
		return FALSE;
	}

	/* Direction. */
	gboolean inbound;

	if (direction_str != NULL) {
		inbound = g_ascii_strncasecmp (direction_str, "Inbound", 7) == 0;
		g_free (direction_str);
	} else {
		inbound = TRUE;
	}
	hit->direction = g_strdup (inbound ? "in" : "out");

	/* The original's In/Out columns showed the interface a packet
	 * arrived on and left on (IN=, OUT=).  Event 5156/5157 carries no
	 * interface, so show the local side under In and the remote side
	 * under Out -- the same local/remote reading, direction aware. */
	if (inbound) {
		hit->in  = g_strdup (hit->destination ? hit->destination : "?");
		hit->out = g_strdup (hit->source ? hit->source : "?");
	} else {
		hit->in  = g_strdup (hit->source ? hit->source : "?");
		hit->out = g_strdup (hit->destination ? hit->destination : "?");
	}

	/* Protocol: numeric to name.  Replace in place -- assigning a new
	 * string over the old one leaked the numeric original on every
	 * event. */
	if (hit->protocol != NULL) {
		const gchar *name = NULL;

		if (g_strcmp0 (hit->protocol, "6") == 0)
			name = "TCP";
		else if (g_strcmp0 (hit->protocol, "17") == 0)
			name = "UDP";
		else if (g_strcmp0 (hit->protocol, "1") == 0)
			name = "ICMP";

		if (name != NULL) {
			g_free (hit->protocol);
			hit->protocol = g_strdup (name);
		}
	}

	/* Service name from port. */
	hit->service = fs_service_lookup_port (atoi (hit->port ? hit->port : "0"));
	if (hit->service == NULL)
		hit->service = g_strdup (_("Unknown"));

	/* Use application name as service if available (more specific). */
	if (app_path != NULL) {
		/* Extract the exe name from the full path. */
		const gchar *base = strrchr (app_path, '\\');
		base = base ? base + 1 : app_path;
		if (*base != '\0') {
			g_free (hit->service);
			hit->service = g_strdup (base);
		}
		g_free (app_path);
	}

	/* Mark blocked events with a visible marker. */
	if (is_blocked) {
		gchar *old = hit->service;
		hit->service = g_strdup_printf ("%s [BLOCKED]", old ? old : "?");
		g_free (old);
	}

	return TRUE;
}

/* [ run_wevtutil ]
 * One Security-log query, with both output streams captured.
 *
 * Goes through spawn_capture(), so the query opens no console window
 * and cannot hang the caller beyond the spawn budget.  On Windows the
 * raw process exit code lands in *exit_code, so 5 here really is
 * ERROR_ACCESS_DENIED. */
static gboolean
run_wevtutil (gchar **standard_output, gchar **standard_error,
              gint *exit_code, GError **error)
{
	gchar *args[] = {
		"wevtutil.exe", "qe", "Security",
		"/q:*[System[(EventID=5156 or EventID=5157)]]",
		"/c:10", "/rd:true", "/f:text", NULL
	};
	gint status = 0;

	if (standard_output != NULL)
		*standard_output = NULL;
	if (standard_error != NULL)
		*standard_error = NULL;

	if (!spawn_capture (args, SPAWN_TIMEOUT_WEVTUTIL_MS,
	                    standard_output, standard_error,
	                    &status, error))
		return FALSE;

	if (exit_code != NULL)
		*exit_code = status;

	return TRUE;
}

/* [ security_log_denied ]
 * The Security log is not readable without Administrator rights.
 * wevtutil says so twice over: exit code 5, and "Access is denied" on
 * stderr.  Either is enough. */
static gboolean
security_log_denied (gint exit_code, const gchar *stderr_text)
{
	return exit_code == ERROR_ACCESS_DENIED ||
	       (stderr_text != NULL &&
	        strstr (stderr_text, "Access is denied") != NULL);
}

/* [ free_hit_fields ]
 * "hit" is a stack local; fs_hit_free would g_free() the struct itself
 * and corrupt the heap.  Free only the strings parse allocated. */
static void
free_hit_fields (FsHit *hit)
{
	g_clear_pointer (&hit->time, g_free);
	g_clear_pointer (&hit->direction, g_free);
	g_clear_pointer (&hit->in, g_free);
	g_clear_pointer (&hit->out, g_free);
	g_clear_pointer (&hit->source, g_free);
	g_clear_pointer (&hit->destination, g_free);
	g_clear_pointer (&hit->port, g_free);
	g_clear_pointer (&hit->protocol, g_free);
	g_clear_pointer (&hit->service, g_free);
}

/* [ record_seen ] / [ remember_record ]
 * The de-duplication the poll loop runs every record through.  Kept as
 * named functions so tests can drive them directly: the old inline
 * "does the record text contain the last timestamp" check re-delivered
 * almost everything on every poll, and that bug was invisible without
 * feeding it two identical batches. */
static gboolean
record_seen (const gchar *record)
{
	return seen_records != NULL &&
	       g_hash_table_contains (seen_records, record);
}

static void
remember_record (const gchar *record)
{
	gchar *key;

	if (seen_records == NULL)
		seen_records = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                       g_free, NULL);

	/* Bounded: the query only ever returns SEEN_RECORDS_MAX-ish
	 * records, so the table holds a batch or two, never history. */
	while (g_queue_get_length (&seen_order) >= SEEN_RECORDS_MAX) {
		gchar *oldest = g_queue_pop_tail (&seen_order);

		g_hash_table_remove (seen_records, oldest);
	}

	key = g_strdup (record);
	g_queue_push_head (&seen_order, key);
	g_hash_table_insert (seen_records, key, GINT_TO_POINTER (1));
}

static void
forget_all_records (void)
{
	g_queue_clear (&seen_order);
	g_clear_pointer (&seen_records, g_hash_table_destroy);
}

/* [ split_firewall_records ]
 * Cuts wevtutil /f:text output into one record per event, at every
 * line starting with "Event[" -- wevtutil's own record marker.
 *
 * Blank lines are NOT record separators: a 5156/5157 record carries
 * them inside its Description block (headline sentence, then the
 * field sections).  The old blank-line split chopped every record in
 * two -- the header half has no addresses and was dropped, the field
 * half had no Date -- which on screen is an empty list no matter how
 * much traffic there is.  Output without the marker falls back to the
 * old split so an oddly shaped batch still yields something. */
static GPtrArray *
split_firewall_records (const gchar *output)
{
	GPtrArray *records = g_ptr_array_new_with_free_func (g_free);
	gchar **lines;
	GString *current = NULL;
	gboolean saw_marker = FALSE;

	if (output == NULL || *output == '\0')
		return records;

	lines = g_strsplit (output, "\r\n", -1);

	for (gint i = 0; lines[i] != NULL; i++) {
		if (g_str_has_prefix (lines[i], "Event[")) {
			saw_marker = TRUE;
			if (current != NULL)
				g_ptr_array_add (records,
				                 g_string_free (current, FALSE));
			current = g_string_new (NULL);

			/* The marker itself is the record's POSITION in this
			 * batch (Event[0] is the newest), and the positions move
			 * every time a new event arrives: an event that was
			 * Event[3] last poll is Event[4] this poll.  Keeping the
			 * line in the record text made every shifted record a
			 * "new" record to the de-duplication below, so one fresh
			 * event re-delivered the whole batch as duplicates --
			 * the same rows over and over in the list.  The content
			 * after the marker is identical for the same event on
			 * every poll, so that is what the record is made of. */
			continue;
		}

		if (current == NULL)
			current = g_string_new (NULL);  /* text before marker */

		g_string_append (current, lines[i]);
		g_string_append (current, "\r\n");
	}

	if (current != NULL)
		g_ptr_array_add (records, g_string_free (current, FALSE));

	g_strfreev (lines);

	if (!saw_marker) {
		gchar **chunks;
		GPtrArray *fallback = g_ptr_array_new_with_free_func (g_free);

		g_ptr_array_unref (records);
		records = fallback;

		chunks = g_strsplit (output, "\r\n\r\n", -1);
		for (gint i = 0; chunks[i] != NULL; i++) {
			if (*chunks[i] != '\0')
				g_ptr_array_add (records, g_strdup (chunks[i]));
		}
		g_strfreev (chunks);
	}

	return records;
}

/* [ poll_deliver ]
 * Runs on the GTK main loop (g_idle_add) -- the only place that may
 * touch the callback, the seen-set and GTK, since the worker thread
 * goes near none of them. */
static gboolean
poll_deliver (gpointer data)
{
	PollResult *result = data;
	GPtrArray *records;
	guint new_events = 0;

	/* Release the in-flight guard first: even a discarded result
	 * means the worker is done. */
	poll_in_flight = FALSE;

	/* firewalled_log_stop() bumped log_generation while this query
	 * ran: the batch belongs to a session that has ended. */
	if (result->generation != log_generation)
		goto out;

	if (result->exit_code != 0) {
		/* firewalled_log_start() checks this before it starts the
		 * timer, so reaching here means the right to read the log was
		 * lost after monitoring began.  Nothing is shown because the
		 * caller has no way to reach the UI; the alternative -- a
		 * message every five seconds -- would be worse. */
		goto out;
	}

	if (result->output == NULL)
		goto out;

	records = split_firewall_records (result->output);

	for (guint i = 0; i < records->len; i++) {
		const gchar *record = g_ptr_array_index (records, i);
		FsHit hit = { 0 };
		guint len = strlen (record);

		if (len < 40)
			continue;

		/* Drop anything an earlier poll already delivered: the query
		 * re-reads the latest ten events every time. */
		if (record_seen (record))
			continue;

		/* Remember before parsing: a record we cannot parse is still
		 * delivered again next poll, and would otherwise be parsed
		 * (and rejected) forever. */
		remember_record (record);

		if (!parse_firewall_event (record, &hit)) {
			free_hit_fields (&hit);
			continue;
		}

		if (log_callback != NULL)
			log_callback (&hit, log_user_data);

		new_events++;

		free_hit_fields (&hit);
	}

	g_ptr_array_unref (records);

out:
	(void) new_events;

	g_free (result->output);
	g_free (result->err_text);
	g_free (result);

	return G_SOURCE_REMOVE;
}

/* [ poll_worker ]
 * The worker thread itself: all it does is run wevtutil -- a plain
 * Win32 spawn through spawn_capture(), no COM, no GTK, no shared
 * state -- and post the result to the main loop. */
static gpointer
poll_worker (gpointer data)
{
	PollResult *result = data;

	run_wevtutil (&result->output, &result->err_text,
	              &result->exit_code, NULL);

	g_idle_add (poll_deliver, result);
	return NULL;
}

/* [ poll_events ]
 * The five second tick.  It only dispatches: a tick that finds the
 * previous query still running skips (poll_in_flight), and the query
 * itself happens off the main loop, so a slow or wedged child costs
 * the UI nothing. */
static gboolean
poll_events (gpointer data)
{
	PollResult *result;
	GThread *thread;

	(void) data;

	if (poll_in_flight)
		return G_SOURCE_CONTINUE;

	result = g_new0 (PollResult, 1);
	result->generation = log_generation;

	poll_in_flight = TRUE;

	thread = g_thread_try_new ("fs-poll", poll_worker, result, NULL);
	if (thread == NULL) {
		/* Out of memory: release the guard and retry next tick
		 * rather than pretend a query is running forever. */
		poll_in_flight = FALSE;
		g_free (result);
		return G_SOURCE_CONTINUE;
	}

	g_thread_unref (thread);
	return G_SOURCE_CONTINUE;
}

/* [ ensure_filtering_audit ]
 * Event 5156/5157 reach the Security log only when the "Filtering
 * Platform Connection" audit subcategory is enabled, and stock
 * Windows ships with it off.  wevtutil can read the log perfectly and
 * still return nothing, forever -- an empty list that reads as "a
 * firewall with no traffic".  The caller only gets here after the
 * read probe succeeded, i.e. while we hold Administrator rights, so
 * switch the subcategory on before promising to watch.
 *
 * auditpol is idempotent and a failure changes nothing: group policy
 * may lock the setting, and the subcategory name is English-only
 * (this build ships no translations), in which case monitoring still
 * runs against whatever the log holds. */
static void
ensure_filtering_audit (void)
{
	gchar *args[] = {
		"auditpol.exe", "/set",
		"/subcategory:Filtering Platform Connection",
		"/success:enable", "/failure:enable", NULL
	};
	gchar *out = NULL;
	gchar *err_text = NULL;

	if (spawn_capture (args, SPAWN_TIMEOUT_WEVTUTIL_MS,
	                    &out, &err_text, NULL, NULL)) {
		g_free (out);
		g_free (err_text);
	}
}

static gboolean
firewalled_log_start (FsLogFunc callback, gpointer user_data, GError **error)
{
	gchar *output = NULL;
	gchar *err_text = NULL;
	gint exit_code = 0;
	GError *local_error = NULL;

	if (log_source_id != 0)
		return TRUE;

	/* Probe once before promising to watch.  Without Administrator
	 * rights wevtutil can never return a single event, so starting the
	 * five second timer anyway would tell the user the opposite of the
	 * truth: monitoring would read as switched on while nothing could
	 * ever arrive. */
	if (!run_wevtutil (&output, &err_text, &exit_code, &local_error)) {
		/* spawn_capture()'s message already names the program and the
		 * Windows error ("Could not run wevtutil.exe: ..."). */
		if (local_error != NULL)
			g_propagate_error (error, local_error);
		else
			g_set_error_literal (
				error,
				g_quark_from_static_string ("fs-backend-windows"),
				0, "Could not run wevtutil.exe");
		g_clear_pointer (&output, g_free);
		g_clear_pointer (&err_text, g_free);
		return FALSE;
	}

	g_clear_pointer (&output, g_free);

	if (err_text != NULL)
		g_strstrip (err_text);

	if (exit_code != 0) {
		if (security_log_denied (exit_code, err_text))
			g_set_error_literal (
				error,
				g_quark_from_static_string ("fs-backend-windows"),
				exit_code,
				_("The Security log cannot be read without "
				  "Administrator rights.  Start StockFW as "
				  "Administrator to see incoming and "
				  "outbound traffic."));
		else
			g_set_error (
				error,
				g_quark_from_static_string ("fs-backend-windows"),
				exit_code,
				_("wevtutil.exe could not read the Security log "
				  "(exit %d): %s"),
				exit_code,
				(err_text != NULL && *err_text != '\0')
					? err_text : _("no detail"));

		g_clear_pointer (&err_text, g_free);
		return FALSE;
	}

	g_clear_pointer (&err_text, g_free);

	/* The log is readable; make sure Windows is recording into it. */
	ensure_filtering_audit ();

	log_callback = callback;
	log_user_data = user_data;

	/* wevtutil is a slow process to spawn, so poll every few seconds
	 * rather than trying to stream. */
	log_source_id = g_timeout_add_seconds (5, poll_events, NULL);

	return TRUE;
}

static void
firewalled_log_stop (void)
{
	if (log_source_id != 0) {
		g_source_remove (log_source_id);
		log_source_id = 0;
	}

	/* A query may still be running on its worker thread.  Bumping the
	 * generation makes poll_deliver drop its result instead of
	 * pushing events from a stopped session into the list; the
	 * in-flight guard it set is released when that delivery arrives,
	 * so the next session starts polling again on its own. */
	log_generation++;

	log_callback = NULL;
	log_user_data = NULL;
	forget_all_records ();
}

static gboolean
firewalled_log_active (void)
{
	return log_source_id != 0;
}

static gboolean
firewalled_dhcp_set_enabled (gboolean enabled, GError **error)
{
	return FALSE;
}

/* [ profile_from_index ]
 * Maps our profile id onto the Windows constant. */
static NET_FW_PROFILE_TYPE2
profile_from_index (gint profile)
{
	switch (profile) {
	case FS_PROFILE_DOMAIN:  return NET_FW_PROFILE2_DOMAIN;
	case FS_PROFILE_PRIVATE: return NET_FW_PROFILE2_PRIVATE;
	case FS_PROFILE_PUBLIC:  return NET_FW_PROFILE2_PUBLIC;
	default:                  return NET_FW_PROFILE2_DOMAIN;
	}
}

/* [ firewalled_get_profile_enabled ]
 * Reads one profile's state.  Returns FALSE when the profile id is
 * unknown or the COM call fails. */
static gboolean
firewalled_get_profile_enabled (gint profile, gboolean *enabled)
{
	INetFwPolicy2 *policy = NULL;
	HRESULT hr;
	VARIANT_BOOL on = VARIANT_FALSE;
	NET_FW_PROFILE_TYPE2 type;

	if (enabled != NULL)
		*enabled = FALSE;

	if (profile < 0 || profile >= FS_PROFILE_COUNT)
		return FALSE;

	type = profile_from_index (profile);

	CoInitializeEx (NULL, COINIT_APARTMENTTHREADED);

	hr = CoCreateInstance (&FS_CLSID_NetFwPolicy2, NULL, CLSCTX_ALL,
	                       &FS_IID_INetFwPolicy2, (void **) &policy);

	if (FAILED (hr) || policy == NULL) {
		CoUninitialize ();
		return FALSE;
	}

	hr = policy->lpVtbl->get_FirewallEnabled (policy, type, &on);

	policy->lpVtbl->Release (policy);
	CoUninitialize ();

	if (FAILED (hr))
		return FALSE;

	if (enabled != NULL)
		*enabled = (on != VARIANT_FALSE);

	return TRUE;
}

/* [ firewalled_set_profile_enabled ]
 * Switches one profile.  Changing the firewall state needs elevation,
 * so a plain session gets a clear error rather than a silent failure. */
static gboolean
firewalled_set_profile_enabled (gint profile, gboolean enabled,
                                GError **error)
{
	INetFwPolicy2 *policy = NULL;
	HRESULT hr;
	NET_FW_PROFILE_TYPE2 type;

	if (profile < 0 || profile >= FS_PROFILE_COUNT) {
		g_set_error_literal (error,
		                     g_quark_from_static_string ("fs-backend-windows"),
		                     0, "Unknown firewall profile.");
		return FALSE;
	}

	type = profile_from_index (profile);

	CoInitializeEx (NULL, COINIT_APARTMENTTHREADED);

	hr = CoCreateInstance (&FS_CLSID_NetFwPolicy2, NULL, CLSCTX_ALL,
	                       &FS_IID_INetFwPolicy2, (void **) &policy);

	if (FAILED (hr) || policy == NULL) {
		g_set_error (error,
		             g_quark_from_static_string ("fs-backend-windows"),
		             (int) hr,
		             "Could not connect to the Windows Firewall service. "
		             "Check that the MpsSvc service is running.");
		CoUninitialize ();
		return FALSE;
	}

	hr = policy->lpVtbl->put_FirewallEnabled (policy, type,
	                                          enabled ? VARIANT_TRUE
	                                                  : VARIANT_FALSE);

	policy->lpVtbl->Release (policy);
	CoUninitialize ();

	if (FAILED (hr)) {
		g_set_error (error,
		             g_quark_from_static_string ("fs-backend-windows"),
		             (int) hr,
		             "Changing the firewall state requires "
		             "administrator privileges. Restart StockFW "
		             "as an administrator and try again.");
		return FALSE;
	}

	return TRUE;
}

/* Designated initialisers, not positional: adding a field to FsBackend
 * then leaves every backend correct instead of silently shifting every
 * entry after the insertion point. */
static const FsBackend windows_backend = {
	.name                  = "windows",
	.display_name          = "Windows Defender Firewall",
	.uses_settings         = FALSE,   /* builds rules from the policy alone */
	.available             = firewalled_com_available,
	.get_state             = firewalled_get_state,
	.start                 = firewalled_start,
	.stop                  = firewalled_stop,
	.reload                = firewalled_reload,
	.apply_rules           = firewalled_apply_rules,
	.clear_rules           = firewalled_clear_rules,
	.list_interfaces       = firewalled_list_interfaces,
	.list_interface_stats  = firewalled_list_interface_stats,
	.list_connections      = firewalled_list_connections,
	.log_start             = firewalled_log_start,
	.log_stop              = firewalled_log_stop,
	.log_active            = firewalled_log_active,
	.dhcp_set_enabled      = firewalled_dhcp_set_enabled,
	.get_profile_enabled   = firewalled_get_profile_enabled,
	.set_profile_enabled   = firewalled_set_profile_enabled,
	.trust_signature       = fs_trust_win_signature
};

const FsBackend *
fs_backend (void)
{
	return &windows_backend;
}

const gchar *
fs_error_domain (void)
{
	return "fs-backend-windows";
}

/* The Windows backend builds rules straight from the policy and needs
 * no generator settings.  This exists so the UI can call the same hook
 * on either platform. */
void
fs_backend_set_context (FsPolicy *policy, FsSettings *settings)
{
	(void) policy;
	(void) settings;
}
