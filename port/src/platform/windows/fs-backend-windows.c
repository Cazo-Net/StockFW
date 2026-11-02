/*---[ fs-backend-windows.c ]-------------------------------------------
 * Windows firewall backend (milestone M4).
 *
 * Implements the FsBackend vtable against the Windows Firewall with
 * Advanced Security COM API (HNetCfg.FwPolicy2):
 *
 *   INetFwPolicy2    profile enumeration and global state, and the
 *                    profiles in force (CurrentProfileTypes)
 *   INetworkListManager  the connected networks, their names and
 *                    categories, for the Overview (1.0.7)
 *   INetFwRules      rule listing
 *   INetFwRule       creating / editing allow and block rules
 *   INetFwRules/INetFwRule  the threat-intel blocklist rules (1.0.7
 *                    Round 3), written and read back in-process
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
#include <netlistmgr.h> /* INetworkListManager: the connected networks */
#include <tlhelp32.h>   /* CreateToolhelp32Snapshot: process enumeration */

#include <stdio.h>   /* _snwprintf */

#include <gio/gio.h>   /* G_IO_ERROR: the threat-intel slots' domain */

#include "core/fs-backend.h"
#include "core/fs-intelset.h"
#include "core/fs-intelwin.h"
#include "core/fs-netplace.h"
#include "core/fs-fwrule.h"
#include "core/fs-settings-plan.h"
#include "core/fs-service.h"
#include "core/fs-i18n.h"
#include "core/fs-util.h"
#include "netfw-compat.h"

/* Linked through CMake: ole32, oleaut32, iphlpapi, ws2_32 */

/* The policy and the settings the apply paths read.  Set through
 * fs_backend_set_context(); the settings feed the settings-plan rules
 * that every whole-set apply re-establishes (see the plan header for
 * the mapping and why these rules share the "StockFW" prefix). */
static FsPolicy   *ctx_policy   = NULL;
static FsSettings *ctx_settings = NULL;

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
 *
 * 1.0.7 Round 3: the first point above was a misreading.  Microsoft
 * documents INetFwRules as Add(INetFwRule *), Remove(BSTR name) and
 * Item(BSTR name, INetFwRule **), exactly as MinGW-w64 declares it;
 * the "corrected" vtable netfw-compat.h used to carry had the
 * signatures of a different interface and was never used.  The
 * threat-intel slots at the end of this file drive INetFwRules and
 * INetFwRule through MinGW's declarations, with every vtable slot they
 * call pinned to its documented position at compile time
 * (netfw-compat.h), so a header that disagreed would stop the build
 * instead of crashing the process.  The policy rules stay on netsh
 * here; moving them is a separate change.
 * ------------------------------------------------------------------ */

/* [ netsh_safe_name ]
 * netsh rejects rule names containing ':' , parentheses and slashes,
 * which the display names generated for the UI do contain.  The
 * spelling lives in core (fs_fwrule_netsh_name), so the argv the
 * tests check and the names this file creates, lists and deletes can
 * never drift apart.
 */
static gchar *
netsh_safe_name (const gchar *name)
{
	return fs_fwrule_netsh_name (name);
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
 * the offset sits at the end after the wait -- rewind first.
 * *truncated is set when the output was longer than the cap and was
 * cut: a caller must never take a cut-off output as complete. */
#define READ_OUTPUT_CAP (16 * 1024 * 1024)

static gchar *
read_handle_output (HANDLE handle, gboolean *truncated)
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
	 * must not get to allocate gigabytes of heap for us.  What is cut
	 * is reported, never passed off as the whole output (review W3:
	 * `netsh show rule name=all' printed every address of every
	 * blocklist rule and could run past the cap). */
	if (size.QuadPart > READ_OUTPUT_CAP) {
		size.QuadPart = READ_OUTPUT_CAP;
		*truncated = TRUE;
	}

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
	gboolean cut = FALSE;

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

	out_text = read_handle_output (out_handle, &cut);
	err_text = read_handle_output (err_handle, &cut);
	if (cut) {
		/* The child ran, but what it said cannot be used whole. */
		if (error != NULL)
			g_set_error (error, quark, 0,
			             "The output of %s was longer than %d MiB and "
			             "was cut off, so it was not used",
			             argv[0], READ_OUTPUT_CAP / (1024 * 1024));
		wait_result = WAIT_FAILED;
		goto out;
	}

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
 * that onto our own result so the UI can explain what to do.  Our own
 * rewritten messages match too ("... requires administrator
 * privileges"): apply_rules classifies failures by the stored error
 * message, and without that phrase the elevation verdict was silently
 * reported as a plain failure. */
static gboolean
netsh_needs_elevation (const gchar *output)
{
	return (output != NULL &&
	        (strstr (output, "requested operation requires elevation") != NULL ||
	         strstr (output, "Access is denied") != NULL ||
	         strstr (output, "requires administrator privileges") != NULL));
}

/* [ netsh_add_rule ]
 * Creates one rule.  Returns FALSE and sets error on failure.
 *
 * The argv comes from core (fs_fwrule_netsh_args), where the tests
 * check it on every platform.  spawn_capture() passes it straight to
 * CreateProcess with no shell parsing, which is why no argument
 * carries quote characters.  1.0.6 built it here and, because netsh
 * refuses ports with protocol=any, dropped the port of every rule
 * whose protocol was "any" -- most services -- so the rule matched
 * all traffic in its direction.  core now refuses to build such an
 * argv at all, and a refused rule is a failed rule, never a wider
 * one. */
static gboolean
netsh_add_rule (const FsFwRule *rule, GError **error)
{
	gchar **args;
	gchar *output = NULL;
	gint status = 0;
	gboolean ok = FALSE;

	args = fs_fwrule_netsh_args (rule);

	if (args == NULL) {
		g_set_error (error,
		             g_quark_from_static_string ("fs-backend-windows"),
		             0, "The rule \"%s\" was not created: a rule "
		             "with ports has to be TCP or UDP, with a valid "
		             "port list.",
		             (rule != NULL && rule->name != NULL)
		             ? rule->name : "(unnamed)");
		return FALSE;
	}

	if (!run_netsh (args, error, &status, &output))
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
	g_strfreev (args);

	return ok;
}

/* [ setting_profiles_arg ]
 * The plan's portable profile mask as one netsh argument. */
static gchar *
setting_profiles_arg (guint mask)
{
	static const guint bits[] = {
		FS_FWP_PROFILE_DOMAIN, FS_FWP_PROFILE_PRIVATE,
		FS_FWP_PROFILE_PUBLIC
	};
	GString *out = g_string_new ("profile=");
	gboolean first = TRUE;

	if (mask == 0) {
		g_string_append (out, "any");
	} else {
		for (guint i = 0; i < G_N_ELEMENTS (bits); i++) {
			const gchar *name;

			if ((mask & bits[i]) == 0)
				continue;

			name = fs_settings_plan_profile_name (bits[i]);

			if (!first)
				g_string_append_c (out, ',');
			g_string_append (out, name);
			first = FALSE;
		}

		/* A mask with no known bit must not become "profile=" with
		 * an empty value; netsh would reject the whole rule. */
		if (first)
			g_string_append (out, "any");
	}

	return g_string_free (out, FALSE);
}

/* [ netsh_add_setting_rule ]
 * Creates one rule from the settings plan.  Same spawn and
 * classification path as netsh_add_rule; the differences are the
 * plan's fields -- profile scoping, an ICMP type/code pair, and a
 * comma-joined remote list.  The error text stays separate from the
 * policy path's because it names the setting, not the policy rule. */
static gboolean
netsh_add_setting_rule (const FsSettingRule *rule, GError **error)
{
	GPtrArray *args;
	gchar *output = NULL;
	gint status = 0;
	gboolean ok = FALSE;

	args = g_ptr_array_new_with_free_func (g_free);
	g_ptr_array_add (args, g_strdup ("netsh.exe"));
	g_ptr_array_add (args, g_strdup ("advfirewall"));
	g_ptr_array_add (args, g_strdup ("firewall"));
	g_ptr_array_add (args, g_strdup ("add"));
	g_ptr_array_add (args, g_strdup ("rule"));

	g_ptr_array_add (args, g_strdup_printf ("name=%s", rule->name));
	g_ptr_array_add (args, g_strdup ("dir=in"));
	g_ptr_array_add (args,
	                 g_strdup_printf ("action=%s",
	                                  rule->allow ? "allow" : "block"));
	g_ptr_array_add (args, g_strdup ("enable=yes"));
	g_ptr_array_add (args, setting_profiles_arg (rule->profiles));

	if (rule->proto == FS_SETPLAN_PROTO_ICMP) {
		/* netsh's grammar is icmpv4:type,code with the literal
		 * "any" for a wildcard; "*" is not accepted (verified by
		 * probe: the parser rejects it with "A specified protocol
		 * value is not valid"). */
		if (rule->icmp != NULL)
			g_ptr_array_add (args,
			                 g_strdup_printf ("protocol=icmpv4:%s",
			                                  rule->icmp));
		else
			g_ptr_array_add (args, g_strdup ("protocol=icmpv4"));
	} else if (rule->proto == FS_SETPLAN_PROTO_UDP) {
		g_ptr_array_add (args, g_strdup ("protocol=udp"));
		g_ptr_array_add (args,
		                 g_strdup_printf ("localport=%u", rule->port));
	}
	/* FS_SETPLAN_PROTO_ANY: netsh's protocol default is already
	 * "any", and a port field would be rejected alongside it. */

	if (rule->remote != NULL)
		g_ptr_array_add (args,
		                 g_strdup_printf ("remoteip=%s", rule->remote));

	g_ptr_array_add (args, NULL);

	if (!run_netsh ((gchar **) args->pdata, error, &status, &output))
		goto out;

	if (status == 0) {
		ok = TRUE;
		goto out;
	}

	if (netsh_needs_elevation (output)) {
		g_set_error_literal (error,
		                     g_quark_from_static_string (
			                     "fs-backend-windows"),
		                     0,
		                     "Creating firewall rules requires "
		                     "administrator privileges. Restart "
		                     "StockFW as an administrator and try "
		                     "again.");
	} else {
		g_set_error (error,
		             g_quark_from_static_string ("fs-backend-windows"),
		             status,
		             "netsh could not create the rule for the setting "
		             "\"%s\": %s",
		             rule->name ? rule->name : "(unnamed)",
		             output ? g_strstrip (output) : "no output");
	}

out:
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

static gboolean com_list_our_names (GHashTable **sink, GError **error);

/* [ netsh_list_our_names ]
 * One enumeration pass over every rule, keeping the names that are
 * ours.  Returns FS_APPLY_OK with *sink set (an empty table is a valid
 * result: none of ours exist), or a failure verdict with *sink NULL.
 *
 * The list comes from INetFwRules in this process (names only), not
 * from `netsh advfirewall firewall show rule name=all' (review W3):
 * netsh prints every address of every rule, and the threat-intel rules
 * can hold some 300,000 of them, which ran past the 16 MiB output cap
 * and the 30 s netsh budget, so names printed after the cut were never
 * seen and the clear "verified" zero with stale rules still active.
 * netsh is only the fallback when COM itself cannot be used, and a
 * cut-off output is now an error there (spawn_capture). */
static FsApplyResult
netsh_list_our_names (GHashTable **sink, GError **error)
{
	gchar *output = NULL;
	gint status = 0;

	*sink = NULL;

	if (com_list_our_names (sink, NULL))
		return FS_APPLY_OK;

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

	*sink = fs_netsh_rule_names_extract (output);
	g_free (output);

	return FS_APPLY_OK;
}

/* [ firewalled_clear_rules ]
 * Removes the rules this application installed on a previous apply.
 *
 * Deliberately NOT "name=all": that would delete every rule on the
 * machine, including ones the user or Windows created.  Instead we ask
 * netsh for the current rule list, keep the names that match our own
 * prefix, and delete exactly those -- and then ASK AGAIN.
 *
 * The re-ask is the P6 fix for two silent failures found in the field:
 * the parser used to expect CSV while netsh prints text ("Rule Name:
 * <name>"), so zero names matched and every full apply piled another
 * copy of each rule on top (479 rules, 28 copies of one name); and a
 * delete that leaves a same-named copy behind used to count as done.
 * The loop ends on a VERIFIED zero, not an assumed one.
 *
 * Returns FS_APPLY_OK only when a fresh enumeration finds none of our
 * rules left. */
static FsApplyResult
firewalled_clear_rules (GError **error)
{
	guint pass;

	/* Bounded: every pass either finds nothing (done), or deletes
	 * every name it found, so a healthy machine finishes in two. */
	for (pass = 0; pass < 5; pass++) {
		GHashTable *ours;
		GList *names, *iter;
		FsApplyResult listed;

		listed = netsh_list_our_names (&ours, error);
		if (listed != FS_APPLY_OK)
			return listed;

		if (g_hash_table_size (ours) == 0) {
			g_hash_table_destroy (ours);
			return FS_APPLY_OK;   /* verified: none of ours remain */
		}

		names = g_hash_table_get_keys (ours);

		for (iter = names; iter != NULL; iter = iter->next) {
			GError *local = NULL;

			/* A name netsh cannot find is a clean no-op; the next
			 * enumeration is what decides whether it worked.  Only
			 * a missing elevation ends the clear at once: the list
			 * now comes from COM, which a standard user may read,
			 * so the delete is where that shows (review W3). */
			netsh_delete_one ((const gchar *) iter->data, &local);
			if (local != NULL &&
			    netsh_needs_elevation (local->message)) {
				g_propagate_error (error, local);
				g_list_free (names);
				g_hash_table_destroy (ours);
				return FS_APPLY_NO_PRIVILEGE;
			}
			g_clear_error (&local);
		}

		g_list_free (names);
		g_hash_table_destroy (ours);
	}

	/* Five delete+verify passes and rules of ours are still there:
	 * say so instead of letting the caller believe the clear. */
	if (error != NULL)
		g_set_error_literal (error,
		                     g_quark_from_static_string (
			                     "fs-backend-windows"),
		                     0,
		                     "Some of StockFW's previous firewall "
		                     "rules could not be removed; stale "
		                     "rules may still be active.");

	return FS_APPLY_PARTIAL;
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
	FsApplyResult clear_result;
	GPtrArray *refused = NULL;
	gchar *refusal = NULL;

	if (policy == NULL)
		return FS_APPLY_FAILED;

	/* A refused BLOCK row stops the apply before anything is
	 * cleared.  This function replaces the whole set, so carrying on
	 * would delete the block that is in force now and put nothing in
	 * its place: fail-open, with only the rollback (when there is a
	 * journal at all) to close the hole again.  The Linux generator
	 * refuses the whole script for a deny it cannot write in the same
	 * way.  A refused allow is different -- leaving it out keeps a
	 * hole closed -- so those are reported below and the rest
	 * applies. */
	refusal = fs_fwrule_block_refusals (policy);
	if (refusal != NULL) {
		g_set_error (error,
		             g_quark_from_static_string ("fs-backend-windows"),
		             0, "The firewall was not changed: a block rule "
		             "could not be applied as written, and applying "
		             "the rest would have removed it.\n%s", refusal);
		g_free (refusal);
		return FS_APPLY_FAILED;
	}

	rules = fs_fwrule_from_policy_checked (policy, &refused);

	/* Rows the translation refused (a port that does not parse) have
	 * no rule to create.  Each one counts as a failed rule, so the
	 * verdict can never be "Rules applied" for a policy that is not
	 * all in force, and their reasons are what the dialog shows:
	 * the user can fix those, unlike a netsh exit code. */
	if (refused->len > 0) {
		GString *why = g_string_new (NULL);

		for (guint i = 0; i < refused->len; i++) {
			if (why->len > 0)
				g_string_append_c (why, '\n');
			g_string_append (why, g_ptr_array_index (refused, i));
		}

		failed += refused->len;
		refusal = g_string_free (why, FALSE);
	}

	g_ptr_array_unref (refused);

	/* Drop the previous set first so applying twice does not
	 * accumulate duplicates.  P6: the clear verifies its own work by
	 * re-enumerating, and a failure here is not swallowed -- the
	 * verdict below degrades to PARTIAL so the caller never hears
	 * "Rules applied" while stale copies are still active. */
	clear_result = firewalled_clear_rules (&first_error);

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

	/* P5: the Preferences settings this backend honors (the ICMP
	 * allow-list, broadcast blocks, reserved-source blocks) become
	 * rules of their own.  firewalled_clear_rules() above already
	 * retired the previous copies -- they carry the same "StockFW"
	 * prefix the rule lifecycle owns -- and the apply gate is still
	 * the only path into this function, so settings cannot reach the
	 * firewall around it.  A settings failure counts exactly like a
	 * policy failure: partial is partial. */
	if (ctx_settings != NULL) {
		FsSettingsPlan *plan = fs_settings_plan_new (ctx_settings);

		for (guint i = 0; i < plan->rules->len; i++) {
			const FsSettingRule *srule =
				g_ptr_array_index (plan->rules, i);
			GError *local = NULL;

			if (netsh_add_setting_rule (srule, &local))
				applied++;
			else {
				failed++;

				if (first_error == NULL && local != NULL)
					first_error = g_error_copy (local);

				g_clear_error (&local);
			}
		}

		fs_settings_plan_free (plan);
	}

	if (failed > 0 && applied == 0) {
		/* Decide the verdict first: g_propagate_error() hands
		 * ownership of first_error to *error (and g_clear_error()
		 * would free it), so reading first_error->message afterwards
		 * would be a use-after-free. */
		gboolean needs_elevation =
			netsh_needs_elevation (first_error != NULL
			                       ? first_error->message : NULL);

		if (refusal != NULL) {
			/* The refused rows first: they are why nothing
			 * could be created as written. */
			g_set_error (error,
			             g_quark_from_static_string (
				             "fs-backend-windows"),
			             0, "%s%s%s", refusal,
			             first_error != NULL ? "\n" : "",
			             first_error != NULL
			             ? first_error->message : "");
			g_clear_error (&first_error);
		} else if (error != NULL && first_error != NULL)
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

		g_free (refusal);
		return needs_elevation ? FS_APPLY_NO_PRIVILEGE : FS_APPLY_FAILED;
	}

	if (failed > 0) {
		g_set_error (error, g_quark_from_static_string ("fs-backend-windows"),
		             (int) failed, "%u of %u rules could not be created%s%s",
		             failed, applied + failed,
		             refusal != NULL ? ":\n" : "",
		             refusal != NULL ? refusal : "");
		/* The dialog gets the count; the first concrete reason is
		 * still owned here and must not leak. */
		g_clear_error (&first_error);
		g_free (refusal);
		return FS_APPLY_PARTIAL;
	}

	g_free (refusal);

	/* P6: nothing to add failed, but the clear could not verify that
	 * the previous set is gone -- the verdict must still say so, with
	 * the reason the clear recorded in first_error. */
	if (clear_result != FS_APPLY_OK) {
		if (error != NULL && first_error != NULL)
			g_propagate_error (error, first_error);
		else
			g_clear_error (&first_error);

		return clear_result;
	}

	return FS_APPLY_OK;
}

/* [ firewalled_apply_delta ]
 * The narrow path: delete only the names that are going away, restore
 * the kept rules whose names those deletions would take with them, and
 * create the new rules.  Rules present in both policy states are never
 * touched -- applying a one-rule edit does not clear and recreate the
 * whole set, and there is no window where the firewall carries none
 * of our rules at all.  The verdict shape matches
 * firewalled_apply_rules: all-or-nothing failures report the first
 * reason (with elevation recognised), anything in between is PARTIAL
 * and gets rolled back by the apply gate. */
static FsApplyResult
firewalled_apply_delta (const GList *remove, const GList *add,
                        const GList *repair, GError **error)
{
	const GList *iter;
	guint created = 0;
	guint failed = 0;
	GError *first_error = NULL;

	if (remove == NULL && add == NULL && repair == NULL)
		return FS_APPLY_OK;

	/* 1. Delete the names that are going away.  A name netsh cannot
	 *    find is a clean exit: the absent rule is the state we
	 *    wanted. */
	for (iter = remove; iter != NULL; iter = iter->next) {
		GError *local = NULL;

		if (netsh_delete_one ((const gchar *) iter->data, &local))
			continue;

		failed++;

		if (first_error == NULL && local != NULL)
			first_error = g_error_copy (local);

		g_clear_error (&local);
	}

	/* 1b. P6: verify the deletions.  A name can survive its own
	 *     delete (same-named copies stack up), and an unverified
	 *     remove is how 22 copies of one block rule stayed active
	 *     after the policy row was gone.  One re-enumeration: what is
	 *     still present gets deleted again, and a delete that fails
	 *     twice is reported instead of believed. */
	if (remove != NULL) {
		GHashTable *ours = NULL;

		if (netsh_list_our_names (&ours, NULL) == FS_APPLY_OK &&
		    ours != NULL) {
			GList *leftover = NULL;
			const GList *r;

			/* netsh lists the netsh spelling of each name
			 * ("StockFW- Allow SSH -inbound-"), so that is the
			 * spelling to look up; comparing the display name
			 * never found a survivor. */
			for (r = remove; r != NULL; r = r->next) {
				gchar *listed = netsh_safe_name (r->data);

				if (g_hash_table_contains (ours, listed))
					leftover = g_list_prepend (leftover,
					                            (gpointer) r->data);
				g_free (listed);
			}

			for (r = leftover; r != NULL; r = r->next) {
				GError *local = NULL;

				if (!netsh_delete_one ((const gchar *) r->data,
				                       &local)) {
					failed++;

					if (first_error == NULL && local != NULL)
						first_error = g_error_copy (local);
				}

				g_clear_error (&local);
			}

			g_list_free (leftover);
		}

		if (ours != NULL)
			g_hash_table_destroy (ours);
	}

	/* 2. Re-create kept rules whose names the deletions took. */
	for (iter = repair; iter != NULL; iter = iter->next) {
		GError *local = NULL;

		if (netsh_add_rule ((const FsFwRule *) iter->data, &local)) {
			created++;
			continue;
		}

		failed++;

		if (first_error == NULL && local != NULL)
			first_error = g_error_copy (local);

		g_clear_error (&local);
	}

	/* 3. Create the new rules. */
	for (iter = add; iter != NULL; iter = iter->next) {
		GError *local = NULL;

		if (netsh_add_rule ((const FsFwRule *) iter->data, &local)) {
			created++;
			continue;
		}

		failed++;

		if (first_error == NULL && local != NULL)
			first_error = g_error_copy (local);

		g_clear_error (&local);
	}

	if (failed > 0 && created == 0) {
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
					"None of the required rule changes "
					"could be made.");

			g_clear_error (&first_error);
		}

		return needs_elevation ? FS_APPLY_NO_PRIVILEGE : FS_APPLY_FAILED;
	}

	if (failed > 0) {
		g_set_error (error, g_quark_from_static_string ("fs-backend-windows"),
		             (int) failed, "%u of %u rule changes failed",
		             failed, created + failed);
		g_clear_error (&first_error);
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

/* [ adapter_kind ]
 * The Type column for one row.  IANA type 6 covers every adapter that
 * speaks Ethernet framing, which includes Hyper-V's vEthernet, the
 * VirtualBox and VMware host-only NICs and most VPN clients' TAP
 * adapters.  Windows marks which of those has a physical device behind
 * it (HardwareInterface), and that is what Linux's interface_kind()
 * asks of sysfs too, so a software adapter reads "Virtual" on both and
 * the Overview can tuck it away by the same rule.  Tunnel and loopback
 * keep their own names. */
static const gchar *
adapter_kind (const MIB_IF_ROW2 *row)
{
	const gchar *name = iface_type_name (row->Type);

	if (row->Type == 24 || row->Type == 131)
		return name;
	if (!row->InterfaceAndOperStatusFlags.HardwareInterface)
		return "Virtual";
	return name;
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

		/* NDIS filter modules (the WFP and QoS lightweight filters)
		 * are listed as interfaces of their own, stacked on a real
		 * adapter and counting the same octets.  Listing them would
		 * show "Ethernet-WFP Native MAC Layer LightWeight Filter-0000"
		 * beside "Ethernet" and add that adapter's traffic twice. */
		if (row->InterfaceAndOperStatusFlags.FilterInterface)
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

		stat->kind     = g_strdup (adapter_kind (row));
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

/* [ firewalled_list_processes ]
 * Full image paths of every process the snapshot shows, deduplicated
 * case-insensitively (Windows paths do not distinguish case).  No
 * elevation: PROCESS_QUERY_LIMITED_INFORMATION answers for user
 * processes and fails quietly for the protected few, whose rows are
 * simply absent -- a scan reports what it could actually read. */
static GList *
firewalled_list_processes (void)
{
	HANDLE snapshot;
	PROCESSENTRY32 entry;
	GList *paths = NULL;
	GHashTable *seen;

	snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return NULL;

	seen = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
	                              NULL);

	entry.dwSize = sizeof (entry);
	if (Process32First (snapshot, &entry)) {
		do {
			HANDLE process;
			gchar path[MAX_PATH];
			DWORD length = MAX_PATH;

			if (entry.th32ProcessID == 0 ||
			    entry.th32ProcessID == 4)
				continue;   /* Idle and System have no image */

			process = OpenProcess (
				PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
				entry.th32ProcessID);
			if (process == NULL)
				continue;

			if (QueryFullProcessImageNameA (process, 0, path,
			                                &length) &&
			    !g_hash_table_contains (seen, path)) {
				g_hash_table_insert (seen, g_ascii_strdown (
				                             path, -1),
				                      NULL);
				paths = g_list_prepend (paths,
				                         g_strdup (path));
			}

			CloseHandle (process);
		} while (Process32Next (snapshot, &entry));
	}

	CloseHandle (snapshot);
	g_hash_table_unref (seen);

	return g_list_reverse (paths);
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

/* ---------------------------------------------------------------------
 * Where this computer is connected (1.0.7): the Overview's subtitle,
 * the "In use" marks and the "profile in use is off" verdict.
 *
 * Two in-process COM reads, no child process:
 *
 *   INetFwPolicy2::get_CurrentProfileTypes   the profiles in force, as
 *       the firewall itself decides them (a bit per profile: two
 *       adapters on networks of different kinds give two bits);
 *   INetworkListManager::GetNetworks         the connected networks:
 *       name, category (Public / Private / DomainAuthenticated, which
 *       is what picks the profile), connectivity, and through each
 *       connection's adapter GUID, the medium.
 *
 * The same facts are what PowerShell's Get-NetFirewallSetting
 * -PolicyStore ActiveStore (ActiveProfile) and Get-NetConnectionProfile
 * print, but asking COM costs milliseconds and opens no window, where
 * powershell.exe costs a process start per poll and, through GLib's
 * spawn, a console window (see spawn_capture() above for that history).
 *
 * The network's name is the network *profile* name.  Windows names a
 * Wi-Fi profile after its SSID, so this is the SSID unless the user
 * renamed it.  The SSID proper would come from the Native Wifi API
 * (WlanQueryInterface, wlan_intf_opcode_current_connection), which on
 * current Windows 11 needs the user's location consent and answers
 * ERROR_ACCESS_DENIED without it; the network list has no such gate.
 * ------------------------------------------------------------------ */

/* Documented values (netlistmgr.h declares them only with INITGUID;
 * defined locally for the reason netfw-compat.h gives for NetFwPolicy2). */
static const GUID FS_CLSID_NetworkListManager =
	{ 0xdcb00c01, 0x570f, 0x4a9b,
	  { 0x8d, 0x69, 0x19, 0x9f, 0xdb, 0xa5, 0x72, 0x3b } };

static const GUID FS_IID_INetworkListManager =
	{ 0xdcb00000, 0x570f, 0x4a9b,
	  { 0x8d, 0x69, 0x19, 0x9f, 0xdb, 0xa5, 0x72, 0x3b } };

/* [ profile_from_category ]
 * A network's category is what selects its firewall profile. */
static gint
profile_from_category (NLM_NETWORK_CATEGORY category)
{
	switch (category) {
	case NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED: return FS_PROFILE_DOMAIN;
	case NLM_NETWORK_CATEGORY_PRIVATE:              return FS_PROFILE_PRIVATE;
	case NLM_NETWORK_CATEGORY_PUBLIC:               return FS_PROFILE_PUBLIC;
	default:                                        return -1;
	}
}

/* [ profiles_from_types ]
 * CurrentProfileTypes' NET_FW_PROFILE2_* bits as FS_PROFILE_BIT()s. */
static guint
profiles_from_types (LONG types)
{
	guint in_use = 0;

	if (types & NET_FW_PROFILE2_DOMAIN)
		in_use |= FS_PROFILE_BIT (FS_PROFILE_DOMAIN);
	if (types & NET_FW_PROFILE2_PRIVATE)
		in_use |= FS_PROFILE_BIT (FS_PROFILE_PRIVATE);
	if (types & NET_FW_PROFILE2_PUBLIC)
		in_use |= FS_PROFILE_BIT (FS_PROFILE_PUBLIC);
	return in_use;
}

/* [ medium_of_adapter ]
 * "Wi-Fi", "Ethernet", "Virtual", ... for one adapter GUID, by the same
 * rule as the adapters panel; NULL when the adapter cannot be read. */
static const gchar *
medium_of_adapter (const GUID *adapter)
{
	MIB_IF_ROW2 row;
	NET_LUID luid;

	if (ConvertInterfaceGuidToLuid (adapter, &luid) != NO_ERROR)
		return NULL;

	memset (&row, 0, sizeof row);
	row.InterfaceLuid = luid;
	if (GetIfEntry2 (&row) != NO_ERROR)
		return NULL;

	/* Windows' own word for IEEE 802.11, physical or not. */
	if (row.Type == 71)
		return "Wi-Fi";
	return adapter_kind (&row);
}

/* [ add_network ]
 * One INetwork into the place.  Every read may fail on its own; what
 * failed is left unknown rather than guessed. */
static void
add_network (FsNetworkPlace *place, INetwork *net)
{
	BSTR name = NULL;
	gchar *utf8 = NULL;
	NLM_NETWORK_CATEGORY category;
	NLM_CONNECTIVITY connectivity = NLM_CONNECTIVITY_DISCONNECTED;
	IEnumNetworkConnections *conns = NULL;
	const gchar *medium = NULL;
	gint profile = -1;

	if (SUCCEEDED (net->lpVtbl->GetName (net, &name)) && name != NULL) {
		utf8 = g_utf16_to_utf8 ((const gunichar2 *) name, -1,
		                        NULL, NULL, NULL);
		SysFreeString (name);
	}
	if (SUCCEEDED (net->lpVtbl->GetCategory (net, &category)))
		profile = profile_from_category (category);
	if (FAILED (net->lpVtbl->GetConnectivity (net, &connectivity)))
		connectivity = NLM_CONNECTIVITY_DISCONNECTED;

	/* The medium of the first connection whose adapter answers. */
	if (SUCCEEDED (net->lpVtbl->GetNetworkConnections (net, &conns)) &&
	    conns != NULL) {
		INetworkConnection *conn = NULL;
		ULONG got = 0;

		while (medium == NULL &&
		       conns->lpVtbl->Next (conns, 1, &conn, &got) == S_OK &&
		       got == 1 && conn != NULL) {
			GUID adapter;

			if (SUCCEEDED (conn->lpVtbl->GetAdapterId (conn, &adapter)))
				medium = medium_of_adapter (&adapter);
			conn->lpVtbl->Release (conn);
			conn = NULL;
		}
		conns->lpVtbl->Release (conns);
	}

	fs_network_place_add (place, utf8, profile, medium,
	                      (connectivity & (NLM_CONNECTIVITY_IPV4_INTERNET |
	                                       NLM_CONNECTIVITY_IPV6_INTERNET))
	                      != 0);
	g_free (utf8);
}

/* [ firewalled_network_place ]
 * See FsBackend.network_place.  NULL when neither COM read answered. */
static FsNetworkPlace *
firewalled_network_place (void)
{
	HRESULT init = CoInitializeEx (NULL, COINIT_APARTMENTTHREADED);
	INetFwPolicy2 *policy = NULL;
	INetworkListManager *nlm = NULL;
	FsNetworkPlace *place = NULL;
	gboolean have_types = FALSE;
	LONG types = 0;

	if (SUCCEEDED (CoCreateInstance (&FS_CLSID_NetFwPolicy2, NULL,
	                                 CLSCTX_ALL, &FS_IID_INetFwPolicy2,
	                                 (void **) &policy)) &&
	    policy != NULL) {
		have_types = SUCCEEDED (policy->lpVtbl->get_CurrentProfileTypes (
		                        policy, &types));
		policy->lpVtbl->Release (policy);
	}

	if (SUCCEEDED (CoCreateInstance (&FS_CLSID_NetworkListManager, NULL,
	                                 CLSCTX_ALL, &FS_IID_INetworkListManager,
	                                 (void **) &nlm)) &&
	    nlm != NULL) {
		IEnumNetworks *nets = NULL;

		if (SUCCEEDED (nlm->lpVtbl->GetNetworks (nlm,
		                                         NLM_ENUM_NETWORK_CONNECTED,
		                                         &nets)) &&
		    nets != NULL) {
			INetwork *net = NULL;
			ULONG got = 0;

			place = fs_network_place_new ();
			while (nets->lpVtbl->Next (nets, 1, &net, &got) == S_OK &&
			       got == 1 && net != NULL) {
				add_network (place, net);
				net->lpVtbl->Release (net);
				net = NULL;
			}
			nets->lpVtbl->Release (nets);
		}
		nlm->lpVtbl->Release (nlm);
	}

	if (have_types) {
		if (place == NULL)
			place = fs_network_place_new ();
		place->in_use = profiles_from_types (types);
	} else if (place != NULL) {
		/* The firewall did not say; the networks' categories are
		 * what it would have said. */
		for (guint i = 0; i < place->networks->len; i++) {
			const FsNetwork *n = g_ptr_array_index (place->networks, i);

			if (n->profile >= 0)
				place->in_use |= FS_PROFILE_BIT (n->profile);
		}
	}

	/* S_FALSE (already initialised on this thread, as GTK's OLE setup
	 * does) still needs its matching CoUninitialize; RPC_E_CHANGED_MODE
	 * does not. */
	if (SUCCEEDED (init))
		CoUninitialize ();

	return place;
}

/* Designated initialisers, not positional: adding a field to FsBackend
 * then leaves every backend correct instead of silently shifting every
 * entry after the insertion point. */
/* =====================================================================
 * Threat intel (1.0.7 Round 3, design section 11)
 *
 * The blocklists are Windows Firewall rules of their own, in the rule
 * group FS_INTELWIN_GROUP, written and read in-process through
 * INetFwPolicy2 / INetFwRules / INetFwRule -- never netsh or
 * PowerShell, which would flash a console and could not be told apart
 * from the user's own commands.  What the rules are (names, address
 * chunks, the manifest) and what a read-back means are decided in
 * core/fs-intelwin.c, where the core suite checks them; this part only
 * moves them across COM.
 *
 * The policy above never names that group (its rules are "StockFW-..."
 * and netsh's clear keeps to that prefix), and these slots never touch
 * a rule outside it, so applying or clearing either never touches the
 * other [N6, P0].
 *
 * An apply writes the new rules first and removes the old ones after:
 * a refused rule takes the new ones out again and leaves the old ones
 * in force, and an old rule that cannot be removed leaves more
 * blocking, never less.  What the firewall holds afterwards, read back
 * whole, is the answer, not what the calls said [S10].
 *
 * [Unverified on Windows here] Compiled and linked with mingw in the
 * development container; tests/test-intel-windows.c drives these slots
 * against the real firewall on the CI's Windows runner.
 * ================================================================== */

typedef struct
{
	gboolean       uninit;    /* CoUninitialize at the end            */
	INetFwPolicy2 *policy;
	INetFwRules   *rules;
} FwIntel;

/* One sentence for a COM failure; access denied gets its own code, so
 * the engine and the UI can say "run as administrator". */
static void
intel_hr_error (GError **error, HRESULT hr, const gchar *what)
{
	gchar *msg;

	if (error == NULL || *error != NULL)
		return;
	if (hr == E_ACCESSDENIED ||
	    hr == HRESULT_FROM_WIN32 (ERROR_ACCESS_DENIED)) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
		             "%s: changing Windows Firewall rules requires "
		             "administrator rights. Run StockFW as "
		             "administrator.", what);
		return;
	}
	msg = g_win32_error_message ((gint) hr);
	g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
	             "%s: %s (0x%08lx)", what,
	             msg != NULL && *msg ? msg : "error",
	             (unsigned long) hr);
	g_free (msg);
}

static void
fw_intel_close (FwIntel *fw)
{
	if (fw->rules != NULL)
		fw->rules->lpVtbl->Release (fw->rules);
	if (fw->policy != NULL)
		fw->policy->lpVtbl->Release (fw->policy);
	if (fw->uninit)
		CoUninitialize ();
	memset (fw, 0, sizeof *fw);
}

/* COM on this thread, the policy and its rule collection.  A thread
 * that already joined the multithreaded apartment (RPC_E_CHANGED_MODE)
 * can use the objects as it is, and must not be uninitialized by us. */
static gboolean
fw_intel_open (FwIntel *fw, gboolean want_rules, GError **error)
{
	HRESULT hr;

	memset (fw, 0, sizeof *fw);
	hr = CoInitializeEx (NULL, COINIT_APARTMENTTHREADED);
	if (FAILED (hr) && hr != RPC_E_CHANGED_MODE) {
		intel_hr_error (error, hr, "COM could not be started");
		return FALSE;
	}
	fw->uninit = SUCCEEDED (hr);

	hr = CoCreateInstance (&FS_CLSID_NetFwPolicy2, NULL,
	                       CLSCTX_INPROC_SERVER, &FS_IID_INetFwPolicy2,
	                       (void **) &fw->policy);
	if (FAILED (hr) || fw->policy == NULL) {
		intel_hr_error (error, FAILED (hr) ? hr : E_FAIL,
		                "Windows Firewall could not be reached");
		fw_intel_close (fw);
		return FALSE;
	}
	if (!want_rules)
		return TRUE;
	hr = fw->policy->lpVtbl->get_Rules (fw->policy, &fw->rules);
	if (FAILED (hr) || fw->rules == NULL) {
		intel_hr_error (error, FAILED (hr) ? hr : E_FAIL,
		                "The Windows Firewall rules could not be read");
		fw_intel_close (fw);
		return FALSE;
	}
	return TRUE;
}

static BSTR
bstr_new (const gchar *utf8)
{
	gunichar2 *w = g_utf8_to_utf16 (utf8 != NULL ? utf8 : "", -1, NULL,
	                                NULL, NULL);
	BSTR b = w != NULL ? SysAllocString ((const OLECHAR *) w) : NULL;

	g_free (w);
	return b;
}

/* UTF-8 copy of a BSTR, which is freed; NULL for NULL. */
static gchar *
bstr_take (BSTR b)
{
	gchar *s = NULL;

	if (b != NULL)
		s = g_utf16_to_utf8 ((const gunichar2 *) b,
		                     (glong) SysStringLen (b), NULL, NULL, NULL);
	SysFreeString (b);
	return s;
}

/* Elements in a VARIANT holding a list (interfaces), 0 for none. */
static guint
variant_count (const VARIANT *v)
{
	if ((v->vt & VT_ARRAY) != 0 && v->parray != NULL) {
		LONG lo = 0, hi = -1;

		if (SUCCEEDED (SafeArrayGetLBound (v->parray, 1, &lo)) &&
		    SUCCEEDED (SafeArrayGetUBound (v->parray, 1, &hi)) &&
		    hi >= lo)
			return (guint) (hi - lo + 1);
		return 0;
	}
	if (v->vt == VT_BSTR)
		return v->bstrVal != NULL && SysStringLen (v->bstrVal) > 0;
	return v->vt == VT_EMPTY || v->vt == VT_NULL ? 0 : 1;
}

/* A string property that must be empty to keep a rule whole.  One
 * that cannot be read counts as set: an unread condition never makes
 * a rule whole (review R3-4). */
static gboolean
bstr_is_set (HRESULT hr, BSTR b)
{
	gboolean set = FAILED (hr) || (b != NULL && SysStringLen (b) > 0);

	SysFreeString (b);
	return set;
}

/* INetFwRule3's conditions: an app package, the owner or authorized
 * users, remote users or machines, or IPsec flags.  Any of them makes
 * the rule apply to less than everything, and so does one that cannot
 * be read (review R3-4).  A Windows without INetFwRule3 (7) has none
 * of them. */
static gboolean
rule_has_conditions (INetFwRule *r)
{
	INetFwRule3 *r3 = NULL;
	BSTR b;
	LONG flags = 0;
	gboolean any = FALSE;

	if (FAILED (r->lpVtbl->QueryInterface (r, &FS_IID_INetFwRule3,
	                                       (void **) &r3)) || r3 == NULL)
		return FALSE;
	b = NULL;
	any |= bstr_is_set (r3->lpVtbl->get_LocalAppPackageId (r3, &b), b);
	b = NULL;
	any |= bstr_is_set (r3->lpVtbl->get_LocalUserOwner (r3, &b), b);
	b = NULL;
	any |= bstr_is_set (r3->lpVtbl->get_LocalUserAuthorizedList (r3, &b),
	                    b);
	b = NULL;
	any |= bstr_is_set (r3->lpVtbl->get_RemoteUserAuthorizedList (r3, &b),
	                    b);
	b = NULL;
	any |= bstr_is_set (r3->lpVtbl->get_RemoteMachineAuthorizedList (r3,
	                                                                 &b),
	                    b);
	if (FAILED (r3->lpVtbl->get_SecureFlags (r3, &flags)) || flags != 0)
		any = TRUE;
	r3->lpVtbl->Release (r3);
	return any;
}

/* Everything about one rule that can narrow or undo a block. */
static FsIntelWinSeen *
seen_from_rule (INetFwRule *r, gchar *grouping)
{
	FsIntelWinSeen *s = fs_intelwin_seen_new ();
	NET_FW_RULE_DIRECTION dir = 0;
	NET_FW_ACTION action = NET_FW_ACTION_MAX;
	VARIANT_BOOL on = VARIANT_FALSE;
	LONG value = 0;
	VARIANT v;
	BSTR b;

	s->grouping = grouping;
	b = NULL; r->lpVtbl->get_Name (r, &b);           s->name = bstr_take (b);
	b = NULL; r->lpVtbl->get_Description (r, &b);    s->description = bstr_take (b);
	b = NULL; r->lpVtbl->get_LocalAddresses (r, &b); s->local_addresses = bstr_take (b);
	b = NULL; r->lpVtbl->get_RemoteAddresses (r, &b);s->remote_addresses = bstr_take (b);
	b = NULL; r->lpVtbl->get_LocalPorts (r, &b);     s->local_ports = bstr_take (b);
	b = NULL; r->lpVtbl->get_RemotePorts (r, &b);    s->remote_ports = bstr_take (b);
	b = NULL; r->lpVtbl->get_ApplicationName (r, &b);s->application = bstr_take (b);
	b = NULL; r->lpVtbl->get_ServiceName (r, &b);    s->service = bstr_take (b);
	b = NULL; r->lpVtbl->get_InterfaceTypes (r, &b); s->interface_types = bstr_take (b);

	/* A property that cannot be read counts as wrong: -1 matches no
	 * direction, action or protocol. */
	s->direction = SUCCEEDED (r->lpVtbl->get_Direction (r, &dir))
	               ? (gint) dir : -1;
	s->action = SUCCEEDED (r->lpVtbl->get_Action (r, &action))
	            ? (gint) action : -1;
	s->enabled = SUCCEEDED (r->lpVtbl->get_Enabled (r, &on)) &&
	             on != VARIANT_FALSE;
	s->profiles = SUCCEEDED (r->lpVtbl->get_Profiles (r, &value))
	              ? (glong) value : 0;
	value = 0;
	s->protocol = SUCCEEDED (r->lpVtbl->get_Protocol (r, &value))
	              ? (glong) value : -1;
	VariantInit (&v);
	if (SUCCEEDED (r->lpVtbl->get_Interfaces (r, &v)))
		s->interfaces = variant_count (&v) > 0;
	else
		s->interfaces = TRUE;
	VariantClear (&v);
	s->conditions = rule_has_conditions (r);
	return s;
}

static void
rule_release (gpointer p)
{
	INetFwRule *r = p;

	if (r != NULL)
		r->lpVtbl->Release (r);
}

/* Counts a name under its case-folded key (fs_intelwin_name_key), so
 * names that differ only in case count as one (review W6). */
static void
name_count (GHashTable *names, const gchar *name)
{
	gpointer n;
	gchar *key;

	if (names == NULL || name == NULL)
		return;
	key = fs_intelwin_name_key (name);
	n = g_hash_table_lookup (names, key);
	g_hash_table_replace (names, key,
	                      GUINT_TO_POINTER (GPOINTER_TO_UINT (n) + 1));
}

static guint
name_lookup (GHashTable *names, const gchar *name)
{
	gchar *key = fs_intelwin_name_key (name);
	guint n = GPOINTER_TO_UINT (g_hash_table_lookup (names, key));

	g_free (key);
	return n;
}

/* One pass over every rule on the firewall.  Ours (the group) are read
 * whole into `ours' (FsIntelWinSeen*), with their rule objects at the
 * same index in `objs' when it is not NULL; every rule's name, ours or
 * not, is counted in `names' (name -> count) when it is not NULL. */
static gboolean
fw_intel_list (FwIntel *fw, GPtrArray *ours, GPtrArray *objs,
               GHashTable *names, GError **error)
{
	IUnknown *unk = NULL;
	IEnumVARIANT *en = NULL;
	HRESULT hr;
	gboolean ok = TRUE;

	hr = fw->rules->lpVtbl->get__NewEnum (fw->rules, &unk);
	if (FAILED (hr) || unk == NULL) {
		intel_hr_error (error, FAILED (hr) ? hr : E_FAIL,
		                "The Windows Firewall rules could not be listed");
		return FALSE;
	}
	hr = unk->lpVtbl->QueryInterface (unk, &FS_IID_IEnumVARIANT,
	                                  (void **) &en);
	unk->lpVtbl->Release (unk);
	if (FAILED (hr) || en == NULL) {
		intel_hr_error (error, FAILED (hr) ? hr : E_FAIL,
		                "The Windows Firewall rules could not be listed");
		return FALSE;
	}

	for (;;) {
		VARIANT v;
		ULONG got = 0;
		INetFwRule *r = NULL;

		VariantInit (&v);
		hr = en->lpVtbl->Next (en, 1, &v, &got);
		if (FAILED (hr)) {
			intel_hr_error (error, hr, "The Windows Firewall rules "
			                "could not be listed");
			ok = FALSE;
			break;
		}
		if (hr != S_OK || got == 0)
			break;
		if (v.vt == VT_DISPATCH && v.pdispVal != NULL &&
		    SUCCEEDED (v.pdispVal->lpVtbl->QueryInterface (
			    v.pdispVal, &FS_IID_INetFwRule, (void **) &r)) &&
		    r != NULL) {
			BSTR b = NULL;
			gchar *group;

			/* A rule whose group cannot be read might be ours:
			 * skipping it would let a clear or an apply report
			 * success with it still in force, so the listing
			 * fails instead (review R3-4). */
			hr = r->lpVtbl->get_Grouping (r, &b);
			if (FAILED (hr)) {
				SysFreeString (b);
				r->lpVtbl->Release (r);
				VariantClear (&v);
				intel_hr_error (error, hr, "The group of a Windows "
				                "Firewall rule could not be read");
				ok = FALSE;
				break;
			}
			group = bstr_take (b);
			if (fs_intelwin_in_group (group)) {
				FsIntelWinSeen *s = seen_from_rule (r, group);

				g_ptr_array_add (ours, s);
				name_count (names, s->name);
				if (objs != NULL) {
					r->lpVtbl->AddRef (r);
					g_ptr_array_add (objs, r);
				}
			} else {
				g_free (group);
				if (names != NULL) {
					gchar *name;

					b = NULL;
					r->lpVtbl->get_Name (r, &b);
					name = bstr_take (b);
					name_count (names, name);
					g_free (name);
				}
			}
			r->lpVtbl->Release (r);
		}
		VariantClear (&v);
	}
	en->lpVtbl->Release (en);
	return ok;
}

/* [ com_list_our_names ]
 * The names of the policy's own rules (fs_netsh_rule_name_is_ours),
 * read through INetFwRules: one name per rule, no addresses, so the
 * size of the blocklist rules cannot cut the list short.  Rules in the
 * threat-intel group are skipped unread.  TRUE with *sink set, or
 * FALSE with *sink NULL when the rules cannot be listed. */
static gboolean
com_list_our_names (GHashTable **sink, GError **error)
{
	FwIntel fw;
	IUnknown *unk = NULL;
	IEnumVARIANT *en = NULL;
	GHashTable *names;
	HRESULT hr;
	gboolean ok = TRUE;

	*sink = NULL;
	if (!fw_intel_open (&fw, TRUE, error))
		return FALSE;
	hr = fw.rules->lpVtbl->get__NewEnum (fw.rules, &unk);
	if (SUCCEEDED (hr) && unk != NULL) {
		hr = unk->lpVtbl->QueryInterface (unk, &FS_IID_IEnumVARIANT,
		                                  (void **) &en);
		unk->lpVtbl->Release (unk);
	}
	if (FAILED (hr) || en == NULL) {
		intel_hr_error (error, FAILED (hr) ? hr : E_FAIL,
		                "The Windows Firewall rules could not be listed");
		fw_intel_close (&fw);
		return FALSE;
	}
	names = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	for (;;) {
		VARIANT v;
		ULONG got = 0;
		INetFwRule *r = NULL;

		VariantInit (&v);
		hr = en->lpVtbl->Next (en, 1, &v, &got);
		if (FAILED (hr)) {
			intel_hr_error (error, hr, "The Windows Firewall rules "
			                "could not be listed");
			ok = FALSE;
			break;
		}
		if (hr != S_OK || got == 0)
			break;
		if (v.vt == VT_DISPATCH && v.pdispVal != NULL &&
		    SUCCEEDED (v.pdispVal->lpVtbl->QueryInterface (
			    v.pdispVal, &FS_IID_INetFwRule, (void **) &r)) &&
		    r != NULL) {
			BSTR bg = NULL, bn = NULL;
			gchar *group, *name = NULL;

			r->lpVtbl->get_Grouping (r, &bg);
			group = bstr_take (bg);
			if (!fs_intelwin_in_group (group)) {
				r->lpVtbl->get_Name (r, &bn);
				name = bstr_take (bn);
			}
			if (name != NULL && fs_netsh_rule_name_is_ours (name))
				g_hash_table_add (names, name);
			else
				g_free (name);
			g_free (group);
			r->lpVtbl->Release (r);
		}
		VariantClear (&v);
	}
	en->lpVtbl->Release (en);
	fw_intel_close (&fw);
	if (!ok) {
		g_hash_table_destroy (names);
		return FALSE;
	}
	*sink = names;
	return TRUE;
}

/* Reads our rules back and judges them (fs_intelwin_read). */
static gboolean
fw_intel_read (FwIntel *fw, FsIntelWinRead *out, GError **error)
{
	GPtrArray *seen = g_ptr_array_new_with_free_func (fs_intelwin_seen_free);
	gboolean ok = fw_intel_list (fw, seen, NULL, NULL, error);

	if (ok)
		fs_intelwin_read (seen, out);
	g_ptr_array_unref (seen);
	return ok;
}

/* Creates one rule.  Unset properties keep their defaults: every
 * protocol, port, local address, program and interface type. */
static HRESULT
fw_intel_add (FwIntel *fw, const FsIntelWinRule *r)
{
	INetFwRule *rule = NULL;
	BSTR name, desc, group, remote;
	HRESULT hr;

	hr = CoCreateInstance (&FS_CLSID_NetFwRule, NULL, CLSCTX_INPROC_SERVER,
	                       &FS_IID_INetFwRule, (void **) &rule);
	if (FAILED (hr) || rule == NULL)
		return FAILED (hr) ? hr : E_FAIL;
	name = bstr_new (r->name);
	desc = bstr_new (r->description);
	group = bstr_new (FS_INTELWIN_GROUP);
	remote = bstr_new (r->remote);
	if (name == NULL || desc == NULL || group == NULL || remote == NULL)
		hr = E_OUTOFMEMORY;
	if (SUCCEEDED (hr))
		hr = rule->lpVtbl->put_Name (rule, name);
	if (SUCCEEDED (hr))
		hr = rule->lpVtbl->put_Description (rule, desc);
	if (SUCCEEDED (hr))
		hr = rule->lpVtbl->put_Grouping (rule, group);
	if (SUCCEEDED (hr))
		hr = rule->lpVtbl->put_Direction (rule,
		                                  (NET_FW_RULE_DIRECTION) r->dir);
	if (SUCCEEDED (hr))
		hr = rule->lpVtbl->put_Action (rule, NET_FW_ACTION_BLOCK);
	if (SUCCEEDED (hr))
		hr = rule->lpVtbl->put_Profiles (rule, NET_FW_PROFILE2_ALL);
	if (SUCCEEDED (hr))
		hr = rule->lpVtbl->put_RemoteAddresses (rule, remote);
	if (SUCCEEDED (hr))
		hr = rule->lpVtbl->put_Enabled (rule, r->enabled ? VARIANT_TRUE
		                                                 : VARIANT_FALSE);
	if (SUCCEEDED (hr))
		hr = fw->rules->lpVtbl->Add (fw->rules, rule);
	SysFreeString (name);
	SysFreeString (desc);
	SysFreeString (group);
	SysFreeString (remote);
	rule->lpVtbl->Release (rule);
	return hr;
}

/* Which of our rules a removal takes. */
typedef gboolean (*FwIntelPick) (const FsIntelWinSeen *seen,
                                 const gchar *gen);

static gboolean
pick_all (const FsIntelWinSeen *seen, const gchar *gen)
{
	return TRUE;
}

static gboolean
pick_other_gen (const FsIntelWinSeen *seen, const gchar *gen)
{
	return g_strcmp0 (fs_intelwin_name_gen (seen->name), gen) != 0;
}

static gboolean
pick_gen (const FsIntelWinSeen *seen, const gchar *gen)
{
	return g_strcmp0 (fs_intelwin_name_gen (seen->name), gen) == 0;
}

/* Lists the firewall and removes the rules of ours `pick' takes.
 * INetFwRules::Remove goes by name, and Windows lets two rules share a
 * name: a rule whose name any other rule also has is first renamed, on
 * the rule object itself, to a name nothing else has, so the removal
 * can only take that rule -- never a user's rule that happens to share
 * it.  Returns how many could not be removed (G_MAXUINT when the list
 * could not be read); the first failure goes to *error. */
static guint
fw_intel_remove (FwIntel *fw, FwIntelPick pick, const gchar *gen,
                 GError **error)
{
	GPtrArray *seen = g_ptr_array_new_with_free_func (fs_intelwin_seen_free);
	GPtrArray *objs = g_ptr_array_new_with_free_func (rule_release);
	GHashTable *names = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                           g_free, NULL);
	guint failed = 0;

	if (!fw_intel_list (fw, seen, objs, names, error)) {
		failed = G_MAXUINT;
		goto out;
	}
	for (guint i = 0; i < seen->len; i++) {
		const FsIntelWinSeen *s = g_ptr_array_index (seen, i);
		INetFwRule *r = g_ptr_array_index (objs, i);
		gchar *unique = NULL;
		const gchar *name = s->name;
		HRESULT hr = S_OK;
		BSTR b;

		if (!pick (s, gen))
			continue;
		if (name == NULL || name_lookup (names, name) != 1) {
			unique = g_strdup_printf ("%sremoving %08x%08x",
			                          FS_INTELWIN_PREFIX,
			                          g_random_int (), g_random_int ());
			b = bstr_new (unique);
			hr = r->lpVtbl->put_Name (r, b);
			SysFreeString (b);
			name = unique;
		}
		if (SUCCEEDED (hr)) {
			b = bstr_new (name);
			hr = fw->rules->lpVtbl->Remove (fw->rules, b);
			SysFreeString (b);
		}
		if (FAILED (hr)) {
			gchar *what = g_strdup_printf (
				"The blocklist rule \"%s\" could not be removed",
				s->name != NULL ? s->name : "");

			intel_hr_error (error, hr, what);
			g_free (what);
			failed++;
		}
		g_free (unique);
	}
out:
	g_hash_table_destroy (names);
	g_ptr_array_unref (objs);
	g_ptr_array_unref (seen);
	return failed;
}

/* Whether Windows Firewall enforces rules now (core/fs-intelwin.h).
 * The service through the service manager (a standard user may ask),
 * the rest through the policy; what cannot be read stays "unknown",
 * and fs_intelwin_not_in_force never reports an unknown as in force. */
static void
fw_intel_force (FsIntelWinForce *f)
{
	SC_HANDLE scm, svc;
	FwIntel fw;

	memset (f, 0, sizeof *f);
	for (guint i = 0; i < 3; i++)
		f->enabled[i] = -1;

	scm = OpenSCManagerW (NULL, NULL, SC_MANAGER_CONNECT);
	if (scm != NULL) {
		svc = OpenServiceW (scm, L"MpsSvc", SERVICE_QUERY_STATUS);
		if (svc != NULL) {
			SERVICE_STATUS st;

			if (QueryServiceStatus (svc, &st)) {
				f->service_known = TRUE;
				f->service_running = st.dwCurrentState ==
				                     SERVICE_RUNNING;
			}
			CloseServiceHandle (svc);
		}
		CloseServiceHandle (scm);
	}

	if (!fw_intel_open (&fw, FALSE, NULL))
		return;
	{
		LONG types = 0;
		NET_FW_MODIFY_STATE ms = NET_FW_MODIFY_STATE_OK;

		if (SUCCEEDED (fw.policy->lpVtbl->get_CurrentProfileTypes (
			    fw.policy, &types))) {
			f->current = (glong) types;
			f->policy_read = TRUE;
		}
		for (guint i = 0; i < G_N_ELEMENTS (profiles); i++) {
			VARIANT_BOOL on = VARIANT_FALSE;
			VARIANT ex;

			if (SUCCEEDED (fw.policy->lpVtbl->get_FirewallEnabled (
				    fw.policy, profiles[i], &on)))
				f->enabled[i] = on != VARIANT_FALSE ? 1 : 0;
			VariantInit (&ex);
			if (SUCCEEDED (fw.policy->lpVtbl->get_ExcludedInterfaces (
				    fw.policy, profiles[i], &ex)))
				f->excluded[i] = variant_count (&ex);
			VariantClear (&ex);
		}
		if (SUCCEEDED (fw.policy->lpVtbl->get_LocalPolicyModifyState (
			    fw.policy, &ms))) {
			f->gp_read = TRUE;
			f->gp_override = ms == NET_FW_MODIFY_STATE_GP_OVERRIDE;
		}
	}
	fw_intel_close (&fw);
}

/* [ firewalled_intel_not_in_force ] -- see FsBackend.intel_not_in_force. */
static gchar *
firewalled_intel_not_in_force (void)
{
	FsIntelWinForce f;

	fw_intel_force (&f);
	return fs_intelwin_not_in_force (&f);
}

/* [ firewalled_intel_live ] -- see FsBackend.intel_live.
 * ABSENT, PRESENT (with the digest) or PARTIAL from the rules read
 * back whole; INACTIVE when there are rules of ours and the firewall
 * does not enforce them on a network in use; UNKNOWN when they cannot
 * be read (the service stopped: intel_not_in_force then says so). */
static FsIntelLive
firewalled_intel_live (gchar **digest)
{
	FwIntel fw;
	FsIntelWinRead r;
	FsIntelLive live;
	gchar *why;

	if (digest != NULL)
		*digest = NULL;
	if (!fw_intel_open (&fw, TRUE, NULL))
		return FS_INTEL_LIVE_UNKNOWN;
	if (!fw_intel_read (&fw, &r, NULL)) {
		fw_intel_close (&fw);
		return FS_INTEL_LIVE_UNKNOWN;
	}
	fw_intel_close (&fw);

	live = r.live;
	if (live != FS_INTEL_LIVE_ABSENT) {
		why = firewalled_intel_not_in_force ();
		if (why != NULL)
			live = FS_INTEL_LIVE_INACTIVE;
		g_free (why);
	}
	if (digest != NULL && r.live == FS_INTEL_LIVE_PRESENT) {
		*digest = r.digest;
		r.digest = NULL;
	}
	fs_intelwin_read_clear (&r);
	return live;
}

/* [ intel_lock ]
 * Apply and clear take many firewall calls each (a full rule set is
 * hundreds of INetFwRules::Add), and each removes every rule of ours
 * that is not its own generation.  Two of them at once, in two
 * processes (the window and `stockfw start', two windows) or two
 * threads, would take out each other's rules half written, so both
 * hold this named mutex from their first read to their read-back
 * (design 11.3, review R3-1).  It lives in the Global namespace, so
 * every session shares it; creating there needs SeCreateGlobalPrivilege,
 * which a standard user does not have, and the default DACL of an
 * elevated token keeps other accounts from opening it.  An abandoned
 * mutex (its holder died mid-apply) is taken over: the apply that
 * follows reads the firewall afresh and repairs what was left. */
#define FS_INTEL_LOCK_NAME    L"Global\\StockFW-ThreatIntel"
#define FS_INTEL_LOCK_WAIT_MS (10u * 60u * 1000u)

static HANDLE
intel_lock (GError **error)
{
	HANDLE m = CreateMutexW (NULL, FALSE, FS_INTEL_LOCK_NAME);
	DWORD w;

	if (m == NULL) {
		intel_hr_error (error, HRESULT_FROM_WIN32 (GetLastError ()),
		                "The lock that keeps two StockFW blocklist "
		                "changes apart could not be taken. Nothing was "
		                "changed");
		return NULL;
	}
	w = WaitForSingleObject (m, FS_INTEL_LOCK_WAIT_MS);
	if (w == WAIT_OBJECT_0 || w == WAIT_ABANDONED)
		return m;
	CloseHandle (m);
	if (w == WAIT_TIMEOUT)
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_BUSY,
		                     "Another StockFW has been changing the "
		                     "blocklist rules for 10 minutes. Nothing was "
		                     "changed; try again when it has finished.");
	else
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		                     "The lock that keeps two StockFW blocklist "
		                     "changes apart could not be waited for. "
		                     "Nothing was changed.");
	return NULL;
}

static void
intel_unlock (HANDLE m)
{
	if (m != NULL) {
		ReleaseMutex (m);
		CloseHandle (m);
	}
}

/* [ firewalled_intel_apply ] -- see FsBackend.intel_apply.  Runs under
 * intel_lock (firewalled_intel_apply below). */
static gboolean
intel_apply_locked (const FsIntelRuleset *ruleset, GError **error)
{
	FwIntel fw;
	FsIntelWinRead before, after;
	FsIntelWinPlan *plan = NULL;
	GError *add_error = NULL, *old_error = NULL, *read_error = NULL;
	gchar *want = NULL, *gen = NULL;
	guint old_left = 0;
	gboolean ok = FALSE, read_ok;

	g_return_val_if_fail (ruleset != NULL, FALSE);
	memset (&before, 0, sizeof before);
	memset (&after, 0, sizeof after);

	if (!fw_intel_open (&fw, TRUE, error))
		return FALSE;
	if (!fw_intel_read (&fw, &before, error)) {
		fw_intel_close (&fw);
		return FALSE;
	}
	/* The empty rule set leaves no rule at all. */
	if (ruleset->sets->len > 0)
		want = fs_intel_ruleset_digest (ruleset);

	/* Exactly these rules are there, whole: nothing to do.  Writing
	 * them again would cost hundreds of firewall calls on every
	 * hourly re-apply, and there are no counters for a replacement to
	 * reset (Windows counts nothing per rule). */
	if (want != NULL ? before.live == FS_INTEL_LIVE_PRESENT &&
	                   g_strcmp0 (before.digest, want) == 0
	                 : before.live == FS_INTEL_LIVE_ABSENT) {
		ok = TRUE;
		goto out;
	}

	if (want != NULL) {
		g_ptr_array_add (before.gens, NULL);
		gen = fs_intelwin_gen_new (g_random_int (),
		                           (const gchar *const *) before.gens->pdata);
		g_ptr_array_remove_index (before.gens, before.gens->len - 1);
		plan = fs_intelwin_plan (ruleset, gen, FS_INTELWIN_MAX_TOKENS,
		                         FS_INTELWIN_MAX_CHARS);
		if (plan == NULL) {
			g_set_error_literal (error, G_IO_ERROR,
			                     G_IO_ERROR_INVALID_ARGUMENT,
			                     "The blocklist rule set cannot be "
			                     "loaded: a list id is invalid or "
			                     "repeated. Nothing was changed.");
			goto out;
		}
		/* The new rules first, the manifest last: until it is
		 * written the new generation reads as incomplete, never as
		 * a rule set. */
		for (guint i = 0; i < plan->rules->len; i++) {
			const FsIntelWinRule *r = g_ptr_array_index (plan->rules, i);
			HRESULT hr = fw_intel_add (&fw, r);

			if (FAILED (hr)) {
				gchar *what = g_strdup_printf (
					"Windows Firewall refused the blocklist rule "
					"\"%s\"", r->name);

				intel_hr_error (&add_error, hr, what);
				g_free (what);
				break;
			}
		}
		if (add_error != NULL) {
			/* Take the new rules out again.  The old ones were never
			 * touched, so what was in force still is.  Remove
			 * succeeds for a name it does not find, so the firewall
			 * is listed again and only no rule of the new
			 * generation left is "nothing was changed" (review W6). */
			GPtrArray *rb = g_ptr_array_new_with_free_func (
				fs_intelwin_seen_free);
			guint left = fw_intel_remove (&fw, pick_gen, gen, NULL);
			gboolean listed = fw_intel_list (&fw, rb, NULL, NULL, NULL);

			if (listed)
				left = fs_intelwin_count_gen (rb, gen);
			g_ptr_array_unref (rb);
			if (listed && left == 0)
				g_set_error (error, add_error->domain,
				             add_error->code,
				             "%s. Nothing was changed: the blocklists "
				             "loaded before are still in force.",
				             add_error->message);
			else if (!listed)
				g_set_error (error, add_error->domain,
				             add_error->code,
				             "%s. The blocklists loaded before were not "
				             "touched, but StockFW could not read the "
				             "firewall back to check that the new rules "
				             "were taken out again; apply again to tidy "
				             "them.",
				             add_error->message);
			else
				g_set_error (error, add_error->domain,
				             add_error->code,
				             "%s. The blocklists loaded before are "
				             "still in force, and some of the new "
				             "rules could not be taken out again: "
				             "they block more, never less. Apply "
				             "again to tidy them.",
				             add_error->message);
			goto out;
		}
	}

	/* Then everything of ours that is not the new generation (all of
	 * it for the empty rule set).  A rule that will not go blocks
	 * more than the new rule set, never less. */
	old_left = fw_intel_remove (&fw, want != NULL ? pick_other_gen
	                                              : pick_all,
	                            gen, &old_error);

	/* What the firewall holds now decides [S10]. */
	read_ok = fw_intel_read (&fw, &after, &read_error);
	ok = read_ok && (want != NULL
	                 ? after.live == FS_INTEL_LIVE_PRESENT &&
	                   g_strcmp0 (after.digest, want) == 0
	                 : after.live == FS_INTEL_LIVE_ABSENT);
	if (!ok) {
		if (!read_ok)
			g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
			             "The blocklist rules were written, but could "
			             "not be read back to confirm them: %s",
			             read_error->message);
		else if (old_left > 0 && old_error != NULL)
			g_set_error (error, old_error->domain, old_error->code,
			             "%s. %s", old_error->message,
			             want != NULL
			             ? "The new blocklists are in force, and older "
			               "StockFW blocklist rules are still there "
			               "too; apply again to remove them."
			             : "Some StockFW blocklist rules are still in "
			               "force.");
		else
			g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
			             "Windows Firewall does not hold the blocklist "
			             "rules just written: %s",
			             after.why != NULL ? after.why
			                               : "they could not be found.");
	}
out:
	fw_intel_close (&fw);
	g_clear_error (&add_error);
	g_clear_error (&old_error);
	g_clear_error (&read_error);
	fs_intelwin_plan_free (plan);
	fs_intelwin_read_clear (&before);
	fs_intelwin_read_clear (&after);
	g_free (want);
	g_free (gen);
	return ok;
}

static gboolean
firewalled_intel_apply (const FsIntelRuleset *ruleset, GError **error)
{
	HANDLE lock;
	gboolean ok;

	g_return_val_if_fail (ruleset != NULL, FALSE);
	lock = intel_lock (error);
	if (lock == NULL)
		return FALSE;
	ok = intel_apply_locked (ruleset, error);
	intel_unlock (lock);
	return ok;
}

/* [ firewalled_intel_clear ] -- see FsBackend.intel_clear.
 * Every rule in the group, and nothing else; then the firewall is
 * listed again, and only none left is success.  Runs under intel_lock
 * (firewalled_intel_clear below). */
static gboolean
intel_clear_locked (GError **error)
{
	FwIntel fw;
	GError *local = NULL;
	GPtrArray *seen;
	guint left;
	gboolean ok;

	if (!fw_intel_open (&fw, TRUE, error))
		return FALSE;
	left = fw_intel_remove (&fw, pick_all, NULL, &local);
	if (left == G_MAXUINT) {
		g_propagate_error (error, local);
		fw_intel_close (&fw);
		return FALSE;
	}
	seen = g_ptr_array_new_with_free_func (fs_intelwin_seen_free);
	ok = fw_intel_list (&fw, seen, NULL, NULL, local == NULL ? error : NULL);
	if (ok && seen->len > 0) {
		ok = FALSE;
		if (local != NULL)
			g_set_error (error, local->domain, local->code,
			             "%s. %u StockFW blocklist rules are still in "
			             "force.", local->message, seen->len);
		else
			g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
			             "%u StockFW blocklist rules could not be "
			             "removed and are still in force.", seen->len);
	} else if (!ok && local != NULL) {
		g_propagate_error (error, local);
		local = NULL;
	}
	g_clear_error (&local);
	g_ptr_array_unref (seen);
	fw_intel_close (&fw);
	return ok;
}

static gboolean
firewalled_intel_clear (GError **error)
{
	HANDLE lock = intel_lock (error);
	gboolean ok;

	if (lock == NULL)
		return FALSE;
	ok = intel_clear_locked (error);
	intel_unlock (lock);
	return ok;
}

static const FsBackend windows_backend = {
	.name                  = "windows",
	.display_name          = "Windows Defender Firewall",
	/* The pages Windows now reads: the ICMP allow-list and the
	 * Advanced Options blocks.  Network Settings stays unoffered
	 * (Internet Connection Sharing needs the HNetCfg COM API, which
	 * the port does not carry) and ToS cannot be marked by Windows
	 * Firewall at all -- hiding both is the WYSIWYG rule working,
	 * not a missing feature note. */
	.fw_sections           = FS_FWSEC_ICMP | FS_FWSEC_ADVANCED,
	/* No per-rule reject (Windows drops silently) and no rate limits
	 * on the ICMP rules, so neither FS_FWHON_* bit is set. */
	.fw_honors             = 0,
	.available             = firewalled_com_available,
	.get_state             = firewalled_get_state,
	.start                 = firewalled_start,
	.stop                  = firewalled_stop,
	.reload                = firewalled_reload,
	.apply_rules           = firewalled_apply_rules,
	.apply_delta           = firewalled_apply_delta,
	.clear_rules           = firewalled_clear_rules,
	.list_interfaces       = firewalled_list_interfaces,
	.list_interface_stats  = firewalled_list_interface_stats,
	.list_connections      = firewalled_list_connections,
	.list_processes        = firewalled_list_processes,
	.log_start             = firewalled_log_start,
	.log_stop              = firewalled_log_stop,
	.log_active            = firewalled_log_active,
	.dhcp_set_enabled      = firewalled_dhcp_set_enabled,
	.get_profile_enabled   = firewalled_get_profile_enabled,
	.set_profile_enabled   = firewalled_set_profile_enabled,
	.network_place         = firewalled_network_place,
	.trust_signature       = fs_trust_win_signature,
	/* Threat intel, Round 3 (design section 11).  intel_counters stays
	 * NULL: Windows Firewall keeps no count per rule, and a NULL slot
	 * is how the engine and the surfaces learn that counts are not
	 * available (fs_intel_counts_unavailable), never "blocked 0". */
	.intel_apply           = firewalled_intel_apply,
	.intel_clear           = firewalled_intel_clear,
	.intel_live            = firewalled_intel_live,
	.intel_not_in_force    = firewalled_intel_not_in_force
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

/* [ fs_backend_set_context ]
 * The policy rules come from the policy parameter of apply_rules; the
 * settings rules come from here, so this stores both (the policy
 * pointer is kept for symmetry with the Linux backend and future
 * settings that need it). */
void
fs_backend_set_context (FsPolicy *policy, FsSettings *settings)
{
	ctx_policy = policy;
	ctx_settings = settings;
}
