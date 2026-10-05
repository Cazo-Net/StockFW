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
 * Unlike the Linux backend this never shells out: there is no bash and
 * no iptables on Windows, so rules are applied through COM directly.
 *
 * Build: add the object to the firestarter target in CMakeLists.txt,
 * link against ole32/oleaut32/hnetcfg.h and drop the
 * fs-backend-null.c entry.
 *--------------------------------------------------------------------*/

/* Windows headers come first and in this exact order: winsock2 must
 * precede windows.h, and doing it before the GLib headers avoids the
 * two sets fighting over the same declarations.  Getting this wrong
 * makes CoCreateInstance fail with CO_E_CLASSSTRING. */
#include <winsock2.h>
#include <windows.h>
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
	 * public) rather than the single on-off state Firestarter models.
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

	/* Only when every profile is on do we call it plain "running";
	 * a mix means partial coverage, reported as running with the
	 * per-profile detail available from the backend later. */
	return (any_on || any_off) ? FS_FW_RUNNING : FS_FW_STOPPED;
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
			             "administrator privileges. Restart Firestarter "
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

	for (const gchar *p = (name != NULL) ? name : "Firestarter rule";
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

/* [ run_netsh ]
 * Runs netsh with the given arguments.  Returns TRUE on success, with
 * the exit status in *exit_status and any output in *output. */
static gboolean
run_netsh (gchar **args, GError **error, gint *exit_status,
           gchar **output)
{
	GError *local_error = NULL;
	gchar *out = NULL;

	if (output != NULL)
		*output = NULL;

	if (!g_spawn_sync (NULL, args, NULL,
	                   G_SPAWN_SEARCH_PATH,
	                   NULL, NULL,
	                   &out, NULL,
	                   exit_status, &local_error)) {
		g_set_error (error,
		             g_quark_from_static_string ("fs-backend-windows"),
		             0, "Could not run netsh: %s",
		             local_error->message);
		g_error_free (local_error);
		return FALSE;
	}

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

	/* g_spawn_sync passes argv straight to CreateProcess with no shell
	 * parsing, so arguments must not carry quote characters: the whole
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
		                     "Firestarter as an administrator and try "
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
		/* Cannot enumerate, so cannot safely delete anything. */
		if (netsh_needs_elevation (output))
			g_set_error_literal (error,
			                     g_quark_from_static_string (
				                     "fs-backend-windows"),
			                     0,
			                     "Listing firewall rules requires "
			                     "administrator privileges.");

		g_free (output);
		return netsh_needs_elevation (output) ? FS_APPLY_NO_PRIVILEGE
		                                       : FS_APPLY_FAILED;
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

			if (g_str_has_prefix (line, "Firestarter "))
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
		if (error != NULL && first_error != NULL)
			g_propagate_error (error, first_error);
		else
			g_set_error_literal (error,
			                     g_quark_from_static_string (
				                     "fs-backend-windows"),
			                     0,
			                     "None of the rules could be created.");

		return netsh_needs_elevation (first_error ? first_error->message
		                                          : NULL)
			? FS_APPLY_NO_PRIVILEGE : FS_APPLY_FAILED;
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
 * timeout re-runs the query and hands anything new to the callback.
 * ------------------------------------------------------------------ */

static guint     log_source_id = 0;
static FsLogFunc log_callback = NULL;
static gpointer  log_user_data = NULL;
static gchar   *last_event_id = NULL;

/* [ parse_firewall_event ]
 * wevtutil text output has the shape:
 *
 *   Date: 2026-10-05 12:00:00
 *   ... Event ID: 5157 ...
 *   Application Information:
 *       Protocol: 6 (TCP)
 *       Local Address: 192.168.1.5
 *       Local Port: 22
 *       Remote Address: 203.0.113.9
 *       Remote Port: 51234
 *
 * Pull the labelled fields out of it. */
static gboolean
parse_firewall_event (const gchar *text, FsHit *hit)
{
	static const gchar *keys[] = {
		"Protocol", "Local Address", "Local Port",
		"Remote Address", "Remote Port", NULL
	};
	gchar **lines = g_strsplit (text, "\r\n", -1);
	gboolean got_address = FALSE;

	for (gint i = 0; lines[i] != NULL; i++) {
		gchar *line = g_strstrip (lines[i]);
		gchar *colon;

		if (line == NULL || *line == '\0')
			continue;

		/* The first line carries the timestamp.  Strip the source
		 * text first, then take a copy: g_strstrip returns a pointer
		 * into the buffer it is given, and storing that in hit->time
		 * means fs_hit_free later frees an interior pointer and
		 * corrupts the heap. */
		if (g_str_has_prefix (line, "Date:")) {
			hit->time = g_strdup (g_strstrip (line + 5));
			continue;
		}

		colon = strchr (line, ':');

		if (colon == NULL)
			continue;

		*colon = '\0';

		{
			const gchar *value = g_strstrip (colon + 1);

			if (g_strcmp0 (line, "Protocol") == 0) {
				gchar *sp = strchr (value, ' ');

				if (sp != NULL)
					*sp = '\0';

				hit->protocol = g_strdup (value);
			} else if (g_strcmp0 (line, "Local Address") == 0) {
				hit->in = g_strdup (value);
			} else if (g_strcmp0 (line, "Local Port") == 0) {
				hit->out = g_strdup (value);
				got_address = TRUE;
			} else if (g_strcmp0 (line, "Remote Address") == 0) {
				hit->destination = g_strdup (value);
			} else if (g_strcmp0 (line, "Remote Port") == 0) {
				hit->source = g_strdup (value);
			}
		}
	}

	(void) keys;
	g_strfreev (lines);

	if (!got_address) {
		/* Free only the fields parse allocated; "hit" itself is a
		 * stack local in the caller, so fs_hit_free would try to
		 * g_free() a stack address and corrupt the heap. */
		g_clear_pointer (&hit->time, g_free);
		g_clear_pointer (&hit->in, g_free);
		g_clear_pointer (&hit->out, g_free);
		g_clear_pointer (&hit->source, g_free);
		g_clear_pointer (&hit->destination, g_free);
		g_clear_pointer (&hit->protocol, g_free);
		g_clear_pointer (&hit->service, g_free);
		return FALSE;
	}

	/* Fill in what the log does not carry. */
	hit->direction = g_strdup ("in");
	hit->port = g_strdup (hit->out ? hit->out : "");

	if (hit->protocol != NULL) {
		if (g_strcmp0 (hit->protocol, "6") == 0 ||
		    g_ascii_strcasecmp (hit->protocol, "TCP") == 0)
			hit->protocol = g_strdup ("TCP");
		else if (g_strcmp0 (hit->protocol, "17") == 0)
			hit->protocol = g_strdup ("UDP");
	}

	hit->service = fs_service_lookup_port (atoi (hit->port
	                                            ? hit->port : "0"));

	if (hit->service == NULL)
		hit->service = g_strdup (_("Unknown"));

	return TRUE;
}

/* [ poll_events ] */
static gboolean
poll_events (gpointer data)
{
	/* The real channel name contains spaces; the widely copied
	 * "WindowsFirewallWithAdvancedSecurity" spelling does not exist. */
	gchar *args[] = {
		"wevtutil.exe", "qe",
		"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
		"/c:20", "/rd:true", "/f:text", NULL
	};
	gchar *output = NULL;
	gint status = 0;
	gchar **records;
	guint new_events = 0;

	if (!g_spawn_sync (NULL, args, NULL, G_SPAWN_SEARCH_PATH,
	                   NULL, NULL, &output, NULL, &status, NULL)) {
		g_free (output);
		return G_SOURCE_CONTINUE;
	}

	if (status != 0 || output == NULL) {
		g_free (output);
		return G_SOURCE_CONTINUE;
	}

	/* wevtutil separates records with a blank line. */
	records = g_strsplit (output, "\r\n\r\n", -1);

	for (gint i = 0; records[i] != NULL; i++) {
		FsHit hit = { 0 };
		guint len = strlen (records[i]);

		if (len < 40)
			continue;

		/* Skip the ones already delivered. */
		if (last_event_id != NULL &&
		    strstr (records[i], last_event_id) != NULL)
			continue;

		if (!parse_firewall_event (records[i], &hit))
			continue;

		/* Remember this record so the next poll does not repeat it. */
		{
			gchar *stamp = g_strdup_printf ("%s", hit.time ? hit.time : "");

			g_free (last_event_id);
			last_event_id = stamp;
		}

		if (log_callback != NULL)
			log_callback (&hit, log_user_data);

		new_events++;

		/* Free only the fields parse allocated: "hit" is a stack
		 * local, so fs_hit_free would try to g_free() it and
		 * corrupt the heap. */
		g_clear_pointer (&hit.time, g_free);
		g_clear_pointer (&hit.in, g_free);
		g_clear_pointer (&hit.out, g_free);
		g_clear_pointer (&hit.source, g_free);
		g_clear_pointer (&hit.destination, g_free);
		g_clear_pointer (&hit.protocol, g_free);
		g_clear_pointer (&hit.service, g_free);
	}

	g_strfreev (records);
	g_free (output);

	(void) new_events;

	return G_SOURCE_CONTINUE;
}

static gboolean
firewalled_log_start (FsLogFunc callback, gpointer user_data, GError **error)
{
	if (log_source_id != 0)
		return TRUE;

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

	log_callback = NULL;
	log_user_data = NULL;
	g_clear_pointer (&last_event_id, g_free);
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
		             "administrator privileges. Restart Firestarter "
		             "as an administrator and try again.");
		return FALSE;
	}

	return TRUE;
}

static const FsBackend windows_backend = {
	"windows",
	"Windows Defender Firewall",
	firewalled_com_available,
	firewalled_get_state,
	firewalled_start,
	firewalled_stop,
	firewalled_reload,
	firewalled_apply_rules,
	firewalled_clear_rules,
	firewalled_list_interfaces,
	firewalled_log_start,
	firewalled_log_stop,
	firewalled_log_active,
	firewalled_dhcp_set_enabled,
	firewalled_get_profile_enabled,
	firewalled_set_profile_enabled
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
