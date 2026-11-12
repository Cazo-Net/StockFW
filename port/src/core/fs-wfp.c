/*---[ fs-wfp.c ]-------------------------------------------------------
 * Windows Filtering Platform (WFP) Per-Process ALE Egress & Ingress Controls
 *--------------------------------------------------------------------*/

#include "core/fs-wfp.h"
#include <string.h>

#ifdef G_OS_WIN32

gchar *
fs_wfp_rule_to_netsh (const FsFwRule *rule, const gchar *executable_path)
{
	if (!rule || !executable_path)
		return NULL;

	const gchar *action_str = (rule->action == FS_ACTION_BLOCK) ? "block" : "allow";
	const gchar *dir_str = (rule->direction == FS_DIR_INBOUND) ? "in" : "out";
	const gchar *proto_str = (rule->protocol == FS_PROTO_TCP) ? " protocol=TCP" :
	                         (rule->protocol == FS_PROTO_UDP) ? " protocol=UDP" : "";
	const gchar *local_port_str = (rule->local_ports) ? g_strdup_printf(" localport=%s", rule->local_ports) : "";
	const gchar *remote_port_str = (rule->remote_ports) ? g_strdup_printf(" remoteport=%s", rule->remote_ports) : "";
	const gchar *remote_ip_str = (rule->remote_address) ? g_strdup_printf(" remoteip=%s", rule->remote_address) : "";

	gchar *res = g_strdup_printf (
		"netsh advfirewall firewall add rule name=\"StockFW: Process %s (%s)\" "
		"dir=%s action=%s program=\"%s\" enable=yes%s%s%s%s",
		executable_path, action_str, dir_str, action_str, executable_path,
		proto_str,
		rule->local_ports ? local_port_str : "",
		rule->remote_ports ? remote_port_str : "",
		rule->remote_address ? remote_ip_str : ""
	);

	if (rule->local_ports)
		g_free ((gchar *)local_port_str);
	if (rule->remote_ports)
		g_free ((gchar *)remote_port_str);
	if (rule->remote_address)
		g_free ((gchar *)remote_ip_str);

	return res;
}

gchar *
fs_wfp_rule_to_powershell (const FsFwRule *rule, const gchar *executable_path)
{
	if (!rule || !executable_path)
		return NULL;

	const gchar *action_str = (rule->action == FS_ACTION_BLOCK) ? "Block" : "Allow";
	const gchar *dir_str = (rule->direction == FS_DIR_INBOUND) ? "Inbound" : "Outbound";

	GString *ps = g_string_new (NULL);
	g_string_printf (ps,
		"New-NetFirewallRule -DisplayName 'StockFW: Process %s' "
		"-Direction %s -Action %s -Program '%s' -Enabled True",
		executable_path, dir_str, action_str, executable_path
	);

	if (rule->protocol == FS_PROTO_TCP)
		g_string_append (ps, " -Protocol TCP");
	else if (rule->protocol == FS_PROTO_UDP)
		g_string_append (ps, " -Protocol UDP");

	if (rule->local_ports)
		g_string_append_printf (ps, " -LocalPort '%s'", rule->local_ports);

	if (rule->remote_ports)
		g_string_append_printf (ps, " -RemotePort '%s'", rule->remote_ports);

	if (rule->remote_address)
		g_string_append_printf (ps, " -RemoteAddress '%s'", rule->remote_address);

	return g_string_free (ps, FALSE);
}

gchar *
fs_wfp_generate_ale_egress_policy (const gchar *executable_path, FsRuleAction action)
{
	if (!executable_path)
		return NULL;

	const gchar *action_desc = (action == FS_ACTION_BLOCK) ? "BLOCK" : "PERMIT";
	const gchar *ps_action = (action == FS_ACTION_BLOCK) ? "Block" : "Allow";

	return g_strdup_printf (
		"# Windows Filtering Platform (WFP) ALE Egress Control Policy\n"
		"# Executable: %s\n"
		"# Enforcement Action: %s\n"
		"function Register-StockFWWfpAleEgress {\n"
		"    param(\n"
		"        [string]$AppPath = '%s',\n"
		"        [string]$Action = '%s'\n"
		"    );\n"
		"    Write-Host \"[StockFW WFP ALE] Enforcing $Action outbound application layer enforcement for process: $AppPath\";\n"
		"    # Register WFP ALE Classify/Callout or NetEvent / WFP PowerShell Provider rule\n"
		"    $existing = Get-NetFirewallRule -DisplayName \"StockFW WFP ALE Egress - $AppPath\" -ErrorAction SilentlyContinue;\n"
		"    if ($null -eq $existing) {\n"
		"        New-NetFirewallRule -DisplayName \"StockFW WFP ALE Egress - $AppPath\" \\\n"
		"            -Direction Outbound -Action $Action -Program $AppPath -Enabled True \\\n"
		"            -Profile Domain,Private,Public;\n"
		"    } else {\n"
		"        Set-NetFirewallRule -DisplayName \"StockFW WFP ALE Egress - $AppPath\" -Action $Action;\n"
		"    }\n"
		"}\n"
		"Register-StockFWWfpAleEgress;\n",
		executable_path, action_desc, executable_path, ps_action
	);
}

#endif /* G_OS_WIN32 */
