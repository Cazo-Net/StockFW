/*---[ fs-wfp.c ]-------------------------------------------------------
 * Windows Filtering Platform (WFP) Per-Process ALE Egress & Ingress Controls
 *--------------------------------------------------------------------*/

#include "core/fs-wfp.h"
#include <string.h>

gchar *
fs_wfp_rule_to_netsh (const FsFwRule *rule, const gchar *executable_path)
{
	if (!rule || !executable_path)
		return NULL;

	const gchar *action_str = (rule->action == FS_ACTION_BLOCK) ? "block" : "allow";
	const gchar *dir_str = (rule->direction == FS_DIR_INBOUND) ? "in" : "out";

	return g_strdup_printf (
		"netsh advfirewall firewall add rule name=\"StockFW: Process %s (%s)\" "
		"dir=%s action=%s program=\"%s\" enable=yes",
		executable_path, action_str, dir_str, action_str, executable_path
	);
}

gchar *
fs_wfp_rule_to_powershell (const FsFwRule *rule, const gchar *executable_path)
{
	if (!rule || !executable_path)
		return NULL;

	const gchar *action_str = (rule->action == FS_ACTION_BLOCK) ? "Block" : "Allow";
	const gchar *dir_str = (rule->direction == FS_DIR_INBOUND) ? "Inbound" : "Outbound";

	return g_strdup_printf (
		"New-NetFirewallRule -DisplayName 'StockFW: Process %s' "
		"-Direction %s -Action %s -Program '%s' -Enabled True",
		executable_path, dir_str, action_str, executable_path
	);
}

gchar *
fs_wfp_generate_ale_egress_policy (const gchar *executable_path, FsRuleAction action)
{
	if (!executable_path)
		return NULL;

	const gchar *action_desc = (action == FS_ACTION_BLOCK) ? "BLOCK" : "PERMIT";

	return g_strdup_printf (
		"# Windows Filtering Platform (WFP) ALE Egress Control Policy\n"
		"# Executable: %s\n"
		"# Enforcement Action: %s\n"
		"function Register-StockFWWfpAleEgress {\n"
		"    param(\n"
		"        [string]$AppPath = '%s',\n"
		"        [string]$Action = '%s'\n"
		"    );\n"
		"    Write-Host \"[StockFW WFP ALE] Enforcing $Action egress for process: $AppPath\";\n"
		"    # Create WFP filter via NetEvent / WFP PowerShell Provider / BFE API stub\n"
		"    New-NetFirewallRule -DisplayName \"StockFW WFP ALE Egress - $AppPath\" \\\n"
		"        -Direction Outbound -Action $Action -Program $AppPath -Enabled True;\n"
		"}\n"
		"Register-StockFWWfpAleEgress;\n",
		executable_path, action_desc, executable_path, (action == FS_ACTION_BLOCK) ? "Block" : "Allow"
	);
}
