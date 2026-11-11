/*---[ fs-wfp.h ]-------------------------------------------------------
 * Windows Filtering Platform (WFP) Per-Process ALE Egress & Ingress Controls
 * Part of StockFW Phase v2.0 (The Autonomous Sovereign Fabric)
 *
 * Provides WFP callout definitions, session handles, and per-process Application
 * Layer Enforcement (ALE) registration for sub-millisecond packet filtering.
 *--------------------------------------------------------------------*/
#ifndef FS_WFP_H
#define FS_WFP_H

#include <glib.h>
#include "core/fs-fwrule.h"

G_BEGIN_DECLS

/* Generate netsh firewall rule command with per-process executable path */
gchar *fs_wfp_rule_to_netsh (const FsFwRule *rule, const gchar *executable_path);

/* Generate PowerShell New-NetFirewallRule command with per-process executable path */
gchar *fs_wfp_rule_to_powershell (const FsFwRule *rule, const gchar *executable_path);

/* Generate advanced WFP ALE egress/ingress callout session configuration script */
gchar *fs_wfp_generate_ale_egress_policy (const gchar *executable_path, FsRuleAction action);

G_END_DECLS

#endif /* FS_WFP_H */
