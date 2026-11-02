/*---[ fs-prefs.h ]------------------------------------------------------
 * Persistent settings.
 *
 * The original code used GConf 2, which no longer exists.  These days the
 * portable answer is a GKeyFile (plain ini) on every platform, so the
 * same settings code works on Windows and Linux unchanged.
 *
 * The key strings are kept in their original GConf form
 * ("/apps/stockfw/client/enable_tray_icon") so that the thousands of
 * existing call sites port without edits; internally they are mapped
 * onto ini groups and keys.
 *--------------------------------------------------------------------*/
#ifndef FS_PREFS_H
#define FS_PREFS_H

#include <glib.h>

G_BEGIN_DECLS

/* Original GConf keys, unchanged. */
#define FS_PREFS_FIRST_RUN       "/apps/stockfw/client/first_run"
#define FS_PREFS_SYSLOG_FILE     "/apps/stockfw/client/system_log"

#define FS_PREFS_ENABLE_TRAY_ICON "/apps/stockfw/client/enable_tray_icon"
#define FS_PREFS_MINIMIZE_TO_TRAY "/apps/stockfw/client/minimize_to_tray"

#define FS_PREFS_SKIP_REDUNDANT          "/apps/stockfw/client/filter/redundant"
#define FS_PREFS_SKIP_NOT_FOR_FIREWALL   "/apps/stockfw/client/filter/not_for_firewall"
#define FS_PREFS_APPLY_POLICY_INSTANTLY  "/apps/stockfw/client/policy_auto_apply"
/* P3 audit-only testing mode: changes reach the policy file and the
 * audit log but never the firewall, until the user turns it off. */
#define FS_PREFS_AUDIT_ONLY              "/apps/stockfw/client/policy_audit_only"

#define FS_PREFS_START_ON_BOOT    "/apps/stockfw/client/start_firewall_on_boot"
#define FS_PREFS_START_ON_GUI     "/apps/stockfw/client/start_firewall_on_gui"
#define FS_PREFS_START_ON_DIAL_OUT "/apps/stockfw/client/start_firewall_on_dial_out"
#define FS_PREFS_START_ON_DHCP    "/apps/stockfw/client/start_firewall_on_dhcp"

#define FS_PREFS_FW_EXT_IF "/apps/stockfw/firewall/ext_if"
#define FS_PREFS_FW_INT_IF "/apps/stockfw/firewall/int_if"
#define FS_PREFS_FW_NAT    "/apps/stockfw/firewall/nat"

#define FS_PREFS_FW_DHCP_ENABLE     "/apps/stockfw/firewall/dhcp/enable_server"
#define FS_PREFS_FW_DHCP_LOWEST_IP  "/apps/stockfw/firewall/dhcp/lowest_ip"
#define FS_PREFS_FW_DHCP_HIGHEST_IP "/apps/stockfw/firewall/dhcp/highest_ip"
#define FS_PREFS_FW_DHCP_NAMESERVER "/apps/stockfw/firewall/dhcp/nameserver"

#define FS_PREFS_FW_FILTER_ICMP "/apps/stockfw/firewall/icmp/enable"
#define FS_PREFS_FW_ICMP_ECHO_REQUEST  "/apps/stockfw/firewall/icmp/echo_request"
#define FS_PREFS_FW_ICMP_ECHO_REPLY    "/apps/stockfw/firewall/icmp/echo_reply"
#define FS_PREFS_FW_ICMP_TRACEROUTE    "/apps/stockfw/firewall/icmp/traceroute"
#define FS_PREFS_FW_ICMP_MSTRACEROUTE  "/apps/stockfw/firewall/icmp/mstraceroute"
#define FS_PREFS_FW_ICMP_UNREACHABLE   "/apps/stockfw/firewall/icmp/unreachable"
#define FS_PREFS_FW_ICMP_TIMESTAMPING  "/apps/stockfw/firewall/icmp/timestamping"
#define FS_PREFS_FW_ICMP_MASKING       "/apps/stockfw/firewall/icmp/masking"
#define FS_PREFS_FW_ICMP_REDIRECTION   "/apps/stockfw/firewall/icmp/redirection"
#define FS_PREFS_FW_ICMP_SOURCE_QUENCHES "/apps/stockfw/firewall/icmp/source_quenches"

#define FS_PREFS_FW_FILTER_TOS  "/apps/stockfw/firewall/tos/enable"
#define FS_PREFS_FW_TOS_CLIENT  "/apps/stockfw/firewall/tos/client"
#define FS_PREFS_FW_TOS_SERVER  "/apps/stockfw/firewall/tos/server"
#define FS_PREFS_FW_TOS_X       "/apps/stockfw/firewall/tos/x"
#define FS_PREFS_FW_TOS_OPT_TROUGHPUT  "/apps/stockfw/firewall/tos/optimize_troughput"
#define FS_PREFS_FW_TOS_OPT_RELIABILITY "/apps/stockfw/firewall/tos/optimize_reliability"
#define FS_PREFS_FW_TOS_OPT_DELAY       "/apps/stockfw/firewall/tos/optimize_delay"

#define FS_PREFS_FW_DENY_PACKETS            "/apps/stockfw/firewall/deny_packets"
#define FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST "/apps/stockfw/firewall/block_external_broadcast"
#define FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST "/apps/stockfw/firewall/block_internal_broadcast"
#define FS_PREFS_FW_BLOCK_NON_ROUTABLES      "/apps/stockfw/firewall/block_non_routables"
#define FS_PREFS_FW_RESTRICTIVE_OUTBOUND     "/apps/stockfw/firewall/restrictive_outbound"
/* 1.0.7: log accepted new connections (Linux; Windows logs them via
 * its own audit policy). */
#define FS_PREFS_FW_LOG_ALLOWED              "/apps/stockfw/firewall/log_allowed"

/* Load / save.  fs_prefs_load is safe to call more than once. */
void fs_prefs_init  (void);
gboolean fs_prefs_load (void);
gboolean fs_prefs_save (void);
const gchar *fs_prefs_path (void);

/* TRUE when a setter changed something since the last load or save:
 * what the running program's periodic save checks (1.0.7). */
gboolean fs_prefs_dirty (void);

gboolean  fs_prefs_get_bool   (const gchar *key, gboolean fallback);
void      fs_prefs_set_bool   (const gchar *key, gboolean value);
gchar    *fs_prefs_get_string (const gchar *key, const gchar *fallback);
void      fs_prefs_set_string (const gchar *key, const gchar *value);
gint      fs_prefs_get_int    (const gchar *key, gint fallback);
void      fs_prefs_set_int    (const gchar *key, gint value);

/* Applies defaults for every setting the application expects. */
void fs_prefs_set_defaults (void);

G_END_DECLS

#endif /* FS_PREFS_H */