/*---[ fs-prefs.h ]------------------------------------------------------
 * Persistent settings.
 *
 * The original code used GConf 2, which no longer exists.  These days the
 * portable answer is a GKeyFile (plain ini) on every platform, so the
 * same settings code works on Windows and Linux unchanged.
 *
 * The key strings are kept in their original GConf form
 * ("/apps/firestarter/client/enable_tray_icon") so that the thousands of
 * existing call sites port without edits; internally they are mapped
 * onto ini groups and keys.
 *--------------------------------------------------------------------*/
#ifndef FS_PREFS_H
#define FS_PREFS_H

#include <glib.h>

G_BEGIN_DECLS

/* Original GConf keys, unchanged. */
#define FS_PREFS_FIRST_RUN       "/apps/firestarter/client/first_run"
#define FS_PREFS_SYSLOG_FILE     "/apps/firestarter/client/system_log"

#define FS_PREFS_ENABLE_TRAY_ICON "/apps/firestarter/client/enable_tray_icon"
#define FS_PREFS_MINIMIZE_TO_TRAY "/apps/firestarter/client/minimize_to_tray"

#define FS_PREFS_SKIP_REDUNDANT          "/apps/firestarter/client/filter/redundant"
#define FS_PREFS_SKIP_NOT_FOR_FIREWALL   "/apps/firestarter/client/filter/not_for_firewall"
#define FS_PREFS_APPLY_POLICY_INSTANTLY  "/apps/firestarter/client/policy_auto_apply"

#define FS_PREFS_START_ON_BOOT    "/apps/firestarter/client/start_firewall_on_boot"
#define FS_PREFS_START_ON_GUI     "/apps/firestarter/client/start_firewall_on_gui"
#define FS_PREFS_START_ON_DIAL_OUT "/apps/firestarter/client/start_firewall_on_dial_out"
#define FS_PREFS_START_ON_DHCP    "/apps/firestarter/client/start_firewall_on_dhcp"

#define FS_PREFS_FW_EXT_IF "/apps/firestarter/firewall/ext_if"
#define FS_PREFS_FW_INT_IF "/apps/firestarter/firewall/int_if"
#define FS_PREFS_FW_NAT    "/apps/firestarter/firewall/nat"

#define FS_PREFS_FW_DHCP_ENABLE     "/apps/firestarter/firewall/dhcp/enable_server"
#define FS_PREFS_FW_DHCP_LOWEST_IP  "/apps/firestarter/firewall/dhcp/lowest_ip"
#define FS_PREFS_FW_DHCP_HIGHEST_IP "/apps/firestarter/firewall/dhcp/highest_ip"
#define FS_PREFS_FW_DHCP_NAMESERVER "/apps/firestarter/firewall/dhcp/nameserver"

#define FS_PREFS_FW_FILTER_ICMP "/apps/firestarter/firewall/icmp/enable"
#define FS_PREFS_FW_ICMP_ECHO_REQUEST  "/apps/firestarter/firewall/icmp/echo_request"
#define FS_PREFS_FW_ICMP_ECHO_REPLY    "/apps/firestarter/firewall/icmp/echo_reply"
#define FS_PREFS_FW_ICMP_TRACEROUTE    "/apps/firestarter/firewall/icmp/traceroute"
#define FS_PREFS_FW_ICMP_MSTRACEROUTE  "/apps/firestarter/firewall/icmp/mstraceroute"
#define FS_PREFS_FW_ICMP_UNREACHABLE   "/apps/firestarter/firewall/icmp/unreachable"
#define FS_PREFS_FW_ICMP_TIMESTAMPING  "/apps/firestarter/firewall/icmp/timestamping"
#define FS_PREFS_FW_ICMP_MASKING       "/apps/firestarter/firewall/icmp/masking"
#define FS_PREFS_FW_ICMP_REDIRECTION   "/apps/firestarter/firewall/icmp/redirection"
#define FS_PREFS_FW_ICMP_SOURCE_QUENCHES "/apps/firestarter/firewall/icmp/source_quenches"

#define FS_PREFS_FW_FILTER_TOS  "/apps/firestarter/firewall/tos/enable"
#define FS_PREFS_FW_TOS_CLIENT  "/apps/firestarter/firewall/tos/client"
#define FS_PREFS_FW_TOS_SERVER  "/apps/firestarter/firewall/tos/server"
#define FS_PREFS_FW_TOS_X       "/apps/firestarter/firewall/tos/x"
#define FS_PREFS_FW_TOS_OPT_TROUGHPUT  "/apps/firestarter/firewall/tos/optimize_troughput"
#define FS_PREFS_FW_TOS_OPT_RELIABILITY "/apps/firestarter/firewall/tos/optimize_reliability"
#define FS_PREFS_FW_TOS_OPT_DELAY       "/apps/firestarter/firewall/tos/optimize_delay"

#define FS_PREFS_FW_DENY_PACKETS            "/apps/firestarter/firewall/deny_packets"
#define FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST "/apps/firestarter/firewall/block_external_broadcast"
#define FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST "/apps/firestarter/firewall/block_internal_broadcast"
#define FS_PREFS_FW_BLOCK_NON_ROUTABLES      "/apps/firestarter/firewall/block_non_routables"
#define FS_PREFS_FW_RESTRICTIVE_OUTBOUND     "/apps/firestarter/firewall/restrictive_outbound"

/* Load / save.  fs_prefs_load is safe to call more than once. */
void fs_prefs_init  (void);
gboolean fs_prefs_load (void);
gboolean fs_prefs_save (void);
const gchar *fs_prefs_path (void);

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