/*---[ preferences.h ]------------------------------------------------
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions for modifying/reading the program preferences and the
 * preferences GUI
 *--------------------------------------------------------------------*/

#ifndef _STOCKFW_PREFERENCES
#define _STOCKFW_PREFERENCES

#define PREFS_FIRST_RUN "/apps/stockfw/client/first_run"
#define PREFS_SYSLOG_FILE "/apps/stockfw/client/system_log"

#define PREFS_ENABLE_TRAY_ICON "/apps/stockfw/client/enable_tray_icon"
#define PREFS_MINIMIZE_TO_TRAY "/apps/stockfw/client/minimize_to_tray"

#define PREFS_SKIP_REDUNDANT "/apps/stockfw/client/filter/redundant"
#define PREFS_SKIP_NOT_FOR_FIREWALL "/apps/stockfw/client/filter/not_for_firewall"

#define PREFS_APPLY_POLICY_INSTANTLY "/apps/stockfw/client/policy_auto_apply"

#define PREFS_START_ON_BOOT "/apps/stockfw/client/start_firewall_on_boot"
#define PREFS_START_ON_GUI "/apps/stockfw/client/start_firewall_on_gui"
#define PREFS_START_ON_DIAL_OUT "/apps/stockfw/client/start_firewall_on_dial_out"
#define PREFS_START_ON_DHCP "/apps/stockfw/client/start_firewall_on_dhcp"

#define PREFS_FW_EXT_IF "/apps/stockfw/firewall/ext_if"
#define PREFS_FW_INT_IF "/apps/stockfw/firewall/int_if"
#define PREFS_FW_NAT "/apps/stockfw/firewall/nat"

#define PREFS_FW_DHCP_ENABLE "/apps/stockfw/firewall/dhcp/enable_server"
#define PREFS_FW_DHCP_LOWEST_IP "/apps/stockfw/firewall/dhcp/lowest_ip"
#define PREFS_FW_DHCP_HIGHEST_IP "/apps/stockfw/firewall/dhcp/highest_ip"
#define PREFS_FW_DHCP_NAMESERVER "/apps/stockfw/firewall/dhcp/nameserver"

#define PREFS_FW_FILTER_ICMP "/apps/stockfw/firewall/icmp/enable"
#define PREFS_FW_ICMP_ECHO_REQUEST "/apps/stockfw/firewall/icmp/echo_request"
#define PREFS_FW_ICMP_ECHO_REPLY "/apps/stockfw/firewall/icmp/echo_reply"
#define PREFS_FW_ICMP_TRACEROUTE "/apps/stockfw/firewall/icmp/traceroute"
#define PREFS_FW_ICMP_MSTRACEROUTE "/apps/stockfw/firewall/icmp/mstraceroute"
#define PREFS_FW_ICMP_UNREACHABLE "/apps/stockfw/firewall/icmp/unreachable"
#define PREFS_FW_ICMP_TIMESTAMPING "/apps/stockfw/firewall/icmp/timestamping"
#define PREFS_FW_ICMP_MASKING "/apps/stockfw/firewall/icmp/masking"
#define PREFS_FW_ICMP_REDIRECTION "/apps/stockfw/firewall/icmp/redirection"
#define PREFS_FW_ICMP_SOURCE_QUENCHES "/apps/stockfw/firewall/icmp/source_quenches"

#define PREFS_FW_FILTER_TOS "/apps/stockfw/firewall/tos/enable"
#define PREFS_FW_TOS_CLIENT "/apps/stockfw/firewall/tos/client"
#define PREFS_FW_TOS_SERVER "/apps/stockfw/firewall/tos/server"
#define PREFS_FW_TOS_X "/apps/stockfw/firewall/tos/x"
#define PREFS_FW_TOS_OPT_TROUGHPUT "/apps/stockfw/firewall/tos/optimize_troughput"
#define PREFS_FW_TOS_OPT_RELIABILITY "/apps/stockfw/firewall/tos/optimize_reliability"
#define PREFS_FW_TOS_OPT_DELAY "/apps/stockfw/firewall/tos/optimize_delay"

#define PREFS_FW_DENY_PACKETS "/apps/stockfw/firewall/deny_packets"
#define PREFS_FW_BLOCK_EXTERNAL_BROADCAST "/apps/stockfw/firewall/block_external_broadcast"
#define PREFS_FW_BLOCK_INTERNAL_BROADCAST "/apps/stockfw/firewall/block_internal_broadcast"
#define PREFS_FW_BLOCK_NON_ROUTABLES "/apps/stockfw/firewall/block_non_routables"

#define PREFS_FW_RESTRICTIVE_OUTBOUND_MODE "/apps/stockfw/firewall/restrictive_outbound"

#define PREFS_HITVIEW_TIME_COL "/apps/stockfw/client/ui/hitview_time_col"
#define PREFS_HITVIEW_DIRECTION_COL "/apps/stockfw/client/ui/hitview_direction_col"
#define PREFS_HITVIEW_IN_COL "/apps/stockfw/client/ui/hitview_in_col"
#define PREFS_HITVIEW_OUT_COL "/apps/stockfw/client/ui/hitview_out_col"
#define PREFS_HITVIEW_PORT_COL "/apps/stockfw/client/ui/hitview_port_col"
#define PREFS_HITVIEW_SOURCE_COL "/apps/stockfw/client/ui/hitview_source_col"
#define PREFS_HITVIEW_DESTINATION_COL "/apps/stockfw/client/ui/hitview_destination_col"
#define PREFS_HITVIEW_LENGTH_COL "/apps/stockfw/client/ui/hitview_length_col"
#define PREFS_HITVIEW_TOS_COL "/apps/stockfw/client/ui/hitview_tos_col"
#define PREFS_HITVIEW_PROTOCOL_COL "/apps/stockfw/client/ui/hitview_protocol_col"
#define PREFS_HITVIEW_SERVICE_COL "/apps/stockfw/client/ui/hitview_service_col"

#include <config.h>
#include <gnome.h>

void preferences_check_schema (void);

gboolean preferences_get_bool   (const gchar *gconf_key);
void     preferences_set_bool   (const gchar *gconf_key, gboolean data);
gchar   *preferences_get_string (const gchar *gconf_key);
void     preferences_set_string (const gchar *gconf_key, const gchar *data);

void preferences_update_conf_from_widget (GtkWidget *widget, const gchar *gconf_key);
void preferences_update_widget_from_conf (GtkWidget *widget, const gchar *gconf_key);

void preferences_show (void);

#endif
