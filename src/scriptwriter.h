/*---[ scriptwriter.h ]-----------------------------------------------
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Functions to write firewall shell scripts
 *--------------------------------------------------------------------*/

#ifndef _STOCKFW_SCRIPTWRITER
#define _STOCKFW_SCRIPTWRITER

#include <config.h>
#include <gnome.h>
#include "wizard.h"
#include "policyview.h"

#define RETURN_EXT_FAILED 2
#define RETURN_INT_FAILED 3
#define RETURN_NO_IPTABLES 100

#define STOCKFW_CONTROL_SCRIPT       STOCKFW_RULES_DIR "/stockfw/stockfw.sh"
#define STOCKFW_FIREWALL_SCRIPT      STOCKFW_RULES_DIR "/stockfw/firewall"
#define STOCKFW_CONFIGURATION_SCRIPT STOCKFW_RULES_DIR "/stockfw/configuration"
#define STOCKFW_SYSCTL_SCRIPT        STOCKFW_RULES_DIR "/stockfw/sysctl-tuning"
#define STOCKFW_USER_PRE_SCRIPT      STOCKFW_RULES_DIR "/stockfw/user-pre"
#define STOCKFW_USER_POST_SCRIPT     STOCKFW_RULES_DIR "/stockfw/user-post"
#define STOCKFW_NON_ROUTABLES_SCRIPT STOCKFW_RULES_DIR "/stockfw/non-routables"
#define STOCKFW_FILTER_HOSTS_SCRIPT  STOCKFW_RULES_DIR "/stockfw/events-filter-hosts"
#define STOCKFW_FILTER_PORTS_SCRIPT  STOCKFW_RULES_DIR "/stockfw/events-filter-ports"
#define STOCKFW_INBOUND_SETUP        POLICY_IN_DIR"/setup"
#define STOCKFW_OUTBOUND_SETUP       POLICY_OUT_DIR"/setup"

gboolean script_exists (void);
void scriptwriter_output_scripts (void);

void scriptwriter_output_stockfw_script (void);
void scriptwriter_output_configuration (void);

void scriptwriter_write_ppp_hook (void);
void scriptwriter_remove_ppp_hook (void);

void scriptwriter_write_dhcp_hook (void);
void scriptwriter_remove_dhcp_hook (void);

gboolean scriptwriter_versions_match (void);

#endif
