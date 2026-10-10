/*---[ fs-settings-plan.c ]---------------------------------------------*/

#include <string.h>
#include "core/fs-settings-plan.h"

/* Templates.  Every field is a static string, so a plan borrows them
 * and freeing one is just dropping the array. */

static const FsSettingRule rule_icmp_all_off = {
	.name = "StockFW ICMP allow (filtering disabled)",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = NULL, .port = 0, .remote = NULL, .profiles = 0
};

static const FsSettingRule rule_icmp_time_exceeded = {
	.name = "StockFW ICMP allow time exceeded",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = "11,any", .port = 0, .remote = NULL, .profiles = 0
};

static const FsSettingRule rule_icmp_param_problem = {
	.name = "StockFW ICMP allow parameter problem",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = "12,any", .port = 0, .remote = NULL, .profiles = 0
};

static const FsSettingRule rule_icmp_echo_request = {
	.name = "StockFW ICMP allow echo request",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = "8,any", .port = 0, .remote = NULL, .profiles = 0
};

static const FsSettingRule rule_icmp_echo_reply = {
	.name = "StockFW ICMP allow echo reply",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = "0,any", .port = 0, .remote = NULL, .profiles = 0
};

/* The original's quirk, kept: this checkbox never was ICMP. */
static const FsSettingRule rule_traceroute_udp = {
	.name = "StockFW allow traceroute (UDP 33434)",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_UDP,
	.icmp = NULL, .port = 33434, .remote = NULL, .profiles = 0
};

static const FsSettingRule rule_icmp_dest_unreachable = {
	.name = "StockFW ICMP allow destination unreachable",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = "3,any", .port = 0, .remote = NULL, .profiles = 0
};

/* Subset of the rule above; skipped when MS Traceroute is ticked. */
static const FsSettingRule rule_icmp_host_unreachable = {
	.name = "StockFW ICMP allow host unreachable",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = "3,1", .port = 0, .remote = NULL, .profiles = 0
};

static const FsSettingRule rule_icmp_ts_request = {
	.name = "StockFW ICMP allow timestamp request",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = "13,any", .port = 0, .remote = NULL, .profiles = 0
};

static const FsSettingRule rule_icmp_ts_reply = {
	.name = "StockFW ICMP allow timestamp reply",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = "14,any", .port = 0, .remote = NULL, .profiles = 0
};

static const FsSettingRule rule_icmp_mask_request = {
	.name = "StockFW ICMP allow address mask request",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = "17,any", .port = 0, .remote = NULL, .profiles = 0
};

static const FsSettingRule rule_icmp_mask_reply = {
	.name = "StockFW ICMP allow address mask reply",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = "18,any", .port = 0, .remote = NULL, .profiles = 0
};

static const FsSettingRule rule_icmp_redirect = {
	.name = "StockFW ICMP allow redirect",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = "5,any", .port = 0, .remote = NULL, .profiles = 0
};

static const FsSettingRule rule_icmp_source_quench = {
	.name = "StockFW ICMP allow source quench",
	.allow = TRUE, .proto = FS_SETPLAN_PROTO_ICMP,
	.icmp = "4,any", .port = 0, .remote = NULL, .profiles = 0
};

/* Limited broadcast, the only broadcast the iptables rules blocked. */
static const FsSettingRule rule_block_broadcast_external = {
	.name = "StockFW block broadcasts from the external network",
	.allow = FALSE, .proto = FS_SETPLAN_PROTO_ANY,
	.icmp = NULL, .port = 0, .remote = "255.255.255.255",
	.profiles = FS_FWP_PROFILE_PUBLIC
};

static const FsSettingRule rule_block_broadcast_internal = {
	.name = "StockFW block broadcasts from the internal network",
	.allow = FALSE, .proto = FS_SETPLAN_PROTO_ANY,
	.icmp = NULL, .port = 0, .remote = "255.255.255.255",
	.profiles = FS_FWP_PROFILE_PRIVATE
};

/* The same four reserved ranges the iptables script refused on the
 * external interface: private space, and loopback arriving from
 * outside, cannot be genuine sources. */
static const FsSettingRule rule_block_reserved_sources = {
	.name = "StockFW block reserved source addresses on public networks",
	.allow = FALSE, .proto = FS_SETPLAN_PROTO_ANY,
	.icmp = NULL, .port = 0,
	.remote = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8",
	.profiles = FS_FWP_PROFILE_PUBLIC
};

static void
plan_add (FsSettingsPlan *plan, const FsSettingRule *rule)
{
	g_ptr_array_add (plan->rules, (gpointer) rule);
}

FsSettingsPlan *
fs_settings_plan_new (const FsSettings *settings)
{
	FsSettingsPlan *plan = g_new0 (FsSettingsPlan, 1);

	plan->rules = g_ptr_array_new ();

	if (settings == NULL)
		return plan;

	if (!settings->filter_icmp) {
		/* Filtering off: all ICMP arrives (the iptables script
		 * rate-limited the accept; netsh cannot, and the UI note
		 * on Windows says so). */
		plan_add (plan, &rule_icmp_all_off);
	} else {
		/* Two types stay unconditional while filtering is on:
		 * path-MTU discovery and traceroute loop reports. */
		plan_add (plan, &rule_icmp_time_exceeded);
		plan_add (plan, &rule_icmp_param_problem);

		if (settings->icmp_echo_request)
			plan_add (plan, &rule_icmp_echo_request);

		if (settings->icmp_echo_reply)
			plan_add (plan, &rule_icmp_echo_reply);

		if (settings->icmp_traceroute)
			plan_add (plan, &rule_traceroute_udp);

		if (settings->icmp_mstraceroute)
			plan_add (plan, &rule_icmp_dest_unreachable);
		else if (settings->icmp_unreachable)
			/* 3,1 is a subset of 3,any: under MS Traceroute the
			 * broader rule already covers it. */
			plan_add (plan, &rule_icmp_host_unreachable);

		if (settings->icmp_timestamping) {
			plan_add (plan, &rule_icmp_ts_request);
			plan_add (plan, &rule_icmp_ts_reply);
		}

		if (settings->icmp_masking) {
			plan_add (plan, &rule_icmp_mask_request);
			plan_add (plan, &rule_icmp_mask_reply);
		}

		if (settings->icmp_redirection)
			plan_add (plan, &rule_icmp_redirect);

		if (settings->icmp_source_quenches)
			plan_add (plan, &rule_icmp_source_quench);
	}

	if (settings->block_external_broadcast)
		plan_add (plan, &rule_block_broadcast_external);

	if (settings->block_internal_broadcast)
		plan_add (plan, &rule_block_broadcast_internal);

	if (settings->block_non_routables)
		plan_add (plan, &rule_block_reserved_sources);

	/* Not planned here, and why:
	 * - deny_packets: Windows Firewall drops silently and has no
	 *   per-rule reject, so there is nothing to plan; the UI keeps
	 *   the control disabled with that admission.
	 * - filter_tos: no Windows Firewall field marks Type of Service;
	 *   the page stays unoffered on Windows.
	 * - nat / ext_device / int_device: Internet Connection Sharing
	 *   needs the HNetCfg COM API, which the port does not carry
	 *   yet; the Network Settings page stays unoffered on Windows
	 *   rather than showing inert switches. */

	return plan;
}

void
fs_settings_plan_free (FsSettingsPlan *plan)
{
	if (plan == NULL)
		return;

	g_ptr_array_unref (plan->rules);
	g_free (plan);
}

const gchar *
fs_settings_plan_profile_name (guint profile_bit)
{
	switch (profile_bit) {
	case FS_FWP_PROFILE_PRIVATE: return "private";
	case FS_FWP_PROFILE_PUBLIC:  return "public";
	case FS_FWP_PROFILE_DOMAIN:  return "domain";
	default: return NULL;
	}
}
