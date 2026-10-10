/*---[ fs-settings-plan.h ]---------------------------------------------
 * The Firewall preferences, as portable firewall rules.
 *
 * fs-script.c turns an FsSettings into an iptables shell script; this
 * module turns the same FsSettings into a platform-neutral plan that a
 * backend can execute however it likes.  The Windows backend maps the
 * plan onto Windows Defender Firewall rules through netsh; Linux keeps
 * its script generator (already shipped and tested) and simply does not
 * call this.
 *
 * The mapping mirrors the iptables generation rule for rule, including
 * the original's quirks: "Traceroute" opens UDP 33434 and is not ICMP
 * at all, "MS Traceroute" allows destination-unreachable, and two ICMP
 * types (time-exceeded, parameter-problem) stay unconditional while
 * filtering is on because path-MTU discovery and traceroute loop
 * reports need them.
 *
 * Profile bits exist because Windows scopes rules to its three network
 * profiles; they are the honest equivalent of the iptables rules'
 * "-i ext_device / -i int_device" interface scoping, with
 * ext ~ public and int ~ private.  Linux has no equivalent and its
 * generator ignores them.
 *
 * Every rule here is INBOUND: the ICMP page governs what may arrive,
 * and the blocks are anti-spoofing/broadcast rules on arriving
 * traffic.  Rule names are deliberately netsh-safe (no ':' ',' or
 * '"'), and start with the spelling "StockFW " so the backend's rule
 * lifecycle -- which owns everything with a "StockFW" prefix and
 * nothing else -- finds and retires them on the next apply.  Policy
 * rules can never produce that spelling (they are always "StockFW-"
 * after netsh_safe_name), so the two sets cannot collide.
 *--------------------------------------------------------------------*/
#ifndef FS_SETTINGS_PLAN_H
#define FS_SETTINGS_PLAN_H

#include <glib.h>
#include "core/fs-script.h"

G_BEGIN_DECLS

/* Portable profile scoping (mapped to NET_FW_PROFILE2_* on Windows). */
#define FS_FWP_PROFILE_PRIVATE (1u << 0)
#define FS_FWP_PROFILE_PUBLIC  (1u << 1)
#define FS_FWP_PROFILE_DOMAIN  (1u << 2)

typedef enum
{
	FS_SETPLAN_PROTO_ANY,    /* no protocol field; the block-all rule  */
	FS_SETPLAN_PROTO_ICMP,   /* icmp with an optional "type,code"      */
	FS_SETPLAN_PROTO_UDP     /* udp with a single local port           */
} FsSetPlanProto;

typedef struct
{
	const gchar    *name;      /* display name, netsh-safe              */
	gboolean        allow;     /* TRUE = allow, FALSE = block          */
	FsSetPlanProto  proto;
	const gchar    *icmp;      /* "type,code", 'any' allowed; ICMP only */
	guint           port;      /* local port; UDP only, 0 = none       */
	const gchar    *remote;    /* comma-joined addresses, NULL = any   */
	guint           profiles;  /* FS_FWP_PROFILE_* mask, 0 = any       */
} FsSettingRule;

typedef struct
{
	GPtrArray *rules;          /* const FsSettingRule*, all inbound     */
} FsSettingsPlan;

/* Builds the plan for these settings.  Never fails: a settings state
 * always maps to some rule set (an empty plan is the plan for
 * "everything the backend cannot express", and the caller then leaves
 * the firewall's own defaults in charge). */
FsSettingsPlan *fs_settings_plan_new (const FsSettings *settings);
void            fs_settings_plan_free (FsSettingsPlan *plan);

/* "private" / "public" / "domain" for one profile bit, or NULL. */
const gchar *fs_settings_plan_profile_name (guint profile_bit);

G_END_DECLS

#endif /* FS_SETTINGS_PLAN_H */
