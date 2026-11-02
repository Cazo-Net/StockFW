/*---[ fs-backend.h ]----------------------------------------------------
 * The firewall backend vtable.
 *
 * Everything the GUI needs from the operating system goes through this
 * interface.  On Linux it is implemented with iptables + syslog, on
 * Windows with the Windows Firewall API.  The core and the UI never
 * call the OS directly, so the same UI drives both.
 *--------------------------------------------------------------------*/
#ifndef FS_BACKEND_H
#define FS_BACKEND_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"
#include "core/fs-trust.h"

G_BEGIN_DECLS

/* Result of applying firewall rules. */
typedef enum
{
	FS_APPLY_OK,
	FS_APPLY_NO_IPTABLES,
	FS_APPLY_EXT_IF_FAILED,
	FS_APPLY_INT_IF_FAILED,
	FS_APPLY_NO_PRIVILEGE,
	FS_APPLY_PARTIAL,
	/* The request was deliberately not applied to the firewall
	 * (audit-only mode, or the Status page Lock).  Backends never
	 * return this; the apply gate does, so "nothing was applied"
	 * is never reported as a failure or as a success. */
	FS_APPLY_DRY_RUN,
	FS_APPLY_FAILED
} FsApplyResult;

/* Whether IPv6 traffic is filtered (1.0.7).  The Linux backend writes
 * IPv4 and IPv6 rules separately, so the two can disagree; the UI shows
 * this state next to the firewall state rather than letting "Running"
 * imply both. */
typedef enum
{
	FS_IPV6_UNKNOWN = 0,   /* cannot tell (not root, no backend)        */
	FS_IPV6_FILTERED,      /* the policy is enforced for IPv6 too       */
	FS_IPV6_UNFILTERED,    /* IPv4 is filtered, IPv6 is not             */
	FS_IPV6_ABSENT         /* the kernel has no IPv6: nothing to filter */
} FsIpv6State;

/* "unknown" / "filtered" / "not-filtered" / "absent": the stable words
 * used in JSON and audit lines. */
const gchar *fs_ipv6_state_to_string (FsIpv6State state);

/* The threat-intel rule set (core/fs-intelset.h).  Declared here so the
 * vtable can name it without this header pulling the intel engine in. */
typedef struct _FsIntelRuleset FsIntelRuleset;

/* Whether the threat-intel rules are in the kernel (1.0.7). */
typedef enum
{
	FS_INTEL_LIVE_UNKNOWN = 0,   /* cannot tell (not root, no nft)       */
	FS_INTEL_LIVE_ABSENT,
	FS_INTEL_LIVE_PRESENT
} FsIntelLive;

/* Where this computer is connected and which firewall profiles are in
 * force (core/fs-netplace.h). */
typedef struct _FsNetworkPlace FsNetworkPlace;

/* Callback invoked for each event reported by the platform's firewall. */
typedef void (*FsLogFunc) (const FsHit *hit, gpointer user_data);

/* Which Firewall sub-pages of the Preferences dialog this backend
 * actually reads, one bit per page.  WYSIWYG: a page is offered only
 * when its bit is set -- showing a page the backend ignores asks the
 * user to configure a firewall that is not listening.  "uses_settings"
 * was the single all-or-nothing version of this; per-page bits let a
 * backend honor some pages (Windows: ICMP and Advanced Options) while
 * honestly hiding the rest (Network Settings needs ICS, ToS cannot be
 * marked at all). */
#define FS_FWSEC_NETWORK  (1u << 0)  /* ext/int devices, NAT          */
#define FS_FWSEC_ICMP     (1u << 1)  /* the ICMP allow-list           */
#define FS_FWSEC_TOS      (1u << 2)  /* ToS page (offered as an
	                                  * admitted-dead page)          */
#define FS_FWSEC_ADVANCED (1u << 3)  /* rejection method, broadcasts,
	                                  * reserved source addresses    */

/* Finer-grained effects on offered pages.  A control whose effect the
 * backend cannot reproduce stays disabled with a note that says why,
 * never live and inert. */
#define FS_FWHON_REJECT_METHOD (1u << 0) /* deny_packets: REJECT vs
	                                  * DROP is a real choice       */
#define FS_FWHON_RATE_LIMIT    (1u << 1) /* ICMP rules are emitted
	                                  * with rate limits           */
#define FS_FWHON_LOG_ALLOWED   (1u << 2) /* 1.0.7: "Log allowed
	                                  * connections" is a real switch
	                                  * (Linux); Windows logs them
	                                  * through its audit policy     */
#define FS_FWHON_HOST_NAMES    (1u << 3) /* 1.0.7: a host name in a
	                                  * rule is looked up at apply
	                                  * time and written as each
	                                  * family's addresses (Linux);
	                                  * Windows Firewall takes
	                                  * addresses only              */

typedef struct
{
	const gchar *name;          /* "linux" / "windows" */
	const gchar *display_name;  /* human readable, for the About box */

	/* FS_FWSEC_* bits: which Firewall sub-pages the backend honors.
	 * The dialog offers exactly these pages, and fs_ui smoke asserts
	 * the count against them. */
	guint32 fw_sections;

	/* FS_FWHON_* bits: per-control effects inside offered pages. */
	guint32 fw_honors;

	/* TRUE when the backend can actually manage a firewall here. */
	gboolean (*available) (void);

	/* Current firewall state.  Returns FS_FW_NONE if unknown. */
	FsFirewallState (*get_state) (void);

	/* Start / stop / reload the firewall. */
	gboolean (*start) (GError **error);
	gboolean (*stop)  (GError **error);
	gboolean (*reload) (GError **error);

	/* Apply the policy to the live firewall.
	 *
	 * The backend decides what that means: on Linux it generates and
	 * runs iptables commands, on Windows it creates INetFwRule objects.
	 * Either way it works from the same FsPolicy, which is why the
	 * signature takes the policy rather than pre-rendered text. */
	FsApplyResult (*apply_rules) (const FsPolicy *policy, GError **error);

	/* Optional narrow apply (P3): touch only what changed.
	 *
	 * `remove' holds rule names to delete, `add' the concrete rules
	 * to create, and `repair' the unchanged rules whose names collide
	 * with a deletion (deleting by name would take them too, so the
	 * backend re-creates them right after the delete).  Rules present
	 * in both policy states are otherwise left alone -- no
	 * clear-then-recreate window, no churn on untouched rules.
	 * NULL slot means "whole-set apply only": callers fall back to
	 * apply_rules, which is still the honest contract. */
	FsApplyResult (*apply_delta) (const GList *remove,    /* gchar*  */
	                              const GList *add,        /* FsFwRule* */
	                              const GList *repair,     /* FsFwRule* */
	                              GError **error);

	/* Remove every rule this application previously created, leaving
	 * rules owned by the user or by Windows alone. */
	FsApplyResult (*clear_rules) (GError **error);

	/* Enumerate usable network interfaces.  Returns a list of
	 * FsInterface*, caller frees with g_list_free_full +
	 * fs_interface_free. */
	GList *(*list_interfaces) (void);

	/* Live traffic counters for the Status page's Network panel.
	 * Returns a GList of FsIfaceStat* (caller frees with
	 * g_list_free_full (..., fs_iface_stat_free)).  Backends with no
	 * counters return NULL and the panel is left out. */
	GList *(*list_interface_stats) (void);

	/* Currently open sockets for the Status page's Active connections
	 * panel.  Returns a GList of FsConnection* (caller frees with
	 * g_list_free_full (..., fs_connection_free)).  May return NULL
	 * when the platform or the account cannot enumerate them. */
	GList *(*list_connections) (void);

	/* Executable paths of currently running processes, deduplicated
	 * (case-insensitively: two spellings of one path are one row).
	 * Returns a GList of gchar* -- caller frees with g_list_free_full
	 * (..., g_free).  NULL when the platform cannot enumerate.  The
	 * Trust page scans these through the trust engine. */
	GList *(*list_processes) (void);

	/* Live event monitor. */
	gboolean (*log_start) (FsLogFunc callback, gpointer user_data, GError **error);
	void     (*log_stop)  (void);
	gboolean (*log_active) (void);
	/* 1.0.7: where the monitor reads ("the kernel ring buffer
	 * (/dev/kmsg)"), and -- when it stopped on its own, with
	 * log_active() now FALSE -- why.  Borrowed strings; NULL when
	 * there is nothing to say.  NULL slots: not reported. */
	const gchar *(*log_source)  (void);
	const gchar *(*log_problem) (void);

	/* DHCP server control (meaningful for a router build). */
	gboolean (*dhcp_set_enabled) (gboolean enabled, GError **error);

	/* Per-profile state.  Windows exposes three independently
	 * switchable profiles (domain / private / public); Linux has one
	 * global state.  Backends with a single state return FALSE here
	 * and the UI hides the per-profile controls. */
	gboolean (*get_profile_enabled) (gint profile, gboolean *enabled);
	gboolean (*set_profile_enabled) (gint profile, gboolean enabled,
	                                GError **error);

	/* 1.0.7: the profiles in force right now and the networks that put
	 * them there (core/fs-netplace.h), for the Overview's subtitle, the
	 * "In use" marks on the profiles card, and the verdict: a computer
	 * whose profile in use is switched off is not protected on that
	 * network, however many other profiles are on.  Read in-process;
	 * cheap enough for a timer.  Caller frees with
	 * fs_network_place_free().  NULL when it cannot tell; a NULL slot
	 * means the platform has no such notion (Linux). */
	FsNetworkPlace *(*network_place) (void);

	/* Authenticode status for one executable -- the platform half of
	 * the trust engine.  Returns TRUE with the verdict (and a
	 * signer's name when there is one), FALSE when the platform
	 * cannot say.  Backends with no trust engine leave the slot
	 * NULL and their executables read "Signature not checked". */
	gboolean (*trust_signature) (const gchar *path,
	                             FsTrustSignature *sig,
	                             gchar **publisher);

	/* 1.0.7: IPv6 enforcement state.  detail, when not NULL, receives
	 * a caller-owned sentence for the UI (may be set to NULL).  NULL
	 * slot means FS_IPV6_UNKNOWN. */
	FsIpv6State (*ipv6_state) (gchar **detail);

	/* 1.0.7: what the last successful apply_rules left out or could
	 * not cover, one sentence per line ("IPv6 is not filtered:
	 * ip6tables is not installed."), or NULL when nothing.  These are
	 * notes on an apply that succeeded -- the policy is in force --
	 * so they are not a PARTIAL result, which the apply gate rightly
	 * treats as a failure and rolls back.  Caller frees.  NULL slot:
	 * the backend has none. */
	gchar *(*apply_notes) (void);

	/* 1.0.7 threat intel: replace every blocklist/location rule this
	 * application owns with `ruleset' (an empty ruleset removes them),
	 * all or nothing where the platform allows it.  NULL slots mean the
	 * platform cannot enforce threat intel; the UI says so.  TRUE when
	 * the kernel holds the new rules afterwards, whatever the tool
	 * said -- except when the tool failed and the kernel holds the
	 * very rules it held before: nothing then shows the change went
	 * through, so FALSE, with an error that says the same rules are
	 * still in force.  The engine reads the kernel back either way. */
	gboolean (*intel_apply) (const FsIntelRuleset *ruleset,
	                         GError **error);
	/* Remove them all.  Not an error when there is nothing to remove,
	 * as long as the platform's tool can say so: without it (Linux
	 * without nft) the slot fails with G_IO_ERROR_NOT_FOUND, and the
	 * engine decides from its own record whether that matters. */
	gboolean (*intel_clear) (GError **error);
	/* Packets and bytes blocked per set id since the rules were loaded:
	 * gchar* -> FsIntelCounter* (core/fs-intelset.h), both owned by the
	 * table.  NULL when the platform cannot count or nothing is
	 * loaded.  Must be cheap: it never lists set elements [S8.3]. */
	GHashTable *(*intel_counters) (void);
	/* Whether the rules are in the kernel right now, and the digest
	 * they were loaded with (caller frees; NULL when absent or not
	 * recorded).  The core compares it with what it last applied, so
	 * a table removed behind StockFW's back (a reboot, `nft flush
	 * ruleset') is reported, never assumed [S10]. */
	FsIntelLive (*intel_live) (gchar **digest);
	/* Why this thread's last intel_live answered UNKNOWN, as one
	 * sentence the user can act on ("nft was not found on PATH.
	 * Install the nftables package ..."); NULL when it did not or the
	 * platform cannot say.  Caller frees.  Optional (NULL slot). */
	gchar *(*intel_live_error) (void);
} FsBackend;

/* Profile identifiers, matching Windows' own numbering. */
#define FS_PROFILE_DOMAIN  0
#define FS_PROFILE_PRIVATE 1
#define FS_PROFILE_PUBLIC  2
#define FS_PROFILE_COUNT   3

/* The backend compiled in for this platform.  Never NULL: platforms
 * without a working implementation get the null backend so the GUI
 * still starts. */
const FsBackend *fs_backend (void);

const gchar *fs_error_domain (void);

/* Hands the backend the policy and settings the rule generator needs.
 * The Windows backend ignores this; the Linux one needs it to build
 * the iptables rules.  Optional: a backend may ignore the arguments. */
void fs_backend_set_context (FsPolicy *policy, FsSettings *settings);

G_END_DECLS

#endif /* FS_BACKEND_H */