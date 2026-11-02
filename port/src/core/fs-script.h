/*---[ fs-script.h ]----------------------------------------------------
 * Firewall rule script generation.
 *
 * Ported from netfilter-script.c and scriptwriter.c.  This module
 * turns an FsPolicy into text.  On Linux the text is a shell script
 * driving iptables; on Windows the generator is unused and the backend
 * builds INetFwRule objects directly, because there is no shell there.
 *
 * The output is deliberately kept as text rather than executed here, so
 * it can be inspected and diffed without touching the live firewall.
 *--------------------------------------------------------------------*/
#ifndef FS_SCRIPT_H
#define FS_SCRIPT_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"
#include "core/fs-util.h"

G_BEGIN_DECLS

/* Interface selection, as the wizard collects it. */
typedef struct
{
	gchar    *ext_device;
	gchar    *int_device;
	gboolean  nat;
	gboolean  filter_icmp;
	gboolean  filter_tos;
	gboolean  block_external_broadcast;
	gboolean  block_internal_broadcast;
	gboolean  block_non_routables;
	gboolean  deny_packets;
	gboolean  restrictive_outbound;

	/* 1.0.7: log the NEW connections the policy accepts, sampled to at
	 * most FS_SCRIPT_ALLOW_LOG_RATE per second, so the Events page and
	 * the Activity graph show allowed traffic on Linux too.  Every
	 * policy ACCEPT then goes through FS_SCRIPT_ACCEPT_CHAIN. */
	gboolean  log_allowed;

	/* Which ICMP types the ICMP Filtering page lets through.  These
	 * follow the original exactly, including the one that is not ICMP
	 * at all: "Traceroute" opened UDP 33434, and "MS Traceroute"
	 * allowed destination-unreachable.  Only consulted when
	 * filter_icmp is set. */
	gboolean  icmp_echo_request;
	gboolean  icmp_echo_reply;
	gboolean  icmp_traceroute;
	gboolean  icmp_mstraceroute;
	gboolean  icmp_unreachable;
	gboolean  icmp_timestamping;
	gboolean  icmp_masking;
	gboolean  icmp_redirection;
	gboolean  icmp_source_quenches;
} FsSettings;

/* The chain every policy ACCEPT jumps to when log_allowed is set: it
 * LOGs the first packet of a new connection ("STOCKFW-ALLOW ", rate
 * limited) and accepts.  Return traffic, loopback and ICMP keep their
 * plain ACCEPT: they are not connections anyone asked about. */
#define FS_SCRIPT_ACCEPT_CHAIN   "ACCEPT_LOG"
#define FS_SCRIPT_ALLOW_LOG_RATE "10/s"
#define FS_SCRIPT_ALLOW_LOG_BURST "20"

FsSettings *fs_settings_new  (void);
void        fs_settings_free (FsSettings *settings);

/* Fills an FsSettings from the Firewall preferences, so the Preferences
 * dialog changes the rules that are actually generated instead of
 * writing keys nothing reads.  Call after fs_prefs_load() and again
 * whenever the dialog is accepted. */
void        fs_settings_load_prefs (FsSettings *settings);

/* Writes an FsSettings back to the same keys. */
void        fs_settings_save_prefs (const FsSettings *settings);

/* The control script: detects iptables, loads the policy modules and
 * dispatches to the per-direction setup scripts. */
gchar *fs_script_generate_control (const FsSettings *settings);

/* Per-direction setup.  "inbound" / "outbound".  IPv4. */
gchar *fs_script_generate_inbound  (const FsPolicy *policy,
                                    const FsSettings *settings);
gchar *fs_script_generate_outbound (const FsPolicy *policy,
                                    const FsSettings *settings);

/* The same for one family (FS_FAMILY_IPV4 or FS_FAMILY_IPV6), as
 * "$IPT ..." text.  For IPv6, $IPT stands for ip6tables.  Host names
 * are kept as written for IPv4 and left out for IPv6 (only the restore
 * form below resolves them). */
gchar *fs_script_generate_inbound_family  (const FsPolicy *policy,
                                           const FsSettings *settings,
                                           FsFamily family);
gchar *fs_script_generate_outbound_family (const FsPolicy *policy,
                                           const FsSettings *settings,
                                           FsFamily family);

/* A policy row's port as the generator writes it for iptables: one
 * port or a "first:last" range, each bound read in base 10 and written
 * as a plain decimal number ("022" -> "22", "67-68" -> "67:68").  NULL
 * when fs_util_is_valid_port() refuses it.  Caller frees. */
gchar *fs_script_port_text (const gchar *port);

/* ---- iptables-restore form (1.0.7) ---------------------------------
 *
 * What the Linux backend loads: per family, one iptables-restore input
 * for the filter table and, when needed, one for the nat table.  Each
 * is applied with `<tool>-restore --noflush', so it replaces StockFW's
 * own chains in one transaction and touches nothing else:
 *
 *   filter   INBOUND, OUTBOUND, ACCEPT_LOG (declared, so flushed and
 *            refilled; ACCEPT_LOG is declared and deleted when logging
 *            of allowed connections is off)
 *   nat      STOCKFW-DNAT (port forwards), STOCKFW-SNAT (router-mode
 *            masquerading, IPv4 only)
 *
 * The jumps from INPUT/OUTPUT/FORWARD and PREROUTING/POSTROUTING into
 * these chains are the backend's business.
 *
 * Host names are looked up here, once per plan, through the resolver
 * (fs_script_set_resolver), and written as addresses: each family gets
 * the addresses of its own kind.  A name with no address of one family
 * is noted (notes) and its rules cover the other family only.  A name
 * that cannot be looked up costs an allow rule (left out, listed in
 * skipped: the firewall fails closed) but fails the whole plan for a
 * block, because leaving a block out would let through what the user
 * blocked. */

#define FS_SCRIPT_DNAT_CHAIN "STOCKFW-DNAT"
#define FS_SCRIPT_SNAT_CHAIN "STOCKFW-SNAT"

GQuark fs_script_error_quark (void);
#define FS_SCRIPT_ERROR (fs_script_error_quark ())

enum
{
	FS_SCRIPT_ERR_RESOLVE = 1,  /* a blocked host could not be looked up */
	FS_SCRIPT_ERR_INVALID       /* a value cannot be written safely      */
};

/* Fills v4 and v6 (GPtrArray of gchar*, with free functions) with the
 * addresses `host' resolves to.  FALSE with error when the lookup
 * failed.  Results are validated again before use. */
typedef gboolean (*FsScriptResolveFunc) (const gchar *host,
                                         GPtrArray *v4, GPtrArray *v6,
                                         GError **error);

/* Tests replace the resolver; NULL restores the system's (GResolver). */
void fs_script_set_resolver (FsScriptResolveFunc func);

typedef struct
{
	gchar *filter;   /* iptables-restore input, "*filter ... COMMIT"   */
	gchar *nat;      /* "*nat ... COMMIT", or NULL: nothing in nat     */
} FsRestorePart;

typedef struct
{
	FsRestorePart v4;
	FsRestorePart v6;
	GPtrArray *notes;    /* gchar*: things worth knowing, no harm done */
	GPtrArray *skipped;  /* gchar*: rules that are not enforced         */
} FsRestorePlan;

/* How a block whose host name cannot be looked up is treated.
 *   STRICT   the plan fails (FS_SCRIPT_ERR_RESOLVE).  Right while
 *            StockFW's rules are loaded: the apply is refused and the
 *            rules in force -- holding that host's addresses from the
 *            last good lookup -- stay.
 *   LENIENT  the block is left out and listed in `skipped' ("Not
 *            blocked: ...").  Right when nothing is loaded yet:
 *            refusing to start over one name would leave every host
 *            unfiltered, which protects nothing. */
typedef enum
{
	FS_PLAN_STRICT_BLOCKS = 0,
	FS_PLAN_LENIENT_BLOCKS
} FsPlanBlocks;

/* NULL with error when the policy cannot be applied safely as a whole
 * (a block that cannot be resolved under STRICT, an invalid interface
 * name).  fs_script_restore_plan is the STRICT form. */
FsRestorePlan *fs_script_restore_plan (const FsPolicy *policy,
                                       const FsSettings *settings,
                                       GError **error);
FsRestorePlan *fs_script_restore_plan_ex (const FsPolicy *policy,
                                          const FsSettings *settings,
                                          FsPlanBlocks blocks,
                                          GError **error);
void           fs_restore_plan_free   (FsRestorePlan *plan);

/* Everything a start needs, as one script. */
gchar *fs_script_generate_full (const FsPolicy *policy,
                                const FsSettings *settings);

G_END_DECLS

#endif /* FS_SCRIPT_H */