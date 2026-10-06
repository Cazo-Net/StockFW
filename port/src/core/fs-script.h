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

/* Per-direction setup.  "inbound" / "outbound". */
gchar *fs_script_generate_inbound  (const FsPolicy *policy,
                                    const FsSettings *settings);
gchar *fs_script_generate_outbound (const FsPolicy *policy,
                                    const FsSettings *settings);

/* Everything a start needs, as one script. */
gchar *fs_script_generate_full (const FsPolicy *policy,
                                const FsSettings *settings);

G_END_DECLS

#endif /* FS_SCRIPT_H */